"""Local DNS filter for the ParentGuard agent.

Listens on 127.0.0.1:53 (UDP + TCP, and ::1 when available). Windows is pointed at it by the agent,
so EVERY name lookup made by every program on the PC passes through here *before* it is resolved:

  * blocked names get an immediate answer (0.0.0.0 / :: for A / AAAA, NXDOMAIN for everything else),
    including any sub-domain of a blocked domain and any name matching the keyword rules;
  * everything else is forwarded unchanged to the upstream resolver (Cloudflare Family DNS when the
    adult filter is on, otherwise the DNS servers the PC used before ParentGuard);
  * every query is written to an in-memory log that the agent drains each cycle.

This is what makes blocking real-time and wildcard-capable (a HOSTS file cannot do either) and what
gives the dashboard a complete, timestamped list of blocked attempts.

Only the standard library is used.
"""
from __future__ import annotations
import socket, struct, threading, time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

QTYPE_A, QTYPE_AAAA = 1, 28


def parse_question(packet: bytes):
    """(qname, qtype, end_offset_of_question) for the first question, or None if malformed."""
    if len(packet) < 17:
        return None
    qd = struct.unpack("!H", packet[4:6])[0]
    if qd < 1:
        return None
    labels, pos = [], 12
    while True:
        if pos >= len(packet):
            return None
        n = packet[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0:          # compression pointers are not valid inside a question
            return None
        pos += 1
        if pos + n > len(packet):
            return None
        labels.append(packet[pos:pos + n].decode("ascii", "ignore").lower())
        pos += n
    if pos + 4 > len(packet):
        return None
    qtype = struct.unpack("!H", packet[pos:pos + 2])[0]
    return ".".join(labels), qtype, pos + 4


def blocked_response(packet: bytes, qtype: int, end: int) -> bytes:
    """Build the reply for a blocked name from the request packet."""
    ident = packet[0:2]
    rd = packet[2] & 0x01
    question = packet[12:end]
    if qtype in (QTYPE_A, QTYPE_AAAA):
        rdata = b"\x00" * (4 if qtype == QTYPE_A else 16)
        flags = 0x8180 if rd else 0x8080
        answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(rdata)) + rdata
        return ident + struct.pack("!HHHHH", flags, 1, 1, 0, 0) + question + answer
    flags = (0x8180 if rd else 0x8080) | 3          # NXDOMAIN
    return ident + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question


def servfail(packet: bytes) -> bytes:
    flags = 0x8180 | 2
    return packet[0:2] + struct.pack("!HHHHH", flags, 0, 0, 0, 0)


class DnsFilter:
    def __init__(self, decide: Callable[[str], tuple[bool, str]], upstreams: Callable[[], list[str]],
                 log: Callable[[str], None] = lambda m: None, port: int = 53, host: str = "127.0.0.1") -> None:
        self.decide, self.upstreams, self.log = decide, upstreams, log
        self.port, self.host = port, host
        self.running = False
        self.error = ""
        self.queries: deque = deque(maxlen=6000)
        self._socks: list[socket.socket] = []
        self._pool: ThreadPoolExecutor | None = None
        self.stats = {"queries": 0, "blocked": 0, "forwardErrors": 0, "started": 0}
        self._good = ""  # last upstream that answered; tried first so one dead server does not slow every lookup

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> bool:
        if self.running:
            return True
        self._pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="dns")
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((self.host, self.port))
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((self.host, self.port))
            tcp.listen(32)
        except OSError as exc:
            self.error = f"cannot listen on {self.host}:{self.port}: {exc}"
            self.log("DNS filter: " + self.error)
            self._close()
            return False
        self._socks = [udp, tcp]
        threading.Thread(target=self._udp_loop, args=(udp,), daemon=True, name="dns-udp").start()
        threading.Thread(target=self._tcp_loop, args=(tcp,), daemon=True, name="dns-tcp").start()
        try:  # IPv6 loopback is optional
            udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            udp6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp6.bind(("::1", self.port))
            tcp6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            tcp6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp6.bind(("::1", self.port))
            tcp6.listen(32)
            self._socks += [udp6, tcp6]
            threading.Thread(target=self._udp_loop, args=(udp6,), daemon=True, name="dns-udp6").start()
            threading.Thread(target=self._tcp_loop, args=(tcp6,), daemon=True, name="dns-tcp6").start()
        except OSError:
            pass
        self.running, self.error = True, ""
        self.stats["started"] = int(time.time())
        self.log(f"DNS filter listening on {self.host}:{self.port}")
        return True

    def _close(self) -> None:
        for s in self._socks:
            try:
                s.close()
            except OSError:
                pass
        self._socks = []
        if self._pool:
            self._pool.shutdown(wait=False)
            self._pool = None

    def stop(self) -> None:
        self.running = False
        self._close()

    def drain(self) -> list[dict]:
        out = []
        while self.queries:
            try:
                out.append(self.queries.popleft())
            except IndexError:
                break
        return out

    # ---------------------------------------------------------------- request handling
    def resolve(self, packet: bytes, tcp: bool = False) -> bytes | None:
        """Answer one DNS request packet (blocked -> synthetic answer, else forwarded)."""
        q = parse_question(packet)
        if not q:
            return self._forward(packet, tcp)
        name, qtype, end = q
        try:
            blocked, why = self.decide(name)
        except Exception as exc:  # a policy bug must never take the internet down
            blocked, why = False, ""
            self.log(f"DNS decide error: {exc!r}")
        self.stats["queries"] += 1
        self.queries.append({"t": int(time.time()), "h": name, "q": qtype, "b": bool(blocked), "why": why})
        if blocked:
            self.stats["blocked"] += 1
            return blocked_response(packet, qtype, end)
        return self._forward(packet, tcp)

    def _forward(self, packet: bytes, tcp: bool) -> bytes | None:
        servers = list(self.upstreams())
        if self._good in servers:
            servers.remove(self._good)
            servers.insert(0, self._good)
        for server in servers:
            try:
                if tcp:
                    with socket.create_connection((server, 53), timeout=4) as s:
                        s.sendall(struct.pack("!H", len(packet)) + packet)
                        head = self._recv_exact(s, 2)
                        if not head:
                            continue
                        self._good = server
                        return self._recv_exact(s, struct.unpack("!H", head)[0])
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(2.5)
                    s.sendto(packet, (server, 53))
                    data, _ = s.recvfrom(4096)
                    if data[:2] == packet[:2]:
                        self._good = server
                        return data
            except OSError:
                continue
        self.stats["forwardErrors"] += 1
        return servfail(packet)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _udp_loop(self, sock: socket.socket) -> None:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                if not self._socks:
                    return
                time.sleep(0.05)
                continue
            if self._pool:
                try:
                    self._pool.submit(self._udp_answer, sock, data, addr)
                except RuntimeError:
                    return

    def _udp_answer(self, sock: socket.socket, data: bytes, addr) -> None:
        try:
            reply = self.resolve(data)
            if reply:
                sock.sendto(reply, addr)
        except Exception as exc:
            self.log(f"DNS udp error: {exc!r}")

    def _tcp_loop(self, sock: socket.socket) -> None:
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                if not self._socks:
                    return
                time.sleep(0.05)
                continue
            if self._pool:
                try:
                    self._pool.submit(self._tcp_answer, conn)
                except RuntimeError:
                    return

    def _tcp_answer(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            head = self._recv_exact(conn, 2)
            if not head:
                return
            packet = self._recv_exact(conn, struct.unpack("!H", head)[0])
            if not packet:
                return
            reply = self.resolve(packet, tcp=True)
            if reply:
                conn.sendall(struct.pack("!H", len(reply)) + reply)
        except Exception as exc:
            self.log(f"DNS tcp error: {exc!r}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
