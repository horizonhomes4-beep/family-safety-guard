"""Local DNS filter for the macOS agent.

Listens on 127.0.0.1:53 (UDP+TCP). Blocked names get 0.0.0.0 / ::, everything else is forwarded to the
network's real resolvers. Every blocked lookup is reported through `on_block`, which is what feeds the
dashboard's "Blocked attempts" list and Live timeline.
"""
from __future__ import annotations
import hashlib, socket, socketserver, struct, threading, time

# Names answered with NXDOMAIN whenever the filter runs, but never reported as "blocked attempts":
#  * mask.icloud.com / mask-h2.icloud.com: Apple's documented way to make iCloud Private Relay switch itself off
#    (it sends Safari's lookups through Apple, past this filter and /etc/hosts)
#  * use-application-dns.net: Firefox's "canary" - NXDOMAIN makes Firefox turn off its own encrypted DNS
FORCE_NXDOMAIN = ("mask.icloud.com", "mask-h2.icloud.com", "use-application-dns.net")

# The agent's own control plane must never be filtered, whatever the rules say.
NEVER_BLOCK = ("firestore.googleapis.com", "identitytoolkit.googleapis.com", "securetoken.googleapis.com",
               "api.emailjs.com", "ipwho.is", "ipapi.co")


def parse_question(data: bytes):
    """-> (qname, qtype, end_offset_of_question) or None for anything malformed."""
    if len(data) < 17:
        return None
    try:
        qd = struct.unpack("!H", data[4:6])[0]
        if qd < 1:
            return None
        i, labels = 12, []
        while True:
            n = data[i]
            if n == 0:
                i += 1
                break
            if n & 0xC0 or i + 1 + n > len(data):
                return None
            labels.append(data[i + 1:i + 1 + n].decode("ascii", "ignore").lower())
            i += 1 + n
        qtype = struct.unpack("!H", data[i:i + 2])[0]
        return ".".join(labels), qtype, i + 4
    except (IndexError, struct.error):
        return None


def blocked_response(query: bytes, qend: int, qtype: int = 0) -> bytes:
    """NXDOMAIN ("no such site"): clean for every browser, and unlike 0.0.0.0 it can never reach this Mac itself."""
    rd = query[2] & 1
    flags = 0x8000 | (rd << 8) | 0x0080 | 3          # QR, RD echoed, RA, rcode 3
    return query[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + query[12:qend]


def servfail_response(query: bytes, qend: int) -> bytes:
    """Return DNS SERVFAIL when all upstream resolvers fail, rather than timing out silently."""
    rd = query[2] & 1
    flags = 0x8000 | (rd << 8) | 0x0080 | 2          # QR, RD echoed, RA, rcode 2
    return query[:2] + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + query[12:qend]


class Matcher:
    """Decides whether a host name is blocked. Immutable once built; swap the whole object to change rules."""

    def __init__(self, blocked=(), allowed=(), keywords=None):
        self.blocked, self.allowed = set(blocked), set(allowed)
        self.keywords = dict(keywords or {})     # category -> compiled regex (only enabled categories)

    @staticmethod
    def _under(host: str, domains) -> str | None:
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in domains:
                return cand
        return host if host in domains else None

    def signature(self) -> str:
        h = hashlib.sha1()
        for part in (sorted(self.blocked), sorted(self.allowed), sorted((k, v.pattern) for k, v in self.keywords.items())):
            h.update(repr(part).encode())
        return h.hexdigest()

    def verdict(self, host: str):
        """-> rule label (the domain/keyword rule that matched) or None."""
        host = host.lower().strip(".")
        if not host or "." not in host:
            return None
        if self._under(host, NEVER_BLOCK) or self._under(host, self.allowed):
            return None
        hit = self._under(host, self.blocked)
        if hit:
            return hit
        for category, rx in self.keywords.items():
            if rx.search(host):
                parts = host.split(".")
                return ".".join(parts[-2:]) if len(parts) >= 2 else host
        return None


class DnsFilter:
    def __init__(self, listen=("127.0.0.1", 53), upstreams=("1.1.1.1", "8.8.8.8"), on_block=None, timeout=3.0):
        self.listen, self.upstreams, self.on_block, self.timeout = listen, list(upstreams), on_block, timeout
        self.matcher = Matcher()
        self.queries = self.blocked = 0
        self._udp = self._tcp = None
        self._lock = threading.Lock()
        self.error = ""

    # ---- configuration (thread safe: replaced atomically)
    def set_matcher(self, matcher: Matcher):
        self.matcher = matcher

    def set_upstreams(self, servers):
        servers = [s for s in servers if s and not s.startswith("127.")]
        if servers:
            self.upstreams = servers

    @property
    def port(self):
        return self._udp.server_address[1] if self._udp else self.listen[1]

    @property
    def running(self):
        t1, t2 = getattr(self, "_t1", None), getattr(self, "_t2", None)
        return bool(self._udp and self._tcp and t1 and t2 and t1.is_alive() and t2.is_alive())

    # ---- core
    def _count(self, blocked_rule, host):
        with self._lock:
            self.queries += 1
            if blocked_rule:
                self.blocked += 1
        if blocked_rule and self.on_block:
            try:
                self.on_block(blocked_rule, host, time.time())
            except Exception:
                pass

    def answer(self, query: bytes, tcp: bool = False) -> bytes | None:
        q = parse_question(query)
        if not q:
            return self._forward(query, tcp)
        host, qtype, qend = q
        if self.matcher._under(host.strip(".").lower(), FORCE_NXDOMAIN):
            return blocked_response(query, qend, qtype)
        rule = self.matcher.verdict(host)
        if rule:
            self._count(rule, host)
            return blocked_response(query, qend, qtype)
        self._count(None, host)
        response = self._forward(query, tcp)
        return response if response else servfail_response(query, qend)

    def _forward(self, query: bytes, tcp: bool):
        for server in list(self.upstreams):
            try:
                if tcp:
                    with socket.create_connection((server, 53), timeout=self.timeout) as s:
                        s.sendall(struct.pack("!H", len(query)) + query)
                        head = self._read(s, 2)
                        return self._read(s, struct.unpack("!H", head)[0])
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(query, (server, 53))
                    return s.recvfrom(65535)[0]
            except (OSError, struct.error):
                continue
        return None

    @staticmethod
    def _read(sock, n):
        buf = b""
        while len(buf) < n:
            part = sock.recv(n - len(buf))
            if not part:
                raise OSError("closed")
            buf += part
        return buf

    # ---- servers
    def start(self):
        if self.running:
            return
        # Close any partially-created listener left by an earlier failed start.
        if self._udp or self._tcp:
            self.stop()
        outer = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                resp = outer.answer(data)
                if resp:
                    try:
                        sock.sendto(resp, self.client_address)
                    except OSError:
                        pass

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(5)
                    n = struct.unpack("!H", outer._read(self.request, 2))[0]
                    resp = outer.answer(outer._read(self.request, n), tcp=True)
                    if resp:
                        self.request.sendall(struct.pack("!H", len(resp)) + resp)
                except (OSError, struct.error):
                    pass

        class UDPServer(socketserver.ThreadingUDPServer):
            allow_reuse_address = False      # never silently share port 53 with another process
            daemon_threads = True

        class TCPServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        try:
            self._udp = UDPServer(self.listen, UDP)
            self._tcp = TCPServer((self.listen[0], self._udp.server_address[1]), TCP)
        except OSError as exc:
            self.stop()
            self.error = f"cannot listen on {self.listen[0]}:{self.listen[1]}: {exc}"
            raise
        self.error = ""
        self._t1 = threading.Thread(target=self._udp.serve_forever, daemon=True, name="dns-udp")
        self._t2 = threading.Thread(target=self._tcp.serve_forever, daemon=True, name="dns-tcp")
        self._t1.start(); self._t2.start()

    def stop(self):
        for srv, th in ((self._udp, getattr(self, "_t1", None)), (self._tcp, getattr(self, "_t2", None))):
            if not srv:
                continue
            try:
                if th and th.is_alive():
                    srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        self._udp = self._tcp = None


# ---------------------------------------------------------------- self-checks (used by the dashboard status and --diagnose)
def probe(host: str, port: int = 53, timeout: float = 2.0) -> str:
    """Ask the local filter itself: 'blocked' (NXDOMAIN), 'resolves' (it let the name through) or 'no-answer'."""
    q = struct.pack("!HHHHHH", 0x4D46, 0x0100, 1, 0, 0, 0)
    for label in host.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\0" + struct.pack("!HH", 1, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(q, ("127.0.0.1", port))
            r = s.recvfrom(4096)[0]
    except OSError:
        return "no-answer"
    if len(r) < 12:
        return "no-answer"
    rcode, answers = r[3] & 0x0F, struct.unpack("!H", r[6:8])[0]
    return "blocked" if rcode == 3 else ("resolves" if answers else "no-answer")


def system_lookup(host: str) -> str:
    """What the Mac's own resolver says: 'blocked' (lookup fails or only gives 0.0.0.0 / ::) or 'resolves'."""
    try:
        infos = socket.getaddrinfo(host, 80, proto=socket.IPPROTO_TCP)
    except OSError:
        return "blocked"
    return "resolves" if any(i[4][0] not in ("0.0.0.0", "::") for i in infos) else "blocked"
