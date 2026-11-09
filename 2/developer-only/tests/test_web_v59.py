"""Tests for the v5.9 web filter: real DNS packets over real sockets, and synthetic Chrome/Firefox history files."""
import os, socket, sqlite3, struct, sys, tempfile, threading, time, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "parent-package-template" / "program-DO-NOT-OPEN"))
os.environ.setdefault("PG_DNS_PORT", "0")
import dnsfilter, webhistory  # noqa: E402


def make_query(name: str, qtype: int = 1, ident: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


class FakeUpstream(threading.Thread):
    """Answers every A query with 93.184.216.34 so we can tell forwarded answers from synthetic ones."""
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.seen = []

    def run(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            q = dnsfilter.parse_question(data)
            self.seen.append(q[0])
            ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
            self.sock.sendto(data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + data[12:q[2]] + ans, addr)


class DnsFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.up = FakeUpstream()
        cls.up.start()
        blocked = {"pornhub.com", "badsite.example"}

        def decide(host):
            if any(host == b or host.endswith("." + b) for b in blocked):
                return True, "list"
            if "xxx" in host:
                return True, "adult"
            return False, ""
        # DnsFilter forwards to port 53; patch _forward to use the fake upstream port
        cls.f = dnsfilter.DnsFilter(decide, lambda: ["127.0.0.1"], port=0)
        cls.f._forward_orig = cls.f._forward

        def fwd(packet, tcp):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2)
                s.sendto(packet, ("127.0.0.1", cls.up.port))
                return s.recvfrom(4096)[0]
        cls.f._forward = fwd

    def ask(self, name, qtype=1):
        return self.f.resolve(make_query(name, qtype))

    def test_blocked_a_returns_null_address(self):
        r = self.ask("pornhub.com")
        self.assertEqual(r[:2], b"\x12\x34")
        self.assertEqual(r[2] & 0x80, 0x80)           # response flag
        self.assertEqual(struct.unpack("!H", r[6:8])[0], 1)
        self.assertEqual(r[-4:], b"\x00\x00\x00\x00")  # 0.0.0.0

    def test_blocked_aaaa_returns_null_v6(self):
        r = self.ask("pornhub.com", 28)
        self.assertEqual(r[-16:], b"\x00" * 16)

    def test_subdomains_of_blocked_domain_are_blocked(self):
        for name in ("www.pornhub.com", "cdn7.static.pornhub.com", "anything.badsite.example"):
            self.assertEqual(self.ask(name)[-4:], b"\x00\x00\x00\x00", name)

    def test_keyword_rule_blocks_unknown_site(self):
        self.assertEqual(self.ask("brand-new-xxx-site.net")[-4:], b"\x00\x00\x00\x00")

    def test_https_record_query_is_nxdomain(self):
        r = self.ask("pornhub.com", 65)
        self.assertEqual(r[3] & 0x0F, 3)

    def test_allowed_site_is_forwarded(self):
        r = self.ask("example.org")
        self.assertEqual(r[-4:], bytes([93, 184, 216, 34]))
        self.assertIn("example.org", self.up.seen)

    def test_blocked_site_never_reaches_upstream(self):
        self.up.seen.clear()
        self.ask("www.pornhub.com")
        self.assertNotIn("www.pornhub.com", self.up.seen)

    def test_every_query_is_logged(self):
        self.f.drain()
        self.ask("pornhub.com"); self.ask("example.org")
        log = {(x["h"], x["b"]) for x in self.f.drain()}
        self.assertEqual(log, {("pornhub.com", True), ("example.org", False)})

    def test_garbage_packet_does_not_crash(self):
        self.f._forward = lambda p, t: b""
        self.assertEqual(self.f.resolve(b"\x00\x01"), b"")

    def test_real_sockets_udp_and_tcp(self):
        """Start the real listener on a free port and talk to it like Windows would."""
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        f = dnsfilter.DnsFilter(lambda h: (h.endswith("pornhub.com"), "list"), lambda: ["127.0.0.1"], port=port)
        self.assertTrue(f.start())
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                u.settimeout(3); u.sendto(make_query("www.pornhub.com"), ("127.0.0.1", port))
                self.assertEqual(u.recvfrom(4096)[0][-4:], b"\x00" * 4)
            with socket.create_connection(("127.0.0.1", port), timeout=3) as t:
                pkt = make_query("www.pornhub.com")
                t.sendall(struct.pack("!H", len(pkt)) + pkt)
                n = struct.unpack("!H", t.recv(2))[0]
                self.assertEqual(t.recv(n)[-4:], b"\x00" * 4)
        finally:
            f.stop()


def make_chromium(path: Path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER)")
    for i, (url, title, t, tr) in enumerate(rows, 1):
        con.execute("INSERT INTO urls VALUES(?,?,?)", (i, url, title))
        con.execute("INSERT INTO visits VALUES(?,?,?,?)", (i, i, int((t + webhistory.EPOCH_1601) * 1_000_000), tr))
    con.commit(); con.close()


def make_firefox(path: Path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)")
    for i, (url, title, t, vt) in enumerate(rows, 1):
        con.execute("INSERT INTO moz_places VALUES(?,?,?)", (i, url, title))
        con.execute("INSERT INTO moz_historyvisits VALUES(?,?,?,?)", (i, i, int(t * 1_000_000), vt))
    con.commit(); con.close()


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.now = time.time()
        d = self.root / "kid" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
        d.mkdir(parents=True)
        self.chrome = d / "History"
        # typed visit, link visit, embedded sub-frame (must be ignored), chrome:// page (ignored), 2-day-old visit (ignored on first read)
        make_chromium(self.chrome, [
            ("https://www.example-adult.com/video/1?x=1", "Hot video", self.now - 60, 1),
            ("https://news.example.org/a", "News", self.now - 50, 0),
            ("https://ads.tracker.net/frame", "", self.now - 40, 3),
            ("chrome://settings/", "Settings", self.now - 30, 1),
            ("https://old.example.com/", "Old", self.now - 2 * 86400, 1),
        ])
        f = self.root / "kid" / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles" / "abc.default"
        f.mkdir(parents=True)
        make_firefox(f / "places.sqlite", [
            ("https://fox.example.com/page", "Fox page", self.now - 20, 2),
            ("https://embed.example.com/x", "", self.now - 10, 4),
        ])
        (self.root / "Public").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_real_pages_are_returned(self):
        marks = {}
        visits, ok, errs = webhistory.collect(marks, self.now, root=self.root)
        self.assertEqual(errs, [])
        self.assertEqual([v["host"] for v in visits], ["www.example-adult.com", "news.example.org", "fox.example.com"])
        self.assertEqual(visits[0]["title"], "Hot video")
        self.assertEqual(visits[0]["u"], "https://www.example-adult.com/video/1")   # query string dropped
        self.assertTrue(any("Chrome (kid)" in x for x in ok) and any("Firefox (kid)" in x for x in ok))

    def test_incremental_reads_return_only_new_visits(self):
        marks = {}
        webhistory.collect(marks, self.now, root=self.root)
        again, _, _ = webhistory.collect(marks, self.now, root=self.root)
        self.assertEqual(again, [])
        con = sqlite3.connect(self.chrome)
        con.execute("INSERT INTO urls VALUES(99,'https://new.example.net/','New')")
        con.execute("INSERT INTO visits VALUES(99,99,?,1)", (int((self.now + webhistory.EPOCH_1601) * 1_000_000),))
        con.commit(); con.close()
        new, _, _ = webhistory.collect(marks, self.now, root=self.root)
        self.assertEqual([v["host"] for v in new], ["new.example.net"])

    def test_locked_or_missing_db_reports_error_not_crash(self):
        self.chrome.write_bytes(b"not a database")
        visits, ok, errs = webhistory.collect({}, self.now, root=self.root)
        self.assertTrue(any("Chrome" in e for e in errs))
        self.assertTrue(any("fox.example.com" == v["host"] for v in visits))


class AgentDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import agent
        cls.agent = agent

    def policy(self, **kw):
        base = {"adult": True, "gambling": False, "social": False, "proxy": False, "sites": [], "allowedSites": []}
        base.update(kw)
        self.agent.update_decider(base)

    def test_listed_adult_site_and_subdomains(self):
        self.policy()
        for h in ("pornhub.com", "www.pornhub.com", "cdn.hub.pornhub.com", "xvideos.com"):
            self.assertTrue(self.agent.dns_decide(h)[0], h)

    def test_unknown_adult_site_caught_by_keyword_before_first_lookup(self):
        self.policy()
        self.assertEqual(self.agent.dns_decide("some-new-porn-tube.biz"), (True, "adult"))

    def test_filters_off_means_nothing_blocked_by_category(self):
        self.policy(adult=False)
        self.assertFalse(self.agent.dns_decide("pornhub.com")[0])

    def test_parent_block_list_blocks_wildcard(self):
        self.policy(adult=False, sites=["https://www.somegame.io/play"])
        self.assertTrue(self.agent.dns_decide("static.somegame.io")[0])

    def test_allowed_site_overrides_block(self):
        self.policy(sites=["example.com"], allowedSites=["help.example.com"])
        self.assertFalse(self.agent.dns_decide("help.example.com")[0])
        self.assertTrue(self.agent.dns_decide("shop.example.com")[0])

    def test_agent_backend_is_never_blocked(self):
        self.policy(sites=["googleapis.com"])
        self.assertFalse(self.agent.dns_decide("firestore.googleapis.com")[0])

    def test_firefox_doh_canary(self):
        self.policy(adult=False)
        self.assertEqual(self.agent.dns_decide("use-application-dns.net"), (True, "doh-canary"))

    def test_notice_is_deduplicated_per_site(self):
        class FakeOs:  # pretend to be Windows for publish_notice without breaking pathlib
            name = "nt"
            def __getattr__(self, item):
                return getattr(os, item)
        sent = []
        saved = (self.agent.os, self.agent.NOTICE_SHARED, self.agent.NOTICE, self.agent.ensure_notice_helper)
        self.agent.os = FakeOs()
        self.agent.NOTICE_SHARED = Path(tempfile.mkdtemp()) / "shared.json"
        self.agent.NOTICE = Path(tempfile.mkdtemp()) / "n.json"
        self.agent.ensure_notice_helper = lambda: sent.append(1)
        self.agent._notice_last.clear()
        try:
            for _ in range(5):
                self.agent.publish_notice("Blocked website: pornhub.com", "block", "pornhub.com")
            self.agent.publish_notice("Blocked website: pornhub.com", "block", "xvideos.com")
        finally:
            self.agent.os, self.agent.NOTICE_SHARED, self.agent.NOTICE, self.agent.ensure_notice_helper = saved
        self.assertEqual(len(sent), 2)  # one per distinct site, not one per lookup


if __name__ == "__main__":
    unittest.main()
