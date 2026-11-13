"""Offline regression tests for website policy and DNS matching."""
import re
import struct
import socket
import unittest
import sqlite3
import tempfile
import time
from pathlib import Path

import webhistory_mac

import blocklists
import dnsfilter
import policy


class WebsitePolicyTests(unittest.TestCase):
    def test_clean_domain_removes_scheme_www_and_path(self):
        self.assertEqual(policy.clean_domain("https://WWW.Example.com/path?q=1"), "example.com")

    def test_blocked_domain_covers_subdomains_not_suffix_lookalikes(self):
        matcher = dnsfilter.Matcher(["example.com"])
        self.assertEqual(matcher.verdict("example.com"), "example.com")
        self.assertEqual(matcher.verdict("www.example.com"), "example.com")
        self.assertIsNone(matcher.verdict("notexample.com"))

    def test_allowed_exception_covers_only_its_subtree(self):
        matcher = dnsfilter.Matcher(["example.com"], ["safe.example.com"])
        self.assertIsNone(matcher.verdict("safe.example.com"))
        self.assertIsNone(matcher.verdict("x.safe.example.com"))
        self.assertEqual(matcher.verdict("x.example.com"), "example.com")

    def test_allowed_exception_overrides_category_keyword(self):
        matcher = dnsfilter.Matcher([], ["goodadult.example"], {"adult": re.compile("adult")})
        self.assertIsNone(matcher.verdict("goodadult.example"))
        self.assertEqual(matcher.verdict("adult.example"), "adult.example")

    def test_control_plane_is_never_blocked(self):
        matcher = dnsfilter.Matcher(["googleapis.com"])
        self.assertIsNone(matcher.verdict("firestore.googleapis.com"))

    def test_unblock_is_applied_by_replacing_matcher(self):
        matcher = dnsfilter.Matcher(["example.com"])
        self.assertEqual(matcher.verdict("www.example.com"), "example.com")
        matcher = dnsfilter.Matcher([], [])
        self.assertIsNone(matcher.verdict("www.example.com"))

    def test_block_response_is_nxdomain_and_preserves_question(self):
        query = (struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
                 + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1))
        parsed = dnsfilter.parse_question(query)
        self.assertIsNotNone(parsed)
        response = dnsfilter.blocked_response(query, parsed[2])
        self.assertEqual(response[3] & 0x0F, 3)
        self.assertEqual(response[12:], query[12:parsed[2]])

    def test_upstream_failure_returns_servfail_not_silent_timeout(self):
        query = (struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0)
                 + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1))
        server = dnsfilter.DnsFilter(("127.0.0.1", 0), upstreams=[])
        response = server.answer(query)
        self.assertIsNotNone(response)
        self.assertEqual(response[3] & 0x0F, 2, "failed upstream resolution must return SERVFAIL")
        self.assertEqual(response[12:], query[12:])

    def test_live_dns_server_blocks_then_unblocks_over_udp_and_tcp(self):
        server = dnsfilter.DnsFilter(("127.0.0.1", 0), upstreams=[])
        # Deterministic local upstream: a forwarded query gets an empty NOERROR reply.
        def forward(query, tcp=False):
            response = bytearray(query)
            response[2] = 0x81
            response[3] = 0x80
            response[6:12] = b"\\0" * 6
            return bytes(response)
        server._forward = forward
        server.set_matcher(dnsfilter.Matcher(["example.com"]))
        server.start()
        try:
            def ask(tcp):
                q = (struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
                     + b"\x07example\x03com\0" + struct.pack("!HH", 1, 1))
                if tcp:
                    with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
                        conn.sendall(struct.pack("!H", len(q)) + q)
                        n = struct.unpack("!H", dnsfilter.DnsFilter._read(conn, 2))[0]
                        return dnsfilter.DnsFilter._read(conn, n)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
                    conn.settimeout(2)
                    conn.sendto(q, ("127.0.0.1", server.port))
                    return conn.recvfrom(4096)[0]
            for tcp in (False, True):
                self.assertEqual(ask(tcp)[3] & 0x0F, 3, "blocked DNS request must return NXDOMAIN")
            server.set_matcher(dnsfilter.Matcher())
            for tcp in (False, True):
                self.assertEqual(ask(tcp)[3] & 0x0F, 0, "unblocked DNS request must be forwarded")
        finally:
            server.stop()

    def test_rule_domain_sets_keep_allow_list_separate(self):
        blocked, allowed = policy.rule_domains(
            {"sites": ["example.com"], "allowedSites": ["safe.example.com"]},
            blocklists.CATEGORY_DOMAINS)
        self.assertIn("example.com", blocked)
        self.assertIn("safe.example.com", allowed)


class BrowserHistoryTests(unittest.TestCase):
    def test_first_history_batch_does_not_skip_rows_after_limit(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "History"
            con = sqlite3.connect(db)
            con.executescript("CREATE TABLE visits(id INTEGER PRIMARY KEY, visit_time INTEGER, transition INTEGER, url INTEGER); CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT);")
            now = time.time()
            for i in range(1, 6):
                con.execute("INSERT INTO urls VALUES(?,?,?)", (i, f"https://site{i}.example/path", f"Site {i}"))
                con.execute("INSERT INTO visits VALUES(?,?,?,?)", (i, int((now + 11644473600) * 1_000_000) + i, 0, i))
            con.commit(); con.close()
            src = {"path": db, "kind": "chromium", "browser": "Chrome", "user": "child"}
            with tempfile.TemporaryDirectory() as snap:
                batch1, mark1 = webhistory_mac.read_source(src, 0, int(now - 3600), 2, Path(snap), True)
            self.assertEqual(len(batch1), 2)
            self.assertEqual(mark1, 2)
            with tempfile.TemporaryDirectory() as snap:
                batch2, mark2 = webhistory_mac.read_source(src, mark1, int(now - 3600), 2, Path(snap), False)
            self.assertEqual(len(batch2), 2)
            self.assertEqual(mark2, 4)
            with tempfile.TemporaryDirectory() as snap:
                batch3, mark3 = webhistory_mac.read_source(src, mark2, int(now - 3600), 2, Path(snap), False)
            self.assertEqual(len(batch3), 1)
            self.assertEqual(mark3, 5)

    def test_history_cursor_recovers_when_browser_database_is_rebuilt(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "History"
            con = sqlite3.connect(db)
            con.executescript("CREATE TABLE visits(id INTEGER PRIMARY KEY, visit_time INTEGER, transition INTEGER, url INTEGER); CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT);")
            now = time.time()
            con.execute("INSERT INTO urls VALUES(1, 'https://fresh.example/path', 'Fresh')")
            con.execute("INSERT INTO visits VALUES(1, ?, 0, 1)", (int((now + 11644473600) * 1_000_000),))
            con.commit(); con.close()
            src = {"path": db, "kind": "chromium", "browser": "Chrome", "user": "child"}
            with tempfile.TemporaryDirectory() as snap:
                visits, mark = webhistory_mac.read_source(src, 900, int(now - 3600), 20, Path(snap), False)
            self.assertEqual(len(visits), 1)
            self.assertEqual(mark, 1)

    def test_policy_block_and_unblock_cover_site_subdomains(self):
        blocked, allowed = policy.rule_domains(
            {"sites": ["https://www.example.com/path"], "allowedSites": []},
            blocklists.CATEGORY_DOMAINS)
        matcher = dnsfilter.Matcher(blocked, allowed)
        self.assertEqual(matcher.verdict("shop.example.com"), "example.com")
        unblocked, allowed = policy.rule_domains(
            {"sites": [], "allowedSites": []}, blocklists.CATEGORY_DOMAINS)
        self.assertIsNone(dnsfilter.Matcher(unblocked, allowed).verdict("shop.example.com"))


if __name__ == "__main__":
    unittest.main()
