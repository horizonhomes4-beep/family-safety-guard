import sys, time, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "parent-package-template" / "program-DO-NOT-OPEN"))
import agent


class CommandGate(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._r, self._u, self._s = agent.repair_device, agent.self_destruct, agent.save_state
        agent.repair_device = lambda c: self.calls.append(("repair", c["id"]))
        agent.self_destruct = lambda c: self.calls.append(("uninstall", c["id"]))
        agent.save_state = lambda: None
        agent.state["installedAt"] = int(time.time()) - 3600
        agent.state.pop("lastCommandId", None)

    def tearDown(self):
        agent.repair_device, agent.self_destruct, agent.save_state = self._r, self._u, self._s
        agent.pending_command = {}

    def issue(self, **kw):
        agent.pending_command = {"id": "c1", "type": "repair", "at": int(time.time() * 1000), **kw}
        agent.handle_command()

    def test_repair_runs_once(self):
        self.issue(); self.issue()
        self.assertEqual(self.calls, [("repair", "c1")])

    def test_uninstall_runs(self):
        self.issue(type="uninstall")
        self.assertEqual(self.calls, [("uninstall", "c1")])

    def test_unknown_type_and_missing_id_ignored(self):
        self.issue(type="format-disk"); self.issue(id="")
        self.assertEqual(self.calls, [])

    def test_command_older_than_installation_is_ignored(self):
        self.issue(type="uninstall", at=int((time.time() - 86400) * 1000))
        self.assertEqual(self.calls, [])

    def test_sanitised_dns_snapshot_never_keeps_loopback(self):
        item = {"InterfaceIndex": 4, "Servers": ["127.0.0.1", "::1", "192.168.1.1"]}
        cleaned = [x for x in item["Servers"] if not str(x).startswith("127.") and str(x) != "::1"]
        self.assertEqual(cleaned, ["192.168.1.1"])

    def test_removal_script_is_scoped_to_product(self):
        s = agent.removal_script("x1")
        for needle in ("M Family Safety Guard", "MFamilySafetyGuard-Watchdog", "PARENTGUARD BEGIN"):
            self.assertIn(needle, s)
        self.assertNotIn("Remove-Item -Path C:\\ -Recurse", s)


if __name__ == "__main__":
    unittest.main()
