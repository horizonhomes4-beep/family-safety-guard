import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "parent-package-template" / "program-DO-NOT-OPEN"))
import policy_rules


class ManualOverrideTests(unittest.TestCase):
    def test_persistent_website_unlock_overrides_paused_and_schedule(self):
        self.assertEqual(policy_rules.manual_override({"overrideMode": "unlock", "unlockedUntil": 0, "paused": True}, 100), "unlock")

    def test_timed_website_unlock_overrides_until_expiry(self):
        p = {"overrideMode": "unlock", "unlockedUntil": 200, "paused": False}
        self.assertEqual(policy_rules.manual_override(p, 199), "unlock")
        self.assertIsNone(policy_rules.manual_override(p, 200))

    def test_website_lock_wins_even_if_old_unlock_expiry_is_future(self):
        p = {"overrideMode": "lock", "unlockedUntil": 500, "paused": False}
        self.assertEqual(policy_rules.manual_override(p, 100), "lock")

    def test_resume_schedule_uses_schedule(self):
        p = {"overrideMode": "schedule", "unlockedUntil": 0, "paused": False}
        self.assertIsNone(policy_rules.manual_override(p, 100))

    def test_legacy_timed_unlock_still_works(self):
        self.assertEqual(policy_rules.manual_override({"unlockedUntil": 200}, 100), "unlock")

    def test_legacy_pause_still_works(self):
        self.assertEqual(policy_rules.manual_override({"paused": True}, 100), "lock")


if __name__ == "__main__":
    unittest.main()
