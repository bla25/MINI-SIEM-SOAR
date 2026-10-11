import json
import tempfile
import unittest

from pathlib import Path

from response.blocklist import BlocklistManager
from response.response_engine import ResponseEngine

class TestResponseEngine(unittest.TestCase):

    def setUp(self):

        self.temp_dir = tempfile.TemporaryDirectory()

        base = Path(self.temp_dir.name)

        self.blocklist_file = (
            base / "blocklist.jsonl"
        )

        self.action_file = (
            base / "response_action.jsonl"
        )

        self.blocklist = BlocklistManager(
            blocklist_file=self.blocklist_file
        )

        self.engine = ResponseEngine(
            blocklist_manager=self.blocklist,
            action_file=self.action_file
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_alert(
        self,
        severity="high"
    ):

        return{
            "alert_id": "test-alert-001",
            "alert_type": "ssh_brute_force",
            "severity": severity,
            "source_ip": "192.168.1.200"
        }

    def test_high_severity_alert_blocks_ip(self):

        alert = self.create_alert()

        action = self.engine.respond(alert)

        self.assertIsNotNone(action)

        self.assertEqual(
            action["action"],
            "block_ip"
        )

        self.assertEqual(
            action["status"],
            "executed"
        )

        self.assertTrue(
            self.blocklist.is_blocked(
                "192.168.1.200"
            )
        )

    def test_low_severity_alert_does_not_block(self):

        alert = self.create_alert(
            severity="low"
        )

        action = self.engine.respond(alert)

        self.assertIsNone(action)

        self.assertFalse(
            self.blocklist.is_blocked(
                "192.168.1.200"
            )
        )

    def test_duplicate_ip_is_not_blocked_twice(self):

        alert = self.create_alert()

        first = self.engine.respond(alert)

        second = self.engine.respond(alert)

        self.assertEqual(
            first["status"],
            "executed"
        )

        self.assertEqual(
            second["status"],
            "already_blocked"
        )

    def test_action_is_saved(self):

        alert = self.create_alert()

        self.engine.respond(alert)

        self.assertTrue(
            self.action_file.exists()
        )

        with self.action_file.open("r") as file:
            line = file.readline()

        action = json.loads(line)

        self.assertEqual(
            action["action"],
            "block_ip"
        )

        self.assertEqual(
            action["source_ip"],
            "192.168.1.200"
        )

    def test_allowlisted_ip_is_not_blocked(self):

        allowlist_file = (
            Path(self.temp_dir.name)
            / "allowlist.json"
        )

        with allowlist_file.open("w") as file:
            json.dump(
                ["192.168.1.200"],
                file
            )

        blocklist = BlocklistManager(
            blocklist_file=self.blocklist_file,
            allowlist_file=allowlist_file
        )

        engine = ResponseEngine(
            blocklist_manager=blocklist,
            action_file=self.action_file
        )

        alert = self.create_alert()

        action = engine.respond(alert)

        self.assertIsNotNone(action)

        self.assertEqual(
            action["status"],
            "allowlisted"
        )

        self.assertFalse(
            blocklist.is_blocked(
                "192.168.1.200"
            )
        )

    def test_non_allowlisted_ip_is_blocking(self):

        alert = self.create_alert()

        action = self.engine.respond(alert)

        self.assertEqual(
            action["status"],
            "executed"
        )

        self.assertTrue(
            self.blocklist.is_blocked(
                "192.168.1.200"
            )
        )

if __name__ == "__main__":
    unittest.main()

