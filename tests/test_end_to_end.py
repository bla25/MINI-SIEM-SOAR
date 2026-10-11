import json
import tempfile
import unittest

from pathlib import Path

from detection.detector import DetectionEngine
from detection.alert_manager import AlertManager
from response.blocklist import BlocklistManager
from response.firewall import FirewallAdapter
from response.response_engine import ResponseEngine

class TestEndToEnd(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        base = Path(self.temp_dir.name)

        self.alert_file = base / "alerts.jsonl"
        self.blocklist_file = base / "blocklist.jsonl"
        self.allowlist_file = base / "allowlist.json"
        self.action_file = base / "response_action.jsonl"

        self.allowlist_file.write_text(
            json.dumps(["127.0.0.1"])
        )

        self.alert_manager = AlertManager(
            alert_file=self.alert_file
        )

        self.blocklist_manager = BlocklistManager(
            blocklist_file=self.blocklist_file,
            allowlist_file=self.allowlist_file
        )

        self.firewall = FirewallAdapter(dry_run=True)

        self.response_engine = ResponseEngine(
            blocklist_manager=self.blocklist_manager,
            firewall_adapter=self.firewall,
            action_file=self.action_file
        )

        self.detection_engine = DetectionEngine(
            alert_manager=self.alert_manager
        )


    def tearDown(self):
        self.temp_dir.cleanup()

    def test_brute_force_generates_alert_and_response(self):
        alerts = []


        for second in [0, 5, 10, 15, 20]:
            event = {
                "event_id": f"test-{second}",
                "timestamp": f"2026-09-26T10:00:{second:02d}",
                "event_type": "authentication_failure",
                "severity": "medium",
                "user": {"username": "admin"},
                "network": {
                    "source_ip": "10.20.30.40",
                    "source_port": 50000 + second
                }
            }

            alerts.extend(
                self.detection_engine.process_event(event)
            )

        brute_force_alerts = [
            alert for alert in alerts
            if alert.get("alert_type") == "ssh_brute_force"
        ]

        self.assertEqual(len(brute_force_alerts), 1)

        alert = brute_force_alerts[0]
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["status"], "open")

        action = self.response_engine.respond(alert)

        self.assertIsNotNone(action)
        self.assertEqual(action["status"], "executed")
        self.assertEqual(
            action["firewall"]["status"],
            "dry_run"
        )


        saved_alerts = [
            json.loads(line)
            for line in self.alert_file.read_text().splitlines()
        ]

        self.assertEqual(len(saved_alerts),1)
        self.assertEqual(
            saved_alerts[0]["alert_type"],
            "ssh_brute_force"
        )

        self.assertTrue(
            self.blocklist_manager.is_blocked("10.20.30.40")
        )

        saved_actions = [
            json.loads(line)
            for line in self.action_file.read_text().splitlines()
        ]

        self.assertEqual(len(saved_actions), 1)
        self.assertEqual(
            saved_actions[0]["firewall"]["status"],
            "dry_run"
        )

if __name__== "__main__":
    unittest.main()

