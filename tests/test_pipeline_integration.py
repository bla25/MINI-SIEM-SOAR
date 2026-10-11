import json
import tempfile
import unittest

from pathlib import Path

from parser.parser_manager import parse_log
from detection.detector import DetectionEngine
from detection.alert_manager import AlertManager
from response.blocklist import BlocklistManager
from response.firewall import FirewallAdapter
from response.response_engine import ResponseEngine

class TestPipelineIntegration(unittest.TestCase):

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

    def test_raw_ssh_logs_trigger_safe_response(self):
        raw_logs = [
            "Oct 11 10:00:00 server sshd[1001]: Failed password for admin from 203.0.113.50 port 50001 ssh2",
            "Oct 11 10:00:05 server sshd[1002]: Failed password for admin from 203.0.113.50 port 50002 ssh2",
            "Oct 11 10:00:10 server sshd[1003]: Failed password for admin from 203.0.113.50 port 50003 ssh2",
            "Oct 11 10:00:15 server sshd[1004]: Failed password for admin from 203.0.113.50 port 50004 ssh2",
            "Oct 11 10:00:20 server sshd[1005]: Failed password for admin from 203.0.113.50 port 50005 ssh2",
        ]

        generated_alerts = []

        for raw_log in raw_logs:
            event = parse_log(
                raw_log,
                source="test_auth.log"
            )

            self.assertEqual(
                event["event_type"],
                "authentication_failure"
            )

            self.assertEqual(
                event["network"]["source_ip"],
                "203.0.113.50"
            )

            alerts = self.detection_engine.process_event(event)
            generated_alerts.extend(alerts)

        brute_force_alerts = [
            alert for alert in generated_alerts
            if alert.get("alert_type") == "ssh_brute_force"
        ]

        self.assertEqual(len(brute_force_alerts), 1)

        alert = brute_force_alerts[0]

        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["status"], "open")

        action = self.response_engine.respond(alert)

        self.assertIsNotNone(action)
        self.assertEqual(action["status"], "executed")
        self.assertEqual(action["firewall"]["status"], "dry_run")

        saved_alerts = [
            json.loads(line)
            for line in self.alert_file.read_text().splitlines()
        ]

        self.assertEqual(len(saved_alerts), 1)

        self.assertTrue(
            self.blocklist_manager.is_blocked("203.0.113.50")
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

if __name__ == "__main__":
    unittest.main()

