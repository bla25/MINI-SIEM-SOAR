import unittest

from detection.rules import SSHBruteForceRule
from detection.detector import DetectionEngine

class TestSSHBruteForceRule(unittest.TestCase):

    def create_event(self, timestamp, source_ip="192.168.1.50"):
        return {
            "event_id": "test_event",
            "timestamp": timestamp,
            "event_type": "authentication_failure",
            "severity": "medium",
            "source": {
                "type": "linux",
                "log_file": "logs/sample_auth.log"
            },
            "user": {
                "username": "admin"
            },
            "network":{
                "source_ip": source_ip,
                "source_port": 22
            },
            "process": {
                "name": "sshd",
                "pid": 1234
            },
            "message": "Failed password",
            "raw_log": "Failed password"
        }

    def test_no_alert_before_threshold(self):
        rule = SSHBruteForceRule(
            threshold=5,
            window_seconds=60
        )

        for second in [0, 5, 10,15]:
            event = self.create_event(
                f"2026-09-24T10:00{second:02d}"
            )

            alert = rule.evaluate(event)

            self.assertIsNone(alert)

    def test_alert_at_threshold(self):
        rule = SSHBruteForceRule(
            threshold=5,
            window_seconds=60
        )

        alert = None

        for seconds in [0, 5, 10, 15, 20]:
            event = self.create_event(
                f"2026-09-24T10:00:{seconds:02d}"
            )

            alert = rule.evaluate(event)

        self.assertIsNotNone(alert)
        self.assertEqual(
            alert["alert_type"],
            "ssh_brute_force"
        )
        self.assertEqual(
            alert["severity"],
            "high"
        )
        self.assertEqual(
            alert["source_ip"],
            "192.168.1.50"
        )
        self.assertEqual(
            alert["attempts"],
            5
        )

    def test_different_ips_are_tracked_seperately(self):
        rule = SSHBruteForceRule(
            threshold=5,
            window_seconds=60
        )

        for second in [0, 5, 10, 15]:
            event = self.create_event(
                f"2026-09-24T10:00:{second:02d}",
                source_ip="192.168.1.50"
            )

            self.assertIsNone(
                rule.evaluate(event)
            )
        event = self.create_event(
            "2026-09-24T10:00:20",
            source_ip="192.168.1.51"
        )

        self.assertIsNone(
            rule.evaluate(event)
        )


    def test_succesful_login_does_not_trigger(self):
        rule = SSHBruteForceRule(
            threshold=5,
            window_seconds=60
        )

        event = self.create_event(
            "2026-09-24T10:00:00"
        )

        event["event_type"] = "authentication_success"

        self.assertIsNone(
            rule.evaluate(event)
        )

class TestDetectionEngine(unittest.TestCase):

    def test_detection_engine(self):
        engine = DetectionEngine()

        for second in [0, 5, 10, 15]:
            event = {
                "timestamp":
                    f"2026-09-24T10:00:{second:02d}",
                "event_type":
                    "authentication_failure",
                "network": {
                    "source_ip":
                         "10.0.0.50"
                 }
            }

            alerts = engine.process_event(event)

            self.assertEqual(
                len(alerts),
                0
            )

        event = {
            "timestamp": "2026-09-24T10:00:20",
            "event_type": "authentication_failure",
            "network": {
                "source_ip": "10.0.0.50"
            }
        }

        alerts = engine.process_event(event)

        self.assertEqual(
            len(alerts),
            1
        )

        self.assertEqual(
            alerts[0]["alert_type"],
            "ssh_brute_force"
        )

if __name__ == "__main__":
    unittest.main()
    
