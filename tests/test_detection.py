import unittest

from detection.rules import (SSHBruteForceRule, SSHUsernameEnumerationRule)
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

class TestSSHUsernameEnumerationRule(unittest.TestCase):

    def create_event(
        self,
        timestamp,
        username,
        source_ip="192.168.1.50"
    ):
        return {
            "event_id": "test-event",
            "timestamp": timestamp,
            "event_type": "authentication_failure",
            "severity": "medium",
            "source": {
                "type": "linux",
                "log_file": "logs/sample_auth.log"
            },
            "user": {
                "username": username
            },
            "network": {
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

        rule = SSHUsernameEnumerationRule(
            threshold=5,
            window_seconds=60
        )

        usernames = [
            "root",
            "admin",
            "test",
            "ubuntu"
        ]

        for second, username in enumerate(usernames):

            event = self.create_event(
                f"2026-09-26T12:00:{second:02d}",
                username
            )

            alert = rule.evaluate(event)

            self.assertIsNone(alert)

    def test_alert_for_multiple_usernames(self):

        rule = SSHUsernameEnumerationRule(
            threshold=5,
            window_seconds=60
        )

        usernames = [
            "root",
            "admin",
            "test",
            "ubuntu",
            "guest"
        ]

        alert = None

        for second, username in enumerate(usernames):

            event = self.create_event(
                f"2026-09-26T12:00:{second:02d}",
                username
            )

            alert = rule.evaluate(event)

        self.assertIsNotNone(alert)

        self.assertEqual(
            alert["alert_type"],
            "ssh_username_enumeration"
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
            alert["unique_usernames"],
            5
        )

    def test_repeated_username_does_not_count_as_new_user(self):

        rule = SSHUsernameEnumerationRule(
            threshold=5,
            window_seconds=60
        )

        usernames = [
            "root",
            "root",
            "root",
            "admin",
            "admin"
        ]

        for second, username in enumerate(usernames):

            event = self.create_event(
                f"2026-09-26T12:00:{second:02d}",
                username
            )

            alert = rule.evaluate(event)

        self.assertIsNone(alert)






if __name__ == "__main__":
    unittest.main()
