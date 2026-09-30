import json
import tempfile
import unittest

from pathlib import Path

from detection.alert_manager import AlertManager

class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        self.alert_file = Path(
            self.temp_dir.name
        ) / "alerts.jsonl"

        self.manager = AlertManager(
            alert_file=self.alert_file
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_detection(self):
        return {
            "alert_type": "ssh_brute_force",
            "severity": "high",
            "source_ip": "192.168.1.50",
            "attempts": 5,
            "window_seconds": 60,
            "description": "Multiple failed SSH authentication attempts"
        }

    def test_create_alert(self):
        detection = self.create_detection()

        alert = self.manager.create_alert(
            detection
        )

        self.assertIn(
            "alert_id",
            alert
        )

        self.assertIn(
            "created_at",
            alert
        )

        self.assertEqual(
            alert["status"],
            "open"
        )

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


    def test_alert_is_saved(self):

        detection = self.create_detection()

        self.manager.create_alert(
            detection
        )

        self.assertTrue(
            self.alert_file.exists()
        )

        with self.alert_file.open("r") as file:
            line = file.readline()

        saved_alert = json.loads(line)

        self.assertEqual(
            saved_alert["alert_type"],
            "ssh_brute_force"
        )

        self.assertEqual(
            saved_alert["status"],
            "open"
        )

    def test_acknowledge_alert(self):
        detection = self.create_detection()

        alert = self.manager.create_alert(
            detection
        )

        result = self.manager.acknowledge_alert(
            alert["alert_id"]
        )

        self.assertTrue(result)

        alerts = self.manager.load_alerts()

        self.assertEqual(
            alerts[0]["status"],
            "acknowledged"
        )

        self.assertIn(
            "updated_at",
            alerts[0]
        )

    def test_resolve_alert(self):
        detection = self.create_detection()

        alert = self.manager.create_alert(
            detection
        )

        result = self.manager.resolve_alert(
            alert["alert_id"]
        )

        self.assertTrue(result)

        alerts = self.manager.load_alerts()

        self.assertEqual(
            alerts[0]["status"],
            "resolved"
        )

    def test_invalid_alert_status(self):

        detection = self.create_detection()

        alert = self.manager.create_alert(
             detection
        )

        with self.assertRaises(ValueError):

            self.manager.update_alert_status(
                alert["alert_id"],
                "invalid"
            )



if __name__ == "__main__":
    unittest.main()




