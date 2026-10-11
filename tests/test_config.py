import json
import tempfile
import unittest

from pathlib import Path

from config.config_loader import load_config


class TestConfiguration(unittest.TestCase):

    def test_default_config_loads(self):
        config = load_config()

        self.assertEqual(
            config["detection"]["ssh_brute_force"]["threshold"],
            5
        )

        self.assertTrue(
            config["response"]["firewall_dry_run"]
        )

    def test_invalid_threshold_is_rejected(self):
        config = {
            "detection": {
                "ssh_brute_force": {
                    "enabled": True,
                    "threshold": 0,
                    "window_seconds": 60,
                    "cooldown_seconds": 60
                },
                "ssh_username_enumeration": {
                    "enabled": True,
                    "threshold": 5,
                    "window_seconds": 60,
                    "cooldown_seconds": 60
                }

            },
            "response": {
                "enabled": True,
                "minimum_severity": "high",
                "firewall_dry_run": True
            }
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "settings.json"
            path.write_text(json.dumps(config))

            with self.assertRaises(ValueError):
                load_config(path)

if __name__=="__main__":
    unittest.main()
