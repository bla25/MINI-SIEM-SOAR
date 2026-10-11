import unittest

from response.firewall import FirewallAdapter

class TestFirewallAdapter(unittest.TestCase):

    def test_dry_run_does_not_execute_command(self):

        firewall = FirewallAdapter(
                dry_run=True
        )

        result = firewall.block_ip(
                "192.168.1.200"
        )

        self.assertEqual(
            result["status"],
            "dry_run"
        )

        self.assertEqual(
            result["action"],
            "block_ip"
        )

        self.assertEqual(
            result["source_ip"],
            "192.168.1.200"
        )

        self.assertIn(
            "command",
            result
        )

    def test_command_contains_source_ip(self):

        firewall = FirewallAdapter(
            dry_run=True
        )

        result = firewall.block_ip(
            "10.10.10.50"
        )

        self.assertIn(
            "10.10.10.50",
            result["command"]
        )

if __name__ ==" __main__":
    unittest.main()
