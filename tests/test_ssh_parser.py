import unittest

from parser.ssh_parser import parse_ssh_log


class TestSSHParser(unittest.TestCase):

    def test_failed_login(self):

        log = (
            "Sep 23 11:20:00 ubuntu "
            "sshd[9201]: Failed password for admin "
            "from 192.168.1.100 port 22 ssh2"
        )

        event = parse_ssh_log(log)

        self.assertEqual(
            event["event_type"],
            "authentication_failure"
        )

        self.assertEqual(
            event["severity"],
            "medium"
        )

        self.assertEqual(
            event["user"]["username"],
            "admin"
        )

        self.assertEqual(
            event["network"]["source_ip"],
            "192.168.1.100"
        )

        self.assertEqual(
            event["network"]["source_port"],
            22
        )

        self.assertEqual(
            event["process"]["name"],
            "sshd"
        )

        self.assertEqual(
            event["process"]["pid"],
            9201
        )

    def test_successful_login(self):

        log = (
            "Sep 23 11:21:00 ubuntu "
            "sshd[9202]: Accepted password for user1 "
            "from 192.168.1.101 port 22 ssh2"
        )

        event = parse_ssh_log(log)

        self.assertEqual(
            event["event_type"],
            "authentication_success"
        )

        self.assertEqual(
            event["severity"],
            "low"
        )

        self.assertEqual(
            event["user"]["username"],
            "user1"
        )

        self.assertEqual(
            event["network"]["source_ip"],
            "192.168.1.101"
        )

    def test_invalid_log(self):

        log = "Random unknown system event"

        event = parse_ssh_log(log)

        self.assertEqual(
            event["event_type"],
            "unknown"
        )

        self.assertEqual(
            event["severity"],
            "info"
        )

        self.assertEqual(
            event["raw_log"],
            log
        )

    def test_invalid_user(self):

        log = (
            "Sep 23 11:22:00 ubuntu "
            "sshd[9203]: Failed password for invalid user hacker "
            "from 10.0.0.50 port 22 ssh2"
        )

        event = parse_ssh_log(log)

        self.assertEqual(
            event["event_type"],
            "authentication_failure"
        )

        self.assertEqual(
            event["user"]["username"],
            "hacker"
        )

        self.assertEqual(
            event["network"]["source_ip"],
            "10.0.0.50"
        )

        self.assertEqual(
            event["network"]["source_port"],
            22
        )


if __name__ == "__main__":
    unittest.main()


        
