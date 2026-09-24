import unittest

from parser.event_schema import create_event

class TestEventSchema(unittest.TestCase):
    def test_event_creation(self):
        event = create_event(
                timestamp="sep 23 11:20:00",
                event_type="authentication_failure",
                severity="medium",
                source="logs/sample_auth.log",
                username="admin",
                source_ip="192.168.1.100",
                source_port=22,
                process_name="sshd",
                process_pid=9201,
                message="Failed password",
                raw_log="raw_log"
            )

        self.assertIn("event_id", event)
        self.assertEqual(event["event_type"],
                         "authentication_failure")

        self.assertEqual(
                event["severity"],
                "medium")

        self.assertEqual(
                event["user"]["username"],"admin")

        self.assertEqual(
                event["network"]["source_ip"],"192.168.1.100")
        self.assertEqual(
                event["network"]["source_port"],22)
        self.assertEqual(
                event["process"]["name"],"sshd")


if __name__=="__main__":
    unittest.main()

