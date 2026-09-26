from collections import defaultdict, deque
from datetime import datetime, timedelta

class SSHBruteForceRule:
    """
    Detect multiple failed SSH authentication attempts
    from the same source IP within a time window
    """

    def __init__(self, threshold=5, window_seconds=60):
        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)

        self.attempts = defaultdict(deque)

    def evaluate(self, event):
        """
        Evaluate a normalized event.

        Returns a alert dictionary if the rule is triggered.
        Otherwise returns None.
        """

        if event.get("event_type") != "authentication_failure":
            return None

        network = event.get("network", {})
        source_ip = network.get("source_ip")

        if not source_ip:
            return None

        timestamp = event.get("timestamp")

        if not timestamp:
            return None

        try:
            event_time = datetime.fromisoformat(timestamp)
        except ValueError:
            return None

        attempts = self.attempts[source_ip]

        attempts.append(event_time)

        cutoff = event_time - self.window

        while attempts and attempts[0] < cutoff:
            attempts.popleft()

        if len(attempts) >= self.threshold:
            return {
                "alert_type": "ssh_brute_force",
                "severity": "high",
                "source_ip": source_ip,
                "attempts": len(attempts),
                "window_seconds":int(
                    self.window.total_seconds()
                ),
                "description": (
                    f"multiple failed SSH authentication attempts"
                    f"from {source_ip}"
                )
            }
        return None
