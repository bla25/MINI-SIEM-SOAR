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

class SSHUsernameEnumerationRule:

    def __init__(
        self,
        threshold=5,
        window_seconds=60,
        cooldown_seconds=60
    ):
        self.threshold = threshold

        self.window = timedelta(
            seconds=window_seconds
        )

        self.cooldown = timedelta(
            seconds=cooldown_seconds
        )


        self.attempts = defaultdict(deque)

        self.last_alert = {}

    def evaluate(self, event):

        if event.get("event_type") != "authentication_failure":
            return None

        network = event.get("network", {})
        source_ip = network.get("source_ip")

        user = event.get("user", {})
        username = user.get("username")

        timestamp = event.get("timestamp")

        if not source_ip:
            return None

        if not username:
            return None

        if not timestamp:
            return None

        try:
            event_time = datetime.fromisoformat(
                timestamp
            )
        except ValueError:
            return None

        attempts = self.attempts[source_ip]

        attempts.append(
            (event_time, username)
        )

        cutoff = event_time - self.window

        while attempts:
            oldest_time = attempts[0][0]

            if oldest_time < cutoff:
                attempts.popleft()
            else:
                break

        unique_usernames = set()

        for _, attempted_username in attempts:
            unique_usernames.add(
                attempted_username
            )

        if len(unique_usernames) < self.threshold:
            return None

        previous_alert = self.last_alert.get(
            source_ip
        )

        if previous_alert is not None:

            elapsed = (
                event_time - previous_alert
            )

            if elapsed < self.cooldown:
                return None

        self.last_alert[source_ip] = event_time

        return {
            "alert_type":
                "ssh_username_enumeration",

            "severity":
                "high",

            "source_ip":
                source_ip,

            "unique_usernames":
                len(unique_usernames),

            "usernames":
                sorted(unique_usernames),

            "window_seconds":
                int(self.window.total_seconds()),

            "description":
                (
                    f"Multiple usernames targeted "
                    f"from {source_ip}"
                )
        }
