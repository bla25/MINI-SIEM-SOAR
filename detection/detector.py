from detection.rules import SSHBruteForceRule
from detection.alert_manager import AlertManager

class DetectionEngine:
    """
    Detection engine responsible for evaluating
    normalized security events against detection rules.
    """

    def __init__(self, alert_manager=None):
        self.rules = [
                SSHBruteForceRule(
                    threshold=5,
                    window_seconds=60
                )
        ]

        self.alert_manager = (
            alert_manager
            if alert_manager
            else AlertManager()
        )

    def process_event(self, event):
        """
        Process an event through all detection rules.

        Returns a list of general alerts.
        """

        alerts = []

        for rule in self.rules:
            detection = rule.evaluate(event)

            if detection:
                alert = self.alert_manager.create_alert(
                    detection
                )

                alerts.append(alert)

        return alerts
