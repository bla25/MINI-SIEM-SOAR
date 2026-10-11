from config.config_loader import load_config
from detection.rules import (
    SSHBruteForceRule,
    SSHUsernameEnumerationRule,
)
from detection.alert_manager import AlertManager

from utils.logger import setup_logger
logger = setup_logger()

class DetectionEngine:
    def __init__(self, alert_manager=None, config=None):
        self.config = config if config is not None else load_config()

        detection_config = self.config["detection"]
        self.rules = []

        brute_force = detection_config["ssh_brute_force"]
        if brute_force["enabled"]:
            self.rules.append(
                SSHBruteForceRule(
                    threshold=brute_force["threshold"],
                    window_seconds=brute_force["window_seconds"],
                    cooldown_seconds=brute_force["cooldown_seconds"],
                )
            )

        enumeration = detection_config["ssh_username_enumeration"]
        if enumeration["enabled"]:
            self.rules.append(
                SSHUsernameEnumerationRule(
                    threshold=enumeration["threshold"],
                    window_seconds=enumeration["window_seconds"],
                    cooldown_seconds=enumeration["cooldown_seconds"],
                )
            )

        self.alert_manager = (
            alert_manager if alert_manager is not None
            else AlertManager()
        )

    def process_event(self, event):
        alerts = []

        for rule in self.rules:
            detection = rule.evaluate(event)
            if detection:
                alert = self.alert_manager.create_alert(detection)
                alerts.append(alert)
                logger.warning(
                    "Detection triggered: type=%s severity=%s source_ip=%s",
                    alert.get("alert_type"),
                    alert.get("severity"),
                    alert.get("source_ip"),
                )

        return alerts

