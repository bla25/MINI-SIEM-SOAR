import json
import uuid

from datetime import datetime
from pathlib import Path


class AlertManager:

    def __init__(self, alert_file="data/alerts.jsonl"):
        self.alert_file = Path(alert_file)

        self.alert_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def create_alert(self, detection):
        """
        Convert a detection into a structured SIEM alert.
        """

        alert = {
            "alert_id": str(uuid.uuid4()),
            "created_at": datetime.now().isoformat(),
            "alert_type": detection.get("alert_type"),
            "severity": detection.get("severity"),
            "status": "open",
            "source_ip": detection.get("source_ip"),
            "attempts": detection.get("attempts"),
            "window_seconds": detection.get("window_seconds"),
            "description": detection.get("description")
        }

        self.save_alert(alert)

        return alert

    def save_alert(self, alert):
        """
        Persist the alert in JSONL format.
        """

        with self.alert_file.open("a") as file:
            file.write(
                json.dumps(alert) + "\n"
            )

    def load_alerts(self):
        """
        Load all persisted alerts.
        """

        if not self.alert_file.exists():
            return[]

        alert = []

        with self.alert_file.open("r") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    alerts.append(
                        json.loads(line)
                    )
                except json.jsonDecodeError:
                    continue
        return alerts
    def update_alert_status(
        self,
        alert_id,
        status
    ):
        valid_statuses = {
            "open",
            "acknowledged",
            "resolved"
        }

        if status not in valid_statuses:
            raise ValueError(
                f"Invalid alert status: {status}"
            )

        alerts = self.load_alerts()

        updated = False

        for alert in alerts:
            if alert.get("alert_id") == alert_id:

                alert["status"] = status
                alert["updated_at"] = (
                    datetime.now().isoformat()
                )

                updated = True

                break
        if not updated:
            return False

        with self.alert_file_open("w") as 

