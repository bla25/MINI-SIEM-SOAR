import json
import uuid

from datetime import datetime
from pathlib import Path

from response.blocklist import BlocklistManager

class ResponseEngine:

    def __init__(
        self,
        blocklist_manager=None,
        action_file="data/response_actions.jsonl"
    ):

        self.blocklist_manager = (
            blocklist_manager
            if blocklist_manager
            else BlocklistManager()
        )

        self.action_file = Path(action_file)

        self.action_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    def respond(self, alert):

        severity = alert.get("severity")

        source_ip = alert.get("source_ip")

        if not source_ip:
            return None

        if severity != "high":
            return None

        action_taken = self.blocklist_manager.block_ip(
            source_ip,
            alert.get("alert_type", "unknown")
        )

        action = {
            "action_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "action": "block_ip",
            "source_ip": source_ip,
            "alert_id": alert.get("alert_id"),
            "alert_type": alert.get("alert_type"),
            "status":(
                "executed"
                if action_taken
                else "already_blocked"
            )
        }

        self.save_action(action)

        return action

    def save_action(self, action):

        with self.action_file.open("a") as file:
            file.write(
                json.dumps(action) + "\n"
        )
