import json
from pathlib import Path


class BlocklistManager:

    def __init__(
        self,
        blocklist_file="data/blocklist.jsonl",
        allowlist_file="data/allowlist.json"
    ):
        self.blocklist_file = Path(blocklist_file)
        self.allowlist_file = Path(allowlist_file)

        self.blocklist_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.allowlist_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def load_allowlist(self):
        """
        Load trusted IP addresses.
        """

        if not self.allowlist_file.exists():
            return []

        try:
            with self.allowlist_file.open("r") as file:
                data = json.load(file)

            if isinstance(data, list):
                return data

        except (json.JSONDecodeError, OSError):
            pass

        return []

    def is_allowlisted(self, source_ip):
        """
        Check whether an IP is trusted.
        """

        return source_ip in self.load_allowlist()

    def is_blocked(self, source_ip):
        """
        Check whether an IP is already blocked.
        """

        if not self.blocklist_file.exists():
            return False

        with self.blocklist_file.open("r") as file:

            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if entry.get("source_ip") == source_ip:
                    return True

        return False

    def block_ip(self, source_ip, reason):
        """
        Add an IP to the blocklist.

        Returns:
            True  -> IP was newly blocked
            False -> IP was already blocked or allowlisted
        """

        if self.is_allowlisted(source_ip):
            return False

        if self.is_blocked(source_ip):
            return False

        entry = {
            "source_ip": source_ip,
            "reason": reason
        }

        with self.blocklist_file.open("a") as file:
            file.write(
                json.dumps(entry) + "\n"
            )

        return True

