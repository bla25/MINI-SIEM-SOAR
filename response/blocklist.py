import json
from pathlib import Path


class BlocklistManager:

    def __init__(self, blocklist_file="data/blocklist.jsonl"):
        self.blocklist_file = Path(blocklist_file)

        self.blocklist_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

    def is_blocked(self, source_ip):
      

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


