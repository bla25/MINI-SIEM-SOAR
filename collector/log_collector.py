from pathlib import Path
from datetime import datetime
import json
import logging


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class LogCollector:

    def __init__(self, log_file, output_file, state_file):
        self.log_file = Path(log_file)
        self.output_file = Path(output_file)
        self.state_file = Path(state_file)

    def load_position(self):

        if not self.log_file.exists():
            return 0
        
        try:
            with self.state_file.open("r") as file:
                state = json.load(file)

            return state.get(str(self.log_file), 0)
        
        except(json.JSONDecodeError, OSError):

            logging.warning("Could not read state file. Starting from begining."
            )
            return 0

    def save_position(self, position):

        self.state_file.parent.mkdir(
                parents=True,
                exist_ok=True
        )

        state = {
                str(self.log_file):position
        }

        with self.state_file.open("w") as file:

            json.dump(
                    state,
                    file,
                    indent=4
            )

    def collect_logs(self):
        
        if not self.log_file.exists():
             logging.error(
                 f"Log file bnot found: {self.log_file}"
             )

             return
        last_position = self.load_position()

        logging.info(
            f"Starting from postion: {last_position}"
        )

        with self.log_file.open("r") as file:

            file.seek(last_position)

            while True:
                line = file.readline()

                if not line:
                    break

                line = line.strip()

                if line:
                   
                   self.process_log(line)

                self.save_position(file.tell())

        logging.info("Log collection completed.")

    def process_log(self, raw_log):
       
        event = {

            "event_id": None,

            "collected_at":
               datetime.now().isoformat(),

            "source":
                str(self.log_file),

            "raw_log":
                raw_log
        }

        self.save_event(event)
    
    def save_event(self, event):

        self.output_file.parent.mkdir(
                parents=True,
                exist_ok=True
        )

        with self.output_file.open("a") as file:

            file.write(
                    json.dumps(event) + "\n"
            )

        logging.info("Event collected")

     

if __name__ == "__main__":

    collector = LogCollector(
        "logs/sample_auth.log",
        "data/collected_events.jsonl",
        "data/collector_state.json"
    )

    collector.collect_logs()
