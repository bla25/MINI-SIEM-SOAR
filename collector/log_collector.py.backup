import sys
from pathlib import Path
sys.path.insert(
        0,
        str(Path(__file__).resolve().parent.parent)
    )
from datetime import datetime
import json
import logging
import time
import signal
from parser.parser_manager import parse_log

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


class LogCollector:

    def __init__(self, log_file, output_file, state_file):
        self.log_file = Path(log_file)
        self.output_file = Path(output_file)
        self.state_file = Path(state_file)

        self.running  = True

        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

    def handle_shutdown(self, signum, frame):

        logging.info("Shutdown signal recieved.")

        self.running = False

    def load_position(self):

        if not self.state_file.exists():

            logging.info("No previous state found. Starting from begining.")
            return 0 
        
        try:
            with self.state_file.open("r") as file:
                state = json.load(file)

            file_state = state.get(str(self.log_file), {})

            if isinstance(file_state, int):
                return file_state

            position = file_state.get("position", 0)
            saved_inode = file_state.get("inode")

            current_inode = self.log_file.stat().st_ino
            current_size = self.log_file.stat().st_size

            if saved_inode is not None and saved_inode != current_inode:

                logging.info("Log file replacement detected")
                logging.info("Resettin position to 0.")

                return 0

            if current_size < position:

                logging.info("log file truncation detected.")
                logging.info("Resetting position to 0.")

                return 0
            
            logging.info(f"Loaded previous position:{position}")
            return position
        
        except json.JSONDecodeError:
            logging.warning("State file containes invalid JSON.")
            return 0

        except OSError as error:
            logging.error(f"Unable to read state:{error}")
            return 0



    def save_position(self, position):
        try:
            self.state_file.parent.mkdir(
                    parents=True,
                    exist_ok=True
            )

            inode = self.log_file.stat().st_ino

            state = {
                    str(self.log_file):{
                        "position": position,
                        "inode": inode
                    }
            }

            with self.state_file.open("w") as file:
                json.dump(
                        state,
                        file,
                        indent=4
                        )
        
        except OSError as error:
            logging.error(f"unable to save state:{error}")

    def collect_logs(self):
        
        if not self.log_file.exists():
             logging.error(
                 f"Log file bnot found: {self.log_file}"
             )

             return
        
        try:
            last_position = self.load_position()
            logging.info(
                    f"Starting from postion: {last_position}"
            )

            with self.log_file.open("r") as file:

                file.seek(last_position)

                logging.info(f"monitoring log file: {self.log_file}")

                while self.running:
                    line = file.readline()

                    if line:

                        line = line.strip()

                        if line:

                            self.process_log(line)

                            self.save_position(file.tell())
                        else:
                            time.sleep(1)
         
        except PermissionError:

            logging.error(f"Permission denied: {self.log_file}")

        except OSError as error:

            logging.error(f"file error:{error}")

        except Exception as error:

            logging.execution(f"unexpeted error: {error}")

        finally:

            logging.info(
                    "log collector stopped.")


    def process_log(self, raw_log):

        try:
            event = parse_log(
                    raw_log,
                    source=str(self.log_file)
            )

            self.save_event(event)

        except Exception as error:
            logging.error(
                    f"Unable to process log:{error}"
            )
    
    def save_event(self, event):

        try:

            self.output_file.parent.mkdir(
                    parents=True,
                    exist_ok=True
            )
            
            with self.output_file.open("a") as file:

                file.write(
                        json.dumps(event) + "\n"
                )
                
                logging.info("Event collected")

        except OSError as error:

            logging.error(f"unable to save event:{error}")

     

if __name__ == "__main__":

    collector = LogCollector(
        "logs/sample_auth.log",
        "data/collected_events.jsonl",
        "data/collector_state.json"
    )

    try:
        collector.collect_logs()

    except KeyboardInterrupt:

        logging.info("Collector interrupted by user.")

    finally:

        logging.info("Log collector exited.")

        sys.exit(0)
