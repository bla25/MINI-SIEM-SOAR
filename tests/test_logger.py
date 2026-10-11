import logging
import tempfile
import unittest
from pathlib import Path

from utils.logger import setup_logger


class TestStructuredLogger(unittest.TestCase):
    def test_logger_writes_to_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "test.log"
            logger_name = f"test_logger_{id(self)}"

            logger = setup_logger(
                name=logger_name,
                log_file=str(log_file),
                level="INFO",
            )

            try:
                logger.info("SentinelLite test message")

                for handler in logger.handlers:
                    handler.flush()

                content = log_file.read_text(encoding="utf-8")
                self.assertIn("INFO", content)
                self.assertIn("SentinelLite test message", content)
            finally:
                for handler in logger.handlers[:]:
                    handler.close()
                    logger.removeHandler(handler)

    def test_invalid_level_is_rejected(self):
        with self.assertRaises(ValueError):
            setup_logger(
                name=f"invalid_logger_{id(self)}",
                log_file="/tmp/sentinellite-invalid-test.log",
                level="NOT_A_LEVEL",
            )


if __name__ == "__main__":
    unittest.main()

