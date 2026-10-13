import logging
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler

def setup_logger(name="sslogs", log_file="/tmp/ss.log", level=None):
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    configured_level = level or os.getenv("LOG_LEVEL", "INFO")
    numeric_level = getattr(logging, configured_level.upper(), None)

    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid logging level: {configured_level}")
    logger.setLevel(numeric_level)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    path = Path(log_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        path,
        maxBytes=5 * 1024 *1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger
