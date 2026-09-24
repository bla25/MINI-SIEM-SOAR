import re

from parser.event_schema import create_event
from parser.normalizer import normalize_timestamp
from parser.normalizer import (
        normalize_timestamp,
        normalize_ip,
        normalize_port
)
FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?"
    r"(?P<process>sshd)\[(?P<pid>\d+)\]:\s+"
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+"
    r"port (?P<source_port>\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?"
    r"(?P<process>sshd)\[(?P<pid>\d+)\]:\s+"
    r"Accepted password for "
    r"(?P<username>\S+)\s+"
    r"from (?P<source_ip>\S+)\s+"
    r"port (?P<source_port>\d+)"
)

def parse_ssh_log(raw_log, source="logs/sample_auth.log"):
    raw_log = raw_log.strip()

    match = FAILED_PASSWORD_PATTERN.search(raw_log)

    if match:
        data = match.groupdict()

        return create_event(
                timestamp=normalize_timestamp(data["timestamp"]),
                event_type="authentication_failure",
                severity="medium",
                source=source,
                username=data["username"],
                source_ip=normalize_ip(data["source_ip"]),
                source_port=normalize_port(data["source_port"]),
                process_name=data["process"],
                process_pid=int(data["pid"]),
                message=raw_log,
                raw_log=raw_log
            )

    match = ACCEPTED_PASSWORD_PATTERN.search(raw_log)
    
    if match:
        data = match.groupdict()

        return create_event(
                timestamp=normalize_timestamp(data["timestamp"]),
                event_type="authentication_success",
                severity="low",
                source=source,
                username=data["username"],
                source_ip=normalize_ip(data["source_ip"]),
                source_port=normalize_port(data["source_port"]),
                process_name=data["process"],
                process_pid=int(data["pid"]),
                message=raw_log,
                raw_log=raw_log
                )
    return create_event(
            timestamp=None,
            event_type="unknown",
            severity="info",
            source=source,
            message=raw_log,
            raw_log=raw_log
        )

