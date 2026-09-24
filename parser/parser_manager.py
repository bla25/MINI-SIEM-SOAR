from parser.ssh_parser import parse_ssh_log

def parse_log(raw_log, source="unknown"):
    """
    Determine the appropriate parser for a raw log.
    """

    if "sshd[" in raw_log:
        return parse_ssh_log(raw_log, source)

    return {
        "event_type": "unknown",
        "severity": "info",
        "source": {
            "type": "linux",
            "log_file": source
        },

        "message": raw_Log,
        "raw_log": raw_log
    }


