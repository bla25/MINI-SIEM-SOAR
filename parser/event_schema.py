import uuid


def create_event(
    timestamp,
    event_type,
    severity,
    source,
    username=None,
    source_ip=None,
    source_port=None,
    process_name=None,
    process_pid=None,
    message=None,
    raw_log=None
):
    event = {
        "event_id": str(uuid.uuid4()),

        "timestamp": timestamp,

        "event_type": event_type,

        "severity": severity,

        "source": {
            "type": "linux",
            "log_file": source
        },

        "user": {
            "username": username
        },

        "network": {
            "source_ip": source_ip,
            "source_port": source_port
        },

        "process": {
            "name": process_name,
            "pid": process_pid
        },

        "message": message,

        "raw_log": raw_log
    }

    return event
