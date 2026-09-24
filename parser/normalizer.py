from datetime import datetime
import ipaddress

def normalize_port(port):

    if port is None:
        return None

    try:
        port = int(port)

        if 1<= port <=65535:
            return port
    except(ValueError, TypeError):
        pass

    return None

def normalize_ip(ip):
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    
    except ValueError:
        return None

def normalize_timestamp(timestamp):
    """
    convert a syslog timestamp such as:
           
        Sep 24 09:00:00

    into an ISO-8601 timestamp.

    The current year is used because the original
    syslog timestamp does not contain a year
    """
    if not timestamp:
        return None

    try:
        current_year = datetime.now().year

        parsed = datetime.strptime(
                F"{current_year} {timestamp}",
                "%Y %b %d %H:%M:%S"
        )

        return parsed.isoformat()

    except ValueError:
        return None
