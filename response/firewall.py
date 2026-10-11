import ipaddress


class FirewallAdapter:

    def __init__(self, dry_run=True):
        self.dry_run = dry_run

    def block_ip(self, source_ip):
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError:
            return {
                "status": "failed",
                "action": "block_ip",
                "source_ip": source_ip,
                "error": "Invalid IP address"
            }

        command = [
            "nft",
            "add",
            "rule",
            "inet",
            "sentinellite",
            "input",
            "ip6" if address.version == 6 else "ip",
            "saddr",
            str(address),
            "drop"
        ]

        if self.dry_run:
            return {
                "status": "dry_run",
                "action": "block_ip",
                "source_ip": str(address),
                "command": command
            }

        return {
            "status": "failed",
            "action": "block_ip",
            "source_ip": str(address),
            "error": (
                "Real firewall execution is not enabled. "
                "Configure and validate a dedicated nftables "
                "table and chain before enabling it."
            )
        }

