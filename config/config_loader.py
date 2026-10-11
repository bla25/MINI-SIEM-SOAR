import json
from pathlib import Path
DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parent/"settings.json"
)

def load_config(config_path=None):
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    with path.open("r", encoding="utf-8") as file:
        config = json.load(file)

    validate_config(config)
    return config

def validate_config(config):
    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object")

    detection = config.get("detection")
    response = config.get("response")

    if not isinstance(detection, dict):
        raise ValueError("Missing detection configuration")

    if not isinstance(response, dict):
        raiseValueError("Missing response configuration")

    for rule_name in (
        "ssh_brute_force",
        "ssh_username_enumeration"
    ):
        rule = detection.get(rule_name)

        if not isinstance(rule, dict):
            raise ValueError(f"Missing rule: {rule_name}")

        for key in ("threshold", "window_seconds", "cooldown_seconds"):
            value  = rule.get(key)

            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"{rule_name}.{key} must be a positive integer"
                )

        if type(rule.get("enabled")) is not bool:
            raise ValueError(f"{rule_name}.enabled must be boolean")

    if type(response.get("enabled")) is not bool:
        raise ValueError("response.enabled must be boolean")

    if type(response.get("firewall_dry_run")) is not bool:
        raise ValueError("response.firewall_dry_run must be boolean")

    severity = response.get("minimum_severity")

    if severity not in ("low", "medium", "high", "critical"):
        raise ValueError("Invalid minimum_severity")

