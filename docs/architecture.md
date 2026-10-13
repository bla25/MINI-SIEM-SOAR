# SentinelLite Architecture

## Overview

SentinelLite is a lightweight Python-based mini-SIEM and SOAR
project for collecting Linux authentication logs, normalizing
events, detecting suspicious SSH activity, managing alerts, and
recording automated response actions.

## Architecture

```mermaid
flowchart TD
    A[Linux SSH Authentication Logs] --> B[Journal Forwarder]
    B --> C[Host Log File]
    C --> D[Log Collector]
    D --> E[Parser and Normalizer]
    E --> F[Detection Engine]
    F --> G[Alert Manager]
    F --> H[Response Engine]
    H --> I[Allowlist and Blocklist]
    H --> J[Firewall Adapter - Dry Run]
    D --> K[Structured Application Logs]
    G --> L[JSONL Alert Storage]
