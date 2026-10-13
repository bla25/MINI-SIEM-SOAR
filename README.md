# SentinelLite — Mini SIEM + SOAR

A lightweight Python cybersecurity project that collects Linux
authentication logs, normalizes events, detects suspicious SSH
activity, manages security alerts, and records automated response
actions.

## Features

- File-based, incremental log collection with persisted reading state
- Structured event normalization
- SSH failed-login and successful-login parsing
- Configurable SSH brute-force and username-enumeration detection
- JSONL event, alert, and response-action storage
- Alert acknowledgement and resolution
- Allowlist-aware response handling
- Safe firewall dry-run adapter
- Structured application logging with rotation
- Docker packaging and Docker Compose
- Automated Python tests and GitHub Actions CI

## Architecture

See [docs/architecture.md](docs/architecture.md) for the component
diagram and data flow.

## Technology Stack

- Python
- JSON and JSONL
- Docker and Docker Compose
- Linux systemd journal
- Git and GitHub Actions
- Unit and integration testing

## Requirements

- Linux environment for host journal collection
- Python 3
- Docker Engine and Docker Compose
- Git

Host journal access is required only for the optional real-time
journal-forwarding workflow. File-based collector tests can use
synthetic authentication logs.

## Quick Start

Clone the repository and enter the project directory:

```bash
https://github.com/bla25/MINI-SIEM-SOAR
cd ss
