#!/usr/bin/env bash
set -euo pipefail

OUTPUT="$HOME/projects/ss/logs/host_auth.log"
mkdir -p "$(dirname "$OUTPUT")"
touch "$OUTPUT"

sudo journalctl -f -n 0 -o cat SYSLOG_IDENTIFIER=sshd |
while IFS= read -r line; do
    printf '%s\n' "$line" >> "$OUTPUT"
done
