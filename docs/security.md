# Security and Operational Considerations

## Firewall safety

The firewall adapter is designed for dry-run operation. The response
engine may record a proposed block action, but the adapter must not
be treated as enforcing a real firewall rule.

## Allowlisting

The response engine checks configured allowlisted addresses before
recording a block action. Keep trusted addresses under review and
test allowlist behavior before changing response policies.

## Log privacy

Authentication logs may contain usernames, IP addresses, hostnames,
and other operational information.

- Do not commit real authentication logs to a public repository.
- Do not publish production alerts or event datasets without review.
- Restrict access to runtime files.
- Use synthetic records for demonstrations whenever possible.

## Container permissions

The development Compose configuration maps the container process
to the host UID and GID to support bind-mounted files.

Use the least privileges needed. Avoid chmod 777 and avoid running
the application as root solely to bypass permission problems.

## Configuration

Review config/settings.json before changing detection thresholds
or response behavior. Validate configuration changes with tests.

## Production limitations

This project is a learning and portfolio implementation, not a
replacement for a production SIEM.

Before production use, assess authentication, authorization,
tamper-resistant storage, secret management, alert delivery,
retention policies, high availability, monitoring, and the security
of all host and container interfaces.
