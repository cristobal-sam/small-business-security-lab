# Validation record

2026-10-09: `python -B -m unittest -v` executed on Windows by the AI coding assistant. Six tests passed: guest isolation, staff application access, administrative access, denied inbound connections, rule precedence and invalid policy rejection.

Scope: offline decision model. No firewall, VPN or switch was configured. Tests do not verify live packet forwarding or a real enterprise deployment.
