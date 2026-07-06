---
name: Bug report
about: Report a problem with the MessageFoundry engine, console, or IDE tooling
title: ''
labels: bug
assignees: ''
---

> ⚠️ **Never paste real PHI / patient data.** MessageFoundry processes HL7 in real
> deployments — use **synthetic** messages only (`messagefoundry generate ...`) and redact
> any IPs, hostnames, partner names, or message bodies before sharing. Security
> vulnerabilities should be reported privately, not here — see
> [SECURITY.md](../SECURITY.md).

**Describe the bug**
A clear and concise description of what the bug is.

**To reproduce**
Steps to reproduce the behavior — include the relevant config (Connection/Router/Handler) and a
**synthetic** sample message where applicable:
1. Configure '...'
2. Send / poll '...'
3. Observe '...'

**Expected behavior**
What you expected to happen.

**Actual behavior / logs**
What happened instead. Include the relevant log lines or stack trace (redact PHI and any
host/partner identifiers).

**Environment**
- MessageFoundry version: <!-- `messagefoundry --version` -->
- OS: <!-- e.g. Windows Server 2022 / Ubuntu 24.04 -->
- Python version: <!-- `python --version` -->
- Store backend: <!-- SQLite (default) / SQL Server (experimental) -->
- Component: <!-- engine / console / IDE extension -->
- Transport(s) involved: <!-- MLLP / file / database / REST / SOAP -->

**Additional context**
Anything else that helps — message type/trigger, whether it's reproducible, recent changes, etc.
