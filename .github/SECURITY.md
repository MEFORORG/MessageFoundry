# Security Policy

MessageFoundry is an HL7 v2.x integration engine that handles **PHI**. We take security
reports seriously and appreciate responsible disclosure.

## Supported versions

The project is pre-1.0 and evolving rapidly; only the latest `main` is supported. Please
verify a report against current `main` before filing.

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Instead, report it privately:

- Preferred: open a [GitHub private security advisory](https://github.com/MEFORORG/MessageFoundry/security/advisories/new)
  ("Report a vulnerability"), or
- Email the maintainer at the address on the GitHub profile.

Please include: affected component (e.g. MLLP/file transport, store, API/auth, console),
a description and impact, and reproduction steps or a proof of concept. Do **not** include
real PHI — use synthetic HL7 (the `messagefoundry generate` corpus is ideal).

We aim to acknowledge within a few business days, agree on a disclosure timeline, and credit
reporters who wish to be named once a fix is released.

## Scope notes

- The engine binds `127.0.0.1` by default and requires authentication; the documented threat
  model and current posture live in [`docs/SECURITY.md`](../docs/SECURITY.md). Findings are
  rated both for today's localhost posture and for a future network-exposed deployment.
- Configuration is **executed Python** (Routers/Handlers) from an admin-owned config directory;
  the ability of a config author to run code in-process is by design, not a vulnerability — see
  `docs/SECURITY.md` and `docs/SERVICE.md` for the trust boundary and required directory ACLs.
