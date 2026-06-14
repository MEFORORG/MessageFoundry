# Maintainers

This file lists who holds maintainer responsibilities and how the list grows. For the roles and the
decision model behind it, see [GOVERNANCE.md](GOVERNANCE.md).

## Current maintainers

| Role | GitHub | Areas |
|---|---|---|
| Steward | [@wshallwshall](https://github.com/wshallwshall) | All subsystems; releases; security advisories |

The project is currently **steward-led** — a single maintainer. This is a known bus-factor risk (see
[GOVERNANCE.md](GOVERNANCE.md)); recruiting a second maintainer is an explicit goal.

## Subsystem ownership

Review routing is defined in [`.github/CODEOWNERS`](.github/CODEOWNERS). Sensitive subsystems
(`auth/`, `store/`, `transports/`, API security, the publish/scan tooling, and the security docs)
require steward review even after additional maintainers join.

## How to become a maintainer

Maintainership is earned, not requested:

1. Build a track record of high-quality pull requests (tests included, gates green, scope respected
   per [GOVERNANCE.md](GOVERNANCE.md)).
2. Help with triage and reviews, showing good judgment and alignment with the project's architecture
   and PHI guardrails.
3. The steward extends an invitation, starting at **Triager** and progressing to **Maintainer** with
   merge rights to specific subsystems.

There is no self-nomination step today; the steward initiates promotions as trust is established.
