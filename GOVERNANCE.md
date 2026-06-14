# Governance

This document describes how decisions are made in MessageFoundry and how responsibility is shared and
earned. It is intentionally honest about the project's size: MessageFoundry is **steward-led** (a
single maintainer) today, and this says so plainly rather than implying a committee that does not
exist yet.

## Roles & the maintainer ladder

Trust is earned incrementally:

1. **Contributor** — anyone whose pull request has been merged. The entry point for everyone.
2. **Triager** — issue/PR triage rights (labeling, closing duplicates/stale items, requesting info).
   Earned through sustained, accurate triage help; invited by the steward.
3. **Maintainer (committer)** — merge rights to one or more subsystems via
   [`.github/CODEOWNERS`](.github/CODEOWNERS). Earned through a track record of high-quality pull
   requests **and** good review judgment; invited by the steward.
4. **Steward** — the project owner. Holds administrative, release, security-advisory, and
   tie-breaking authority. Currently the sole maintainer (see [MAINTAINERS.md](MAINTAINERS.md)).

## How decisions are made

- **Day to day: lazy consensus.** Most issues and PRs proceed by lazy consensus — if no maintainer
  objects within a reasonable window, the change moves forward. Anyone may raise concerns.
- **Ties and disputes: the steward decides.** While the project is steward-led, the steward is the
  final decision-maker.
- **Architecture: by ADR.** Any change touching the engine's invariants or core model is proposed as
  an **Architecture Decision Record** under [`docs/adr/`](docs/adr/) and discussed before
  implementation. "ADR or it didn't happen" for anything load-bearing.

## What we welcome — and what to discuss first

**Welcome (open a PR):**

- Bug fixes accompanied by a test.
- New **Connections / transports** — pluggable by design via the connector registry.
- Documentation, example Routers/Handlers, synthetic generators, and test-coverage improvements.
- Performance work backed by a benchmark.

**Discuss first (open an issue / ADR before writing code):**

- Anything touching the reliability invariants, the staged pipeline, the message store/queue, or
  authentication/RBAC.
- Changes to the "configuration *is* the graph" model (named Connections wired by Router/Handler).

**Out of scope (declined on principle):**

- Re-introducing a declarative "channel"/"route" element that bundles the graph.
- YAML (or any declarative DSL) for routing/handling *logic* — logic stays code-first.
- Adding Black, switching the console from PySide6 to PyQt, or importing GUI/web frameworks into the
  engine packages.
- Anything that weakens the PHI guardrails in [CONTRIBUTING.md](CONTRIBUTING.md) and
  [`docs/PHI.md`](docs/PHI.md).

## Bus factor — a named risk

The project currently has **one** maintainer, a single point of failure for releases and for the
private security-advisory process. Growing to a **second trusted maintainer** is an explicit goal,
sequenced in the [contributor program plan](docs/CONTRIBUTOR-PROGRAM-PLAN.md). Until then, response
times reflect one person's bandwidth.

## License & the CLA

MessageFoundry is licensed under **AGPL-3.0-or-later**. Contributions require agreement to the
[Contributor License Agreement](CLA.md), which grants the project the ability to offer a
separately-licensed commercial edition (open-core). The CLA is a template pending legal review; see
[CONTRIBUTING.md](CONTRIBUTING.md) for how the CLA Assistant bot collects signatures.

## Changing this document

Governance changes are proposed via pull request and decided by the steward. As the project and its
maintainer team grow, this document is expected to evolve from steward-led toward a small maintainer
team.
