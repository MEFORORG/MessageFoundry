# Architecture Decision Records

Each ADR captures one significant, hard-to-reverse decision: the context, the options weighed, the
choice, and its consequences. They are append-only history — supersede an ADR with a new one rather
than rewriting it.

**Status** values: `Proposed` (drafted, awaiting sign-off — no code yet) → `Accepted` (ratified;
build may start) → `Superseded by NNNN` / `Rejected`.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-staged-pipeline-architecture.md) | Staged pipeline — per-stage durable queues | Accepted |
| [0002](0002-phase2-transport-security-and-strong-auth.md) | Phase 2 — transport security & strong auth (off-loopback) | Accepted (TLS WP-13a/13b/15 → v0.1; MFA WP-14 → 0.2) |
| [0003](0003-non-hl7-transports-database-rest-soap.md) | Non-HL7 transports — database, REST, SOAP connectors | Accepted (destinations); sources open |
| [0004](0004-payload-agnostic-ingress.md) | Payload-agnostic ingress (non-HL7 sources) | Accepted |
| [0005](0005-transform-accessible-state.md) | Transform-accessible state (cross-message correlation) | Accepted (design; build pending) |
| [0006](0006-external-data-lookups.md) | External data lookups for transforms (reference enrichment) | Accepted; Tier 1 (file + database sources) built |
| [0007](0007-gui-manageable-connections-toml.md) | GUI-manageable connections as a config-as-data TOML artifact | Proposed |
| [0008](0008-cluster-observability-api.md) | Read-only cluster observability API (`/cluster/status` + `/cluster/nodes`) | Proposed (built) |
