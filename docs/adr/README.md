# Architecture Decision Records

Each ADR captures one significant, hard-to-reverse decision: the context, the options weighed, the
choice, and its consequences. They are append-only history — supersede an ADR with a new one rather
than rewriting it.

**Status** values: `Proposed` (drafted, awaiting sign-off — no code yet) → `Accepted` (ratified;
build may start) → `Superseded by NNNN` / `Rejected`.

| ADR | Title | Status |
|---|---|---|
| [0001](0001-staged-pipeline-architecture.md) | Staged pipeline — per-stage durable queues | Accepted |
| [0002](0002-phase2-transport-security-and-strong-auth.md) | Phase 2 — transport security & strong auth (off-loopback) | Accepted (TLS WP-13a/13b/15 → v0.1; MFA WP-14 built 2026-06-17) |
| [0003](0003-non-hl7-transports-database-rest-soap.md) | Non-HL7 transports — database, REST, SOAP connectors | Accepted (destinations); sources open |
| [0004](0004-payload-agnostic-ingress.md) | Payload-agnostic ingress (non-HL7 sources) | Accepted |
| [0005](0005-transform-accessible-state.md) | Transform-accessible state (cross-message correlation) | Accepted (design; build pending) |
| [0006](0006-external-data-lookups.md) | External data lookups for transforms (reference enrichment) | Accepted; Tier 1 (file + database sources) built |
| [0007](0007-gui-manageable-connections-toml.md) | GUI-manageable connections as a config-as-data TOML artifact | Proposed |
| [0008](0008-cluster-observability-api.md) | Read-only cluster observability API (`/cluster/status` + `/cluster/nodes`) | Proposed (built) |
| [0009](0009-run-scoped-context-providers.md) | Run-scoped context providers | Accepted |
| [0010](0010-handler-callable-db-lookup.md) | Handler-callable live database lookup (`db_lookup`) | Accepted |
| [0011](0011-timer-scheduled-source.md) | Timer source (scheduled synthetic message emission) | Proposed (built) |
| [0012](0012-x12-edi-codec.md) | X12 EDI codec — tolerant codec + raw-framed transport | Accepted (built) |
| [0013](0013-query-response-orchestration.md) | Query/response orchestration — capture an outbound's reply into an immutable per-message `response` table. Increment 2 (re-ingress) design lives beside it under the same number: [0013-increment-2-reingress-design](0013-increment-2-reingress-design.md) — a design companion to this ADR, not a separate decision. | Accepted |
| [0014](0014-alerting-rules-engine.md) | Alerting rules engine — configurable `[alerts].rules` over the built notifier | Proposed (built) |
| [0015](0015-ws-soap-outbound-mtls-wssecurity.md) | WS-\* SOAP outbound — mutual-TLS client cert + WS-Security / WS-Addressing (extends the SOAP destination) | Accepted (2026-06-15) |
| [0016](0016-synchronous-x12-request-response.md) | Synchronous X12 request/response feeds (real-time eligibility 270/271 + friends) — capture/re-ingress + TA1 classifier | Accepted (2026-06-15) |
| [0017](0017-consumer-deployment-model.md) | Consumer deployment model — engine as a read-only installed dependency + org-owned config repo across multiple instances | Accepted (2026-06-16) |
| [0018](0018-per-message-signatures-accepted-risk.md) | Per-message digital signatures (ASVS 4.1.5) — accepted risk / deferred-by-design | Accepted (2026-06-16) |
| [0019](0019-pluggable-keyprovider-hsm-kms-vault.md) | Pluggable KeyProvider seam (HSM/KMS/Vault envelope decryption) for store-key material (ASVS 13.3.3) | Proposed |
| [0020](0020-protocol-diagnostic-capture.md) | Protocol-level diagnostic capture (Corepoint "Protocol Data" + "Protocol Text") — per-connection RAM ring + on-error/snapshot flush to a `protocol_trace` table | Proposed |
| [0021](0021-inbound-ack-nak-capture-response-sent.md) | Inbound ACK/NAK capture ("Response Sent") — ADR 0013 Increment 3: a `kind` discriminator on the `response` table | Proposed |
