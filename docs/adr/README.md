# Architecture Decision Records

Each ADR captures one significant, hard-to-reverse decision: the context, the options weighed, the
choice, and its consequences. They are append-only history — supersede an ADR with a new one rather
than rewriting it.

**Status** values: `Proposed` (drafted, awaiting sign-off — no code yet) → `Accepted` (ratified;
build may start) → `Superseded by NNNN` / `Rejected`. A `Reserved` row is a **number allocation**
for a not-yet-authored ADR — recorded here (coordinator-owned) so parallel sessions don't collide on
ADR numbers; the row gets a title/file/link when the ADR is authored.

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
| [0020](0020-protocol-diagnostic-capture.md) | Protocol-level diagnostic capture (Corepoint "Protocol Data" + "Protocol Text") — per-connection RAM ring + on-error/snapshot flush to a `protocol_trace` table | **Dropped (Plan-3 §G)** — raw-PHI-at-rest tier, no demand; superseded by ADR 0021 §7's metadata-only connection-error log |
| [0021](0021-inbound-ack-nak-capture-response-sent.md) | Inbound ACK/NAK capture ("Response Sent") — ADR 0013 Increment 3: a `kind` discriminator on the `response` table; **§7** adds a metadata-only `connection_event` log for pre-ingress listener failures | Accepted (2026-06-19) |
| [0022](0022-fhir-resource-codec-rest-client.md) | FHIR resource codec (pure `parsing/fhir/`, two-tier `FhirPeek`/`FhirResource` over `fhir.resources`+`fhirpathpy`) + FHIR REST **destination** — outbound client only; inbound server facade gated on a future ADR 0023 | Accepted (2026-06-19) |
| 0023 | Inbound HTTP listener (+ FHIR server facade) — **reserved** (#7); not yet authored | **Reserved** |
| [0024](0024-smart-backend-services-token-provider.md) | SMART Backend Services token provider — OAuth2 `client_credentials` + signed-JWT client assertion (`RS384`/`ES384`) for the FHIR/REST outbound; extends the ADR 0018 signer, injects a short-lived bearer per request. Client-only (App Launch + authZ-server out of lane) | Accepted (2026-06-20) |
| [0025](0025-dicom-codec-store-connectors.md) | DICOM codec + C-STORE store connectors — pure `parsing/dicom/` codec (`pydicom`; two-tier `DicomPeek`/`DicomDataset` + SR→HL7 helpers), `content_type=dicom` over payload-agnostic ingress, inbound C-STORE SCP source; Phase-2 SCU/C-ECHO/DICOMweb STOW-RS destinations. Code-first SR→HL7 Handler (binary carriage via ADR 0028, not latin-1) | Accepted (2026-06-20) |
| [0026](0026-off-box-egress-update-check.md) | Off-box egress posture for the MEFOR version update-check (#30): a no-network "pinned-vs-current lock diff" as the default + only MVP build (zero egress); a future live-egress check defined as a constrained, off-by-default, env-clamped, https-only/no-redirect/host-allowlisted, advisory-only opt-in (not built); the auto dep-vuln-scan half dropped (§G) | Accepted (2026-06-19) |
| 0027 | Per-connection retention — **reserved** (#34); not yet authored | **Reserved** |
| [0028](0028-base64-binary-carriage-codec.md) | base64 binary-carriage codec (+ HL7 OBX-5 ED embedding) — carry arbitrary bytes over the str/TEXT ingress+store as `mfb64:v1:` unbroken base64; pure stdlib `parsing/binary.py` + `RawMessage.from_bytes`/`.raw_bytes`. Supersedes ADR 0025's latin-1 round-trip (NUL-unsafe across the store) | Accepted (2026-06-20) |
| 0029 | Email/SMTP destination — **reserved** (#23); not yet authored (was earmarked 0024 before SMART claimed it) | **Reserved** |
| [0030](0030-anonymization-test-harness-tee.md) | Anonymizer / de-identification for the test harness + tee (`messagefoundry.anon`) — build PHI-free test datasets from real traffic; pure-stdlib surrogate pools/encoders (lifted from `generators/_hl7data.py`); tee + harness hooks | Accepted (2026-06-20) |
| [0031](0031-startup-connection-fault-isolation.md) | Startup connection fault isolation — a single connection that fails to build/bind at startup is isolated (logged + alerted + reported `failed`), not fatal: the engine starts the rest of the graph and serves the API; a failed outbound retries (never drops) and self-heals on reload/restart. Reload stays fail-fast | Accepted (2026-06-21) |
| [0032](0032-console-desktop-launch.md) | Console desktop launch — a windowed `gui-script` (`messagefoundry-console`) + window/taskbar icon + Desktop/Start-Menu shortcut installer (Phase A, built); a frozen zero-Python installer deferred (Phase B, BACKLOG #39) | Accepted (2026-06-20) |
