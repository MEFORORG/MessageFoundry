# ADR 0003 — Non-HL7 transports: database, REST, and SOAP connectors

- **Status:** Accepted (2026-06-12) — ratified on the owner's go. **Destinations-first** (§1–§2, §4) is
  built starting now (REST destination first). The non-HL7 **source** direction is **decided:
  payload-agnostic ingress** (§5 option B) — but its detailed design (the ingress `content_type` +
  router/store changes) is a **follow-up ADR** before any non-HL7 source is built, so §3 stays
  forward-looking. **First database backend: SQL Server** (reuses the store's existing `aioodbc` path —
  no new driver). (Proposed → Accepted same day.)
- **Built:** Nothing yet. The extension *point* it uses is already built and is explicitly meant for
  this: the connector **registry** (`register_source` / `register_destination` keyed by
  `ConnectorType`, [transports/base.py](../../messagefoundry/transports/base.py)) and the
  transport-agnostic `Source`/`Destination` models ([config/models.py](../../messagefoundry/config/models.py),
  whose docstring says adding a transport "never requires touching this file"; the enum already carries
  the placeholder comment `# Phase 2+: TCP, DATABASE, REST, FHIR`).
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline these feed:
  sources → ingress, destinations ← outbound), [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)
  (TLS/egress posture these inherit), the Corepoint-migration estate (185 MLLP but also database, REST,
  SOAP, FTP endpoints — the real driver), [CONNECTIONS.md](../CONNECTIONS.md), and the existing
  `[egress]` allowlist (WP-11c) + `env()` value layer these reuse for hosts and secrets.

## Context

MessageFoundry ships two transports — MLLP and File. Its reason to exist is to be a code-first
alternative to Mirth/Corepoint that can take on a **real** integration estate, and that estate is not
all HL7-over-MLLP: it has **databases** (read a result set, or write rows / call a stored procedure),
**REST** services (POST/GET JSON or XML), and **SOAP** services (WS-* envelopes). Until those
connectors exist, the migration can't proceed past the MLLP slice.

The architecture is ready for this by construction — the registry resolves connectors by
`ConnectorType` so `pipeline/` never special-cases a transport, and the contract is small:

- **`SourceConnector`** — `start(handler)` begins delivering received messages to `handler` in the
  background and returns once live; `stop()` shuts it down. `InboundHandler = (bytes) -> Awaitable[str
  | None]`.
- **`DestinationConnector`** — `send(payload: str)` delivers one already-transformed payload or raises
  `DeliveryError` (transient → retry) / `NegativeAckError` (partner rejected; permanent → dead-letter);
  `aclose()` releases resources.

The **File source is the working template** for a polling connector
([transports/file.py](../../messagefoundry/transports/file.py)): a background `_run` loop driven by an
interval, cooperatively cancellable via an `asyncio.Event`, scan errors logged-not-fatal (a bad poll
never kills the listener), "process then mark done" giving **at-least-once** (a crash before the mark
re-emits — acceptable and already how File behaves), and blocking work pushed off the loop with
`asyncio.to_thread`.

**The one hard question — payload type.** Destinations are easy: the Handler already produced the
outbound `payload` string, so a destination just delivers it (DB write, HTTP POST, SOAP call) and maps
the result onto `DeliveryError`/`NegativeAckError`. **Sources are not:** the ingress hot path is
HL7-centric — the listener decodes/parses/(optionally strict-)validates as HL7, the router *peeks*
HL7 fields ([parsing/peek.py](../../messagefoundry/parsing/peek.py)) to route, and the store derives
`summary` / `control_id` / `message_type` from HL7. A database row or a JSON webhook body is **not
HL7**, so a non-HL7 *source* either has to (a) emit an HL7 envelope, or (b) make the ingress path
**payload-agnostic**. That decision is bigger than one connector and is the heart of this ADR.

## Decision (proposed)

### 1. Three new registry connectors, zero pipeline/model changes

Add `ConnectorType.DATABASE`, `.REST`, `.SOAP` and register each in `transports/` exactly like MLLP and
File. Per-connection config rides the existing free-form `settings` dict via new `Database(...)` /
`Rest(...)` / `Soap(...)` factories in [config/wiring.py](../../messagefoundry/config/wiring.py)
(siblings of `MLLP(...)` / `File(...)`). No change to `config/models.py`, `pipeline/`, or the store
schema for destinations. **Secrets** (DB password, bearer token, client-cert passphrase) come only from
the environment via the `env()` value layer / `MEFOR_*` — never the TOML or a config module.

### 2. Destinations first (the clean half) — build order REST → DATABASE → SOAP

Destinations compose with everything already built (retry policy, `NegativeAckError` fail-fast,
`InternalErrorPolicy`, the per-outbound FIFO worker, the `[egress]` allowlist):

- **REST destination** (first — simplest, validates the pattern): `send(payload)` issues an HTTP
  request to a configured URL with a method + headers + auth. **5xx / timeout / connection error →
  `DeliveryError`** (retry); **4xx → permanent** (raise a `NegativeAckError`-style permanent failure so
  it dead-letters instead of retrying forever). Reuses the WP-11c egress posture — extend `[egress]`
  with an HTTP host allowlist; no redirects (the WP-7a webhook hardening pattern); TLS verify on, the
  `insecure_tls_allowed()` escape hatch for dev.
- **DATABASE destination**: `send(payload)` runs a **parameterized** statement or stored procedure
  (never string-built SQL) against a pooled connection; the payload→parameters mapping is operator-
  declared in `settings`. Transient DB errors (deadlock, connection drop, timeout) → `DeliveryError`;
  a constraint/permanent error → dead-letter. Idempotency is the **receiver's** responsibility (the
  engine's at-least-once invariant already requires idempotent destinations — `MERGE`/upsert or a
  natural key).
- **SOAP destination**: a thin layer over the REST/HTTP client — build the envelope (+ optional
  WS-Security per the [Secure Development Standards](../Secure_Development_Standards.md)), POST it, map SOAP `Fault` → permanent vs the
  transport error → retry.

### 3. Sources second — gated on the payload-agnostic decision (§5)

A **DATABASE source** is the File-source pattern with a query instead of a directory: poll on an
interval, `SELECT` a claimed batch, hand each row to the handler, then **mark it processed** — via a
status-column `UPDATE`, a monotonic **high-water-mark** cursor, or a delete — in the File "process then
mark" shape, at-least-once. It is cooperatively cancellable and scan-errors-non-fatal, reusing the File
`_run`/`stop` structure; the blocking driver call goes through `asyncio.to_thread` unless an async
driver is used. A **REST/webhook source** is the open sub-question (poll a GET, or *receive* an inbound
HTTP request — the latter needs a listener the connector owns, since `transports/` must not import
`api/`). Both are deferred behind §5.

### 4. Dependencies as optional extras, verified before adding

Each backend's driver is an **optional extra** mirroring `messagefoundry[sqlserver]`
([store/sqlserver.py](../../messagefoundry/store/sqlserver.py) + the `aioodbc` precedent): e.g.
`[postgres]` → `asyncpg`, `[mysql]` → an async driver, ODBC reusing the existing `aioodbc`. The
**first DB backend is SQL Server** (owner-chosen) — it reuses the store's existing `aioodbc` + Microsoft
ODBC Driver 18, so the first DATABASE connector adds **no new driver dependency**; Postgres/MySQL extras
follow as the estate needs them. For HTTP,
**prefer the stdlib** (`urllib` in `asyncio.to_thread`, as the alert webhook already does) to avoid a
new core dependency, with `httpx` considered only if the stdlib proves limiting. Every dependency is
**verified to exist + reputable, added to `pyproject.toml`, and re-locked** (`uv lock`/`uv export`) —
no ad-hoc installs. The base package stays driverless; SQLite-only installs are unaffected.

### 5. The architectural fork to resolve — HL7-only vs payload-agnostic ingress

Two ways to let a non-HL7 **source** exist:

- **(A) Source emits HL7.** The DB/REST source maps its input to an HL7 message *inside the connector*
  (or a bound mapping), so the pipeline stays purely HL7 and nothing downstream changes. Cheapest, but
  forces every non-HL7 source into HL7 shape (awkward for genuinely non-clinical data) and puts mapping
  logic in the connector instead of code-first Handlers.
- **(B) Payload-agnostic ingress.** Tag a message's `content_type` (e.g. `hl7v2` | `json` | `xml` |
  `raw`); the ingress peek/parse/validate and the HL7-derived `summary`/`control_id` apply **only** to
  `hl7v2`; for others the Router (code-first — it can branch on raw bytes) routes without an HL7 peek,
  and the store records a generic summary. More work and a genuine widening of the engine's identity
  (it stops being HL7-only), but it matches "code-first mapping in Handlers" and serves a real-world
  estate honestly.

**Decided (owner, 2026-06-12): (B) payload-agnostic ingress.** The engine will tag each message a
`content_type` and apply HL7 peek/parse/validate + the HL7-derived `summary`/`control_id` **only** to
`hl7v2`; other types route via the code-first Router on raw bytes and get a generic summary.
Destinations (§2) ship now and need no ingress change; the **detailed (B) design** — the
ingress/store/router changes and how `summary` is derived for non-HL7 — is a **follow-up ADR** before
the first non-HL7 *source*. The database connector is the **worked example**: its destination ships in
§2; its source is built once the (B) design ADR lands.

## Options considered

1. **Extend the registry, destinations-first (CHOSEN).** *Pros:* uses the built extension point; reuses
   retry/NAK/egress/`env()`; unblocks outbound migration now; defers the hard question without blocking
   value. *Cons:* sources lag; two-phase delivery.
2. **Build sources and destinations together per transport.** *Pros:* a transport is "done" in one go.
   *Cons:* forces the payload-agnostic decision (§5) up front for marginal early value — most first-wave
   migration needs are outbound; couples a big architectural choice to a connector build.
3. **A generic "script/exec" connector instead of typed DB/REST/SOAP.** *Pros:* one connector, infinite
   flexibility. *Cons:* pushes transport concerns (pooling, retry classification, TLS, secrets) into
   user code, loses the typed config + egress allowlisting, and invites unsafe patterns (string SQL,
   unbounded shell). → Rejected; typed connectors keep the safety rails.
4. **Adopt an external integration library (e.g. an ESB/HTTP framework) per transport.** *Cons:* heavy
   dependencies against the on-prem, minimal-dep, single-binary posture. → Rejected; thin connectors on
   stdlib/optional-extras instead.

## Consequences

**Positive**
- Unblocks the real Corepoint migration's non-MLLP connections (the actual product goal).
- Each connector is small and isolated behind the registry — buildable/reviewable one PR at a time, no
  `pipeline/` risk; SQLite-only installs keep a driverless base.
- Reuses the whole reliability stack (retry, FIFO, `NegativeAckError`, `[egress]`, `env()` secrets) —
  destinations inherit at-least-once + dead-lettering for free.

**Negative / risks**
- **Payload-agnostic ingress (§5)** is now decided (B), but its detailed design is a follow-up ADR —
  non-HL7 *sources* wait on that design, not on the decision.
- **New dependencies** (DB drivers, maybe an HTTP client) — supply-chain + lock surface; mitigated by
  optional extras + the verify-then-add rule.
- **Idempotency burden moves to operators** for DB/REST destinations (at-least-once means a retry can
  re-POST / re-execute) — must be documented loudly per connector.
- **Connection pooling + secret lifecycle** are new operational surface (pool sizing, credential
  rotation) the connectors must handle cleanly via `aclose()`.

## To resolve on acceptance

1. **§5 fork** — ✅ **resolved (owner): payload-agnostic ingress (B).** Destinations ship now; the (B)
   ingress design (`content_type`, router/store changes) is a follow-up ADR before any non-HL7 source.
2. **First DB backend** — ✅ **resolved (owner): SQL Server**, reusing the store's existing `aioodbc` +
   ODBC Driver 18 (no new driver dep). Postgres/MySQL extras later.
3. **HTTP client** — stdlib-`urllib`-in-a-thread vs adopt `httpx`. (Lean: stdlib first.)
4. **REST/webhook source shape** — polling GET vs an inbound HTTP listener the connector owns (and how
   that listener stays out of `api/`).
5. **Build order** — proposed REST dest → DATABASE dest → SOAP dest, then (post-(B)) DATABASE source.

---

*On acceptance: build one connector per branch/PR with the standard quartet gate, starting with the
REST destination; document each connector's config schema + an example + its idempotency contract in
[CONNECTIONS.md](../CONNECTIONS.md); extend `[egress]` for HTTP/DB hosts; add ConnectorType values +
`env()`-resolved secrets. Update CLAUDE.md's transport list only as code ships.*
