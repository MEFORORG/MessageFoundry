# ADR 0022 — FHIR resource codec + REST client

- **Status:** **Accepted (2026-06-19)** — ratified on the owner's go. Design-only (no code yet); the Lane B
  `fhir-codec` **build may start once `ci-py311-finalizer` (#17) has also merged** (the build start-gate is *ADR
  0022 Accepted AND #17 merged*). The "To resolve on acceptance" confirmations are ratified at their recommended
  positions — see **Resolved** below.
- **Resolved (2026-06-19, on the owner's go):** `fhir_version` defaults to **`"R4B"`** (no plain-R4 on
  pydantic-v2; `"R5"`/`"STU3"` opt-in); the endpoint settings key is **`"url"`** (so the §3.4 egress gate and the
  FhirDestination read one key); **JSON-FHIR is the MVP path and FHIR-XML is deferred** to a hardened-`lxml`
  follow-up (never bare-parsed); the **three conditional knobs** (`if-none-exist` / `conditional-update` /
  `if-match`) ship in the MVP, opt-in/off-by-default; and the `OperationOutcome` severity/code →
  permanent/transient mapping is adopted (`fatal`/`error` → permanent; the FHIR `transient` IssueType group →
  retry; `success`/`information`/`warning` → non-failing; HTTP status wins when in doubt, 5xx stays transient).
  The build still re-runs the verify-then-add dependency discipline and **pins exact versions at build time**
  ([CLAUDE.md](../../CLAUDE.md) §5/§7).
- **Built (this ADR):** nothing. It layers FHIR semantics over **already-shipped** substrate:
  - the payload-agnostic ingress ([ADR 0004](0004-payload-agnostic-ingress.md)): `_handle_inbound`'s
    **non-HL7 branch** ([wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py)) already decodes a
    non-HL7 body verbatim, commits it to the ingress stage as `message_type = ic.content_type.value`, and hands
    the Router/Handler a **`RawMessage`** (`.raw`/`.text`/`.json()`/`.encode()` —
    [parsing/message.py](../../messagefoundry/parsing/message.py)). FHIR inherits ingress/routing/finalizer
    behaviour **for free** once `ContentType.FHIR` exists.
  - the REST destination it leans on, which is **already shipped and stdlib-only** (`urllib`, ADR 0003): the
    HTTP plumbing, TLS posture, redirect refusal, retry classification, and the egress host gate already exist in
    [transports/rest.py](../../messagefoundry/transports/rest.py) and
    [pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py). This ADR **reuses rest.py's
    shared helpers** — it does **not** re-implement HTTP.
- **Decision in one line:** ship FHIR as **two decoupled pieces** — a pure, console-importable `parsing/fhir/`
  codec (a two-tier `FhirPeek`/`FhirResource`, backed by the optional `fhir.resources` + `fhirpathpy` libraries,
  referenced by the literal string `"fhir"`, imported on demand by code-first Routers/Handlers against a
  `RawMessage`) **plus** a `transports/fhir.py` FHIR REST **destination** that **reuses `transports/rest.py`'s
  shared helpers** (adding FHIR media types, create/update/Bundle interactions, and `OperationOutcome`
  classification) under a **new additive** `ConnectorType.FHIR` that folds into the existing `allowed_http` egress
  branch — and **explicitly excludes** the inbound FHIR server facade, which is gated on a separate **ADR 0023**.
  It is the direct FHIR mirror of how X12 shipped ([ADR 0012](0012-x12-edi-codec.md)).
- **Related:** [ADR 0004](0004-payload-agnostic-ingress.md) (the `content_type` ingress path this rides;
  `RawMessage`), [ADR 0012](0012-x12-edi-codec.md) (the pure `parsing/x12/` codec pattern + the optional-extra
  dependency rule this mirrors), [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (the REST destination
  this builds on + the non-HL7 transport registry / optional-extra posture),
  [ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md) (the HTTP-egress hardening, per-connection cert opener, and
  value-placement contract a FHIR HTTP destination inherits), [ADR 0016](0016-synchronous-x12-request-response.md)
  (synchronous request/response via capture→re-ingress — the `OperationOutcome`-as-content model),
  [ADR 0013](0013-query-response-orchestration.md) (the capture / immutable `response` artifact / `Loopback()`
  re-ingress machinery the response path reuses), [ADR 0001](0001-staged-pipeline-architecture.md) (the staged
  queue + at-least-once invariant FHIR feeds), [CLAUDE.md](../../CLAUDE.md) §1/§4/§8/§9
  (no-grouping-unit graph, code-first logic, the pure `parsing/` library + console carve-out, two-tier parsing,
  PHI rules), [CONNECTIONS.md](../CONNECTIONS.md), and the research that vetted the dependency picks,
  [docs/research/non-hl7-transform-components.md](../research/non-hl7-transform-components.md).

## Context

The migration estate is not all HL7-over-MLLP. **FHIR** (Fast Healthcare Interoperability Resources) — `Patient`,
`Observation`, `Bundle`, `MessageHeader`, `DiagnosticReport`, etc., as JSON or XML over REST — is the modern
interoperability lane every competing engine (Mirth, Corepoint, Rhapsody) now ships, and MessageFoundry has **no
FHIR support today** (the `ConnectorType` comment at [config/models.py](../../messagefoundry/config/models.py)
already flags "TCP/**FHIR are future**"; [FEATURE-MAP.md](../FEATURE-MAP.md) lists FHIR as a Tier-1 planned
lane and notes "SMART on FHIR … needs a FHIR transport first (none today)").

The *ingress contract* for "not HL7" already exists ([ADR 0004](0004-payload-agnostic-ingress.md)): a
non-`hl7v2` inbound skips the HL7 peek/validate/ACK, commits the body verbatim, and the Router/Handler receive a
generic **`RawMessage`** whose `.json()` is directly usable for a FHIR JSON body. So — exactly as with X12 — the
*ingress wiring is essentially done*; what is missing is **(a)** a way to *parse/route/transform* FHIR from a
code-first Router/Handler, and **(b)** a *transport* that can speak FHIR REST to a downstream server.

Two further facts shape the design and make it a near-clone of [ADR 0012](0012-x12-edi-codec.md):

- **FHIR is self-describing JSON/XML.** Unlike X12 (whose four delimiters are partner-variable and must be
  *discovered* from a fixed-offset ISA header before any tokenizing), FHIR structure is intrinsic to the
  serialization — a standard JSON/XML parser already knows the boundaries. So the FHIR codec **drops X12's entire
  `delimiters.py`/`interchange.py` framing apparatus**: there is no delimiter discovery and no bespoke stream
  reassembler, because FHIR rides standard transports (an HTTP body, a file) whose framing the transport already
  owns.
- **A real, vetted library exists.** X12's MVP was hand-rolled and dependency-free because X12 tokenization is
  trivial once delimiters are known; FHIR's resource model is large and version-specific, so a **typed library is
  the right call** — and unlike X12, one was already verified. Project research
  ([docs/research/non-hl7-transform-components.md](../research/non-hl7-transform-components.md), the FHIR section
  and the verification snapshot) ran the CLAUDE.md §5 "verify-before-add" gate (PyPI existence to catch
  hallucinated/typosquat packages, license, maintenance, 3.11+ support, dependency weight, offline/PHI-safety) and
  selected **`fhir.resources`** (BSD-3, pydantic-v2 via the transitive `fhir-core`, **local schema validation with
  zero terminology-server calls** → offline + PHI-safe) for the typed model and **`fhirpathpy`** (MIT, the standard
  FHIRPath evaluator, works directly on a dict) for field extraction. The research **explicitly caught the
  typosquat trap**: the near-namesake **`fhirpath`** (nazrulworld) is **GPLv3 per its PyPI classifier** (its repo
  now lists Apache-2.0 — treat the copyleft PyPI metadata as the binding signal) and is a **heavyweight,
  storage-abstract** engine (zope.interface/fhirspec, with Elasticsearch as an *optional* provider, not a hard
  dependency) — the **wrong tool** here vs the lightweight, MIT, dict-native `fhirpathpy`; it is named so it is
  never picked by mistake. A GPLv3 dependency would also poison the AGPL bundle's licensing posture.

The same two project constraints that shaped X12 apply verbatim:

- **No grouping unit / code-first logic** ([CLAUDE.md](../../CLAUDE.md) §1/§4). FHIR logic (which resource /
  Bundle entry goes where, how an HL7 v2 message maps to a FHIR resource) belongs in **code-first
  Routers/Handlers**, not a new declarative FHIR surface or a bespoke object pushed through the engine.
- **Payload-agnostic, hot-path-cheap** ([CLAUDE.md](../../CLAUDE.md) §8). Routing must not force a full validated
  parse; the FHIR analog of "read the separators from MSH" is a **shallow read of `resourceType`/`meta.profile`/
  the Bundle entry resource-type list** — no pydantic model construction on the hot path.

## Decision (proposed)

FHIR ships as **two decoupled pieces** wired through existing seams, exactly mirroring X12 ([ADR 0012](0012-x12-edi-codec.md)).
Edits to the engine hotspots are **additive only**; **no routing-logic** in
`pipeline/wiring_runner.py` (`_handle_inbound`, `route_only`, `transform_one`) or `pipeline/dryrun.py`
(`_payload`) is touched. (One **additive, `ConnectorType`-keyed** egress branch in `wiring_runner.py` is required
for security parity — §3.4; it is the same kind of branch X12 added, not pipeline logic.) Nothing FHIR-typed is
added to the `Payload` union (`Message | RawMessage`); nothing in `pipeline/` learns FHIR.

### 1. A pure, console-importable codec at `parsing/fhir/` (NOT pushed through the pipeline)

A new package mirroring [parsing/x12/](../../messagefoundry/parsing/x12) — **pure, side-effect-free, zero I/O,
zero engine imports** (so the console may import it for client-side rendering — the §4 carve-out). Every module
carries the `# SPDX-License-Identifier: AGPL-3.0-or-later` header and `from __future__ import annotations`.
**It must import nothing from `messagefoundry.config`, `pipeline`, `store`, or `transports`** — internal imports
are sibling-only — and it refers to the FHIR content type by the **literal string `"fhir"`** (never
`ContentType.FHIR`), so a console import of `parsing.fhir` pulls in no engine. Two purity tests guard this
(§5).

It is **two-tier**, mirroring the project's python-hl7(tolerant)/hl7apy(strict) split and X12's
`X12Peek`/`X12Message`:

- **`FhirPeek`** — the **tolerant routing peek** (the hot-path analog of HL7 `Peek` / `X12Peek`). A frozen
  dataclass with a `FhirPeek.parse(raw, *, format=None) -> FhirPeek` classmethod taking `str | bytes`. It does a
  **cheap, shallow read** of routing-relevant fields **without constructing the validated model** — directly off
  the parsed dict (for JSON) or a shallow XML read:
  - `resource_type: str | None` (the top-level `resourceType` discriminator — the FHIR analog of MSH-9);
  - `id: str | None`;
  - `profiles: tuple[str, ...]` (`meta.profile[]` — the conformance profiles a Router most often branches on,
    e.g. a US Core profile URL);
  - for a `Bundle`: `bundle_type: str | None` (`Bundle.type` — `transaction`/`batch`/`message`/`searchset`/…) and
    **`entry_resource_types() -> list[str]`** (the `entry[].resource.resourceType` **list** — see §6: a Bundle
    fans out, so this returns the full list, never just the first). It **skips entries with no inline
    `entry.resource`** (a transaction/batch entry may carry only `request.method`+`request.url` — e.g. a
    conditional `DELETE` — so a missing `.resource` is tolerated, never a `KeyError`); for routing such request-
    only entries it may also expose **`entry_requests() -> list[tuple[str, str]]`** (the
    `entry[].request.method`/`url` pairs).
  - Optionally **`evaluate(path: str) -> list`** — a FHIRPath extraction against the raw dict via `fhirpathpy`,
    for richer routing (e.g. `Bundle.entry.resource.ofType(MessageHeader).event.code`) without typed
    instantiation. This is the cheap, idiomatic field-path tier the research prescribed. (`evaluate` pulls
    `fhirpathpy` from the `[fhir]` extra and raises a clear, actionable error if the extra is absent; the bare
    structural accessors above need no extra.)
  - Raises **`FhirPeekError`** on unparseable/non-FHIR input.
  The peek is **version-agnostic** — `resourceType`/`meta.profile`/`Bundle.type`/`entry` are structurally stable
  across R5/R4B/STU3, so routing needs no version selection (full model construction does — see below).
- **`FhirResource`** — the **full, validated model** for transforms (the strict/slow path, the HL7 `Message` /
  `X12Message` analog), backed by `fhir.resources` (pydantic-v2 base model carried by the transitive `fhir-core`).
  `FhirResource.parse(raw, *, version="R4B", format="json") -> FhirResource` constructs and **validates** the
  typed resource (raising on non-conformant structure/cardinality — local pydantic schema work, **zero
  terminology-server calls**, offline-safe); read/set elements (by attribute or FHIRPath); `encode(format="json")
  -> str` re-serializes to JSON. **XML re-serialization is experimental and optional** — it rides `fhir.resources`'
  `lxml` extra and is gated/deferred per Options #5, never bare-parsed on untrusted input. This is **not** the hot
  path — it is constructed on demand inside a Handler. `fhir.resources` is the only import that pulls the optional
  `[fhir]` extra; `FhirResource.parse` raises a clear, actionable error if the extra is not installed (mirroring
  how the SQL-Server/Postgres connectors fail when their driver extra is absent).
- **`FhirError(ValueError)`** base → **`FhirPeekError(FhirError)`** (the `X12PeekError` analog). Deriving from
  `ValueError` means a Router/Handler already routing `ValueError` to the dead-letter path catches malformed/
  non-FHIR bodies **without special-casing** — the count-and-log invariant (never accept-and-drop) holds for
  free. **PHI rule (do not break):** `FhirError`/`FhirPeekError` messages — and *any* codec/transport log line —
  carry only **routing-safe identifiers** (`resourceType`, resource `id`, an `OperationOutcome` `issue.code`/
  `severity`), **never the FHIR resource body**; the full PHI-bearing body goes only to the secured store, the
  same way `rest.py` logs `_redact_url(...)` not the URL/body (§9 / [CLAUDE.md](../../CLAUDE.md) §9 — never log a
  full payload at INFO or above; never raise the service to DEBUG in prod).

**R5 vs R4B vs STU3.** `fhir.resources` ships **R5 (5.0.0) as the default/root import**
(`from fhir.resources.patient import Patient`), with **R4B (4.3.0)** under `fhir.resources.R4B.*` and **STU3
(3.0.2)** under `fhir.resources.STU3.*`; modern (pydantic-v2) wheels **no longer ship a plain R4 (4.0.1)
sub-package** — it was dropped in `fhir.resources` 7.0.0, and pydantic-v2 support did not arrive until 7.1.0, so
"pydantic-v2 + plain-R4" cannot co-exist on one wheel (true 4.0.1 fidelity only exists on the pydantic-V1
`<=6.5.0` line, which contradicts this ADR's pydantic-v2 choice). The version is an **explicit per-connection
choice** (a `fhir_version` setting, default **`"R4B"`** — the closest the library offers to the still-dominant
deployed R4, and the maintainer's recommended R4 replacement; `"R5"`/`"STU3"` opt-in), directly analogous to
CLAUDE.md §8's "be explicit about HL7 version for strict inbound connections; don't rely on silent
autodetection." The **routing peek does not need the version** (structural fields are stable); only
`FhirResource.parse` does, and it takes `version` from the resolved connection setting (or an explicit Handler
argument).

Routers/Handlers call this library **on demand** against `RawMessage.json()`/`.raw` (`FhirPeek` to route,
`FhirResource` to transform). **Nothing FHIR-typed is added to the `Payload` union**, and **nothing in
`pipeline/` is taught about FHIR**. HL7 v2 ↔ FHIR **mapping stays in code-first Handlers** — python-hl7 `Message`
in → `fhir.resources` resource out, hand-authored (no pure-Python v2↔FHIR converter exists; see Out of scope) —
**never** in the connector/codec.

### 2. A FHIR REST **destination** at `transports/fhir.py` that REUSES `transports/rest.py`'s helpers

`FhirDestination` is its own **`DestinationConnector` subclass** ([transports/base.py](../../messagefoundry/transports/base.py))
that **reuses the shared module-level helpers** in [transports/rest.py](../../messagefoundry/transports/rest.py) —
**exactly as the SOAP destination does**. `SoapDestination` ([transports/soap.py](../../messagefoundry/transports/soap.py))
is *not* a wrapper of `RestDestination`; it is a sibling `DestinationConnector` that imports rest.py's
`_NO_REDIRECT_OPENER`/`_NoRedirectHandler`, `_insecure_opener`, `_redact_url`, `enforce_outbound_length_limits`,
`refuse_cleartext_credentials`, plus `signer_from_destination` — and follows rest.py's status→retry idiom.
`FhirDestination` does the **same**: it **does not compose or instantiate `RestDestination`**, and it does
**not** re-implement HTTP. It implements the `DestinationConnector` contract: one `async def send(self, payload:
str) -> DeliveryResponse | None`, optional `aclose`/`test_connection` overrides, and it raises **only**
`DeliveryError`/`NegativeAckError` from the delivery path (any other exception escaping `send` is treated by the
`RegistryRunner` as an internal code error).

**Reused verbatim from `rest.py` (do not reinvent) — the same helpers SOAP reuses:**
- The TLS posture: the no-redirect, TLS-verifying opener (`_NO_REDIRECT_OPENER`/`_NoRedirectHandler` — a 3xx is
  raised, never followed: the PHI-redirect defense, ASVS 15.3.2) and the `verify_tls=False` escape gated by
  `MEFOR_ALLOW_INSECURE_TLS` (`insecure_tls_allowed()`), plus the cleartext-credential refusal.
- `enforce_outbound_length_limits`, `refuse_cleartext_credentials`, `_redact_url`, and the optional JWS signer
  hook (`signer_from_destination`, ADR 0018) for signed bodies.
- The retry classification **idiom** from rest.py's `_post`: **2xx → delivered**; status in `_RETRYABLE_4XX =
  {408, 429}` **or** `5xx` → `DeliveryError` (transient → pipeline retries with backoff); **any other 4xx** (and a
  refused 3xx) → `NegativeAckError(code=str(status), permanent=True)` → dead-letter immediately; DNS/conn/TLS/
  timeout → `DeliveryError`. (FhirDestination reuses the idiom — the constants and helper shape — not the
  `RestDestination` instance.)
- The egress host allowlist — **not** re-implemented in `fhir.py`; the runner owns it (§3.4). The connector trusts
  that wiring already vetted the URL.

**Added (FHIR-specific, on top of REST) — the net-new logic:**
1. **FHIR media types.** Default `Content-Type`/`Accept` = **`application/fhir+json`** (and
   `application/fhir+xml` when `format="xml"`), overriding REST's generic `application/json` default. (The media
   type is set on *both* `Content-Type` and `Accept` per the FHIR HTTP spec.)
2. **FHIR REST interactions** (REST hardcodes a single `url` + `method`; FHIR derives method + path from the
   resource/interaction). The configured `url` setting is the **FHIR service base URL** (e.g.
   `https://host/fhir`); each interaction appends to it:
   - **create** — `POST {base}/{ResourceType}` (the server assigns the id);
   - **update** — `PUT {base}/{ResourceType}/{id}` (the resource carries its id);
   - **Bundle transaction/batch** — `POST {base}` with a `Bundle` body (`Bundle.type =
     transaction`/`batch`). The engine *builds/posts* the Bundle; the FHIR **server** applies it (transaction =
     all-or-nothing, batch = independent per entry) — this is a server-side semantic the engine never executes.
   The `ResourceType`/`id` are read from the outgoing body via `FhirPeek` (cheap, no typed parse) when the
   interaction needs them, so the destination derives its method+path without a full model build.
3. **Conditional interactions — three distinct, spec-correct knobs (CHOSEN: supported, header/URL-driven,
   opt-in/off-by-default).** These are the FHIR-native idempotency/concurrency primitives and the **direct answer
   to the at-least-once duplicate problem** (every HTTP destination in [CONNECTIONS.md](../CONNECTIONS.md)
   documents "a retry re-sends — the receiver must be idempotent"). The FHIR HTTP spec defines **three separate
   interactions** (do not conflate them — cite
   [hl7.org/fhir/http.html#cond-update](https://www.hl7.org/fhir/http.html#cond-update) and `#concurrency`):
   - **`"if-none-exist"` — conditional create.** URL **unchanged** from a plain create (`POST {base}/{ResourceType}`);
     the search criteria live **only** in the `If-None-Exist: <search-params>` **header** (create only if no
     existing resource matches the search). The criteria do **not** go in the URL.
   - **`"conditional-update"` — search-based update.** `PUT {base}/{ResourceType}?<search-params>` — the **search
     query is in the URL**, not an id; the **server resolves** which resource to update (the update-side mirror of
     `If-None-Exist`).
   - **`"if-match"` — version-aware update / optimistic locking.** `PUT {base}/{ResourceType}/{id}` (a **known**
     id) with `If-Match: W/"<versionId>"` (the ETag) to prevent a lost update. This is **not** "conditional
     update" — it locks an already-identified resource.
   They are **HTTP header / URL** mechanisms, so they ride the existing REST header/URL path. Per the ADR 0015
   **value-placement contract**, any per-call non-deterministic header value (a fresh idempotency token) is minted
   in the transport's `send()` (which runs *after* the staged-queue boundary), **never** in the pure transform; a
   static or resource-derived criterion comes from config/the body. Conditional support is **in scope** for the
   MVP because it is the load-bearing idempotency lever — but it is **opt-in** (`conditional=None` by default), so
   a partner that does not support conditionals is unaffected.
4. **`OperationOutcome` handling.** A FHIR server returns an `OperationOutcome` (FHIR's structured error/result
   resource — the analog of an HL7 NAK / X12 TA1-reject) on a failure (an HTTP **300+** body, where at least one
   `issue` MUST be `severity = error`) and as the body of validation/transaction-entry responses; a server **MAY
   also** include one in a **2xx** body (e.g. warnings, or when the client sent `Prefer: return=OperationOutcome`)
   — not every 2xx carries one. The destination **refines** REST's pure-HTTP-status classification with
   `OperationOutcome.issue`:
   - On an **error HTTP status**, if the body is an `OperationOutcome`, map `issue.severity`/`issue.code`:
     - `severity` ∈ `{fatal, error}` with a client/structure code → `NegativeAckError(permanent=True)` →
       dead-letter (treat `fatal`, which R5 ranks worse than `error`, like `error`);
     - an `issue.code` in the FHIR **`transient` IssueType group** — its children `lock-error`, `throttled`,
       `timeout`, `incomplete` (cite the
       [issue-type value set](https://www.hl7.org/fhir/valueset-issue-type.html)) → `DeliveryError` → retry. This
       group is hierarchical, so the heuristic is **spec-grounded**, not ad-hoc;
     - `severity` ∈ `{success, information, warning}` is **non-failing** (captured, not an error).
   - **The HTTP status wins when in doubt** (a 5xx stays transient even with an ambiguous outcome), which aligns
     with the spec's "OperationOutcome SHOULD align with the HTTP response code" — refining, never contradicting,
     the 4xx-permanent / 5xx+timeout-transient base.
   - When `capture_response` is on, a returned `OperationOutcome` (or the server's assigned resource / ETag) is a
     **captured response artifact** — `send()` returns a `DeliveryResponse(body=..., outcome=…)` from the closed
     `RESPONSE_OUTCOMES` vocabulary ([transports/base.py](../../messagefoundry/transports/base.py)):
     **`accepted`** (a positive reply / OK resource or success `OperationOutcome`), **`rejected`** (an error
     `OperationOutcome` on an otherwise-OK transport), **`unparseable`** (a reply frame *was* received but its body
     is not parseable FHIR — garbage/HTML error page; **distinct** from "no reply", which is a retryable
     `DeliveryError`), or **`no_reply`** (a deliberately empty 2xx). On a **2xx** the destination treats delivery
     as **succeeded** and only captures the `OperationOutcome` as a response artifact. The artifact is persisted in
     the immutable `response` table and re-ingressed via `reingress_to=` into a `Loopback()` inbound, exactly as
     ADR 0013/0016 do. Per ADR 0016's line between a *transport* signal (TA1) and *content* (999/997): the live
     response (assigned id, ETag, server timestamp, the `OperationOutcome`) is **content for a pure Router/Handler
     to reason about**, read back only from the immutable artifact — **never** produced by or fetched inside a pure
     transform. There is **no new `Stage`, store table, or finalizer**.

The destination is **one-way dependent**: `transports/fhir.py` imports `parsing/fhir/` (for `FhirPeek` to read
the outgoing resource type/id) and `transports/rest.py`'s helpers, **never the reverse** — preserving the
dependency direction and the console carve-out.

### 3. Additive hotspot edits — `ContentType.FHIR`, `ConnectorType.FHIR`, a `FHIR()` factory, exports, the egress branch

The config models are **transport-agnostic by design** ([config/models.py](../../messagefoundry/config/models.py)
states "adding a new transport never requires touching this file" beyond the enum) — so the only `models.py`
edits are two **additive** enum members; FHIR options live in the flat `settings` dict, **no new
`Source`/`Destination` fields**.

3.1. **`ContentType.FHIR = "fhir"`** — a **new, additive** member in
[config/models.py](../../messagefoundry/config/models.py) (after `X12`). A FHIR inbound declares
`inbound("IB_…", FHIR(...), router=…, content_type="fhir")` and rides the existing non-HL7 branch → the stored
`message_type` is literally `"fhir"`, no HL7 parse/peek/ACK, and the Router/Handler see `RawMessage.content_type
== "fhir"` so they can branch. **A dedicated `ContentType.FHIR` (CHOSEN), not a reuse of `JSON`/`XML`** — the X12
precedent (X12 got its own `ContentType` even though it rides raw bytes) and the need for a Handler to branch on a
FHIR-vs-plain-JSON body both favour a distinct tag. (`strict` is HL7-only — a FHIR inbound cannot combine `strict`
with `content_type="fhir"`. **No new guard code is needed:** the **existing** `inbound()` validation in
[config/wiring.py](../../messagefoundry/config/wiring.py) (`if content_type is not ContentType.HL7V2 and strict:`)
already raises `WiringError`. FHIR resources are validated in the Handler via `FhirResource.parse`, not via
`strict`.)

3.2. **`ConnectorType.FHIR = "fhir"`** — a **new, additive** member in
[config/models.py](../../messagefoundry/config/models.py) (after `LOOPBACK`); update the existing "TCP/FHIR are
future" comment to drop FHIR. The registry is one builder per `ConnectorType`
([transports/base.py](../../messagefoundry/transports/base.py)), and FHIR layers FHIR semantics over REST while
needing its **own** factory, default media types, and (crucially) its own egress-gate arm — so a dedicated key is
cohesive (see Options #2 for why not reuse `ConnectorType.REST`). The module ends with
`register_destination(ConnectorType.FHIR, FhirDestination)`. **No `register_source`** — FHIR is **destination-only**
in this ADR (the inbound listener is ADR 0023).

3.3. **`FHIR()` factory** — additive, in [config/wiring.py](../../messagefoundry/config/wiring.py) near `Rest()`,
keyword-only, returning `ConnectionSpec(ConnectorType.FHIR, {…flat dict…})`. It mirrors `Rest()` and reuses
**`Rest()`'s exact settings key for the endpoint — `url`** (so the §3.4 egress gate and the FhirDestination read
the *same* key the runner and `RestDestination` already read), adding the FHIR knobs:

```python
def FHIR(*, url,                               # str | EnvRef — FHIR service BASE url, e.g. https://host/fhir
         fhir_version="R4B",                   # "R4B" (default) | "R5" | "STU3" — explicit, no autodetect.
                                               #   (plain R4 4.0.1 is not in modern fhir.resources; R4B is its replacement)
         format="json",                        # "json" (MVP) | "xml" (experimental, lxml extra) → application/fhir+json | +xml
         interaction="create",                 # "create" (POST) | "update" (PUT) | "transaction"/"batch" (Bundle POST)
         conditional=None,                     # None | "if-none-exist" (cond. create, header)
                                               #      | "conditional-update" (search-based PUT, URL query)
                                               #      | "if-match" (optimistic lock on a known id, ETag header)
         headers=None,                         # dict[str,str] — static, NOT env()-resolved, no secrets
         bearer_token=None,                    # str | EnvRef — Authorization: Bearer … (SMART/OAuth; env() secret)
         basic_user=None, basic_password=None, # str | EnvRef — env() secrets
         timeout_seconds=30.0,
         verify_tls=True,                       # False (dev only) needs MEFOR_ALLOW_INSECURE_TLS
         encoding="utf-8",
         capture_response=False,                # capture the server reply / OperationOutcome (ADR 0013)
         reingress_to=None) -> ConnectionSpec:
    # NOTE: the endpoint is stored under the settings key "url" (NOT "base_url") — the same key
    # Rest() uses, RestDestination's helpers read, and check_egress_allowed() reads (§3.4). The
    # value is a FHIR *base* URL semantically; the key name stays "url" so the egress gate works
    # unchanged. The factory may accept a base_url= alias mapped to settings["url"] for readability.
    return ConnectionSpec(ConnectorType.FHIR, { "url": url, ...every other kwarg, flat... })
```

The auth/TLS/header/timeout/capture knobs are the **same keys** `Rest()` exposes (so SMART-on-FHIR OAuth bearer
tokens flow through the same `env()`-resolved, `_SECRET_SETTING_KEYS`-redacted `bearer_token` path; a
cert-authenticated endpoint can reuse the ADR 0015 per-connection mTLS opener). Add `"FHIR"` to `__all__`
([config/wiring.py](../../messagefoundry/config/wiring.py)) among the other factories, and re-export `FHIR` from
the top-level `messagefoundry` surface so config modules can `from messagefoundry import FHIR`.

3.4. **The fail-closed egress gate — one additive branch (the security-parity edit).** FHIR is HTTP(S), so it
**folds into the existing `allowed_http` REST/SOAP branches** in
[pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py) — **no new helper, no new `[egress]`
list, no `EgressSettings` change**:
- `_allowlist_for` ([wiring_runner.py:1437](../../messagefoundry/pipeline/wiring_runner.py)) — add
  `ConnectorType.FHIR` to the existing `(REST, SOAP)` tuple that returns `egress.allowed_http`, so
  `deny_by_default` correctly refuses an unlisted FHIR destination.
- `check_egress_allowed` ([wiring_runner.py:1634](../../messagefoundry/pipeline/wiring_runner.py)) — add
  `ConnectorType.FHIR` to the existing `(REST, SOAP)` host-check branch. Its body reads `dest.settings.get("url",
  "")`, calls `_http_egress_allowed(url, egress.allowed_http)`, and emits a `dest.type.value`-parameterized warning
  + `WiringError`. **This is exactly why the `FHIR()` factory stores the endpoint under the `"url"` key (§3.3):**
  the gate reads `settings["url"]`, so a `base_url`-keyed value would parse `host=""`, never match the allowlist,
  and (when `allowed_http` is empty) skip this `elif` so the connector receives no `url` and breaks — a
  correctness/security defect. With the `"url"` key it works **unchanged** for FHIR.
  This is the **minimal** mirror of X12's egress branch — but where X12 needed its **own** `allowed_tcp` arm
  (host:port TCP matching), FHIR reuses REST/SOAP's `allowed_http` arm. **This is the load-bearing reason for the
  edit:** a brand-new `ConnectorType` that is *not* added to these arms would **fall through the egress `elif`
  chain → a fail-open hole** for a PHI-bearing destination. `check_source_allowed` needs **no** change — FHIR is
  destination-only.

3.5. **Exports.** Add `fhir` to the import tuple in
[transports/__init__.py](../../messagefoundry/transports/__init__.py) so importing the package registers the FHIR
destination at load (like `rest`/`soap`/`x12`; the class itself needs no `__all__` entry — registration is the
side effect). Re-export the **headline** codec types — `FhirPeek`, `FhirResource`, `FhirPeekError` — from
[parsing/__init__.py](../../messagefoundry/parsing/__init__.py) and add them to its `__all__` (mirroring the X12
block), keeping lower-level internals reachable only under `messagefoundry.parsing.fhir`. **No `RawMessage`
export change** — it is already exported.

### 4. Ingress rides the existing payload-agnostic branch (no engine teaching)

`content_type="fhir"` rides the **existing** non-HL7 branch ([ADR 0004](0004-payload-agnostic-ingress.md)): the
listener commits the decoded body verbatim to the ingress stage (`message_type = "fhir"`), the transform worker
passes `"fhir"` as `RawMessage.content_type`, and the engine stays **format-blind** — no HL7 parsing of a FHIR
body, no FHIR-typed object in the `Payload` union, nothing in `pipeline/` learns FHIR. A FHIR Handler reads
`RawMessage.json()` (FHIR-JSON) and calls the codec on demand. (For inbound *over HTTP*, the listener is ADR 0023;
this ADR's FHIR ingress is the generic non-HL7 path that any source — File, Loopback re-ingress of a captured
response — already feeds.) Malformed/non-FHIR input dead-letters as `ERROR` (fail-loud, the count-and-log
invariant), **carrying only routing-safe identifiers in the log/error — never the body** (§1 PHI rule, §9).

### 5. Purity is enforced by two tests (mirroring X12)

Mirroring [tests/test_x12_parsing.py](../../tests/test_x12_parsing.py)'s "console-carve-out import-purity guard":
1. A **runtime** test — a subprocess that `import messagefoundry.parsing.fhir`, then scans `sys.modules` for any
   `messagefoundry.pipeline`/`store`/`transports`/`api`/`console` module and fails if present. (`config` is
   **excluded** from this runtime scan because the root `messagefoundry/__init__` imports config models
   unconditionally — config is already loaded regardless.)
2. A **static** test that closes the config gap — globs every `*.py` in `parsing/fhir/` and asserts no line
   imports `messagefoundry.config`/`.pipeline`/`.store`/`.transports`/`.api`/`.console`. This is what enforces the
   "literal `"fhir"`, never `ContentType.FHIR`" rule the runtime test cannot.

### 6. Dependencies — the `messagefoundry[fhir]` optional extra (verified, not core)

Per CLAUDE.md §5/§7 (verify a dependency exists / is reputable / correctly named **before** adding; AI-suggested
packages are often hallucinated) — the picks were **already vetted** by
[docs/research/non-hl7-transform-components.md](../research/non-hl7-transform-components.md) (multi-agent research →
adversarial verifiers; both confirmed real on PyPI, permissively licensed, pure-Python/offline, actively
maintained as of 2026-06-19; the GPLv3 `fhirpath` typosquat explicitly caught):

| Package | PyPI name | License | Role / capability |
|---|---|---|---|
| **`fhir.resources`** | `fhir.resources` (**dot**, not dash/underscore — the real distribution name) | BSD-3 | the typed `FhirResource` model. Ships **R5 (default root import), R4B, STU3** (no plain-R4 on pydantic-v2 wheels). **JSON is the stable, first-class format**; **XML/YAML serialization is experimental and rides the optional `lxml` extra** — JSON-only at MVP (Options #5). Local schema validation, **zero terminology-server calls** (offline + PHI-safe). |
| **`fhir-core`** | `fhir-core` | BSD-3 | the pydantic-v2 base-model engine **pulled transitively** by `fhir.resources` (≥7.1.0) — carries the `pydantic>=2` validation core. Named here so the dependency narrative is complete; not listed directly in the extra. |
| **`fhirpathpy`** | `fhirpathpy` (beda-software) | MIT | the FHIRPath evaluator for `FhirPeek.evaluate` against a raw dict. Pure-Python; only runtime deps are `antlr4-python3-runtime` + `python-dateutil` (both common). Min Python 3.10 (< project 3.11 floor — fine). |

They ship as an **optional extra**, never core (mirroring `[sqlserver]`/`[postgres]`/`[sftp]` in
[pyproject.toml](../../pyproject.toml)); the base/SQLite-only install stays driverless. The extra string uses the
PyPI name with the dot. `fhir.resources` drags `fhir-core` + a compiled `pydantic-core` wheel (pydantic itself is
already core), which is precisely why it belongs in an extra:

```toml
# FHIR (R5/R4B/STU3) typed-model + FHIRPath support, lazy-imported (parsing/fhir/). Base installs skip it.
# fhir.resources>=7.1.0 is the floor for pydantic-v2 (it dropped plain-R4 in 7.0.0 and pydantic-v1 in 7.1.0);
# it drags fhir-core (>=1.1.5, BSD-3, the pydantic-v2 base model) + pydantic-core (compiled). fhirpathpy is
# pure-Python + antlr4 runtime + python-dateutil. XML support rides fhir.resources' optional lxml extra (deferred).
fhir = ["fhir.resources>=7.1.0", "fhirpathpy>=2.2.0"]
```

The research recorded **no hard minimum versions** and is emphatic that versions/CVEs are a drift-prone snapshot to
**re-confirm at adoption** — so the floors above are the **library-realism minimums** (`fhir.resources>=7.1.0` is
the first pydantic-v2 line; `fhirpathpy>=2.2.0` ≈ current), to be **pinned exactly at build time** via the
standard `uv lock`/`uv export` flow, not numbers asserted from the snapshot. mypy (strict) third-party silencing:
add `"fhirpathpy.*"` (and `"fhir.*"`/`"fhir_core.*"` **only if** the pinned wheels lack a `py.typed` marker —
`fhir.resources`/`fhir-core` are pydantic-v2-based and *may* ship `py.typed`, in which case they must **not** be
silenced) to the **existing** single `[[tool.mypy.overrides]]` `module = […]` list in
[pyproject.toml](../../pyproject.toml) — not a new block. The exact globs are confirmed against the installed
wheels at adoption.

### 7. SCOPE BOUNDARY — this ADR is the codec + the OUTBOUND REST client ONLY

**State this loudly.** This ADR covers the pure `parsing/fhir/` codec and the `transports/fhir.py` FHIR REST
**destination** (outbound client). It does **NOT** design the **FHIR server facade** — a FHIR REST API server that
**receives** FHIR over HTTP. That inbound facade is a **separate sub-item gated on a future ADR 0023** (the
inbound HTTP listener): per the §4 one-way-dependency rule the listener must live in `transports/`, **not**
`api/`, to preserve the engine-never-imports-`api`/`console` direction, which is a non-trivial decision of its
own. The codec + outbound client depend **only on ADR 0022** and need **nothing** from ADR 0023; conversely, an
inbound FHIR Handler that merely receives a FHIR body over a generic source (File, a future HTTP listener) and
parses it with this codec needs only this ADR. Do **not** design the inbound facade here.

## Options considered

1. **FHIR as `RawMessage` + an on-demand library (CHOSEN) vs a parsed FHIR object added to the `Payload`
   union.** Adding `Payload = Message | RawMessage | FhirResource` with `dryrun.py::_payload()` branching on
   `ContentType.FHIR` would edit the **forbidden routing hotspots**, couple the pipeline to FHIR + a heavy
   pydantic library, and force a full validated parse on the hot path even when a Router needs only the
   `resourceType` peek. **Rejected.** `RawMessage` + an on-demand `parsing/fhir/` library keeps the engine
   format-blind, matches the X12/JSON/XML/SOAP precedent, and lets the cheap routing tier (`FhirPeek`/FHIRPath on
   a dict) run without instantiating a typed model.

2. **A dedicated `ConnectorType.FHIR` (CHOSEN) vs reusing `ConnectorType.REST` + FHIR settings on the generic
   REST destination.** Reusing REST inherits the egress gate "for free" (no fall-through hole) — a real pull — but
   FHIR needs its **own** default media types, its create/update/Bundle method+path derivation, the three
   conditional knobs, and `OperationOutcome` classification, none of which the generic `RestDestination` should
   carry; and the one-builder-per-`ConnectorType` registry means a distinct connector is the clean home for that
   logic. **Rejected (reuse-REST), CHOSEN (dedicated `ConnectorType.FHIR`)** — but the egress-gate inheritance is
   **preserved deliberately** by folding FHIR into the existing `allowed_http` `_allowlist_for`/`check_egress_allowed`
   arms (§3.4) **and keeping the `"url"` settings key**, so the dedicated type does **not** open the fall-through
   fail-open hole that a naively-added `ConnectorType` (or a `base_url`-keyed one) would. This is the same call ADR
   0016 made for X12 (extend-don't-fork the *transport*, add the security arm), applied to FHIR.

3. **A typed `fhir.resources` library (CHOSEN) vs hand-rolling a FHIR model** (as X12's MVP did). X12's model is
   trivial once delimiters are known, so hand-rolling cost nothing and avoided an unvetted dependency. FHIR's
   resource model is **large, version-specific, and conformance-bearing** — hand-rolling it is a multi-quarter
   liability and re-implements validation a vetted BSD-3 pydantic library already does offline. The "verify
   before add" gate was already run for `fhir.resources` + `fhirpathpy` (real, reputable, permissive,
   offline/PHI-safe; the GPLv3 typosquat caught). **Rejected (hand-roll), CHOSEN (`fhir.resources` + `fhirpathpy`
   as an optional `[fhir]` extra).** The *transport* half stays **stdlib-only** (it reuses the `urllib`-based REST
   helpers); the library is confined to `parsing/fhir/` — the lowest-risk split.

4. **Ship the codec + outbound client now, defer the inbound FHIR server facade (CHOSEN) vs build the inbound
   facade in this ADR.** The inbound facade requires an HTTP **listener** whose correct home (`transports/`, not
   `api/`, to preserve the one-way dependency) is a genuine architectural decision with no bearing on the codec or
   the outbound client. Folding it in here would couple two independent decisions and bloat the slice. **Rejected
   (build inbound now), CHOSEN (codec + outbound only; inbound → ADR 0023).** The codec + outbound client deliver
   standalone value (push FHIR to any FHIR server; parse/transform FHIR received over File/Loopback) and unblock
   the SMART-on-FHIR precondition ([FEATURE-MAP.md](../FEATURE-MAP.md) §7 "needs a FHIR transport first").

5. **JSON-FHIR as the MVP path (CHOSEN) vs FHIR-XML co-equal at MVP.** `fhir.resources`' XML support is
   **experimental** and rides **`lxml`, not `defusedxml`**, and the hardened-XML door is a separate backlog item;
   inbound FHIR is attacker-influenceable PHI ([CLAUDE.md](../../CLAUDE.md) §8/§9 — never bare-parse untrusted
   XML). **JSON-FHIR is the primary/MVP path** (the dominant wire format; the stable serializer; no XML parser
   surface); FHIR-XML is **supported only on a hardened-lxml path or deferred** — never bare-parsed. **CHOSEN:
   JSON-first; FHIR-XML gated/deferred.** (This is consistent with the §6 capability table, which marks XML as
   experimental/lxml-optional.)

## Consequences

**Positive**

- **Zero pipeline routing-logic risk.** `_handle_inbound`/`route_only`/`transform_one` and `dryrun.py` are
  untouched; FHIR rides the proven non-HL7 ingress/route/transform/finalizer path and the proven REST HTTP
  transport helpers. The only `wiring_runner.py` edit is the additive egress arm (§3.4) — security parity, not
  logic.
- **A pure, console-importable FHIR library.** Routers/Handlers and the PySide6 console get
  `FhirPeek`/`FhirResource` against `RawMessage`, trivially unit-testable with no socket and no engine.
- **No HTTP re-implementation.** `FhirDestination` **reuses the shipped, stdlib-only rest.py helpers** (the same
  ones `SoapDestination` reuses) — TLS verification, redirect refusal, cleartext-credential refusal, the
  retry/dead-letter classification idiom, the JWS/mTLS hooks — plus the fail-closed egress gate, adding only the
  FHIR-specific layer. It does not wrap or instantiate `RestDestination`.
- **Fail-loud, count-and-log honest, PHI-safe.** Malformed/non-FHIR input raises a `ValueError`-derived
  `FhirPeekError` and dead-letters as `ERROR` (never accept-and-drop), with the **body kept out of the log/error**
  (only `resourceType`/`id`/`issue` codes); an error `OperationOutcome` maps to a permanent NAK or a retryable
  `DeliveryError`, refining (never contradicting) the HTTP-status base.
- **Base install unaffected.** The two FHIR libraries are an optional `[fhir]` extra; SQLite-only installs never
  pull `fhir-core`/`pydantic-core`/`antlr4`.
- **Idempotency has a native lever.** FHIR conditional create / conditional update / version-aware update
  (`If-None-Exist` / search-based PUT / `If-Match` ETag) gives the at-least-once duplicate problem a partner-side
  answer, satisfying the standing "receiver must be idempotent" posture with real mechanisms.

**Negative / risks**

- **A new compiled dependency in the `[fhir]` extra.** `fhir.resources` drags `fhir-core` + a compiled
  `pydantic-core` wheel — heavier than the hand-rolled X12 codec. Confined to an extra and to `parsing/fhir/`, but
  it must be pinned, hash-locked, and audited (DEP-1) at adoption, and the snapshot re-verified per the research's
  standing caveat.
- **No plain-R4 fidelity.** Modern (pydantic-v2) `fhir.resources` ships **R5/R4B/STU3**, not plain R4 (4.0.1,
  dropped in 7.0.0). The default `fhir_version="R4B"` is the closest replacement for the still-dominant deployed
  R4; teams that strictly need 4.0.1 models cannot get them from a pydantic-v2 wheel (only the EOL pydantic-v1
  `<=6.5.0` line) — a deliberate trade for the pydantic-v2 base. R4↔R4B differences are minor for most resources;
  operators must set `fhir_version` deliberately (the HL7 §8 version-explicitness rule, applied to FHIR), and a
  Handler that parses the wrong version raises.
- **FHIR-XML attack surface.** `fhir.resources` XML is **experimental** and rides `lxml`, not `defusedxml`.
  Bare-parsing untrusted FHIR-XML would be a PHI-bearing XML-attack vector — the MVP keeps FHIR-XML off or on a
  hardened-lxml path only; the JSON path adds **no** XML parser.
- **`OperationOutcome` classification is heuristic.** Mapping `issue.severity`/`issue.code` to permanent-vs-transient
  refines the HTTP-status base but is not exhaustive across server implementations; the conservative rule (HTTP
  status wins when in doubt; a 5xx stays transient; the spec-grounded `transient` IssueType group drives retry)
  bounds the risk, and `capture_response` lets an operator route the full `OperationOutcome` to a Handler for
  bespoke handling.
- **PHI-leak risk in error/log paths.** Because `FhirError`/`FhirPeekError` derive from `ValueError` and feed the
  `ERROR`/dead-letter log path, a careless implementation could embed the offending FHIR body in an exception or
  log line and leak PHI at `ERROR`. The §1 PHI rule (body never in the message/log; only `resourceType`/`id`/
  `issue` codes; mirror `_redact_url`) is a **hard invariant** the build must honour — covered by review and,
  where feasible, a test.
- **Purity regression risk.** `parsing/fhir/` must import **zero** engine/`config`; the two import-purity tests
  (§5) guard it — but the `fhir.resources`/`fhirpathpy` imports inside the codec must stay lazy enough that a
  console import (peek-only, structural accessors) does not require the `[fhir]` extra.

**Out of scope (deferred / explicitly NOT promised)**

- **The inbound FHIR server facade** (a FHIR REST API server receiving FHIR over HTTP) — **gated on ADR 0023**
  (the inbound HTTP listener in `transports/`, not `api/`). §7.
- **Profile / StructureDefinition conformance** (US Core, etc.) and **terminology / code-binding validation** —
  HAPI/Firely (Java/.NET) territory; no production-ready offline pure-Python option (research-mandated scope-out).
  The MVP validates **structure/cardinality** via `fhir.resources` only.
- **Bidirectional HL7 v2 ↔ FHIR mapping as a built converter** — no production-ready pure-Python v2↔FHIR
  converter exists; mapping stays **hand-authored code-first Handlers** (python-hl7 `Message` in → `fhir.resources`
  resource out), consistent with the code-first-logic rule.
- **A FHIR *read*/search client** (`GET`/`_search`, `fhirpy`/`fhirclient`) — this ADR is a *write*/POST/PUT/Bundle
  **destination**; a read client is a later transport item.
- **FHIR Bundle transaction execution semantics** — the engine builds/posts a Bundle; the FHIR **server** applies
  the transaction/batch. The engine does not orchestrate cross-entry atomicity.
- **SMART-on-FHIR OAuth2 flows** — the bearer-token path carries a token via `env()`; minting/refreshing it
  through an OAuth2 authZ flow is a later item ([FEATURE-MAP.md](../FEATURE-MAP.md) §7).
- **FHIR-XML as a first-class format** — experimental in `fhir.resources` and `lxml`-bound; JSON-only at MVP
  (Options #5), XML behind a hardened path later.

## To resolve on acceptance

- **Confirm the ADR number is 0022** and the codec + outbound-only scope boundary (inbound facade → ADR 0023);
  add the `Proposed` row for 0022 to [docs/adr/README.md](README.md) at authoring (it flips to `Accepted` on go).
- **Re-run the verify-then-add discipline at build time** ([CLAUDE.md](../../CLAUDE.md) §5/§7): confirm
  `fhir.resources` (+ transitive `fhir-core`) + `fhirpathpy` are still real/reputable/maintained, **pin exact
  versions** (floors `fhir.resources>=7.1.0`, `fhirpathpy>=2.2.0`), add the `[fhir]` extra to
  [pyproject.toml](../../pyproject.toml), re-run `uv lock`/`uv export`, and run the DEP-1 audit — **do not** trust
  the 2026-06-19 snapshot.
- **Confirm the `fhir_version` default = `"R4B"`** (plain R4 is unavailable on pydantic-v2 `fhir.resources`;
  `"R5"`/`"STU3"` opt-in) and the version matrix in §1/§6.
- **Confirm the endpoint settings key is `"url"`** (not `base_url`) so the §3.4 egress gate and the FhirDestination
  read the same key `Rest()`/`RestDestination`/the runner already use — and that the `FHIR()` factory stores it
  there.
- **Confirm the mypy override scope** against the installed wheels: add `"fhirpathpy.*"`, and `"fhir.*"`/
  `"fhir_core.*"` **only if** they lack a `py.typed` marker (do not silence a typed wheel).
- **Decide the FHIR-XML posture concretely** — ship FHIR-XML on a hardened-lxml path, or **defer** it and ship
  JSON-only for the MVP (the recommended default; XML is experimental in the library).
- **Confirm the three conditional knobs in the MVP** (`if-none-exist` / `conditional-update` / `if-match`, opt-in/
  off-by-default as the idempotency + concurrency levers) vs deferring some to a follow-up — and that the path/
  header/URL placement matches the FHIR HTTP spec (`#cond-update`, `#concurrency`).
- **Confirm `OperationOutcome` severity/code → permanent/transient mapping table** with a worked example per
  common FHIR server: `fatal`/`error` (non-transient code) → permanent; the FHIR `transient` IssueType group
  (`lock-error`/`throttled`/`timeout`/`incomplete`) → retry; `success`/`information`/`warning` → non-failing; and
  "HTTP status wins when in doubt; 5xx stays transient" is the tie-breaker.
- **Lane-B gating (v0.2 plan-of-record):** the `fhir-codec` BUILD is **next**, gated on **ADR 0022 Accepted AND
  ci-py311-finalizer (#17) merged**; it is **first** in Lane B (the serialized connector lane) and depends **only**
  on ADR 0022. Lane B holds its `tests/conftest.py` + `pyproject.toml` (the `[fhir]` extra + mypy-override) edits
  until **both** ci-py311-finalizer (#17) **and** obs-metrics' `pyproject.toml` PR have merged to `main`, then
  rebases — to avoid a `pyproject.toml` merge race.
- **Build order on go** (each behind the standard quartet gate — `ruff format --check` · `ruff check` · `mypy
  messagefoundry` · `pytest` with `QT_QPA_PLATFORM=offscreen`): (1) the pure `parsing/fhir/` codec
  (`errors` → `peek` → `resource`) with the two import-purity tests + the PHI-no-log assertion + synthetic
  PHI-free FHIR-JSON fixtures; (2) `transports/fhir.py` reusing rest.py's helpers + the §3 wiring (`FHIR()`
  factory with the `"url"` key, the two enum members, exports, the §3.4 egress arm) + a sample `outbound(...)`
  FHIR config; (3) docs — flip the `FHIR-IN/FHIR-OUT` rows and add the per-connector `### FHIR — FHIR(...)`
  section in [CONNECTIONS.md](../CONNECTIONS.md), fill the §1/§3 rows in [FEATURE-MAP.md](../FEATURE-MAP.md),
  enrich BACKLOG #20, and flip this ADR's [README.md](README.md) row to Accepted.
