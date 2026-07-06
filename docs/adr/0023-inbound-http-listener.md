# ADR 0023 — Inbound HTTP listener (a connector-owned SOAP/REST web-service source)

- **Status:** Accepted (2026-06-27, built — first slice in 0.2.10; SOAP-reply/auth/routing-metadata deferred)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-27
- **Related:** BACKLOG #7 (inbound web-service listener — this consumes the pre-Reserved README row) ·
  unblocks #20 (inbound FHIR server facade) and #24 (inbound DICOMweb STOW-RS receiver) ·
  [ADR 0003 §3/§5](0003-non-hl7-transports-database-rest-soap.md) (the deferred "REST/webhook source — an
  inbound HTTP request the connector owns, since `transports/` must not import `api/`") ·
  [ADR 0004](0004-payload-agnostic-ingress.md) (the `content_type`/`RawMessage` ingress this rides — a POSTed
  body is a non-HL7 inbound) · [ADR 0002 §0](0002-phase2-transport-security-and-strong-auth.md) (the
  off-loopback "exposed" gate + per-listener TLS this inherits) · [ADR 0013 §"capture + correlate" /
  Increment 1](0013-query-response-orchestration.md) (the **sync-response seam** the SOAP-envelope follow-on
  reuses — NOT 0013 Increment 2 re-ingress) · [ADR 0021](0021-inbound-ack-nak-capture-response-sent.md) (the
  inbound capture + the OFF-by-default per-inbound `connection_event` plumbing this listener reuses) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (ACK-on-receipt + count-and-log + the one-way `transports/ ↛ api/` rule),
  §4 (pluggable connector registry), §8 (payload-agnostic ingress) ·
  [`transports/base.py`](../../messagefoundry/transports/base.py) `register_source`/`SourceConnector`/
  `peer_ip_allowed`/`ConnectionEventSink` · [`transports/mllp.py`](../../messagefoundry/transports/mllp.py)
  `MLLPSource.start`/`_on_client`/`_emit_event` (the real listen-source template) ·
  [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)
  `_start_inbound_unsafe`/`_make_handler`/`_make_connection_event_sink`/`check_mllp_tls_exposure` (listener
  supervision + the ACK/exposed-gate path) · [`config/models.py`](../../messagefoundry/config/models.py)
  `ConnectorType` (the registry enum a new listener type joins)

---

## Context

MessageFoundry ingests over exactly **two listen transports** today — MLLP and raw TCP/X12 — plus poll
sources (File, DATABASE, Timer, REMOTEFILE). There is **no inbound HTTP socket**: a partner cannot `POST`
a JSON/XML/SOAP body, a FHIR client cannot hit a `/fhir` server facade, and a modality cannot `STOW-RS` a
study. The `ConnectorType` enum ([`config/models.py`](../../messagefoundry/config/models.py)) carries
`REST`/`SOAP`/`FHIR`/`DICOMWEB` as **destination-only** today — the inline comment is explicit: "*REST/SOAP
sources (HTTP listeners) and TCP are future*" and "*An inbound DICOMweb (STOW-RS) receiver is destination-only
here — it awaits the HTTP listener (ADR 0023)*". So three queued items are all blocked on the **same missing
substrate**: a bound HTTP socket a *source connector* owns.

ADR 0003 §5 chose payload-agnostic ingress (option B) and ADR 0004 built the `content_type`/`RawMessage`
contract — but both left the **REST/webhook source** explicitly open, naming the exact constraint this ADR
must satisfy:

> "A **REST/webhook source** is the open sub-question (poll a GET, or *receive* an inbound HTTP request — the
> latter needs a listener the connector owns, since `transports/` must not import `api/`)." — ADR 0003 §3
> (echoed in ADR 0004 §7's "a webhook needs an HTTP listener the connector owns, kept out of `api/`").

That one-way rule is the architectural crux. The engine's only external HTTP surface today is the FastAPI
app in `api/` ([CLAUDE.md](../../CLAUDE.md) §2: the API is the engine's only external surface; §4: `transports/`
never imports `api/`). The naive move — add a `/ingest` route to the existing FastAPI app — is **forbidden**:
it inverts the dependency direction (a transport's intake would live in `api/`, and the pipeline resolves
sources through the registry, never special-cased), and it couples message intake to the admin/RBAC surface
that binds for the console. The listener must be a **registry connector in `transports/`** that owns its own
`asyncio` HTTP server, exactly as `MLLPSource` owns its `asyncio.start_server` socket — a sibling listen
source, not a second consumer of the API app.

**The existing listen-source template is `MLLPSource`** and it already supplies every structural piece this
needs ([`transports/mllp.py`](../../messagefoundry/transports/mllp.py)):

- `start(handler, *, leader_gate=None)` binds via `asyncio.start_server(self._on_client, host, port,
  ssl=self._ssl)` and **returns once live**; `stop()` closes the listener, actively closes established
  client writers, and bounds `wait_closed()` against the Windows overlapped-op wedge (#55).
- a per-connection **peer-IP allowlist** (`source_ip_allowlist` → `peer_ip_allowed`,
  [`transports/base.py`](../../messagefoundry/transports/base.py)), fail-closed when set.
- per-connection **inbound TLS** built at construction (`_mllp_ssl_context(..., server=True)`; `None` =
  plaintext, byte-identical) — and the runner's **exposed-gate** (`check_mllp_tls_exposure`,
  [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)) refuses a non-loopback bind
  without TLS at start (ADR 0002 §0).
- the OFF-by-default **`connection_event`** sink (#46, ADR 0021 §7): the runner injects
  `source.on_connection_event` *after* build via `_make_connection_event_sink(ic)`; the source calls it on
  accept/refuse/close (`_emit_event`, **fail-soft** — a capture hiccup never drops a client) and
  `transports/` stays store-agnostic (an injected coroutine, never a `store/` import).

The runner supervises every source uniformly in `_start_inbound_unsafe`: port-conflict guard →
exposed/TLS guard → `build_source` → inject the event sink → `await source.start(self._make_handler(ic),
leader_gate=...)`, with a bound bind-failure → `PortConflictError` and **ADR 0031 per-connection fault
isolation** (a failed listener degrades that one connection, never the engine). A new HTTP listen source
plugs into all of this **unchanged** — the work is the connector, not the supervision.

**The hard part is the response.** MLLP and HTTP are both **request/response on the wire**, but the staged
pipeline (ADR 0001) is **ACK-on-receipt**: the inbound is acknowledged the instant the raw body is durably
committed to the **ingress** stage — *before* routing/transform/delivery. For MLLP that reconciliation is
already settled: `_handle_inbound` parses/(strict-)validates synchronously, commits ingress, and returns an
**AA the moment the body is persisted** (`ack_after=ingest`, the default); a routing/transform/delivery
failure happens *after* the sender was told AA and is **never** NAK'd — operators rely on the message's
`ERROR`/dead-letter disposition + the AlertSink, not the wire ACK (CLAUDE.md §2/§8). HTTP forces the same
question: **what does the synchronous HTTP response say, and when?** Two answers exist, and this ADR builds
the cheap one first and defines the harder one as a bounded follow-on.

## Decision

**Add a connector-owned inbound HTTP listen source in `transports/` — its own bound `asyncio` HTTP socket,
modelled on `MLLPSource`, registered in the connector registry — that decodes a POSTed body, commits it to
the ingress stage via the existing `InboundHandler`, and (first slice) returns a `202`-style
respond-with-receipt; the synchronous downstream-reply (SOAP-envelope) response is a defined follow-on
reusing the ADR 0013 capture seam.** The socket lives in `transports/`, never `api/`; it inherits the ADR
0004 ingress, the ADR 0002 TLS/exposed-gate, the ingress IP allowlist, and the ADR 0021 OFF-by-default
`connection_event` plumbing.

### D1 — A new listen source in `transports/`, registered like every other connector (NOT a route in `api/`)

Add an `HttpSource` (a sibling of `MLLPSource`) in `transports/` that owns its own `asyncio` HTTP server and
is registered via `register_source(ConnectorType.<HTTP_LISTEN>, …)`
([`transports/base.py`](../../messagefoundry/transports/base.py)), so the pipeline resolves it through
`build_source` with **zero `pipeline/` change** — exactly the registry extension point CLAUDE.md §4 mandates
("never special-case a connection type inside `pipeline/`"). It implements `SourceConnector.start(handler, *,
leader_gate=None)` / `stop()` with the **`MLLPSource` lifecycle**: bind-and-return-once-live in `start`;
close-listener + actively-close-established-clients + bounded-`wait_closed()` in `stop` (the #55 Windows
teardown discipline). `leader_gate` is **ignored** (a listen source runs on every node — each binds its own
endpoint; `polls_shared_resource` stays `False`), matching `MLLPSource.start`'s contract.

**Dependency direction is the load-bearing decision.** The socket is **in `transports/`**, never `api/`. The
engine's FastAPI app stays the admin/RBAC surface; message intake is a transport, resolved through the
registry, with no `api/` import — preserving the one-way rule (CLAUDE.md §2/§4) that ADR 0003 §3/§5 and ADR
0004 §7 both flagged as the constraint. The HTTP server is **stdlib-only** (an `asyncio`-driven HTTP/1.1
request reader over `asyncio.start_server`, or a thin embedded server) — **no new web framework dependency**
(the same stdlib-first stance ADR 0003 §4 takes for the HTTP *destination*; FastAPI/uvicorn are an `api/`
concern and must not be pulled into the engine transport layer, CLAUDE.md §12).

### D2 — Intake rides the ADR 0004 payload-agnostic ingress; a POSTed body is a non-HL7 inbound

A received request body flows through the **existing** `InboundHandler` the runner hands the source
(`self._make_handler(ic)`, [`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)) —
the source decodes the request body to bytes and calls `await handler(body)`, exactly as `MLLPSource` does
with a de-framed MLLP message. The inbound declares a `content_type` (ADR 0004): `json`/`xml`/`text` → the
Router/Handler receive a **`RawMessage`** (`.raw`/`.text`/`.json()`/`.xml()`), `hl7v2` → a `Message`
(an HL7-over-HTTP body is still HL7). The ingress branch in `_handle_inbound` is **unchanged** — HTTP is
just a new *carrier* feeding the same `enqueue_ingress`, the same disposition machine
(`RECEIVED → ROUTED/UNROUTED → PROCESSED/FILTERED/ERROR`), and the same count-and-log invariant (every
received body is persisted before the wire response — §2). The **method/path/headers** an HTTP request
carries (which an HL7 frame lacks) are surfaced to the Router via the per-inbound metadata seam (ADR 0004 §4
named the extractor hook) — a `POST /fhir/Patient` vs `POST /stow` is a routing input, not a new pipeline
stage. **Method/route policy:** the listener accepts `POST` for body intake; `GET`/`HEAD` health-probes
return a static non-PHI response without an ingress row. This keeps HTTP *off the HL7 hot path* — it never
HL7-parses a non-HL7 body (CLAUDE.md §8).

### D3 — The response reconciliation: respond-with-receipt first (the cheap slice), captured-reply second

This is the hard decision the brief names. The synchronous HTTP response must reconcile with **ACK-on-receipt
+ count-and-log**, and there are two postures:

- **First slice — respond-with-receipt (`202`-style), the REST body-POST path.** The listener returns its
  HTTP response the instant the body is **durably committed to the ingress stage** — a `202 Accepted` (or a
  `200` with a receipt id) carrying the engine `message_id`, **mirroring MLLP's AA-on-receipt** (ADR 0001
  `ack_after=ingest`). A post-ingress routing/transform/delivery failure happens *after* the `202` and is
  **not** reflected in the HTTP status — it is the message's `ERROR`/dead-letter disposition + the AlertSink,
  exactly as a post-ACK MLLP failure is (CLAUDE.md §2/§8; ADR 0021's "captured ≠ delivered-on-wire"). A
  decode/oversize/allowlist refusal *before* an ingress row returns a `4xx` synchronously (the HTTP twin of
  MLLP's synchronous AR/AE NAK + the ADR 0021 §7 pre-ingress `connection_event`). This is the **cheap, correct,
  low-blast-radius** half — it adds *no* new store surface and is sufficient for a fire-and-forget webhook,
  the inbound FHIR `create` (return `201`/`202` + the resource location), and STOW-RS (return the
  per-instance receipt). It is the only thing this ADR authorizes to build.

- **Follow-on — block-on-captured-downstream-reply (the SOAP-envelope seam).** A SOAP web service (and some
  synchronous FHIR operations) must return the **downstream partner's actual reply** in the HTTP response
  body, not a receipt — request → route → call an outbound → return *its* answer. That is precisely the
  **ADR 0013 Increment 1 capture seam**: a response-capturing outbound returns a `DeliveryResponse`
  ([`transports/base.py`](../../messagefoundry/transports/base.py)) persisted in the immutable `response`
  artifact table. The synchronous-reply HTTP listener **reuses that captured reply** as its response body —
  correlating the inbound `message_id` to the captured `response` row and blocking the HTTP request until the
  reply is captured (bounded by a per-inbound timeout → `504`/`202`-fallback). This is the **harder seam**
  and is **deferred**: it re-opens the synchronous request/response orchestration ADR 0013 already scoped,
  it must bound the block so a slow downstream cannot pin an HTTP worker, and it touches the at-least-once
  re-run window (a blocked-and-returned reply must be the *committed* captured one, never a not-yet-sent one
  — ADR 0013's central tension). It is **explicitly the ADR 0013 capture seam (Increment 1), NOT Increment 2
  re-ingress** — the SOAP listener returns a captured reply, it does not route the reply as a new inbound
  message (loop-prevention / re-ingress stays out of scope here).

`ack_after=delivered` (defer the response until delivery, CLAUDE.md §8) remains planned-not-built for every
transport; the SOAP follow-on is its first concrete consumer and inherits whatever that work settles.

### D4 — Security: inherit the ingress allowlist + ADR 0002 TLS + the ADR 0021 connection log

The listener adds **no new security mechanism** — it inherits four:

1. **Per-connection IP allowlist.** Reuse `source_ip_allowlist` → `peer_ip_allowed`
   ([`transports/base.py`](../../messagefoundry/transports/base.py)): a peer not on the list is refused at
   accept, fail-closed, exactly as `MLLPSource._on_client` does ([`mllp.py`](../../messagefoundry/transports/mllp.py)).
2. **Per-connection inbound TLS + the exposed-gate (ADR 0002 §0).** TLS is built at construction (the
   `_mllp_ssl_context(server=True)` analog; `None` = plaintext, byte-identical), and the runner's exposed-gate
   **refuses a non-loopback HTTP listener without TLS at start** — a new `check_http_tls_exposure` sibling of
   `check_mllp_tls_exposure`/`check_tcp_tls_exposure`
   ([`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py)), so cleartext PHI can never
   cross an off-loopback HTTP socket by accident. The bind defaults to loopback like every inbound (the
   `host` falls back to `127.0.0.1`, never `0.0.0.0` — `MLLPSource.__init__`).
3. **Authentication on the intake socket.** A web-service receiver that is exposed needs request auth (an API
   key / mTLS client cert / bearer) distinct from the admin API's session RBAC — terminated at the listener
   or its WP-15 reverse proxy (ADR 0002). This is a **per-inbound `settings` concern** (the secret from
   `env()`/`MEFOR_*`, never the TOML — ADR 0003 §1), shaped here as a follow-on knob, not the first slice
   (a loopback-bound webhook needs none).
4. **The OFF-by-default `connection_event` log (ADR 0021 §7).** A pre-ingress HTTP failure (allowlist refuse,
   oversize body, malformed request, TLS-accept where a seam exists) emits a metadata-only `connection_event`
   via the injected `on_connection_event` sink — the **same** OFF-by-default per-inbound
   `capture_connection_errors` plumbing, reusing `_make_connection_event_sink(ic)` and the fail-soft
   `_emit_event` pattern, with **no `store/` import in `transports/`**. The `kind` enum gains HTTP-shaped
   values (e.g. `frame_oversize` → an oversize body, `framing_error` → a malformed request) — scrubbed
   metadata only, never a body or field value.

### What this must not break

- **One-way dependency (CLAUDE.md §2/§4).** The socket is in `transports/`; it never imports `api/`. The
  FastAPI app stays the admin surface; intake is a registry connector. (This is the whole reason ADR 0003/0004
  deferred the webhook source — it is the binding constraint, satisfied by D1.)
- **ACK-on-receipt + count-and-log (ADR 0001, CLAUDE.md §2).** The body is durably committed to ingress
  **before** the HTTP response, so received counts reflect true volume and nothing is accepted-and-dropped.
  The first-slice `202` *is* the receipt-and-persistence signal, not a final disposition — identical to MLLP's
  AA-on-receipt; a post-ingress failure is a logged `ERROR`/dead-letter + AlertSink, not an HTTP error.
- **Payload-agnostic ingress, HL7 unchanged (ADR 0004, CLAUDE.md §8).** HTTP is a new carrier feeding the
  same `enqueue_ingress` + disposition machine; the HL7 hot path is untouched and a non-HL7 body is never
  HL7-parsed.
- **At-least-once re-run purity (ADR 0001/0013).** The first slice writes only an ingress row (already
  re-run-safe). The SOAP follow-on must return only a **committed** captured reply (ADR 0013's immutability
  rule), so a crash/re-run never returns a not-yet-sent answer.
- **Per-connection fault isolation (ADR 0031).** A failed HTTP bind (port in use, bad cert, exposed-without-TLS
  refusal) degrades that one connection (`PortConflictError` → recorded failed, engine DEGRADED), never crashes
  the engine — inherited free from `_start_inbound_unsafe`.

## Acceptance Criteria

> EARS form; each linked (`→`) to its test/fixture. `messagefoundry adr-analyze` checks each `→` resolves.

- **AC-1** — WHEN a peer POSTs a body to a bound inbound HTTP listener, THE SYSTEM SHALL decode it and hand it
  to the inbound's `InboundHandler` so it is committed to the **ingress** stage exactly as an MLLP message is
  (count-and-log: the received body is persisted before the HTTP response).
  → `tests/test_http_source.py::test_post_body_enqueues_ingress`
- **AC-2** — WHEN the body is durably committed, THE SYSTEM SHALL return a `202`-style respond-with-receipt
  carrying the engine `message_id`, BEFORE any routing/transform/delivery runs.
  → `tests/test_http_source.py::test_respond_with_receipt_on_ingress`
- **AC-3** — IF a routing/transform/delivery failure occurs AFTER the `202`, THEN THE SYSTEM SHALL NOT alter
  the already-returned HTTP status; the failure surfaces only as the message's `ERROR`/dead-letter disposition
  + AlertSink (the MLLP post-ACK semantics).
  → `tests/test_http_source.py::test_post_ingress_failure_does_not_change_http_status`
- **AC-4** — WHERE an inbound HTTP listener binds off-loopback without TLS, THE SYSTEM SHALL refuse at start
  (the `check_http_tls_exposure` exposed-gate, ADR 0002 §0), isolating that connection (ADR 0031) without
  crashing the engine.
  → `tests/test_http_source.py::test_exposed_without_tls_refused`
- **AC-5** — WHERE `source_ip_allowlist` is set, WHEN a peer not on the list connects, THE SYSTEM SHALL refuse
  it fail-closed and (when `capture_connection_errors`) emit a metadata-only `connection_event`.
  → `tests/test_http_source.py::test_ip_allowlist_refuse_and_connection_event`
- **AC-6** — WHEN the inbound declares `content_type=json`/`xml`/`text`, THE SYSTEM SHALL deliver a
  `RawMessage` to the Router/Handler; WHEN `hl7v2`, a `Message` (ADR 0004 — HTTP is just a carrier).
  → `tests/test_http_source.py::test_content_type_selects_payload_object`
- **AC-7** — WHEN the listener is stopped, THE SYSTEM SHALL close the listener, actively close established
  client connections, and bound `wait_closed()` (the `MLLPSource` #55 teardown discipline), without hanging.
  → `tests/test_http_source.py::test_stop_is_bounded`
- **AC-8** — THE SYSTEM SHALL add **no** `api/` import to `transports/` and resolve the listener through
  `build_source` with no `pipeline/` special-casing (the one-way registry rule).
  → `tests/test_architecture_layers.py::test_transports_does_not_import_api`

## Options considered

1. **A connector-owned HTTP listen source in `transports/`, stdlib HTTP server, registry-registered, riding
   the ADR 0004 ingress — CHOSEN.** Models `MLLPSource` exactly (bind/stop/allowlist/TLS/event-sink), so the
   runner supervises it unchanged and the pipeline resolves it through `build_source` with zero `pipeline/`
   change. Preserves the one-way `transports/ ↛ api/` rule the prior ADRs flagged. First slice = respond-with-
   receipt; SOAP-reply = a defined ADR 0013 follow-on. Minimal new surface; unblocks #7/#20/#24 on one
   substrate.
2. **Add an `/ingest` route to the existing FastAPI `api/` app.** Rejected: inverts the dependency direction
   (intake would live in `api/`, which `transports/`/`pipeline/` must never depend on), couples message intake
   to the admin/RBAC/console surface, and special-cases a transport outside the registry — the exact thing ADR
   0003 §3/§5 and ADR 0004 §7 deferred the webhook source to avoid. Breaks CLAUDE.md §2/§4.
3. **Block the HTTP response on full delivery (no receipt slice) from day one.** Rejected as the *first*
   slice: it forecloses the cheap, correct fire-and-forget/FHIR-create path, contradicts ACK-on-receipt (the
   engine's settled MLLP posture), and a slow/failing downstream would pin an HTTP worker indefinitely. The
   captured-reply (SOAP) path is real but is a **bounded follow-on** on the ADR 0013 capture seam, not the
   default.
4. **A new web framework (FastAPI/uvicorn/aiohttp) inside the engine transport layer.** Rejected: a heavy new
   dependency against the on-prem, minimal-dep posture (CLAUDE.md §7/§12); the HTTP *destination* already
   proved stdlib-first is sufficient (ADR 0003 §4), and FastAPI is an `api/`-only concern that must not enter
   the engine packages.
5. **Per-facade bespoke listeners (one socket for FHIR, one for DICOMweb, one for SOAP).** Rejected: three
   listeners triplicate the bind/TLS/allowlist/teardown/exposed-gate surface for one substrate. #20 and #24 are
   *facades over* this one listener (route/method + `content_type` + a code-first Handler), not new sockets.

## Consequences

**Positive** — Unblocks three queued items (#7 web-service listener, #20 inbound FHIR facade, #24 inbound
DICOMweb STOW-RS) on **one** substrate, built and reviewed as a single connector. It is a faithful `MLLPSource`
sibling, so it inherits the runner's supervision, per-connection IP allowlist, ADR 0002 TLS + exposed-gate,
ADR 0031 fault isolation, and the ADR 0021 OFF-by-default `connection_event` log **for free** — and rides the
ADR 0004 ingress, so the HL7 hot path and the disposition/count-and-log machinery are untouched. The hard
response tension is **settled, not re-litigated**: respond-with-receipt mirrors the engine's existing
ACK-on-receipt posture (cheap, correct, low-blast-radius), and the SOAP-reply path is a bounded, pre-scoped
reuse of the ADR 0013 capture seam rather than a fresh orchestration debate. The one-way `transports/ ↛ api/`
rule is preserved by construction — the socket is a registry connector, never a FastAPI route.

**Negative / risks** — A new listen transport is genuine new attack surface (an HTTP socket that may bind
off-loopback): the exposed-gate, IP allowlist, request auth, and an oversize-body cap must all hold, and the
SOAP follow-on adds request-blocking (a bounded timeout, an HTTP-worker pinning concern) the first slice
avoids. Method/path routing introduces an HTTP-shaped routing input HL7 lacks (the ADR 0004 metadata hook
must carry it cleanly). The stdlib HTTP server must be robust to malformed/oversize/slow-loris requests
(transient `connection_event`, not a listener crash) — the `MLLPDecoder` `max_frame_bytes` discipline has an
HTTP twin (a `Content-Length`/body cap). And the captured-reply seam, when built, inherits ADR 0013's
at-least-once re-run window (a returned reply must be the committed one).

**Out of scope / deferred** — The **SOAP-envelope synchronous-reply** path (block-on-captured-downstream-reply,
the ADR 0013 capture-seam follow-on) is defined here but **not** authorized to build. **Re-ingress / routing
the captured reply as a new inbound** (ADR 0013 Increment 2) is **out of scope** — the SOAP listener returns a
captured reply, it does not re-route it. `ack_after=delivered` stays planned-not-built. Request **authentication
on the intake socket** (API key / mTLS / bearer) is shaped but the first loopback slice ships without it. The
**inbound FHIR facade (#20)** and **inbound DICOMweb STOW-RS receiver (#24)** are *consumers* of this listener
(route + `content_type` + a code-first Handler), each their own follow-on build, not part of this ADR.

## To resolve on acceptance

- [ ] **`ConnectorType` value.** Pick the registry enum member for the inbound HTTP listen source — a new
  `HTTP`/`HTTPSERVER` source, or a `source=True` arm of the existing `REST`/`SOAP` destination types — and
  whether one listen type fans out to all three facades (#20/#24 route over it) or each facade gets its own
  `ConnectorType`. (Lean: one HTTP listen source; facades are route + `content_type` + Handler.)
- [ ] **Method/path → routing seam.** Confirm how `POST /fhir/Patient` vs `POST /stow` reaches the Router —
  via the ADR 0004 §4 per-inbound metadata extractor hook (method/path/headers as routing inputs), and what a
  `GET`/`HEAD` health probe returns (static, no ingress row).
- [ ] **Receipt shape.** Confirm the first-slice response is `202 Accepted` + `message_id` (vs `200` + body),
  and the synchronous `4xx` mapping for a pre-ingress refusal (decode/oversize/allowlist) — the HTTP twin of
  MLLP's synchronous AR/AE NAK.
- [ ] **`check_http_tls_exposure`.** Confirm the exposed-gate sibling refuses a non-loopback HTTP listener
  without TLS at start (ADR 0002 §0), keyed off the same "exposed" predicate as MLLP/TCP.
- [ ] **Request-auth model.** Decide the intake-socket auth (API key / mTLS client cert / bearer) and that its
  secret rides `env()`/`MEFOR_*` (never the TOML), terminated at the listener or the WP-15 proxy — and whether
  any of it ships in the first slice or is a follow-on.
- [ ] **`connection_event` `kind` additions.** Confirm the HTTP-shaped pre-ingress `kind` values (oversize
  body, malformed request, allowlist refuse) added to the ADR 0021 §7 enum, scrubbed metadata only.
- [ ] **SOAP follow-on gating.** Confirm the captured-reply (block-on-downstream) path is authorized
  separately, reuses the ADR 0013 Increment-1 `response`/`DeliveryResponse` seam (NOT Increment 2 re-ingress),
  and bounds the HTTP block with a per-inbound timeout so a slow downstream can't pin a worker.
- [ ] **Stdlib HTTP server choice.** Confirm a stdlib `asyncio` HTTP/1.1 reader (no new web-framework
  dependency) is sufficient for the body-POST + SOAP cases, with the malformed/oversize/slow-loris hardening
  the `MLLPDecoder` cap has an HTTP analog of.
