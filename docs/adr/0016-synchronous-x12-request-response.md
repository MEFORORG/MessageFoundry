# ADR 0016 — Synchronous X12 EDI request/response feeds (real-time eligibility, 270/271 and friends)

- **Status:** **Accepted (2026-06-15)** — ratified on the owner's "go"; the open questions below are resolved. **No code written yet** (build authorized; not started).
- **Resolved open questions (owner go, 2026-06-15):** (1) **TA1\*E (accepted-with-errors)** = **accepted-with-warning** by default (the interchange *was* accepted → delivered, **no retry**, an `AlertSink` notification), **superseding the draft body's tentative "transient/retry"** — retrying would re-send an already-accepted interchange (unsafe for a state-changing 278N); per-connection overridable. (TA1\*A = accepted; TA1\*R = permanent reject → dead-letter.) (2) **`ta1_required` default = `False`** (preserves fire-and-forget for non-RTE X12); eligibility/RTE connections should set it `True` (documented in `docs/CONNECTIONS.md`). (3) **SOAP-X12 sub-variant** = handler-side envelope build/un-wrap accepted; a dedicated SOAP-X12 helper / transport-level un-wrap is out of scope (a follow-up if needed). (4) The **residual non-idempotent crash-re-send window** (a real second reply at `response_seq=N+1`) is **accepted as inherited from ADR 0013** and not in scope to close for RTE. (5) **Reuse `ConnectorType.X12`** (sharing `[egress].allowed_tcp`) over a dedicated `X12Rte` type — adopted, consistent with ADR 0015's extend-don't-fork reasoning.
- **Built:** nothing yet. This document is the design only.
- **Decision in one line:** a real-time X12 request/response feed (a 270 eligibility inquiry → 271
  response over one socket; 278N/277 variants; or X12 over a REST/SOAP web service) is **not a new
  pipeline mode** — it is the **already-built capture-then-re-ingress machinery** (ADR 0013) wired onto a
  **capture path added to the existing X12 raw-TCP destination** (and the existing REST/SOAP
  destinations for the web variant), with a **TA1 interchange-ack classifier inside the X12 transport**
  modelled on MLLP's `_check_ack`; "synchronous on one socket" is a *transport implementation detail*,
  never a new staged-queue shape.
- **Related:** [ADR 0012](0012-x12-edi-codec.md) (the pure X12 codec + the raw-TCP `X12()` connector this
  extends — and whose **deferred TA1/997/999** note this supersedes), [ADR 0013](0013-query-response-orchestration.md)
  + [ADR 0013 Increment 2](0013-increment-2-reingress-design.md) (capture → immutable `response` artifact →
  atomic `ingress_handoff` → `Loopback()`/`reingress_to=` — the composition this reuses verbatim),
  [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (the REST/SOAP destinations the web variant
  composes), [ADR 0004](0004-payload-agnostic-ingress.md) (the captured 271 re-enters ingress as a
  `RawMessage` under `content_type="x12"`), [ADR 0001](0001-staged-pipeline-architecture.md) (the staged
  queue + the **pure-re-run** + **count-and-log** invariants this must preserve),
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability + count-and-log invariants — *do not break*; §4 one-way
  dependency direction; §8 read separators from MSH/ISA, never hardcode).

## Context

A large class of real-time integration is **synchronous X12 request/response** over a *single*
connection: send an X12 270 (eligibility/benefit inquiry), **block, and read the X12 271 (response) back
on the same socket**; the same shape carries 278/278N (services review) and 277 variants. A transport-
level **TA1** (interchange acknowledgement) may be returned and must be classified — accept / permanent-
reject / transient-retry — much like an MLLP MSA ACK. A second deployment delivers the same X12 270 over a
**REST or SOAP web service** (the X12 payload is the HTTP request body / SOAP envelope content), again
synchronous request → response.

### Everything needed already exists — except two small gaps

The building blocks are built and merged:

- The **pure X12 codec** (`parsing/x12/`) — a tolerant routing peek `X12Peek` (a fixed-offset ISA read +
  shallow GS/ST walk, "Pure: works on `str`/`bytes`, no I/O, no engine imports",
  [parsing/x12/peek.py:15](../../messagefoundry/parsing/x12/peek.py)) **plus the mutable, list-of-segments
  `X12Message`** (`X12Message.parse(raw)` → `.segment_ids()` → `.get("SEG-EE")`,
  [parsing/x12/message.py:56](../../messagefoundry/parsing/x12/message.py),
  [:96](../../messagefoundry/parsing/x12/message.py), [:80](../../messagefoundry/parsing/x12/message.py))
  and the ISA/IEA interchange splitter — and the **raw-TCP `X12()` connector** ([ADR 0012](0012-x12-edi-codec.md),
  [transports/x12.py](../../messagefoundry/transports/x12.py)).
- **Capture → immutable artifact → re-ingress** ([ADR 0013](0013-query-response-orchestration.md) +
  [Increment 2](0013-increment-2-reingress-design.md)): a capturing outbound's `send()` returns a
  typed `DeliveryResponse` ([transports/base.py:129](../../messagefoundry/transports/base.py)); the
  delivery worker persists it inside the same committed transaction as `mark_done` via
  `complete_with_response` into the immutable per-message `response` table; `reingress_to=` on the
  outbound + a `Loopback()` inbound re-ingress the reply via the atomic `ingress_handoff`, content-
  addressed and depth-capped. **No store change** is required by this ADR — the `response` table,
  `Stage.RESPONSE`, `ingress_handoff`, and the run-context `response_view`/`response_get(...)`
  ([config/response.py:70](../../messagefoundry/config/response.py)) are all built and backend-parity'd.
- The **connector registry** + the `X12()` factory ([config/wiring.py:658](../../messagefoundry/config/wiring.py)),
  the offline wiring-validation choke points (`messagefoundry check` / dry-run), and the X12 egress arm
  keyed to `ConnectorType.X12` on `[egress].allowed_tcp`
  ([pipeline/wiring_runner.py:1463](../../messagefoundry/pipeline/wiring_runner.py)).

The two genuine gaps:

1. **The X12 destination throws the reply away.** `X12Destination.send` is still `async def send(self,
   payload: str) -> None` ([transports/x12.py:71](../../messagefoundry/transports/x12.py)); with
   `expect_reply` it reads one returned interchange in `_read_reply` and **discards it** ("any complete
   frame counts as confirmation (not inspected)", [transports/x12.py:99](../../messagefoundry/transports/x12.py)).
   To capture the 271 it must return a `DeliveryResponse` like MLLP/TCP/REST/SOAP already do.
2. **The `X12()` factory and the capture-validity guard don't know about X12.** The `X12()` factory
   ([config/wiring.py:658](../../messagefoundry/config/wiring.py)) accepts `expect_reply` but **not**
   `capture_response`/`reingress_to`, and the ADR-0013 capture-validity guard
   ([config/wiring.py:1494](../../messagefoundry/config/wiring.py)) has **no X12 arm** (it covers
   FILE/REMOTEFILE/TCP/DATABASE). So a capturing X12 outbound cannot be declared or validated today.

### The deferral this ADR closes

ADR 0012 deliberately **froze the X12 connector as an opaque relay with TA1/997/999 *deferred*** —
"There is **no X12 acknowledgment** (TA1/997/999 are deferred) … if a Handler returns a reply it is
written back verbatim" ([transports/x12.py:15-17](../../messagefoundry/transports/x12.py)), echoed in the
factory docstring ("There is **no X12 ACK** (TA1/997/999 are deferred)",
[config/wiring.py:681](../../messagefoundry/config/wiring.py)). **This ADR is the planned closure of that
deferral** for the *outbound* (request/response) direction, and **supersedes** that "deferred" note for a
capturing X12 outbound. The inbound opaque-relay behavior is unchanged.

### The central tension — "real-time/synchronous" vs the staged pipeline + re-run purity

A live 271 is **non-deterministic**: a 270 re-sent after a crash may yield a *different* 271 (different
control numbers, a different eligibility snapshot at that instant). ADR 0001's at-least-once guarantee
re-runs a stage after a crash and is only safe because **routers and transforms are pure** (message in →
message out) and **outbounds are idempotent**. Therefore a 271 must **never** be derived inside a pure
router/transform; it must be **captured** by the transport and **routed via re-ingress** over the
*committed, immutable* artifact. "Synchronous" lives entirely inside the destination's `send()` (it holds
the socket open and blocks for the reply); the pipeline above it sees an ordinary capturing delivery.

## Decision

There is **no `SynchronousRteSource`, no `X12Rte` connector, and no new `Stage`.** A real-time X12
request/response feed is expressed by composing built parts; this ADR adds only (a) a capture path +
TA1 classifier on `X12Destination`, and (b) the X12 wiring/factory edits to declare and validate it.

### The shape: where every non-deterministic value lives (the load-bearing proof)

This is the heart of the design: every non-deterministic value is pinned to the **transport return value
or the immutable artifact**, never to a pure router/transform.

| Value | Non-deterministic? | Where it is produced / lives | Why re-run-safe |
|---|---|---|---|
| The 270 inquiry body | No (pure) | Built by a Handler transform from the inbound trigger | Pure: same in → same out on a re-run |
| The 271 reply body | **Yes** | `X12Destination.send()` return → `DeliveryResponse.body` → `response.body` (immutable, `response_seq`) | Captured, never derived. A re-send appends `response_seq=N+1`; latest wins (ADR 0013 §Negative) |
| TA1 outcome (accept/reject/retry) | **Yes** | Classified **in the transport** (`_check_ta1`), returned as `DeliveryResponse.outcome` or raised as `DeliveryError`/`NegativeAckError` | Same read-failure/parse-failure split as MLLP `_check_ack` ([mllp.py:448](../../messagefoundry/transports/mllp.py)) |
| The re-ingressed message id | Looks non-deterministic | **Content-addressed** — `sha256(b"reingress:"+origin_id+b":"+dest+b":"+str(seq)+b":"+body).hexdigest()[:32]` (simplified; exact form at [0013-increment-2:361](0013-increment-2-reingress-design.md)) | Stable across re-runs of the *same* artifact body; a genuinely different reply is a different artifact → a legitimately distinct id |
| Routing of the 271 | No (pure) | A `@router` on the `Loopback()` inbound, run over the captured body | Pure: reads the committed immutable artifact via re-ingress, never a live socket |

The crucial invariant statement: **the X12 codec stays pure.** `_check_ta1` *parses* a TA1 with the
**already-built** `parsing/x12` codec (`X12Message`, see Q2 — no new codec API), but the **socket read**
and the **retry decision** live in `transports/x12.py` — exactly as MLLP keeps `_check_ack`
([mllp.py:448](../../messagefoundry/transports/mllp.py)) out of `parsing/`. A Handler never calls the
partner; it only ever reads a **prior committed** 271 through `response_get(...)`
([config/response.py:70](../../messagefoundry/config/response.py)) or as a re-ingressed `RawMessage`.
The `parsing/` purity carve-out (CLAUDE.md §4) is preserved.

### Q1 — Synchronous-same-socket vs async capture-then-re-ingress: it is *both*, layered

The modelling decision: a synchronous-same-socket exchange and the ADR-0013 async capture-then-re-ingress
model are **not alternatives** — they are two **layers** of one design:

- **Synchronous, in the transport.** `X12Destination.send()` opens the connection, writes the 270
  verbatim ([transports/x12.py:79](../../messagefoundry/transports/x12.py)), then **blocks** reading the
  returned interchange within `timeout_seconds`. This is real same-socket request/response; the partner's
  271 (or a TA1) comes back on the connection the destination owns. This layer is where "real-time" lives.
- **Asynchronous, above the transport.** The destination **returns** the 271 as a `DeliveryResponse`; the
  delivery worker captures it into the immutable `response` artifact and (when `reingress_to` is set)
  produces a `Stage.RESPONSE` work-row; the re-ingress worker hands the 271 off via `ingress_handoff` into
  the `Loopback()` inbound, where a **pure** `@router` routes it. This layer is where re-run purity lives:
  the 271 is committed state, routed deterministically.

Reconciling the two: **the synchronous read produces the non-deterministic value once, inside the
transport; the asynchronous machinery only ever reads it back from an immutable row.** A pure transform
that needs the 271 (e.g. to stitch the eligibility result onto the original query's context) reads the
*origin's prior committed* reply via `response_get(...)` — ADR 0013's rule that a transform never reads a
reply being produced in the same run (ADR 0013 §"central tension"). This is why neither a synchronous-only
design (which would force a transform to consume a live socket — fatal to re-run purity) nor an async-only
design (which cannot do same-socket request/response — the partner protocol *requires* the reply on the
same connection) is sufficient alone.

### Q2 — TA1 classification lives in the X12 transport, on the existing `X12Message` codec

A **new `_check_ta1(interchange: str) -> DeliveryResponse | None` in `transports/x12.py`**, structured
exactly like MLLP `_check_ack` ([mllp.py:448](../../messagefoundry/transports/mllp.py)) and obeying the
ADR-0013 **read-failure / parse-failure split** verbatim. It uses **only existing codec API** — there is
no new helper in `parsing/x12/`:

- **A read failure is a delivery failure that retries — never a captured outcome.** `_read_reply` today
  raises `DeliveryError("X12 peer closed before returning an interchange")`
  ([transports/x12.py:104](../../messagefoundry/transports/x12.py)) and on a frame-size breach
  ([transports/x12.py:109](../../messagefoundry/transports/x12.py)); the `send` body also raises
  `DeliveryError("X12 timed out")` on `timeout_seconds` ([transports/x12.py:84](../../messagefoundry/transports/x12.py)).
  These mean the partner's disposition is **UNKNOWN** and **MUST keep raising `DeliveryError` and retry**;
  they are **never** captured as `no_reply`. This mirrors MLLP `_read_ack`'s peer-close/frame-size
  failures ([mllp.py:441](../../messagefoundry/transports/mllp.py), [mllp.py:446](../../messagefoundry/transports/mllp.py)).
- **Only a fully-read interchange is classified.** Once `_read_reply` returns one interchange, the bytes
  exist. `_check_ta1` parses them with the existing mutable codec —
  `msg = X12Message.parse(interchange)` ([message.py:56](../../messagefoundry/parsing/x12/message.py)) —
  and reads structure with the methods that **already exist** (separators discovered from the ISA inside
  the codec, never hardcoded — CLAUDE.md §8):
  - **Detection rule.** A returned interchange is a **TA1** iff its **first non-`ISA` functional segment
    is `TA1`** — i.e. `[s for s in msg.segment_ids() if s != "ISA"][0] == "TA1"`
    ([message.py:96](../../messagefoundry/parsing/x12/message.py)). (TA1 is a peer of `GS` directly under
    the ISA, so it appears before any `GS`/`ST`.) The interchange-acknowledgement code is **TA104**, read
    with `msg.get("TA1-04")` ([message.py:80](../../messagefoundry/parsing/x12/message.py)):
    - `A` (accepted, no errors) → `DeliveryResponse(body=interchange, outcome="accepted", detail="TA1*A")`.
    - `R` (rejected) → **permanent** `NegativeAckError(code="AR", permanent=True)` → the worker
      dead-letters it (the partner will never accept this interchange), reusing the exact MLLP reject
      semantics ([base.py:98](../../messagefoundry/transports/base.py), [mllp.py:478](../../messagefoundry/transports/mllp.py)).
    - `E` (accepted with errors / interchange note) → **transient** `NegativeAckError(code="AE",
      permanent=False)` → retry, the conservative choice (mirrors MLLP AE/CE).
  - **It is a business 271 (or 277/278 response) returned *instead of* a TA1** — the success body itself
    (first functional segment is `GS`/`ST`, not `TA1`). → `DeliveryResponse(body=interchange,
    outcome="accepted", detail="271")`. The TA1 was either omitted (many real-time partners skip it) or
    already consumed; the application response *is* the confirmation.
  - **Both a TA1 *and* a co-present business 271** can appear in one returned interchange (a TA1 is a peer
    of `GS` under the same ISA). **The rule: if a TA1 is present it is the retry gate** — classify on
    TA104 as above; **a co-present 271 still rides re-ingress as the captured body** (it is returned in
    `DeliveryResponse.body` on a TA1*A, so the application response is not lost and the `@router` on the
    `Loopback()` inbound peeks it normally).
  - **It is a returned interchange that the codec cannot frame/parse** (`X12Message.parse` raises
    `X12PeekError` — a reply arrived but won't parse) → `DeliveryResponse(body=<decoded bytes>,
    outcome="unparseable", detail=...)` — **only when capturing** (matching MLLP's "unparseable ACK" →
    `outcome="unparseable"` only for a capturing outbound, [mllp.py:456](../../messagefoundry/transports/mllp.py)).
    The precise meaning is **"a reply interchange was received but could not be parsed"**, never "no reply".

**Only TA1 is a transport-level classifier.** 999/997 *functional* acks (and a 271/277/278 application
response) are **content** — they ride the **re-ingress** path and are routed by a Handler over the
captured body, *not* classified in the transport. The distinction is exact: a TA1 acknowledges the
**interchange envelope** (and is therefore the retry gate for *the interchange MEFOR just sent*, the same
role an MSA plays for an MLLP message), whereas a 999 acknowledges a **functional group's** transaction
sets — an application-level outcome a Router/Handler reasons about, not a transport-retry signal. Putting
999/997 in the transport would wrongly couple application acceptance to interchange retry.

### Q3 — The X12 destination capture contract change

`X12Destination` gains the standard ADR-0013 capture surface (it already has `expect_reply` +
`_read_reply`):

- **`send` return type changes to `DeliveryResponse | None`** (the ADR-0013 Increment-1 contract already
  on `DestinationConnector`, [base.py:129](../../messagefoundry/transports/base.py)). When neither
  `capture_response` nor `reingress_to` is set, behavior is **byte-identical** to today (returns `None`,
  fire-and-forget, [transports/x12.py:71](../../messagefoundry/transports/x12.py)). When capturing, `send`
  reads one returned interchange via `_read_reply`, calls `_check_ta1`, and returns the resulting
  `DeliveryResponse` (or raises `DeliveryError`/`NegativeAckError` per Q2).
- **`__init__` gains `self.capture_response: bool`** (read from `settings`, like MLLP/TCP), so `_check_ta1`
  can apply the capturing-vs-non-capturing branch exactly as MLLP `_check_ack` keys on `self.capture_response`
  ([mllp.py:456](../../messagefoundry/transports/mllp.py)).
- **One new connector setting: `ta1_required: bool = False`.** When `True`, a delivery that reads neither
  a TA1 nor a business response within `timeout_seconds` is a `DeliveryError` (retry), not a silent
  success — for partners who contractually always send a TA1. Default `False` preserves the current
  fire-and-forget posture exactly ([transports/x12.py:81](../../messagefoundry/transports/x12.py)). This is
  the *only* new knob; no new connector type.
- **The store contract is untouched.** `send` returns; the **delivery worker** writes the store via
  `complete_with_response` (already built). The transport never imports `store/` — the one-way dependency
  direction (CLAUDE.md §4) is preserved, exactly as ADR 0013 requires for every capturing transport.

### Q4 — The X12-over-web variant: REST is zero new code; SOAP needs a Handler un-wrap step

The web-service variant composes the **existing** REST/SOAP destinations (ADR 0003) with the X12 codec —
no new connector, no transport edit. But **REST and SOAP differ in what the captured body contains**, and
the design must split them:

**REST sub-variant — bare X12 in, bare X12 out (truly zero new code).**

1. A Handler on the trigger inbound builds the **X12 270** body with the pure `parsing/x12` codec and
   `Send`s it to a `Rest(...)` outbound that POSTs that body verbatim and **already captures the HTTP
   response body** as `DeliveryResponse(body=resp.text, outcome="accepted")` (ADR 0013 Increment 1). The
   271 is the bare X12 interchange in the HTTP response body.
2. That outbound carries `reingress_to="IB_LOOP_ELIG_RESULT"`; the **bare 271 rides back in the captured
   HTTP body**.
3. A `Loopback()` inbound declared `content_type="x12"` (ADR 0004/0012) re-ingresses the 271 body as a
   **`RawMessage`**; its `@router`/handler peek/parse it on demand via `parsing/x12`. For REST this works
   as-is — the captured body *is* a bare interchange.

**SOAP sub-variant — the captured body is a SOAP *envelope wrapping* the 271, so it must be un-wrapped.**

The SOAP destination POSTs the Handler-built envelope verbatim ([transports/soap.py:156](../../messagefoundry/transports/soap.py))
and captures the **SOAP response *envelope*** as `DeliveryResponse(body=body, outcome="accepted")`
([transports/soap.py:173](../../messagefoundry/transports/soap.py)) — `body` is the whole `<soap:Envelope>…</soap:Envelope>`,
**not** a bare X12 interchange. Therefore:

1. The trigger Handler **builds the SOAP envelope** around the X12 270 (the SOAP body element carries the
   270 payload, per the partner's WSDL) and `Send`s it to a `Soap(...)` outbound with
   `reingress_to=...`.
2. The captured response body is a **SOAP envelope** wrapping the 271. A `content_type="x12"` `Loopback()`
   fed that envelope directly would **fail to peek/parse** (X12Peek/X12Message cannot frame a SOAP
   envelope) — landing every SOAP-variant 271 in `ERROR` (count-and-log still records it; nothing is
   dropped — but it is a functional dead-end). So either:
   - **(a) Re-ingress as `content_type="soap"`/raw and un-wrap in the handler:** the `Loopback()` inbound
     declares `content_type="soap"` (or any raw type); its handler extracts the X12 271 element from the
     SOAP body and *then* peeks it via `parsing/x12`. This is the recommended SOAP shape.
   - **(b) Un-wrap before re-ingress is not possible** without a transform on the captured artifact (the
     artifact is immutable and the delivery worker does not run handler logic), so option (a) — un-wrap in
     the `Loopback()` handler — is the design.

So the SOAP sub-variant is **not** "zero new code AND `content_type="x12"` Loopback works as-is"; it is
"zero new *transport* code, one extra envelope un-wrap in the trigger Handler (build) and the Loopback
handler (extract)". The REST sub-variant *is* fully zero-touch.

```python
# REST sub-variant: bare X12 270 out, bare X12 271 back in the HTTP body.
# (logic code-first; transport config may be data — connections.toml, ADR 0007)

outbound(
    "OB_ELIG_RTE_WEB",
    Rest(url=env("elig_rte_url"), method="POST",
         headers={"Content-Type": "application/edi-x12"},
         reingress_to="IB_LOOP_ELIG_RESULT"),   # implies capture_response=True (wiring.py:1485)
)

inbound(
    "IB_LOOP_ELIG_RESULT",
    Loopback(),                       # no source; the 271 arrives via ingress_handoff
    router="route_elig_result",       # a PURE @router over the captured 271 (a RawMessage)
    content_type=ContentType.X12,     # REST: the captured body IS a bare interchange — peek as-is
    ack_mode=AckMode.NONE,            # forced by Loopback() (no external peer)
)

# SOAP sub-variant differs: the trigger Handler BUILDS the envelope around the 270, the outbound is
# Soap(url=..., reingress_to="IB_LOOP_ELIG_RESULT"), and the Loopback() declares content_type="soap"
# (raw) — its handler UN-WRAPS the response envelope to extract the X12 271 element before peeking it
# via parsing/x12. X12Message/X12Peek never see the SOAP envelope.
```

The raw-socket variant is identical in shape to REST except the outbound is
`X12(host=..., port=..., reingress_to=...)`.

### Q5 — Correlating the 271 back to the 270; routing via `Loopback()`; loop prevention

- **Pipeline correlation is inherited from ADR 0013 Increment 2.** `ingress_handoff` stamps the
  re-ingressed 271 child with `correlation_id` (the origin 270's message id), `correlation_root_id`, and
  `correlation_depth` in `messages.metadata` ([0013-increment-2 Q4](0013-increment-2-reingress-design.md));
  `GET /messages/{id}/chain` exposes request → captured reply → re-ingressed answer. No new correlation
  surface is added.
- **Application-level correlation (X12 control numbers) is a Handler concern.** A 271 echoes the 270's
  BHT/ST/control identifiers; a Handler on the `Loopback()` inbound that needs to match the *specific*
  inquiry reads them from the captured body via the pure `X12Peek` (ISA13 / GS06 / ST02) — never from a
  hardcoded offset (separators read from the ISA, [parsing/x12/peek.py](../../messagefoundry/parsing/x12/peek.py),
  CLAUDE.md §8). If a Handler wants the origin's stored reply to stitch context, it reads
  `response_get("OB_ELIG_RTE")` ([config/response.py:70](../../messagefoundry/config/response.py)).
- **Loop prevention is the existing depth cap** (`[pipeline] max_correlation_depth`, default 8;
  [0013-increment-2 Q4](0013-increment-2-reingress-design.md)). A real eligibility chain is depth 1–2
  (trigger → 270 → 271 → optional derived send). No new mechanism.

### Q6 — Idempotency, count-and-log, PHI, egress, backend parity, dry-run, validation

- **A non-idempotent 270 re-send is inherited, not closed.** An eligibility query is non-idempotent: a
  crash **after** `send()` returns the 271 but **before** `complete_with_response` commits re-queues the
  outbound row, the worker re-sends, and the partner returns a **possibly different** 271 — captured as a
  *new* `response_seq=N+1`, latest-wins, append-only and visible (ADR 0013 §Negative). This window is
  **no worse than today's `mark_done` window**; this ADR does **not** claim to close it (closing it needs
  a distributed transaction with the partner, which does not exist). The X12 connector docstring states
  the standing "receiver must be idempotent" requirement ([transports/x12.py:17](../../messagefoundry/transports/x12.py))
  and adds: *if you re-ingress a non-idempotent query's reply, treat a crash-re-send as exactly that
  idempotency hazard.*
- **Count-and-log holds.** The trigger message is persisted before ACK and finalized by the single store
  finalizer; the re-ingressed 271 is a **new** `messages` row with its own `RECEIVED → disposition` (an
  X12 body that won't peek is `ERROR` on the new message, not dropped — ADR 0013 Increment 2 Q5/Q7).
  Nothing is accepted-and-dropped.
- **PHI.** A 270/271 (and a TA1, which can carry an ISA/note) is PHI: `response.body`/`detail` are
  **AES-256-GCM at rest** when a key is set (ADR 0013 schema) and **never logged at INFO+** (a TA1-reject
  log line carries the TA104 code + ids only, never the interchange body — CLAUDE.md §9). Secrets
  (`host`/`port`/`url`) come from `env()` via the deferred `EnvRef` mechanism the factories already accept
  ([config/wiring.py:660](../../messagefoundry/config/wiring.py), `host: str | EnvRef`) / DPAPI — never
  source.
- **Egress allowlist — a positive argument *for* connector reuse.** Because the raw-socket variant reuses
  **`ConnectorType.X12`** (not a new `X12Rte` type), the existing egress arm at
  [pipeline/wiring_runner.py:1463](../../messagefoundry/pipeline/wiring_runner.py) — `elif dest.type is
  ConnectorType.X12 and egress.allowed_tcp:` — **already gates RTE** on `[egress].allowed_tcp` exactly as
  raw-TCP/MLLP outbounds are when an allowlist is configured (the engine's standard opt-in egress posture:
  the arm enforces only when the allowlist is non-empty, identical to the TCP arm at
  [wiring_runner.py:1452](../../messagefoundry/pipeline/wiring_runner.py)). A **new** connector type would
  have needed its own egress arm added or it would skip the check entirely; reuse means there is no new arm
  to forget. The REST/SOAP variant is gated by `[egress].allowed_http`.
- **Backend parity — nothing new to parity.** This ADR adds **no** store method, table, stage, or
  finalizer change: `response`, `complete_with_response`, `Stage.RESPONSE`, and `ingress_handoff` are
  already implemented for SQLite, Postgres, **and** SQL Server with an identical single-transaction
  boundary (ADR 0013 §"Backend parity"). The X12 capture path reaches that machinery unchanged.
- **Dry-run.** Dry-run runs **no connectors and no `send()`**, so it never produces a `DeliveryResponse`
  and never simulates a captured 271 (ADR 0013 §"Dry-run is live-only for capture"); the Test Bench shows
  the would-send 270 only. Only **wiring-time validity** is enforced at `check` time.
- **The X12 codec stays pure.** `parsing/x12/` **gains nothing** — `_check_ta1` calls the existing
  `X12Message.parse`/`.segment_ids`/`.get` and lives in `transports/x12.py`
  ([parsing/x12/message.py:56](../../messagefoundry/parsing/x12/message.py)).

### Q7 — The X12 wiring edits (the two real gaps, fixed precisely)

Two factory/validation edits, both at the offline choke point `messagefoundry check`/dry-run already use
(no store):

1. **The `X12()` factory gains `capture_response` and `reingress_to` kwargs** beside the existing
   `expect_reply` ([config/wiring.py:658-699](../../messagefoundry/config/wiring.py)) — and `ta1_required`
   (Q3) — threading them into `ConnectionSpec.settings` exactly as the other connector factories carry
   `capture_response`/`reingress_to`. (Today the factory accepts only `expect_reply`; this is the
   declaration gap.)
2. **The ADR-0013 capture-validity guard gains an X12 arm** at
   [config/wiring.py:1494](../../messagefoundry/config/wiring.py), mirroring the existing **TCP arm** at
   [config/wiring.py:1500](../../messagefoundry/config/wiring.py): a **capturing X12 outbound implies
   `expect_reply=True`** (there is no reply to capture otherwise), so an X12 outbound with
   `capture_response=True`/`reingress_to=...` but `expect_reply=False` is a `WiringError`. Because
   `reingress_to` already forces `capture_response=True` at [config/wiring.py:1485](../../messagefoundry/config/wiring.py)
   and the per-connection guards run for **both** the code-first factory and the `connections.toml` desugar
   (ADR 0007), the X12 arm is enforced on both authoring surfaces with no extra code. The **cross-registry**
   check — `reingress_to` names an existing `Loopback()` inbound — already runs in `build_check_registry`
   ([0013-increment-2 §"cross-registry validation"](0013-increment-2-reingress-design.md)) and sees an X12
   outbound identically to any other.

> **Do not overclaim the current state:** the `X12()` factory does **not** accept
> `capture_response`/`reingress_to` today, and the guard at
> [config/wiring.py:1494](../../messagefoundry/config/wiring.py) has **no** X12 arm — both edits above are
> required. The build is not "X12 just joins an existing set"; it is two concrete additions.

### What is explicitly OUT of scope

- **No inbound SOAP/REST/X12 *listener source*.** These feeds are **MEFOR-outbound** to the partner; the
  *trigger* arrives over an existing inbound transport, and the 271 returns on the connection the
  destination owns (raw socket) or in the captured HTTP/SOAP body (web variant). The `Loopback()` inbound
  is a no-source re-ingress sink, not a listener.
- **No mutual-TLS client cert / WS-Security / WS-Addressing for the SOAP variant** (the SOAP destination
  has none today, ADR 0003); a partner requiring those is a separate transport-hardening ADR.
- **No 999/997 *transport* classifier.** Functional acks are content, routed via re-ingress (Q2).
- **No new `Stage`, store method, or finalizer change** — the whole point is composition over the built
  ADR-0013 machinery.

## Consequences

**Positive**

- Real-time X12 request/response (eligibility 270/271, 278N, 277) becomes expressible **without a new
  pipeline mode** — it is the built capture-then-re-ingress machinery plus a small transport capture path.
- **Byte-identical when unused.** No `capture_response`/`reingress_to` on an X12 outbound ⇒ `send()` still
  returns `None`, the worker still calls `mark_done`, no `response` row is written — the existing X12
  fire-and-forget suite passes unchanged (a required test).
- **Re-run purity is provably preserved:** the live 271/TA1 is produced only in the transport, captured
  into the immutable artifact, and routed by a pure router over committed bytes (the values table above).
- **Egress is gated for free** because the raw-socket RTE reuses `ConnectorType.X12` — the existing
  `[egress].allowed_tcp` arm ([wiring_runner.py:1463](../../messagefoundry/pipeline/wiring_runner.py))
  already covers it; a new connector type would have needed its own arm or it would skip the check.
- **The X12-over-REST variant is zero new code** — `Rest()` already returns `DeliveryResponse` and accepts
  `reingress_to`; only a Handler + a `content_type="x12"` `Loopback()` are authored. (The SOAP variant
  needs no transport code either, but adds an envelope build/un-wrap in the Handlers — see Q4.)
- **No store/backend-parity work** — the `response` table, `Stage.RESPONSE`, and `ingress_handoff` are
  already parity'd across SQLite, Postgres, and SQL Server.

**Negative / costs**

- The X12 `send` path changes from `-> None` to `-> DeliveryResponse | None` and the **capture branch is a
  fresh code path that must re-prove the read-failure/parse-failure split** MLLP already has reviewed — the
  highest-risk spot for silently reclassifying a retryable transport error as a "delivered, unknown
  outcome". The parametrized TA1 regression matrix (Testing) is therefore **mandatory**.
- A non-idempotent 270 re-sent in the residual crash window produces a real second 271 at
  `response_seq=N+1` — inherited from ADR 0013, **not closed** here; operators reconciling RTE feeds must
  treat a re-send as the idempotency hazard the standing invariant already names.
- `_check_ta1` adds X12-acknowledgement semantics the connector deliberately deferred (ADR 0012) —
  modest new transport surface (TA1-detection + TA104 classification + the business-response-instead-of-TA1
  case).
- The **SOAP sub-variant is not zero-touch**: its 271 comes back wrapped in a SOAP envelope, so the
  trigger Handler must build the envelope and the `Loopback()` handler must un-wrap it before peeking via
  `parsing/x12` (Q4). A naïve `content_type="x12"` Loopback fed a SOAP envelope would land every reply in
  `ERROR` (recorded, not dropped — but a functional dead-end).
- The synchronous `send` holds a socket open for `timeout_seconds` per delivery; a slow partner ties up a
  delivery worker for that window (bounded by the existing timeout, [transports/x12.py:65](../../messagefoundry/transports/x12.py)),
  and `ta1_required=True` turns a no-reply into a retry (intended, but it can amplify load against a
  flapping partner — operators tune `timeout_seconds`/retry policy accordingly).

## Testing strategy (required artifacts)

A task isn't done until these pass (CLAUDE.md §5 — new behavior gets a test):

- **Byte-identical-when-off (regression).** Run the existing X12 destination suite unchanged with the
  capture code present but no `capture_response`/`reingress_to`: `send()` returns `None`, `mark_done` is
  called, no `response` row, fire-and-forget unchanged.
- **TA1 classification matrix (mandatory, modelled on the MLLP ACK matrix, ADR 0013).** A parametrized
  regression over:
  - **TA1*A → `outcome="accepted"`** (detected via `X12Message.segment_ids()` first-non-ISA `== "TA1"`,
    `get("TA1-04") == "A"`).
  - **TA1*R → permanent `NegativeAckError(permanent=True)` raised *before* any `DeliveryResponse` is
    returned**, so **no `response` row with `outcome="rejected"` is ever written by this path** — reject is
    a failure-policy / dead-letter outcome, not a captured outcome, exactly as MLLP AR/CR
    ([mllp.py:478](../../messagefoundry/transports/mllp.py)).
  - **TA1*E → transient `NegativeAckError(permanent=False)` → retry.**
  - **business-271-returned-instead-of-TA1 → `outcome="accepted"`** (first functional segment is `GS`/`ST`,
    not `TA1`; the application response is the confirmation).
  - **TA1*A co-present with a 271 in one interchange → `outcome="accepted"`, and the 271 is carried in
    `DeliveryResponse.body`** so the `Loopback()` `@router` peeks it.
  - **peer-close-before-any-frame → `DeliveryError` STILL retries** (read failure, never `no_reply`).
  - **timeout with `ta1_required=True` → `DeliveryError` retries / with `False` → success (`None`).**
  - **frame read but un-parseable by the codec (`X12Message.parse` raises `X12PeekError`) →
    `outcome="unparseable"` *only when capturing*, else `DeliveryError`.**

  Each case asserts the capturing-vs-non-capturing branch, mirroring `_check_ack`
  ([mllp.py:448](../../messagefoundry/transports/mllp.py)).
- **Capture round-trip + re-ingress.** A faked X12 peer returns a 271; assert `send` returns
  `DeliveryResponse(body=271, outcome="accepted")`, the delivery worker writes one immutable `response`
  row, a `Stage.RESPONSE` work-row is produced (because `reingress_to` is set), and `ingress_handoff`
  produces exactly one re-ingressed message into the `Loopback()` inbound (content-addressed id stable on
  a re-run).
- **Crash-window re-run.** Inject a fault between `send()` returning the 271 and `complete_with_response`
  committing; on restart assert the outbound re-sends and a **second** `response_seq=N+1` row appears
  (at-least-once; never two committed re-ingresses — the `ingress_handoff` DELETE-guard, ADR 0013 Inc 2 Q3).
- **X12-over-REST composition (bare X12).** A faked HTTP endpoint returns a bare X12 271 in the body;
  assert `Rest` captures it (no X12-transport code touched), a `content_type="x12"` `Loopback()`
  re-ingresses it as a `RawMessage`, and a Handler peeks it via `parsing/x12` directly.
- **X12-over-SOAP composition (enveloped X12).** A faked SOAP endpoint returns a 271 wrapped in a SOAP
  envelope; assert `Soap` captures the **envelope** as `DeliveryResponse.body`, a `content_type="soap"`
  (raw) `Loopback()` re-ingresses it, and the Loopback **handler un-wraps the envelope** to extract the X12
  271 before peeking via `parsing/x12`. Assert that a `content_type="x12"` Loopback fed the raw SOAP
  envelope lands in `ERROR` (the contrapositive — proves the un-wrap step is required, nothing dropped).
- **Wiring-time rejection via `messagefoundry check` (no store).** `X12(capture_response=True,
  expect_reply=False)` and `X12(reingress_to="X", expect_reply=False)` each fail `check`/dry-run; an X12
  `reingress_to` pointing at a non-`Loopback()`/missing inbound fails in `build_check_registry`; the
  `connections.toml` desugar path fails identically.
- **Egress allowlist.** With a non-empty `[egress].allowed_tcp`, an X12 RTE outbound to a host not on it
  is rejected at wiring by the **existing** X12 egress arm
  ([wiring_runner.py:1463](../../messagefoundry/pipeline/wiring_runner.py)); the REST/SOAP variant by
  `[egress].allowed_http`.
- **PHI / logging.** Assert a TA1-reject log line carries the TA104 code + ids only (no interchange body)
  and `response.body`/`detail` are encrypted at rest when a key is set; no full body at INFO+.
- **Codec purity.** `parsing/x12/` imports no engine module and `_check_ta1` lives in `transports/x12.py`
  (an import-direction assertion, like the existing engine/console boundary tests).

## Alternatives considered

| Alternative | Why considered | Why rejected | Verdict |
|---|---|---|---|
| **Capture path on `X12Destination` + TA1 classifier (on `X12Message`) in the transport + ADR-0013 re-ingress** *(chosen)* | Reuses every built part (codec incl. `X12Message`, capture, artifact, `ingress_handoff`, `Loopback()`, egress arm); only two real gaps to fill | Inherits the non-idempotent-270 re-send window (visible, not worse than today); a fresh capture branch must re-prove the read/parse split; SOAP variant needs a Handler envelope un-wrap | **Adopted** |
| **A new `SynchronousRteSource` / "RTE pipeline mode"** | "Real-time" *sounds* like a distinct mode | A live 271 in a source/transform would feed a non-deterministic value into a pure stage — **fatal to re-run purity** (ADR 0001); also duplicates the staged queue | **Rejected** |
| **A dedicated `X12Rte` connector type** | A bespoke connector could bundle send+TA1+capture | A **new `ConnectorType`** would need its own `[egress].allowed_tcp` arm added at [wiring_runner.py:1463](../../messagefoundry/pipeline/wiring_runner.py) or it would skip the egress check entirely; reuse of `ConnectorType.X12` gets the existing arm for free | **Rejected (reuse X12)** |
| **A new TA1 helper in `parsing/x12/` (e.g. `X12Peek` extended to walk TA1)** | A codec-level TA1 reader feels "purer" | `X12Peek` does only a fixed-offset ISA read + a shallow GS/ST walk ([peek.py:4-13](../../messagefoundry/parsing/x12/peek.py)) — it has no general segment access; but **`X12Message` already provides `segment_ids()` + `get("TA1-04")`**, so no new codec API is needed and `parsing/x12` gains nothing | **Rejected (use existing `X12Message`)** |
| **Detect TA1 / read TA104 by raw string slicing of the interchange in the transport** | "Just look at the first segment" | Mutating/parsing raw X12 by offset violates CLAUDE.md §8 (read separators from the ISA; never string-slice) and would mis-handle non-default delimiters; `X12Message.parse` discovers delimiters from the ISA | **Rejected (parse via `X12Message`)** |
| **Synchronous-only: a transform reads the 271 off a live socket and routes it inline** | Simplest mental model of "send 270, get 271, route it" | A transform consuming a live, non-deterministic socket reply **breaks re-run purity** and the staged-pipeline at-least-once invariant; a crash re-derives a *different* 271 | **Rejected** |
| **Async-only: never block; capture nothing same-socket** | Pure capture-then-re-ingress without a blocking read | The partner protocol **requires the 271 on the same connection** — there is no async inbound for it; you cannot capture what you never read | **Rejected (need the synchronous read layer)** |
| **999/997 functional acks classified in the transport (like TA1)** | Symmetry with TA1 | A 999 is an **application/functional** outcome a Router/Handler reasons about, not an interchange-retry signal; only TA1 (interchange envelope) is the retry gate analogous to an MSA | **Rejected (999/997 ride re-ingress as content)** |
| **`content_type="x12"` Loopback for the SOAP variant (treat the captured body as bare X12)** | Symmetry with the REST variant | The SOAP destination captures the **response envelope** ([soap.py:173](../../messagefoundry/transports/soap.py)), not a bare interchange — `X12Peek`/`X12Message` cannot frame a SOAP envelope, so every reply would land in `ERROR`; the SOAP body must be un-wrapped in the Loopback handler first | **Rejected (un-wrap the envelope, content_type=soap/raw)** |
| **A second `SELECT`/separate read for the web variant instead of capturing the HTTP body** | "Just re-query the partner" | Non-deterministic, off-transaction, and the REST/SOAP destinations **already** capture the response body — re-querying is redundant and re-run-unstable | **Rejected (capture the HTTP/SOAP body)** |
| **Do nothing (keep X12 opaque-relay, TA1 deferred per ADR 0012)** | Zero risk | Forecloses real-time eligibility and the broad class of synchronous X12 request/response feeds; the reply already returns on the socket and is discarded at [transports/x12.py:99](../../messagefoundry/transports/x12.py) | **Rejected** |
