# ADR 0013 — Query/response orchestration (capture an outbound's response, correlate it, re-route it)

- **Status:** **Accepted (2026-06-14)** — ratified on the owner's "go"; design produced via a judge-panel
  workflow (5 diverse proposals, adversarially scored against the engine invariants — only this one drew no
  fatal flaw — plus a synthesis + adversarial re-run/completeness critique). **Increment 1 (capture +
  correlate) is authorized to build; Increment 2 (re-ingress) stays deferred behind its own "go".** Build
  notes: this branch is based on the **foundation** (`runtime-context-seams`, ADR 0009); its PR rebases onto
  post-merge `main` and **reconciles the run-context registration order** once `db-lookup` + `ingest-time-clock`
  land (both append providers). Increment 1 is **table-only** — it touches **no** `Stage` enum value or
  stage-aware `queue` primitive — so it does **not** require the fleet-wide stage-model freeze (that gate
  applies only to an Increment-2 `Stage.RESPONSE`).
- **Built:** nothing yet. This document is the design only.
- **Decision in one line:** let a response-capable outbound **return its partner's reply** from `send()`
  as a typed `DeliveryResponse`; the delivery worker persists it **inside the same single committed
  transaction as `mark_done`** into a dedicated **immutable `response` artifact table** (a sibling of
  `state`/`reference`, **not** a fourth `queue` stage), keyed `(message_id, destination_name, response_seq)`
  so immutability is a **PRIMARY KEY**, not a discipline — and **defer** re-ingress orchestration (route the
  captured answer as a new message) to a second increment behind its own "go", which consumes the response
  via an **atomic `ingress_handoff`**, never a bare `enqueue_ingress`.
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the staged queue + the pure-re-run
  invariant this must preserve), [ADR 0004](0004-payload-agnostic-ingress.md) (a captured response re-enters
  ingress as a `RawMessage`/`hl7v2` body in Increment 2), [ADR 0005](0005-transform-accessible-state.md) (the
  *mutating* `(namespace,key)` table this deliberately is **not**), [ADR 0006](0006-external-data-lookups.md)
  (the **non-negotiable rule** a persisted external-read result must obey — immutable for the life of the
  message that read it — which this enforces as a schema property), [ADR 0009](0009-run-scoped-context-providers.md)
  (the run-context registry the `response` provider plugs into), [CLAUDE.md](../../CLAUDE.md) §2 (reliability +
  count-and-log invariants — *do not break*).

## Context

A large class of integration work is **request/response**, not fire-and-forget: send an eligibility or
order query to a partner and **route the partner's answer**; deliver to an MLLP destination and
**reconcile the application ACK** (MSA/ERR) it returns; POST to a REST endpoint and capture the created
resource id; run a DB-query `Send` and act on the result-set. In every case the destination **returns a
payload that MessageFoundry throws away today.**

### The exact seam where the response is discarded

The contract `DestinationConnector.send` is `async def send(self, payload: str) -> None`
([transports/base.py:107](../../messagefoundry/transports/base.py)). It returns `None`: the reply bytes
exist *inside* the transport but never leave it. Eight transports implement `send`; five derive a
response and discard it:

- **MLLP** ([mllp.py:239](../../messagefoundry/transports/mllp.py)) already reads the framed ACK
  (`_read_ack`, [mllp.py:241](../../messagefoundry/transports/mllp.py)) and *parses* it
  (`_check_ack`, [mllp.py:253](../../messagefoundry/transports/mllp.py)) to raise `NegativeAckError` on
  AR/CR/AE/CE — the MSA/ERR segments are in hand and dropped on the AA/CA path.
- **TCP** ([tcp.py:118](../../messagefoundry/transports/tcp.py)) reads a framed reply under
  `expect_reply` but explicitly discards the bytes ("any frame counts as confirmation … the bytes are
  not inspected", [tcp.py:131](../../messagefoundry/transports/tcp.py)).
- **REST/SOAP** have an HTTP response body / envelope in hand.
- **DATABASE** ([database.py:229](../../messagefoundry/transports/database.py)) executes a statement
  whose result-set / `RETURNING` / `OUTPUT` is available on the cursor before the commit at
  [database.py:237](../../messagefoundry/transports/database.py).
- **FILE / REMOTEFILE** have **no synchronous response** — there is nothing to capture.

The delivery worker discards whatever `send` could return:
`await connector.send(item.payload)` at
[pipeline/wiring_runner.py:644](../../messagefoundry/pipeline/wiring_runner.py), and on success the only
store write is `await self.store.mark_done(item.id)`.

### Two distinct capabilities — keep them separate

1. **Capture + correlate (Increment 1).** Persist the partner's reply, durably keyed to the inbound
   message that produced it, and expose it on a read surface (API/console) for reconciliation,
   troubleshooting, and audit. This is the high-value, low-blast-radius half.
2. **Re-ingress / orchestrate (Increment 2).** Feed a captured response back through `enqueue_ingress`
   as a *new* inbound message so a Router/Handler routes the answer — true request → response → route.
   This re-opens the queue surface and adds a loop-prevention obligation, so it is deferred behind its
   own "go".

### The central tension — re-run purity vs a live, non-deterministic partner

ADR 0001's at-least-once guarantee works by **re-running a stage after a crash**, and that is only safe
because **a re-run re-derives identical output** (routers/transforms are pure; outbounds are idempotent).
A captured response is **durable state derived from a live partner call** — the antithesis of pure: the
partner is not consulted under our transaction's isolation, and a second call after a crash can return a
*different* reply (a different ACK control id, a different `RETURNING` identity, a different result-set).

This forces three rules that the rest of this ADR is built to satisfy:

- **The capture must never participate in deriving routing/transform output during the same run that
  produced it.** A router/transform reads a *committed prior* response, never one being produced now.
  (Concretely: the `response` provider in Increment 1 reads rows committed by an *earlier* delivery;
  there is no path by which a transform reads its own outbound's not-yet-sent reply.)
- **A persisted response must be immutable for the life of the message** (ADR 0006's non-negotiable
  rule). It is keyed **per message** and **content-addressed by a monotonic sequence**, never written
  into the *mutating* `(namespace, key)` state table — a TTL refresh or a later message would overwrite
  it and a replay would diverge.
- **The capture is the *last* thing a successful delivery does, and it cannot un-succeed a delivery.**
  `send()` already succeeded (the partner has the message); capture must not re-raise.

## Decision

### The shape: a `response` artifact table, not a `Stage.RESPONSE` queue row (Increment 1)

Persist each captured reply as a row in a **new `response` table**, a sibling of the `state` and
`reference` read-through artifacts — **not** as a fourth value of the `Stage` enum on the `queue` table.

This is the decisive choice, and it is forced by the finalizer. `_maybe_finalize_message`
([store.py:2848](../../messagefoundry/store/store.py)) is the **sole disposition authority**; it computes
a message's terminal status from **every `queue` row** sharing its `message_id`:

```
SELECT stage, status, COUNT(*) AS n FROM queue WHERE message_id=? GROUP BY stage, status
```

and (a) **refuses to finalize** while any row is `PENDING`/`INFLIGHT`
([store.py:2855](../../messagefoundry/store/store.py)), (b) flips the message to `ERROR` on **any** `DEAD`
row ([store.py:2859](../../messagefoundry/store/store.py)). A response modelled as a `queue` row keyed by
the **origin `message_id`** would therefore **corrupt disposition**: a still-pending response row would
pin the message out of `PROCESSED` forever, and a dead response row would flip a perfectly-delivered
message to `ERROR`. A separate table is **invisible** to that `SELECT`, so the count-and-log invariant
(CLAUDE.md §2) is preserved by construction. The `response` table is **not** a pipeline stage and is
**never** drained by a worker in Increment 1 — it is pure derived state, like `state`/`reference`.

### Schema — immutability as a PRIMARY KEY

```sql
CREATE TABLE response (
    message_id        TEXT    NOT NULL REFERENCES messages(id),
    destination_name  TEXT    NOT NULL,
    response_seq      INTEGER NOT NULL,   -- monotonic per (message_id, destination_name); see below
    body              BLOB,               -- AES-256-GCM ciphertext at rest, like queue.payload/messages.raw
    outcome           TEXT    NOT NULL,   -- 'accepted' | 'rejected' | 'unparseable' | 'no_reply'
    detail            TEXT,               -- short, e.g. MSA-1 / HTTP status; encrypted (PHI-bearing)
    captured_at       REAL    NOT NULL,
    PRIMARY KEY (message_id, destination_name, response_seq)
);
```

- **`body` is encrypted at rest** with the same cipher as `queue.payload` / `messages.raw`
  (AES-256-GCM when a key is set), and `detail` is encrypted identically (it can carry PHI — an MSA-3
  text, a result-set echo). This row never leaks a body to a log.
- **`response_seq` is replay-stable** and is the reason this is *not* keyed by `attempts`. `replay`
  ([store.py:1830](../../messagefoundry/store/store.py)) does `UPDATE queue SET attempts=0`, so an
  `attempts`-keyed artifact would collide on the *next* delivery of a replayed row (PK violation / silent
  overwrite). `response_seq` is assigned as `1 + MAX(response_seq)` for the `(message_id,
  destination_name)` pair at insert time, inside the capture transaction; a replay's re-delivery simply
  appends `response_seq = N+1` — the full reply history of a message is preserved and immutable, each row
  written by a plain `INSERT` that **never updates** an existing row.

### The exactly-once capture transaction: `complete_with_response` XOR `mark_done`

Add `complete_with_response(outbox_id, response: CapturedResponse, now=None)` to the `QueueStore`
protocol ([store/base.py](../../messagefoundry/store/base.py)) and the SQLite/Postgres implementations.
It does **everything `mark_done` does, plus one `INSERT INTO response`, in one atomic transaction**.

The delivery worker calls **exactly one** of `mark_done` (non-capturing outbound, or a capturing outbound
that legitimately got no reply — see *no-reply* below) **or** `complete_with_response` (capturing
outbound with a reply). They are never both called for one delivery; this XOR is the single-writer
discipline that makes the row count of `(success, captured-response)` exactly one.

**Atomicity is explicit, not implicit (folds in minor #3).** `mark_done`
([store.py:1613](../../messagefoundry/store/store.py)) relies on aiosqlite's *implicit* transaction (no
`BEGIN`; a single trailing `commit()`). `complete_with_response` does **more** writes — `UPDATE queue` +
`INSERT response` + the `UPDATE messages` inside `_maybe_finalize_message` — so it **must** use an
**explicit** transaction, matching `route_handoff`
([store.py:1193](../../messagefoundry/store/store.py)): `await self._db.execute("BEGIN")` … all three
writes … a **single** trailing `commit()`, under `self._lock`, with a `rollback()` on any exception. The
`INSERT response` sits **between** the `UPDATE queue` and the single commit; **no intermediate `commit()`
may be introduced.** `store/postgres.py` must mirror this *exact single-transaction boundary* (its
autocommit posture differs from aiosqlite's), and the backend-parity bullet below names **atomicity**,
not merely method existence.

### Returning the response: a typed `DeliveryResponse`, not `str | None`

Widen the contract to:

```python
@dataclass(frozen=True)
class DeliveryResponse:
    body: str                 # the partner's reply text (already decoded by the transport)
    outcome: str              # 'accepted' | 'rejected' | 'unparseable' | 'no_reply'
    detail: str | None = None # short reason, e.g. MSA-1=AA / HTTP 201 / "peer closed"

# DestinationConnector.send return type becomes:  DeliveryResponse | None
```

`None` means "no capture" (the existing behavior; every non-capturing outbound keeps returning `None`).
A **typed frozen** return (over a bare `str | None`) lets the transport hand back the **already-derived
outcome** it computed anyway — MLLP/SOAP/REST/DATABASE all inspect the reply to decide success/failure —
so the store never re-parses the encrypted-at-rest body to reconstruct an MSA-1. The `outcome` is a
small closed vocabulary; the full body lives only in `response.body`.

`capture must not re-raise.` The capture branch of the worker wraps the `complete_with_response` call so
that **a store-write failure during capture cannot un-succeed an already-successful `send()`** — but note
the asymmetry below: a *transport read failure* is **not** a capture failure, it is a delivery failure,
and it still raises.

### Per-transport response semantics — and the read-failure / parse-failure split (folds in MLLP-major + TCP-blocker)

The single most important correction in this design: **a failure to *read* a reply frame is a delivery
failure that must still retry; only a *successfully-read* reply that merely won't parse becomes a
captured `outcome='unparseable'`.** Conflating the two would silently reclassify today's retryable
transport errors as "delivered", losing the retry and recording a phantom delivery for an unknown
outcome. The rule, per transport:

- **MLLP.** `_read_ack` ([mllp.py:241](../../messagefoundry/transports/mllp.py)) raises `DeliveryError`
  on **"peer closed before sending an ACK"** ([mllp.py:246](../../messagefoundry/transports/mllp.py)) and
  on **"ACK exceeded max frame size"** ([mllp.py:251](../../messagefoundry/transports/mllp.py)). These
  are **read failures** — the partner's disposition is **UNKNOWN** — and they **MUST keep raising
  `DeliveryError` and retry**; they are **never captured**. Only once a frame is fully read does
  `_check_ack` ([mllp.py:253](../../messagefoundry/transports/mllp.py)) run: AA/CA →
  `DeliveryResponse(outcome='accepted')`; AR/CR → today's permanent `NegativeAckError`; AE/CE/unknown →
  today's transient `NegativeAckError` (retry); and the **one new mapping** — a frame that arrived but
  whose MSH won't `Peek.parse` (today the `DeliveryError("unparseable ACK")` at
  [mllp.py:260](../../messagefoundry/transports/mllp.py)) — becomes
  `DeliveryResponse(outcome='unparseable', detail=...)` **only for capturing outbounds**. The precise
  meaning of `unparseable` is **"a reply frame was received but its MSA could not be parsed"** — *never*
  "no reply was received". For a non-capturing MLLP outbound the behavior is byte-identical (still
  `DeliveryError`, still retries). The AA/AE/AR/CA/CE/CR matrix plus a **"frame-read-failure still
  retries"** case is a required regression artifact (Testing, below).
- **TCP.** Capture requires `expect_reply=True`. `_read_reply`
  ([tcp.py:131](../../messagefoundry/transports/tcp.py)) raises `DeliveryError("TCP peer closed before
  sending a reply")` ([tcp.py:137](../../messagefoundry/transports/tcp.py)) when no frame arrives — a
  **read failure**, so a capturing TCP outbound whose partner sends nothing **still retries** (it does
  **not** silently return `no_reply`). A frame that *is* read returns
  `DeliveryResponse(body=frame, outcome='accepted')` (TCP does not interpret the bytes). This means
  enabling capture on TCP does **not** change delivery semantics: a missing reply was already a retryable
  `DeliveryError` and stays one.
- **REST.** A 2xx with a body → `DeliveryResponse(body=resp.text, outcome='accepted', detail='HTTP
  201')`. A **2xx with an empty body** is a *successful delivery with an empty capture*:
  `DeliveryResponse(body='', outcome='no_reply')` (not an error — the request succeeded). Non-2xx keeps
  today's `DeliveryError`/retry classification unchanged.
- **SOAP.** A returned envelope → `DeliveryResponse(body=envelope, outcome='accepted')`; a SOAP `<Fault>`
  → `outcome='rejected'`; an **empty/absent envelope on an otherwise-OK transport** → `outcome='no_reply'`.
  Today's transport-level faults keep their `DeliveryError`/retry behavior.
- **DATABASE — see the dedicated subsection below.**
- **FILE / REMOTEFILE.** No synchronous response — `capture_response=True` is a **wiring-time error**
  (below), never a runtime branch.

**`no_reply` vs read-failure, stated once:** `outcome='no_reply'` means *the transport completed a
successful round-trip and the partner deliberately returned an empty payload* (REST empty 2xx, SOAP empty
envelope). A *failure to read a frame* (MLLP/TCP peer-close, timeout, frame-size) is **not** `no_reply` —
it is a `DeliveryError` and **retries**. This distinction is load-bearing and is an explicit row in the
regression matrix.

### DATABASE capture must be `RETURNING`/`OUTPUT`, not a second `SELECT` (folds in DATABASE-major)

`DatabaseDestination.send` executes the write and **commits immediately** at
[database.py:237](../../messagefoundry/transports/database.py). A capture modelled as a *separate*
`SELECT` would necessarily run **after** that commit, in a **new transaction**, reading post-commit
state. That is unsafe: on an at-least-once re-run (crash before `complete_with_response` commits) the
**entire write statement re-executes** (DATABASE `send` is non-idempotent unless the operator wrote a
`MERGE`), so a separate post-commit `SELECT` could read **different** state on the re-run (a new identity,
a different row count). Therefore:

- **Capture MUST be expressed as a `RETURNING` / `OUTPUT` clause of the write statement itself** — one
  statement, one round-trip, fetched from the **same cursor before the existing `commit()`**. A separate
  `SELECT` is rejected. (If a future backend cannot do `RETURNING`, the alternative is to run the capture
  `SELECT` on the **same connection inside the existing pre-commit transaction** by deferring the commit —
  but the default and documented path is `RETURNING`/`OUTPUT`.)
- The captured result-set is **JSON-serialized** (reusing `_json_default`) and bounded: a
  **`capture_max_rows`** cap (default e.g. 100) and a serialized-body byte cap. Exceeding either yields
  `DeliveryResponse(outcome='unparseable', detail='result-set exceeded capture cap')` with a truncated/
  empty body — never an unbounded encrypted blob.
- **DATABASE capture inherits the standing "outbounds must be idempotent" requirement.** A `RETURNING` of
  a non-idempotent `INSERT` re-derives a *different* generated id on a re-send — and a generated id is
  exactly the value a request/response feed wants to route. The wiring docs and connector docstring state
  this explicitly: if you capture a `RETURNING` id and re-ingress it (Increment 2), make the write
  idempotent (`MERGE`/upsert keyed by a natural key) or accept that a crash-re-send produces a second id.
- Result-set bodies are **PHI** identically to message bodies (encrypted at rest, never logged at INFO+).

### Wiring-time validation lives in the factories, not connector `__init__` (folds in wiring-major)

`capture_response` (and DATABASE's `capture_statement`/`RETURNING` requirement) is validated at the
**author factories in [config/wiring.py](../../messagefoundry/config/wiring.py)** — the same layer where
`route_only`/`transform_one` reject unknown handlers/outbounds — so **`messagefoundry check` / dry-run
catches it without a live store** (dry-run builds **no** connectors; validating only in connector
`__init__` would defer the error to engine start). Specifically:

- `File()` / `RemoteFile()` factories **reject `capture_response=True`** ("FILE/REMOTEFILE have no
  synchronous response").
- `Database()` factory **rejects a capturing outbound whose write statement carries no
  `RETURNING`/`OUTPUT`** ("DATABASE capture requires a RETURNING/OUTPUT clause, not a separate SELECT").
- `Tcp()` capture **implies `expect_reply=True`** (rejected if the operator set `expect_reply=False`).
- The **`connections.toml` desugar path (ADR 0007)** runs the **same** factory validation, so a File/
  RemoteFile outbound that sets `capture_response` in TOML fails identically at load — the desugar passes
  through the same `inbound()`/`outbound()` factories.

### The run-context `response` provider — exact field, registration order, and worker threading (folds in run-context blocker)

A Router/Handler reads a prior captured response via a new accessor (`response_get(...)`), wired through
the ADR 0009 run-context registry. The under-specified parts, pinned:

1. **A new `RunContext` field.** Add `response_view: Any = None` to `RunContext`
   ([run_context.py:60](../../messagefoundry/config/run_context.py)). Defaulted to `None` like the other
   four fields, so it is **byte-identical when unused** — a phase/run that never reads it leaves it `None`.
2. **The provider is keyed per-message.** Unlike `state`/`reference` (process-wide views), a response
   read is **scoped to the current message_id** (and its correlation lineage). So `response_view` is not a
   flat mapping; it is a **store-backed read closure** bound to the claimed item's `message_id`, built by
   the worker for *this* run. The closure reads only **committed** `response` rows (immutable), so it is
   re-run-stable: a re-run reads the identical committed history.
3. **Registration position.** Register `response` in
   [run_context.py:129–140](../../messagefoundry/config/run_context.py) **after `state`, before
   `environment`** (so the order becomes `code_sets → reference → state → response → environment`), in
   **phases `{TRANSFORM}`** only (a Handler reconciling an answer is a transform concern; the router phase
   does not read responses in Increment 1). Registration order is the ExitStack nesting order and is
   load-bearing for determinism, so it is pinned here and asserted by `registered_providers()` in a test.
4. **Worker threading.** The transform worker builds the `RunContext` for each run from the **claimed
   item's `message_id`** (the worker has the item in hand; `message_id` is on it, not in `RunContext`
   today). The call site that constructs the transform-phase `RunContext` in
   [pipeline/wiring_runner.py](../../messagefoundry/pipeline/wiring_runner.py) passes
   `response_view=<closure bound to item.message_id>`. The **router** call site is unchanged
   (`response_view=None`, router phase doesn't register the provider).
5. **Dry-run stays a no-op.** The dry-run path supplies `response_view=None` (it has no store), so
   `response_get(...)` resolves to empty and the Test Bench/CLI preview is byte-identical. (Dry-run also
   never produces a `DeliveryResponse` — see *Dry-run* below.)

### Dry-run is live-only for capture

Dry-run ([pipeline/dryrun.py](../../messagefoundry/pipeline/dryrun.py)) runs **no connectors and no
`send()`**, so it can never produce a `DeliveryResponse`, and `response_view=None` means a captured
response is never simulated. The Test Bench / CLI preview shows would-send payloads only; a captured reply
(and, in Increment 2, a re-ingressed answer) does **not** appear in the preview. Only the **wiring-time
validity** (capture on a no-reply transport, DATABASE without `RETURNING`) is enforced at `check` time.
This is stated so operators don't expect dry-run to show the response or the re-ingress chain.

### Read surface, RBAC, audit (folds in PHI/retention-major)

`correlate_response` (the store read used by the API) is a **new PHI read surface**, gated exactly like
`get_message` (CISO Risk #6):

- **API route:** `GET /messages/{id}/responses` returns the response history (outcome/detail always;
  `body` only with the body permission), on the engine API ([api/app.py](../../messagefoundry/api/app.py)).
- **RBAC permission:** deny-by-default, gated by the **same body-read permission** that gates raw-message
  view (`messages:read_body` lineage); outcome/detail metadata uses the lighter `messages:read`.
- **Audit event:** `response.read` emitted with the acting user and `message_id`, mirroring the
  `message.read_body` audit lineage.
- The **console** rendering of "ACK: AA / unparseable / no_reply" + any body display reads through the
  same gated route and is **audited identically** — no in-process or DB access.

### Retention / purge (folds in PHI/retention-major)

`purge_message_bodies` ([store.py:2617](../../messagefoundry/store/store.py)) already blanks
`messages.raw`/`summary`/`error`, the `done`/`cancelled` outbound `queue.payload`, and `message_events.detail`
**for the same eligible set in one transaction**, gated on "no queue row still `pending`/`inflight`". This
ADR adds a **fourth `UPDATE` inside that same transaction**:

```sql
UPDATE response SET body=NULL, detail=NULL WHERE message_id IN (<eligible>)
```

Crucial FK detail: `purge_message_bodies` **does not delete the `messages` row** (Mirth Data-Pruner
pattern — it nulls bodies, keeps metadata), so `response.message_id REFERENCES messages(id)` is **never
violated** by retention; the response **row is kept, its `body`/`detail` nulled in place** (not deleted),
on the *same* window as `messages.raw`. The new UPDATE is idempotent (guards on a non-null body) like the
existing three. (`purge_dead_letters` is untouched — responses are not dead-letter rows.)

### Backend parity

`complete_with_response`, `correlate_response`, the `response` table + its `_migrate` creation, and the
retention UPDATE are implemented for **both** SQLite ([store/store.py](../../messagefoundry/store/store.py))
and Postgres ([store/postgres.py](../../messagefoundry/store/postgres.py)) with the **identical
single-transaction boundary** (the parity requirement is *atomicity*, not just method existence — see the
explicit-transaction note above). The **SQL Server** backend ([store/sqlserver.py](../../messagefoundry/store/sqlserver.py))
implements the `response` table + `complete_with_response` with the **same single-transaction
boundary**, so capture works identically there (`supports_response_capture = True`).

### `OutboxItem` is untouched in Increment 1

`OutboxItem` ([store/store.py](../../messagefoundry/store/store.py)) gains **no field** in Increment 1 —
capture writes a separate `response` row, never the `queue` row — so all existing `OutboxItem` hydration
sites and the frozen dataclass are byte-identical. (The correlation field is an Increment-2 concern;
see below.)

---

### Increment 2 — re-ingress / orchestration (deferred, behind its own "go")

Increment 2 routes a captured answer as a new inbound message. It is sketched here so Increment 1 doesn't
foreclose it, but it is **not** authorized by this ADR's Increment-1 "go".

- **Re-ingress is an atomic `ingress_handoff`, never a bare `enqueue_ingress`.** `enqueue_ingress`
  ([store.py:1062](../../messagefoundry/store/store.py)) mints a fresh `uuid4().hex` **unconditionally**
  and consumes **no** prior row — so calling it on a re-run **double-injects** the answer (two inbound
  messages from one reply). Increment 2 adds a **new `ingress_handoff`** that **consumes the response row
  (or a claim token) and produces the ingress rows in one transaction**, cloning the
  claim→produce-next→complete + INFLIGHT-guarded-DELETE shape of `route_handoff`
  ([store.py:1165](../../messagefoundry/store/store.py)) / `transform_handoff`
  ([store.py:1318](../../messagefoundry/store/store.py)): a crash before commit rolls back and re-runs;
  a committed run is an idempotent no-op (the consumed token is gone → rowcount 0 → `False`). This is the
  *only* re-ingress path; a bare `enqueue_ingress` re-injection is explicitly rejected.
- **Adding `Stage.RESPONSE` re-opens the stage-frozen surface.** If Increment 2 chooses a
  `Stage.RESPONSE` work-row (one option for ordering the re-ingress against siblings), it touches the
  stage-aware primitives the Increment-1 design left **byte-identical**: `claim_next_fifo`,
  `_fifo_created_at`, `reset_stale_inflight`, and `pending_depth` each gain a **`response → channel_id`
  lane-key branch** (RESPONSE lanes key by `channel_id`, like ingress), and **`reset_stale_inflight(stage=None)`
  must be confirmed to recover inflight RESPONSE rows on startup**. So Increment 2 needs **its own stage-model
  freeze window** — the "byte-identical, zero stage-exclusion clauses" claim is true for Increment 1's
  table-only design but **not** for an Increment-2 new stage.
- **`OutboxItem.correlation_id=None` is appended as the FINAL field.** If Increment 2 threads a
  correlation id through outbound rows, it is added **after `handler_name=None`** to preserve positional
  construction of the frozen dataclass, every row→`OutboxItem` hydration site defaults it, and the
  `_migrate` `ALTER TABLE queue ADD COLUMN correlation_id … DEFAULT NULL` is **idempotent on an existing
  DB** (guarded by the existing `_migrate` "column exists?" pattern).
- **Loop prevention is a depth cap, not cycle detection.** Re-ingress carries a `correlation_depth` in
  `messages.metadata`. A normal (non-re-ingressed) inbound is **depth 0** (absent ⇒ treated as 0);
  `ingress_handoff` stamps `depth = parent_depth + 1`; exceeding `max_correlation_depth` →
  `dead_letter_now`. This is deliberately **coarse**: it bounds *total work*, not *topology* — two
  outbounds whose replies feed each other still oscillate up to the cap. Stated plainly so operators
  don't mistake it for cycle detection.

## Consequences

**Positive**

- The thrown-away response becomes durable, immutable, per-message, audited state — request/response and
  ACK-reconciliation feeds (a large slice of the Corepoint migration) become expressible.
- **Byte-identical when unused.** No `capture_response` ⇒ `send()` still returns `None`, the worker still
  calls `mark_done`, no `response` row is written, `RunContext.response_view` stays `None`, and the
  existing one-way suite passes unchanged (a required test).
- The finalizer / disposition model is **untouched** — the `response` table is invisible to
  `_maybe_finalize_message`, so count-and-log and at-least-once hold without modification.
- Immutability is a **PRIMARY KEY** (`response_seq` monotonic, plain `INSERT`), so ADR 0006's
  non-negotiable rule is a schema property, not a discipline; replay (`UPDATE queue SET attempts=0`)
  cannot collide.
- The transport→store dependency direction is **never inverted**: the transport *returns* a value; the
  *worker* writes the store. No "capture callback into the store" is passed into `send()` (which would
  break CLAUDE.md §4).

**Negative / costs**

- **A residual at-least-once crash window remains, and it is real.** If the engine crashes **after**
  `send()` returns a reply but **before** `complete_with_response` commits, the row is still
  `INFLIGHT`; on restart `reset_stale_inflight` re-queues it, the worker **re-sends**, and the partner
  returns a **possibly different** reply, captured as `response_seq = N+1`. **Exactly-once delivery is no
  better and no worse than today** (the same window exists today for `mark_done` — a crash after `send`
  before `mark_done` re-sends), but **capture makes the divergence *visible*** as a second response row.
  This is honest and intended: the history is append-only and immutable; the **latest** `response_seq` is
  the authoritative reply, and operators reconciling a feed must treat a non-idempotent outbound's
  re-send as exactly the idempotency hazard the standing invariant already names. We do **not** claim to
  close this window — closing it would require a distributed transaction with the partner, which does not
  exist.
- A new PHI-bearing table, read surface, RBAC permission, audit event, retention branch, and run-context
  provider — surface area in five subsystems, each needing a test.
- The MLLP `_check_ack` refactor touches the **hot ACK path for every MLLP outbound** (capturing or not),
  so the AA/AE/AR/CA/CE/CR + read-failure regression matrix is mandatory, not optional.
- DATABASE capture is constrained to `RETURNING`/`OUTPUT` (no arbitrary second `SELECT`), which is a real
  expressiveness limit for operators on engines/queries without `RETURNING`.
- Increment 2 (re-ingress) re-opens the stage-frozen store surface and needs its own freeze window —
  the orchestration half is not "free" once capture lands.

## Testing strategy (required artifacts)

A task isn't done until these pass (CLAUDE.md §5 — new behavior gets a test):

- **Byte-identical-when-off (regression).** Run the **existing one-way suite unchanged** with the
  capture code present but no outbound configured `capture_response=True`: `send()` returns `None`,
  `mark_done` is called, no `response` row exists, `RunContext.response_view is None`. Proves invariant #3.
- **MLLP ACK matrix + read-failure split.** A parametrized regression over **AA / CA / AE / CE / AR / CR**
  asserting today's classification is preserved for non-capturing outbounds and the capturing-outbound
  outcome mapping, **plus** an explicit **"frame-read-failure still retries"** case (peer-close,
  frame-size-blown, timeout ⇒ `DeliveryError` + retry, **no** `response` row) and a **"frame read but
  MSA unparseable ⇒ `outcome='unparseable'`, row DONE"** case. Distinguishes read-failure from parse-failure.
- **Crash-window re-run.** Inject a fault **between `send()` returning and `complete_with_response`
  committing**; on restart assert the row re-sends and a **second** response row appears with
  `response_seq=N+1` (exactly-one *committed* response per delivery; no partial/duplicate within a run).
- **`response_seq` replay-stability.** `replay` (resets `attempts=0`) then re-delivers ⇒ `response_seq`
  is still monotonic, **no PK collision**, prior rows immutable. Proves the attempts-key rejection.
- **`complete_with_response` XOR `mark_done`.** Assert a capturing delivery never calls both, and a
  non-capturing delivery never writes a `response` row.
- **Wiring-time rejection via `messagefoundry check`.** `File()`/`RemoteFile()` with `capture_response=True`,
  and `Database()` capturing without `RETURNING`, and `Tcp()` capture with `expect_reply=False`, each fail
  `check`/dry-run **without a store**; the `connections.toml` desugar path fails identically.
- **Backend parity.** A Postgres `complete_with_response` test producing an identical `response` row +
  finalization; a **SQL Server "rejected at engine start"** test.
- **Finalizer invisibility.** A message with a `done` outbound **and** a `response` row finalizes to
  `PROCESSED` (the `response` table never appears in `_maybe_finalize_message`'s `GROUP BY`).
- **Retention.** `purge_message_bodies` nulls `response.body`/`detail` in the same transaction for the
  eligible set, keeps the row, never violates the `messages(id)` FK, and is idempotent.
- **RBAC/audit.** `GET /messages/{id}/responses` is deny-by-default, body gated by the raw-body
  permission, and emits a `response.read` audit event.
- **Registration order.** `registered_providers()` returns
  `[code_sets, reference, state, response, environment]` and `response` is transform-phase only.

## Alternatives considered

| Alternative | Why considered | Why rejected | Verdict |
|---|---|---|---|
| **`response` artifact table beside `state`/`reference`** *(chosen)* | Immutable, per-message, invisible to the finalizer; no queue/stage surgery | Residual capture re-run window (made *visible* but not worse than today); new surface in five subsystems | **Adopted (Increment 1)** |
| **Fourth `Stage.RESPONSE` queue row keyed by origin `message_id`** | Reuses the existing queue/claim/recovery machinery | **Fatal:** a pending response row pins the message out of `PROCESSED`; a dead one flips it to `ERROR` — `_maybe_finalize_message`'s `GROUP BY message_id` ([store.py:2848](../../messagefoundry/store/store.py)) corrupts disposition. Breaks count-and-log | **Rejected** |
| **Write the response into the `(namespace,key)` state table (ADR 0005)** | One existing table, existing read-through provider | **Fatal:** the state table *mutates* — a TTL refresh or a later message overwrites the key, so a replay diverges. Violates ADR 0006's non-negotiable immutability rule | **Rejected** |
| **`attempts`-keyed artifact row** | Naturally "one per delivery attempt" | **Fatal:** `replay` does `UPDATE queue SET attempts=0` ([store.py:1830](../../messagefoundry/store/store.py)) → the next delivery's capture collides on the PK / overwrites history. Not replay-stable | **Rejected (→ `response_seq`)** |
| **Capture callback passed into `send(payload, on_response=...)`** | Keeps `send` returning `None`; transport "pushes" the reply to the store | **Fatal:** the callback writes the store from inside `transports/`, inverting the one-way dependency (CLAUDE.md §4: `transports/` never imports `store/`). The transport must stay store-agnostic | **Rejected** |
| **`send` returns `str | None`** | Smallest signature change | The store would re-parse the encrypted body to reconstruct outcome (MSA-1/HTTP status) that the transport already computed; loses the read/parse-failure distinction at the boundary | **Rejected (→ typed `DeliveryResponse`)** |
| **DATABASE capture via a separate post-write `SELECT`** | Works on any backend | Runs **after** `send`'s commit ([database.py:237](../../messagefoundry/transports/database.py)) in a new txn; a crash-re-run re-executes the non-idempotent write and the `SELECT` reads different state. Not re-run-stable | **Rejected (→ `RETURNING`/`OUTPUT` only)** |
| **Re-ingress via a bare `enqueue_ingress` (Increment 2)** | Reuses the existing ingress entry point | `enqueue_ingress` mints a new `uuid4().hex` and consumes no row ([store.py:1062](../../messagefoundry/store/store.py)) → a re-run double-injects the answer | **Rejected (→ atomic `ingress_handoff`)** |
| **Do nothing (keep discarding the reply)** | Zero risk to invariants | Forecloses request/response + ACK-reconciliation feeds central to the Corepoint migration; the reply already exists in the transport and is wasted | **Rejected** |
