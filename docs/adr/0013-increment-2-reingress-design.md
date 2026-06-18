# ADR 0013 — Increment 2 design: re-ingress orchestration

- **Status:** **Accepted (2026-06-14)** — ratified on the owner's "go"; **core built** (Increment 2 of
  [ADR 0013](0013-query-response-orchestration.md), whose Increment 1 is merged). Built in its own worktree
  holding the stage-model freeze (Q8). **Built:** the `Stage.RESPONSE` work-row + lane-key (Q2/Q8), the
  `Loopback()`/`reingress_to=` declaration surface + validation (Q1), the atomic `ingress_handoff` +
  `_response_worker` (Q3/Q8, SQLite + Postgres), loop prevention (Q4), content-type peek (Q5), and the
  run-context `response_view` live feed (Q6). **Deferred to a follow-up (noted in the PR):** the
  per-outbound `OutboxItem.correlation_id` traceability field and the `GET /messages/{id}/chain`
  observability endpoint + console view (Q7) — message-level correlation (`metadata.correlation_id` /
  `correlation_root_id` + the `reingressed`/`received` events) already links the chain; the aggregation
  endpoint and finer-grained per-delivery id are convenience polish, not correctness.
- **Decision in one line:** feed a captured reply back into the pipeline as a **new inbound message** by
  (1) declaring a **no-source loopback inbound** plus an explicit **`reingress_to=` on the capturing
  outbound** (the two are coupled and validated at wiring time — no orphaned captures), (2) having
  `complete_with_response` additionally produce **one `Stage.RESPONSE` work-row** atomically beside the
  immutable `response` artifact when (and only when) `reingress_to` is set, and (3) draining it with a new
  atomic **`ingress_handoff`** — a clone of `route_handoff`'s claim→produce-next→**INFLIGHT-guarded-DELETE**
  that consumes the work-row and produces a content-addressed ingress message+row in **one transaction**,
  so a crash rolls back and a committed run is an idempotent no-op (no double-injection).
- **Related:** [ADR 0013](0013-query-response-orchestration.md) (Increment 1 — the `response` artifact
  table, `complete_with_response`, `correlate_response`, the deferred `ingress_handoff` this details),
  [ADR 0001](0001-staged-pipeline-architecture.md) (the staged queue, the atomic-handoff pattern
  `route_handoff`/`transform_handoff` cloned here, the pure-re-run + count-and-log invariants),
  [ADR 0004](0004-payload-agnostic-ingress.md) (a re-ingressed body re-enters as `Message` *or*
  `RawMessage` by the loopback inbound's `content_type`), [ADR 0007](0007-gui-manageable-connections-toml.md)
  (the `connections.toml` desugar `reingress_to` rides through), [ADR 0009](0009-run-scoped-context-providers.md)
  (the `response` run-context provider this finally feeds), [ADR 0011](0011-timer-scheduled-source.md)
  (the synthetic timer source — re-ingress is *not* a source, contrasted below),
  [ADR 0008](0008-cluster-observability-api.md) / Track B (leader-gating + lane ownership the new stage
  inherits), [ADR 0012](0012-x12-edi-codec.md) (an X12 loopback's `content_type`),
  [CLAUDE.md](../../CLAUDE.md) §2 (reliability + count-and-log invariants — *do not break*).

## Context

Increment 1 made a partner's reply **durable, immutable, per-message state**: a capturing outbound's
`send()` returns a `DeliveryResponse`, and the delivery worker persists it inside the same committed
transaction as `mark_done` via `complete_with_response`
([store/store.py:1748](../../messagefoundry/store/store.py)), into a dedicated immutable `response` table
([store/store.py:459](../../messagefoundry/store/store.py)) keyed `(message_id, destination_name,
response_seq)`. That table is a sibling of `state`/`reference` — **invisible to the finalizer**
`_maybe_finalize_message` ([store/store.py:3054](../../messagefoundry/store/store.py)), which scans
`queue` only — so a captured reply can never pin a message out of `PROCESSED` or flip it to `ERROR`. The
`response` run-context provider ([config/response.py](../../messagefoundry/config/response.py)) is
registered (`code_sets → reference → state → response → environment`,
[config/run_context.py:146](../../messagefoundry/config/run_context.py)) but, in Increment 1, is fed
`None` for every run — there is no path yet by which a Handler reads a real reply.

**Increment 2 adds the second half: route the answer.** Send an eligibility query and route the
eligibility result; POST an order and route the created-resource id; reconcile an application ACK and
route on its MSA. The captured reply re-enters the pipeline as a **new inbound message** so an ordinary
Router/Handler decides where it goes — true request → response → route.

### The central tension — exactly-once re-ingress against a bare `enqueue_ingress`

The obvious implementation is fatal. `enqueue_ingress`
([store/store.py:1157](../../messagefoundry/store/store.py)) mints a fresh `uuid4().hex`
**unconditionally** and **consumes no prior row** — it is the *external-listener* seam, called by
`_handle_inbound` ([pipeline/wiring_runner.py:638](../../messagefoundry/pipeline/wiring_runner.py),
[:679](../../messagefoundry/pipeline/wiring_runner.py)) after a socket read, where at-least-once is the
partner's job (re-deliver) not ours. If Increment 2 called `enqueue_ingress` from a worker draining
captured replies, a **crash-re-run would inject the answer twice** — two inbound messages from one reply.
This is the ADR-0013 review's central finding, and it is the single hardest constraint this design
satisfies. The settled shape (ADR 0013 §"Increment 2") is an **atomic `ingress_handoff`, never a bare
`enqueue_ingress`**: consume a token and produce the ingress rows in **one transaction**, cloning
`route_handoff` ([store/store.py:1280](../../messagefoundry/store/store.py)) / `transform_handoff`'s
([store/store.py:1433](../../messagefoundry/store/store.py)) claim→produce-next→complete +
**INFLIGHT-guarded-DELETE** shape, where a committed run has *deleted* the token (rowcount 0 on a re-run →
`False` → no-op) and an uncommitted one is rolled back and recovered by `reset_stale_inflight`
([store/store.py:1911](../../messagefoundry/store/store.py)). This document pins *what the token is*,
*which transaction deletes it*, *how the new message_id is derived*, and *the exact recovery + lane-key +
stage-model edits* — the parts the sketch deferred.

### The bare-`enqueue_ingress` double-injection trap, stated once

A re-ingress is **not a source.** Routing a captured reply through `_handle_inbound → enqueue_ingress` (or
a synthetic loopback *source* that calls the same listener seam) repeats exactly the trap above: the
listener seam mints a fresh id and consumes nothing, so a crash between "send the reply into the listener"
and "the listener committed it" re-runs and double-injects. Re-ingress **must** be an **internal stage
worker** doing an **atomic handoff** that consumes a durable token. Every alternative that re-uses the
listener seam is rejected in *Alternatives*.

## Decision

Increment 2 is built as five coupled pieces: a **declaration surface** (a loopback inbound + a
`reingress_to=` on the outbound, validated together); a **`Stage.RESPONSE` work-row** produced atomically
with the response artifact; the **atomic `ingress_handoff`**; a **re-ingress worker** that drains the new
stage; and the **stage-model edits + freeze**. Each resolved open question gets a subsection.

### Q1 — Declaration surface: a loopback inbound *coupled to* `reingress_to` on the outbound

The capturing outbound and the re-ingress target are declared **separately but coupled by name**, and
the coupling is **validated at wiring time** so a capturing outbound can never have its replies orphaned
(the central flaw the judges raised against a loopback-inbound-only design).

**A loopback inbound** is an ordinary `inbound(...)` whose transport is a new **`Loopback()`** connector
(`ConnectorType.LOOPBACK`, added to the enum at [config/models.py:21](../../messagefoundry/config/models.py)):
it has **no listening or polling source** — messages arrive *exclusively* via the internal
`ingress_handoff`. It carries a `router`, a `content_type`, and `ack_mode=NONE` (there is no external peer
to ACK), exactly like any other inbound. Its router/handlers are authored code-first; the routing logic
for the answer lives there, not scattered across outbound declarations.

**The capturing outbound names its target** with a new `reingress_to="<loopback inbound name>"` keyword,
which *implies* `capture_response=True` (the factory sets `capture_response=True` whenever `reingress_to`
is non-empty, so you never declare both). This is the decisive coupling: the **outbound declares its
re-ingress intent in one place**, and the wiring validator can prove the target exists. A loopback
inbound with no outbound pointing at it is inert (a wiring warning, below); a `reingress_to` pointing at a
missing or non-loopback inbound is a **wiring error** caught by `messagefoundry check` / dry-run with no
store — the same choke points Increment 1 uses for `capture_response`
(`build_outbound_connection` [config/wiring.py:1364](../../messagefoundry/config/wiring.py) for the
per-connection facts; `build_check_registry` [pipeline/wiring_runner.py:1167](../../messagefoundry/pipeline/wiring_runner.py)
for the cross-registry edge).

Why both surfaces, and why *coupled* (resolving the judges' "two independent surfaces → orphaned
captures" flaw): the loopback inbound owns the *routing of the answer* (a first-class Router/Handler graph,
composable, testable, and reusable across many capturing outbounds); `reingress_to` owns the *intent and
the wiring proof* (this outbound's reply goes there). Neither alone suffices — a flag-only design (`Send`
carrying a re-ingress directive) has nowhere to declare the answer's router/content_type; a
loopback-only design leaves the outbound→inbound edge implicit and un-validatable. Coupling them makes the
edge explicit *and* validated.

**Worked example** (`samples/config/` style):

```python
# loopback inbound — NO source; the answer arrives via ingress_handoff and is routed like any inbound.
inbound(
    "IB_LOOP_ELIG_RESULT",
    Loopback(),
    router="route_elig_result",          # ordinary @router — decides where the eligibility result goes
    content_type=ContentType.HL7V2,      # the reply is HL7 v2 (RSP^K11); a Message reaches the handler
    ack_mode=AckMode.NONE,               # implied/forced by Loopback(); no peer to ACK
)

# capturing outbound — declares BOTH "capture" and "where the reply re-enters" in one place.
outbound(
    "OB_PAYER_ELIG_QUERY",
    Mllp(host=env("payer_host"), port=2575, reingress_to="IB_LOOP_ELIG_RESULT"),
)

# the QUERY handler (on some real inbound) Sends the eligibility query to OB_PAYER_ELIG_QUERY;
# its captured reply is re-ingressed into IB_LOOP_ELIG_RESULT and routed by route_elig_result.
```

#### `connections.toml` desugar (ADR 0007) — `reingress_to` is a `[settings]` field, not a top-level key

`reingress_to` lives on the **connector factory** (`Mllp`/`Tcp`/`Rest`/`Soap`/`Database`), exactly beside
`capture_response`, and is therefore a per-connector **setting** carried in `spec.settings` — *not* a
top-level outbound key. The desugar path is unchanged in shape (this is the same path `capture_response`
already rides):

1. In `connections.toml`, `reingress_to` appears under the outbound's `[settings]` table
   (`reingress_to = "IB_LOOP_ELIG_RESULT"`), like every other connector kwarg. It is **not** added to
   `_OUTBOUND_KEYS` ([config/connections_file.py:92](../../messagefoundry/config/connections_file.py)),
   whose members are the top-level wiring keys (`retry`/`ordering`/…); `[settings]` keys are validated by
   the factory, not that frozenset.
2. `_build_spec` ([config/connections_file.py:188](../../messagefoundry/config/connections_file.py))
   `parse_env_setting`-decodes the `[settings]` table and calls the transport factory with it
   (`factory(**settings)`), so the factory normalizes `reingress_to` into `spec.settings["reingress_to"]`
   identically to a code-first `Mllp(reingress_to=…)`. A typo'd factory kwarg already fails loud there
   ("the factory IS the schema", [connections_file.py:204](../../messagefoundry/config/connections_file.py)).
3. `_outbound_from_table` ([config/connections_file.py:163](../../messagefoundry/config/connections_file.py))
   calls the **same** `build_outbound_connection`, so the per-connection `reingress_to` validation runs on
   the TOML path with no extra code; the cross-registry check runs later in `build_check_registry` over the
   assembled `registry` (it sees TOML- and code-first-declared connections identically).

So a single `spec.settings["reingress_to"]` is the one normalized form both authoring surfaces produce,
and both validators read it from there.

#### The cross-registry validation (in `build_check_registry`)

`build_outbound_connection` is **pure and registry-blind** (it "does not touch the active registry",
[config/wiring.py:1348](../../messagefoundry/config/wiring.py)), so it can only enforce per-connection
facts (capture-valid transport, `reingress_to` is a non-empty string). The **cross-registry** facts —
*does `reingress_to` name an existing inbound, and is that inbound a `Loopback`?* — are enforced in
`build_check_registry` ([pipeline/wiring_runner.py:1167](../../messagefoundry/pipeline/wiring_runner.py)),
which already iterates **both** `registry.inbound` and `registry.outbound` and is the offline choke point
`messagefoundry check` / the `connection` CLI / `RegistryRunner.build_check`
([pipeline/wiring_runner.py:471](../../messagefoundry/pipeline/wiring_runner.py)) all funnel through. Add,
inside its existing `for oc in registry.outbound.values()` loop, a `reingress_to` arm:

- **per-connection** (`build_outbound_connection`, beside the `capture_response` block at
  [config/wiring.py:1364](../../messagefoundry/config/wiring.py)): `reingress_to`, when set, forces
  `spec.settings["capture_response"] = True` and re-runs the **same** capture-validity guards (so a
  `reingress_to` on FILE/REMOTEFILE fails with the existing "no synchronous response" error
  [config/wiring.py:1366](../../messagefoundry/config/wiring.py); a `reingress_to` on TCP implies
  `expect_reply=True`; on DATABASE implies a `RETURNING`/`OUTPUT` clause). `reingress_to` must be a
  non-empty string → else `WiringError("outbound {name!r}: reingress_to must be a non-empty inbound name")`.
- **cross-registry** (`build_check_registry`): for each outbound with `spec.settings.get("reingress_to")`,
  look it up in `registry.inbound`; raise `WiringError("outbound {name!r}: reingress_to names
  unknown/non-loopback inbound {target!r}")` if it is absent or its `spec.type is not
  ConnectorType.LOOPBACK`.

Because `build_check_registry` builds **no** connectors against a live store (it constructs-and-discards),
all of this fails at `check`/dry-run with no DB — the Increment-1 guarantee preserved.

#### Loopback inbound guards (in `build_inbound_connection`)

The loopback inbound's facts are enforced in `build_inbound_connection`
([config/wiring.py:1199](../../messagefoundry/config/wiring.py)) — the shared core of `inbound()` and the
TOML loader, so both authoring surfaces enforce them — extending its existing `listens`/`bind_address`
guards ([config/wiring.py:1252](../../messagefoundry/config/wiring.py)):

- `Loopback` is **not** in the `listens` set (MLLP/TCP), so the existing guard already rejects
  `bind_address`/`source_ip_allowlist` on it; add `ConnectorType.LOOPBACK` to the `strict`-rejection path
  too (no socket, no untrusted intake → strict is meaningless), reusing the same `WiringError` shape as the
  non-HL7-strict guard at [config/wiring.py:1247](../../messagefoundry/config/wiring.py).
- **`ack_mode` is forced/checked to `NONE`** in `build_inbound_connection`: when `spec.type is
  ConnectorType.LOOPBACK`, an unset `ack_mode` **defaults to `AckMode.NONE`** (override the
  `ack_mode=AckMode.ORIGINAL` default for this connector type) and a **set, non-`NONE`** value is a
  `WiringError("inbound {name!r}: Loopback() takes no ACK (no external peer) — ack_mode must be NONE")`
  (a loud error, not a silent override). This is the same layer that already rejects `ack_after=delivered`
  ([config/wiring.py:1232](../../messagefoundry/config/wiring.py)).
- A loopback inbound with **no** capturing outbound pointing at it is **legal but logged** at start
  ("loopback inbound `IB_LOOP_…` has no `reingress_to` source; it will never receive a message") — inert,
  not an error (it may be a staging artifact), but visible.

#### The `Loopback` transport (a deliberately inert source)

`LoopbackSource(SourceConnector)` ([transports/loopback.py](../../messagefoundry/transports/loopback.py),
new, `register_source(ConnectorType.LOOPBACK, LoopbackSource)` mirroring
[transports/timer.py:144](../../messagefoundry/transports/timer.py)) is a no-op source whose `start(...)`
records the handler and returns, and whose run loop never fires. It sets `polls_shared_resource = False`
(contrast `TimerSource.polls_shared_resource = True` at [transports/timer.py:38](../../messagefoundry/transports/timer.py)):
it reads no shared external resource, so there is **nothing to leader-gate at the source** — re-ingress is
leader-gated at the *worker* (Q8). It exists only to satisfy the source-registry contract so
`_start_inbound_unsafe` ([pipeline/wiring_runner.py:265](../../messagefoundry/pipeline/wiring_runner.py))
can build the loopback inbound like any other (and so its router/transform/response workers spawn). A unit
test asserts the handler is **never** invoked (the copy-paste-footgun guard — re-ingress must *never* flow
through the source/listener seam).

### Q2 — The work-row model: a drainable `Stage.RESPONSE` row beside the immutable artifact

Increment 1's `response` table is an **immutable artifact**, *not* a queue stage — by design, so the
finalizer never sees it. But re-ingress needs a **drainable, claimable, recoverable** unit of work, which
is exactly what a `queue` row is. So Increment 2 introduces a **fourth `Stage` value, `Stage.RESPONSE`**
([store/store.py:66](../../messagefoundry/store/store.py)), and the artifact and the work-row **coexist**:
the artifact is the immutable record of *what the partner said*; the work-row is the **transient token**
that says *this reply still owes a re-ingress*.

```python
class Stage(str, Enum):
    INGRESS  = "ingress"
    ROUTED   = "routed"
    OUTBOUND = "outbound"
    RESPONSE = "response"   # NEW: a drainable "this reply owes a re-ingress" token (Increment 2)
```

**`complete_with_response` gains one parameter and one conditional INSERT.** Its current signature
([store/store.py:1748](../../messagefoundry/store/store.py)) takes `(outbox_id, *, body, outcome, detail,
now)`; add **`reingress_to: str | None = None`**, threaded by the delivery worker from the outbound
connection's `spec.settings.get("reingress_to")` (at the capture branch
[pipeline/wiring_runner.py:806](../../messagefoundry/pipeline/wiring_runner.py)). When `reingress_to is
None` the method is **byte-identical to Increment 1** (no work-row). When it is set, after the existing
`INSERT INTO response` ([store/store.py:1798](../../messagefoundry/store/store.py)) and **before** the
single commit ([store/store.py:1820](../../messagefoundry/store/store.py)), it also inserts the work-row in
the *same* `BEGIN…COMMIT` (the explicit transaction Increment 1 already opened at
[store/store.py:1774](../../messagefoundry/store/store.py)):

```sql
-- only when reingress_to is set (else byte-identical to Increment 1):
INSERT INTO queue
  (id, message_id, stage, channel_id, destination_name, handler_name,
   payload, status, attempts, next_attempt_at, created_at, updated_at)
VALUES
  (:work_id, :origin_message_id, 'response', :reingress_to /* loopback inbound */, NULL, NULL,
   :artifact_ref_enc, 'pending', 0, :now, :fifo_created_at, :now);
```

The relationship is **one-way: the work-row references the artifact, never the reverse.**

- `channel_id` = the **loopback inbound name** (from `reingress_to`). This is the lane key (Q8): a
  `Stage.RESPONSE` row's `destination_name` is **NULL**, exactly like ingress/routed rows, so it keys by
  `channel_id` in `claim_next_fifo`. `fifo_created_at` is computed with the existing FIFO clamp for the
  loopback lane — `await self._fifo_created_at("response", "channel_id", reingress_to, now)`
  ([store/store.py:1073](../../messagefoundry/store/store.py)) — so replies into one loopback inbound keep
  monotonic FIFO order even across an NTP step-back (the same clamp ingress/routed rows get).
- `message_id` = the **origin** message id (the request that produced the reply). The work-row therefore
  groups under the original message in `ix_queue_message` — and because it is at `stage='response'`, the
  finalizer's `GROUP BY stage,status` *does* see it. **This is intended and required** (Q7): a
  still-pending RESPONSE row legitimately keeps the **origin** message out of `PROCESSED` until its reply
  has been handed off, and a dead RESPONSE row (depth-cap breach, Q4) flips the origin to `ERROR`. The
  origin's disposition now honestly reflects "the answer still owes a route." This is *not* the Increment-1
  hazard the artifact table avoided (a delivered reply pinning a message) — it is a real outstanding unit
  of work on the origin message, and finalizing it via the normal handoff (which deletes the row) is
  correct.
- `payload` = `:artifact_ref_enc` — **Option A (reference), adopted** over storing the body again. The
  artifact's composite PK is encoded as one opaque string `f"{message_id}\x1f{destination_name}\x1f
  {response_seq}"` and **encrypted exactly like any payload** via `self._enc(...)`
  (the same helper `complete_with_response` uses for `body`/`detail`,
  [store/store.py:1806](../../messagefoundry/store/store.py)); the re-ingress worker reads it back and
  `self._cipher.decrypt(...)`s it inside `ingress_handoff`'s transaction (Q3 step 1). The artifact remains
  the single authoritative immutable copy of the body; the work-row stays a small token; and the worker's
  "read the prior stage's data, then produce the next stage" mirrors `route_handoff` exactly. (This is why
  the ref is a payload, not a join: it survives unchanged through the same cipher path as everything else,
  and the body is read from the artifact, never re-encrypted into the token.)

**Orphan-free production** (resolving the judges' "work-row orphaned if `complete_with_response` crashes
between artifact INSERT and work-row INSERT"). Both INSERTs are in the **same** `BEGIN…COMMIT` Increment 1
already established (explicit transaction under `self._lock`). There is no window between them: either the
commit lands (artifact **and** work-row durable) or it rolls back (neither). The "orphaned artifact with no
work-row" case cannot occur for a `reingress_to` outbound, because the work-row is produced in the same
atomic act as the artifact — not by a later scan. (The pre-existing residual window is unchanged: a crash
*before* `complete_with_response` commits re-sends and produces a *new* `response_seq` **and** its own
work-row on the retry — at-least-once, not zero, never two committed re-ingresses; see Q3.)

### Q3 — The atomic `ingress_handoff` transaction + idempotent-re-run argument

`ingress_handoff` is the **only** re-ingress path. It clones `route_handoff` exactly: the worker claims the
work-row INFLIGHT (via the normal `claim_next_fifo(stage='response')`) and **peeks** the body for the
loopback's `content_type` (Q5), then calls `ingress_handoff`, which in one transaction
**consumes-the-token-by-DELETE-guarded-on-INFLIGHT** + produces the ingress message+row. New store method
(the peek-derived fields are passed **in** so the store stays parsing-free — Q5):

```python
async def ingress_handoff(
    self,
    *,
    response_row_id: str,             # the claimed Stage.RESPONSE work-row (status=INFLIGHT)
    loopback_channel_id: str,         # the work-row's channel_id (the loopback inbound)
    correlation_depth_cap: int,       # max_correlation_depth (Q4)
    control_id: str | None,           # peek-derived (HL7V2) or None (non-HL7 / peek_failed)
    message_type: str | None,         # peek-derived, or the content_type value for non-HL7
    summary: str | None,              # peek-derived, or None
    peek_failed: bool = False,        # an HL7V2 loopback body that would not Peek.parse
    now: float | None = None,
) -> bool:
    """Consume one INFLIGHT Stage.RESPONSE work-row and produce the re-ingressed message+ingress row
    in ONE transaction (clone of route_handoff). Returns True if this call performed the handoff,
    False if it was a committed-and-gone no-op (idempotent re-run)."""
```

**Exact transaction** (SQLite shown; Postgres mirrors the *same single boundary* — Q8):

```sql
BEGIN;
  -- 1. Read the work-row (must still be INFLIGHT — the claim set it so). It carries the artifact ref.
  SELECT message_id AS origin_id, channel_id, payload AS artifact_ref_enc
    FROM queue WHERE id = :response_row_id AND stage='response' AND status='inflight';
  -- Python: artifact_ref = self._cipher.decrypt(artifact_ref_enc); split on \x1f ->
  --         (origin_msg_id, dest, response_seq).  (Same cipher path as every payload read.)

  -- 2. Read the IMMUTABLE artifact body (same committed bytes on every re-run -> re-run-stable).
  SELECT body, outcome FROM response
    WHERE message_id=:origin_msg_id AND destination_name=:dest AND response_seq=:seq;
  -- Python: body = self._cipher.decrypt(body) if body is not None else ''.   (body IS NULL only if
  -- retention purged it; Q8 proves an outstanding work-row makes the message purge-INELIGIBLE, so in
  -- practice body is always present here; the NULL branch is defensive: treat as empty, still consume.)

  -- 3. Read the ORIGIN's correlation lineage from messages.metadata (absent keys -> 0 / self).
  SELECT metadata FROM messages WHERE id = :origin_id;
  --   parent_depth = metadata.get('correlation_depth', 0);  child_depth = parent_depth + 1
  --   root = metadata.get('correlation_root_id') or origin_id      -- origin is its own root if unset
  -- If child_depth > correlation_depth_cap: DO NOT produce a message. Instead, in THIS txn:
  --   UPDATE queue SET status='dead', last_error=:enc('correlation depth exceeded (n > cap)'),
  --                    next_attempt_at=:now, updated_at=:now WHERE id=:response_row_id;
  --   INSERT message_events(origin_id, 'dead', :dest, :enc('reingress depth cap'), :now);
  --   _maybe_finalize_message(origin_id, now)  -- the dead row flips origin to ERROR (Q4)
  --   COMMIT; return True   -- token consumed (must not re-loop); no child created.

  -- 4. Derive the new message id, CONTENT-ADDRESSED from the artifact (defense-in-depth, below):
  --    new_mid = sha256(b"reingress:" + origin_id + b":" + dest + b":" + str(seq) + b":" + body)
  --                .hexdigest()[:32]            -- 32 hex chars, matching the uuid4().hex id convention
  SELECT 1 FROM messages WHERE id = :new_mid;    -- defense-in-depth pre-check; see argument below

  -- 5. INSERT the re-ingressed message (RECEIVED; correlation metadata stamped). Skipped iff step-4
  --    pre-check found :new_mid already present (a partial prior run produced it):
  INSERT INTO messages
    (id, channel_id, raw, status, control_id, message_type, source_type, summary, metadata, error,
     received_at)
  VALUES
    (:new_mid, :loopback_channel_id, :enc_body, :status, :control_id, :message_type,
     'reingress', :summary, :child_metadata_json, :error, :now);
  --   status   = 'error' if peek_failed else 'received'   -- count-and-log: RECEIVED then ERROR, see Q5
  --   error    = 'reingress body failed HL7 peek' if peek_failed else NULL
  --   child_metadata_json = json({**origin_metadata-carried-keys-as-needed,
  --                               'correlation_id':      origin_id,
  --                               'correlation_root_id': root,
  --                               'correlation_depth':   child_depth,
  --                               'reingress_of_seq':    seq})

  -- 6. INSERT the ingress queue row (Stage.INGRESS) UNLESS peek_failed (an ERROR message owes no work):
  --    fifo_created_at = _fifo_created_at('ingress', 'channel_id', loopback_channel_id, now)
  INSERT INTO queue
    (id, message_id, stage, channel_id, destination_name, handler_name,
     payload, status, attempts, next_attempt_at, created_at, updated_at)
  VALUES
    (:ingress_row_id, :new_mid, 'ingress', :loopback_channel_id, NULL, NULL,
     :enc_body, 'pending', 0, :now, :fifo_created_at, :now);

  INSERT INTO message_events (message_id, ts, event, detail)
    VALUES (:new_mid, :now, 'received', :enc('reingress from <origin_id>/<dest>/seq<seq>'));
  INSERT INTO message_events (message_id, ts, event, destination, detail)
    VALUES (:origin_id, :now, 'reingressed', :dest, :enc('-> <new_mid> depth <child_depth>'));

  -- 7. CONSUME THE TOKEN — the synchronization point. DELETE guarded on INFLIGHT (clone route_handoff):
  DELETE FROM queue WHERE id = :response_row_id AND stage='response' AND status='inflight';
  --    rowcount 1 -> this call did the handoff;  rowcount 0 -> already consumed -> ROLLBACK, return False.

  -- 8. The origin message may now finalize (its last outstanding RESPONSE row is gone):
  --    _maybe_finalize_message(origin_id, now)   -- same single-authority finalizer, in this txn.
COMMIT;
```

`message_type` for an HL7V2 loopback is the peek's `message_type`; for a non-HL7 loopback it is the
`content_type` value (e.g. `"x12"`), byte-for-byte matching `_handle_inbound`'s non-HL7 branch
([pipeline/wiring_runner.py:642](../../messagefoundry/pipeline/wiring_runner.py)).

**Why this is exactly-once (the idempotency argument the judges demanded, resolving "consumed-check inside
the same txn → double-injection").** The judges' fatal against the *flag-on-the-artifact* designs was
correct: a `consumed=true` flag *read* at the top of a transaction does **not** prevent a re-run from
re-INSERTing, because a crash mid-transaction rolls back *both* the INSERT and the flag, so the re-run sees
`consumed=false` and produces a *second* message with a *fresh* `uuid4()`. This design closes that two
ways, and **(1) alone is sufficient**:

1. **The token is the work-row's existence, consumed by a guarded DELETE in the *same* transaction that
   produces the message (step 7).** Atomicity makes "message produced" and "token gone" a single durable
   fact: either the commit lands (message exists **and** the work-row is deleted) or it rolls back
   (neither). On a crash before commit, `reset_stale_inflight` reverts the still-present work-row
   INFLIGHT→PENDING; the worker re-claims and re-runs; step 7's DELETE again matches the (still-present)
   row → the *single* message is produced and the row deleted. On a crash *after* commit, the work-row is
   **gone**, so the worker never re-claims it — there is no second run to guard. This is byte-for-byte the
   `route_handoff`/`transform_handoff` guarantee (ADR 0001), which the engine already relies on for
   ingress→routed→outbound. The `consumed`-flag designs failed precisely because the flag was *not* the
   claimed row whose deletion is the commit; the **work-row is**, so there is no separate flag to skew.

2. **Defense-in-depth: the new `message_id` is content-addressed** (`sha256(b"reingress:" + origin_id +
   dest + seq + body).hexdigest()[:32]` — a 32-hex-char id, the same width as the `uuid4().hex` ids
   `enqueue_ingress` mints, so it slots into `messages.id`/`queue.message_id` with no schema change). The
   step-4 pre-check is **not a race guard** (Q8 proves a single lane-owner means no two workers ever hold
   the same token), and it is **not** the primary exactly-once mechanism — the guarded DELETE is. Its only
   job is to make a re-run after a *rolled-back partial* idempotent: on such a re-run the pre-check sees the
   partially-produced `:new_mid` (if the crash was *after* the message INSERT but *before* the DELETE
   commit) and skips steps 5–6, then step 7's DELETE consumes the still-present token — so the whole
   operation collapses to "consume the token, produce nothing new," exactly once. Because the artifact body
   is immutable, `new_mid` is **stable across re-runs of the same reply**. A genuinely *different* reply (a
   non-idempotent partner re-send producing `response_seq=N+1` after the residual crash window of Q2) is a
   *different* artifact → a *different* `new_mid` → a legitimately distinct re-ingress — the correct, honest
   behavior (the partner really did answer twice). Content-addressing therefore can never *be* the consume
   gate (a second real reply *should* get a new id); it is strictly belt-and-suspenders on top of the
   token DELETE.

**No second worker can race it.** The re-ingress worker is a **single owner** per loopback lane (one
worker, leader-gated in a cluster — Q8), and the claim is the atomic `claim_next_fifo` INFLIGHT update
under `self._lock`. Two workers cannot both hold the same work-row INFLIGHT; the guarded DELETE is the
serialization point regardless.

### Q4 — Loop prevention: a `correlation_depth` cap, not cycle detection

Re-ingress can loop (A's reply routes a Send to B, B's reply re-ingresses, routes a Send back to A…).
Prevention is a **depth cap**, deliberately **coarse** — it bounds *total work*, not *topology*.

- **The `messages.metadata` correlation schema** (a JSON object, the field `_handle_inbound`/`enqueue_ingress`
  already write per message) carries four keys on a re-ingressed child, stamped by `ingress_handoff` step
  5: `correlation_id` (the **origin** message id — the immediate parent that produced this reply),
  `correlation_root_id` (the **first ancestor**'s id — `origin_metadata.correlation_root_id` if the origin
  is itself a re-ingress, else the origin's own id, so the whole chain shares one root), `correlation_depth`
  (the int below), and `reingress_of_seq` (which `response_seq` of the origin this child came from). A
  normal (non-re-ingressed) inbound has **none** of these keys.
- **Depth.** A normal inbound message has no `correlation_depth` key ⇒ treated as **0** (Increment-1
  messages unchanged). `ingress_handoff` reads `parent_depth` from the **origin** message's metadata (step
  3) and stamps `child_depth = parent_depth + 1`.
- **The cap** is a **service setting** (`[pipeline] max_correlation_depth`, default **8**), validated at
  load. It is enforced **inside `ingress_handoff`** (step 3), *before* producing the child: if `child_depth
  > cap`, the handoff **dead-letters the RESPONSE work-row** (`status='dead'`,
  `last_error="correlation depth exceeded (<n> > <cap>)"`) **in the same transaction**, finalizes the
  origin (the dead row flips it to `ERROR`), commits, and returns `True` (the token is consumed — it must
  not re-loop). No child message is created. The breach is logged (TYPE + ids only, never the body) and an
  `AlertSink` notification fires (it is a real `ERROR` disposition the operator must see).
- **Why depth, not cycle detection:** cycle detection needs a visited-set traversal that is hard to make
  re-run-stable and false-positives on legitimate request→response→request chains (ask B *because of* A's
  answer is not a loop). The cap is computed purely from immutable parent metadata, so it is re-run-stable
  by construction. Two outbounds whose replies feed each other still oscillate up to the cap — stated
  plainly so operators don't mistake it for topology detection.
- **Tuning guidance** (ships in `docs/CONFIGURATION.md`): `max_correlation_depth` is the longest chain in
  hops. Real healthcare query/response chains are short — a query → response → derived send → response
  typically stays under 3; set the cap to **N+1** where N is the deepest legitimate chain you wire. Watch
  the AlertSink for depth-breach events: a sudden burst means a loop (tune *down* / fix the wiring), a
  steady trickle on a deep legitimate feed means the cap is too low (tune *up*). The default 8 is generous
  headroom over typical healthcare depth while still bounding a runaway to a small constant.

### Q5 — `content_type` + body selection for the re-ingressed message

- **`content_type` is inherited from the *loopback inbound's* declaration**, never from the origin
  outbound. The same HL7V2 capturing outbound can feed an HL7V2 loopback (parse → `Message`) or, for an
  opaque relay, an `X12`/`TEXT` loopback (no structured parse → `RawMessage`). The re-ingressed message
  routes through that loopback's normal router/transform path.
- **Body is verbatim `response.body`.** The transport already decoded the reply once at capture (MLLP
  `_read_ack` → str, HTTP response → str, DB `RETURNING` → JSON str). The re-ingressed message's `raw` is
  that body, read back from the immutable artifact in `ingress_handoff` step 2 — **no second transport
  decode** (there is no socket).
- **Re-ingress skips the *listener* decode/NAK seam but applies the loopback inbound's *content* contract.**
  The listener `_handle_inbound` ([pipeline/wiring_runner.py:601](../../messagefoundry/pipeline/wiring_runner.py))
  does three things: charset-decode (already done — skip), build/return an ACK (no peer — skip), and HL7
  peek/strict-validate for `content_type=hl7v2`. Re-ingress reproduces only the **peek**, and does so in
  the **re-ingress worker** (`pipeline/`, which already imports `parsing`), not in the store — exactly as
  `_handle_inbound` peeks via `Peek.parse` ([pipeline/wiring_runner.py:650](../../messagefoundry/pipeline/wiring_runner.py))
  *before* calling `enqueue_ingress` with the derived `control_id`/`message_type`/`summary`
  ([pipeline/wiring_runner.py:682](../../messagefoundry/pipeline/wiring_runner.py)). This keeps the store
  parsing-free and the `pipeline → parsing` dependency direction intact (CLAUDE.md §4):
  - **HL7V2 loopback:** the worker runs `Peek.parse(body)`. On success it passes
    `control_id=peek.control_id`, `message_type=peek.message_type`, `summary=summarize(peek) or None`,
    `peek_failed=False` into `ingress_handoff`. On `HL7PeekError` it passes `peek_failed=True` (and
    `control_id=message_type=summary=None`); `ingress_handoff` then produces an **ERROR** re-ingressed
    message (RECEIVED→ERROR, step 5 `status='error'`) and **no** ingress row (step 6 skipped) — count-and-log
    holds (the re-ingressed message is recorded and dispositioned `ERROR`, never accepted-and-dropped), and
    the token is still consumed (step 7) so the work never re-loops.
  - **X12 loopback** (`content_type=x12`, ADR 0012): no HL7 peek (it is relayed opaquely as a `RawMessage`).
    The worker passes `control_id=None`, `message_type="x12"`, `summary=None`, `peek_failed=False`; the body
    is byte-verbatim. (X12 framing/parse is the Handler's job on a `RawMessage`, exactly as for a real X12
    inbound — re-ingress does **not** ISA/IEA-validate, mirroring how a real X12 inbound relays opaquely.)
  - **Any other non-HL7 loopback** (`TEXT`/`json`/…): identical to the X12 case — verbatim body,
    `control_id=NULL`, `message_type=<content_type>`, `summary=NULL` — matching `_handle_inbound`'s non-HL7
    branch ([pipeline/wiring_runner.py:634](../../messagefoundry/pipeline/wiring_runner.py)).
- **Strict hl7apy validation is *not* re-run on re-ingress.** Strict validation is the **untrusted-socket**
  intake gate; a captured reply is internal state we already stored, and a `Loopback()` inbound declares no
  `strict` (rejected at wiring, Q1). Re-running it would add CPU on a hot path and could dead-letter a
  legitimately-stored reply on a profile mismatch.

### Q6 — Run-context correlation: live feeding of the `response` provider

A re-ingressed answer's Handler often needs the **original request's** captured reply (e.g. to stitch the
eligibility result onto the original query's context). Increment 1 built the seam and fed it `None`;
Increment 2 feeds it **live, per re-ingressed message**, using the *existing* accessor — no new surface.

- **What is published.** The `response` provider activates `RunContext.response_view`
  ([config/run_context.py:71](../../messagefoundry/config/run_context.py)) as a **`Mapping[str, Any]`**
  (`ResponseView`, [config/response.py:40](../../messagefoundry/config/response.py)) — `{destination_name:
  latest_reply}`. `response_get(dest, default)` ([config/response.py:70](../../messagefoundry/config/response.py))
  reads it **synchronously** (`view.get(dest, default)`), already shaped to "the latest reply per
  destination". So the live feed is a **plain dict**, not a callable — it matches the Increment-1
  `ResponseView` contract exactly and needs no accessor change.
- **How it is built.** The transform worker, when the claimed item's message is a **re-ingressed** one
  (its `messages.metadata.correlation_id` is set), reads the **origin's** committed replies once via
  `correlate_response(correlation_id)` ([store/store.py:1825](../../messagefoundry/store/store.py)) and
  collapses them to `{r.destination_name: r}` keeping the **highest `response_seq` per destination** (the
  authoritative reply — `correlate_response` already orders by `destination_name, response_seq`, so the
  last per destination wins). That dict is the `response_view` passed at the transform call site
  ([pipeline/wiring_runner.py:990](../../messagefoundry/pipeline/wiring_runner.py)) — the **only** edit
  there is adding `response_view=<the dict or None>` to the `RunContext(...)` constructor (the run-context
  registry handles activation; "features add one provider/field, never edit the call site" — but the
  *value* of an existing field is supplied here, exactly like `state_view=self.store.state_view()` already
  is). The decrypt happens once when the dict is built (the worker is async and can await
  `correlate_response`), so `response_get` stays synchronous and the per-message read is one bounded query;
  the dict's small size (one entry per destination the origin hit) needs no further caching.
- **For a normal (non-re-ingressed) message `response_view` stays `None`** (byte-identical to Increment 1 —
  the worker only builds the dict when `metadata.correlation_id` is present), so `response_get` returns its
  default and the seam is unchanged.
- **Re-run-stable by construction.** The view reads only the **immutable committed** `response` rows
  (ADR 0009); a re-run reads identical values. And it reads only the origin's *prior committed* replies —
  never the re-ingressed message's *own* future replies — preserving ADR 0013's rule that a transform never
  reads a reply being produced in the same run.

### Q7 — Disposition + observability of the original → response → re-ingress chain

- **Count-and-log holds.** The re-ingressed message is a **new** `messages` row with its own
  `RECEIVED → disposition`, routed/finalized by the *same* finalizer authority. Nothing is
  accepted-and-dropped: a body that fails the loopback's HL7 peek is `ERROR` on the new message (Q5); a
  depth-cap breach is `ERROR` on the **origin** (its dead RESPONSE row, Q4). The origin reaches `PROCESSED`
  only **after** its RESPONSE work-row is handed off (the row is gone) **and** every other origin row is
  terminal — so an outstanding re-ingress correctly holds the origin "in flight," which is the truthful
  disposition.
- **Phantom inbound volume is a bug, and is excluded.** A re-ingressed message is counted on the
  **loopback inbound's** channel, not on any real socket inbound, and it exists **iff** a handoff committed
  (exactly-once, Q3). No double-injection ⇒ no phantom volume.
- **Chain linkage for operators.** A new store read `correlate_chain` + an API endpoint expose the chain:

  - **Store:** `async def correlate_chain(self, message_id: str) -> CorrelationChain`. Algorithm: (a)
    resolve the **root** = `get_message(message_id)` ([store/store.py:2176](../../messagefoundry/store/store.py))
    then its `metadata.correlation_root_id` (or `message_id` itself if unset); (b) the **request** = the
    root message summary + its `correlate_response(root_id)` captured replies
    ([store/store.py:1825](../../messagefoundry/store/store.py)); (c) the **re-ingress children** = a
    bounded tree-walk from the root following `metadata.correlation_id = <node id>` (one query per level,
    capped by `max_correlation_depth`, so the walk is **finite by the same cap** that bounds the chain — no
    unbounded recursion). Returns a `CorrelationChain` dataclass: `{root_id, request: MessageSummary,
    responses: list[CapturedResponse], reingress: list[ReingressNode]}` where `ReingressNode =
    {message_id, parent_id, depth, status, channel_id}`. The list is depth-capped, so it is intrinsically
    bounded (no pagination needed; a future deep-chain page-token is a follow-up if the cap is ever raised
    high).
  - **API:** `GET /messages/{id}/chain` → a `MessageChain` Pydantic model
    ([api/models.py](../../messagefoundry/api/models.py), new; mirrors `MessageResponses`
    [api/models.py:83](../../messagefoundry/api/models.py)) wrapping the request summary, the captured
    `CapturedResponseInfo`s, and the re-ingress nodes. It is added to `api/app.py` **immediately beside**
    the existing `GET /messages/{id}/responses` ([api/app.py:806](../../messagefoundry/api/app.py)) and is
    gated **identically**: bodies only with the raw-body permission (`MESSAGES_VIEW_RAW`), the lighter
    metadata with `messages:read`, and **every access emits the same `response.read` audit event**
    ([api/app.py:827](../../messagefoundry/api/app.py)) with the acting user + `message_id`. No new PHI
    surface is ungated.
  - A `reingressed` `message_event` on the origin and a `received (reingress …)` event on the child
    (written in `ingress_handoff` steps 5/6) make the hop visible in the existing per-message timeline with
    no API change.
- **Console** renders a "Correlation chain" section from `/messages/{id}/chain` (request → captured replies
  → re-ingressed children), each node navigable. No in-process/DB access (it uses the API client).

### Q8 — Failure handling, the `Stage.RESPONSE` lane-key, and the stage-model freeze

**The re-ingress worker.** A new `_response_worker(name)` per loopback inbound, spawned by
`_ensure_inbound_workers` ([pipeline/wiring_runner.py:437](../../messagefoundry/pipeline/wiring_runner.py))
alongside that inbound's router/transform workers — a **loopback inbound gets all three**: its
router/transform drain the *re-ingressed* message; its response worker drains the *Stage.RESPONSE* tokens.
Concretely, extend the `for kind in ("router", "transform")` tuple to include `"response"`, and the
`_inbound_worker_coro`/`_inbound_worker_dict` dispatch ([pipeline/wiring_runner.py:430](../../messagefoundry/pipeline/wiring_runner.py),
[:434](../../messagefoundry/pipeline/wiring_runner.py)) gains a `"response"` arm returning `_response_worker`
and a `self._response_workers` dict — but the `"response"` kind is spawned **only for loopback inbounds**
(guard on `ic.spec.type is ConnectorType.LOOPBACK`; non-loopback inbounds spawn only router+transform, so
they are byte-identical). It is woken by a new per-runner `self._response_work` `asyncio.Event` (a sibling
of `self._ingress_work`/`self._routed_work`), set by `complete_with_response`'s caller after a work-row is
produced and on startup. It mirrors `_router_worker`
([pipeline/wiring_runner.py:826](../../messagefoundry/pipeline/wiring_runner.py)) precisely:

```text
loop until stop:
  item = claim_next_fifo(name, stage='response', owner=self._coordinator.lane_owner())  # FIFO per lane
  if item is None: await self._wait_for_work(self._response_work); continue
  ic = self.registry.inbound.get(name)
  if ic is None:                         # loopback removed by a reload, residual RESPONSE rows remain
      mark_failed(item.id, "inbound not in registry", RetryPolicy())   # retry-FOREVER; exit worker
      return                              # mirrors _router_worker missing-inbound at line 851/859
  control_id, message_type, summary, peek_failed = peek_for_loopback(ic, item.payload)  # Q5, in pipeline/
  ok = await store.ingress_handoff(response_row_id=item.id, loopback_channel_id=name,
                                   correlation_depth_cap=self._max_correlation_depth,
                                   control_id=..., message_type=..., summary=..., peek_failed=...)
  # transient store error anywhere in the body -> caught by the same outer try, log TYPE only,
  # _stop_or_sleep(_WORKER_ERROR_BACKOFF_SECONDS) (== 1.0, pipeline/wiring_runner.py:77), keep going.
```

`_on_inbound_worker_done` ([pipeline/wiring_runner.py:453](../../messagefoundry/pipeline/wiring_runner.py))
respawns it on an unexpected death and leaves it down on a normal return (the missing-inbound exit), exactly
like router/transform.

- **Lane key = `channel_id`.** A `Stage.RESPONSE` row carries NULL `destination_name`, so it keys by
  `channel_id` (the loopback inbound) exactly like ingress/routed — preserving FIFO of replies into a
  loopback. The lane-key is selected in **three** places; the exact edits:
  - **SQLite `claim_next_fifo`** ([store/store.py:1675](../../messagefoundry/store/store.py)):
    ```python
    lane_col = (
        "channel_id"
        if stage in (Stage.INGRESS.value, Stage.ROUTED.value, Stage.RESPONSE.value)  # + RESPONSE
        else "destination_name"
    )
    ```
  - **SQLite `pending_depth`** ([store/store.py:1893](../../messagefoundry/store/store.py)): the identical
    three-line conditional, add `Stage.RESPONSE.value` to the `channel_id` tuple.
  - **Postgres `_lane_col`** ([store/postgres.py:997](../../messagefoundry/store/postgres.py)): the single
    static helper both Postgres `claim_next_fifo` and `pending_depth` call — add `Stage.RESPONSE.value` to
    the `channel_id` tuple once, and both methods inherit it.
- **Stage-generic primitives need *no* code change, only pinning tests.** `_fifo_created_at`
  ([store/store.py:1073](../../messagefoundry/store/store.py)) already takes `lane_col` as a parameter (pass
  `"channel_id"`). `reset_stale_inflight` ([store/store.py:1911](../../messagefoundry/store/store.py)) is
  already `stage=None`-recovers-every-stage. Postgres `reclaim_expired_leases`
  ([store/postgres.py:1809](../../messagefoundry/store/postgres.py)) is already stage-generic (its
  `WHERE … ($2::text IS NULL OR stage=$2)` sweeps all stages; the Track-B lease sweep recovers RESPONSE rows
  with no branch). `_maybe_finalize_message` ([store/store.py:3054](../../messagefoundry/store/store.py))
  already `GROUP BY stage,status` over every queue row, so it sees a RESPONSE row with **no** change (this
  is the *intended* behavior, Q2/Q7). Each is pinned with an assertion test, not edited.
- **Recovery / failure.**
  - *Crash mid-`ingress_handoff`* → rolled back; `reset_stale_inflight` reverts the token to PENDING; the
    worker re-runs; the guarded DELETE makes the second run produce exactly one message (Q3).
  - *Transient store error in `ingress_handoff`* → the whole txn rolls back, token stays INFLIGHT (then
    PENDING on recovery / next claim attempt); the worker backs off (`_WORKER_ERROR_BACKOFF_SECONDS`) and
    retries — at-least-once.
  - *Artifact body purged by retention before re-ingress* (step 2 reads NULL): produce a `no_reply`-bodied
    re-ingress (empty `raw`) and **still consume the token** — never dangle. But this is **prevented by
    ordering, not just tolerated**: `purge_message_bodies` ([store/store.py:2833](../../messagefoundry/store/store.py))
    only nulls bodies for messages with **no `pending`/`inflight` queue row** — and a `Stage.RESPONSE` row
    *is* such a row, so a reply still owing re-ingress makes its message **ineligible for purge**. (Document
    + test: purge cannot null an artifact body whose work-row is outstanding.)
  - *Depth-cap breach* → dead-letter the token, `ERROR` the origin, alert (Q4).
  - *Loopback inbound removed by a reload while RESPONSE rows remain* → `claim_next_fifo` returns rows but
    `self.registry.inbound.get(name) is None`; the worker reverts the claim with a retry-forever policy and
    exits (mirrors the router worker's missing-inbound handling, [pipeline/wiring_runner.py:851](../../messagefoundry/pipeline/wiring_runner.py)–[:859](../../messagefoundry/pipeline/wiring_runner.py));
    a reload restoring the loopback re-arms the worker and drains the backlog. Never dropped.
- **Leader-gating + single ownership.** Re-ingress is an **internal single-owner** stage: the claim is gated
  by `coordinator.lane_owner()` exactly like every other FIFO claim, so on a clustered Postgres store
  exactly one node owns a given loopback lane (Track B Step 5 claim-time lease); single-node passes `None`
  (byte-identical). There is **no** separate "global drainer" and no `is_leader()` gate at the worker — the
  lane-owner claim is the singleton mechanism, consistent with ingress/routed/outbound.
  (`LoopbackSource.polls_shared_resource=False` means no *source*-level leader gate either; correct, because
  there is no source.)

**Backend specifics.**
- **Postgres** mirrors `complete_with_response`'s conditional work-row INSERT and `ingress_handoff` with the
  **identical single-transaction boundary** (`async with conn.transaction()` — the same pattern its
  `route_handoff` [store/postgres.py:1190](../../messagefoundry/store/postgres.py) uses), parameterized
  `$n` placeholders, the same guarded DELETE rowcount semantics (`_rowcount`), and the same content-addressed
  id (computed in Python, not a CTE — the hash inputs are already in hand from the work-row + artifact
  reads). Both backends are tested for exactly-once with crash injection.
- **SQL Server** needs **no new rejection code**: `reingress_to` *implies* `capture_response=True`, and the
  engine **already** fails closed at start for any capturing outbound on a backend with
  `supports_response_capture = False` ([pipeline/wiring_runner.py:330](../../messagefoundry/pipeline/wiring_runner.py)–[:339](../../messagefoundry/pipeline/wiring_runner.py),
  the SQL Server flag at [store/sqlserver.py:181](../../messagefoundry/store/sqlserver.py)). A `reingress_to`
  outbound is a capturing outbound, so it hits that guard and is rejected with the existing clear error. A
  test pins that a `reingress_to` outbound on the SQL Server backend is rejected at start.

**Stage-model freeze (the coordination obligation).** Adding `Stage.RESPONSE` **reopens the stage-frozen
surface** the Increment-1 ADR explicitly kept byte-identical. This is the largest cost. The freeze window is
a single coordinated change that:

1. adds `Stage.RESPONSE` to the enum ([store/store.py:66](../../messagefoundry/store/store.py));
2. adds `Stage.RESPONSE.value` to the `channel_id` arm of `claim_next_fifo`
   ([store/store.py:1675](../../messagefoundry/store/store.py)) **and** `pending_depth`
   ([store/store.py:1893](../../messagefoundry/store/store.py)) on SQLite, and to Postgres `_lane_col`
   ([store/postgres.py:997](../../messagefoundry/store/postgres.py)) (one edit covers both Postgres
   methods);
3. confirms (by assertion test, **no code change**) `_fifo_created_at`, `reset_stale_inflight`,
   `reclaim_expired_leases`, and `_maybe_finalize_message` handle the new stage — pinning that with
   `test_response_stage_lanes_by_channel_id`, `test_reset_stale_inflight_recovers_response`,
   `test_reclaim_expired_leases_recovers_response` (Postgres), `test_finalizer_sees_pending_response_row`;
4. mirrors the lane-key + the two new store methods in **`store/postgres.py`** with the identical
   single-transaction boundary; relies on the **existing** start-time capture guard for **`store/sqlserver.py`**
   (the `supports_response_capture` gate — no new SQL Server code).

No other code may add a `Stage` value in the same window; the freeze is re-applied (the model is frozen
again) once these land and tests pin the lane-key mapping.

**`OutboxItem.correlation_id` is appended as the FINAL field.** Increment 2 threads a correlation id onto
outbound rows produced by a re-ingressed message's handler so an operator can trace *which* request an
outbound delivery ultimately served. `OutboxItem` ([store/store.py:89](../../messagefoundry/store/store.py))
gains `correlation_id: str | None = None` **after** the current last field `created_at`
([store/store.py:106](../../messagefoundry/store/store.py)) to preserve positional construction of the
frozen dataclass. The exact edits:

- **The dataclass** appends the field; **`from_row`** ([store/store.py:108](../../messagefoundry/store/store.py))
  — the **sole** row→`OutboxItem` constructor (it uses keyword args, so adding `correlation_id=row["correlation_id"]`
  is the only hydration edit; an audit confirms no positional `OutboxItem(...)` construction exists
  elsewhere, only `from_row`) — defaults it from the new column.
- **The column** is a nullable `queue.correlation_id` added by an idempotent `_migrate`
  ([store/store.py:949](../../messagefoundry/store/store.py)) ALTER, cloning the **exact** `handler_name`
  pattern at [store/store.py:965](../../messagefoundry/store/store.py)–[:967](../../messagefoundry/store/store.py):
  ```python
  cur = await db.execute("PRAGMA table_info(queue)")
  if "correlation_id" not in {row["name"] for row in await cur.fetchall()}:
      await db.execute("ALTER TABLE queue ADD COLUMN correlation_id TEXT")
  ```
  (idempotent on an existing DB; NULL on every pre-existing row is correct). Postgres adds the column to its
  `queue` DDL the same way it carries `handler_name`.
- It is **plaintext** (an internal message-id link, not PHI), defaults `NULL`, and is byte-identical when
  unused. The `transform_handoff` ([store/store.py:1433](../../messagefoundry/store/store.py)) that produces
  a re-ingressed message's outbound rows stamps `queue.correlation_id` **only when** the routed message's
  `metadata.correlation_id` is set (i.e. the message is itself a re-ingress) — read from the message's
  metadata at the handoff and written onto each produced outbound row; every other producer leaves it `NULL`.
  A test asserts `from_row` tolerates the new column (NULL) and that a re-ingressed message's outbound rows
  carry the id while a normal message's stay `NULL`.

**Coexistence with merged main features.**
- **Timer source** (ADR 0011): a message from **any** source — Timer, MLLP, File, DB-poll — may be routed to
  a handler that `Send`s to a `reingress_to` outbound; the reply re-ingresses into the **loopback** inbound,
  *not* back to the original source. A timer-sourced request producing a loopback child is an explicit test.
- **Message-split** (N `enqueue_ingress` per file): unaffected — split fans *intake* out into N independent
  ingress messages, each of which may independently produce its own captured reply + re-ingress; each child
  is a distinct content-addressed message.
- **X12 / payload-agnostic** (ADR 0004/0012): covered in Q5 — an X12 loopback re-ingresses verbatim as a
  `RawMessage` (no HL7 peek), inheriting the loopback's `content_type`.
- **db-lookup / ingest-time** (other run-context providers, ADR 0009/0010): the `response` provider is the
  registered transform-phase provider Increment 1 already slotted between `state` and `environment`
  ([config/run_context.py:146](../../messagefoundry/config/run_context.py)); Increment 2 only changes the
  *value* fed to it (a real dict for re-ingressed messages), not the registration order — a registration-order
  test still asserts `code_sets → reference → state → response → environment`, and `ingest_time` for a
  re-ingressed message is its own loopback-lane `created_at` (the re-run-stable enqueue time), exactly like
  any ingress row.
- **Operability** (per-connection metadata): a loopback inbound and a `reingress_to` outbound carry the same
  `metadata` surface as any connection (`_check_metadata` already runs in both build functions); nothing
  special-cased.

## Consequences

**Positive**

- **True request → response → route** becomes expressible — the second half of a large slice of the
  Corepoint migration (eligibility, order-status, ACK-driven routing).
- **Exactly-once re-ingress** is a *schema + transaction* property (the guarded-DELETE of the claimed
  work-row), not a discipline — the same guarantee `route_handoff`/`transform_handoff` already provide, plus
  content-addressed defense-in-depth. The bare-`enqueue_ingress` double-injection trap is closed.
- **Byte-identical when no `reingress_to` is declared.** `complete_with_response(reingress_to=None)` writes
  no `Stage.RESPONSE` row; no `_response_worker` is spawned (no loopback inbound exists); `Stage.RESPONSE` is
  inert; `RunContext.response_view` stays `None`; `OutboxItem.correlation_id` stays `NULL`. Increment 1's
  full suite passes unchanged (a required test, with the exact checklist below).
- **The finalizer stays the single disposition authority** — now correctly counting an outstanding
  re-ingress as "origin in flight" because the `Stage.RESPONSE` row is a real `queue` row (the deliberate
  difference from the Increment-1 invisible artifact, and the correct one for work genuinely outstanding).
- **Declaration is explicit and validated**: the outbound→loopback edge is a single `reingress_to=`,
  cross-checked at `check`/dry-run with no store; no orphaned captures, no scattered routing intent. The TOML
  desugar carries it through `[settings]` with no new top-level key.
- The dependency direction is preserved: the store stays parsing-free (the worker peeks and passes fields
  in), and the console reaches the chain only through the API.

**Negative / costs**

- **The stage-model freeze.** `Stage.RESPONSE` reopens the frozen surface; `claim_next_fifo` +
  `pending_depth` (SQLite) and `_lane_col` (Postgres) gain a branch, four more primitives need pinning
  tests, and both backends must move in lockstep. This is fleet-wide coordination, not a local change — it
  needs its own session/worktree and must not race another stage-touching feature.
- **Bigger blast radius than Increment 1.** Increment 1 was table-only; Increment 2 touches the enum, two
  stage-aware claim/depth methods (+ the Postgres helper), the finalizer's *semantics* (an outstanding
  RESPONSE row now holds the origin), the delivery worker (thread `reingress_to`), `complete_with_response`
  (a conditional second INSERT + a new param), a new worker type + wake event, a new connector type + source,
  the wiring validator (per-connection + cross-registry), the run-context live feed, a new API endpoint +
  model, the console, `OutboxItem` + a `queue` column + a migration. Every one needs a test.
- **The residual at-least-once window is inherited, not closed.** A crash after `send()` but before
  `complete_with_response` commits re-sends; a non-idempotent partner returns a *different* reply
  (`response_seq=N+1`) with its *own* work-row → a *second, legitimately distinct* re-ingress. This is the
  standing non-idempotent-outbound hazard the engine already names; re-ingress makes it *visible* (a second
  child message) but no worse. Operators must make capturing-then-re-ingressed outbounds idempotent
  (`MERGE`/natural key) or accept a duplicate answer.
- **Loop prevention is coarse** (depth cap, not cycle detection): mutually-feeding outbounds oscillate up to
  the cap before dead-lettering. Documented as a feature, not a bug.
- **No `ack_after=delivered` interaction** is in scope (still not built); a re-ingressed message ACKs
  nothing (loopback `ack_mode=NONE`).

## Alternatives considered

| Alternative | Why considered | Why rejected | Verdict |
|---|---|---|---|
| **Loopback inbound + `reingress_to` on the outbound; `Stage.RESPONSE` work-row produced atomically with the artifact; atomic `ingress_handoff` (guarded DELETE) + content-addressed id** *(chosen)* | First-class routing of the answer (a real Router/Handler graph), explicit + validated outbound→loopback edge, exactly-once by the proven handoff pattern, work-row never orphaned (same txn as the artifact) | Reopens the stage-model freeze; bigger blast radius; inherits the residual at-least-once window | **Adopted (Increment 2)** |
| **Bare `enqueue_ingress` from a re-ingress worker (or a synthetic loopback *source* calling the listener seam)** | Reuses the existing ingress entry point / source machinery | **Fatal:** `enqueue_ingress` mints a fresh `uuid4()` and consumes no row ([store/store.py:1157](../../messagefoundry/store/store.py)) → a crash-re-run double-injects the answer. A loopback *source* repeats the trap (the listener seam is not idempotent) | **Rejected (→ atomic `ingress_handoff`)** |
| **No work-row; a `consumed=true` flag on the immutable `response` artifact, checked at the top of `ingress_handoff`** | Avoids a fourth `Stage`, keeps the artifact as the only row | **Fatal:** a crash mid-transaction rolls back *both* the message INSERT and the flag, so the re-run reads `consumed=false` and produces a *second* message with a fresh `uuid4()` — the flag is not the claimed row whose deletion is the commit (the judges' central finding against flag designs) | **Rejected (→ guarded-DELETE of a claimed work-row)** |
| **Content-addressed `message_id` as the *primary* exactly-once guard (no work-row token)** | Deterministic id → re-runs collide on PK → "naturally" deduped | The id only dedups the *message INSERT*; it does **not** make "produce the answer" and "consume the reply" one atomic fact, and a non-idempotent partner re-send (different body) *should* produce a new id, so the PK can't be the consume gate. Sound only as **defense-in-depth on top of** the guarded-DELETE token, which is how it is used | **Rejected as primary (→ secondary defense-in-depth)** |
| **Source-based loopback (a `LoopbackSource` that *fires* the captured reply into `_handle_inbound`)** | Symmetry with the timer source ([ADR 0011](0011-timer-scheduled-source.md)) | A source emits into the **listener seam** (`enqueue_ingress`), which is not idempotent and not a handoff → double-injection; and a source has no token to consume. Re-ingress is an **internal stage handoff**, not intake. (`LoopbackSource` exists only as an inert no-op to satisfy the registry, never fires) | **Rejected (→ no-source loopback + internal `ingress_handoff`)** |
| **Outbound flag only (`Send(..., reingress=True)` / a `capture_response` with an inferred default loopback), no explicit loopback inbound** | One declaration site | Nowhere to declare the answer's **router**/**content_type**/**disposition**; routing intent scattered; an inferred loopback is a hidden, untestable inbound | **Rejected (→ explicit loopback inbound, coupled by `reingress_to`)** |
| **Loopback inbound only, with *no* coupling to the outbound** | Maximal decoupling | **Fatal UX:** a capturing outbound's replies can be **orphaned** (no loopback, or the wrong one) with no wiring-time error; the outbound→inbound edge is implicit and un-validatable (the judges' finding against the loopback-only proposal) | **Rejected (→ explicit `reingress_to` coupling, validated at `check`)** |
| **Store the reply *body* in the work-row (not the artifact PK reference)** | One read in `ingress_handoff` | Duplicates the immutable body into a second encrypted blob (two copies to purge, two to keep consistent); the artifact is already the authoritative immutable copy. A small PK reference keeps the work-row a token and the body single-sourced | **Rejected (→ Option A: artifact-PK reference)** |
| **Re-ingress runs strict hl7apy validation like the listener** | Symmetry with untrusted intake | Strict validation is the **untrusted-socket** gate; a captured reply is internal state we already stored. Re-running it adds CPU on the hot path and can dead-letter a legitimately-stored reply on a profile mismatch | **Rejected (peek for metadata; no strict re-validate)** |
| **Defer re-ingress entirely / do nothing** | Zero stage-model risk | Forecloses the *route the answer* half — the whole point of the query/response feature class | **Rejected** |

## Required tests

A task isn't done until these pass (`ruff`, `mypy --strict`, `pytest`; Qt offscreen where relevant):

- **Byte-identical-when-off (regression).** Increment 1's full suite passes unchanged with the Increment-2
  code present but **no** `reingress_to` declared anywhere. "Byte-identical" means **all** of: (1)
  `complete_with_response(reingress_to=None)` writes the `response` artifact and **no** `Stage.RESPONSE`
  work-row; (2) **no** `_response_worker` is spawned (the `"response"` kind is gated on a loopback inbound
  existing); (3) `RunContext.response_view` stays `None` for every normal inbound's transform run; (4)
  `OutboxItem.correlation_id` is `NULL` on every outbound row and `from_row` tolerates the new (NULL) column;
  (5) the run-context registration order is unchanged (`code_sets → reference → state → response →
  environment`). Proves invariant #3.
- **Exactly-once — crash mid-`ingress_handoff`.** Inject a fault between the message INSERT (step 5) and the
  guarded-DELETE commit (step 7); on restart assert `reset_stale_inflight` reverts the token, the worker
  re-runs, and **exactly one** re-ingressed message exists (content-addressed id stable; guarded DELETE
  rowcount-0 on the no-op re-run).
- **Exactly-once — committed run is an idempotent no-op.** Call `ingress_handoff` twice on the same work-row;
  the second returns `False`, writes nothing.
- **No double-injection across many crash-restarts.** A property/loop test: N injected crashes around the
  handoff still yield exactly one committed re-ingress.
- **Work-row produced atomically with the artifact.** A capturing+`reingress_to` delivery writes **both** the
  `response` artifact **and** the `Stage.RESPONSE` row in one transaction; a non-`reingress_to` capturing
  delivery writes the artifact and **no** work-row.
- **Finalizer semantics.** A message with a `done` outbound **and** an outstanding (`pending`)
  `Stage.RESPONSE` row stays out of `PROCESSED`; after `ingress_handoff` consumes the row the origin
  finalizes `PROCESSED`. A depth-cap-breached (`dead`) `Stage.RESPONSE` row flips the origin to `ERROR`.
- **Lane-key + recovery.** `claim_next_fifo(stage='response')` / `pending_depth(stage='response')` key by
  `channel_id` (SQLite + Postgres); `reset_stale_inflight` (SQLite) and `reclaim_expired_leases` (Postgres)
  recover/release INFLIGHT response rows (`test_response_stage_lanes_by_channel_id`,
  `test_reset_stale_inflight_recovers_response`, `test_reclaim_expired_leases_recovers_response`,
  `test_finalizer_sees_pending_response_row`).
- **Loop prevention.** A re-ingress at `depth = cap` succeeds; the next (`cap+1`) dead-letters the token,
  `ERROR`s the origin, fires the AlertSink, creates **no** child. `correlation_depth` absent ⇒ 0;
  `correlation_root_id` propagates (root stable down a 3-hop chain).
- **`content_type` selection.** HL7V2 loopback → re-ingressed `Message` with parsed
  `control_id`/`message_type`/`summary`; a non-peekable HL7 body → child `ERROR` + no ingress row
  (RECEIVED→ERROR, not dropped) + token consumed. X12/TEXT loopback → `RawMessage`, verbatim body, NULL
  control_id, `message_type=<content_type>`.
- **Run-context live feed.** A re-ingressed message's Handler reads the **origin's** captured reply via
  `response_get(dest)` (the latest `response_seq` per destination); a re-run reads the identical value; a
  normal message's `response_view` is `None`.
- **Retention ordering.** `purge_message_bodies` cannot null an artifact body whose `Stage.RESPONSE` work-row
  is still outstanding (the row is `pending`/`inflight` ⇒ the message is ineligible).
- **Wiring-time validation via `messagefoundry check` (no store).** `reingress_to` to an unknown /
  non-loopback inbound fails (in `build_check_registry`); `reingress_to` on FILE/REMOTEFILE fails (in
  `build_outbound_connection`); a `Loopback()` inbound with `bind_address`/`strict`/`ack_mode≠NONE` fails (in
  `build_inbound_connection`); a `Loopback()` inbound with unset `ack_mode` defaults to NONE; the
  `connections.toml` desugar (`reingress_to` in `[settings]`) fails identically; a loopback inbound with no
  `reingress_to` source logs (not errors).
- **Backend parity.** A Postgres `complete_with_response(reingress_to=…)` + `ingress_handoff` producing
  identical rows and exactly-once behavior; a **SQL Server "rejected at engine start"** test for a
  `reingress_to` outbound (hits the existing `supports_response_capture` guard).
- **Coexistence.** A **timer-sourced** request routed to a `reingress_to` outbound produces a
  loopback-sourced child (not a timer child). A **message-split** file whose children each capture+re-ingress
  yields N distinct children.
- **Observability.** `GET /messages/{id}/chain` returns root→request→responses→reingress, body-gated +
  `response.read`-audited (same as `/responses`); the origin's `reingressed` and the child's `received
  (reingress …)` events exist; the chain walk is finite (depth-capped).
- **`OutboxItem.correlation_id`.** `from_row` tolerates the new column; a re-ingressed message's outbound
  rows carry the correlation id; every other producer writes `NULL`; positional/`from_row` construction
  unaffected; the `_migrate` ALTER is idempotent on a pre-existing DB.
- **Loopback source is inert.** `LoopbackSource.start(...)`'s handler is **never** invoked.

## Build sequence + gates

Build in this order; each step is a coherent commit with its tests green before the next. The whole
increment is one PR on its own worktree (it holds the stage-model freeze).

1. **Stage-model edits (the freeze) — first, isolated.** Add `Stage.RESPONSE`; add `Stage.RESPONSE.value` to
   the `channel_id` lane-key arm of `claim_next_fifo` + `pending_depth` (SQLite) and `_lane_col` (Postgres);
   add pinning tests for `_fifo_created_at`, `reset_stale_inflight`, `reclaim_expired_leases`,
   `_maybe_finalize_message` over the new stage; mirror the lane-key in `store/postgres.py`. **Gate:** the
   four pinning tests + Increment-1 suite green; no other `Stage` value added in this window. (No re-ingress
   behavior yet — the stage is inert.)
2. **`Loopback` connector + declaration surface + validation.** `ConnectorType.LOOPBACK`, the inert
   `LoopbackSource` (+ `register_source`), the `Loopback()` factory, `reingress_to=` on the outbound
   factories (forcing `capture_response`), the per-connection validation in `build_outbound_connection` +
   `build_inbound_connection` (loopback `ack_mode`/`bind_address`/`strict` guards), and the **cross-registry**
   `reingress_to → loopback` check in `build_check_registry`. **Gate:** the `messagefoundry check` /
   desugar / loopback-guard validation tests; the inert-source test; byte-identical-when-off. (Built together
   so an authored loopback never lacks its validator.)
3. **Work-row production.** Add `reingress_to` to `complete_with_response`; thread it from the delivery
   worker's capture branch ([pipeline/wiring_runner.py:806](../../messagefoundry/pipeline/wiring_runner.py));
   conditionally INSERT the `Stage.RESPONSE` work-row (artifact-PK reference, encrypted) in the same
   transaction; add the `self._response_work` wake event set after production. **Gate:** the atomic-production
   + finalizer-semantics tests.
4. **`ingress_handoff` + the re-ingress worker.** The atomic transaction (guarded DELETE, content-addressed
   id, depth cap, peek-derived metadata, retention-NULL tolerance) + `_response_worker` spawned by
   `_ensure_inbound_workers` for loopback inbounds + the `[pipeline] max_correlation_depth` setting. **Gate:**
   every exactly-once / crash-window / no-double-injection / loop-prevention / content_type / recovery /
   coexistence test.
5. **Run-context live feed + correlation field.** Feed `response_view` (the origin's `{dest: latest reply}`
   dict) for re-ingressed messages at the transform call site; add `OutboxItem.correlation_id` + the
   `queue.correlation_id` migration; stamp it in `transform_handoff` on a re-ingressed message's outbounds.
   **Gate:** the run-context + correlation-field tests.
6. **Observability.** `correlate_chain` + the `MessageChain` model + `GET /messages/{id}/chain` (body-gated,
   `response.read`-audited) + the console chain view. **Gate:** the RBAC/audit + endpoint + finite-walk tests.
7. **Docs.** `docs/CONNECTIONS.md` (the `Loopback()`/`reingress_to` surface + the worked example),
   `docs/CONFIGURATION.md` (`[pipeline] max_correlation_depth` + tuning guidance), and a re-ingress section in
   `docs/ARCHITECTURE.md`. Flip this ADR's **Status** to Accepted on the owner's "go".

**Stop gates (do not proceed past on a failure):** the byte-identical-when-off regression (any step), the
exactly-once crash-window test (step 4), and the stage-model pinning tests (step 1) are blocking — a failure
there means an invariant is broken, not a flaky test.
