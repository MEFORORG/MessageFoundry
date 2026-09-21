# Message Ordering — FIFO per Connection (Design)

**Status:** Phase 1 **complete (Layers 1–4 built & merged).** Layer 1 (global+per-connection
settings), Layer 2 (FIFO-per-outbound with head-of-line blocking), Layer 3 (failure classification +
policy — partner-NAK vs transport vs internal-error split, a **finite `max_attempts` default of 100**
since BACKLOG #1051 with `max_attempts=None` (retry forever) as the opt-in, and **AR fail-fast**),
Layer 4a (the configurable *stop-connection* override
`internal_error = continue | stop`, the `AlertSink` abstraction
[`pipeline/alerts.py`](../messagefoundry/pipeline/alerts.py) defaulting to `WARNING` logs, and the
`connection_stopped` emit-point), and Layer 4b (the `queue_buildup` detector + its `buildup_max_depth`
/ `buildup_max_oldest_seconds` threshold and the `pending_depth` store query). A **real** alerting
framework (routing the `AlertSink` events to notifications) remains [`BACKLOG-CLOSED.md`](BACKLOG.md) item 5;
**Phase 2** (per-stage durable queues) followed and is **built** — see
[ADR 0001](adr/0001-staged-pipeline-architecture.md).
Companion to the engine survey in
[`hl7-message-ordering-reference.md`](hl7-message-ordering-reference.md). Per-key (sequence-keyed)
ordering was once the long-term follow-on. It is now **declined** — see
[Declined: sequence-keyed ordering](#declined-sequence-keyed-ordering) below, which is this
project's single record of that decision.

## Goal

Guarantee **in-order (FIFO) delivery per outbound connection** so HL7 dependencies hold
(ADT before the ORM that references the encounter; ORM before its ORU; no stale update overwriting a
newer one). Parallelism stays *across* connections (one worker per outbound, already the model);
ordering is enforced *within* each connection. Per-key parallelism is **declined**, not deferred —
see [Declined: sequence-keyed ordering](#declined-sequence-keyed-ordering).

## Locked decisions

- **FIFO per outbound connection** is the default. Ordering is by **enqueue time on the outbound
  connection** — the order outbox rows were created for *that* destination. Fan-out (one inbound → N
  outbounds) and fan-in (multiple routers → one outbound) both resolve the same way: each outbound
  orders only its own rows, by enqueue time on it. A per-connection `ordering=UNORDERED` is opt-in
  **today**: it claims a batch and rotates past a failing message, trading strict order for
  throughput on that lane. Sequence-keyed lanes are a separate idea, and are declined (below).
- **Nothing is silently lost** (conservative posture). Default failure policy, by failure *kind*:
  - **Internal/code error** at a **router, transformer, or connection** (a bug / unexpected
    exception) → **default: error the message and continue** — record the `ERROR` disposition
    (recoverable/replayable) and process the next. **Configurable** per stage/connection (e.g.
    stop-the-connection-and-alert). *This is already how the engine treats inbound parse/transform
    errors today; we add the config knob and extend it to each stage.*
  - **Partner NAK / transport failure** on outbound delivery → **retry the head forever and alert on
    queue build-up.** The head blocks (FIFO) until it succeeds or an operator purges it.
- **Every default is overridable** via global + per-connection settings (e.g. set a finite
  `max_attempts` to opt back into retry-then-dead-letter; change the internal-error action).
- **Operator escape valves already exist** — `POST /connections/{name}/purge?scope=top|all`
  (soft-cancel + per-message `cancelled` audit event), in the console context menu. Keep the
  **soft-cancel** semantics (preserves body + audit trail; honors count-and-log) over a hard delete.
- **All connection settings get a global default + a per-connection override** (see next section).

## Settings model: global default + per-connection override

**Principle:** every connection setting resolves through a precedence chain, so an operator sets a
sensible fleet-wide default once and overrides only the connections that need it.

```
per-connection override (code-first)  >  service-global default (messagefoundry.toml)  >  built-in default
```

This mirrors the existing service-settings precedence (`config/settings.py`:
`CLI flag > env var > messagefoundry.toml > built-in default`) and extends it to connection-scoped
settings: **retry policy, ordering mode, ack handling, framing (future), validation**, etc.

- **Global defaults** live in `messagefoundry.toml` as new `ServiceSettings` sections, e.g.
  `[defaults.retry]` (`max_attempts`, `backoff_seconds`, `backoff_multiplier`, `max_backoff_seconds`)
  and `[defaults.ordering]` (`mode = "fifo"`). Operator-editable, environment-overridable.
- **Per-connection overrides** stay code-first on the authoring API, e.g.
  `outbound("OB_ACME_ADT", MLLP(...), retry=RetryPolicy(max_attempts=3))`.

**Implementation note (today's gap):** the code-first `outbound(..., retry=...)` currently
*materializes* `RetryPolicy()` with built-in defaults when unset
([`config/wiring.py:412`](../messagefoundry/config/wiring.py#L412)), so "unset" and "set to the
defaults" are indistinguishable — there's nowhere for a global default to apply. The override must be
kept **`None` when unspecified** and resolved against the global at registry-build / runner time
(`RegistryRunner` already reads `self._retry[name]` live per item, so resolution can happen there).
Same pattern for the new ordering setting.

## Current behavior (grounded)

- **One delivery worker per outbound connection**
  ([`pipeline/wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py)); connections drain
  independently — a slow/failed one never blocks siblings.
- The worker **claims a batch** (`claim_limit=20`) ordered by `next_attempt_at` and sends
  **sequentially** — so the *happy path is already FIFO* within a connection.
- **On failure it rotates:** a failed delivery is `mark_failed` → exponential backoff
  (`next_attempt_at = now + backoff`) and the worker **advances to the next message**. The failed one
  is retried later and **dead-letters after `RetryPolicy.max_attempts`** (default 5). This is correct
  for liveness but **not strict FIFO** — a stuck message is overtaken by later ones.
- **Partner NAK handling:** outbound `MLLPDestination.send()` reads the partner's MSA-1
  ([`transports/mllp.py`](../messagefoundry/transports/mllp.py) `_check_ack`); anything not `AA`/`CA`
  → `DeliveryError` → the same retry/backoff/dead-letter path. **AE and AR are treated identically.**

## Target FIFO delivery

Changes to the delivery worker + claim, behind the per-connection `ordering.mode` setting
(default `fifo`):

1. **Order by enqueue time on the outbound connection.** `ORDER BY created_at, rowid` scoped to
   `destination_name`. `outbox.created_at` *is* "when this delivery was enqueued for this OB
   connection"; SQLite's built-in `rowid` is a monotonic insertion counter that breaks
   same-timestamp ties deterministically — so no new column is needed. (An explicit `seq INTEGER`
   column is the alternative only if we later want an ordering fully independent of the wall clock;
   not required now.)
2. **Block the head on failure (no rotate).** When a delivery fails, **stop advancing that
   connection's queue** and keep retrying the *same head* — head-of-line blocking — instead of moving
   past it. On success, advance. What happens on persistent failure is the **Failure policy** below;
   the default is to **never auto-advance past a failure**.

## Failure policy (defaults & overrides)

Per-stage / per-connection setting with a global default. The split is by **failure kind** — a
*code* failure (our bug) is treated differently from a *partner* rejection.

> **This section records the Phase-1 proposal, not today's shipped default.** The retry-forever
> default it argues for was shipped and has since been reversed: `max_attempts` defaults to a finite
> **100** (BACKLOG #1051), with `max_attempts=None` the opt-in. The default is stated once, in the
> Status header above and in [`CONFIGURATION.md`](CONFIGURATION.md) `[delivery]`; read the rows below
> as the reasoning that produced the *knob*, not as the current value. The "default 5 today" in the
> paragraph after them was already stale when this doc was written.

| Failure | Default | Override examples |
|---|---|---|
| **Internal/code error** at router / transformer / connection (bug, unexpected exception) | **error the message and continue** — record `ERROR` (recoverable), process next. *(Already the engine's behavior for inbound parse/transform errors.)* | stop-the-connection-and-alert |
| **Partner NAK** (MSA-1 not `AA`/`CA`) | retry the head **forever**; **alert** on queue build-up | finite `max_attempts` → dead-letter-then-advance (uses the existing DLQ + replay); **AR fail-fast** (backlog item 4) |
| **Transport failure** (connect / timeout / I-O) | retry forever; alert on build-up (transient, like NAK) | finite `max_attempts` |

Two distinctions are new work:

- **Code error vs partner failure.** Today the outbound worker funnels NAK *and* I/O *and* any
  exception into one `DeliveryError`. The delivery path must separate "partner said no / unreachable"
  (retry-forever) from "the engine itself failed" (error-and-continue, or configured stop).
- **`RetryPolicy.max_attempts`** (default 5 today) becomes **effectively unlimited** for NAK/transport
  under the new default unless an operator sets a finite value — the existing retry-then-dead-letter
  path stays, but as **opt-in**. DLQ + replay unchanged, used whenever a finite cap is configured.

## Failure handling: engine error vs partner NAK

These are different paths and only the second interacts with FIFO:

- **Engine-internal error** (parse / transform / validation): recorded `ERROR` in the **inbound**
  path at receive time and routed to the error disposition **before any outbox row is written** — it
  never enters the outbound queue, so it cannot block delivery.
- **Outbound delivery failure** (partner NAK, or I/O/timeout): a `DeliveryError` in the outbox path →
  retry → dead-letter after `max_attempts`. This is the case FIFO head-of-line blocking applies to.

## Per-stage queues (router & transformer) — architectural direction

**Intent:** a message can fail at the **router**, the **transformer (handler)**, or **inside a
connection** — so each stage should have its own queue, with FIFO + the configurable error policy
above applied at every stage (not just the outbound connection).

**Current reality:** routers and handlers run **inline** in the inbound path today — there is one
durable queue, the per-outbound **outbox**; routing + transform happen synchronously *before* the
inbound ACK (the count-and-log invariant records the disposition pre-ACK). So a per-router and
per-transformer **durable queue** is a real architectural change: it turns the inline pipeline into a
**staged / decoupled** one (a durable queue between every stage), which shifts ACK timing and the
inbound-path invariants.

**Decided phasing:** per-stage durable queues are **foundational** (the target architecture). The
staged pipeline starts with an **ADR** — it's the top item in [`BACKLOG.md`](BACKLOG.md) ("Next up").

1. **Phase 1 (near-term, build first):** apply FIFO + the configurable error policy to what exists —
   the **outbound queue** (FIFO by enqueue time) and the **inline router/transform** stages
   (internal-code-error default = error-and-continue, with a stop-and-alert option). No new durable
   queues yet. **Deliberately scoped to the carry-forward parts:** the global/override **settings
   layer** and the **failure-policy semantics** transfer unchanged to the staged pipeline, and FIFO-
   on-outbound becomes its reference implementation. It also fixes a live ordering gap (today's
   rotate-on-failure can reorder ADT→ORM→ORU). Keep the inline-worker plumbing minimal — it's the one
   part Phase 2 re-homes.
2. **Phase 2 (foundational, ADR first):** **per-stage durable queues** for routers and transformers —
   the full staged pipeline. ACK-on-receipt + revised invariants + transactional stage handoff. See
   the ADR (top of `BACKLOG.md`).

## ACK-code-aware retry (AE vs AR)

**Built in Layer 3.** `_check_ack` now raises a
[`NegativeAckError`](../messagefoundry/transports/base.py) carrying the MSA-1 family, so the delivery
worker tells a *partner rejection* from a transport failure and AR from AE. Previously it collapsed
every negative ACK to one `DeliveryError`, so **AR (permanent reject)** was retried like **AE
(transient)** — under the retry-forever default that left a permanently-rejected head blocking the
lane indefinitely. The implemented behavior:

- **AR** (application reject — permanent) → **fail-fast**: dead-letter immediately — the partner will
  never accept it, so don't hold the lane hostage to a message that can't succeed.
- **AE** (application error — transient) → keep retrying (the conservative default).
- Per-connection-overridable (some partners misuse AE/AR).

This is the one principled exception to "retry forever": only a *permanent* reject auto-quarantines;
a transient error still blocks-and-retries.

## Operator controls & observability

- **Purge top / purge all** — built (`/connections/{name}/purge?scope=top|all`, console context
  menu). The manual fast-path to clear a blocked head.
- **Alerting (not built — backlog item 5).** The conservative defaults *depend on* alerts: a stopped
  connection and a building queue are only safe defaults if the operator is told. Until the alerting
  framework exists, the FIFO worker emits these as **placeholder alert events to a no-op sink**
  (logged), to be wired to real notifications when alerting lands:
  - `connection_stopped` — an OB connection halted on an internal error.
  - `queue_buildup` — an OB connection's backlog crossed a depth / oldest-in-lane-age threshold
    (threshold itself a global-default + per-connection-override setting).

## Decided / open

- **Poison-head policy — DECIDED:** no auto-dead-letter by default. Internal error → stop + alert;
  NAK/transport → retry-forever + build-up alert; both overridable (see Failure policy).
- **Sequence — DECIDED:** order by enqueue time on the OB connection (`created_at, rowid`; no new
  column).
- **Scope — DECIDED:** FIFO per outbound connection, by enqueue time on that connection (fan-out and
  fan-in both order on the OB's own rows).
- **Open — internal-error scope:** stop-connection-on-internal-error is specified for the *outbound
  delivery* path. Inbound parse/transform errors today are recorded `ERROR` and the inbound connection
  continues (count-and-log). Confirm whether inbound processing errors should *also* stop-and-alert,
  or keep the current ERROR-disposition behavior.
- **Note — backoff is lane latency:** if an operator opts into finite retries, the head's backoff
  delays everything behind it, so the retry schedule becomes a per-connection latency knob.

## Declined: sequence-keyed ordering

**Per-key (sequence-keyed) ordering is declined by owner ruling, 2026-09-20.** It is not scheduled,
not deferred, and not awaiting a design. Build around it rather than waiting for it. This section is
the single record of the **reasoning**; the other engine documents state the status and link here.

**What was proposed.** Preserve order only *within* a **sequence group** — the messages sharing a
**sequence key** such as an MRN, an encounter, or a sending facility — and run different groups in
parallel on their own **sequence-keyed lanes**. `partition_key` is the retired name for the same
idea, and no setting by that name exists anywhere in the engine.

**What the engine guarantees instead.** **FIFO per outbound connection**, by enqueue time on that
connection. That is the guarantee this document specifies and the engine has built. One strictly
ordered feed is therefore bound to **one core**, as it is in every engine. A feed that outgrows a
core is answered by **fanning out at source**, splitting it upstream into several inbound
connections that each carry their own ordered outbound; the scaling axis stays per *connection*
(engine shards, [ADR 0037](adr/0037-multi-process-sharding-l3.md)).

**Fan-out does not compose additively, and nothing here should be sized as though it did.** Lanes
contend on a shared store-side wall. Summing per-interface ceilings was measured to over-report by
roughly 11x, and [`THROUGHPUT.md`](THROUGHPUT.md) carries that correction plus the rule to take the
measured concurrent run instead. Fan-out is still the sanctioned answer; it is simply not free.

**The standing technical reason.** Sequence-keyed parallelism is sound only while no message's
correct processing depends on another group's order. Real HL7 traffic breaks that assumption. The
canonical counter-example is an **A40 patient merge**, which legitimately spans two MRNs and so
belongs to two sequence groups at once. Every such cross-key message needs a serialization fallback
or explicit two-group handling, and getting it wrong corrupts data silently rather than failing
loudly. The survey and hazard analysis in
[`hl7-message-ordering-reference.md`](hl7-message-ordering-reference.md) are **not retracted**: what
changed is the status of the feature, not the accuracy of the research.

**Fan-out does not make that hazard disappear; it moves it.** Splitting a feed upstream partitions
it by some key too, so a cross-key A40 can still land on two connections draining two independent
FIFO lanes. What changes is where the boundary sits and who owns it. At the source it is chosen
deliberately, by whoever splits the feed and knows what the split means. Inside the engine it would
be an implied promise the engine cannot keep for a message that belongs to two groups at once.
Declining sequence-keyed lanes declines the promise, not the hazard.

**What this does not rule out.** `OrderingMode.UNORDERED`
([`config/models.py`](../messagefoundry/config/models.py)) is shipped and stays. An operator may set
`ordering=UNORDERED` on an outbound connection to claim a batch and rotate past a failing message,
trading strict order for throughput, and the
[ADR 0154](adr/0154-synchronous-captured-downstream-reply-and-intake-authentication-for-the-inbound-http-listener-adr-0023-deferred-tail.md)
`reply_from` lane requires it. What is declined is **sequence-keyed lanes as the scaling answer for
an ordered feed**, never the existence of an unordered mode.
