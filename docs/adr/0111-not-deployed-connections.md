# ADR 0111 — Connection present but not deployed

- **Status:** Accepted (2026-07-14) — owner-directed; built (BACKLOG #233).
- **Deciders:** owner (the flag spelling, the precedence rule, the 7th disposition) + a code-fact
  verification pass over the pipeline / store / API seams.
- **Related:** [ADR 0001](0001-staged-pipeline-architecture.md) (the staged queue + at-least-once /
  re-run purity this must not break) · [ADR 0007](0007-gui-manageable-connections-toml.md)
  (`connections.toml` — the flag's data surface) · [ADR 0084](0084-accepts-router-seam.md) (the
  `accepts=` seam this mirrors for the *handler* half) · [ADR 0090](0090-resend-a-stored-message-to-an-alternate-outbound-connection.md)
  (the resend path that bypasses `transform_one` and therefore needs its own guard) ·
  [ADR 0048](0048-third-tier-disaster-recovery-standby.md) / [ADR 0095](0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)
  (**parking** — a neighbouring state this must never be conflated with) · BACKLOG **#15** (`simulate`) ·
  BACKLOG **#115** (`auto_start`) · BACKLOG **#233** (this build) · BACKLOG **#234** (a separate
  pre-existing data-loss bug uncovered here) · CLAUDE.md §12 (count-and-log).

---

## Context

A ported estate carries connections that are **real, reviewed, and in the config repo — but must not run
yet**. Retired trading partners, superseded duplicate sends, a relay pulled from production: the object
should stay in the graph (history, traceability, a dated go-live) while the engine does not wire it, does
not start it, does not queue to it, and — decisively — **does not resolve its `env()` values**, because
those values do not exist yet.

Today there is no way to say that. The only expressible approximations all fail:

- **Comment the code out.** The connection leaves the graph entirely: `validate` no longer sees it, the
  operator no longer sees it, and the *reason* it is dark lives in a comment nobody reads. A commented-out
  connection is not documentation; it is deleted code with a fig leaf.
- **Leave it deployed with missing credentials.** The engine comes up **DEGRADED on every single boot**
  ("2 failed to start"). DEGRADED-on-every-boot is indistinguishable from a real regression: the operator
  stops reading the line, and the day a third connection genuinely breaks, **nobody notices**. A permanent
  alarm is a disabled alarm.
- **`auto_start=False`** (#115) says "deployed, just not up right now" — a *boot* gate. It does not mean
  "this thing has no credentials and is not supposed to work."

Corepoint modelled this natively as `class="disabled"`. We had no equivalent.

### The key finding: `auto_start` already dodges `env()` on the cold path — and that is not enough

`env()` is lazy (`config/wiring.py` returns an `EnvRef`; a config import touches no environment value), and
`resolve_env_settings` is its single choke point — it raises `WiringError("environment value(s) unusable —
missing: …")`. A cold `serve` **does** already dodge that for an `auto_start=False` connection: both boot
gates return before `_source_config` / `_dest_config` are ever called.

**But `_build_check_connectors` (`pipeline/wiring_runner.py:5181` inbound, `:5186` outbound) loops EVERY
inbound and EVERY outbound with no gate at all** — no `auto_start`, no DR, no simulate. It is reached from:

- **`messagefoundry check`** — the *required* commit/CI gate (`checks.py`);
- **every live reload** (`RegistryRunner.build_check` → `Engine`), and therefore every **promote**;
- **every `connection upsert` / `remove`** — the VS Code GUI's write path (`__main__.py`). One
  unresolvable connection today blocks edits to **every other connection in the file**.

So the flag that "already works" works on exactly one path and explodes on the four that an author touches
all day. **Honoring the flag inside `_build_check_connectors` IS the feature.** Without that line, nothing
is fixed.

### The invariants that bound the choice

CLAUDE.md §12, verbatim: *"log every received message with its disposition (route bad messages to the
error/dead-letter path — **never accept-and-drop**)."* A decline with no ERROR, no dead-letter, and no
operator-visible disposition **is** an accept-and-drop, and is forbidden. `pipeline/dryrun.py` already
says this in-code at the very seam we are about to modify.

CLAUDE.md §2, verbatim: *"at-least-once now relies on a re-run re-deriving identical output, so **routers
and transforms must be pure**."* A decline decided from live runner state (`_destinations` membership,
`_failed`, `_outbound_paused`) would make the delivery set a function of *when the crash happened*. It must
be a function of the **graph**.

## Decision

**`deployed: bool = True` on both `InboundConnection` and `OutboundConnection`.** In TOML:
`deployed = false`. Code-first: `outbound("OB_PARTNER_ADT", MLLP(...), deployed=False)`. A not-deployed
connection is **never wired, never started, never queued to, and its `env()` is never resolved** — on any
path, including `check`, reload, promote and `connection upsert`.

Positive default, matching every sibling flag (`auto_start=True`, `simulate=False`), so *"unset is
byte-identical to today"* is trivially provable rather than argued.

**`deployed=False` WINS over `auto_start`.** If both are set, `auto_start` is ignored entirely. There is no
composition to reason about: not-deployed is not a lifecycle state the scheduler, a reload, or an operator
can climb out of. Deploying it is a **config change**, not a runtime action — so `POST
/connections/{name}/start|restart` answers **409**, not "started".

### The three-way distinction — never conflate these

| | Built? | Receives rows? | Rows retained? | Terminal disposition |
|---|---|---|---|---|
| **SIMULATED** (#15, `[shadow].simulate_all_egress`) | **yes** | **yes** | n/a — consumed | **`PROCESSED`** (egress suppressed at the wire) |
| **PARKED** (DR [ADR 0048](0048-third-tier-disaster-recovery-standby.md), scheduler [ADR 0095](0095-connection-lifecycle-scheduler-and-credential-fault-stop.md)) | yes | **yes** | **RETAINED — queued, retried, drained on resume** | pending → `PROCESSED` later |
| **NOT DEPLOYED** (this ADR) | **no** | **no** | **no row is ever created** | **`NOT_DEPLOYED`** (or `PROCESSED` if a deployed sibling delivered) |

`simulate` is the *opposite* of this feature: the lane is up and eating messages, it just does not put bytes
on the wire. Parking is a **promise to deliver later**. Not-deployed is a **refusal to accept the work at
all** — and it is the only one of the three that is a property of the *config*, not of the run.

### Where the decline is enforced, and why there

**The `transform_one` Send-materialization seam — `pipeline/dryrun.py:403-416`.** That loop turns each
`Send` into a `DeliveryPreview`; unknown targets already fail closed there. A not-deployed destination
never becomes a `DeliveryPreview`, so it can **never be committed to the outbound stage** — the decline
happens *before* the row exists, which is the acceptance criterion ("assert no row is left in the outbound
stage").

This structurally mirrors [ADR 0084](0084-accepts-router-seam.md)'s `accepts=` seam, which filters the
**router** half at the same layer. Same shape, same reason: it is the **one** place every in-pipeline
producer converges —

- the **split** path (the default: router worker → transform worker → `transform_handoff`),
- the [ADR 0057](0057-inline-step-a-fast-path.md) **inline** fast-path (fused into the router worker),
- the [ADR 0071](0071-cut-executor-round-trips-b5.md) **fused sync** path,
- **dry-run**, **`messagefoundry check`**, and the IDE **Test Bench**

— all of them. One edit, six producers, no divergence between what the Test Bench previews and what the
engine does.

**The decline is keyed on the REGISTRY FLAG, never on live runner state.** `deployed` is a frozen field of
a frozen dataclass in the graph. A crash-and-re-run of the same message against the same registry re-derives
the *identical* delivery set — at-least-once ([ADR 0001](0001-staged-pipeline-architecture.md)) is intact
because the decline is pure.

**A fourth producer does NOT pass through `transform_one` and needs its OWN guard:** operator **resend /
edit-resend** ([ADR 0090](0090-resend-a-stored-message-to-an-alternate-outbound-connection.md)) inserts an
outbound-stage row **directly** in the store. Its only liveness check is `outbound_running(...)`. A divert
in `transform_one` does not cover it, so `POST /messages/{id}/resend` and `/edit-resend` to a not-deployed
connection answer **409** at the API.

### How count-and-log is preserved

Two mechanisms, because one is not enough:

1. **A per-destination `message_events` row** — `_event(mid, "not_deployed", <connection>, <reason>, now)`
   for **every** declined `Send`, in the same committed handoff transaction. This is the count-and-log
   record. It is also the *only* record of the skipped leg when the message still delivers to a deployed
   sibling and therefore finalizes `PROCESSED`.
2. **`"not_deployed"` joins `_AUDIT_FLOOR_EVENTS`** (`store/store.py:842`). The #63 verbosity gate
   (`should_record_event`) **drops** any event outside that floor set at verbosity `errors`/`off` — so
   without this line the operator-visible record evaporates on exactly the instances that thinned their
   logs, silently re-creating the accept-and-drop the event exists to prevent.

And a **7th `MessageStatus.NOT_DEPLOYED`**, emitted by the finalizer **only when EVERY destination the
handler selected was declined**. If any deployed sibling delivers, the message finalizes `PROCESSED` as
normal and the event row above carries the skipped leg.

**Why a new status at all, rather than just dropping the target from the delivery list?** Because the
finalizer decides `FILTERED` **by absence**: it sees only queue rows, and *"no rows + `messages.status ==
'routed'`"* means `FILTERED`. Dropping the only target from `deliveries` would collapse the message to
**`FILTERED`** — "the handler chose not to send this" — with **zero code changes and zero test failures.**
That is a lie about operator intent (the handler *did* choose to send; the engine declined the destination),
and it is the single most likely silent-wrong outcome of this whole change. The decline must therefore be
**persisted where the finalizer can see it**, in the same handoff transaction — not inferred from an empty
list.

The 7th value needs **no DDL on any backend**: `messages.status` is `TEXT`/`TEXT`/`NVARCHAR(32)` on
SQLite/Postgres/SQL Server with no `CHECK` constraint anywhere. No migration rev bump, no schema-hash change.

### What stays untouched

- **The connection stays in `Registry.outbound`.** The startup orphan sweep
  (`dead_letter_missing_destinations`) keys on the **registry**, not on built connectors — a connection
  *removed* from the registry gets every already-queued row dead-lettered on the next start. Flipping
  `deployed=False` on a connection with rows in flight must not detonate them.
- **A not-deployed *inbound* still spawns its router + transform workers** if an ingress/routed backlog
  could exist (the ADR 0048 AC-3 rule). It stops *listening*; it does not strand what it already took in.
- **No delivery worker is spawned** for a not-deployed outbound — unlike `auto_start=False`, whose park
  today spawns a worker over a popped connector, so claimed rows retry forever and **page the operator**
  (a buildup/stall alert). Nothing can queue, back off, or alert, because nothing is there.

## Acceptance Criteria

- **AC-1** — WHERE a connection is marked `deployed = false`, THE SYSTEM SHALL NOT resolve its `env()`
  values on any path (`serve`, `messagefoundry check`, reload, promote, `connection upsert`), and an
  entirely-absent value set SHALL NOT raise. → `tests/test_not_deployed.py`
- **AC-2** — WHEN a not-deployed outbound's `env()` values are absent, THE ENGINE SHALL start clean (no
  `_failed` entry, not DEGRADED). → `tests/test_not_deployed.py`
- **AC-3** — WHEN a handler `Send`s to a not-deployed outbound, THE SYSTEM SHALL leave **zero rows in the
  outbound stage** and SHALL record a `not_deployed` `message_events` row naming the connection.
  → `tests/test_not_deployed.py`
- **AC-4** — IF **every** destination a handler selected is not deployed, THEN THE FINALIZER SHALL set
  `messages.status = 'not_deployed'` (never `FILTERED`, never a non-terminal strand); IF a deployed sibling
  delivers, THEN the message SHALL finalize `PROCESSED` with the event row still present.
  → `tests/test_not_deployed.py`
- **AC-5** — THE `not_deployed` EVENT SHALL survive verbosity `errors`/`off` (it is in
  `_AUDIT_FLOOR_EVENTS`). → `tests/test_not_deployed.py`
- **AC-6** — WHILE a connection is not deployed, `POST /connections/{name}/start|restart` SHALL answer
  **409**, and `POST /messages/{id}/resend` / `/edit-resend` targeting it SHALL answer **409**.
  → `tests/test_not_deployed.py`
- **AC-7** — THE SYSTEM SHALL distinguish not-deployed from stopped / `auto_start=False` in `graph --json`
  and in the `GET /connections` status ladder (`status: "not_deployed"`). → `tests/test_not_deployed.py`
- **AC-8** — WHEN `deployed` is flipped to `true` and the env values supplied, THE CONNECTION SHALL deploy
  with **no other change** to the config. → `tests/test_not_deployed.py`
- **AC-9** — WHERE `deployed` is unset, behaviour SHALL be byte-identical to today; a **deployed** outbound
  with a missing `env()` SHALL still fail loud, be isolated, and keep its rows queued + retrying.
  → `tests/test_startup_fault_isolation.py::test_failed_outbound_isolated_retries_and_recovers`
- **AC-10** — `deployed = false` SHALL survive a `connections.toml` round-trip through the GUI/CLI write
  path (it is in `_SCALAR_FIELDS`). → `tests/test_connections_file.py`

## Options considered

1. **`deployed: bool = True` on the connection model, enforced at `_build_check_connectors` + the
   `transform_one` seam** — **CHOSEN.** One flag, one graph property, one decline seam covering six
   producers, plus one separate guard on the resend path.
2. **`enabled` / `disabled` / `active` as the spelling** — rejected. `disabled` is negative-default
   (`disabled = false` as the norm is a double negative to read), and `enabled`/`active` both read as
   *runtime* state, which is precisely the confusion with `auto_start` and parking this ADR exists to
   remove. "Deployed" is a statement about the *config*, not about the process.
3. **Reuse `auto_start=False`, and simply make it skip `_build_check_connectors` too** — rejected. It
   conflates two genuinely different facts ("not up right now, but it works" vs "this has no credentials
   and is not supposed to work"), and it would silently weaken the promote-time fail-loud guarantee for
   every operator who only ever wanted a boot gate.
4. **A separate `[disabled]` section / a separate file listing dark connections** — rejected. It splits one
   connection's truth across two places, and every consumer (loader, `validate`, `graph`, the GUI, the API)
   would have to remember to join them. A field on the object cannot be forgotten.
5. **Drop the target from `deliveries` and let the finalizer's existing `FILTERED`-by-absence handle it** —
   rejected, and it is the trap this ADR most wants on the record: it requires *zero* code changes, passes
   *every* existing test, and reports "the handler filtered this message" when the handler did no such
   thing. See "Why a new status at all", above.
6. **Enforce the decline in the delivery worker (refuse to build the connector, dead-letter the row)** —
   rejected. The row would already exist in the outbound stage, violating the acceptance criterion; and a
   dead-letter is an *error* disposition, which is exactly the false alarm this feature removes.
7. **Remove the connection from the `Registry` at load** — rejected. `dead_letter_missing_destinations`
   keys on registry membership, so this would dead-letter every already-queued row for a connection an
   operator merely paused pending a go-live.

## Consequences

**Positive**

- **DEGRADED-on-every-boot goes away** for a config that legitimately carries dark connections, which
  restores the meaning of the DEGRADED line: it is once again a signal that something is *wrong*.
- The `messagefoundry check` commit gate, reload, promote and the GUI's `connection upsert` stop being held
  hostage by one unresolvable connection. Today a single missing credential blocks edits to every other
  connection in the file.
- A retired partner keeps its history, its `validate` coverage, and its row in the operator's view. The
  reason it is dark is a **field**, not a comment.
- The decline is visible: a `message_events` row per declined leg, a `NOT_DEPLOYED` disposition when it was
  the only leg, and a `not_deployed` status string in the console. Nothing is accepted-and-dropped.
- Turning it on is one flag and the env values — **no other change** (AC-8).

**Negative / risks**

- **A seventh `MessageStatus` is a vocabulary change.** Anything that exhaustively matches dispositions
  (dashboards, KPI roll-ups, a downstream report) gains a bucket. The API's `connections_stopped ==
  conn_total - conn_running` identity in particular must be preserved while the third connection bucket is
  added, or the KPI silently inflates.
- **`deployed=False` beating `auto_start` means an operator cannot start it from the console.** That is
  intentional (409, "deploying it is a config change"), but it *is* a control an operator might reach for.
  The refusal must say why, not just refuse.
- The status string is cheap (one CSS rule, the console interpolates `status-{status}`); a new
  `ConnectionRow` **field** would not be — it forces an `ENGINE_UI_SEAM` bump and a two-package handshake.
  Future work must resist adding one.

**Out of scope / NOT built here**

- **The `ide/` form controls.** Three TypeScript field enumerations (`ide/src/connectionEditor.ts`,
  `ide/src/connectionWizardModel.ts`, `ide/src/graphModel.ts`) would each need a `deployed` control to
  surface the flag in the VS Code connection editor / wizard / graph. **Deferred deliberately** to avoid
  colliding with the in-flight [ADR 0106](0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md)
  Steps-palette work in the same tree. The flag is fully functional without them: hand-edited
  `connections.toml` and code-first `deployed=False` both work, and the engine, CLI, API and web console all
  honor it. The GUI simply will not *offer* the checkbox yet.
- **BACKLOG #234 — `connections.toml` GUI save silently stripped per-connection fields. CLOSED; the
  description below is kept as the record of what was true when this ADR was written.** Uncovered while
  adding `deployed` to the TOML **write** schema, `_SCALAR_FIELDS` in `config/connections_edit.py` was
  then a short whitelist with no passthrough, so a GUI/CLI `connection upsert` dropped fields it did not
  name from an existing connection's table. That was a **pre-existing data-loss bug**, filed as **#234**
  and deliberately **not** fixed by this ADR, which only added `deployed` and `auto_start` to the
  whitelist.

  **#234 has since landed, and both halves of the old description are now wrong** — the count and the
  mechanism. The whitelist is no longer short, and an unrecognised key is no longer dropped: it is
  **rejected fail-loud with a `WiringError`**, mirroring the loader's `_reject_unknown` message shape.
  Derive the current field set from `_SCALAR_FIELDS` in `config/connections_edit.py` rather than trusting
  any count written here — a number in this ADR is a number that goes stale.
- `ack_after=delivered`, per-connection scheduling of a *go-live date*, and any notion of a "planned"
  deployment window. `deployed` is a boolean; a date is a different feature.
