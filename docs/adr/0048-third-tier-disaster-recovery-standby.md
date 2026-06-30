# ADR 0048 — Third-tier disaster-recovery standby (right-sized, degraded, high-priority feeds only)

- **Status:** Accepted (2026-06-28 — ratified; open items resolved in 'Ratification decisions' below)
  — **finalized 2026-06-28, EARS criteria added, adversarial review applied.** The owner DR posture is now
  **locked into the body as decided** (cold-seed-from-#60, manual activation; `auto` deferred to a future mode that
  config rejects). This ADR stays `Proposed` only because the owner accepts at ratification; the items in *To
  resolve on acceptance* are ratification-confirmations and a small number of genuinely-open contract details, not
  open design forks.
- **Date:** 2026-06-27 (finalized 2026-06-28)
- **ADR-index note:** the existing `0048` row in [`docs/adr/README.md`](README.md) was **stale** (it described the
  superseded `auto`/`/healthz`-probe activation and a co-equal "warm (DB-replica) or cold" seed). It has been
  **corrected in this finalization** to match the locked posture below (cold-only seed; manual-only activation with
  `auto` config-rejected; the passive-VIP fence). The number `0048` is the project owner's assignment for this work
  and must not be renumbered. The `0047` slot is claimed by
  [ADR 0047 — Cloud / Kubernetes HA deployment packaging](0047-cloud-kubernetes-ha-deployment-packaging.md), which
  packages an *operator-assembled* L4 load balancer whose VIP **follows** failover via a **primary-only health
  check** with **zero engine VIP code** — that **passive** mechanism is the fence this ADR rides (see §"VIP
  takeover and fencing").
- **Related:** ADR 0001 (staged pipeline / ACK-on-receipt) · ADR 0007 (`connections.toml`) · ADR 0017 (consumer
  deployment model) · ADR 0019 (pluggable KeyProvider / store DEK — the encryption seam #60 reuses, and whose key
  must be present at the DR site to cold-restore) · ADR 0027 (per-connection retention, #34) · ADR 0031 (startup
  fault isolation — the selective-start / status path this DR run-profile rides; this ADR's new `status:"filtered"`
  is **distinct** from 0031's `status:"failed"`) · ADR 0042 (embedded-doc pruning, #47 — sibling
  per-connection-override plumbing) · ADR 0047 (cloud/K8s HA packaging — the operator-assembled,
  **passive** VIP-follows-failover load-balancer this ADR delegates the VIP move to) · shipped active-passive HA
  (`pipeline/cluster.py` · `docs/CLUSTERING.md`) · **ADR 0049 / BACKLOG #60** (turnkey DR backup + restore-verify —
  the encrypted, restore-verified backup this ADR **consumes** to cold-seed; ADR 0049 is being authored in the
  parallel #60 lane and is **not yet present in this worktree**, so it is referenced by number, not re-specified) ·
  BACKLOG #61 (this) · CLAUDE.md §2 (reliability invariant, count-and-log invariant) · CLAUDE.md §9 (PHI / no-egress).

---

## Context

MessageFoundry today has a **two-tier recovery model**:

1. **Primary** — normal operation: one engine instance owns the store and supervises one listener + router
   worker + transform worker per inbound, plus one delivery worker per outbound.
2. **Active-passive HA (shipped)** — same-tier engine failover at **full capacity**. Leadership is a
   self-fencing lease in the shared `leader_lease` DB row; exactly one node (the leader) binds all listeners
   and runs all workers, a warm standby takes over on failover (~one heartbeat to ~lease-TTL), and
   double-processing is fenced by a monotonic leader epoch validated inside the FIFO claim transaction
   (`pipeline/cluster.py`, `docs/CLUSTERING.md`). **The `leader_lease` row and `DbCoordinator` exist only on a
   server-DB backend** — `ClusterSettings` requires `[store].backend in {postgres, sqlserver}`
   (`config/settings.py`); on a **SQLite** store the engine always uses the `NullCoordinator` and there is **no
   lease row at all** (`pipeline/cluster.py`: "SQLite store always gets the NullCoordinator"). Per CLUSTERING.md,
   **DB-tier HA is delegated to the DBA** (PostgreSQL streaming replication, SQL Server Always On); the engine does
   not replicate the store or orchestrate DB failover.

This handles a **node failure**. It does **not** handle loss of the **whole HA pair / site** — most concretely,
**loss of the shared store** (the production database goes down, or the datacenter does). Tier 2 *assumes shared
DB availability*; when that assumption fails, both the leader and the warm standby are dead in the water because
they point at the same gone store. That is the gap this ADR closes.

The forcing constraint is cost. A second **full-capacity hot standby site** is the textbook answer, but it means
provisioning duplicate full-size hardware that mostly sits idle — a poor trade for an open-source on-prem engine
whose adopters are budget-bound. So the decision here is a **right-sized (deliberately under-provisioned) DR box**
that activates **only** when tier 2 is also gone, and runs **less, not more**: only the **high-priority feeds**,
in an accepted **degraded mode**. **This is the inverse of the dropped active-active scale-out path (removed
2026-06-18, code deleted) — DR runs a *reduced* feed set on smaller hardware, not the graph concurrently across
more nodes.**

The decision is bounded by the standing project invariants ([CLAUDE.md](../../CLAUDE.md) §2), quoted verbatim:

> **Reliability invariant (do not break):** the transactional **staged queue on SQLite (WAL)** gives at-least-once
> delivery, retries, replay, and dead-lettering *without* a separate broker. … At-least-once now relies on a re-run
> re-deriving identical output, so **routers and transforms must be pure** … outbound connections must still be
> **idempotent**.

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK** … so inbound
> counts still reflect the true received volume and nothing is accepted-and-dropped.

A subtlety this ADR must name explicitly: the reliability invariant's at-least-once guarantee is an **in-engine,
same-store** property (a re-run re-derives identical output against *the same* staged queue). The cold-seed posture
below runs DR on a **separate restored copy** of the store; across that handoff the engine provides **no machine
guarantee** against loss or duplication — that gap is closed by an operator reconciliation runbook, not the engine.
The body below is careful to scope every "invariant preserved" claim to within a single store.

And by the PHI rule that PHI at rest must be protected — the DR seed (an encrypted store/config backup, #60 / ADR
0049) is itself a PHI-at-rest artifact and is encrypted with the store DEK via the KeyProvider seam (ADR 0019); the
on-prem / no-egress default ([CLAUDE.md](../../CLAUDE.md) §9) means the DR target is a **local/UNC path, never a
cloud destination**.

And by the standing decline that **DB-tier backup / HA / restore is the DBA's job** (CLUSTERING.md, BACKLOG
§"DB-tier HA delegated to the DBA. Handles a node failure, not loss of the whole HA pair/site."). The engine owns
the **feed-priority + selective-startup half**, not the DB-replication half. This ADR also **consumes #60 / ADR
0049** (scheduled, **encrypted** config/store backup + restore-verify) as the **default** state-seeding path — it
does not re-specify that mechanic.

## Decision

**Add a third recovery tier: a right-sized DR standby box that activates only when the entire HA pair / site is
unreachable, takes over the service VIP, and starts only the connections at or above a configured priority tier —
running in a deliberately degraded mode.** The DR store is **cold-seeded** from #60's encrypted backups
(the owner-locked default), and activation is a **manual, audited operator runbook** fenced by an
acquire-VIP-or-abort takeover, with a tier-2-lease quorum check layered on **only where a server-DB primary store
is still reachable**. The engine owns two halves of this — the **per-connection priority tier** and the
**selective-startup DR run-profile** — and **delegates the rest** to infra/DBA exactly as it already delegates
DB-tier HA, including the **VIP move itself** (the passive ADR 0047 LB mechanism).

This must **not** break the reliability invariant (routers/transforms stay pure; outbound stays idempotent; every
stage handoff stays a single committed transaction), the count-and-log invariant (every message a *bound* DR
listener receives is still persisted-before-ACK and dispositioned — never accept-and-drop), the no-broker / on-prem
/ code-first identity, or the no-grouping-unit rule (we add a per-connection **attribute** and a **run-profile
filter**, not a "channel"/"route" element).

**Scope guardrail — priority is a connection attribute, not declarative routing.** The tier governs **when a
connection runs** (whether its listener binds / its connector builds in a given run of the engine), never **what a
connection does**. Routing and filtering *logic* — the decision about which messages to process or drop — **stays
in Handlers as code-first Python**, exactly as today; the priority tier is not a declarative `Filter`/`TransformStep`
and never grows into one ([CLAUDE.md](../../CLAUDE.md) §1 "no grouping unit", §12 "never build declarative
Filter/TransformStep"). A Handler may *inspect* the resolved tier for its own logic, but the tier itself routes
nothing.

### Half (a) — a per-connection priority / DR-tier setting

A new classification on each connection, layered as the **same global-default + per-connection-override idiom**
already proven for `RetryPolicy`, `OrderingMode`, `BuildupThreshold`, `StallThreshold`, per-connection retention
(#34 / ADR 0027), and embedded-doc pruning (#47 / ADR 0042). The taxonomy is **critical / normal / low** (default
`normal`). Concrete proposal:

- **Enum** (`config/models.py`, alongside `OrderingMode`) — an enum is not orderable by default, so the tier
  carries an **explicit total order** (a backing rank) so threshold comparisons are unambiguous:
  ```python
  class Priority(str, Enum):
      """Per-connection DR/priority tier (ADR 0048). Higher rank = more critical."""
      CRITICAL = "critical"
      NORMAL = "normal"
      LOW = "low"

      @property
      def rank(self) -> int:
          return {"critical": 2, "normal": 1, "low": 0}[self.value]
  ```
  The run-profile threshold compares ranks: a connection runs iff `resolved.rank >= threshold.rank`. The total
  order is `CRITICAL > NORMAL > LOW`.

- **Global default** on `DeliverySettings` (`config/settings.py`, the `[delivery]` section), mirroring how the
  other per-connection defaults live there:
  ```python
  priority: Priority = Priority.NORMAL   # global default for all connections
  ```

- **Per-connection override** — `None` means *inherit the global `[delivery].priority`*; an explicit value
  overrides it, resolved in the `RegistryRunner` (**per-connection override > `[delivery]` global default >
  built-in** — the exact resolution order already used for `retry`/`ordering`/`buildup`, see
  `wiring_runner.py` "per-connection override > global default > built-in"). Unlike retry/ordering, the tier is
  meaningful for **both** directions (a DR profile must filter inbound *listeners* and outbound *destinations*),
  so the field lives on **both** `InboundConnection` and `OutboundConnection` (`config/wiring.py`). The two
  dataclasses do **not** carry the same neighbor fields, so `priority` is added beside the **direction-correct**
  existing overrides:
  - on `InboundConnection` (`config/wiring.py`, the frozen dataclass at ~line 1607) beside
    `messages_days` / `prune_documents_after` / `ack_after` (its inbound-side overrides; `retry`/`ordering`/
    `buildup`/`stall` do **not** live here),
  - on `OutboundConnection` (~line 1654) beside `retry` / `ordering` / `buildup` / `stall` / `dead_letter_days`.

  In both cases the field and idiom are identical:
  ```python
  # None = inherit [delivery].priority; an explicit value overrides it.
  priority: Priority | None = None
  ```
  Inbound and outbound tiers are **independent** — a high-priority inbound may route to low-priority outbounds;
  during DR activation that inbound accepts messages while those outbounds queue them for later delivery. This
  asymmetry is intentional (accept time-critical intake even if a downstream is degraded); the recommended
  operator practice is nonetheless to tier the whole path consistently (critical inbound → critical handlers →
  critical outbound).

- **`connections.toml`** (ADR 0007) — desugared through the same `inbound()`/`outbound()` factories, so it stays
  hand-/GUI-editable, exactly like the sibling override keys (`messages_days`, `prune_documents_after`):
  ```toml
  [[inbound]]
  name = "IB_ACME_ADT"
  transport = "mllp"
  router = "acme_adt_router"
  priority = "critical"          # else inherit [delivery].priority
  ```
  Add `"priority"` to `_INBOUND_KEYS` / `_OUTBOUND_KEYS` in `config/connections_file.py` and coerce via
  `_enum(Priority, …)` when present.

- **Code-first** authoring is unchanged in shape: `outbound("OB_X", MLLP(...), priority=Priority.CRITICAL)`.

The signal is **reusable beyond DR** (load-shedding, ordered startup, alert severity), but this ADR only
specifies its DR run-profile use.

### Half (b) — a DR run-profile (selective startup at tier ≥ X)

A DR run-profile is **"start only connections at priority ≥ X"**, hooking into the **existing per-connection
startup path** rather than introducing any new supervisor. `RegistryRunner.start()` already iterates
`registry.outbound` then `registry.inbound`, starting each connection in an **isolated** try/except (ADR 0031,
`_start_outbound` / `_start_inbound_unsafe` / `_record_failed`). The run-profile inserts a single threshold gate
at that iteration:

- **Inbound listeners** at tier < X are **not bound** (no `source.start(...)`) — but their **router + transform
  workers are still spawned** (the existing `_ensure_inbound_workers(name)` loop is left to run over *all*
  inbounds, exactly as it already does for an ADR-0031 failed inbound), so any crash-recovered `ingress`/`routed`
  backlog still drains. The workers poll an empty stage as a no-op when nothing arrives.
- **Outbound destinations** at tier < X are **not built** — the delivery worker still spawns (as it always does)
  but, lacking a connector, rows routed to it simply sit in the `outbound` stage and back off via the retry
  policy, self-healing on the next full startup. This is exactly how an ADR-0031 degraded outbound already
  behaves (the worker's existing "no connector for a claimed row" branch).

On startup the engine **logs a one-line filter summary** (e.g. "DR profile threshold=CRITICAL: 5 of 20
connections started; 15 below-threshold filtered: …") so an operator can audit the curated critical set
immediately and on every failover, rather than discovering a mis-tagged feed only when it is absent under load.

This **composes with, and is distinct from, ADR 0031**: ADR 0031 isolates a connection that *fails* to build/bind
into a `failed` (degraded) status; the DR run-profile *deliberately does not start* a sub-threshold connection.
Both must be surfaced distinctly so an operator can tell a deliberately-parked feed from a broken one.
The connection-status field (`api/models.py`, `ConnectionRow.status`) already carries
**`running` | `stopped` | `failed` | `draining`** — this ADR adds a **fifth value, `filtered`** (skipped by the DR
run-profile), distinct from ADR 0031's `failed`. It is surfaced via a sibling `filtered_connections()` accessor
on the `RegistryRunner` (the exact shape of the existing `connection_failed()` / `degraded_connections()` at
`wiring_runner.py` ~516/522), wired into the same status-derivation branch in `api/app.py` that already maps
`running`/`stopped`/`failed`/`draining` — **not** a new API model — and reported on `GET /connections`,
`GET /connections/{name}/metadata`, and the console connections table.

The threshold X is a **DR-box-level service setting** (a new `[dr]` section, `dr.priority_threshold: Priority =
Priority.CRITICAL`), threaded into the `RegistryRunner` like the other delivery defaults — **not** a
`connections.toml` key (the per-connection key carries the tier; the threshold is a property of *this run* of the
engine). The DR profile is a **startup decision**, not a runtime toggle: the threshold is read at engine start and
a reload re-evaluates the whole graph, so a connection never flips between bound and filtered mid-run with
in-flight rows stranded.

### Seeding DR state — cold-from-#60 (the owner-locked default)

**Locked (owner posture, 2026-06-28): the DR store is COLD-seeded from #60's encrypted backups on activation —
not a warm DB replica.** The DR box does not maintain a live, continuously-replicated copy of the production
store; it is seeded by **restoring #60 / ADR 0049's most recent encrypted, restore-verified backup** at the moment
of activation. The engine owns only the feed-priority + selective-startup half; the restore mechanic is #60's.

- **Cold — restore from #60 backups (the default and only built seed path).** The DR box is seeded from #60's
  scheduled, **encrypted** config + store backup (restore-verified). **RPO** = backup cadence (e.g. daily, the #60
  default, or on-demand → up to one cadence interval of loss); **RTO** = restore time + engine start
  (minutes–hours). #60 / ADR 0049 owns the backup/restore mechanic (a consistent snapshot, whole-archive
  encryption under the store DEK, an `open + PRAGMA integrity_check + row-count` restore-verify); this ADR consumes
  its output. If #60's restore-verify **fails**, or the backup cannot be decrypted, the DR box **refuses to
  activate** (never silently degrades onto an unverified/empty store).

- **Key availability at the DR site (the consequence the owner posture calls out).** Because #60's backup archive
  is **encrypted** (the whole archive, since the config bundle can carry secrets) with the store DEK via the
  KeyProvider seam (ADR 0019), **the DR box must be able to obtain that decryption key at the DR site** to restore
  it. This is an explicit operator precondition, recorded here and in the runbook: the same KeyProvider /
  DEK-wrapping configuration (e.g. the KMS/HSM/Vault endpoint, or the key file under OS-protected perms) **must be
  reachable from the DR box**. The engine **fails the restore closed with a clear error** if the key is
  unavailable — it never falls back to plaintext and never starts against an undecryptable backup. There are **two
  distinct failure modes** the engine must handle, both fail-closed: (1) the archive is reachable but
  **cannot be decrypted** (wrong/missing wrapped key — AC-9); and (2) the configured KeyProvider endpoint is set
  but is **unreachable from the DR site** within a bounded timeout (a KMS/Vault reachable only from the primary —
  AC-14). The second is the **most likely real-world DR-key failure**; the engine must abort with a clear
  "KeyProvider unreachable at DR site" error (no hang, no silent retry-forever, no plaintext fallback). "A
  KeyProvider reachable only from the primary site" is therefore a **pre-activation operator checklist item** in
  the runbook; a portable/escrowed key for the DR site is the operator's responsibility.

- **Warm DB replication is OUT of this slice (DBA-owned, future).** A continuously-replicated DR-site store
  (PostgreSQL streaming replication / SQL Server Always On) would give near-zero RPO / seconds RTO, but it is
  **not** the chosen path here: it is DBA-owned infrastructure outside the engine's role, and the owner posture is
  explicitly **cold**. The engine's cold path is the built behavior; a warm seed is a possible **future** mode for
  a deployment whose DBA already replicates the store, not specified or built here.

Either way, **config** (Routers/Handlers/`connections.toml`/`environments/<env>.toml`) arrives by the normal
git-redeploy of the org-owned config repo (ADR 0017) — including the new `priority` keys — and/or via the config
half of #60's bundle; the runbook pins which is authoritative.

### Single-active-writer guard on the cold-restored store

The cold seed is a restore of an **independent** copy of the store taken at the backup moment. If the production
backend was a server DB, that restored copy **carries a `leader_lease` row from the backup instant**. The engine
**must never treat the cold-restored copy's own `leader_lease` as authoritative** for the split-brain quorum check
below: the lease consulted for arbitration is **only** the lease in a **still-live primary/replica production
store**, never the DR box's own restored row. On a fully-gone-store cold restore (the disaster that triggers DR),
there is no live store to consult, the restored copy's lease is ignored entirely, and the **VIP acquire-or-abort
is the sole fence** (see below). This keeps the single-active-writer invariant intact: a re-run/restart of the DR
box against its own restored store can never read its own stale lease and believe it holds leadership of the
(gone) primary.

### Activation mode (engine/DR-box-level, not per-connection)

**Locked (owner posture, 2026-06-28): activation is MANUAL — a `manual` runbook is the only built mode.** A
configurable `[dr].activation_mode`:

- **`manual` (default and the only mode built in this slice)** — the DR box takes over **only** on explicit
  operator action: an operator declares the HA pair down and promotes DR. The interface is a **new**,
  **audited, RBAC-gated control endpoint** (`POST /dr/activate`) invoked from the runbook / CLI. There is **no
  existing cluster *control* endpoint to mirror** — the tier-2 cluster API is **read-only**
  (`GET /cluster/status`, `GET /cluster/nodes`; active-passive failover is automatic lease-based with no operator
  stepdown). `POST /dr/activate` and `POST /dr/release` are net-new endpoints that reuse the project's standing
  RBAC + audit patterns: gated by `Depends(require(Permission.CONNECTIONS_CONTROL))` (a high-privilege
  connection-lifecycle permission held by `Role.ADMINISTRATOR`; a dedicated `dr:operate` permission may be minted
  at ratification) and recording every action and every abort via the `auth/service.py` audit log
  (`_audit("dr.activate"/"dr.release"/"dr_activation_aborted", actor=…)`). No health-probe ever activates a
  `manual` box; there is no auto-probe in this slice.
- **`auto` (deferred future mode — NOT built here).** A future mode in which the DR box takes over automatically
  when it cannot reach the primary AND the HA passive (the *whole HA pair* unreachable, not just one node), gated
  by a configured health-probe window tuned to exceed the tier-2 leader-lease TTL. **It is named here only as a
  forward-looking option; this ADR neither specifies nor builds the probe (no `probe_targets`/interval/
  miss-threshold).** Ping-based site decisions are higher-risk, so the owner posture is manual-first; `auto` is a
  candidate for a later ADR once the manual runbook and fencing are proven in the field. Config load **rejects**
  `activation_mode = auto` with a clear "not yet supported" error until that future mode lands — never a silent
  no-op.

This setting lives in **engine service settings** (`messagefoundry.toml` `[dr]`), **not** `connections.toml` — it
is a property of the DR deployment, not of any endpoint. A new `DrSettings` section is added to
`config/settings.py` (alongside `ClusterSettings`/`RetentionSettings`) and threaded into `ServiceSettings` and the
`Engine`; a deployment with no `[dr]` section defaults to a no-op DR config and is unaffected. Unknown or malformed
`[dr]` values (an unknown `activation_mode`, a bad `priority_threshold`) **fail config load with a clear error** —
never a silent default.

### VIP takeover and fencing (the engine-vs-infra boundary)

On activation the DR box must **take over the service Virtual IP (VIP)** so partners/senders keep connecting to the
same address with **no client reconfiguration**. The VIP is also the **single fencing / arbitration token**: only
one node may hold it at a time, and *that* is what makes a manual promotion safe against a partitioned-but-alive
primary. This is the **same VIP** that tier-2 HA / the ADR 0047 operator-assembled load balancer already moves
between leader and standby — here it is reassigned **one tier down**, to the DR box.

**The mechanism is the PASSIVE one ADR 0047 ships — the engine does not drive VIP reassignment.** ADR 0047
(option 5, lines ~193–198 + Out-of-scope) **explicitly rejects** "an engine-managed VIP (the engine actively
reassigns the floating IP on failover)" and reserves engine-driven VIP work for a separate future ADR. This ADR
therefore **does not** make an engine VIP hook its fence. Instead it rides the same passive primary-only LB
health check: the DR box, on activation, **binds its high-priority listeners**, and the operator-assembled L4 load
balancer's health check (which targets the active node) moves the VIP to the DR box because only a live, bound node
answers — exactly as the VIP follows the tier-2 leader today, with **zero engine VIP code**. The engine's
contribution is the **decision** (when to activate) + the **priority-feed startup** + (optionally) a verification
that the VIP has in fact converged.

The boundary is explicit and consistent with the project's other delegations (DB-tier → DBA; OCSP/PKI → infra;
the L4 LB / VIP-follows-failover packaging → ADR 0047):

- **Infra owns the VIP-reassignment mechanism** — the ADR 0047 operator-assembled L4 LB / primary-only health
  check (or keepalived / Windows Failover Clustering / NLB in a non-LB topology). The engine **must not manipulate
  OS networking itself.**
- **The engine owns the decision (when) and the priority-feed startup.** An **optional, belt-and-braces**
  `dr.takeover_hook` / `dr.release_hook` may name an operator-supplied command for topologies whose VIP does **not**
  follow a health check automatically (e.g. bare-metal keepalived that needs an explicit nudge). It is **not the
  primary fence** and **not required** for an ADR-0047 LB deployment. When configured, its contract is load-bearing
  (see *To resolve*): exit code 0 / command success = "VIP acquired", any non-zero / timeout (`dr.takeover_timeout_seconds`)
  = "not acquired", and a hook failure **must not allow activation to proceed**.

**Activation ordering is fixed and is the no-fenced-but-dead-box guarantee.** The engine MUST, in order:
**(1)** obtain the DEK and successfully **open + restore-verify** the #60 backup (decrypt + `integrity_check` +
row-count) — aborting **before** any VIP step if the key is unavailable/unreachable or the backup is
unverified/undecryptable; **then (2)** confirm/acquire the VIP (bind the high-priority listeners so the passive LB
moves it, and/or run the optional takeover hook), aborting if the VIP cannot be confirmed within the timeout;
**then (3)** begin serving. This ordering means a key-unavailable or unverified-backup failure aborts **before** the
VIP is taken — there is **no window where the VIP is held but the store will not open** (no fenced-but-dead DR box).

**Activation is acquire-VIP-or-abort.** If the VIP cannot be confirmed/acquired (the passive LB has not moved it,
or the optional hook failed/timed out), the engine **aborts activation, binds no high-priority listener serving the
VIP, stays passive, and records a `dr_activation_aborted` audit row** with the reason. Because only one node can
hold the VIP, a partitioned-but-alive primary and the DR box can therefore **never both serve** the high-priority
feeds.

### Split-brain & arbitration

A manual promotion can still race a **live** primary that is merely *unreachable* from the operator's vantage
(a partition). The **hard** guarantee that prevents DR and a recovering/partitioned primary from both running the
feeds is the **VIP-as-fence (acquire-or-abort) above**: the partition does not grant DR the VIP, and the engine
refuses to serve without it.

Layered on top — **and only where a server-DB primary store survives the site and is reachable from the DR box** —
is a **tier-2-lease quorum check**: before serving, the DR engine confirms the primary's tier-2 leader lease is
**expired on the DB clock** (reusing the tier-2 `leader_lease` semantics) — if the lease is still held (the primary
is alive, merely partitioned from the operator), the engine **refuses, stays passive, and records a
`dr_activation_aborted` audit row** (reason: primary lease still held).

**This quorum check applies ONLY to a clustered server-DB (postgres/sqlserver) primary that is still reachable.**
On the **default, owner-locked path** — a cold restore of a #60 **SQLite** backup, where the production store is
*gone* (the very disaster that triggers DR) — there is **no `leader_lease` to consult at all** (SQLite always uses
the `NullCoordinator`; there is no lease row), and the engine **must not** consult the cold-restored copy's own
lease. On that path the **VIP acquire-or-abort is the SOLE fence**, and the manual runbook carries the residual
responsibility (the operator declares the pair down before promoting). This is a **real, named residual
split-brain risk on the primary in-scope path** (see Negative/risks): the VIP fence is sound, but unlike the
server-DB path there is no DB-clock corroboration — the operator's declaration plus the single-VIP token are the
whole guarantee.

(An automated probe to *detect* pair-loss — rather than relying on the operator's declaration — is the deferred
`auto` mode above; it is not part of this slice.)

### Degraded-mode partner behavior

Low-priority inbound feeds are **down** on the DR box (their listeners are never bound). The default partner
experience is a **refused connection** — the sender's own MLLP resend/queue covers the gap, which is the
least-surprising behavior and requires no DR-specific protocol.

**Count-and-log during DR — an explicit, accepted coverage reduction (not a redefinition of the invariant).** The
count-and-log invariant continues to hold **unchanged** for every **bound** (high-priority) listener on the DR box:
each message it receives is persisted-before-ACK and dispositioned exactly as in normal operation. A message that a
**filtered (unbound)** listener never accepts is never *received* by the DR box, so there is no ingress row to
persist — accepting-and-dropping never occurs. But this **does** mean site-wide received-volume **legitimately
drops** during DR with no `ERROR`/disposition row anywhere in the engine for the dark feeds. This is a
**deliberate coverage reduction**, not the invariant silently continuing: the missed inbound volume on the dark
feeds is the **primary's responsibility** on fail-back (those senders resend/queue against the recovered primary),
it is surfaced up-front by the **startup filter-summary log** (which names every below-threshold feed), and the
fail-back reconciliation runbook accounts for it. It is listed as a named cost in Negative/risks.

An optional `dr.maintenance_nak` may instead bind the listener and return an explicit maintenance NAK (AE/AR) so a
sender that does not retry-on-refusal gets a clear signal. **Feasibility caveat:** the current engine model is
**persist-then-AA-on-receipt** (ACK-on-receipt, ADR 0001), where a `FILTERED` disposition is a *post-ingress
finalizer outcome*, not a synchronous pre-ACK decision at the listener. A synchronous "persist-as-ingress,
immediately finalize `FILTERED`, then NAK" at a bound maintenance listener is therefore **net-new listener
behavior**, not a drop-in reuse of existing plumbing — the exact pre-NAK `FILTERED` mechanism is an open item (see
*To resolve*). The intended contract, if built: each such message is **persisted to the ingress stage and
dispositioned `FILTERED` before the NAK** — never silently rejected — and the fail-back runbook reconciles those
`FILTERED` rows against the primary.

### Fail-back

Returning to the restored primary must not lose or double-process what DR handled. Fail-back is
**drain-then-hand-back**, operator-driven (`POST /dr/release`, which moves the VIP back — releasing the bind / the
optional release hook so the passive LB returns the VIP to the primary — waits for VIP convergence, then unbinds all
inbound listeners while keeping the workers running to drain, returning success only once the VIP is off the DR box
and listeners are unbound, so there is **no dual-accept window** while the VIP moves):

1. Operator stops new intake on DR — `POST /dr/release` releases the VIP so partners reconnect to the primary and
   listeners stop accepting; the operator waits for VIP / ARP / route convergence before restarting the primary.
2. DR **drains its staged queue to completion** (all `outbound` rows delivered or dead-lettered) **before
   `POST /dr/release` returns**. *Within DR's single store* the at-least-once + idempotency invariants make this
   safe: any row re-run re-derives identical output, and idempotent outbounds tolerate a duplicate.
3. Primary resumes against the authoritative store. Because the owner-locked seed is **cold**, DR ran on a
   **separate restored copy** that has since diverged from the primary's recovered store. **Across this cold
   handoff the engine provides NO cross-store guarantee** — at-least-once/idempotency are within-a-store properties
   and do **not** extend across the two stores — so the two stores **must be explicitly reconciled per the mandatory
   runbook below**. There is no engine auto-merge, and silent fail-back is not permitted. Crucially, **at no point
   do both serve the same VIP**, so no partner is ever double-targeted.

**Cold-restore fail-back runbook (mandatory; the cross-store reconciliation is operator-verified, not an engine
AC).** Because the engine does not reconcile divergent stores, a cold fail-back follows explicit, non-silent steps:
(a) stop intake and drain DR to completion as above; (b) the DBA/operator selects the **authoritative** store (or
merges), identifying rows the primary's store is missing that DR processed, and rows DR never saw (the dark-feed
volume); (c) any DR-handled-but-primary-missing work is replayed onto the authoritative store *before* the primary
resumes; (d) any `dr.maintenance_nak` `FILTERED` rows are reviewed and replayed or discarded against the primary's
state; (e) primary resumes only against the reconciled, restore-verified store. At-least-once + idempotency mean a
duplicated delivery in this window is tolerated by idempotent outbounds, but **missed or double-processed
reconciliation across the two stores is an operator responsibility, not an engine guarantee** — the cold path
carries a real RPO and this reconciliation burden by design (the explicit cost of the owner-chosen cheap, cold DR).

## Acceptance Criteria

> EARS — testable, each linked to a test/fixture. (Paths below are the intended homes; created with the build.
> `messagefoundry adr-analyze` checks each `→` link resolves once the build lands.)

- **AC-1** — WHERE a connection declares no `priority`, THE SYSTEM SHALL resolve its tier to the
  `[delivery].priority` global default; WHERE it declares an explicit `priority`, THE SYSTEM SHALL use that value
  (resolution order: per-connection override > `[delivery]` global default > built-in `normal`).
  → `tests/test_priority_resolution.py::test_priority_inherits_then_overrides` (built)
- **AC-2** — WHEN the engine starts under a DR run-profile with threshold X, THE SYSTEM SHALL bind only inbound
  listeners and build only outbound connectors whose resolved priority rank ≥ X's rank.
  → `tests/test_dr_run_profile.py::test_startup_filters_below_threshold` (built)
- **AC-3** — WHILE running under a DR run-profile, THE SYSTEM SHALL still spawn the router/transform workers for
  every inbound (including filtered ones) so crash-recovered `ingress`/`routed` backlog drains.
  → `tests/test_dr_run_profile.py::test_filtered_inbound_drains_backlog` (built)
- **AC-4** — IF a connection is skipped by the DR run-profile, THEN THE SYSTEM SHALL report it as
  `status:"filtered"` on `GET /connections`, `GET /connections/{name}/metadata`, and the console — a fifth status
  value distinct from `running` / `stopped` / the ADR-0031 `failed` / `draining`.
  → `tests/test_dr_api_status.py::test_filtered_vs_failed_status` (built)
- **AC-5** — WHEN a high-priority (bound) inbound on the DR box receives a message, THE SYSTEM SHALL persist it
  before the ACK and record its disposition (the count-and-log invariant holds in degraded mode for every bound
  listener). *(Inherent — a bound listener on a DR box is an ordinary bound listener: the run-profile changes
  WHICH listeners bind, never the persist-then-ACK count-and-log path a bound one runs. The
  `tests/test_dr_run_profile.py::test_filtered_inbound_drains_backlog` case exercises a bound critical lane
  finalizing a message under the profile; no behavior change to assert separately.)*
- **AC-6** — WHEN `POST /dr/activate` is invoked AND the VIP cannot be confirmed/acquired (the passive LB has not
  moved it, or — where configured — the optional takeover hook errors or exceeds `dr.takeover_timeout_seconds`),
  THE SYSTEM SHALL abort activation, bind no high-priority listener serving the VIP, remain passive, AND record a
  `dr_activation_aborted` audit row with the reason.
  → `tests/test_dr_activation.py::test_acquire_vip_or_abort_records_audit` (built)
- **AC-7** — WHEN `POST /dr/activate` is invoked AND the store backend is a clustered server-DB
  (postgres/sqlserver) whose `leader_lease` is reachable AND still shows the primary's lease unexpired on the DB
  clock, THE SYSTEM SHALL refuse to serve, remain passive, AND record a `dr_activation_aborted` audit row (reason:
  primary lease still held) — and SHALL NOT serve concurrently with the primary under any partition.
  *(Server-DB-only, NOT in this slice's owner-locked SQLite cold path. The quorum check rides the shipped tier-2
  `leader_lease` semantics; on the SQLite cold path there is no lease to consult — AC-13 covers that path, where
  the VIP acquire-or-abort is the sole fence. A server-DB quorum-refuse test lands with the warm/server-DB DR
  follow-up, not this SQLite slice.)*
- **AC-8** — IF `activation_mode = manual` (the default), THEN THE SYSTEM SHALL activate only on the explicit,
  RBAC-gated `POST /dr/activate` operator action and SHALL NOT activate on any automatic/background trigger.
  → `tests/test_dr_activation.py::test_manual_only_activation` (built)
- **AC-9** — WHEN the DR box activates against a #60 backup whose restore-verify fails OR whose archive cannot be
  decrypted (the wrapped DEK is wrong/missing), THE SYSTEM SHALL refuse activation with a clear error and SHALL NOT
  start against an empty/unverified/plaintext store (fail-closed; never silently degrade) — AND SHALL do so
  **before** acquiring the VIP (no fenced-but-dead box).
  → `tests/test_dr_seeding.py::test_refuses_unverified_or_undecryptable_backup_before_vip` (built)
- **AC-10** — WHEN a settings file sets `[delivery].priority`, a connection `priority`, or any `[dr]` value to an
  unknown/malformed value (an unknown `activation_mode`, the not-yet-supported `auto` mode, an invalid
  `priority_threshold`), THE SYSTEM SHALL fail config load with a clear error (never silently default).
  → `tests/test_settings.py::test_invalid_priority_and_dr_settings_rejected` (built)
- **AC-11** — WHEN `POST /dr/release` is invoked, THE SYSTEM SHALL release the VIP, wait for it to converge,
  **drain all `outbound`-stage rows to delivered/dead-lettered**, unbind all inbound listeners while the workers
  drain, AND return success only once the VIP is off the DR box and no listener is bound (no dual-accept window
  while the VIP moves). Cross-store reconciliation with the recovered primary is **operator-verified per the
  runbook, not an engine guarantee**.
  → `tests/test_dr_failback.py::test_release_drains_then_hands_back` (built)
- **AC-12** — WHERE `dr.maintenance_nak` is enabled, WHEN a bound maintenance listener receives a message, THE
  SYSTEM SHALL persist it to the ingress stage and disposition it `FILTERED` **before** returning the maintenance
  NAK (never a silent reject). *(**NOT built this slice** — the ratification (2026-06-28) decided a refused
  connection is the DR partner behavior for down feeds; `dr.maintenance_nak` documents the contract if a future
  slice builds it. There is no `[dr].maintenance_nak` setting in this slice.)*
- **AC-13** — WHEN the DR box activates from a cold restore AND no live production/replica server-DB store is
  reachable, THE SYSTEM SHALL NOT consult the restored copy's own `leader_lease` row for arbitration AND SHALL rely
  on the VIP acquire-or-abort as the sole fence (single-active-writer preserved on the cold path).
  → `tests/test_dr_seeding.py::test_cold_restore_ignores_own_lease` (built)
- **AC-14** — WHEN the DR box activates AND the configured KeyProvider endpoint (KMS/Vault/HSM/key file) is set but
  **unreachable from the DR site** within a bounded timeout, THE SYSTEM SHALL fail activation closed with a clear
  "KeyProvider unreachable at DR site" error (no hang, no plaintext fallback, no silent retry-forever) — distinct
  from the in-archive decrypt failure of AC-9.
  → `tests/test_dr_seeding.py::test_keyprovider_unreachable_at_dr_site_fails_closed` (built)
- **AC-15** — WHEN the DR box starts against a restored cold copy, THE SYSTEM SHALL run `reset_stale_inflight` so
  in-flight rows of **every** stage (`ingress`/`routed`/`outbound`) carried in the backup are recovered and re-run
  (the reliability invariant's startup recovery, applied to the restored store).
  → `tests/test_dr_seeding.py::test_cold_restore_resets_stale_inflight_all_stages` (built)

## Options considered

1. **Right-sized, degraded, priority-filtered DR standby — cold-seed from #60, manual activation, passive-VIP
   fence, engine-owned decision + delegated VIP/restore** — adds a per-connection priority tier and a
   selective-startup run-profile on the existing ADR-0031 path; cold-seeds the store from #60's encrypted,
   restore-verified backup; **delegates the VIP move to ADR 0047's passive operator-assembled L4 LB** (the engine
   does not drive it) and the backup mechanic to #60; manual activation fenced by acquire-or-abort VIP plus a
   tier-2-lease quorum check **only where a server-DB primary store is reachable**. Cheapest credible site-loss DR;
   reuses proven plumbing; honors every invariant within-a-store. **CHOSEN (owner posture locked 2026-06-28).**
2. **Engine-driven VIP takeover hook as the primary fence** — the engine invokes a command to acquire the VIP and
   makes that hook its sole guarantee. **Rejected:** ADR 0047 explicitly reserves "engine-managed VIP failover" to
   a separate future ADR and ships a *passive* primary-only-health-check LB instead; making an engine VIP hook the
   fence would claim that reserved scope. The hook survives only as an **optional** belt-and-braces for non-LB
   topologies, never the lone fence.
3. **Warm DB-replica DR seed (DBA-owned streaming replication / Always On to the DR site)** — best RTO/RPO
   (near-zero), the DR engine starts against a live replica. Rejected for this slice: it is DBA-owned
   infrastructure outside the engine's role, and the owner posture is explicitly **cold** (no warm replica). A
   possible future mode for deployments whose DBA already replicates the store — not built here.
4. **Auto-probe activation (the DR box detects pair-loss and promotes itself)** — better RTO (no human in the
   loop). Deferred: ping-based site decisions are higher-risk; the owner posture is manual-first. Named only as a
   future mode; config rejects `auto` until that mode lands.
5. **Full hot standby site (second full-capacity HA cluster)** — best RTO/RPO, but doubles full-size hardware that
   mostly idles. Rejected: defeats the budget premise of #61; no engine work needed beyond tier-2 anyway (it *is*
   tier 2 at another site).
6. **Active-active horizontal scale-out** — every node runs the graph concurrently. Rejected: **dropped
   2026-06-18, code removed** (lane-ownership / `lane_leases`); DR here runs *less*, not more — the opposite of
   scale-out.
7. **Pure DBA/infra DR with no engine role** — DBA replicates the store, infra moves the VIP, engine does nothing
   special. Rejected: it cannot run a *reduced* feed set (no priority tier), so the "right-sized box" must either
   be full-capacity or hand-edited per failover — exactly the gap this ADR fills.
8. **Do nothing** — accept that whole-site / store loss is unrecovered until the DBA restores the primary.
   Rejected: a recognized enterprise expectation and a Corepoint-parity gap (standby failover/failback).

## Consequences

**Positive**
- Cheap, credible site / HA-pair-loss DR without a second full-capacity hot standby, seeded from the backups #60
  already produces — no new replication infrastructure.
- The per-connection priority tier is **reusable** (load-shedding, ordered startup, alert severity) and follows
  the established override idiom (zero new config-resolution concept).
- Reuses the ADR-0031 selective-startup path and **ADR 0047's passive VIP-follows-failover LB** (no engine VIP
  code, nothing 0047 reserved) — minimal new machinery, no new supervisor, no "channel" element.
- Within-a-store invariants preserved: degraded mode still persists-before-ACK and dispositions every message a
  **bound** listener takes; fail-back drains DR's own store via at-least-once + idempotency *within that store*;
  the DR seed stays encrypted PHI-at-rest (no new cleartext tier, no cloud egress).
- `manual` activation keeps the higher-risk auto-promotion out of this slice; the startup filter summary makes the
  curated critical set auditable on every activation, and every refused activation leaves a
  `dr_activation_aborted` audit trail.

**Negative / risks**
- **Cross-store fail-back has NO engine guarantee.** at-least-once + idempotency are within-a-store properties; the
  cold seed runs DR on a separate store that diverges from the recovered primary, so loss/duplication across the
  two stores is prevented only by the **mandatory operator reconciliation runbook**, not by the engine. Skipping or
  fumbling that runbook causes message loss or double-processing.
- **Reduced count-and-log coverage during DR (by design).** Low-priority feeds are dark on DR, so site-wide
  received volume legitimately drops with no engine disposition row for those feeds. The invariant still holds
  fully for every *bound* listener; the dark-feed volume is the primary's responsibility on fail-back, surfaced by
  the startup filter-summary log and accounted for in the reconciliation runbook. Operators must curate the
  critical-feed set correctly (a mis-tagged feed is absent in DR — mitigated, not eliminated, by the summary log).
- **Cold (#60-restore) seeding carries real RPO** (backup cadence — daily by default) and the mandatory
  reconciliation burden above. (Near-zero RPO would require warm DB replication, explicitly out of this slice.)
- **Residual split-brain on the SQLite cold path.** The tier-2-lease quorum check only fires for a **reachable
  server-DB** primary; on the default SQLite cold-restore path (store gone) there is no lease to consult and the
  **VIP acquire-or-abort is the sole fence** — the operator's pair-down declaration plus the single-VIP token are
  the whole guarantee there. A no-op/misconfigured VIP move (or an optional hook that lies) would undermine
  fencing — so the VIP convergence check (and, where configured, the hook contract: exit code, timeout,
  abort-on-failure) must be tested and documented before build.
- **Key availability at the DR site is a hard precondition.** Because the #60 backup is encrypted with the store
  DEK (ADR 0019), the DR box must reach the KeyProvider / hold the wrapped key to restore — a KeyProvider reachable
  only from the primary site would leave the DR box unable to restore. The engine fails closed (clear error, no
  plaintext fallback) for both the in-archive decrypt failure (AC-9) and the unreachable-endpoint case (AC-14); the
  operator owns provisioning a DR-reachable/escrowed key.
- DR is a small box — under load it may shed even some high-priority traffic; sizing is the operator's
  responsibility.

**Out of scope**
- **Warm DB replication mechanics** (PostgreSQL streaming replication / SQL Server Always On, failover
  orchestration, split-brain arbitration at the DB layer) — **DBA-owned**, consistent with the standing DB-tier-HA
  decline; not the seed path here.
- **The backup/restore-verify + encryption mechanic itself** — that is **#60 / ADR 0049** (authored in parallel,
  not yet in this worktree); this ADR consumes its encrypted output and does not re-specify it.
- **Engine-driven VIP reassignment** — reserved by ADR 0047 to a separate future ADR; this ADR rides 0047's
  passive LB and offers only an optional, non-fence takeover hook.
- **Auto-probe activation** — deferred future mode; not specified or built here (no probe targets/interval/threshold).
- **Active-active scale-out** — dropped.
- **Per-message priority** — the tier here is a *connection* attribute; a message-level priority (set in a
  Handler) is a separate, future concern.

## To resolve on acceptance

> The owner DR posture is **locked into the body above** (cold-seed-from-#60, manual activation, `auto` deferred,
> passive-VIP fence). The items below are **ratification confirmations** plus the handful of genuinely-open contract
> details to settle before this flips to `Accepted`. Tracked so `adr-analyze` surfaces anything still open.

- [ ] Confirm the default `[dr].priority_threshold` (proposed `CRITICAL`) and whether `NORMAL` should also start
      in DR for some deployments.
- [ ] Ratify that `priority` lives on **both** `InboundConnection` (beside `messages_days`/`prune_documents_after`/
      `ack_after`) and `OutboundConnection` (beside `retry`/`ordering`/`buildup`/`stall`), and the inbound/outbound
      tier-independence.
- [ ] **Lock the optional `dr.takeover_hook` / `dr.release_hook` contract** (only for non-LB topologies that need
      an explicit nudge) — invocation, environment, success signal (exit code 0 / command success),
      `dr.takeover_timeout_seconds`, abort-on-failure, and how the engine verifies VIP convergence when the passive
      LB is the fence (no hook).
- [ ] Confirm the tier-2-lease quorum precondition scope: **required wherever a reachable server-DB primary store
      exists** at activation; on the SQLite/store-gone cold path the VIP acquire-or-abort is the **sole** fence
      (AC-7/AC-13) — sign off that the residual split-brain risk on that path is acceptable for the owner posture.
- [ ] Confirm the DR-site **key-availability** preconditions and fail-closed behavior for **both** failure modes:
      in-archive decrypt failure (AC-9) and KeyProvider-endpoint-unreachable-from-DR (AC-14); add the "KeyProvider
      reachable only from primary" check to the runbook precondition list.
- [ ] **Net-new pipeline work flagged, not assumed:** decide whether to build `dr.maintenance_nak` at all, and if
      so lock the **synchronous persist-ingress → finalize `FILTERED` → NAK** mechanism at a bound listener — it is
      *not* a drop-in under the current persist-then-AA-on-receipt model (ADR 0001) and needs a real listener change
      (or accept refused-connection as the only DR partner behavior in this slice).
- [ ] Lock the manual-activation surface — the **new** `POST /dr/activate` / `POST /dr/release` endpoints (RBAC via
      `Depends(require(Permission.CONNECTIONS_CONTROL))` or a dedicated `dr:operate` permission; the
      `auth/service.py` `_audit(...)` rows incl. `dr_activation_aborted`), the fixed activation **ordering**
      (key+restore-verify → VIP → serve), and the `POST /dr/release` drain-then-hand-back semantics.
- [ ] Confirm the **mandatory cold (#60-restored) fail-back reconciliation runbook** wording so nothing DR handled
      is lost or double-processed across the two stores (operator-verified, not an engine AC), and pin which copy
      (#60 config bundle vs git-redeploy) is authoritative for config on the DR box.
- [ ] Verify the corrected `0048` row in [`docs/adr/README.md`](README.md) (updated in this finalization to the
      cold-only / manual-only / passive-VIP posture) reads correctly to the owner, and that the ADR 0047
      cross-reference (To-resolve item) agrees that 0047 keeps the VIP slot and engine-managed-VIP stays a future
      number.


---

## Ratification decisions (2026-06-28)

- **VIP boundary** resolved per ADR 0047: the passive primary-only-health-check LB is the fence (the DR box binds, the VIP follows); the `dr.takeover_hook` is **optional belt-and-braces for non-LB topologies only**, never the lone fence.
- **`dr.maintenance_nak` is NOT built this slice** — a refused connection is the DR partner behavior for down (low-priority) feeds; senders' own resend/queue covers the gap. (AC-12 documents the contract *if* later built.)
- **Residual split-brain on the SQLite cold path is ACCEPTED by posture:** SQLite uses `NullCoordinator` (no lease row), so the tier-2 lease quorum cannot fire — the **VIP acquire-or-abort fence + the operator's manual pair-down declaration are the sole fence**. Documented loudly in the runbook.
- **RBAC:** mint a dedicated **`dr:operate`** permission for `POST /dr/activate` | `/dr/release` (held by `ADMINISTRATOR`), not a reuse of `CONNECTIONS_CONTROL`.
- **`[dr].priority_threshold` default = `CRITICAL`;** `priority` on **both** inbound and outbound connections, tiers independent.
- **DR-site key availability:** two fail-closed modes both required + tested — in-archive decrypt failure (AC-9) and KeyProvider-unreachable-from-DR within a bounded timeout (AC-14); runbook precondition "KeyProvider reachable from the DR site."
- **Cross-store cold fail-back reconciliation is operator-verified** (the engine gives no cross-store loss/duplicate guarantee; at-least-once/idempotency are within-a-store only); the runbook pins which config copy is authoritative.
