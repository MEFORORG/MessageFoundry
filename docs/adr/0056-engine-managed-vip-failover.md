# ADR 0056 — Engine-managed virtual IP (VIP) failover

- **Status:** Proposed (2026-06-27) — drafted on the owner's go. **No code**; this is a **design**
  decision to record the seam, the correctness argument, the privilege cost, and the operator surface
  before any build. There is **no engine-managed-VIP code today** — every reference below to a bind/
  release/`/cluster/stepdown`/VIP-owner field is **proposed**, not built.
  - **ADR number:** first drafted as `0047`; that slot was reassigned on `origin/main` (to the cloud/k8s
    HA deployment-packaging ADR), so this was renumbered to `0056` — the next free number on `main`, which
    now carries through 0055. Parallel worktrees can race the number, so confirm `0056` is still free
    (`git fetch`) before merging.
- **Amends:** the **"document, don't build" VIP stance.** The floating VIP was previously declared an
  **operator/infra responsibility** — MEFOR "designs for the VIP and exposes the health-check/role
  endpoints, but **does not ship a load balancer** — you stand it up (keepalived, HAProxy, F5, a cloud
  NLB, …)" ([DEPLOYMENT.md](../DEPLOYMENT.md) §"High availability"; [CLUSTERING.md](../CLUSTERING.md)
  §"Client reconnect"; `docs/marketing/ha-failover-research-2026-06-14.md`, a local research note).
  This ADR adds an **opt-in** path where the **engine itself** owns the VIP, tied to the leadership
  lease. It does **not** retract the external path — that stays the default and the recommended posture
  for the strictest split-brain guarantee.
- **Decision in one line:** optionally let the engine **bind the VIP on leader promotion** (with a
  gratuitous ARP) and **release it on demotion / self-fence / clean stop**, so an active-passive cluster
  gets Corepoint-style "the standby takes the address on failover" **without** an external L4 LB **or** an
  external VRRP/WSFC agent — at the cost of granting the otherwise-least-privilege engine network-config
  rights, and accepting a residual split-brain-on-the-wire window that dedicated VRRP does not have. A
  read-mostly **console "High Availability" page** (the Corepoint A2 equivalent) plus one **audited,
  RBAC-gated control endpoint** (`POST /cluster/stepdown`) give operators the monitor-and-control surface.
  **Engine-managed VIP is Windows-only at v1** (Linux is a possible later increment, explicitly out of
  scope now) — only *this feature* is Windows-only; the rest of HA stays cross-platform.
- **Related:**
  - [ADR 0008](0008-cluster-observability-api.md) (`/cluster/status` + `/cluster/nodes`, the read-only
    leadership surface this extends with VIP ownership) and [CLUSTERING.md](../CLUSTERING.md)
    (active-passive HA: the self-fencing lease, leader-gated graph, on-promotion recovery, the current
    **external** floating-VIP topology this amends);
  - [ADR 0031](0031-startup-connection-fault-isolation.md) (startup fault isolation + the
    `RegistryRunner` supervisor / `AlertSink` a VIP failure surfaces through);
  - [ADR 0037](0037-multi-process-sharding-l3.md) (the multi-process/cluster shape; a per-shard VIP is a
    *To resolve* item, not a v1 goal);
  - the leadership-lease + self-fence + epoch-token core in
    [`pipeline/cluster.py`](../../messagefoundry/pipeline/cluster.py) (Postgres,
    `DbCoordinator._check_fence` / `_release_leadership`) /
    [`pipeline/cluster_sqlserver.py`](../../messagefoundry/pipeline/cluster_sqlserver.py) (SQL Server),
    the graph supervisor in [`pipeline/engine.py`](../../messagefoundry/pipeline/engine.py)
    (`_reconcile_graph` / `_start_graph` / `_stop_graph`), the timing invariant in
    [`config/settings.py`](../../messagefoundry/config/settings.py) (`ClusterSettings._fence_ordering`);
  - [SERVICE.md](../SERVICE.md) §"Run as a least-privilege account (**DEPLOY-1**)" — the hardening
    direction this decision is in direct tension with;
  - [CLAUDE.md](../../CLAUDE.md) §2 (reliability + count-and-log; asyncio cooperative cancellation),
    §5/§9 (untrusted data / PHI; on-premises by default), §10 (console reaches the engine **only** via the
    HTTP API), and the *no-grouping-unit* model (this binds an *address*, not a new "channel" element).

---

## Decisions taken (2026-06-27)

The owner resolved v1 scope; the items below are **decided**, not open (the *To resolve* list at the end
is reduced to genuine build-time leftovers):

| Decision | Choice |
|---|---|
| **Platform (v1)** | **Windows only.** `netsh` + a Windows privileged helper, NSSM-first. **Linux (`ip addr` / CAP_NET_ADMIN) is explicitly out of scope for v1** — a possible later increment, not a promise. Engine-managed VIP is documented as a **Windows-only** capability until/unless Linux is added. |
| **Privilege mechanism** | **Privileged helper** (`mefor-net-helper.exe`, `requireAdministrator`, caller-authenticated named-pipe IPC, scoped to the one configured VIP+interface). The engine itself stays least-privilege per DEPLOY-1. |
| **Self-fence release failure** | **Alert + force-close, keep running.** On release timeout/failure: CRITICAL `AlertSink` alert + force-close listener sockets; the engine does **not** fail-closed-stop (it is already not processing — epoch is stale). No operator toggle. |
| **Failover authorization** | **`CLUSTER_CONTROL` = ADMINISTRATOR-only**, gated by `require_step_up()` **+ TOTP MFA**. **No** second-approver dual-control at v1 (reconsider in a later increment). |
| **IPv6** | **Deferred (all platforms).** IPv4 gratuitous ARP only at v1; IPv6 NDP / unsolicited-NA is a later cross-platform follow-up (not a Windows-specific gap). |
| **Console surface** | **Dedicated "High Availability" page** (not an extension of the Engine Status cluster box); needs a bundled nav icon. |
| **Stepdown `force` flag** | **Deferred.** v1 ships clean lease-release only; `409` is the normative non-leader response. |

**Cross-platform scope — read this carefully.** Only **engine-managed VIP** is Windows-only. The rest of
HA — active-passive clustering, the lease / epoch / leader-gated graph, on-promotion recovery, and the
**external** floating-VIP / L4-LB path — stays **cross-platform** (PostgreSQL **or** SQL Server;
Linux, Windows, and k8s). A Linux or containerized operator keeps using the external VIP / LB exactly as
today; engine-managed VIP simply is not offered to them at v1. The user-facing HA docs
([CLUSTERING.md](../CLUSTERING.md), [DEPLOYMENT.md](../DEPLOYMENT.md)) must carry this Windows-only caveat
when the feature ships, so no one expects it on Linux.

---

## Context

MessageFoundry's HA is **active-passive clustering** and is **already built** ([CLUSTERING.md](../CLUSTERING.md),
Track B): N identical engine processes against **one** shared server DB (PostgreSQL or SQL Server); a
**self-fencing leadership lease** elects exactly one leader; the **whole graph** (all listeners + the
router/transform/delivery workers) runs **only on the leader**; a standby binds nothing and contends
only. The correctness pivots are closed and **must not be re-decided here**:

- **Self-fencing lease.** The leader renews the `leader_lease` row every `heartbeat_seconds` on the
  **database's** clock; a standby acquires only once the lease has **expired**. A leader that cannot
  renew within `leader_fence_timeout_seconds` **self-fences** (`_check_fence` sets `is_leader=False` in
  memory, drops its epoch — a **pure in-memory, no-DB-I/O** action so it fires even when the DB is
  unreachable). The load-time invariant `heartbeat_seconds < leader_fence_timeout_seconds <
  leader_lease_ttl_seconds` (defaults 10s/20s/30s; `ClusterSettings._fence_ordering`) **guarantees a
  partitioned old leader stops processing before a standby can acquire** — the split-brain guard.
- **Store-checked leader epoch (H1).** A monotonic `leader_epoch` bumped **only on a fresh acquire** is a
  durable second backstop: a superseded ex-leader that resumes after a long pause claims **0 rows** (its
  epoch is stale; the claim `UPDATE` matches nothing). Server-DB-only; a no-op on SQLite.
- **On-promotion recovery (#293).** The new leader recovers the prior leader's stranded in-flight rows
  immediately (owner-scoped, lease-blind), so failover delivery resumes at once.

Today the **VIP is delegated outward.** Clients reach "the engine" through an operator-stood-up
**floating VIP / L4 LB**, one VIP per inbound port with a **TCP-connect health check** — only the primary
binds the port, so "the check passes only on the primary … on failover the new primary binds the port,
the old one's closes, and the VIP follows" ([CLUSTERING.md](../CLUSTERING.md) §"Client reconnect").
MEFOR exposes the health/role contract and **ships no LB** ([DEPLOYMENT.md](../DEPLOYMENT.md) §"High
availability").

**Why an operator would want the engine to own the VIP instead.** The forcing problem is **parity and
operational simplicity for a Windows-first, on-prem shop**:

1. **No extra component.** keepalived/VRRP is a Linux daemon; WSFC is a Windows Failover Cluster role
   (AD + shared-quorum ceremony); an L4 LB is another appliance to license, monitor, and keep in sync
   with the cluster's own notion of "who's primary." A two-node MEFOR cluster on two Windows VMs (NSSM
   services, a shared SQL Server) currently still needs a **third** HA mechanism just to move one address.
2. **A single arbiter = the lease.** The external path has **two** arbiters: the lease decides who
   *processes*, and the LB's health check / VRRP's priority advertisement *independently* decides who
   *gets traffic*. They can disagree transiently. If the engine moves the VIP **as a strict consequence
   of the lease**, there is **one** arbiter — the address follows the exact same `is_leader()` decision
   that already gates the graph, eliminating the "LB thinks A is healthy but the lease has moved to B"
   skew class.
3. **Corepoint A2 parity.** Corepoint's "standby takes the address on failover" is a headline HA story in
   the HA/failover competitor research (`docs/marketing/ha-failover-research-2026-06-14.md`, a local note). MEFOR can match it out-of-the-box
   for bare-metal/VM rather than saying "and now go configure keepalived."
4. **Windows-first.** The shop is NSSM + SQL Server + PowerShell ([SERVICE.md](../SERVICE.md)); the most
   "native" external option (WSFC) is the heaviest. An engine-owned `netsh` bind is, *operationally*, far
   lighter — which is exactly what makes the **privilege** question (below) the crux.

Two [CLAUDE.md](../../CLAUDE.md) invariants bound this design and **must not** be relaxed:

- **Reliability + count-and-log (§2).** Moving an address must not drop a received message or change a
  disposition. A VIP failure must surface (alert + status), never silently strand a feed.
- **On-premises / least-privilege posture (§9 + DEPLOY-1).** The engine is being pushed *toward* a
  least-privilege service account (read config / read-write data only); IP manipulation needs *more*
  privilege. This ADR cannot hand-wave that tension — it presents it as a first-class open decision.

**What is already closed (do not re-decide).** The lease, self-fence, epoch token, leader-gated graph,
and on-promotion recovery are the existing correctness model and are unchanged. **What this ADR adds:** a
*new* state the engine moves in lockstep with leadership (the VIP), the *new* duplicate-IP-on-the-wire
hazard that introduces, the privilege seam to do it, the lifecycle attach points, and the operator
console/API surface.

## Decision

Add an **opt-in, engine-managed VIP** whose bind/release is a **strict consequence of the leadership
lease** (one arbiter). Single-node and the existing external-VIP path are **byte-identical** until it is
enabled.

### D1 — Bind on promotion, release on demotion/fence/clean-stop (attached to the existing lifecycle)

The VIP controller is a **hook callback** registered at engine init, invoked at the leadership
transitions the lifecycle **already** exposes — no new arbiter, no new poll loop. There are **three
distinct attach points** and naming them precisely matters (the eventual implementer must not hook the
wrong one):

- **Acquire (False→True).** When `is_leader()` flips False→True, **before** `_start_graph()` brings up
  listeners ([`pipeline/engine.py`](../../messagefoundry/pipeline/engine.py) `_reconcile_graph`), the
  controller **binds the VIP** to the configured NIC and **sends an IPv4 gratuitous ARP** (IPv6
  unsolicited neighbour advertisement deferred — see *Out of scope*) to flush peer caches. Bind-before-
  bind-listeners means the address is present when the listener starts answering.
- **Clean stop / demotion — release rides the existing teardown.** On a **clean stop** the lease is
  expired in `_release_leadership()` (called from `engine.stop()`); on a **demotion** the path is the
  *asynchronous* `_graph_supervisor` poll → `_reconcile_graph` → `_stop_graph` — the **same latency as
  listener teardown**. The VIP release attaches here for these two cases. This asynchrony is exactly why
  the duplicate-IP window in §Correctness exists, and is acceptable for clean-stop/demotion (the DB is
  reachable, the lease moves in order).
- **Self-fence — the load-bearing change.** `_check_fence` today is **pure in-memory** and does **not**
  release the VIP (or even tear down the listener socket — that happens later, asynchronously). The
  **mandatory new behaviour** is that the self-fence path **also releases the VIP locally**, as a
  **non-DB action** (so it works precisely in the DB-partition case), within the budget §Correctness
  derives. This is the single most important new contract in this ADR — **not** the bind.

The move is **driven by the lease, never by an independent probe.** This is the single-arbiter property:
the address follows the same `is_leader()` predicate that already gates every listener and worker, so the
VIP can never land on a node the lease says is not primary.

### D2 — The config seam (named, not implemented)

A new optional block under `[cluster]` — **`[cluster.vip]`** — turns the feature on and carries the
address/interface knobs. Exactly **one** of `prefix` / `netmask` is accepted (mutually exclusive,
validated at load):

```toml
[cluster.vip]
enabled               = true            # OFF by default; single-node & external-VIP path unchanged
address               = "10.20.0.50"    # the floating address
interface             = "Ethernet0"     # this node's NIC: Windows adapter name (Linux deferred)
prefix                = 24              # XOR netmask = "255.255.255.0" — exactly one, validated at load
gratuitous_arp        = true            # announce on bind (default true)
release_grace_seconds = 2.0            # new-leader bind/ARP delay (see Correctness); preserves
                                        #   release(old) < bind(new)
```

It validates at config load alongside `_fence_ordering`, and **refuses to load** unless
`[cluster].enabled` and a server-DB backend are set (the same gate as the rest of clustering). It is **a
single address that follows the primary**, not a graph element: it adds a *value*, not a "channel"/
"route" object — the *no-grouping-unit* rule is intact.

### D3 — What this must not break

- **Single-node + external-VIP.** `[cluster.vip].enabled=false` (the default) is a no-op; the shipping
  external-LB topology is unchanged and remains the documented recommendation.
- **The lease / epoch / graph-gating contracts.** D1 *consumes* `is_leader()`; it does not change when or
  how leadership moves. The H1 epoch guard, on-promotion recovery, and FIFO survival are untouched.
- **Reliability + count-and-log.** A VIP bind/release failure is logged at ERROR, alerted (reuse the
  `AlertSink` path per [ADR 0031](0031-startup-connection-fault-isolation.md)), and surfaced on status —
  it never drops a message or changes a disposition.

## Correctness / split-brain — the critical section

The existing self-fencing lease **guarantees no double-processing of graph work**: the graph runs only on
`is_leader()=True`, which flips False **before** the lease can expire (`fence_timeout < ttl`), and the
epoch token is the durable backstop against a long-paused resumer. **None of that changes, and
engine-managed VIP does not weaken it.** But the existing fence guarantee does **not** cover IP release,
and engine-managed VIP introduces a **new, on-the-wire hazard** the external path does not have. Be
skeptical and explicit.

### The release time budget — `ttl − fence_timeout`, not `fence_timeout`

Walk the timeline from the last successful lease renew (defaults heartbeat=10s, fence=20s, ttl=30s):

| Time (after last renew) | Event | Clock |
|---|---|---|
| `T=0` | leader renews; lease set to `DB_now + ttl`; records `_last_renew_ok = monotonic()` | DB + local monotonic |
| `T ≈ fence_timeout` (≈20s) | watchdog fires: `_check_fence` sets `is_leader=False`, drops epoch | local **monotonic** (no DB I/O) |
| `T ≈ ttl` (≈30s) | a standby's acquire tick sees the lease expired and acquires it | **DB** clock |

So after the fence fires, the old leader has only **`ttl − fence_timeout` ≈ 10s** (not `fence_timeout` ≈
20s) to release the VIP before a standby can bind it. **The VIP release deadline is `ttl − fence_timeout`,
measured from the fence firing.** Any ADR/implementation text that says "release within `fence_timeout`"
is wrong by ~2×. The new ordering rule of this ADR is therefore:

> `self-fence fires (≈ fence_timeout)` → `release(old VIP) completes within (ttl − fence_timeout)` →
> `bind(new VIP) only after ttl`.

`_fence_ordering` already enforces `fence_timeout < ttl`, so the budget is always positive; operators who
shrink the timings for faster failover **shrink this budget too** and must keep it larger than the
worst-case local release latency (below). The new leader additionally waits `release_grace_seconds`
before its gratuitous ARP, so it does not assert the address while a just-fenced old binding might still
answer.

### Async-release latency must be bounded (or it eats the budget)

The release is **not free** and **not instantaneous**. If the fence merely schedules a task
(`asyncio.create_task(...)`), the path is: fence fires → task enqueued → event loop reaches it (may be
delayed behind a busy transform/DB call) → `netsh`/`ip` subprocess runs → completes. On a loaded event
loop or a slow `netsh`, that can exceed the ~10s budget and the old leader would still hold the VIP when
the standby binds it. The design **must therefore**:

1. **Signal the release synchronously** from `_check_fence` (not defer it to the async graph teardown).
2. Give it a **hard deadline well under the budget** (e.g. `asyncio.wait_for(release, timeout≈5s)` at
   default timings) and, because `netsh` can block on driver/network I/O, run the OS call **off the event
   loop** (a thread/executor) so a hung subprocess cannot stall the loop.
3. On timeout/failure: **CRITICAL alert via `AlertSink`, force-close listener sockets, do not block.** The
   old leader is already not processing (epoch is stale), so a lingering address is a connectivity
   problem, not a data one.

### Clock-domain mismatch is safe — because of the epoch token

The fence is on the node's **monotonic local** clock; lease expiry (what gates a standby acquire) is on
the **DB** clock. If those drift (NTP correction, a host clock jump), a standby could acquire the lease
**before** the old leader's fence even fires. This does **not** corrupt data: the H1 epoch token makes the
superseded leader's FIFO claims match **0 rows**, so it processes nothing regardless of the VIP. Clusters
**must** run NTP ([CLUSTERING.md](../CLUSTERING.md) already requires it); the epoch token is the
correctness backstop, NTP is the hygiene that keeps the VIP window tight.

### Brief IP duplication = a connectivity handoff, NOT data corruption

State the failure mode honestly. If the VIP is momentarily bound on both the fenced old leader and the new
leader, an inbound connection could briefly reach either. The old leader **cannot double-process**: its
graph is torn down and, even mid-teardown, every FIFO claim it attempts is rejected by the stale-epoch
guard, so it claims 0 rows. The visible effect is a **transient client error** (connection drop / reset /
an MLLP sender reconnect) — the normal active-passive failover experience — **not** duplicate delivery and
**not** corruption. The ADR deliberately does **not** claim "transparent, zero-visible-impact failover";
it claims "no double-processing, with a brief connectivity flip."

### Residual risk we cannot close — the wedged/partitioned host

If the old leader's **host** is wedged — kernel hung, NIC driver stuck, monotonic clock frozen so the
fence never fires, or power-fenced-but-NIC-still-energized — the local release call **cannot run or
complete**. The address stays bound on the dead/hung node while the new leader (after the full `ttl`)
binds it too: **split-brain on the wire** until manual isolation. The lease TTL **bounds** the window but
does not eliminate it; the local-release contract above only helps the **healthy-process-but-DB-
partitioned** case. This is the **irreducible difference from dedicated VRRP**.

**How dedicated VRRP differs (and why it is stronger).** With VRRP (RFC 5798) **VIP ownership is decoupled
from the listener binding**: the backup is lower-priority and **never holds the address**, only watches
advertisements; failover is an **advertisement timeout (~3s)** independent of TCP/DB/app health, so a
master whose network hung loses the election **by protocol** and the backup's takeover does not race an
application-managed unbind. WSFC's clustered-IP resource is similar (the cluster service + quorum owns the
address, not the app).

**The guarantee MEFOR can vs cannot make — stated plainly:**

- **CAN guarantee:** *no double-processing of graph work* (unchanged: lease + self-fence + epoch), and,
  with the contract above, *a healthy-process old leader releases the VIP within `ttl − fence_timeout`,
  before a standby binds it.*
- **CANNOT guarantee:** *VIP release on a wedged/partitioned host.* Engine-managed VIP is therefore a
  **best-effort convenience**, not a hard split-brain-on-the-wire guarantee. For the strictest posture,
  external VRRP/WSFC remains the recommendation — and stays fully supported.

## Privilege & platform

This is the **hard cost** and collides head-on with **DEPLOY-1** ([SERVICE.md](../SERVICE.md)): the
engine is being moved *toward* a least-privilege account (a Windows **virtual service account** /
**gMSA**, granted only file ACLs via `icacls` — read config, read-write data) precisely because
"LocalSystem … widens the blast radius." **Moving an IP needs more than file I/O:**

- **Windows:** `netsh interface ip add address …` requires **Administrator** or
  **SeNetworkConfigOperatorPrivilege** — outside the virtual-account/gMSA file-ACL model. Silent
  service-level elevation is not in the Windows security model.
- **Linux:** `ip addr add … dev … && <gratuitous ARP>` requires **CAP_NET_ADMIN** — which the container
  posture **explicitly drops** (`cap_drop: [ALL]`, read-only rootfs, `allowPrivilegeEscalation: false`).

**Options for granting the privilege (DECIDED 2026-06-27: option 2, the privileged helper; others kept
for context):**

1. **Run the service with net-config rights (reject as the default).** One account, no helper — but
   directly contradicts DEPLOY-1 and re-widens the blast radius the gMSA work just narrowed; on Linux/k8s
   it means root/CAP_NET_ADMIN. Not suitable for the stated hardening direction.
2. **A small privileged helper + IPC — CHOSEN (v1).** A tiny companion
   process holds the privilege; the least-privileged engine asks it to bind/release over a local IPC
   boundary that is itself the audit/trust point.
   - **Windows:** `mefor-net-helper.exe` with a `requireAdministrator` manifest, reached over a named
     pipe (`\\.\pipe\MessageFoundryNetHelper`); the helper **authenticates the caller** (pipe ACL / token
     / PID).
   - **Linux:** a `CAP_NET_ADMIN` systemd helper (or narrow suid) over a Unix socket with `SO_PEERCRED`
     caller authentication.
   - **Security requirement (not optional):** the helper is constrained to **bind/release only the single
     configured `[cluster.vip].address` + `interface`, read from a trusted config source — NOT an
     arbitrary address the caller supplies over IPC.** An unconstrained "bind any address to any NIC"
     helper is a *sharper* local-privilege-escalation primitive than the engine it protects; scoping it to
     the one configured VIP keeps the DEPLOY-1 story intact (segregated **and narrow** privilege).
   - Cost: two binaries to version/sign/audit per platform.
3. **Install-time OS capability grant (Windows-domain-only, partial).** Grant
   `SeNetworkConfigOperatorPrivilege` to the service account via Group/Local Policy — narrower than full
   Admin, but domain/policy-dependent, not portable, not one-pass-scriptable, and has no Linux/k8s analogue.

**Platform mechanics — v1 is Windows-only.** v1 implements **Windows only**:
`netsh interface ip add/delete address` (gratuitous ARP is implicit on bind / via an ARP announce),
fronted by the `requireAdministrator` named-pipe helper, NSSM-first ([SERVICE.md](../SERVICE.md)). The
Linux path (`ip addr add/del` + an explicit `arping -A` / raw gratuitous ARP, a `CAP_NET_ADMIN` helper
over a Unix socket) is sketched here for design continuity but is **out of scope for v1** — a possible
later increment, not a commitment. **Linux operators use the external VIP / LB path** (unchanged and fully
supported). The
feature must be **documented as Windows-only** so no one expects it on Linux.

**Kubernetes / cloud note.** **VIP semantics differ in the cloud and this feature does not apply there.**
In k8s a floating address is a **Service / cloud LB** (or MetalLB on bare-metal k8s), the Pod owns no
secondary NIC address, and the hardened container drops `CAP_NET_ADMIN` by design. **Engine-managed VIP is
a bare-metal / VM feature only**; containerized deployments keep delegating to the orchestration layer,
exactly as today.

## Observability

Surface VIP ownership on the existing read-only cluster API ([ADR 0008](0008-cluster-observability-api.md)):
extend **`GET /cluster/status`** with the node's VIP posture — e.g. `vip: {enabled, address, held}`, with
`held=true` only on the node that currently has it bound — so operators (and the console) can see "who
holds the address" alongside `role`/`is_leader` from one cheap in-memory read. **This is a real contract
addition**, not a free read: a new field on the `ClusterStatus` Pydantic model
([`api/models.py`](../../messagefoundry/api/models.py), the surface `api/__init__` exposes lazily so the
console can import it without pulling FastAPI). It stays in the **`MONITORING_READ`** tier with **no PHI**
(cluster/node metadata only). A bind/release failure raises an alert through the established `AlertSink`
path.

## Console — High Availability page

The MessageFoundry equivalent of Corepoint's **Health → "Assured Availability (A2)"** screen, re-shaped
for our topology. It is **read-mostly**: a monitoring page plus exactly one live control (planned
failover, below). It reaches the engine **only through the HTTP API** ([CLAUDE.md](../../CLAUDE.md) §10);
no engine/store/config import.

### Placement and construction

A new **"High Availability"** page joins the console's left nav after Engine Status (registered in
[`console/shell.py`](../../messagefoundry/console/shell.py) `_NAV` / `_NAV_ICONS` and built in
`_build_pages()`, its `error` signal wired to the shell's `_show_error`). It reuses the
`refresh()`/`reload()`/`stop()` + `AsyncRunner` + in-flight-guard + snapshot/`_apply` **threading
shape** of `EngineStatusPage` ([`console/status.py`](../../messagefoundry/console/status.py)).

> **Construction note (do not copy `EngineStatusPage`'s constructor).** `EngineStatusPage` is built with
> **only** the read-only `poll_client` and does its few writes (service start/stop) via local UAC, *not*
> the API. The HA page's failover is a genuine **API write** that needs the **main-thread `client`** (the
> one carrying the step-up/MFA challenge handlers; `poll_client` from `for_polling()` has **none**). So
> model the **construction** on `ConnectionsPage`
> ([`console/connections.py`](../../messagefoundry/console/connections.py)):
> `HighAvailabilityPage(client, *, poll_client=poll_client)` — reads off-thread via `poll_client`, the
> failover write on the main thread via `client`.

### Topology mapping (the key simplification)

Corepoint's A2 page shows **two replicated servers** (each its own DB) and a **"Viewing: Primary / Backup"**
toggle because each server only knows its own side. MessageFoundry is **N identical nodes sharing one
server DB**: membership, leadership, and lease live in **one shared `nodes`/`leader_lease` table**, so
`GET /cluster/nodes` returns the **whole cluster from any node's API**. There is therefore **no "Viewing"
toggle** — one page renders the entire cluster regardless of which node the console is attached to. The
two-server "viewing side" concept does not map and is **deliberately dropped**.

### Layout (fed by the existing `cluster_status()` / `cluster_nodes()` reads, both `MONITORING_READ`)

- **Overall status banner** (Corepoint's *"A2 Status — …"*): **"Clustering: Enabled (active-passive)"** vs
  **"Disabled (single-node)"** from `ClusterStatus.clustered`, plus the **engine-managed-VIP** posture
  on/off from the read-only config display. Until the VIP mechanism ships this reads **"engine-managed
  VIP: not configured"** and the per-card VIP-owner row is absent. (The banner replaces Corepoint's
  right-aligned "Viewing" context, which has no analogue.)
- **One card per node** (`ClusterNodeList.nodes`, ≥2 clustered; one synthetic self-entry single-node):
  - **Role badge** — **Primary** / **Standby** / **single-node**, driven by **that node's own
    `ClusterNode.is_leader`** (the server-side, freshness-filtered live-leader flag — the same field the
    status page's leader column uses). `ClusterStatus.role` is used only to label which card is "this
    node." (Do **not** re-derive remote roles from `leader_node_id`/`lease_owner` — that risks a badge
    disagreeing with its own `is_leader`.)
  - **Identity** — `node_id`, `host` (Corepoint's server name), `pid` where present.
  - **Bind / VIP address** — Corepoint's *"Server IP"*: the node's bind address and — **once
    engine-managed VIP ships (PROPOSED field, not yet a contract)** — a marker on whichever node currently
    **owns the VIP**, so an operator can answer "where is the VIP right now?" at a glance.
  - **Last ping** — `ClusterNode.last_seen` rendered relative (`status.py`'s `_ago()` helper, **display
    only**).
  - **Lease detail** — `lease_owner`, `lease_expires_at`, `is_leader`. A brief `lease_owner` vs
    `leader_node_id` divergence during failover is expected and shown as-is (the lease is the truth).
  - **Status / CTA line** — a **state line** ("Leader — running graph", "Standby — warm", "Stale — last
    seen 47s ago"), **not** a per-card enable button (enablement is config-time — see non-goals).
  - **Stale / tombstoned rendering** is driven by **server-provided signals** — `ClusterNode.status`
    (active/left) and the freshness-filtered `is_leader` — **not** a client-side `last_seen`-vs-threshold
    constant (that would duplicate, and drift from, the engine-owned freshness window).
- **Empty/denied state.** Because this dedicated page *is* the cluster surface, a single-node/old-engine
  or `MONITORING_READ`-denied caller must see an informative placeholder ("Clustering not available on
  this engine" / "You lack monitoring permission"), not a blank page (the existing in-box form simply
  hid; the standalone form must say why).

### Polling / threading

`refresh()` guards against pile-up with an in-flight flag and submits an off-thread `_fetch()` calling
`cluster_status()` + `cluster_nodes()` (bundled; `ApiError` → cluster section degrades gracefully),
`on_done=_apply` repainting on the main thread. Reads use `poll_client`; the failover write uses the
main-thread `client`.

## Control API — planned failover

The page's one live control is a **planned failover** ("Step down primary"), specified here as a
**contract**, not an implementation.

### Proposed endpoint

| Field | Value |
|---|---|
| **Method / path** | `POST /cluster/stepdown` |
| **Summary** | The current leader **voluntarily releases its leadership lease** so a standby promotes promptly (planned failover / maintenance drain). |
| **Permission** | **`CLUSTER_CONTROL`** (new), gated via `require_step_up(Permission.CLUSTER_CONTROL)` |
| **Request** | `ClusterStepdownRequest` — `{ "force": bool = false }` (`false` = clean lease release; `true` = immediate fence, *deferred to a later increment* — see [Decisions taken](#decisions-taken-2026-06-27)) |
| **Success** | `200` `ClusterStepdownResult` — `{ node_id, was_leader, released_at, new_leader_eligible? }` |
| **Errors** | `400` not clustered (single-node — gated **before** the coordinator is called) · `403` missing `CLUSTER_CONTROL` · `403` step-up/MFA not satisfied · `409` **target node is not the current leader** (the normative non-leader behaviour — the console resolves the leader first, so this is operator error, not an idempotent retry) · `503` engine not started / auth not configured |

### Coordinator seam

The engine already contains a **complete, crash-correct** voluntary release:
`DbCoordinator._release_leadership()` demotes the in-memory leader flag **before** touching the DB (so a
concurrent `is_leader()` reader never sees stale `true`), expires the lease row so a standby acquires on
its next tick, and logs. It is currently **private** and only called from `stop()` (clean shutdown). The
only difference for a planned failover is that the node keeps **running and heartbeating** afterward
(demoted to standby).

**Seam to add:** lift this into a **public protocol method** —
`async def step_down_leadership() -> tuple[bool, float | None]` returning `(was_leader, released_at)` —
`DbCoordinator` reusing the existing release body, the SQL Server coordinator mirroring it, and the
single-node `NullCoordinator` returning `(False, None)` (it is never reached — the endpoint returns `400`
for single-node first). This is a **visibility lift of existing logic, not a new mechanism**.

**Audit the return value, not a pre-read.** The handler **must** audit the tuple
`step_down_leadership()` returns — **not** a prior `is_leader()` read — because a fence/lost-lease tick can
flip leadership between the read and the release; auditing the pre-read could record `was_leader=true` for
an action that released nothing, corrupting the "who triggered the failover" record. `ClusterStepdownResult.was_leader`
is likewise the returned value.

After release, the demoted node's heartbeat clears `nodes.is_leader` on its next tick, the standby
acquires the expired lease and bumps the epoch, and the standby's graph-supervision promotes the graph.
**Once engine-managed VIP ships, the VIP move is the engine sections' concern**, triggered by that same
promotion; this API contract is unchanged by it.

### RBAC & audit

- **New, dedicated** permission `CLUSTER_CONTROL` (`"cluster:control"`), **ADMINISTRATOR-only** at v1 —
  **not** a reuse of `MONITORING_READ` (read) or a catch-all. Deny-by-default, separation of duties,
  self-documenting in the audit log, and delegable to a future `CLUSTER_OPERATOR` role without granting
  full admin.
- Gated with **`require_step_up()`** like the other high-impact writes (`CONFIG_DEPLOY`,
  `MESSAGES_REPLAY`, `MESSAGES_PURGE`): recent password re-prove within the step-up window, plus **TOTP
  MFA** when enrolled or `[auth].require_mfa` is on.
- **Granted** audit: action `cluster_stepdown`, `detail={node_id, was_leader, released_at}` (no `force` —
  deferred), via the
  standard `store.record_audit(actor=identity.username, channel_id=None, …)` into the hash-chained
  `audit_log`. **Do not** hand-roll a denied-audit for permission/step-up 403s — `require_step_up()`
  already records those (`auth.permission_denied`) and the handler body never runs on that denial. If a
  distinct denied signal is wanted, scope it to denials the **handler actually reaches** (the `409`
  wrong-node / `400` not-clustered cases).
- **PHI-free by construction:** the page and the audit detail carry only cluster/node metadata
  (`node_id`/`host`/`pid`/lease state) — never message bodies. Keep confirm-dialog and error copy limited
  to node identifiers.

### Confirm / step-up posture (console)

The failover button follows the established **privileged-write** pattern, not the read pattern:

1. **Enabled only when** `client.can("cluster:control")` **and** a live leader exists to step down;
   otherwise disabled with an explanatory tooltip.
2. On click, a **confirm dialog** spelling out the consequence — *"This releases leadership on `<node>`;
   a standby will promote and the VIP will move. In-flight messages are not drained. Continue?"*
3. On confirm, call `client.stepdown_node(...)` via the **main-thread `client`** (the `403` step-up/MFA
   challenge + re-auth flows through `_request`), **never** the read-only `poll_client`. Run it
   **off-thread** (the call can block for seconds while the standby promotes), disabling the button and
   showing **"Stepping down `<node>`…"**.
4. **Render the leaderless window honestly.** Immediately after stepdown there is a real in-between window
   where `cluster_nodes()` returns `leader_node_id=None` (old leader released, standby not yet promoted).
   Show **"Failover in progress — standby promoting"** (keyed off `lease_owner`/`lease_expires_at`
   indicating an imminent acquire) rather than the bare "— (no live leader)", so the operator who just
   clicked does not think they broke the cluster. Re-enable the button only once a fresh leader reappears.

## Console scope / non-goals

- The HA page is **read + one failover button**. It is **not** a cluster-configuration editor.
- **Enabling/disabling clustering (and engine-managed VIP) is config-time, not a live console toggle** —
  it needs a shared server DB and a **coordinated restart**. The banner *reports* the state from config
  display; it does not *set* it. This is the honest **enable-is-config / failover-is-live** split.
- The page does **not** implement automatic health-driven failover, in-flight drainage/quiesce before
  stepdown, or per-lane reassignment (active-active was dropped).
- The page touches the engine **only** through the HTTP API client.

## Acceptance criteria

> EARS form; each linked (`→`) to the test/fixture that verifies it **once built**. Tests land with the
> build, not this design ADR.

- **AC-1** — WHEN a node's `is_leader()` flips False→True with `[cluster.vip].enabled=true`, THE SYSTEM
  SHALL bind the configured VIP to the configured interface **before** starting listeners and SHALL emit
  an **IPv4** gratuitous ARP. *(IPv6 NDP / unsolicited-NA is deferred for **all platforms** — a later
  cross-platform follow-up, not a Windows-specific limitation; see To resolve on acceptance.)*
  → `tests/test_cluster_vip.py::test_binds_on_promotion_before_listeners`
- **AC-2** — WHEN a leader self-fences (lease not renewed within `leader_fence_timeout_seconds`), THE
  SYSTEM SHALL release the VIP locally (a non-DB action signalled synchronously from the fence) **within
  `leader_lease_ttl_seconds − leader_fence_timeout_seconds`** of the fence firing — i.e. before a standby
  can acquire the expired lease.
  → `tests/test_cluster_vip.py::test_self_fence_releases_vip_within_budget`
- **AC-3** — IF the local VIP release does not complete within its deadline, THEN THE SYSTEM SHALL raise a
  CRITICAL `AlertSink` alert, force-close the listener sockets, and SHALL NOT block the event loop.
  → `tests/test_cluster_vip.py::test_release_timeout_alerts_does_not_block`
- **AC-4** — WHEN a leader stops cleanly or is demoted, THE SYSTEM SHALL release the VIP and SHALL NOT
  leave it bound on a standby.
  → `tests/test_cluster_vip.py::test_release_on_clean_stop_and_demotion`
- **AC-5** — IF a VIP bind or release fails, THEN THE SYSTEM SHALL log it at ERROR, alert, and SHALL NOT
  drop, re-order, or change the disposition of any received message.
  → `tests/test_cluster_vip.py::test_vip_failure_alerts_never_drops`
- **AC-6** — WHERE `[cluster.vip].enabled=false` (default) or the node is single-node, THE SYSTEM SHALL
  perform no VIP action and behave byte-identically to the external-VIP path.
  → `tests/test_cluster_vip.py::test_disabled_is_noop`
- **AC-7** — WHEN `GET /cluster/status` is read, THE SYSTEM SHALL report VIP ownership (`held=true` on at
  most one node) consistent with the lease holder.
  → `tests/test_api_cluster_status.py::test_status_exposes_vip_holder`
- **AC-8** — IF `[cluster.vip]` is set without `[cluster].enabled`, on a non-server-DB backend, or with
  both `prefix` and `netmask`, THEN THE SYSTEM SHALL refuse to load.
  → `tests/test_settings.py::test_vip_requires_clustered_server_db_and_one_mask_form`
- **AC-9** — WHEN `POST /cluster/stepdown` is called on the current leader with `CLUSTER_CONTROL` + step-up
  satisfied, THE SYSTEM SHALL release leadership, audit the **returned** `was_leader`/`released_at` with
  the acting user, and SHALL return `200`; on a non-leader it SHALL return `409`; single-node `400`;
  missing permission/step-up `403`.
  → `tests/test_api_cluster_stepdown.py::test_stepdown_rbac_audit_and_status_codes`

## Options considered

1. **Opt-in engine-managed VIP, lease-driven, with a privileged helper (this) — CHOSEN, the decided v1 design.**
   Corepoint-style "standby takes the address" with **no extra HA component** and a **single arbiter**
   (the lease). Chosen *despite* the privilege cost because the cost is **containable** (a segregated,
   narrowly-scoped, auditable helper keeps the engine least-privileged per DEPLOY-1) and the residual
   wedged-host window is **documented and bounded**, with external VRRP/WSFC still recommended for the
   strictest posture. Opt-in, OFF by default → zero risk to existing deployments.
2. **External keepalived/VRRP gated on `role==primary`.** Strongest correctness (VIP decoupled from the
   listener, ~3s advertisement-timeout failover, robust to a hung host) — but **two arbiters** (VRRP
   priority vs the lease) and a **second component**, the burden this ADR removes for a small Windows
   shop. **Kept as the recommended posture for the strictest split-brain requirement**, not retired.
3. **External WSFC clustered-IP resource (Windows).** Native, quorum-arbitrated, OS-owned address —
   heaviest to stand up (AD + Failover Clustering + shared quorum) and again a second arbiter. Remains
   valid for shops already running WSFC.
4. **External L4 load balancer (keepalived/HAProxy/F5/cloud NLB) — the status quo.** Mature, portable,
   **the current documented design and the only path in k8s/cloud.** Rejected as the *sole* option going
   forward only because it forces a **separate HA component** and a **second arbiter** for two-node on-prem
   shops. **Stays fully supported.**

All three external options share the **two-arbiter drawback**; engine-managed VIP's whole point is to
collapse to **one** arbiter, accepting the privilege cost and the wedged-host residual in exchange.

## Consequences

**Positive** — Out-of-the-box, **no-extra-component** active-passive failover that moves the client-facing
address with the leader (Corepoint A2 parity), driven by a **single arbiter** (the lease) so the address
can never diverge from "who processes." A small Windows-first cluster (two VMs + a shared SQL Server) gets
failover *and* a floating VIP without keepalived/WSFC/an LB, plus an operator **monitor-and-control**
surface (the HA page + an audited `POST /cluster/stepdown`). VIP ownership is **observable**, failures are
**alerted**, and the feature is **opt-in and OFF by default**.

**Negative / risks** — (a) **Privilege.** Needs network-config rights the engine deliberately does *not*
have under DEPLOY-1; the narrowly-scoped helper mitigates but adds a second privileged binary to
version/sign/audit per platform. (b) **New split-brain-on-the-wire window.** Engine-managed bind/unbind is
not atomic and a **wedged host cannot release**; dedicated VRRP does not have this failure mode. The
§Correctness contract bounds the *healthy-process* case (release within `ttl − fence_timeout`) but
**cannot** bound the wedged-host case. (c) **New non-DB action on the deliberately-no-I/O fence path** —
synchronous signal, hard deadline, off-loop OS call, timeout→alert-don't-block. (d) **More
platform-specific surface** (`netsh` vs `ip addr`; named pipe vs Unix socket helper). The trade is
*convenience + single-arbiter, accepting a documented best-effort residual* vs *delegate-and-stay-least-
privileged*.

## Out of scope / accepted residual

**Not a load balancer**: a **single VIP that follows the primary**, no traffic distribution, no backend
pools, no L7. The three scope categories are kept distinct on purpose:

- **Windows-only at v1 (platform scope):** engine-managed VIP itself. Linux is a deferred later increment
  (not a commitment); **Linux / containerized operators use the external VIP/LB path, which stays
  cross-platform and fully supported.**
- **Deferred for all platforms (feature timeline):** IPv6 NDP / unsolicited neighbour advertisement (v1
  does IPv4 gratuitous ARP) — *not* a Windows-specific limitation.
- **Out of scope entirely:** multi-VIP weighting / per-port VIP fan-out; cloud LB / k8s Service
  integration (orchestration owns the address there — bare-metal/VM only); a per-shard VIP
  ([ADR 0037](0037-multi-process-sharding-l3.md)).

**Accepted residual:** a wedged/partitioned host can leave the VIP dual-bound until manual isolation —
engine-managed VIP is **best-effort**, and external VRRP/WSFC remains the recommendation where a hard
guarantee is required.

## To resolve on acceptance

The big v1-scope calls are **decided** — see [Decisions taken](#decisions-taken-2026-06-27) (Windows-only
platform, privileged helper, alert+force-close on release failure, admin-only step-up+MFA failover,
IPv6 deferred, dedicated console page, `force` deferred). What remains is build-time detail, to settle when
the build is greenlit:

- [ ] **Seam keys, confirmed at build** — ratify the `[cluster.vip]` key names (`address`, `interface`,
  `prefix` XOR `netmask`, `gratuitous_arp`, `release_grace_seconds`); OFF-by-default is decided.
- [ ] **`release_grace_seconds` default** — pick the value (e.g. tie to ~2× the old fence timeout) so the
  new leader does not gratuitous-ARP while a just-fenced binding might still answer.
- [ ] **`vip.held` field shape** — fix the exact `GET /cluster/status` field the per-node card/banner bind
  to, so console and engine agree on one mechanism.
- [ ] **`new_leader_eligible` in the stepdown result** — derive the successor cheaply at stepdown time, or
  drop it and have the console re-poll `/cluster/nodes`.
- [ ] **Helper packaging** — Windows code-signing + versioning/auditing of `mefor-net-helper.exe`, and the
  named-pipe ACL model for caller authentication.
- [ ] **Published guarantee wording** — finalize the honest "CAN (no double-processing; healthy-process
  release within `ttl − fence_timeout`) / CANNOT (wedged-host VIP release); external VRRP recommended for
  the strictest posture; **Windows-only at v1**" statement for the user-facing docs
  ([CLUSTERING.md](../CLUSTERING.md), [DEPLOYMENT.md](../DEPLOYMENT.md)) when the feature ships.
