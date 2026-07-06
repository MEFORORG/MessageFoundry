# MessageFoundry — Multisession Execution Plan 4 (2026-06-27)

> **Lineage.** This is the **fourth** MessageFoundry multisession plan, driven by a dedicated **coordinator
> lane** (the active session). Plan 1 = [`MULTISESSION-PLAN.md`](MULTISESSION-PLAN.md) (v0.1, shipped).
> Plan 2 = [`MULTISESSION-PLAN-v0.2.md`](MULTISESSION-PLAN-v0.2.md) (v0.2 board — merged; historical record).
> Plan 3 = [`MULTISESSION-PLAN-3.md`](MULTISESSION-PLAN-3.md) (connector/codec wave — landed). **Plan 4
> supersedes Plan 3** as the living plan: the **post-throughput-build wave** (operational hardening +
> retention granularity + CI health + a load/throughput re-measure).
>
> **Header.** All lanes branch off **`origin/main` @ `7a8151b`** (#602, `fix(supervise): forward
> --project-root to shards`). The **single-writer coordinator = the active session** (owns this plan, ADR
> numbering, and the shared AI project memory). **Autonomy = L1:** workers **build + verify the quartet**
> (`ruff format --check` · `ruff check` · `mypy` strict · `pytest`, with `QT_QPA_PLATFORM=offscreen` for the
> console tests) and **commit locally**; the **OWNER merges/ratifies PRs** and ratifies ADRs (worker ADRs
> stay `Proposed`).
>
> **Hardening pass (corrected draft).** Two draft lanes are **dropped — already shipped**:
> **#46** (connection-lifecycle event log + "Response Sent" ACK + console **Event Log** page) is **SHIPPED
> (PR #541)**, so **#16 is satisfied** and #46's lanes are removed — Lane A **reuses #46's per-connection-
> override plumbing**. **#22b Alerts GUI is shipped** (`console/alerts_page.py`). The pool-prewarm worktree is
> **STORE connection-pool pre-warming** (not MLLP-delivery pooling) — it is the dominant store-file collision
> sibling for Lane A.

---

## A. Wave items (all verified OPEN on `origin/main` @ 7a8151b)

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| **#34** | Per-connection retention windows | **ADR 0027** (Proposed, authored) | A | sequential `#34 → #47`; sole store-writer |
| **#47** | Embedded-document (base64 attachment) pruning | **ADR 0042** (Proposed, authored) | A | same Lane-A pass as #34; design fork (a)/(b) |
| **#50** | App-log disk-meter + msg-stall alert | none (rides ADR 0014) | G | small/additive; `api/app.py` + `pipeline/alerts.py` |
| **#53** | Dual-control `config:deploy` | **ADR 0041 D2** (EARS sign-off) | D | `[approvals].operations += config_reload` |
| **#54** | Startup attestation + non-editable wheel | **ADR 0041 D3 + 0017 amend** (EARS sign-off) | D | alert-default + opt-in fail-closed + no-op editable |
| **#55** | CI `windows-2022` pytest hang | none | E | per-test timeout + faulthandler; unwedges a required check |
| **#28/#29** | Load + throughput run + refresh `TUNING-BASELINE.md` | none | F | zero product code; needs the Win2025+SQL box |

---

## B. Lane assignment (worktree per lane off `origin/main`)

### Lane 0 — COORD / ADR (pure docs; builds no product code)
**Owns ADR numbering + this plan + the shared memory (single-writer).** Gates **A** and **D**.
- **ADR 0027** (per-connection retention) — authored (Proposed); owner ratifies → unblocks Lane A #34.
- **ADR 0042** (embedded-document pruning) — authored (Proposed); reserved the next free number after 0041;
  owner ratifies the **(a)-now / (b)-defer** fork → unblocks Lane A #47.
- **ADR 0041 D2/D3 EARS** + **ADR 0017 amend** — sign off the EARS acceptance criteria for #53/#54 → unblocks
  Lane D. (0041 D1 already built; D2/D3 were staged.)
- Keeps this plan current (flips statuses, retires lanes), reconciles `BACKLOG.md`. **Does NOT edit
  `docs/adr/README.md`** (the Registry phase owns it, single-writer) and **does NOT commit** (Registry phase
  commits).

### Lane A — RETENTION + PRUNING (#34 → #47; sequential; **sole store-writer**)
**Branch:** `per-conn-retention` · **Worktree:** off `origin/main`.
- Edits `pipeline/retention.py` `run_once` + store purge/schema across **x3 backends**
  (`store/{store,base,postgres,sqlserver}.py`).
- **Reuses #46's per-connection-override plumbing** (do not re-derive a resolver).
- **Gated on ADR 0027 + 0042 Accepted.** `#34` lands first, `#47` rebases onto its `retention.py` + store
  changes (one pass, two ADRs).
- **REAL collision** with the **pool-prewarm sibling** on the three store backends + `base.py` → **coordinate
  land-order** (pool-prewarm has store-pool WIP, **no PR** — the **#1 coordination risk**).
- `retention.run_once` **already carries** #46's `connection_event` purge — thread the per-connection cutoff
  in beside it.

### Lane D — TAMPER-HARDEN (#53 + #54; parallel with A)
**Branch:** `tamper-harden` · **Worktree:** off `origin/main`.
- **#53:** `[approvals].operations += config_reload`; server-enforced distinct second approver (requester can
  never self-approve; both identities audited) — touches `api/approvals.py`.
- **#54:** startup self-attestation of the installed wheel vs `dist-info/RECORD` — **alert-default + opt-in
  `fail_closed_on_drift`**, a **no-op off an editable install**; **ADR 0017 → enforced non-editable wheel**.
  Touches **engine startup** (`pipeline/engine.py`) — **coordinate `engine.py` with pool-prewarm's
  `warm_pool`**.
- **Needs Lane-0 EARS sign-off** on ADR 0041 D2/D3 + the 0017 amend before building.

### Lane E — CI-HEALTH (#55)
**Branch:** `ci-win2022-hang` · **Worktree:** off `origin/main`.
- `ci.yml` **per-test timeout + faulthandler + watchdog** + fix the culprit teardown.
- **Land AFTER the `ci-smoke`/`lockconfigdir` sibling** (shared `ci.yml`, 1 ahead — land first).
- Unwedges a **required** status check (the `windows-2022` job times out at the 15-min cap).

### Lane F — PERF (#28 + #29; zero product code)
**Branch:** `perf-baseline` · **Worktree:** off `origin/main` (`-NoInstall` posture; runs the harness, not
the engine source).
- Run the load + throughput harness; **refresh `TUNING-BASELINE.md`**. No product code.
- **Needs the Win2025 + SQL Server box.** Unblocked — the v0.2.6/.7 wheel is published (install-from-PyPI on
  the test box works).

### Lane G — OPS-HEALTH (#50; small/additive)
**Branch:** `ops-health` · **Worktree:** off `origin/main`.
- **App-log disk metering** in `GET /status` + a **message-stall alert rule** binding to **ADR 0014**.
- Touches `api/app.py` + `pipeline/alerts.py` only — **low contention**, additive.

---

## C. Land-order

```
(1) Lane 0 ADRs (0027 + 0042 Accepted; 0041 D2/D3 + 0017 EARS sign-off)  ──┐ unblock A, D
(2) parallel non-gated value:  Lane E (after ci-smoke)  ·  Lane F  ·  Lane G
(3) Lane A   (#34 → #47)  AFTER ADRs Accepted + pool-prewarm land-order coordination
(4) Lane D   (#53 + #54)  parallel with A (its own files; engine.py coordinated w/ pool-prewarm)
```

1. **Lane 0 ADRs first** — ratify 0027 + 0042; sign off 0041 D2/D3 + 0017 EARS → unblocks A, D.
2. **Parallel non-gated value:** **E** (after the `ci-smoke` sibling lands its shared `ci.yml`), **F**, **G**
   — none gated on the ADRs; staff immediately.
3. **Lane A** after the ADRs are **Accepted** and the **pool-prewarm** store-file land-order is settled.
4. **Lane D** in parallel with A (disjoint files; coordinate only `engine.py` with pool-prewarm).

---

## D. Contention matrix

| File(s) | Items | Resolution |
|---|---|---|
| `store/{store,base,postgres,sqlserver}.py` (x3 backends) | **Lane A (#34/#47)** vs **pool-prewarm sibling** | **DOMINANT collision.** pool-prewarm = store-pool WIP, **no PR** → **#1 coordination risk**. Settle land-order before Lane A touches the backends; parity test mandatory. |
| `pipeline/retention.py` `run_once` | **Lane A internal (#34 + #47, same pass)** | Single-owned by Lane A; already carries #46's `connection_event` purge — thread per-connection cutoff in beside it. |
| `pipeline/engine.py` (startup) | **Lane D (#54)** vs **pool-prewarm (`warm_pool`)** | Coordinate the startup-path edit; both add a startup step — sequence so neither clobbers the other. |
| `api/approvals.py` | **Lane D (#53)** | Lane D sole toucher (add `config_reload` to the gated set). |
| `ci.yml` | **Lane E (#55)** vs **`ci-smoke` sibling** | Shared file — **`ci-smoke` lands first**; Lane E rebases onto it. |
| `api/app.py` + `pipeline/alerts.py` | **Lane G (#50)** | Low contention; additive (a `/status` field + an ADR-0014 rule). |
| `docs/adr/0027*`, `0042*` + this plan | **Lane 0** | Coordinator-owned; **not** `docs/adr/README.md` (Registry phase, single-writer). |

> **Sibling worktrees:** **`ci-smoke`** (1 ahead — land first for E) · **`pool-prewarm`** (store-pool WIP, **no
> PR** — #1 coordination risk for A; also `engine.py` for D) · **`corepoint-recon`** (dormant — ignore).

---

## E. Coordination rules

- **Single-writer coordinator** (active session) owns this plan, ADR numbering/authoring, and the shared AI
  project memory — records every ADR-status change + gating decision **before** a worker lane acts on it.
- **L1 autonomy:** workers build + verify the quartet + commit **locally**; the **owner** merges PRs and
  ratifies ADRs. Worker-authored ADRs stay **`Proposed`** until the owner flips them.
- **Verify quartet (every build lane):** `ruff format --check` · `ruff check` · `mypy` (strict) · `pytest`
  (`QT_QPA_PLATFORM=offscreen` for console tests). Re-check the **count-and-log / never-purge-in-flight /
  one-way-dependency / reliability** invariants on any store/retention/engine edit.
- **Worktree-per-lane** off `origin/main`; no two lanes share a working tree. Coordinate the named **file
  collisions** in §D before editing — store backends (A vs pool-prewarm), `engine.py` (D vs pool-prewarm),
  `ci.yml` (E vs ci-smoke).
- **ADR numbering** is coordinator-owned: 0027 (per-conn retention) + 0042 (embedded-doc pruning) authored
  here; **`docs/adr/README.md` is edited by the Registry phase only** (do not touch from a worker lane).

---

## F. Out of scope (deferred — verified)

| Item | Why deferred |
|---|---|
| **#7** inbound-HTTP / **ADR 0023** | Needs the HTTP listener ADR Accepted + a real feed. |
| **#52** NEW candidates (alert-state model, turnkey DR, declarative modeling, correlation UX, web monitor) | Fresh candidates — not scoped into this wave. |
| **#51** content search | Needs an ADR first. |
| **#45 / #49** on-trigger | No trigger yet. |
| **#13** licensing | Counsel-blocked. |
| **#39 / #41** | P3. |
| **SecretProvider seam** | Deferred. |
| **#33 follow-ups A–E** | Config-UX review outputs — each becomes its own scoped item on demand. |

---

## G. Owner decisions locked 2026-06-27

- **Scope confirmed** for this wave — **minus the shipped #46 / #22b** (Event Log page + ACK "Response Sent" +
  Alerts GUI all landed; #16 satisfied).
- **#47 = a fork:** **(a)** in-place selective strip **now** *or* **(b)** defer — owner ratifies on ADR 0042.
- **#54 =** **alert-default + opt-in fail-closed + no-op editable**; **ADR 0017 → enforced wheel**.
- **Coordinator owns the shared memory** (single-writer for this wave).
