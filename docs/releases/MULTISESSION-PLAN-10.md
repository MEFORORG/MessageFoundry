# MessageFoundry — Multisession Execution Plan 10 (2026-07-10)

**Owner-scheduled batch: operator/transport parity + two engine seams.**

Seven items the owner chose to schedule out of the demand-gated backlog (they are mostly `demand-gate` by
verdict, promoted here by owner decision — except **#150**, whose trigger has fired via the committed
Corepoint cutover, and **#82**, which carries a *confirmed correctness bug*). File footprints and contention
below are verified against `origin/main`.

**Method.** Coordinator + one worker subagent per lane in its own worktree
(`scripts/worktree/new.ps1 -Name plan10-<lane>`); workers **build + verify + local-commit**; the **owner**
opens and approves every PR. Same discipline as PLAN-8/9.

> **Status: PLAN — awaiting "go".** Two lanes (#150, #134) introduce a new engine surface and need an **ADR
> first**. Several lanes touch files the in-flight PLAN-8 sessions own, so they are Wave 2 by necessity.

---

## A. In-flight collision map (do NOT collide)

The two live PLAN-8 sessions (Waves 2-3 landing now — #204 merged as #870) own the files this batch needs:
- `transports/mllp.py` — PLAN-8 **#201** (TLS/mllp). → blocks **#82**.
- `pipeline/alerts.py` / `alert_sinks.py` + `settings.py [alerts]` — PLAN-8 **#188** (notifications). → blocks **#118/#144/#145**.
- `config/settings.py` — both PLAN-8 waves + PLAN-9's Wave 2. → any settings.py touch waits.
- PLAN-9 also queues a **STORE** lane (store backends + `store/crypto.py`) — **#150** shares the store metadata column with it.

So: land the PLAN-8 alerts (#188) and mllp (#201) work **first**, then the Wave-2 lanes here rebase on `main`.

## B. Lane roster

| Wave | Lane | Item(s) | V/D | Owns | Notes |
|---|---|---|---|---|---|
| **1** | **AUTOSTART** | #115 | 6/3 | `config/models.py` (per-connection `auto_start`), the loader/`RegistryRunner` startup gate, `connections.toml` desugar, tests | A persisted per-connection start-disabled flag honored at engine start (today every wired connection auto-starts; `models.py:260 enabled=True` is the nearest field). Low contention — `config/models.py` only lightly shared (PLAN-9 DIRECT-HISP, Wave 3). Start now. |
| **2** | **SENDER** | #82 | 6/2 | `transports/mllp.py`, `transports/tcp.py`, tests | **Contains a confirmed correctness bug** — `_check_ack` (`mllp.py:798`) matches MSA-1/MSA-3 only, so a *mismatched* ACK (wrong MSA-2 vs the sent MSH-10) is wrongly accepted. Plus send-pacing + TCP keep-alive polish. **Split: land the ACK-matching fix first** (small, high-value). Blocked on PLAN-8 **#201** (owns mllp.py) — rebase after it lands. |
| **2** | **ALERTS-OPS** | #118, #144, #145 | 6/2, 6/3, 6/3 | `pipeline/alerts.py`, `pipeline/alert_sinks.py`, `pipeline/cluster.py`, `api/app.py`, console | **One serial lane** — all three share `pipeline/alerts.py`. #118 test-send-email endpoint (reuses `EmailSink`, `alert_sinks.py:146`); #144 alert-triggered connection start/stop (reuses `api/app.py:1166 start/stop_connection` behind the alert seam); #145 failover-transition alert (emits on `cluster.py` leader change). Blocked on PLAN-8 **#188** (owns [alerts]) — rebase after it lands. |
| **2/3** | **METADATA** | #150 | 6/6 | `parsing/message.py` (new metadata surface), `config/wiring.py`, `store/*` (metadata column), `api/models.py`, console — **+ ADR** | **Trigger fired** (the committed Corepoint cutover needs channelMap/userdata-style values; SetState is no equivalent). A per-message metadata bag a Handler can write, persisted through the pipeline and surfaced read-only — `api/models.py:40` already reserves `metadata: str \| None  # mechanism TBD`, so wire *that*. Engine-wide → **ADR first**. Coordinate the store-metadata column with PLAN-9's STORE lane. |
| **2/3** | **BATCH** | #134 | 7/6 | `pipeline/wiring_runner.py` (outbound stage), a new aggregation seam, `transports/*`, `store/*` outbound — **+ ADR** | Outbound batch aggregation: N messages → one BHS/BTS envelope on send. Handler purity bars cross-message accumulation, so it needs a **new batch-window seam at the delivery stage** (not a Handler). Touches the outbound hot path → **ADR first**; must not weaken at-least-once / strict-FIFO. Highest value (7) but the heaviest. |

## C. Waves & sequencing

1. **Wave 1 now:** **AUTOSTART (#115)** — the only lane that collides with nothing in flight. In parallel, the
   coordinator can **author the two ADRs** (METADATA #150, BATCH #134) for owner ratification — no engine code yet.
2. **Wave 2 after PLAN-8 #188 + #201 land** (they are merging now): **SENDER (#82)** — do the ACK-matching
   correctness fix as its own first commit — and **ALERTS-OPS (#118/#144/#145)** in one serial lane. These are
   file-disjoint from each other (transports vs. alerts), so they run in parallel once their PLAN-8 blockers land.
3. **Wave 2/3 (ADR-gated):** **METADATA (#150)** once its ADR is ratified and PLAN-9's STORE lane's
   store-metadata edits are known; **BATCH (#134)** once its ADR is ratified — sequence it last (outbound hot path).

## D. Contention matrix

- `transports/mllp.py` — SENDER vs. PLAN-8 #201 → SENDER is Wave 2 (after #201).
- `pipeline/alerts.py` — all three ALERTS-OPS items + PLAN-8 #188 → serial lane, Wave 2 (after #188).
- `store/*` metadata column — METADATA vs. PLAN-9 STORE (#190/#63) → coordinate; METADATA rebases after STORE.
- `config/wiring.py` / `pipeline/wiring_runner.py` — METADATA + BATCH both touch the pipeline; keep them
  sequential (BATCH last) so two engine-surface changes don't land on the hot path at once.
- `api/app.py` — ALERTS-OPS (#144 connection-control) + `api/models.py` (METADATA) → light, different regions.

## E. Coordination rules & gotchas (same as PLAN-8/9)

- One worktree/branch per lane; workers build+verify+local-commit; owner pushes/PRs/auto-merges.
- Every PR `git merge main` first (the CI gate hangs otherwise). **No `Co-Authored-By: Claude` trailer** (CLA
  bot fails). Finishing PR carries `BACKLOG #N` + flips the banner to ✅.
- **3-backend tests** (SQLite + Postgres + SQL Server) for METADATA (store column) and any store touch; SQL
  Server is the win2025 CI leg. No new dependency is expected in this batch (no DEP-1 re-lock).
- **#134 and #150 must not weaken the reliability invariant** (at-least-once, strict FIFO, ACK-after-ingress):
  the batch-window and the metadata write both ride the staged handoff — keep re-runs idempotent and pure.
- Verify order every lane: `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for console tests).

## F. Owner / decision-gated callouts

1. **#150 ADR** — the per-message metadata surface (where it lives on `Message`, how it persists, PHI rules on
   the read-only view). Ratify before build; it is the most-justified item (trigger fired).
2. **#134 ADR** — the outbound batch-window design (time/count window, envelope framing, FIFO/at-least-once
   preservation). Ratify before build; sequence last.
3. **#82 ACK fix** — this is a *confirmed correctness bug*, not just polish. It is worth pulling to the front of
   its lane (and arguably worth a standalone fix PR ahead of Wave 2 if the mllp.py #201 collision can be
   coordinated) rather than waiting on the pacing/keep-alive polish.

---

*Source: the 2026-07-10 ten-level re-score (owner-selected items #82/#115/#118/#134/#144/#145/#150) + a
targeted code-scout of each item's footprint and contention against `origin/main`. Companion plans:
`MULTISESSION-PLAN-8.md` (IDE low-code) and `MULTISESSION-PLAN-9.md` (ASVS completion + non-ASVS).*
