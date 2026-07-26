# DEMAND-GATE-BACKLOG — session handoff

**Date:** 2026-07-17 · **For:** the next session picking up this build.

> **Your mandate:** carry Waves 2→6 to completion — build, claim, ADR, code, test, local-commit,
> adversarially verify — but **DO NOT `git push`, open a PR, or merge.** When a wave is built and
> verified, **hand back to the owner** for push/merge. (Owner instruction, 2026-07-17.)

---

## What this is

An adversarially-verified multisession plan to build **32 demand-gated backlog items** across
**15 sessions / 6 waves**. Authoritative docs:

- **Master:** [`docs/releases/DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md`](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)
  — waves, store-serialization, hotspot matrix, ADR ledger, cross-cutting risks, concurrency fixes.
- **Per-session phase docs:** [`demand-gate-backlog/README.md`](README.md) index + one doc per session
  (owned files, ADRs, PHI notes, build order, Definition of Done, claim rule).
- **Reconciliation:** these 32 items were previously laned (mostly not-started) in
  [`plan-11`](../plan-11/README.md); this plan **supersedes** those lanes for these items.
  `plan-13` is a **different** effort (branch `plan13-doc`) — do not collide with it.

## Status

| Wave | Sessions | State |
|---|---|---|
| **1** | S11 #73 · S6 #67/#69 · S4 #172/#160 · S9 #84/#168 | ✅ **BUILT + VERIFIED + MERGED** (ADRs 0119–0123 + amendments to 0011, 0013) |
| 2 | S1a #146/#138/#145/#144 · S2 #112/#128/#127 · S5 #117/#97 | ○ next — no owner-decisions needed (S1a has PHI #138) |
| 3 | S3a #114/#142 (store slot 1) · S7b #171/#124 | ○ |
| 4 | S3b #111 · S1b #143/#81 (store slot 2) | ○ |
| 5 | S8b #125/#126/#151 (store slot 3) · S10 #95 | ○ (gated: #125 dep, #95 owner) |
| 6 | S8a #76/#131/#136 · S7a #121/#122 | ○ (gated: S8a store-fork, #122) |

## The build pattern (repeat per lane)

1. **Serial worktree creation** (the shared `.claude/worktrees` dir on Windows has clobbered under
   concurrent creation — create worktrees **one at a time**): `pwsh -NoProfile -File
   scripts/worktree/new.ps1 -Name dg-<lane>`. new.ps1 bases the branch on `origin/main` and names the
   branch after `-Name` (so the branch is `dg-<lane>`, not the phase-doc's aspirational name). Each gets
   its own `.venv`.
2. **Allocate ADR(s) atomically** — `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title
   "<title>"`. **Never grep for the next number** (ledger gate). Write the ADR file + its
   `docs/adr/README.md` index row in the **same commit**. **ADR numbers already used: 0119–0123** (plus
   amendments to 0011 and 0013) — the allocator will skip them.
3. **Claim before code (mandatory — no gate catches a double-build):** flip each item's
   `docs/BACKLOG.md` banner `🔢 → 🚧` in its **own commit**, before writing code:
   `> 🚧 **Status — in progress (lane \`dg-<lane>\`, branch \`dg-<lane>\`).**` (keep the existing 🔢
   line — two OPEN banners pass the gate). Run `python scripts/docs/backlog_status_check.py` (must be OK).
   See memory `claim-backlog-item-before-building`.
4. **Implement** per the phase doc's build order + owned files. Honor the CLAUDE.md invariants:
   router/transform **purity**, **count-and-log**, **ACK-on-receipt**, **no "channel"/"route" element**,
   one-way deps (`pipeline/transports/parsing/store/config` never import `api/`), never log full PHI at
   INFO+, parameterized SQL, verify-a-dep-exists-then-relock. New behavior gets a test.
5. **Verify (must be green):** `ruff check` + `ruff format --check` → `mypy messagefoundry` (strict) →
   `pytest` (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. Use the worktree's `.venv`.
6. **Local-commit** per coherent layer. **No `Co-Authored-By: Claude` trailer** (the CLA bot rejects it).
7. **STOP.** Do **not** push, PR, merge, or flip `🚧 → ✅`. Report to the owner for push/merge; the
   finishing merge is where `🚧 → ✅` happens (replace both open banners with one `> ✅ **SHIPPED …**`,
   moving the score to a `_(was 🔢 …)_` parenthetical, or the gate flags a closed+open contradiction).

## Ordering rules (do not break)

- **Wave order** is sequential; sessions **within** a wave run concurrently in **separate worktrees**
  (verified disjoint files). See the master's "Sequencing & parallelism map".
- **Store-serialization (hard):** the three store-editing sessions must land **one per wave, in order**:
  **S3a (wave 3) → S1b (wave 4) → S8b (wave 5)**. Never run two concurrently — they all edit
  `store/store.py` + `sqlserver.py` + `postgres.py` and trip the ADR 0111 schema-hash gate.
- **Hotspot files** (additive but coordinate): `config/models.py` (S2/S3a/S3b/S8a), `transports/file.py`
  + `remotefile.py` (S3a then S3b), `transports/mllp.py` (S5/S8a), `logging_setup.py` (S7b before S7a),
  `config/wiring.py`, `api/app.py` (disjoint routes), `messagefoundry_webconsole/static/app.js`.

## Owner decisions still pending (gate later waves)

- **#122** (corrupted-log stop, S7a) — an architecture reversal of the stdout-only invariant. Plan
  recommends shipping **#121 alone** and deferring #122.
- **#95** (AI broker, S10) — XL / speculative; recommend parking behind everything.
- **#125 `python-multipart`** (S8b) — a new dep contradicting the deliberate no-multipart stance; needs a
  vet, or hand-parse multipart with stdlib.
- **S8a universal-flag store-fork** — TOML-managed-only default keeps S8a out of the store-serialized
  chain; only the "code-first-connection flags everywhere" option makes it a 4th store session.
- (**#160 croniter** was resolved → **stdlib** evaluator; **#69 zeep** → resolved → **pure lxml `[xml]`**.)

## PHI surfaces to guard (from the plan's 14-item census)

#138 templated alert email (closed non-PHI allowlist), #124 bulk body export (step-up + per-body audit),
#171 log viewer (redacted tail), #125 uploaded files (encrypt/document the tier), #172 gzip
(decompression-bomb ceiling), #95 AI egress (server-side policy re-resolve), #168 Test Bench collections
(machine-local only). Each phase doc carries the specific guardrail.

## Environment cautions

- **Shared worktrees are contention-prone.** ~10 worktrees share this history/remote. Create worktrees
  serially; expect foreign untracked files; the coordinator branch `claude/asvs-drive-to-pass` is shared
  with other (ASVS/harness) sessions — don't push it.
- Memory: `claim-backlog-item-before-building`, `worktree-hijack-on-windows`, `no-claude-coauthor-trailer`.

## Verification bar (a lane isn't done until these pass)

`ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen`) →
`messagefoundry check`. Store/service changes: validate on the Windows CI legs. Then **hand back — do not
push or merge.**
