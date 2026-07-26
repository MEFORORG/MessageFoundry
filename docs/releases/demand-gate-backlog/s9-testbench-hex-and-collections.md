# DEMAND-GATE-BACKLOG · S9 · IDE Test Bench — hex/byte pane + saved regression collections

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S9` |
| **Wave** | 1 |
| **Status** | **🚧 In progress (ADR 0119, ADR 0121)** |
| **Effort** | L |
| **Backlog items** | #84 · #168 |
| **Build order** | #84 → #168 |
| **ADR(s)** | (decision note) Test Bench UTF-8 byte hex pane — demand-gate trigger fired (#84 fill-in; scope to a byte dump, not mfb64 whole-body decode); NEW — Test Bench saved regression collections — PHI-at-rest storage posture + compare/normalization semantics |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | Yes |
| **Branch** | `dg-s9` (new.ps1 names branch after -Name) |
| **Depends on** | 84 |

## Items

| Item | Title | Status |
|---|---|---|
| #84 | Diagnostic panes — hex body view + HL7-aware diff + profiling | ○ open |
| #168 | Test Bench saved regression collections | ○ open |

## Owned files / seams

- `ide/src/testBench.ts (Incoming union; Hex button + showHex; collection save/run/compare UI; use this.context Memento)`
- `ide/src/hexdump.ts (NEW pure vscode-free module), ide/src/testCollections.ts (NEW model + compare reusing hl7diff.diffMessages)`
- `ide/src/test/suite/hexdump.test.ts + test-collections.test.ts, ide/src/extension.ts, ide/package.json`

## Notes, PHI & gotchas

#84 rides the existing --show-phi Test Bench surface (no new egress) — in-memory render only, never write decoded bytes to disk, cap render size. #168 is a NEW PHI-at-rest surface (records full case + expected-output bodies): store under machine-local extension storage (workspaceState / a non-synced storageUri) — NEVER a repo-tracked/committable file, and NOT context.globalState (eligible for Settings Sync → could sync PHI off-machine). Steer authors to synthetic PHI-free cases (ADR 0030). VERIFIER REFUTED #84's decode design: dryrun --show-phi --json UTF-8/replace-decodes file bytes (peek.py) and NEVER emits the mfb64:v1: marker — the true binary bytes are already lossily corrupted, and the marker-strip path has nothing to strip. Scope #84 to a UTF-8 byte hex dump of DryRunRow.raw (real binary hex would need an engine/CLI read-path change); the ADR note must not claim mfb64 whole-body decoding. #168 compare MUST be HL7-aware with a volatile-field ignore policy (MSH-7/MSH-10/ACK dates) decided up front; upgraded to a full ADR. Both edit testBench.ts → sequential. ide/-only — fully parallel-safe vs engine/store/api sessions.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s9\`, branch \`claude/s9-testbench-hex-and-collections\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
