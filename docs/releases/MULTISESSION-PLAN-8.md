# MessageFoundry — Multisession Execution Plan 8 (2026-07-10)

**Intent.** Build the **analyst-facing low-code layer** ranked by the 2026-07-10 IDE deep-research
([`docs/research/ide-low-code-options.md`](../research/ide-low-code-options.md)): native VS Code polish
(**#221**) + the typed action vocabulary and structured action-list lens (**#222**, ADR **0076**) — the
Corepoint-familiar experience over real Python, composing with the shipped #92 live-debug loop. Everything
stays inside the amended bright line (CLAUDE.md §12 / #26 amendment): the lens is a **projection of real
`.py`**, never a stored declarative artifact, never a canvas.

**Execution model — coordinator-dispatch (NOT owner-launched parallel chats).** Per the throughput-build
and Wave-4 method that has worked before: the owner gives **one handoff** (§F) to **one coordinator
session**; the coordinator dispatches worker agents **via the Workflow tool, each in its own worktree**,
recovers interrupted lanes, verifies quartets, sets merge order, and single-writes the coordination
ledger (AI memory, `plan8-coord-ledger`). **Autonomy L1:** workers build + verify + **commit local** —
no push/PR; the **owner** opens/merges PRs and has already ratified ADR 0076 before Wave 1 engine work.
(If the owner pre-authorizes it in the handoff, the coordinator may push branches + open PRs when a
lane's quartet is green — the Wave-4 variant.)

**Scope.** Four buildable lanes after the docs lane:
1. **L1 — #221 IDE native-surface polish** (walkthrough extension, registered custom editors for the
   existing config forms, engine status-bar item, TOML association, QuickInput wizard);
2. **L2 — #222 phase 1+2a**: `messagefoundry/actions.py` vocabulary + static `lens parse --json` CLI
   (ADR 0076 §2–§4) — the engine half;
3. **L3 — #222 phase 2b**: the read-only action-list custom editor consuming the L2 JSON contract;
4. **L4 — #222 phase 3** (editing) — **deferred**: scoped only at phase-2 bake + explicit owner go.

**Out of scope — HARD bright line (CLAUDE.md §12, amended).** No declarative logic artifact or
interpreter, no drag-drop/canvas logic authoring, no field-mapping grid; the lens grammar is fixed by
ADR 0076 §4 — **widening the grammar requires an ADR amendment, not a lane decision**. Router lens,
`lens rewrite`, notebook surfaces: out of v1. Transforms stay pure (only `db_lookup`/`fhir_lookup`).

**Lineage.** Supersedes-forward [`MULTISESSION-PLAN-7.md`](MULTISESSION-PLAN-7.md) (the AI-off DX wave —
its board is complete: #48 palette, #92 v1/v2, #104 Cookbook+Walkthrough, ADR 0072/L5 traced dry-run,
#84 diff). PLAN-8 is the same IDE/DX program's next chapter and consumes PLAN-7's deliverables (#92
values inside the lens; the walkthrough L1 extends).

**Numbering state (verified 2026-07-10; branch rebased onto `origin/main @ 39df911` after PRs #863/#864
merged same-day).** ADR **0076** is claimed by this plan's docs PR (next-free = **0077**). BACKLOG
next-free heading = **`## 223.`** (`## 221.`/`## 222.` claimed by the same PR; both self-scored on the
**#863 ten-level value×difficulty scheme** and, like #206–#220, awaiting the next ranked-table pass).
⚠ Re-check both on `origin/main` immediately before any further claim — `docs/BACKLOG.md` is a
high-traffic file (two touching PRs merged the day this plan was written) and heading races are live.

**Live siblings (do not edit — verified 2026-07-10; coordinator MUST re-verify at each wave start,
including open PRs, not just branches).** The only OPEN PR touching `ide/` is dependabot **#649**
(`ide/package.json` + `package-lock.json` devDependency bump — trivial land-order/rebase for L1).
Unmerged non-PR branches also exist (`feat/config-repo-storage` touches `ide/package.json` +
`extension.ts` + several `ide/src` files; several stale PLAN-7 lane branches whose content is already
squash-merged) — treat only OPEN PRs as live contention, but list what you find in the ledger.
`feat/adr0071-pr3-dispatch-wiring` owns `pipeline/wiring_runner.py` (not `__main__.py`, not
`actions.py`-adjacent — L2 clear; re-confirm at L2 start). `docs/adr-0070-t17…` and `setup-tester-adr`
both edit `docs/adr/README.md` — expect the known one-line index conflict against this docs PR;
land-order or trivial rebase resolves. Unrelated: the merged PR **#864**'s branch was named
`plan8-metrics` (ops/metrics work) — the "plan8" moniker is already in the wild; keep
`plan8-coord-ledger` status reports clearly scoped to THIS plan to avoid cross-wiring.

---

## A. Lane roster

| ID | Title | Primary files | ADR | Deps | Parallel-safe-with | Effort |
|---|---|---|---|---|---|---|
| **L0** | COORD / research + backlog + ADR + plan (this branch) | `docs/research/ide-low-code-options.md`, `docs/BACKLOG.md` (#26 amendment, #221, #222), `CLAUDE.md` §12, `docs/adr/0076-*.md` + index, this plan | authors **0076** | none | all | S — **DONE pending owner merge + ratify** |
| **L1** | #221 IDE native polish | `ide/src/statusBar.ts` (NEW), `ide/src/connectionQuickInput.ts` (NEW), `ide/src/connectionEditor.ts`, `ide/src/codeSetEditor.ts`, `ide/src/test/suite/*`, `ide/package.json` + `ide/src/extension.ts` (direct — walkthrough steps, customEditors, TOML association) | none | docs PR merged | L2 | M |
| **L2** | #222 P1+P2a — vocabulary + `lens parse` | `messagefoundry/actions.py` (NEW, SPDX), `messagefoundry/lens.py` (NEW, SPDX), `messagefoundry/__main__.py` (subcommand), `tests/test_actions.py` + `tests/test_lens_parse.py` (NEW), `ide/snippets` delta note only | **0076** (Accepted first) | L0 (ratify) | L1 (**sole engine editor**) | M–L · **critical path** |
| **L3** | #222 P2b — action-list lens editor | `ide/src/actionLens.ts` (NEW), `ide/src/test/suite/action-lens.test.ts` (NEW), `ide/package.json` + `ide/src/extension.ts` (direct, rebased over L1) | **0076** | **L1 + L2 merged** | — | L |
| **L4** | #222 P3 — editing (`lens rewrite` + form edits) | scoped at go | **0076 §5** | L3 baked + **owner go** | — | M–L |

> **Manifest rule (simplified from PLAN-7):** PLAN-7's delta-snippet indirection existed to let
> *multiple concurrent* IDE lanes avoid a rebase chain. PLAN-8 has only **one IDE lane per wave**, so
> lanes edit `ide/package.json` / `ide/src/extension.ts` **directly** — the quartet then actually
> exercises the registrations (a delta left unapplied would under-verify). The only manifest
> contention is dependabot **#649** (land-order/rebase). L3 (Wave 2) rebases over L1's landed
> manifest before starting.

## B. Waves

```
Wave 0  L0 docs PR ──▶ owner: merge (ratifies #26 amendment) + ratify ADR 0076
        (ratification mechanics: flip the ADR's Status line and its docs/adr/README.md
         row from Proposed → Accepted — that edit is what §F's precondition check looks for)
Wave 1  L1 (#221)  ─────────────┐        dispatched together; L1 needs only the merge,
        L2 (vocab + lens parse) ─┴──▶    L2 needs 0076 Accepted
Wave 2  L3 (lens editor) — after max(L1, L2) merges; rebases over L1's manifest
Wave 3  L4 (editing) — owner-gated at phase-2 bake
```

## C. Worker dispatch specs (coordinator passes these as Workflow agent prompts)

Common preamble for every worker (coordinator prepends): *branch off `origin/main` (fresh fetch);
worktree via `scripts/worktree/new.ps1 -Name <lane> -NoInstall`; build your own venv — engine lanes
install `[dev,console,dicom,fhir]` extras (a `[dev,console]`-only venv showed ~13 pre-existing
DICOM/FHIR mypy stub errors at last check, W4 ledger — known trap, count may drift); first action: `git fetch && git log origin/main --oneline -5 && gh pr
list --state all --limit 20` to rule out already-merged duplicates, and re-verify your files against
live siblings; commit local with explicit paths (repo hook blocks `git add -A`/`-u`/`.`; no `commit
-a`); **omit the `Co-Authored-By` trailer** (CLA bot); **no push, no PR**; SPDX header on every new
`.py`; synthetic HL7 only.*

**L1 (branch `feat/ide-221-native-polish`).** Build #221 exactly as filed: (a) extend the shipped Get
Started walkthrough (PR #798) with point-at-engine / open-config-dir / live-debug / promote steps;
(b) `CustomTextEditorProvider` adapters registering the existing connection form + code-set grid as
`customEditors` (glob: the config dir's `connections.toml` / code-set files; `priority: "default"` with
"Reopen With" fallback — AWS pattern); (c) status-bar engine indicator (target URL/env, reachable-poll
via existing `engineClient`, click → Home); (d) TOML language association for config-dir files;
(e) native multi-step QuickInput new-connection wizard (official `multiStepInput` pattern) writing via
the same `connection upsert` CLI as the form. **Verify:** IDE quartet — `npm ci && npm run typecheck &&
npm run compile && npm test`; note `@vscode/test-electron` cannot launch on a headless box (exit 9) —
unit-test pure logic node-side. ⚠ The CI `ide` job is **NOT a required check and ci-gate does not roll
it up** (the windows electron leg runs only on the public mirror) — it cannot block a merge; the
coordinator inspects it manually after the owner pushes. Edit the manifest/`extension.ts` directly
(§A manifest rule); IDE tests must **mock the CLI boundary** — canned JSON, no live engine, the CI
`ide` job has no Python (PLAN-7 rule, kept).

**L2 (branch `feat/adr0076-actions-vocab`).** Build ADR 0076 §2 phase 1 + §3–§4 `lens parse`:
`actions.py` (v1 roster from ADR table, pure, typed, mypy-strict), `lens.py` (stdlib `ast`, static-only,
row contract + coverage invariant), `__main__.py` `lens` subcommand (`parse <module> --json`). Tests =
the ADR §6 gates **1, 3–5** (coverage partition property over `samples/config` + adversarial handlers;
static-only proof; purity; no new dep — gate 2 byte-stability is L4's, it tests `lens rewrite`).
**Also deliver for L3:** canned `lens parse --json` output fixtures committed under
`ide/src/test/fixtures/lens/` (generated from the samples corpus) — L3's tests stub the CLI spawn with
these, since the CI `ide` job has no Python. **Verify:** engine quartet — `ruff check .`,
`ruff format --check .`, `mypy messagefoundry` (strict), `QT_QPA_PLATFORM=offscreen pytest -q` (FULL
suite — never a subset). Sole editor of `__main__.py` this wave; re-confirm
`feat/adr0071-pr3-dispatch-wiring` still doesn't touch it before starting.

**L3 (branch `feat/adr0076-action-lens`, Wave 2).** Build the read-only lens editor per ADR 0076 §2
phase 2b: `actionLens.ts` `CustomTextEditorProvider` (opt-in entry: "Reopen in Action-List view" CodeLens
on `@handler` + command; NOT default for `.py`), rows→list rendering with parameter forms (read-only),
in-editor toolbar, Test button → Test Bench, degradation ladder (code rows in place; parse failure →
notice + text editor), live values via existing #92 lanes (redacted default). Consumes `lens parse`
JSON only — never parses Python in TS; tests **stub the CLI spawn with L2's committed fixtures**
(`ide/src/test/fixtures/lens/`) — no live engine in `npm test` (the CI `ide` job has no Python).
**Verify:** IDE quartet; rebase over L1's landed manifest first.

## D. Contention matrix

| File(s) | Lanes | Resolution |
|---|---|---|
| `ide/package.json`, `ide/src/extension.ts` | L1, L3 (+ dependabot #649) | direct edits (§A manifest rule — one IDE lane per wave); L3 rebases over L1's landed state (cross-wave, never concurrent); #649 = trivial land-order |
| `messagefoundry/__main__.py` | L2 | sole editor this wave; re-verify vs `feat/adr0071-pr3-dispatch-wiring` at start |
| `docs/BACKLOG.md` | L0 now; status banners later | coordinator-only writes; 4-way in-flight race — flip banners in the coordinator integration commit, re-checking numbering |
| `docs/adr/README.md` | L0 | known one-line conflict vs the 0070/0074 in-flight branches; land-order/rebase |
| `ide/src/connectionEditor.ts`, `codeSetEditor.ts` | L1 only | uncontested (verified — no in-flight branch touches `ide/`) |

## E. Coordinator operating notes (lessons carried from the throughput/W4 ledgers)

- **Interrupted dispatches are normal.** A killed Workflow may leave a lane complete-but-unverified or
  uncommitted-in-worktree: check `git -C <worktree> status/log` before re-dispatching; re-run a lost
  verify/adversarial-review as a standalone agent; commit verified work yourself rather than rebuilding.
- **Adversarial review per lane before calling it PR-ready** (build → verify → independent review →
  fix), the pattern every prior wave used. Definition: a separate reviewer agent with **no build
  context** reviews the lane's full diff against its spec + the ADR/backlog item; every finding is
  folded or explicitly waived in the ledger with a reason — never silently skipped.
- **Combined-tree rule:** when a second lane lands on a shared file, verify the *combined* tree locally
  (quartet in the rebased worktree) before declaring green — GitHub "CLEAN" is textual only.
- **Ledger:** create memory `plan8-coord-ledger` (single-writer, this coordinator) — lanes, worktrees,
  branches, commits, verify results, owner decisions; update on every state change.
- **Cleanup:** `scripts\worktree\remove.ps1 -Name <lane>` from the main checkout when a lane lands;
  delete local branches; remote deletes need owner auth.
- **Marketplace-publish follow-up:** after L1 + L3 land, the "publish to Marketplace + Open VSX" do-next
  trigger ("AFTER the planned IDE-focused improvements") is plausibly met — surface to owner, don't act.

## F. Coordinator handoff (the one prompt the owner gives a session)

> **ultracode** — You are the PLAN-8 coordinator. Read `docs/releases/MULTISESSION-PLAN-8.md`,
> `docs/research/ide-low-code-options.md`, and ADR 0076, then run the plan under its §E rules:
> confirm the docs PR is merged and ADR 0076 is **Accepted** (stop and report if not — deliberately
> conservative: both Wave-1 lanes wait for Acceptance even though L1 strictly needs only the merge);
> re-verify the §"Live siblings" contention facts **including open PRs (dependabot)**; create the
> Wave-1 worktrees and dispatch **L1 and
> L2 in parallel** via the Workflow tool (build → verify quartet → adversarial review → fix → commit
> local, per §C specs); recover any interrupted lane per §E; when a lane is green, report it PR-ready;
> after both Wave-1 lanes merge, dispatch L3 the same way (rebasing over L1's manifest); L4 only on my
> explicit go. Single-write the `plan8-coord-ledger` memory. Autonomy L1: you commit local only — I
> open and merge PRs [owner may amend: "…or push + open PRs yourself when green"].

## G. Definition of done (per lane)

- [ ] Quartet green in the lane's own worktree venv (engine: ruff ×2 + mypy strict + FULL pytest; IDE:
      npm ci/typecheck/compile/test with the headless-electron caveat noted)
- [ ] Adversarial review run; findings folded or explicitly waived by the coordinator with reason
- [ ] New `.py` files SPDX-headed; no new runtime dependency (else stop — DEP-1 re-lock is owner-visible)
- [ ] (L3) lens live values render **redacted by default**; the IDE never auto-passes `--show-phi`
- [ ] Commit(s) local, explicit paths, no Co-Authored-By trailer; delta snippets documented (IDE lanes)
- [ ] Ledger updated; lane reported PR-ready to the owner
