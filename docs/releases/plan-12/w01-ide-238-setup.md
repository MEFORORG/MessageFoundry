# PLAN-12 · Wave 1 · #238 engine-pill guided setup page

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `ide-238-setup` |
| **Wave** | 1 |
| **Status** | ✅ **Complete** (2026-07-16 — built + docs tail landed in this session's PR; IDE v0.0.32) |
| **Effort** | 2 (~2 sittings, one worktree) |
| **Backlog items** | #238 (all phases) |
| **ADR** | Yes — **ADR 0112 in-file amendment, ratified + appended 2026-07-16** (with the plan; index row updated same commit). This session builds against it and updates its build-state rider on landing. |
| **Store schema / 3-backend** | No (ide lane; zero Python) |

## Items

| Item | Title | Status |
|---|---|---|
| #238 | Engine-pill guided setup page for store-less workspaces | ✅ built (this PR; manual F5 smoke with the owner) |

## Ratified decisions (owner, 2026-07-16 — the former pre-code gate)

1. **(a) Ledger form:** in-file **ADR 0112 amendment** (not a new ADR) — appended with the plan; see
   [ADR 0112 § Amendment (2026-07-16)](../../adr/0112-ide-engine-lifecycle-from-the-status-bar-pill-guarded-start-stop-restart.md).
2. **(b) Dev engine:** the page **DOES** offer the test-only developer engine via the existing guarded
   `CMD.startEngine` (modal create-DB confirm remains the guard), with **context-honest copy**.
3. **(c) Gate:** stays **`canControl`-only**; unreachable/foreign states keep their current actions (copy-start AND
   Configure engine target). A no-control informational page is deferred.

## Owned files / seams

`ide/src/engineStatusModel.ts` · `ide/src/engineSetup.ts` (new) · `ide/src/engineSetupContent.ts` (new, vscode-free)
· `ide/src/extension.ts` (registration beside cookbook ~:124-131) · `ide/package.json`(+`package-lock.json`) —
**takes 0.0.32 (W1 ide-hotspot owner)** · `ide/src/test/suite/engine-control.test.ts` ·
`ide/src/test/suite/engine-setup.test.ts` (new) · docs tail: `docs/adr/0112-…md` (build-state rider),
`docs/adr/README.md` 0112 row, `docs/BACKLOG.md` #238 flip, `ide/README.md` (conditional).

## The work

**BRANCH FROM `main`.** The pill work is merged (`c2239a05`, PR #1067); the `pill-engine-lifecycle` worktree tip
`eb560f38` is tree-identical to it and **behind** main — resuming it would regress four merged PRs (#1068–#1071).
Correct BACKLOG.md:7001's stale "build it with that work" premise in the close-out.

**Phase 1 — pill lead swap + guided setup webview + tests:**

1. Add `CMD.openEngineSetup` to the CMD map (`engineStatusModel.ts` ~:574-588).
2. Replace the `hasStore == false` `lifecycleActions` branch (~:655-659) with the **"Set up an engine…"** action
   dispatching the new CMD; update the function's doc comment (~:624-631), which currently describes the create-DB
   labelled start. The `hasStore == true` branch keeps plain "Start the engine" unchanged.
3. `ide/src/engineSetupContent.ts` (vscode-free: action-button data + page copy sections) and `ide/src/engineSetup.ts`
   (WebviewPanel shell **mirroring `cookbook.ts`** — `nonce()`, quote-escaping `esc()`, CSP
   `default-src 'none'; script-src 'nonce-…'`, reveal-if-open, dispose). **The command-dispatch message handler is
   NEW code whose discipline mirrors `statusBar.ts:783-785`** (executeCommand of a known CMD looked up in the content
   model — never a command string from the webview message itself); `cookbook.ts` is mirrored only for the panel
   shell (its own handler inserts snippets and dispatches nothing).
4. Page content: production-as-a-service posture (`docs/SERVICE.md`), point-at-an-engine (engine-target settings),
   copy-start fallback, "Set up environment", and the **visually separated test-only dev-engine section**
   dispatching `CMD.startEngine`. **Context-honest copy** (the command is palette-visible and the page
   context-blind): *"if no engine store exists here you'll be asked to confirm creating a NEW database and a
   bootstrap admin; if one exists, this starts that engine"* — `statusBar.ts:527` guards only `!hasStore`.
5. Register in `extension.ts` beside cookbook; contribute the command in `ide/package.json`; bump version → 0.0.32.
6. Tests: **rewrite** `engine-control.test.ts:142-146` (store-less first action === `CMD.openEngineSetup`, label
   matches `/set up/i`, **no `CMD.startEngine` offered** for `canControl && !hasStore`) — the old `/new engine/i`
   assertion is deleted in the same commit the behavior changes (never a skipped test). The sweep context
   `CONTROL({canControl:true, hasStore:false})` **already exists at ~:172 — verify it covers the new id, don't
   re-add**. New `engine-setup.test.ts`: contribution assertion (per `cookbook.test.ts:83-89` pattern) +
   content-model commands ⊆ `Object.values(CMD)` + dev-engine button === `CMD.startEngine`.

**Phase 2 — docs tail + smoke + PR:**

1. ADR 0112: update the amendment's build-state rider (built; extension version) — the decision text is already
   ratified/appended; keep `docs/adr/README.md`'s 0112 row Status cell in sync in the same commit.
2. Flip BACKLOG #238 to built; correct the stale pill-coordination premise in its status note.
3. `ide/README.md` touch-up if it describes the store-less pill lead.
4. Manual Extension Development Host smoke (F5): store-less workspace → pill leads with "Set up an engine…", hover's
   first command-link opens the page; every page button dispatches (settings / copyStart / setupEnvironment modal /
   dev-engine modal create-DB confirm, cancel aborts); a workspace WITH a service TOML or `*.db` still gets plain
   "Start the engine".

## Dependencies

None (ratifications done; branch from main). **Merge order:** first IDE merger of the plan — claims
`ide/package.json` 0.0.32; `ide-230-autocomplete` (W2) and `ide-234-merge-fix` (W3) rebase over it.

## Notes & gotchas

- **`npm run test:unit` is plain-node mocha** — `require('vscode')` fails there. Every unit-tested helper lives in
  `engineSetupContent.ts` (pure); never export test helpers from `engineSetup.ts`/`statusBar.ts`.
- **The ide CI leg is NOT a required check and auto-merge is on** — explicit **manual merge hold**: do not enable
  auto-merge or approve until the ide leg reports green.
- `statusBar.ts` should need zero edits (hover allowlist is `Object.values(CMD)`); if an edit proves necessary, keep
  it minimal and re-run the full engine-doctor suite.
- The ADR 0110 §4 boundary stays intact: **no `EngineLink` field, no probe endpoint, no setting** — the frozen CI
  allowlists must stay green.
- Optional root `pytest -q` (no Python is touched): either drop it or run with `QT_QPA_PLATFORM=offscreen`.

## Verification — Definition of Done

- `cd ide && npm run typecheck && npm run compile && npm run test:unit` — including the rewritten store-less
  assertion and the known-CMD sweep covering `openEngineSetup`.
- Manual F5 smoke checklist above (terminal-lifecycle mechanics are not node-testable — same posture ADR 0112
  records).
- Ledger check before PR: the ADR 0112 build-state rider + `docs/adr/README.md` row in one commit; amended AC-2/AC-7
  and `engine-control.test.ts` agree.
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; **manual ide-leg hold**; owner approves.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
