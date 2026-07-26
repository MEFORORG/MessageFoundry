# PLAN-13 · Wave 2 · #240 (c) — connection-wizard name-collision refusal

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `ide-240-wizard-collision` |
| **Wave** | 2 |
| **Status** | 🔢 Not started |
| **Effort** | 1 |
| **Backlog items** | #240 fix (c) — closes #240 |
| **ADR** | No — reuses the #1081 `planSave`/collision precedent under ADR 0007 |
| **Store schema / 3-backend** | No (IDE surface) |

## The work

`connectionQuickInput.saveConnection` fetches a fresh `connection list` and runs a **create-semantics** name-collision gate
— reuse `planSave` / `findNameCollision` / `nameCollisionError` from `connectionMerge.ts` by **import only** (`WizardConnObj`
is structurally assignable to `ConnObj` via its index sig) — **before** `runJson(connectionUpsertArgs(...))`, so finishing
the keyboard wizard on an existing name **refuses** instead of full-replacing. Add an optional pure `planWizardSave` helper
in `connectionWizardModel.ts` for node-side testability.

## Owned files / seams

`ide/src/connectionQuickInput.ts` · `ide/src/connectionWizardModel.ts` · `ide/src/test/suite/connection-wizard.test.ts` ·
`docs/BACKLOG.md` (#240 @7036).

## Notes & gotchas

- `connectionMerge.ts` is **imported / READ**, never owned/edited (the #1081 reuse). `npm run test:unit` is plain-node
  mocha → the tested `planWizardSave` helper must live in the **vscode-free** `connectionWizardModel.ts`, never exported
  from a vscode-importing module.
- Owns different TS files than config-240's `codeSetEditor.ts` (no cross-wave TS collision).
- Flips **#240** banner ✅ once all three fixes (a+b from config-240, c here) have landed.

## Dependencies / gate

**Gate:** `config-240-editor-writers` MERGED (banner-flip ordering — the (c) code is itself file-disjoint from a+b). The
ide CI leg is **NOT** a required check and auto-merge is on → **MANUAL HOLD**: do not enable auto-merge / approve until the
ide leg reports green.

## Verification — Definition of Done

- `cd ide && npm run typecheck && npm run compile && npm run test:unit` + eslint; the wizard collision-refusal test green.
- **No `Co-Authored-By: Claude` trailer**; owner approves PR after the ide leg is green.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
