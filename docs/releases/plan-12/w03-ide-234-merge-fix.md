# PLAN-12 · Wave 3 · #234 IDE client-side strip fix (both writers)

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `ide-234-merge-fix` |
| **Wave** | 3 |
| **Status** | ✅ **Complete** (2026-07-16 — landed in this session's PR; IDE v0.0.34; wizard collision path re-scoped to S10) |
| **Effort** | 1 |
| **Backlog items** | #234 (Phase 3 of 4) |
| **ADR** | No |
| **Store schema / 3-backend** | No (ide lane) |

## Items

| Item | Title | Status |
|---|---|---|
| #234 (P3) | Extension-side merge so a GUI save posts the full object, not just rendered fields | ✅ built (this PR) |

## Owned files / seams

`ide/src/connectionMerge.ts` (new, **pure**) · `ide/src/connectionEditor.ts` (save() merge; hold full `initial`) ·
`ide/src/configEditors.ts` (save-handler merge) · `ide/src/test/suite/connection-merge.test.ts` (new — must NOT join
`test:unit`'s ignore list) · `ide/package.json`(+lock) — **takes 0.0.34 after rebasing (W3 ide-hotspot owner)**.

## The work

1. **Pure module `connectionMerge.ts`:** `mergeFormIntoInitial(initial, posted)` — result = `{initial minus
   RENDERED_FIELDS(direction)}` overlaid with the posted object, where `RENDERED_FIELDS` = the fields the form
   actually renders per `build()` (`connectionEditor.ts:400-430`): inbound {settings, router, ack_mode, strict} /
   outbound {settings, ordering, retry.max_attempts}. `retry` merges field-wise (posted `max_attempts`
   set-or-delete over `initial.retry`'s other RetryPolicy fields); `settings` posted wins wholesale (the form renders
   all rows); a cleared select / unchecked strict **deletes** the key (absent = read-schema default).
2. **Verdict-corrected — clone direction-flip rule:** the merge applies **ONLY when
   `posted.direction === initial.direction`**. Clone keeps direction editable (`connectionEditor.ts:378`); a naive
   overlay would carry direction-inapplicable keys (`router`/`ack_mode`/`shard`/…) into the other direction's table
   and the loader's `_reject_unknown` would fail EVERY clone-flip save — a regression of a working flow. On a flip:
   intersect carried keys with the posted direction's read-schema set, or fall back to posted-only.
3. **Verdict-corrected — ONE stated merge-source policy for both writers:** save-time **fresh `connection list`**
   (or an explicitly documented staleness window). `connectionEditor.ts` save() (~:106-127) and `configEditors.ts`'s
   save handler (~:142-153) use the same source; the clone path preserves non-rendered fields too (a clone of a
   scheduled connection carries the schedule).
4. **The name-collision overwrite hole — decide, don't drift:** the create/clone/wizard paths shell the same
   full-replace upsert with **no existing-name refusal**, so saving under an existing name still silently destroys
   that connection. Either **fix here** (existing-name refusal via `connection list`) or **explicitly re-scope**:
   drop the "closes the silent-drop class entirely" claim and hand the hole to
   [w04-docs-234-closeout](w04-docs-234-closeout.md)'s follow-up filing.
5. No webview HTML behavior change (`build()` keeps posting rendered fields; the merge happens where the full object
   lives). Bump `ide/package.json`(+lock) → **0.0.34**.
6. **BACKLOG #234's flip is NOT done here** — deferred to W4 so Wave 3's `docs/BACKLOG.md` touch belongs to
   [w03-store-235-flip](w03-store-235-flip.md) alone (the #234/#235 entries are line-adjacent).

## Dependencies

- **Gate: [w01-config-234-writer](w01-config-234-writer.md) merged** — without the writer fix the merged post is
  silently re-stripped server-side (the fix is unobservable); without its Phase 2 the list feeding the merge crashes
  on schedule-bearing files.
- Rebases over the W1/W2 ide merges; takes the next patch version.

## Notes & gotchas

- **`npm run test:unit` is plain-node mocha** — every unit-tested helper lives in the pure `connectionMerge.ts`;
  never export from vscode-importing modules.
- **Manual ide-leg hold** before merge (the leg is not a required check; auto-merge is on).
- Manual end-to-end verify: seed a maximal `connections.toml` (all casualty keys, TOML-native times, hand comments),
  edit an unrelated field in BOTH the command-opened form and the custom editor, diff: every key survives;
  `messagefoundry check` passes.

## Verification — Definition of Done

- `cd ide && npm run typecheck && npm run compile && npm run test:unit` — merge unit cases:
  edit-preserves-schedule/shard/allowlist; clear-deletes-key; retry field-wise; clone-preserves;
  direction-flip does not carry inapplicable keys.
- Root `QT_QPA_PLATFORM=offscreen pytest -q` once (no Python touched — prove no cross-lane drift).
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; manual ide-leg hold; owner approves.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
