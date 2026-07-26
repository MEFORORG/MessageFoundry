# PLAN-13 · Wave 1 · #240 (a)+(b) — alerts/codeset GUI write-path hygiene

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `config-240-editor-writers` |
| **Wave** | 1 |
| **Status** | 🚀 Built + adversarially CONFIRMED (2026-07-20) — PR [#1126](https://github.com/MEFORORG/MessageFoundry/pull/1126) (auto-merge/squash, CI running incl. ide-build leg). Also closed a live bug: 4 `AlertRule` fields silently dropped on save. #240 left 🚧 (✅ deferred to W2 ide lane). |
| **Effort** | 1.5 |
| **Backlog items** | #240 fixes (a) + (b) |
| **ADR** | No — increments the #234 write-path rule under ADR 0007 (connections.toml) + ADR 0014 (alert-rule writer); precedents PR #1076 / #1081 already merged |
| **Store schema / 3-backend** | No (config-editor + CLI) |

## Step 0 — claim the item (🚧, before any code)

Per [master §D](../MULTISESSION-PLAN-13.md#d-coordination-rules--gotchas): this session is the **W1 banner owner for #240**.
Before writing code, commit a **🚧 in-progress claim** on #240 in `docs/BACKLOG.md` (its own commit), naming the lane —
`> 🚧 **Status — in progress (lane `plan13-config-240`, branch off `origin/main`).**`. It stops a sibling worktree
double-building #240. **Defer the ✅ close** to the W2 `ide-240-wizard-collision` session (which lands part (c)); this
session leaves the banner at 🚧. The claim edit sits at the top of #240's banner (@7036), ~16 lines above #241's (@7052)
— serialize this merge with `store-241` (master §C).

## Items

| Item | Title | Status |
|---|---|---|
| #240 (a) | alerts_edit fail-loud unknown-key + parity guard | 🔢 to build |
| #240 (b) | codeset over-wide-row refusal + create-collision refusal (server-side) | 🔢 to build |

## The work

**(a)** Keep `_RULE_FIELDS` **pinned** (module const; do **not** import `settings.py` at runtime — preserve the module's
deliberate engine-import isolation). Add a fail-loud unknown-posted-key reject in `_validate_input`
(`set(obj) - set(_RULE_FIELDS)` after the existing index check, mirroring `connections_edit`'s message shape) + a **pytest
parity guard** `set(_RULE_FIELDS) == set(AlertRule.model_fields)` (test-only import).

**(b)** Make `_read_csv_grid` **REFUSE** an over-wide row (raise `WiringError`) **at read time** (so show→shear→save can't
defeat the write-path `_validate_rows` guard). Give `upsert_code_set` a `create: bool` that refuses a create-flavored save
under an existing stem, wired **server-side** via the `_codeset` CLI handler (`messagefoundry/__main__.py`) reading
create-intent from the existing `editName` arg. **Own the engine/editor-symmetry call:** also tighten `code_sets._load_csv`
to reject over-wide (`csv.DictReader` silently sinks extra cells into the restkey today) so the editor is not stricter than
the engine — never accept-and-drop.

## Owned files / seams

`config/alerts_edit.py` · `config/codeset_edit.py` · `messagefoundry/__main__.py` (`_codeset` create-signal — **≠**
`harness/__main__.py`) · `ide/src/codeSetEditor.ts` (**conditional** — only if the CLI cannot derive create-intent from
`editName`) · `tests/test_alerts_edit.py` · `tests/test_codeset_edit.py`.

## Explicitly NOT

- **Claims #240 (🚧) but does NOT flip it ✅** — the ✅ close is deferred to `ide-240-wizard-collision` (W2) so it reflects
  all of a+b+c. Only the 🚧 claim (Step 0) and no other #240 edit lands here; the ✅ flip is W2's, a different wave from any
  same-wave BACKLOG co-editor.
- Keep the codeset collision **server-side** so (b) stays wholly Python; the W2 ide session owns different TS files.

## Dependencies

None — both mirrored patterns already shipped (#234 fail-loud writer + parity guard; #1081 collision-refusal).

## Verification — Definition of Done

- `ruff check messagefoundry tests` + `ruff format --check` → `mypy messagefoundry` (strict) →
  `pytest tests/test_alerts_edit.py tests/test_codeset_edit.py tests/test_connections_cli.py`.
- Red-first: parity guard fails when a key is added to `AlertRule` but not `_RULE_FIELDS`; over-wide row fails loud.
- **No `Co-Authored-By: Claude` trailer**; owner approves PR.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
