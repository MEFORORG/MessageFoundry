# PLAN-13 · Wave 1 · #241 F3 — thread `snapshot_on_send` into verify/smoke

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `verify-241-snapshot-thread` |
| **Wave** | 1 |
| **Status** | 🔢 Not started |
| **Effort** | 0.5 |
| **Backlog items** | #241 finding 3 |
| **ADR** | No — completes ADR 0104's copy-on-Send preview parity |
| **Store schema / 3-backend** | No |

## The work

`verify.smoke.smoke_self` calls `dry_run(reg, msg, inbound=inbound)` at `smoke.py:66` using the **library default False**
while a default engine runs with `[pipeline].snapshot_on_send` **ON** (default True). Thread the setting through
`verify.runner.run_verify` (settings available at `runner.py:149`, call site `runner.py:172`) into that `dry_run` call as
`snapshot_on_send=...`. **Keep the library default when `settings is None`.** Config key
`settings.pipeline.snapshot_on_send` (`PipelineSettings`, default True, env `MEFOR_PIPELINE_SNAPSHOT_ON_SEND`). Add a smoke
self-route parity test asserting the thread-through.

## Owned files / seams

`messagefoundry/verify/smoke.py` · `messagefoundry/verify/runner.py` · `tests/test_verify.py`.

## Explicitly NOT

- Does **NOT** touch `docs/BACKLOG.md` (store-241 owns #241).
- The #230-banner-pointer sub-task is **already landed** (BACKLOG.md:6813 + 6828) — do **not** redo it.
- File-disjoint from store-241 (verify/ vs store/) → runs fully parallel, merges off its own no-DB gate.

## Dependencies

None. Pure local; no DB gate.

## Verification — Definition of Done

- `ruff` + `ruff format --check` → `mypy --strict messagefoundry` → `pytest -q tests/test_verify.py`.
- **No `Co-Authored-By: Claude` trailer**; owner approves PR.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
