# mefor-run-checks

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.


### A Builder runs the checks before it commits, because nobody downstream can ask it to

- New behavior gets a test. Run, in order: `ruff check` + `ruff format --check`, `mypy` (strict),
  `pytest` (with `QT_QPA_PLATFORM=offscreen` for the PySide6 harness tests).
- `pre-commit` does not run mypy. Run it by hand before you commit, or strict typing first fails in
  CI, after your process is gone.
- If the full suite will not finish inside your turn, run the tests covering your change and push.
  Record in the PR body which checks you ran and which you skipped. An unpushed branch is lost.
- Some checks only ever run on a hosted runner, for example NSSM under `windows-service-smoke`. A
  Builder never sees their result. Push, open the PR, and name in the body which legs must be read.
  The Console or the Regulator reads them after the process exits.
---


- **Format + lint with Ruff** (`ruff format`, `ruff check`) — **there is no Black**. Type-check
  with **mypy (strict)**. Test with **pytest**.
- Dependencies live in [`pyproject.toml`](../../pyproject.toml) (`>=` minimums) and are pinned in a
  hash-locked `requirements.lock` (exported from `uv.lock`; CI checks it stays in sync and audits
  it — DEP-1). No ad-hoc installs — add deps to `pyproject.toml`, then re-run `uv lock`/`uv export`.
