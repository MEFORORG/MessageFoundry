# Deferred quality gates — build handoff: mutation (#6) + diff-coverage (#7)

**Status: DRAFT / ready-to-run.** These two advisory gates from the
[Code Quality & Anti-Slop Standards](../Code_Quality_Standards.md) rubric (**signals 6 and 7**) were
*deferred* because they need a **working test environment** to build and verify — they run the full test
suite, which the drafting session could not do locally (no `uv`/`venv`/`pip`). Everything a session with a
working venv needs is here: **environment setup → the exact jobs/configs → local verify → push.**

They are **advisory / non-required**, exactly like the already-shipped complexity + clone gates in
[`.github/workflows/quality-advisory.yml`](../../.github/workflows/quality-advisory.yml) (PR #1028). A job
here can show a red ✗ on its own PR but **can never block a merge**.

---

## 0. Ground rules (same as the shipped gates)

- **Advisory-first.** Every command is `--exit-zero` / `|| true` and the jobs are **not** required status
  checks. Rubric §4.1: coverage % and mutation *score* are weak/gameable as single numbers — **surface, never
  gate.**
- **Cost is real.** Coverage re-runs the ~2–5 min suite; mutation runs the suite *per mutant*
  (minutes → hours). Placement below keeps per-PR cost sane.
- **Verify with a real run before merging.** That is the entire reason these were deferred — build them where
  you can run `pytest` / `mutmut` locally, watch them work, *then* push.

---

## 1. Set up the environment (do this first) 🧰

These gates exercise the real engine, so you need the same full test env CI uses.

### Fastest — an isolated worktree with its own `.venv` (project-sanctioned, see [WORKTREES.md](../WORKTREES.md))
```powershell
# from the primary checkout (C:\Users\<you>\Code\MessageFoundry)
pwsh -NoProfile -File scripts\worktree\new.ps1 -Name quality-gates
#   -> creates ..\MessageFoundry-quality-gates : checkout + branch + a .venv with deps installed
cd ..\MessageFoundry-quality-gates
.\.venv\Scripts\Activate.ps1
```

### Or by hand (mirrors CI's install exactly — from `.github/workflows/ci.yml`)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# uv is the project installer; install the engine + all test extras + the web-console package:
uv pip install -e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole
```

### Then add the two gate tools (into the venv, for LOCAL testing only)
```powershell
uv pip install pytest-cov diff-cover mutmut
```
> These are **CI-only tools** — the drafted jobs below `pip install` them at runtime, so **do not** add them
> to `pyproject.toml` unless you also re-run `uv lock` + `uv export` (the **DEP-1 lock-sync gate** fails a PR
> whose `pyproject` deps changed without a regenerated `requirements.lock`).

### Confirm the suite is green first (console tests need offscreen Qt; whole suite ≈ 2–5 min)
```powershell
$env:QT_QPA_PLATFORM = "offscreen"
pytest -q
```
If that passes you have the environment these gates need. *(Some SQL-Server legs are env-gated and skip
locally — expected. The occasional MFA/TOTP timing flake re-runs clean.)*

---

## 2. Gate #7 — diff-coverage (signal 7)

**What it does:** runs the suite with coverage, then reports coverage of the **changed lines only** — never a
whole-repo % gate (rubric §4.1). Advisory.

### 2a. Local verify (before touching CI)
```powershell
$env:QT_QPA_PLATFORM = "offscreen"
pytest -q --cov=messagefoundry --cov-report=xml
diff-cover coverage.xml --compare-branch=origin/main --fail-under=0
```
- `--fail-under=0` ⇒ report only, never fail (advisory). Confirm `diff-cover` prints a sane per-file
  changed-line coverage table.
- Optional (keeps invocations clean; config only, no new deps): add to `pyproject.toml`
  ```toml
  [tool.coverage.run]
  source = ["messagefoundry"]
  branch = true
  [tool.coverage.report]
  show_missing = true
  ```

### 2b. The CI job — append under the existing jobs in `quality-advisory.yml`
```yaml
  coverage:
    # Signal 7 - diff-coverage visibility (advisory). Reports coverage of CHANGED lines only, never a
    # whole-repo % gate (rubric 4.1). Non-required. NOTE: re-runs the full suite (~2-5 min) per code PR.
    name: diff-coverage (advisory)
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out the source
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
          fetch-depth: 0            # diff-cover compares against origin/main
      - name: Set up Python 3.14
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.14"
      - name: Set up uv
        uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2
      - name: Install project + coverage tools
        run: |
          uv pip install --system -e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole
          uv pip install --system pytest-cov diff-cover
      - name: Tests with coverage (advisory)
        env:
          QT_QPA_PLATFORM: offscreen
        run: pytest -q --cov=messagefoundry --cov-report=xml --timeout=60 --timeout-method=thread || true
      - name: Diff-coverage vs main (advisory - never fails)
        run: |
          git fetch --no-tags --depth=1 origin main || true
          diff-cover coverage.xml --compare-branch=origin/main --fail-under=0 || true
```
**Cost lever:** if a full-suite run per PR is too much on the private repo, either add a path filter (only run
when `messagefoundry/**` or `tests/**` change) or gate the whole job to the mirror with the repo-slug
`if: github.repository == 'MEFORORG/MessageFoundry'` (free minutes) — but then it won't report on private
PRs. Start advisory-on-PR; move to mirror if cost bites.

---

## 3. Gate #6 — mutation-on-diff (signal 6) — highest leverage, hardest

**What it does:** mutates the **changed** source lines and checks the tests kill the mutants — the one gate
that *adversarially* proves your tests assert something (rubric A.4: matters most under solo review). Advisory.

### 3a. Two decisions to make first (this is why #6 was deferred)
1. **`mutmut` version + CLI.** mutmut **3.x rewrote the CLI and config** vs 2.x. Run `mutmut version` after
   install and use *that* version's syntax — the commands below are the shape, not gospel. **Verify locally.**
2. **Where it runs** (mutation is too slow for every private PR):
   - **(A) PR, diff-scoped** — mutate only files changed vs `origin/main` (small diffs → few mutants →
     tolerable). Closest to the rubric's "mutation on changed code"; higher per-PR cost. **Recommended.**
   - **(B) mirror-nightly, rotating** — a nightly cron on the mirror (free minutes) mutates a rotating
     slice. Cheap, but not per-PR.

### 3b. Local verify (against the installed mutmut version)
```powershell
$env:QT_QPA_PLATFORM = "offscreen"
$changed = (git diff --name-only origin/main...HEAD -- "messagefoundry/**/*.py") -join ","
# 2.x shape — CONFIRM against your installed version:
mutmut run --paths-to-mutate $changed
mutmut results
```
- Optional `pyproject.toml` config (2.x shape — verify for 3.x):
  ```toml
  [tool.mutmut]
  paths_to_mutate = "messagefoundry/"
  runner = "python -m pytest -x -q --timeout=60"
  ```
- Expect it to be **slow even diff-scoped.** Confirm `mutmut run` completes and `mutmut results` lists
  survived/killed mutants before wiring CI.

### 3c. CI job — option (A) PR diff-scoped (recommended)
```yaml
  mutation:
    # Signal 6 - mutation testing on CHANGED code (advisory, highest leverage). EXPENSIVE (suite per mutant);
    # scoped to files changed vs origin/main so a small PR stays tolerable. Non-required.
    name: mutation-on-diff (advisory)
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Check out the source
        uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0
        with:
          persist-credentials: false
          fetch-depth: 0
      - name: Set up Python 3.14
        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.14"
      - name: Set up uv
        uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2
      - name: Install project + mutmut
        run: |
          uv pip install --system -e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole
          uv pip install --system mutmut
      - name: Mutation-test the changed lines (advisory - never fails)
        env:
          QT_QPA_PLATFORM: offscreen
        run: |
          git fetch --no-tags --depth=1 origin main || true
          changed=$(git diff --name-only origin/main...HEAD -- 'messagefoundry/**/*.py' | paste -sd, -)
          if [ -z "$changed" ]; then echo "no changed messagefoundry/*.py; nothing to mutate"; exit 0; fi
          echo "mutating: $changed"
          mutmut run --paths-to-mutate "$changed" || true   # VERIFY CLI vs installed mutmut version
          mutmut results || true
```

### 3c′. CI job — option (B) mirror-nightly (add a `schedule:` trigger + repo-slug gate)
Add the cron to the workflow's `on:` block, then the job:
```yaml
# on:
#   pull_request:
#   workflow_dispatch:
#   schedule:
#     - cron: "23 4 * * *"     # nightly; the job's repo-slug if keeps it mirror-only (free minutes)

  mutation-nightly:
    name: mutation (nightly, advisory)
    if: (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && github.repository == 'MEFORORG/MessageFoundry'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      # ... same checkout / setup-python / setup-uv / install as option (A) ...
      - name: Mutation-test a rotating slice (advisory)
        env:
          QT_QPA_PLATFORM: offscreen
        run: |
          # e.g. a fixed high-value module, or rotate by day-of-month:
          mutmut run --paths-to-mutate messagefoundry/parsing/ || true
          mutmut results || true
```

---

## 4. Wire in + push

1. Add the chosen job(s) under the existing `complexity` + `clone` jobs in `quality-advisory.yml`.
2. If available, run `actionlint .github/workflows/quality-advisory.yml` (catches YAML/expression breaks that
   zizmor misses).
3. Commit — **avoid the literal word "checkout" in the commit message / PR body** (worktree-gate rule 3), and
   **omit the `Co-Authored-By` trailer** (the CLA bot fails on it).
4. Push → open/append the PR → confirm on **the PR's own run** that the job runs (the jobs are non-required,
   so a red one blocks nothing). Iterate on failures — that's the CI-verify loop.

## 5. After they're green — flip the rubric

> **UNACTIONABLE as written (2026-07-27).** `docs/Code_Quality_Standards.md` has never existed in this
> repo's git history, despite being cited by `quality-advisory.yml`'s header and `pyproject.toml`. There is
> no rubric file to flip. Leave the existing dangling citations alone and do not add new ones; if the rubric
> is ever written, redo this step then.

Update [Code_Quality_Standards.md](../Code_Quality_Standards.md) exactly as #10/#8 were flipped in v0.3:
signals 6 + 7 go from *deferred* → ✅ **Built (advisory)** in **§5** (status column), **Appendix A.2** (rows
6/7), **A.3**, and the **A.1** verdict. Bump the rubric **Version** + add a history row.

## 6. Update — how these signals now surface (2026-07-27)

All four advisory signals were wired to reach a reviewer without buying GitHub's paid Code Quality SKU
(GA 2026-07-20, $10 per active committer/month, a standalone product **not** bundled with GHAS). They use
**workflow-command annotations**, not code scanning — no token, no permission grant, and identical
behaviour on fork PRs. The workflow still holds **no write scope on any job**.

- **Diff-coverage** — `diff-cover --format "github-annotations:notice,markdown:diff-cover.md"` puts
  `::notice` annotations **inline on the Files changed tab**. Adjacent uncovered lines are coalesced into
  ranges, so a long uncovered block costs one annotation, not one per line.
- **Complexity** — a merge-base-vs-HEAD **delta** (`scripts/quality/c901_delta.py`). Raw `C901` is
  unshippable as a diff signal: all 122 findings on this tree anchor on a single `def` line, so body edits
  produce nothing and signature edits fire on pre-existing debt. The delta reports only what the PR caused.
- **Clones** — step summary only. jscpd emits one location per clone pair chosen by scan order.
- **Mutation** — **the signal is dead and was reporting success anyway.** Measured from the scheduled run
  `30248096425` (2026-07-27): the job takes **37 seconds** and goes green because `mutmut run || true`
  swallows a crash. mutmut 2.5.1 prints its banner, runs the baseline, then dies in its pony-ORM cache with
  `TypeError: cannot pickle 'itertools.count' object` (`cache.py:369 update_line_numbers`) — **before
  generating a single mutant**. The job now captures the exit status, emits a `::warning`, and says so in
  the summary rather than presenting a results block for a tool that produced none. The `.mutmut-cache`
  artifact still uploads (`include-hidden-files: true` — it is a dotfile and `upload-artifact` skips hidden
  files by default), but expect it to be a stale/empty cache until the tool works.

**The real blocker (supersedes the old "measure the wall-clock" step):** the PR-vs-nightly question cannot
be answered while the tool produces nothing — 37s is the cost of crashing, not of mutating. Fix mutmut
first (mutmut 3.x has a different CLI; cosmic-ray is the other candidate), *then* measure a real run, then
decide about PRs. Do not read the current duration as evidence that a PR run would be cheap.

---

*Drafted 2026-07-13 by the session that shipped the complexity + clone gates (#1028) but could not run a local
venv. If `mutmut` / `diff-cover` behave differently than drafted, trust the local run — these are a
verified-shape starting point, not an untested paste.*
