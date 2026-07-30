# CI overview

**Audience:** contributors and maintainers working on MessageFoundry. This page describes what
Continuous Integration runs on a pull request, which checks must pass before a change can merge, and a
few gotchas that have cost real debugging time.

Branch protection on `main` is the **server-side** source of truth for which checks are *required*.
Because that is unreadable from a clone, the set is mirrored in
[`.github/required-contexts.txt`](../.github/required-contexts.txt) — the checked-in claim that this
page and every other in-repo statement must agree with, asserted by `tests/test_required_contexts.py`.
Prose lists are what drift: this page understated the required set by four blocking security gates and
named the CLA context by the wrong string. Edit the canonical file, and let the test tell you which
claims move with it.

## Workflows

| Workflow | What it does |
|---|---|
| `ci.yml` | Lint (`ruff check` + `ruff format --check`), types (`mypy --strict`, plus a `--platform win32` pass on Linux so Windows type-branches are checked), and the `pytest` suite across **ubuntu-latest**, **windows-2022**, and **windows-2025** (Python 3.14). Also builds the VS Code extension (`ide/`). A `CI gate` job rolls the legs up. |
| `security.yml` | Static and supply-chain security: `bandit` (Python SAST), `semgrep`, `pip-audit` and `npm-audit` against the hash-locked tree, `gitleaks` (secret scan), `forbidden-content` (customer/PHI leak guard), a crypto-inventory check, an SBOM build, and a `trivy` scan. A **daily cron** re-runs the dependency audits so a CVE filed against an unchanged pin is caught within ~24h. |
| `codeql.yml` | GitHub CodeQL analysis (python / javascript-typescript). |
| `scorecard.yml` | OpenSSF Scorecard analysis. |
| `cla.yml` | CLA Assistant — records the Contributor License Agreement signature on each PR. |
| `zizmor.yml` | Lints the workflow files themselves for insecure patterns (template injection, over-broad tokens), and runs `actionlint` on the workflow syntax. Hard-fails, but **not a required check** — it is paths-filtered to `.github/**`, so it does not report on a PR that touches no workflow, and requiring it would wedge every such PR. The `actionlint` pre-commit hook is the local half. |
| `quality-advisory.yml` | Advisory quality measurement — complexity (ruff `C901`), duplication (`jscpd`), diff-coverage (`diff-cover`) and mutation testing (`mutmut`). **Every job is advisory and none is in branch protection.** See below for how each signal reaches a reviewer. |

Several heavier legs (server-DB store tests, load/throughput, service-smoke, DICOM/FHIR breadth) run
**nightly on a schedule** and/or only when a PR touches their paths, so an ordinary PR does not pay for
them. Because they do not run on every PR, they are **not** required to merge (a job that never reports
would otherwise wedge the PR — see the gotcha below).

## Checks required to merge

The stable contexts required on `main` are — mirroring
[`.github/required-contexts.txt`](../.github/required-contexts.txt), which is the file to edit:

- `test (ubuntu-latest, py3.14)`
- `test (windows-2022, py3.14)`
- `test (windows-2025, py3.14)`
- `bandit (Python SAST)`
- `pip-audit (dependency vulnerabilities)`
- `npm-audit (ide dependency vulnerabilities)`
- `gitleaks (secret scan)`
- `semgrep (project SAST rules)`
- `crypto-inventory (ASVS 11.1.3 discovery gate)`
- `forbidden-content (customer/PHI leak guard)`
- `a PR that implements BACKLOG #N must update BACKLOG.md`
- `cla`

That last string is the **job key** in `cla.yml`, whose job declares no `name:`. Branch protection
matches the job name, never the workflow name — so the context is `cla`, not "CLA Assistant". Every
non-advisory job in `security.yml` is in the set; the two that are not (`sbom`, `trivy`) declare
`continue-on-error: true`, and `tests/test_security_posture.py` pins which side of that line each one
is on.

CodeQL is **advisory** (not in the required set) — its SARIF upload needs `security-events: write`,
which fork-PR tokens do not have, so requiring it would block PRs from forks. Scorecard is advisory for
the same reason and additionally **does not run on PRs at all** (`scorecard.yml` has no `pull_request`
trigger — it runs on push-to-main, a schedule, and branch-protection changes). Nightly / path-gated
legs (service-smoke, load, SQL/Postgres store) are deliberately **not** required.

The `quality-advisory.yml` jobs create **no code-scanning category** and **no _required_ check context** —
they do report as ordinary advisory checks, and they **must never be added to the required list**. Two
things keep them advisory: they are absent from branch protection, and every analysis step is
`continue-on-error: true` plus `--exit-zero` / `--fail-under=0` / `|| true`, so the job reports success
whatever it finds. (The workflow also holds **no write permission on any job** — that is least privilege,
worth having because two of these jobs run third-party code fetched at run time, but it is *not* what
determines merge gating; required-checks membership is.)
`tests/test_quality_advisory_invariants.py` fails if a write scope, a SARIF upload, or a removed
`--exit-zero` ever lands there.

### How the advisory quality signals reach a reviewer

These use GitHub **workflow-command annotations** (`::notice` / `::warning` on stdout) rather than code
scanning. That needs no token and no permission grant, and behaves identically on fork PRs. The
reasoning — including why SARIF was measured and rejected — is recorded in the workflow's header comment.

An annotation renders **inline on Files changed only when its line is in the diff**. That is always true
for diff-coverage and usually *not* true for complexity, so the two land in different places:

| Signal | Where it shows up |
|---|---|
| Diff-coverage | **Inline on the Files changed tab**, one `::notice` per contiguous uncovered range of lines the PR changed, plus a step summary. Every line it flags is a line the PR touched, so this is the one signal that is reliably inline. |
| Complexity (`C901`) | A **merge-base-vs-HEAD delta** — only functions this PR introduced over the threshold or made more complex. Findings anchor on the `def` line, which a body-only edit does not touch, so **most complexity annotations appear in the Checks tab and the step summary rather than inline**. The summary table is this signal's primary surface. Pre-existing findings are never reported; the full list stays in the job log. |
| Duplication (`jscpd`) | Step summary only. jscpd emits one location per clone pair chosen by scan order, so annotating it would anchor on the untouched twin about half the time. |
| **Gate liveness** | A pass/fail table proving each gate above actually *measured* something. See below — this is the only job in that workflow that can go red. |
| Mutation (`mutmut`) | A **killed / survived / not-covered** table in the step summary, with the surviving mutants listed — those are injected bugs the tests did not catch. Runs on PRs too: measured at **461 mutants in 3 seconds** (87 killed, 19 survived) over the bounded scope, because mutmut 3 only runs the tests that cover each mutant. Repaired 2026-07-27 — `mutmut<3` resolved to 2.5.1, which crashes on Python 3.14 before generating a single mutant and, thanks to `\|\| true`, had been reporting success in 37s while measuring nothing. |

### Gate liveness — the check that watches the checks

Three defects across two of `quality-advisory.yml`'s gates spent months green. Two were gates
**measuring nothing** — diff-coverage (a shallow fetch destroyed its merge base, and the resulting
empty report looked clean) and mutation (the tool crashed before producing a single mutant, and
`|| true` made that green in 37 seconds). The third was the close cousin: a gate that measured
correctly and **published a wrong number** — a `grep` for a line the tool never prints, so a healthy
461-mutant run reported "Killed 0".

The rubric's anti-metric rule guards against trusting a *number* too much. Nothing guarded against
trusting a *green check that never ran*. The `liveness` job is that control.

Each measurement job emits a small **receipt** recording what it examined; the `liveness` job reads
them all and demands either proof of execution or an explicit, reasoned "nothing to measure".

- **Liveness is not "the gate found something."** A clean repo legitimately has zero clones. Receipts
  count units **examined** — files scanned, mutants processed, changed lines analysed — which is
  non-zero whenever the tool ran, whatever it concluded. A check that fires on good news gets muted.
- **"Nothing to measure" passes — if it says why.** `no lines with coverage information in this diff`
  is a real, correct outcome. A silent empty report is not. The two look identical on screen; the
  reason is the difference.
- **Numbers must reconcile, against an independent source.** Two checks, because the obvious one is
  weaker than it looks. `killed + survived + no-tests + other` must equal the mutants processed — but
  since `killed` is *derived* as total-minus-listed, that sum reduces algebraically to
  "every listed mutant carries a recognised status" and never validates `killed` at all. So `killed`
  is additionally reconciled against **mutmut's own counter**, parsed from its progress line: two
  independent derivations that must agree. That second check is what would catch a recurrence of the
  `killed=0` bug; the sum alone would not. `tests/test_gate_liveness.py` asserts both, including an
  explicit test documenting the sum's blindness rather than hiding it.
- **It is the one job there allowed to go red**, deliberately: it has no `continue-on-error` and no
  `|| true`. A red mark still blocks nothing — it is not, and must never become, a required context.

`tests/test_gate_liveness.py` replays all three historical incidents and asserts each is caught, and
asserts the good-news cases pass. A liveness gate that cannot catch the failures it was built for
would be exactly the thing it exists to prevent.

### The `CI gate` roll-up

`CI gate` `needs:` the individual legs, runs with `if: always()`, and fails **only** on a `failure` or
`cancelled` leg. A **`skipped`** leg counts as a **pass** — that is what lets a path-gated leg stay off
an unrelated PR without turning the gate red.

> ### The required-but-absent trap
> A **required** status check that never reports **blocks every PR forever**. So before you stop a job
> from running on PRs (path-gate it, or make it schedule-only), make sure it is **not** in the required
> list first. Add a job to the required list only once you have seen it report on a real PR.

## Gotchas

- **`actionlint` runs on every workflow edit — let it.** GitHub interpolates `${{ }}` expressions
  *anywhere* in a `run:` script — comments included — before the shell sees it, so a stray/invalid
  expression aborts workflow compilation: **no jobs are created**, the run is attributed to a phantom
  event, and required contexts silently never appear (the PR just looks stuck). `zizmor` does not catch
  this; `actionlint` does. This used to be an instruction aimed at human memory, which is the wrong
  mechanism for a failure whose symptom is "the PR is stuck" and whose tempting remedy is relaxing
  branch protection. It is now a **pre-commit hook** scoped to `.github/workflows/**`, plus a step in
  `zizmor.yml` (which is already paths-filtered to `.github/**`). The hook is the load-bearing half —
  `zizmor.yml` is not a required check.
- **Pass matrix/expression values through `env:`, don't inline them in `run:`.** A dynamic
  `matrix: ${{ fromJSON(...) }}` defeats zizmor's static analysis, which then flags its expansion inside
  `run:` as template injection. The fix is to route the value through `env:` — the remedy endorsed in
  `.github/zizmor.yml` — not to suppress the rule. The same applies to any secret used in a `run:` step:
  write it to a file via an intermediate `env:` var rather than inlining `${{ secrets.* }}`.
- **A SQL-Server test leg can die with a native segfault** (exit 139, in the DB driver). It hits `main`
  too — it is not a regression in your PR. Clear it with `gh run rerun <run-id> --failed`.
- **`prod` is a fail-closed PHI environment.** `serve --env prod` refuses to start without a store
  encryption key, without an egress allow-list, and without bounded retention windows
  (`[retention].messages_days` **and** `dead_letter_days` must be `> 0`). Any prod-like CI job must
  supply all three or the service crash-loops and never serves `/health`.
- **Git-Bash mangles `git show <ref>:<path>`** (the colon). Use
  `MSYS_NO_PATHCONV=1 git show "origin/main:.github/workflows/ci.yml"`.
