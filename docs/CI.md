# CI overview

**Audience:** contributors and maintainers working on MessageFoundry. This page describes what
Continuous Integration runs on a pull request, which checks must pass before a change can merge, and a
few gotchas that have cost real debugging time. Branch protection on `main` is the source of truth for
which checks are *required* — this page describes the intended layout.

## Workflows

| Workflow | What it does |
|---|---|
| `ci.yml` | Lint (`ruff check` + `ruff format --check`), types (`mypy --strict`, plus a `--platform win32` pass on Linux so Windows type-branches are checked), and the `pytest` suite across **ubuntu-latest**, **windows-2022**, and **windows-2025** (Python 3.14). Also builds the VS Code extension (`ide/`). A `CI gate` job rolls the legs up. |
| `security.yml` | Static and supply-chain security: `bandit` (Python SAST), `semgrep`, `pip-audit` and `npm-audit` against the hash-locked tree, `gitleaks` (secret scan), `forbidden-content` (customer/PHI leak guard), a crypto-inventory check, an SBOM build, and a `trivy` scan. A **daily cron** re-runs the dependency audits so a CVE filed against an unchanged pin is caught within ~24h. |
| `codeql.yml` | GitHub CodeQL analysis (python / javascript-typescript). |
| `scorecard.yml` | OpenSSF Scorecard analysis. |
| `cla.yml` | CLA Assistant — records the Contributor License Agreement signature on each PR. |
| `zizmor.yml` | Lints the workflow files themselves for insecure patterns (template injection, over-broad tokens). **Blocking.** |

Several heavier legs (server-DB store tests, load/throughput, service-smoke, DICOM/FHIR breadth) run
**nightly on a schedule** and/or only when a PR touches their paths, so an ordinary PR does not pay for
them. Because they do not run on every PR, they are **not** required to merge (a job that never reports
would otherwise wedge the PR — see the gotcha below).

## Checks required to merge

The stable contexts required on `main` are:

- `CI gate`
- `test (ubuntu-latest, py3.14)`
- `test (windows-2022, py3.14)`
- `test (windows-2025, py3.14)`
- `bandit (Python SAST)`
- `pip-audit (dependency vulnerabilities)`
- `forbidden-content (customer/PHI leak guard)`
- `CLA Assistant`

CodeQL and Scorecard run on PRs but are **advisory** (not in the required set) — their SARIF upload needs
`security-events: write`, which fork-PR tokens do not have, so requiring them would block PRs from forks.
Nightly / path-gated legs (service-smoke, load, SQL/Postgres store) are deliberately **not** required.

### The `CI gate` roll-up

`CI gate` `needs:` the individual legs, runs with `if: always()`, and fails **only** on a `failure` or
`cancelled` leg. A **`skipped`** leg counts as a **pass** — that is what lets a path-gated leg stay off
an unrelated PR without turning the gate red.

> ### The required-but-absent trap
> A **required** status check that never reports **blocks every PR forever**. So before you stop a job
> from running on PRs (path-gate it, or make it schedule-only), make sure it is **not** in the required
> list first. Add a job to the required list only once you have seen it report on a real PR.

## Gotchas

- **Run `actionlint` on every `ci.yml` edit.** GitHub interpolates `${{ }}` expressions *anywhere* in a
  `run:` script — comments included — before the shell sees it, so a stray/invalid expression aborts
  workflow compilation: **no jobs are created**, the run is attributed to a phantom event, and required
  contexts silently never appear (the PR just looks stuck). `zizmor` does not catch this; `actionlint`
  does.
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
