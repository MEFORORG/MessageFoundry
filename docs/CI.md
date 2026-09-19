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
| `security.yml` | Static and supply-chain security: `bandit` (Python SAST), `semgrep`, `pip-audit` and `npm-audit` against the hash-locked tree, `gitleaks` (secret scan), `forbidden-content` (customer/PHI leak guard), a crypto-inventory check, an SBOM build, and a `trivy` scan. A **daily cron** re-runs the dependency audits so a CVE filed against an unchanged pin is caught within ~24h. A separate `released-line-audit` job runs on the same cron and audits the **latest release tag's** pinned core runtime, which the daily audits do not cover — they read the checked-out tree, so between a fix landing on `main` and a release carrying it the two answers differ. Hard-failing but **not** a required check (schedule/dispatch only), the same posture as `dast.yml`. Two **composite** jobs, `repo-scan` and `dependency-and-secret-scan`, run the same seven scans in two runner slots instead of seven; they are staged alongside the originals, so during the overlap every scan runs twice. **Only the composite copy gates the merge, since 2026-09-16** -- this cell said *"both are now required ... both copies gate the merge"*, which was true for two days and then was not. `.github/required-contexts.txt` is the live answer; see *Consolidating the seven security contexts* below. |
| `codeql.yml` | GitHub CodeQL analysis (python / javascript-typescript). Advisory — **not** required checks. |
| `scorecard.yml` | OpenSSF Scorecard analysis. |
| `cla.yml` | CLA Assistant — records the Contributor License Agreement signature on each PR. |
| `zizmor.yml` | Lints the workflow files themselves for insecure patterns (template injection, over-broad tokens), and runs `actionlint` on the workflow syntax. Hard-fails, but **not a required check** — it is paths-filtered, so it does not report on a PR that touches no workflow, and requiring it would wedge every such PR. The `actionlint` pre-commit hook is the local half. |
| `dast.yml` | Authenticated authorization sweep against a live loopback listener in front of a real engine. **Not a required check** — nightly / release-tag / manual dispatch only, with no `pull_request` trigger, so it never reports on a PR and cannot wedge one. It is NOT `continue-on-error`: it goes red on a finding. See [ADR 0155](adr/0155-dast-dynamic-security-testing-of-the-running-engine.md). |
| `quality-advisory.yml` | Advisory quality measurement — complexity (ruff `C901`), duplication (`jscpd`), diff-coverage (`diff-cover`) and mutation testing (`mutmut`). **Every job is advisory and none is in branch protection.** See below for how each signal reaches a reviewer. |
| `asvs-prove-absences.yml` | Runs `scripts/asvs/scorecard.py --prove-absences`: applies each absence claim's stated reintroduction to a scratch tree and requires its named observable to go red. **Advisory and not in branch protection.** Two jobs. `selftest` runs on any PR touching the wiring, needs no credential, and is what stops the tool rotting in the repo that develops it. `prove` is **`workflow_dispatch` only** — the scheduled pass runs in the vault, the only repo holding the scorecard, per the 2026-08-09 location decision recorded in that workflow's own header block. A dispatch here still fails closed with exit 2 when no input is configured, because a run that scanned nothing must not report success; it is simply not *scheduled* to obtain nothing. `scripts/asvs/prove_report.py` ships here and `MIRRORED_TOOLS` in `tests/test_asvs_verifier_vault_contract.py` holds it to that list's **contract** — stdlib-only, so a vault copy would run on the bare interpreter there. That contract is in force *before* any mirror exists, deliberately, because the cheap moment to hold a tool to it is before it acquires a dependency. **Do not read that entry as evidence a vault copy exists: it does not.** The vault's mirror automation is scoped to `scorecard.py` alone, and `MIRRORED_TOOLS` asserts the stdlib property, never that a vault copy exists — so widening the vault's automation is the open half, tracked with the vault-side scheduled pass. |
| `asvs-anchor-report.yml` | Runs `scripts/asvs/anchor_report.py`: reads the ASVS scorecard and reports which **anchors** — citations from a graded requirement to a line of engine code — no longer resolve in this tree, narrowed to the files the triggering range touched. **Advisory and not in branch protection.** It **reports and never rewrites**: a citation that moved and one that was wrong when written need different human responses, so proposing a repair is what would manufacture silent corruption. Output is **counts and file paths only** — never a requirement identifier, because pairing those enumerates coverage over a closed set and hands out the gaps by subtraction, and this repository's run logs are public. Its one job is **skipped** unless `vars.ASVS_VAULT_REPO` is configured, which it is not: the record lives in the private vault and this repository holds no read credential for it (the boundary decision is recorded in `asvs-prove-absences.yml`). The half that runs today is the instrument: `tests/test_asvs_anchor_report.py`, in the `tooling` tier, proves the checker detects a stale anchor, fails closed on a record it could not read, and prints no identifier. |
| `net-helper.yml` | Publishes `mefor-net-helper.exe` (`net-helper/`), the privileged helper [ADR 0056](adr/0056-engine-managed-vip-failover.md) specifies. On `main` it signs the binary when the `net-helper-signing` environment holds the signing secret; without the secret the build still passes, unsigned. The workflow's header records the signing policy, and `net-helper/README.md` "Signing" has the environment setup. **Not a required check**: it is paths-filtered to the helper and its own workflow file, so it does not report on most PRs. |

Several heavier legs (server-DB store tests, load/throughput, service-smoke, DICOM/FHIR breadth) run
**nightly on a schedule** and/or only when a PR touches their paths, so an ordinary PR does not pay for
them. Because they do not run on every PR, they are **not** required to merge (a job that never reports
would otherwise wedge the PR — see the gotcha below).

## Checks required to merge

The stable contexts required on `main` are — mirroring
[`.github/required-contexts.txt`](../.github/required-contexts.txt), which is the file to edit:

- `CI gate`
- `test (ubuntu-latest, py3.14)`
- `test (windows-2022, py3.14)`
- `test (windows-2025, py3.14)`
- `repo-scan (bandit, semgrep, crypto-inventory, forbidden-content)`
- `dependency-and-secret-scan (pip-audit, npm-audit, gitleaks)`
- `a PR that implements BACKLOG #N must update BACKLOG.md`
- `cla`

`cla` is the **job key** in `cla.yml`, whose job declares no `name:`. Branch protection
matches the job name, never the workflow name — so the context is `cla`, not "CLA Assistant".

**Only the two composites carry `security.yml` into the required set, as of 2026-09-16.** This
paragraph used to read "Every non-advisory job in `security.yml` is in the set. Three are not, in two
different ways" — and that stopped being true when the owner removed the seven original scan contexts
from branch protection. **Ten** of the workflow's jobs are now out of the set, in **three** ways, and
`tests/test_security_posture.py` pins which bucket each job is in:

| Bucket | Jobs | Why it is out |
| --- | --- | --- |
| advisory by **design** | `sbom`, `trivy` | they declare `continue-on-error: true`, so a finding never reddens them |
| advisory by **placement** | `released-line-audit` | schedule/dispatch-only, so it can never report on a PR — it deliberately does **not** carry `continue-on-error` and still goes red on a finding (the `dast.yml` posture) |
| **superseded** | the seven original scan jobs | they hard-fail and they report on every PR; a required composite now runs the same scan, so the original no longer gates the merge. Deleted at step 3 below |

The **superseded** bucket is the new one and the easy one to misread: from inside `security.yml` those
seven jobs look exactly like required jobs. Nothing about the job changed — a setting outside the
repository did.

CodeQL is **advisory** (not in the required set) — its SARIF upload needs `security-events: write`,
which fork-PR tokens do not have, so requiring it would block PRs from forks. Both matrix contexts
were seen on branch protection earlier on 2026-08-31 and were off again by 20:57 CDT that day; the
rationale is unchanged, and `.github/required-contexts.txt` records it. Scorecard is advisory for
the same reason and additionally **does not run on PRs at all** (`scorecard.yml` has no `pull_request`
trigger — it runs on a weekly schedule, on branch-protection changes, and on demand). Nightly / path-gated
legs (service-smoke, load, SQL/Postgres store) are deliberately **not** required.

`a reviewer has read this` (`review-gate.yml`) was **retired by the owner on 2026-09-04**. The context
came off branch protection and the workflow was **deleted** in the same change, so nothing posts that
check any more and **a PR needs no `reviewed` label to land**. Read the live set from the server rather
than from any prose, here or elsewhere:

```powershell
gh api repos/MEFORORG/MessageFoundry/branches/main/protection --jq '.required_status_checks.contexts[]'
```

The same endpoint read the settings that decide a merge, on 2026-09-04:

```powershell
gh api repos/MEFORORG/MessageFoundry/branches/main/protection --jq '{n: (.required_status_checks.contexts|length), strict: .required_status_checks.strict, enforce_admins: .enforce_admins.enabled, approvals: .required_pull_request_reviews.required_approving_review_count}'
```

It returned `{"approvals":0,"enforce_admins":true,"n":13,"strict":true}`. `strict` and `enforce_admins`
did not move; the review context is simply not among what is required.

**Read what that leaves, because the two halves were always separate.** `required_approving_review_count`
is 0 and stays 0 -- every session pushes as one GitHub identity, so a human-approval rule would wedge
every PR rather than review any. With the label context retired as well, **no automated control now
requires that any change be read before it merges.** That is a deliberate owner decision, recorded here
rather than inferred; it is not a gap to be quietly closed by re-arming the context. Re-arming it is an
owner decision too.

Worth keeping in view if it is ever reconsidered: the label is applied by hand, commonly by the PR's own
author, so the check proved a **step happened**, not that an independent party looked. Two further
findings the gate produced outlive it, because neither was about that one workflow. It failed **stale
rather than closed**, and `strict: true` is what stopped the one measured case merging (BACKLOG #1417).
The mechanism is not specific to that workflow, so it is written up once under *Gotchas*, in the bullet
on reading `github.event.*`. And **nothing ever told a reviewer a pull request was waiting**, measured as
zero hits for each of `requested_reviewers`, `review_requested`, `pull_request_review`, `--reviewer`
and `gh pr review` across the workflow directory, against a `runs-on` positive control that hit every
file (BACKLOG #1413).

**The `reviewed` label still exists, and nothing reads it any more.** With `review-gate.yml` gone,
nothing adds or removes the label -- labels already sitting on open PRs are inert leftovers, and the
`synchronize` strip is gone with the workflow that did it. `unread-signal.yml` and
`scripts/ci/check_unread_prs.py` were the last readers: they commented on and labelled an
otherwise-mergeable PR that carried no `reviewed` label, so **that signal reported against a standard
nothing enforces**. The owner ruled it off on 2026-09-08, the workflow was disabled on the server that
day, and both files were deleted on 2026-09-13 (BACKLOG #1490).

### Consolidating the seven security contexts

`security.yml` owns **two** of the eight required contexts — the two composites, since 2026-09-16.
It owned **nine** of fifteen for two days before that, the seven original scan jobs included; the seven
still exist and still run, and are simply no longer required. Each scan job is a separate job that
acquires a separate runner slot. Five of the seven finish inside **55 seconds**, so seven
acquisitions buy about four minutes of scanning. A slot is the scarce resource here: peak concurrency
measured **exactly 20**, the free-plan ceiling for an organisation, and healthy pull requests have
been evicted from the merge queue for want of a runner. Measured over one week to 2026-09-13, this
workflow spent about **8,211 slot-starts** for about **4,770 execution-minutes**.

Two composite jobs now run those seven scans in two slots, worth roughly 4,700 to 5,900 slot-starts a
week at no coverage cost -- the same scanners, the same arguments, the same findings. **None of that
saving is realised yet**: the composites run beside the originals, so the overlap costs two extra slots
a run and pays only at step 3 below. The two are:

| Composite job | Consolidates |
| --- | --- |
| `repo-scan (bandit, semgrep, crypto-inventory, forbidden-content)` | the four scans of the checked-out tree, which share one Python setup |
| `dependency-and-secret-scan (pip-audit, npm-audit, gitleaks)` | the dependency audits and the secret scan, which share a full-history checkout |

**A required context is a job NAME, so this lands in four steps and the first three are done — but not
in the order first written.** Deleting the seven jobs while branch protection still names them wedges
every pull request in the repository: protection waits forever for a context nothing produces. Moving
protection first, to names nothing yet reports, wedges it identically -- that is the required-but-absent
trap below, and on 2026-07-30 ten required contexts sat on disabled workflows that still carried their
files and job names.

1. **Done.** The composites run **alongside** the seven. Both sets report; nothing was deleted.
2. **Done** (some time between 2026-09-13 22:41Z and 2026-09-14 06:59Z). The owner added the two
   composite names to branch protection, taking the required set from thirteen to fifteen.
   `.github/required-contexts.txt`, this page and `tests/test_security_posture.py` were synced to
   match on 2026-09-15 -- a day late, which is the finding recorded at the end of this section.
4. **Done, and taken BEFORE step 3** (about 2026-09-16 18:45Z). The owner removed the seven original
   **names** from branch protection, taking the required set from fifteen to **eight**. This page,
   `.github/required-contexts.txt`, `tests/test_required_contexts.py`'s count pin,
   `tests/test_security_posture.py`'s classification and `tests/negative_controls.toml` were synced to
   match on 2026-09-17 -- about six hours late, which is the same lag as step 2 in the other direction.
3. **Still to do, and it no longer needs the owner.** A later PR deletes the seven original **jobs**
   from `security.yml`. Nothing requires those contexts now, so the deletion can no longer wedge a
   pull request and needs no protection edit beside it. That PR also retires the
   `_SUPERSEDED_SECURITY_JOBS` bucket in `tests/test_security_posture.py` and the provenance notes on
   the nine re-pointed entries in `tests/negative_controls.toml`.

**The step order was inverted on purpose, and the asymmetry is why.** This section used to warn that
steps 3-then-4 "open the required-but-absent trap between them", a defect in the plan rather than a
subtlety of it: once the seven jobs are deleted, protection still names seven contexts nothing can
report, and every pull request is wedged until step 4 lands. Taking 4 first costs a window of the
opposite kind -- the seven jobs run, burn seven runner slots and gate nothing -- which is wasted
compute and a misleading checks tab, recoverable by one pull request. The other window is a wedged
repository recoverable only by the owner. **Prefer this order next time.** The advice the section
previously gave (get both in one window, or invert the pair) was right; the inversion is the half that
was taken.

Through step 2 the workflow carried two copies of every scan and **both copies were required**, so a
finding blocked the merge twice over. Since step 4 both copies still **run** and only the composite is
**required**, so the runner-slot saving is still unrealised while the merge-gating consolidation is
already complete. `tests/test_security_composite_parity.py` asserts each copied body is
**byte-identical** to its original, which is what makes the consolidation safe to review: every control
this repository already asserts about an original step is an assertion about a string the copy shares,
so step 3 is a deletion rather than a rewrite -- and it is what licenses the nine negative controls
written about an original scan to be re-pointed at the composite that now gates it.

#### Step 2 landed on the server and nothing in the repository noticed for a day

Recorded because the gap, not the two missing lines, is the durable finding. From step 2 until
2026-09-15 branch protection required fifteen contexts while `.github/required-contexts.txt` named
thirteen, and the two it omitted were the two its own header described as deliberately absent and
blocking nothing. So the checked-in claim asserted the **opposite** of the server, in the direction that
reads as reassuring: a context this file does not name looks advisory.

Two things follow, and the second is the one worth keeping.

`tests/test_required_contexts.py` stayed green throughout. Every assertion in it compares in-repo text
to in-repo text -- the file against this page, against the workflow job names, against a pinned count --
so the whole suite agreed with itself while the server moved underneath it. Its own comments predicted
this; the pin's caution that it "goes stale in the direction that looks fine" was written after the same
thing happened on 2026-09-04.

`scripts/ci/check_required_contexts_drift.py` **did** catch it, on the first cron after the change, and
reported to nobody. It reads the live API; `required-workflow-state.yml`'s `accurate` job runs it on a
07:00 UTC cron, on `workflow_dispatch`, and on a pull request that touches
`.github/required-contexts.txt` or `.github/workflows/**`; and that workflow is **not a required
context** -- so it failed every run in the window and no merge, label or notice surfaced the failure.
The detector that exists for exactly this defect found it immediately and could not tell anyone. Two
sessions counting passing checks against the file read a pull request as fully green with two required
contexts unreported; one escaped only because it counted against branch protection instead.

**"Reported to nobody" is an alerting gap, not a missing detector**, and the distinction is worth the
sentence because a reader who concludes the checker is unwired goes on to build a second one. The
wiring is real and `tests/test_required_contexts_drift.py` now pins it -- one arm asserts a workflow
invokes the script, another asserts the job invoking it is **not** a required context, so neither the
wiring nor its advisory posture can be dropped silently. What is still missing is a consumer for the
cron's red: `failure-signal.yml` watches CI, Security and backlog-hygiene, not this workflow. Giving it
one is an alerting design over shared CI and is deliberately not folded in here.

#### Step 4 landed on the server and the repository was six hours behind

The same gap, in the opposite direction, on 2026-09-16. Protection went from fifteen contexts to eight
at about 18:45Z and nothing in the repository moved until 2026-09-17, so for about six hours the file
**over**-claimed: it named seven security contexts as blocking when nothing required them.

**Over-claiming is the less dangerous error and it is still an error.** A reader who believes a gate is
blocking treats their change as more constrained than it is, which fails safe. But the seven were not
idle -- they still run on every pull request and still go red on a finding -- so this is the first drift
in which *"does this check block a merge?"* and *"does this check report?"* had different answers. A
session reading a red `bandit (Python SAST)` on its pull request would have concluded, from the file,
that the merge was blocked. It was not; `repo-scan` carries bandit now.

That is why the seven are recorded as **superseded** rather than quietly deleted from every list: the
posture is real, it lasts until step 3, and it is invisible from inside `security.yml`.

### "What was required when this merged" is not answerable

GitHub exposes **no history for branch-protection settings**. The endpoint above reads the present set,
and nothing reads a past one. So for a pull request that has already merged, the set of checks required
at the moment it merged cannot be recovered from the API.
[`.github/required-contexts.txt`](../.github/required-contexts.txt) exists because the live set is
unreadable from a clone, and it records only the present as well. It is a mirror, not a log.

**Treat that as a known limit of this repository's own auditability**, written down here so nobody hunts
for a log that was never kept. It has already cost one answer: PR 712 merged on 2026-08-31 with the
review verdict red and no `reviewed` label, and the likeliest reading -- that the context was not
required yet at that instant -- can be neither proved nor disproved (BACKLOG #1417 records it as
unresolved rather than explained away). The 2026-09-04 retirement added a second undated transition to
the same gap. Closing the gap would mean recording each change to the required set with its date, which
nothing does today.

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
| Mutation (`mutmut`) | A **killed / survived / not-covered** table in the step summary, with the surviving mutants listed — those are injected bugs the tests did not catch. **Off pull requests** — it runs on the nightly cron and on dispatch, alongside `jscpd`, because an advisory job holds a runner slot the merge queue wants whatever its runtime. Measured at **461 mutants in 3 seconds** (87 killed, 19 survived) over the bounded scope, because mutmut 3 only runs the tests that cover each mutant. Repaired 2026-07-27 — `mutmut<3` resolved to 2.5.1, which crashes on Python 3.14 before generating a single mutant and, thanks to `\|\| true`, had been reporting success in 37s while measuring nothing. |

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

### Baseline for a path-gated leg

A path-gated leg (`postgres store`, `sql server`, `load test`, `windows service smoke`,
`docker image smoke`) runs only when its paths change, so it is thinly sampled and a red one has
no recent green to judge it against. The nightly already provides that baseline, and nothing here
said so:

```
gh run list --repo MEFORORG/MessageFoundry --workflow=ci.yml --event=schedule --limit 7
```

A **green nightly run** means every gated leg was green on `main` that night, because `CI gate`
`needs:` them all -- one run conclusion answers it, with no per-job walk.

Two limits, stated so nobody reads more into a green than it carries:

- **`tooling` is not in the nightly.** The schedule arm sets `tooling=false`, so `repo harness
  tests` has no nightly baseline. Its baseline is the push arm: `--event=push`, then read the
  failing job names.
- **One issue per workflow masks siblings.** `nightly-notice.yml` opens a single issue naming the
  run, not the leg, so a chronically red leg hides the state of every other leg beside it.

## Gotchas

- **`actionlint` runs on every workflow edit — let it.** GitHub interpolates `${{ }}` expressions
  *anywhere* in a `run:` script — comments included — before the shell sees it, so a stray/invalid
  expression aborts workflow compilation: **no jobs are created**, the run is attributed to a phantom
  event, and required contexts silently never appear (the PR just looks stuck). `zizmor` does not catch
  this; `actionlint` does. This used to be an instruction aimed at human memory, which is the wrong
  mechanism for a failure whose symptom is "the PR is stuck" and whose tempting remedy is relaxing
  branch protection. It is now a **pre-commit hook** scoped to `.github/workflows/**`, plus a step in
  `zizmor.yml` (which is already paths-filtered). The hook is the load-bearing half —
  `zizmor.yml` is not a required check.
- **A step's wall-clock cap is now checked against the step, and a low margin reds the leg.** Each
  gated step in `test` carries its own `timeout-minutes`, and `scripts/ci/step_margin.py` runs after
  them: it times the **step** (not the job — the job runs minutes longer under its own cap, and
  misreading one for the other has produced published-then-retracted numbers here more than once),
  keys on that step's **own** `outcome`, and reds below 1.30x. It prints the elapsed, the
  percent-of-cap and its own red/green control pair into the job summary. A **skipped** step (a
  docs-only PR) reports `NO OBSERVATION` in words rather than a healthy-looking ratio. Recorded
  per-leg maxima — with their pool, their date, and whether they are right-censored — live in
  `scripts/ci/step_margin_baseline.toml`; a capped step with no row there fails the check closed.
  **A red here is not a request to raise the cap:** the cap is sized against the work in `ci.yml`,
  and the underlying Windows slowness is its own backlog item.
- **Pass matrix/expression values through `env:`, don't inline them in `run:`.** A dynamic
  `matrix: ${{ fromJSON(...) }}` defeats zizmor's static analysis, which then flags its expansion inside
  `run:` as template injection. The fix is to route the value through `env:` — the remedy endorsed in
  `.github/zizmor.yml` — not to suppress the rule. The same applies to any secret used in a `run:` step:
  write it to a file via an intermediate `env:` var rather than inlining `${{ secrets.* }}`.
- **A workflow reading `github.event.*` is reading a snapshot; branch protection is not.** The webhook
  payload freezes when the event fires. Branch protection then picks the newest check-run by
  **execution** time. Those are two different clocks, so a queued run reports the state from its own
  creation moment, however long ago that was. Measured on PR 724 on 2026-09-01: a run created at
  13:24:22Z executed at 13:43:46Z against its stale payload, reported SUCCESS, and overwrote the correct
  FAILURE from a run created earlier. The pull request then carried a green review context with no
  `reviewed` label for ten minutes. **Read the state live inside the job** (`gh pr view --json labels` at
  run time), or make the verdict invalidate itself when its payload is older than what it claims to have
  read. One near-miss is worth naming, because two sessions adopted it before it was refuted: reading the
  check **context** instead of the label does not help, because the context inherits the same staleness
  through the same snapshot. The gate that produced this is retired, so it is a constraint on the next
  control rather than a defect in a live one (BACKLOG #1417).
- **Every `gh api` list route defaults to `per_page=30`, so it will answer confidently about a population
  it cannot see.** Measured on two routes: check-runs returned 30 where the heads carried 39 to 48, and
  `issues/<n>/timeline` returned 30 and hid a label re-application two hours past the cut, which sent its
  reader to the wrong conclusion. A truncated list looks exactly like a short one, and nothing in the
  reply says it was cut. Use `--paginate`, and when a count decides something, reconcile it against a
  paginated count. `per_page=100` covered the largest population seen and is not a permanent guarantee;
  `scripts/ci/report_ci_red.py` uses it with that caveat written beside the call (BACKLOG #1417).
- **The advisory `dast.yml` scan has a merge-blocking half, and it lives somewhere else.**
  `tests/test_dast_auth_sweep.py` runs inside the existing required `test` legs and drives the *same*
  shipped sweep, proving its two canaries still detect an injected defect. So a change that **blinds the
  detector** reds a PR even though the nightly scan itself is advisory: the probe's *ability to fail*
  gates the merge, the probe *run* does not. `dast.yml` has no `pull_request` arm, so it never reports on
  a PR — and `nightly-notice.yml` watches only `ci.yml`, so a red DAST nightly surfaces in the Actions
  tab rather than as an issue. See [ADR 0155](adr/0155-dast-dynamic-security-testing-of-the-running-engine.md).
- **A SQL-Server test leg can die with a native segfault** (exit 139, in the DB driver). It hits `main`
  too — it is not a regression in your PR. Clear it with `gh run rerun <run-id> --failed`.
- **`prod` is a fail-closed PHI environment.** `serve --env prod` refuses to start without a store
  encryption key, without an egress allow-list, and without bounded retention windows
  (`[retention].messages_days` **and** `dead_letter_days` must be `> 0`). Any prod-like CI job must
  supply all three or the service crash-loops and never serves `/health`.
- **Git-Bash mangles `git show <ref>:<path>`** (the colon). Use
  `MSYS_NO_PATHCONV=1 git show "origin/main:.github/workflows/ci.yml"`.
- **An instrument that does not record WHICH TREE answered can be self-consistently wrong.** Two
  directories can supply `messagefoundry/` to one interpreter, it picks between them silently, and a
  review packet was once measured against the wrong one with no signal at all. Why that happens is
  stated once, on `_VersionAction` in [`messagefoundry/__main__.py`](../messagefoundry/__main__.py);
  what to do about it is here. **`messagefoundry --version` prints the resolved package directory on
  its own second line (BACKLOG #1677) — record that line whenever a measurement will be quoted.**
  - **`PYTHONSAFEPATH=1` is not the fix, and is deliberately NOT set across these workflows.** It
    drops the working directory from `sys.path`, which removes *one* of the two candidates and lets
    the venv's editable `.pth` target win unconditionally — and on a multi-worktree box that target
    can be a third checkout, unrelated to both the working directory and the repository you think you
    are testing. It does not answer "which tree"; it changes which wrong answer you get silently. It
    would also change nothing here, because every leg installs editable from its own checkout, so the
    two candidates already agree. Print the path and read it.
