# CI failure log

A running record of individual CI failures, one row per observation, kept so that trends become
visible and recurring causes get fixed once instead of re-diagnosed every time.

**This is a log, not a dashboard.** It records what somebody actually observed and what it turned
out to be. It is not generated, it is not complete, and it does not try to be. See
[Scope and honesty](#scope-and-honesty).

For what CI runs and which contexts gate a merge, see [CI.md](CI.md). This file is only about
failures.

---

## Why the verdict column is the point

A row saying "test X failed on PR Y" is noise. The question a reader actually has is **whose fault
was it**, and if not the pull request's, **what class of thing was it**. That is the `verdict`
column, and it is the only column worth arguing about.

Everything else on a row is transcription. The verdict is a judgement, so it carries a vocabulary
with fixed meanings rather than free text -- an undefined category is how two readers reach opposite
conclusions from the same row and neither notices.

### Verdict vocabulary

| Verdict | Means | The fix belongs to |
|---|---|---|
| `pr-defect` | The change genuinely broke this. CI is correct. | The PR's author |
| `pr-ordering` | The change is correct but depends on something not yet on `main`. | Nobody; it waits |
| `flake` | Same head, different result, with no change in between. | Whoever owns the test |
| `infra` | Runner, network, capacity, timeout. Nothing to do with the code. | Nobody, unless it recurs |
| `gate-artifact` | A rule or config change made this red, not the code. | Whoever changed the rule |
| `instrument` | The failure is in how the result was READ, not in CI. | The reader |
| `advisory-noise` | Not a required context, fails routinely, blocks nothing. | Retire it or fix it |

**`instrument` is deliberately in the list.** Several entries below are cases where CI was working
and a person misread it. Those are worth logging precisely because they are invisible otherwise: a
misread produces a confident wrong conclusion and no artifact at all.

---

## How to add a row

1. Put the newest row at the **top** of the table.
2. Fill `verdict` from the vocabulary above. If none fits, add one here first with its meaning.
3. Put the **specific** symptom in `symptom` -- a test name or an error string, not "tests failed".
4. If you have not established the cause, write `unestablished` in `cause`. **Do not guess.** A
   wrong cause in this file is worse than a blank one, because the next reader will build on it.
5. Times are US Central, matching the rest of this project's operator-facing records.

If a row's cause is later found to be wrong, **correct it in place and say so on the row** rather
than adding a second row. A log that carries both a wrong answer and a right one, without saying
which is which, is worse than either alone.

---

## The log

| Date (CT) | PR | Context | Symptom | Verdict | Cause and resolution |
|---|---|---|---|---|---|
| 2026-08-26 19:20 | all | the merge queue itself | PR 619 sat `AWAITING_CHECKS` 40 min with `main` unmoved; **32 check-runs green on the queue branch, 0 failing, 0 pending** | `gate-artifact` | The three `CodeQL` contexts were made required, and `codeql.yml` has **no `merge_group` trigger** -- PR 616 added one to `ci.yml`, `backlog-hygiene.yml`, `cla.yml`, `security.yml` and not to codeql. A merge_group event cannot start it, so those contexts can never report on a queue branch and **every entry waits forever**. `security.yml`'s own `on:` block predicted this verbatim in the PR that added the other four. Fix: PR 629. |
| 2026-08-26 19:12 | 625 | `test (ubuntu-latest / windows-2022 / windows-2025)` | my sweep reported all three as FAILING | `instrument` | **They were pending, not failing.** My classifier's `case` had no arm for an empty conclusion, so `""` fell through to the failure branch. `gh run list --branch` showed `CI` still `in_progress`. Same absent-versus-queued ambiguity as the 613 row below, in a tool I wrote after logging that one. |
| 2026-08-26 18:40 | 623 | `test (windows-2025, py3.14)` | `empty_claims_monotonic: fixed_per_conn@N=24: 25 < prior 44.5 * 0.75` | `flake` | Short by **8.375** against prior recorded excursions of 1.400, 1.250 and 0.300 -- six times worse than any before it. The PR touches zero connscale files. **The branch predated #1211 limb one, so it ran the version that RECORDS NOTHING**: `render_readings_markdown` present 0 times at its head, 3 on main. A re-run would have produced a fifth bare verdict; merging main in produced the first instrumented sample. |
| 2026-08-26 17:41 | 613 | 15 of 16 required | all reported `ABSENT` in the PR checks rollup | `instrument` | Not absent. The workflows had been queued about 9 minutes and registered 1 minute after the reading. **A never-run context and a not-yet-registered one are the same empty string in a PR's checks.** Discriminator is `gh run list --branch <ref>`, not the PR's checks. |
| 2026-08-26 17:33 | 613 | `repo harness tests` (ubuntu, windows-2025), `CI gate` | `test_every_relative_link_in_the_repo_resolves` -- unresolved link to `docs/adr/0166-sandbox-...md` | `pr-defect` | An ADR renumbering (0166 to 0176) renamed the file; 31 citations were not updated. **Only 1 of the 31 is a markdown link, so CI saw 3% of the defect.** Fixed all 30 real citations; 1 left deliberately (a synthetic near-miss path in a negative-control table, not a citation). |
| 2026-08-26 17:20 | 623 | `a PR that implements BACKLOG #N must update BACKLOG.md` | required context FAILURE | `pr-defect` | Subject cited `BACKLOG #234`; the PR touched no ledger row. Gate working correctly. Row added, context cleared. |
| 2026-08-26 17:05 | 609 | `repo harness tests`, `CI gate` | `test_every_relative_link_in_the_repo_resolves` -- link to `docs/adr/0172-...md` | `pr-ordering` | ADR 0172 exists only inside PR 575, which is unmerged. **609 also asserts the behaviour 575 introduces**, so stripping the link would leave a false claim on `main` with no check on it. The link test is an ordering guard and it worked. Waits for 575. |
| 2026-08-26 16:55 | 621 | `CodeQL` | `js/regex/missing-regexp-anchor`, high, in a vendored bundle | `pr-defect` | Real alert, not exploitable here (chooses only `text()` vs `arrayBuffer()` on an `api.github.com` header). Adversarial review found three worse defects in the same PR that CodeQL did not flag. Held. |
| 2026-08-26 16:55 | 621 | `test` (all three legs) | `test_the_real_vendored_cla_action_file_is_compliant` | `pr-defect` | The PR's own new test. `VENDORED_LICENCES` is keyed on a repo-relative path; the lookup passes `path.as_posix()`, which the test supplies as **absolute**. Windows backslashes were handled, absolute-vs-relative was not. Production reads `git ls-files` (relative), so only the test exposes it. |
| 2026-08-26 16:30 | 620, 609, 599 | `CI gate` and others | reported to the owner as "all 16 required contexts pass" | `instrument` | They did not. The probe hard-coded three CodeQL contexts, returned a true result about those three, and the claim was widened to all sixteen **in the sentence reporting it**. No better instrument prevents this; the correction has to happen in the prose. |
| 2026-08-26 15:00 | 597, 615, 619, 620 | `test (windows-*, py3.14)` | `empty_claims_monotonic` -- `fixed_per_conn@N=24: 30.2 < prior 48 * 0.75` | `flake` | None of the four touches `harness/load/connscale/`. Cleared on 597 and 619 with no change to either PR. Probe defect filed as BACKLOG #1357; fix unbuilt. **PR 624 adds five diagnostic fields so a future recurrence can be attributed rather than only detected.** |
| 2026-08-26 all day | every PR observed | `diff-coverage (advisory)` | `CANCELLED` on every PR checked, including several already merged to `main` | `advisory-noise` | A repo-wide 20-minute job budget cancels it. Not a required context and not in `CI gate`'s `needs:`. Blocks nothing, and is a dead instrument for the coverage question it exists to answer. Owner: whoever maintains `quality-advisory.yml`. |
| 2026-08-26 17:00 | 613, 531 | the three `CodeQL` contexts | reported `ABSENT`, not failing | `gate-artifact` | Required contexts went 13 to 16 mid-session. Heads predating the change had never run CodeQL, and **a context that never reports can never turn green** -- it is neither red nor pending. A push produces them (measured on 613: push at 17:33, CodeQL `in_progress` by 17:42). |
| 2026-08-26 (reported) | several | gate-parity tests | 4 failed from a worktree 31 behind `main`; 2 failed and 22 passed from the primary, 3 behind | `instrument` | The tests compare the installed hook against **the reader's checkout**, not against `origin/main`. Every seat holding an open PR is necessarily behind, so every one of them sees this. Reported by the Cleaner; a misread of it led to a gate reinstall that briefly left 121 worktrees ungoverned. |

---

## Trends

Read these as observations over a short window, not as rates. See
[Scope and honesty](#scope-and-honesty).

**The largest single category so far is `instrument`, not `pr-defect`.** Three of the eleven rows
are cases where CI was working correctly and a person read it wrong. That is not a CI problem and
no CI change fixes it, which is exactly why it needs recording somewhere.

**Two failure classes are invisible to the check that catches them.** The ADR link on 613 and the
missing ledger row on 623 both had a red check pointing at one instance of a larger population --
613's most sharply, where the link test could see 1 of 31 stale citations because only links
resolve. **Repairing the line CI names, without measuring the population behind it, is how a defect
lands green.**

**Reading a rollup instead of the required list has produced a wrong answer three times.**
`mergeable: MERGEABLE` sits next to `mergeStateStatus: BLOCKED` and both are true. An absent context
and a queued one render identically. A subset probe reports truthfully about its subset. The rule
that survives all three: **check each required context by name against the live required list.**

**A REQUIRED CONTEXT THAT CANNOT FIRE ON THE EVENT IS INVISIBLE UNTIL SOMETHING WAITS ON IT.** The
merge-queue deadlock is the sharpest instance: 32 green checks, nothing red, nothing pending, and
three contexts simply never arriving. **A rollup cannot distinguish "absent" from "queued" from
"will never report"** -- all three render as nothing. Reading the required list BY NAME against the
SHA that is actually being gated is the only thing that separates them, and it has now been the
answer four times in one evening on four different surfaces.

**`diff-coverage (advisory)` has not produced a usable result on any PR observed.** It is cancelled
by a job budget every time. It is harmless to merges and useless for coverage, which is the worst
combination for a check nobody is forced to look at.

---

## Scope and honesty

**Rows are added when somebody diagnoses a failure, not by a job.** So this file records at least
what is listed and certainly not everything that went red. A count taken from it is a count of
*logged* failures, which is a different quantity from failures that happened. Any trend drawn from
it should say which window it covers and that the sample is observation-selected.

**That selection has a specific bias worth naming: failures that got looked at are
over-represented, and failures nobody investigated are absent by construction.** A log like this
cannot find the thing nobody noticed. It is good for "this keeps happening" and bad for "this never
happens".

**Dates are the date of diagnosis, not necessarily of first occurrence.** The connscale flake row
covers four PRs across several hours under one timestamp, which is honest about when it was
understood and imprecise about when it started.
