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
| 2026-08-27 01:15 | 641 | `sql server (store + connector)` 2022 then 2025, reaching `CI gate` | `test_cipher_invocations_upsert_is_atomic_and_additive` -- `StoreAcquireTimeout: sqlserver`, twice, on TWO DIFFERENT OS legs | `infra` | **Deliberately not called a flake.** Everything points away from the PR -- it touches ZERO store files, PR 640 has both sqlserver legs green at the same time, the symptom is a POOL ACQUIRE TIMEOUT rather than an assertion, and an open vault PR exists to retry this exact upsert past transient failures. **But I pre-registered before the second attempt that the SAME test failing twice means stop, and it is the same test.** Re-reading the rule after seeing the result is what pre-registration exists to prevent, so 641 was DEQUEUED rather than re-run. One thing I cannot exclude: 641 edits the required `test` job in `ci.yml`. The sqlserver job is separate and I see no mechanism -- but that is an absence of imagination, not the proof I had for the 625 row below. **RESOLVED 2026-08-27 02:35, corrected in place per the rule above.** The cause was the environment, not this pull request. The author split the branch: PR 644 carried the same connscale work with ZERO workflow files and landed green on its FIRST queue attempt, and PR 645 then carried the `ci.yml` change ALONE and also landed clean **without the cipher test reappearing**. So the one thing I could not exclude -- that 641's edit to the required `test` job reached the sqlserver job -- is now excluded by measurement rather than by argument. **My pre-registered discriminator was WRONG**, and honouring it anyway cost one rebase and two queue cycles. Recorded because a rule that is only obeyed when it agrees with you is not a rule. |
| 2026-08-27 01:05 | 621 | `test` (all three legs) | `test_the_real_vendored_cla_action_file_is_compliant` | `pr-defect` | The PR's own new test. Reported to me as a branch whose "only conflict is a tail append" -- true of the CONFLICT, and it is also red on three required legs. **A rebase would have produced a clean branch that still cannot land.** Author lane is gone (the worktree pool re-took the directory), so it is parked rather than fixed. |
| 2026-08-27 00:40 | 637 | `repo harness tests (windows-2025)`, reaching `CI gate` | `test_dead_record_is_not_a_veto_and_not_a_permission` | `flake` | Passed on re-run. Control arm before re-running: the same leg was green on 638, 634 and 635, and 637's diff is ONE DOCS FILE, which cannot reach `tests/test_worktree_prune_merged.py`. Reading pre-registered before the re-run. |
| 2026-08-27 00:25 | 627 | `test (windows-2022, py3.14)` on the QUEUE BRANCH | `test_connscale_smoke.py` | `flake` | Merged on the second queue attempt. Rate for this assert now measured: **19% per RUN, 10.7% per LEG**, reconciling as `1-(1-0.107)^2 = 20.3%` against 19.0%. builder-2's truncation work puts the metric's mean ratio ABOVE 1.0 and finds it **bimodal** with local sd 0.024 -- so **do not widen the band**, which would mask a real 2.6x collapse. Cause of the bimodality unknown; a CPU-capacity explanation was tested at 2 cores against 20 and came back flat. |
| 2026-08-27 01:10 | several | the durability checks, not CI | I reported "could not reproduce" against a peer's measurement | `instrument` | **It reproduced. I ran the other command.** The claim was about `for-each-ref`; I checked it with `ls-remote` and got the ls-remote value. Measured after: `for-each-ref 'refs/tags/rescue/auto/*'` gives **2** against a true local **111**. `ls-remote` gives 693 because it matches with fnmatch and the star crosses slashes. **A failure to reproduce is only evidence if the reproduction used the same instrument** -- and a negative result reads as diligence, so it gets audited less than a finding would. |
| 2026-08-26 22:56 | 625 | `sql server (store + connector) 2022`, reaching `CI gate` through its `needs:` | `test_adr0070_4_fifo_head_first_after_stop[sqlserver]` ERROR on a 60s `pytest-timeout`, hung in async fixture setup; `test_adr0070_3b_streak_resets_on_forward_progress[sqlserver]` FAILED | `flake` | **Queue branch only.** The leg RAN and PASSED on 625's own head (268s, success). I checked for a real merge-result interaction rather than assuming: main's tip was 619, which touches only `transports/wincred.py`, a **Windows** connector, while this job runs on Ubuntu under docker where that module cannot load. 625 adds five lines to `config/settings.py`. No mechanism connects either to `test_stage_dispatcher.py`. Third attempt passed and 625 merged at `50300e583`. |
| 2026-08-26 22:25 | 625 | `load test (smoke, sqlserver) 2025`, reaching `CI gate` through its `needs:` | `Sqlcmd: Login timeout expired` / `TCP Provider: Error code 0x2749` / `Server is not found or not accessible` | `infra` | SQL Server container never became reachable. Distinct from the 22:56 row: **different job, different symptom** (container absent vs container healthy and slow). Two unlike failures across two attempts is the signature that made a third attempt worth taking. |
| 2026-08-26 21:39 | 627, 626 | `sql server (store + connector) 2022`, reaching `CI gate` | `apt-get failed 3 times` on the Ubuntu runner mirror | `infra` | The workflow's own error text names it: *"This is the UBUNTU RUNNER MIRROR, not the change under test."* Both PRs were green at their heads. Evicted from the queue with no code defect. |
| 2026-08-26 21:31 | 618 | `test (windows-2025, py3.14)` | `empty_claims_monotonic` -- `fixed_per_conn@N=24` below `prior * 0.75` | `flake` | Same assert as the rows below, on the queue branch. **Rate now measured: 19% per RUN, 10.7% per LEG across 21 real windows-2022 runs / 84 legs; the two reconcile as 1-(1-0.107)^2 = 20.3% vs 19.0% measured.** ~~builder-2's truncation analysis puts the mean ratio at 1.05 with sd 0.243 against a 0.25 band -- the band is the defect, not the direction~~ **CORRECTED 2026-08-28: THOSE FIGURES ARE RETRACTED. BACKLOG #1211 withdrew them the same day they were written -- the truncation estimate inverted the censoring under a single-normal assumption, and #1211 states the model is misspecified and its numbers should not be used. The DIRECTION conclusion survived; the mechanism and every number did not. Read #1211 for the current model rather than any figure restated here -- it is under active review and this log should not carry a second copy of it.**; all 9 failures sit in 9 distinct runs, where a wrong direction would fail both legs together. |
| 2026-08-26 22:40 | several | the queue itself | I reported that 627 and 626 were "green on all 15 required contexts and were evicted anyway", and attributed five evictions to a `docs/BACKLOG.md` tail-append collision | `instrument` | **Wrong, and broadcast to seven mailboxes; three seats repeated it back.** They were green on their PR **heads** and red on their **queue branches** -- separate shas, separate run sets. Zero of the five evictions was a collision. The `git merge-tree` collision result is real as a *mechanism* and was never evidence about what *happened*. Corrected in place at the claim. **Check `gh run list --event merge_group` before calling a PR landable.** |
| 2026-08-26 22:48 | 630 | `test (windows-2022, py3.14)` | I computed the connscale failure rate as 100% (3 of 3), having published 22% (4 of 18) shortly before | `instrument` | **Both wrong; the figure is 19% (4 of 21).** The 22% denominator included a path-filtered no-op leg. The 100% came from classifying "did this leg run the test?" by grepping the log for `connscale` -- **pytest only prints a test name when it FAILS**, so the detector could only ever see failures and the sample became the condition. The tell I read past: 19 legs the classifier called "did not run" had durations of 449-565 seconds. |
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
