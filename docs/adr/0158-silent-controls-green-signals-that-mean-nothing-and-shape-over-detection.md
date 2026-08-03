# ADR 0158 -- Silent controls: green signals that mean nothing, and shape over detection

- **Status:** Proposed -- records a defect class; the coordination-layer fixes it cites are already built on this branch  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-08-01
- **Related:** [ADR 0155](0155-dast-dynamic-security-testing-of-the-running-engine.md), [ADR 0156](0156-asvs-scorecard-as-data-a-derived-count-verified-evidence-anchors-and-a-fail-closed-drift-gate.md), [CLAUDE.md](../../CLAUDE.md) section 11, [Secure_Development_Standards](../Secure_Development_Standards.md) section 3, [SESSION-DRIFT-CONTROLS](../SESSION-DRIFT-CONTROLS.md), BACKLOG #139, #323, #344

---

## Context

> **Provenance note, applying to this whole document.**
>
> Each load-bearing figure below was re-derived by someone who did not produce it, against the
> repository, the GitHub API, or a live interpreter. At least the following did not survive that pass
> and are recorded here as explicit retractions, because an ADR about unverified claims propagating
> cannot itself carry one. Claims that could not be sourced from the repository are marked
> **[unverified]** and nothing here depends on them.
>
> Every instance and every retraction carries a **found by:** tag. That tagging is not decoration --
> "no author caught their own defect" is this document's central empirical finding, and it is
> invisible if attribution is smoothed away. Where provenance exists only in session transcripts and
> not in the repository, the tag says so.
>
> Two conventions. Timestamps ending `Z` are UTC as returned by the GitHub API; coordination
> allocation records carry a local offset (`-05:00`), so one working evening appears as both
> `2026-08-01` and `2026-08-02` depending on which artifact you read -- the first instance of the
> class, in miniature: a value and its unit travel separately. And this file is written ASCII-only
> at its author's request; nothing in the repository requires that (most ADR index rows use em
> dashes), so quoted material below is normalised, not verbatim, and is flagged where it matters.

The forcing rules are [CLAUDE.md](../../CLAUDE.md) section 11, quoted with em dashes normalised to
`--` and one pointer clause elided:

> - **Review security prose by asking what a reader would DO with it, not whether it is accurate.**
>   The three rules below are instances of it. [...]
> - **State a load-bearing fact ONCE and link to it; never restate it.**
> - **A completeness claim is a liability -- prefer "at least" to an enumeration.**
> - **A compensating control must not rest on a false premise.**

The reasoning behind those one-liners is already the source of record at
[Secure_Development_Standards](../Secure_Development_Standards.md) section 3, subsection *"Reviewing
security prose: ask what a reader would DO with it"* (line 72). **This ADR does not restate it.** It
records a different-shaped failure the same working day produced repeatedly, and the method that
caught it.

### The spine

**A signal that does not carry enough information to act on forces every reader to re-derive
significance by hand, and eventually one of them derives it wrong.**

Green-means-nothing and red-means-nothing are two faces of one failure. A correct-but-useless RED
costs what a silent green costs: a drift check that reported two differing SHAs when the whole diff
was a single redacted comment consumed the same triage as a hook that printed a reassuring status
message on every prompt while resolving nothing. Both true. Neither actionable.

At least two sub-classes, each with a one-line test. The taxonomy is not claimed to be complete.

- **Class 1 -- a bound or claim stated INDEPENDENTLY of the thing it bounds.**
  Test: *what measurement backs this?*
- **Class 2 -- a control that cannot OBSERVE or ACT ON its own failure.**
  Test: *if this control were broken, what would tell me?* If the answer is the control, that is the
  defect.

### Class 1, as it actually occurred

**The CI cap.** [`ci.yml`](../../.github/workflows/ci.yml) carried, from f8d11685 (#104), the
sentence that the Windows legs were "unchanged because 26 min against the same suite is still ~2x
headroom." Nothing produced that number and nothing re-derived it. On 2026-08-01 PR #119's
`windows-2025` `Tests (pytest)` step was killed at **26:07** against the 26:00 step cap (run
30717229521 attempt 1, `2026-08-01T20:34:42Z` -> `21:00:49Z`, step conclusion failure);
[`ci.yml`](../../.github/workflows/ci.yml) records, in the comment beside that cap,
"ZERO tests failing" on that run. Attempt 2, on the same commit against the same cap,
ran **22:25** and succeeded. Same code, same ceiling, two
outcomes. 28d186b5 (#131) replaced the claim with a measured table and raised both Windows legs from
`job_timeout: 30 / step_timeout: 26` to `40 / 36`.
*found by: a peer session (transcript-only for the discovery; the artifacts are in-tree).*

**The correction was itself wrong in at least four ways, and each is the same defect recurring.**

- *Retraction 1 -- the pool size.* [`ci.yml`](../../.github/workflows/ci.yml)'s margin table, as written
  on 2026-08-01, stated the figures were
  "Measured over the 11 PASSING windows-2025 runs on 2026-08-01"
  (restated in `docs/BACKLOG.md` as "over 11 runs"). Three independent re-measurements against the GitHub API
  returned 35, 36 and 38 depending on the predicate applied; none is near 11, and none of the three
  could reconstruct a filter yielding 11. The comment states no filter. **[unverified]** hypothesis,
  recorded but not relied on: a default `gh run list` page is 20 rows, so the sample may have been
  tool-truncated rather than chosen.
  *found by: two independent verifiers, then confirmed by two adversarial reviewers.*
- *Retraction 2 -- the anchor.* `24:35` is the maximum passing step **only under a job-conclusion
  filter**, and that filter removes the interesting case. Run 30724385719 (a `main` push, created
  `2026-08-01T23:59:45Z`, i.e. before #131 landed and so under the 26:00 cap) ran its `windows-2025`
  `Tests (pytest)` step `2026-08-02T00:01:21Z` -> `00:27:12Z` = **25:51**, step conclusion
  **success** -- 9 seconds under the cap, a margin of **1.006x**, not 1.06x. Its enclosing job was
  killed at 30:13 by the 30-minute *job* cap during a later step (`Web console tests (pytest)`,
  cancelled `00:30:14Z`; every sibling job in that run concluded success and the next `main` run was
  created after the cancel, which rules out a cancel-in-progress). Consequence for the new cap:
  36:00 over 25:51 is **1.39x**, not the **1.46x** that
  [`ci.yml`](../../.github/workflows/ci.yml) claimed when this was written.
  *found by: two independent verifiers, independently; cause established by an adversarial reviewer.*
- *Retraction 3 -- the table rows.* Two of the three rows in that margin table are single-run values,
  not maxima over any pool. The ubuntu maximum passing step was 12:31, not the tabled 12:27 (which is
  the ubuntu leg of the same run that supplied 24:35); the windows-2022 maximum was 21:34, not the
  tabled 18:39 (which is PR #119's own windows-2022 leg), making the old windows-2022 margin
  **1.21x**, not the 1.39x that made it look safe. Only the windows-2025 row was maximised at all.
  *found by: one independent verifier; arithmetic reproduced by two adversarial reviewers.*
- *Retraction 4 -- the sizing criterion, including this document's own first statement of it.* A
  "headroom exceeds spread" criterion was asserted over six hand-picked runs and stated flatly. Stated
  with its pool, it reads: over the **36** `windows-2025` `Tests (pytest)` steps that concluded
  SUCCESS in the `ci.yml` runs created 2026-08-01 (latest attempt only -- the jobs endpoint returns
  only the latest attempt, so re-run first attempts, including #119's 26:07, are absent unless
  queried per-attempt), the spread is **9:55** (15:56 min, run 30705857511; 25:51 max, run
  30724385719). Two re-measurements agree on that pool exactly. Restrict the pool to runs whose
  enclosing **job** also succeeded (n=35, max 24:35) and one re-measurement puts the spread at 8:39.
  The headroom is equally pool-dependent: 36:00 over the maximum passing step (25:51) is **10:09**,
  which clears 9:55; 36:00 over the cap-kill (26:07) is **9:53**, which does not -- but 26:07 is a
  FAILED step and a member of no success pool, so anchoring the criterion there compares a cap
  against an observation outside its own population. An earlier statement of this retraction paired a
  count of "42" with the 9:55 spread; no `windows-2025` pool of 42 reproduces (42 is the
  ubuntu-latest count over the same runs), and 9:55 belongs only to step-success pools. Neither
  "9:53" nor the six-run "5:26" spread appears anywhere in the repository: the arithmetic is
  verified, the criterion itself is **[unverified]** as a stated bound. The verdict is a function of
  the pool and the anchor, and neither was named. (The pool is genuinely arguable: the suite grew
  mid-day when #74, f7e12695, added a 1,506-line test file, so the population mixes pre- and
  post-growth runs.)
  *found by: an independent verifier (the original), then retracted by two adversarial reviewers who
  re-measured the population.*

**The worked inversion: a correct estimate retracted and replaced by an incorrect measurement.**
While triaging PR #133 (run 30725619514), an estimate of "~25:30" for the `windows-2025`
`Tests (pytest)` step was withdrawn in favour of a stated measurement of **28:14**, from which
followed "it would have been KILLED, over by 134s" -- and a peer amplified it. The step actually ran
`2026-08-02T00:43:32Z` -> `01:08:23Z` = **24:51** (1491s). 28:14 (1694s) is the **job**, not the
step. `1694 - 1560` (the 26:00 step cap) is exactly 134, so the arithmetic reproduces only under the
job-vs-step mismatch. Against the old caps the step was 69s under the step cap and the job 106s under
the job cap. The retracted estimate was 39s HIGH of the truth, conservative in the safe direction,
and reached the **correct** verdict. **The measurement's authority came from being called a
measurement, not from what it measured.** Two caveats stated rather than smoothed: the "~25:30"
estimate is recorded only in session transcripts and is **[unverified]** from this repository (no
occurrence of that string in any tracked file; PR #133 has zero issue comments); and run 30725619514
was created `00:39:47Z`, after #131 merged `00:35:29Z`, so it ran under the NEW caps -- "would have
been killed" is a counterfactual about a run that never faced them.
*found by: an independent verifier re-deriving both figures from the run's own timestamps.*

**Other Class-1 instances found the same day**, each a claim stated independently of its subject:

- [`.github/zizmor.yml`](../../.github/zizmor.yml) said `release.yml` "sets persist-credentials:
  false on both checkouts". `release.yml` has three, all false. Fixed by 0fdc326e, merged as 851c849b
  (#130) -- the branch SHA is unreachable from `main`, which squash-merges -- which dropped the
  count rather than correcting it -- the right move, because the count was doing no work. Two things
  about attribution: the wrong sentence was in `zizmor.yml` describing `release.yml`, never in
  `release.yml` (sourcing it to `release.yml` would itself be a Class-1 error); and the line numbers
  0fdc326e's own message quotes are the checkout steps, while the `persist-credentials` keys sit two
  lines below each -- which is why this ADR follows the precedent and states no line numbers.
  *found by: an independent verifier for the count; the line-number ambiguity by an adversarial
  reviewer, after this ADR's own first draft copied numbers from the commit message without opening
  the file.*
- The same suppression comment said "The jobs below do not push", listing among others
  [`dependabot-lock-resync.yml`](../../.github/workflows/dependabot-lock-resync.yml), which commits at
  line 156 and pushes at line 160. The comment's own carve-out two lines below already said so, on
  purpose. The contradiction was inside one paragraph.
  *found by: an independent verifier.*
- Two dependency-cap comments in [`pyproject.toml`](../../pyproject.toml) said "CI installs with a
  FRESH resolve", while [`ci.yml`](../../.github/workflows/ci.yml):130 states that EVERY install
  below passes `--constraint constraints.lock`. Rewritten by 2a6649fb (#121). Attribution matters
  again: every surviving "fresh resolve" string under `.github/` is coherent, and the one genuinely
  unconstrained install (`freethread-smoke.yml`:90) says so deliberately -- a reader grepping the
  phrase will "find" instances that are not instances.
  *found by: an independent verifier, who also bounded the blast radius.*
- `docs/BACKLOG.md` stated, as the reason an item is an anti-feature, that the engine "uses
  STARTTLS with a verifying context by design". Two lines earlier the same item accurately says it
  "calls starttls() with the default SSL context". The code calls `smtp.starttls()` with no context
  argument ([`alert_sinks.py`](../../messagefoundry/pipeline/alert_sinks.py):382-384). The same bare
  call stood at [`transports/email.py`](../../messagefoundry/transports/email.py) and
  [`transports/direct.py`](../../messagefoundry/transports/direct.py) when this was written; *update
  (after this ADR was committed): 093db339 (#132) gave both connectors an explicit verifying context,
  and the alerts call site is tracked separately as BACKLOG #323 layer 3. This instance is recorded
  because it is the worked example the taxonomy was derived from, not as a statement of what is
  outstanding now -- a reader wanting the current state must grep, not cite this.* On the project's own
  interpreter (Python 3.14.6), `smtplib.SMTP.starttls` resolves a `None` context via
  `ssl._create_stdlib_context`, which **is** `ssl._create_unverified_context`: `verify_mode`
  CERT_NONE, `check_hostname` False. The sink encrypts and authenticates nothing. **A retraction is
  already filed -- and the false sentence was still there:** BACKLOG #323 in `docs/BACKLOG.md` says
  that #139's rationale "is **false** and should be retracted there", and the anti-feature item still
  said it. A retraction is not done until the original sentence changes. *Update (2026-08-02, after
  this ADR was committed): 093db339 (#132) changed the source sentence. On `main` the clause survives
  only inside its own "CORRECTED 2026-08-01" block and as a quotation under #323 -- so the interval this
  instance records is closed, and the rule it produced is unaffected.* (Naming correction: `EmailAlertSink` is
  not a symbol in this codebase; it occurs only in BACKLOG prose.)
  *found by: a peer session, filed against another item as BACKLOG #323 -- the one instance in this
  record whose cross-author provenance is documented in the repository itself.*
- `docs/BACKLOG.md` #344, whose remedy 4 says to prefer "a measured ratio with a date over
  round multiples", proposes at remedy 1 -- three lines above -- a gate that fails "below
  ~1.3x": a bare multiple, with no measurement, pool or date. *Retraction 5:* an earlier statement of
  this instance quoted the figure as "1.45x". That string appears **nowhere in the repository**.
  *found by: an independent verifier, who retracted the figure while confirming the pattern.*
- `tests/test_stage_dispatcher.py`:356 bounds `_wait_until` with a hardcoded `timeout: float = 8.0`
  polled against `loop.time()` -- real monotonic time -- while the system under test runs on an
  injected `ManualClock` (:182). The file already documents the split deliberately (`_settle`,
  :349-351: park/sweep timing is the ManualClock's job), so the defect is not the wrong clock: it is
  a **fixed real-time bound over unbounded runner latency**, stated independently of the work it
  bounds. Filed as BACKLOG #344 instance 2 and still open.
  *found by: an independent verifier.*

### Class 2, as it actually occurred

- **The founding instance.** A `UserPromptSubmit` hook in the user-level settings probes
  `scripts/hooks/announce.ps1`. That path has never existed on any ref of this repository
  (`git log --all` over it returns nothing); it exists in a **different** repository. Replayed live
  from a linked worktree, both candidate bases miss, nothing runs, stdout is empty, exit 0. It
  carried a status message reading "Announcing to sessions in this repo" and fired on every prompt.
  The structural cause is stated once, in the block quote added to
  [SESSION-DRIFT-CONTROLS](../SESSION-DRIFT-CONTROLS.md) (the document is on `main`; that block quote
  is branch-local at time of writing) -- this ADR links it rather than restating it.
  *found by: a peer session; the live replay by an independent verifier.*
- **The same shape in the gate, and nothing pins it.** The installed collision-gate shim is a
  `foreach` over candidate bases with `if (Test-Path ...) { & $s; break }` and **no else**
  (`scripts/coord/install-coordination.ps1`:86-98, `New-ShimCommand`). A miss exits 0 and the
  `Edit`/`Write` proceeds ungated. **No test covers this.**
  `tests/test_collision_gate.py::test_fails_open_when_the_overlap_script_is_missing` covers the
  adjacent layer -- the gate failing open when `overlap.ps1` is missing -- not the shim failing to
  find the gate. This ADR's own first draft cited that test for the uncovered behaviour, which is
  section 11's fourth rule (a compensating control resting on a false premise) committed inside the
  document that quotes it. The absence is a stronger illustration than the test would have been.
  *found by: an independent verifier for the missing else; the mis-citation by an adversarial
  reviewer who opened the test.*
- **A non-required check on a repository that permits auto-merge fails toward landing.** `main` has
  13 required status contexts; zizmor's context is not among them, and is not required transitively
  (the `CI gate` roll-up names six jobs, none of them zizmor's, and zizmor is a separate workflow).
  Repository settings report `allow_auto_merge: true` -- auto-merge is *permitted*; whether it is
  enabled on any given PR was not measured. The same fact is written in-tree at
  [`zizmor.yml`](../../.github/workflows/zizmor.yml):10-11 with the opposite emphasis: non-required
  *protects* a PR from being wedged by a paths-filtered skip. Both readings are correct. Neither
  sentence tells a reader which failure direction they are buying.
  *found by: an independent verifier; the "armed" overstatement corrected by an adversarial reviewer.*
- **A validator whose input is derived from its subject is satisfied by construction.** zizmor's
  `pull_request` paths filter once listed only `.github/**`, while zizmor's own pinned version lives
  in `pyproject.toml`'s `[dependency-groups].ci-scanners` and reaches the install step through
  `ci/locks/ci-scanners.lock`. [`zizmor.yml`](../../.github/workflows/zizmor.yml):13-21 and commit
  7ebb2ffa record that PR #66 (a Dependabot bump moving zizmor 1.5.2 -> 1.28.0; never merged, the
  version landed later via #130) ran 33 check contexts and not one of them was zizmor -- a figure
  quoted from that comment, not independently re-derived. *Retraction 6:* this is **false in the
  present tense**. 7ebb2ffa, merged as 2a6649fb (#121) on 2026-08-01, added
  `ci/locks/ci-scanners.lock` to the filter (`zizmor.yml`:23). The residual, still live:
  `pyproject.toml`'s `[dependency-groups].ci-scanners` -- where the pin actually lives -- is still outside the filter; only the
  exported lock closes the gap.
  *found by: a peer session; retracted in the present tense by an independent verifier; the
  merge status of #66 corrected by an adversarial reviewer.*
- **An equality check satisfiable by coincidence is not an equality check.** Three copies of
  `worktree_gate.ps1` (installed, primary checkout, worktree) are all exactly 49709 bytes and 781
  lines. The installed copy differs from both source copies on exactly one comment line, where a
  5-character account name was replaced by a 5-character placeholder. A size comparison reports MATCH
  on drifted files. `tests/test_gate_installed_parity.py` compares content.
  *found by: an independent verifier.*
- **The control built in response would not have caught the defect that motivated it.**
  *Retraction 7:* `tests/test_installed_coord_hooks.py` was described as the first control that can
  observe its own failure. It is not first (`tests/test_gate_installed_parity.py` is on `main` and
  the new module's own docstring credits it as the model it follows verbatim; two announce-wiring
  modules precede it on the same branch), and it does not observe its own failure in the strict
  sense: its negative control covers the path predicate only, so if marker parsing or the extraction
  regex broke, the entry list would be empty and the assertion would **skip**, not fail. Measured on
  the box where the founding instance lives, the founding entry is classified FOREIGN and routed to
  an informational test that never asserts. It also skips entirely in CI. What survives is worth
  having and worth stating exactly: it is the first control that **asserts a wired coordination hook
  resolves to a file that exists**, and it carries a negative control so its resolution predicate
  cannot be vacuously green. Its one real mitigation is ordering: it prints what it scanned BEFORE it
  can skip, because the repo's pytest config carries no `-rs` and a bare `sss.` reads as a pass.
  *found by: an independent verifier who replayed the module's own logic against the live box.*

### The unit trap, in general form

Every instance above is one shape: **a value and its meaning are separate facts, and only one of
them gets carried around.**

- A duration without its unit -- `28:14` is a job, `24:51` is a step, and the cap gates the step.
- A maximum without its pool -- `24:35` is a maximum over job-success runs; `25:51` is the maximum
  over passing steps.
- A file set without its diff form -- `overlap.ps1`'s row emitted the union of committed and
  working-tree files. The header's LIVE-vs-DORMANT contract *was* implementable and *was*
  implemented (`Live` is a row field on `main`; the gate already branched on it). What no caller
  could distinguish was committed-and-unlanded from working-tree **within a live row**, so "block on
  live" could only be implemented as "block on any live row that mentions the file" -- which
  over-blocks indefinitely, because a committed file stays in `Files` until the branch LANDS. The
  concrete harm is recorded at `scripts/hooks/collision_gate.ps1`:77-82: a session committed a file,
  confirmed in writing it was done, and the peer it handed off to was still refused. **Do not restate
  the broad form of this finding** ("the contract was unimplementable"); it is false.
  *found by: a peer session with a repro; the broad-form overstatement corrected by an independent
  verifier.*
- A guarantee without its enforcing gate -- `claim.ps1`:37 documents `-Take` as "Idempotent:
  re-taking your own claim just refreshes the note"; the code at :126-132 early-returns and discards
  `-Note`, with a comment on :129 saying re-taking is a no-op. Two contradictory sentences three
  lines apart in one file.
- A path without its filesystem shape -- in a linked worktree `.git` is a 98-byte FILE, so a
  worktree-relative read of `.git/mefor-coord/...` fails with "Not a directory". It is an error, not
  an empty result -- but a caller that swallows stderr sees "nothing there".

## Decision

**Record this class, and split what is ENFORCED from what is CONVENTION -- because most of these
instances were corrected, not made unrepresentable, and saying otherwise would be the same defect.**

### A. Enforced -- each names its gate and reds a PR

Verified: the tests below skip only on `pwsh missing or os.name != "nt"`, and both Windows legs are
among `main`'s 13 required contexts, so they run on the merge path.

1. **Emit signals separately; a union is a lossy encoding the caller cannot invert.**
   Gate: AC-3, `tests/test_coord_overlap_signals.py`.
2. **A consumer that meets a row lacking the discriminating field takes the conservative branch.**
   Gate: AC-4, `tests/test_collision_gate.py`.
3. **A shim that resolves a script has a miss path that says so, on a surface outside the script it
   failed to find.** Gate: AC-5, `tests/test_announce_wiring.py` -- covering the announce row only.
   The collision-gate row (`New-ShimCommand`) still has no else and no test; see *To resolve*.

### B. Enforced only locally -- runs on a developer box, never on the merge path

These skip in CI (no user settings, no installed gate) and are therefore **not merge-gating**. Their
one mitigation is that each announces what it scanned before it can skip.

4. **A wired hook entry resolves to a file that exists, and the resolution predicate has a negative
   control.** AC-1, `tests/test_installed_coord_hooks.py`.
5. **Installed artifacts are compared to their source by content, never by size.** AC-2,
   `tests/test_gate_installed_parity.py`.

### C. Convention -- unenforced, and knowingly re-breakable by the next edit

Nothing checks these. They are stated because each traces to a specific instance above, not because
adopting them closes anything.

6. **CI figures come from the step's own timestamps.** Quote a step duration from that step's
   `started_at`/`completed_at` and compare it only to `step_timeout`; compare a job's elapsed only to
   `job_timeout`; name in the sentence which quantity you measured. A Windows job here runs roughly
   three minutes longer than its `Tests (pytest)` step -- enough to invert a pass/fail verdict.
7. **A stated bound carries four things: the measured value, the quantity measured, the pool and how
   it was filtered, and the date.** A bare multiple is not acceptable. If a maximum was taken, say
   what it was maximised over; if a cap is sized against an observation, say whether that observation
   is in the pool.
8. **Treat a filter as part of the measurement and ask what it removes.** A job-conclusion filter
   removed the tightest passing observation in this record. A listing tool's default page size and a
   "latest attempt only" endpoint are filters too.
9. **A measurement beats an estimate only when it measures the SAME QUANTITY.** When one contradicts
   the other, reconcile the units before replacing the number, and say which you reconciled.
10. **Before adding a control, name the surface that still reports when the control itself fails to
    load.** If the answer is the control, it is not installed however it looks. A status message is
    not that surface.
11. **A validator whose expected value is derived from its subject is satisfied by construction.**
    Derive the expectation independently, and give every detector a negative control -- naming which
    predicate the control covers, since one predicate is not the scan around it.
12. **When a comment states a count, verify it in the same commit or drop the count.** 0fdc326e is
    the precedent: the claim was right, the count was a liability, so the count went.
13. **A retraction is not done until the original sentence changes.** Filing a correction under a
    different item leaves the false sentence where readers act on it (BACKLOG :5264, for the interval
    between #323 filing the retraction and 093db339 (#132) changing the sentence).
14. **Any figure that will live in a durable artifact gets re-derived by someone who did not produce
    it.** This is the rule to protect if the others erode; see *Consequences* for the evidence, and
    for the bound on that evidence.

**What this must not break:** nothing in the engine. This ADR changes documentation and coordination
practice only. It states no fact that [CLAUDE.md](../../CLAUDE.md) section 11 or
[Secure_Development_Standards](../Secure_Development_Standards.md) section 3 already states -- it
links to them, per section 11's first rule, which is the rule this class of ADR is most likely to
violate.

## Acceptance Criteria

- **AC-1** -- WHEN a wired hook entry names a script path, THE SYSTEM SHALL assert that the path
  resolves to a file that exists in this checkout, and SHALL carry a negative control proving the
  resolution predicate can fail. *(Local-machine only: skips in CI, not merge-gating.)*
  -> `tests/test_installed_coord_hooks.py::test_the_resolution_check_can_detect_a_missing_script`
- **AC-2** -- WHEN an installed artifact is compared against its committed source, THE SYSTEM SHALL
  compare content, never size. *(Local-machine only: skips in CI, not merge-gating.)*
  -> `tests/test_gate_installed_parity.py::test_the_installed_gate_matches_the_committed_source`
- **AC-3** -- WHERE a caller must respond differently to two conditions, THE SYSTEM SHALL emit the
  two signals separately rather than their union.
  -> `tests/test_coord_overlap_signals.py::test_a_committed_and_clean_file_does_not_report_matcheddirty`
- **AC-4** -- IF a consumed row lacks the discriminating field, THEN THE SYSTEM SHALL take the
  conservative branch.
  -> `tests/test_collision_gate.py::test_a_row_without_the_dirty_signal_still_denies`
- **AC-5** -- WHERE a shim resolves the announce script and finds nothing in this checkout, THE
  SYSTEM SHALL report that fact on a surface that does not live inside the script it failed to find.
  -> `tests/test_announce_wiring.py::test_the_announce_shim_says_so_when_the_script_is_missing`

Deliberately absent: no acceptance criterion is offered for the unenforced rules in Decision C, and
none is offered for the `_wait_until` bound or for `ci.yml`'s margin block. Both are real and both
are open; pointing a SHALL at the artifact that fails it would make the link check pass by
construction, which is this document's Class 2. They are in *To resolve on acceptance* instead.

## Options considered

1. **Record the class, enforce what can be enforced, and state the rest as convention -- reporting
   the ratio rather than flattering it. CHOSEN.** It is the only option that survives the evidence:
   each rule derives from a specific instance, and the split makes visible how little is actually
   gated.
2. **Fix the instances and write nothing.** Rejected: the class recurred at least a dozen times in
   one day across independent surfaces (workflows, dependency caps, backlog prose, hooks, tests,
   coordination scripts), which is the signature of a shape, not of a dozen mistakes.
3. **Adopt a general "verify claims before stating them" policy and nothing else.** Rejected *as the
   whole answer*: every false statement in this record was written by someone intending to be
   accurate, and each passed an accuracy check at the time; the project's own standard holds that the
   mitigation must be structural, not diligence. This ADR therefore enforces rules 1-5 with tests and
   labels 6-14 as convention rather than pretending they are controls. Rule 14 is the one place
   diligence is retained on purpose, because the measured evidence below is that independent
   re-derivation is the only method here with a nonzero catch rate -- and it is retained as a
   *practice with a named cost*, not as a gate.
4. **Build a lint that detects the class.** Rejected for now, and the reason matters: the detector
   would have to decide whether a number in prose is a bound and what it bounds -- exactly the
   information the defective sentences omit. A lint over a corpus that hides the discriminating fact
   is the Class-2 shape again. Narrow checkable pieces (rule 6's step-vs-job comparison; a required
   pool and date beside a stated margin) may be worth a gate; that is BACKLOG #344's territory, and
   #344's own remedy 1 currently proposes a bare multiple, which must be fixed before it is built.

## Consequences

**Positive** -- The rules are mechanical enough to apply without judgement, and each traces to a
concrete failure rather than to a principle. Three coordination-layer fixes (separated
`Dirty`/`MatchedDirty` signals, the fail-safe consumer branch, the announce miss-path notice) are
covered by tests that run in required CI legs, so those specific regressions red a PR.

**The finding that matters, stated with its bound** -- Within this document's own production, **no
retraction was produced by the author of the claim it retracts**. Every one came from a peer or a
verifier re-deriving the figure independently, including the retractions of corrections that had
themselves been filed as fixes (the `11 runs` pool, the `24:35` anchor, the headroom-versus-spread
criterion, the "42" pool count, a BACKLOG number, and a set of line numbers this ADR copied from a
commit message without opening the file). Two independent re-measurements of the same population
disagreed (35 versus 36) because one required the enclosing job to succeed and one did not, and only
one said which -- a third re-measurement reproduced both exactly. That disagreement is the useful
output, not a defect in the method. **The bound:** the repository documents cross-author provenance
for exactly one instance (BACKLOG #323's amendment of #139); the rest is provenance from this
document's own review chain, and the wider evening's session and retraction counts are transcript-only
and **[unverified]**. What is claimed here is therefore not "self-review has a zero success rate in
general" but the narrower, checkable statement above -- which is what rule 14 rests on.

**Negative / risks -- shape over detection is a ratio here, not an achievement.** Of the instances
recorded above: three are covered by a test that runs in a required CI leg; two by tests that always
skip in CI; one (zizmor's paths filter) by a workflow change with a named live residual; and the
remainder are corrected prose or still open. Anyone editing those comments can reintroduce the same
claim tomorrow, and at least two instances left a residual (`pyproject.toml` is still outside
zizmor's filter; the false `docs/BACKLOG.md` rationale stood with its retraction filed elsewhere
until 093db339 (#132) changed the sentence itself, the day after this was written). The
coordination-layer signal split is the clearest case where the wrong statement became
structurally harder to make, and even it is a corrected emission rather than an unrepresentable one.
Do not read this ADR as evidence the class is closed, and do not read the taxonomy as complete.
Further: adding rules raises the cost of writing a bound, and a rule that is expensive to follow gets
followed selectively.

**Out of scope** -- Any engine behaviour. The reliability, count-and-log, purity and PHI invariants
are untouched; no connector, store, pipeline stage or API surface changes. Re-deriving the correct
Windows step cap is out of scope: this ADR records that the stated criterion's verdict depends on an
unnamed pool and an out-of-pool anchor, not what the cap should be. Session counts from that evening
are out of scope and unverified; note that a confusable adjacent statement exists and must not be
conflated with them -- the block quote in [SESSION-DRIFT-CONTROLS](../SESSION-DRIFT-CONTROLS.md)
credits "the session that hit four instances of the same class in one day": four *instances*, one
*session*.

## To resolve on acceptance

- [ ] Restate [`ci.yml`](../../.github/workflows/ci.yml)'s margin block with a defined pool. Three
      independent re-measurements returned 35, 36 and 38 under different predicates; none is the
      stated 11. Decide the pool definition and record the filter beside the number.
- [ ] Decide whether the 36:00 Windows step cap clears the population spread, and against which
      anchor: over the maximum passing step (25:51) the headroom is 10:09 and clears the 9:55 spread;
      over the cap-kill (26:07, a failed step in no success pool) it is 9:53 and does not.
- [ ] Correct or drop the table rows now known to be single-run values or job-filtered maxima
      (`24:35` and its `1.46x`, ubuntu `12:27`, windows-2022 `18:39`).
- [ ] Apply the retraction already filed in `docs/BACKLOG.md` under BACKLOG #323 to the false
      sentence in the anti-feature item it names, and decide separately whether the bare `starttls()` calls
      get a verifying context.
- [ ] Replace BACKLOG #344 remedy 1's bare "~1.3x" threshold with a measured, dated ratio before that
      gate is built, and decide whether rule 6 (step-versus-job) becomes part of it.
- [ ] Decide the `_wait_until` bound (BACKLOG #344 instance 2): a fixed 8.0s real-time budget over
      unbounded runner latency, beside an injected virtual clock.
- [ ] Give the collision-gate shim (`New-ShimCommand`) a miss path and a test, or record why
      fail-open is the intended behaviour there. Neither was verified.
- [ ] Add `pyproject.toml` to zizmor's `pull_request` paths filter, or record why the exported lock
      is sufficient.
- [ ] Resolve the `claim.ps1` contradiction: honour `-Note` on a re-take (matching the header at line
      37) or change the header to match the no-op at lines 126-132.
- [ ] Decide whether this ADR's link to the branch-local block quote in
      [SESSION-DRIFT-CONTROLS](../SESSION-DRIFT-CONTROLS.md) is acceptable before that branch lands.
