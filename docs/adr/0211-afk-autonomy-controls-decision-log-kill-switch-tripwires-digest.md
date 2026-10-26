# 0211 -- AFK-autonomy controls: decision log, kill switch, tripwires, digest

- **Status:** Accepted (2026-10-21, on build). The owner approved docs/AUTONOMY-PLAN.md, whose
  section 4 requires these controls, on 2026-10-21 (branch `autonomy-plan`, commit `18fbca9c2`).
  The storage choice, the schema and the enforcement split below are this build's design inside
  that approval; the owner may overrule them at review. **Amended 2026-10-22:** the `-Banner`
  hook also tells non-Special sessions to load driver and empower while the switch reads OFF
  (owner approval 2026-10-22); the ON banner carries no such instruction.
- **Date:** 2026-10-21
- **Related:** docs/AUTONOMY-PLAN.md sections 3, 4 and 10 (wave 1); CLAUDE.md section 5 (the cloud
  session rule) and section 11 (SDS-3.6, SDS-3.7); SAIDS section 9 (a rule is not a control until
  something enforces it)

## Context

The AFK-autonomy plan lets sessions act on their own judgment and bring the owner only what is the
owner's. Its order of operations is fixed: *"build these, then retire the owner's plan go, then
widen Class B."* Section 4 names the controls. This ADR builds the first, smallest working slice of
four of them: the decision log (4.1), the kill switch (4.3), the tripwires (4.4) and the daily
digest with its blind sample and calibration arithmetic (4.2, 4.8).

Nothing in this slice widens autonomy. Until wave 2 changes the rules, every class is still in
ask-mode, so the controls are built before anything depends on them.

Constraints that bound the choice:

- The log must be **private**, **append-only in practice**, **readable by every account**, and
  **reachable over REST**.
- The owner ruled that vault work stays local (plan section 9, question 3), so the log need not
  reach a cloud session. A cloud Builder's decisions are logged by its Manager.
- Every seat posts as **one GitHub identity** and draws on one shared 5,000-an-hour REST budget.
- A record is data. Owner authority arrives only as a user turn in a session's own chat (plan R5).

## Decision

### 1. Storage: one vault issue per UTC day, one comment per record, spooled locally first

`scripts/coord/decision.ps1` writes each record to a local spool,
`<git-common-dir>/mefor-coord/decisions/spool/<id>.json`, and then posts it as one comment on the
private vault repository's issue titled `decision-log <yyyy-MM-dd>`, labelled `decision-log`. The
script creates the day's issue on first use. A posted record leaves the spool. A record that
cannot be posted stays there, and the script says so and exits 4; the next `-Log` or `-Flush`
posts it. A flush holds back only a `PENDING` record whose id is under ten minutes old, since its
gate is still running (*Where it is enforced* below); `-Flush` counts it as `held`, and a later
`-Log` or `-Flush` posts it. `-NoPost` spools with no network at all, which the tripwire hook needs.

A day's issue number never changes, so it is cached in `decisions/issues.json` and the listing
is asked only on a miss; a record then costs one REST request. A cached number that answers 404
is dropped and listed again on the next flush. The scripts find the coordination directory from
where they live, not from the cwd, so a run from inside another checkout cannot spool into it.

A reader merges the vault's records with the spool's and drops duplicates by id, so a record
posted twice reads once. Two machines that create the same day's issue leave two issues with one
title, and a reader reads both. A reader pages through the whole issue listing, one request per
100 issues, so a day missing from it has no issue rather than an unread one.

### 2. The record schema (version 1)

| Field | Meaning |
|---|---|
| `v` | Schema version, `1`. |
| `id` | `d<yyyyMMddTHHmmssfff>-<6 hex>`. It carries its UTC day, so a reader finds a record by reading one day. |
| `ts` | UTC write time. |
| `kind` | `decision`, `tripwire`, `rating` (the owner's blind-sample verdict) or `outcome` (a later outcome of a decision). |
| `item` | The backlog item or PR the decision is about. |
| `seat`, `session` | Who decided. The seat defaults to the session's own declared seat in the seat registry. |
| `account`, `host` | The Claude config root's leaf and the machine name. |
| `class` | `A`, `B`, `C` or `D`, per plan R3. A tripwire is `C`. |
| `predicates` | `{name, evidence}` pairs: each state predicate checked this turn, and what the read showed. |
| `recommendation`, `alternatives` | The choice taken or proposed, and the others weighed. |
| `undo` | The named undo path. |
| `confidence` | The stated confidence, 0 to 100, or null. Logged, never used as a gate (plan R4). |
| `reviewed`, `reviewedBy` | `yes` or `no`, and by whom. |
| `outcome` | `pending` by default; `detected` on a tripwire; an `outcome` record's `reversed` is a reversal. |
| `ref` | On a `rating` or `outcome` record, the decision it refers to. |
| `rating` | `agree` or `disagree`, on a `rating` record. |
| `note` | Free text. A tripwire's note names the acts, never the command text, which can carry a secret. |

### 3. The kill switch

The repository Actions variable `MEFOR_AFK_KILL` on `MEFORORG/MessageFoundry`, read over REST with
`gh api repos/MEFORORG/MessageFoundry/actions/variables/MEFOR_AFK_KILL`. When it is ON, every class
reverts to ask-mode.

**It fails safe.** Only a read that returns exactly `off`, ignoring case and surrounding space, is
OFF. A missing variable, any other value, a gh error, no gh, or a read that does not finish inside
its timeout (10 seconds by default) is ON. `scripts/coord/afk-kill.ps1 -Status` prints the word.
`-Banner` runs at every SessionStart from `.claude/settings.json` and prints a loud banner, as a
`systemMessage` the owner sees and `additionalContext` the session reads, only when the switch is
ON. The read runs in its own runspace with its own timeout, so a hung gh cannot outlast the hook's
timeout and leave no banner, and a fault in the read prints the ON banner. A hook that
cannot start at all prints nothing: in a fresh cloud VM, pwsh does not exist until cloud-setup.sh
installs it, so the first session start there shows no banner whatever the switch says. When
the switch reads OFF, `-Banner` tells every session but a Special seat to load the `driver` and
then the `empower` skill (owner approval 2026-10-22). A seat nothing has declared yet gets it too,
and its text tells a Special seat to skip it, because a Special seat declares late. After a
SessionStart from `compact` or `clear` the text says to load both again, with no skip clause,
because a compaction may leave a summary saying both were loaded while their text is gone (not
measured here). From any other source, at least `startup`, `resume` and `fork`, it says to skip a
skill only if its full text is in context now, so a resume that kept both loads no second copy.
From every source it says an owner instruction in the conversation to stop using either skill
outranks it. Those three rules are this build's design inside the approval, and the owner may
overrule them at review. A fault on that path prints no instruction.

**The owner sets it, and nothing enforces that.** Every seat acts as the one shared GitHub
identity, which can write repository variables. The tripwire hook records a `gh variable
set|delete MEFOR_AFK_KILL` or a non-GET `gh api` call on its path; that is a record, not a block,
and a write by any other route leaves none.

**The variable does not exist when this merges, so every session reads ON until the owner sets
it to `off`.** That is the fail-safe reading, not a fault. Setting it is the one owner or Lander
step this ADR needs.

This slice reads the switch at session start only. The plan's *"read ... by every seat at turn
start"* is wave 2's driver rule, which calls `-Status`.

### 4. Tripwires: what a hook enforces, and what is a rule only

`scripts/hooks/afk-tripwire.ps1` runs under `shell-guard-dispatch.ps1` on every Bash and PowerShell
tool call. **It does not block, so this slice does not meet plan section 4.4, which says each
tripwire "stops the act".** The brief for this slice left blocking out. Most of these acts are not
denied by anything else either: the deny rules in `.claude/settings.json` match a few command
prefixes only, and the hook's header names forms they miss. The context reaches the session
with the call, so by the time it reads "stop" the act has run. What the hook gives is the record
and the reminder. Making it block is the change that would meet section 4.4; it is not built.

On a hit it spools a `tripwire` record through `decision.ps1 -NoPost` and returns
`additionalContext` telling the session the act is Class C. It makes no network call. A record
means the act was **attempted**: the hook runs before the permission rules, so a command they
then refuse is recorded too, with outcome `detected`. A command an earlier guard in the dispatcher
denied never reaches the hook and leaves no record. The dispatcher now passes every non-deny
guard's `additionalContext` through, after the kept `ask` or `allow` decision's own and then in
guard order, or alone when nothing decided, and says in it when a guard failed open on the same
call.
Its timeout rises from 60 to 75 seconds, the tripwire's 15-second share.

| Section 4.4 tripwire | In this slice |
|---|---|
| `--no-verify`, and the other hook bypasses the header lists | **Hook**: recorded and flagged, not blocked. |
| `--force`, `-f`, `--force-with-lease`, `--mirror`, a `+` refspec on push | **Hook**, not blocked. Some plain forms are also refused by the deny rules in `.claude/settings.json`. |
| A ref deletion by push: `--delete`, `-d`, `--prune`, a `:<branch>` refspec | **Hook**, not blocked. |
| `reset --hard` | **Hook**, not blocked. Some plain forms are also refused by the settings deny rules. |
| `-Force` on `remove.ps1` or `claim.ps1`; `-AllowOrphanedAllocations` | **Hook**, not blocked. |
| A write to `MEFOR_AFK_KILL` (not in section 4.4; added because any seat can write it) | **Hook**, not blocked. |
| A diff touching Class C paths | **Rule only.** No hook reads a diff. |
| The same permission denial twice | **Rule only.** No hook sees a denial. |
| `main` red for more than two hours | **Rule only.** |
| Two seats on one item | **Reported, not enforced**: the digest lists items with decisions from two sessions. |

What the hook does not see, at least: a script file that runs one of these acts, an alias or a
variable that spells the command, git plumbing that moves or deletes a ref (`update-ref -d`,
`branch -D`), and every tool other than a shell. A tripwire record is written only by the hook,
so a missing record proves nothing about an act the hook cannot see (SDS-3.7, SDS-3.10).

### 5. The digest

`scripts/coord/digest.ps1` builds one UTC day's digest from the log alone. It writes it to
`<git-common-dir>/mefor-coord/digests/<day>.md`, which only this machine reads and which is never
committed, and prints it. It holds plan section 4.8's list: decisions by class; the blind sample;
reversals and tripwire hits; the bundled open Class C questions; spend (not in the log, so the
section says so and points at `scripts/coord/usage.ps1`: designed, not built); collisions; Class D
commands; and a calibration table.

**The blind sample.** Class B decisions from the day, drawn at random and saved locally, so a
rerun shows the same sample. The target is 5 or 10 percent of the day's Class B decisions,
whichever is more, or N with `-Sample N`; each run keeps the saved draw and tops it up from
decisions logged since, so an early run does not freeze the day's sample. A decision with fewer
than two distinct options is never drawn, since its only option is the recommendation. Each
sampled decision
shows its options in an order fixed by a hash of its id, with no mark on the recommendation, and
without the confidence, the undo path, the review or the outcome. The day's decision list and the
reversals section leave the same things off a sampled decision until it is rated. `-Rate <id>
<agree|disagree|N>` records the owner's verdict as a `rating` record, and refuses a decision that
was not in the day's saved sample on that machine, whose recommendation was visible. N is the
option number the digest showed, compared with the hidden recommendation.

**Who rates is a rule, not a control.** Every seat writes as the one GitHub identity, so a rating a
session writes (`decision.ps1 -Log -Kind rating`, or `-Rate` on its own judgment) cannot be told
from the owner's. Plan R5 is what keeps ratings the owner's, and calibration is only as good as
that rule. Enforcing it needs an identity the sessions do not hold; it is not built.

**Calibration**, per seat and class, over the records `-Window` days back (60 by default): the
owner's disagreements on the trailing 60 rated decisions, calibrated at 60 samples with 3 or
fewer. After a breach, any trailing 60 with more than 3, the class stays on the review path until
60 ratings newer than the breach pass, as plan section 4.2 says. And the 14-day reversal rate, a
breach above 5 percent. A rating older than the window is not read.

**An unread vault is said aloud.** The digest is marked INCOMPLETE and exits 4, and `decision.ps1
-List` does the same, because an empty answer from an unread log looks like a quiet day. A local
spool file of a day read that cannot be read counts the same way, and the gate then answers
REVIEW.

### 6. Cloud sessions

`decision.ps1` and `digest.ps1` refuse in a cloud session, with the coordination scripts' one
refusal line, and join the census in `tests/test_coord_cloud_refusal.py`. `afk-kill.ps1` reads no
local coordination state and runs there too, because the switch must hold everywhere. In a cloud
session the tripwire hook still adds its context, and says that the session's Manager logs the act.

## Acceptance Criteria

- **AC-1** -- WHEN a session logs a decision, THE SYSTEM SHALL post one comment carrying the full
  schema to the vault issue for its UTC day, creating the issue once.
  -> `tests/test_afk_decision_log.py::test_log_posts_one_comment_to_the_days_issue_with_the_full_schema`
- **AC-2** -- IF the post fails, THEN THE SYSTEM SHALL keep the record spooled, say so, exit 4, and
  post it on the next flush.
  -> `tests/test_afk_decision_log.py::test_a_failed_post_keeps_the_record_spooled_and_says_so`
- **AC-3** -- IF the vault cannot be read, THEN `-List` and the digest SHALL say INCOMPLETE and
  exit 4.
  -> `tests/test_afk_decision_log.py::test_list_says_incomplete_when_the_vault_cannot_be_read`,
  `tests/test_afk_digest.py::test_an_unread_vault_marks_the_digest_incomplete`
- **AC-4** -- IF the kill switch is missing, unreadable, hung, or set to anything but `off`, THEN
  THE SYSTEM SHALL read it as ON.
  -> `tests/test_afk_kill_switch.py`
- **AC-5** -- WHEN a shell command carries a section 4.4 act the hook detects, THE SYSTEM SHALL
  spool a tripwire record with no network call and tell the session the act is Class C, without
  blocking it.
  -> `tests/test_afk_tripwire.py::test_a_hit_is_spooled_as_a_tripwire_record_with_no_network`
- **AC-6** -- THE SYSTEM SHALL show the blind sample without marking the recommendation, and SHALL
  map an option number back to agree or disagree.
  -> `tests/test_afk_digest.py::test_the_blind_sample_hides_the_recommendation`,
  `tests/test_afk_digest.py::test_rate_by_option_number_compares_with_the_hidden_recommendation`
- **AC-7** -- THE SYSTEM SHALL report a seat and class as calibrated only at 60 rated samples with 3
  or fewer disagreements, and SHALL flag a 14-day reversal rate above 5 percent.
  -> `tests/test_afk_digest.py::test_sixty_rated_samples_calibrate_at_three_disagreements_or_fewer`,
  `tests/test_afk_digest.py::test_the_fourteen_day_reversal_rate_breaches_above_five_percent`

## Options considered

1. **Vault GitHub Issues, one issue per day, one comment per decision.** Private, because the vault
   is. Every account on every machine reads it as the one shared identity, over REST. A comment is
   one atomic write that needs no merge, and two writers never conflict. An edited comment keeps
   its edit history on GitHub, and a deletion needs a repository writer, so it is append-only in
   practice, not by construction. Costs: one REST request per record from the shared budget, about
   two per day read, and the network. The local spool answers the network cost. **CHOSEN.**
2. **A JSONL file in the vault.** Private and reachable over REST, and git history keeps every
   version. But each append is a commit and a push to a repository many seats write, so two
   writers race: the contents API's `sha` precondition makes the second fail and retry, and a
   clone-and-push path conflicts outright. A decision log written several times an hour by
   several seats would spend its effort on merges. Rejected.
3. **A local file under `.git/mefor-coord`.** Fast, private and offline, and every account on one
   machine reads it. It is not reachable over REST, it is per machine, and any session can rewrite
   it with no history. Rejected as the store; it is kept as the spool in front of option 1.

## Consequences

**Positive.** The controls exist before any autonomy widens, as the plan orders. A record survives
a network failure. The tripwire hook adds no network call and no process to a shell call that
trips nothing, because it runs inside the dispatcher's process.

**Negative and open.**

- The log is append-only in practice only: anyone with write access to the vault can edit or
  delete a comment, and GitHub keeps the edit history but not a deleted comment.
- The trailing 60 is read within a 60-day window. At fewer than one rated decision a day per seat
  and class, older ratings fall out of it.
- Spend is not in the digest; it says so.
- No tripwire blocks, so section 4.4's "stops the act" is not met. Tripwires for Class C paths,
  repeated denials and a red `main` are rules only (section 4).
- Rating authorship and kill-switch authorship are rules only: every seat holds the same identity.
- A cloud session reads the kill switch only if its GitHub proxy grants the variables read. If
  not, it reads ON, which is the safe side.
- The issue listing grows by a page every 100 days of log; a reader reads every page.
- The digest reads each day's issue in turn: about one request per day of `-Window`, once a day.
  A local cache of past days' comments would cut that; it is not built.
- On a kill-switch read that times out, the hung `gh` child is left to finish on its own.

## Steps outside this change

- **Owner or Lander:** set the repository variable to `off` when autonomy may proceed:
  `gh variable set MEFOR_AFK_KILL --repo MEFORORG/MessageFoundry --body off`. Until then every
  session prints the ON banner. Setting it is a live repository settings change, so this build
  does not make it.
- After the merge, sessions pick up the new SessionStart and PreToolUse wiring from the primary
  checkout's `.claude/settings.json` on their next start.
- **Lander: re-run the gate installer on each account**, from an up-to-date `main`:
  `pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -ConfigDir <account config root>`.
  This change edits `shell-guard-dispatch.ps1`, and an account's own shell entry stands down only
  for the dispatcher copy the installer pinned, so until the re-install the worktree gate runs
  twice on every shell call (`install-gate.ps1 -Status` reports it as NOT CURRENT).

## Amendment 2026-10-26: gate, reversal budget, chain limit, cost rung

Builds plan section 4 items 5 to 7, with R4's bar for acting without review. Plan section 10
puts the no-review path itself in wave 5, as calibration passes; this builds the check that path
must pass, so it exists before anything depends on it. The design is this build's inside the
owner's 2026-10-21 approval of the plan, and the owner may overrule it at review.

### The gate

`scripts/coord/decision.ps1 -Gate -Item <item> [-Seat <seat>] [-BuildsOn <id>]` answers which path
a Class B act may take, as one word: **NO-REVIEW** (exit 10), **REVIEW** (exit 11) or **HALT**
(exit 12). None is 0 or 4, so a crash (1), a usage error (2), the cloud refusal (3) or "spooled"
(4) never reads as permission. NO-REVIEW is necessary, not sufficient: plan R4 also needs a single
revert or PR close to undo the act, no Class C path touched, and live state read this turn, which
the gate cannot see, so the session still checks those. The script's header lists the gate's own
conditions; in short, NO-REVIEW needs all of them:

- the kill switch reads exactly OFF;
- the seat's Class B is calibrated, by the digest's own arithmetic, which now lives in one shared
  function (`Get-DecisionCalibration` in `_decisionlog.ps1`) that both scripts call;
- no decision on the item was reversed, among the records the gate reads (60 days, the digest's
  default window);
- the reversal budget is open;
- the chain is no deeper than two;
- the cost rung is not hit.

**It fails closed.** A log that is not fully read, a seat that cannot be named, a decision a link
or a reversal names that the log does not hold, an unreadable thresholds file, and any error inside
the gate all answer REVIEW. It checks the cost rung first and the kill switch second, and stops at
the first that closes the no-review path, so a REVIEW for the kill switch reads no log.

**Today it answers REVIEW (or HALT) for every seat**, because no seat has 60 rated samples.
`tests/test_afk_gate.py` pins that, and pins NO-REVIEW for a calibrated seat with nothing against
it, which every other test starts from.

### Reversal budget (4.5)

An `outcome` record with outcome `reversed` is one reversal, deduplicated by its ref, dated by the
earliest such record; a decision whose latest outcome is something else is not one, as the
calibration reads it. It is charged to the seat of the **decision** it refers to, joined through
the ref, never to the seat that logged the outcome. Three inside any 24 hours close the no-review
path for every seat, and two of one seat's decisions close it for that seat, in each case for 24
hours from the reversal that reached the limit. A reversal whose id is dated after now, by a
clock running ahead, counts as now, and so does such a decision in the chain floor below; the gate
also reads tomorrow's day for them. A reversal of a decision the log does not hold has
no seat; it counts against every seat's budget, and for the item rule it closes the path for any
item, since its item cannot be told.

### Chain limit (4.6)

`-Log` takes `-BuildsOn <id>`, split at newlines like `-Predicate`, and the record schema gains
two fields, still version 1: `buildsOn`, the ids, and `gate`, the gate's answer on an unreviewed
Class B record (empty otherwise; `PENDING` until the gate answers). A reader fills both for an
older record. Depth is the unsampled
(never rated) Class B decisions on the same item reachable through `buildsOn` links, and never
less than the unsampled Class B decisions on that item logged in the trailing 24 hours. The floor
exists because `-BuildsOn` is self-reported: a session that names nothing still meets it. More
than two goes to review. The walk stops at a decision the owner rated, which ends the unsampled
chain. A record the gate answered HALT for was deferred, not acted on, so it does not count.

### Cost rung (4.7)

The gate reads `scripts/coord/usage.ps1 -Json` in a child pwsh, for the 5-hour window only: a
weekly rung names a severity and stops nobody (korus `roles/STEWARD.md` 3a). The start-nothing
rung is HOLD NEW WORK, STEWARD.md section 3's 20 minutes to cutoff and 80 percent, unless the
Steward's `thresholds.json` beside its `watch.py` overrides them as `watch.py` reads it. That file
names the window `5-hour`, not `five_hour`.

**The burn rate governs, which the brief for this build did not say.** STEWARD.md 9.6a records an
owner ruling of 2026-08-14 that a level fires the protect half and does not stop new work when the
rate says there is room. So with a rate, the rung is hit when the window is projected to run out
within 20 minutes and before it resets. Only with no rate is 80 percent the backstop. A window at
98 percent or more, `usage.ps1`'s own "at the ceiling" band, is hit whatever the rate: a flat rate
there says there is no room. `usage.ps1` skips its check of the statusLine's wiring when it reads
CRITICAL overall, so a CRITICAL reading the gate grades below the rung is UNKNOWN. A reader that
does not finish within 30 seconds is UNKNOWN. A window graded HIT stays HIT whatever
`usage.ps1` reads overall, because downgrading a hit would fail open.

At the rung the answer is HALT. A 5-hour reading `usage.ps1` calls UNKNOWN, or an overall UNKNOWN
below the rung, answers REVIEW, not HALT:
UNKNOWN is common, because a Desktop session runs no statusLine, and halting on it would shut the
gate for good. The Steward's `status.json` fallback, which `usage-headroom-inject.ps1` prints for
such a session, is **not read**. Reading it would mean a third copy of `watch.py`'s pool rules. So
a Desktop session at the rung gets REVIEW, not HALT; that gap is open. The Lander is exempt from
HALT and from the rung entirely, as STEWARD.md 3e exempts it from all three states, and so is a
roster alias of the Lander.

### Where it is enforced, and where it is not

**`-Log` is the enforcement point.** A `decision` record of Class B with `-Reviewed no` is spooled
first with `gate` `PENDING`, so the log keeps its rule that every record is spooled locally first.
The gate then runs, skipping that record's own id, and its answer replaces `PENDING` in the
spooled copy; a flusher leaves a `PENDING` record younger than ten minutes alone, so it is not
posted first. A gate that crashes or hangs loses no record, and a record left `PENDING` counts
toward the chain floor. The record is posted whatever the answer. When the answer is not
NO-REVIEW, `-Log` prints `GATE <word>` and the reasons, and exits 11 or 12 in place of 0 or 4. The
`LOGGED` line still says whether the record was posted. Under `-NoPost` the gate reads no network,
so it can answer HALT or REVIEW but never NO-REVIEW. A reviewed record is not gated, because its
review has already run; a session that wants the rung before spending a review runs `-Gate` first.
**`-Log` stops an act only when the log comes before it.** The empower skill, as read on
2026-10-26, says to log each decision and not when, so a session following it should run `-Gate`
before it acts. Making the skill say so is a skill edit, outside this change.

**At least these do not call `-Gate`:** the spawn hooks, `wait-pr.ps1`, and the driver and empower
skills. None of them halts on the cost rung, so plan 4.7's *"spawning, polling ... halt"* is
**designed, not built**. The gate also enforces nothing against a session that does not log, or that logs
`-Reviewed yes` without a review: like the rest of this ADR, it is a check a cooperating session
meets, not a boundary.

### The digest

`digest.ps1` gains two sections. **Gate state**: the fleet budget, the cost rung on the account the
digest ran on (today's digest only, since it is a live reading), each seat's budget and whether its Class B is calibrated, and each item past the
chain floor, all from the gate's own functions. **The attic**: every `refs/attic` ref on this clone
with its age, as a Class C prune question (plan 6.3). The digest deletes nothing.

### Cost

A gate that reaches the log reads about one REST request per UTC day in the 60-day window that
has an issue, plus the listing: the digest's read, once per unreviewed Class B record. It is not
cached; the cache that Consequences names for the digest would cut both.
