# 0211 -- AFK-autonomy controls: decision log, kill switch, tripwires, digest

- **Status:** Accepted (2026-10-21, on build). The owner approved docs/AUTONOMY-PLAN.md, whose
  section 4 requires these controls, on 2026-10-21 (branch `autonomy-plan`, commit `18fbca9c2`).
  The storage choice, the schema and the enforcement split below are this build's design inside
  that approval; the owner may overrule them at review.
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
posts it. `-NoPost` spools with no network at all, which the tripwire hook needs.

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
then the `empower` skill (owner approval 2026-10-22). A fault on that path prints no instruction.

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
-List` does the same, because an empty answer from an unread log looks like a quiet day.

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
