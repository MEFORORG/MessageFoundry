# Role cards: giving a worktree a seat that outlives its session

Design doc and build record. Written and built 2026-09-05. Re-measured against the shipped code
2026-09-18.

**Status: MERGED.** `b3c1ddff7` (PR #895) landed this document and a SessionStart wiring;
`1584742b2` (PR #970) landed the roster, the cards, the hook and the tests, and a **second**
wiring; `cbb63ad28` (PR #1030) rewrote parts of it when the owner retired the Console. Two commits
each wiring the same hook is why `origin/main` ran it twice at every session start for 13 days.
That is fixed, and section 7 carries the tests that pin it.

**This file is three genres and only one of them keeps itself true. Read the labels.**

| Part | What it is | How much to trust it |
|---|---|---|
| Sections 1 to 8 | The design as approved, plus later corrections | Current as of 2026-09-18 |
| Section 9 | A dated record of the 2026-09-05 build | True of a feature branch, and nothing re-derives it |
| Any count | A measurement, with its instrument and cut named beside it | Re-run the command; do not quote the number |

**That last row binds this file, and it caught this file.** The 2026-09-18 pass quoted korus
`roles/LANDER.md` at 1,231 lines; korus moved 53 seconds later and it is 1,239 at tip `ff11047`.
The worktree census below read 113 entries at 11:52 and 117 ninety minutes on. Every count here
therefore names its instrument and its cut, and several were replaced by the command instead.

Two build-time divergences are marked "Amended during the build" in place. Sections 2.2, 3 and 4
were additionally rewritten on 2026-09-11 by `cbb63ad28` with no marker of any kind, and one of
those silent edits introduced a false claim about the Regulator's playbook that stood until
2026-09-18. The promise in the original of this paragraph -- that nothing would be corrected
silently -- was not kept.

A session is told its role in its first message. That works for the conversation and dies with it.
This design binds the role to the **worktree** instead and injects the seat's rules at session
start. Section 8 records what the emission shape actually is.

---

## 1. The problem, measured

Every seat record in `<git-common-dir>/mefor-coord/seats/` was counted on 2026-09-05.

| Box type | Records | Carry a role |
|---|---|---|
| Subagent boxes | 25 | 25 (100%) |
| Worktree sessions | 968 | 145 (14%) |
| Worktree sessions, last 7 days | 380 | 49 (12%) |

Worktree sessions sat at 12% because a person says it out loud. The gap was not effort. It was who
writes it, and the slice for the week to 2026-09-05 showed no improvement.

**Recounted 2026-09-18.** Instrument, once, for all three rows: records under
`<git-common-dir>/mefor-coord/seats/`, split on the `agent-` prefix of the **box key**, seated
meaning a non-empty `seat` field, the window being `asOf >= 2026-09-11T00:00:00Z`. The boundary
changes the answer by about three points either way, so it is stated rather than implied. 0 of
1,669 records were unreadable at that cut; the corpus grows hourly.

| Box type | Records | Carry a role |
|---|---|---|
| Boxes named `agent-*` | 87 | 87 (100%) |
| All other boxes | 1,582 | 312 (19%) |
| All other boxes, `asOf >= 2026-09-11` | 461 | 121 (26%) |

The rate roughly doubled, so "not improving" no longer holds. It is not evidence for this design: a
SessionStart declare-prompt hook shipped in between, and of the 399 seated records 398 read
`seatSource: declared`.

**The 100% row is true by construction and the two rows are not comparable populations.** Every
`agent-*` record has `asOfSource: cli:Declare` -- it exists *because* somebody ran
`seat.ps1 -Declare`, and that one invocation both creates the record and sets the seat. A subagent
that never declares contributes no record, so the denominator cannot hold an unseated row. The
other boxes are written by four paths (`cli:other`, `hook:Stop`, `cli:Declare`, `cli:Close`) and so
have a real denominator. The split is also a proxy for the worktree's NAME, not for what a session
is: the record's `kind` field that would answer it is null in every record, and a subagent without
worktree isolation writes into its parent's box. Of the 398 `declared` records, 87 sit in `agent-*`
boxes, so at most 311 are a person typing.

**The labels drift as well.** 46 distinct role strings appeared on worktree boxes for a five-seat
roster, including eight spellings of one seat: `builder`, `Builder`, `BUILDER1`, `BUILDER2`,
`builder1`, `builder2`, `builder-2`, `builder3`. Ten records declared seats that section 5 of
`CLAUDE.md` had retired.

Recounted 2026-09-18: **at least 58 records across 9 retired labels** -- asvs-tracker 12,
dispatcher 11, liaison 10, console 9, cleaner 6, pm 5, process-improvement 3, role-manager 1,
consul 1. "At least", because the count is over the labels `seats.json` knows; an unmapped one is
invisible to it. Twelve of those were invisible until this pass: **`asvs-tracker` was in no map at
all**, so one of section 5's own seven retirements resolved to the "MATCHES NO SEAT" typo branch
and read as a misspelling. It is now in `retired`, and
`test_every_seat_section_5_retired_resolves_to_a_retirement` pins the seven as a set, because
iterating whatever the file happens to contain cannot notice an omission.

**Three costs followed.**

1. A session that compacts loses the role, because a first-turn instruction is an ordinary user turn
   competing with everything else.
2. Two Builders get different rules, because the rules are whatever the spawner typed.
3. No instrument could group by seat, because 46 labels do not group.

The third is partly closed, and not by this design. `scripts/coord/seat.ps1` resolves a declared
label against `docs/roles/seats.json` and writes `seatCanonical` and `seatRosterVerdict` beside the
raw seat. Measured 2026-09-18: 209 records carry the `seatCanonical` **key** and about half carry a
**value**, the rest recording `seatRosterVerdict: none`. Only a `-Declare` pass resolves a label,
and a later write assigns the field from that pass's own resolve with no carry-forward
(`seat.ps1:763-764` against `:766`), so a `hook:Stop` write clears the grouping key while
preserving the raw label -- six seated records already hold a null canonical. Grouping is available
for a declaration, not for every record written since.

---

## 2. What gets built

Four pieces. Each is small and can be read on its own.

### 2.1 The marker: `.claude/seat.local.txt`

One file in the worktree root holding one lowercase word.

```
builder
```

It is git-ignored. Measured with `git check-ignore`: `/.claude/*` is ignored and the `.gitignore`
permits negating only `settings.json`, so a marker **at the worktree root** can never dirty a tree
or ride into a commit. `CLAUDE.local.md`, `ROLE.md` and `docs/ROLE.md` were all tested and would
show as untracked, which is why none of them is used.

**The ignore rule is root-anchored, so that guarantee does not travel.** A nested spelling such as
`docs/.claude/seat.local.txt` is not ignored -- measured with `git check-ignore`, which reports
IGNORED for the root path and not-ignored for the nested one. The hook resolves the marker against
its `-WorktreeRoot`, so the wiring passes the project directory explicitly and the remedy the hook
prints must be run from the root. `TheMarkerCannotRideIntoACommit` checks only the root-relative
path.

**Both this file and the injected `.claude/ROLE.local.md` are git-ignored, so they DECAY, and their
absence dates nothing.** A worktree refresh destroys them while the tracked wiring survives. Do not
read a zero count of either as evidence that nothing ever happened -- section 6 made exactly that
mistake, and section 8 records the history that refuted it.

It belongs to the worktree, not to a session. Sessions come and go inside a worktree; the marker
survives a crash, a compaction, an account switch, and a respawn. It does **not** survive the
worktree -- see section 6, where that turns out to be the whole problem.

### 2.2 The cards: `docs/roles/<seat>.card.md`

One tracked file per live seat. Six of them: Manager, Builder, Watchdog, Steward,
Lander, Special. (At the time of writing the first name was Console; the owner retired that seat on
2026-09-10 and the Manager replaced it, BACKLOG #1529. The third name was Regulator until
2026-09-19, when the owner retired it and added the Watchdog; the Watchdog is an addition and
**not** its successor. One further seat was retired on 2026-09-05 and is deliberately not named,
here or anywhere else in this repository -- owner instruction 2026-09-16.)

Each card is capped at **150 lines and 6 KB**. One card is selected per session and the hook must be
wired exactly once, so a session pays for one card: roughly 700 tokens for the smallest and 1,250
for the largest, plus about 70 for the hook's own banner, against the 72 KB `CLAUDE.md` already
loaded. The 6 KB cap bounds it at about 1,540. (No tokenizer is installed here, so those are
characters-over-four estimates, not measurements.) Sizes at 2026-09-18: special 116 lines and
5,992 bytes, manager 103 and 4,970, builder 91 and 4,649, lander 78 and 3,370, regulator 72 and
2,955, steward 68 and 2,801.

**Measure the cap the way the checkout will.** `core.autocrlf=true` here, so a card authored at
6,120 LF bytes arrives as 6,241 and reds the Windows leg alone. `special.card.md` hit exactly that.
At 116 lines it has 116 bytes of headroom spent on line endings, leaving it 36 under the cap.

Every card carries the same seven sections, and the Manager's carries an eighth. Six are pinned by
`tests/test_role_cards.py`, and pinned now means **as a heading**:

| Section | Holds | Pinned |
|---|---|---|
| What this seat owns | The work only this seat does. | yes |
| What it must not do | Prohibitions, each with the reason it exists beside it. | yes |
| Its authority | What it may do without asking. | yes |
| On arrival | The checks it runs before its first change. | yes |
| The full playbook | The korus path, and the rule that a card carries nothing that expires. | yes |
| You are not a renamed Console | Manager only. Why a Console rule does not transfer. | yes |
| Before you claim it works | The verification the seat owes before it reports done. | no |
| What this seat does not own | The adjacent work that belongs to another seat. | no |

*The Console section is pinned by `test_the_manager_card_denies_the_rename_too`, which asserts the
string "not a renamed Console" -- and that string occurs exactly once in the card, as that very
heading. The five required sections were pinned as bare SUBSTRINGS anywhere in the file until
2026-09-18: renaming all five headings while leaving the phrases in prose kept the suite green, so a
card could lose every section as structure and pass. They are matched as `## <heading>` now.*

No shipped prohibition carries an expiry condition, and all but one carry the reason or the
consequence beside it. The Builder's `**Spawn another session.**` is the bare one. No card's
authority section says what needs the owner. The note that a card is a summary is in each card's
preamble, not in its playbook section.

Cards inherit the rule korus's `roles/README.md` is built on: **a card carries nothing that
expires.** Live state -- open queues, item numbers, who is blocked on whom -- belongs in a dated
episode note. That folder paid for this rule twice: a standing "do not install" instruction inverted
when the held fix merged, and a "no new lanes" freeze cited twice as authority that had never been
issued.

**Cards live in the engine repo, not in korus and not in the vault.** The hook runs inside an engine
worktree, and both other clones may be absent beside it. Cards hold no ASVS content and no security
specifics, so nothing vaulted moves. A card may name the vault as a repository and say which seat
works in it -- the Lander's standing authority, and since 2026-09-23 the Manager's ASVS record work
-- but it names no cell.

### 2.3 The hook: `scripts/hooks/role-card-inject.ps1`

Wired once at `SessionStart` in `.claude/settings.json`, beside `seat-declare-prompt.ps1` and
`precompact-reprime.ps1`, passing `-WorktreeRoot ${CLAUDE_PROJECT_DIR}`.

It resolves the seat, reads that card, and injects it. It also writes the resolved card to
`.claude/ROLE.local.md`, git-ignored, so a session can re-read it after a compaction. **That write
is not proof of an injection either way:** it sits in its own try/catch that prints and falls
through, so the card is injected whether or not the copy lands.

**Resolution order, highest first:**

1. `.claude/seat.local.txt` in the worktree root.
2. `$env:KORUS_SEAT`.
3. Nothing. The hook injects no card and prints the one command that sets the marker.

**Amended during the build: a fourth rung reading the seat record was designed and then dropped.**
It would have fired only where a session had declared a seat but nobody had written a marker, and in
that state the next session is no more likely to have one. The cheaper end state is to have
`seat.ps1 -Declare -Seat` write the marker, which collapses that rung into rung 1. That is still not
built, and section 6 is the measured cost of leaving it unbuilt.

**It never guesses from a branch or directory name.** A worktree name is a creation-time label that
nothing keeps current, and this repository has one whose name describes a question its session
answered in its first two minutes. A card is injected before the session has read anything, so a
wrong card outranks the document that would correct it. Silence costs one printed line. The class
`TheHookNeverGuessesASeat` pins both the behaviour and the absence of any branch read in the hook
source, through `test_the_hook_reads_no_branch_or_directory_name` and
`test_the_hook_resolves_only_the_marker_and_the_variable`.

*The reasoning above used to be cited to section 5 of `CLAUDE.md`. That pointer does not resolve:
searched 2026-09-18 with a positive control on the same grep, `CLAUDE.md` contains none of
"creation-time", "keeps current", "worktree name" or "worktree label". The argument is sound and is
stated here in full instead.*

**No path through its body fails a turn.** All nine of its `exit` statements are `exit 0`, as
`seat-record.ps1` and `seat-declare-prompt.ps1` already do, and `test_every_exit_in_the_hook_is_zero`
pins that no literal `exit N` is non-zero. Two limits on that guard, because it was previously cited
for more than it carries: it does not pin the COUNT, so a tenth exit added tomorrow is green; and it
cannot see a failure that skips the body. Parameter binding is the real one -- given an undeclared
parameter the hook exits 1 with no stdout at all, before any `exit 0` can run.

### 2.4 The label map

Four maps in `docs/roles/seats.json` -- `live`, `aliases`, `retired` and `elsewhere` -- classifying
the non-canonical strings, plus a rule that an unmapped string resolves to nothing. Only the
**aliases** resolve *onto* a seat: the `retired` and `elsewhere` strings resolve to an explanation
and no card. Seven Builder aliases collapse to `builder`, and the hook lowercases first, so all
eight spellings section 1 lists resolve.

A retired seat resolves to no card and prints the date and reason stored in `seats.json`. **It names
no governing section** -- no retirement reason contains one, and only the `elsewhere` branch cites
`CLAUDE.md` section 5.

`elsewhere` is for a seat a session may hold in korus that this table does not run. **It is empty
today, and empty is the correct state**, not an unfinished edit -- its one occupant was removed on
2026-09-16 by owner instruction. The branch stays in both scripts, exercised against an injected
roster, so refilling the bucket is not a silent no-op.

---

## 3. Who writes the marker

Four ways worktrees are actually made here, bucketed by path shape. The uptake column is measured
2026-09-18 at 11:52 -0500, 13 days after the merge; `git worktree list --porcelain` reported 113
entries at that cut and 117 ninety minutes later, so re-run it rather than quoting this.

| Path | How the marker gets written | Uptake |
|---|---|---|
| The harness worktree feature | The owner or the dispatching Manager runs the command below. | 1 of 49 |
| The Agent tool's worktree isolation | **Not covered.** | 0 of 24 |
| `scripts/worktree/new.ps1` | The same command, after creation. The script writes nothing itself. | 0 of 24 |
| A scratchpad or temp checkout | Nothing writes one. | 0 of 15 |

**The subagent row was wrong, and it was wrong in the way that matters.** The original read
"Already covered. The Agent tool sets the seat mechanically, at 100%." Two instruments are
conflated there. The Agent tool writes the seat into the **coordination registry**, which is still
at 100%. The hook reads neither that registry nor anything it writes -- only
`.claude/seat.local.txt` and `$env:KORUS_SEAT`, and it contains no reference to `mefor-coord`. So a
subagent is covered for seat **declaration** and not for card **injection**, which is the mechanism
this document builds. It gets silence. The 24 `agent-*` worktrees also sat inside the harness row's
count in the previous version of this table, which counted them twice.

**Amended during the build: `new.ps1` gains no `-Seat` parameter in v1.** It creates sibling
worktrees only -- 24 of the 113 at that cut, against 49 from the harness feature -- so the parameter
would serve the minority path. The single `Set-Content` line below covers every path, and the hook
prints that same line when no marker is set.

`spawn.ps1` is deliberately untouched. It opens VS Code at the worktree and never launches Claude,
so it has no session to hand a role to. The marker works for it anyway because the marker lives in
the worktree, not in the launch.

One command sets it by hand, from the worktree root:

```powershell
Set-Content .claude/seat.local.txt 'builder'
```

---

## 4. The roster, and which document governs it

Six seats: **Manager, Builder, Watchdog, Steward, Lander, Special.** That list comes from
section 5 of `CLAUDE.md`. The **Special** seat joined 2026-09-16 by owner decision, for work
outside the other five; it is an addition, and nothing retired to make room for it. A different
sixth seat existed until 2026-09-05, when the owner retired it along with the `reviewed` label and
the review gate; it is deliberately unnamed. The **Console** held the Manager's place until 2026-09-10,
when the owner retired it; the Manager is its replacement and **not a rename of it**, so a Console
rule does not carry across (BACKLOG #1529).

The **Regulator** held the third row until 2026-09-19, when the owner retired it. **Nothing replaced
it, and no seat attributes a red now.** The **Watchdog** joined the same day and is an addition
rather than a successor: it measures whether reds are being cleared and never says whose one is. The
two moves are recorded separately here on purpose, because reading them as one rename is the error
that would send a red to a Watchdog and wait for a verdict it does not issue.

*Section 4 above states that the retired sixth seat is deliberately unnamed. An earlier draft of
this document named it while correcting a related error, and `docs/roles/seats.json` carried the
name in a retirement entry. Both are removed: owner instruction 2026-09-16 is that the seat is not
named anywhere in this repository. The fact the correction was for -- that the seat existed HERE and
was retired HERE, rather than being a roster difference with korus -- survives in section 4 without
it.*

**The vault's `roles/README.md` disagrees, and it is the stale one.** Its table still
lists Dispatcher, PM, Liaison, ASVS Tracker, Cleaner, Role manager and Process
improvement as live seats, and it says of itself that it is a partial list. Section 5
settles this directly: a document naming a retired seat is stale, and section 5 wins.

**korus `roles/README.md` names the seven seats retired on 2026-09-01 in prose, and its live table
is current.** That table runs six seats: the five here plus a **Special** seat the owner added on
2026-09-16 as an addition, not a replacement. Section 5 still settles the roster for this
repository: it is the **naming** of a retired seat that goes stale, not the whole document that
names one on purpose, so the cards follow section 5's six.

*The 2026-09-18 pass claimed that README "opens with a STOP banner", puts the seven in "one row
marked RETIRED", and that "the whole table is superseded". All three were false. Checked with the
pickaxe over the file's whole history at tip `ff11047`, with controls: "STOP" appears in 0 commits
touching it, while "RETIRED" appears in 4 and "seat" in 7, so the search ran. The error mattered
past accuracy -- a reader told the table was superseded would discard a current six-seat roster and
never learn korus runs a Special seat this one does not name.*

So the cards are written against section 5's roster, drawing on the korus `roles/` playbooks for the
seats that survived. The playbooks moved there from the vault on **2026-09-02** (`a3df144`, which
also added `roles/README.md`; korus itself was initialised 35 minutes earlier). 2026-09-04 is the
separate, later owner ruling that they are READ at `origin/main` -- conflating the two dates the
move two days late, which this document and a test docstring both did.

**Every live seat has a korus playbook, and all six cards cite one.** Measured at korus
`origin/main`, tip `efd7b42`, 2026-09-19: `roles/SPECIAL.md` 248 lines, `roles/WATCHDOG.md` 398,
`roles/MANAGER.md` 459, `roles/BUILDER.md` 1,077, `roles/LANDER.md` 1,500, `roles/STEWARD.md`
1,545. Control, run the same way so it can fail on its own: `roles/NOTASEAT.md` returns 404.

**A retired seat's playbook is not absent from korus, it is under `roles/retired/`,** and reading
"no top-level file" as "no file" gets that backwards. `roles/retired/` holds ten files at
`efd7b42`, `REGULATOR.md` among them. korus keeps them so a reader who remembers a seat finds it
retired rather than missing.

*Two earlier passes said the Regulator had no playbook at all. Both were wrong, and the second is
worth naming because it survived a review. `roles/REGULATOR.md` sat at the TOP LEVEL of korus
`roles/` while the seat was rostered here -- 27,170 bytes at tip `ff11047` on 2026-09-18 -- and the
2026-09-19 retirement MOVED it to `roles/retired/`. So "the Regulator was the one that did not have
a playbook" is false, and so is the narrower "it had no file in the live `roles/` folder while it
was rostered here". The file moved; it was never missing.*

List the korus `roles/` folder rather than typing a filename from memory. The seat set moves, and a
missing playbook is the quietest failure here, because an absent file reports nothing at all.

---

## 5. What this does not do

- **It does not make a session obey.** It makes the rules present. That is the same honest limit
  `seat-declare-prompt.ps1` states about goals: a machine that invents one writes a record that
  looks declared and says nothing.
- **It does not touch the root `CLAUDE.md`.** No section moves and no line is added. The consequence
  is worth stating: `CLAUDE.md` names neither the cards, the hook, nor the marker, so a session
  reading it alone learns nothing about this mechanism.
- **It does not replace the seat declaration.** `seat.ps1 -Declare` still carries the goal, which no
  machine can write. The marker carries the role, which one can.
- **It does not compete with nested `CLAUDE.md` files.** Those scope by directory. A Builder and a
  Lander editing the same folder need different rules, so directory scoping cannot carry a seat.

---

## 6. Rollout, and the prediction that failed

The hook is wired in the tracked `.claude/settings.json`, so a worktree gets it only once its branch
contains that commit.

Measured 2026-09-05 against `origin/main` at `16efb8cde`: of 20 live worktrees, 5 contained the tip
and 15 were behind it. The position taken then was **no backfill** -- worktrees turn over fast
enough that adoption settles on its own, and 216 of 233 were reaped that day.

**That was wrong, and the mechanism runs the opposite way.** Measured 2026-09-18 at 11:52 -0500 over
the 113 worktrees `git worktree list --porcelain` reported at that instant. Re-run it; it read 117
ninety minutes later.

| State | Worktrees |
|---|---|
| Wire the hook **twice** | 103 |
| Wire the hook once | 1 |
| Have a `settings.json` without the hook | 4 |
| Have no `settings.json` | 5 |
| Hold a marker | **1** |
| Hold the injected `.claude/ROLE.local.md` | 0 |

**Effective adoption was 0, because marker and wiring had an empty intersection.** The single
marker-holder was also one of the five worktrees with no `settings.json` -- its marker was written
at 11:13 and its `settings.json` did not exist until 11:57 -- so nothing in the fleet could have
injected a card from a marker at that cut. Either figure is below the 12% section 1 measured as the
problem.

Turnover distributes the **hook** and destroys the **marker**, because they sit on opposite sides of
`.gitignore`. The wiring is tracked and rides the commit. The marker is git-ignored, so it is
worktree-local and dies with its worktree. Every recreated worktree is therefore born with the hook
and without a seat, and nothing shipped writes a marker: `new.ps1` has no `-Seat` and
`seat.ps1 -Declare` does not write one.

Turnover also distributed a defect rather than a fix. 103 of the 104 wired worktrees **ran the hook
twice**; with no marker that doubles its no-seat note, not a card. Where a marker existed the card
itself doubled: worktree `manager-112d2a` holds two injection records 17 milliseconds apart,
5,203 characters each, so that session paid 10,406 for one card.

*The 2026-09-18 pass wrote "No surviving worktree has ever had a card injected", from the zero in
the table above. The reading was right and the sentence was not: "ever" is a claim about nine days
of history that a present-tense file count cannot make, and the justification offered -- that the
hook writes the copy on every successful injection -- is false in the source (section 2.3). Both
files are git-ignored and decay.

Scanning the transcript corpus refutes it. Instrument: every `*.jsonl` under `projects/` in each of
the machine's six Claude config roots -- glob `$HOME/.claude*/projects` -- 26,531 files, searched
for the banner `[role-card] SEAT:`, **excluding this session's own transcripts**. Measured
2026-09-18:
**84 injections across 20 distinct worktrees.** Three are still registered -- `manager-112d2a`,
`manager-a6370e`, `manager-c07f6b`, two records each, between 2026-09-15 and 2026-09-17 -- and
every injection resolved from `.claude/seat.local.txt`. Positive control: 243 files carry
`[role-card]` in some form, so the search reaches the corpus.

**The exclusion is not tidiness, and the negative control is why.** A decoy needle that nothing
emits came back with ONE hit, and that hit was this session's own transcript -- written by the act
of running the search. A grep for a string puts that string in the transcript of the session
grepping. Excluding the searching session takes the decoy to 0 and is the only way this
instrument's negative arm means anything.

A first pass reported 34 injections across 5 worktrees. That was an undercount from a narrower
sweep, corrected here; the direction was never in doubt and the magnitude was understated.*

**So the no-backfill position rests on a mechanism that runs backwards, and one of two things has to
happen.** Either `seat.ps1 -Declare -Seat` writes the marker -- the collapse section 2.3 filed and
did not build -- or a backfill is required. The present state is neither.

**Neither follow-up is filed anywhere, and this document is the only record of them.** The marker
collapse and `new.ps1 -Seat` were both "filed as a follow-up, unallocated". The ledger they would
have gone into left this repository on 2026-09-13; `docs/BACKLOG.md` is now a pointer stub carrying
no rows. Allocate them in the maintainer-internal ledger.

---

## 7. Testing

Read the count from `pytest tests/test_role_cards.py --collect-only`, not from here. **No test runs
the hook.** Its only subprocess call is `git check-ignore`, so every hook-behaviour row below is
asserted by reading the source rather than by driving it, and the table says which is which.

| Behaviour | What actually asserts it |
|---|---|
| Missing marker prints the command | **Not tested as a run.** The source is scanned for a non-zero exit and for the marker path. The printed command and the absent card are unasserted. |
| Unknown label does not guess | **Partly tested.** `TheHookNeverGuessesASeat` proves by source absence that nothing reads a branch or directory name. Exit 0 and the absent card on that path are unasserted. |
| Oversized card is refused | **Not tested as a run.** The hook re-checks the 6 KB cap and names the file. An unreadable card has no branch of its own: it falls to the outer catch, which prints the exception and names no card. |
| The playbook repository is absent | **Not tested**, and no longer the vault. The hook reads only `docs/roles/`, and every card is required to name korus. |
| The Builder spellings collapse | **Not tested as a set.** `test_every_alias_lands_on_a_live_seat` iterates only the aliases present, so deleting them all stays green. Pin the set the way `CONSOLE_SPELLINGS` is pinned. |
| Every retired string resolves to no card | **Tested.** Never also live, no card, and a reason of at least 20 characters. Nothing asserts a retiring section is named, and no reason names one. |
| Section 5's seven retirements each resolve to a retirement | **Tested as a set**, by `test_every_seat_section_5_retired_resolves_to_a_retirement`. Added 2026-09-18, when `asvs-tracker` was found missing from every map. |
| `git check-ignore` on `.claude/seat.local.txt` and `.claude/ROLE.local.md` | **Tested**, with `CLAUDE.md` as the control that the check can tell ignored from tracked. |
| Each card is at or under 150 lines and 6 KB | **Tested**, with a control that the scan reads real files. The hook re-checks the byte cap. |
| Each required section is present **as a heading** | **Tested.** Matched as `## <heading>`; it was a bare substring until 2026-09-18. |
| No marker, whatever the worktree is called | **Tested by source absence**, not by a run. The resolution order ends at rung 3; the designed fourth rung was cut. |
| The hook is wired **exactly once** at SessionStart | **Tested**, across every hook group and across both the `args` and `command` fields of this file. |
| The wiring passes `-WorktreeRoot` spelled in full, and nothing else | **Tested positively**: the tokens after the script path must be exactly `-WorktreeRoot ${CLAUDE_PROJECT_DIR}`. |

The card budget is enforced twice, in the suite and again in the hook, so a card edited in a
worktree that never runs the tests still cannot cost every session. The resolution order has the
weaker guard: no test runs the hook, so its silent paths rest on the absence of four strings from
the source.

**The wiring rows were added on 2026-09-18, after the defects they pin had shipped, and their first
versions were themselves too weak to catch what they were written for.** The original wiring test
was `any("role-card-inject.ps1" in c)`, which a duplicate passes, so it stayed green for 13 days.
Its replacement counted registrations but read only the `args` field, so a duplicate expressed
through `command` still passed -- and that is the shape the user-scope settings on this machine
actually use. The parameter test subtracted known names rather than asserting the shape, so a value
passed positionally, or pointed at another directory, passed it; and a comment inside the hook's
param block naming the superseded `$Worktree` spelling re-admitted that name and turned the test
green on the exact wiring it exists to catch. Each of those is now covered by an interleaved
mutation arm with a green control. A test that cannot fail is the failure mode this section exists
to catch, and it took three passes to get these two to fail.

---

## 8. The emission shape, which the source decided

The hook emits **plain stdout on every path**. Nine of its ten emission sites go through a
`Write-Note` wrapper that is a bare `Write-Output`; the outer catch writes directly, to the same
place. No test inspects what it emits, so the shape is fixed by the source and not by the suite, and
a change of shape would pass the tests in silence.

**At `SessionStart` that is not the weaker channel.** The hooks reference lists that event among the
ones whose exit-0 stdout Claude Code adds to context as plain text, and this repository measured
that shape landing in context on 2026-09-15. Plain stdout and an `additionalContext` envelope reach
the same destination here.

**The question this section used to pose is answered.** It asked whether a hook wired in the
project's own `.claude/settings.json` can emit `hookSpecificOutput.additionalContext`. It can:
`context-budget.ps1` does so at `UserPromptSubmit` and `usage-headroom-inject.ps1` at `PreToolUse`,
both wired in that same file. On 2026-09-15 the harness parsed such an envelope from
`precompact-reprime.ps1` and rejected only its event name, naming `SessionStart` among the ones it
accepts.

*The hook's own comment asserted the opposite and cited this file for it -- "the one thing not
proven" in `docs/ROLE-CARDS.md`. That phrase has never appeared here: 0 occurrences in the working
tree and 0 at HEAD, so the pointer never resolved, and the 2026-09-18 pass left it pointing at
nothing while offering it as evidence. The comment is rewritten in the same commit as this section.
A pointer and the thing it points at are two edits, and nothing fails when only one is made --
which is the lesson section 4 already records about the playbooks moving.*

What stays unmeasured is narrower than the old sentence claimed: whether an envelope and plain
stdout **render differently** when both come from a `SessionStart` hook. Nothing in this design
turns on it, because this hook emits no envelope. If it is ever wanted, drive the hook from a test
and read its stdout the way `tests/test_precompact_reprime_hook.py` already does -- cheaper than
starting a fresh session, and it does not depend on somebody happening to have set a marker.

---

## 9. Build record

**Dated 2026-09-05. Every count below was true of a feature branch and nothing re-derives it.** For
current state read the code: `pytest tests/test_role_cards.py --collect-only` for the test count,
`.claude/settings.json` for the wiring, `scripts/hooks/role-card-inject.ps1` for the emission shape.

Test-driven: the tests were written first and watched fail before any of the code below existed.

### Files the 2026-09-05 branch added (`9f2aaf0a8`, PR #895)

| File | What it is |
|---|---|
| `docs/ROLE-CARDS.md` | This document |
| `docs/roles/seats.json` | The roster, the alias map, and the retired seats with reasons |
| `docs/roles/console.card.md` | Role card. Renamed to `manager.card.md` and rewritten on 2026-09-11 (`cbb63ad28`) when the owner retired the Console. Its playbook is korus `roles/retired/CONSOLE.md`. |
| A sixth role card | For the seat the owner retired the same day (`12063c91e`), deliberately unnamed here per owner instruction 2026-09-16. |
| `docs/roles/builder.card.md` | Role card |
| `docs/roles/regulator.card.md` | Role card. Its playbook is korus `roles/REGULATOR.md`, which existed on 2026-09-02 and which the card cites. |
| `docs/roles/steward.card.md` | Role card |
| `docs/roles/lander.card.md` | Role card |
| `scripts/hooks/role-card-inject.ps1` | The SessionStart hook |
| `tests/test_role_cards.py` | The suite |

**Only `docs/ROLE-CARDS.md` reached `main` from #895.** `b3c1ddff7`, the squash, carries this
document, the settings wiring and three unrelated files; the cards were dropped from it and landed
from #970 as `1584742b2` on 2026-09-08. So no single commit matches this table, which is why the
heading names the branch commit rather than the merge.

`seats.json` has since gained a fourth map, `elsewhere`, and its roster key was renamed from `seats`
to `live`. The shipped card set today is `builder`, `lander`, `manager`, `special`, `steward` and
`watchdog`.

**That last sentence read "`manager`, `builder`, `regulator`, `steward`, `lander`" until 2026-09-20,
and it was wrong at both ends.** It named a card that does not exist and omitted two that do.
Measured with `git ls-files docs/roles/`: seven entries, six `*.card.md` files and `seats.json`.
There is no `regulator.card.md` — the Regulator retired 2026-09-19 and nothing replaced it, so no
seat attributes a red check now. `special` and `watchdog` were absent from the list.

Control, the same listing read against `seats.json`'s `live` array: each of the six live names
resolves to a shipped card, so the read above was of a populated directory and not an empty match.

### Files changed

| File | Change |
|---|---|
| `.claude/settings.json` | Wires the hook at SessionStart beside `seat-declare-prompt.ps1`. **`1584742b2` added a second wiring for the same hook, and both fired until 2026-09-18.** |
| `tests/tooling_manifest.txt` | Classifies the new test as harness tier |

### What was cut, and why

Two things in the design were deliberately not built. Both are marked in place above, and **neither
is filed anywhere** -- see the end of section 6.

1. **The seat-record resolution rung.** It fires only where a session declared a seat but nobody
   wrote a marker, and in that state the next session is no likelier to have one. Having
   `seat.ps1 -Declare -Seat` write the marker collapses it into rung 1 and is the better end state.
   Section 6 measures what leaving it unbuilt cost.
2. **`new.ps1 -Seat`.** That script makes sibling worktrees only. One `Set-Content` line covers
   every path and the hook prints it.

### Verification actually run

| Check | Result |
|---|---|
| `pytest tests/test_role_cards.py` | 50 passed |
| `pytest` on the 4 affected files | 117 passed |
| `ruff check` | clean |
| `ruff format` | 1 file reformatted, then clean |
| `mypy` strict | no issues |
| Glyph scan, with `BACKLOG.md` as positive control | control fired at 2,134; subject 0 |

**The 50 is correct, and a 2026-09-18 pass wrongly called it unreproducible.** That pass counted
`def test_` lines and read 17, because the 2026-09-05 suite was parametrized where today's is not.
Collecting it properly reproduces the figure exactly: blob `a2d8e9ed` at `9f2aaf0a8` collects 50.
The unreliable figure in this section is the RED state recorded above it, 46 failed and 2 passed,
which sums to 48 and reconciles with nothing. 35 tests landed on `main` with #970.

**That glyph control is dead. Do not re-run it as written.** `docs/BACKLOG.md` left with the ledger
on 2026-09-13 and is now a stub carrying zero glyphs, so it returns a false zero everywhere -- the
exact failure `CLAUDE.md` section 11 warns about. Section 11 names the live replacements. Measured
2026-09-18: `docs/FEATURE-MAP.md` 139 and `docs/CONNECTIONS.md` 142, against 0 for this file.

**Not run: the full suite.** It does not finish inside one turn.

**Not run: any hosted-runner leg.** Those report after the session exits and somebody else has to
read them.
