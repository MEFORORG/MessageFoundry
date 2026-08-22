# Instruments that returned confident wrong answers

Measured across one session, 2026-08-22, by several sessions working the same tree. Tracked here
rather than left in a coordination handoff because `<git-common-dir>/mefor-coord/handoffs/` sits
inside `.git`, which git cannot track by construction, so no rescue ref covers it (COMMON 5.6b).

**Every entry is a real measurement that was correct about what it measured and wrong about what it
was asked.** None is a typo or a slip. That is the point: the failures survive care, so the guard has
to be structural.

## The single shape

**An instrument answered a question adjacent to the one asked.** Name the question and the answer in
the same sentence and check they are the same sentence. That is SDS-3.8, and every entry below is an
instance of it.

## The catalogue

| The check | What it answered | What was asked |
|---|---|---|
| `grep ... \| head -60` | The first 60 lines of the result | How many sites exist. It FOUND four and PRINTED three |
| `grep -c <symbol>` | How many times a name occurs | Whether the code handles it. All 8 hits WERE the handling |
| A count on a settings model | That one real field took | Whether unknown keys are dropped. Only a BOGUS key discriminates |
| `git status` | Does this differ from HEAD | Is someone mid-edit. A restore-to-current renders identically |
| `git status` in a stale checkout | Differs from a HEAD 28 commits behind | Did anyone edit this |
| Two mail timestamps | The gap between two messages | What caused an event three minutes earlier |
| Reading a commit by SHA | What was true at that commit | What is true now. A SHA is a snapshot, a TIP is a state |
| `grep -i "superseded"` on a row | The word is present | The row's status. Both bodies used it as NARRATIVE |
| `parse_items` `is_open` | The BANNER state | Which row the authors say survives. Different questions |
| A `tail`-piped background run | Nothing until exit | Progress. The buffer hid a 0-byte file for a run that never started |
| A harness "exit code 0" | The wrapper's status | Whether the suite passed. It reported 0 over `3 failed` |

## Four rules that survived the session

**1. A zero needs a positive control -- AND the control proves the instrument, not the AIM.**
Confirming a pattern fires on a corpus establishes the grep works THERE. It cannot establish that
there is the right place to look. Both halves are needed and the second is the one that gets skipped.

**2. Not on origin means UNPUBLISHED, not UNREADABLE.** Its mirror: WHAT YOU READ IS NOT NECESSARILY
WHAT IS COMMITTED. Several checks stop at `origin/main` and report unknown when the answer sits in a
sibling worktree. Read through `git show <ref>:<path>` so the command NAMES the corpus -- but note
the limit: naming the corpus prevents drift, not misaim.

**3. Never filter a command whose output IS evidence** -- a count, an id, a receipt, a verdict. A
truncated COUNT is wrong immediately and might be caught. A truncated ARTIFACT is not wrong at all,
it is ABSENT, and absence surfaces only when something downstream needs it.

**4. A completeness claim is a liability.** Prefer "at least" (SDS-3.6). Two published population
claims in one session were unmeasured extrapolations from a real mechanism, and both had to be
withdrawn. The honest form is "the next one will do this silently", not "these are everywhere".

## Two shapes that are not instrument failures

**A marker that reverses its own meaning in context is worse than no marker.** A row containing
"THIS ROW SURVIVES A CROSS-SUPERSEDE" was read as superseded by three separate readers grepping for
that word. This is the positional-meaning defect CLAUDE.md section 11 gives as the reason not to use
status glyphs -- reproduced exactly, in prose. The rule is not about pictographs; it is about tokens
whose meaning depends on the sentence around them.

**Mutual deference has no fixed point, and neither does mutual assertion.** Two seats deferring to a
third produced two records of one defect; both then yielding to each other produced zero; both then
asserting produced two again. Same courtesy, three directions, never convergence. Only an ASYMMETRIC
decider settles it -- and by position rather than by judgement, since a merit tie-break between two
good options is still a tie.

## The one that generalises furthest

**A test that cannot fail in the direction of the bug will certify it.** Observed four times: a test
asserting a string the loader rejects; a gate reading a refusal and reporting `skipped`; a settings
object silently dropping the flag a test is named after; an assertion reading `.path` where httpx
decodes what the fix encodes. **Mutation testing is the only thing that answers "can this test fail
at all", and it caught two tests written by the person applying the rule.**
