# Instruments that returned confident wrong answers, 2026-08-22

**Committed here per COMMON 5.6b: a session handoff lives under `<git-common-dir>/mefor-coord/`,
which git cannot track by construction, so the irreplaceable part of one belongs somewhere tracked.**
This is that part. The coordination copy stays where it is; per-session state is deliberately not
migrated.

**Scope.** One session, one day, building three ledger instruments and reviewing a multi-session
setup. Every entry is a case where a tool returned a plausible number rather than an obvious break.
None was caught by re-reading. Each was caught by something that could return no, or by a peer.

**Why this is worth keeping.** `scripts/ci/step_margin.py:11-17` already states the principle with
its own evidence: *"seven published claims were retracted. Not one was caught by re-reading. Every
one was caught by something that could return no."* This file is fifteen more, from one day, so the
next person building a gate has a catalogue of the shapes rather than the principle alone.

---

## 1. False zeros: the instrument could not see the class it was measuring

| # | What was measured | What it returned | Why it was wrong |
|---|---|---|---|
| 1 | Mail delivery latency | **0 messages** | A date-parse bug, swallowed by a bare `except ValueError: continue`. A broken parse and an empty corpus render identically. |
| 2 | Mail delivery latency, retry | **0.0 min at every percentile** | File `mtime` survives the `new` to `seen` move, so the measurement subtracted a timestamp from itself. |
| 3 | Expiry-clause audit, basename index | **18 DANGLING** | The skip-dir list contained `worktrees`, and every root here IS a worktree path, so the index matched nothing and every bare-name citation read as missing. |
| 4 | Items carrying a `Verdict` field | **1 of 330** | A `^`-anchored grep. The field is inline beside Priority, so the anchor excluded all 304 real occurrences. |
| 5 | Whether a duplicate existed | **"cannot verify"** | Checked `origin/main` only. Both commits were readable in sibling worktrees the whole time. **Not on origin means unpublished, not unreadable.** |

**The shape.** In four of five, a zero was indistinguishable from a clean result. The fix in every
case was a positive control: prove the instrument can see the thing before believing it saw nothing.
`scripts/quality/expiry_audit.py` now refuses to report when its index holds under 100 entries, for
exactly this reason.

## 2. Over-reporting: the instrument answered a broader question than asked

| # | What was measured | What it returned | Why it was wrong |
|---|---|---|---|
| 6 | Expiry-clause drift | **16 DRIFTED** | Every backticked token checked against every cited file. A commit SHA is not "missing" from a YAML file; it was never meant to be there. |
| 7 | Expiry-clause drift, retry | **3 DRIFTED** | Short ubiquitous tokens (`.git`, `--ci`) treated as anchors. "Found elsewhere in the file" is trivially true for them. |

**The fix that held:** a token is only checked against a `path:LINE` citation, because a bare path
asserts nothing about content. Plus a distinctiveness floor. The final count was 4.

**The count sequence across both classes: 18, then 9, then 16, then 3, then 4.** The first two runs
would have sent someone chasing seventeen defects that did not exist.

## 3. Verification that could not fail

| # | The check | Why it proved nothing |
|---|---|---|
| 8 | "All six numbered citations still resolve after the move" | Every match landed on the file header **I had just written**, which lists all six numbers. The check matched the claim, not the entries. |
| 9 | A mutation harness reporting "no test caught it" | Its grep looked only for `failed`. The mutant was a syntax error, which pytest reports as `error`. |
| 10 | `if good:` over a function that had started returning a level string | Every level is truthy, so an undeclared item reported as dispatchable. Caught mid-edit. |

**Entry 8 is the one to remember.** It felt like rigour. Stating a limitation carefully is not the
same as having a working instrument.

## 4. Right measurement, wrong question

| # | The claim | The correction |
|---|---|---|
| 11 | "Unpushed: 7" | `git log origin/main..HEAD` answers *what does the PR carry*, not *what have I failed to push*. The real number was 0. Asked while writing the document describing that error. |
| 12 | "Crossed in flight, fourteen seconds apart" | The allocation records show 22 seconds between filings, and the message blamed as the cause landed **three minutes after both**. Two real timestamps, a real gap, and the wrong events. |
| 13 | "#1326 is live, #1327 superseded" | Read from a SHA that two newer commits had already replaced. **A SHA is a snapshot; a TIP is a state.** |
| 14 | Reading item status by grepping for `superseded` | A row read *"THIS ROW SURVIVES A CROSS-SUPERSEDE"* -- the word inside a sentence meaning the opposite. Three seats read it backwards. |
| 15 | A test named `..._being_disabled` passing a deleted setting | Pydantic `extra="ignore"` drops the unknown key silently, so the test established nothing it was named for. Filed as BACKLOG #1326. |

## 5. The two controls that actually worked

**A positive control, stated beside the number.** Not "I found zero" but "I found zero, and the same
pattern returns N on a case I know exists." Entry 5 was caught this way by a peer; entries 1 to 4
were not caught until one was added.

**A negative control, to discriminate mechanisms.** Entry 15's mechanism was established by passing
a deliberately bogus key. Checking only the real field would have shown "my tests are fine" and
nothing about whether unknown keys are rejected or dropped -- a pass is consistent with both. **Only
the bogus key separates them.**

## 6. What this says about where checking pays

Every entry above was caught in minutes, by a tool that could return no or by a peer reading the
same artifact. None was caught by careful re-reading, and several survived careful re-reading by
their author.

The distinction that matters is not how rigorous a check is. It is **whether the check can fail in
the direction of the defect**. `CLAUDE.md` section 11 (SDS-3.8) already states this: *name the
question and what the tool returns, and check they are the same sentence.* Fifteen entries in one
day say the rule is correct and that stating it is not sufficient -- every one of these was written
by someone who knew the rule.
