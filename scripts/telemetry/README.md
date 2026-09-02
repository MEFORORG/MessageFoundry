# Rule telemetry: did sessions actually follow the rules?

**What it does in one line:** scores whether sessions obeyed this project's rules, read from their
own transcripts, at no extra session cost.

```powershell
python scripts\telemetry\rule_telemetry.py --self-test
python scripts\telemetry\rule_telemetry.py --sweep --since-days 7
```

**Run `--self-test` first, every time.** It is not a formality. Five checkers, each with a case that
must trip it and one that must not, and the numbers below are the reason.

---

## Why it exists

Research on instruction-following in long documents measures **fact retrieval**, not rule adherence,
and on models that all predate 2024. The nearest thing to a direct test of whether a rule's position
affects whether an agent obeys it is 162 words with no figure and no number, in a paper about
something else.

So rather than run a controlled study, measure the documents we ship against the sessions we run.
The transcripts already exist. This reads them.

## The one design rule

**A compliance rate needs a denominator of opportunities, not of sessions.**

A transcript with no `git push` in it cannot violate the push rule. Counting it as a pass makes a
quiet session look obedient and drags every rate toward 100 percent. So every checker reports
opportunities and violations separately, and a rule with zero opportunities reports **no rate at
all** rather than a perfect one.

A rule with no opportunity is unmeasured here. That is not the same as obeyed.

## What the first run taught, which is most of the value

Every checker passed its self-test before being run on anything. The first real sweep then reported
167 glyph violations, 75 fence violations and 13 unallocated citations. **Every one of those was the
instrument.**

| Reported | What it actually was |
|---|---|
| 167 glyphs | The class included arrows, which are typography. It also ignored the two exceptions the rule states: quoting a glyph in backticks, and the backlog banner alphabet |
| 75 bad fences | The rule is owner-set 2026-09-01 and 40 of the transcripts predate it. Those sessions were following the rule that existed at the time |
| 13 unallocated citations | Not checkable from a transcript. An allocation is per-worktree and persists across sessions, so the entitling call is usually in a different file |
| 1 direct push, 4 gate bypasses | A compound command is many commands. A later `main` and an unrelated `-n` tripped rules about earlier verbs |
| 4 secret reads | Naming a path is not reading it. A bare `>` caught `2>/dev/null`, and the GitHub secrets API returns metadata, never values |

After fixing the instrument: **two real glyph violations in 8,632 opportunities**, and zero on push,
gate bypass, fences and secret reads, each with a real denominator.

One regex escape was eaten by an editing pipeline four separate times, once turning a word boundary
into a literal backspace so the pattern matched nothing while looking correct. That is why
`_CONTENT_VERBS` is a token set rather than a regex, and why `_GLYPH` is built from integer code
points.

## Adding a checker

1. Count an **opportunity** only when the session did something the rule could apply to.
2. Count a **violation** only when that thing broke the rule.
3. Split compound commands with `_segments()` and match inside one segment.
4. Add the rule to `EFFECTIVE` if it has a start date, or a corpus spanning its introduction will
   measure the rule's age rather than obedience.
5. Add both self-test arms. Take the known-good from a real false positive if you have one, because
   an invented one tests what you imagined rather than what happens.

A checker that cannot fire is worse than no checker. It licenses the behaviour it was meant to watch.

## What it does not do

It does not know which rules a given brief put in scope, so it scores every rule against every
session. It does not read the repository state, which is why the allocation rule is retired rather
than approximated. And it says nothing about whether a rule's **position** in a document matters:
answering that needs two versions of a document differing only in placement, which is a separate
experiment this tool would supply the scoring for.
