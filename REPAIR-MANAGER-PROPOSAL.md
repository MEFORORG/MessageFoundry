# Proposal: a Repair Manager the Lander spawns

Status: DRAFT for the owner, 2026-11-03. Not committed. Every rule change below edits CLAUDE.md
section 5 or a korus playbook, which is class C: nothing here takes effect without the owner's go.

## The problem, as observed

Held pull requests wait on their original author for hours. In one Lander session (2026-11-02 to
2026-11-03), at least these:

| PR | Wait | What stalled the repair |
|---|---|---|
| engine 2716 | about 13h | Author Manager suspended on an AskUserQuestion; a suspended session drains no messages. The fix was one line. |
| engine 2683 | over 21h | Author Manager quiet; mail is delivered only at its next SessionStart or Stop. |
| vault 2771 to 2793 | about 40h | Author Manager on another account, so mail was the only channel. |
| engine 2705 | over 9h | Author misread a hold as an all-clear. |
| engine 2711 | about a day | Author responsive, but each hold and repair round trip took 1 to 3 hours, four rounds. |

The pattern is reachability more than neglect: a suspended session cannot be woken, a peer on
another account can only be mailed, and a Manager running a new wave puts repairs second.

**Evidence limit:** five PRs in one session. No latency was measured across sessions, and the
thresholds below are judgement, not measurement.

## The proposal

### Tier 1: one determinate fix -- the existing quiet-author repair Builder, loosened

The current rule (CLAUDE.md section 5, decision d20261029T165610526-c13ae6) blocked engine 2716,
because its author was "live" while suspended on a question. Two changes:

- **Quiet window: 4 hours becomes 2 hours.**
- **A session counts as quiet when its transcript ends on an unanswered question older than 2 hours,
  even though it shows as running.** The Lander reads this with `list_events` or korus
  `scripts/board/seatstate.py`.

Everything else in that rule stays: one determinate fix, fetch before push, never force-push, stop
if the head moved, the Lander's own `xhigh` review on the repair head.

### Tier 2: everything else -- a Repair Manager

- **Who:** one Manager session the Lander spawns in its own CCD instance, so it is wakeable with
  `send_message`. One at a time; the Lander respawns it if it dies. The 2026-09-16 spawn ruling
  already lets the Lander spawn a Manager.
- **When a PR transfers:** the Lander posts a hold. If the author has not acknowledged it (a
  comment or a commit) within 2 hours, the repair transfers. The author may also hand it over.
- **The transfer is one act, in this order:**
  1. The Lander posts on the PR: `<!-- repair-owner session=<id> -->` and "Repair owned by the Repair
     Manager from <time>; the original author stands down on this PR."
  2. The Lander mails the original author's seat-record worktree the same line.
  3. The Lander sends the Repair Manager the hold comment's URL. That comment is the brief.
- **What the Repair Manager does:** reads the PR body, the hold, the decision log entries the hold
  cites, and the diff; briefs a subagent Builder; reads the commit back; posts the new head on the
  PR. It never opens a new PR, never enqueues, never merges.
- **What it never does:** call AskUserQuestion. An owner question goes in an end-of-turn table, the
  Lander's pattern, because a suspended Repair Manager would recreate the stall it exists to remove.
- **Independence is unchanged:** the Repair Manager authors, the Lander lands, and the Lander's own
  `xhigh` review covers each repair head.

### What stays with the original author

- A stacked set or a landing order (the vault Argon stack needed batch context to fix).
- A question of the author's intent, or one waiting on an owner ruling.
- ASVS record content, which stays a Manager's under the 2026-09-23 ruling (the Repair Manager is a
  Manager, so it may take it if the author is gone; say so in the transfer comment).

### Making the brief cheap: write holds as briefs

The research cost falls on the hold's author, the Lander, who already has the context. Every hold
that names a fix carries these four lines:

    What is wrong: <file:line or behaviour, with the evidence>
    Fix: <the required change, not the implementation>
    Proof: <the test or command that must fail before and pass after>
    Out of scope: <what the repair must not touch>

A hold in this shape is a Builder brief, so the Repair Manager forwards it rather than researching.

## Costs and risks

- **Collision:** the original author resumes and pushes too. Engine 2716 nearly did this on
  2026-11-03. The `repair-owner` marker plus the mail is the control, and Builders already stop if
  the head moved. Residual: an author who reads neither.
- **Context loss on design-heavy fixes:** security or behaviour repairs (engine 2683, the 2711
  cross-shard fix) need design context the Repair Manager must rebuild from the PR and its ADR.
  Expect those to cost a research turn each.
- **Usage:** one more long-lived session on the Lander's account.
- **Single point of failure:** if the Repair Manager dies, repairs stall again. The Lander's loop
  checks it each tick, as it checks the Watchdog.

## Rule text it would change

1. **CLAUDE.md section 5**, the paragraph *"The Lander may send a repair Builder subagent to a held
   PR whose author has gone quiet"*: change "4 hours" to "2 hours", and add: *"An author whose
   transcript ends on an unanswered question older than 2 hours counts as quiet, whatever its
   running state."*
2. **CLAUDE.md section 5**, after that paragraph, a new one:

   > **A held PR whose author has not acknowledged the hold within 2 hours transfers to the Repair
   > Manager** (owner ruling <date>). The Lander spawns one Manager in its own CCD instance for
   > repairs and keeps it alive. The transfer is a `repair-owner` marker on the PR, mail to the
   > original author's worktree, and the hold's URL sent to the Repair Manager. Stacks, landing
   > order, author intent and owner rulings stay with the original author. The Repair Manager never
   > uses AskUserQuestion; it carries owner questions in a table. The Lander still reviews every
   > repair head at `xhigh` before it merges.

3. **korus `roles/LANDER.md`**: a section on spawning and checking the Repair Manager, and the
   four-line hold format.
4. **korus `roles/MANAGER.md`**: *"A PR carrying a `repair-owner` marker that is not you is no
   longer yours to push to."*
5. **`scripts/coord/held_pr_turns.py`**: a `REPAIR` turn for PRs carrying the marker, so the board
   shows who owns the repair.

## Decision for the owner

Adopt tier 1 alone, tiers 1 and 2, or neither. Tier 1 is two edits to an existing rule and would
have cleared engine 2716 about 8 hours sooner. Tier 2 is a new seat duty and a new long-lived
session.
