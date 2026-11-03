# Handoff: repair pipeline investigation (Repair Manager proposal), 2026-11-03

Approved by the owner, not built. The full spec is beside this file: `REPAIR-MANAGER-PROPOSAL.md`.
Both files ride on the investigating session's own pushed branch, as a carrier; neither is meant
to merge as-is.

## The owner's ruling

In the investigating session's own chat, 2026-11-03. Asked *"Which tiers do you want to adopt?"*,
the owner answered *"Tiers 1 and 2"*. Quote it in each commit and PR.

## What the investigation found

Held PRs waited hours on their original author, mostly because the author could not be reached:

| PR | Wait | Cause |
|---|---|---|
| engine 2716 | about 13h | Author suspended on an AskUserQuestion; a suspended session drains no messages. One-line fix. |
| engine 2683 | over 21h | Author quiet; mail arrives only at its next SessionStart or Stop. |
| vault 2771 to 2793 | about 40h | Author on another account, so mail was the only channel. |
| engine 2705 | over 9h | Author misread a hold as an all-clear. |
| engine 2711 | about a day | Author responsive, but four hold and repair rounds of 1 to 3 hours each. |

Evidence limit: five PRs in one session. The 2-hour thresholds are judgement, not measurement.

## What was approved

- **Tier 1:** CLAUDE.md section 5's quiet-author repair Builder rule. 4 hours becomes 2, and an
  author whose transcript ends on an unanswered question older than 2 hours counts as quiet
  whatever its running state.
- **Tier 2:** the Lander spawns a Repair Manager in its own CCD instance, so it is wakeable.
  - A hold unacknowledged for 2 hours transfers to it.
  - The transfer: a `<!-- repair-owner session=<id> -->` marker on the PR, mail to the original
    author's worktree, and the hold's URL sent as the brief.
  - Stays with the author: stacks, landing order, author intent, and owner rulings.
  - It never uses AskUserQuestion (owner questions go in a table), and never opens a PR,
    enqueues or merges.
  - The Lander still reviews every repair head at `xhigh`.
- **Hold format:** every hold that names a fix uses four lines: What is wrong / Fix / Proof /
  Out of scope.

## What remains

1. **Engine PR:**
   - CLAUDE.md section 5: the tier 1 edit, and a new Repair Manager paragraph after it. The
     wording is in the proposal, *Rule text it would change*, items 1 and 2.
   - `scripts/coord/held_pr_turns.py`: a `REPAIR` turn for a PR whose newest `repair-owner`
     marker is newer than the latest `lander-hold` marker with no commit after it. Add a test
     and a control.
2. **Korus PR:**
   - `roles/LANDER.md`: a new section (spawn and keep-alive, the 2-hour transfer in order, the
     hold format, the tier 1 change, a standing-rules row). Census the section id first.
   - `roles/MANAGER.md`: a `repair-owner` marker that does not name you means the PR is no
     longer yours to push to; plus the Repair Manager's duties.
3. Each PR runs the Builder checks and an `xhigh` `code-review`, then goes to the Lander.
4. After both merge, the Lander spawns the Repair Manager.

## Unverified leftovers

A first build attempt was dispatched and then stopped by the owner before it reported.

- Check `git ls-remote --heads origin repair-manager-rules` in both the engine repo and korus for
  a partial branch.
- Check for leftover worktrees: engine `agent-*` worktrees from that dispatch, and any under
  `D:/Code/korus/.claude/worktrees/`.

## Open questions

- No threshold is measured. If repairs still stall after this lands, measure hold-to-fix latency
  across sessions before tuning.
- Residual collision risk: an original author who reads neither the marker nor the mail may still
  push. Builders already stop if the head moved.
