# mefor-read-a-merge-state

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.

- **A PR's merge state is a join over clocks, and the join is the part you must not miss.**
  `gh pr view <N> --json mergeStateStatus` is the starting read, never the verdict: it reports
  `BEHIND` or `DIRTY` in preference to `BLOCKED`. **The `reviewed`-label arm of this join is RETIRED
  with the gate** -- there is no gate run and no strip, so comparing a gate run's `createdAt` against
  the newest `reviewed` label event now compares two things that decide nothing. The rest stands:
  `mergeStateStatus` still hides one blocking reason behind another, so poll the gate RUN for the
  contexts that are still required. BACKLOG #1417 recorded the stale-payload defect and PR 731 was
  built against a workflow that no longer exists; see that item's 2026-09-04 amendment before acting
  on either.
- Never write the required-context count into a document. `.github/required-contexts.txt` is a
  checked-in claim that can lag the server, so read branch protection for the live set. When the set
  moves, move that file and the pinned count in `tests/test_required_contexts.py` in the same PR, or
  the test leg goes red for everyone.
