# 0177 — Rule 3c governs a repository by identity, not by path prefix

- **Status:** Accepted
- **Date:** 2026-08-27
- **Related:** BACKLOG #1067 · #1066 (the pass that measured this and deferred it) · #1061 · #1082 · `scripts/hooks/worktree_gate.ps1`

---

## Context

Rule 3c of the worktree gate refuses a write to a disarm key such as `core.hooksPath` in a **governed**
repository, because that one write turns off the ledger, claim and secret-leak commit gates for every
worktree of that repository at once.

It decided *"is this governed"* by an equality-or-slash-prefix test comparing the **target's git common
dir** against each allowlisted root's **working tree path**. Path containment was standing in for
repository membership, and the two are not the same relation.

So any repository living anywhere under a governed root inherited that root's governance, including an
independent clone that shares nothing with it but its path. Measured on the shipped gate at
`58e710ad4`: a disarm write in `<primary>/vendor/thirdparty` DENIED, from that repo's own cwd and by an
absolute path token from the primary, and both refusals named the **primary**.

The refusal's own text is what makes this more than a nuisance. It asserts that every worktree of the
repository shares one `.git` directory, which is simply untrue of a vendored clone. The rule-3 comment
in the same file already records what a misdescribing refusal produces: people route around the gate,
and then it guards nothing.

This is a **false deny in developer tooling**, not a product surface, and not reachable on this box
today — no independent repo currently lives under the primary. It fires the day someone vendors a clone
or drops a scratch repo there.

## Decision

**Compare the target's common dir against the root's OWN common dir, equality-or-under — not against
the root's working tree path.**

Repository identity is what rule 3c was always trying to ask. Every worktree of the primary, sibling or
nested under `.claude/worktrees/`, answers the *same* common dir, so they keep denying without the path
shape being what decides it. A vendored clone answers a different one and is no longer governed.

**Equality-or-under, rather than equality alone, is the load-bearing half.** A submodule's git dir is
`<root>/.git/modules/<name>`. The obvious identity-only predicate would have flipped submodules from
DENY to ALLOW as a silent side effect of fixing the vendored case — a control weakened by accident,
under cover of a fix. Under-the-common-dir leaves them exactly where they were.

**Where a root is not a repository's top level, the old path test stays, unchanged.** An allowlist entry
may legitimately name a directory that merely contains checkouts. There is no identity to compare there,
so the fallback keeps catching what it used to catch rather than failing open on it. The top-level check
is not decoration: without it, a root that is a *subdirectory* of some repo would report that repo's git
dir and quietly govern the whole thing.

Cost is two `git rev-parse` calls per root, cached per invocation, on a path only reached once a disarm
key is already present.

## Acceptance Criteria

- **AC-1** — WHEN a disarm key is set in an independent repository that lives under a governed root,
  THE SYSTEM SHALL allow it.
  → `tests/test_worktree_gate_control_plane.py::test_a_repo_VENDORED_UNDER_a_governed_root_is_not_governed_by_it`
- **AC-2** — WHEN that same repository is named by an absolute path from the governed root's own cwd,
  THE SYSTEM SHALL allow it.
  → `tests/test_worktree_gate_control_plane.py::test_a_vendored_repo_is_ungoverned_when_named_by_an_ABSOLUTE_PATH_too`
- **AC-3** — WHILE a worktree is nested under `<root>/.claude/worktrees/`, THE SYSTEM SHALL keep denying
  a disarm key set from it.
  → `tests/test_worktree_gate_control_plane.py::test_a_worktree_NESTED_under_the_governed_root_still_denies`
- **AC-4** — IF the target is a submodule of a governed root, THEN THE SYSTEM SHALL deny, unchanged from
  before this decision.
  → `tests/test_worktree_gate_control_plane.py::test_a_SUBMODULE_of_a_governed_root_still_denies`

## Options considered

1. **Equality-or-under against the root's own common dir** — **CHOSEN.** Fixes the vendored case, keeps
   every worktree denying, and leaves the submodule answer untouched so that changing it has to be a
   decision rather than a side effect.
2. **Identity alone (`-eq` against the root's common dir)** — Rejected. Correct on the vendored case and
   on every worktree, and it silently flips submodules to ALLOW. The item warned about this before the
   work started; a mutation of the shipped fix to this form reds AC-4 and nothing else.
3. **Leave the prefix test and repair only the deny WORDING** — Rejected. The verdict is wrong, not just
   the sentence. Wording is #1082's subject and is deliberately untouched here.
4. **Resolve the submodule question in this change** — Rejected as out of scope. It is a real question
   about what a submodule's config is worth protecting, and it deserves its own item rather than being
   answered by whichever predicate happened to be convenient.

## Consequences

**Positive** — the gate stops refusing work it has no business refusing, and stops telling the person it
refused something false about their repository. The predicate now compares two things of the same kind.

**Negative / risks** — two extra `git rev-parse` calls per root the first time a disarm key appears in a
command. A root whose git dir is unreadable falls back to the path test, which is the prior behaviour.

**Out of scope** — the deny message's wording (#1082). `Get-SessionRoot` carries the same path-prefix
shape, so a session standing in a vendored repo is still attributed to the enclosing governed root; that
value feeds a remedy STRING inside a rule-4 deny message and gates no verdict, so it is a reporting
defect and is recorded rather than fixed here.

## To resolve on acceptance

- [x] Does the fix flip submodules? No — pinned by AC-4, and a mutation to the identity-only form reds
      that row alone.
- [ ] Should a submodule's shared config be governed at all? Deliberately unanswered. Deciding it means
      deciding whether `<root>/.git/modules/<name>/config` is worth the same protection as the
      superproject's, which this change does not need to settle. Not filed as a number — naming the
      subject rather than citing an unallocated one.
