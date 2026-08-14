<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0165 — A builder PR satisfies the ledger gate with a paired commit authored by the Dispatcher or Lander

- **Status:** Accepted (2026-08-13) — **already in force; no code change was required.** See §"The decision needed no build"
- **Date:** 2026-08-13
- **Related:** [backlog-hygiene.yml](../../.github/workflows/backlog-hygiene.yml) (the gate) · [BACKLOG #1240, #1241](../BACKLOG.md) (the PR that surfaced it) · [ADR 0158](0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md) (a control that cannot observe its own failure) · [CLAUDE.md](../../CLAUDE.md) §5 (git discipline), §11 (state a load-bearing fact once)

---

## Context

### Two correct rules met and produced an unsatisfiable state

Neither rule is defective. Neither party erred. That is the whole reason this needed a decision rather
than a fix.

- **The gate.** `.github/workflows/backlog-hygiene.yml` publishes a required status check named *"a PR
  that implements BACKLOG #N must update BACKLOG.md"*. If a PR's title or body carries an explicit
  `BACKLOG #N` token **and** the PR touches engine or IDE code, the PR's own diff must also touch
  `docs/BACKLOG.md` or `docs/archive/backlog/`. It exists because a fix once landed on `main` with its
  item still reading *not started*.
- **The authoring ruling (owner, 2026-08-13).** A builder **may** resolve a merge conflict in
  `docs/BACKLOG.md`; a builder **may not author** ledger content — bodies, banners, closures. The
  property being protected is narrow and load-bearing: **a mechanical union cannot invent a
  disposition, but authoring a banner can, and a seat that can author its own item's banner can turn
  its own PR green.**

Compose them and **a compliant builder PR cannot pass a required check.** Measured live: PR #379
implemented two numbered items, withheld its banner exactly as instructed, and went red **for
obeying**.

### The failure mode is not the red check

A red check is loud and self-announcing. The cost is what a builder does next: conclude the ruling is
unworkable and flip the banner anyway. **The ruling would then be defeated by the gate that has
nothing to do with it**, silently, on every future PR — and the check would still be green, so
nothing would report it.

## Decision

**A builder PR satisfies the ledger gate with a paired ledger commit AUTHORED by the Dispatcher or the
Lander and carried ON THE PR BRANCH.** The builder never authors ledger content; the check passes on
the PR's own diff.

Concretely, as executed on PR #379: the Dispatcher authored both dispositions (one close, one
partial-progress amendment), committed them on its own branch, and the Lander cherry-picked that commit
onto the PR head.

### The decision needed no build

This is the part that inverted the expected answer, and it was established by reading the gate rather
than by reasoning about it. `backlog-hygiene.yml:64-98` does exactly two things:

```
changed = git diff --name-only BASE_SHA...HEAD_SHA        (three-dot, deliberately)
pass if changed touches docs/BACKLOG.md or docs/archive/backlog/*.md
```

**It never inspects authorship.** It tests the PR's changed *file set*. A commit authored by the
Dispatcher and cherry-picked onto the PR branch is, to the gate, indistinguishable from one the builder
wrote.

Evaluated against the real cherry-picked head for #379:

| predicate | value |
|---|---|
| `changed` | `docs/BACKLOG.md`, `transports/fhir.py`, `tests/test_fhir_lookup.py`, `tests/test_fhir_transport.py` |
| `touches_code` | 1 |
| touches ledger namespace | 1 |
| **verdict** | **PASS** |

So the pattern was in force before it was named. **No gate change was needed, and none is pending.**

### The ledger gate permits the cherry-pick, which is not obvious

`scripts/hooks/ledger_check.py` keys ledger-number ownership on the worktree that ran `alloc.ps1` and
refuses a number allocated elsewhere. That would appear to block a Lander from committing a
Dispatcher's ledger edit. It does not: the gate iterates **headings added relative to base**, and a
banner flip or body amendment on an item already on `origin/main` **adds no `## N.` heading**. The
heading set is unchanged, ownership is never consulted, and the committing seat is irrelevant.
Confirmed live — the pre-commit hooks ran clean on the cherry-pick.

**This holds only for items already on `main`.** A PR that *files* a new item is a different shape and
is out of scope here.

## Alternatives considered and rejected

**(a2) The ledger commit lands separately and the gate correlates it.** Rejected: it would undo a
deliberate control. The gate uses a **three-dot** diff on purpose, and its own comment states why —
two-dot *"includes everything main gained since this PR branched"*, so any main-side ledger change
would be credited to every open PR with an older base and *"this gate would pass while enforcing
nothing."* Building cross-branch correlation re-opens exactly that.

**(b) A narrow carve-out letting a builder flip only the banner of the item it was dispatched.**
Rejected: it reopens the self-approval hazard the authoring ruling had just closed. *(Property
identified by the Builder 2 seat before any ruling existed.)*

**(c) Dispatcher/Lander supplies the edit as standing process, as an interim before (a2).** **Dissolved
rather than rejected** — (c) and the accepted decision are the *same mechanism*. There is no interim
and no transition.

### A recorded near-miss: an expiry condition whose trigger had already fired

The decision was briefly recorded as *"(c) is fine until (a) lands"*. That clause **looks like the safe
construction** — a standing rule carrying its own expiry, which is the discipline this project applies
precisely so prohibitions do not become permanent by default.

**It behaves like the unsafe one.** (a) had already landed, so the trigger could never be observed, and
the rule would have become permanent by default anyway while appearing bounded. A successor would wait
indefinitely for a gate change nobody was building.

**Recorded rather than deleted, because the wrong version is the one a later reader re-derives: an
expiry tied to a state that is already true is not an expiry.**

## Consequences

- **One manual step per builder PR that implements a numbered item, indefinitely.** Accepted with open
  eyes; it is the price of keeping the self-approval property.
- **The builder MUST declare the withheld banner in its PR body.** A missing banner flip is visually
  identical to the defect the gate exists to catch — a fix on `main` with its item still reading *not
  started*, which is exactly what happened on BACKLOG #1237. Same shape, opposite cause; **only a
  declaration separates them.**
- **The Dispatcher or Lander becomes a serialisation point** on every such PR. If that seat is absent
  or out of budget, the PR waits. It cannot be worked around by the builder without defeating the
  ruling.
- **This ADR changes no engine behaviour.** It records a coordination decision and the measurement that
  showed it needed no build.

## What this does NOT decide

- **Whether a builder may author ledger content in any other circumstance.** It may not; that ruling
  stands unchanged and this ADR neither widens nor narrows it.
- **How a PR that FILES a new item should behave.** Filing adds a heading, so ledger ownership *is*
  consulted, and that routes to whoever allocated the number. Out of scope.
- **Whether the gate should ever learn authorship.** Not proposed, not desirable on present evidence,
  and it would not help — the constraint is who *writes* the content, not who *carries* the commit.

## Provenance

Stated because three seats contributed different halves and the reasoning is only checkable if each is
attributable.

| part | seat |
|---|---|
| The collision, found on PR #379's red check | Lander |
| The self-approval property that rejects (b) | Builder 2 |
| The gate measurement, and the split that showed no build was needed | Dispatcher |
| The ruling | Owner |
