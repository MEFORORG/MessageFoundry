# Role cards: giving a worktree a seat that outlives its session

Design doc and build record. Written and built 2026-09-05.

**Status: BUILT on its feature branch, not merged.** What
shipped, what was cut, and how to verify it is section 9 at the end of this file. Sections
1 to 8 are the design as approved; two places where the build diverged are marked
"Amended during the build" in place, rather than corrected silently.

A session is told its role in its first message. That works for the conversation and
dies with it. This design binds the role to the **worktree** instead, and injects the
seat's rules at session start at the same weight as `CLAUDE.md`.

---

## 1. The problem, measured

Every seat record in `<git-common-dir>/mefor-coord/seats/` was counted on 2026-09-05.

| Box type | Records | Carry a role |
|---|---|---|
| Subagent boxes | 25 | 25 (100%) |
| Worktree sessions | 968 | 145 (14%) |
| Worktree sessions, last 7 days | 380 | 49 (12%) |

Subagents reach 100% because the Agent tool writes the seat mechanically. Worktree
sessions sit at 12% because a person says it out loud. The gap is not effort. It is
who writes it, and the recent slice shows it is not improving.

**The labels drift as well.** 46 distinct role strings appear on worktree boxes for a
six-seat roster, including eight spellings of one seat: `builder`, `Builder`,
`BUILDER1`, `BUILDER2`, `builder1`, `builder2`, `builder-2`, `builder3`. Ten records
still declare seats that section 5 of `CLAUDE.md` retired.

**Three costs follow.**

1. A session that compacts loses the role, because a first-turn instruction is an
   ordinary user turn competing with everything else.
2. Two Builders get different rules, because the rules are whatever the spawner typed.
3. No instrument can group by seat, because 46 labels do not group.

---

## 2. What gets built

Four pieces. Each is small and can be read on its own.

### 2.1 The marker: `.claude/seat`

One file in the worktree root holding one lowercase word.

```
builder
```

It is git-ignored. Measured with `git check-ignore`: `.claude/*` is ignored and the
`.gitignore` permits negating only `settings.json`, so the marker can never dirty a
tree or ride into a commit. `CLAUDE.local.md`, `ROLE.md` and `docs/ROLE.md` were all
tested and would show as untracked, which is why none of them is used.

It belongs to the worktree, not to a session. Sessions come and go inside a worktree;
the marker survives a crash, a compaction, an account switch, and a respawn.

### 2.2 The cards: `docs/roles/<seat>.card.md`

One tracked file per live seat. Five of them: Console, Builder, Regulator, Steward,
Lander. (Six at the time of writing; the Reviewer was retired on 2026-09-05.)

Each card is capped at **150 lines and 6 KB**. Only one is ever injected, so the cost
to a session is about 1,500 tokens against the 60 KB `CLAUDE.md` already loaded.

Every card carries the same five sections:

| Section | Holds |
|---|---|
| What this seat owns | The work only this seat does. |
| What it must not do | Prohibitions, each with its expiry condition beside it. |
| Its authority | What it may do without asking, and what needs the owner. |
| On arrival | The checks it runs before its first change. |
| The full playbook | A path to the long file, and a note that the card is a summary. |

Cards inherit the rule the vault's `roles/README.md` is built on: **a card carries
nothing that expires.** Live state -- open queues, item numbers, who is blocked on
whom -- belongs in a dated episode note. That folder paid for this rule twice: a
standing "do not install" instruction inverted when the held fix merged, and a "no new
lanes" freeze cited twice as authority that had never been issued.

**Cards live in the engine repo, not the vault.** The hook runs inside an engine
worktree, and the vault is a separate clone that may not be beside it. Cards hold no
ASVS content and no security specifics, so nothing vaulted moves.

### 2.3 The hook: `scripts/hooks/role-card-inject.ps1`

Wired at `SessionStart` in `.claude/settings.json`, beside the existing
`seat-declare-prompt.ps1`.

It resolves the seat, reads that card, and injects it. It also writes the resolved card
to `.claude/ROLE.md`, git-ignored, so a session can re-read it after a compaction.

**Resolution order, highest first:**

1. `.claude/seat` in the worktree root.
2. `$env:MEFOR_SEAT`.
3. Nothing. The hook injects no card and prints the one command that sets the marker.

**Amended during the build: a fourth rung reading the seat record was designed and then
dropped.** It would have fired only where a session had declared a seat but nobody had
written a marker, and in that state the next session is no more likely to have one. The
cheaper end state is to have `seat.ps1 -Declare -Seat` write the marker, which collapses
that rung into rung 1. That is not built. Filed as a follow-up, unallocated.

**It never guesses from a branch or directory name.** Section 5 of `CLAUDE.md` records
that a worktree name is a creation-time label nothing keeps current, and that one is
known to describe work its session never did. A wrong card injected at maximum
importance is worse than no card, so the last rung stays silent rather than inventing a
seat. `test_hook_does_not_guess_a_seat_from_a_branch_that_looks_like_one` pins it.

**It never fails a turn.** It exits 0 on every path, as `seat-record.ps1` and
`seat-declare-prompt.ps1` already do. A hook that can break a session is a worse fault
than an undeclared seat, and this one runs in every worktree of a repo with a live
fleet in it.

### 2.4 The label map

A table mapping the 46 observed strings onto the six canonical seats, plus a rule that
an unmapped string resolves to nothing. Eight Builder spellings collapse to `builder`.
Retired seats map to nothing and print a line saying the seat was retired and by which
section.

---

## 3. Who writes the marker

Three paths, matching how worktrees are actually made.

| Path | How the marker gets written |
|---|---|
| The harness worktree feature | The owner or the spawning Console writes it in one command. |
| `scripts/worktree/new.ps1` | The same one command, run after creation. |
| A subagent | Already covered. The Agent tool sets the seat mechanically, at 100%. |

**Amended during the build: `new.ps1` gains no `-Seat` parameter in v1.** It creates
sibling worktrees only, which is 3 of the 20 live ones, so the parameter would serve the
minority path. The single `Set-Content` line below covers every path, and the hook prints
it when no marker is set. Adding the parameter is a follow-up, not a prerequisite.

`spawn.ps1` is deliberately untouched. It opens VS Code at the worktree and never
launches Claude, so it has no session to hand a role to. The marker works for it anyway
because the marker lives in the worktree, not in the launch.

One command sets it by hand:

```powershell
Set-Content .claude\seat 'builder'
```

---

## 4. The roster, and which document governs it

Five seats: **Console, Builder, Regulator, Steward, Lander.** That list comes from section 5
of `CLAUDE.md`. The Reviewer was a sixth until 2026-09-05, when the owner retired it with the
`reviewed` label and the review gate.

**The vault's `roles/README.md` disagrees, and it is the stale one.** Its table still
lists Dispatcher, PM, Liaison, ASVS Tracker, Cleaner, Role manager and Process
improvement as live seats, and it says of itself that it is a partial list. Section 5
settles this directly: a document naming a retired seat is stale, and section 5 wins.

So the cards are written against section 5's roster, using the vault playbooks only as
raw material for the seats that survived.

**Two live seats have no playbook at all.** Console and Regulator have no file in
`roles/`. Their cards are written from section 5 alone, and this is stated on the card
so nobody goes looking for a longer version that does not exist.

---

## 5. What this does not do

- **It does not make a session obey.** It makes the rules present. That is the same
  honest limit `seat-declare-prompt.ps1` states about goals: a machine that invents one
  writes a record that looks declared and says nothing.
- **It does not touch the root `CLAUDE.md`.** No section moves and no line is added.
- **It does not replace the seat declaration.** `seat.ps1 -Declare` still carries the
  goal, which no machine can write. The marker carries the role, which one can.
- **It does not compete with nested `CLAUDE.md` files.** Those scope by directory. A
  Builder and a Lander editing the same folder need different rules, so directory
  scoping cannot carry a seat.

---

## 6. Rollout

The hook is wired in the tracked `.claude/settings.json`, so a worktree gets it only
once its branch contains that commit.

Measured 2026-09-05 against `origin/main` at `16efb8cde`: of 20 live worktrees, **5**
contain the tip and **15** are behind it.

**No backfill.** The 15 pick it up on their next rebase or when they are recreated.
Worktrees turn over fast enough that this settles on its own -- 216 of 233 were reaped
on 2026-09-05.

---

## 7. Testing

| Test | Asserts |
|---|---|
| Missing marker | Exit 0, no card, the setting command is printed. |
| Unknown label | Exit 0, no card, no guess. |
| Unreadable or oversized card | Exit 0, the failure is named. |
| Vault absent | Exit 0. The hook never reads the vault. |
| All 8 Builder spellings | Each maps to `builder`. |
| Every retired seat string | Maps to nothing, and says which section retired it. |
| `git check-ignore` on the marker and `ROLE.md` | Both ignored. |
| Each card | At or under 150 lines and 6 KB. |
| Branch named `claude/lander-x` with no marker | No card. Proves rung 4 does not guess. |

The last two rows matter most. A card budget that is not enforced drifts, and a
resolution order that is not tested for silence is one bug away from guessing.

---

## 8. The one unverified assumption

A `SessionStart` hook can return JSON carrying `hookSpecificOutput.additionalContext`,
which renders at the weight this design wants. This session received exactly that from
a plugin hook, so the mechanism works. **What is untested is whether a hook wired in
the project's own `.claude/settings.json` can emit it.**

The probe is cheap: one hook, one distinctive token, one fresh session.

**The fallback is already proven.** `seat-declare-prompt.ps1` writes plain stdout from
project settings and that text reaches the session. It renders as hook output rather
than as additional context, which is a little weaker, but it is not a blocker. The
design ships either way.

---

## 9. Build record

Built 2026-09-05 on its feature branch. Test-driven: the tests
were written first and watched fail (46 failed, 2 passed) before any of the code below
existed. The 2 that passed at RED were the git-ignore assertions, which correctly held
already and must keep holding.

### Files added

| File | What it is |
|---|---|
| `docs/roles/seats.json` | The roster, the alias map, and the retired seats with reasons |
| `docs/roles/console.card.md` | Role card, no vault playbook exists |
| `docs/roles/builder.card.md` | Role card |
| `docs/roles/regulator.card.md` | Role card, no vault playbook exists |
| `docs/roles/steward.card.md` | Role card |
| `docs/roles/lander.card.md` | Role card |
| `scripts/hooks/role-card-inject.ps1` | The SessionStart hook |
| `tests/test_role_cards.py` | 50 tests |

### Files changed

| File | Change |
|---|---|
| `.claude/settings.json` | Wires the hook at SessionStart, beside `seat-declare-prompt.ps1` |
| `tests/tooling_manifest.txt` | Classifies the new test as harness tier |

### What was cut, and why

Two things in the design were deliberately not built. Both are marked in place above.

1. **The seat-record resolution rung.** It fires only where a session declared a seat but
   nobody wrote a marker, and in that state the next session is no likelier to have one.
   Having `seat.ps1 -Declare -Seat` write the marker collapses it into rung 1 and is the
   better end state. Not built, unallocated.
2. **`new.ps1 -Seat`.** That script makes sibling worktrees only, 3 of the 20 live ones.
   One `Set-Content` line covers every path and the hook prints it.

### Verification actually run

| Check | Result |
|---|---|
| `pytest tests/test_role_cards.py` | 50 passed |
| `pytest` on the 4 affected files | 117 passed |
| `ruff check` | clean |
| `ruff format` | 1 file reformatted, then clean |
| `mypy` strict | no issues |
| Glyph scan, with `BACKLOG.md` as positive control | control fired at 2,134; subject 0 |

**Not run: the full suite.** It does not finish inside one turn. The four files above are
the ones this change can affect: the new tests, the tooling partition gate, the settings
contract, and the private-paths gate.

**Not run: any hosted-runner leg.** Those report after this session exits and somebody
else has to read them.

### The one thing still unproven

Whether a hook wired in the project's own `.claude/settings.json` can emit
`hookSpecificOutput.additionalContext`, or only plain stdout. Section 8 states the probe.
The hook emits the JSON and the tests accept EITHER shape, so it works either way -- what
is unknown is only whether the card renders at full weight or as hook output. The first
session to start in a worktree with a marker set will answer it.
