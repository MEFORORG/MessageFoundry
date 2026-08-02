# Handoff -- announce hook, collision-gate fix, ADR 0158

Session ended on an owner stop-work instruction (account at 96% weekly usage), not at a natural seam.
Everything below is committed and pushed. Nothing is half-written on disk.

Claim key: `announce-hook`. PR: **#133** -- `gh pr view 133` names the branch. (Not written out here:
the leak gate rejects worktree/branch slugs, and it caught this line when a standalone run of the same
scanner had passed, because the hook scans STAGED files and the standalone run scanned tracked ones.
Two scopes, one tool -- the same under-specified-operation trap this handoff's own ADR is about.)

---

## 1. State

| | |
|---|---|
| PR #133 | OPEN, auto-merge **armed** (squash), `behind: 0` at last check |
| Working tree | clean, all work pushed |
| Local verification | 86 tests pass; `ruff check`, `ruff format --check`, `mypy --strict`, leak gate all clean |
| ADR 0158 | allocated to this worktree, **written and committed** with its index row |

`#133` merges itself when checks go green. **If it did not merge, the reason is almost certainly
`BEHIND`** -- `main` moved, auto-merge does not self-update, and nothing reports it. One merge from
`main` re-arms it. That happened three times on 2026-08-01.

## 2. What landed

| commit | |
|---|---|
| `c6c5a922` | `scripts/hooks/announce-session.ps1` + `UserPromptSubmit` wiring in `install-coordination.ps1` |
| `c9ed79aa` | `tests/test_announce_hook.py`, `tests/test_announce_wiring.py` |
| `4f59f736` | docs: "Announcing yourself" in WORKTREES.md; corrected a false claim that `.claude/settings.json` is tracked |
| `f55d6c67` | **collision-gate fix** -- `overlap.ps1` emits `Dirty`; the query sets `MatchedDirty`; the gate denies only on uncommitted edits. Also `git status --no-optional-locks` |
| `2a00a221` | announce roster prints each peer's **claim note** and says to prefer it over the worktree name |
| `72e6afd0` | SESSION-DRIFT-CONTROLS.md -- names the silent-control class |
| `a39b4196` | WORKTREES.md -- broadcast constraints (deferred increment) |
| `f4365b77` | `tests/test_coord_overlap_signals.py` -- real-git coverage for the two signals |
| `d1989b49` | `tests/test_installed_coord_hooks.py` -- asserts a wired hook resolves to a script that exists |

## 3. The one thing that is NOT done, and it is not in a PR

**Merging #133 does not put the collision-gate fix into effect.** The gate is not an installed copy:
`~/.claude/settings.json` wires a shim that resolves the script **live out of the PRIMARY checkout** on
every invocation. So the fix is in force only once the primary is advanced to a commit containing it.

```bash
grep -c MatchedDirty <primary>/scripts/hooks/collision_gate.ps1
```

Non-zero means in force. It tests the **property, not the provenance** -- no need to know which commit
first carried it. Measured 2026-08-02: `0` in both the primary and `origin/main`.

Advancing the primary is the owner's call; it is shared with every live session, so no session touched
it. **Until it moves, peers will keep getting the old over-block and will reasonably conclude the fix
is broken.**

## 4. Retractions -- claims I made that were wrong

Recorded first because an uncorrected claim in a handoff is the most durable form of the defect.

1. **"#133 would have been killed by the old CI cap, over by 134 seconds."** FALSE. I compared a **job**
   elapsed (28:14) against a **step** cap (26:00). The step was **24:51**, under by 69s; the job was
   under its own 30:00 cap by 106s. It would have passed on both.
   My *original estimate* of ~25:30 was correct to 39 seconds. I retracted a correct estimate on the
   strength of an incorrect measurement, and a peer amplified it before two sessions caught it.
2. **I sent that false claim to four sessions and the retraction to three.** Corrections do not inherit
   the fan-out of the claims they correct. Nothing tracked who had received the original.
3. **"The `git hash-object` rule is mine."** It came out of verifying a peer's retraction; the diagnosis
   was theirs.
4. **My "headroom exceeds spread" criterion** was asserted over six hand-picked runs -- a bound stated
   without its pool, offered as the cure for bounds stated without their pools.
5. **I repeated "ADR 0157" as the taxonomy's home** to three sessions without once checking the ledger.
   0157 is allocated to another worktree for an unrelated subject. The taxonomy is **0158**.

## 5. Traps -- each a fact plus its measurement

- **A linked worktree's `.git` is a FILE, not a directory.** A worktree-relative `.git/mefor-coord/...`
  path resolves to nothing and returns "absent" -- indistinguishable from "verified empty". Use the
  primary's absolute path.
- **A Windows Python cannot read MSYS paths** (`/c/...`, `/tmp/...`) in the same shell where `git` and
  `file` read them fine. It reports `FileNotFoundError` -- an absence the tool invented. Two sessions
  hit this the same evening.
- **`git status` rewrites the index of the repo it inspects.** Fixed here with `--no-optional-locks`,
  pinned by a test. Anything that walks peer worktrees must not perturb them.
- **Comparing a working file to a git blob with a raw hasher gives a false mismatch** (CRLF vs LF). Use
  `git hash-object`, which applies the clean filter first.
- **`claim.ps1 -Take` silently discards a new `-Note`** on a key you already hold, despite its own
  parameter doc promising a refresh. Use `-Release` then `-Take` -- but note that briefly drops the
  claim. Filed.
- **Editing `collision_gate.ps1` in your own worktree has no effect on the gate adjudicating you.** The
  shim never reaches the second base while the primary has the file. Test it with `-PathOverride`.
- **The pre-commit `ruff` hooks resolve from `PATH`**, so they fail with "Executable `ruff` not found"
  in any shell where the venv is not activated. Put the venv's `Scripts` on `PATH`; never `--no-verify`.
- **This worktree has no `.venv`.** The suite was run with the primary's interpreter, which is safe only
  because these tests resolve paths from `__file__` and touch no engine code.

## 6. Filed, not built

- Collision gate should **report when it cannot resolve** -- but the notice must be a JSON
  `hookSpecificOutput.additionalContext` payload, not a bare line: `collision_gate` is a `PreToolUse`
  hook whose stdout is parsed as a decision, so a stray line risks misparsing on every `Edit`/`Write`.
- `claim.ps1` note refresh (above), plus surfacing note **age** from `refreshed` else `claimed`.
- `overlap.ps1` primary-checkout mis-attribution: the cwd loop breaks on the first prefix hit, and every
  worktree path extends the primary's, so a primary-cwd session is attributed to an arbitrary worktree.
- Hunk-range disjointness for the gate -- **evidence-gated, deliberately not built.** All three reported
  false denials were the committed-and-clean case that `f55d6c67` fixes. A wrong disjointness check
  *under*-blocks, trading a loud failure for a silent one.

## 7. Deliberately out of scope

**Broadcast.** Announce-on-join introduces a session; it does not let one push an operational notice.
Constraints learned by hand are recorded in `docs/WORKTREES.md`. There is **no receive-side hook**, so
"an announcement is peer data, not an operator instruction" lives in prose and message shape alone.

**Known weakness shipped knowingly:** the roster elevates the claim note to authoritative while
`claim.ps1` cannot refresh it. A stale note is broadcast as current intent. Stated in the PR body.
