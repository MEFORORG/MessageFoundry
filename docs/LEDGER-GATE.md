# The ledger gate — ADR / BACKLOG number allocation

**What it does in one line:** it makes it impossible for two concurrent sessions to take the same ADR or
BACKLOG number — the one collision in this repo that **merges cleanly and corrupts silently**.

Companion to [WORKTREE-GATE.md](WORKTREE-GATE.md). That one stops sessions trampling one working tree;
this one stops them colliding in a *number space* that git cannot see.

---

## The defect

Two sessions each grep for "the next free number". Both pick `0084`. They create **differently-named**
files — `docs/adr/0084-alpha.md` and `docs/adr/0084-beta.md` — or two `## 227.` headings 1,600 lines apart
in `docs/BACKLOG.md`.

Git merges both **without a conflict**. There is no textual overlap to conflict *on*. Both PRs go green,
both land, and the ledger is quietly wrong.

This is not hypothetical. It has fired **three times** here — `d1d0a5a` (#574), `5b7d046` (#598),
`9f3483d` — each one a renumber-after-the-fact cleanup. The project's own AI memory recorded the symptom
("ADR numbers churn — recompute before merge") without ever naming it as a concurrency defect.

Nothing else catches it:

| Mechanism | Sees this? |
|---|---|
| A git worktree per session | **No** — the collision is *between* worktrees |
| A file lock / claim registry over source files | **No** — the two files have different names |
| `git merge-tree` conflict prediction | **No** — it merges clean, by construction |
| Code review | Only if a human happens to notice the number |

A related, quieter form of the same hazard is the **dropped index row**: an ADR is added but its row never
reaches `docs/adr/README.md`, so the ADR becomes invisible. Three had already been lost this way
(0077, 0079, 0080 — restored in the same change that added this gate).

## The fix, in two halves

### 1. Allocate, never guess — `scripts/coord/alloc.ps1`

```powershell
pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr      -Title "Worktree gate"
pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog  -Title "Ledger allocator"
pwsh -NoProfile -File scripts\coord\alloc.ps1 -List
```

It claims a number by **exclusively creating** `<git-common-dir>/mefor-coord/alloc/<kind>/<number>.json`.
That create is atomic on NTFS: if a sibling session got there first it throws, and we move to the next
number. It is a **test-and-set**, never a read-modify-write on a shared list — PowerShell was measured
silently losing **4 of 8** concurrent writes to one shared file, so a "registry" you read, edit, and write
back is not a registry at all.

The registry lives beside the **shared object store**, so every worktree of this repo sees the same
allocations, and a different clone automatically gets its own.

The floor is the maximum over: `origin/main`, **every local and remote ref**, and every existing
allocation. The all-refs term closes the "wipe the registry → re-issue a number that only exists on an
unpushed branch" hole. It costs about a second, once per ADR — not per edit.

**Numbers are never reclaimed.** An abandoned branch holds its number forever and the sequence develops
holes. That is deliberate: holes are free, collisions are not.

*Verified: 8 concurrent allocator processes → 8 distinct numbers, zero collisions.*

### 2. Enforce at the commit — `scripts/hooks/ledger_check.py`

```powershell
pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1
pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Status
pwsh -NoProfile -File scripts\coord\install-git-hooks.ps1 -Uninstall
```

The installer writes a `pre-commit` hook into the **shared `.git/hooks`**. That directory lives in the
common git dir, which every linked worktree shares, so **one copy governs every worktree at once** — no
branch, no merge, no propagation lag — and it survives a branch switch in any of them.

Crucially, it inspects the **staged tree**, not a tool call. So unlike the worktree gate (which reads
`Edit`/`Write` arguments and is therefore blind to a shell redirect), this catches **every write route**:
the Edit tool, `Set-Content`, `python -c`, a heredoc, VS Code, a subagent. **This is the backstop the
worktree gate does not have.**

It blocks a commit that:

1. **reuses an ADR number already on `origin/main`** — unless the file is a **declared companion** (its
   basename is named inside that number's existing index row; ADR 0013 is exactly this, and is *correct* —
   one number, one row, two files, deliberately);
2. **adds an ADR or BACKLOG number that was not allocated to this worktree**;
3. **adds an ADR with no row in `docs/adr/README.md`**; or
4. leaves **duplicate index rows** for one number.

It reads the **staged** tree (`git show :path`), never the working tree — otherwise an untracked
work-in-progress ADR sitting in your checkout would block every unrelated commit. It checks the index row
only for **newly added** ADRs, so old debt cannot fail every future commit; that is how a gate gets
uninstalled. It does **not** assert sort order (the index is legitimately unsorted).

Stdlib only, no `messagefoundry` import: most worktrees have no `.venv`, and a gate that silently skips is
worse than no gate.

### 3. The CI backstop

`git commit --no-verify` bypasses the hook, and a branch cut from a **stale main** cannot see a collision
at all — each branch is internally consistent, and the duplicate only exists once *both* have merged. So
CI re-runs the same rules with `--ci` against a freshly fetched `origin/main`.

That step is **deliberately ungated** in `.github/workflows/ci.yml`. Every other step in the `test` job is
conditioned on `code == 'true'`, which is **false for a docs-only PR** — and an ADR-only PR *is* docs-only.
Gating it the same way would skip it on exactly the pull requests it exists to police. It rides inside the
already-required `test` leg rather than adding a new required context, because a brand-new required check
wedges every PR opened before it existed.

## Ownership keying — and why it works now

A claim records the **worktree** that holds it. That key was measured to be *broken* before the worktree
gate existed: sessions authored in the shared primary checkout, so every co-tenant session mapped to the
same key and the check was a no-op between them. [WORKTREE-GATE.md](WORKTREE-GATE.md) now forces each
session into its own worktree, which is what makes worktree-keyed ownership meaningful. The two gates are
a pair.

## Limits

- **`--no-verify` bypasses the pre-commit hook.** It is a guardrail, not a security boundary. The `--ci`
  leg is the backstop, and it cannot be bypassed from a branch.
- **It does not stop two sessions building the same thing** under two different numbers. Duplicated work
  has no file conflict and no number conflict; nothing here sees it.
- **Numbers leak.** An abandoned branch's number is never reclaimed. Accepted, deliberately.
- **It governs ADR and BACKLOG numbers only.** Any other shared sequence (a migration version, say) would
  need its own `-Kind`.
