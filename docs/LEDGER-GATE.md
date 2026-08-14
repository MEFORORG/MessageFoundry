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
pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog  -ShowFloor   # read-only: allocates nothing
```

`-ShowFloor` prints the computed floor, **the paths it swept**, the sub-partition maximum and the number
it would issue next — without claiming anything. Use it to answer "what can the floor see" instead of
spending a number on the question: allocation is a one-way door, so before this existed the floor's own
correctness was the one property nobody re-tested.

It claims a number by **exclusively creating** `<git-common-dir>/mefor-coord/alloc/<kind>/<number>.json`.
That create is atomic on NTFS: if a sibling session got there first it throws, and we move to the next
number. It is a **test-and-set**, never a read-modify-write on a shared list — PowerShell was measured
silently losing **4 of 8** concurrent writes to one shared file, so a "registry" you read, edit, and write
back is not a registry at all.

The registry lives beside the **shared object store**, so every worktree of this repo sees the same
allocations, and a different clone automatically gets its own.

The floor is the maximum over: `origin/main`, **every local and remote ref**, every existing
allocation, and a **persisted high-water mark**. The all-refs term closes the "wipe the registry →
re-issue a number that only exists on an unpushed branch" hole. It costs about a second, once per ADR —
not per edit.

**The all-refs term is only as good as the refs this clone still has, so the floor ratchets.** Measured
on the maintainer clone: the backlog floor is **314** counting every ref, but **252** counting only
`refs/remotes/origin` and local heads — the missing 62 live on remote-tracking refs for a remote that
`git remote -v` no longer lists. If those refs are removed, every derived term collapses and the
allocator silently resumes issuing numbers that are already in use, with no error. So the highest floor
ever computed is stored at `<git-common-dir>/mefor-coord/alloc/<kind>/.floor-highwater` and the floor
never goes below it; a computed floor beneath the mark prints a loud NOTE rather than quietly handing
out a used number. The mark can only rise.

**Two maximums, not one — and conflating them bricked the allocator on 2026-08-03.** The public backlog
sequence is partitioned from the maintainer-internal one at `PUBLIC_BACKLOG_FLOOR` (`#1000`), so the
allocator needs two different numbers:

| Measurement | Question it answers | Must include public numbers? |
|---|---|---|
| **Floor** — max over everything swept | *What must I not re-issue?* | **Yes** |
| **Sub-floor max** — max below the partition | *How much runway does the internal sequence have?* | **No** |

The residual detector read `Floor`. So the first legitimate item filed in the public sequence — `BACKLOG
#1000` — made every backlog allocation in the repository throw `REFUSING TO ALLOCATE … has reached the
public floor`. The guard was not detecting a breach; it was detecting the partition being used exactly as
designed, and it fired on correct input.

**That detector can now only WARN, and the limit is the data, not the implementation.** Once an internal
item is allocated at or above the boundary it is indistinguishable, in the published files, from a
legitimate public item at the same number — both are just `## N.` with N ≥ the floor. A refusal arm would
have to fire on correct input or never fire at all, so it was **removed** rather than made unreachable: a
branch that cannot fire reads as protection and is worse than none. Detecting a real breach needs an
internal-side input this repository does not have. What remains is a warning at 90 % of the boundary,
measured on the sub-floor band, where public numbers cannot distort it.

*(The sweep did reach internal numbers while the vault-ish refs were in this clone, which is worth
stating because the opposite was suspected: measured 2026-08-03, 489 of 490 of them carried
`docs/BACKLOG.md`, and 67 item numbers lived only there — including `#240`–`#247`, the numbers the
Ledger erratum records as re-issued over cited work. Those refs were deleted on 2026-08-05 and the sweep
no longer reaches them; see [The ref store, and the cleanup of
2026-08-05](#the-ref-store-and-the-cleanup-of-2026-08-05) for why neither measurement moved. Telling an
internal `#1001` from a public `#1001` was impossible either way.)*

Two consequences worth knowing before you tidy refs:

- **`git fetch origin --prune` is safe** — it prunes only `refs/remotes/origin/*`, which is not where the
  high numbers live. It is also what you *should* run before allocating.
- **Removing a non-`origin` remote, deleting its refs, or an aggressive `gc` / `reflog expire` that drops
  unreachable objects is what the ratchet defends against.** It keeps the number space correct, but the
  underlying history would still be gone — the ratchet is a backstop, not a substitute for the refs.
  **The principle stands; the specific alarm it was written under no longer binds here.** The 489
  vault-ish refs it named were deleted on 2026-08-05, and both allocator measurements — floor `1032`,
  sub-floor maximum `353` — were unchanged before and after. Read [The ref store, and the cleanup of
  2026-08-05](#the-ref-store-and-the-cleanup-of-2026-08-05) before concluding that a ref deletion here is
  or is not survivable: the answer turns on the `#1000` partition and the ratchet, not on the refs.

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
CI re-runs the rules with `--ci` against a freshly fetched `origin/main`.

**It re-runs all of them but one, and the exception is the ownership rule** — `ledger_check.py:196` and
`:241` both read `not self.ci and not self.owns(...)`, so *"was this number allocated to you"* is
**enforced locally and never in CI**. It has to be: `owns()` reads the allocation store from
`<git-common-dir>/mefor-coord/alloc`, a CI runner clones fresh and has none, so the check would return
False for every ADR and no ADR could ever merge. The consequence is worth stating plainly rather than
leaving as an inference — **a green CI on an ADR or BACKLOG PR is not evidence that the number was
allocated to anybody.** What CI *does* still catch, and what actually prevents the ledger corruption
this gate exists for, is collision-with-base, the missing index row, and duplicate rows.

So the residual after `--no-verify` is narrower than "unprotected" and wider than "backstopped": a
number belonging to another session's *unmerged* branch can be taken and committed with nothing
objecting. The corruption surfaces when the second of the two merges — the collision rule blocks it —
which is late, loud, and recoverable, rather than silent. That is the property the gate was built for;
allocation discipline itself is on the honour system once the local hook is skipped.

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

## The ref store, and the cleanup of 2026-08-05

This section exists because the ratchet warning above names refs a future session will go looking for and
not find. It is also the **only** record of where those refs came from: nothing else in the repository
named them, and the `refs/vault/**` trio was named by no tracked file at all.

### Where they came from

Reflogs record **two direct-URL `git fetch` commands, 45 seconds apart on 2026-07-28**, against
`github.com/wshallwshall/MessageFoundry` — the maintainer's private vault repository. One passed explicit
per-branch refspecs writing into `refs/remotes/vault/`; the other passed a wildcard writing into
`refs/remotes/vaultall/`. **No remote named `vault` or `vaultall` was ever configured** — `git remote -v`
has only ever listed `origin` — so no refspec could advance them and no `--prune` could ever have reached
them. They were orphaned the moment the fetch returned.

Three of them landed one level up, at `refs/vault/**` rather than `refs/remotes/vault/**`. That is what
made `vault/main` *look* like a remote-tracking ref when it was not:
`git rev-parse --symbolic-full-name vault/main` resolved to `refs/vault/main`, because gitrevisions tries
`refs/<name>` **before** `refs/remotes/<name>`. `refs/remotes/vault/main` never existed.
`docs/releases/BACKLOG-MULTISESSION-PLAN.md` §0 called it a
remote-tracking ref on that basis; that line is corrected.

### What was deleted, and what it cost the allocator

**2026-08-05: 489 refs carrying `docs/security` content were removed with `git update-ref -d`** —
`refs/remotes/vaultall/**` (466), `refs/remotes/vault/**` (20), `refs/vault/**` (3). That material is
maintainer-internal and its home is the separate `MessageFoundry-vault` clone, checked out beside this
repository — not a working checkout of the public one. Nothing was ever published from it: `origin/main`,
all 30 `origin` refs and every local branch carry zero `docs/security` files at tip and in history, and
`git rev-list --all -- docs/security` returns nothing here. A manifest of refname/SHA pairs is kept
**outside** the repository, every deleted tip is still addressable in this object store (no `gc` ran, and
`gc.auto` is now `0`), and every one is present in the vault clone — restoring any of them is one
`git update-ref` away. Per [ADR 0160](adr/0160-public-repo-content-policy-operator-and-security-review-material-only.md),
this is a content-placement decision and **must not be described as a confidentiality control**.

**Measured directly, before and after: the BACKLOG floor is `1032` and the sub-floor maximum `353`, with
the refs and without them.** Neither moved. Three reasons, any one of them sufficient:

1. **The partition clamps the answer.** A backlog allocation emits
   `max(observed, PUBLIC_BACKLOG_FLOOR - 1) + 1`, so every new number is issued at or above `#1000`. The
   internal band tops out at `#314` and cannot determine the next number.
2. **The internal band was already masked.** Internal `#314` sits below the public pre-partition maximum
   `#353`, so the deleted refs did not set the sub-floor maximum either — and the sub-floor maximum is
   the only term the residual warning reads. `alloc.ps1` records this as reason (d) beside its removed
   refusal.
3. **The ratchet held regardless.** The persisted marks were already `1031` (backlog floor high-water),
   `1000` (boundary) and `160` (ADR floor high-water) before the deletion, and a floor may only rise.

The allocator also **emits `max + 1` and never fills a gap**, so a number that drops out of the sweep
cannot be re-issued into a hole. Only a fall in the maximum itself would hurt, and the ratchet is the
instrument for that.

### One trap this closed, and the general lesson

While those refs were present, `git log --all -- <path>` in this clone could return commits from the
**vault lineage**, whose root is disjoint from the public repository's. A session reading that output
drew the wrong conclusion about a file's provenance, because a commit appearing under `--all` says only
that *some* ref reaches it — not that `origin/main` does. **The check that settles it is
`git merge-base --is-ancestor <commit> origin/main`.** This particular trap is closed with the refs gone;
the general form is not. Name the question, name what the tool returns, and check they are the same
sentence (CLAUDE.md §11).

## Editing an item *body* — the open-count control

Everything above governs **numbers**. Nothing above governs an item's **status**, which is encoded as a
banner glyph and read by `parse_items` (`scripts/docs/backlog_status_check.py`). There is no hook for
that, and the failure it admits is worse than a collision.

**The trap, measured 2026-08-13 on BACKLOG #1245.** A glyph from the closed alphabet
(`_CLOSED = "✅⛔🪦"`) used as **emphasis inside an item body** is read as a **status banner**. A
live, just-filed defect parsed as **CLOSED**. The open count went **200 to 199 on a pure prose
insertion** that added no item and closed nothing.

**Care does not prevent it, and knowing the rule does not either.** The glyph in that draft was doing
the same job it does throughout root `CLAUDE.md` — marking a "do not do this" paragraph. A banner and
an emphasis marker are the *same character in the same file*; only position distinguishes them, and
`parse_items` cannot see intent. This is `CLAUDE.md` §11's argument arriving as a defect rather than a
principle.

**The direction is what makes it dangerous.** A false OPEN is noise — someone re-reads a closed item.
A false **CLOSED removes the item from the queue**, so nobody looks again. The failure is silent *and*
semantically inverted: an unresolved defect recorded as resolved.

### The control

Run `parse_items` **before and after** every `docs/BACKLOG.md` edit and **diff the counts**:

```bash
python -c "import importlib.util,pathlib; s=importlib.util.spec_from_file_location('b','scripts/docs/backlog_status_check.py'); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); i=m.parse_items(pathlib.Path('docs/BACKLOG.md').read_text(encoding='utf-8')); print(f'{len(i)} items, {sum(1 for x in i if x.is_open)} open')"
```

Expected deltas, and **an edit that produces anything else is the tell**:

| edit | items | open | closed |
|---|---:|---:|---:|
| filing N new items | +N | +N | 0 |
| amending an item body | 0 | 0 | 0 |
| closing one item | 0 | −1 | +1 |

- **It must run *after* the edit.** Running it only beforehand catches nothing — the whole failure is
  in what the edit did.
- **"Does the file still parse?" is not the control.** The file parses perfectly. It simply means
  something else.
- **Run it every time, not when something feels off.** A control that only runs when you already
  suspect a problem is not a control. Applied blind to an unrelated item the same day, it correctly
  reported no change — which is the point.
- **The control was attacked before being written down.** A stray `⛔` was injected into a *copy* of
  the live file inside an open item's body: the count moved `201 open` to `200 open`, with the item
  total unchanged at `275`. So it demonstrably **sees this class**, rather than merely having been
  green on the day. A gate nobody has made fail on purpose is an assertion, not evidence.

**Safest habit:** never use `✅ ⛔ 🪦 🔢 🚧` anywhere in an item body — not as emphasis, not in a
nested blockquote. Say the word (`WARNING`, `DO NOT`). `⚠️` and `⭐` are outside both alphabets and
are safe.

## Limits

- **`--no-verify` bypasses the pre-commit hook.** It is a guardrail, not a security boundary. The `--ci`
  leg is the backstop for *collision*, and it cannot be bypassed from a branch — but it does **not**
  re-check ownership (§3), so that one rule has no backstop at all.
- **It does not stop two sessions building the same thing** under two different numbers. Duplicated work
  has no file conflict and no number conflict; nothing here sees it.
- **Numbers leak.** An abandoned branch's number is never reclaimed. Accepted, deliberately.
- **It governs ADR and BACKLOG numbers only.** Any other shared sequence (a migration version, say) would
  need its own `-Kind`.

## Citing a number you have not allocated

**The allocation rule has a mirror, and the mirror is the more insidious half.** `alloc.ps1` stops two
sessions from *issuing* the same number. Nothing stops a document from *citing* a number that was never
issued at all.

**While the number is unissued, the citation resolves to nothing.** That is honest and harmless: a
dangling reference advertises its own brokenness, and anyone who follows it immediately sees there is
nothing there.

**The day someone legitimately allocates that number, the citation begins resolving — to unrelated
work.** Nothing anywhere reports a problem, because nothing is broken in any mechanical sense. A
wrongly-resolving reference reads as a working cross-reference forever, which is strictly worse than a
broken one. This file's own header already states the general form of that trade: renumbering *"would
only make stale citations resolve uniquely and WRONGLY, which is worse than resolving ambiguously."*

### The rule

**Either allocate the number before citing it, or write the reference so it CANNOT resolve.**

Naming the subject instead of a number is enough, and costs nothing:

    #1203                                  arms the day 1203 is issued
    "the retention runbook step"           cannot arm
    "unallocated - see the runbook step"   cannot arm, and says so

### What is and is not dangerous

**Only a citation ABOVE the current allocation floor can arm.** A number at or below the floor is
already spoken for and can never be re-issued: `alloc.ps1` issues `$observed + 1` and never fills a
hole, and the floor is computed from **committed ledger headings**, which survive a fresh clone. So a
citation to a reserved-but-never-filed number resolves to nothing **permanently** — it is inert, not
merely quiet.

**Foreign `#N` references are not citations of this ledger at all** — an upstream driver issue, a
vendor forum thread, another project's tracker. They match a naive scan and are not this rule's
subject.

### Enforcement

`scripts/docs/dangling_citation_check.py` reports unresolved citations and keys its exit code on the
**live shape** — above the floor, and not foreign — rather than on a raw hit count, so the inert cases
are reported without failing anything. **It is fail-closed by default**, with `--advisory` as the
explicit escape. Note its stated coverage bound: it sees this repository only, and **not** the private
companion repository.

**Enforcement does not replace the rule.** A checker can only find what has already been written; the
rule is what stops it being written.
