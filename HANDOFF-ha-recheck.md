# HANDOFF — HA construct re-check / ADR 0157

Written 2026-08-02 on owner stop-work (weekly usage cap). Branch `claude/ha-recheck-adr0157`.

## 1. STATE

| | |
|---|---|
| Branch | `claude/ha-recheck-adr0157` (follow-up branch; its predecessor merged as #129) |
| PR | **[#139](https://github.com/MEFORORG/MessageFoundry/pull/139)** — OPEN, all commits pushed |
| Uncommitted | none |
| Claim | `ha-recheck` (this worktree) |

Earlier PR **#129 is MERGED** (`884036f8`, merged by the owner) — the doc corrections are on `main`.

## 2. DONE

| SHA | What |
|---|---|
| `bc9ccd73` | Corrected 5 classes of false split-brain claim in code + docs (in #129, on `main`) |
| `6c81c65e` | The third false-premise site `bc9ccd73` missed (in #129, on `main`) |
| `547b088b` | **ADR 0157** — demotion safety, Proposed, + index row (ledger gate passed) |
| `c20295c0` | **fix(delivery)** — leadership loss dead-lettered an un-sent row (strand) |
| `850e3f7b` | **ADR 0157 C3/C4 corrections** — both were strand-direction as written |

`c20295c0` is mutation-verified in both directions: revert the body to `mark_failed` → both tests FAIL;
restore → both PASS.

Gates at last run: `ruff check` clean · `ruff format --check` clean (1020 files) · `mypy` **no issues,
260 source files** · **125 passed** across dispatcher / pooled-rider / wiring / cluster suites.

## 3. IN FLIGHT — nothing half-built in code. One spec ready to apply.

**No partial edits exist.** The store's terminal-write path and the teardown ordering are untouched.

**The applyable spec is saved (79 KB):**
`<session-scratchpad>/ADR-0157-implementation-spec.md`

It covers Inc 1 (Postgres fences, C1+C5+C4) and Inc 4/5 (bounded demotion, C6). It opens with a
**five-item STOP list** — read that first. Its line numbers are re-derived from source because
**the ADR's own line numbers are stale**.

**Not yet designed:** the SQL Server increment. See §5 — the ADR's premise for it is wrong.

## 4. BLOCKED ON

**Nothing external.** The collision-gate deadlock is cleared: PR #133 merged, and I advanced the
**primary checkout** (it was 5 commits behind, 0 dirty, pure fast-forward), which is what actually puts
the fix in force — the hook resolves live from the primary, not from `main`.

Verify before assuming:

```bash
grep -c MatchedDirty <primary-checkout>/scripts/hooks/collision_gate.ps1
```

Non-zero = in force. It was **2** when I checked.

**Owner decisions are made** (C1 = terminal writes only, fail-open; C6 = yes, bounded, abandon-don't-
await). The remaining work is implementation against the corrected ADR.

## 5. RETRACTIONS — things I asserted tonight that were wrong

**These matter more than the wins. Every one was caught by a peer or by a check, never by me noticing.**

1. **My own ADR's C3 was a strand.** I wrote that a fenced terminal write should roll back and leave the
   row INFLIGHT for recovery. On SQL Server there is **no periodic in-flight recovery at all**, so that
   is an unbounded strand — the exact outcome the ADR forbids, produced by its own fence.
   **Corrected in `850e3f7b`:** roll back, then re-pend via unguarded `release_claimed`.
2. **My own ADR's C4 was a silent total halt.** "Delete the `set_leader_epoch(None)` clear" alone is
   unsafe once C5 lands: `_reconcile_graph` has only two branches, so `is_leader() and running` matches
   neither, forever, holding a stale epoch → a live leader claiming nothing, no exception, no alert.
   **Corrected in `850e3f7b`:** delete the clear **and** re-stamp on every reconcile pass while leader.
3. **I amplified a wrong CI number.** I reported #133's windows-2025 leg as **28:14** and said the old
   26:00 cap "would have killed it by 134s", calling it the strongest number of the night.
   **Wrong — that is the JOB; `step_timeout` gates the STEP, which was 24:51, UNDER the old cap by 69s.**
   #133 was **not** a second casualty; **#119 remains the only PR that cap killed.** I accepted it
   because it arrived as "a measurement correcting an estimate", which I treated as strictly improving.
   It is not: *a measurement is better than an estimate only when it measures the same quantity.*
4. **I mis-attributed BACKLOG #333** to the ASVS-scorecard session. It is the **Public repo security
   review** session's, filed in `b4665b10`. Verify attribution from `git log`, not from conversation.
5. **My merge-priority reasoning was wrong.** I argued #133 should merge before #129 "because it
   unblocks everyone". It does not unblock anyone *on merge* — the gate resolves from the primary
   checkout, so merging collects nothing until the primary advances. I had both measurements in hand
   and built the ordering on the conclusion anyway.
6. **I overstated a tally.** I said "one unit confusion, four sessions, six retractions". Audited: the
   job/step unit accounts for **three** of six. Exact form: *three of six from one unit confusion; all
   six caught by a peer, none by the author.*
7. **ADR scope drift — measured at 142 of 510 lines (28%)** on a subject allocated to ADR 0158, after I
   had written the guard against exactly that drift in my own notes. Trimmed to 319 lines.
8. **Four instrument errors**, three caught before acting:
   - `Get-FileHash` over a shell-redirected temp file reported DIFFERS for byte-identical files (the
     redirection re-encodes). `git hash-object` vs `git rev-parse origin/main:<f>` is the like-for-like
     form. I **nearly refuted a correct peer claim** with this.
   - A `.git/…` path relative to a **linked worktree** resolves to nothing (`.git` is a *file* there).
     `alloc.ps1` joins from `--git-common-dir`. I nearly reported a correct ledger as missing.
   - A regex with `**` on the wrong side of a word reported a surviving correction as absent.
   - **My first version of the `c20295c0` tests was vacuous** — asserting the row is `PENDING` with
     `attempts=0` passes against the pre-fix code, because a seeded row is *already* in that state.
     Only mutation testing caught it. Both tests now wait on a spy (positive signal).

## 6. TRAPS

- **`reset_stale_inflight` is startup/DR-only.** `RegistryRunner.reload()` is a quiesce-and-swap and
  calls no recovery, so a reload leaves cancelled prefixes INFLIGHT until the next process start.
  The codebase contradicts itself here: **`wiring_runner.py:1800` is right** ("strands INFLIGHT forever
  … startup/DR-only"); **`:4718` is wrong** ("recovered … on the next start/reload").
  ➡️ **Therefore the ADR's SQL Server increment is mis-specified.** It proposes an owner-blind,
  age-based periodic sweep. The verified defect is narrower — *no recovery at graph re-start* — and the
  right fix is a scoped reset there. An age sweep on SQL Server has **no `owner` column populated** to
  discriminate with, so it would re-pend live rows. **Do not build the ADR's version as written.**
- **Local `pytest` SILENTLY SKIPS the Postgres and SQL Server legs.** 97 skips in my last run. A green
  local run proves nothing about either backend.
- **`mypy` reports 21 phantom errors** unless the venv has the full extras. Bootstrap with
  `pip install --constraint constraints.lock -e ".[dev,harness,postgres,sqlserver,fhir,dicom,x12,xml,webauthn,sftp,vault,otel]"`.
- **Pre-commit needs `ruff` on PATH** in this worktree, or the ruff hooks fail with "Executable not
  found". Activate `.venv` or prepend the main checkout's. **Never `--no-verify`.**
- **The ADR's line numbers are stale.** Use the spec's re-derived ones.
- **Three parties have touched `wiring_runner.py`** (this fix, PR #136, an ASVS anchor). All far apart,
  but whoever rebases last should read it rather than trust a clean auto-merge.
- **`git status` rewrites the index of the repo it inspects** — `overlap.ps1` now uses
  `--no-optional-locks`. Relevant if you write tooling that walks peer worktrees.

## 7. NEXT STEP

Apply the spec's Inc 1 (Postgres fences) against the **corrected** C3/C4, then Inc 4/5. Re-scope the
SQL Server increment per §6 before building it. Everything is decided; nothing is ambiguous.
