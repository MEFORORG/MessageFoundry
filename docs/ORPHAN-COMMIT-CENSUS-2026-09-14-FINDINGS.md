# Orphaned-commit census, 2026-09-14

A census of work that was committed and pushed, never landed on `origin/main`, and never
carried a pull request. It covers the whole ref history, not one day.

## This number is a snapshot and it decays in hours

**47 distinct unlanded work items, 19 of them touching `messagefoundry/`, as of
2026-09-14T20:19:58 CDT, measured against `origin/main` at `1aa2d6a1b003568149d2727a1134b0c2add07db2`,
over 3203 pushed refs (1488 of them engine rescue tags).**

Never quote that as a bare count. It is a property of a moment, not of the repository.

**The tables below name 40 of those 47.** Seven engine-touching items are counted and never
named. Read "Counted 47, named 40" before you conclude that any commit is absent from this
register.

Two death events happened in one evening, four hours apart: 16:11:47 to 16:13:57 CDT, then
20:04:30 to 20:06:13 CDT. A sweep run between them was correct about its own window and wrong
as a statement about the repository. A census run before 20:04 could not see the second event,
and this one cannot see a third.

Re-run it rather than trusting it. The recipe is in the last section.

## Scope of the PR filter, which changed meaning during the census

The pull-request snapshot behind every "had a PR" verdict here was taken at **1126 PRs, highest
number 1133**. PRs 1134 to 1142 were opened from raw orphan branches after that snapshot, by an
actor no seat registry identifies.

Those nine are **not** in this data, and that is deliberate. This register reports the orphan
state as it stood before an unidentified actor attached PRs to it.

So do not read "has a PR" in any later re-run as "rescued and handled". Five orphans now carry
two PRs each, and a PR from an unknown actor is not evidence that work is safe.

## Controls, and two instruments that were broken

Every control below was run in this worktree. Two of them changed the answer.

### The deref control reproduces, at 538 rather than 537

The naive form drops annotated tags silently, because `%(committerdate)` is empty for a tag object.

```
git for-each-ref --format='%(committerdate:iso) | %(objectname:short) | %(refname:short)' \
  'refs/remotes/private/rescuetags/auto/**'
```

| Form | Refs | Empty dates |
|---|---|---|
| Naive, `refs/remotes/private/rescuetags/auto/**` | 1967 | **538** |
| Deref, same pattern | 1967 | **0** |

The prior measurement was 537 of 2301. Over `refs/remotes/private/rescuetags/**` this run counts
**2302** refs, one more than the recorded 2301, and 538 empty rather than 537. The corpus grew by
one ref between the two runs. The instrument agrees.

### The prescribed deref form corrupts the SHA for exactly those 538 refs

This was not in the brief and it is worth carrying forward.

```
--format='%(*committerdate:iso)%(committerdate:iso) | %(*objectname:short)%(objectname:short) | %(refname:short)'
```

The date halves concatenate cleanly, because a tag object has no `committerdate`. **The SHA halves
do not.** An annotated tag has both a `*objectname` (the commit) and an `objectname` (the tag
object), so the field becomes 80 characters: two SHAs glued together.

| SHA field length | Refs |
|---|---|
| 40 characters | 2665 |
| **80 characters** | **538** |

An 80-character string never matches a 40-character SHA, so every set-membership test fails for
those refs and all 538 are forced into the candidate bucket. **That defect alone inflated this
census by 229 branches** (1344 candidates before the fix, 1115 after).

Use the conditional form instead:

```
--format='%(if)%(*objectname)%(then)%(*objectname)%(else)%(objectname)%(end)|...'
```

Control: SHA field length is 40 for all 3203 refs, and empty dates are 0.

### The repository was shallow, which faked 739 unrelated histories

`git rev-parse --is-shallow-repository` returned **true**, with 16 graft points. On a shallow
repository `git merge-base` fails at the graft boundary, and that failure is indistinguishable
from genuinely unrelated history.

The first content pass returned **739 UNRELATED_HISTORY** verdicts. Deepening from both remotes
(`git fetch --unshallow origin`, then `git fetch private --unshallow`) dropped it to 728, and
inspection showed the remainder had a different cause entirely.

The adjacent instrument was **fine**, which is the trap: `git rev-list --count origin/main`
returned 1260 both before and after deepening, and all three reachability sets were byte-identical.
One instrument was silently broken while the one beside it was correct.

### Main's history was reset on 2026-07-06, so ancestry is void before that

```
git log -1 --format='%H %ci %s' 5fa6db9f42f1b71a36406208e1442903e77386bb
5fa6db9f4  2026-07-06 16:52:04 -0500  MessageFoundry - clean snapshot (history reset)
```

Main's root is a history reset. **97** candidate branches predate it and can never share an
ancestor with main, no matter how deep the clone. For those, content is the only available test.

### The remaining no-merge-base branches are vault content under engine-looking names

631 post-reset branches still had no merge-base. Sampling them by tree content rather than by
name shows why: they carry `BRIEF.md`, `COMMERCIAL-LICENSE.md`, `HANDOFF-*.md` and `.mefor-hooks`,
which is the **MessageFoundry-vault** tree, under branch names with no vault path segment
(`build-hook-drift-check`, `usage-log-format`, `lander/ruff-exclude-evidence-tree`).

A name-based vault exclusion does not catch these. A merge-base test on a deep repository does.

One marker test failed and is recorded so nobody repeats it: `COMMERCIAL-LICENSE.md` and
`CHANGELOG.md` are **not** vault-only. The engine tree carries both, so a marker test built on
them classified all 309 engine survivors as ambiguous. Presence of `messagefoundry/` plus a
resolving merge-base is the test that works.

### Validation against the known answer

The three known unrescued orphans (`1c0e442d3`, `00cf5ead4`, `88639f608`) all survive this
pipeline to the final register. The method reproduces a known answer before being trusted on
unknown ones.

## Namespaces covered, and those not

| Namespace | Refs | Covered |
|---|---|---|
| `refs/remotes/private/**` | 3022 | yes |
| `refs/remotes/origin/**` | 181 | yes |
| `refs/remotes/prfresh/**` (fetched fresh) | 1126 | yes, as the PR oracle |
| `refs/remotes/pr/**`, `prheads/**`, `origin-pr/**` | 2516 | yes, as a historical PR oracle |
| `refs/heads/**` (local branches) | about 1100 | **no** |
| `refs/tags/rescue*`, `refs/privtags/rescue*` | 3176 | **no** |
| `refs/anchor/**`, `refs/archive/**`, `refs/mfq/**` | about 230 | **no** |

The repository holds **13839 refs in total**. This census examined the pushed remote-tracking
namespaces, which is where the question lives, and did not examine local-only or archive tag
namespaces. A commit reachable only from `refs/heads/**` was committed but never pushed, which is
a different failure and outside this question.

The local PR mirrors were **stale** — highest numbers 1087, 939 and 593 against a live maximum of
1133. Relying on them alone would have missed every PR above 1087. One
`git fetch origin '+refs/pull/*/head:refs/remotes/prfresh/*'` closed that gap locally and kept the
whole pull-request join off the REST API.

## Counts, stated separately

| Stage | Count |
|---|---|
| Pushed refs examined | 3203 |
| Distinct tip commits | 2821 |
| Engine rescue-tag refs (peer's namespace) | 1488 |
| Engine branches whose **name** matched no PR | 872 |
| Engine branches surviving the full filter stack | **309** |
| Of those, deep symbol-checked | **309** |
| Symbol-check verdict: every added symbol on main | 113 |
| Symbol-check verdict: some added symbols on main | 44 |
| Symbol-check verdict: no added symbol on main | **31** |
| Symbol-check verdict: no symbols to check | **121 (unverified)** |
| Unlanded branches after ranking, deduped, non-merge | **47** |
| Of those, touching `messagefoundry/` | **19** |

Those last two rows are counts, not enumerations. The tables further down name 40 of the 47 and
12 of the 19. See "Counted 47, named 40".

**121 branches are unverified.** They add no Python function or class, so a symbol check cannot
speak to them. They are documentation, configuration, ledger and script changes. A separate
content test would be needed and this census does not make one.

The full filter stack over the 1488 engine rescue-tag refs:

| Filter | Removed |
|---|---|
| Branch name matched a PR head branch | 616 |
| Tip commit is on `origin/main` | 13 |
| Tip commit is a PR head oid | 145 |
| Tip reachable from some PR head | 405 |
| **Surviving** | **309** |

## Cross-check against the parallel sweep

Derived independently, not adjusted toward agreement.

| Quantity | Peer | This census | Read |
|---|---|---|---|
| Engine rescue-tag refs | 1481 | **1488** | Corpus grew by 7; consistent |
| Branch names with no PR | 299 | **309** | **Corroborates.** Same filter stack, different route |
| Death-signature branches | 12 | **16** | **Differs.** See below |
| Named branches left unchecked | 276 | **298** | Consistent with the above |

The 309 figure is real corroboration. A name-join alone gives **872**; only the full stack
(name join, then main-reachability, then PR-head oid, then PR reachability) lands near 299. Two
routes reaching the same neighbourhood is evidence.

The death-signature count differs because four branches were committed after the peer's sweep ran.
This census found all four independently, before being told they existed:

- `071376d5b` 20:04:30 `test(pipeline): confirm the log-halt teardown hole on the outbound tier`
- `3ddc2664b` 20:06:00 `wip(rescue): partial work for BACKLOG #1610 from a Builder killed mid-push`
- `99b04deda` 20:06:06 `wip(rescue): partial work for BACKLOG #1717 from a Builder killed mid-push`
- `76a39b80d` 20:06:13 `feat(tls): per-connection tls_ciphers on the MLLP and DICOM connectors`

## The death-signature filter has false negatives, and the sample did not support it

This is the residual the parallel sweep did not close, and it is the main result here.

Of the **31** branches whose added symbols are entirely absent from `origin/main`:

| Branch naming | Count |
|---|---|
| Harness `worktree-agent-*` or `detached/*` | 13 |
| **Ordinary branch name** | **18** |

**18 unlanded branches carry ordinary names.** A filter keyed on the `worktree-agent-*` signature
cannot see any of them. A session that renamed its branch before dying looks exactly like healthy
work to that filter, which is precisely the false-negative shape the filter cannot detect in
itself.

Examples, all named, all with zero added symbols resolving on main:

- `b1-1332-scannable-segments` — `wip(gate): round two on the four fail-opens, VERDICT UNKNOWN -- DO NOT LAND`
- `claude/builder-2-1264-clock-fanout` — `fix(coord): the exclusion receipt withheld the address`
- `b1-1327-settings-kwarg-check` — `test(settings): pin every settings-model keyword to a real field`
- `1220a608e` — `feat(coord): detect a dead fleet and brief its replacements`
- `85e74facb` — `#1141 (ASVS 6.4.5): admin-issued credential carries the deadline the login gate enforces`

On whether ten sampled branches justified skipping the other 276: **they did not.** Ten is under
four percent of the population, all drawn from one namespace, and the property being tested
(did this work land under another name) varies by seat, by date and by whether the session
survived long enough to rename. The sample could not have detected the 18 above, because a
name filter and a sample drawn from already-landed branches share the same blind spot. Running
the mechanical check was cheap: one `git grep -f` pass over 637 symbols resolved all 309 branches
at once.

## Counted 47, named 40

The count and the enumeration disagree. Recorded here rather than quietly corrected, because
either number on its own misleads a reader.

| Quantity | Counted | Named in a table below |
|---|---|---|
| Distinct unlanded work items | **47** | **40** |
| Touching `messagefoundry/` | **19** | **12** |
| Not touching engine packages | **28** | **28** |

The counted figures partition exactly: 19 plus 28 is 47. The non-engine table is complete at 28
rows. So the deficit is one gap and not two. The engine table below carries 12 rows against 19
counted items, and the seven that are missing are engine-touching.

**Do not read the headline down to 40.** The 19 and the 28 were measured over the ranked set. The
12 is a count of rows that got written. Lowering 47 to 40 would throw away a real measurement to
match an incomplete table.

**Do not read the 12 rows as the whole engine-touching population either.** A reader who fails to
find a commit in the table below has learned nothing about that commit. That is the failure this
register exists to prevent, so it is stated here rather than left to be discovered.

### It is not a severity filter, and that was checked

The heading over the 12 rows names a narrower set than `messagefoundry/`, so an unstated filter
is the natural first reading. It does not hold. The rows themselves already include `pipeline/`,
`config/`, `support/` and `secretscrub.py`, which that heading does not cover, and the second
table states that none of its 28 items touch engine packages. There is no third bucket for the
seven to sit in. The heading was loose prose over an engine-touching table and is corrected
below.

### The seven are not recoverable, and this register's own scope note says why

Re-derived 2026-09-15T08:51 CDT against `origin/main` `0f9206ad2`, over 1535 engine rescue-tag
refs, against a pull-request snapshot of 1167 PRs, lowest number 1 and highest 1174. Three
controls held: every SHA field 40 characters, zero empty dates, and a lowest PR number of 1,
which is what rules out the list cap this register warns about. `origin/main` did not move during
the pass. This is a second reading at a later clock, not a correction of the reading above.

That pass cannot reproduce the population this register measured, for the reason recorded in
"Scope of the PR filter" above. Of the 12 named engine rows:

| Outcome of the re-derivation | Rows |
|---|---|
| Removed, because a PR now attaches to them | 8 |
| Survive every join and still read as unlanded | 3 |
| Survive every join, but their added symbols now resolve on main | 1 |

The eight now carry the pull requests this register deliberately excluded: `00cf5ead4` to PR 1134,
`1c0e442d3` to 1135, `88639f608` to 1136, `f527196e5` to 1137, `9c1efdaaf` to 1138, `071376d5b` to
1139, `99b04deda` to 1141 and `76a39b80d` to 1142. The three still reading as unlanded are
`ec723cc33`, `85e74facb` and `1d012f8f9`. The one whose added symbols now resolve on main is
`b2fe6d5ea`.

So a re-run now reads two thirds of this register's own engine rows as handled. That is the decay
the snapshot section predicted, measured rather than argued.

The census's intermediate files did not survive, and a later pass draws a different population
over a moved PR oracle. Naming seven items found at a later clock would put a different population
under the same heading, so none is offered. **The 12 named rows are the durable artifact. The
seven unnamed items are lost unless the author's working data resurfaces.**

## Verified unlanded work, ranked

Severity reads the paths against the invariants CLAUDE.md names. Nothing here is a live exposure
(section 0: zero deployments); these are unlanded fixes, and the cost is that the fix is missing.

Rows cite the **SHA**, not the branch name. The leak gate refuses a worktree or branch slug in
committed text, and it refused this file twice while it was being written. A SHA is the better
citation anyway: it survives a branch rename, and a rename is one of the ways this work went
missing.

### Touching `messagefoundry/`, 12 rows against 19 counted

**This table is incomplete by seven rows** and they are engine-touching. Not finding a commit
here is not evidence that the census missed it. See "Counted 47, named 40".

| Date (CDT) | SHA | Subject | Engine paths | Symbols on main |
|---|---|---|---|---|
| 09-14 16:13:57 | `88639f608` | `fix(store)`: unwind the SQLite writer transaction on cancellation, not only on Exception | `store/store.py` | 0 of 5 |
| 09-14 16:12:55 | `1c0e442d3` | `fix(auth)`: a config knob could switch off the factor-binding refusal | `api/security.py`, `auth/service.py` | 0 of 2 |
| 09-14 16:12:07 | `f527196e5` | `fix(auth)`: make the account-lockout counter atomic so parallel failures cannot evade it | `auth/service.py`, `store/base.py`, `store/postgres.py`, `store/sqlserver.py`, `store/store.py` | 0 of 3 |
| 09-14 16:13:03 | `00cf5ead4` | `fix(secretscrub)`: bound the DSN scheme class so the scan is linear | `secretscrub.py`, `support/redact.py` | 0 of 4 |
| 09-14 16:11:47 | `9c1efdaaf` | `fix(dr)`: open the snapshot under the real store settings, and read its PHI | `__main__.py`, `pipeline/dr_backup.py` | 0 of 4 |
| 09-14 20:06:13 | `76a39b80d` | `feat(tls)`: per-connection `tls_ciphers` on the MLLP and DICOM connectors | `config/tls_policy.py`, `config/wiring.py`, `transports/dicom.py`, `transports/mllp.py` | 0 of 1 |
| 09-14 20:06:06 | `99b04deda` | `wip(rescue)`: partial work for the `.mfbak` restore subcommand | `__main__.py`, `pipeline/dr.py`, `pipeline/dr_backup.py` | 0 of 12 |
| 09-14 20:04:30 | `071376d5b` | `test(pipeline)`: confirm the log-halt teardown hole on the outbound tier | `pipeline/wiring_runner.py` | 1 of 3 |
| 09-03 17:40:08 | `ec723cc33` | `#1134`: give the corpus a provenance digest that is true everywhere | `auth/policy.py`, `auth/service.py`, `config/settings.py` | 0 of 5 |
| 08-22 07:38:34 | `85e74facb` | ASVS 6.4.5: admin-issued credential carries the deadline the login gate enforces | `api/auth_routes.py`, `api/auth_models.py`, `api/_ui_seam.py`, `auth/service.py` | 0 of 4 |
| 08-22 08:08:26 | `b2fe6d5ea` | ASVS 11.2.4: constant-time, total comparison of the secret-rotation keyed MAC | `pipeline/secret_rotation.py` | 0 of 6 |
| 08-22 07:27:40 | `1d012f8f9` | `#1134`: retire the seven top-10k corpus claims the rebuild falsified | `auth/policy.py`, `auth/service.py`, `config/settings.py` | 0 of 3 |

`88639f608` is the one that touches a CLAUDE.md section 2 do-not-break invariant. It unwinds the
SQLite writer transaction on cancellation, which is the at-least-once staged-queue guarantee, and
it adds a test file absent from main. `f527196e5` and `b2fe6d5ea` are the next most serious: an
atomic lockout counter across all four store backends, and a constant-time MAC comparison.

Two of the August ASVS items (`85e74facb`, `b2fe6d5ea`, both from the same seat's worktree family)
have sat unlanded for **23 days**. They are not part of either evening event. Whatever produced
them failed quietly three weeks ago and nothing surfaced it.

### Not every orphan is lost work, and three say so themselves

Three of these branches carry a deliberate refusal in their own subject line:

- `ae9066bf6` — `wip(worktree-gate): fourth UNVERIFIED snapshot ... DO NOT LAND`
- `caae4ce31` — `verdict(worktree-gate): #1336 candidate is NOT LANDABLE -- it opens the gate it was fixing`
- `5c889a822` — `wip(gate): round two on the four fail-opens, VERDICT UNKNOWN -- DO NOT LAND`

These are pushed so the evidence survives, and unlanded on purpose. A rescue pass that treats
every orphan as recoverable work would land a change its author had already judged unsafe. Read
the subject before acting on any row in this register.

### Older, lower-severity

28 further unlanded items touch `scripts/`, `docs/`, the IDE extension, the web console and
coordination tooling. None touch engine packages.

This table is complete: 28 rows for the 28 counted. The shortfall is entirely in the engine table
above.

| Date (CDT) | SHA | Subject |
|---|---|---|
| 2026-08-14T23:51 | `670bf14a2` | wip(coord): in-flight output for the fatal and serious findings |
| 2026-08-15T11:24 | `f7bbd99e7` | fix(coord): compare normalised paths with Ordinal, including the liveness fence |
| 2026-08-20T14:01 | `c1543b76b` | fix(gate): close an escape-blind span scan in the worktree gate |
| 2026-08-22T07:29 | `3ec818fad` | console: report the session revoke that actually happened |
| 2026-08-22T13:43 | `ca31c3ad8` | backlog: file the field 304 items already carry, where no tool can read it |
| 2026-08-22T15:46 | `c77a8cf69` | fix(coord): seat.ps1 wrote a literal backtick-t, so .writer-errors.txt was never a TSV |
| 2026-08-22T16:44 | `f5cde38ed` | feat(coord): a seat can see that the script it is coordinating with is out of date |
| 2026-08-22T16:45 | `82c9c085b` | feat(coord): the roster shows which seat.ps1 wrote each record |
| 2026-08-22T16:50 | `5d914e209` | fix(coord): the currency check called a branch that is AHEAD of main out of date |
| 2026-08-22T18:29 | `a603eedba` | fix(coord): pay for the caller-relative overlap term |
| 2026-08-23T00:53 | `ae9066bf6` | wip(worktree-gate): fourth UNVERIFIED snapshot -- DO NOT LAND |
| 2026-08-23T08:19 | `caae4ce31` | verdict(worktree-gate): candidate is NOT LANDABLE -- it opens the gate it was fixing |
| 2026-08-25T18:18 | `2fb552634` | feat(ide): a skipped live lookup offers the stubbing affordance instead of a dead end |
| 2026-08-27T16:01 | `1220a608e` | feat(coord): detect a dead fleet and brief its replacements |
| 2026-08-27T17:00 | `3fd70375c` | fix(webconsole): fetch-metadata never reached the /ui/static mount |
| 2026-08-27T19:39 | `2f9448ba1` | fix(coord): the claim gate reads the registry the WRITER writes |
| 2026-08-28T08:59 | `10b2ecb13` | test(settings): pin every settings-model keyword to a real field |
| 2026-08-28T10:47 | `2fe195644` | feat(coord): the assignment tracker, the output meter, and four corrections |
| 2026-08-28T11:13 | `0939d2875` | fix(coord): fleet.ps1 could not see a session that relocated |
| 2026-08-29T06:59 | `d90b72d29` | fix(coord): fleet.ps1 read stamp recency as an origin/main refresh |
| 2026-08-29T07:06 | `5dc8d00da` | fix(coord): the exclusion receipt withheld the address |
| 2026-08-29T07:41 | `eaf6d0940` | feat(coord): the dispatch gate green-lit three items the ledger retired in place |
| 2026-08-29T14:23 | `5c889a822` | wip(gate): round two on the four fail-opens, VERDICT UNKNOWN -- DO NOT LAND |
| 2026-08-31T18:55 | `9a48fcec6` | docs(tests): the required-set count in two control docstrings said thirteen |
| 2026-08-31T19:08 | `07b39cd02` | docs(tests): the required-set count in two control docstrings said thirteen |
| 2026-09-07T12:27 | `ffdceee86` | fix(board): withhold the merge-state panel when the read is TRUNCATED |
| 2026-09-12T14:00 | `bd24c462e` | wip(ledger): salvage the path-spelling pin test from a stalled Builder |
| 2026-09-14T20:06 | `3ddc2664b` | wip(rescue): partial work for the per-message finalize-lock concurrency tests |

### Excluded from the ranking, with reasons

- **3 merge commits.** A merge commit's diff against its merge-base includes the other parent's
  content, so file lists and symbol counts are not attributable to that branch's own work.
  `lander/w6-879` and `lander/458-merge-seat` looked severe for exactly this reason and are not.
- **7 duplicate snapshot families**, 62 distinct commits collapsing to 47 work items. The rescue
  copies made this evening (`e9cbb0e9e`, `7cd10fa1d` at 20:08 and 20:09) are re-tagged copies of
  `1c0e442d3` and `88639f608`, not new orphans. Counting snapshots rather than work items would
  have over-reported by about a third.
- **The BACKLOG #1494 cluster family**, six near-identical `detached/*` snapshots from 09-09 with
  11 of 12 symbols already on main. Very likely landed; not called orphaned.

## What this method cannot see

Stated plainly, because a census that hides its blind spots is worse than none.

1. **Anything committed after 2026-09-14T20:19:58 CDT.** Two events happened four hours apart
   this evening. There is no reason to think that was the last one.
2. **Work that was never pushed.** A commit reachable only from `refs/heads/**`, or living in a
   dead worktree's index, leaves no remote-tracking ref. This census cannot see it, and per
   CLAUDE.md section 5 an unpushed subagent branch produces nothing recoverable at all.
3. **The 121 branches with no added Python symbols.** Documentation, configuration and script
   changes are unverified here. That is 39 percent of the 309 survivors.
4. **Branches renamed between the tag and the PR.** The name join fails; the SHA joins catch most
   but not all of these.
5. **Work that landed as part of a larger squash.** A squashed commit's content is the union of
   its branch's commits, so an individual snapshot's symbols can be present on main while that
   snapshot was never itself merged. This inflates `ALL_ON_MAIN` and is the safe direction.
6. **Orphans do not map to dispatched items.** `#1717` in the 20:06 group was verified and
   **declined** as too large for one turn, and somebody built it anyway. A census keyed on
   assigned work would not have looked for it.
7. **The vault namespace**, deliberately. Vault refs were excluded by merge-base, not by name,
   after name-based exclusion proved to miss vault content on engine-looking branches.
8. **Seven of the 47 items this register itself counts.** The engine table names 12 of 19. A
   commit absent from the tables is not thereby absent from the census, and the seven cannot be
   re-derived now. See "Counted 47, named 40".

## Re-run recipe

Run these in order, from an engine checkout. They take a few minutes and need no REST budget
beyond one `gh pr list`.

```
# 0. Deepen. A shallow clone fakes unrelated histories and silently voids merge-base.
git rev-parse --is-shallow-repository
git fetch --unshallow origin
git fetch private --unshallow

# 1. Refresh the PR head mirror locally. The checked-in mirrors lag by dozens of PRs.
git fetch origin '+refs/pull/*/head:refs/remotes/prfresh/*'

# 2. Reachability baselines.
git rev-list origin/main                      > main_commits.txt
git rev-list --glob=refs/remotes/prfresh      > pr_commits.txt

# 3. Deref every pushed ref. Use the CONDITIONAL form: the plain concatenation
#    form doubles the SHA for annotated tags.
git for-each-ref \
  --format='%(if)%(*objectname)%(then)%(*objectname)%(else)%(objectname)%(end)|%(if)%(*committerdate:iso-strict)%(then)%(*committerdate:iso-strict)%(else)%(committerdate:iso-strict)%(end)|%(refname)' \
  'refs/remotes/private/**' 'refs/remotes/origin/**'  > pushed_refs.txt

# 4. Controls. Both must hold before you trust anything downstream.
cut -d'|' -f1 pushed_refs.txt | awk '{print length($0)}' | sort | uniq -c   # expect 40 only
awk -F'|' '$2==""' pushed_refs.txt | wc -l                                  # expect 0

# 5. The PR join, one call, not one per ref.
gh pr list --state all --limit 2000 --json number,headRefName,headRefOid,state > prs.json

# 6. Filter stack, then the symbol check: collect added `def`/`async def`/`class`
#    names per surviving branch, write them to patterns.txt, then resolve all at once:
git grep -F -o -h -f patterns.txt origin/main | sort -u
```

A symbol absent from that last command's output is absent from `origin/main`. A branch whose
added symbols are all absent did not land.

Grep for `def test_` alone is async-blind and will miss every `async def test_*`. The pattern
above takes both.

## Provenance

Measured 2026-09-14T20:19:58 CDT against `origin/main` `1aa2d6a1b`, over 3203 pushed refs,
against a pull-request snapshot of 1126 PRs with highest number 1133. Seat: Builder.

The count reconciliation in "Counted 47, named 40" is a second, later reading: 2026-09-15T08:51
CDT against `origin/main` `0f9206ad2`, over 1535 engine rescue-tag refs, against a pull-request
snapshot of 1167 PRs with highest number 1174. Seat: Builder. It does not restate or replace the
measurement above.

This register does not rescue, rebase or re-open anything, and files no backlog numbers. Which of
these items get rescued is a Lander or owner decision.
