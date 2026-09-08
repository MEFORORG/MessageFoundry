# 0185 — Retention levers for the tamper-evident `audit_log`: what each deletion shape costs verifiability

- **Status:** Proposed — this is an options memo, not a decision. It waits on the owner ruling
  [BACKLOG #1421](../BACKLOG.md) names.
- **Date:** 2026-09-05
- **Related:** BACKLOG #1421 · BACKLOG #1277 (the grant-trail default) · BACKLOG #190 (chain keying) ·
  BACKLOG #328 (the prefix comparator) · [ADR 0118](0118-secure-by-default-security-configuration-section.md) §5 ·
  [ADR 0150](0150-client-address-on-audit-entries.md) · [CONFIGURATION.md](../CONFIGURATION.md#retention)
  `audit_days`, the source of record for the chain-truncation reasoning · [PHI.md](../PHI.md) §2, §7, §8

---

## Context

`[security].audit_all_authorization_decisions` ships `true`. On the shipped default, every
authenticated request on a `require()`-gated route writes one `auth.permission_granted` row. Nothing
prunes that table: `[retention].audit_days` defaults `0` and is accepted but never enforced
(`config/settings.py:1683`), and the `Store` protocol carries no audit purge at all.

**Severity is conditional, per [CLAUDE.md](../../CLAUDE.md) section 0.** MessageFoundry is a
not-deployed beta with zero instances. Nothing is growing today. A first deployment *would* grow the
table for the life of the instance, one row per authenticated read, with no configured window able to
stop it.

BACKLOG #1421 records four costs and picks no fix. Three pull requests have landed against it
already, and this memo does not re-derive their work:

| PR | What it settled | Verified on `main` by content |
|---|---|---|
| 766 | Cost 4 — [ADR 0118](0118-secure-by-default-security-configuration-section.md) §5 now carries both questions put to the owner, all eight options and both answers. Cost 3 — the `_audit_all_authz` docstring no longer argues a wider fallback would invent a grant row. | `api/security.py:175-188` carries the replacement reason (preserving prior behaviour for a hand-built `app.state`) and names it a compatibility argument. The word "inventing" is still in the file, quoted as the retired reasoning it corrects — so a bare grep for it would read as "the fix did not land", which is the wrong answer. |
| 775 | The measurement: which deletion shapes break `verify_audit_chain`. | `docs/BACKLOG.md` row 1421 carries the six cases. |
| 805 | The rationale disagreement. `docs/CONFIGURATION.md`'s `audit_days` row is the source of record; `settings.py`, `retention_classification.py` and `PHI.md` §2/§7/§8 now link to it instead of restating it. | `settings.py:1675-1683` carries the corrected comment; `CONFIGURATION.md:750` carries the archive contract. |

This repository squash-merges and deletes branches, so `git merge-base --is-ancestor` returns false
for work that landed. Each row above was checked with `git grep` against `origin/main` for text the PR
added, and for text it removed.

**What is left is one decision.** Which retention lever exists for a table that must stay
tamper-evident. This memo lays out the options and their costs so the owner can choose.

## The chain is a hash over the previous row's *stored* hash, and nothing else orders it

`audit_row_hash` (`store/store.py:1009`) builds the payload at `:1057`:

```python
fields: list[object] = [prev_hash, ts, actor, action, channel_id, detail]
if client is not None:
    fields.append(client)
canonical = json.dumps(fields, sort_keys=True, default=str)
```

It digests those bytes three ways (`:1062-1066`): an isolated-module MAC when one is supplied, else
HMAC-SHA256 when a store key is set, else keyless SHA-256.

**The row `id` is not in the payload.** The only link between two rows is the earlier row's stored
`row_hash`, folded in as `prev_hash`. `record_audit` (`:7603`) reads that head under the store lock
immediately before it inserts:

```python
cur = await self._db.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
last = await cur.fetchone()
prev = last["row_hash"] if last and last["row_hash"] else ""
```

So chain order is `id` order and nothing else. `row_hash` is a plain nullable `TEXT` column
(`store/store.py:1782`), writable by anyone who can write the table.

The verifier walks in `id` order and chains from the **stored** hash, not the recomputed one
(`:7998`):

```python
# Chain from the STORED hash (not `expected`) so a divergence is reported once, at its own
# row, instead of cascading a false break onto every successor.
prev = r["row_hash"] or ""
```

That one line decides most of what follows.

## A verifier exists, it is reachable three ways, and it ships off

This is not a "would fail" claim with nothing behind it. `verify_audit_chain` is on the `Store`
protocol (`store/base.py:1543`), implemented on all three backends, and reachable by:

1. **The CLI.** `messagefoundry audit-verify` and `messagefoundry audit-anchor`
   (`__main__.py:617` and `:646`).
2. **The engine at startup**, behind `[integrity].audit_verify_on_start`, which ships `False`
   (`config/settings.py:3370`). It is alert-only when on: a broken chain logs and alerts, never
   crashes startup.
3. **The API**, through the same protocol method.

It takes no input but the database. Two optional arguments sharpen it: `expected_anchor`, an exact
`(count, head)` seal from `audit_anchor` (`store/store.py:7910`), and `expected_prefix`, the #328
comparator. **Both must be held out-of-band.** Nothing in the engine stores an anchor for you.

The walk returns one boolean for the whole log and names the **first** divergent row
(`store/store.py:8008`): `audit chain broken at row id=N`.

## What a purge would actually do, measured

Driven on this branch at `c57903c2c`: a throwaway SQLite store in a temp directory, six rows written
through the real `MessageStore.record_audit`, each shape applied out-of-band with plain SQL, then
`verify_audit_chain` re-run. Synthetic actors only. Two controls: a clean store, which must verify,
and an ordinary interior edit, which must break.

Beside the shipped verifier I ran a second walk that reports **every** divergent row, because the
shipped one returns only the first. That is what shows whether a break spreads.

| Case | What happened to the rows | `verify_audit_chain()` | Rows that actually mismatch | Against a held anchor |
|---|---|---|---|---|
| control | nothing | `True`, 6 rows | none | `True` |
| control | edit row 3's `actor` | `False` at id=3 | 3 | `False` |
| A | delete interior row 3 | `False` at id=4 | 4 | `False` |
| B | delete the two oldest | `False` at id=3 | 3 | `False` |
| D | delete the two newest | **`True`, 4 rows** | none | `False` — count and head both moved |
| E | tombstone row 3, keep its `row_hash` | `False` at id=3 | 3 | `False` |
| F | tombstone the two oldest, keep their `row_hash` | `False` at id=1 | 1 and 2 | `False` |
| G | delete the two oldest, then re-seal every survivor | **`True`, 4 rows** | none | `False` — head moved |

Both controls fired, so the instrument can say both things.

Four findings follow, and three of them are not on `main` today.

**A break is local. It does not spread.** In every broken case, only the rows I touched mismatched.
Their successors verified. Case A deleted row 3 and only row 4 diverged; rows 5 and 6 still chained
cleanly. This falls straight out of the `prev = r["row_hash"]` line above. It matters because it means
a purge does not destroy the evidentiary value of the rows that survive — but the shipped verifier
reports one boolean, so the whole log reads broken forever regardless.

**Deleting an interior row does not change the head.** Case A's anchor head was byte-identical before
and after; only the count fell, from 6 to 5. So an anchor catches an interior delete by its **count**,
not by its hash. An anchor comparison that checked only the head would pass over it.

**A tombstone that preserves the link still breaks the walk.** Cases E and F kept each row's stored
`row_hash` untouched and only redacted its content. The walk recomputes each row's hash from its own
content, so it diverges at the tombstoned row. The successors verify, because they chain from the
preserved stored hash. So preserving the link bounds the damage, and does not remove it.

**A re-seal verifies clean, and only an anchor tells it from an attack.** Case G deleted the two
oldest rows and recomputed every surviving `row_hash` from an empty `prev`. The result verifies
`True`. A bare `audit-verify` reports a healthy four-row chain. The only thing that catches it is an
anchor held off-box, whose head no longer matches.

**That is the crux of the whole decision.** A re-seal is exactly what an attacker who can write the
table would do. If the engine ships a purge that re-seals, the verifier can no longer tell a
configured retention pass from a cover-up, and the anchor becomes the only control that still works.

## The options, and what each costs

"Chain cost" is what the shipped verifier would report after the lever ran.

| Lever | What it does to the chain | Build cost | Operator cost |
|---|---|---|---|
| **Hard delete (in-place age window)** | Breaks it permanently at the first surviving row, with the same sentence a tamper produces. Nothing heals it: `_backfill_audit_chain` (`store/store.py:2454`) fills only NULL hashes and skips any row that has one, so a reopen cannot repair a purge. | Low. One purge method plus a `RetentionRunner` phase. | High and permanent. Every verify fails forever. The alarm an operator most needs is now stuck on. |
| **Tombstone preserving the link** | Breaks at each tombstoned row; successors verify. Making it chain-neutral would need the verifier to accept a marked row on its stored hash alone — which hands an attacker a way to edit any row by marking it. | Medium for the write, high for a safe verifier change. A tombstone would need its own authenticated form. | Medium. Verify reports a known, bounded break, so operators must learn to read a `False` that is expected. |
| **Time-based partitioning, no deletion** | None. Rows stay, so the walk is untouched. | Medium. Partitioned tables differ across SQLite, Postgres and SQL Server, and `verify_audit_chain` walks one ordered set. | Low, but it does not bound the table. It moves storage, it does not reclaim it. |
| **Archive-and-reseal (signed summary replaces the span)** | Verifies clean afterwards — see case G — which is the problem. It destroys the evidence that anything was removed, so the summary's signature becomes the only proof, and a held anchor becomes mandatory rather than optional. | High. A signing key with its own custody, a summary format, and a re-anchor step. | High. Whoever holds the anchor now holds the whole integrity claim. |
| **Archive-first, restore-capable (no reseal)** | None while the rows are present. The purge is the delete, so it carries the hard-delete cost — unless the archive can be restored, which case C1 in #1421 showed requires the original `id` and `row_hash`, not just row content. | Medium. An export format that carries `id` and `row_hash`, plus a restore path. | Medium. The archive must be kept for the full retention period, which is what the requirement asked for anyway. |
| **A write-time bound (sample or aggregate the read-grant rows)** | None. It deletes nothing, so the chain constrains it not at all. | Low to medium. It changes what `require()` records, not the store. | Low. No new artifact to hold, no verify to interpret. |

The write-time bound is the one lever whose cost is not paid in verifiability. Its cost is paid in
completeness of the grant trail, which is the property BACKLOG #1277 turned on deliberately.

Two things this table deliberately leaves out. **Enrolling audit in the ADR 0055 group committer** is
cost 2 of #1421, not a retention lever: it changes commit batching, not row count. The chain does set
one constraint on it — each hash folds the previous row's stored hash, so the head read and the insert
must stay serialized in `id` order, which the standalone commit inside the lock gets for free today
(`store/store.py:7650`, and the committer excludes audit by name at `:2109`). **Turning
`audit_all_authorization_decisions` back off** is not a retention lever either. It lowers the write
rate without bounding the table, and it is reported as a loosening.

## What each option does to the PHI position

The privacy map is [PHI.md](../PHI.md); this section only records where the options differ, and does
not restate it.

`audit_log` rows are metadata, not bodies. `detail` holds filter shapes, counts and ids
([PHI.md](../PHI.md) §2). It is stored in the clear — it is not a cipher-covered column — and
`client` is stored in the clear by decision, so it stays greppable for incident response.

Three differences matter to a ruling:

1. **An audit row records who read what.** Keeping it longer is better for accountability and worse
   for the subject, because the access record itself is personal data about the reader. Deleting it
   is the reverse. The retention requirement (45 CFR 164.316(b)(2)(i), about six years) already
   settles which way that trade goes, and it points at keeping.
2. **Archive-first moves PHI-adjacent metadata outside the store's controls.** The store's protections
   are its ACL and the volume layer. An archive file inherits neither unless the operator supplies
   them. Any archive option needs that said in the runbook, or it quietly widens exposure while
   looking like a retention win.
3. **A write-time bound is the only option that reduces the amount of access metadata written at
   all.** It shrinks the record rather than relocating or deleting it. That is better for the reader's
   privacy and worse for the trail an investigator would want.

The off-box tee is unaffected by every option here. It emits one PHI-safe JSON object per committed
row (`store/audit_tee.py`), after the commit and outside the lock, so a copy of the trail survives
whatever happens to the table. That copy is not chained.

## Options considered

This ADR chooses nothing. The six levers above are the options, and the ruling is the owner's.

## Recommendation — the Builder's, and separable from the findings above

Everything above this heading is measured or quoted. This section is my judgment and the owner may
take it or leave it.

**Order the levers this way.**

1. **Make the anchor a real operational step first, before any deletion lever ships.** Every safe
   deletion option depends on an anchor held off-box, and today nothing holds one:
   `audit_verify_on_start` ships `False`, and `audit-anchor` exists with no runbook step that calls
   it. Shipping a purge before the anchor is routine would remove the one control that could tell a
   retention pass from an attack. This is the cheapest item here and it unblocks the rest.
2. **Take the write-time bound as the primary lever.** It is the only one that costs verifiability
   nothing. The table's growth problem is caused by writing one row per authenticated read, and the
   honest fix for writing too much is to write less — not to damage the property the table exists to
   have. A sampling or aggregating rule over `auth.permission_granted` reads, with state-changing
   actions never sampled, keeps the trail that matters intact.
3. **If a bound on the table itself is still required, use archive-first with the case C1 contract,
   and never re-seal.** The export must carry each row's `id` and `row_hash`, and a restore must land
   them back at their original ids. Accept that a bare verify reports broken afterwards, and give
   operators a documented way to verify the archive plus the live tail together.
4. **Reject hard delete and reject archive-and-reseal.** Hard delete leaves a permanent alarm that
   reads exactly like a tamper, which trains operators to ignore the alarm. Re-seal is worse: it
   leaves a clean-verifying chain that an attacker could produce identically.

**One thing I would change regardless of the ruling.** `verify_audit_chain` returns a single boolean
for the whole log while the underlying break is local. An operator cannot currently tell "one old row
went" from "the log is compromised". Reporting the divergent row ids and the length of the clean
suffix would cost little and would make every option above easier to run. That is a separate item and
I have not filed it.

## Consequences

**Positive** — the retention question now has the costs written down beside it, so a ruling can be
made once instead of re-derived per lever.

**Negative / risks** — this memo adds a fifth record touching the `audit_days` rationale. It links to
[CONFIGURATION.md](../CONFIGURATION.md#retention) rather than restating it, per SDS-3.5, because four
copies of that reasoning is exactly how the records drifted apart before PR 805 reconciled them.

**Out of scope** — cost 2 of #1421 (the standalone commit per authenticated read), any change to
`[security].audit_all_authorization_decisions`, and any engine behaviour at all. Nothing is built
here.

## To resolve on acceptance

- [ ] The owner picks a lever, or rules that no bound ships and the table stays keep-forever.
- [ ] If a deletion lever is chosen, decide whether the anchor becomes mandatory before it ships.
- [ ] File the follow-up for a richer `verify_audit_chain` result, if the owner wants it.
