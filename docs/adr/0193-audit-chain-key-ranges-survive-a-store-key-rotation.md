# 0193 — Audit chain key ranges survive a store key rotation

- **Status:** Accepted (2026-09-23) -- built with the change. **Amended 2026-10-01** by owner
  ruling: see *Amendment 2026-10-01* at the end. Decision items 2 and 8, and the first sentence
  of *Negative / risks*, are superseded there. The text below is kept as it was decided.
- **Date:** 2026-09-23
- **Related:** BACKLOG #1904 (the defect), #1905 (keyless chain after `provision-admin`), #190 (the
  keyed chain and its watermark), [ADR 0138](0138-transit-bulk-crypto-provider-dek-out-of-engine-heap-for-asvs-13-3-3-demand-gated.md)
  (Transit-keyed chain), vault row #1165 (an authenticated audit-chain algorithm epoch; not built here)

---

## Context

The audit chain is HMAC-keyed from a key derived from the store DEK (#190). Before this ADR the
cipher derived that key from the **active** DEK only, `audit_chain_meta` recorded only a watermark,
and `rotate-key` never touched the chain. The rotation `docs/PHI.md` documents -- new key B active,
old key A retired, `rotate-key`, then drop A -- therefore made `audit-verify` report the chain broken
at row 1, and for good once A was dropped. An operator could no longer tell a rotation from an
attack. `rekey-audit` printed OK over the broken chain, because it returned early once keyed.
Reproduced with synthetic data at engine `fcbe2f93a`; zero deployments (CLAUDE.md section 0), so
this is what the first rotation on a first deployment would have hit.

Two constraints bound the fix:

- **No existing `row_hash` may be rewritten.** The off-box tee and every recorded anchor hold those
  values; re-MACing history under the new key would invalidate both, and would bless any forged row
  present at the time.
- **The range record must not be a redirect.** Keys are rotated because one may have leaked. A
  record that says "rows from N on use key X" and is not itself authenticated lets whoever can write
  rows point verification at a key they hold.

## Decision

**The keyed chain is a sequence of ranges, each MAC'd under one audit key, and every range after the
first is opened by a row inside the chain.**

1. **Every keyring key has an audit key.** `AesGcmCipher` derives one per keyring entry, active and
   retired, at construction (`audit_mac_keyring()`), identified by `audit_key_id` -- a one-way digest
   of the DERIVED key under its own label.
2. **The first range names its key** in the new `audit_chain_meta.key_id` column (all three
   backends), written where the watermark is written. There is no resolution path for a row that
   lacks one: at zero deployments no such row exists (CLAUDE.md section 0), so a NULL `key_id` under
   a watermark is reported as a chain that "does not record which key its keyed range is under".
3. **`rotate-key` opens a new range.** After re-encrypting, it verifies the whole chain and refuses
   on any break. It then appends ONE `audit.key_epoch` row, MAC'd under the NEW key. The row's detail
   holds three things:
   - the new key's id;
   - a `closes` record for the range it ends: its key, first and last id, and row count; a SHA-256
     digest over every row's id, chained fields and stored MAC; and `prev_hash`, the stored hash of
     the row just before the range (`""` when there is none);
   - a **handover tag**, a MAC under the OUTGOING key over the new key id and the `closes` record.

   It seals and verifies from one read, and the append is refused if the chain head has moved since.
   It also refuses when the active key already keyed a range.
4. **Verify checks each row under its own range's key** (`verify_audit_rows`, one function shared by
   all three backends). A range whose key is no longer held is proved by the digest in the row that
   closes it; that row lies in the next range, so the proof chains forward to the newest range, whose
   key must be held. The closing record's `prev_hash` must equal the stored hash of the row before
   the range. While the range's key is held, the MAC on its first row carries that link; once the key
   is dropped, only `prev_hash` does. Without it, the keyless rows below a `rekey-audit` watermark
   could be rewritten and re-hashed once the first range's key was dropped (PR 1446, Lander blocker).
5. **A forged or moved range fails.** The range rows are chain rows, so they are inside every MAC
   and every anchor. A range row must match the range it closes, must carry a handover tag that
   verifies under the outgoing key whenever that key is held, and must name a key that has not keyed
   a range before. The tag is what stops a leaked retired key that NEVER keyed a range from opening
   one: its holder can MAC the row and compute the (unkeyed) digest, but not the outgoing key's tag.
   The one-range rule stops a key coming back once rotated away from.
6. **Appends join the CURRENT range**, which is not always the active key's: between a key change
   and `rotate-key` it is still the retired key's, and the store warns at open not to drop that key
   (and says differently, at ERROR, when that key is not configured at all). Opening a range is
   `rotate-key`'s explicit step, never a side effect of an append.
7. **The current range is authenticated at open, not read.** It routes every live append, so the
   open checks, cheaply, that the recorded first key reproduces the first keyed row's MAC and that
   each range row follows the one before it, is new, and carries a valid handover tag where the
   outgoing key is held. If any check fails, new rows go under the ACTIVE key, the store logs an
   ERROR, and `rotate-key` refuses; `audit-verify` reports the break.
8. **`rekey-audit` reports the verify** when the chain is already keyed, so it never prints OK over
   a chain that does not verify.

## Acceptance Criteria

- **AC-1** -- WHEN the documented rotation runs (A active; B active with A retired; `rotate-key`; A
  dropped), THE SYSTEM SHALL verify the chain at every step.
  → `tests/test_audit_key_rotation.py::test_the_documented_rotation_verifies_at_every_step`
- **AC-2** -- WHEN a row of a dropped key's range is edited, THE SYSTEM SHALL report a break.
  → `tests/test_audit_key_rotation.py::test_editing_a_row_of_a_dropped_keys_range_is_caught`
- **AC-7** -- WHEN a row BELOW a range is edited and re-hashed after that range's key is dropped,
  THE SYSTEM SHALL report a break naming the rows before the range.
  → `tests/test_audit_key_rotation.py::test_a_forged_keyless_prefix_is_caught_after_the_first_key_is_dropped`
  → `tests/test_audit_key_rotation.py::test_a_key_holders_range_row_that_misstates_its_link_is_caught`
- **AC-3** -- IF a range row's `closes` record, or `audit_chain_meta.key_id`, is altered, THEN THE
  SYSTEM SHALL report a break rather than verify under the named key.
  → `tests/test_audit_key_rotation.py::test_a_moved_range_boundary_is_caught`
  → `tests/test_audit_key_rotation.py::test_a_forged_range_meta_is_caught`
- **AC-4** -- IF a range row opens a range under a key that already had one, or is not authorised
  by the outgoing key, or misstates the range it closes, THEN THE SYSTEM SHALL report a break.
  → `tests/test_audit_key_rotation.py::test_a_key_cannot_open_a_second_range_even_when_authorised`
  → `tests/test_audit_key_rotation.py::test_a_configured_key_that_never_keyed_a_range_cannot_open_one`
  → `tests/test_audit_key_rotation.py::test_a_key_holders_range_row_that_misstates_its_range_is_caught`
- **AC-5** -- IF the newest range row does not authenticate at open, THEN THE SYSTEM SHALL key new
  rows under the active key and refuse to roll.
  → `tests/test_audit_key_rotation.py::test_a_forged_range_row_does_not_route_live_appends`
- **AC-6** -- IF the chain does not verify, THEN `rotate-key` SHALL write no range row and
  `rekey-audit` SHALL NOT print OK.
  → `tests/test_audit_key_rotation.py::test_rolling_is_idempotent_and_refuses_a_broken_chain`
  → `tests/test_audit_key_rotation.py::test_rekey_audit_does_not_print_ok_over_a_chain_that_does_not_verify`

## Options considered

1. **In-chain range rows with a closing digest** -- as above. **CHOSEN.** Rewrites nothing, keeps
   the anchor and tee valid, and keeps old ranges provable with the old key gone.
2. **Re-MAC every row under the new key at rotation.** Rejected: invalidates every anchor and the
   tee, and would bless a forged row present at rotation time.
3. **A separate range table outside the chain.** Rejected: unauthenticated, so a writer of that
   table redirects verification to any key it holds -- the failure the brief named.
4. **Keep the retired key forever.** Rejected: makes key retirement impossible, which defeats the
   reason to rotate.

## Consequences

**Positive** -- rotation no longer reads as tampering; a key can be dropped; the range record is
authenticated by the chain itself; one verify walk now serves all three backends.

**Negative / risks** -- the first range's key is recorded in `audit_chain_meta` outside the chain.
Altering it cannot make a forged row verify without a key the attacker holds, and it breaks
verification at row 1 otherwise; a wholesale rewrite under a leaked key changes the head, which the
out-of-band anchor catches. Between a key change and `rotate-key`, new rows are MAC'd under the
retired key. Under `vault_transit` the engine sees one range (`vault-transit`); Transit's own key
versioning is outside this ADR.

Five residuals are recorded rather than solved:

- **`rotate-key` is offline-only, and only partly enforced.** Another process keeps the range it
  read at open, so an engine left running would append under the old key after the range row and
  break the chain. The command's help and PHI.md already say to stop the engine. *Amended for
  BACKLOG #1915:* on SQLite the command now refuses to start while another connection holds the
  store. Gaps remain. It does not see an engine started after that check. It prints a note and
  checks nothing when the probe cannot read the store, when the store is not in WAL mode, and on
  PostgreSQL or SQL Server.
- **A broken chain cannot be rolled.** The roll refuses rather than certify tampered rows with a
  closing digest, so new rows stay under the old key until the break is dealt with. Whether an
  operator may roll over a known break (recording it as unverified) is a policy question left open.
- **Finding the range rows scans `audit_log`** at every open (no index on `action`). Rotations are
  rare, so the rows are few, but the scan is over every row after the watermark.
- **The newest handover cannot be authenticated once its outgoing key is dropped.** The tag needs
  the outgoing key. Once A is dropped after A -> B, a writer holding a configured retired key X that
  never keyed a range can rewrite the A -> B row and every row after it under X, and the chain
  verifies; the open then routes appends to X. Only a recorded anchor catches it. An EARLIER handover
  is safe, because the next one's digest (under a held key) covers it. Keeping the previous key
  configured until the NEXT rotation closes it operationally; closing it in code needs a choice this
  ADR does not make (for example, requiring the newest range to be under the active key whenever its
  opening handover cannot be checked, which misreads the pending window of a second rotation).
- **`rotate-key` verifies without an anchor**, so a tail truncated before the roll is sealed into
  the closing digest; only a separately recorded `[integrity].audit_anchor_file` prefix still shows
  it once the old key is gone.

**Out of scope** -- vault row #1165's algorithm epoch (digest and KDF label per range); this ADR
records a KEY per range, and the range row's `detail` is JSON so a later field can be added.

---

## Amendment 2026-10-01 -- the first range is named inside the chain, and every row carries a sequence number

- **Status:** Accepted by owner ruling (2026-10-01) -- built with the change (vault BACKLOG #2594).
- **Supersedes:** Decision items 2 and 8, the keyless-prefix reasoning in item 4, and the first
  sentence of *Negative / risks*. Everything else above stands.

### Why

This ADR set a constraint for every range after the first: *the range record must not be a
redirect*, so it lives inside the MAC'd chain. The first range did not meet that constraint. Its
key, and the row from which the chain counted as keyed, were recorded in `audit_chain_meta`, a
table beside the chain that nothing authenticated. The *Negative / risks* paragraph weighed the key
id held there and did not weigh the keyed-from mark in the same row. That mark decided which rows
the verifier checked under a key. A record outside the chain that decides what verification checks
is the shape this ADR rejected as option 3, and the first range was left with it.

The chain also had no coordinate inside its MAC. The row `id` was not in the payload, the off-box
tee sent the `id`, and the anchor took a row count, so three numbers named a row and none was
authenticated.

### What changes

1. **`audit_chain_meta` is removed, on all three backends.** Nothing in the database says where
   keying starts.
2. **Whether a chain is keyed is decided by the process.** A handle that holds a keying secret (a
   store key, or the isolated-module MAC) MACs every row it appends and requires every row it
   verifies to be keyed, from the first. A row it cannot check under a key is a reported break.
3. **Row 1 of a keyed chain is a genesis row.** Its action is `audit.key_epoch`, it is MAC'd under
   the first range's key, and its detail names that key. A handle that holds a key writes it at its
   first writable open of an empty log. The append requires the log to be empty, so on a server
   database a second engine opening the same fresh store writes nothing and adopts the row already
   there. A read-only open writes nothing. The detail is a JSON record, so a later field can be
   added beside the key id.
4. **A handle with no key learns from the genesis row that the chain is keyed.** It refuses to
   append to it, and reports that it cannot verify it.
5. **Every row carries `seq` inside its MAC.** `audit_log.seq` is `NOT NULL` and `UNIQUE`. It
   starts at 1 and each append takes the head's `seq` plus one. On PostgreSQL and SQL Server the
   head is read under the lock every append already takes in the database (the advisory lock, the
   applock), so the number is safe across engine shards and cluster nodes. On SQLite the writer
   lock belongs to one handle, so a second connection to the same file, such as a CLI command run
   beside the engine, can append in between. The `UNIQUE` constraint refuses the second insert,
   and the append reads the head again while it holds SQLite's write lock.
   The verifier walks in `seq` order and requires the numbers to start at 1 and rise by one. The
   row `id` stays a surrogate key outside the chain: a rolled-back insert can skip an `id`, and
   nothing in the chain reads it.
6. **One coordinate.** A range's closing record names its range by `from_seq` and `to_seq`, and its
   digest covers each row's `seq`. An anchor is the newest row's `seq` and hash. The off-box tee
   sends `seq` beside `row_hash`, so a collector's record is an anchor the verifier takes
   unchanged.
7. **The MAC input is a fixed list of named, typed, length-prefixed fields:** `seq`, the previous
   row's hash, `ts`, `actor`, `action`, `channel_id`, `detail`, `client`. `NULL`, the empty string
   and the text `None` encode differently. The conditional trailing `client` element of
   [ADR 0150](0150-client-address-on-audit-entries.md) is gone with the rows it kept compatible:
   `client` is always in the payload.
8. **`rekey-audit` is deleted** (item 8). On a store that holds a key no keyless chain is
   accepted, so the command has nothing to do. Making it rewrite every `row_hash` under the key was
   rejected: that needs `UPDATE` on `audit_log`, which the runtime login is denied
   ([DEPLOY-SERVER-DB.md](../DEPLOY-SERVER-DB.md), owner ruling R16); it would give a key to
   whatever each row says on the day it runs; and it would break every recorded anchor.
9. **The open authenticates the genesis row** (item 7): its MAC must verify under the key it names
   whenever that key is held. If it does not, new rows go under the active key, the store logs an
   ERROR, and `rotate-key` refuses, as item 7 already says for a range row.
10. **A store that holds a key and opens onto keyless rows** logs an ERROR, sets the
    `audit_chain_unkeyed` posture entry, keys every row it appends, and fails `audit-verify`. No
    command converts those rows.
11. **No earlier `audit_log` layout is converted.** `seq` is inside every row's MAC, so no `ALTER`
    can supply it for rows already written. SQLite refuses such a store at open and names the
    missing column. There is no installed base (CLAUDE.md section 0), so nothing is migrated.

Owner ruling R16's table list becomes `audit_log` alone. Everything the engine writes to the chain
is an inserted row, the genesis row and a rotation's range row included, so the runtime login
still needs `INSERT` and `SELECT` there and nothing more.

### What item 4's `prev_hash` link is for now

Item 4 added `prev_hash` because keyless rows could sit below the first keyed range, tied in only by
that range's first MAC. A keyed chain has no such rows now: the genesis row opens the first range
at row 1, so every row sits in a range and under a closing digest. The link check stays. It costs
one comparison per rotation, and it still ties each range to the row before it without that
range's key.

### Acceptance criteria, as amended

- **AC-3**, second arm -- IF the genesis row is rewritten to name another configured key, THEN THE
  SYSTEM SHALL report a break. Same test, new subject:
  `tests/test_audit_key_rotation.py::test_a_forged_range_meta_is_caught`
- **AC-6** -- the `rekey-audit` arm is withdrawn with the command, and its test is deleted. The
  `rotate-key` arm stands.
- **AC-7** -- the two keyless-prefix tests are deleted with the state they built. The link is still
  pinned by `test_a_key_holders_range_row_that_misstates_its_link_is_caught`, and the proof through
  more than one dropped key by
  `test_editing_the_oldest_range_is_caught_with_two_keys_dropped`.
- **AC-8** -- WHILE a process holds a keying secret, IF any audit row is unkeyed, or the chain does
  not open with a genesis row, THEN `verify_audit_chain` SHALL report a break.
  → `tests/audit_chain_cases.py::keyless_rows_on_a_keyed_store_are_a_reported_break`
  → `tests/audit_chain_cases.py::a_chain_recomputed_without_the_key_is_reported`
  → `tests/audit_chain_cases.py::a_chain_with_its_genesis_row_removed_is_reported`
- **AC-9** -- IF `seq` does not start at 1 and rise by one, THEN `verify_audit_chain` SHALL report a
  break at the position where the numbers stop matching.
  → `tests/audit_chain_cases.py::a_renumbered_or_missing_row_is_reported`
- **AC-10** -- WHEN a handle with no keying secret opens a keyed chain, THE SYSTEM SHALL refuse its
  append and write nothing.
  → `tests/audit_chain_cases.py::a_handle_with_no_key_refuses_to_append_to_a_keyed_chain`
- **AC-11** -- WHEN two handles open one fresh keyed store, THE SYSTEM SHALL hold exactly one
  genesis row and no two rows SHALL share a `seq`.
  → `tests/audit_chain_cases.py::two_opens_of_a_fresh_keyed_store_share_one_genesis_row`
- **AC-12** -- THE SYSTEM SHALL have no `audit_chain_meta` table and no `rekey-audit` command.
  → `tests/test_audit_chain_genesis.py::test_no_backend_schema_or_statement_names_the_removed_table`
  → `tests/test_audit_chain_genesis.py::test_the_parser_offers_no_rekey_audit_command`

The cases in `tests/audit_chain_cases.py` run on SQLite from `tests/test_audit_chain_genesis.py`,
on PostgreSQL from `tests/test_postgres_store.py` and on SQL Server from
`tests/test_sqlserver_store.py`. The last two need a live server, so they run on the CI legs that
have one and are skipped elsewhere.

### What this amendment does not do

- **It does not show rows cut off the end of the chain.** A shorter chain still verifies, and so
  does a log emptied altogether, because the next start writes a new genesis row. The sequence
  number shows a row missing from the middle, not rows missing from the end. Only an anchor held
  outside the database shows either, and on the shipped defaults none is kept
  (`[integrity].audit_verify_on_start` is off and `audit_anchor_file` is empty). The engine writing
  that anchor off the host is a later slice.
- **It does not bind the chain to one store.** The genesis row carries no store identity and the
  audit key does not derive from one. A decision recorded on 2026-10-01 puts the store identity in
  the outside anchor, not in the database, because a value kept in the database moves with the
  rows it is meant to identify. That is a named later slice, and it is not built here. Until then
  a chain is not told apart from another store's chain under the same key.
- **It does not separate the audit key from the store key.** The audit key is still derived from
  the store key, so verifying the chain needs the key that decrypts the store. A later slice.
- **It does not change the residuals recorded above** for a rewrite under a configured key, for the
  newest handover once its outgoing key is dropped, or for `vault_transit`, where the engine still
  sees one range and Transit's own key versioning stays outside this ADR.
- **It does not remove the keyless store mode.** A store opened with no key, under the audited
  opt-outs, still has a wholly keyless chain, and its posture says so. The owner has ruled that
  mode is to be removed; that is a separate, later change.
