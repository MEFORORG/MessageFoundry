# 0193 — Audit chain key ranges survive a store key rotation

- **Status:** Accepted (2026-09-23) -- built with the change. **Amended 2026-10-01** by owner
  ruling: see *Amendment 2026-10-01* at the end. Decision items 2 and 8, the field names in item
  3's closing record, and the first sentence of *Negative / risks* are superseded there. The text
  below is kept as it was decided. **Amended 2026-10-20** (BACKLOG #3420): see *Amendment
  2026-10-20*, which adds a scheme to each range record and supersedes nothing. **Amended
  2026-10-27** (BACKLOG #2720): see *Amendment 2026-10-27*, which records what a Transit key
  rotation does to the chain. It supersedes only the clause, stated twice, that put Transit's key
  versioning outside this ADR; that the engine sees one Transit range still stands. **Amended
  2026-11-11** (BACKLOG #2720): see *Amendment 2026-11-11*, under which the walk checks each Transit
  row MAC with Transit's verify call. It supersedes the 2026-10-27 amendment's item 2 and its
  *Why regenerating pinned stands in for Transit's verify call*, and closes that amendment's edge.
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
- **Supersedes:** Decision items 2 and 8; the field names in item 3's closing record, which now
  counts in sequence numbers (item 6 below); the keyless-prefix reasoning in item 4; and the first
  sentence of *Negative / risks*. Item 7 gains the genesis row (item 9 below). The rest stands.

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
5. **Every row carries `seq` inside its MAC.** `audit_log.seq` is `NOT NULL` and `UNIQUE`. On
   PostgreSQL and SQL Server a `CHECK` also refuses a value below 1, to a role that cannot alter
   the table. SQLite carries no such `CHECK`: every writer of a SQLite file can switch one off,
   and a row that broke it would fail the store's integrity check, where it is the audit
   verify's to report. It
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
   whenever that key is held. If it does not, new rows go under the active key, never the key
   that row names, the store logs an ERROR, and `rotate-key` refuses. Item 7 and AC-5 say the
   same of a range row that fails, in the words *new rows go under the ACTIVE key*. The code has
   always been narrower there, and this amendment leaves it so: after a failed range row, new
   rows stay under the last range that did authenticate when its key is held, and go under the
   active key only when it is not.
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

---

## Amendment 2026-10-20 -- each range record names its scheme

- **Status:** Accepted -- built with the change (BACKLOG #3420). It builds part of the algorithm
  epoch that *Out of scope* above left to vault row #1165. The census re-grade stays #1165's.
- **Supersedes:** nothing. It adds fields to the genesis record (amendment 2026-10-01, item 3), to
  the range record (Decision item 3), and to the edit-resend body-digest record.

### Why

The genesis row and each range row named the key their range is MAC'd under, and nothing else. The
row MAC is HMAC-SHA256 (`audit_row_hash`), and the key is HKDF-SHA256 over the DEK under the label
`mefor/audit-chain/v1` (`_derive_audit_mac_key`). A Transit range is Transit's HMAC with the hash
`sha2-256`. A release that changed any of these would have made `audit-verify` report every existing
row broken, because no row said which scheme sealed it. The edit-resend body digests named their
MAC but not the two labels their key came through, so a change to either label would have made
every stored digest stop verifying. Zero deployments (CLAUDE.md section 0): this is what such a
release would have done to a first deployment's rows.

### What changes

1. **The genesis record and the range record carry `mac` and `kdf`.** In-heap ranges name
   `hmac-sha256` and `hkdf-sha256:mefor/audit-chain/v1`. The Transit range names
   `vault-transit:hmac-sha2-256` and `vault-transit`. The names are `AUDIT_SCHEME_IN_HEAP` and
   `AUDIT_SCHEME_TRANSIT` in `store/crypto.py`. The in-heap `kdf` is built from the label HKDF
   uses, and `crypto_transit` reads its hash from `AUDIT_TRANSIT_HASH_ALGO`, so a record names what
   the release computes.
2. **A record without them is read as the scheme every such record was sealed under**, a fixed name
   per key kind (`AUDIT_SCHEME_UNNAMED_IN_HEAP`, `AUDIT_SCHEME_UNNAMED_TRANSIT`). It is written out,
   not taken from what the release writes, so a later release that changes the written scheme still
   reads an older record as what sealed it. Its handover tag was taken without the fields, and is
   checked that way.
3. **A record may name only the scheme this release seals its key with** (`audit_scheme_refusal`).
   Each key kind has one compiled scheme today, so "verify each range under the scheme its record
   names" is: refuse every other name, then verify under that one. A release that adds a scheme adds
   an entry there and looks keys up by scheme. Anything else is refused: an unknown name, the other
   key kind's scheme, or a malformed pair. A record that holds all its own fields but is otherwise
   malformed still reads as a record. That covers half a pair, a name that is not text, and a field
   beyond the pair. It names a scheme no release holds, so it is refused. Before this amendment the
   range parser ignored an extra field. AMENDED 2026-11-04 (vault BACKLOG #3411): a genesis record
   may also carry `store_id`, the lowercase hex of the 16-byte store id, as a label beside a named
   scheme. The row MAC covers it and no key is derived from it. A malformed one, or one on a record
   that names no scheme, is refused as a field beyond the pair is. The refusal names the missing
   scheme first, then a refused scheme, then the store id, so a malformed label cannot hide a record
   naming the keyless mode. A range record carrying `store_id` is refused the same way. That holds
   until the key-custody restore slice lands, not as a rule about range records: that draft's rule 4
   restore appends an `audit.key_epoch` range row that names the new store id, and that slice
   amends this item for it.
4. **No record may name the keyless store mode.** Its `mac` is `sha256` (`AUDIT_KEYLESS_MAC`), and a
   record naming it is refused whatever its `kdf` says, by a handle with or without a key. So a row
   cannot declare its chain keyless. A record naming an unknown scheme or the keyless mode still
   parses as a genesis record. So a handle with no key still reads the chain as keyed, refuses to
   append, and reports the refusal as a break, never as a keyless pass. It does not stop every
   rewrite. A writer can still remove the genesis row,
   drop one of its required fields, or rename its action. A handle with no key then reads the chain
   as keyless, as it did before. The control there is the `keyless_walk` verdict. A caller whose
   settings require a key never reports it as a pass (vault BACKLOG #3054).
5. **Where a refusal applies.** At open, a refused genesis or range record makes the ranges untrusted:
   new rows go under the active key, or the last range that authenticated, as for any range row that
   fails, and `rotate-key` refuses. The walk reports a break at the record's position, even where every
   MAC on the row is valid. A one-row MAC check returns nothing for a row whose range names a
   refused scheme. That check backs `newest_keyed_audit_row` and the Transit attestation check.
6. **The handover tag covers the scheme a range row names.** The incoming key MACs the range row, and
   the outgoing key's tag authorises its key and its scheme. A holder of the incoming key alone cannot
   change either while the outgoing key is held. `audit_epoch_detail` takes the outgoing secret and
   computes the tag from the same scheme it writes, so the two cannot disagree.
7. **The body-digest record carries `kdf`** beside `alg`: `BODY_DIGEST_KDF` names the audit-chain
   label, then `mefor/audit-body-digest/v1`. `verify_audit_body_digest` takes the record's `alg` and
   `kdf` as `record.get(...)`. It reads a missing one as the fixed pre-#3420 name
   (`BODY_DIGEST_UNNAMED_ALG`, `BODY_DIGEST_UNNAMED_KDF`), and returns false unless the pair is the
   one this release digests with, so a plain hash is refused.
8. **The anchor's hex width is defined once, beside the in-heap scheme** (`AUDIT_MAC_HEX_LEN`), not
   written as 64 in the anchor parser. The keyless mode's plain SHA-256 has the same width, which a
   test pins.

### Acceptance criteria

- **AC-13** -- WHEN a chain's genesis and range records name no scheme, THE SYSTEM SHALL verify it,
  route appends to its current range, and roll it as a no-op.
  → `tests/audit_chain_cases.py::records_that_name_no_scheme_still_verify`
- **AC-14** -- IF a genesis or range record names a scheme this release does not seal its key with,
  or the keyless mode, THEN THE SYSTEM SHALL report a break, route no append by it, and refuse to
  roll, even when every MAC on the row verifies.
  → `tests/audit_chain_cases.py::a_record_naming_a_scheme_this_release_does_not_hold_is_refused`
  → `tests/test_audit_chain_scheme.py::test_a_range_row_naming_a_refused_scheme_is_a_break_though_its_holders_sealed_it`
- **AC-15** -- IF a writer with no key renames the chain keyless and recomputes it, THEN a handle with
  no key SHALL refuse to append and SHALL NOT pass the chain as a keyless walk.
  → `tests/audit_chain_cases.py::a_chain_renamed_keyless_and_recomputed_does_not_pass_as_keyless`
- **AC-16** -- IF a range row's scheme differs from the one its handover tag was taken over, THEN THE
  SYSTEM SHALL report the row as not authorised.
  → `tests/test_audit_chain_scheme.py::test_the_handover_tag_covers_the_scheme_the_range_row_names`
- **AC-17** -- IF a body-digest record names another `alg` or `kdf`, THEN `verify_audit_body_digest`
  SHALL return false. A record that names no `kdf` SHALL verify.
  → `tests/test_edit_resend_provenance.py::test_a_digest_record_naming_another_scheme_is_refused`
  → `tests/test_edit_resend_provenance.py::test_the_digest_names_its_key_derivation_and_a_record_without_it_still_verifies`

The AC-13 to AC-15 cases run on all three backends, as the 2026-10-01 cases do.

### What this amendment does not do

- **It compiles no second scheme.** It makes a later swap possible without stranding rows. The swap
  itself, with a keyring per KDF label, is that later release's work.
- **It does not name the range digest's or the handover tag's own hash.** The `closes` digest is
  plain SHA-256. The tag is the outgoing range's MAC, HMAC-SHA256 in heap, over input that starts
  with the domain label `mefor/audit-handover/v1`. Neither is named in a record, so a change to
  either would still strand the range rows written before it.
- **It does not name the scheme in the anchor.** An anchor stays `COUNT:HEAD`. Its hex width follows
  the in-heap scheme, and a Transit head stays opaque.

---

## Amendment 2026-10-27 -- a Transit key rotation keeps the chain

- **Status:** Accepted -- records behaviour already built by engine PR 2167 (merged 2026-10-08,
  BACKLOG #2337). This amendment changes no code (BACKLOG #2720).
- **Supersedes:** one clause, stated twice: *"Transit's own key versioning is outside this ADR"*,
  at the end of *Negative / risks*, and its restatement in the 2026-10-01 amendment's *What this
  amendment does not do*. Under `vault_transit` the engine still sees one range, `vault-transit`; what is no longer
  outside this ADR is what a Transit key rotation does to that range.

### Why

Under `cipher_provider = "vault_transit"` each row MAC is Transit's `generate_hmac`, and the string
Transit returns names the key version that made it: `vault:v<N>:...`. Before PR 2167 the check of a
stored row called `generate_hmac` again with no version, so Transit used its latest. After a
rotation every older row's recompute named the new version, differed from the stored string, and
`audit-verify` reported the chain broken at row 1 with nothing tampered. Zero deployments (CLAUDE.md
section 0): this is what the first deployment's first routine rotation would have done.

### What PR 2167 built

1. **An append names its version.** It calls `generate_hmac` unpinned, so Transit uses its latest
   version, and the string it stores carries that version.
2. **A check recomputes pinned to the stored version.** (Superseded 2026-11-11: see *Amendment
   2026-11-11*. `_version_pinned_mac` is gone.) `_version_pinned_mac` in `store/store.py`
   reads `<N>` from the stored string and calls `TransitCipher.audit_hmac(data, key_version=N)`.
   The chain walk (`_audit_row_mac`), the genesis-row check at open, and the one-row MAC check
   behind the Transit attestation all go through it. The recompute is compared with the stored
   string in constant time (`hmac.compare_digest`).
3. **A refused version is a break at that row; an outage is not.** A pinned call that Transit
   answers with HTTP 400 for that version alone raises `AuditKeyVersionRefusedError`
   (`TransitCipher._refuses_only_version`). The test reads the reply, not who wrote it: a pinned
   call that gets an HTTP 400 that hvac raises as `InvalidRequest`, while a probe under the latest
   version answers with a string that does not start with `vault:v<pinned>:`, raises it. An empty
   answer or one naming no version passes too, and a proxy, not Transit, can author the 400
   (corrected 2026-11-11, BACKLOG #6707). The walk records a break at that row, naming the
   version, and goes on. A 400 on which hvac raises an exception other than `InvalidRequest`
   raises neither `AuditKeyVersionRefusedError` nor its subclass `AuditKeyVersionUnverifiedError`
   (BACKLOG #6707). For example, these exact 400 bodies with the Content-Type exactly
   `application/json`:
   `[]`, `null`, `{"errors":[{"message":"x"}]}`, `{"errors":[1]}`, `{"errors":5}` and
   `{"errors":true}`. On each, hvac 2.4.0 raises `AttributeError` or `TypeError` in place of
   `InvalidRequest`. A `MemoryError` that hvac raises while it joins a
   truthy `errors` value, before it raises any `InvalidRequest`, is not read as a refusal either.
   Each is a plain `CipherError`, so a version planted behind a proxy that wrote such a body would
   not read as a break. Any other failure, an unreachable Vault among them, is a `CipherError`
   too. In every such case the walk could not run, and no tamper alert fires. The genesis-row
   check at open (item 2) catches only `AuditKeyVersionRefusedError`, so there such a
   `CipherError` can fail the store open.

### Why regenerating pinned stands in for Transit's verify call

Superseded 2026-11-11: the walk now makes Transit's verify call (*Amendment 2026-11-11*).

#2720 asked for Transit's verify call on the stored string in place of regenerate-and-compare. The
pinned recompute gives the two properties that call would:

- **No break on rotation.** Each row is recomputed under the version that sealed it, so a rotation
  changes only what new rows name.
- **Forgery resistance.** The recompute runs inside Transit under that version's key, which never
  enters the engine's heap. A writer with database access and no Transit access cannot produce a
  string that matches altered content. Planting a version Transit does not hold is refused, and so
  reads as a break.

The engine does the comparison instead of Transit, and does it in constant time.

### The edge: a version Transit will no longer compute with

A row whose version Transit refuses reads as a chain break, by design: the walk fails closed rather
than pass a row it cannot check. A planted version is one case. The other is a real older version
Transit will no longer compute an HMAC with. PR 2167's review recorded that raising the Transit
key's `min_encryption_version` does this, so every row sealed under a lower version would then read
as a break, and so would the attestation, with no re-attest hint. That limit is specific to
regenerating. Vault's Transit API documentation, read on 2026-10-27, says a pinned HMAC generate
needs a version at or above the key's `min_encryption_version`, and that `min_decryption_version`
is the floor for verifying an HMAC. Closed 2026-11-11: the walk verifies instead of regenerating,
so `min_encryption_version` no longer bears on it (*Amendment 2026-11-11*).

`_refuses_only_version` infers a refused version from the reply, which a proxy can author (item
3); it does not read the key's
version range. So a node whose copy of the key lags a rotation can refuse a real, newer version, and
that row reads as a break too.

### Evidence

All against an in-process fake Transit client with key versions, never a real server, in
`tests/test_transit_bound_attestation.py`:

- `test_rotating_the_transit_key_keeps_the_attestation` -- the chain and the attestation verify
  after the fake key moves from version 1 to version 2. Since 2026-11-11 it checks that Transit
  verified at version 1 and no call was pinned.
- `test_a_planted_unheld_key_version_is_a_chain_break_on_the_startup_walk` and
  `test_a_planted_unheld_key_version_on_the_genesis_row_opens_and_reads_as_a_break` -- a planted
  version is a break at its row.
- `test_a_verify_failure_whose_fixed_input_probe_fails_on_the_startup_walk_could_not_run` and
  `test_a_verify_failure_whose_fixed_input_verify_fails_could_not_run` (renamed 2026-11-11) -- a
  verify failure whose fixed-input check fails too is not a break. An outage
  `is_vault_unavailable` names is `test_a_service_failure_of_the_verify_call_still_could_not_run`.

## Amendment 2026-11-11 -- the walk checks each Transit row MAC with Transit's verify call

- **Status:** Accepted -- built with the change (BACKLOG #2720, closing step 1).
- **Supersedes:** the 2026-10-27 amendment's item 2 and its *Why regenerating pinned stands in for
  Transit's verify call*. It closes that amendment's edge.

### What changes

1. **A stored MAC is checked by Transit, never regenerated.** `TransitCipher.audit_mac_fn` returns
   an `AuditMacVerifier` (`store/crypto.py`). For one, `_audit_row_mac` in `store/store.py` calls
   `TransitCipher.verify_audit_hmac(data, stored)`, which makes Transit's `verify` call on the
   stored string. Transit checks it at the version it names. The chain walk, the genesis-row check
   at open, the pin check, and the one-row MAC checks behind the Transit attestation and keyed
   evidence all go through `_audit_row_mac`. An append still calls `generate_hmac` unpinned, and
   raises `CipherError` on a reply `transit_mac_version` does not accept, so it never writes a
   malformed MAC (`TransitCipher.audit_hmac`).
2. **The policy floor that applies is `min_decryption_version`.** Vault's `pathHMACVerify` at
   commit cbc874e2358f, read on 2026-11-11, refuses a version above the latest (*"invalid HMAC:
   version is too new"*) or below `min_decryption_version`, and does not read
   `min_encryption_version`. So raising `min_encryption_version` leaves older rows verifying, and
   raising `min_decryption_version` above a version a stored row names makes that row a break.
   No Vault or OpenBao server was run to confirm it.
3. **A malformed stored MAC is a break with no verify call.** A stored string that
   `row_seal.transit_mac_version` does not accept reads as not verified, so no malformed value
   reaches Transit to draw a 400. It still costs one round trip, an unpinned `generate_hmac` whose
   answer is discarded, so a malformed row is no cheaper to check than a clean one (the ASVS 11.2.4
   note on `verify_audit_chain`).
4. **A refusal of the row is a break; an outage could not run.** A 400 on the verify call that
   `_refuses_only_version` reads as a refused version (2026-10-27 amendment, item 3, where "a
   pinned call" now reads as this verify call) raises `AuditKeyVersionRefusedError`, or
   `AuditKeyVersionUnverifiedError` where `_names_no_version_reason` does not read it as Vault's
   own refusal, and is a break at that row with the alert. An outage `is_vault_unavailable` names
   raises a plain `CipherError`, and the walk could not run (`_settled_verify_failure`). A failure of the
   verify call that is neither a refused version nor an outage `is_vault_unavailable` names is
   checked by `_recheck_refused_row` once the handler has let go of it (BACKLOG #2720): a
   `generate_hmac` and a verify over fixed input must succeed, and then the row's own verify is
   asked once more. An answer is read as usual, and a refused version or an outage on the second
   ask is read as on the first. Any other second failure is a break at that row once the fixed
   input verifies again, and a `CipherError` when it does not. A planted row past
   `max_request_size` (HTTP 413) is one such case, and so are the 400 bodies the 2026-10-27
   amendment's item 3 lists. This item replaces item 3's reading, that every such failure is a
   `CipherError` and the walk could not run, for each failure it reads as a break; on the genesis
   row at open, such a break is logged by `settle_audit_ranges` and the store opens. Transit's
   `valid: false` is a break. A reply with no bool `valid` is a `CipherError`.
5. **A range row's handover tag is not moved.** `_audit_tag_ok` still regenerates the tag under
   the outgoing key and compares it.
6. **The in-process key paths are unchanged.** A plain MAC provider, an in-heap key and the keyless
   mode still recompute and compare in constant time.

### Evidence

In-process fake Transit, never a real server, in `tests/test_transit_bound_attestation.py`. Its
`_RotatingTransit` models both policy floors as item 2 reads them.

- `test_a_mixed_v1_and_v2_chain_verifies_after_a_rotation`.
- `test_raising_min_encryption_version_past_v1_leaves_v1_rows_verifying`.
- `test_raising_min_decryption_version_past_v1_is_a_break_with_the_alert`.
- `test_a_tampered_row_in_a_mixed_chain_still_breaks` and
  `test_a_malformed_stored_mac_is_a_break_with_no_verify_call`.

Item 1's append refusal is pinned in `tests/test_crypto_transit.py`:

- `test_audit_hmac_refuses_a_reply_its_own_check_would_reject`.

## Amendment 2026-11-13 -- a timeout on one row's verify could not run; a malformed handover reply is a break

Owner ruling 2026-11-13, "Fix forward", on engine PR 2903 (BACKLOG #8222 items 1 and 5). It
changes two readings of the 2026-11-11 amendment.

1. **A 408 or 504 on one row's verify is an outage.** Item 4 above sent every failure that is
   neither a refused version nor an outage `is_vault_unavailable` names to `_recheck_refused_row`,
   so a persistent 504 on one row, while the fixed input verified, was a break. hvac raises a 408,
   a 413 and a 504 as one class, `UnexpectedError`, with no status, so the store's Vault client
   (`keyprovider_vault._build_client`) now records each failed reply's status on hvac's error
   (`_record_reply_status`). `TransitCipher._is_outage` reads a 408 or 504 as an outage
   (`is_vault_timeout_reply`), so the walk could not run and no tamper alert fires. Every other
   status hvac raises as `UnexpectedError`, a 413 among them, and an error with no recorded status,
   still go to `_recheck_refused_row` as item 4 says, so a planted oversize row stays a break.
2. **A malformed reply to a handover tag is a break in the walk.** Item 1 above makes
   `audit_hmac` raise for a reply `transit_mac_version` does not accept. For a non-empty string it
   now raises the subclass `AuditMacMalformedError`, and the walk's handover-tag check
   (`_walk_tag_ok`) reads it as a tag that does not match: a break at that range row, as before
   engine PR 2903. An empty or non-string reply is still a plain `CipherError`, and the walk could
   not run. The store open (`settle_audit_ranges`) still lets the subclass propagate, so the open
   fails, as since engine PR 2903.

Evidence, in `tests/test_transit_bound_attestation.py`:
`test_a_timeout_on_one_rows_verify_could_not_run_though_the_fixed_input_verifies`,
`test_a_413_on_one_rows_verify_is_still_a_break`,
`test_a_persistent_504_on_one_rows_verify_could_not_run_on_the_startup_walk`,
`test_the_store_vault_client_records_the_reply_status_on_hvacs_error`,
`test_a_malformed_transit_reply_to_a_handover_tag_is_a_break_in_the_walk` and
`test_an_empty_or_non_text_transit_reply_to_a_handover_tag_still_could_not_run`.
