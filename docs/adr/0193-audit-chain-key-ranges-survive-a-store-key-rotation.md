# 0193 — Audit chain key ranges survive a store key rotation

- **Status:** Accepted (2026-09-23) -- built with the change.
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
3. **`rotate-key` opens a new range.** After re-encrypting, it verifies the whole chain (refusing on
   any break) and appends ONE `audit.key_epoch` row, MAC'd under the NEW key. Its detail names the
   new key, carries a `closes` record for the range it ends (key, first and last id, row count, and a
   SHA-256 digest over every row's id, chained fields and stored MAC), and a **handover tag**: a MAC
   under the OUTGOING key over the new key id and the `closes` record. It refuses, too, when the
   active key already keyed a range.
4. **Verify checks each row under its own range's key** (`verify_audit_rows`, one function shared by
   all three backends). A range whose key is no longer held is proved by the digest in the row that
   closes it; that row lies in the next range, so the proof chains forward to the newest range, whose
   key must be held.
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

Three residuals are recorded rather than solved:

- **`rotate-key` is offline-only, and nothing enforces it.** Another process keeps the range it read
  at open, so an engine left running would append under the old key after the range row and break
  the chain. The command's help and PHI.md already say to stop the engine.
- **A broken chain cannot be rolled.** The roll refuses rather than certify tampered rows with a
  closing digest, so new rows stay under the old key until the break is dealt with. Whether an
  operator may roll over a known break (recording it as unverified) is a policy question left open.
- **Finding the range rows scans `audit_log`** at every open (no index on `action`). Rotations are
  rare, so the rows are few, but the scan is over every row after the watermark.

**Out of scope** -- vault row #1165's algorithm epoch (digest and KDF label per range); this ADR
records a KEY per range, and the range row's `detail` is JSON so a later field can be added.
