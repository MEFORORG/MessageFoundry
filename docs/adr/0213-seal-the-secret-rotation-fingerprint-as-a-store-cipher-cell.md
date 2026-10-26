# 0213 — Seal the secret-rotation fingerprint as a store-cipher cell

- **Status:** Accepted (2026-10-26) -- owner ruling 2026-10-26, in session (batch 343 Manager); the
  option chosen, verbatim: *"S: seal as cipher cell (Recommended) -- Store the fingerprint as a
  store-cipher cell that reencrypt_to_active re-seals. vault_transit stays off. Adds a scheme tag;
  old rows never reset a clock. Supersedes the #2242 re-key rule. A is the Builder's stop-and-report
  fallback."*
- **Date:** 2026-10-26
- **Related:** vault BACKLOG #3472 (this decision), #3247 item 1 (where it was found, engine PR
  2293), #3473 (`vault_transit` fingerprinting, not decided here), #2242 (the re-key rule this
  supersedes), #3421 (scheme tags), #1167 (constant-time compare), #282 (the watcher);
  [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) section 5 (the reminder);
  [ADR 0196](0196-a-fresh-or-rewound-store-must-not-restart-a-store-key-s-aes-gcm-invocation-count.md)
  (the key-age floor); [PHI.md](../PHI.md) sections 2, 3 and 8

---

## Context

The secret-rotation watcher (ASVS 13.3.4) detects that a held secret was rotated by keeping a
fingerprint of it in `secret_rotation_meta` and resetting that class's clock when the fingerprint
changes. Under `[security].enforcement = ENFORCE` with the class named in
`[secret_rotation].enforce_secret_expiry_classes`, an overdue clock refuses the engine start.

Until this decision the fingerprint was `HMAC-SHA256(key, value)` cut to 32 hex, with the key
derived by HKDF from the store's audit-MAC key, which is itself derived from the store DEK. So a DEK
rotation changed every fingerprint while no secret had changed. BACKLOG #2242 answered that with a
re-key rule: each stored fingerprint names its key by a key id, and a start that holds the retired
DEK recomputes the old fingerprint under it and keeps the date. Without the retired DEK the answer is
undecided and the row keeps its older date.

That rule leaves a gap, recorded in #3247 item 1 and found in engine PR 2293. Under the Windows
service the first start after `rotate-key` runs without the retired DEK, because `serve` refuses a
store key in the service's environment lists. Every non-DEK secret is then undecided, and its
date is kept, so a secret rotated in the same window is not seen as rotated. Under enforce, a secret
that really was rotated can still refuse the start; the way out was to rotate it again.

The fingerprint key is the only thing between a reader of `secret_rotation_meta` and offline
guessing of a low-entropy secret (an AD bind, SMTP or store password), because the HMAC is not
stretched. Any fix has to keep that, and keep forward security: a DEK that leaked before a rotation
must not open what is written after it.

A design review by the batch 253 Manager on 2026-10-12 (read-only, from engine `origin/main`
`1e5bfcc6c5`) rejected the first proposal, a random per-store fingerprint key sealed under the DEK,
because a leaked old DEK would keep that key forever. Its full text is on vault PR 2404, comment
6152821504. It recommended S, below, with A as the fallback.

## Decision

**Seal each non-DEK fingerprint as an ordinary store-cipher cell, which `reencrypt_to_active`
re-seals. Stored behind a new scheme tag, `sealed-hmac-sha256-32`.**

- **The cell.** Its plaintext is `<key hex>:<mac hex>:<class id>`: a fresh random 32-byte HMAC key
  drawn per write, `HMAC-SHA256(key, value)` cut to 32 hex, and the row's `secret_key`. It is sealed
  by the store cipher under the cell AAD `("secret_rotation_meta", "fingerprint", secret_key)` and
  stored as `sealed-hmac-sha256-32:` followed by the `mfenc:` value
  (`store/crypto.py`, `seal_rotation_fingerprint` and `open_rotation_fingerprint`). The class id is
  checked inside the plaintext too, on every open, so a cell moved to another row reads as
  unreadable even when the frozen v1 writer sealed it with no AAD (`[store].aad_bind = false`), and
  the rotation pass never re-seals such a cell as its new row's.
- **The compare.** The reconcile opens the cell and recomputes the MAC under the key inside it,
  through `hmac.compare_digest` over bytes (#1167). A match keeps the row as it is. A mismatch is a
  rotation and resets `last_rotated`. Either way a rotation writes a fresh key.
- **A DEK rotation does not move it.** `rotate-key`'s `reencrypt_to_active` re-seals each sealed
  fingerprint under the new key on all three backends (`_reseal_rotation_fingerprints_to_active` in
  `store.py`, `sqlserver.py` and `postgres.py`), so what is compared inside the cell is unchanged and
  no start needs the retired DEK. A cell no configured key opens is left as it is and counted in a
  WARNING; a fingerprint is not PHI, and it must not stop a key rotation.
- **Keep the dates for anything unreadable.** A cell that no key opens, that names another row, that
  is malformed or blank, a pre-#3472 `hmac-sha256-32` row, an untagged pre-#3421 row, and a tag this
  release does not know all keep `tracked_since` and `last_rotated`, and a fresh cell is sealed. That
  direction can only over-report an age. **An old row never resets a clock.** A missing row is a new
  class, as before.
- **`vault_transit` stays off.** Only the in-process AES-GCM cipher fingerprints (the
  `key_provider = vault` one included), as before. `TransitCipher` could seal with no key in heap;
  whether it should is #3473 and is not decided here. The keyless store fingerprints nothing.
- **Removed:** the DEK-derived fingerprint key (`rotation_fingerprint_key`,
  `rotation_fingerprint_keys`, `_derive_rotation_fp_key` and its HKDF label), the key id and the
  re-key path (`_fingerprint_key_id`, `_keyed_fingerprint`, `_rekeyed`, `prior_fingerprint_keys`),
  and the advice to keep the retired key through the first start after a rotation.
- **The DEK row is unchanged.** Its fingerprint is still its key id, tagged `sha256-16`, and
  `rotate-key` still stamps it.
- **Schema.** No new table or column. One column's stored format changes for non-DEK rows. A
  sealed cell can be longer than 255 characters (measured: about 240 to 255 under the frozen v1
  writer, 260 to 320 under the default cell-bound writer, more for a long `env()` key), so on SQL
  Server, where the column was `NVARCHAR(255)`, it becomes `NVARCHAR(MAX)`, and an existing table
  is widened in place. SQLite and PostgreSQL store it as `TEXT` already.

This supersedes the BACKLOG #2242 re-key rule.

## Acceptance Criteria

- **AC-1** — WHEN the store key is rotated with `rotate-key` and the engine then starts without the
  retired key, THE SYSTEM SHALL keep every unchanged non-DEK secret's `last_rotated` date.
  → `tests/test_secret_rotation_sealed_fingerprint.py::test_a_store_key_rotation_keeps_every_clock`
- **AC-2** — WHEN a non-DEK secret changed in the same window as a store key rotation, THE SYSTEM
  SHALL reset that secret's clock at the next start.
  → `tests/test_secret_rotation_sealed_fingerprint.py::test_a_secret_changed_with_the_store_key_reads_as_rotated`
- **AC-3** — IF a stored non-DEK fingerprint is a pre-#3472 keyed MAC, untagged, unknown, unreadable
  or another row's, THEN THE SYSTEM SHALL keep its dates and store a sealed cell.
  → `tests/test_secret_rotation_sealed_fingerprint.py::test_an_unreadable_fingerprint_never_resets_a_clock`
- **AC-4** — THE SYSTEM SHALL store a non-DEK fingerprint only as a sealed cell under the
  `sealed-hmac-sha256-32` tag, never as a bare MAC.
  → `tests/test_secret_rotation_sealed_fingerprint.py::test_the_fingerprint_is_stored_sealed`
- **AC-5** — WHERE the store cipher is keyless or `vault_transit`, THE SYSTEM SHALL fingerprint no
  non-DEK secret.
  → `tests/test_secret_rotation_sealed_fingerprint.py::test_only_the_in_process_cipher_fingerprints`

## Options considered

1. **S, seal the fingerprint as a cipher cell.** Keeps the protection against a store reader (the
   store key is needed), keeps forward security (an old key cannot open a cell sealed after the
   rotation), and deletes the key ids, the retired-key fingerprint keys, the undecided path's
   warning and the retired-key caveat. **CHOSEN** (owner ruling above).
2. **A, carry the retired fingerprint keys forward.** `rotate-key` seals each retired DEK's
   fingerprint key under the new DEK in a one-row table, and the reconcile adds them to the prior
   keys. No race, no forward-security loss, but a new table on three backends and all of the #2242
   machinery kept. Rejected as the primary; it was the Builder's fallback had S cost far more than one
   build, or had review rejected the inner MAC.
3. **A random per-store fingerprint key sealed under the DEK and re-sealed by `rotate-key`.** The
   first proposal. Rejected: whoever held the old DEK and one old store copy keeps the key forever and
   can test guesses against every later copy. Fixing that means regenerating the key at rotation,
   which moves the fingerprints again and becomes A with extra parts.
4. **Recompute every fingerprint inside `rotate-key`.** Rejected: the secret values live in the
   service environment and the live graph, not in the offline command, and an HMAC cannot be re-keyed
   without its input.
5. **Derive the key from something that does not rotate.** Rejected: nothing secret and
   non-rotating exists; the store salt is public.
6. **Document "start the engine once between `rotate-key` and any other secret change".** It closes
   the gap with no code, but the Windows service's first start has no retired key, so it does not.

## Consequences

**Positive** — A store key rotation no longer reads as a change, or an undecided change, of every
non-DEK secret, on any backend and under the Windows service. A secret changed together with the
store key is still detected. Forward security after a leaked-DEK rotation is kept. The retired key no
longer has to survive past `rotate-key` for the watcher's sake.

**Negative / risks** — `secret_rotation_meta.fingerprint` joins the store cipher's covered cells,
so each reconcile write costs one AES-GCM invocation against the key's bound. The first start on
this release keeps every non-DEK secret's date and re-seals it, so a secret changed between the last
start on an earlier release and this one is not detected; that is the "old rows never reset a clock"
half of the ruling. An operator with write access to the store can still delete a row, which makes
the class new with today's dates, or edit its plaintext dates; neither changes with this decision.

**Out of scope** — Whether `vault_transit` stores fingerprint secrets (#3473). Which secrets an
operator can see lost rotation detection (#3247 item 1's third residual).
