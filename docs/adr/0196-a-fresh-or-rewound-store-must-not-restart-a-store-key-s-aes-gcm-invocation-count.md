# 0196 — A fresh or rewound store must not restart a store key's AES-GCM invocation count

- **Status:** **Accepted -- 2026-09-26, by an owner ruling given to a Manager seat.** The owner
  accepted the drafter's recommendation, choosing the option labelled "C+ per-store sub-key
  (Recommended)". The ruling is posted on engine PR 1655. The build may start. Under *To resolve
  on acceptance*, five items are settled and one is a build list rather than a choice. One stays
  open: how the salt reaches the cipher. It is an implementation detail the build decides, not
  policy.
  > **Superseded status text, kept as a record.** Until 2026-09-26 this line read: *"Proposed
  > (2026-09-26). An options memo with the drafter's recommendation. The owner accepts or rejects it,
  > and no code may follow until it is Accepted. BACKLOG #2070 stays open until then; its closing step
  > 1 asks for exactly this record before any build."*
- **Date:** 2026-09-26
- **Related:** BACKLOG #2070 (the row this answers) ·
  [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md), amendment 2026-07-22 (the persisted
  bound) · [ADR 0049](0049-turnkey-dr-backup-restore-verify.md) (DR backup and `restore`) ·
  [ADR 0048](0048-third-tier-disaster-recovery-standby.md) (the DR cold seed, under the same key) ·
  [ADR 0193](0193-audit-chain-key-ranges-survive-a-store-key-rotation.md) (audit keys derived from
  the DEK) · [ADR 0052](0052-enterprise-scale-target.md) (the scale target) · BACKLOG #1720 and
  engine PR 1629 (the keyed refusal text) · BACKLOG #1004 (the calendar refusal)

---

## Context

Every fact below was read at engine `origin/main` `0bbe01d22` on 2026-09-26. Line numbers are left
out on purpose; find each by the symbol named.

### The count lives in the store it protects

1. Every encrypt draws a fresh random 96-bit nonce: `os.urandom(_NONCE_BYTES)` in
   `AesGcmCipher.encrypt`, with `_NONCE_BYTES = 12` (`store/crypto.py`).
2. The cipher warns at 2^31 invocations of one key and fails closed at 2^32
   (`_GCM_SOFT_WARN_INVOCATIONS`, `_GCM_MAX_INVOCATIONS`, `_count_invocation`). No write path catches
   the `CipherError`, so crossing 2^32 halts ingest.
3. The count is persisted in the `cipher_meta` table, one row per `key_id`, with the same shape on
   SQLite, Postgres and SQL Server (DDL in `store/store.py`, `store/postgres.py`,
   `store/sqlserver.py`). The open path never reads the row on its own. Its first checkpoint calls
   `add_cipher_invocations`, which adds a block by upsert and learns the key's total from that same
   write (`checkpoint_invocations` in `store/gcm_bound.py`). So that first write also CREATES the row
   for a key that had none.
4. `key_id` is the first 16 hex characters of SHA-256 over the key (`_fingerprint`,
   `_KEY_ID_LEN = 16`). A new key has no row, so its count starts at zero. That is the whole of how
   `rotate-key` resets the count (the `_rotate_key` docstring in `__main__.py`, and "Rotation
   semantics" in the `gcm_bound.py` module docstring).
5. No operation zeroes an existing row, and that is deliberate. The `gcm_bound.py` docstring says it
   "would let an operator refresh the birthday budget of a key they never actually changed".
6. Exactly three places build an `AESGCM` object: `_install_key` in `store/crypto.py`, and
   `store/backup_codec.py` once to seal DR archive frames and once to open them. Backup frames are
   charged to the key by `BackupRunner._charge_archive_invocations` (`pipeline/dr_backup.py`), after
   each run that finishes building its archive.

So the count is a property of the key only while the key is used in exactly one store, and that
store only moves forward. BACKLOG #2070 names at least five routes that break this:

| Route | What happens | What the store meets |
|---|---|---|
| 1 | The store file is deleted and `serve` recreates it under the same key. | No row. |
| 2 | The data directory is wiped while the key stays in the environment. | No row. |
| 3 | A Postgres or SQL Server store is pointed at a new, empty database under the same key. | No row. |
| 4 | An older backup is restored. | A row behind the key's true use. If the key was rotated after the backup, no row for the active key. |
| 5 | Two stores are live under one key, such as a standby seeded from a backup, or a staging copy given the production key. | Two rows, each counting only its own spend. A standby seeded before a rotation meets no row for the active key. |

Two of these are product paths, not only operator slips. `restore` (ADR 0049) writes an archive's
store to a new path. ADR 0048's cold seed restores that archive at the DR site under the **same** DEK,
by design, and then runs on it. That is route 4, and if the primary is still running it is also
route 5. `restore` covers SQLite only. Server-backend backup and restore is delegated to the DBA
(the `pipeline/dr_backup.py` module docstring, BACKLOG #52), so the engine never sees those.

Engine PR 1629 (merged as `41e326e0e`) added a schema check on SQLite open. Its only contribution to
this problem is a message. When the check refuses a keyed store, `_REMEDY_KEYED` and `_KEYED_DETAIL`
in `store/schema_verify.py` tell the operator to set a NEW key before recreating the store. That is
advice on one path. Nothing enforces it, and routes 1 to 5 do not pass through that refusal.

The code review of this ADR found at least four more gaps in the bound. They are outside BACKLOG
#2070's five routes, and none of the options below is about them. AC-6 and AC-8 name two of them, so
accepting the recommendation as written would pull those two into its build. They are named here so a
build does not assume they are covered:

- **A backup run that fails while building its archive is not charged.** When
  `_build_archive_blocking` raises, `_do_backup` raises `BackupError` before
  `_charge_archive_invocations` runs. The frames stay in `self._frames`. The next run that finishes
  its build charges them, under its own key. A one-shot `backup`, or a rotation in between, loses
  them or charges the wrong key. The charge itself also logs and swallows a failed add.
- **A failing counter write falls back quietly.** `checkpoint_invocations` and
  `reserve_invocations_ahead` log a warning and fall back to the in-process count when the add
  fails. If `cipher_meta` writes keep failing, each restart restarts from a stale row.
- **The full restore-verify opens a scratch copy under the live key.** Both
  `[backup].full_restore_verify` and the CLI `restore-verify --full` reach `_full_open_check`, which
  opens the snapshot through the real store. Anything that open seals is charged only to the
  throwaway copy's row.
- **The DR codec never consults the ceiling.** `encrypt_stream` in `store/backup_codec.py` seals every
  frame with no check against `_GCM_MAX_INVOCATIONS`, and the frames are charged afterwards. A key just
  below 2^32 still seals a whole archive past it, under every option here.

### What the count protects, and what a reset costs

With a random 96-bit nonce, the chance that two of `q` encrypts under one key share a nonce is about
q² / 2^97. At the 2^32 ceiling that is about 2^-33. NIST SP 800-38D caps random-nonce use of one key
at 2^32 invocations. The 2^32 ceiling is the engine's chosen control for ASVS 11.3.4. ADR 0019's
2026-07-17 amendment records the project's reading of that requirement as "bound the number of AEAD
invocations per key".

A repeated nonce matters only to someone who holds both ciphertexts: a copy of the store file, a DR
archive, or a moved-aside old store. For that reader it does two things. It gives the XOR of the two
plaintexts. It also lets them recover the GCM authentication key, and so forge values that the store
would accept as authentic under that key.

A reset lets the key's real use run past its recorded use. After `k` resets that each ran to the
ceiling, the key could reach (k + 1) × 2^32 encrypts while the count reads below 2^32. The collision
chance grows to about (k + 1)² × 2^-33, so one reset gives about 2^-31. That is still small, and this
ADR does not claim one reset is a practical break. The defect is that the control reads low with no
signal. The ceiling is the promise the engine makes, and on these routes it does not hold.

The ceiling is reachable at the scale the project targets. A `crypto.py` comment estimates about six
ciphered writes per message, and ADR 0052 targets 45 million messages a day on one unified store.
Together that is about 2.7 × 10^8 encrypts a day, which reaches 2^32 in about 16 days. This ADR did not
measure either figure; it only multiplies them. At that rate a site would meet the ceiling often, and
routes 1 to 3 would clear it without anyone meaning to defeat it.

Per engine `CLAUDE.md` section 0 there are no deployments. Every consequence above is what a
deploying site would meet, not something happening now.

### Whom the count defends against

Anyone who can write to the store can delete a `cipher_meta` row and zero the count. So the count does
not defend against a store writer, and no option here changes that. It defends against honest overuse
of a key. All five routes are honest operations. The fix therefore has to make the honest paths safe;
it does not have to resist someone who can already edit the store.

### The store cannot tell a new key from a reused one

A store with no row for its active key is also what every legitimate case looks like:

- a new install with a new key;
- `serve` under a new active key, with the old one retired, before `rotate-key` runs;
- `rotate-key` itself, which relies on the new key having no row.

Routes 1 to 3 look exactly the same. A key in `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` cannot prove the
active key is new. PR 1629's own remedy tells operators to keep retired keys set, so it is standing
state, not an act.

## Decision

**Owner ruling, 2026-09-26: option C+.** The owner accepted the drafter's recommendation, choosing the
option labelled "C+ per-store sub-key (Recommended)". The label names the option. The Manager seat
read the ruling as accepting the whole recommendation, which also names where the salt lives and how
the residual routes are handled. *To resolve on acceptance* records both as settled on that reading.

> **Superseded decision text, kept as a record.** Until 2026-09-26 this section read: *"**None. This
> memo does not choose.** It lays out the options with their costs and gives one drafter's
> recommendation, which the owner may take or reject."*

## Options considered

"Closes" means the route can no longer make the count read low. "Refuses" means the engine stops and
waits for the operator to act. Routes 4 and 5 are split by whether they pass through the engine's
`restore` command.

| Option | Routes 1 to 3 | Route 4 via `restore` | Route 5 via `restore` (cold seed) | Routes 4 and 5 outside the engine | Operator burden | Main failure mode |
|---|---|---|---|---|---|---|
| **A.** Refuse a keyed open that meets no row, unless the operator attests the key is new | Refuses | Partly: refuses only if the active key changed since the archive | Partly, as route 4 | Partly: refuses only after a rotation | An attest step on every fresh keyed store and on every new active key, first install included | The attest step gets scripted or skipped, and a false attestation is one command |
| **B.** Keep the count outside the store, beside the key, and enforce the larger figure | Closes where a place beside the key exists | Closes only with a counter the restoring host shares | Closes only with a shared atomic counter | Route 4 on the same host closes with a per-host counter; route 5 needs a shared atomic counter | New state to back up, protect and keep consistent | An environment-variable key has no place beside it, and a per-host figure falls behind on multi-host `[cluster]` nodes |
| **C.** Derive a per-store sub-key with HKDF over the DEK and a random store salt | Closes by construction | No | No | No | None | Every `AESGCM` site must use the sub-key; under sub-choice 1 the salt row also becomes load-bearing |
| **C+.** C, and `restore` gives the restored store a new salt | Closes by construction | Closes | Closes | No | None | As C, and the restored store must be re-salted before it encrypts anything |
| **D.** Require a new active key at every `restore`, checked against the archive's recorded `key_id` | No | Partly: only when the archive was sealed under the current key | Partly, as route 4 | No | A second key provisioned at the DR site, at failover time | Passes a restore taken before the last rotation, where the current key's count is lost anyway |
| **E.** Accept and document | No | No | No | No | Read the runbook | Silent: the count reads low with no signal |

### A. Refuse a keyed open that meets no row, unless attested

**What it does.** A keyed open that finds no `cipher_meta` row for the active key refuses to seal
anything. The operator clears the refusal with an explicit act that states the key is new.
`rotate-key` cannot count as that act as it stands. It re-encrypts to whatever key is active and
never checks that the key is new, so on route 1 it would create the row and clear the refusal. A
needs its own attest command, and `rotate-key` must refuse under the same rule. The attestation has
to be a one-shot command, not a setting, because a setting would stay in place and pass the next
wiped store too. The attestation's record is the new `cipher_meta` row itself. Losing it with the
store is what forces a fresh attestation after a wipe.
The check has to run before the open's first checkpoint, because that checkpoint creates the row.

**Closes.** Routes 1 to 3, as refusals. Routes 4 and 5 in part: a store restored, seeded or copied
from before the last rotation meets no row for the current key, so A refuses it. That holds inside
and outside the engine.

**Cannot close.** Routes 4 and 5 under an unchanged key. They meet a row, just a low one, and a check
that fires on "no row" cannot see them.

**Burden.** Every new keyed store needs the step, including the first install. So does `serve` under
a new active key before `rotate-key` runs, which is a legitimate case today. An installer that
creates the store has to run the step too.

**Failure mode.** The step becomes routine. Once an installer or a runbook runs it automatically, it
proves nothing, and a false attestation is one command.

### B. Keep the count outside the store, beside the key

**What it does.** The count, or a copy of it, lives with the key rather than with the data. The
engine enforces the larger of the store's figure and the outside figure.

**Closes.** Routes 1 to 3 wherever an outside place exists. Route 4 when the restoring host reads the
same outside figure, because that figure does not rewind with the store. The ADR 0048 cold seed runs
on a different host, so a per-host figure does not reach it. Route 5 only if both live stores charge
one counter that supports an atomic add, such as a Vault KV entry with check-and-set.

**Cannot close, or costs.** The built-in `env` key provider has nowhere to write: the key is a string
in the environment. The `dpapi` provider has a key file, so a sidecar file could sit beside it. An
external provider (ADR 0019) would need its own counter store. None of those is built. Because B
enforces the larger figure, a per-host file never lowers today's count. Engine shards share one host,
so they share the file. `[cluster]` HA nodes on separate hosts each see only their own file, so there
the outside figure falls behind the shared row and adds nothing. Across hosts, B closes routes only
with a shared atomic counter, which a plain on-box deployment does not have.

**Burden.** New state with its own backup, permissions and consistency rules, per key provider.

**Failure mode.** The outside counter is lost, restored or copied along with the key, and the problem
returns one level out.

### C. Derive a per-store sub-key

**What it does.** Each store mints a random salt when it is created. Data is sealed under a sub-key,
not under the DEK itself. The sub-key is HKDF-SHA256 over the DEK. Its `info` is the label
`mefor/store-data-key/v1` followed by the store salt, and its HKDF salt is `None`. That is the shape
`_derive_audit_mac_key` already uses on the DEK. The store salt then sits in `info`, which HKDF-Expand
takes as input to a PRF (RFC 5869). With `salt=None` the Extract step still runs, keyed with zeros.
The DEK is already a uniform 32-byte key, so the build may call HKDF-Expand directly and skip Extract.
The count is kept
per sub-key. A fresh store has a fresh salt, so it has a fresh AES key, and a count of zero is then
the key's **true** count, not a reset. This works for any key provider that hands the engine key
bytes; `vault_transit` is already out of scope because it draws no local nonce.

**Closes.** Routes 1 to 3, by construction and with no operator step. On an empty server database,
several HA nodes may open at once, so minting the salt must be an atomic insert-if-absent that every
node then reads back.

**Cannot close.** Routes 4 and 5. A restored or copied store carries its salt, so it carries its
sub-key and its low count.

**What it must also change.**

- All three `AESGCM` sites must use the sub-key. That includes the DR archive codec, whose header
  would need to carry the salt so the DR site can derive the key. A site left on the raw DEK is
  still counted, but on a raw-DEK row that routes 1 to 3 reset.
- The frozen `mfenc:v1` writer, selected by `[store].aad_bind = false`, has no field for a salt.
  Under sub-choice 2 below it must either stay on the raw DEK, or be retired as a writer. Staying
  on the raw DEK leaves routes 1 to 3 open for sites that choose it.
- The DR codec should reserve its frames before it seals them, as `reserve_invocations_ahead` does
  for the at-open seal. Today it seals with no check against the ceiling.
- Key age must stay keyed on the root DEK. Today `engine.py` passes `store.cipher_info().active_key_id`
  to the age tracker. If that became the sub-key id, a re-salt under C+, or a lost salt row, would
  change the id on a store that already has a stamp. `reconcile_rotation_meta` would read that as a
  rotation and set `last_rotated` to today on a DEK that never changed.
- ADR 0193's audit keys are HKDF-derived from the DEK with no salt. They are HMAC keys with no nonce,
  so they need no change, and a new salt opens no audit range.

**A sub-choice: where the salt lives.**

1. **In one store row.** Short markers. Decrypting a value means trying the DEK with each known salt.
   Losing the row strands every value sealed under it. Uploaded files (ADR 0134) share the store's
   cipher. Recreating the store would strand the uploads sealed under the old salt. PR 1629's remedy
   says the operator still needs those.
2. **In each value's marker**, as a new marker version. The salt is not secret. Every value becomes
   self-describing. Uploads and moved-aside stores stay readable with the DEK alone. A lost salt row
   only means new writes get a new salt, which is safe. The cost is about 24 more characters
   per sealed value, for a 16-byte salt.

**Burden.** None for the operator.

**Failure mode.** A missed `AESGCM` site, or the salt row lost under sub-choice 1.

### C+. C, and `restore` re-salts the store it writes

**What it does.** Everything in C. In addition, `restore` mints a new salt for the store it writes,
before that store seals anything. Old values stay readable under the old salt, as in the sub-choice
above. New writes go under a new sub-key whose count is truly zero. The restored store's low row for
the old sub-key no longer matters, because nothing encrypts under that sub-key again.

**Closes.** Routes 1 to 3 as C does. Route 4 and the standby half of route 5 whenever they go
through `restore`, which covers the ADR 0048 cold seed. That holds whether or not the key was rotated
after the archive was taken, because the new salt makes a new sub-key either way. The DR site needs
no new key.

**Cannot close.** Anything the engine never sees. That includes a copied store file and a VM snapshot
rolled back. It also includes a server backend restored by a DBA, and a staging copy of a live store
given the production key.

**Burden.** None for the operator.

**Failure mode.** As C. Also, `restore` must finish the re-salt before the restored store can open,
or the first write lands under the old sub-key. The full restore-verify's scratch open is not a
`restore`, so it must either re-salt too or seal nothing.

### D. Require a new active key at every `restore`

**What it does.** `restore` compares the active key's `key_id` with the one the archive manifest
records (ADR 0049), and refuses when they match. The archive's key stays in the retired list, so old
values still decrypt.

**Closes.** Route 4 and the standby half of route 5, through `restore` only, and only when the
archive was sealed under the current active key.

**Cannot close.** A restore taken before the last rotation. Say the archive is sealed under K1, and
the site rotated to K2 and spent N encrypts under it. The operator restores with K2 active. D's check
passes, because K2 is not K1. Yet the restored store has no K2 row, so K2's count restarts after N
real uses. D also cannot close routes 1 to 3, where the store cannot tell a new key from a reused
one, or anything outside the engine.

**Burden.** The DR site must hold a second, new key and put it in place at failover time. ADR 0048
already makes key availability at the DR site an operator precondition; this adds a second key to it.

**Failure mode.** A step on the recovery path, the one moment an operator is under the most pressure.

### E. Accept and document

**What it does.** Nothing in code. The runbook tells operators to use a new key for every new store,
every restore and every copy.

**Closes.** Nothing.

**Failure mode.** Silent. This is where the engine stands today.

## Drafter's recommendation

**This is the drafter's recommendation, not a decision.** Take **C+, with the salt in each value's
marker** (sub-choice 2). Record what it leaves open as an accepted limit under **E**: a store copy or
rewind the engine never sees.

Why: it is the only option that closes routes 1 to 3 without asking the operator anything. It does so
by making a fresh store a genuinely fresh key rather than by guessing whether a key is new. The same
re-salt closes the product's own restore paths at the DR site, with no second key to provision. The
per-value marker keeps uploads, moved-aside stores and DR archives readable with the DEK alone, so no
new row can strand data.

**Confidence: moderate, about 60 percent.** These would change it:

- **The owner wants routes 4 and 5 closed outside the engine too.** Only B reaches them under an
  unchanged key, and across hosts only with a shared atomic counter such as Vault. That fits as an
  opt-in on top of C+, not as a replacement, because a plain on-box site has no such counter.
- **A build-time read finds an AES-GCM use under the raw DEK that cannot learn the salt.** C then
  loses its "by construction" claim at that site, and the choice needs a second look.
- **The marker growth proves material** on the ADR 0051 and ADR 0052 write path. Sub-choice 1 would
  then be preferred, and it brings back the load-bearing row.
- **The owner prefers one DEK to mean one AES key**, because operators and auditors can reason about
  that directly. Then A plus D is the plainest pair. A refuses routes 1 to 3 and a restore taken
  before the last rotation; D refuses a restore under the archive's own key. Together they cover
  `restore` either way, at the cost of an attest step and a second DR key.

## The key-age clock is a floor by design, with one consequence to accept by name

`reconcile_rotation_meta` in `pipeline/secret_rotation.py` stamps a secret class with no
`secret_rotation_meta` row as `tracked_since = last_rotated = today`. The module docstring calls
`tracked_since` an age FLOOR: "the stamp records when tracking began, not the key's true age". When
`[secret_rotation].store_key_last_rotated` is set, the operator's date is used instead.

Routes 1 to 3 reset this clock. Routes 4 and 5 carry the store's own `secret_rotation_meta` rows
along with the file. Under an unchanged key, the age they show is the same or older, which errs the
safe way. After a rotation it does not. Say the archive's stamp names K1, the site rotated to K2 on
day 100, and it restores on day 400 with K2 active. `reconcile_rotation_meta` sees a changed
fingerprint and sets `last_rotated` to today, so K2 reads 0 days old instead of 300.

The consequence to accept by name is BACKLOG #1004. Under `[security].enforcement=ENFORCE`,
`enforce_store_key_expiry` refuses to start on a DEK past `store_key_max_age_days + enforce_grace_days`.
Recreating the store under that same key writes a fresh stamp, and the refusal clears. So does a
restore taken before the last rotation, as above. The floor was written with an upgrade in mind, where
a pre-existing key gets a fresh clock. These are the same shape, but under ENFORCE they now also clear
a refusal.

**Drafter's recommendation for this half: accept the floor as designed.** No store can know a key's
true age without an outside record. The engine already has the true-age path, which is the operator
setting `store_key_last_rotated`. Record the ENFORCE consequence in `docs/PHI.md`'s rotation steps,
including the restore case. Keep the age keyed on the root DEK under any option. Confidence is lower
than it would be without the restore case, about 65 percent. It
would change if the owner wants ENFORCE to refuse a fresh keyed store that has no stamp and no
`store_key_last_rotated`. That is option A's attest step, applied to age, with option A's costs.

## Acceptance Criteria

> Stated for the recommended shape, so that accepting it has a testable meaning. No test exists yet
> and none is linked; each is "to build with the chosen shape". Per BACKLOG #2070 step 4, each route
> arm starts with the count set near 2^31. An arm that only asserts the count is "not zero" passes
> with no fix at all, so every arm asserts which key the next write lands under.

- **AC-1** — WHEN a keyed store is created, as a new file or in an empty server database, THE SYSTEM
  SHALL seal new values under a key no other store has used, so its count starting at zero is that
  key's true count. Test: to build with the chosen shape.
- **AC-2** — WHEN several engine processes first open one empty server database at the same time, THE
  SYSTEM SHALL settle on exactly one store salt. Test: to build with the chosen shape.
- **AC-3** — WHEN `restore` writes a store, THE SYSTEM SHALL ensure no new value in it is sealed under
  a key whose persisted count may be below that key's true use. Test: to build with the chosen shape.
- **AC-4** — WHEN `rotate-key` runs, or `serve` starts under a new active key, THE SYSTEM SHALL still
  start the new key's count at zero with no operator step. Test: to build with the chosen shape.
- **AC-5** — IF a value was sealed under an earlier salt of a DEK in the keyring, such as an uploaded
  file or a value in a moved-aside store, THEN THE SYSTEM SHALL decrypt it. Test: to build with the
  chosen shape.
- **AC-6** — THE SYSTEM SHALL charge DR archive frames to the same key the frames are sealed under,
  including frames sealed by a run that then fails. Test: to build with the chosen shape.
- **AC-7** — THE SYSTEM SHALL track the store key's age by the root DEK's fingerprint, never by a
  derived key. Test: to build with the chosen shape.
- **AC-8** — WHEN the full restore-verify opens a scratch copy, THE SYSTEM SHALL NOT seal any value
  in it under the live store's sub-key. Test: to build with the chosen shape.

## Consequences

**Positive.** The routes are named in one place, each option is priced against each route, and the
difference between routes 1 to 3 and routes 4 and 5 is recorded. That difference is what makes a
"no row" check look like a fix when it is half of one. The ADR 0048 cold seed is recorded as a product
path into route 4, not an operator mistake.

**Negative and risks.** This memo proposes and does not decide, so the count still reads low on all
five routes on `main`, and the four gaps found in review stay open. The recommendation adds a key
derivation and a new marker version, which is more cryptographic surface. Every future `AESGCM`
site must remember to use the sub-key. The residual limit, a copy or rewind the engine never sees,
stays open by choice.

**Out of scope.** Resisting someone who can write to the store; they can already zero the row.
Detecting a rewound store against an off-box witness, such as the audit anchor, which could be a later
item. `vault_transit`, which has no local nonce. Re-scoring ASVS 11.3.4, which is record work for a
Manager-dispatched vault Builder once something is built.

## To resolve on acceptance

- [x] **The shape.** C+, A with D, B as an opt-in, or something else. This is the owner's ruling and the
      reason the status is Proposed. **Settled 2026-09-26:** C+, by the owner ruling.
- [x] **Where the salt lives**, if C or C+: one row, or each value's marker. **Settled 2026-09-26: in
      each value's marker (sub-choice 2).** The Manager seat read the 2026-09-26 ruling as accepting the
      drafter's recommendation, so an item that recommendation already answers is settled by the ruling.
      The accepted recommendation reads "Take **C+, with the salt in each value's marker** (sub-choice
      2)".
- [x] **The residual routes.** Accept a copy or rewind the engine never sees as a documented limit, or
      ask for B as an opt-in for sites that run Vault or a KMS. **Settled 2026-09-26: an accepted limit
      under E; B is not offered.** The Manager seat read the 2026-09-26 ruling as accepting the
      drafter's recommendation, so an item that recommendation already answers is settled by the ruling.
      The accepted recommendation reads "Record what it leaves open as an accepted limit under **E**: a
      store copy or rewind the engine never sees".
- [x] **The key-age half.** Accept the floor with the #1004 consequence recorded, or add an ENFORCE
      refusal for a fresh keyed store with no stamp. **Settled 2026-09-26: keep the `tracked_since`
      floor.** The Manager seat read the 2026-09-26 ruling as accepting the drafter's recommendation, so
      an item that recommendation already answers is settled by the ruling. This half has its own
      recommendation, which reads "accept the floor as designed". Its named cost is recorded with it:
      under ENFORCE, recreating the store, or restoring one taken before the last rotation, clears the
      #1004 refusal. The build records that in `docs/PHI.md`'s rotation steps, including the restore
      case, as the recommendation says.
- [ ] **How the salt reaches the cipher.** `open_store` builds every store's cipher with
      `build_store_cipher` before the backend opens, and so does `dr_backup._decrypt_check`. Under C the
      salt lives in the store, so the cipher must learn it after open, or the order must change. **Open
      for the build, as an implementation detail, not policy.** The build decides it, following the
      engine's existing conventions.
- [x] **The four gaps found in review.** The backup run that fails mid-build, the quiet fallback on a
      failing counter write, the full restore-verify's scratch open, and the DR codec that never
      consults the ceiling. Say whether AC-6 and AC-8 stay in this build or move to their own ledger
      items, and what handles the other two. **Settled 2026-09-26.** AC-6 and AC-8 stay in this build as
      drafted, because they are acceptance criteria of the ADR the owner accepted. The other two gaps,
      the quiet fallback and the DR codec that never consults the ceiling, go to the backlog ledger as
      their own items. That routing is the Manager seat's, not the recommendation's; the recommendation
      did not address it.
- [x] **Not a choice; carried to the build.** The accepted option makes these corrections part of the
      build, and the build brief must list them. **Text to update in the same build**, at least: PR
      1629's keyed remedy ("would zero its AES-GCM use count") and the comment above it in
      `schema_verify.py`; the "Rotation semantics" paragraph in `gcm_bound.py`; the `cipher_meta` DDL
      comment in `store.py`; the invocation-bound comment in `crypto.py` and the `_count_invocation`
      error text; the `_rotate_key` docstring; and the "Rotation semantics" paragraph of ADR 0019's
      2026-07-22 amendment.
