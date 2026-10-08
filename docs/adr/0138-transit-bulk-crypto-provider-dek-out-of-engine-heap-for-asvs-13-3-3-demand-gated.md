<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# ADR 0138 — Transit bulk-crypto provider: move the store DEK out of engine heap for ASVS 13.3.3 (demand-gated)

- **Status:** Accepted (2026-07-20) — **Increment 1 built + verified** (see *Implementation status*); the deferred legs stay demand-gated. Amended 2026-09-28: the AES-GCM invocation bound on this path is a **documented operator precondition**, weaker than the engine's counted bound, and it does not meet owner ruling R3 (see the amendment at the end). Amended 2026-10-07: the engine records who attested the bound for the configured Transit key name, in an audited store row only the CLI writes, and `serve` refuses without it under enforce (BACKLOG #2337).
- **Date:** 2026-07-20
- **Related:** [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (the KeyProvider seam this extends) · [ADR 0109](0109-at-rest-encryption-fail-closed-on-an-undeclared-phi-posture.md) (Rejected — undeclared-PHI fail-closed) · ASVS-L3-ASSESSMENT-2026-07-20.md §3 (13.3.3 Fail) · ASVS-L3-RISK-ACCEPTANCE-REGISTER.md theme 5 · solutions research (`ASVS-L3-FAILS-SOLUTIONS-RESEARCH-2026-07-20.md`) · BACKLOG **#271** · CLAUDE.md §2 (reliability/at-rest), §9 (PHI/HIPAA)

---

## Implementation status

**Increment 1 — built + verified (commit `a2bae457`).** The store-DEK / at-rest scope of the Decision:
- `store/crypto_transit.py` — `TransitCipher` (the `Cipher` protocol) does bulk AES-GCM inside OpenBao/Vault
  Transit; the plaintext DEK never enters engine heap. New `mfenc:v3` at-rest marker. `cell_aad` rides
  Transit `associated_data` (11.3.3 binding — a moved blob fails the tag). `audit_mac_key()` = `None` → the
  audit chain is keyless SHA-256 in this mode (owner decision; **16.4.2 stays a documented residual here**).
- `store/base.py` `build_store_cipher` dispatches on the new `[store].cipher_provider` (default `aesgcm`,
  byte-identical); `open_store` routes through that single seam. Fail-closed (`KeyProviderError` → `serve`
  refuses; per-op `CipherError`).
- **Verified:** ruff + ruff format + `mypy --strict` clean; 15 tests incl. 2 **live OpenBao 2.6.0**
  integration tests proving `open_store` lands a DEK-free `mfenc:v3` value at rest; 84 existing store/crypto
  tests still pass.

**Deferred (stay demand-gated / prerequisites):** the `vault-benchmark` throughput spike; the SQL Server /
Postgres call-site legs (single-value calls today — `batch_input` is the throughput lever); the serve-gate
keyless-PHI awareness (a Transit-mode PHI instance must not trip the "no key → refuse" gate); rotation
across a Transit↔in-process boundary; and 13.3.1's **hardware** clause (HSM-seal the vault, or a Luna A750+)
plus the argon2id/token/audit-HMAC scope (see *To resolve*).

## Context

ASVS 5.0 L3 requirement **13.3.3** — *"Verify that all cryptographic operations are performed using an
isolated security module (such as a vault or hardware security module)…"* — is scored **Fail** in both
postures on the 2026-07-20 assessment. Today the store's 32-byte DEK does bulk AES-256-GCM **in-process**,
with the plaintext key resident in the engine's heap; the shipped Vault provider
([`store/keyprovider_vault.py`](../../messagefoundry/store/keyprovider_vault.py)) only **KEK-unwraps** the
DEK, so the unwrapped key still lands in process memory for the bulk work.

Two verified facts (from the solutions research,
3-vote adversarially verified) reframe the fix:

1. **The requirement's own text names "a vault"** — disjunctively from "hardware security module" — as a
   qualifying isolated module. The earlier assumption that only an HSM qualifies was wrong. A software vault
   (HashiCorp **Vault** / **OpenBao**) whose **Transit** engine performs the *bulk* encrypt/decrypt is a
   qualifying module; its `batch_input` (order-preserving) + 32 MiB request cap comfortably swallow this
   workload (10–1000 msg/s, 1–100 KB values).
2. **Bulk crypto in a hardware HSM is largely a non-starter** and is not needed here: AWS/Azure publish no
   AES-GCM throughput and their own guidance prescribes KEK-wrap envelope encryption; YubiHSM 2 has no
   AES-GCM at all; only a mid-tier Thales **Luna A750+** (10,000 AES-GCM tps) is nominally viable — reserved
   for the mandated-HSM tier.

**Significance is low-to-moderate and the trigger is specific:** 13.3.3's residual only bites a privileged
**live-memory** attacker, and does **not** weaken at-rest protection against the primary threats (stolen
disk/backup/DB file). It is a signed accepted residual (register theme 5); this ADR records the chosen
architecture for when a **BAA/contract mandates hardware key custody**, not a decision to build now.

## Decision

**When the hardware-key-custody trigger fires, close 13.3.3 by extending the [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md)
KeyProvider seam with a Transit bulk-crypto provider: the store cipher path routes its bulk AES-GCM
encrypt/decrypt through a local Vault/OpenBao Transit sidecar (via `batch_input`), so the plaintext DEK
never enters the engine process. Ship OpenBao (MPL) as the reference sidecar. The provider is fail-closed —
if the sidecar is unreachable the store operation errors, never silently falls back to in-process crypto.**

Tiered, matching the deployment model:

| Tier | Config | 13.3.3 | 13.3.1 (hardware clause) |
|---|---|---|---|
| **Default** (SQLite, no infra) | in-process crypto, as today | Fail (accepted, theme 5) | Fail (accepted) |
| **Hardened** (server DB, sidecar OK) | OpenBao/Vault Transit **bulk-crypto** provider | **Pass-when-configured** | Partial (software vault) |
| **Mandated-HSM** (BAA requires HW custody) | Transit with an **HSM-sealed** vault, or Luna A750+ direct PKCS#11 | **Pass** | **Pass** (hardware) |

**Scope of "all crypto".** The primary target is the **store DEK + bulk data** (the highest-value key and
the largest attack surface). Whether a clean Pass additionally requires routing argon2id password hashing,
session-token CSPRNG/HMAC, and the audit-chain HMAC through the module — or whether scoping 13.3.3 to the
data-at-rest path is defensible — is an open adjudication (see *To resolve*).

**Prerequisite spike (blocking the build, not this decision):** no published Transit throughput figure
exists; a `vault-benchmark` run at 1–100 KB payloads with realistic batch sizes on representative Windows
hardware must confirm the sidecar sustains the 1000 msg/s end before committing.

## Options considered

1. **Vault/OpenBao Transit bulk-crypto sidecar** — rides the existing seam; ASVS-text-qualifying; OpenBao is
   MPL (AGPL-compatible as an optional dependency); local low-latency. **CHOSEN** for the hardened tier.
2. **Direct HSM PKCS#11 bulk AES-GCM** — only Luna A750+ is throughput-viable; heavy, hardware-bound.
   **CHOSEN only for the mandated-HSM tier** (also clears 13.3.1).
3. **Windows VBS enclave (in-process, host-can't-read)** — genuine isolation, but production enclave DLLs
   sign **only** via Microsoft's paid Trusted Signing cloud and require Win11 26100.2314+/Server 2025+
   (deprecated on Server 2022↓). **Rejected** — wrong fit for an AGPL on-prem product with older-Windows customers.
4. **Crypto-broker daemon (Rust, lsass-style local IPC)** — CNG key isolation is Microsoft's own CC precedent
   for OS-process key isolation, so it is defensible, but assessor-dependent and still fails 13.3.1's
   hardware clause. **Deferred** as a fallback if the vault path proves operationally unfit.
5. **DB-side delegation (SQL Server Always Encrypted enclaves / TDE+EKM)** — removes the engine DEK only if
   HSM/enclave-backed; plain TDE relocates it to the DB process and decrypts into DB memory (no DBA
   protection); server-DB only (SQLite gets nothing). **Rejected as the primary path**; available to operators.
6. **In-process mlocked native buffer (libsodium / Rust `zeroize`)** — reduces heap-copy exposure (helps
   11.7.2) but the DEK is still in-process → **no movement on 13.3.3**. **Rejected** for this cell.

## Consequences

**Positive** — closes 13.3.3 (and, HSM-sealed, 13.3.1) when configured; reuses the shipped KeyProvider seam
and the OpenBao/Vault dependency already in the tree; the default install is byte-identical.

**Negative / risks** — an operational sidecar to run and monitor; a store hot-path network round-trip
(mitigated by `batch_input`, but unmeasured — the spike gates it); fail-closed means a dead sidecar stops
the store (correct, but an availability coupling to document); the sidecar's own key custody just relocates
the trust boundary unless HSM-sealed (which is why 13.3.1 stays Partial in the hardened tier).

**Out of scope** — building it now (demand-gated); the other-crypto scope question (see below); ECH/12.1.5
([ADR 0139](0139-ech-egress-sidecar-sni-hiding-for-asvs-12-1-5-demand-gated.md)).

## To resolve on acceptance

- [ ] Run the `vault-benchmark` throughput spike (1–100 KB, batched) on representative Windows hardware.
- [ ] Confirm OpenBao (MPL) as the shipped reference sidecar and its AGPL-compatibility as an optional dep.
- [ ] Decide the **scope of "all crypto"**: does Pass require argon2id/token/audit HMAC also in the module, or is the store-DEK data-at-rest path sufficient (with the others as a documented residual)?
- [ ] Define the fail-closed + availability semantics (sidecar-down behaviour, HA, startup ordering) and the migration for existing at-rest rows.

## Amendment 2026-09-28 — the AES-GCM bound on this path is a documented operator precondition, not a counted bound (BACKLOG #1173)

**The engine does not count Transit encrypts, and this amendment does not change that.** It records who
owns the bound instead, because nothing on the record said so. The owner ruled on 2026-09-24 that ASVS
11.5.2 reaches this opt-in path, and that the row stays open until it gets "a bound or attested
delegation" (ruling R3 in `ASVS-OWNER-RULINGS-2026-09-24-BATCH126.md`).

**This amendment does NOT meet R3.** It is a documented operator precondition. The owner ruled on
2026-09-28 that a precondition only written down, with nothing recorded by the engine, does not satisfy
R3's attested delegation. R3 needs an audited, per-deployment attestation surface that the engine
records. That surface is not built. A new backlog row for it is being filed, and this amendment cites no
number for it.

**What the engine does in `vault_transit` mode, by symbol.**

- `TransitCipher.encrypt` hands each value to Transit `encrypt_data`. It draws no local nonce and never
  calls `AesGcmCipher._count_invocation`.
- `store/gcm_bound.py` `bounded_cipher` returns `None` for any cipher that is not an `AesGcmCipher`. So
  this path writes no `cipher_meta` row, raises no 2^31 `gcm_invocations` alert, and has no 2^32
  refusal.
- At startup `build_transit_cipher` checks that the data key exists and that its type is in
  `TRANSIT_KEY_TYPES_DATA`. `require_transit_key_type` reads the key's metadata with `read_key` and
  checks only its type. It does not check the key's rotation settings.

**Who owns the budget today.** The per-key-version invocation budget belongs to the operator's Transit key
management, not to the engine. The engine's local bound (the 2026-07-22 amendment to
[ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) and `store/gcm_bound.py`) does not reach it.

**Deployment precondition, owned by the operator.** Before serving in `vault_transit` mode, the operator
rotates the Transit data key (`MEFOR_STORE_TRANSIT_KEY`) often enough that no single key version seals
more than 2^32 values. Size the schedule from the site's peak encrypt rate, not its average. Keep the
same margin the local bound keeps: plan to rotate by 2^31. A backfill, replay or bulk re-send spends
the budget faster than steady traffic, so count it in.

`TRANSIT_KEY_TYPES_DATA` admits `aes256-gcm96`, `chacha20-poly1305` and `xchacha20-poly1305`. The
2^32 figure is the AES-GCM figure, from the page cited below. This amendment applies the same budget to
`chacha20-poly1305` as a conservative choice and claims no vendor figure for it. `xchacha20-poly1305`
uses a 192-bit nonce, so a random-nonce collision is not the limit there; no figure is claimed for it
either.

**What HashiCorp's documentation says, fetched 2026-09-28.** Only these two pages were read:

- The Transit secrets engine page (<https://developer.hashicorp.com/vault/docs/secrets/transit>)
  advises rotating an AES-GCM key before about 2^32 encryptions per key version, citing NIST SP
  800-38D. It describes rotation as an explicit command that creates a new key version.
- The Transit API page (<https://developer.hashicorp.com/vault/api-docs/secret/transit>) documents
  `auto_rotate_period` on key create and key config. It rotates on a time period, is off by default
  (`"0"`), and cannot be shorter than one hour.
- Neither page describes rotation triggered by an encryption count.

So on Vault, the precondition is met by setting `auto_rotate_period` to a period sized as above, or by
rotating on a schedule by hand. Rotation by time bounds a key version's count only while the real rate
stays under the rate the period was sized for. **OpenBao's documentation was not fetched.** The
precondition applies to it unchanged, and this amendment claims nothing about what OpenBao enforces.

**This is weaker than the local bound, and the record must say so.** The local bound counts every
encrypt against a persisted per-key total, alarms at 2^31 and stops ingest at 2^32. The precondition does
none of those things:

1. Nothing counts, so nothing alarms and nothing refuses. Passing 2^32 on one key version would be
   silent.
2. The bound rests on a schedule sized from an estimated rate. A burst above the estimate can outrun it.
3. The engine cannot see whether the operator met the precondition. It reads the key's metadata but
   checks only the type, so a key with rotation off starts and serves normally.

**Not built, and named so nobody reads them as done.** A counted bound for this path is still possible.
Transit returns the key version in each ciphertext's `vault:vN:` prefix, so the engine could charge a
per-version total the way `cipher_meta` charges a local key. A narrower step would read the key's
rotation settings at startup and warn when rotation is off. The engine already calls `read_key` there;
whether that answer carries the rotation settings was not checked for this amendment. Neither step
exists today, and neither is the R3 attestation surface either.

The operator-facing statement of this precondition belongs in the `cipher_provider` row of
`docs/CONFIGURATION.md`. That row does not carry it yet. *(Since the 2026-10-07 amendment it
does, as precondition (3).)*

## Amendment 2026-10-07 — the engine records who attested the bound, and refuses without it (BACKLOG #2337)

The owner settled the R3 attestation surface on 2026-10-07, given to the batch 201 Manager in
session. Three rulings:

1. A reasoned config declaration with no who and when does not meet R3. The engine records who
   attested and when.
2. The record is a new audited row in the store, on all three backends. Only a CLI command writes
   it, with the `cli:<osuser>` actor other host-run commands use. `serve` reads it at start. There
   is no new RBAC permission and no API endpoint.
3. It binds to the Transit data-key NAME. Pointing the store at another key name voids it.
   Rotating versions inside one key does not, because the operator attests to that key's rotation
   policy. A CLI command withdraws it, also audited.

**What was built.** The one-row `transit_bound_attestation` table holds the key name, the reason,
the actor and the time. `messagefoundry store attest-transit-bound --reason` writes it and
`messagefoundry store withdraw-transit-bound` deletes it. Each commits its audit row
(`store.transit_bound_attested`, `store.transit_bound_withdrawn`) in the same transaction, so the
row never exists without the record of who wrote it. `Engine.start` calls
`enforce_transit_bound_attestation` first, before recovery or any listener. With no row naming
the live cipher's key, it raises `TransitBoundUnattestedError` under `[security].enforcement =
enforce` and logs a warning under `warn`. `GET /security/posture` reports the row in
`transit_bound_attestation`.

**The row is bound to its audit row.** A Manager decision in the same batch, within ruling 2's
"audited row", and not a further owner ruling. The row also stores the sequence number and chain
hash of the audit row its write appended. Every read, by the start gate and by the posture alike,
checks that audit row: it exists, it is the newest attest or withdraw row, it names the same key,
reason, actor and time, it carries the recorded hash, and its MAC verifies under the audit key of
its own range. It reuses the chain's row MAC and constant-time compare and walks no chain, so it
costs one MAC per read. A row that fails counts as no attestation. Without this, anyone with DML on
the store could insert a row the gate would trust, with no audit trace. The MAC is recomputed
under the Transit key version the audit row names, so rotating the key keeps the attestation, as
ruling 3 says. The store builds the withdraw audit row itself, as it does the attest row.

**What the binding does not catch.** Deleting a later withdraw row and re-inserting the old row
passes this check. If rows follow the deleted one, the chain breaks and `audit-verify` reports it,
as does the start-up walk when `[integrity].audit_verify_on_start` is on. If the withdraw row was
the newest row, only an external anchor taken after it catches the cut.

**The binding is to the key name only**, as ruling 3 says. A store pointed at another Vault, or
another Transit mount, that holds a key with the same name keeps the attestation.

**What it does not change.** The engine still counts no Transit encrypts. The 2026-09-28
weaknesses 1 and 2 above stand: passing 2^32 on one key version is silent, and a burst can outrun
a schedule. Weakness 3 narrows only to this: the engine now knows that a named operator vouched
for the schedule, and when. It still does not read the key's rotation settings. Whether this
meets R3 is a scorecard call, not this amendment's.
