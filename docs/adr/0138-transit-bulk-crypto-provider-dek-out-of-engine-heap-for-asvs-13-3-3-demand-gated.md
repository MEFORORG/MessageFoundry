<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0138 — Transit bulk-crypto provider: move the store DEK out of engine heap for ASVS 13.3.3 (demand-gated)

- **Status:** Accepted (2026-07-20) — **Increment 1 built + verified** (see *Implementation status*); the deferred legs stay demand-gated
- **Date:** 2026-07-20
- **Related:** [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (the KeyProvider seam this extends) · [ADR 0109](0109-at-rest-encryption-fail-closed-on-an-undeclared-phi-posture.md) (Rejected — undeclared-PHI fail-closed) · [ASVS-L3-ASSESSMENT-2026-07-20.md](../security/ASVS-L3-ASSESSMENT-2026-07-20.md) §3 (13.3.3 Fail) · [ASVS-L3-RISK-ACCEPTANCE-REGISTER.md](../security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md) theme 5 · [solutions research](../security/ASVS-L3-FAILS-SOLUTIONS-RESEARCH-2026-07-20.md) · BACKLOG **#271** · CLAUDE.md §2 (reliability/at-rest), §9 (PHI/HIPAA)

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

Two verified facts (from the [solutions research](../security/ASVS-L3-FAILS-SOLUTIONS-RESEARCH-2026-07-20.md),
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
