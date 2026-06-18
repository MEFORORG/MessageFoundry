# ADR 0019 — Pluggable KeyProvider seam (HSM/KMS/Vault envelope decryption) for store-key material (ASVS 13.3.3)

- **Status:** **Proposed (2026-06-17) — design only.** Designs the pluggable **KeyProvider** seam
  (work package **WP-BL3-04**) that lets the store's at-rest data-encryption key be sourced from an
  external HSM / cloud KMS / Vault via **envelope decryption**. **No production code, no
  `[store].key_provider` setting, and no cloud-KMS/Vault dependency land from this ADR.** The seam
  itself is buildable now, off-by-default (byte-identical to today when unset); the **requirement** to
  use an external provider — and the resulting ASVS 13.3.3 verdict-flip — is gated on the
  off-prem trigger below. Mirrors the "design now, build then" shape of [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) and the accepted-risk shape of [ADR 0018](0018-per-message-signatures-accepted-risk.md).
- **Requirement:** OWASP ASVS 5.0 **13.3.3** (V13 Configuration, **Level 3**) — *"Verify that all
  cryptographic operations are performed using an isolated security module such as a vault or HSM to
  manage and protect key material from exposure outside of the security module."* Scored a hard **Fail**
  at L3 ([ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) §V13), classified
  **DEFERRED-BY-DESIGN** (not off-loopback-gated) in [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md).
- **Built:** Nothing. The Phase-1 at-rest groundwork this *builds on* is already shipped and must **not**
  be redesigned: the `Cipher` protocol + AES-256-GCM keyring and the `mfenc:v1:<key_id>` stored format
  ([store/crypto.py](../../messagefoundry/store/crypto.py)), the single key-resolution chokepoint
  `resolve_active_key` and the single cipher-build seam `open_store`
  ([store/base.py](../../messagefoundry/store/base.py)), the env + Windows-DPAPI key sources
  ([config/settings.py](../../messagefoundry/config/settings.py) `[store]`,
  [secrets_dpapi.py](../../messagefoundry/secrets_dpapi.py)), and the `gen-key` / `protect-key` /
  `rotate-key` CLI ([__main__.py](../../messagefoundry/__main__.py)).
- **Supersedes (on acceptance, for the 13.3.3 dimension):** the **WP-L3-14** "HSM/vault key material"
  deferral one-liner in [ASVS-L3-REMEDIATION-PLAN.md](../security/ASVS-L3-REMEDIATION-PLAN.md) — this
  ADR formalizes the seam that discharges it.
- **Related:** [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md) (13.3.3
  detail + the accepted on-prem residual), [BEYOND-ASVS-L3-REMEDIATION-PLAN.md](../security/BEYOND-ASVS-L3-REMEDIATION-PLAN.md)
  (WP-BL3-04 the implementing WP, WP-BL3-05 posture-gated encryption, **WP-BL3-28** the future
  `mfenc:v2` PQ envelope), [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (the related
  off-loopback transport-security trigger), [ADR 0017](0017-consumer-deployment-model.md) (the per-instance
  adopter posture this composes with), [PHI.md](../PHI.md) §4 / §11 (data at rest + roadmap), and
  [CONFIGURATION.md](../CONFIGURATION.md) `[store]`.

## Context

MessageFoundry encrypts PHI at rest with **AES-256-GCM**, performed **in-process** by the
`cryptography` library. The 32-byte data-encryption key is a base64 secret that is decoded into the
engine's heap at startup and resolved by exactly one chokepoint —
`resolve_active_key(settings)` ([store/base.py](../../messagefoundry/store/base.py) `resolve_active_key`) — from
one of two built-in sources today:

1. `[store].encryption_key` (env `MEFOR_STORE_ENCRYPTION_KEY`; the field default lives at
   [config/settings.py](../../messagefoundry/config/settings.py) `StoreSettings.encryption_key`, and the
   env-overrides-file secret registration is the `('store', 'encryption_key')` entry in
   `_FILE_SECRET_KEYS`); or
2. `[store].encryption_key_file`, a Windows-**DPAPI**-protected key file (WP-11d) that
   `load_protected_key` ([secrets_dpapi.py](../../messagefoundry/secrets_dpapi.py)) `CryptUnprotectData`s
   into memory.

`open_store` ([store/base.py](../../messagefoundry/store/base.py) `open_store`) then builds **one** cipher
— `cipher = make_cipher(resolve_active_key(settings), retired)` — and threads it into every
backend (SQLite / SQL Server / Postgres), so all three share an identical at-rest contract.

**Why 13.3.3 is a Fail today.** Even with DPAPI, the key material **is exposed outside any security
module**: DPAPI protects the key only **at rest on disk** (machine-bound), not **during use** — the
crypto is *not* performed inside DPAPI. There is no vault / HSM / isolated module performing the
operations; a grep of the tree for HSM / PKCS#11 / vault / enclave / TPM returns zero matches. The
requirement **genuinely applies** (the app performs cryptographic operations on PHI) and is not met. It
is one of the **6 remaining L3 Fails** (scorecard 178 / 20 / 6 / 141) and one of the **4 new L3-only
Fails** (4.1.5, 8.4.2, 12.1.4, 13.3.3).

**Governance — deferred-by-design, with a hard trigger.** Per
[ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md) and [PHI.md](../PHI.md) §11,
13.3.3 is **DEFERRED-BY-DESIGN** — closed via an explicit accepted-risk decision, *not* purely
off-loopback-conditional. The accepted residual: on an **on-prem localhost** instance, the env / DPAPI
posture — machine-bound DPAPI key file, owner-only ACLs, AES-256-GCM at rest, loopback bind — is an
**accepted residual**. The **build trigger** that requires an external provider (verbatim): *"Off-prem /
PHI-critical / off-loopback deployment, or a BAA / customer mandating an external HSM/vault (ADR 0002)."*
Same governance shape as [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)'s off-loopback
trigger, but classified deferred-by-design rather than off-loopback-conditional.

The **seam** that lets a triggered deployment satisfy 13.3.3 can be designed and built **now**,
off-by-default — building it does not change loopback behavior. This ADR designs that seam and keeps
the on-prem residual honest: an *accepted Fail is still a Fail* (managed, not remediated) until an
external provider is actually configured.

**Design philosophy** (same as [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)): reuse
the patterns already in the tree — the **single** `resolve_active_key` chokepoint, the unchanged
`Cipher`/keyring and `mfenc:v1` format, the env-overrides-file secret shape, the lazy-imported optional
backends. Add the smallest surface that closes the gap; keep the on-prem, broker-free, single-binary
story intact.

## Decision (proposed)

Introduce a **KeyProvider seam** at the existing key-resolution chokepoint. The seam changes **only how
the base64 active/retired DEK bytes are *provisioned*** — never how they are used. The
`Cipher`/`AesGcmCipher` keyring, the `mfenc:v1:<key_id>` stored format, the active + retired keyring
model, the dead-letter-on-undecryptable contract, and `rotate-key` are all **UNCHANGED**.

### 1. A `KeyProvider` protocol that returns the same bytes `make_cipher` already consumes

Define a small `@runtime_checkable Protocol` — sited next to the `Cipher` protocol in
[store/crypto.py](../../messagefoundry/store/crypto.py) or in a new `store/keyprovider.py`:

```python
@runtime_checkable
class KeyProvider(Protocol):
    def active_key(self) -> str | None: ...          # base64 32-byte DEK, or None (→ identity)
    def retired_keys(self) -> Sequence[str]: ...      # optional; default () — for a rotation window
```

The contract is exactly what `make_cipher(key_b64, retired_b64)` already accepts
([store/crypto.py](../../messagefoundry/store/crypto.py) `make_cipher`): `active_key()` returns the
**base64 of a 32-byte DEK** (validated by `_decode_key`) and `retired_keys()` returns the decrypt-only
keyring entries. Because the provider returns the *same key bytes*, the cipher and keyring are
untouched and **existing `mfenc:v1` rows decrypt with no rotation**.

**Element-level contract for `retired_keys()` (important — avoids a provider-author footgun).**
`make_cipher`'s second parameter is typed `retired_b64: Sequence[str] = ()` and is applied **per
element**: `[_decode_key(k, ...) for k in retired_b64 if k]` (empties filtered). So `retired_keys()`
must return a `Sequence` of **individual** base64 32-byte DEK strings — **one element per key** — each
of which is fed straight through `_decode_key`. **Do NOT pre-join with commas.** The comma-split is a
property *only* of the built-in `[store].encryption_keys_retired` string, and it happens *in*
`open_store` (`[k.strip() for k in settings.encryption_keys_retired.split(",") if k.strip()]`) before
the list reaches `make_cipher`. An external provider that copied the comma-joined shape of the built-in
setting would hand `make_cipher` a single 44-byte "key" that fails `_decode_key`'s 32-byte check.

### 2. `resolve_active_key` dispatches on a new `[store].key_provider`; env + DPAPI become built-ins

Refactor the single chokepoint `resolve_active_key`
([store/base.py](../../messagefoundry/store/base.py) `resolve_active_key`) to dispatch on a new setting:

`[store].key_provider: str = "auto"` — one of `auto` | `env` | `dpapi` | `aws_kms` | `azure_kv` |
`gcp_kms` | `vault` | `pkcs11`. This value-set **intentionally extends** WP-BL3-04's enumerated
`env | dpapi | aws_kms | azure_kv | vault` with three additions: **`auto`** (the secure-by-default
env-then-DPAPI ladder, new default), **`gcp_kms`** (the third hyperscaler, keeping the cloud-neutral
story complete — see §3), and **`pkcs11`** (direct HSM, the isolated *security module* 13.3.3 names by
example). The two **built-in** providers reproduce today's behavior exactly:

- **`env`** — return `settings.encryption_key`, the `MEFOR_STORE_ENCRYPTION_KEY` value.
- **`dpapi`** — return `load_protected_key(settings.encryption_key_file)`.
- **`auto`** (the default, secure-by-default field per WP-BL3-06): **env-then-DPAPI**, i.e. the present
  `resolve_active_key` ladder verbatim (env key if set, else the DPAPI key file). **Unset / `auto` is
  BYTE-IDENTICAL to today.**

`open_store` is unchanged structurally: it still computes `retired` (the comma-split of
`settings.encryption_keys_retired`) and calls `make_cipher(resolve_active_key(settings), retired)` before
selecting a backend. The retired keyring continues to flow from `[store].encryption_keys_retired` for the
built-ins; an external provider that manages its own rotation window may surface retired keys via
`retired_keys()` (additive, optional) as the per-element list described in §1. `key_provider` is **not**
a file-secret — it must **never** be added to `_FILE_SECRET_KEYS` or any plaintext-key surface (it names
a provider, it is not key material).

### 3. Cloud / HSM providers are lazy-imported optional extras that **envelope-decrypt** a wrapped DEK

Each external provider is **lazy-imported** inside its dispatch branch (mirroring the lazy
`SqlServerStore` / `PostgresStore` imports in [store/base.py](../../messagefoundry/store/base.py)
`open_store`) and lives behind an **optional `pyproject.toml` extra** — so the base install pulls **zero**
cloud SDKs. Each performs **envelope decryption** and returns the **base64 plaintext DEK**:

| `key_provider` | Optional extra (PyPI, build-time pin) | Envelope-unwrap call (KEK stays inside the boundary) |
|---|---|---|
| `aws_kms` | `boto3` / `aws-encryption-sdk` | `kms.decrypt(CiphertextBlob=wrapped_dek, KeyId=kek_arn)` → `Plaintext` |
| `azure_kv` | `azure-keyvault-keys` + `azure-identity` | `CryptographyClient(kek_id, cred).unwrap_key(rsa_oaep_256, wrapped_dek)` → `UnwrapResult.key` |
| `gcp_kms` | `google-cloud-kms` | `KeyManagementServiceClient().decrypt(name=kek_resource_name, ciphertext=wrapped_dek)` → `response.plaintext` |
| `vault` | `hvac` | `transit.decrypt_data(name=kek, ciphertext=wrapped_dek)` → base64 plaintext |
| `pkcs11` | `python-pkcs11` / `PyKCS11` | `session.unwrap_key(...)` / `unwrapKey(...)` → `C_UnwrapKey` handle/bytes |

The model is **two-tier**: a **Key-Encryption-Key (KEK)** is generated and held **non-extractable**
inside the HSM / KMS / Vault — its raw bytes never leave the boundary. MessageFoundry's local
**Data-Encryption-Key (DEK)** is the 32-byte AES-256-GCM key the keyring already uses; at rest only the
**wrapped DEK** (KEK-encrypted ciphertext) is persisted. At startup the provider sends the wrapped DEK
to the provider's unwrap API, the unwrap runs **inside** the module against the non-extractable KEK, and
the provider returns the **plaintext DEK** over the (TLS-protected) channel — which `make_cipher` then
consumes unchanged.

**Canonical wrapped form = the raw 32-byte DEK (avoid double-base64).** The provider sealed under the
KEK is the **raw 32 DEK bytes** — not the already-base64 DEK string's UTF-8 bytes. Each provider's unwrap
therefore returns `raw32`, which the seam base64-encodes **exactly once** before handing it to
`make_cipher` (whose `active_key()` contract is "base64 32-byte DEK"). This matters most for Vault
Transit: `transit.decrypt_data` returns `response['data']['plaintext']`, which is *itself* base64 of
whatever was sealed — so sealing `raw32` yields `base64(raw32)` = the correct `active_key()` value
directly, whereas sealing the already-base64 string yields `base64(base64(...))` and `_decode_key` then
sees 44 bytes ≠ 32 → `ValueError`. The `wrap-key` companion CLI ("To resolve" #3) mints the DEK and
wraps `raw32` so this is enforced at provisioning time.

**Build-time discipline (CLAUDE.md §5/§7, DEP-1):** these package names are confirmed real against live
PyPI / official docs as of 2026-06, but the **existence re-check, exact version pin, optional-extra add,
and `uv lock` / `uv export` re-lock** all happen at BUILD time — **no dependency lands from this ADR.**
Acceptance criterion (WP-BL3-04): a **faked** KMS/Vault provider returns a base64 key that `make_cipher`
accepts and decrypts existing `mfenc:v1` rows with **no rotation**.

```
startup, key_provider = aws_kms | azure_kv | gcp_kms | vault | pkcs11
─────────────────────────────────────────────────────────────────────────────
  at rest (disk/config):   wrapped_DEK  ──┐
                                          │  send over TLS
                                          ▼
                              ┌───────────────────────────────┐
                              │  HSM / KMS / Vault              │
                              │  ┌──────────────┐               │
                              │  │  KEK (root)  │ non-extractable│
                              │  └──────┬───────┘               │
                              │   unwrap│ inside the module      │
                              └─────────┼─────────────────────┘
                                        ▼  plaintext DEK (base64) over TLS
                       resolve_active_key()  →  base64 32-byte DEK
                                        ▼
                       make_cipher(dek, retired)  →  AesGcmCipher (mfenc:v1, UNCHANGED)
```

The KEK never reaches the host; the engine holds only the unwrapped DEK (see the residual below). A
provider **MUST NEVER log key material** — neither the wrapped DEK nor the plaintext DEK (consistent
with [PHI.md](../PHI.md) never-log-PHI and the opaque `CipherError` with no distinguishing oracle).

### 4. Fail-closed: an unresolvable / foreign / missing provider key raises at startup

A provider that cannot unwrap (KEK revoked/disabled, wrong wrapped-DEK, credential/network failure,
foreign key) **MUST raise loudly** out of `resolve_active_key` — exactly mirroring the existing
`DpapiError` / `DpapiUnavailable` fail-closed contract for a configured-but-unreadable
`encryption_key_file` ([store/base.py](../../messagefoundry/store/base.py) `resolve_active_key`).
`open_store` propagates it (no catch), so `serve` **fails to start** rather than silently degrading to
the `IdentityCipher` (plaintext) path. This **composes with**, and does not weaken, the **future**
**WP-BL3-05**: that WP would add a new `[instance].data_class = phi` flag — **not yet built**, and
distinct from today's `data_class`, which currently lives under `[ai]`
([config/settings.py](../../messagefoundry/config/settings.py) `AiSettings.data_class`) — that would
imply `[store].require_encryption = true`. The guard that **already exists today** keys off
`[store].require_encryption` directly (not off any `data_class` derivation): when it is set and no key is
configured, `serve` refuses to start with exit 2
([__main__.py](../../messagefoundry/__main__.py) — the "require_encryption is set but no key" branch). A
configured external provider counts as a configured key for that same guard; an external provider that
fails to resolve is a fail-closed startup error, never a no-key degrade.

### 5. Generalize the same seam for connector secrets (follow-on, not core)

The connector / `env()` secret path ([config/environments.py](../../messagefoundry/config/environments.py)
— the `MEFOR_VALUE_*` env-overrides-file) is a **separate** mechanism from the store key but shares
the same env-secret shape (secret in env, never the config file). A future deployment could resolve those
secrets from the **same** provider (e.g. Vault for a partner password), so the `KeyProvider`/secret-source
seam is designed to **generalize** to a `SecretProvider`. This is recorded as a **follow-on** (the
"SecretProvider" half of WP-BL3-04) — **not** part of the core store-key seam and **not** built here. The
store key continues to flow through its own `MEFOR_STORE_ENCRYPTION_KEY` chokepoint, distinct from
`MEFOR_VALUE_*`.

## ASVS 13.3.3 mapping — what flips Fail → Pass, and what does not

- **On-prem, loopback, `key_provider = auto` (env/DPAPI):** **stays a Fail (accepted residual).** The
  crypto is still in-process software and the DEK still lives in heap during use. This is the documented
  MANAGED deviation, not a Pass.
- **Off-prem instance that *configures* `aws_kms` / `azure_kv` / `gcp_kms` / `vault` / `pkcs11`:**
  **flips the key-material-protection dimension of 13.3.3 to Pass** for that instance — the root **KEK**
  is now managed and protected inside an isolated security module (vault/HSM/KMS), **non-extractable**,
  with centralized rotation, revocation, and per-call audit; the key bytes are no longer sat in an env
  var or a machine-bound file. This is the verdict-flip the off-prem/BAA trigger requires. **It is not an
  unqualified, whole-requirement Pass:** 13.3.3 as worded asks that *all* cryptographic operations run
  inside the module, and the **bulk AES-256-GCM operations on message bodies still run in-process**
  against a plaintext DEK in heap (see the residual in Consequences). That in-use, operations-in-process
  clause is the **separately-deferred 11.7.1 / WP-BL3-28** residual — not closed by this seam.
- The seam shipping **does not** retroactively flip on-prem instances; the scorecard line for 13.3.3 is
  per-deployment-posture, and an accepted Fail remains a Fail until a provider is actually configured.

## Consequences

**Positive**
- **Non-extractable root key.** The KEK lives inside an audited HSM / KMS / Vault and never reaches the
  host; only a **wrapped DEK** sits at rest. Loss/theft of the at-rest key file no longer leaks usable
  key material, and KEK sprawl is eliminated.
- **No plaintext key in the env block or on disk** for provider deployments — the operator stores a
  wrapped DEK + a KEK reference, not a base64 secret.
- **Centralized rotation / revocation / audit:** rotate or **disable** the KEK in one place and every
  instance loses access; each unwrap is logged per-call inside the provider — the audited, revocable,
  rotatable infrastructure 13.3.3 asks for.
- **Smallest possible surface:** one new setting, one provider protocol, dispatch at the **single**
  existing chokepoint. The cipher, keyring, `mfenc:v1` format, `rotate-key`, and every backend are
  **byte-identical** when `key_provider` is unset/`auto`. No core dependency added.
- **Fail-closed preserved:** an unresolvable provider refuses startup; it never degrades to the identity
  cipher; composes with WP-BL3-05's posture-gated `require_encryption`.

**Negative / risks**
- **Residual — plaintext DEK still in process memory.** Envelope encryption protects the **root** key,
  **not** in-use exposure. To run AES-256-GCM on bulk message bodies, the engine must hold the
  **plaintext DEK** in its own heap for the lifetime of crypto operations; the provider returns plaintext
  DEK bytes that then live in the engine's address space. An attacker who can read engine process memory
  (which already implies host compromise at or above the engine's privilege) can extract the live DEK
  **regardless of where the KEK lives**. So the threat this closes is **loss/theft of the at-rest wrapped
  DEK + KEK sprawl** (plus enabling rotation/revocation/audit) — **not** in-process key exposure, and
  **not** the "all operations inside the module" clause of 13.3.3 (which stays the deferred residual). The
  host-compromise threat is **unchanged**. *True never-expose-the-key* (per-operation HSM crypto where
  the DEK never leaves the boundary) is far slower and not what this bulk AES-256-GCM path does; it is the
  separately-deferred ASVS **11.7.1** / **WP-BL3-28** (below).
- **Plaintext DEK transits the network** from provider to engine, protected only by the provider call's
  TLS.
- **New runtime dependency on the provider's availability** at startup (and a cloud SDK, as an optional
  extra) for provider deployments — a Vault/KMS outage means the engine cannot start. This is the
  intended fail-closed trade.
- **Operator burden:** provisioning the KEK, wrapping the DEK once, and supplying provider credentials
  (themselves an env-secret / managed identity) become an ops runbook item.
- **On-prem residual is honest:** even after the seam ships, on-prem env+DPAPI **remains an accepted
  Fail** — MANAGED via documented compensating controls + this hard trigger, not REMEDIATED.

## Alternatives considered

1. **Hardcode a single cloud (e.g. AWS-KMS only).** Smallest code, but ties an open-source on-prem
   engine to one cloud and breaks the broker-free / no-required-SDK story. **Rejected** — a provider
   *protocol* with lazy optional extras costs little more and stays cloud-neutral (AWS / Azure / GCP /
   Vault / PKCS#11) and offline-by-default.
2. **DPAPI-only forever (accept 13.3.3 indefinitely).** Keeps the build trivial but leaves no path to
   Pass when an off-prem/BAA trigger fires, and DPAPI is Windows-only and not a security module *during
   use*. **Rejected** — the trigger is foreseeable; designing the seam now (off-by-default) costs nothing
   at runtime and unblocks the verdict-flip.
3. **Kubernetes Sealed Secrets / sealed-secret operators.** Solves *delivery* of an encrypted secret to a
   pod, but the unsealed key still lands as a plaintext env var / file in the container — it does **not**
   put key management inside an isolated module and does **not** satisfy 13.3.3. **Rejected** as a 13.3.3
   answer (it can still *feed* the `env` provider, orthogonally).
4. **Do nothing / accept-risk on-prem only (the [ADR 0018](0018-per-message-signatures-accepted-risk.md)
   shape).** This is in fact the **status quo for on-prem** and is preserved — but it provides **no**
   off-prem path. **Rejected as the whole answer:** the accepted-risk posture stays for on-prem, *and*
   the seam exists for the triggered case. (This ADR is the union of both, not a choice between them.)
5. **Per-operation HSM crypto (DEK never leaves the module).** Genuinely satisfies *never-expose* but is
   far slower than in-process AES-256-GCM on the bulk message path and would require re-architecting the
   cipher. **Rejected for this seam** — it is the separately-deferred 11.7.1 / WP-BL3-28 horizon, not the
   envelope-decrypt-at-startup design here.

## Relationship to other work packages

- **WP-BL3-04** ([BEYOND-ASVS-L3-REMEDIATION-PLAN.md](../security/BEYOND-ASVS-L3-REMEDIATION-PLAN.md)) —
  the implementing work package this ADR formalizes: refactor the `resolve_active_key` chokepoint to
  dispatch on `[store].key_provider`, env + DPAPI as built-ins, cloud/Vault/HSM as lazy optional extras.
  This ADR's enum extends the WP one-liner's `env|dpapi|aws_kms|azure_kv|vault` with `auto`, `gcp_kms`,
  and `pkcs11` (recorded in §2). Trigger **now** as DESIGN. *(Note: that plan's `store/base.py` line
  anchors predate the current tree; the line/symbol references in this ADR are the accurate point-in-time
  ones.)*
- **WP-L3-14** ([ASVS-L3-REMEDIATION-PLAN.md](../security/ASVS-L3-REMEDIATION-PLAN.md)) — the prior
  HSM/vault deferral. WP-BL3-04's design **discharges** it; this ADR supersedes that deferral one-liner
  for the 13.3.3 dimension (reusing the WP-11d DPAPI groundwork + the `crypto.py` `Cipher` seam).
- **WP-BL3-05** (posture ⇒ `require_encryption`) — a **future, not-yet-built** `[instance].data_class = phi`
  flag that would imply `[store].require_encryption = true` and fail `serve` closed (exit 2) unless a key
  is configured. (Today `data_class` lives under `[ai]`, and the exit-2 guard keys off
  `[store].require_encryption` directly — see §4.) The KeyProvider's fail-closed resolution **composes
  with** this: a PHI-posture instance must have a key, and an external provider that fails to resolve is a
  fail-closed startup error, never a no-key degrade.
- **WP-BL3-28** — the **future** `mfenc:v2` envelope: an **ML-KEM-768 (FIPS 203) / RFC 9794 hybrid**
  KEK-wrap of the per-record AES-256-GCM DEK, format
  `mfenc:v2:<kek_id>:<wrapped_dek>:<base64(nonce‖ct‖tag)>`, dispatched alongside `v1` by the version token
  in the [store/crypto.py](../../messagefoundry/store/crypto.py) `PREFIX`. The KeyProvider **KEK-seam this
  ADR designs is the migration lever WP-BL3-28 dovetails into** — a provider can later source the v2 KEK
  from the same HSM/KMS. This ADR keeps its design **strictly forward-compatible** with a later v2 version
  token but **does NOT pre-empt or implement v2**; `mfenc:v1` rows keep decrypting unchanged.
- **WP-BL3-06** (security-config-drift gate) — `[store].key_provider` is a **secure-by-default** field
  (default `auto` / unset = today's env-then-DPAPI behavior) that the drift gate can later pin.

## To resolve on acceptance

1. **Wrapped-DEK storage location** — where the wrapped DEK lives for each provider (a file path? a
   `[store]` field? the provider's own secret store?), and whether `retired_keys()` is sourced per-provider
   or stays on `[store].encryption_keys_retired`.
2. **Provider credentials** — managed-identity-first (Azure MSI / AWS instance role / GCP workload
   identity / Vault agent) vs an explicit env-secret, and how that composes with the `MEFOR_VALUE_*`
   secret path (the §5 follow-on).
3. **`gen-key` / `protect-key` companion** — an offline `wrap-key` CLI to mint a DEK and wrap the **raw 32
   bytes** (per §3's no-double-base64 rule) under a named KEK, parallel to today's `protect-key` (DPAPI).
   `rotate-key` stays unchanged (it operates on the resolved DEK, provider-agnostic).
4. **Per-instance posture interplay** — how `key_provider` is expressed across the
   [ADR 0017](0017-consumer-deployment-model.md) multi-instance config (one provider per instance vs shared).
5. **Build order** — the protocol + `auto`/`env`/`dpapi` built-ins first (byte-identical, fully testable
   with no SDK), then one external provider per branch/PR behind its optional extra, each with a faked
   provider in tests and a real-SDK leg gated like the SQL Server CI job.

---

*Proposed (design only). No code, setting, or dependency lands from this ADR; the base install continues
to pull **zero** cloud SDKs. On acceptance, build under **WP-BL3-04** off-by-default (byte-identical when
`key_provider` is unset/`auto`); verify each external provider against a faked unwrap before adding any
SDK, add it only as a lazy optional `pyproject` extra, and re-lock (DEP-1). The 13.3.3 verdict flips —
**for the key-material-protection dimension only** (the in-process bulk-crypto residual stays deferred to
11.7.1 / WP-BL3-28) — to Pass only for an off-prem instance that actually configures an external
provider; on-prem env+DPAPI remains an accepted (managed) Fail. Flip the relevant
[ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) / [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md)
rows and update [PHI.md](../PHI.md) §4/§11 + [CONFIGURATION.md](../CONFIGURATION.md) + [SECURITY.md](../SECURITY.md)
as each lands.*
