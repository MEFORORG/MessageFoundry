# ADR 0019 — Pluggable KeyProvider seam (HSM/KMS/Vault envelope decryption) for store-key material (ASVS 13.3.3)

- **Status:** **Accepted (2026-06-17); Amended 2026-06-18 — core seam BUILT; Amended 2026-07-10 — `vault`
  provider (BACKLOG #196) + secret-rotation reminder (§5.1, BACKLOG #195b) BUILT.** Designs the pluggable
  **KeyProvider** seam (work package **WP-BL3-04**) that lets the store's at-rest data-encryption key be
  sourced from an external HSM / cloud KMS / Vault via **envelope decryption**. **As of the 2026-06-18
  amendment the core seam is built** ([store/keyprovider.py](../../messagefoundry/store/keyprovider.py)):
  the `KeyProvider` protocol, the `auto`/`env`/`dpapi` built-ins (default `auto` is **byte-identical** to
  the prior behavior), the `[store].key_provider` setting, and the `resolve_active_key` routing — all
  off-by-default. The external HSM/KMS/Vault providers stay **lazy optional extras, deferred per-provider**:
  **no cloud-KMS/Vault dependency lands**, so the base install still pulls **zero** cloud SDKs. On the
  strength of the built isolation seam + an operator-activated external module, **ASVS 13.3.3 flips Fail →
  Pass-with-documented-residual** (mapping below — the same operator-activated shape as off-box logging
  16.4.3 and transport TLS / [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)). Mirrors the
  "design now, build then" shape of [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) and the
  accepted-risk shape of [ADR 0018](0018-per-message-signatures-accepted-risk.md).
- **Requirement:** OWASP ASVS 5.0 **13.3.3** (V13 Configuration, **Level 3**) — *"Verify that all
  cryptographic operations are performed using an isolated security module such as a vault or HSM to
  manage and protect key material from exposure outside of the security module."* Scored a hard **Fail**
  at L3 ([ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) §V13), classified
  **DEFERRED-BY-DESIGN** (not off-loopback-gated) in [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md).
- **Built (this amendment, WP-BL3-04 step 1):** the **core seam** —
  [store/keyprovider.py](../../messagefoundry/store/keyprovider.py) (the `KeyProvider` protocol, the
  `auto`/`env`/`dpapi` built-ins, and the lazy external-provider hooks), the `[store].key_provider` setting
  ([config/settings.py](../../messagefoundry/config/settings.py) `StoreSettings.key_provider`), and the
  `resolve_active_key` routing through it ([store/base.py](../../messagefoundry/store/base.py)) — all
  off-by-default and **byte-identical when `auto`**. The external providers
  (`aws_kms`/`azure_kv`/`gcp_kms`/`vault`/`pkcs11`) are **not** built — one per follow-on PR behind an
  optional extra, **zero** cloud SDK in the base install. The Phase-1 at-rest groundwork this *builds on* is
  already shipped and must **not** be redesigned: the `Cipher` protocol + AES-256-GCM keyring and the
  `mfenc:v1:<key_id>` stored format
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

**Why 13.3.3 was a Fail (pre-seam).** Before this seam, even with DPAPI the key material **was exposed
outside any security module**: DPAPI protects the key only **at rest on disk** (machine-bound), not
**during use** — the crypto is *not* performed inside DPAPI. There was no vault / HSM / isolated-module
*integration point* (a pre-seam grep of the tree for HSM / PKCS#11 / vault / enclave / TPM returned zero
matches; this amendment adds that integration point — see *Built* above). The requirement **genuinely
applies** (the app performs cryptographic operations on PHI). At the time of this amendment 13.3.3 is one
of the **3 remaining combined L3 Fails** — current scorecard **189 / 20 / 3 / 133**
([ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md)); the `178 / 20 / 6 / 141` this ADR originally
cited was a stale intermediate tally (it predated WP-L3-13 admin defense closing **8.4.2** and the
sec-offbox-log forwarder closing **16.4.3**). The 3 are all **L3-only**: **4.1.5, 12.1.4, 13.3.3** (8.4.2
is no longer a Fail). This amendment's built seam + an operator-activated external module flip 13.3.3 (see
*ASVS 13.3.3 mapping* below).

**Governance — the original deferred-by-design posture (superseded for the verdict by this amendment).**
The design-time posture, per [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md)
and [PHI.md](../PHI.md) §11, classified 13.3.3 **DEFERRED-BY-DESIGN** — to be closed via an explicit
accepted-risk decision, *not* purely off-loopback-conditional — with the **build trigger** that requires an
external provider (verbatim): *"Off-prem / PHI-critical / off-loopback deployment, or a BAA / customer
mandating an external HSM/vault (ADR 0002)."* Same governance shape as
[ADR 0002](0002-phase2-transport-security-and-strong-auth.md)'s off-loopback trigger. **This amendment
supersedes that deferral for the verdict:** the owner built the seam early (default-off), so 13.3.3 is now
**Pass-with-documented-residual**, not a deferred Fail. What survives as the **MANAGED residual** is the
on-prem `auto` posture itself — on an **on-prem localhost** instance left at env / DPAPI (machine-bound key
file, owner-only ACLs, AES-256-GCM at rest, loopback bind), the crypto is still in-process software until an
external provider is activated.

The **seam** that lets a triggered deployment satisfy 13.3.3 is designed and (2026-06-18) **built**,
off-by-default — building it does not change loopback behavior. This amendment ships that seam and keeps
the residual honest: 13.3.3 flips to **Pass-with-documented-residual** on the built seam + an
operator-activated external module, with the operator-activation step and the in-use DEK-in-heap exposure
(11.7.1) as the standing residuals (see *ASVS 13.3.3 mapping*). The owner chose to build the seam **now,
default-off** — the same "build early, byte-identical on loopback" move as 6.3.3 MFA and 8.4.2 admin
defense — rather than wait for the off-prem trigger to fire.

**Design philosophy** (same as [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)): reuse
the patterns already in the tree — the **single** `resolve_active_key` chokepoint, the unchanged
`Cipher`/keyring and `mfenc:v1` format, the env-overrides-file secret shape, the lazy-imported optional
backends. Add the smallest surface that closes the gap; keep the on-prem, broker-free, single-binary
story intact.

## Decision (accepted; core seam built 2026-06-18)

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

### 5.1 Secret-rotation reminder (BUILT — BACKLOG #195b, amended 2026-07-10)

A KeyProvider (or any of the built-in env/DPAPI sources) tells the engine **how** to source a secret,
but nothing tells an operator **when** a long-lived secret is *overdue for rotation*. A TLS cert carries
its own `notAfter`, so `[cert_monitor]` ([cert_expiry.py](../../messagefoundry/pipeline/cert_expiry.py))
can alarm ahead of expiry; the store DEK and connector credentials have **no intrinsic expiry**, so a
stale key can sit unrotated indefinitely with no in-engine signal. This amendment adds the **secret-side
twin** of the cert monitor:

- **`[secret_rotation]`** ([config/settings.py](../../messagefoundry/config/settings.py)
  `SecretRotationSettings`) — the operator records, per tracked secret, a **last-rotated date** + a
  **max age** (plus a `warn_days` look-ahead and a scan `check_interval_seconds`), mirroring
  `[cert_monitor]`. `warn_days = 0` disables it.
- **`SecretRotationRunner`** ([pipeline/secret_rotation.py](../../messagefoundry/pipeline/secret_rotation.py))
  — a small engine-owned background task modelled **verbatim** on `CertExpiryRunner` (injected clock, a
  recomputed-each-pass secret **source callable**, a pure `run_once`, an `enabled` gate, `start`/`stop`).
  Each pass it compares each tracked secret's age to its max age and emits the new
  **`secret_rotation_due`** AlertSink event when the secret is overdue or within `warn_days` of due.
- **PHI-free / never the value.** The reminder reads **only** the operator-configured rotation *dates* +
  a static label + the secret's config/env **identifier** (e.g. `MEFOR_STORE_ENCRYPTION_KEY`). It never
  reads, loads, decrypts, or logs any secret value — a reminder needs the *when*, not the *what*. The
  event carries only label + identifier + dates (no PHI), keyed per-secret for the realert throttle.
- **Deny-by-default scope.** Today the runner tracks exactly one secret — the **store DEK** — and only
  once the operator sets `store_key_last_rotated` (an unset date → not tracked → the runner is a no-op).

This is a **reminder**, not enforcement: it never rotates a key or blocks startup. Actual rotation stays
the operator running `rotate-key` (store DEK) / re-provisioning a credential; §4's fail-closed resolution
is unchanged.

**Still design-only (the connector `SecretProvider`).** Generalizing the KeyProvider seam to resolve
**connector** secrets (AD/SQL/SMTP passwords off the `MEFOR_VALUE_*` path) from the *same* external
provider — the "SecretProvider half" named above — remains a **follow-on, not built**. #195b builds the
rotation *reminder* only; it does **not** add a `SecretProvider`, does not touch the `MEFOR_VALUE_*`
chokepoint, and leaves the two secret paths distinct. When the connector `SecretProvider` lands, the
reminder's secret source generalizes to enumerate those secrets too (the `MonitoredSecret` source callable
is already the seam for it).

## ASVS 13.3.3 mapping — Pass-with-documented-residual (amended 2026-06-18)

With the **isolation seam built** and an **operator-activated external module**, 13.3.3 flips **Fail →
Pass-with-documented-residual** — the same operator-activated shape as the project's other such Passes:
off-box logging (16.4.3) passed on a built-but-opt-in forwarder the operator points at a SIEM, and
transport TLS ([ADR 0002](0002-phase2-transport-security-and-strong-auth.md)) passes on operator-activated
TLS. 13.3.3 names "an isolated security module such as a vault or HSM to manage and protect key material";
the built `KeyProvider` seam **is** that integration point, and the store now sources its DEK through it.

- **Pass basis — built seam + delegated activation.** The seam is in-tree and the store's key-sourcing
  runs through it. An operator **activates** an external HSM/KMS/Vault provider
  (`aws_kms`/`azure_kv`/`gcp_kms`/`vault`/`pkcs11`) so the root **KEK** is managed **non-extractable**
  inside an isolated module — centralized rotation, revocation, per-call audit; the key bytes no longer
  sit in an env var or a machine-bound file. Activation is operator-driven and off-by-default, exactly like
  the TLS and 16.4.3 controls.
- **Residual 1 — deployment-delegated (operator activation).** Full isolated-module protection requires
  the operator to configure an external provider. On a pure on-prem loopback instance left at
  `key_provider = auto` (env/DPAPI), the crypto is still in-process software — the **MANAGED residual** of
  an otherwise-Pass control whose seam is built and activatable (byte-identical to before on loopback).
- **Residual 2 — in-use DEK in heap (ASVS 11.7.1 / WP-BL3-28).** Even with an external provider, the bulk
  AES-256-GCM operations on message bodies run **in-process against a plaintext DEK in heap** (the provider
  returns the unwrapped DEK; envelope decryption protects the **root** KEK, not in-use exposure). The
  "*all* cryptographic operations inside the module" clause stays the **separately-deferred** 11.7.1 /
  WP-BL3-28 residual — **not** closed by this seam. An attacker who can already read engine process memory
  (host compromise at/above the engine's privilege) can extract the live DEK regardless of where the KEK
  lives; that host-compromise threat is unchanged.

This is the honest flip: a **Pass with two documented residuals**, not an unqualified whole-requirement
Pass. The cross-document scorecard recompute (combined **189 / 20 / 3 / 133 → 192 / 20 / 0 / 133** once
4.1.5 / 12.1.4 / 13.3.3 all flip; V13 **+1 Pass / −1 Fail**) is applied by the **Coordinator's
single-writer score-doc sweep** ([ASVS-OPTION-A-MULTISESSION-PLAN.md](../releases/ASVS-OPTION-A-MULTISESSION-PLAN.md));
this ADR records 13.3.3's verdict-flip intent only — it edits **no** score doc.

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
- **On-prem residual is honest:** the on-prem env+DPAPI posture is the **MANAGED residual** of the now
  **Pass-with-documented-residual** control — managed via documented compensating controls + the
  activation trigger, **not** the full isolated-module remediation (which requires activating an external
  provider, and even then leaves the in-use DEK-in-heap residual of 11.7.1 / WP-BL3-28).

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
- **WP-BL3-28** — the **future** post-quantum envelope: an **ML-KEM-768 (FIPS 203) / RFC 9794 hybrid**
  KEK-wrap of the per-record AES-256-GCM DEK. The KeyProvider **KEK-seam this ADR designs is the migration
  lever WP-BL3-28 dovetails into** — a provider can later source the wrapping KEK from the same HSM/KMS.
  **Reconciled with M9 (see "M9 crypto-agility marker" below):** the `mfenc:v2` version token is now
  **owned by the M9 agility format** `mfenc:v2:<alg>:<key_id>:<b64>`, so WP-BL3-28 lands as a **new
  registered `alg` id** under that v2 dispatch (the alg segment carries the PQ-hybrid suite), **not** as a
  competing `mfenc:v2:<kek_id>:<wrapped_dek>:…` layout. This keeps a single, additive v2 grammar and a
  single version dispatcher; `mfenc:v1` rows keep decrypting unchanged.
- **M9 crypto-agility marker (BUILT 2026-06-24, additive — CRYPTO-1):** the cipher
  ([store/crypto.py](../../messagefoundry/store/crypto.py)) is now **version/alg-dispatching**. It decodes
  both `mfenc:v1:<key_id>:<b64>` and the additive, self-describing `mfenc:v2:<alg>:<key_id>:<b64>` (`alg`
  names the AEAD suite), and **fails closed** (`CipherError`) on an unknown version or unknown `alg` —
  never a silent pass-through or mis-decrypt. **AES-256-GCM (`a256gcm`) is the only registered algorithm**
  and the **v1 writer is frozen byte-identical** (a frozen-fixture test pins it); v2 writing is **wired +
  tested but off by default** (`make_cipher(..., write_v2=True)`), so **no at-rest format change ships** —
  this is agility *infrastructure*, honoring CRYPTO-1. The store's find-all/migration scans anchor on the
  version-agnostic `mfenc:` prefix (a v2 row is recognised as already-encrypted); the rotation scan anchors
  on the cipher's active-format prefix through the key fingerprint (a v2-active rotation matches v2 rows and
  terminates). This is the "strictly forward-compatible v2 version token" this ADR reserved, now realized.
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
   with no SDK) **— ✅ built 2026-06-18 ([store/keyprovider.py](../../messagefoundry/store/keyprovider.py),
   [tests/test_keyprovider.py](../../tests/test_keyprovider.py))** — then one external provider per
   branch/PR behind its optional extra, each with a faked provider in tests and a real-SDK leg gated like
   the SQL Server CI job. (Items 1–4 above resolve as each external provider lands; the core seam needs
   none of them.)

---

*Accepted (2026-06-17); amended 2026-06-18. The **core seam is built** under **WP-BL3-04** (the
`KeyProvider` protocol + `auto`/`env`/`dpapi` built-ins + `[store].key_provider` + the `resolve_active_key`
routing), off-by-default and **byte-identical when `key_provider` is unset/`auto`**. **No cloud SDK lands**
— the base install still pulls **zero** cloud SDKs; the external HSM/KMS/Vault providers ship per-provider
in follow-on PRs (each verified against a faked unwrap before any SDK is added, then added only as a lazy
optional `pyproject` extra, and re-locked — DEP-1). ASVS 13.3.3 flips **Fail → Pass-with-documented-residual**
on the built isolation seam + an operator-activated external module (residuals: the operator-activation step,
and the in-process bulk-crypto DEK-in-heap deferred to 11.7.1 / WP-BL3-28). The cross-document scorecard flip
(to **192 / 20 / 0 / 133** once 4.1.5 / 12.1.4 / 13.3.3 all flip) and the
[ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) / [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md)
/ [PHI.md](../PHI.md) §4/§11 / [CONFIGURATION.md](../CONFIGURATION.md) / [SECURITY.md](../SECURITY.md) row
updates are the **Coordinator's** single-writer task — this ADR edits no score doc.*
