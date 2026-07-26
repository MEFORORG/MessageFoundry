# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``vault_transit`` store cipher — bulk at-rest crypto INSIDE Vault/OpenBao Transit (ADR 0138).

This is a :class:`~messagefoundry.store.crypto.Cipher`, **not** a KeyProvider. The ADR 0019 KeyProvider
seam only *sources* the DEK bytes — ``make_cipher`` then feeds them to an **in-process** ``AESGCM``, so the
plaintext DEK lands in engine heap for the bulk work (the ASVS 13.3.3 residual). ``TransitCipher`` replaces
the cipher object itself: every ``encrypt``/``decrypt`` is a Transit ``encrypt_data``/``decrypt_data`` call,
so **the data-encryption key never leaves the isolated module** and never enters this process. ASVS 5.0's
13.3.3 names "a vault" as a qualifying isolated security module; sibling 13.3.1's L3 *hardware* clause still
wants the vault itself HSM-sealed (deployment tier — see the ADR).

**At-rest form.** Values are stored as ``mfenc:v3:`` + Transit's own ``vault:v1:…`` ciphertext (a new
marker version — the frozen ``mfenc:v1`` / additive ``mfenc:v2`` writers are our-nonce AES-GCM and stay
byte-identical). ``is_encrypted`` / the stores' ``mfenc:%`` find-all scans recognise it; only ``TransitCipher``
decodes it.

**Cell-binding (ASVS 11.3.3) for free.** The store passes ``aad=cell_aad(table, column, *pk)`` at every
call; we forward it as Transit's ``associated_data``, so a v3 blob cut-and-pasted into another cell fails
the tag inside Transit → :class:`CipherError` (verified against OpenBao 2.6.0). Encrypt and decrypt of the
same cell see the same stable AAD, so binding is symmetric by construction.

**Audit chain (keyed IN Transit).** :meth:`audit_mac_key` returns ``None`` — there is no in-heap DEK to
HKDF a raw HMAC key from — but the chain is **not** keyless: :meth:`audit_mac_fn` hands the store a
Transit-backed MAC (:meth:`audit_hmac` → Transit ``generate_hmac``), so every audit row's MAC is computed
INSIDE the isolated module and the key never enters heap. This lifts the audit chain from keyless SHA-256
(tamper-evident) to forgery-**resistant** (ADR 0138 §To-resolve, closing the ASVS 16.4.2 residual for this
mode). The MAC key defaults to the data key and is overridable to a dedicated Transit key via
``MEFOR_STORE_TRANSIT_AUDIT_KEY`` for domain separation.

**Fail-closed (ADR 0138).** Missing config or an unreachable/unknown Transit key at construction raises
:class:`~messagefoundry.store.keyprovider.KeyProviderError` (``open_store`` propagates it → ``serve`` refuses
to start, never an in-process fallback). A per-operation Transit failure raises :class:`CipherError` — the
store's existing at-rest error discipline. **No plaintext/PHI is EVER placed in a message** (only the
exception TYPE): the base64 plaintext handed to Transit is the message body.

``hvac`` is the optional ``[vault]`` extra, lazy-imported via
:func:`~messagefoundry.store.keyprovider_vault._build_client` (shared with the KEK-unwrap provider so there
is ONE Vault client-construction path); the base install pulls zero Vault SDK.
"""

from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING, Any

from messagefoundry.store.crypto import _V3_PREFIX, MARKER_PREFIX, AuditMacFn, CipherError
from messagefoundry.store.keyprovider import KeyProviderError
from messagefoundry.store.keyprovider_vault import _EXTRA, _build_client

if TYPE_CHECKING:
    from messagefoundry.config.settings import StoreSettings

#: The `[store].cipher_provider` value that selects this cipher.
PROVIDER_NAME = "vault_transit"

# Connection reuses the shared Vault wiring (a deployment runs one Vault); the DATA key is distinct from
# keyprovider_vault's KEK (that unwraps a DEK; this one encrypts the data directly), so it has its own name.
_ENV_ADDR = "MEFOR_STORE_VAULT_ADDR"
_ENV_TOKEN = "MEFOR_STORE_VAULT_TOKEN"  # nosec B105 — env-var NAME, not a token value
#: The Transit key the store data is encrypted/decrypted under (the isolated-module data key).
_ENV_TRANSIT_KEY = "MEFOR_STORE_TRANSIT_KEY"
#: The Transit key the audit-chain HMAC is computed under (ADR 0138 §To-resolve follow-up). Optional —
#: unset ⇒ reuse the data key (``_ENV_TRANSIT_KEY``): Transit ``generate_hmac`` works on any key type
#: (verified against an ``aes256-gcm96`` key), so the audit chain is keyed-in-Transit out of the box in
#: ``vault_transit`` mode. Set it to a DEDICATED Transit key for domain separation from the data key.
_ENV_AUDIT_KEY = "MEFOR_STORE_TRANSIT_AUDIT_KEY"
#: Transit HMAC hash algorithm (matches the SHA-256 the in-process chain used). Byte-length differs from
#: SHA-256 hex, but the audit column is opaque TEXT — verify recomputes and string-compares, so any
#: deterministic MAC round-trips. NEVER change on an existing keyed-in-Transit store (it re-breaks the
#: suffix), same discipline as rotating the in-heap key.
_AUDIT_HASH_ALGO = "sha2-256"


class TransitCipher:
    """Bulk at-rest cipher whose crypto runs inside Vault/OpenBao Transit — the DEK never enters heap."""

    encrypts = True

    def __init__(self, client: Any, key_name: str, audit_key: str | None = None) -> None:
        self._client = client
        self._key = key_name
        # The Transit key the audit-chain HMAC runs under. Defaults to the data key (Transit HMAC works
        # on any key type) so the chain is keyed-in-Transit by default; a dedicated key domain-separates.
        self._audit_key = audit_key or key_name

    def _associated_data(self, aad: bytes | None) -> str | None:
        # Transit's associated_data is base64; None → omit it (symmetric with a None-aad encrypt).
        return base64.b64encode(aad).decode("ascii") if aad is not None else None

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        pt_b64 = base64.b64encode(plaintext.encode("utf-8")).decode("ascii")
        assoc = self._associated_data(aad)
        try:
            kwargs: dict[str, Any] = {"name": self._key, "plaintext": pt_b64}
            if assoc is not None:
                kwargs["associated_data"] = assoc
            response: Any = self._client.secrets.transit.encrypt_data(**kwargs)
            ciphertext = response["data"]["ciphertext"]  # "vault:v1:…" — no plaintext, no key
        except Exception as exc:
            # Type-only message: the plaintext going in is PHI; never surface it or the key material.
            raise CipherError(
                f"Transit encrypt failed (key={self._key!r}): {type(exc).__name__}"
            ) from exc
        if not isinstance(ciphertext, str) or not ciphertext:
            raise CipherError(f"Transit returned an empty ciphertext (key={self._key!r})")
        return f"{_V3_PREFIX}{ciphertext}"

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        if not stored.startswith(MARKER_PREFIX):
            return stored  # legacy plaintext (pre-encryption) or a purged/blank value
        if not stored.startswith(_V3_PREFIX):
            # An mfenc:v1/v2 value is in-process AES-GCM; Transit holds no key that can read it. Fail
            # closed (rotate the store into Transit before reading it in Transit mode) — never mis-decrypt.
            raise CipherError(
                "value was encrypted in-process (mfenc:v1/v2); the Transit cipher cannot read it — "
                "rotate the store to the Transit provider before serving in this mode"
            )
        ciphertext = stored[len(_V3_PREFIX) :]  # the full "vault:v1:…" blob (may contain ':')
        assoc = self._associated_data(aad)
        try:
            kwargs: dict[str, Any] = {"name": self._key, "ciphertext": ciphertext}
            if assoc is not None:
                kwargs["associated_data"] = assoc
            response: Any = self._client.secrets.transit.decrypt_data(**kwargs)
            plaintext_b64 = response["data"]["plaintext"]
        except Exception as exc:
            # Covers a failed AEAD tag (wrong cell AAD / corrupt blob) AND transport failure — both fail
            # closed. Type-only: a Transit error can echo ciphertext, and we never surface key material.
            raise CipherError(
                f"Transit decrypt failed (key={self._key!r}): {type(exc).__name__}"
            ) from exc
        try:
            return base64.b64decode(plaintext_b64).decode("utf-8")
        except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise CipherError(f"Transit returned malformed plaintext (key={self._key!r})") from exc

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(MARKER_PREFIX)

    def audit_mac_key(self) -> None:
        """No in-heap DEK to HKDF a raw HMAC key from — so there is NO in-process key. The chain is still
        keyed, but the MAC runs inside Transit via :meth:`audit_mac_fn` / :meth:`audit_hmac`, NOT here.
        Returning ``None`` keeps this the honest signal 'no in-heap key material'."""
        return None

    def audit_hmac(self, data: bytes) -> str:
        """Compute the audit-chain row MAC INSIDE Transit (``generate_hmac``) — no key ever enters heap.

        Returns Transit's own ``vault:v1:…`` HMAC string (deterministic for a given input+key+version, so
        the chain round-trips at :meth:`~messagefoundry.store.store.MessageStore.verify_audit_chain`; a
        different input yields a different MAC → tamper/forgery is detected). ADR 0138 §To-resolve: this
        moves the audit chain from keyless SHA-256 to forgery-**resistant** without an in-heap key,
        closing the ASVS 16.4.2 residual for ``vault_transit`` mode. Fail-closed: any Transit error raises
        :class:`CipherError` (type-only — the canonical row bytes are PHI-derived and never surfaced)."""
        inp = base64.b64encode(data).decode("ascii")
        try:
            response: Any = self._client.secrets.transit.generate_hmac(
                name=self._audit_key, hash_input=inp, algorithm=_AUDIT_HASH_ALGO
            )
            mac = response["data"]["hmac"]  # "vault:v1:…" — no key, no plaintext
        except Exception as exc:
            raise CipherError(
                f"Transit audit HMAC failed (key={self._audit_key!r}): {type(exc).__name__}"
            ) from exc
        if not isinstance(mac, str) or not mac:
            raise CipherError(f"Transit returned an empty audit HMAC (key={self._audit_key!r})")
        return mac

    def audit_mac_fn(self) -> AuditMacFn:
        """The audit-chain MAC provider: route each row's MAC through Transit (:meth:`audit_hmac`). The
        store uses this INSTEAD of an in-heap ``hmac.new(key, …)`` when present, so the audit chain is
        keyed even though :meth:`audit_mac_key` is ``None`` (the key stays inside the isolated module)."""
        return self.audit_hmac


def build_transit_cipher(settings: StoreSettings) -> TransitCipher:
    """Construct the Transit cipher from the environment, failing **closed** at startup.

    ``settings`` is accepted for signature parity with ``make_cipher``/``build_store_cipher`` (the Vault
    address/token/key are env-only secrets/provisioning outputs, like the KEK-unwrap provider). A missing
    key name, a missing extra, or an unreachable/unknown Transit key raises :class:`KeyProviderError` so
    ``open_store`` refuses to start rather than degrading to plaintext."""
    key_name = os.environ.get(_ENV_TRANSIT_KEY)
    if not key_name:
        raise KeyProviderError(
            f"[store].cipher_provider={PROVIDER_NAME!r} is selected but {_ENV_TRANSIT_KEY} is not set — "
            f"supply the Transit data-key name via the environment."
        )
    # Optional dedicated audit-HMAC key; unset ⇒ reuse the data key (Transit HMAC works on any key type).
    audit_key = os.environ.get(_ENV_AUDIT_KEY) or key_name
    addr = os.environ.get(_ENV_ADDR)
    token = os.environ.get(_ENV_TOKEN)
    try:
        client = _build_client(
            addr, token
        )  # lazy hvac import; fails closed naming the [vault] extra
        # Startup connectivity + key-existence check: read the key metadata (no crypto, no secrets). This
        # turns a mis-provisioned Vault into a refuse-to-start rather than a first-write dead-letter.
        client.secrets.transit.read_key(name=key_name)
        # Same fail-closed existence check for a DEDICATED audit key (skip the redundant read when it is
        # the data key we just verified) — a mis-set audit key must refuse to start, not dead-letter the
        # first audit-row append.
        if audit_key != key_name:
            client.secrets.transit.read_key(name=audit_key)
    except KeyProviderError:
        raise
    except Exception as exc:
        raise KeyProviderError(
            f"[store].cipher_provider={PROVIDER_NAME!r} could not reach a Vault Transit key "
            f"(data={key_name!r}, audit={audit_key!r}, extra {_EXTRA!r}): {type(exc).__name__}."
        ) from exc
    return TransitCipher(client, key_name, audit_key=audit_key)
