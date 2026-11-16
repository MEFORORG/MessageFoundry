# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the `vault` KeyProvider (store/keyprovider_vault.py, ADR 0019 §3, BACKLOG #196).

Covers the WP-BL3-04 acceptance criterion for the Vault provider: a faked Transit backend returns a
base64 key that flows straight through `make_cipher` and decrypts an `mfenc:v1` row with NO rotation;
the `resolve_key_provider` dispatch picks the shipped module up by name; and every fail-closed path
(missing hvac extra, missing env config, a Transit/transport failure) raises `KeyProviderError` — never
a silent degrade to the identity cipher, and never with key material in the message.
"""

from __future__ import annotations

import base64
import sys
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import keyprovider_vault
from messagefoundry.store.crypto import PREFIX, make_cipher
from messagefoundry.store.keyprovider import KeyProviderError, resolve_key_provider
from tests._vault_hop_env import STORE, supply_vault_hop


@pytest.fixture(autouse=True)
def _store_vault_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    """The key provider refuses an unset address or token before any client is built (BACKLOG
    #2851), so every test here names both."""
    supply_vault_hop(monkeypatch, STORE)


ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

# A fixed 32-byte base64 DEK — the shape Vault Transit returns as response['data']['plaintext'] when the
# sealed value is the raw 32 DEK bytes (ADR 0019 §3, no double-base64).
KEY_A = base64.b64encode(b"\x00" * 32).decode("ascii")

_TRANSIT_KEY = "mefor-store-kek"
_WRAPPED_DEK = "vault:v1:ZmFrZS13cmFwcGVkLWRlaw=="


class _FakeTransit:
    """Stands in for hvac's `client.secrets.transit`; records the unwrap call and returns a base64 DEK.

    `read_key` exists because BACKLOG #1166 made the KEK's TYPE a checked precondition of the unwrap;
    `key_type` picks what it reports so a test can supply an unsuitable one."""

    def __init__(self, plaintext: str, key_type: str = "aes256-gcm96") -> None:
        self._plaintext = plaintext
        self._key_type = key_type
        self.calls: list[tuple[str, str]] = []
        self.read_calls: list[str] = []

    def read_key(self, *, name: str) -> dict[str, Any]:
        self.read_calls.append(name)
        return {"data": {"name": name, "type": self._key_type}}

    def decrypt_data(self, *, name: str, ciphertext: str) -> dict[str, Any]:
        self.calls.append((name, ciphertext))
        return {"data": {"plaintext": self._plaintext}}


class _FakeSecrets:
    def __init__(self, transit: _FakeTransit) -> None:
        self.transit = transit


class _FakeClient:
    def __init__(self, transit: _FakeTransit) -> None:
        self.secrets = _FakeSecrets(transit)


def _configure_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _TRANSIT_KEY)
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", _WRAPPED_DEK)


# --- happy path: a faked Transit backend's key flows through make_cipher -----


def test_vault_active_key_unwraps_and_decrypts_without_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)
    transit = _FakeTransit(KEY_A)
    # Substitute the client factory so no live Vault (or hvac import) is needed.
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(transit)
    )

    provider = keyprovider_vault.build_provider(StoreSettings())
    active = provider.active_key()
    assert active == KEY_A
    # The wrapped DEK + KEK name were passed straight through to Transit.
    assert transit.calls == [(_TRANSIT_KEY, _WRAPPED_DEK)]

    # A row written under KEY_A decrypts with the provider's key — NO re-encryption, mfenc:v1 unchanged.
    # DELIBERATELY v1 (do not sweep to MARKER_PREFIX): "an existing v1 row survives a KeyProvider swap
    # byte-for-byte" is the claim, so the fixture being v1 is the premise of the test.
    token = make_cipher(KEY_A).encrypt(ADT)
    assert token.startswith(PREFIX)
    cipher = make_cipher(active, provider.retired_keys())
    assert cipher.decrypt(token) == ADT


def test_resolve_key_provider_wires_the_vault_module(monkeypatch: pytest.MonkeyPatch) -> None:
    # The base dispatch (keyprovider._load_external_provider) imports store.keyprovider_vault by name and
    # calls build_provider — no edit to keyprovider.py.
    _configure_env(monkeypatch)
    transit = _FakeTransit(KEY_A)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(transit)
    )
    provider = resolve_key_provider(StoreSettings(key_provider="vault"))
    assert isinstance(provider, keyprovider_vault.VaultKeyProvider)
    assert provider.active_key() == KEY_A


def test_vault_surfaces_built_in_retired_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    # Construction checks the KEK name, so the runner's own environment must not supply one.
    monkeypatch.delenv("MEFOR_STORE_VAULT_TRANSIT_KEY", raising=False)
    key_b = base64.b64encode(b"\x01" * 32).decode("ascii")
    provider = keyprovider_vault.build_provider(
        StoreSettings(encryption_keys_retired=f" {KEY_A} , {key_b} ,")
    )
    # Per-element (never comma-joined) so each feeds _decode_key's 32-byte check straight through.
    assert list(provider.retired_keys()) == [KEY_A, key_b]


# --- fail-closed paths -------------------------------------------------------


def test_missing_hvac_fails_closed_naming_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch)
    # Make a real `import hvac` fail (None in sys.modules raises ImportError) — the fail-closed path when
    # the [vault] extra is not installed.
    monkeypatch.setitem(sys.modules, "hvac", None)
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError, match="vault"):
        provider.active_key()


def test_missing_config_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Neither env var set → misconfiguration, not a no-key degrade. The message names the missing var.
    monkeypatch.delenv("MEFOR_STORE_VAULT_TRANSIT_KEY", raising=False)
    monkeypatch.delenv("MEFOR_STORE_VAULT_WRAPPED_DEK", raising=False)
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError, match="MEFOR_STORE_VAULT_TRANSIT_KEY"):
        provider.active_key()


def test_transit_failure_fails_closed_without_leaking_ciphertext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure_env(monkeypatch)

    class _BoomTransit:
        def read_key(self, *, name: str) -> dict[str, Any]:
            return {"data": {"name": name, "type": "aes256-gcm96"}}

        def decrypt_data(self, *, name: str, ciphertext: str) -> dict[str, Any]:
            # A Transit error can echo the ciphertext — the provider must not surface it.
            raise RuntimeError(f"vault denied for ciphertext {ciphertext}")

    monkeypatch.setattr(
        keyprovider_vault,
        "_build_client",
        lambda addr, token, **_: _FakeClient(_BoomTransit()),  # type: ignore[arg-type]
    )
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError) as excinfo:
        provider.active_key()
    # The message names the failure TYPE only — never the wrapped DEK / ciphertext (no key-material oracle).
    assert _WRAPPED_DEK not in str(excinfo.value)
    assert "RuntimeError" in str(excinfo.value)


def test_empty_plaintext_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _configure_env(monkeypatch)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(_FakeTransit(""))
    )
    provider = keyprovider_vault.build_provider(StoreSettings())
    with pytest.raises(KeyProviderError, match="empty"):
        provider.active_key()


# --- the KEK's key TYPE is checked before the unwrap (BACKLOG #1166, ASVS 11.2.3) ------------------
#
# Owner ruling 2026-08-22; the pre-fix measurement is on this module's own section header. The
# positive control that this path was otherwise live is
# `test_transit_failure_fails_closed_without_leaking_ciphertext` above, which refused in the same run.


def _provider_on(
    monkeypatch: pytest.MonkeyPatch, transit: _FakeTransit
) -> keyprovider_vault.VaultKeyProvider:
    """Wire ``transit`` in as the Vault backend and hand back a provider built against it."""
    _configure_env(monkeypatch)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(transit)
    )
    return keyprovider_vault.build_provider(StoreSettings())


@pytest.mark.parametrize(
    "key_type",
    [
        "ecdsa-p256",  # signing only — cannot decrypt anything
        "ed25519",  # signing only
        "aes128-cmac",  # MAC only
        "rsa-2048",  # can decrypt, but ~112 bits: the exact shortfall 11.2.3 names
    ],
)
def test_kek_of_an_unusable_or_sub_128_bit_type_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, key_type: str
) -> None:
    transit = _FakeTransit(KEY_A, key_type=key_type)
    with pytest.raises(KeyProviderError) as excinfo:
        _provider_on(monkeypatch, transit).active_key()
    assert key_type in str(excinfo.value)
    assert "MEFOR_STORE_VAULT_TRANSIT_KEY" in str(excinfo.value)  # names the knob to change
    # Refused BEFORE the unwrap, not after: no decrypt was attempted under the unsuitable key.
    assert transit.calls == []


@pytest.mark.parametrize("key_type", ["aes256-gcm96", "rsa-4096"])
def test_kek_of_a_supported_type_still_unwraps(
    monkeypatch: pytest.MonkeyPatch, key_type: str
) -> None:
    transit = _FakeTransit(KEY_A, key_type=key_type)
    assert _provider_on(monkeypatch, transit).active_key() == KEY_A
    assert transit.read_calls == [_TRANSIT_KEY]  # the one added round trip, on the startup path


def test_an_aes128_kek_is_refused_with_the_steps_that_fix_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``aes128-gcm96`` was a supported KEK type until owner ruling R4 of 2026-09-26 (BACKLOG #2043).

    The refusal names the key, its type, the type to create and the knob, and warns that a Vault
    rotate keeps the type. The CONTROL is the ``aes256-gcm96`` case in
    ``test_kek_of_a_supported_type_still_unwraps`` above: same fake, same wiring, and it unwraps.
    """
    withdrawn = "aes128-gcm96"
    transit = _FakeTransit(KEY_A, key_type=withdrawn)
    with pytest.raises(KeyProviderError) as excinfo:
        _provider_on(monkeypatch, transit).active_key()
    message = str(excinfo.value)
    assert repr(_TRANSIT_KEY) in message  # the key, by name
    assert "'aes128-gcm96'" in message  # its type
    assert "type=aes256-gcm96" in message  # a type to create instead
    assert "MEFOR_STORE_VAULT_TRANSIT_KEY" in message  # the knob to change
    assert "rotating the key keeps its type" in message  # the fix that does not work
    # The wrapped DEK is sealed under the old key, so a new key alone would fail the next unwrap.
    assert "re-wrap the DEK" in message and "MEFOR_STORE_VAULT_WRAPPED_DEK" in message
    # A withdrawn type's refusal carries no floor clause, so the list ends at the sentence's end.
    supported = message.split("Supported types: ", 1)[1].split(". ", 1)[0]
    assert "aes256-gcm96" in supported.split(", ") and "aes128-gcm96" not in supported.split(", ")
    assert KEY_A not in message  # and no key material rides the refusal
    # Refused BEFORE the unwrap: nothing was decrypted under the withdrawn key.
    assert transit.calls == []


def test_kek_type_that_cannot_be_read_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pins the fail-closed rule stated on ``require_transit_key_type``, through this path's wiring:
    an unreadable response shape must refuse rather than shrug."""

    class _ShapelessTransit(_FakeTransit):
        def read_key(self, *, name: str) -> dict[str, Any]:
            return {"data": {"name": name}}  # no 'type' at all

    with pytest.raises(KeyProviderError, match="did not report a key type"):
        _provider_on(monkeypatch, _ShapelessTransit(KEY_A)).active_key()


def test_the_three_uses_have_distinct_allowed_type_sets() -> None:
    """The sets are deliberately different, and a future edit that collapses them should have to
    confront why. Their reasons live on the constants; this pins the SHAPE, so a collapse cannot
    happen silently."""
    data = keyprovider_vault.TRANSIT_KEY_TYPES_DATA
    audit = keyprovider_vault.TRANSIT_KEY_TYPES_AUDIT
    kek = keyprovider_vault.TRANSIT_KEY_TYPES_KEK
    assert data < audit and data < kek  # both are strict supersets of the AEAD core
    assert audit - data == {"hmac"}
    assert kek - data == {"rsa-3072", "rsa-4096"}
    assert "rsa-2048" not in (data | audit | kek)
    assert not any("ecdsa" in t or t == "ed25519" for t in data | audit | kek)
    # Owner ruling R4 of 2026-09-26 (BACKLOG #2043): the audit and KEK sets inherit the data set,
    # so dropping AES-128 there has to drop it from all three.
    assert not [t for t in data | audit | kek if t.startswith("aes128")]


# --- the KEK name is checked before it reaches a Vault path (BACKLOG #6010) -------------------------
#
# hvac quotes the name into the request path with "/" left unescaped, and requests drops ".."
# segments, so before this check "a/../../../sys/x" reached /v1/sys/x with the store token, and the
# capability probe asked about a path no request takes.

_MALFORMED_KEK_NAMES = [
    "a/../../../sys/policy/x",  # walks out of the Transit mount, to /v1/sys/policy/x
    "a/../../keys/other",  # stays in the mount, but names another key's path
    "..",
    "kek/sub",
    ".kek",  # a dot at either end
    "kek-",  # a hyphen at either end
    " kek",
    "kek\n",
    "kék",  # not ASCII
]


@pytest.mark.parametrize("name", _MALFORMED_KEK_NAMES)
def test_a_malformed_kek_name_refuses_at_construction_and_in_the_probe(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", name)
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", _WRAPPED_DEK)
    transit = _FakeTransit(KEY_A)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(transit)
    )
    with pytest.raises(KeyProviderError, match="MEFOR_STORE_VAULT_TRANSIT_KEY") as excinfo:
        keyprovider_vault.build_provider(StoreSettings())
    assert name not in str(excinfo.value)  # fixed text: the name is not echoed
    with pytest.raises(KeyProviderError, match="not a Vault transit key name"):
        keyprovider_vault.kek_required_capabilities()


def test_a_kek_name_changed_after_construction_is_checked_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``active_key`` reads the name again through the same check, so a name that changed between
    construction and the unwrap still never reaches a request path."""
    transit = _FakeTransit(KEY_A)
    provider = _provider_on(monkeypatch, transit)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "a/../../../sys/x")
    with pytest.raises(KeyProviderError, match="not a Vault transit key name"):
        provider.active_key()
    assert transit.read_calls == [] and transit.calls == []


@pytest.mark.parametrize("name", ["mefor-store-kek", "kek.v2", "K_1", "a", "a.b-c_d"])
def test_a_well_formed_kek_name_unwraps_and_names_the_probe_paths(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    transit = _FakeTransit(KEY_A)
    _configure_env(monkeypatch)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", name)
    monkeypatch.setattr(
        keyprovider_vault, "_build_client", lambda addr, token, **_: _FakeClient(transit)
    )
    assert keyprovider_vault.build_provider(StoreSettings()).active_key() == KEY_A
    assert transit.read_calls == [name] and transit.calls == [(name, _WRAPPED_DEK)]
    assert set(keyprovider_vault.kek_required_capabilities()) == {
        f"transit/keys/{name}",
        f"transit/decrypt/{name}",
    }


# --- the unwrapped DEK is base64 of exactly 32 bytes (BACKLOG #6710) --------------------------------


_NOT_A_32_BYTE_KEY = [
    base64.b64encode(b"\x02" * 16).decode("ascii"),  # a 16-byte DEK
    base64.b64encode(b"\x02" * 33).decode("ascii"),  # one byte too many
    base64.b64encode(KEY_A.encode("ascii")).decode("ascii"),  # wrapped as its own base64
    base64.urlsafe_b64encode(b"\xfb" * 32).decode("ascii"),  # URL-safe alphabet
    KEY_A.rstrip("="),  # unpadded
    KEY_A + "\n",
    " " + KEY_A,
    "not base64 at all",
]


@pytest.mark.parametrize("plaintext", _NOT_A_32_BYTE_KEY)
def test_a_plaintext_that_is_not_base64_of_32_bytes_refuses(
    monkeypatch: pytest.MonkeyPatch, plaintext: str
) -> None:
    provider = _provider_on(monkeypatch, _FakeTransit(plaintext))
    with pytest.raises(KeyProviderError, match="not base64 of 32 bytes") as excinfo:
        provider.active_key()
    assert plaintext.strip() not in str(excinfo.value)  # no key material in the refusal
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None


def test_a_misshapen_dek_refuses_at_the_key_seam(monkeypatch: pytest.MonkeyPatch) -> None:
    """Before this check ``resolve_active_key`` returned a misshapen DEK unjudged, and only a later
    decode refused it. Now the seam refuses it, with its fixed text for a key source that failed,
    which names the setting to check and no key material."""
    from messagefoundry.store.base import resolve_active_key

    plaintext = _NOT_A_32_BYTE_KEY[0]
    _provider_on(monkeypatch, _FakeTransit(plaintext))
    with pytest.raises(KeyProviderError, match=r"check \[store\]\.key_provider") as excinfo:
        resolve_active_key(StoreSettings(key_provider="vault"))
    assert plaintext not in str(excinfo.value)


def test_the_32_byte_shape_matches_what_the_store_cipher_decodes() -> None:
    """The text pattern stands in for ``crypto._decode_key``, so pin the two together both ways:
    keys whose last character carries non-zero spare bits, which both accept, and every refused
    shape above, which both refuse."""
    from messagefoundry.store.crypto import _decode_key

    for raw in (b"\x00" * 32, b"\xff" * 32, bytes(range(32))):
        key = base64.b64encode(raw).decode("ascii")
        loose = key[:42] + "B="  # non-canonical spare bits: b64decode still yields 32 bytes
        for text in (key, loose):
            assert len(_decode_key(text, "k")) == 32
            assert keyprovider_vault._B64_32_BYTES.fullmatch(text) is not None
    for text in _NOT_A_32_BYTE_KEY:
        with pytest.raises(ValueError):
            _decode_key(text, "k")
        assert keyprovider_vault._B64_32_BYTES.fullmatch(text) is None


# --- a withdrawn key type is not refused as a shortfall against the floor (BACKLOG #6010 item 1) ---


def test_the_withdrawn_type_refusal_does_not_claim_a_sub_128_bit_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``aes128-gcm96`` meets the 128-bit floor; it is refused by ruling. CONTROL: ``rsa-2048``,
    which is below the floor, still gets the floor's clause."""
    withdrawn, below_floor = "aes128-gcm96", "rsa-2048"
    with pytest.raises(KeyProviderError) as excinfo:
        _provider_on(monkeypatch, _FakeTransit(KEY_A, key_type=withdrawn)).active_key()
    message = str(excinfo.value)
    assert "at least 128 bits of security" not in message
    assert "meets the 128-bit floor of ASVS 11.2.3" in message
    with pytest.raises(KeyProviderError) as control:
        _provider_on(monkeypatch, _FakeTransit(KEY_A, key_type=below_floor)).active_key()
    assert "at least 128 bits of security" in str(control.value)
    assert "meets the 128-bit floor" not in str(control.value)
