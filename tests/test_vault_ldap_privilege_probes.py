# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #305 (ASVS 13.2.2): the Vault and LDAP probes behind ``check-privileges``.

Every Vault answer and every directory answer here is MOCKED, and every token, accessor and password
is a synthetic string that could not authenticate anywhere. The tests hand the probes the shapes a
real Vault and a real AD return -- a clean token, an over-granted one, a root token, a 403 on
lookup-self, an unreachable server, and a bind account in or out of an administrative group -- and
assert what the read-out says. No test opens a socket.

Three pins tie the probes to the code they describe: the Vault paths each probe asks about are the
paths a recording fake sees the engine's own provider call, so the two cannot drift apart.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth import ldap as ldap_module
from messagefoundry.auth.ldap import (
    BindAccountReading,
    LdapAuthenticator,
    LdapError,
    sid_text,
)
from messagefoundry.config import secretprovider_vault
from messagefoundry.config.settings import (
    AuthSettings,
    SecretsSettings,
    ServiceSettings,
    StoreBackend,
    StorePrivilegeStatus,
    StoreSettings,
)
from messagefoundry.privilege_check import (
    EXIT_OVER_PRIVILEGED,
    EXIT_UNOBSERVABLE,
    VAULT_ADMIN_PATHS,
    HopState,
    VaultConsumer,
    _vault_hops,
    administrative_group,
    exit_code_for,
    ldap_hop,
    settings_hops,
    vault_admin_paths,
    vault_consumers,
    vault_hop,
)
from messagefoundry.privilege_probes import (
    VaultTokenReading,
    probe_vault,
    read_ldap_bind,
    read_vault_token,
)
from messagefoundry.store import crypto_transit, keyprovider_vault
from messagefoundry.store.crypto import cell_aad
from messagefoundry.store.keyprovider import KeyProviderError
from messagefoundry.store.privilege import StorePrivilegeReport

#: Synthetic, never a real credential. The assertions check none of them reaches the output.
_TOKEN = "hvs.synthetic-not-a-token-305"
_ACCESSOR = "synthetic-accessor-305"
_KEK = "mefor-kek"
#: Low entropy on purpose, so the secret scanner reads it as the fixture it is.
_BIND_SECRET = "bind-bind-bind-bind"
#: A Vault address that names no real host. The sentinel below is what an operator shell might
#: hold in VAULT_ADDR; no test may ever build a client for it.
_VAULT_ADDR = "https://vault.mefor.invalid:8200"
_OPERATOR_ADDR = "https://operator-vault.invalid:8200"

_KEK_PATHS = {
    f"transit/keys/{_KEK}": frozenset({"read"}),
    f"transit/decrypt/{_KEK}": frozenset({"update"}),
}


# --- a fake hvac client: only lookup-self and capabilities-self -------------------------------------


class Forbidden(Exception):  # noqa: N818 - hvac's own name for a 403, which the probe reads
    pass


class _FakeVault:
    def __init__(
        self,
        *,
        policies: tuple[str, ...] = ("default", "mefor-store"),
        caps: dict[str, list[str]] | None = None,
        lookup_error: Exception | None = None,
        caps_error: Exception | None = None,
        accessor: str = _ACCESSOR,
    ) -> None:
        self.asked: list[str] = []
        self.unanswered: set[str] = set()
        self._accessor = accessor
        self._policies = list(policies)
        self._caps = caps or {}
        self._lookup_error = lookup_error
        self._caps_error = caps_error
        outer = self

        class _Token:
            def lookup_self(self) -> dict[str, Any]:
                if outer._lookup_error is not None:
                    raise outer._lookup_error
                return {
                    "data": {
                        "id": _TOKEN,
                        "accessor": outer._accessor,
                        "policies": outer._policies,
                        "ttl": 2764800,
                        "renewable": True,
                    }
                }

        class _Auth:
            token = _Token()

        class _Sys:
            def get_capabilities(self, paths: list[str]) -> dict[str, Any]:
                if outer._caps_error is not None:
                    raise outer._caps_error
                outer.asked.extend(paths)
                answer = {
                    p: outer._caps.get(p, ["deny"]) for p in paths if p not in outer.unanswered
                }
                return {**answer, "data": answer}

        self.auth = _Auth()
        self.sys = _Sys()


def _least_caps() -> dict[str, list[str]]:
    return {p: sorted(c) for p, c in _KEK_PATHS.items()}


def _reading(vault: _FakeVault, token: str = _TOKEN) -> VaultTokenReading:
    return read_vault_token(lambda: token, lambda t: vault, lambda: dict(_KEK_PATHS))


_STORE = VaultConsumer("vault.store", "kek", "store key provider", "read and decrypt the KEK")


def _out(hop: Any) -> str:
    return json.dumps(hop.as_dict())


# --- Vault: judging the reading ----------------------------------------------------------------


def test_a_least_privilege_token_reads_clean_and_shows_no_secret() -> None:
    vault = _FakeVault(caps=_least_caps())
    hop = vault_hop(_STORE, _reading(vault))
    assert hop.state is HopState.CLEAN
    assert "token policies [default, mefor-store], ttl 2764800s, renewable" in hop.detail
    assert f"transit/decrypt/{_KEK}: update" in hop.detail
    assert _TOKEN not in _out(hop) and _ACCESSOR not in _out(hop)
    # The one capabilities read asked about the engine's paths and the administrative ones.
    policies = ("default", "mefor-store")
    assert set(vault.asked) == {
        *_KEK_PATHS,
        *vault_admin_paths(_KEK_PATHS, policies, transit_mount="transit"),
    }
    assert set(VAULT_ADMIN_PATHS) <= set(vault.asked)


@pytest.mark.parametrize(
    "path",
    [
        "sys/policies/acl/mefor-store",
        "sys/policy/mefor-store",
        f"transit/keys/{_KEK}/config",
        f"transit/export/encryption-key/{_KEK}",
        f"transit/backup/{_KEK}",
    ],
)
def test_a_token_that_can_rewrite_its_policy_or_export_its_key_is_over_granted(path: str) -> None:
    """A grant on the token's own policy name, or on the key's config and export paths, which the
    placeholder administrative names cannot catch."""
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=_least_caps() | {path: ["update"]})))
    assert hop.state is HopState.OVER_GRANTED
    assert f"{path} grants update; the engine never calls it" in hop.detail


def test_a_capability_beyond_the_call_is_an_over_grant() -> None:
    caps = _least_caps() | {f"transit/decrypt/{_KEK}": ["delete", "update"]}
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=caps)))
    assert hop.state is HopState.OVER_GRANTED
    assert f"transit/decrypt/{_KEK} also grants delete (needs update)" in hop.detail
    assert exit_code_for([hop]) == EXIT_OVER_PRIVILEGED


def test_a_root_policy_is_an_over_grant() -> None:
    hop = vault_hop(_STORE, _reading(_FakeVault(policies=("root",), caps=_least_caps())))
    assert hop.state is HopState.OVER_GRANTED
    assert "the token carries the root policy" in hop.detail


def test_a_root_capability_on_a_path_is_an_over_grant() -> None:
    caps = _least_caps() | {f"transit/keys/{_KEK}": ["root"]}
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=caps)))
    assert hop.state is HopState.OVER_GRANTED
    assert f"transit/keys/{_KEK} also grants root" in hop.detail


def test_any_grant_on_an_administrative_path_is_an_over_grant() -> None:
    caps = _least_caps() | {"auth/token/create": ["update"]}
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=caps)))
    assert hop.state is HopState.OVER_GRANTED
    assert "auth/token/create grants update; the engine never calls it" in hop.detail


@pytest.mark.parametrize(
    "path",
    [
        "sys/policy/messagefoundry-check-privileges",
        "identity/group",
        "identity/group/name/messagefoundry-check-privileges",
    ],
)
def test_the_older_policy_endpoint_and_identity_groups_are_administrative(path: str) -> None:
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=_least_caps() | {path: ["update"]})))
    assert hop.state is HopState.OVER_GRANTED
    assert f"{path} grants update; the engine never calls it" in hop.detail


_HOSTILE = "mefor\u202etoor\x9b31m\x1b"


def _clean(text: str) -> bool:
    return not any(ch in text for ch in ("\u202e", "\x9b", "\x1b"))


def test_a_policy_name_cannot_drive_the_terminal_or_reorder_the_line() -> None:
    hop = vault_hop(_STORE, _reading(_FakeVault(policies=(_HOSTILE,), caps=_least_caps())))
    assert _clean(hop.detail)
    assert "token policies [mefortoor31m]" in hop.detail


def test_a_hostile_policy_name_inside_a_granted_path_is_printed_and_logged_clean(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """The name reaches the output a second way: inside the policy-write PATH the check asks
    about. The fake GRANTS that path, so the over-grant line that names it is printed, and it
    answers nothing for the older endpoint, so a problem naming that path is logged too."""
    from messagefoundry.privilege_check import render_text

    granted = f"sys/policies/acl/{_HOSTILE}"
    vault = _FakeVault(policies=(_HOSTILE,), caps=_least_caps() | {granted: ["update"]})
    vault.unanswered = {f"sys/policy/{_HOSTILE}"}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.privilege_probes"):
        hop = vault_hop(_STORE, _reading(vault))
    assert hop.state is HopState.OVER_GRANTED
    assert "sys/policies/acl/mefortoor31m grants update" in hop.detail
    for line in render_text([hop]):
        print(line)
    printed = capsys.readouterr().out
    assert "sys/policies/acl/mefortoor31m" in printed and _clean(printed)
    assert "capabilities-self returned nothing for sys/policy/mefortoor31m" in caplog.text
    assert _clean(caplog.text)


@pytest.mark.parametrize("lookalike", ["ro\x00ot", "r\u200boot", "root\u202e"])
def test_a_policy_that_only_looks_like_root_is_judged_as_root(lookalike: str) -> None:
    """The printed list would show "root"; the judgement must agree with what is printed."""
    hop = vault_hop(_STORE, _reading(_FakeVault(policies=(lookalike,), caps=_least_caps())))
    assert hop.state is HopState.OVER_GRANTED
    assert "the token carries the root policy" in hop.detail


def test_a_capability_with_a_stray_character_is_read_as_the_capability() -> None:
    caps = {f"transit/keys/{_KEK}": ["read\x00"], f"transit/decrypt/{_KEK}": ["update"]}
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=caps)))
    assert hop.state is HopState.CLEAN


def test_an_unset_token_and_address_are_both_named_in_one_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_STORE_VAULT_TOKEN", raising=False)
    monkeypatch.delenv("MEFOR_STORE_VAULT_ADDR", raising=False)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _KEK)
    reading = probe_vault(_STORE)
    joined = " ".join(reading.problems)
    assert "MEFOR_STORE_VAULT_TOKEN is not set" in joined
    assert "MEFOR_STORE_VAULT_ADDR is not set" in joined


def test_one_token_serving_both_hops_is_judged_on_the_union_of_its_grants() -> None:
    kv_path = "secret/data/mefor/ad"
    caps = _least_caps() | {kv_path: ["read"]}
    store = _reading(_FakeVault(caps=caps))
    # A batch token: no accessor, and the match still holds, because it is made on the token.
    secrets = read_vault_token(
        lambda: _TOKEN,
        lambda t: _FakeVault(caps=caps, accessor=""),
        lambda: {kv_path: frozenset({"read"})},
    )
    assert store.same_token_as(secrets)
    kv = VaultConsumer("vault.secrets", "kv", "kv", "read the KV path")
    hops = _vault_hops([_STORE, kv], [store, secrets])
    assert [h.state for h in hops] == [HopState.OVER_GRANTED, HopState.OVER_GRANTED]
    assert f"the same token serves vault.secrets, so it also holds read on {kv_path}" in (
        hops[0].detail
    )
    assert f"serves vault.store, so it also holds update on transit/decrypt/{_KEK}" in (
        hops[1].detail
    )
    assert store.token_ref is not None
    assert store.token_ref not in _out(hops[0]) and store.token_ref not in repr(store)
    assert _TOKEN not in repr(store)
    # The control: two different tokens with the same grants are each judged alone.
    other = read_vault_token(
        lambda: "other-other-other",
        lambda t: _FakeVault(caps=caps),
        lambda: {kv_path: frozenset({"read"})},
    )
    assert [h.state for h in _vault_hops([_STORE, kv], [store, other])] == [
        HopState.CLEAN,
        HopState.CLEAN,
    ]


def test_an_unknown_consumer_kind_is_refused_not_probed_as_the_kek() -> None:
    bogus = VaultConsumer("vault.x", cast("Any", "kv2"), "x", "x")
    with pytest.raises(ValueError, match="no Vault probe for consumer kind 'kv2'"):
        probe_vault(bogus)


def test_a_probe_problem_is_logged_without_the_token(caplog: pytest.LogCaptureFixture) -> None:
    error = ConnectionError(f"https://vault.invalid/ token={_TOKEN}")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.privilege_probes"):
        _reading(_FakeVault(lookup_error=error))
    assert "check-privileges: token lookup-self failed: ConnectionError" in caplog.text
    assert _TOKEN not in caplog.text


def test_a_kv_mount_named_like_keys_is_not_read_as_a_transit_key() -> None:
    paths = vault_admin_paths(
        {"mefor/keys/data/ad": frozenset({"read"})}, (), transit_mount="transit"
    )
    assert not any("/config" in p or "/export/" in p or "/backup/" in p for p in paths)
    # The control: the Transit mount's own key path does get its key-admin paths.
    assert f"transit/keys/{_KEK}/config" in vault_admin_paths(
        _KEK_PATHS, (), transit_mount="transit"
    )


def test_a_value_error_keeps_its_own_text_and_a_subclass_does_not() -> None:
    from messagefoundry.privilege_probes import _why

    assert _why(ValueError("lookup-self returned no data")) == (
        "ValueError: lookup-self returned no data"
    )
    assert _why(json.JSONDecodeError("server body here", "doc", 0)) == "JSONDecodeError"


def test_a_missing_capability_is_noted_and_is_not_an_over_grant() -> None:
    caps = {f"transit/keys/{_KEK}": ["read"]}  # decrypt left at deny
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=caps)))
    assert hop.state is HopState.CLEAN
    assert "lacks update, so the engine's own call would fail" in hop.detail


def test_a_denied_lookup_is_unobservable_not_an_exception() -> None:
    hop = vault_hop(_STORE, _reading(_FakeVault(caps=_least_caps(), lookup_error=Forbidden())))
    assert hop.state is HopState.UNOBSERVABLE
    assert "token lookup-self failed: permission denied (Forbidden)" in hop.detail
    assert exit_code_for([hop]) == EXIT_UNOBSERVABLE


def test_a_denied_capabilities_read_is_unobservable() -> None:
    hop = vault_hop(_STORE, _reading(_FakeVault(caps_error=Forbidden())))
    assert hop.state is HopState.UNOBSERVABLE
    assert "capabilities-self failed: permission denied (Forbidden)" in hop.detail


def test_an_unreachable_vault_is_unobservable_and_names_only_the_type() -> None:
    error = ConnectionError(f"https://vault.invalid/ token={_TOKEN}")
    hop = vault_hop(_STORE, _reading(_FakeVault(lookup_error=error, caps_error=error)))
    assert hop.state is HopState.UNOBSERVABLE
    assert "token lookup-self failed: ConnectionError" in hop.detail
    assert _TOKEN not in _out(hop)


def test_a_client_that_cannot_be_built_is_unobservable_with_the_engines_own_text() -> None:
    def _refuse(token: str) -> Any:
        raise KeyProviderError("Vault transit key provider: refusing a cleartext address")

    hop = vault_hop(_STORE, read_vault_token(lambda: _TOKEN, _refuse, lambda: dict(_KEK_PATHS)))
    assert hop.state is HopState.UNOBSERVABLE
    assert "no Vault client: Vault transit key provider: refusing a cleartext address" in hop.detail


def test_an_unknown_key_name_is_unobservable_but_a_root_token_still_shows() -> None:
    def _unknown() -> dict[str, frozenset[str]]:
        raise KeyProviderError("MEFOR_STORE_VAULT_TRANSIT_KEY is not set")

    blind = vault_hop(_STORE, read_vault_token(lambda: _TOKEN, lambda t: _FakeVault(), _unknown))
    assert blind.state is HopState.UNOBSERVABLE
    assert "MEFOR_STORE_VAULT_TRANSIT_KEY is not set" in blind.detail
    rooted = _FakeVault(policies=("root",))
    root = vault_hop(_STORE, read_vault_token(lambda: _TOKEN, lambda t: rooted, _unknown))
    assert root.state is HopState.OVER_GRANTED


# --- Vault: the paths asked about are the paths the engine calls ------------------------------------


class _RecordingTransit:
    """A Transit double that records the Vault path each call reaches."""

    def __init__(self) -> None:
        self.paths: set[str] = set()

    def read_key(self, *, name: str, mount_point: str = "transit") -> dict[str, Any]:
        self.paths.add(f"{mount_point}/keys/{name}")
        return {"data": {"type": "aes256-gcm96"}}

    def decrypt_data(
        self, *, name: str, ciphertext: str, mount_point: str = "transit", **_: Any
    ) -> dict[str, Any]:
        self.paths.add(f"{mount_point}/decrypt/{name}")
        return {"data": {"plaintext": ciphertext.removeprefix("vault:v1:")}}

    def encrypt_data(
        self, *, name: str, plaintext: str, mount_point: str = "transit", **_: Any
    ) -> dict[str, Any]:
        self.paths.add(f"{mount_point}/encrypt/{name}")
        return {"data": {"ciphertext": f"vault:v1:{plaintext}"}}

    def generate_hmac(self, *, name: str, mount_point: str = "transit", **_: Any) -> dict[str, Any]:
        self.paths.add(f"{mount_point}/hmac/{name}")
        return {"data": {"hmac": "vault:v1:synthetic-mac"}}


class _TransitClient:
    def __init__(self, transit: _RecordingTransit) -> None:
        self.secrets = type("S", (), {"transit": transit})()


def test_the_kek_paths_are_the_ones_the_key_provider_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    transit = _RecordingTransit()
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _KEK)
    monkeypatch.setenv(
        "MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:" + base64.b64encode(b"k" * 32).decode()
    )
    monkeypatch.setattr(keyprovider_vault, "_build_client", lambda a, t: _TransitClient(transit))
    keyprovider_vault.VaultKeyProvider(StoreSettings()).active_key()
    assert transit.paths == set(keyprovider_vault.kek_required_capabilities())


@pytest.mark.parametrize("audit_key", [None, "mefor-audit"])
def test_the_transit_paths_are_the_ones_the_cipher_calls(
    monkeypatch: pytest.MonkeyPatch, audit_key: str | None
) -> None:
    transit = _RecordingTransit()
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "mefor-data")
    if audit_key is None:
        monkeypatch.delenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", raising=False)
    else:
        monkeypatch.setenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", audit_key)
    monkeypatch.setattr(crypto_transit, "_build_client", lambda a, t: _TransitClient(transit))
    cipher = crypto_transit.build_transit_cipher(StoreSettings())
    aad = cell_aad("messages", "raw", 1)
    cipher.decrypt(cipher.encrypt("synthetic", aad=aad), aad=aad)
    cipher.audit_hmac(b"synthetic row")
    assert transit.paths == set(crypto_transit.transit_cipher_required_capabilities())


def test_the_kv_paths_are_the_ones_the_secret_provider_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    class _V2:
        def read_secret_version(self, *, path: str, mount_point: str) -> dict[str, Any]:
            seen.append(f"{mount_point}/data/{path}")
            return {"data": {"data": {"value": "synthetic", "pw": "synthetic"}}}

    client = type("C", (), {"secrets": type("S", (), {"kv": type("K", (), {"v2": _V2()})()})()})()
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_KV_MOUNT", "kv-mefor")
    monkeypatch.setattr(secretprovider_vault, "_build_client", lambda a, t: client)
    refs = ["mefor/ad", "mefor/smtp#pw"]
    provider = secretprovider_vault.build_provider(SecretsSettings(provider="vault"))
    for ref in refs:
        provider.resolve(ref)
    assert set(seen) == set(secretprovider_vault.kv_required_capabilities(refs))


# --- Vault: which hops the settings name ------------------------------------------------------------


def _no_ldap() -> BindAccountReading:
    raise AssertionError("the LDAP probe ran with AD off")


def test_each_vault_token_is_its_own_hop_and_is_probed_once() -> None:
    settings = ServiceSettings.model_validate(
        {
            "store": {"key_provider": "vault"},
            "secrets": {"provider": "vault"},
            "alerts": {"email_password_secret": "mefor/smtp"},
        }
    )
    consumers = vault_consumers(settings)
    assert [(c.hop, c.kind) for c in consumers] == [("vault.store", "kek"), ("vault.secrets", "kv")]
    assert consumers[1].refs == ("mefor/smtp",)
    probed: list[str] = []

    def _probe(consumer: VaultConsumer) -> VaultTokenReading:
        probed.append(consumer.hop)
        return VaultTokenReading(looked_up=True)

    hops = {h.hop: h for h in settings_hops(settings, vault_probe=_probe, ldap_probe=_no_ldap)}
    assert probed == ["vault.store", "vault.secrets"]
    assert hops["vault.store"].state is HopState.CLEAN
    assert hops["ldap"].state is HopState.NOT_CONFIGURED
    assert "vault" not in hops


def test_no_vault_consumer_probes_nothing() -> None:
    def _never(consumer: VaultConsumer) -> VaultTokenReading:
        raise AssertionError("a Vault probe ran with no Vault consumer")

    hops = settings_hops(ServiceSettings(), vault_probe=_never, ldap_probe=_no_ldap)
    assert hops[0].hop == "vault" and hops[0].state is HopState.NOT_CONFIGURED


def test_the_transit_cipher_probe_asks_about_the_cipher_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault = _FakeVault()
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _VAULT_ADDR)
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "mefor-data")
    monkeypatch.delenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", raising=False)
    monkeypatch.setattr(keyprovider_vault, "_build_client", lambda a, t: vault)
    settings = ServiceSettings.model_validate({"store": {"cipher_provider": "vault_transit"}})
    (consumer,) = vault_consumers(settings)
    reading = probe_vault(consumer)
    assert set(reading.required) == set(crypto_transit.transit_cipher_required_capabilities())
    assert "transit/hmac/mefor-data" in vault.asked


# --- LDAP: Who am I and the bind account's groups -----------------------------------------------


def _sid(*parts: int, authority: int = 5) -> bytes:
    return (
        bytes([1, len(parts)])
        + authority.to_bytes(6, "big")
        + b"".join(p.to_bytes(4, "little") for p in parts)
    )


_DOMAIN = (21, 1111, 2222, 3333)
_DOMAIN_USERS = "S-1-5-21-1111-2222-3333-513"


def test_sid_text_and_the_administrative_groups() -> None:
    assert sid_text(_sid(32, 544)) == "S-1-5-32-544"
    assert sid_text(b"\x01\x02short") is None
    assert administrative_group("S-1-5-21-1111-2222-3333-512") == "Domain Admins"
    assert administrative_group("S-1-5-21-1111-2222-3333-519") == "Enterprise Admins"
    assert administrative_group("S-1-5-32-548") == "Account Operators"
    assert administrative_group(_DOMAIN_USERS) is None
    # The strict shape the config-directory check uses: exactly S-1-5-21-a-b-c-<rid>.
    assert administrative_group("S-1-5-21-1111-512") is None
    assert administrative_group("S-1-5-21-1111-2222-3333-５１２") is None


class _FakeAttr:
    def __init__(self, raw: list[bytes]) -> None:
        self.raw_values = raw
        self.values = [v.decode() for v in raw]
        self.value = self.values[0] if len(self.values) == 1 else self.values


class _FakeEntry:
    def __init__(self, raw: dict[str, list[bytes]]) -> None:
        self._attrs = {k: _FakeAttr(v) for k, v in raw.items() if k != "tokenGroups"}
        if "tokenGroups" in raw:
            self._attrs["tokenGroups"] = type("T", (), {"raw_values": raw["tokenGroups"]})()

    def __contains__(self, name: object) -> bool:
        return name in self._attrs

    def __getitem__(self, name: str) -> Any:
        return self._attrs[name]


class _FakeLdapConn:
    """The service connection: Who am I, then one BASE read of the bind DN. Records each search;
    any write method raises, so a probe that wrote would fail the test."""

    def __init__(
        self, raw: dict[str, list[bytes]] | None, authzid: str | None = "u:EXAMPLE\\svc"
    ) -> None:
        self.unbound = False
        self.searches: list[dict[str, Any]] = []
        self.result: dict[str, Any] | None = None
        self.entries: list[_FakeEntry] = []
        self._raw = raw
        who = authzid
        self.extend = type(
            "E", (), {"standard": type("S", (), {"who_am_i": staticmethod(lambda: who)})()}
        )()

    def __enter__(self) -> _FakeLdapConn:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def search(self, **kwargs: Any) -> bool:
        self.searches.append(kwargs)
        self.result = (
            {"result": 0}
            if self._raw is not None
            else {"result": 32, "description": "noSuchObject"}
        )
        self.entries = [] if self._raw is None else [_FakeEntry(self._raw)]
        return bool(self.entries)

    def unbind(self) -> bool:
        self.unbound = True
        return True

    def __getattr__(self, name: str) -> Any:
        if name in {"modify", "add", "delete", "modify_dn", "password_modify"}:
            raise AssertionError(f"the probe called {name}")
        raise AttributeError(name)


def _ad_settings() -> AuthSettings:
    return AuthSettings(
        ad_enabled=True,
        ad_server="ldaps://dc.example.com",
        ad_domain="example.com",
        ad_user_search_base="OU=Users,DC=example,DC=com",
        ad_bind_dn="CN=svc,OU=Svc,DC=example,DC=com",
        ad_bind_password=_BIND_SECRET,
    )


def _ad_service_settings() -> ServiceSettings:
    return ServiceSettings.model_validate({"auth": _ad_settings().model_dump()})


def _read(monkeypatch: pytest.MonkeyPatch, conn: _FakeLdapConn) -> BindAccountReading:
    auth = LdapAuthenticator(_ad_settings(), enforcing=True)
    monkeypatch.setattr(auth, "_service_conn", lambda: conn)
    return auth.read_bind_account()


def _judge(reading: BindAccountReading) -> Any:
    return ldap_hop(_ad_service_settings(), lambda: reading)


def test_whoami_and_a_transitive_read_with_no_admin_group_is_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ldap3

    conn = _FakeLdapConn({"tokenGroups": [_sid(*_DOMAIN, 513), _sid(32, 545)]})
    reading = _read(monkeypatch, conn)
    assert reading == BindAccountReading(
        "u:EXAMPLE\\svc", group_sids=(_DOMAIN_USERS, "S-1-5-32-545")
    )
    (search,) = conn.searches
    assert search["search_base"] == "CN=svc,OU=Svc,DC=example,DC=com"
    assert search["search_scope"] == ldap3.BASE
    hop = _judge(reading)
    assert hop.state is HopState.CLEAN
    assert "Who am I: bound as 'u:EXAMPLE\\\\svc'" in hop.detail
    assert "rights not read" in hop.detail
    assert _BIND_SECRET not in _out(hop)
    assert conn.unbound  # the session is closed, not left for the collector


def test_a_whoami_that_names_no_one_is_unobservable_never_clean(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _FakeLdapConn({"tokenGroups": [_sid(*_DOMAIN, 513)]}, authzid=None)
    hop = _judge(_read(monkeypatch, conn))
    assert hop.state is HopState.UNOBSERVABLE
    assert "Who am I returned no identity" in hop.detail


@pytest.mark.parametrize(
    ("sid", "group"),
    [
        (_sid(*_DOMAIN, 516), "Domain Controllers"),
        (_sid(*_DOMAIN, 520), "Group Policy Creator Owners"),
        (_sid(*_DOMAIN, 526), "Key Admins"),
        (_sid(*_DOMAIN, 527), "Enterprise Key Admins"),
        (_sid(9), "Enterprise Domain Controllers"),
    ],
)
def test_the_wider_administrative_groups_are_over_grants(
    monkeypatch: pytest.MonkeyPatch, sid: bytes, group: str
) -> None:
    hop = _judge(_read(monkeypatch, _FakeLdapConn({"tokenGroups": [_sid(*_DOMAIN, 513), sid]})))
    assert hop.state is HopState.OVER_GRANTED
    assert f"member of {group} (transitive" in hop.detail


def test_an_ordinary_group_named_administrators_is_not_the_builtin_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With tokenGroups read, the SIDs settle the fixed-SID groups: an OU group that is merely
    NAMED Administrators is not BUILTIN\\Administrators."""
    raw = {
        "tokenGroups": [_sid(*_DOMAIN, 513), _sid(*_DOMAIN, 1105)],
        "memberOf": [b"CN=Administrators,OU=App,DC=example,DC=com"],
        "primaryGroupID": [b"513"],
    }
    hop = _judge(_read(monkeypatch, _FakeLdapConn(raw)))
    assert hop.state is HopState.CLEAN


def test_a_domain_admins_primary_group_counts_even_beside_a_tokengroups_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A RID cannot be faked by naming a group, so the primary group counts on both paths, even
    when a tokenGroups read somehow lacks it."""
    raw = {"tokenGroups": [_sid(*_DOMAIN, 513)], "primaryGroupID": [b"512"]}
    hop = _judge(_read(monkeypatch, _FakeLdapConn(raw)))
    assert hop.state is HopState.OVER_GRANTED
    assert "Domain Admins (direct memberOf)" in hop.detail


@pytest.mark.parametrize(
    ("rid", "group"),
    [
        (498, "Enterprise Read-only Domain Controllers"),
        (521, "Read-only Domain Controllers"),
        (522, "Cloneable Domain Controllers"),
    ],
)
def test_the_read_only_and_cloneable_controller_groups_are_over_grants(
    monkeypatch: pytest.MonkeyPatch, rid: int, group: str
) -> None:
    raw = {"tokenGroups": [_sid(*_DOMAIN, 513), _sid(*_DOMAIN, rid)]}
    hop = _judge(_read(monkeypatch, _FakeLdapConn(raw)))
    assert hop.state is HopState.OVER_GRANTED
    assert f"member of {group} (transitive" in hop.detail


def test_a_who_am_i_that_raises_after_a_good_bind_is_not_a_bind_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ldap3

    conn = _FakeLdapConn({"tokenGroups": [_sid(*_DOMAIN, 513)]})

    def _raise() -> str:
        raise ldap3.core.exceptions.LDAPExtensionError("unsupported")

    conn.extend = type("E", (), {"standard": type("S", (), {"who_am_i": staticmethod(_raise)})()})()
    reading = _read(monkeypatch, conn)
    assert reading.bound is True and reading.group_sids  # the group read still ran
    assert reading.whoami_error == "Who am I failed: LDAPExtensionError: unsupported"
    hop = _judge(reading)
    assert hop.state is HopState.UNOBSERVABLE
    assert "Who am I failed: LDAPExtensionError: unsupported" in hop.detail
    assert "bind probe" not in hop.detail


def test_dnsadmins_is_found_by_direct_membership_beside_a_clean_sid_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DnsAdmins has no fixed RID, so its SID in tokenGroups cannot be recognised; the direct
    memberOf is read on every path for it."""
    raw = {
        "tokenGroups": [_sid(*_DOMAIN, 513), _sid(*_DOMAIN, 1101)],
        "memberOf": [b"CN=DnsAdmins,CN=Users,DC=example,DC=com"],
    }
    hop = _judge(_read(monkeypatch, _FakeLdapConn(raw)))
    assert hop.state is HopState.OVER_GRANTED
    assert "member of DnsAdmins (direct memberOf)" in hop.detail
    assert "DnsAdmins by direct membership only" in hop.detail


@pytest.mark.parametrize(
    ("sid", "group"),
    [
        (_sid(*_DOMAIN, 512), "Domain Admins"),
        (_sid(*_DOMAIN, 519), "Enterprise Admins"),
        (_sid(32, 544), "Administrators"),
        (_sid(32, 548), "Account Operators"),
    ],
)
def test_a_nested_administrative_group_is_an_over_grant(
    monkeypatch: pytest.MonkeyPatch, sid: bytes, group: str
) -> None:
    reading = _read(monkeypatch, _FakeLdapConn({"tokenGroups": [_sid(*_DOMAIN, 513), sid]}))
    hop = _judge(reading)
    assert hop.state is HopState.OVER_GRANTED
    assert f"member of {group} (transitive, from tokenGroups)" in hop.detail


def test_without_tokengroups_a_direct_admin_group_still_shows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = {"memberOf": [b"CN=Domain Admins,CN=Users,DC=example,DC=com"], "primaryGroupID": [b"513"]}
    reading = _read(monkeypatch, _FakeLdapConn(raw))
    assert reading.member_of == ("Domain Admins",) and reading.primary_group_rid == 513
    hop = _judge(reading)
    assert hop.state is HopState.OVER_GRANTED
    assert "member of Domain Admins (direct memberOf)" in hop.detail


def test_without_tokengroups_and_no_direct_admin_group_it_is_unobservable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = {"memberOf": [b"CN=Mefor,OU=Groups,DC=example,DC=com"]}
    hop = _judge(_read(monkeypatch, _FakeLdapConn(raw)))
    assert hop.state is HopState.UNOBSERVABLE
    assert "nested group membership not read" in hop.detail


def test_a_primary_group_of_domain_admins_is_an_over_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    hop = _judge(_read(monkeypatch, _FakeLdapConn({"primaryGroupID": [b"512"]})))
    assert hop.state is HopState.OVER_GRANTED
    assert "Domain Admins" in hop.detail


def test_a_missing_entry_keeps_the_identity_and_is_unobservable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reading = _read(monkeypatch, _FakeLdapConn(None))
    assert reading.authzid == "u:EXAMPLE\\svc"
    assert reading.problem is not None and "returned no entry (noSuchObject)" in reading.problem
    assert _judge(reading).state is HopState.UNOBSERVABLE


def test_a_failed_bind_is_unobservable_never_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(self: LdapAuthenticator) -> BindAccountReading:
        raise LdapError("automatic bind not successful - invalidCredentials")

    monkeypatch.setattr(LdapAuthenticator, "read_bind_account", _boom)
    reading = read_ldap_bind(_ad_service_settings(), None)
    assert reading.authzid is None
    assert reading.problem == "AD bind probe: automatic bind not successful - invalidCredentials"
    hop = _judge(reading)
    assert hop.state is HopState.UNOBSERVABLE
    # Who am I never ran, so the hop does not blame it; the bind failure is the one finding.
    assert "Who am I returned no identity" not in hop.detail


def test_a_vault_held_bind_password_is_never_read_with_a_fallback_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With MEFOR_SECRETS_VAULT_TOKEN unset, resolving the bind password would let hvac read it
    with VAULT_TOKEN. The probe refuses before the provider is built."""
    monkeypatch.delenv("MEFOR_SECRETS_VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_TOKEN", "hvs.synthetic-operator-305")
    monkeypatch.setattr(secretprovider_vault, "_build_client", lambda a, t: pytest.fail("built"))
    auth = _ad_settings().model_dump() | {
        "ad_bind_password": None,
        "ad_bind_password_secret": "mefor/ad",
    }
    settings = ServiceSettings.model_validate({"auth": auth, "secrets": {"provider": "vault"}})
    reading = read_ldap_bind(settings, None)
    assert reading.bound is False
    assert reading.problem is not None
    assert "MEFOR_SECRETS_VAULT_TOKEN is not set" in reading.problem


def test_the_group_read_goes_through_the_referral_refusing_search() -> None:
    """Every search in auth/ldap.py goes through ``_search`` (BACKLOG #2530); the new one too."""
    source = Path(ldap_module.__file__).read_text(encoding="utf-8")
    body = source[source.index("def read_bind_account") : source.index("def _authzid_text")]
    assert "_search(" in body and ".search(" not in body


# --- the command ---------------------------------------------------------------------------------


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(("MEFOR_", "VAULT_")):
            monkeypatch.delenv(key, raising=False)


def _vault_toml(tmp_path: Path) -> Path:
    toml = tmp_path / "svc.toml"
    toml.write_text('[store]\nkey_provider = "vault"\n', encoding="utf-8")
    return toml


def _sqlite_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _probe(settings: StoreSettings, *, posture: Any = None) -> StorePrivilegeReport:
        return StorePrivilegeReport(
            backend=StoreBackend.SQLITE, status=StorePrivilegeStatus.NOT_APPLICABLE
        )

    monkeypatch.setattr("messagefoundry.store.base.probe_store_privileges", _probe)


def _cli(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, build: Callable[[Any, Any], Any]
) -> list[str]:
    _clear_env(monkeypatch)
    _sqlite_probe(monkeypatch)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _VAULT_ADDR)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _KEK)
    monkeypatch.setattr(keyprovider_vault, "_build_client", build)
    return ["check-privileges", "--service-config", str(_vault_toml(tmp_path)), "--json"]


def test_cli_exits_3_on_a_root_token_and_says_it_does_not_gate_a_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _cli(monkeypatch, tmp_path, lambda a, t: _FakeVault(policies=("root",)))
    assert main(argv) == EXIT_OVER_PRIVILEGED
    out = capsys.readouterr().out
    assert _TOKEN not in out and _ACCESSOR not in out
    payload = json.loads(out)
    vault = next(h for h in payload["hops"] if h["hop"] == "vault.store")
    assert vault["state"] == "over_granted"
    assert "vault.store is reported only; it does not gate a start" in payload["serve"]


def test_cli_exits_4_when_vault_is_unreachable_and_sends_one_request(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    error = ConnectionError("vault.invalid")
    vault = _FakeVault(lookup_error=error)
    argv = _cli(monkeypatch, tmp_path, lambda a, t: vault)
    assert main(argv) == EXIT_UNOBSERVABLE
    payload = json.loads(capsys.readouterr().out)
    hop = next(h for h in payload["hops"] if h["hop"] == "vault.store")
    assert hop["state"] == "unobservable"
    # A transport failure on the lookup skips the capabilities read, which would only time out too.
    assert vault.asked == []
    assert "capabilities-self" not in hop["detail"]


def test_cli_never_judges_a_fallback_token_when_the_engines_is_unset(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """With MEFOR_STORE_VAULT_TOKEN unset, hvac would read VAULT_TOKEN or ~/.vault-token: the
    operator's token, not the engine's. The probe refuses before any client is built."""
    built: list[object] = []

    def _build(addr: Any, token: Any) -> _FakeVault:
        built.append(token)
        return _FakeVault()

    argv = _cli(monkeypatch, tmp_path, _build)
    monkeypatch.delenv("MEFOR_STORE_VAULT_TOKEN")
    monkeypatch.setenv("VAULT_TOKEN", "hvs.synthetic-operator-305")
    assert main(argv) == EXIT_UNOBSERVABLE
    hop = next(h for h in json.loads(capsys.readouterr().out)["hops"] if h["hop"] == "vault.store")
    assert hop["state"] == "unobservable"
    assert "MEFOR_STORE_VAULT_TOKEN is not set" in hop["detail"]
    assert built == []


def test_the_store_probe_never_sends_the_token_to_vault_addr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With MEFOR_STORE_VAULT_ADDR unset, hvac would read VAULT_ADDR, which in an operator's shell
    may be another Vault. The probe refuses before any client is built."""
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.delenv("MEFOR_STORE_VAULT_ADDR", raising=False)
    monkeypatch.setenv("VAULT_ADDR", _OPERATOR_ADDR)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", _KEK)
    monkeypatch.setattr(keyprovider_vault, "_build_client", lambda a, t: pytest.fail(f"built {a}"))
    with pytest.raises(KeyProviderError, match="MEFOR_STORE_VAULT_ADDR is not set"):
        keyprovider_vault.store_vault_client(_TOKEN)
    reading = probe_vault(_STORE)
    assert any("MEFOR_STORE_VAULT_ADDR is not set" in p for p in reading.problems)
    assert not reading.looked_up


def test_the_secrets_probe_never_sends_the_token_to_vault_addr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.config.secretprovider import SecretProviderError

    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
    monkeypatch.delenv("MEFOR_SECRETS_VAULT_ADDR", raising=False)
    monkeypatch.setenv("VAULT_ADDR", _OPERATOR_ADDR)
    monkeypatch.setattr(
        secretprovider_vault, "_build_client", lambda a, t: pytest.fail(f"built {a}")
    )
    with pytest.raises(SecretProviderError, match="MEFOR_SECRETS_VAULT_ADDR is not set"):
        secretprovider_vault.secrets_vault_client(_TOKEN)
    kv = VaultConsumer("vault.secrets", "kv", "kv", "kv", ("mefor/ad",))
    reading = probe_vault(kv)
    assert any("MEFOR_SECRETS_VAULT_ADDR is not set" in p for p in reading.problems)


def test_the_ldap_probe_never_reads_the_bind_password_from_vault_addr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
    monkeypatch.delenv("MEFOR_SECRETS_VAULT_ADDR", raising=False)
    monkeypatch.setenv("VAULT_ADDR", _OPERATOR_ADDR)
    monkeypatch.setattr(
        secretprovider_vault, "_build_client", lambda a, t: pytest.fail(f"built {a}")
    )
    auth = _ad_settings().model_dump() | {
        "ad_bind_password": None,
        "ad_bind_password_secret": "mefor/ad",
    }
    settings = ServiceSettings.model_validate({"auth": auth, "secrets": {"provider": "vault"}})
    reading = read_ldap_bind(settings, None)
    assert reading.bound is False
    assert reading.problem is not None and "MEFOR_SECRETS_VAULT_ADDR is not set" in reading.problem


def test_the_secrets_probe_refuses_an_unset_token_too(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_SECRETS_VAULT_TOKEN", raising=False)
    monkeypatch.setenv("VAULT_TOKEN", "hvs.synthetic-operator-305")
    monkeypatch.setattr(secretprovider_vault, "_build_client", lambda a, t: pytest.fail("built"))
    kv = VaultConsumer("vault.secrets", "kv", "kv", "kv", ("mefor/ad",))
    reading = probe_vault(kv)
    assert any("MEFOR_SECRETS_VAULT_TOKEN is not set" in p for p in reading.problems)
    assert not reading.looked_up


def test_cli_exits_0_on_a_least_privilege_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    argv = _cli(monkeypatch, tmp_path, lambda a, t: _FakeVault(caps=_least_caps()))
    assert main(argv) == 0
    assert "does not gate a start" not in json.loads(capsys.readouterr().out)["serve"]


def test_cli_probes_the_ldap_bind_when_ad_is_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_env(monkeypatch)
    _sqlite_probe(monkeypatch)
    calls: list[str] = []

    def _probe(self: LdapAuthenticator) -> BindAccountReading:
        calls.append("whoami")
        return BindAccountReading("u:EXAMPLE\\svc", group_sids=("S-1-5-21-1-2-3-512",))

    monkeypatch.setattr(LdapAuthenticator, "read_bind_account", _probe)
    monkeypatch.setenv("MEFOR_AUTH_AD_BIND_PASSWORD", _BIND_SECRET)
    toml = tmp_path / "svc.toml"
    toml.write_text(
        '[auth]\nad_enabled = true\nad_server = "ldaps://dc.example.com"\n'
        'ad_domain = "example.com"\nad_user_search_base = "OU=Users,DC=example,DC=com"\n'
        'ad_bind_dn = "CN=svc,OU=Svc,DC=example,DC=com"\n',
        encoding="utf-8",
    )
    assert main(["check-privileges", "--service-config", str(toml), "--json"]) == 3
    out = capsys.readouterr().out
    assert calls == ["whoami"]
    assert _BIND_SECRET not in out
    ldap = next(h for h in json.loads(out)["hops"] if h["hop"] == "ldap")
    assert ldap["state"] == "over_granted"
