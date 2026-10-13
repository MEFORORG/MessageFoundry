# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Vault hops' revocation attestation (vault BACKLOG #2983, owner ruling 2026-10-13).

Each of the engine's three Vault hops (the store key provider, the Transit cipher and the connector
secret provider) verifies the Vault server's certificate and checks no revocation. The ruling: each
hop refuses under an enforcing posture unless its own settings pair attests that revocation is
covered outside the engine. ``[store].vault_revocation_attested`` covers the two store hops and
``[secrets].vault_revocation_attested`` the secret provider. Each needs a reason. No CRL lever is
built, and the process-wide ``MEFOR_TLS_REVOCATION_ATTESTED`` does not cross an enforcing hop.

Synthetic data only: every host, token, key name and reason here is made up.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecretsSettings,
    SecuritySettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)
from tests._ast_sites import call_sites, parse_source
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

_REASON = "the Vault server certificate lives 24 hours (synthetic)"
_SECTIONS = pytest.mark.parametrize(
    ("section", "model"), [("store", StoreSettings), ("secrets", SecretsSettings)]
)


# --- the settings pair ------------------------------------------------------------------------


@_SECTIONS
def test_the_pair_loads_and_the_default_is_off(
    section: str, model: type[StoreSettings] | type[SecretsSettings]
) -> None:
    assert model().vault_revocation_attested is False
    assert model().vault_revocation_attested_reason is None
    attested = model(vault_revocation_attested=True, vault_revocation_attested_reason=_REASON)
    assert attested.vault_revocation_attested is True


@_SECTIONS
@pytest.mark.parametrize(
    ("values", "refusal"),
    [
        ({"vault_revocation_attested": True}, "requires [{s}].vault_revocation_attested_reason"),
        (
            {"vault_revocation_attested_reason": _REASON},
            "is set without [{s}].vault_revocation_attested=true",
        ),
        (
            {"vault_revocation_attested": True, "vault_revocation_attested_reason": " \t"},
            "[{s}].vault_revocation_attested_reason must be non-empty",
        ),
        (
            {"vault_revocation_attested": True, "vault_revocation_attested_reason": "a\r\nb"},
            "[{s}].vault_revocation_attested_reason must not contain control characters",
        ),
        # A lone surrogate cannot be encoded as UTF-8, so the posture route could not answer.
        (
            {"vault_revocation_attested": True, "vault_revocation_attested_reason": "a\udce9b"},
            "[{s}].vault_revocation_attested_reason must not contain control characters or lone",
        ),
        # The string "false" is truthy to a lax reader. Here it reads as false, so the reason
        # beside it is a reason without the flag.
        (
            {"vault_revocation_attested": "false", "vault_revocation_attested_reason": _REASON},
            "is set without [{s}].vault_revocation_attested=true",
        ),
    ],
)
def test_a_pair_that_is_not_whole_refuses_at_the_model(
    section: str,
    model: type[StoreSettings] | type[SecretsSettings],
    values: dict[str, object],
    refusal: str,
) -> None:
    """Mutation: drop the ``_vault_revocation_attestation_pair`` validator from either section and
    every case for that section loads."""
    with pytest.raises(ValidationError) as caught:
        model.model_validate(values)
    assert refusal.format(s=section) in str(caught.value)


@pytest.mark.parametrize("section", ["STORE", "SECRETS"])
def test_a_flag_with_no_reason_refuses_at_settings_load(section: str) -> None:
    """The load every command runs. The environment overlay reaches the typed field, so the
    variable needs no entry in ``_OUT_OF_BAND_ENV``."""
    flag = f"MEFOR_{section}_VAULT_REVOCATION_ATTESTED"
    with pytest.raises(ValueError, match="vault_revocation_attested=true requires"):
        load_settings(environ={flag: "true"}, default_file=False)
    # The control: the same load with the reason beside the flag succeeds and sets the field.
    settings = load_settings(environ={flag: "true", f"{flag}_REASON": _REASON}, default_file=False)
    loaded = settings.store if section == "STORE" else settings.secrets
    assert loaded.vault_revocation_attested is True
    assert loaded.vault_revocation_attested_reason == _REASON


# --- the loosening report ---------------------------------------------------------------------


def _loosenings(
    *, store: StoreSettings | None = None, secrets: SecretsSettings | None = None
) -> dict[str, str]:
    return dict(
        security_loosenings(
            SecuritySettings(),
            store or StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=secrets or SecretsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_each_attestation_is_a_named_loosening_that_carries_its_reason() -> None:
    """Mutation: delete the ``out.extend`` in ``security_loosenings`` and neither name appears."""
    names = ("store.vault_revocation_attested", "secrets.vault_revocation_attested")
    # The control: the shipped defaults name neither.
    assert not set(names) & set(_loosenings())

    store_only = _loosenings(
        store=StoreSettings(
            vault_revocation_attested=True, vault_revocation_attested_reason=_REASON
        )
    )
    assert names[0] in store_only and names[1] not in store_only
    assert f"(reason: {_REASON})" in store_only[names[0]]
    assert "the key provider and the Transit cipher" in store_only[names[0]]

    secrets_only = _loosenings(
        secrets=SecretsSettings(
            vault_revocation_attested=True, vault_revocation_attested_reason=_REASON
        )
    )
    assert names[1] in secrets_only and names[0] not in secrets_only
    assert f"(reason: {_REASON})" in secrets_only[names[1]]
    assert "the connector secret provider's Vault hop" in secrets_only[names[1]]
    # The wording the review asked for: the lever is not built, which is not "cannot exist".
    assert "No CRL lever is built" in secrets_only[names[1]]


# --- the caller census ------------------------------------------------------------------------
#
# The guard's keyword is REQUIRED, so Python refuses a call that leaves it out. But that refusal
# comes only when the call runs, and a literal ``True`` satisfies it. These scans read the source,
# so they hold with no Vault extra installed and before any client is built.

_PACKAGE = Path(__file__).resolve().parent.parent / "messagefoundry"
_MOUNT = "mount_strict_reply_adapter"
_BUILD = "_build_client"
_FLAG = "revocation_attested"
_SETTING = "vault_revocation_attested"

#: Every module that mounts the strict reader, with the settings section its hop's pair is in.
_MOUNTERS = {
    "config/secretprovider_vault.py": "secrets",
    "store/keyprovider_vault.py": "store",
}
#: Every function that builds a Vault client, by module, with what it may pass as the flag:
#: ``setting`` is its own section's ``vault_revocation_attested``, and ``False`` fails closed.
_BUILDERS = {
    ("config/secretprovider_vault.py", "resolve"): "setting",
    ("config/secretprovider_vault.py", "secrets_vault_client"): "False",
    ("store/keyprovider_vault.py", "active_key"): "setting",
    ("store/keyprovider_vault.py", "store_vault_client"): "False",
    ("store/crypto_transit.py", "build_transit_cipher"): "setting",
}


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _mount_problems(source: str, section: str) -> list[str]:
    """What is wrong with each mount call in ``source``: the flag missing, a constant where the
    caller's own flag belongs, or the wrong section."""
    problems = []
    for call in call_sites(parse_source(source), _MOUNT):
        flag = _keyword(call, _FLAG)
        if not (isinstance(flag, ast.Name) and flag.id == _FLAG):
            problems.append(f"line {call.lineno}: {_FLAG} is not the caller's own {_FLAG}")
        named = _keyword(call, "attestation_section")
        if not (isinstance(named, ast.Constant) and named.value == section):
            problems.append(f"line {call.lineno}: attestation_section is not {section!r}")
    return problems


def _build_shape(call: ast.Call) -> str:
    """How a client build passes the flag: ``setting``, ``False``, or what is wrong."""
    flag = _keyword(call, _FLAG)
    if flag is None:
        return "MISSING"
    if isinstance(flag, ast.Attribute) and flag.attr == _SETTING:
        return "setting"
    if isinstance(flag, ast.Constant) and flag.value is False:
        return "False"
    return f"UNEXPECTED {ast.unparse(flag)}"


def _builders(path: Path) -> dict[tuple[str, str], str]:
    tree = parse_source(path.read_text(encoding="utf-8"))
    relative = path.relative_to(_PACKAGE).as_posix()
    return {
        (relative, func.name): _build_shape(call)
        for func in ast.walk(tree)
        if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
        for call in call_sites(func, _BUILD)
    }


def _modules() -> list[Path]:
    modules = sorted(_PACKAGE.rglob("*.py"))
    # 337 modules when tests/test_vault_hop_refusal_marker.py set this floor. A moved package or
    # a changed glob leaves few or none to scan.
    assert len(modules) >= 300, f"the walk found only {len(modules)} module(s) under {_PACKAGE}"
    return modules


def test_every_mount_of_the_strict_reader_passes_its_callers_own_flag() -> None:
    """A new caller that mounts the reader must say whether its hop is attested, from a setting.
    This is what the required keyword buys, checked without running the call."""
    found = {}
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        # Code that calls the name has to spell it, so a file that never does is not parsed.
        if _MOUNT in source and call_sites(parse_source(source), _MOUNT):
            found[path.relative_to(_PACKAGE).as_posix()] = source
    assert sorted(found) == sorted(_MOUNTERS), "a module mounts the reader and is not listed here"
    for relative, source in found.items():
        assert _mount_problems(source, _MOUNTERS[relative]) == [], relative


_SHIPPED_MOUNT = (
    "mount_strict_reply_adapter(client, connector=c, ssl_context_factory=f, "
    'revocation_attested=revocation_attested, attestation_section="store")'
)


@pytest.mark.parametrize(
    ("planted", "problem"),
    [
        # The planted omission: a new client build that mounts the reader and forgets the flag.
        (
            "mount_strict_reply_adapter(client, connector=c, ssl_context_factory=f, "
            'attestation_section="store")',
            "revocation_attested is not",
        ),
        # A literal satisfies Python's required keyword and attests every hop the caller builds.
        (
            _SHIPPED_MOUNT.replace("=revocation_attested,", "=True,"),
            "revocation_attested is not",
        ),
        # The process-wide variable in the per-hop slot is the defect BACKLOG #299 removed.
        (
            _SHIPPED_MOUNT.replace("=revocation_attested,", "=tls_revocation_attested(),"),
            "revocation_attested is not",
        ),
        # The other section's pair would name the wrong lever in the refusal.
        (_SHIPPED_MOUNT.replace('"store"', '"secrets"'), "attestation_section is not 'store'"),
    ],
)
def test_the_mount_scan_can_fail(planted: str, problem: str) -> None:
    """The control for the scan above. The shipped call shape passes it, and each of these does
    not."""
    assert planted != _SHIPPED_MOUNT
    (found,) = _mount_problems(planted, "store")
    assert problem in found
    assert _mount_problems(_SHIPPED_MOUNT, "store") == []


def test_every_vault_client_build_is_listed_and_none_is_a_no_op() -> None:
    """The list of callers. An unknown posture counts as enforcing, so the only way a client
    build could skip the guard is by what it passes as the flag: each passes its own section's
    setting, or ``False`` where no settings are in scope, which fails closed. Never a literal
    ``True``, and never nothing."""
    found: dict[tuple[str, str], str] = {}
    for path in _modules():
        if _BUILD in path.read_text(encoding="utf-8"):
            found.update(_builders(path))
    assert found == _BUILDERS


@pytest.mark.parametrize(
    ("call", "shape"),
    [
        ("_build_client(addr, token)", "MISSING"),
        ("_build_client(addr, token, revocation_attested=True)", "UNEXPECTED True"),
        (
            "_build_client(addr, token, revocation_attested=tls_revocation_attested())",
            "UNEXPECTED tls_revocation_attested()",
        ),
        (
            "_build_client(a, t, revocation_attested=self._settings.vault_revocation_attested)",
            "setting",
        ),
        ("_build_client(a, t, revocation_attested=False)", "False"),
    ],
)
def test_the_build_scan_tells_the_shapes_apart(call: str, shape: str) -> None:
    """The control for the list above: a build that passes nothing, or a literal ``True``, would
    not match the listed shape."""
    (site,) = call_sites(parse_source(call), _BUILD)
    assert _build_shape(site) == shape


def test_the_flag_is_required_at_every_layer() -> None:
    """No default anywhere between the setting and the decision, so leaving the flag out is an
    error at each layer and never a silent ``False`` or ``True``."""
    if not extra_is_installed(OPTIONAL_EXTRAS["vault"]):
        pytest.skip("the [vault] extra is not installed, so strict_requests does not import")
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.store import keyprovider_vault
    from messagefoundry.transports import strict_requests

    for func, names in (
        (strict_requests.mount_strict_reply_adapter, (_FLAG, "attestation_section")),
        (strict_requests.StrictReplyAdapter.__init__, (_FLAG, "attestation_section")),
        (strict_requests._refuse_an_unrevoked_vault_hop, (_FLAG, "attestation_section")),
        (keyprovider_vault._build_client, (_FLAG,)),
        (secretprovider_vault._build_client, (_FLAG,)),
    ):
        parameters = inspect.signature(func).parameters
        for name in names:
            assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY, (func, name)
            assert parameters[name].default is inspect.Parameter.empty, (func, name)
