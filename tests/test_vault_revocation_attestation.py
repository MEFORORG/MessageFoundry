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
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from messagefoundry.checks import CheckResult

_REASON = "the Vault server certificate lives 24 hours (synthetic)"
_PAIR: dict[str, Any] = {
    "vault_revocation_attested": True,
    "vault_revocation_attested_reason": _REASON,
}
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
#: Every call that builds a Vault client: module, enclosing function, and what it passes as the
#: flag. ``setting`` is the ``vault_revocation_attested`` of the settings object that function
#: holds. ``parameter`` is the function's own required ``revocation_attested``, which its caller
#: fills; :data:`_CLIENT_CALLERS` lists those callers. ``False`` fails closed, and no shipped
#: build passes it. A list, so a second call in one function is a second row.
_BUILDERS = sorted(
    [
        ("config/secretprovider_vault.py", "resolve", "setting"),
        ("config/secretprovider_vault.py", "secrets_vault_client", "parameter"),
        ("store/crypto_transit.py", "build_transit_cipher", "setting"),
        ("store/keyprovider_vault.py", "active_key", "setting"),
        ("store/keyprovider_vault.py", "store_vault_client", "parameter"),
    ]
)
#: The two ``check-privileges`` clients, with the settings section each one's hop is in. Every
#: use of one, as a call or handed to ``functools.partial``, must pass that section's own pair.
_CLIENTS = {"secrets_vault_client": "secrets", "store_vault_client": "store"}
#: Every use of a ``check-privileges`` client: module and client. Each is checked for its pair.
_CLIENT_CALLERS = sorted(
    [
        ("privilege_probes.py", "secrets_vault_client"),
        ("privilege_probes.py", "store_vault_client"),
    ]
)
#: The two spellings of "the settings object this function holds". Each module holds only its own
#: section's settings, so one of these names that section's pair.
_OWN_SETTING = ("self._settings.vault_revocation_attested", "settings.vault_revocation_attested")


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
    if ast.unparse(flag) in _OWN_SETTING:
        return "setting"
    if isinstance(flag, ast.Name) and flag.id == _FLAG:
        return "parameter"
    if isinstance(flag, ast.Constant) and flag.value is False:
        return "False"
    return f"UNEXPECTED {ast.unparse(flag)}"


def _client_uses(source: str, relative: str) -> list[tuple[str, str, str, str]]:
    """One row per use of a ``check-privileges`` client in ``source``: where, which client, and
    the flag and reason it is given. A use is a call, or the client handed to another call as
    its first argument with the client's own keywords after it, as ``functools.partial`` takes
    it. Any other mention of the name is a row with nothing given, so it cannot pass."""
    tree = parse_source(source)
    rows, counted = [], set()
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        target = call.func
        if not (isinstance(target, ast.Name) and target.id in _CLIENTS) and call.args:
            target = call.args[0]
        if isinstance(target, ast.Name) and target.id in _CLIENTS:
            counted.add(id(target))
            flag, reason = _keyword(call, _FLAG), _keyword(call, "revocation_reason")
            rows.append(
                (
                    relative,
                    target.id,
                    ast.unparse(flag) if flag is not None else "MISSING",
                    ast.unparse(reason) if reason is not None else "MISSING",
                )
            )
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Name)
            and node.id in _CLIENTS
            and id(node) not in counted
            and isinstance(node.ctx, ast.Load)
        ):
            rows.append((relative, node.id, "NOT GIVEN", "NOT GIVEN"))
    return rows


def _builders(source: str, relative: str) -> list[tuple[str, str, str]]:
    """One row per client build in ``source``: where it is, and the shape it passes.

    Every call is a row. A call outside any function is listed under ``<module>``, and two calls
    in one function are two rows, so neither can hide behind a listed one."""
    tree = parse_source(source)
    inside = {
        id(call): func.name
        for func in ast.walk(tree)
        if isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef)
        for call in call_sites(func, _BUILD)
    }
    return [
        (relative, inside.get(id(call), "<module>"), _build_shape(call))
        for call in call_sites(tree, _BUILD)
    ]


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
    found: list[tuple[str, str, str]] = []
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        if _BUILD in source:
            found.extend(_builders(source, path.relative_to(_PACKAGE).as_posix()))
    assert sorted(found) == _BUILDERS


def test_each_check_privileges_client_is_given_its_own_sections_pair() -> None:
    """``check-privileges`` probes a Vault through the client the provider builds, so it must be
    held to the same rule with the same attestation. Each client is given the flag and the
    reason of the section its hop is in, read off the loaded settings.

    RED before this change: both clients passed ``False``, so the command could not probe an
    off-box ``https://`` Vault, and its refusal named a flag that path ignored.
    Mutation: give the store client ``settings.secrets.vault_revocation_attested``."""
    uses: list[tuple[str, str, str, str]] = []
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        relative = path.relative_to(_PACKAGE).as_posix()
        if any(name in source for name in _CLIENTS):
            # The module that defines a client names it once, in its `def`, which is no use.
            uses.extend(_client_uses(source, relative))
    assert sorted((relative, client) for relative, client, _, _ in uses) == _CLIENT_CALLERS
    for relative, client, flag, reason in uses:
        pair = f"settings.{_CLIENTS[client]}.vault_revocation_attested"
        assert (flag, reason) == (pair, f"{pair}_reason"), (relative, client)


@pytest.mark.parametrize(
    ("planted", "flag"),
    [
        # A literal attests every Vault the command is ever pointed at.
        ("partial(store_vault_client, revocation_attested=True, posture=posture)", "True"),
        # The other section's pair: the secrets hop's review does not cover the store's Vault.
        (
            "partial(store_vault_client, "
            "revocation_attested=settings.secrets.vault_revocation_attested)",
            "settings.secrets.vault_revocation_attested",
        ),
        # The process-wide variable in the per-hop slot is the defect BACKLOG #299 removed.
        (
            "store_vault_client(a, t, revocation_attested=tls_revocation_attested())",
            "tls_revocation_attested()",
        ),
        ("store_vault_client(a, t)", "MISSING"),
        # Handed on with nothing bound, as this file's own earlier shape did.
        ("read_vault_token(token, address, store_vault_client, required)", "NOT GIVEN"),
    ],
)
def test_the_client_scan_can_fail(planted: str, flag: str) -> None:
    """The control for the scan above: five shapes it must not pass, and the shipped one."""
    ((_, client, found, _),) = _client_uses(planted, "planted.py")
    assert (client, found) == ("store_vault_client", flag)
    assert found != "settings.store.vault_revocation_attested"
    shipped = (
        "partial(store_vault_client, "
        "revocation_attested=settings.store.vault_revocation_attested, "
        "revocation_reason=settings.store.vault_revocation_attested_reason, posture=posture)"
    )
    assert _client_uses(shipped, "planted.py") == [
        (
            "planted.py",
            "store_vault_client",
            "settings.store.vault_revocation_attested",
            "settings.store.vault_revocation_attested_reason",
        )
    ]


def _reason_problems(source: str) -> list[str]:
    """Each client build in ``source`` that passes a setting as its flag and not that same
    object's reason."""
    problems = []
    for call in call_sites(parse_source(source), _BUILD):
        flag = _keyword(call, _FLAG)
        if flag is None or ast.unparse(flag) not in _OWN_SETTING:
            continue
        reason = _keyword(call, "revocation_reason")
        wanted = f"{ast.unparse(flag)}_reason"
        if reason is None or ast.unparse(reason) != wanted:
            problems.append(f"line {call.lineno}: revocation_reason is not {wanted}")
    return problems


def test_every_build_that_passes_its_setting_passes_that_settings_reason() -> None:
    """An attested crossing logs its reason, so each build hands down the reason that sits
    beside the flag it passes. Without it the line would read ``(none provided)``."""
    checked = 0
    for path in _modules():
        source = path.read_text(encoding="utf-8")
        if _BUILD in source:
            assert _reason_problems(source) == [], path.relative_to(_PACKAGE).as_posix()
            checked += sum(shape == "setting" for _, _, shape in _builders(source, ""))
    # The control that the scan read something: the builds listed with a setting.
    assert checked == sum(shape == "setting" for _, _, shape in _BUILDERS)
    # And that it can fail: a build with the flag and no reason, and one with another's reason.
    flag = "revocation_attested=self._settings.vault_revocation_attested"
    assert len(_reason_problems(f"_build_client(a, t, {flag})")) == 1
    other = "revocation_reason=other.vault_revocation_attested_reason"
    assert len(_reason_problems(f"_build_client(a, t, {flag}, {other})")) == 1
    own = "revocation_reason=self._settings.vault_revocation_attested_reason"
    assert _reason_problems(f"_build_client(a, t, {flag}, {own})") == []


def test_the_build_census_sees_a_call_a_listed_one_could_hide() -> None:
    """The control for the census, from the second review round. Three plants that a census keyed
    by function name would have missed: a build outside any function, a literal ``True`` ahead of
    the real build in a listed function, and another object's setting."""
    planted = (
        "client = _build_client(a, t, revocation_attested=True)\n"
        "def active_key(self):\n"
        "    _build_client(a, t, revocation_attested=True)\n"
        "    return _build_client(a, t, revocation_attested=self._settings.vault_revocation_attested)\n"
        "def resolve(self, ref):\n"
        "    return _build_client(a, t, revocation_attested=other.vault_revocation_attested)\n"
    )
    assert sorted(_builders(planted, "planted.py")) == [
        ("planted.py", "<module>", "UNEXPECTED True"),
        ("planted.py", "active_key", "UNEXPECTED True"),
        ("planted.py", "active_key", "setting"),
        ("planted.py", "resolve", "UNEXPECTED other.vault_revocation_attested"),
    ]


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
        ("_build_client(a, t, revocation_attested=revocation_attested)", "parameter"),
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
        (keyprovider_vault.store_vault_client, (_FLAG,)),
        (secretprovider_vault.secrets_vault_client, (_FLAG,)),
    ):
        parameters = inspect.signature(func).parameters
        for name in names:
            assert parameters[name].kind is inspect.Parameter.KEYWORD_ONLY, (func, name)
            assert parameters[name].default is inspect.Parameter.empty, (func, name)


# --- the check line ---------------------------------------------------------------------------

_LEG = "vault-revocation-attested"
_ATTESTATION_ENV = tuple(
    f"MEFOR_{section}_VAULT_REVOCATION_ATTESTED{suffix}"
    for section in ("STORE", "SECRETS")
    for suffix in ("", "_REASON")
)


def _checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str | None) -> CheckResult:
    """The leg's own result for a service file holding ``toml``, or for no service file."""
    from messagefoundry.checks import _check_vault_revocation_attested

    for name in (*_ATTESTATION_ENV, "MEFOR_AI_ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    if toml is None:
        return _check_vault_revocation_attested(tmp_path, suppress_search=True)
    service = tmp_path / "service.toml"
    service.write_text(toml, encoding="utf-8")
    return _check_vault_revocation_attested(tmp_path, service_config=service)


def _toml(*sections: str, reason: bool = True) -> str:
    lines = []
    for section in sections:
        lines += [f"[{section}]", "vault_revocation_attested = true"]
        if reason:
            lines.append(f'vault_revocation_attested_reason = "{_REASON}"')
    return "\n".join(lines) + "\n"


def test_check_says_none_when_no_vault_hop_is_attested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It says so rather than going quiet: an absent line reads like a check that did not run.
    Mutation: list a section whether or not its flag is set."""
    result = _checked(tmp_path, monkeypatch, "[store]\n")
    assert (result.ok, result.required, result.skipped) == (True, False, False)
    assert result.detail == "no Vault hop's revocation is attested"


@pytest.mark.parametrize(
    ("sections", "count"), [(("store",), 1), (("secrets",), 1), (("store", "secrets"), 2)]
)
def test_check_lists_each_attested_vault_hop_with_its_reason(
    sections: tuple[str, ...], count: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The names are the loosening report's own, so the two surfaces cannot disagree.
    Mutation: read ``settings.store`` for both sections."""
    result = _checked(tmp_path, monkeypatch, _toml(*sections))
    assert (result.ok, result.required, result.skipped) == (True, False, False)
    assert f"{count} Vault attestation(s)" in result.detail
    for section in ("store", "secrets"):
        entry = f'{section}.vault_revocation_attested ("{_REASON}")'
        assert (entry in result.detail) is (section in sections)
        if section in sections:
            store = StoreSettings(**_PAIR) if section == "store" else None
            secrets = SecretsSettings(**_PAIR) if section == "secrets" else None
            assert f"{section}.vault_revocation_attested" in _loosenings(
                store=store, secrets=secrets
            )


def test_check_fails_a_flag_with_no_reason_and_skips_a_bare_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A flag with no reason is refused by the settings load, and a present but refused file is
    a failure, not a skip. With no service file at all there is nothing to read."""
    refused = _checked(tmp_path, monkeypatch, _toml("store", reason=False))
    assert (refused.ok, refused.skipped) == (False, False)
    assert "settings did not load" in refused.detail
    bare = _checked(tmp_path, monkeypatch, None)
    assert (bare.ok, bare.skipped) == (True, True)


def test_check_runs_the_vault_attestation_leg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The leg is one of ``check``'s, in the report a CI gate reads.
    Mutation: drop it from the list ``run_checks`` builds."""
    from messagefoundry.checks import run_checks

    for name in (*_ATTESTATION_ENV, "MEFOR_AI_ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / "config"
    config.mkdir()
    service = tmp_path / "service.toml"
    service.write_text(_toml("secrets"), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    report = run_checks(config, run_lint=False, service_config=service)
    (result,) = [r for r in report.results if r.name == _LEG]
    assert f'secrets.vault_revocation_attested ("{_REASON}")' in result.detail
