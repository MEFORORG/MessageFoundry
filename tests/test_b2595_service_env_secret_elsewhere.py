# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An engine secret reaching a Windows service from outside the lists it read (vault BACKLOG
#2595, slice B's other half).

The owner's 2026-10-01 ruling refuses a secret in the environment under ``enforce``, and always
only in the service's own NSSM environment. So a secret other than a store key that reaches a
known service from somewhere else, such as the machine-wide environment, refuses ``serve``,
``supervise`` and the API app factories under ``enforce`` and is named under ``warn``. Where the
service is known and its lists could not be read, such a secret most likely came from them, and
refuses whatever the setting, as a store key there already did. Synthetic values only.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from messagefoundry import serviceenv
from messagefoundry.config.settings import SecurityEnforcement, SecuritySettings
from messagefoundry.serviceenv import (
    DIRECTORY_CLASS_NAMES,
    ServiceEnvironmentRefused,
    ServiceEnvPosture,
    ServiceEnvStatus,
    read_service_env_posture,
    service_env_enforced_refusal,
    service_env_loosenings,
    service_env_refusal,
    service_env_start_refusal,
)
from tests.test_service_env_secrets import (
    _SAMPLES_CONFIG,
    _UNDER_NSSM,
    _Probe,
    _record_loosening_reads,
    _serve,
    _service,
    settings_file,  # noqa: F401 - a fixture the tests below take by name
)

_PASSWORD_VALUE = "synthetic-store-password-value"
_TOKEN_VALUE = "synthetic-vault-token-value"
#: Split so the gitleaks private-key rule reads no PEM key marker in this file.
_PEM_VALUE = "-----BEGIN " + "PRIVATE KEY-----synthetic"


def _value(name: str) -> str:
    """A synthetic value that is a secret for ``name``: the OIDC signing key takes a path too,
    which is no secret, so it gets inline PEM armour."""
    return _PEM_VALUE if name == "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY" else _PASSWORD_VALUE


#: A known service whose lists set nothing secret, with a store password in the engine's own
#: environment, so it came from outside the lists.
_ELSEWHERE = _service(["MEFOR_AI_ENVIRONMENT=prod"], MEFOR_STORE_PASSWORD=_PASSWORD_VALUE)


def _unreadable(**environ: str) -> ServiceEnvPosture:
    probe = _Probe(ancestors=_UNDER_NSSM, services={100: "MessageFoundry"}, unreadable=True)
    return read_service_env_posture(probe=probe, environ=environ)


def _names(posture: ServiceEnvPosture) -> list[str]:
    return [name for name, _risk in service_env_loosenings(posture)]


# --- the reading ------------------------------------------------------------------------------------


def test_the_reading_keeps_each_secret_name_in_the_environment_and_no_value() -> None:
    environ = {name: _value(name) for name in DIRECTORY_CLASS_NAMES}
    posture = _service([], **environ)
    assert posture.others_in_environment == DIRECTORY_CLASS_NAMES
    assert posture.others_from_elsewhere == DIRECTORY_CLASS_NAMES
    assert _PASSWORD_VALUE not in repr(posture)
    assert _PEM_VALUE not in repr(posture)


def test_a_blank_secret_in_the_environment_is_not_read_as_set() -> None:
    posture = _service([], MEFOR_STORE_PASSWORD="  ")
    assert posture.others_in_environment == ()
    assert service_env_enforced_refusal(posture) is None


def test_a_secret_the_lists_set_is_not_from_elsewhere() -> None:
    """The list refusal covers it, whatever the setting, so the enforce-only one does not repeat
    it."""
    posture = _service(
        [f"MEFOR_STORE_PASSWORD={_PASSWORD_VALUE}"], MEFOR_STORE_PASSWORD=_PASSWORD_VALUE
    )
    assert posture.others_from_elsewhere == ()
    assert service_env_refusal(posture) is not None
    assert service_env_enforced_refusal(posture) is None
    assert "secret_from_outside_service_lists" not in _names(posture)


# --- a known service whose lists could not be read --------------------------------------------------


@pytest.mark.parametrize("name", DIRECTORY_CLASS_NAMES)
def test_an_unreadable_list_refuses_another_secret_in_the_environment(name: str) -> None:
    """Before this change only a store key was read here, so the secret was neither refused nor
    named."""
    posture = _unreadable(**{name: _value(name)})
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert f"{name} reaches this engine through its environment" in refusal
    assert "could not be read (the registry key of service 'MessageFoundry'" in refusal
    assert refusal.endswith('[security].enforcement = "warn" does not change this refusal')
    assert _PASSWORD_VALUE not in refusal and _PEM_VALUE not in refusal
    assert "secret_in_service_environment" in _names(posture)


def test_an_unreadable_list_never_says_the_lists_set_no_directory() -> None:
    """The lists were not read, so the remedy cannot say what they hold, and says nothing about
    adding the directory back; it still says where the secret goes."""
    refusal = service_env_refusal(_unreadable(MEFOR_STORE_PASSWORD=_PASSWORD_VALUE))
    assert refusal is not None
    assert "set no MEFOR_SECRETS_DIRECTORY" not in refusal
    assert "back to the service's AppEnvironmentExtra" not in refusal
    assert "Put MEFOR_STORE_PASSWORD in the secrets directory" in refusal


def test_an_unreadable_list_names_a_key_and_a_secret_together() -> None:
    refusal = service_env_refusal(
        _unreadable(MEFOR_STORE_ENCRYPTION_KEY="x" * 44, MEFOR_STORE_VAULT_TOKEN=_TOKEN_VALUE)
    )
    assert refusal is not None
    assert "MEFOR_STORE_ENCRYPTION_KEY, MEFOR_STORE_VAULT_TOKEN reaches this engine" in refusal
    assert "messagefoundry protect-key" in refusal
    assert "Put MEFOR_STORE_VAULT_TOKEN in the secrets directory" in refusal
    assert _TOKEN_VALUE not in refusal


def test_an_unknown_service_is_still_not_refused() -> None:
    """No service found: the start may be a shell's, where the environment is a way in."""
    probe = _Probe(ancestors=_UNDER_NSSM, services={})
    posture = read_service_env_posture(probe=probe, environ={"MEFOR_STORE_PASSWORD": "x"})
    assert posture.status is ServiceEnvStatus.UNOBSERVABLE
    assert service_env_refusal(posture) is None
    assert service_env_enforced_refusal(posture) is None
    assert _names(posture) == ["service_environment_unobservable"]


def test_a_shell_is_not_refused() -> None:
    posture = read_service_env_posture(
        probe=_Probe(ancestors=[(9, "python.exe"), (8, "pwsh.exe")]),
        environ={"MEFOR_STORE_PASSWORD": _PASSWORD_VALUE},
    )
    assert posture.status is ServiceEnvStatus.NOT_A_SERVICE
    assert service_env_refusal(posture) is None
    assert service_env_enforced_refusal(posture) is None
    assert _names(posture) == []


# --- a known service, from outside its lists ---------------------------------------------------------


@pytest.mark.parametrize("name", DIRECTORY_CLASS_NAMES)
def test_a_secret_from_outside_the_lists_is_refused_under_enforce_and_named(name: str) -> None:
    """Before this change it was neither refused nor named."""
    posture = _service(["MEFOR_AI_ENVIRONMENT=prod"], **{name: _value(name)})
    assert service_env_refusal(posture) is None
    refusal = service_env_enforced_refusal(posture)
    assert refusal is not None
    assert refusal.startswith(f"{name} reaches the Windows service 'MessageFoundry'")
    assert "machine-wide environment" in refusal
    assert "names this as secret_from_outside_service_lists" in refusal
    assert refusal.endswith("so move the secret instead")
    assert "The other secrets: a secrets directory" in refusal
    assert _PASSWORD_VALUE not in refusal and _PEM_VALUE not in refusal
    entries = dict(service_env_loosenings(posture))
    assert name in entries["secret_from_outside_service_lists"]
    assert "secret_in_service_environment" not in entries
    assert _PASSWORD_VALUE not in str(entries)


def _supervise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    posture: ServiceEnvPosture,
    *,
    warn: bool,
    service_config: str,
) -> tuple[int, list[str]]:
    from messagefoundry import __main__ as cli

    spawned: list[str] = []

    async def fake_supervise(config: str, **kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.chdir(tmp_path)
    if warn:
        monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    else:
        monkeypatch.delenv("MEFOR_SECURITY_ENFORCEMENT", raising=False)
    monkeypatch.setattr(serviceenv, "service_env_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    args = argparse.Namespace(
        config=str(_SAMPLES_CONFIG),
        db=str(tmp_path / "mefor.db"),
        base_port=8765,
        env="dev",
        service_config=service_config,
        project_root=str(tmp_path),
    )
    return cli._supervise(args), spawned


def test_serve_refuses_a_secret_from_outside_the_lists_under_enforce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,  # noqa: F811
) -> None:
    read = _record_loosening_reads(monkeypatch)
    rc = _serve(tmp_path, monkeypatch, _ELSEWHERE, warn=False, service_config=settings_file)
    err = capsys.readouterr().err
    assert rc == 2
    assert "refusing to start: MEFOR_STORE_PASSWORD reaches the Windows service" in err
    assert _PASSWORD_VALUE not in err
    assert not read
    assert not any(tmp_path.iterdir()), sorted(p.name for p in tmp_path.iterdir())


def test_serve_names_a_secret_from_outside_the_lists_under_warn_and_starts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,  # noqa: F811
) -> None:
    rc = _serve(tmp_path, monkeypatch, _ELSEWHERE, warn=True, service_config=settings_file)
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert "refusing to start: MEFOR_STORE_PASSWORD" not in captured.err
    # serve installs its own stdout handler, so the loosening line is read from stdout.
    assert "secret_from_outside_service_lists (" in captured.out
    assert _PASSWORD_VALUE not in captured.out + captured.err


def test_supervise_refuses_a_secret_from_outside_the_lists_under_enforce(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,  # noqa: F811
) -> None:
    read = _record_loosening_reads(monkeypatch)
    rc, spawned = _supervise(
        tmp_path, monkeypatch, _ELSEWHERE, warn=False, service_config=settings_file
    )
    err = capsys.readouterr().err
    assert rc == 2 and not spawned
    assert "MEFOR_STORE_PASSWORD reaches the Windows service 'MessageFoundry'" in err
    assert "refusing to start the fleet" in err
    assert not read


def _build(factory: str, tmp_path: Path, enforcement: SecurityEnforcement) -> object:
    from messagefoundry.api.app import create_app, create_managed_app
    from messagefoundry.config.settings import EgressSettings

    security = SecuritySettings(enforcement=enforcement)
    if factory == "create_app":
        return create_app(allow_no_auth=True, security_settings=security)
    return create_managed_app(
        db_path=tmp_path / "embedded.db",
        egress_settings=EgressSettings(deny_by_default=False),
        allow_no_auth=True,
        security_settings=security,
    )


@pytest.mark.parametrize("factory", ["create_app", "create_managed_app"])
def test_an_embedded_app_refuses_under_enforce_and_builds_under_warn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factory: str
) -> None:
    monkeypatch.setattr("messagefoundry.api.app.service_env_posture", lambda: _ELSEWHERE)
    (tmp_path / "enforce").mkdir()
    with pytest.raises(ServiceEnvironmentRefused) as raised:
        _build(factory, tmp_path / "enforce", SecurityEnforcement.ENFORCE)
    refusal = service_env_enforced_refusal(_ELSEWHERE)
    assert str(raised.value) == f"{factory}: refusing to start: {refusal}"
    (tmp_path / "warn").mkdir()
    _build(factory, tmp_path / "warn", SecurityEnforcement.WARN)


# --- repair round 1 (code review round-862b5a4ac8) ---------------------------------------------------

_KEY_PATH = "C:/keys/oidc.pem"


def test_an_oidc_signing_key_path_in_the_lists_and_the_environment_is_not_a_secret() -> None:
    """NSSM puts a listed value in the engine's environment too. A key path is no secret in the
    lists (``_path_form``), so the environment reading judges it the same way, and the engine
    neither says the lists do not set it nor refuses."""
    posture = _service(
        [f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY={_KEY_PATH}"],
        MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=_KEY_PATH,
    )
    assert posture.others_in_environment == ()
    assert service_env_start_refusal(posture, enforcing=True) is None
    assert "secret_from_outside_service_lists" not in _names(posture)


def test_an_oidc_signing_key_path_with_unreadable_lists_is_not_refused() -> None:
    posture = _unreadable(MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=_KEY_PATH)
    assert service_env_start_refusal(posture, enforcing=True) is None


def test_an_inline_oidc_signing_key_from_elsewhere_is_still_refused() -> None:
    posture = _service([], MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=_PEM_VALUE)
    assert posture.others_from_elsewhere == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)


def test_one_start_names_a_listed_secret_and_one_from_elsewhere_together() -> None:
    posture = _service(
        [f"MEFOR_STORE_PASSWORD={_PASSWORD_VALUE}"],
        MEFOR_STORE_PASSWORD=_PASSWORD_VALUE,
        MEFOR_AI_API_KEY=_TOKEN_VALUE,
    )
    refusal = service_env_start_refusal(posture, enforcing=True)
    assert refusal is not None
    assert "MEFOR_STORE_PASSWORD (in Parameters" in refusal
    assert "MEFOR_AI_API_KEY reaches the Windows service" in refusal
    assert service_env_start_refusal(posture, enforcing=False) == service_env_refusal(posture)


def test_an_unreadable_list_says_to_remove_it_from_the_machine_wide_environment_too() -> None:
    refusal = service_env_refusal(_unreadable(MEFOR_STORE_PASSWORD=_PASSWORD_VALUE))
    assert refusal is not None
    assert "may come from the machine-wide environment instead" in refusal


def test_create_managed_app_honours_an_explicit_warn_dial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``create_managed_app`` passes its dial on to ``create_app``, which runs the check again, so
    an explicit ``security_enforcement`` wins over ``security_settings`` there too."""
    from messagefoundry.api.app import create_managed_app
    from messagefoundry.config.settings import EgressSettings

    monkeypatch.setattr("messagefoundry.api.app.service_env_posture", lambda: _ELSEWHERE)
    create_managed_app(
        db_path=tmp_path / "embedded.db",
        egress_settings=EgressSettings(deny_by_default=False),
        allow_no_auth=True,
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.ENFORCE),
        security_enforcement=SecurityEnforcement.WARN,
    )
    with pytest.raises(ServiceEnvironmentRefused, match="^create_managed_app: "):
        create_managed_app(
            db_path=tmp_path / "embedded2.db",
            egress_settings=EgressSettings(deny_by_default=False),
            allow_no_auth=True,
            security_settings=SecuritySettings(enforcement=SecurityEnforcement.WARN),
            security_enforcement=SecurityEnforcement.ENFORCE,
        )
