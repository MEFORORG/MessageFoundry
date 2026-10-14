# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Secrets in the engine's own Windows service environment (vault BACKLOG #2595, #2601).

NSSM keeps a service's environment list in a registry key any local user can read. A store key
there refuses ``serve`` and ``supervise`` under every enforcement setting. Another engine secret
there is named as a loosening. A store key reaching a service through its environment at all is
named too (key-custody slice S2a). The host is reached through a probe, so every test here runs
on every platform; the Windows probe itself is exercised on a Windows host only.
"""

from __future__ import annotations

import argparse
import inspect
import re
import sys
import types
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from messagefoundry import serviceenv
from messagefoundry.config.settings import (
    _FILE_SECRET_KEYS,
    ENFORCEABLE_SECRET_EXPIRY_CLASSES,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.serviceenv import (
    KEY_CLASS_NAMES,
    LOOSENING_CLASS_NAMES,
    ServiceEnvPosture,
    ServiceEnvStatus,
    missing_service_config_refusal,
    read_service_env_posture,
    service_env_loosenings,
    service_env_refusal,
)

#: Synthetic stand-ins. Never a real key: the tests check that no value is kept, by searching for
#: these strings in what the reading returns.
_KEY_VALUE = "synthetic-store-key-value"
_PASSWORD_VALUE = "synthetic-store-password-value"


@dataclass
class _Probe:
    """A host with a chosen process tree, service and NSSM list."""

    ancestors: list[tuple[int, str]] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    entries: list[str] = field(default_factory=list)
    unreadable: bool = False
    asked: list[str] = field(default_factory=list)

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        return iter(self.ancestors)

    def service_at(self, pid: int) -> str | None:
        return self.services.get(pid)

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        self.asked.append(service_name)
        if self.unreadable:
            raise PermissionError("access denied")
        return [("Parameters\\AppEnvironmentExtra", entry) for entry in self.entries]


#: The shape the installer makes: NSSM starts the virtual environment's python.exe, which starts
#: the base interpreter as its child, so nssm.exe is the grandparent.
_UNDER_NSSM = [(200, "python.exe"), (100, "nssm.exe"), (4, "services.exe")]


def _service(entries: list[str], **environ: str) -> ServiceEnvPosture:
    probe = _Probe(ancestors=_UNDER_NSSM, services={100: "MessageFoundry"}, entries=entries)
    return read_service_env_posture(probe=probe, environ=environ)


def _names(posture: ServiceEnvPosture) -> list[str]:
    return [name for name, _risk in service_env_loosenings(posture)]


# --- the reading -----------------------------------------------------------------------------------


def test_a_process_with_no_nssm_ancestor_is_not_a_service() -> None:
    probe = _Probe(ancestors=[(300, "pwsh.exe"), (4, "explorer.exe")], services={300: "Other"})
    posture = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert posture == ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE)
    assert probe.asked == [], "a process that is not a service must not read any service's key"
    assert service_env_refusal(posture) is None
    assert service_env_loosenings(posture) == []


def test_the_nearest_nssm_ancestor_names_the_service_whose_list_is_read() -> None:
    probe = _Probe(
        ancestors=[(300, "python.exe"), (200, "python.exe"), (100, "NSSM.EXE")],
        services={100: "MessageFoundry-Test"},
        entries=["MEFOR_AI_ENVIRONMENT=prod"],
    )
    posture = read_service_env_posture(probe=probe, environ={})
    assert posture.status is ServiceEnvStatus.OBSERVED
    assert posture.service_name == "MessageFoundry-Test"
    assert probe.asked == ["MessageFoundry-Test"]
    assert posture.listed == ("MEFOR_AI_ENVIRONMENT",)


def test_the_reading_keeps_names_and_never_a_value() -> None:
    posture = _service(
        [f"MEFOR_STore_Encryption_Key={_KEY_VALUE}", f"mefor_store_password={_PASSWORD_VALUE}"],
        MEFOR_STORE_ENCRYPTION_KEY=_KEY_VALUE,
    )
    assert posture.listed == ("MEFOR_STORE_ENCRYPTION_KEY", "MEFOR_STORE_PASSWORD")
    rendered = (
        repr(posture)
        + "".join(risk for _name, risk in service_env_loosenings(posture))
        + str(service_env_refusal(posture))
    )
    assert _KEY_VALUE not in rendered
    assert _PASSWORD_VALUE not in rendered


def test_every_name_printed_is_a_constant_and_never_a_registry_string() -> None:
    """The registry decides only WHICH constant prints. In a loosening or a refusal line, a name
    the engine does not know never prints, and a known one prints as the module's own constant,
    not the registry's spelling. ``posture.listed`` and ``sources`` keep the registry's names."""
    known = (*KEY_CLASS_NAMES, *LOOSENING_CLASS_NAMES)
    posture = _service(
        [f"{name.lower()}=-----BEGIN x" for name in known]
        + ["MEFOR_STORE_PASSWORDX=x", "mefor_unknown_thing=x"],
        MEFOR_STORE_ENCRYPTION_KEY=_KEY_VALUE,
    )
    for name in (*posture.listed_keys, *posture.listed_loosening_names):
        assert any(name is constant for constant in known), name
    printed = "".join(risk for _name, risk in service_env_loosenings(posture)) + str(
        service_env_refusal(posture)
    )
    assert set(re.findall(r"MEFOR_[A-Z_]+", printed, flags=re.IGNORECASE)) == set(known)


#: A stand-in for the identifier words CodeQL's ``py/clear-text-logging-sensitive-data`` takes as
#: sensitive by name alone. It is not CodeQL's own pattern, and nothing checks it against the
#: query, so an alert it misses can still come back in CI.
_SENSITIVE_IDENTIFIER = re.compile(
    r"secret|trusted|pass(wd|word|code|phrase)|token|private|cert"
    r"|acc(ou)?nt|user_?(name|id)|session_?(id|key)",
    re.IGNORECASE,
)


def _code_names(code: types.CodeType) -> set[str]:
    """The local, cell, global and attribute names in ``code`` and in the functions and
    comprehensions nested in it."""
    names = set(code.co_varnames) | set(code.co_cellvars) | set(code.co_names)
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            names |= _code_names(const)
    return names


def test_no_identifier_in_the_module_reads_as_a_secret_to_codeql() -> None:
    """The printed lines carry names only. An identifier that reads as a secret makes CodeQL
    report each line as a secret logged in clear text, as it did on PR 2238. The walk covers
    this module's functions, methods, static and class methods, and properties, so a new one is
    covered too. It does not cover the callers that print the lines."""
    namespaces: list[Mapping[str, object]] = [vars(serviceenv)]
    namespaces += [
        vars(obj)
        for obj in vars(serviceenv).values()
        if inspect.isclass(obj) and obj.__module__ == serviceenv.__name__
    ]
    identifiers: set[str] = set()
    walked: set[str] = set()
    for namespace in namespaces:
        for name, obj in namespace.items():
            if name.startswith("__"):
                continue
            identifiers.add(name)
            fn: object
            if isinstance(obj, property):
                fn = obj.fget
            elif isinstance(obj, (staticmethod, classmethod)):
                fn = obj.__func__
            else:
                fn = obj
            if callable(fn):
                fn = inspect.unwrap(fn)  # a decorator such as functools.cache hides the body
            if inspect.isfunction(fn) and fn.__module__ == serviceenv.__name__:
                identifiers |= _code_names(fn.__code__)
                walked.add(fn.__qualname__)
    # A control for each kind of member the module has today: a function, a method, a property.
    assert {
        "service_env_loosenings",
        "ServiceEnvPosture.named_with_source",
        "ServiceEnvPosture.listed_loosening_names",
    } <= walked, sorted(walked)
    assert not sorted(name for name in identifiers if _SENSITIVE_IDENTIFIER.search(name))


def test_a_name_set_to_nothing_is_not_listed() -> None:
    posture = _service(["MEFOR_STORE_ENCRYPTION_KEY=", "MEFOR_STORE_PASSWORD=   ", "=orphan"])
    assert posture.listed == ()
    assert service_env_refusal(posture) is None


def test_a_service_that_cannot_be_found_is_named_and_not_refused() -> None:
    probe = _Probe(ancestors=_UNDER_NSSM, services={})
    posture = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert posture.status is ServiceEnvStatus.UNOBSERVABLE
    assert "no service runs at nssm.exe process 100" in posture.detail
    assert service_env_refusal(posture) is None
    assert _names(posture) == ["service_environment_unobservable"]


def test_a_known_service_whose_lists_cannot_be_read_refuses_a_key_in_the_environment() -> None:
    """The key most likely came from the lists the engine could not read, so it is refused as a
    listed key would be. With no key in the environment, the start goes on and is named."""
    probe = _Probe(ancestors=_UNDER_NSSM, services={100: "MessageFoundry"}, unreadable=True)
    keyed = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert keyed.status is ServiceEnvStatus.UNOBSERVABLE
    assert "'MessageFoundry' could not be read: access denied" in keyed.detail
    refusal = service_env_refusal(keyed)
    assert refusal is not None and "MEFOR_STORE_ENCRYPTION_KEY reaches this engine" in refusal
    keyless = read_service_env_posture(probe=probe, environ={})
    assert service_env_refusal(keyless) is None
    assert _names(keyless) == ["service_environment_unobservable"]


def test_a_probe_that_raises_is_unobservable_and_never_stops_the_reading() -> None:
    class _Broken(_Probe):
        def ancestor_images(self) -> Iterator[tuple[int, str]]:
            raise OSError("snapshot failed")

    posture = read_service_env_posture(
        probe=_Broken(), environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert posture.status is ServiceEnvStatus.UNOBSERVABLE
    assert "snapshot failed" in posture.detail
    assert service_env_refusal(posture) is None
    # No service is known, so the key may be a shell's: only the failed read is named.
    assert _names(posture) == ["service_environment_unobservable"]


def test_nssm_above_a_wrapper_is_named_and_neither_read_nor_refused() -> None:
    """NSSM registered to start ``cmd.exe``, and a shell inside an unrelated NSSM service, look
    the same from the engine. Neither is read as the engine's own service, and both are named."""
    probe = _Probe(
        ancestors=[(300, "python.exe"), (250, "cmd.exe"), (100, "nssm.exe")],
        services={100: "BuildAgent"},
        entries=[f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}"],
    )
    posture = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert posture.status is ServiceEnvStatus.UNOBSERVABLE
    assert "is above cmd.exe" in posture.detail
    assert probe.asked == []
    assert service_env_refusal(posture) is None
    assert _names(posture) == ["service_environment_unobservable"]


def test_a_walk_that_fails_above_a_shell_reads_as_the_shell() -> None:
    class _FailsAboveShell(_Probe):
        def ancestor_images(self) -> Iterator[tuple[int, str]]:
            yield 300, "pwsh.exe"
            raise OSError("access denied")

    posture = read_service_env_posture(probe=_FailsAboveShell(), environ={})
    assert posture.status is ServiceEnvStatus.NOT_A_SERVICE


def test_the_messagefoundry_launcher_may_sit_between_nssm_and_the_engine() -> None:
    probe = _Probe(
        ancestors=[(300, "messagefoundry.exe"), (100, "nssm.exe")],
        services={100: "MessageFoundry"},
        entries=[f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}"],
    )
    assert service_env_refusal(read_service_env_posture(probe=probe, environ={})) is not None


def test_an_oidc_signing_key_path_is_not_a_secret_but_the_inline_key_is() -> None:
    path = _service(["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:/keys/oidc.pem"])
    assert path.listed == ()
    inline = _service(["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=-----BEGIN PRIVATE KEY----- x"])
    assert inline.listed_loosening_names == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)


def test_off_windows_the_host_reading_is_not_a_service() -> None:
    """With no probe the host decides. Off Windows there is no NSSM to find. On Windows the
    test process has no nssm.exe ancestor either, so both read the same."""
    assert read_service_env_posture().status is ServiceEnvStatus.NOT_A_SERVICE


# --- the refusal -----------------------------------------------------------------------------------


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_a_store_key_in_the_nssm_list_refuses(key: str) -> None:
    posture = _service([f"{key}={_KEY_VALUE}", "MEFOR_AI_ENVIRONMENT=prod"])
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert f"{key} (in Parameters\\AppEnvironmentExtra)" in refusal
    assert "'MessageFoundry'" in refusal
    assert "Services\\MessageFoundry" in refusal
    assert "protect-key" in refusal


def test_other_secrets_in_the_nssm_list_are_named_and_not_refused() -> None:
    posture = _service([f"MEFOR_STORE_PASSWORD={_PASSWORD_VALUE}", "MEFOR_AUTH_AD_BIND_PASSWORD=x"])
    assert service_env_refusal(posture) is None
    entries = dict(service_env_loosenings(posture))
    assert list(entries) == ["service_environment_secret"]
    assert (
        "MEFOR_STORE_PASSWORD (in Parameters\\AppEnvironmentExtra), MEFOR_AUTH_AD_BIND_PASSWORD"
        in entries["service_environment_secret"]
    )


def test_a_non_secret_variable_in_the_nssm_list_is_neither_refused_nor_named() -> None:
    posture = _service(["MEFOR_AI_ENVIRONMENT=prod", "MEFOR_SECURITY_REQUIRE_MFA=false"])
    assert service_env_refusal(posture) is None
    assert service_env_loosenings(posture) == []


# --- the loosening entry (key-custody slice S2a) ---------------------------------------------------


def _registry_names(service_env: ServiceEnvPosture | None) -> list[str]:
    return [
        name
        for name, _risk in security_loosenings(
            SecuritySettings(),
            StoreSettings(),
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
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=service_env,
        )
    ]


def test_the_registry_names_a_store_key_reaching_a_service_through_its_environment() -> None:
    """The machine-wide environment is one such place: the key is in the process, and not in
    NSSM's list, so nothing refuses and the registry must name it."""
    posture = _service(["MEFOR_AI_ENVIRONMENT=prod"], MEFOR_STORE_ENCRYPTION_KEY=_KEY_VALUE)
    assert service_env_refusal(posture) is None
    assert "store_key_in_service_environment" in _registry_names(posture)


def test_the_registry_does_not_name_a_store_key_outside_a_service() -> None:
    """The control: the same key in the environment of a ``serve`` started from a shell."""
    probe = _Probe(ancestors=[(300, "pwsh.exe")])
    posture = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert "store_key_in_service_environment" not in _registry_names(posture)


def test_a_service_with_the_key_in_a_dpapi_file_is_not_named() -> None:
    posture = _service(["MEFOR_STORE_ENCRYPTION_KEY_FILE=C:/ProgramData/MessageFoundry/k.dpapi"])
    assert service_env_refusal(posture) is None
    assert not [n for n in _registry_names(posture) if "service" in n]


def test_a_caller_with_no_reading_names_nothing_for_it() -> None:
    assert not [n for n in _registry_names(None) if "service" in n]


# --- the name sets keep up with the settings -------------------------------------------------------


def test_every_environment_only_secret_the_settings_know_is_checked() -> None:
    """A secret added to the settings' own lists must not be missed in the service's list."""
    from_file_list = {
        f"MEFOR_{section.upper()}_{key.upper()}" for section, key in _FILE_SECRET_KEYS
    }
    from_rotation = set(ENFORCEABLE_SECRET_EXPIRY_CLASSES) - {"connector"}
    known = set(KEY_CLASS_NAMES) | set(LOOSENING_CLASS_NAMES)
    assert from_file_list <= known, sorted(from_file_list - known)
    assert from_rotation <= known, sorted(from_rotation - known)
    assert not set(KEY_CLASS_NAMES) & set(LOOSENING_CLASS_NAMES)
    assert set(KEY_CLASS_NAMES) == {
        "MEFOR_STORE_ENCRYPTION_KEY",
        "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
    }


# --- serve and supervise refuse, whatever the enforcement setting ----------------------------------

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
_KEY_LISTED = ServiceEnvPosture(
    ServiceEnvStatus.OBSERVED,
    service_name="MessageFoundry",
    listed=("MEFOR_STORE_ENCRYPTION_KEY",),
    keys_in_environment=("MEFOR_STORE_ENCRYPTION_KEY",),
)
_PASSWORD_LISTED = ServiceEnvPosture(
    ServiceEnvStatus.OBSERVED, service_name="MessageFoundry", listed=("MEFOR_STORE_PASSWORD",)
)
_A_SERVICE = ServiceEnvPosture(ServiceEnvStatus.OBSERVED, service_name="MessageFoundry")
_A_SHELL = ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE)
_KEY_REFUSAL = (
    "refusing to start: MEFOR_STORE_ENCRYPTION_KEY is set in the environment of the Windows service"
)
#: Vault BACKLOG #2626 step 2.
_FLAG_REFUSAL = (
    "refusing to start: this engine runs as the Windows service 'MessageFoundry' and was started "
    "with no --service-config"
)
#: A service started with no settings file passes the flag refusal only when it has the flag, so
#: each refusal case names whether it passes one.
_REFUSALS = pytest.mark.parametrize(
    ("posture", "with_flag", "reason"),
    [(_KEY_LISTED, True, _KEY_REFUSAL), (_A_SERVICE, False, _FLAG_REFUSAL)],
    ids=["store-key-listed", "no-service-config"],
)


@pytest.fixture
def settings_file(tmp_path_factory: pytest.TempPathFactory) -> str:
    """An empty settings file outside the working directory, so the flag is what names it, and a
    test can still check that the working directory stays empty."""
    path = tmp_path_factory.mktemp("settings") / "messagefoundry.toml"
    path.write_text("", encoding="utf-8")
    return str(path)


def _serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    posture: ServiceEnvPosture,
    *,
    warn: bool,
    service_config: str | None,
) -> int:
    from messagefoundry.__main__ import main

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    if warn:
        monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    else:
        monkeypatch.delenv("MEFOR_SECURITY_ENFORCEMENT", raising=False)
    monkeypatch.setattr(serviceenv, "service_env_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    flag = [] if service_config is None else ["--service-config", service_config]
    return main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "dev", *flag])


@pytest.mark.parametrize("warn", [False, True], ids=["enforce", "warn"])
@_REFUSALS
def test_serve_as_a_service_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,
    warn: bool,
    posture: ServiceEnvPosture,
    with_flag: bool,
    reason: str,
) -> None:
    service_config = settings_file if with_flag else None
    assert _serve(tmp_path, monkeypatch, posture, warn=warn, service_config=service_config) == 2
    assert reason in capsys.readouterr().err
    # Before any side effect: nothing was minted or opened in the working directory.
    assert not any(tmp_path.iterdir()), sorted(p.name for p in tmp_path.iterdir())


def test_serve_names_another_secret_in_its_nssm_list_and_does_not_refuse_on_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,
) -> None:
    """The control for the key refusal: it may stop at a later gate, not at this one."""
    _serve(tmp_path, monkeypatch, _PASSWORD_LISTED, warn=True, service_config=settings_file)
    captured = capsys.readouterr()
    assert "is set in the environment of the Windows service" not in captured.err
    # serve installs its own stdout handler, so the loosening line is read from stdout.
    assert "service_environment_secret (MEFOR_STORE_PASSWORD is set in" in captured.out


@pytest.mark.parametrize(
    ("posture", "with_flag"),
    [(_A_SERVICE, True), (_A_SHELL, False)],
    ids=["service-with-flag", "shell-without-flag"],
)
def test_serve_runs_as_a_service_with_the_flag_and_from_a_shell_without_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,
    posture: ServiceEnvPosture,
    with_flag: bool,
) -> None:
    """The control for the flag refusal: a service with the flag, and the developer loop."""
    service_config = settings_file if with_flag else None
    rc = _serve(tmp_path, monkeypatch, posture, warn=True, service_config=service_config)
    err = capsys.readouterr().err
    assert "--service-config" not in err
    assert rc == 0, err


@_REFUSALS
def test_supervise_as_a_service_refuses_before_it_starts_an_engine_shard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,
    posture: ServiceEnvPosture,
    with_flag: bool,
    reason: str,
) -> None:
    from messagefoundry import __main__ as cli

    spawned: list[str] = []

    async def fake_supervise(config: str, **kwargs: object) -> int:
        spawned.append(config)
        return 0

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_SECURITY_ENFORCEMENT", "warn")
    monkeypatch.setattr(serviceenv, "service_env_posture", lambda: posture)
    monkeypatch.setattr("messagefoundry.pipeline.supervisor.supervise", fake_supervise)
    monkeypatch.setattr(cli, "configure_logging", lambda *args, **kwargs: None)
    args = argparse.Namespace(
        config=str(_SAMPLES_CONFIG),
        db=str(tmp_path / "mefor.db"),
        base_port=8765,
        env="dev",
        service_config=settings_file if with_flag else None,
        project_root=str(tmp_path),
    )
    rc = cli._supervise(args)
    err = capsys.readouterr().err
    assert rc == 2 and not spawned
    # The key refusal's own line drops the "refusing to start: " prefix serve prints.
    assert reason.removeprefix("refusing to start: ") in err
    assert "refusing to start the fleet" in err


def test_only_a_known_service_with_no_settings_flag_is_refused() -> None:
    cases = [
        (_A_SERVICE, True),
        # The service is known and only its lists could not be read: still a service.
        (ServiceEnvPosture(ServiceEnvStatus.UNOBSERVABLE, service_name="MessageFoundry"), True),
        (_A_SHELL, False),
        # No service found, so the start may be a shell's, and the reading settles nothing.
        (ServiceEnvPosture(ServiceEnvStatus.UNOBSERVABLE, detail="walk failed"), False),
    ]
    for posture, refused in cases:
        reason = missing_service_config_refusal(posture, None)
        assert (reason is not None) is refused, posture
        if reason is not None:
            assert "'MessageFoundry'" in reason and "-ServiceConfig <path>" in reason
        assert missing_service_config_refusal(posture, r"C:\mf\messagefoundry.toml") is None


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows probe reads this host")
def test_the_windows_probe_reads_this_process_ancestors() -> None:
    """The real probe on a Windows host: it returns this process's parent first, and a pytest
    run has no nssm.exe among them."""
    import os

    nearest = next(iter(serviceenv._WindowsProbe().ancestor_images()))
    assert nearest[0] == os.getppid()
    assert read_service_env_posture().status is ServiceEnvStatus.NOT_A_SERVICE
