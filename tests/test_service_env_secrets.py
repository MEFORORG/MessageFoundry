# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Secrets in the engine's own Windows service environment (vault BACKLOG #2595, #2601).

NSSM keeps a service's environment list in a registry key any local user can read. A store key
there, or another secret-class setting, refuses ``serve`` and ``supervise`` under every
enforcement setting. A store key reaching a service through its environment at all is named as a
loosening (key-custody slice S2a). The host is reached through a probe, so every test here runs
on every platform; the Windows probe itself is exercised on a Windows host only.
"""

from __future__ import annotations

import argparse
import inspect
import re
import sys
import tracemalloc
import types
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from messagefoundry import serviceenv
from messagefoundry.config.settings import (
    _FILE_SECRET_KEYS,
    ENFORCEABLE_SECRET_EXPIRY_CLASSES,
    AiSettings,
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
    security_loosenings,
)
from messagefoundry.serviceenv import (
    DIRECTORY_CLASS_NAMES,
    KEY_CLASS_NAMES,
    ServiceEnvironmentRefused,
    ServiceEnvPosture,
    ServiceEnvStatus,
    missing_service_config_refusal,
    read_service_env_posture,
    service_env_loosenings,
    service_env_refusal,
)
from tests._serviceenv_remedy import ADD_BACK, CREATE, REMOVE, RUNS_ON

#: Synthetic stand-ins. Never a real key: the tests check that no value is kept, by searching for
#: these strings in what the reading returns.
_KEY_VALUE = "synthetic-store-key-value"
_PASSWORD_VALUE = "synthetic-store-password-value"
#: Split so the gitleaks private-key rule reads no PEM key marker in this file.
_PEM_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"


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


_ENFORCEMENT_NOTE = '[security].enforcement = "warn" does not change this refusal'


def _assert_twin_of(refusal: str, twin: str) -> None:
    """``twin`` carries the refusal's finding and remedy, and drops its last sentence, the
    enforcement note, since the engine it is named in ran no refusal for the note to be about."""
    body, _sep, note = refusal.rpartition(". ")
    assert note == _ENFORCEMENT_NOTE
    assert twin.endswith(body)
    assert _ENFORCEMENT_NOTE not in twin


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
        entries=["MEFOR_AI_ENVIRONMENT=prod", "MEFOR_SECRETS_DIRECTORY=C:\\s"],
    )
    posture = read_service_env_posture(probe=probe, environ={})
    assert posture.status is ServiceEnvStatus.OBSERVED
    assert posture.service_name == "MessageFoundry-Test"
    assert probe.asked == ["MessageFoundry-Test"]
    # Vault BACKLOG #5394 item 2: only a name the refusal reads is listed.
    assert posture.listed == ("MEFOR_SECRETS_DIRECTORY",)


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
    known = (*KEY_CLASS_NAMES, *DIRECTORY_CLASS_NAMES)
    posture = _service(
        [f"{name.lower()}=-----BEGIN x" for name in known]
        + ["MEFOR_STORE_PASSWORDX=x", "mefor_unknown_thing=x"]
        # Vault BACKLOG #8212 item 7: refused, and counted, never spelled.
        + ["MEFOR_VALUE_PASTED_SECRET_TEXT=x"],
        MEFOR_STORE_ENCRYPTION_KEY=_KEY_VALUE,
    )
    for name in (*posture.listed_keys, *posture.listed_directory_names):
        assert any(name is constant for constant in known), name
    printed = "".join(risk for _name, risk in service_env_loosenings(posture)) + str(
        service_env_refusal(posture)
    )
    # Plus the secrets directory's own variable, a constant the loosening points to (vault BACKLOG
    # #2595, ADR 0214), and the bare prefix the value count prints.
    assert set(re.findall(r"MEFOR_[A-Z_]+", printed, flags=re.IGNORECASE)) == {
        *known,
        "MEFOR_SECRETS_DIRECTORY",
        "MEFOR_VALUE_",
    }


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
        "ServiceEnvPosture.listed_directory_names",
    } <= walked, sorted(walked)
    assert not sorted(name for name in identifiers if _SENSITIVE_IDENTIFIER.search(name))


def test_a_name_set_to_nothing_is_not_listed() -> None:
    posture = _service(["MEFOR_STORE_ENCRYPTION_KEY=", "MEFOR_STORE_PASSWORD=   ", "Path=C:\\x"])
    assert posture.listed == ()
    assert service_env_refusal(posture) is None
    # An equals-led item may be the password itself, split from its name, so it is read as its
    # value and refuses, Windows' own nameless entries among them (vault BACKLOG #5394).
    for item in ("=orphan", "=C:=C:\\x"):
        orphan = _service(["MEFOR_STORE_PASSWORD=   ", item])
        assert orphan.listed == ("MEFOR_STORE_PASSWORD",), item


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


def _console_script_probe() -> _Probe:
    """A console-script launcher, ``uvicorn.exe``, between NSSM and the interpreter."""
    return _Probe(
        ancestors=[(300, "python.exe"), (250, "uvicorn.exe"), (100, "nssm.exe")],
        services={100: "MessageFoundry"},
        entries=[f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}"],
    )


def test_a_console_script_launcher_under_nssm_names_only_the_unobservable_entry() -> None:
    """docs/SECURITY-LOOSENING.md says a console-script launcher such as ``uvicorn.exe`` between
    NSSM and the interpreter is neither a Python interpreter nor ``messagefoundry.exe``, so the
    engine does not find its service and ``secret_in_service_environment`` is not named."""
    probe = _console_script_probe()
    posture = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
    )
    assert posture.status is ServiceEnvStatus.UNOBSERVABLE
    assert "is above uvicorn.exe, which is neither a Python interpreter nor messagefoundry.exe" in (
        posture.detail
    )
    assert probe.asked == []
    assert service_env_refusal(posture) is None
    assert _names(posture) == ["service_environment_unobservable"]


def test_an_oidc_signing_key_path_is_not_a_secret_but_the_inline_key_is() -> None:
    path = _service(["MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:/keys/oidc.pem"])
    assert path.listed == ()
    inline = _service([f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY={_PEM_BEGIN} x"])
    assert inline.listed_directory_names == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)
    # A whole inline key whose header starts on its second line is still the inline key.
    later = _service([f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=\r\n{_PEM_BEGIN}\r\nx"])
    assert later.listed_directory_names == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)


@pytest.mark.parametrize("brk", ["\r\n", "\n", "\r"])
@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_a_store_key_on_a_later_line_of_one_value_refuses(key: str, brk: str) -> None:
    """Vault BACKLOG #5394: one ``REG_SZ`` value can hold several ``NAME=value`` lines. A store
    key on a line after the first is read as its own variable, whatever breaks the lines."""
    posture = _service([f"MEFOR_AI_ENVIRONMENT=prod{brk}{key}={_KEY_VALUE}{brk}"])
    assert posture.listed_keys == (key,)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    # The refusal says which line of its string sets the name, so the operator looks below it.
    assert (
        f"{key} (in Parameters\\AppEnvironmentExtra, line 2 of the registry string that sets it)"
    ) in refusal
    assert _KEY_VALUE not in refusal


def test_an_env_value_on_a_later_line_of_one_value_refuses() -> None:
    posture = _service(["MEFOR_AI_ENVIRONMENT=prod\nMEFOR_VALUE_PARTNER_HOST="])
    assert posture.listed_value_names == ("MEFOR_VALUE_PARTNER_HOST",)
    assert posture.empty_value_names == ("MEFOR_VALUE_PARTNER_HOST",)
    assert service_env_refusal(posture) is not None


def test_a_later_line_of_key_material_is_never_read_as_a_name() -> None:
    """A padded base64 line holds an equals sign. Read as ``NAME=value`` it would put key
    material in ``listed``; only a name the refusal is about is read off a later line."""
    posture = _service([f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY={_PEM_BEGIN}\nMIIB==\n-----END"])
    assert posture.listed == ("MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",)


@pytest.mark.parametrize("entry", ["MEFOR_VALUE_A\nX=1", "MEFOR_VALUE_\nFOO=1"])
def test_a_whole_string_whose_name_holds_a_line_break_still_refuses(entry: str) -> None:
    """NSSM may set the whole string as one variable, whose name then holds a line feed and
    still starts ``MEFOR_VALUE_``, which the engine loads. The whole-string reading refuses it."""
    assert service_env_refusal(_service([entry])) is not None


@pytest.mark.parametrize(
    "entry",
    [
        "MEFOR_AI_ENVIRONMENT=prod\nMEFOR_STORE_ENCRYPTION_KEY=\nabcdef",
        "MEFOR_AI_ENVIRONMENT=prod\nMEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=\n-----BEGIN x",
    ],
)
def test_a_later_name_whose_value_starts_on_the_next_line_refuses(entry: str) -> None:
    """A later line's name keeps the rest of the string as its value, as the first line's does."""
    assert service_env_refusal(_service([entry])) is not None


@pytest.mark.parametrize("name", DIRECTORY_CLASS_NAMES)
def test_every_other_secret_class_name_on_a_later_line_refuses(name: str) -> None:
    posture = _service([f"MEFOR_AI_ENVIRONMENT=prod\n{name}=-----BEGIN x"])
    assert posture.listed_directory_names == (name,)


def test_a_secrets_directory_on_a_later_line_is_not_taken_as_set() -> None:
    """NSSM may take the whole item as one variable, so a later line's MEFOR_SECRETS_DIRECTORY is
    not evidence the service has one, and the refusal still says to add it."""
    posture = _service(
        ["MEFOR_AI_ENVIRONMENT=prod\nMEFOR_SECRETS_DIRECTORY=C:\\s\nMEFOR_VALUE_X=1"]
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert CREATE in refusal


def test_a_blank_first_line_still_reads_the_secrets_directory_below_it() -> None:
    """The whole-string reading strips the name, so a blank first line moves the first name down.
    The secrets directory below one is set, and the refusal must not tell the operator to add
    it."""
    posture = _service(["\nMEFOR_SECRETS_DIRECTORY=C:\\s", "MEFOR_VALUE_X=1"])
    assert "MEFOR_SECRETS_DIRECTORY" in posture.listed
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert CREATE not in refusal


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_an_ordinary_name_windows_allows_ends_the_empty_value_above_it(key: str) -> None:
    """A name such as ``ProgramFiles(x86)`` is an ordinary variable's line, so an empty later
    ``KEY=`` above it stays empty and nothing refuses."""
    posture = _service([f"MEFOR_AI_ENVIRONMENT=prod\n{key}=\nProgramFiles(x86)=C:\\x"])
    assert posture.listed_keys == ()
    assert service_env_refusal(posture) is None


def test_a_secret_class_line_below_an_ordinary_name_windows_allows_still_refuses() -> None:
    """The control: the widened ordinary name does not hide a real secret-class line below it."""
    key = KEY_CLASS_NAMES[0]
    posture = _service([f"MEFOR_AI_ENVIRONMENT=prod\nProgramFiles(x86)=C:\\x\n{key}={_KEY_VALUE}"])
    assert posture.listed_keys == (key,)
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize("key", KEY_CLASS_NAMES)
def test_an_empty_store_key_above_another_variable_still_refuses(key: str) -> None:
    """Vault BACKLOG #5394: an empty ``KEY=`` line, then another variable's line. The key is
    empty under the line reading, but NSSM may set the whole string as one variable, and then the
    key holds the line below it, so this refuses."""
    posture = _service([f"{key}=\nMEFOR_AI_ENVIRONMENT=prod"])
    assert posture.listed_keys == (key,)
    assert service_env_refusal(posture) is not None


@pytest.mark.parametrize(
    "entry",
    [
        "MEFOR_STORE_PASSWORD=\nPass=word",
        f"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=\nFOO=bar\n{_PEM_BEGIN}\nx",
        "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:\\oidc.pem\nMEFOR_AI_ENVIRONMENT=-----BEGIN x",
    ],
)
def test_a_first_name_whose_whole_string_holds_a_secret_refuses(entry: str) -> None:
    """A line that sets an ordinary variable ends the value above it only under the line reading.
    Under the whole-string reading the first name holds every line below it, so a value that
    reads empty, or a path, on its own line refuses when its string carries more."""
    assert service_env_refusal(_service([entry])) is not None


@pytest.mark.parametrize(
    "entry",
    [
        "\nMEFOR_STORE_ENCRYPTION_KEY=\nOTHER=1",
        "MEFOR_STORE_ENCRYPTION_KEY\n=abc",
        "MEFOR_STORE_PASSWORD\r\n==",
        "\nMEFOR_VALUE_A\nX=1",
        "\nMEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:\\k.pem\nX=-----BEGIN x",
    ],
)
def test_every_string_the_whole_string_reading_refuses_still_refuses(entry: str) -> None:
    """The reader before vault BACKLOG #5394 read each string whole: the stripped name before the
    first equals sign, and the rest. A blank first line, or a line break before the equals sign,
    still names a secret-class
    variable under that reading, so the line reading must not let it through."""
    assert service_env_refusal(_service([entry])) is not None


@pytest.mark.parametrize(
    "entry",
    [
        "MEFOR_VALUE_A\nMEFOR_STORE_ENCRYPTION_KEY=",
        "MEFOR_VALUE_A\nMEFOR_STORE_ENCRYPTION_KEY=   ",
        "MEFOR_VALUE_A\nMEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY=C:\\k.pem",
    ],
)
def test_a_broken_value_name_above_a_later_name_nothing_keeps_still_refuses(entry: str) -> None:
    """The broken ``MEFOR_VALUE_A<LF>...`` name is dropped only when a later line sets a name the
    refusal keeps. A later key that is empty, blank or a path is not one, so the whole-string
    variable, which the engine loads, still refuses."""
    posture = _service([entry])
    assert posture.unplain_value_names == ("MEFOR_VALUE_A",)
    assert service_env_refusal(posture) is not None


def test_a_line_with_no_equals_sign_is_not_glued_onto_the_next() -> None:
    posture = _service(["NOT A VARIABLE\nMEFOR_AI_ENVIRONMENT=prod"])
    assert posture.listed == ()
    glued = _service(["MEFOR_VALUE_A\nX=1"])
    assert glued.listed_value_names == ("MEFOR_VALUE_A",)
    assert glued.unplain_value_names == ("MEFOR_VALUE_A",)
    assert service_env_refusal(glued) is not None


def test_an_empty_env_value_above_another_line_is_still_empty() -> None:
    posture = _service(["MEFOR_VALUE_A=\nMEFOR_VALUE_B=x"])
    assert posture.listed_value_names == ("MEFOR_VALUE_A", "MEFOR_VALUE_B")
    assert posture.empty_value_names == ("MEFOR_VALUE_A",)


def test_a_first_line_with_no_equals_sign_is_not_counted_twice() -> None:
    """``MEFOR_VALUE_A`` with no equals sign, then ``MEFOR_VALUE_B=1``: one variable under
    either reading, so the refusal counts one."""
    posture = _service(["MEFOR_VALUE_A\nMEFOR_VALUE_B=1"])
    assert posture.listed_value_names == ("MEFOR_VALUE_B",)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert "1 MEFOR_VALUE_* variable(s)" in refusal


def test_a_long_multi_line_value_is_read_in_linear_memory() -> None:
    """A reader that read the rest of the string again from every later line took about 160 MB
    for 4,000 lines. Each line is read once. The peak is measured from a reset, above what was
    already allocated, and a trace someone else started, such as ``python -X tracemalloc``, is
    left running."""
    entry = "\n".join(f"MEFOR_VALUE_K{n}=synthetic-value-{n}" for n in range(4000))
    started_here = not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        before, _peak = tracemalloc.get_traced_memory()
        posture = _service([entry])
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        if started_here:
            tracemalloc.stop()
    assert len(posture.listed_value_names) == 4000
    assert peak - before < 16 * 1024 * 1024, f"peak {peak - before} bytes"


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


@pytest.mark.parametrize("name", DIRECTORY_CLASS_NAMES)
def test_every_other_secret_class_name_in_the_nssm_list_refuses(name: str) -> None:
    """Vault BACKLOG #2595 slice B: the rule a store key there follows, for each secret the
    secrets directory supplies. The refusal names the directory as the way in."""
    value = f"{_PEM_BEGIN} x" if name == "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY" else "x"
    posture = _service([f"{name}={value}", "MEFOR_AI_ENVIRONMENT=prod"])
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert f"{name} (in Parameters\\AppEnvironmentExtra) is set in" in refusal
    assert "'MessageFoundry'" in refusal
    assert f"Put {name} in the secrets directory MEFOR_SECRETS_DIRECTORY names" in refusal
    assert 'enforcement = "warn" does not change this refusal' in refusal
    # The store key's remedy is not offered for a secret that is not the store key.
    assert "protect-key" not in refusal
    assert CREATE in refusal
    # `serve` refuses before it reads the loosenings; an engine it did not start names it there.
    [(entry, twin)] = service_env_loosenings(posture)
    assert entry == "secret_in_service_environment"
    _assert_twin_of(refusal, twin)


def test_a_service_that_names_its_secrets_directory_is_not_told_to_add_it() -> None:
    from messagefoundry.engine_secrets import SECRETS_DIRECTORY_VARIABLE

    assert serviceenv._DIRECTORY_VARIABLE == SECRETS_DIRECTORY_VARIABLE
    posture = _service(["MEFOR_STORE_PASSWORD=x", "MEFOR_SECRETS_DIRECTORY=C:/s"])
    refusal = service_env_refusal(posture)
    assert refusal is not None and CREATE not in refusal


@pytest.mark.parametrize(
    ("entries", "adds_back"),
    [
        pytest.param(["MEFOR_VALUE_PARTNER_HOST=example.test"], True, id="value"),
        pytest.param(["MEFOR_STORE_PASSWORD=x"], True, id="directory-secret"),
        pytest.param(
            ["MEFOR_STORE_PASSWORD=", "synthetic-run-on", "MEFOR_VALUE_B=1"], True, id="run-on"
        ),
        pytest.param(
            ["MEFOR_VALUE_PARTNER_HOST=example.test", "MEFOR_SECRETS_DIRECTORY=C:/s"],
            False,
            id="directory-listed",
        ),
        # A joined directory string that no step keeps goes with the run-on (the Lander's
        # ruling on handback 7085947392, F1), in either spelling, and so does a path the
        # fail-closed rule does not keep.
        pytest.param(
            ["MEFOR_STORE_PASSWORD=", "MEFOR_SECRETS_DIRECTORY==", "MEFOR_VALUE_B=1"],
            True,
            id="directory-joined",
        ),
        pytest.param(
            ["MEFOR_STORE_PASSWORD=", "mefor_secrets_directory ==", "MEFOR_VALUE_B=1"],
            True,
            id="directory-joined-spaced",
        ),
        pytest.param(
            [
                "MEFOR_STORE_PASSWORD=",
                "mefor_secrets_directory=C:\\d",
                "MEFOR_VALUE_A=",
                "synthetic-run-on",
            ],
            True,
            id="directory-path-not-kept",
        ),
        pytest.param(
            ["MEFOR_STORE_PASSWORD=", "mefor_secrets_directory=C:\\d", "MEFOR_VALUE_B=1"],
            False,
            id="directory-path-kept",
        ),
        pytest.param([f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}"], False, id="store-key"),
    ],
)
def test_an_unnamed_directory_is_added_back_as_main_says(
    entries: list[str], adds_back: bool
) -> None:
    """origin/main's step for a secrets directory that exists but the lists no longer name,
    restored by the Lander's hold on PR 3142 (comment 7085002242): printed once, after the Put
    step and the removal, where the lists set no MEFOR_SECRETS_DIRECTORY and the remedy keeps
    no joined path entry. A store key alone goes to a key file and gets none."""
    refusal = service_env_refusal(_service(entries))
    assert refusal is not None
    assert refusal.count(ADD_BACK) == (1 if adds_back else 0)
    if adds_back:
        assert refusal.index("Put ") < refusal.index(REMOVE) < refusal.index(ADD_BACK)
        # The list it says to pass back is the one the run-on sentence left.
        assert RUNS_ON not in refusal or refusal.index(RUNS_ON) < refusal.index(ADD_BACK)
    assert "synthetic-run-on" not in refusal


@pytest.mark.parametrize(
    ("entries", "adds_back"),
    [
        (["MEFOR_STORE_PASSWORD=x"], True),
        ([f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}"], False),
        (["MEFOR_VALUE_PARTNER_HOST=example.test"], True),
        (["MEFOR_STORE_ENCRYPTION_KEY=", "abc==", "MEFOR_AUTH_AD_BIND_PASSWORD=x"], True),
    ],
)
def test_the_remedy_names_no_list_string_or_command(entries: list[str], adds_back: bool) -> None:
    """The installer refuses an existing directory the service does not name, so the remedy
    sends nobody to a re-run. It says what to remove and points at SERVICE.md."""
    refusal = service_env_refusal(_service(entries))
    assert refusal is not None
    # The control: the finding before the remedy names the lists, so the probe can fire.
    assert "appenvironment" in refusal.lower()
    remedy = refusal.split("each value refused here. ", 1)[1]
    # origin/main's add-back step, which names the list, nssm and the installer, is restored
    # by the Lander's hold in comment 7085002242; the rest of the remedy still names none.
    assert (ADD_BACK in remedy) is adds_back
    remedy = remedy.replace(ADD_BACK, "")
    # Removal comes after every step that moves a value (the fourth hold, H1).
    tail = remedy[remedy.index(REMOVE) :]
    assert "protect-key" not in tail and "Put " not in tail
    for named in ("appenvironment", "nssm", "string", "install-service.ps1"):
        assert named not in remedy.lower(), named


def test_a_store_key_and_another_secret_in_the_nssm_list_name_both_remedies() -> None:
    posture = _service(
        [f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}", f"MEFOR_STORE_PASSWORD={_PASSWORD_VALUE}"]
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert (
        "MEFOR_STORE_ENCRYPTION_KEY (in Parameters\\AppEnvironmentExtra), "
        "MEFOR_STORE_PASSWORD (in Parameters\\AppEnvironmentExtra) is set in"
    ) in refusal
    assert "protect-key" in refusal and "MEFOR_SECRETS_DIRECTORY" in refusal


def test_an_unreadable_list_does_not_refuse_on_another_secret_in_the_environment() -> None:
    """The unobservable branch keeps the store key's rule only: it reads key-class names from
    this process's environment and no other."""
    probe = _Probe(ancestors=_UNDER_NSSM, services={100: "MessageFoundry"}, unreadable=True)
    posture = read_service_env_posture(
        probe=probe, environ={"MEFOR_STORE_PASSWORD": _PASSWORD_VALUE}
    )
    assert service_env_refusal(posture) is None
    assert _names(posture) == ["service_environment_unobservable"]


def test_the_old_named_not_refused_entry_is_gone_and_only_the_refusals_twin_names_it() -> None:
    """Row step 4: the ``service_environment_secret`` loosening is removed. A secret-class name in
    the list refuses instead, and reaches the entries and the loosening registry only as the
    refusal's advisory twin, ``secret_in_service_environment``, for an engine no refusal ran in."""
    posture = _service([f"{name}=-----BEGIN x" for name in DIRECTORY_CLASS_NAMES])
    assert service_env_refusal(posture) is not None
    assert _names(posture) == ["secret_in_service_environment"]
    assert [n for n in _registry_names(posture) if "service" in n] == [
        "secret_in_service_environment"
    ]


#: The postures the refusal refuses.
_REFUSED_POSTURES = pytest.mark.parametrize(
    "posture",
    [
        _service([f"MEFOR_STORE_PASSWORD={_PASSWORD_VALUE}"]),
        _service([f"MEFOR_STORE_ENCRYPTION_KEY={_KEY_VALUE}"]),
        read_service_env_posture(
            probe=_Probe(ancestors=_UNDER_NSSM, services={100: "MessageFoundry"}, unreadable=True),
            environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE},
        ),
        _service([f"MEFOR_VALUE_PARTNER_PASSWORD={_PASSWORD_VALUE}"]),
    ],
    ids=[
        "store-password-listed",
        "store-key-listed",
        "unreadable-list-key-in-environment",
        "env-value-listed",
    ],
)


@_REFUSED_POSTURES
def test_every_posture_serve_refuses_is_named_where_serve_did_not_run(
    posture: ServiceEnvPosture,
) -> None:
    """A caller that reads the loosening registry with no refusal of its own is told what the
    refusal refuses. The removed ``service_environment_secret`` entry used to name a listed secret
    there, so the registry names each posture the refusal refuses, with the refusal's finding and
    remedy, rather than going quiet."""
    refusal = service_env_refusal(posture)
    assert refusal is not None
    entries = dict(_registry_entries(posture))
    _assert_twin_of(refusal, entries["secret_in_service_environment"])


def _values_in_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the synthetic values in this process's environment, so a check that a message or a
    response never carries one can fail where the code reads ``os.environ``."""
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", _KEY_VALUE)
    monkeypatch.setenv("MEFOR_STORE_PASSWORD", _PASSWORD_VALUE)


def _build_embedded(factory: str, tmp_path: Path) -> object:
    """Build an app the way an embedder does, with neither ``serve`` nor ``supervise``."""
    from messagefoundry.api.app import create_app, create_managed_app
    from messagefoundry.config.settings import EgressSettings

    if factory == "create_app":
        return create_app(allow_no_auth=True)
    return create_managed_app(
        db_path=tmp_path / "embedded.db",
        egress_settings=EgressSettings(deny_by_default=False),
        allow_no_auth=True,
    )


_FACTORIES = pytest.mark.parametrize("factory", ["create_app", "create_managed_app"])


@_FACTORIES
@_REFUSED_POSTURES
def test_an_embedded_app_refuses_where_serve_would(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factory: str, posture: ServiceEnvPosture
) -> None:
    """Vault BACKLOG #8212 item 1: an app built without ``serve`` refuses on ``serve``'s own
    finding, as it is built. The message is the refusal's, value-free."""
    refusal = service_env_refusal(posture)
    assert refusal is not None
    _values_in_the_environment(monkeypatch)
    monkeypatch.setattr("messagefoundry.api.app.service_env_posture", lambda: posture)
    with pytest.raises(ServiceEnvironmentRefused) as raised:
        _build_embedded(factory, tmp_path)
    assert str(raised.value) == f"{factory}: refusing to start: {refusal}"
    assert _KEY_VALUE not in str(raised.value)
    assert _PASSWORD_VALUE not in str(raised.value)


async def test_an_app_built_around_an_engine_refuses_a_listed_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The embedder shape the module docstring used to exempt, ``create_app(engine)``, refuses
    too."""
    from messagefoundry.api.app import create_app
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline import Engine

    listed = _service([f"MEFOR_STORE_PASSWORD={_PASSWORD_VALUE}"])
    _values_in_the_environment(monkeypatch)
    monkeypatch.setattr("messagefoundry.api.app.service_env_posture", lambda: listed)
    engine = await Engine.create(
        tmp_path / "embedded.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        with pytest.raises(ServiceEnvironmentRefused) as raised:
            create_app(engine, allow_no_auth=True)
    finally:
        await engine.stop()
    assert str(raised.value) == f"create_app: refusing to start: {service_env_refusal(listed)}"


async def test_an_embedded_app_names_a_key_from_elsewhere_in_its_posture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The embedder path end to end, on a reading that builds: ``GET /security/posture`` on an app
    built with ``create_app(engine)`` names a store key reaching the service from outside its
    lists, and never its value."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline import Engine
    from tests.test_api_security_posture import _add_viewer, _app_and_client, _token
    from tests.test_api_security_posture import _service as _auth_service

    elsewhere = _service([], MEFOR_STORE_ENCRYPTION_KEY=_KEY_VALUE)
    _values_in_the_environment(monkeypatch)
    monkeypatch.setattr("messagefoundry.api.app.service_env_posture", lambda: elsewhere)
    engine = await Engine.create(
        tmp_path / "embedded.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        auth = await _auth_service(engine)
        await _add_viewer(auth, "vw")
        _app, client = _app_and_client(
            engine, auth, ai_settings=AiSettings(), security_settings=SecuritySettings()
        )
        async with client as c:
            body = (await c.get("/security/posture", headers=await _token(c, "vw"))).json()
    finally:
        await engine.stop()
    risks = {row["switch"]: row["risk"] for row in body["loosenings"]}
    assert (
        "MEFOR_STORE_ENCRYPTION_KEY reaches this Windows service"
        in (risks["store_key_in_service_environment"])
    )
    assert "secret_in_service_environment" not in risks
    assert _KEY_VALUE not in str(body)


#: A console-script launcher between NSSM and the interpreter reads UNOBSERVABLE with no service,
#: so ``serve`` does not refuse there (the ``uvicorn.exe`` test above), and an app builds.
_CONSOLE_SCRIPT_LAUNCHER = read_service_env_posture(
    probe=_console_script_probe(), environ={"MEFOR_STORE_ENCRYPTION_KEY": _KEY_VALUE}
)


@_FACTORIES
@pytest.mark.parametrize(
    "posture",
    [
        _CONSOLE_SCRIPT_LAUNCHER,
        ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE),
        _service(["MEFOR_AI_ENVIRONMENT=prod", "MEFOR_VALUE_PARTNER_HOST"]),
        _service([], MEFOR_STORE_ENCRYPTION_KEY=_KEY_VALUE),
        read_service_env_posture(
            probe=_Probe(ancestors=_UNDER_NSSM, services={100: "MessageFoundry"}, unreadable=True),
            environ={},
        ),
    ],
    ids=[
        "console-script-launcher",
        "not-a-service",
        "no-listed-secret",
        "key-from-elsewhere",
        "unreadable-list-no-key",
    ],
)
def test_an_embedded_app_builds_where_serve_would_not_refuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, factory: str, posture: ServiceEnvPosture
) -> None:
    """The control: with no listed secret, and where the reading is UNOBSERVABLE with no known
    service, ``serve`` does not refuse, and an app builds as it did before the refusal."""
    assert service_env_refusal(posture) is None
    monkeypatch.setattr("messagefoundry.api.app.service_env_posture", lambda: posture)
    _build_embedded(factory, tmp_path)


def test_a_non_secret_variable_in_the_nssm_list_is_neither_refused_nor_named() -> None:
    """A setting that is not secret-class, and the secrets directory's own path, are left alone.
    A ``MEFOR_VALUE_*`` entry with no ``=`` sets no variable, so it is not read as one."""
    posture = _service(
        [
            "MEFOR_AI_ENVIRONMENT=prod",
            "MEFOR_SECURITY_REQUIRE_MFA=false",
            "MEFOR_VALUE_PARTNER_HOST",
            "MEFOR_SECRETS_DIRECTORY=C:/ProgramData/MessageFoundry-secrets",
        ]
    )
    assert service_env_refusal(posture) is None
    assert service_env_loosenings(posture) == []


@pytest.mark.parametrize(
    "entry",
    [
        "MEFOR_VALUE_REGISTRY_PASSWORD=synthetic-value",
        "mefor_value_partner_host=example.test",
        "MEFOR_VALUE_PARTNER_HOST=",
        "MEFOR_VALUE_PARTNER_HOST=   ",
    ],
)
def test_an_env_value_in_the_nssm_list_refuses(entry: str) -> None:
    """Vault BACKLOG #8212 item 7, the owner's ruling of 2026-11-14: every ``MEFOR_VALUE_*``
    variable in the service's lists refuses, a host name as well as a password, since the engine
    cannot tell which is a secret. An empty or blank one refuses too: the engine still overlays it
    on the value file. The name came from the registry, so it is counted and never printed. The
    remedy names both ways in: the secrets directory, and the environment's value file for a value
    that is not a secret."""
    name = entry.split("=", 1)[0].upper()
    posture = _service([entry, "MEFOR_AI_ENVIRONMENT=prod"])
    assert posture.listed_value_names == (name,)
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.startswith(
        "1 MEFOR_VALUE_* variable(s) (in Parameters\\AppEnvironmentExtra) is set in"
    )
    assert name not in refusal and name.lower() not in refusal
    assert "'MessageFoundry'" in refusal
    assert (
        "Put each MEFOR_VALUE_* variable in the secrets directory MEFOR_SECRETS_DIRECTORY names"
        in refusal
    )
    assert "environments/<env>.toml" in refusal and '"[environments]"' in refusal
    assert CREATE in refusal
    assert _ENFORCEMENT_NOTE in refusal
    assert "protect-key" not in refusal
    value = entry.split("=", 1)[1]
    assert not value.strip() or value not in refusal, "the value must never reach the refusal"
    # An empty entry is also told to go, since the secrets directory refuses an empty file.
    told_to_delete = "An empty or blank MEFOR_VALUE_* entry is refused too: delete it" in refusal
    assert told_to_delete is (not value.strip())
    [(loosening, twin)] = service_env_loosenings(posture)
    assert loosening == "secret_in_service_environment"
    _assert_twin_of(refusal, twin)


def test_env_values_are_counted_per_registry_value() -> None:
    """Two values in one list and one in another are counted per value. The bare prefix names no
    ``env()`` key, but a value under it is as readable as any other, so it is counted too."""

    class _AlsoInEnvironment(_Probe):
        def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
            return [*super().environment_entries(service_name), ("Environment", "MEFOR_VALUE_C=w")]

    probe = _AlsoInEnvironment(
        ancestors=_UNDER_NSSM,
        services={100: "MessageFoundry"},
        entries=["MEFOR_VALUE_A=x", "MEFOR_VALUE_B=y", "MEFOR_VALUE_=z"],
    )
    posture = read_service_env_posture(probe=probe, environ={})
    assert posture.listed_value_names == (
        "MEFOR_VALUE_A",
        "MEFOR_VALUE_B",
        "MEFOR_VALUE_",
        "MEFOR_VALUE_C",
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.startswith(
        "3 MEFOR_VALUE_* variable(s) (in Parameters\\AppEnvironmentExtra), "
        "1 MEFOR_VALUE_* variable(s) (in Environment) is set in"
    )
    bare = service_env_refusal(_service(["MEFOR_VALUE_=z"]))
    assert bare is not None
    assert "The bare name MEFOR_VALUE_ sets no env() key, so delete that entry" in bare
    assert "rename that env() key" not in bare and "An empty or blank" not in bare
    assert "The bare name" not in refusal.split("3 MEFOR_VALUE_", 1)[0]
    assert "counted once, without regard to case, under the first registry value" in refusal
    # The fifth hold on PR 3142, H3: the counted-once sentence ends there.
    assert "remove it from every value that sets it" not in refusal
    # Names are printed nowhere, so the shared ending speaks of what was refused, not named.
    assert REMOVE in refusal
    assert "each value named" not in refusal and "Remove each name" not in refusal


def test_an_env_value_name_the_secrets_directory_refuses_gets_the_rename_hint() -> None:
    """The remedy sends each MEFOR_VALUE_* to the secrets directory, whose file names are letters,
    digits and underscores. A listed name outside that rule is told to rename first; the name
    itself stays unprinted."""
    odd = service_env_refusal(_service(["MEFOR_VALUE_ACME-HOST=synthetic-value"]))
    assert odd is not None
    assert "a file name the secrets directory refuses, so rename that env() key" in odd
    assert "ACME-HOST" not in odd and "synthetic-value" not in odd
    plain = service_env_refusal(_service(["MEFOR_VALUE_ACME_HOST=x"]))
    assert plain is not None and "rename that env() key" not in plain
    # Judged as written: str.upper turns the sharp s into SS, which would pass the rule, but the
    # secrets directory checks the file name before case-folding and refuses it.
    folded = _service(["MEFOR_VALUE_PA\u00df=synthetic-value"])
    assert folded.listed_value_names == ("MEFOR_VALUE_PASS",)
    sharp = service_env_refusal(folded)
    assert sharp is not None and "rename that env() key" in sharp


def test_an_env_provider_reference_named_as_a_value_gets_a_route_that_reads_it() -> None:
    """A ``[secrets].provider = "env"`` reference may name a MEFOR_VALUE_* variable. It is refused
    like any other, and since EnvSecretProvider reads only the environment, the refusal must not
    leave the secrets directory as its only way in."""
    from messagefoundry.config.secretprovider import EnvSecretProvider

    refusal = service_env_refusal(_service(["MEFOR_VALUE_PARTNER_PW=synthetic-value"]))
    assert refusal is not None
    assert '[secrets].provider = "env" reference names is read from the environment only' in (
        refusal
    )
    assert (
        "Drop that reference instead and put the credential in the secrets directory under the "
        "setting it stands for"
    ) in refusal
    assert (
        'or, second, use [secrets].provider = "vault", which applies to every such reference in '
        "the engine"
    ) in refusal
    # The premise the remedy rests on: the env provider does not read the secrets directory.
    assert "secrets_directory" not in inspect.getsource(EnvSecretProvider)


def test_a_directory_secret_and_an_env_value_share_one_remedy_sentence() -> None:
    posture = _service(
        [
            "MEFOR_STORE_PASSWORD=x",
            "MEFOR_VALUE_PARTNER_HOST=example.test",
            "MEFOR_SECRETS_DIRECTORY=C:/s",
        ]
    )
    refusal = service_env_refusal(posture)
    assert refusal is not None
    assert refusal.startswith(
        "MEFOR_STORE_PASSWORD (in Parameters\\AppEnvironmentExtra), "
        "1 MEFOR_VALUE_* variable(s) (in Parameters\\AppEnvironmentExtra) is set in"
    )
    assert (
        "Put MEFOR_STORE_PASSWORD and each MEFOR_VALUE_* variable in the secrets directory "
        "MEFOR_SECRETS_DIRECTORY names"
    ) in refusal
    assert refusal.count('"The secrets directory"') == 1
    assert CREATE not in refusal


def test_the_smoke_legs_nssm_list_is_one_serve_does_not_refuse() -> None:
    """The windows-service-smoke leg replaces the service's NSSM list with ``nssm set``, and the
    merge queue is the first place it runs. So the list it sets is read here and judged by the
    refusal, which a ``MEFOR_VALUE_*`` entry there would trip, and it must name the secrets
    directory the leg writes the registry endpoint's values to."""
    pytest.importorskip("yaml")
    from tests._workflow_contexts import step_script

    script = step_script("ci.yml", "windows-service-smoke", "Install the service")[1]
    block = script.split('nssm.exe" set MessageFoundry AppEnvironmentExtra `', 1)[1]
    entries: list[str] = []
    for line in block.splitlines()[1:]:
        entries.append(line.strip().rstrip("`").strip().strip('"'))
        if not line.rstrip().endswith("`"):
            break
    assert "MEFOR_SECURITY_REQUIRE_MFA=false" in entries, f"CONTROL FAILED: {entries}"
    assert service_env_refusal(_service(entries)) is None, entries
    assert "MEFOR_SECRETS_DIRECTORY=$secretsDir" in entries


# --- the loosening entry (key-custody slice S2a) ---------------------------------------------------


def _registry_names(service_env: ServiceEnvPosture | None) -> list[str]:
    return [name for name, _risk in _registry_entries(service_env)]


def _registry_entries(service_env: ServiceEnvPosture | None) -> list[tuple[str, str]]:
    return list(
        security_loosenings(
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
            ech_cleartext_sidecar_hops=(),
            listener_trusted_proxy_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=SecretsSettings(),
            ai=AiSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=service_env,
        )
    )


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
    known = set(KEY_CLASS_NAMES) | set(DIRECTORY_CLASS_NAMES)
    assert from_file_list <= known, sorted(from_file_list - known)
    assert from_rotation <= known, sorted(from_rotation - known)
    assert not set(KEY_CLASS_NAMES) & set(DIRECTORY_CLASS_NAMES)
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
_ENVIRONMENT_ONLY = ServiceEnvPosture(
    ServiceEnvStatus.OBSERVED,
    service_name="MessageFoundry",
    keys_in_environment=("MEFOR_STORE_ENCRYPTION_KEY",),
)
_A_SERVICE = ServiceEnvPosture(ServiceEnvStatus.OBSERVED, service_name="MessageFoundry")
_A_SHELL = ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE)
_KEY_REFUSAL = (
    "refusing to start: MEFOR_STORE_ENCRYPTION_KEY is set in the environment of the Windows service"
)
_PASSWORD_REFUSAL = (
    "refusing to start: MEFOR_STORE_PASSWORD is set in the environment of the Windows service"
)
#: Vault BACKLOG #2626 step 2.
_FLAG_REFUSAL = (
    "refusing to start: this engine runs as the Windows service 'MessageFoundry' and was started "
    "with no --service-config"
)


def _record_loosening_reads(monkeypatch: pytest.MonkeyPatch) -> list[ServiceEnvPosture]:
    """Record every read of the service-environment loosenings, through either binding of the
    function, so a refusing start can show it refused before it read them. That order is what
    keeps ``secret_in_service_environment``, the refusal's advisory twin, out of ``serve`` and
    ``supervise``."""
    from messagefoundry.config import settings as settings_module

    read: list[ServiceEnvPosture] = []

    def recording(posture: ServiceEnvPosture) -> list[tuple[str, str]]:
        read.append(posture)
        return []

    monkeypatch.setattr(serviceenv, "service_env_loosenings", recording)
    monkeypatch.setattr(settings_module, "service_env_loosenings", recording)
    return read


#: Each refusal case says whether it passes --service-config. The store-key case passes one, so
#: the flag refusal, which comes first, does not hide the key refusal it tests.
_REFUSALS = pytest.mark.parametrize(
    ("posture", "with_flag", "reason"),
    [
        (_KEY_LISTED, True, _KEY_REFUSAL),
        (_PASSWORD_LISTED, True, _PASSWORD_REFUSAL),
        (_A_SERVICE, False, _FLAG_REFUSAL),
    ],
    ids=["store-key-listed", "store-password-listed", "no-service-config"],
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
    read = _record_loosening_reads(monkeypatch)
    assert _serve(tmp_path, monkeypatch, posture, warn=warn, service_config=service_config) == 2
    assert reason in capsys.readouterr().err
    assert not read
    # Before any side effect: nothing was minted or opened in the working directory.
    assert not any(tmp_path.iterdir()), sorted(p.name for p in tmp_path.iterdir())


def test_serve_names_a_store_key_from_elsewhere_in_its_environment_and_does_not_refuse_on_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    settings_file: str,
) -> None:
    """The control for the list refusals: a key that reached the service from outside its lists
    may stop at a later gate, not at this one, and is named."""
    _serve(tmp_path, monkeypatch, _ENVIRONMENT_ONLY, warn=True, service_config=settings_file)
    captured = capsys.readouterr()
    assert "is set in the environment of the Windows service" not in captured.err
    # serve installs its own stdout handler, so the loosening line is read from stdout.
    assert "store_key_in_service_environment (MEFOR_STORE_ENCRYPTION_KEY reaches" in captured.out


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
    read = _record_loosening_reads(monkeypatch)
    rc = cli._supervise(args)
    err = capsys.readouterr().err
    assert rc == 2 and not spawned and not read
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
        assert missing_service_config_refusal(posture, str(_SAMPLES_CONFIG / "x.toml")) is None


def test_a_service_refuses_a_relative_settings_flag() -> None:
    """A relative --service-config with no --project-root is read from the working directory, the
    file the flag refusal exists to keep out. The caller passes the flag anchored under the root,
    so a relative flag with a root arrives absolute."""
    for relative in ("messagefoundry.toml", str(Path("settings", "messagefoundry.toml"))):
        reason = missing_service_config_refusal(_A_SERVICE, relative)
        assert reason is not None and "which is not an absolute path" in reason, relative
        assert missing_service_config_refusal(_A_SHELL, relative) is None


@pytest.mark.skipif(sys.platform != "win32", reason="the Windows probe reads this host")
def test_the_windows_probe_reads_this_process_ancestors() -> None:
    """The real probe on a Windows host: it returns this process's parent first, and a pytest
    run has no nssm.exe among them."""
    import os

    nearest = next(iter(serviceenv._WindowsProbe().ancestor_images()))
    assert nearest[0] == os.getppid()
    assert read_service_env_posture().status is ServiceEnvStatus.NOT_A_SERVICE
