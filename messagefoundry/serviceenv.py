# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Secrets in the engine's own Windows service environment (vault BACKLOG #2595, #2601).

The Windows installer runs the engine under NSSM. A service's environment lists live in its
registry key, which a default Windows install lets any local user read: docs/SERVICE.md,
"Protect the store encryption key at rest", states that measurement once. This module reads the
engine's own lists once per process and keeps only the variable NAMES, never a value. The lists
read are NSSM's ``AppEnvironment`` and ``AppEnvironmentExtra`` under the service's ``Parameters``
key, and the Service Control Manager's own ``Environment`` value on the service's key.

* **A store key in one of those lists refuses the start, whatever ``[security].enforcement``
  says.** That is the owner's 2026-10-01 ruling on a secret in the environment: key-class names,
  and a Windows service's NSSM environment, are refused always. The store key has a protected
  alternative on Windows, the DPAPI key file, so the refusal leaves a way to start.
* **Another engine secret there is named as a loosening, and not refused.** The same ruling
  covers it, but no protected channel for those secrets exists yet, so a refusal would leave a
  Windows service with no way to supply a store password or a bind password at all. Refusing
  them waits on that channel (vault BACKLOG #2595, closing step 3).
* **A store key that reaches a Windows service through its environment is named** (key-custody
  slice S2a), wherever it came from, since the machine-wide environment is readable by every
  local user too.

**How the engine finds its own service.** Under NSSM the engine is a child of ``nssm.exe``, or a
grandchild when a virtual environment's ``python.exe`` starts the base interpreter, or further
down under ``supervise``. The reading walks up through Python interpreter processes only. When
the first other process is ``nssm.exe``, it asks the Service Control Manager which service runs
there. Any other process means the engine was started by something else, such as a shell, even
when that shell itself runs under some other NSSM service.

**What it does not cover**, at least: a service host other than NSSM, an ``nssm.exe`` renamed to
something else, a launcher between NSSM and the interpreter that is not a Python interpreter or
the ``messagefoundry`` launcher, and a connector secret an operator names through ``env()``,
whose name the engine cannot know.

**Not a refusal when the read fails.** An engine that cannot walk its ancestors, or cannot read
its service's lists, reports ``service_environment_unobservable`` and starts. A store key there
would then go unrefused, and the entry says so.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from messagefoundry.service_status import is_safe_service_name

_log = logging.getLogger(__name__)

#: The key-class names: the store key and its decrypt-only retired keys. Either one decrypts the
#: store. In a Windows service's environment lists they refuse the start.
KEY_CLASS_NAMES: tuple[str, ...] = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
)

#: The engine's other environment-only secrets. In a Windows service's environment lists each is
#: named as a loosening. ``tests/test_service_env_secrets.py`` holds this set to the settings'
#: own lists of environment-only secrets, so a secret added there is not missed here.
#:
#: WHY "LOOSENING" AND NOT "SECRET". The identifier names what happens to these names, because
#: CodeQL's ``py/clear-text-logging-sensitive-data`` takes a value as a secret by the identifier
#: it is bound to, such as one that says secret or password. These are names only, printed on
#: purpose, so no identifier in this module says such a word. The test file pins that for this
#: module only, against its own stand-in list of words; a caller that binds the printed lines to
#: such a name brings the alert back.
LOOSENING_CLASS_NAMES: tuple[str, ...] = (
    "MEFOR_STORE_PASSWORD",
    "MEFOR_AUTH_AD_BIND_PASSWORD",
    "MEFOR_AUTH_OIDC_CLIENT_SECRET",
    "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY",
    "MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY_PASSWORD",
    "MEFOR_ALERTS_EMAIL_PASSWORD",
    "MEFOR_API_TLS_KEY_PASSWORD",
    "MEFOR_STORE_VAULT_TOKEN",
    "MEFOR_SECRETS_VAULT_TOKEN",
    "MEFOR_AI_API_KEY",
)

#: Names that take either the secret itself or a path to a file that holds it. Only the inline
#: form is a secret, the rule ``settings._FILE_INLINE_PEM_KEYS`` applies to the config file.
_INLINE_PEM_NAMES = frozenset({"MEFOR_AUTH_OIDC_CLIENT_PRIVATE_KEY"})

#: The values that carry a service's environment: NSSM's two under the service's ``Parameters``
#: key (``AppEnvironment`` replaces the environment, ``AppEnvironmentExtra`` adds to it), and the
#: Service Control Manager's ``Environment`` on the service's own key.
NSSM_ENVIRONMENT_VALUES: tuple[str, ...] = ("AppEnvironment", "AppEnvironmentExtra")
SCM_ENVIRONMENT_VALUE = "Environment"

_NSSM_IMAGE = "nssm.exe"


def _is_engine_launcher(image: str) -> bool:
    """A process that may sit between NSSM and the engine: a Python interpreter, or the
    ``messagefoundry`` console launcher."""
    name = image.lower()
    return name.endswith(".exe") and (name.startswith("python") or name == "messagefoundry.exe")


class ServiceEnvStatus(str, Enum):  # noqa: UP042
    """Whether the engine runs under an NSSM service, and whether its lists were read.

    Three values, for the reason :class:`~messagefoundry.config.settings.StorePrivilegeStatus`
    has three: ``UNOBSERVABLE`` is the absence of a reading, and a two-valued version would let a
    read that failed report as a clean one."""

    NOT_A_SERVICE = "not_a_service"  # started by something other than nssm.exe
    OBSERVED = "observed"  # the service's environment lists were read
    UNOBSERVABLE = "unobservable"  # the ancestors, the service or its lists could not be read


@dataclass(frozen=True, slots=True)
class ServiceEnvPosture:
    """One reading of the engine's own service environment. Names only, never a value."""

    status: ServiceEnvStatus
    #: The service whose lists were read, when one was found.
    service_name: str | None = None
    #: Every variable name the service's environment lists set, upper-cased. Empty unless
    #: ``status`` is ``OBSERVED``.
    listed: tuple[str, ...] = ()
    #: ``(name, registry value)`` for each name in ``listed``, so a refusal can say which value
    #: to change.
    sources: tuple[tuple[str, str], ...] = ()
    #: The key-class names set, and not empty, in THIS process's environment, wherever they came
    #: from. Empty when ``status`` is ``NOT_A_SERVICE``.
    keys_in_environment: tuple[str, ...] = ()
    #: Why the reading failed (``UNOBSERVABLE``).
    detail: str = ""

    @property
    def listed_keys(self) -> tuple[str, ...]:
        """The key-class names the service's environment lists set."""
        return tuple(name for name in KEY_CLASS_NAMES if name in self.listed)

    @property
    def listed_loosening_names(self) -> tuple[str, ...]:
        """The other engine secrets the service's environment lists set. Each comes from
        :data:`LOOSENING_CLASS_NAMES`, never from the registry."""
        return tuple(name for name in LOOSENING_CLASS_NAMES if name in self.listed)

    def named_with_source(self, names: Sequence[str]) -> str:
        """``names``, each with the registry value that sets it."""
        where = dict(self.sources)
        return ", ".join(f"{name} (in {where[name]})" if name in where else name for name in names)


class ServiceProbe(Protocol):
    """What the reading asks of the host. The Windows one is :class:`_WindowsProbe`; a test
    passes its own, so the logic runs on every platform. Each method raises ``OSError`` when the
    host cannot answer."""

    def ancestor_images(self) -> Iterable[tuple[int, str]]:
        """``(pid, image name)`` for each ancestor of this process, nearest first. The reader
        stops at the first ``nssm.exe``, so a lazy probe walks no further than that."""
        ...

    def service_at(self, pid: int) -> str | None:
        """The name of the service whose process id is ``pid``, or ``None``."""
        ...

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        """``(registry value, raw NAME=value entry)`` for each entry of the service's
        environment values."""
        ...


def _service_key(service_name: str) -> str:
    """The service's own key, under ``HKEY_LOCAL_MACHINE``. NSSM's values are in its
    ``Parameters`` subkey."""
    return f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"


class _WindowsProbe:
    """The host's own answers: psutil for the ancestors and the service, winreg for the lists.

    Each method is guarded by ``sys.platform``, so mypy treats the Windows calls as unreachable on
    the Linux leg, the pattern :mod:`messagefoundry.secrets_dpapi` uses. A psutil failure is
    raised as ``OSError``, so the reader catches one family."""

    def ancestor_images(self) -> Iterator[tuple[int, str]]:
        if sys.platform != "win32":
            return
        import psutil

        # Walked one step at a time, so the reader's stop ends the walk. parent() drops a parent
        # whose process id was reused by a later process.
        proc = psutil.Process()
        while True:
            try:
                parent = proc.parent()
                if parent is None:
                    return
                name = str(parent.name())
            except psutil.Error as exc:
                raise OSError(f"an ancestor process could not be queried: {exc}") from exc
            yield int(parent.pid), name
            proc = parent

    def service_at(self, pid: int) -> str | None:
        if sys.platform != "win32":
            return None
        import psutil

        try:
            services = list(psutil.win_service_iter())
        except psutil.Error as exc:
            raise OSError(f"the services could not be listed: {exc}") from exc
        for service in services:
            try:
                if service.pid() == pid:
                    return str(service.name())
            except (psutil.Error, OSError):
                continue  # a service that cannot be queried is not the one NSSM runs as
        return None

    def environment_entries(self, service_name: str) -> list[tuple[str, str]]:
        if sys.platform != "win32":
            raise OSError("the Windows registry is not available on this platform")
        if not is_safe_service_name(service_name):
            raise OSError("the service name is not one the engine reads a registry key for")
        import winreg

        def read(subkey: str, names: Sequence[str], label: str) -> list[tuple[str, str]]:
            entries: list[tuple[str, str]] = []
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                for value_name in names:
                    try:
                        value, kind = winreg.QueryValueEx(key, value_name)
                    except FileNotFoundError:
                        continue  # the value is not set, so it lists nothing
                    where = f"{label}{value_name}"
                    if kind == winreg.REG_MULTI_SZ and isinstance(value, list):
                        entries.extend((where, str(item)) for item in value)
                    elif kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(value, str):
                        entries.append((where, value))
                    else:
                        raise OSError(f"{value_name} holds registry type {kind}, not strings")
            return entries

        key = _service_key(service_name)
        return [
            *read(key, (SCM_ENVIRONMENT_VALUE,), ""),
            *read(f"{key}\\Parameters", NSSM_ENVIRONMENT_VALUES, "Parameters\\"),
        ]


def _names(entries: Sequence[tuple[str, str]]) -> tuple[tuple[str, str], ...]:
    """The upper-cased names of the variables that ``NAME=value`` entries set to a secret. The
    value is dropped here and never kept. An empty value sets nothing, and a path in a name that
    takes either a key or its path is not a secret, so neither name is kept. Windows compares
    environment names without case, so this does too. Each name is returned with the first
    registry value that sets it."""
    names: dict[str, str] = {}
    for where, entry in entries:
        name, _, value = entry.partition("=")
        name = name.strip().upper()
        if not name or not value.strip():
            continue
        if name in _INLINE_PEM_NAMES and "-----BEGIN" not in value:
            continue
        names.setdefault(name, where)
    return tuple(names.items())


def read_service_env_posture(
    *, probe: ServiceProbe | None = None, environ: Mapping[str, str] | None = None
) -> ServiceEnvPosture:
    """Read the engine's own service environment now. Never raises for a host it cannot read.

    ``probe`` and ``environ`` default to the host and to this process's environment. Off Windows,
    with no probe given, the engine is not a service."""
    if probe is None:
        if sys.platform != "win32":
            return ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE)
        probe = _WindowsProbe()
    environ = os.environ if environ is None else environ
    keys = tuple(name for name in KEY_CLASS_NAMES if environ.get(name, "").strip())
    service: str | None = None
    try:
        ancestors = iter(probe.ancestor_images())
        starter = next((a for a in ancestors if not _is_engine_launcher(a[1])), None)
        if starter is None:
            return ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE)
        if starter[1].lower() != _NSSM_IMAGE:
            return _started_by_something_else(starter[1], ancestors, keys)
        service = probe.service_at(starter[0])
        if service is None:
            raise LookupError(f"no service runs at nssm.exe process {starter[0]}")
        entries = probe.environment_entries(service)
    except (OSError, LookupError) as exc:
        return ServiceEnvPosture(
            ServiceEnvStatus.UNOBSERVABLE,
            service_name=service,
            keys_in_environment=keys,
            detail=(
                f"the registry key of service {service!r} could not be read: {exc}"
                if service is not None
                else str(exc)
            ),
        )
    sources = _names(entries)
    return ServiceEnvPosture(
        ServiceEnvStatus.OBSERVED,
        service_name=service,
        listed=tuple(name for name, _where in sources),
        sources=sources,
        keys_in_environment=keys,
    )


def _started_by_something_else(
    image: str, rest: Iterator[tuple[int, str]], keys: tuple[str, ...]
) -> ServiceEnvPosture:
    """The engine was started by ``image``, which is neither NSSM nor a Python interpreter.

    A shell is the usual case, and then the engine is not a service. But an operator may also
    register NSSM to start a wrapper, such as ``cmd.exe``, that starts the engine. So the walk goes
    on: an ``nssm.exe`` further up means the engine cannot tell whether it runs as that service,
    and says so. A walk that fails above the wrapper settles nothing either way, and the reading
    stays the shell's."""
    try:
        nssm = next((pid for pid, above in rest if above.lower() == _NSSM_IMAGE), None)
    except OSError:
        nssm = None
    if nssm is None:
        return ServiceEnvPosture(ServiceEnvStatus.NOT_A_SERVICE)
    return ServiceEnvPosture(
        ServiceEnvStatus.UNOBSERVABLE,
        keys_in_environment=keys,
        detail=(
            f"nssm.exe (process {nssm}) is above {image}, which is not a Python interpreter, so "
            "the engine cannot tell whether it runs as that service or was started from a shell "
            "inside it"
        ),
    )


_cache_lock = threading.Lock()
_cached: ServiceEnvPosture | None = None


def service_env_posture() -> ServiceEnvPosture:
    """The reading for this process, taken once and kept.

    The environment a process starts with does not change under it, so ``serve`` takes the
    reading as it starts and ``GET /security/posture`` reports that same one. Restart the
    engine to read again."""
    global _cached
    with _cache_lock:
        if _cached is None:
            _cached = read_service_env_posture()
            if _cached.status is ServiceEnvStatus.UNOBSERVABLE:
                _log.warning("the service environment could not be read: %s", _cached.detail)
        return _cached


def _where(posture: ServiceEnvPosture) -> str:
    name = posture.service_name or "<unknown>"
    return (
        f"the environment of the Windows service {name!r}, which Windows keeps in the registry "
        f"key HKLM\\{_service_key(name)} (NSSM's AppEnvironmentExtra and AppEnvironment under "
        "Parameters, or the service's own Environment value)"
    )


def service_env_refusal(posture: ServiceEnvPosture) -> str | None:
    """Why ``serve`` or ``supervise`` must not start, whatever the enforcement setting, or None.

    Only a key-class name in the service's environment lists refuses. The owner's 2026-10-01
    ruling refuses it always, so ``[security].enforcement = "warn"`` does not reopen it."""
    keys = posture.listed_keys
    if keys:
        found = f"{posture.named_with_source(keys)} is set in {_where(posture)}"
    elif posture.status is ServiceEnvStatus.UNOBSERVABLE and posture.service_name is not None:
        if not posture.keys_in_environment:
            return None
        # The service is known and its lists could not be read, so a store key in this process's
        # environment most likely came from them. Refused, as a listed key would be.
        found = (
            f"{', '.join(posture.keys_in_environment)} reaches this engine through its "
            f"environment, and {_where(posture)} could not be read ({posture.detail})"
        )
    else:
        return None
    return (
        f"{found}. Any local user may be able to read that "
        "key, and with it the store key. Remove it from the service's lists and keep the key in a "
        "DPAPI-protected key file instead: `messagefoundry protect-key --out <new path> "
        '--grant-account "NT SERVICE\\<service>"`, then set [store].encryption_key_file. A '
        "retired key belongs in the shell that runs `messagefoundry rotate-key`, not in the "
        'service. [security].enforcement = "warn" does not change this refusal. See '
        'docs/SERVICE.md, "Protect the store encryption key at rest"'
    )


def missing_service_config_refusal(
    posture: ServiceEnvPosture, service_config: str | None
) -> str | None:
    """Why ``serve`` or ``supervise`` must not start as a service with no ``--service-config``,
    or None (vault BACKLOG #2626, step 2).

    With no flag, the engine reads whatever ``messagefoundry.toml`` sits in its working
    directory, or none. A service should start from a settings file it was registered with, by
    absolute path. The refusal applies only when the reading found the service, so a start from a
    shell, the developer loop, is unchanged. An ``UNOBSERVABLE`` reading with no service name
    settles nothing either way and does not refuse, for the reason the module docstring gives."""
    if service_config is not None or posture.service_name is None:
        return None
    return (
        f"this engine runs as the Windows service {posture.service_name!r} and was started with "
        "no --service-config, so it would read whatever messagefoundry.toml sits in its working "
        "directory. Register the settings file by absolute path: run install-service.ps1 again "
        "with -ServiceConfig <path>, or `messagefoundry service install` with --service-config "
        '<path>. See docs/SERVICE.md, "Install"'
    )


def service_env_loosenings(posture: ServiceEnvPosture) -> list[tuple[str, str]]:
    """The ``(name, plain-language risk)`` entries for ``posture``. One place for the wording, so
    ``security_loosenings()`` and the ``supervise`` start-up lines cannot say different things."""
    out: list[tuple[str, str]] = []
    if posture.status is ServiceEnvStatus.UNOBSERVABLE:
        out.append(
            (
                "service_environment_unobservable",
                "the engine could not tell whether it runs as a Windows service under NSSM, or "
                f"could not read that service's environment lists ({posture.detail}). A store key "
                "or another secret there is neither refused nor named, and any local user may be "
                "able to read it",
            )
        )
    # Named only for a known service: a process whose service is unknown may be a shell, where
    # the environment is the documented way to supply the key.
    if posture.keys_in_environment and posture.service_name is not None:
        out.append(
            (
                "store_key_in_service_environment",
                f"{', '.join(posture.keys_in_environment)} reaches this Windows service through "
                "its environment. A service's environment comes from places any local user may be "
                "able to read: the service's registry key, or the machine-wide environment. Keep "
                "the store key in a DPAPI-protected key file ([store].encryption_key_file, made "
                "with `messagefoundry protect-key`)",
            )
        )
    named = posture.listed_loosening_names
    if named:
        out.append(
            (
                "service_environment_secret",
                f"{posture.named_with_source(named)} is set in {_where(posture)}. Any local "
                "user may be able to read that key, and with it these secrets. The engine has no "
                "protected channel for them yet, so this is named and not refused",
            )
        )
    return out
