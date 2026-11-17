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
* **Another engine secret there refuses the start too, whatever ``[security].enforcement``
  says.** The same ruling covers it. Its protected alternative is the secrets directory
  ``MEFOR_SECRETS_DIRECTORY`` names (:mod:`messagefoundry.engine_secrets`, ADR 0214), and the
  refusal points there (vault BACKLOG #2595, slice B).
* **So does every ``MEFOR_VALUE_*`` variable there, whatever ``[security].enforcement`` says.**
  The owner ruled on 2026-11-14 that the same ruling covers an ``env()`` value (vault BACKLOG
  #8212 item 7). The engine cannot tell which of them is a secret, so it refuses each, and counts
  them without printing a name it read from the registry. The way in is the secrets directory,
  or the environment's value file for a value that is not a secret and is the same for every
  instance.
* **Each refusal above is ``serve``'s and ``supervise``'s, and the API app factories'.**
  ``create_app`` and ``create_managed_app`` raise on the same finding as they are built (vault
  BACKLOG #8212 item 1). The loosening ``secret_in_service_environment`` names it for a caller
  that reads the loosenings with no refusal of its own.
* **A store key that reaches a Windows service through its environment is named** (key-custody
  slice S2a), wherever it came from, since the machine-wide environment is readable by every
  local user too.

**How the engine finds its own service.** Under NSSM the engine is a child of ``nssm.exe``, or a
grandchild when a virtual environment's ``python.exe`` starts the base interpreter, or further
down under ``supervise``. The reading walks up through Python interpreter and
``messagefoundry.exe`` processes only. When the first other process is ``nssm.exe``, it asks the
Service Control Manager which service runs there. Any other process means the engine was started
by something else, such as a shell, even when that shell itself runs under some other NSSM service.

**What it does not cover**, at least: a service host other than NSSM, an ``nssm.exe`` renamed to
something else, a launcher between NSSM and the interpreter that is not a Python interpreter or
the ``messagefoundry`` launcher, and a variable an operator names as a ``[secrets].provider =
"env"`` reference, whose name the engine does not read here, unless that name starts with
``MEFOR_VALUE_``, which is refused as every such name is; and any secret or ``MEFOR_VALUE_*``
variable, other than a store key, that reaches the engine from the machine-wide environment. An
``env()`` value's ``MEFOR_VALUE_*`` name in the service's own lists is covered.

**Not a refusal when the read fails, with one exception.** An engine that cannot walk its
ancestors, or cannot read its service's lists, reports ``service_environment_unobservable`` and
starts, and a secret in those lists goes unrefused. The exception: a known service whose lists
could not be read refuses a store key in this process's environment, since it most likely came
from them.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol

from messagefoundry import engine_secrets as _setting_names
from messagefoundry.service_status import is_safe_service_name

_log = logging.getLogger(__name__)

#: The key-class names: the store key and its decrypt-only retired keys. Either one decrypts the
#: store. In a Windows service's environment lists they refuse the start.
KEY_CLASS_NAMES: tuple[str, ...] = _setting_names.KEY_CLASS_NAMES

#: The engine's other secret-class names, the ones the secrets directory supplies. In a Windows
#: service's environment lists each refuses the start, as a key-class name does. Both lists come
#: from the one list in :mod:`messagefoundry.engine_secrets`, which
#: ``tests/test_service_env_secrets.py`` holds to the settings' own lists of environment-only
#: secrets, so a secret added there is not missed here.
#:
#: WHY "DIRECTORY" AND NOT "SECRET". The identifier names where these settings belong, because
#: CodeQL's ``py/clear-text-logging-sensitive-data`` takes a value as a secret by the identifier
#: it is bound to, such as one that says secret or password. These are names only, printed on
#: purpose, so no identifier in this module says such a word. The test file pins that for this
#: module only, against its own stand-in list of words; a caller that binds the printed lines to
#: such a name brings the alert back.
DIRECTORY_CLASS_NAMES: tuple[str, ...] = _setting_names.DIRECTORY_SETTING_NAMES

#: ``engine_secrets.SECRETS_DIRECTORY_VARIABLE``, spelled out so no identifier here says the word
#: the CodeQL note above is about; ``tests/test_service_env_secrets.py`` holds the two equal.
_DIRECTORY_VARIABLE = "MEFOR_SECRETS_DIRECTORY"

#: The prefix of an ``env()`` value's variable. Every listed name that starts with it refuses.
_VALUE_PREFIX = _setting_names.VALUE_PREFIX

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
    #: Every variable name the service's environment lists set, upper-cased, under either
    #: reading of a string (:func:`_listed`): each name ``sources`` holds, each string's name as
    #: ``main`` read it, and each name a later line of it sets. Empty unless ``status`` is
    #: ``OBSERVED``.
    listed: tuple[str, ...] = ()
    #: ``(name, registry value)`` for each name in ``listed``, so a refusal can say which value
    #: to change.
    sources: tuple[tuple[str, str], ...] = ()
    #: The key-class names set, and not empty, in THIS process's environment, wherever they came
    #: from. Empty when ``status`` is ``NOT_A_SERVICE``.
    keys_in_environment: tuple[str, ...] = ()
    #: Why the reading failed (``UNOBSERVABLE``).
    detail: str = ""
    #: The ``MEFOR_VALUE_*`` names in ``listed`` that an entry sets empty or blank, so the
    #: refusal can say to delete it rather than move it.
    empty_value_names: tuple[str, ...] = ()
    #: The ``MEFOR_VALUE_*`` names in ``listed`` that an entry spells, as written in the
    #: registry, with a character the secrets directory refuses in a file name.
    unplain_value_names: tuple[str, ...] = ()

    @property
    def listed_keys(self) -> tuple[str, ...]:
        """The key-class names the service's environment lists set."""
        return tuple(name for name in KEY_CLASS_NAMES if name in self.listed)

    @property
    def listed_directory_names(self) -> tuple[str, ...]:
        """The other engine secrets the service's environment lists set. Each comes from
        :data:`DIRECTORY_CLASS_NAMES`, never from the registry."""
        return tuple(name for name in DIRECTORY_CLASS_NAMES if name in self.listed)

    @property
    def listed_value_names(self) -> tuple[str, ...]:
        """The ``MEFOR_VALUE_*`` names the service's environment lists set. Unlike the two
        properties above, these come from the registry, so a refusal counts them and never prints
        one: an operator may have typed a value where the name goes. The bare prefix is one too:
        it names no ``env()`` key, but a value set under it is as readable as any other."""
        return tuple(name for name in self.listed if name.startswith(_VALUE_PREFIX))

    def named_with_source(self, names: Sequence[str]) -> str:
        """``names``, each with the registry value that sets it."""
        where = dict(self.sources)
        return ", ".join(f"{name} (in {where[name]})" if name in where else name for name in names)

    def counted_with_source(self, names: Sequence[str]) -> str:
        """How many of ``names`` each registry value sets, with no name printed. The names were
        de-duplicated without regard to case as they were read, each credited to the first
        registry value that sets it, so a name a later value also sets is counted there only."""
        where = dict(self.sources)
        counts: dict[str, int] = {}
        for name in names:
            source = where.get(name, "an unknown value")
            counts[source] = counts.get(source, 0) + 1
        return ", ".join(f"{n} MEFOR_VALUE_* variable(s) (in {src})" for src, n in counts.items())


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
        try:
            proc = psutil.Process()
        except psutil.Error as exc:
            raise OSError(f"this process could not be queried: {exc}") from exc
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


#: What splits one registry string into lines. A single ``REG_SZ`` value can hold several
#: ``NAME=value`` lines, and one ``REG_MULTI_SZ`` item can too. No NUL: ``winreg`` cuts a
#: ``REG_SZ`` at its first one and splits a ``REG_MULTI_SZ`` on them, so none reaches here.
_LINE_BREAK = re.compile(r"\r\n|[\r\n]")

#: A later line that sets an ordinary variable: a name Windows allows in an environment block,
#: which is any non-blank text without an equals sign (``ProgramFiles(x86)`` among them), then an
#: equals sign, then a value holding something other than equals signs and blanks. Such a line
#: ends the variable above it. A line of base64 does not match, since its only equals signs are
#: the padding at its end, and neither does a line of PEM armour, which holds no equals sign. So
#: ``OTHER=`` with an empty value does not match either, and is read as part of the value above
#: it: a store key left empty above it then reads as set, an error toward refusing.
_ORDINARY_LINE = re.compile(r"\s*[^=\s][^=]*=(?!=*\s*\Z)")

#: The secret-class names, the two lists above together, both taken from ``engine_secrets``.
_REFUSED_CLASS_NAMES = frozenset((*KEY_CLASS_NAMES, *DIRECTORY_CLASS_NAMES))


def _refused_name(name: str) -> bool:
    """Whether the upper-cased ``name`` is one the refusal is about: a secret-class name or a
    ``MEFOR_VALUE_*`` one, the three classes ``listed_keys``, ``listed_directory_names`` and
    ``listed_value_names`` read. A line of PEM armour cannot start one, and nor can a line of
    standard base64, which has no underscore. Base64url has one, so a line of it could in
    principle start ``MEFOR_VALUE_``; it is then read as a name, which refuses rather than
    misses."""
    return name in _REFUSED_CLASS_NAMES or name.startswith(_VALUE_PREFIX)


@dataclass(frozen=True, slots=True)
class _Variable:
    """One variable as :func:`_variables` reads it from a registry string. Kept only while the
    read runs: :func:`_names` drops the value."""

    #: The registry value, and the line when the variable is not on its string's first line.
    where: str
    #: The name as written, stripped.
    written: str
    #: The rest of its line, and every line after it up to the next variable's. Left out of the
    #: repr, since it may hold the secret itself.
    value: str = field(repr=False)
    #: Whether NSSM may read the name with a line break in it.
    broken: bool = False


def _variables(entries: Sequence[tuple[str, str]]) -> list[_Variable]:
    """The variables each registry string sets, read a line at a time (vault BACKLOG #5394).

    The reader cannot tell whether NSSM takes a line or the whole string as a variable, so it
    keeps what either reading would refuse. Each string's first non-blank line is a variable when
    it holds an equals sign: blank lines above it are skipped, as ``main``'s strip of the name
    skipped them, so a secrets directory set below a blank first line is still read as set. A
    later line is one when it sets a name the refusal is about, so a store key on a later line
    still refuses. A later line that sets an ordinary variable
    (:data:`_ORDINARY_LINE`) ends the value above it under the line reading, and is not kept:
    under the whole-string reading it sets nothing, so the secrets directory's name is never taken
    as set by a later line. Any other line, such as one of key material, belongs to the value
    above it, so a key whose value starts on the next line is not empty.

    Each string is also read whole, as ``main`` read it: the name before its first equals sign,
    stripped, and everything after it as the value. That variable is kept when its name is one
    the refusal is about. So ``KEY=`` above another variable's line, a path-form OIDC key above a
    line holding PEM armour, a blank first line, or a line break before the equals sign refuses
    as ``main`` refused it. Where that name still holds a line break, such as ``MEFOR_VALUE_A``
    on a first line with no equals sign, the engine loads a variable whose name starts with it.
    It is kept unless a later line sets a name :func:`_names` keeps, since both readings then
    describe the same variable and it is counted once."""
    read: list[_Variable] = []
    for where, entry in entries:
        lines = _LINE_BREAK.split(entry)
        # ``skip`` keeps the later lines' numbers counted from the string's real first line.
        skip = next((i for i, line in enumerate(lines) if line.strip()), len(lines) - 1)
        first, *rest_lines = lines[skip:]
        first_written, first_equals, first_rest = first.partition("=")
        first_written = first_written.strip()
        first_parts = [first_rest]
        # A later line kept as a variable: its line number, name as written and value parts.
        later: list[tuple[int, str, list[str]]] = []
        parts = first_parts  # the value the current line belongs to
        for number, line in enumerate(rest_lines, skip + 2):
            written, equals, rest = line.partition("=")
            if not equals:
                parts.append(line)
                continue
            written = written.strip()
            if _refused_name(written.upper()):
                parts = [rest]
                later.append((number, written, parts))
            elif _ORDINARY_LINE.match(line):
                parts = [rest]  # ends the value above, and is not kept
            else:
                parts.append(line)
        later_variables = [
            _Variable(
                f"{where}, line {number} of a string whose first line is another entry",
                written,
                "\n".join(value_parts),
            )
            for number, written, value_parts in later
        ]
        if first_equals:
            read.append(_Variable(where, first_written, "\n".join(first_parts)))
        # The whole-string reading, exactly as ``main`` read every entry: the name is everything
        # before the first equals sign, stripped, and the value everything after it. Kept when that
        # name is one the refusal is about, so a blank first line, a line break before the equals
        # sign, or a value empty on its own line but not in its string refuses as ``main`` refused
        # it. A name that still holds a line break is counted once: only when no later line sets a
        # name :func:`_names` keeps, since both readings then describe the same variable.
        whole_written, whole_equals, whole_value = entry.partition("=")
        whole_written = whole_written.strip()
        broken = _LINE_BREAK.search(whole_written) is not None
        if (
            whole_equals
            and _refused_name(whole_written.upper())
            and not (broken and _names(later_variables))
        ):
            # A broken name is kept under its first line, as the line reading names it.
            name = _LINE_BREAK.split(whole_written, 1)[0].rstrip() if broken else whole_written
            read.append(_Variable(where, name, whole_value, broken=broken))
        read.extend(later_variables)
    return read


def _names(variables: Sequence[_Variable]) -> tuple[tuple[str, str], ...]:
    """The upper-cased names of the variables set to a secret. The value is dropped here and
    never kept. An empty value carries no secret, so its name is not kept, except a
    ``MEFOR_VALUE_*`` name, which the owner's ruling refuses whatever it holds and whose empty
    value the engine still overlays on the value file. A path in a name that takes either a key or
    its path is not a secret, so that name is not kept either. Windows compares environment names
    without case, so this does too. Each name is returned with the first registry value, and the
    line, that sets it."""
    names: dict[str, str] = {}
    for variable in variables:
        name = variable.written.upper()
        value = variable.value
        # An ``env()`` value is kept even when empty: the engine overlays an empty one on the
        # value file, so it still decides what ``env()`` returns (vault BACKLOG #8212 item 7).
        if not name or not ((value and not value.isspace()) or name.startswith(_VALUE_PREFIX)):
            continue
        if name in _INLINE_PEM_NAMES and "-----BEGIN" not in value:
            continue
        names.setdefault(name, variable.where)
    return tuple(names.items())


def _listed(
    entries: Sequence[tuple[str, str]], sources: Sequence[tuple[str, str]]
) -> tuple[str, ...]:
    """Every name either reading of a string sets, for ``ServiceEnvPosture.listed`` (vault
    BACKLOG #5394). It starts with the names in ``sources``, the ones :func:`_names` keeps, so
    the secret-class names, and so what refuses, are exactly theirs. To them it adds two kinds,
    so a remedy never says a name the lists set is unset, as one saying the secrets directory is
    missing would. One is each string's name as ``main`` read it: the stripped text before its
    first equals sign, kept under ``main``'s rule for an empty value, so ``FOO=`` above another
    line, or ``MEFOR_SECRETS_DIRECTORY`` with a line break before its equals sign, is listed as
    ``main`` listed it. A ``MEFOR_VALUE_*`` name that still holds a line break is left out: it is
    the variable :func:`_variables` keeps, and counts, under its first line. The other is each
    name a later line sets as an ordinary variable (:data:`_ORDINARY_LINE`), which the line
    reading takes as set. Neither kind is a secret-class name, beyond one ``main`` also kept."""
    listed = dict.fromkeys(name for name, _where in sources)
    for _where, entry in entries:
        name, equals, value = entry.partition("=")
        name = name.strip().upper()
        kept = name and (value.strip() or (equals and name.startswith(_VALUE_PREFIX)))
        pem_path = name in _INLINE_PEM_NAMES and "-----BEGIN" not in value
        broken = _refused_name(name) and _LINE_BREAK.search(name) is not None
        if kept and not pem_path and not broken:
            listed.setdefault(name)
        for line in _LINE_BREAK.split(entry)[1:]:
            written, _equals, _rest = line.partition("=")
            written = written.strip().upper()
            if _ORDINARY_LINE.match(line) and not _refused_name(written):
                listed.setdefault(written)
    return tuple(listed)


def _value_entry_shapes(
    variables: Sequence[_Variable],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(empty, unplain)``: the upper-cased ``MEFOR_VALUE_<KEY>`` names a variable sets empty or
    blank, and those spelled with a character other than an ASCII letter, a digit or an
    underscore, a line break NSSM may read into the name among them. The second is judged on the
    name as written, before upper-casing, because ``str.upper`` maps some non-ASCII letters onto
    ASCII ones (``engine_secrets`` holds its file names to the same rule for that reason). The
    bare prefix is in neither. Names only."""
    empty: dict[str, None] = {}
    unplain: dict[str, None] = {}
    for variable in variables:
        written = variable.written
        name = written.upper()
        if not name.startswith(_VALUE_PREFIX) or name == _VALUE_PREFIX:
            continue
        if not variable.value or variable.value.isspace():
            empty[name] = None
        if variable.broken or not (written.isascii() and _setting_names.is_value_name(name)):
            unplain[name] = None
    return tuple(empty), tuple(unplain)


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
    variables = _variables(entries)
    sources = _names(variables)
    empty, unplain = _value_entry_shapes(variables)
    return ServiceEnvPosture(
        ServiceEnvStatus.OBSERVED,
        service_name=service,
        listed=_listed(entries, sources),
        sources=sources,
        keys_in_environment=keys,
        empty_value_names=empty,
        unplain_value_names=unplain,
    )


def _started_by_something_else(
    image: str, rest: Iterator[tuple[int, str]], keys: tuple[str, ...]
) -> ServiceEnvPosture:
    """The engine was started by ``image``, which is neither NSSM, a Python interpreter, nor
    ``messagefoundry.exe``.

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
            f"nssm.exe (process {nssm}) is above {image}, which is neither a Python interpreter "
            "nor messagefoundry.exe, so the engine cannot tell whether it runs as that service "
            "or was started from a shell inside it"
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


class ServiceEnvironmentRefused(Exception):  # noqa: N818 - a refusal, not an error condition
    """An API app factory refused to build on :func:`service_env_refusal`'s finding.

    Not a ``RuntimeError``, so a handler written for another build failure, such as the absent
    web console ``create_app(serve_ui=True)`` reports, does not catch this refusal with it."""


def service_env_refusal(posture: ServiceEnvPosture) -> str | None:
    """Why ``serve``, ``supervise`` or an API app factory must not start, whatever the enforcement
    setting, or None.

    Every secret-class name in the service's environment lists refuses, a key-class name and each
    name the secrets directory supplies, and so does every ``MEFOR_VALUE_*`` name (the owner's
    2026-11-14 ruling). The owner's 2026-10-01 ruling refuses them always, so
    ``[security].enforcement = "warn"`` does not reopen it. A known
    service whose lists could not be read refuses only on a store key in this process's
    environment, since only the store key's names are read from it."""
    found = _refusal_findings(posture)
    if found is None:
        return None
    return f'{found}. [security].enforcement = "warn" does not change this refusal'


def _refusal_findings(posture: ServiceEnvPosture) -> str | None:
    """What :func:`service_env_refusal` refuses on and the remedy, without its enforcement note,
    which the ``secret_in_service_environment`` entry has no refusal to attach to."""
    keys = posture.listed_keys
    others = posture.listed_directory_names
    values = posture.listed_value_names
    if keys or others or values:
        named = [posture.named_with_source((*keys, *others))] if keys or others else []
        if values:
            named.append(posture.counted_with_source(values))
        found = f"{', '.join(named)} is set in {_where(posture)}"
    elif posture.status is ServiceEnvStatus.UNOBSERVABLE and posture.service_name is not None:
        if not posture.keys_in_environment:
            return None
        # The service is known and its lists could not be read, so a store key in this process's
        # environment most likely came from them. Refused, as a listed key would be, and with the
        # same remedy, so ``keys`` now names them.
        keys = posture.keys_in_environment
        found = (
            f"{', '.join(keys)} reaches this engine through its "
            f"environment, and {_where(posture)} could not be read ({posture.detail})"
        )
    else:
        return None
    steps: list[str] = []
    if keys:
        steps.append(
            "Keep the store key in a DPAPI-protected key file instead: `messagefoundry protect-key "
            '--out <new path> --grant-account "NT SERVICE\\<service>"`, then set '
            "[store].encryption_key_file. A retired key belongs in the shell that runs "
            '`messagefoundry rotate-key`, not in the service. See docs/SERVICE.md, "Protect the '
            'store encryption key at rest"'
        )
    if others or values:
        put = [", ".join(others)] if others else []
        if values:
            put.append("each MEFOR_VALUE_* variable")
        step = (
            f"Put {' and '.join(put)} in the secrets directory MEFOR_SECRETS_DIRECTORY names, as "
            "one restricted file per setting named as its variable"
        )
        cite = 'See docs/CONFIGURATION.md, "The secrets directory"'
        if values:
            step += (
                ". A MEFOR_VALUE_* value that is not a secret and is the same for every instance "
                "of the environment may go in its value file instead, environments/<env>.toml by "
                "default, keyed by the name after MEFOR_VALUE_ in lower case. Each MEFOR_VALUE_* "
                "name is counted once, without regard to case, under the first registry value "
                "that sets it, so remove it from every value that sets it"
            )
            if _VALUE_PREFIX in values:
                step += (
                    ". The bare name MEFOR_VALUE_ sets no env() key, so delete that entry rather "
                    "than move it"
                )
            if posture.empty_value_names:
                step += (
                    ". An empty or blank MEFOR_VALUE_* entry is refused too: delete it, or, where "
                    "an empty override is really wanted, write it in the value file instead, "
                    "since the secrets directory refuses an empty file"
                )
            if posture.unplain_value_names:
                step += (
                    ". At least one of them is spelled with a character other than an ASCII "
                    "letter, a digit or an underscore, a file name the secrets directory refuses, "
                    "so rename that env() key before moving it there"
                )
            step += (
                '. A MEFOR_VALUE_* variable that a [secrets].provider = "env" reference names is '
                "read from the environment only, never from the secrets directory. Drop that "
                "reference instead and put the credential in the secrets directory under the "
                "setting it stands for, such as MEFOR_AUTH_AD_BIND_PASSWORD; or, second, use "
                '[secrets].provider = "vault", which applies to every such reference in the '
                "engine. Renaming the variable outside MEFOR_VALUE_* ends this refusal but leaves "
                "the secret in the registry key"
            )
            cite += ' and "[environments]"'
        steps.append(f"{step}. {cite}")
        if _DIRECTORY_VARIABLE not in posture.listed:
            # Two routes, because install-service.ps1 refuses an existing directory the service
            # does not name: an operator whose later `nssm set` dropped the variable must not be
            # sent to the installer, which would say to remove the directory holding the files.
            steps.append(
                f"The service's lists set no {_DIRECTORY_VARIABLE}. Where install-service.ps1 "
                f"already made the secrets directory, add {_DIRECTORY_VARIABLE} naming that "
                "existing path back to the service's AppEnvironmentExtra, beside its other "
                "entries, before any re-run of the installer, which refuses an existing directory "
                "the service does not name. `nssm set` replaces that whole list, so read it first "
                "with `nssm get`, running the service's own nssm.exe by its full path, and pass "
                "back every entry but those refused above: see docs/SERVICE.md, "
                '"Start / stop / status". Where none exists yet, the bullet "The other secrets: '
                'a secrets directory" under docs/SERVICE.md, "Protect the store encryption key at '
                'rest", says how the directory is created'
            )
    return (
        f"{found}. Any local user may be able to read that key, and with it each value refused "
        f"here. Remove each refused variable from the service's lists. {'. '.join(steps)}"
    )


def missing_service_config_refusal(
    posture: ServiceEnvPosture, service_config: str | None
) -> str | None:
    """Why ``serve`` or ``supervise`` must not start as a service without an absolute
    ``--service-config``, or None (vault BACKLOG #2626, step 2).

    ``service_config`` is the flag as anchored under ``--project-root``. With no flag, or a
    relative one and no root, the engine reads a ``messagefoundry.toml`` from its working
    directory. A service should start from the settings file it was registered with, by absolute
    path. The refusal applies only when the reading found the service, so a start from a shell, the
    developer loop, is unchanged. An ``UNOBSERVABLE`` reading with no service name settles nothing
    either way and does not refuse, for the reason the module docstring gives."""
    if posture.service_name is None:
        return None
    if service_config is None:
        started = "no --service-config"
    elif not Path(service_config).is_absolute():
        started = f"--service-config {service_config!r}, which is not an absolute path"
    else:
        return None
    return (
        f"this engine runs as the Windows service {posture.service_name!r} and was started with "
        f"{started}, so it would read a messagefoundry.toml from its working directory. Register "
        "the settings file by absolute path: run install-service.ps1 again with -ServiceConfig "
        "<path>, or `messagefoundry service install` with --service-config <path>. See "
        'docs/SERVICE.md, "Install"'
    )


def service_env_loosenings(posture: ServiceEnvPosture) -> list[tuple[str, str]]:
    """The ``(name, plain-language risk)`` entries for ``posture``. One place for the wording, so
    ``security_loosenings()`` and the ``supervise`` start-up lines cannot say different things.

    A caller that refuses on :func:`service_env_refusal` checks it first, as ``serve``,
    ``supervise``, ``create_app`` and ``create_managed_app`` do, so
    ``secret_in_service_environment`` reaches only a caller that does not."""
    out: list[tuple[str, str]] = []
    if posture.status is ServiceEnvStatus.UNOBSERVABLE:
        out.append(
            (
                "service_environment_unobservable",
                "the engine could not tell whether it runs as a Windows service under NSSM, or "
                f"could not read that service's environment lists ({posture.detail}), so it "
                "cannot say whether a store key or another secret is in them. Any local user may "
                "be able to read one there",
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
    # What `serve`, `supervise` and the API app factories refuse, named for a caller that reads
    # this list with no refusal of its own, rather than going quiet. Those refuse before they read
    # it, so it never reaches them.
    refused = _refusal_findings(posture)
    if refused is not None:
        out.append(
            (
                "secret_in_service_environment",
                "`serve`, `supervise` and the API app factories would refuse to start on this: "
                f"{refused}",
            )
        )
    return out
