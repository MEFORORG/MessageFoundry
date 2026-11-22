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

import bisect
import logging
import os
import re
import sys
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import Enum
from pathlib import Path
from typing import Literal, Protocol

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
    #: The variable names the service's environment lists set that the refusal reads, upper-cased:
    #: each secret-class or ``MEFOR_VALUE_*`` name, and ``MEFOR_SECRETS_DIRECTORY``. Any other
    #: name is left out, since the text before an equals sign may be key material, such as a line
    #: of padded base64 (vault BACKLOG #5394). Empty unless ``status`` is ``OBSERVED``. Left out
    #: of the repr, with the other fields below that hold registry text: an operator may have
    #: typed a value where a ``MEFOR_VALUE_*`` name goes.
    listed: tuple[str, ...] = field(default=(), repr=False)
    #: ``(name, registry value)`` for each name in ``listed``, so a refusal can say which value
    #: to change.
    sources: tuple[tuple[str, str], ...] = field(default=(), repr=False)
    #: ``(name, line)`` for each name in ``listed`` that is not on its registry string's first
    #: line, so a refusal can say where in that string to look.
    source_lines: tuple[tuple[str, int], ...] = field(default=(), repr=False)
    #: The key-class names set, and not empty, in THIS process's environment, wherever they came
    #: from. Empty when ``status`` is ``NOT_A_SERVICE``.
    keys_in_environment: tuple[str, ...] = ()
    #: Why the reading failed (``UNOBSERVABLE``).
    detail: str = ""
    #: The ``MEFOR_VALUE_*`` names in ``listed`` that an entry sets empty or blank, so the
    #: refusal can say to delete it rather than move it.
    empty_value_names: tuple[str, ...] = field(default=(), repr=False)
    #: The ``MEFOR_VALUE_*`` names that an entry spells, as written in the registry, with a
    #: character the secrets directory refuses in a file name. Most are in ``listed``; a name
    #: holding a line break that is counted under a later line's name is not.
    unplain_value_names: tuple[str, ...] = field(default=(), repr=False)
    #: Whether a refused name's value, empty in its own string, runs on into the next strings of
    #: its registry value, so the refusal can say to remove those strings too.
    value_runs_on: bool = False
    #: Whether a string read as part of a value that runs on sets ``MEFOR_SECRETS_DIRECTORY`` on
    #: its first line, as ``MEFOR_SECRETS_DIRECTORY==`` does (:func:`_continues_string`), whether
    #: or not :func:`_names` keeps the variable it was joined to.
    #: NSSM may read that string as its own variable, so the refusal must not say the lists set no
    #: secrets directory. It may also hold the value, so the refusal says to remove it, whatever
    #: it holds, and to write ``MEFOR_SECRETS_DIRECTORY=<path>`` again on its own.
    directory_joined: bool = False

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
        """``names``, each with the registry value that sets it, and the line of its string when
        that is not the first."""
        where = dict(self.sources)
        lines = dict(self.source_lines)

        def located(name: str) -> str:
            if name not in where:
                return name
            if name in lines:
                return (
                    f"{name} (in {where[name]}, line {lines[name]} of the registry string that "
                    "sets it)"
                )
            return f"{name} (in {where[name]})"

        return ", ".join(located(name) for name in names)

    def counted_with_source(self, names: Sequence[str]) -> str:
        """How many of ``names`` each registry value sets, with no name printed. The names were
        de-duplicated without regard to case as they were read, each credited to the first
        registry value that sets it, so a name a later value also sets is counted there only. The
        count is per registry value, never per line, so the text does not grow with the number of
        lines one string holds."""
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
#: ends the variable above it, except below an empty secret-class value, where
#: :func:`_ends_blank_class` decides instead. A line of base64 does
#: not match, since its only equals signs are the padding at its end, and neither does a line of
#: PEM armour, which holds no equals sign. So ``OTHER=`` with an empty value does not match
#: either, nor does one whose value is only equals signs and blanks in any order, and each is
#: read as part of the value above it: a store key left empty above it then reads as set, an
#: error toward refusing.
_ORDINARY_LINE = re.compile(r"\s*[^=\s][^=]*=(?![=\s]*\Z)")

#: A run of 43 standard base64 characters: a store key, 32 bytes, less its one padding character.
#: A retired-keys list, ``<key>,<key>``, reads as ``NAME=value`` with the first key in the name,
#: and so does a key quoted or led by a comma. So a line whose name holds such a run is read as
#: key material, never as a variable that ends the value above it (vault BACKLOG #5394). No engine
#: name holds one, since each has an underscore, which standard base64 lacks. Any other name with
#: 43 such characters in a row, such as a hex digest, is read as key material too, an error toward
#: refusing.
_KEY_SHAPED_RUN = re.compile(r"[A-Za-z0-9+/]{43}")

#: One 32-byte secret, whole (vault BACKLOG #5394 added items 6 and 12): 43 characters of the
#: standard base64 alphabet and its one ``=``, as a store key is written, or 43 of the base64url
#: alphabet with or without that ``=``. Length alone does not tell a secret from a name, a path or a
#: service name, so :func:`_is_one_key_text` also asks for what a random secret of that length all
#: but always holds: letters of both cases and, in base64url, whose alphabet a mixed-case name
#: shares, a digit. A name or value of that exact shape that is not a secret is read as one too,
#: an error toward refusing.
_STANDARD_KEY_TEXT = re.compile(r"[A-Za-z0-9+/]{43}=")
_URLSAFE_KEY_TEXT = re.compile(r"[A-Za-z0-9_-]{43}=?")


#: Text of the standard base64 alphabet alone, as the body of a padded secret is.
_BASE64_TEXT = re.compile(r"[A-Za-z0-9+/]+")

#: The names Windows itself sets in a service's environment, each spelled exactly as Windows
#: spells it, at least these. Matched with case, unlike the comparison Windows makes, so mixed-case
#: secret text such as ``Public=Summer!`` is not taken for ``PUBLIC`` (:func:`_ends_blank_class`).
#: A name missing from it only refuses more.
_WINDOWS_NAMES = frozenset(
    (
        "ALLUSERSPROFILE",
        "APPDATA",
        "CommonProgramFiles",
        "CommonProgramFiles(x86)",
        "CommonProgramW6432",
        "COMPUTERNAME",
        "ComSpec",
        "DriverData",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "LOGONSERVER",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "Path",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_IDENTIFIER",
        "PROCESSOR_LEVEL",
        "PROCESSOR_REVISION",
        "ProgramData",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "PSModulePath",
        "PUBLIC",
        "SystemDrive",
        "SystemRoot",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERDOMAIN_ROAMINGPROFILE",
        "USERNAME",
        "USERPROFILE",
        "windir",
    )
)


def _ends_blank_class(line: str) -> bool:
    """Whether ``line``, below a secret-class value (:data:`_REFUSED_CLASS_NAMES`) that is empty
    or blank so far, is a variable of its own that ends that value. This is the one statement of
    the fail-closed rule (vault BACKLOG #5394, added items 6 and 12); the readers that apply it
    point here.

    The reader cannot tell such a line or item from the secret ``nssm set`` split from its name,
    so it is read as the secret's value, and refuses, unless it is exactly one of:

    * an ordinary line (:func:`_is_ordinary_line`) under a name Windows itself sets, spelled as
      Windows spells it (:data:`_WINDOWS_NAMES`), such as ``Path=C:\\x``;
    * an ordinary line under ``MEFOR_SECRETS_DIRECTORY`` in upper case, so an item that sets the
      directory is still read as setting it (a later line of one string never is, under the
      line rule :func:`_variables` states);

    and its value is not one secret or a list of them (:func:`_is_key_value`). So ``Path=<key>``
    or ``MEFOR_SECRETS_DIRECTORY=<key>`` there is read as the secret's value (vault BACKLOG #5394
    added items 6 and 12), an error toward refusing: such a variable whose whole value has a
    secret's shape makes an empty secret above it read as set.

    No other name ends the value, however conventional: ``HTTP_PROXY=x``, ``TZ=UTC``,
    ``MEFOR_AI_ENVIRONMENT=prod``, ``Public=Summer!``, ``PATH=,C:\\x`` and ``=orphan`` all refuse,
    and the refusal names the secret-class variable. A line led by blanks is not exact either.
    Nor does any equals-led line, Windows' own nameless entries such as ``=C:=C:\\x`` and
    ``=ExitCode=0`` among them: the plain line rule reads such a later line of one string as the
    value above it, and so refuses, and this rule refuses no less
    (``tests/test_b532w3_serviceenv_split_shapes.py`` pins it). What
    this misses, at least: a secret whose own text is exactly such a line, such as
    ``OS=Summer!``."""
    name, _equals, value = line.partition("=")
    return (
        (name in _WINDOWS_NAMES or name == _DIRECTORY_VARIABLE)
        and _is_ordinary_line(line)
        and not _is_key_value(value)
    )


def _mixed_case(text: str) -> bool:
    """Whether ``text`` holds both an ASCII upper-case and an ASCII lower-case letter."""
    return any("a" <= c <= "z" for c in text) and any("A" <= c <= "Z" for c in text)


def _is_one_key_text(text: str) -> bool:
    """Whether ``text`` is exactly one 32-byte secret (:data:`_STANDARD_KEY_TEXT`,
    :data:`_URLSAFE_KEY_TEXT`)."""
    if not _mixed_case(text):
        return False
    if _STANDARD_KEY_TEXT.fullmatch(text) is not None:
        return True
    return _URLSAFE_KEY_TEXT.fullmatch(text) is not None and any(c.isdigit() for c in text)


def _holds_key_run(text: str) -> bool:
    """Whether ``text`` holds a store-key-shaped run (:data:`_KEY_SHAPED_RUN`), or, stripped, is
    one base64url secret less its padding (:func:`_is_one_key_text`), as the name a secret with one
    ``=`` of padding reads as."""
    return _KEY_SHAPED_RUN.search(text) is not None or _is_one_key_text(text.strip())


def _is_key_value(text: str) -> bool:
    """Whether ``text``, stripped and with one pair of surrounding quotes taken off, is one secret
    or a comma-separated list of them with no empty entry (:func:`_is_one_key_text`; vault
    BACKLOG #5394 added items 6 and 12). A retired-keys list the engine would load with an empty
    entry, from a trailing or doubled comma, is not read as one, a known gap."""
    value = text.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    return all(_is_one_key_text(part.strip()) for part in value.split(","))


def _is_ordinary_line(line: str) -> bool:
    """Whether ``line`` sets an ordinary variable (:data:`_ORDINARY_LINE`) and its name holds no
    key material (:func:`_holds_key_run`)."""
    return bool(_ORDINARY_LINE.match(line)) and not _holds_key_run(line.partition("=")[0])


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


def _starts_refused(written: str, *, below_empty_class: bool) -> bool:
    """Whether the text before a line's first equals sign, ``written``, names a variable the
    refusal is about (:func:`_refused_name`), so the line starts a variable of its own. Below an
    empty secret-class value a name that takes either a key or its path
    (:data:`_INLINE_PEM_NAMES`) must be in upper case, as the engine spells it: mixed-case text
    such as ``Mefor_Auth_Oidc_Client_Private_Key=Summer!`` may be the secret split from its name,
    and read as that key it would be dropped as a path, and the empty value above it with it, so
    it is read as the value instead, which refuses. Any other refused name is kept in any case,
    as Windows compares names, since it refuses on its own."""
    name = written.strip()
    upper = name.upper()
    if below_empty_class and upper in _INLINE_PEM_NAMES and name != upper:
        return False
    return _refused_name(upper)


def _line_start(line: str, *, below_empty_class: bool = False) -> Literal["kept", "ends"] | None:
    """How a line below a registry string's first is read: ``"kept"`` when it sets a name the
    refusal is about, so it is a variable of its own; ``"ends"`` when it sets an ordinary
    variable (:func:`_is_ordinary_line`), which ends the value above and is not kept; ``None``
    when it starts no variable and so belongs to the value above. :func:`_continues_string`
    applies it to a string's first line, narrowed as it says.

    ``below_empty_class`` is for a line whose value above is a secret-class name set so far to
    nothing but blanks (:func:`_blank_class`), or a refused name written alone
    (:func:`_name_alone`): the line then ends that value only under :func:`_ends_blank_class`.
    Below any other value the plain rule applies. An empty ``MEFOR_VALUE_*`` name, with its
    equals sign, refuses whatever it holds, so reading the next line into it would only change
    the remedy, to removing that line and no longer naming the empty entry. The secrets
    directory's name is no secret, and reading the next line into it would take the directory as
    set. Below such a value a refused name starts a variable of its own only in upper case
    (:func:`_starts_refused`)."""
    written, equals, _rest = line.partition("=")
    if not equals:
        return None
    if _starts_refused(written, below_empty_class=below_empty_class):
        return "kept"
    ends = _ends_blank_class(line) if below_empty_class else _is_ordinary_line(line)
    return "ends" if ends else None


def _blank_class(written: str, rest: str) -> bool:
    """Whether a line split at its first equals sign into ``written`` and ``rest`` sets a
    secret-class name (:data:`_REFUSED_CLASS_NAMES`) to nothing but blanks so far, so the line
    below it is read under :func:`_ends_blank_class`. A line with no equals sign is all
    ``written``, so a secret-class name alone on its line, as ``nssm set ... NAME =value``
    writes it, counts as one set to nothing."""
    return written.strip().upper() in _REFUSED_CLASS_NAMES and _still_blank(rest)


def _still_blank(text: str) -> bool:
    """Whether ``text`` holds only blanks and equals signs, as ``nssm set ... NAME = value``
    leaves between a name and its value, so a secret-class value is still empty after it.

    A value of equals signs alone is read on the side that refuses, wherever it is read: still
    empty where it takes a path-form key as no path (:func:`_path_form`), and set where an empty
    value would not be kept (:func:`_names`), so ``MEFOR_STORE_PASSWORD==`` refuses alone. On a
    later line, as ``NAME<LF>=`` writes it, it keeps a secret-class value open to the strings
    after it (:func:`_value_still_open`); on the name's own line it is set, so the value does not
    run on into the next item."""
    return not text.replace("=", "").strip()


def _name_alone(line: str) -> bool:
    """Whether ``line`` is a name the refusal is about (:func:`_refused_name`) alone, with no
    equals sign, as ``nssm set ... NAME =value`` writes the name as an item of its own. It is
    read as that name set to nothing so far, so the value below it is read into it."""
    return "=" not in line and _refused_name(line.strip().upper())


def _value_still_open(variable: _Variable) -> bool:
    """Whether ``variable``, the one a string ends on, may take the strings after it as its
    value (:func:`_variables`): a secret-class value or a refused name written alone that is
    blank on its own line and still blank after it (:func:`_still_blank`), as ``NAME<LF>=``
    leaves it, or a ``MEFOR_VALUE_*`` value that is empty or blank. ``NAME==`` sets ``=`` in its
    own string, so it does not run on, and it refuses as set (:func:`_names`)."""
    if _below_open_class(variable):
        own_line = _LINE_BREAK.split(variable.value, 1)[0]
        return not own_line.strip() and _still_blank(variable.value)
    return variable.written.upper().startswith(_VALUE_PREFIX) and not variable.value.strip()


def _below_open_class(variable: _Variable) -> bool:
    """Whether the strings a still-open ``variable`` takes (:func:`_value_still_open`) are read
    under the fail-closed rule (:func:`_ends_blank_class`): it is a secret-class name's, or a
    refused name written alone."""
    return variable.alone or variable.written.upper() in _REFUSED_CLASS_NAMES


@dataclass(frozen=True, slots=True)
class _Variable:
    """One variable as :func:`_variables` reads it from a registry string. Kept only while the
    read runs: :func:`_names` drops the value. Only where it is and how it was read reach the
    repr: the name, as text before an equals sign, may be key material too."""

    #: The registry value that sets it.
    where: str
    #: The name as written, stripped.
    written: str = field(repr=False)
    #: The rest of its line, and every line after it up to the next variable's.
    value: str = field(repr=False)
    #: Its line on its registry string, counted from 1, when that is not the string's first.
    line: int | None = None
    #: Whether NSSM may read the name with a line break in it.
    broken: bool = False
    #: Whether :func:`_names` counts it. A variable the line reading also describes under another
    #: name is not counted twice, but :func:`_value_entry_shapes` still reads its spelling.
    counted: bool = True
    #: Whether its value, blank in its own string, takes the strings after it, which
    #: :func:`_variables` joins to that string.
    runs_on: bool = False
    #: Whether it runs on, and the string its value takes first sets ``MEFOR_SECRETS_DIRECTORY``
    #: on its first line (:func:`_sets_directory_first`).
    holds_directory: bool = False
    #: Whether its name is written alone, with no equals sign (:func:`_name_alone`). Such a name
    #: sets nothing on its own, so :func:`_names` keeps it only once a value is read into it.
    alone: bool = False


def _read_string(
    where: str, entry: str, own_lines: int | None = None
) -> tuple[list[_Variable], _Variable | None]:
    """The variables one registry string sets, and the one it ends on when that is a name the
    refusal is about whose value is empty or blank. :func:`_variables` says how a string is read.

    ``own_lines`` is for strings joined from several: the number of lines the first of them
    holds. A broken whole-string name is then counted once only against a later line of that
    first string, since NSSM reads each string of the group as its own variable."""
    lines = _LINE_BREAK.split(entry)
    # ``skip`` keeps the later lines' numbers counted from the string's real first line.
    skip = next((i for i, line in enumerate(lines) if line.strip()), None)
    if skip is None:
        return [], None  # a blank string sets nothing
    first, *rest_lines = lines[skip:]
    first_written, first_equals, first_rest = first.partition("=")
    first_written = first_written.strip()
    # The whole-string reading, below: the name is everything before the first equals sign.
    whole_written, whole_equals, whole_value = entry.partition("=")
    whole_written = whole_written.strip()
    whole_kept = bool(whole_equals) and _refused_name(whole_written.upper())
    # A refused name alone in a string the whole-string reading names nothing in, such as a
    # ``MEFOR_VALUE_*`` name as ``nssm set ... MEFOR_VALUE_X =value`` writes it.
    first_alone = not first_equals and not whole_kept and _name_alone(first_written)
    empty_class = _blank_class(first_written, first_rest) or first_alone
    # Whether the first line starts a variable: it sets a name, or is a refused name alone.
    first_sets = bool(first_equals) or empty_class
    first_line = skip + 1 if skip else None
    first_parts = [first_rest]
    # A later line kept as a variable: its line number, name as written and value parts.
    later: list[tuple[int, str, list[str], bool]] = []
    starts_seen = False  # whether any later line starts a variable, kept or ordinary
    parts = first_parts  # the value the current line belongs to
    for number, line in enumerate(rest_lines, skip + 2):
        start = _line_start(line, below_empty_class=empty_class)
        # A refused name alone below another variable, or below lines that start none, starts a
        # variable of its own. Not below an empty secret-class value, which takes it, nor inside
        # a name the whole-string reading keeps, such as ``MEFOR_VALUE_A<LF>`` on the first
        # line, which names the variable instead, unless the line is in a later string of a
        # joined group, which NSSM reads as its own variable.
        alone = (
            start is None
            and not empty_class
            and (
                first_sets
                or starts_seen
                or not whole_kept
                or (own_lines is not None and number > own_lines)
            )
            and _name_alone(line)
        )
        if alone:
            start = "kept"
        if start is None:
            parts.append(line)
            empty_class = empty_class and _still_blank(line)
            continue
        written, _equals, rest = line.partition("=")
        parts = [rest]
        starts_seen = True
        empty_class = start == "kept" and (alone or _blank_class(written, rest))
        if start == "kept":
            later.append((number, written.strip(), parts, alone))
        # an ordinary line ends the value above, and is not kept
    read: list[_Variable] = []
    ending: _Variable | None = None  # the kept variable the last line belongs to
    if first_sets:
        read.append(
            _Variable(
                where, first_written, "\n".join(first_parts), line=first_line, alone=first_alone
            )
        )
        if parts is first_parts:
            ending = read[-1]
    later_variables = [
        _Variable(where, written, "\n".join(value_parts), line=number, alone=alone)
        for number, written, value_parts, alone in later
    ]
    # The whole-string reading: the name is everything before the first equals sign, stripped,
    # and the value everything after it. Kept when that name is one the refusal is about, so a
    # blank first line, a line break before the equals sign, or a value empty on its own line but
    # not in its string refuses under that reading. A name that still holds a line break is
    # counted only when no later line sets a name :func:`_names` keeps, since both readings then
    # describe the same variable.
    broken = _LINE_BREAK.search(whole_written) is not None
    if whole_kept:
        # A broken name is kept under its first line, as the line reading names it.
        name = _LINE_BREAK.split(whole_written, 1)[0].rstrip() if broken else whole_written
        same_string = [
            v for v in later_variables if own_lines is None or (v.line or 1) <= own_lines
        ]
        counted = not (broken and _names(same_string))
        read.append(
            _Variable(where, name, whole_value, line=first_line, broken=broken, counted=counted)
        )
        # Its value ends with the string, so it is the one the string ends on when no line of
        # the line reading starts a variable, as with ``MEFOR_VALUE_A<LF>=``, or
        # ``MEFOR_VALUE_A<LF>X=``, whose name holds a line break.
        if not first_sets and not starts_seen:
            ending = read[-1]
    read.extend(later_variables)
    if later and parts is later[-1][2]:
        ending = later_variables[-1]
    if ending is None or not _value_still_open(ending):
        ending = None
    return read, ending


def _continues_string(entry: str, *, below_empty_class: bool = False) -> bool:
    """Whether the registry string ``entry`` may continue an empty value the string above it
    ends on (:func:`_variables`). ``below_empty_class`` says that value is a secret-class
    name's (:data:`_REFUSED_CLASS_NAMES`) or a refused name's written alone
    (:func:`_below_open_class`), not one a ``MEFOR_VALUE_*`` name sets with its equals sign.

    It may not when it holds no non-blank line. It may not when a name the refusal is about
    starts it under the whole-string reading, as one starts ``MEFOR_VALUE_A<LF>X=1``. Otherwise
    its first non-blank line decides. A first line with no equals sign continues the value.

    Below an empty secret-class value, a first line continues the value unless
    :func:`_ends_blank_class` says it ends it, the same rule a later line of one string is read
    under, so the two readings of one shape agree on whether the secret-class value refuses.

    Below any other value, NSSM reading each item as its own variable, a first line with an
    equals sign continues the value only in the cases below. Its name is the text before its
    first equals sign, stripped, and its value the text after it:

    * the name holds key material (:func:`_holds_key_run`), whatever the value, or the value is
      one secret (:func:`_is_key_value`), so a base64url secret with one ``=`` and ``=<key>``
      continue it (vault BACKLOG #5394 added items 6 and 12), but ``x=<key>``, an ordinary line
      (:func:`_is_ordinary_line`), ends it, so the empty ``MEFOR_VALUE_*`` item is named;
    * the name is standard base64 text, and the value holds only whitespace and equals signs;
    * the name is not blank, and the value holds an equals sign and nothing but equals signs
      and whitespace.

    So there ``abc==`` continues it in any alphabet, ``abc=`` continues it only under the first
    two cases, so ``ab-c_dE=``, too short to be key material, ends it, and ``PATH=`` continues it
    too. ``HTTP_PROXY=`` and ``PATH=C:\\x`` end it, as they fit no case, but
    ``MEFOR_SECRETS_DIRECTORY==`` fits the third and continues it. In each case
    :func:`_line_start` reads the first line as starting no variable. So when the strings are
    joined, the line and the item's later lines are read as later lines of one string."""
    first = next((line for line in _LINE_BREAK.split(entry) if line.strip()), None)
    if first is None:
        return False
    whole, whole_equals, _value = entry.partition("=")
    if whole_equals and _starts_refused(whole, below_empty_class=below_empty_class):
        return False
    if below_empty_class:
        return not _ends_blank_class(first)
    written, equals, rest = first.partition("=")
    if not equals:
        return True
    name = written.strip()
    could_be_key = (
        _BASE64_TEXT.fullmatch(name) is not None or _holds_key_run(name) or _is_key_value(rest)
    )
    # A secret outside the standard alphabet padded with ``==``, such as base64url, reads as a
    # name set to ``=``. The rule of 3085e1d5c55 continued on that, so this case keeps it.
    # ``_line_start`` holds the value to equals signs and whitespace, as on a later line.
    padded = bool(name) and "=" in rest
    return (could_be_key or padded) and _line_start(first) is None


def _sets_directory_first(entry: str) -> bool:
    """Whether the first non-blank line of ``entry`` sets ``MEFOR_SECRETS_DIRECTORY``, without
    regard to case, as Windows compares names."""
    first = next((line for line in _LINE_BREAK.split(entry) if line.strip()), "")
    written, equals, _rest = first.partition("=")
    return bool(equals) and written.strip().upper() == _DIRECTORY_VARIABLE


def _variables(entries: Sequence[tuple[str, str]]) -> list[_Variable]:
    """The variables each registry string sets, read a line at a time (vault BACKLOG #5394).

    The reader cannot tell whether NSSM takes a line or the whole string as a variable, so it
    keeps what either reading would refuse. Each string's first non-blank line is a variable when
    it holds an equals sign, or is a refused name alone (:func:`_name_alone`), a
    ``MEFOR_VALUE_*`` one only in a string with no equals sign: blank lines above it are skipped,
    as the whole-string reading's strip of the name skips them, so a secrets directory set below
    a blank first line is still read as set. A later line is one when it sets a name the refusal
    is about, or is a refused name alone below another variable, so a store key on a later
    line still refuses. A later line that sets an ordinary variable (:func:`_is_ordinary_line`)
    ends the value above it under the line reading, and is not kept: under the whole-string
    reading it sets nothing, so the secrets directory's name is never taken as set by a later
    line. Below an empty secret-class value :func:`_ends_blank_class` decides instead whether a
    later line ends it. Any other line, such as one of key material, belongs to the value above it,
    so a key whose value starts on the next line is not empty.

    Each string is also read whole: the name before its first equals sign, stripped, and
    everything after it as the value. That variable is kept when its name is one the refusal is
    about. So ``KEY=`` above another variable's line, a path-form OIDC key above a line holding
    PEM armour, a blank first line, or a line break before the equals sign refuses under that
    reading. Where that name still holds a line break, such as ``MEFOR_VALUE_A`` on a first line
    with no equals sign, the engine loads a variable whose name starts with it. It is counted
    unless a later line sets a name :func:`_names` keeps, since both readings then describe the
    same variable and it is counted once; its spelling is read either way.

    From one string to the next string of one ``REG_MULTI_SZ`` value the rule is narrower, since
    NSSM reads each item as its own variable. When a string ends on a name the refusal is about
    whose value is empty or blank, and the next non-blank string of the same registry value may
    continue it (:func:`_continues_string`), the two are joined and read as one string, so
    ``MEFOR_STORE_ENCRYPTION_KEY=`` as one item and the key as the next refuses, as ``nssm set``
    writes a key split from its name. An empty store key above an item whose first line ends it
    under :func:`_continues_string`, such as one that sets a variable under a name Windows itself
    sets (:func:`_ends_blank_class`), does not, and a value that is not empty in its own string
    does not run on, so a path-form OIDC key above an item of PEM armour is still a path. Each
    string is read alone first to decide this, and a joined group is read once more, so the work
    stays linear."""
    # Each group: its registry value, its strings, its first string read alone, and for each
    # string but the last the variable it ends on, whose empty value the next string continues.
    groups: list[tuple[str, list[str], list[_Variable], list[_Variable]]] = []
    ending: _Variable | None = None
    for where, entry in entries:
        alone, ends = _read_string(where, entry)
        if not entry.strip():
            continue  # a blank string sets nothing, and ends no value above it
        if (
            groups
            and ending is not None
            and groups[-1][0] == where
            and _continues_string(entry, below_empty_class=_below_open_class(ending))
        ):
            groups[-1][1].append(entry)
            groups[-1][3].append(ending)
            if _still_blank(entry):
                # Only equals signs, as ``nssm set ... NAME = value`` writes between the name and
                # its value, so the value still runs on into the item after it.
                continue
        else:
            groups.append((where, [entry], alone, []))
        ending = ends
    read: list[_Variable] = []
    for where, strings, alone, endings in groups:
        if len(strings) == 1:
            read.extend(alone)
            continue
        starts: list[int] = []
        line = 1
        for string in strings:
            starts.append(line)
            line += len(_LINE_BREAK.split(string))
        # The variables that ran on: each string's ending, and its whole-string twin, which has
        # the same name, line and spelling and was as empty. Only these make the refusal say to
        # remove the strings after them.
        ran = {(i, v.written, v.line, v.broken) for i, v in enumerate(endings)}
        # A name written alone has no line variable once joined, only the whole-string one,
        # whose name holds a line break when the next string's first line has an equals sign
        # after other text, as ``Winter=2026!`` does. That break is the join's: NSSM reads the
        # name's own string alone, so the twin is not taken as broken.
        joined_breaks = {(i, v.written, v.line, True) for i, v in enumerate(endings) if v.alone}
        # ``\r\n`` between strings: a string ending in a lone ``\r`` then still ends a line of
        # its own, so each line keeps the number ``starts`` gives it.
        joined, _ends = _read_string(where, "\r\n".join(strings), own_lines=starts[1] - 1)
        for variable in joined:
            index = bisect.bisect_right(starts, variable.line or 1) - 1
            local = (variable.line or 1) - starts[index] + 1
            line_on_string = None if local == 1 else local
            key = (index, variable.written, line_on_string, variable.broken)
            joined_break = key in joined_breaks
            ran_on = (key in ran or joined_break) and bool(variable.value.strip())
            # Its value takes the next string's first line, which may set the directory, past any
            # string of equals signs alone, which keeps the value running on (_still_blank).
            holds = False
            if ran_on:
                taken = next(
                    (
                        strings[i]
                        for i in range(index + 1, len(strings))
                        if not _still_blank(strings[i])
                    ),
                    "",
                )
                holds = _sets_directory_first(taken)
            read.append(
                replace(
                    variable,
                    line=line_on_string,
                    broken=variable.broken and not joined_break,
                    runs_on=ran_on,
                    holds_directory=holds,
                )
            )
    return read


def _kept_empty(variable: _Variable) -> bool:
    """Whether :func:`_names` keeps ``variable`` even when its value is empty: a
    ``MEFOR_VALUE_*`` name, unless it is written alone with nothing read into it, which sets no
    variable."""
    return variable.written.upper().startswith(_VALUE_PREFIX) and not (
        variable.alone and not variable.value.strip()
    )


def _path_form(value: str) -> bool:
    """Whether the value of a name that takes either a key or its path (:data:`_INLINE_PEM_NAMES`)
    is a path, which is no secret: it holds no PEM armour, and its own line, the text after the
    name's equals sign up to the first line break, is not blank (:func:`_still_blank`). Only that
    line is judged, never the lines or strings a blank one took below it, since those may be
    another secret split from its name: ``[KEY=, MEFOR_STORE_PASSWORD, =hunter2]`` refuses."""
    return "-----BEGIN" not in value and not _still_blank(_LINE_BREAK.split(value, 1)[0])


def _names(variables: Sequence[_Variable]) -> tuple[tuple[str, str, int | None], ...]:
    """The upper-cased names of the variables set to a secret that the refusal reads. The value
    is dropped here and never kept. An empty value carries no secret, so its name is not kept,
    except a ``MEFOR_VALUE_*`` name, which the owner's ruling refuses whatever it holds and whose
    empty value the engine still overlays on the value file, unless it is written alone with
    nothing read into it (:func:`_kept_empty`). A path in a name that takes either a key or its
    path is not a secret, so that name is not kept either (:func:`_path_form`). Only a
    secret-class name, a ``MEFOR_VALUE_*`` name and ``MEFOR_SECRETS_DIRECTORY`` are kept: the
    text before any other line's equals sign may be key material (vault BACKLOG #5394). Windows
    compares environment names without case, so this does too. Each name is returned with the
    first registry value, and the line, that sets it."""
    names: dict[str, tuple[str, int | None]] = {}
    for variable in variables:
        name = variable.written.upper()
        value = variable.value
        if not variable.counted or not (_refused_name(name) or name == _DIRECTORY_VARIABLE):
            continue
        # An ``env()`` value is kept even when empty: the engine overlays an empty one on the
        # value file, so it still decides what ``env()`` returns (vault BACKLOG #8212 item 7).
        if not ((value and not value.isspace()) or _kept_empty(variable)):
            continue
        if name in _INLINE_PEM_NAMES and _path_form(value):
            continue
        names.setdefault(name, (variable.where, variable.line))
    return tuple((name, where, line) for name, (where, line) in names.items())


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
        if not _kept_empty(variable):
            continue  # a name alone with nothing read into it sets no variable
        if variable.counted and (not variable.value or variable.value.isspace()):
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
    found = _names(variables)
    empty, unplain = _value_entry_shapes(variables)
    return ServiceEnvPosture(
        ServiceEnvStatus.OBSERVED,
        service_name=service,
        listed=tuple(name for name, _where, _line in found),
        sources=tuple((name, where) for name, where, _line in found),
        source_lines=tuple((name, line) for name, _where, line in found if line is not None),
        keys_in_environment=keys,
        empty_value_names=empty,
        unplain_value_names=unplain,
        value_runs_on=any(variable.runs_on and _names([variable]) for variable in variables),
        # Not filtered through ``_names``: the directory string is in the lists whichever
        # variable it was joined to, so one ``_names`` drops counts too.
        directory_joined=any(variable.holds_directory for variable in variables),
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
    if posture.value_runs_on:
        # A directory string joined to the value is removed with it too, whatever it holds: it
        # may hold the value itself (the Lander's second hold on PR 3142, H3), so the step below
        # writes the directory's entry again rather than keeping it.
        steps.append(
            "At least one refused variable is empty in its own string and its value runs on into "
            "the strings after it in the same registry value, as `nssm set` writes each argument "
            "as its own string, so remove those strings with it, or the value stays in the "
            "registry key"
        )
    # Only where the remedy touches the lists' strings or needs the secrets directory: a refusal
    # about a store key alone sends the operator to a key file, not to the directory's entry.
    if posture.directory_joined and (posture.value_runs_on or others or values):
        steps.append(
            f"At least one string in the service's lists sets {_DIRECTORY_VARIABLE} on its first "
            "non-blank line and is read here as part of the empty value of the variable in the "
            "string above it. NSSM may instead read it as a variable of its own, so this reading "
            "does not take it as naming the secrets directory. Remove each such string, whatever "
            "it holds, since it may hold that value, and do not keep it as the directory's entry. "
            f"The lists must then hold exactly one {_DIRECTORY_VARIABLE} entry, written as "
            f"{_DIRECTORY_VARIABLE}=<path> on its own, naming the secrets directory by its path: "
            "write it again where a removed string was the only one, before any re-run of the "
            "installer, which refuses an existing directory the service does not name. `nssm "
            "set` replaces a whole list, so read it first with `nssm get`, running the service's "
            "own nssm.exe by its full path, and pass back every entry but those refused above "
            "and the strings this step and any step above say to remove: see docs/SERVICE.md, "
            '"Start / stop / status". Where no secrets directory exists yet, the bullet "The '
            'other secrets: a secrets directory" under docs/SERVICE.md, "Protect the store '
            'encryption key at rest", says how the directory is created'
        )
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
        if _DIRECTORY_VARIABLE not in posture.listed and not posture.directory_joined:
            # A joined directory string is covered by its own step above: the lists may still set
            # it, so "add it back" would be false there.
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
