# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The environment a child process of the engine is started with (vault BACKLOG #2587).

A process started with no ``env=`` gets a copy of its parent's whole environment. The engine's own
environment holds its secrets by design: the store key, the store password and every ``env()``
connection secret arrive as ``MEFOR_*`` variables. So each spawn site names what its child gets,
through one of the builders here, and ``tests/test_child_process_environment.py`` fails a
process start whose environment does not come from one of them.

* :func:`system_tool_environment` is the platform's start-up names, for a fixed
  operating-system tool the engine runs by its absolute path, such as ``icacls`` or ``sc``
  (vault BACKLOG #2716), and for ``openssl``. Such a tool reads no engine setting, so it gets no
  ``MEFOR_*`` variable and no interpreter variable. A caller may add only the tool's own
  variables, by name, and fixed values that replace inherited ones (BACKLOG #3803).

* :func:`worker_environment` is an **allowlist**, for a child that runs code the engine does not
  fully trust (the sandbox worker). It carries what the platform and the interpreter need to start,
  and the extra names its caller adds. A variable nobody listed does not cross.
* :func:`hook_environment` is an **allowlist** too, for a shell command an operator configured (the
  DR hook): the platform's start-up names, on Windows the few
  machine-layout names a shell script expects (:data:`_WINDOWS_SHELL_NAMES`), and the names the
  operator listed in ``[dr].pass_environment``. A variable nobody listed does not cross, so no
  secret is in the hook's own environment by default, whatever name it is kept under. Settings
  load refuses the engine's own names in that setting.
* :func:`non_engine_environment` is **everything except the engine's own namespace**: the whole
  ``MEFOR_*`` prefix, and the few names outside it in :data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX`.
  It is a deny-list, so **a secret kept under any other name still crosses**: a
  ``[secrets].provider = "env"`` reference may name any variable, and a library may read one this
  module does not know. Only for a fixed tool the engine's own code names, run on a build or CI
  runner rather than by the service, that reads settings the engine cannot list in advance: the
  dependency auditor's ``pip`` and ``pip-audit``, which read their index, proxy and certificate
  settings from the environment. ``tests/test_child_process_environment.py`` fails another caller.
* :func:`engine_environment` is the **whole** environment, for a Python child started through the
  bootstrap that runs the engine's own trusted code: an engine shard, which opens the store and
  builds connections and so needs the secrets, and other such children, the tray's relaunch among
  them.

**THIS IS NOT AN ISOLATION BOUNDARY BY ITSELF.** A child that runs as the same operating-system
account as the engine can still read the engine process, and the files that account can read. What
an explicit environment removes is the direct read: the secret is no longer sitting in the child's
own environment. Running the child as a different account is separate work.

Stdlib only, so any package may import it.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path
from typing import Final

__all__ = [
    "CHILD_INTERPRETER_FLAGS",
    "ENGINE_ENV_PREFIX",
    "ENGINE_SECRETS_OUTSIDE_THE_PREFIX",
    "engine_environment",
    "hook_environment",
    "inherited_interpreter_flags",
    "non_engine_environment",
    "outside_engine_namespace",
    "python_child_argv",
    "python_module_argv",
    "system_tool_environment",
    "worker_environment",
]

#: The engine's own settings and secrets are named with this prefix. Secrets under other names are
#: kept from children too; :data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX` holds the ones known here,
#: and its comment says why each is there.
ENGINE_ENV_PREFIX: Final = "MEFOR_"

#: The interpreter options every Python child is started with. Each child starts a script,
#: :data:`_BOOTSTRAP`, and a script start puts the script's own directory first on the import path
#: and never the working directory. ``-P`` drops that directory, which is this package's own, so
#: a module in it cannot stand in for a top-level module the child imports. For ``-m`` and ``-c``
#: starts, ``-P`` drops the working directory instead. The engine starts no child that way; the
#: tray's short login command, from :func:`python_module_argv`, is a ``-m`` start.
#: ``-X disable-remote-debug`` starts the child with the interpreter's remote debugging disabled.
#: The option is spelled with hyphens; the interpreter accepts and ignores other spellings, which is
#: why ``tests/test_child_process_environment.py`` reads the result off a real child.
#: :func:`inherited_interpreter_flags` adds the parent's own isolation ahead of these.
CHILD_INTERPRETER_FLAGS: Final = ("-P", "-X", "disable-remote-debug")

#: The script a Python child is started through. Its docstring says where it puts this package on
#: the child's import path, and why.
_BOOTSTRAP: Final = str(Path(__file__).resolve().parent / "_child_bootstrap.py")

#: The interpreter's own variables that cross, by name. Each one changes whether the interpreter
#: starts, where it imports from, or how the same code behaves (encoding, hash seed, warnings), so
#: a child started without one the parent has would run the same Handler differently from
#: ``[sandbox].mode = "off"``. Named one by one, not by the ``PYTHON`` prefix: an operator's own
#: variable can start with those letters. The ones that hand control to a console or a debugger
#: (``PYTHONSTARTUP``, ``PYTHONINSPECT``, ``PYTHONBREAKPOINT``) are left out on purpose. A variable
#: a later interpreter adds is not here until somebody adds it.
_INTERPRETER_NAMES: Final = frozenset(
    {
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
        "PYTHONHASHSEED",
        "PYTHONOPTIMIZE",
        "PYTHONUTF8",
        "PYTHONIOENCODING",
        "PYTHONCOERCECLOCALE",
        "PYTHONLEGACYWINDOWSFSENCODING",
        "PYTHONLEGACYWINDOWSSTDIO",
        "PYTHONINTMAXSTRDIGITS",
        "PYTHONWARNINGS",
        "PYTHONDEVMODE",
        "PYTHONCASEOK",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONPYCACHEPREFIX",
        "PYTHONUNBUFFERED",
        "PYTHONFAULTHANDLER",
        "PYTHONMALLOC",
        "PYTHON_GIL",
        "PYTHON_JIT",
        "PYTHON_CPU_COUNT",
        "PYTHON_FROZEN_MODULES",
    }
)

#: What a Windows process needs to start and to find its temp and profile directories, plus the
#: machine facts ``platform`` reads. Upper case: Windows names are case-insensitive.
_WINDOWS_NAMES: Final = frozenset(
    {
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "PROCESSOR_ARCHITEW6432",
        "PROCESSOR_IDENTIFIER",
        "OS",
        "COMPUTERNAME",
        "USERNAME",
        "USERDOMAIN",
        "TZ",
    }
)

#: The POSIX equivalent, with the locale categories. ``LD_LIBRARY_PATH`` is here because an
#: interpreter built against a shared library outside the default search path cannot start
#: without it.
_POSIX_NAMES: Final = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TMPDIR",
        "TZ",
        "LANG",
        "LANGUAGE",
        "LD_LIBRARY_PATH",
        "LC_ALL",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_MONETARY",
        "LC_NUMERIC",
        "LC_TIME",
        "LC_ADDRESS",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_NAME",
        "LC_PAPER",
        "LC_TELEPHONE",
    }
)

#: What a Windows shell script expects beyond :data:`_WINDOWS_NAMES`, for the DR hook only: where
#: programs and shared data are installed. Machine layout, never a secret. Measured on Windows 11
#: with the start-up names alone, ``cmd`` leaves ``%ProgramFiles%`` unexpanded. ``PSModulePath``
#: is left out on purpose: PowerShell builds it when it is unset, as measured, and the engine's
#: own value may name another PowerShell edition's modules.
_WINDOWS_SHELL_NAMES: Final = frozenset(
    {
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        "ALLUSERSPROFILE",
        "PUBLIC",
    }
)

#: Secrets outside the ``MEFOR_*`` prefix that are kept from every child process and refused in
#: ``pass_environment``. At least these two. asyncpg falls back to ``PGPASSWORD`` when
#: ``[store].password`` is unset. ``VAULT_TOKEN`` is no longer read by the engine, whose Vault
#: clients refuse an unset ``MEFOR_*_VAULT_TOKEN`` rather than let hvac fall back (BACKLOG
#: #2851); it stays because an operator's own Vault token, inherited from the shell that started
#: the engine, is still a secret a Router, a Handler or a hook has no business holding. A list of
#: names, so it can be incomplete; the module docstring says what that leaves.
ENGINE_SECRETS_OUTSIDE_THE_PREFIX: Final = frozenset({"VAULT_TOKEN", "PGPASSWORD"})


def _key(name: str) -> str:
    """A variable name as the platform compares it: Windows names are case-insensitive."""
    return name.upper() if sys.platform == "win32" else name


def _platform_names() -> frozenset[str]:
    """What this platform needs to start a process, read at call time as :func:`_key` is."""
    return _WINDOWS_NAMES if sys.platform == "win32" else _POSIX_NAMES


def _allowed_for_a_worker(name: str, extra_names: Collection[str]) -> bool:
    key = _key(name)
    return key in extra_names or key in _INTERPRETER_NAMES or key in _platform_names()


def outside_engine_namespace(name: str) -> bool:
    """Whether ``name`` is neither one of the engine's own ``MEFOR_*`` variables nor one of the
    secrets in :data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX`. Upper-cased on every platform: Windows reads ``mefor_x`` and
    ``MEFOR_X`` as one variable, and on POSIX refusing the lower-case spelling costs nothing."""
    upper = name.upper()
    return (
        not upper.startswith(ENGINE_ENV_PREFIX) and upper not in ENGINE_SECRETS_OUTSIDE_THE_PREFIX
    )


def inherited_interpreter_flags() -> tuple[str, ...]:
    """The isolation options this interpreter was started with, which each Python child repeats.

    ``-I`` when this process is isolated. Otherwise ``-E`` when it ignores the ``PYTHON*``
    variables, and ``-s`` when its user site directory is off (vault BACKLOG #2701, #2724). **A
    child honours ``PYTHONPATH`` and the other interpreter variables exactly when its parent
    does.** Two behaviours a child that ignores the variables would otherwise lose ride along:
    ``-B`` when this process writes no bytecode, and ``-u`` when ``PYTHONUNBUFFERED`` is set. The
    container image sets that variable for the children of an engine it starts with ``-I``. Both shipped service launches pass ``-I``, so the engine's children there are isolated
    too, and a ``PYTHON*`` variable in the service's environment reaches neither. A parent that
    reads the variables, such as a developer's ``messagefoundry serve`` from a prompt, hands its
    children the absolute ``PYTHONPATH`` entries it imports from itself. That is a stated limit: it
    gives a child no ``PYTHONPATH`` entry its parent lacks. The bootstrap still adds the folder
    above this package, as :data:`_BOOTSTRAP` says.

    Repeated rather than forced, so a sandbox worker imports the way ``[sandbox].mode = "off"``
    does in the engine process. ``-I`` would also drop the user site directory, which a parent
    that is not isolated may be reading."""
    flags = sys.flags
    out: list[str] = []
    if flags.isolated:
        out.append("-I")
    else:
        out += ["-E"] if flags.ignore_environment else []
        out += ["-s"] if flags.no_user_site else []
    out += ["-B"] if flags.dont_write_bytecode else []
    ignores_variables = flags.isolated or flags.ignore_environment
    out += ["-u"] if ignores_variables and os.environ.get("PYTHONUNBUFFERED") else []
    return tuple(out)


def _flags(extra_flags: Sequence[str], inherit: bool) -> list[str]:
    """``extra_flags``, then :func:`inherited_interpreter_flags` not already among them when
    ``inherit``, then :data:`CHILD_INTERPRETER_FLAGS`."""
    if isinstance(extra_flags, str):
        # A bare string is a sequence of its characters, so "-E" would arrive as "-" and "E".
        raise TypeError("extra_flags takes a sequence of options, not one string")
    own = inherited_interpreter_flags() if inherit else ()
    inherited = [flag for flag in own if flag not in extra_flags]
    return [*extra_flags, *inherited, *CHILD_INTERPRETER_FLAGS]


def python_child_argv(
    module: str,
    *,
    executable: str | None = None,
    extra_flags: Sequence[str] = (),
    inherit: bool = True,
) -> list[str]:
    """The command line that runs ``module`` in a child interpreter, as ``python -m`` would.

    Two differences from ``python -m``. The child starts with :data:`CHILD_INTERPRETER_FLAGS`,
    after this interpreter's own isolation (:func:`inherited_interpreter_flags`).
    And it starts through :data:`_BOOTSTRAP`, which hands it the package location. A script start
    does not search the working directory, which is where ``python -m`` found the package in a
    source checkout that is not installed. Pass the result of :func:`worker_environment` or
    :func:`engine_environment` as its ``env``: they keep a ``PYTHONPATH`` entry from putting the
    working directory on the child's import path.

    ``extra_flags`` go ahead of the shared flags, for one caller's own options. The tray's login
    command passes ``-E`` this way (vault BACKLOG #2852). ``inherit=False`` leaves this process's
    own isolation out, for a command line that is stored and run later by someone else, such as
    the tray's login command.
    """
    return [executable or sys.executable, *_flags(extra_flags, inherit), _BOOTSTRAP, module]


def python_module_argv(
    module: str,
    *,
    executable: str | None = None,
    extra_flags: Sequence[str] = (),
    inherit: bool = True,
) -> list[str]:
    """``python -m module`` with :data:`CHILD_INTERPRETER_FLAGS`, after this interpreter's own
    isolation (:func:`inherited_interpreter_flags`), and no bootstrap.

    Shorter than :func:`python_child_argv`, and only for a package the interpreter can import on
    its own, from site-packages or a ``.pth`` entry. ``-P`` drops the working directory from a
    ``-m`` start, so a source checkout that is not installed cannot be found this way. Nothing
    pins this build either: the first ``messagefoundry`` on the import path answers. The tray's
    login command is one user. It passes ``-E`` in ``extra_flags``, so an absolute
    ``PYTHONPATH`` entry naming another copy does not answer that start (vault BACKLOG #2852). The
    tray it relaunches repeats that ``-E`` (:func:`inherited_interpreter_flags`). The other is
    :mod:`messagefoundry.security.audit_all_platforms`, which starts ``pip`` and ``pip_audit``.
    """
    return [executable or sys.executable, *_flags(extra_flags, inherit), "-m", module]


def _without_working_directory_entries(env: dict[str, str]) -> dict[str, str]:
    """Keep only the absolute entries of an inherited ``PYTHONPATH``.

    An empty or relative entry is resolved against the working directory, which the child's script
    start otherwise keeps off its import path.
    """
    inherited = env.pop("PYTHONPATH", "")
    entries = [entry for entry in inherited.split(os.pathsep) if os.path.isabs(entry)]
    if entries:
        env["PYTHONPATH"] = os.pathsep.join(entries)
    return env


def _source(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def _extra_keys(extra_names: Collection[str]) -> frozenset[str]:
    """``extra_names`` as :func:`_key` compares them."""
    if isinstance(extra_names, str):
        # A bare string is a collection of its characters, so no name would cross and nothing
        # would say why.
        raise TypeError("extra_names takes a collection of names, not one string")
    return frozenset(_key(name) for name in extra_names)


def worker_environment(
    environ: Mapping[str, str] | None = None,
    *,
    extra_names: Collection[str] = (),
    defaults: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The environment for a Python child that runs code the engine does not fully trust.

    An allowlist over ``environ`` (default :data:`os.environ`): the platform's start-up names, the
    interpreter's own variables, and ``extra_names``. Code in the child that reads any other
    variable finds it unset, which is a difference from running in the engine process.

    ``extra_names`` is what the caller adds: an engine switch the child's own code reads to make a
    decision its parent already made, and the names an operator listed in
    ``[sandbox].pass_environment``. Never a secret: whatever is named here is in the environment of
    the code this builder exists to keep secrets from. Settings load refuses the engine's own.

    ``defaults`` are values for names the result does not already hold, so a value the operator
    passed through ``extra_names`` wins. They are set here, not on the returned dict, because
    ``tests/test_child_process_environment.py`` trusts a builder's result only while nothing
    writes to it (vault BACKLOG #2724). A default in the engine's own namespace is refused, as
    ``[sandbox].pass_environment`` refuses one: a builder call is all the spawn guard checks.
    """
    extras = _extra_keys(extra_names)
    env = _without_working_directory_entries(
        {n: v for n, v in _source(environ).items() if _allowed_for_a_worker(n, extras)}
    )
    present = {_key(name) for name in env}
    for name, value in (defaults or {}).items():
        # Refuses an engine or interpreter name: the worker's import path is the inherited one,
        # filtered above, and nothing else.
        key = _ordinary_key(name, "defaults")
        if key not in present:
            env[name] = value
    return env


def _ordinary_key(name: str, argument: str) -> str:
    """``name`` as :func:`_key` compares it. A name of the engine's namespace or of the
    interpreter is refused, since a value a builder sets for it would bypass that builder's own
    filter. ``argument`` names the caller's argument in the refusal."""
    if not outside_engine_namespace(name):
        raise ValueError(f"{argument} may not name the engine's own variable {name!r}")
    if _key(name) in _INTERPRETER_NAMES:
        raise ValueError(f"{argument} may not name the interpreter's variable {name!r}")
    return _key(name)


def system_tool_environment(
    environ: Mapping[str, str] | None = None,
    *,
    extra_names: Collection[str] = (),
    pinned: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """The environment for a fixed operating-system tool: the platform's start-up names, plus
    what ``extra_names`` and ``pinned`` add.

    For a tool the engine runs with an argument list and no shell, that reads none of the
    engine's settings: ``icacls`` and ``sc`` by their absolute paths (vault BACKLOG #2716), and
    ``openssl``, which ``verify`` finds on ``PATH`` as the manual check does. It gets what the
    platform needs to start a process and find its temp and profile directories, and nothing
    else. No interpreter variable crosses, because the tool is not Python.

    ``extra_names`` are the tool's own variables, which cross as ``environ`` holds them: the
    ``OPENSSL_*`` names for ``openssl`` (BACKLOG #3803 item 5). ``pinned`` are fixed values that
    replace whatever ``environ`` holds under the same name, such as the ``PATH`` and
    ``PSModulePath`` of the cipher probe's PowerShell (BACKLOG #3803 S1). Both are set here, not on
    the returned dict, for the reason :func:`worker_environment` gives for ``defaults``. Neither may
    name a variable of the engine's namespace or of the interpreter."""
    if isinstance(extra_names, str):
        # A bare string is a collection of its characters, so no name would cross.
        raise TypeError("extra_names takes a collection of names, not one string")
    pins = pinned or {}
    allowed = _platform_names() | {_ordinary_key(name, "extra_names") for name in extra_names}
    allowed -= {_ordinary_key(name, "pinned") for name in pins}
    return {**{n: v for n, v in _source(environ).items() if _key(n) in allowed}, **pins}


def hook_environment(
    environ: Mapping[str, str] | None = None, *, extra_names: Collection[str] = ()
) -> dict[str, str]:
    """The DR hooks' allowlist over ``environ`` (default :data:`os.environ`), as the module
    docstring describes; ``extra_names`` is ``[dr].pass_environment``.

    No interpreter variable crosses unless listed: the hook is a shell command, not this
    interpreter's child. ``LD_LIBRARY_PATH`` does, with the other POSIX start-up names, so a hook
    that starts an interpreter needing it still starts. An extra in the engine's own namespace
    raises :class:`ValueError`. Settings load refuses one first, so this is the last check, not
    the first."""
    extras = _extra_keys(extra_names)
    for key in extras:
        if not outside_engine_namespace(key):
            raise ValueError(f"extra_names may not name the engine's own variable {key!r}")
    names = _platform_names() | extras
    if sys.platform == "win32":
        names |= _WINDOWS_SHELL_NAMES
    return {n: v for n, v in _source(environ).items() if _key(n) in names}


def non_engine_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """Everything in ``environ`` (default :data:`os.environ`) outside the engine's own ``MEFOR_*``
    namespace, less :data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX`: the deny-list the module docstring
    says is only for the dependency auditor. ``PYTHONPATH`` crosses as ``environ`` has it."""
    return {n: v for n, v in _source(environ).items() if outside_engine_namespace(n)}


def engine_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for a Python child started through the bootstrap that runs the engine's own
    trusted code: all of it, less any empty or relative ``PYTHONPATH`` entry, which would resolve
    against the working directory.

    An engine shard is one such child, and it needs the secrets. The tray's branded relaunch is
    another. A child that runs code the engine does not fully trust takes
    :func:`worker_environment` instead."""
    return _without_working_directory_entries(dict(_source(environ)))
