# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The environment a child process of the engine is started with (vault BACKLOG #2587).

A process started with no ``env=`` gets a copy of its parent's whole environment. The engine's own
environment holds its secrets by design: the store key, the store password and every ``env()``
connection secret arrive as ``MEFOR_*`` variables. So each spawn site names what its child gets,
through one of the three builders here, and ``tests/test_child_process_environment.py`` fails a
process start whose environment does not come from one of them.

* :func:`worker_environment` is an **allowlist**, for a child that runs code the engine does not
  fully trust (the sandbox worker). It carries what the platform and the interpreter need to start,
  and the extra names its caller adds. A variable nobody listed does not cross.
* :func:`hook_environment` is **everything except the engine's own namespace**, for a command an
  operator configured (the DR hook). Such a command may need ordinary variables the engine cannot
  list in advance, such as a cloud profile or a proxy. It has no use for the engine's settings, so
  the whole ``MEFOR_*`` prefix is dropped. Dropping a prefix does not go stale the way a list of
  secret names would. A few names outside the prefix are dropped too
  (:data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX`). **A secret kept under any other name still reaches
  the hook**: a ``[secrets].provider = "env"`` reference may name any variable, a library may read
  one this module does not know, and neither can be listed here.
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
    "outside_engine_namespace",
    "python_child_argv",
    "python_module_argv",
    "worker_environment",
]

#: The engine's own settings and secrets are named with this prefix. The libraries it uses read
#: other names as well; :data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX` holds the secret ones known here.
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

#: Secrets the engine may rely on that are not named ``MEFOR_*``, because a library it uses reads
#: them when the engine's own setting is unset. At least these two: hvac falls back to
#: ``VAULT_TOKEN`` when ``MEFOR_STORE_VAULT_TOKEN`` or ``MEFOR_SECRETS_VAULT_TOKEN`` is unset, and
#: asyncpg falls back to ``PGPASSWORD`` when ``[store].password`` is unset. A list of names, so it
#: can be incomplete; the module docstring says what that leaves.
ENGINE_SECRETS_OUTSIDE_THE_PREFIX: Final = frozenset({"VAULT_TOKEN", "PGPASSWORD"})


def _key(name: str) -> str:
    """A variable name as the platform compares it: Windows names are case-insensitive."""
    return name.upper() if sys.platform == "win32" else name


def _allowed_for_a_worker(name: str, extra_names: Collection[str]) -> bool:
    key = _key(name)
    if key in extra_names or key in _INTERPRETER_NAMES:
        return True
    return key in (_WINDOWS_NAMES if sys.platform == "win32" else _POSIX_NAMES)


def outside_engine_namespace(name: str) -> bool:
    """Whether ``name`` is neither one of the engine's own ``MEFOR_*`` variables nor a secret a
    library reads on its behalf. Upper-cased on every platform: Windows reads ``mefor_x`` and
    ``MEFOR_X`` as one variable, and on POSIX refusing the lower-case spelling costs nothing."""
    upper = name.upper()
    return (
        not upper.startswith(ENGINE_ENV_PREFIX) and upper not in ENGINE_SECRETS_OUTSIDE_THE_PREFIX
    )


def _flags(extra_flags: Sequence[str]) -> list[str]:
    """``extra_flags`` ahead of :data:`CHILD_INTERPRETER_FLAGS`."""
    if isinstance(extra_flags, str):
        # A bare string is a sequence of its characters, so "-E" would arrive as "-" and "E".
        raise TypeError("extra_flags takes a sequence of options, not one string")
    return [*extra_flags, *CHILD_INTERPRETER_FLAGS]


def python_child_argv(
    module: str, *, executable: str | None = None, extra_flags: Sequence[str] = ()
) -> list[str]:
    """The command line that runs ``module`` in a child interpreter, as ``python -m`` would.

    Two differences from ``python -m``. The child starts with :data:`CHILD_INTERPRETER_FLAGS`.
    And it starts through :data:`_BOOTSTRAP`, which hands it the package location. A script start
    does not search the working directory, which is where ``python -m`` found the package in a
    source checkout that is not installed. Pass the result of :func:`worker_environment` or
    :func:`engine_environment` as its ``env``: they keep a ``PYTHONPATH`` entry from putting the
    working directory on the child's import path.

    ``extra_flags`` go ahead of the shared flags, for one caller's own options. The tray's login
    command passes ``-E`` this way (vault BACKLOG #2852).
    """
    return [executable or sys.executable, *_flags(extra_flags), _BOOTSTRAP, module]


def python_module_argv(
    module: str, *, executable: str | None = None, extra_flags: Sequence[str] = ()
) -> list[str]:
    """``python -m module`` with :data:`CHILD_INTERPRETER_FLAGS`, and no bootstrap.

    Shorter than :func:`python_child_argv`, and only for a package the interpreter can import on
    its own, from site-packages or a ``.pth`` entry. ``-P`` drops the working directory from a
    ``-m`` start, so a source checkout that is not installed cannot be found this way. Nothing
    pins this build either: the first ``messagefoundry`` on the import path answers. The tray's
    login command is the one user. It passes ``-E`` in ``extra_flags``, so an absolute
    ``PYTHONPATH`` entry naming another copy does not answer that start (vault BACKLOG #2852). The
    tray it relaunches still reads the user's ``PYTHONPATH``, less any empty or relative entry.
    """
    return [executable or sys.executable, *_flags(extra_flags), "-m", module]


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


def worker_environment(
    environ: Mapping[str, str] | None = None, *, extra_names: Collection[str] = ()
) -> dict[str, str]:
    """The environment for a Python child that runs code the engine does not fully trust.

    An allowlist over ``environ`` (default :data:`os.environ`): the platform's start-up names, the
    interpreter's own variables, and ``extra_names``. Code in the child that reads any other
    variable finds it unset, which is a difference from running in the engine process.

    ``extra_names`` is what the caller adds: an engine switch the child's own code reads to make a
    decision its parent already made, and the names an operator listed in
    ``[sandbox].pass_environment``. Never a secret: whatever is named here is in the environment of
    the code this builder exists to keep secrets from. Settings load refuses the engine's own.
    """
    if isinstance(extra_names, str):
        # A bare string is a collection of its characters, so no name would cross and nothing
        # would say why.
        raise TypeError("extra_names takes a collection of names, not one string")
    extras = frozenset(_key(name) for name in extra_names)
    return _without_working_directory_entries(
        {n: v for n, v in _source(environ).items() if _allowed_for_a_worker(n, extras)}
    )


def hook_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for a command an operator configured: everything outside the engine's own
    ``MEFOR_*`` namespace, less :data:`ENGINE_SECRETS_OUTSIDE_THE_PREFIX`.

    ``PYTHONPATH`` crosses as this process has it."""
    return {n: v for n, v in _source(environ).items() if outside_engine_namespace(n)}


def engine_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for a Python child started through the bootstrap that runs the engine's own
    trusted code: all of it, less any empty or relative ``PYTHONPATH`` entry, which would resolve
    against the working directory.

    An engine shard is one such child, and it needs the secrets. The tray's branded relaunch is
    another. A child that runs code the engine does not fully trust takes
    :func:`worker_environment` instead."""
    return _without_working_directory_entries(dict(_source(environ)))
