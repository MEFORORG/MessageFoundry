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
  and the engine switches its caller names. A variable nobody listed does not cross.
* :func:`hook_environment` is **everything except the engine's own namespace**, for a command an
  operator configured (the DR hook). Such a command may need ordinary variables the engine cannot
  list in advance, such as a cloud profile or a proxy. It has no use for the engine's settings, so
  the whole ``MEFOR_*`` prefix is dropped. Dropping a prefix does not go stale the way a list of
  secret names would. A few names outside the prefix are dropped too
  (:data:`_ENGINE_SECRETS_OUTSIDE_THE_PREFIX`). **A secret kept under any other name still reaches
  the hook**: a ``[secrets].provider = "env"`` reference may name any variable, a library may read
  one this module does not know, and neither can be listed here.
* :func:`engine_environment` is the **whole** environment, for a child that is itself a full engine
  (an engine shard). It opens the store and builds connections, so it needs the secrets.

**THIS IS NOT AN ISOLATION BOUNDARY BY ITSELF.** A child that runs as the same operating-system
account as the engine can still read the engine process, and the files that account can read. What
an explicit environment removes is the direct read: the secret is no longer sitting in the child's
own environment. Running the child as a different account is separate work.

Stdlib only, so any package may import it.
"""

from __future__ import annotations

import os
import site
import sys
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Final

__all__ = [
    "ENGINE_ENV_PREFIX",
    "SAFE_PATH_FLAG",
    "engine_environment",
    "hook_environment",
    "worker_environment",
]

#: The engine's own settings and secrets are named with this prefix. The libraries it uses read
#: other names as well; :data:`_ENGINE_SECRETS_OUTSIDE_THE_PREFIX` holds the secret ones known here.
ENGINE_ENV_PREFIX: Final = "MEFOR_"

#: The interpreter flag a ``python -m`` child is started with. Without it Python puts the working
#: directory first on the child's import path, so a file there could stand in for a module the child
#: imports. :func:`_with_import_path` hands the child the package location that flag takes away,
#: and says when the flag's promise holds.
SAFE_PATH_FLAG: Final = "-P"

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
_ENGINE_SECRETS_OUTSIDE_THE_PREFIX: Final = frozenset({"VAULT_TOKEN", "PGPASSWORD"})


def _allowed_for_a_worker(name: str, engine_switches: Collection[str]) -> bool:
    # Windows names are case-insensitive; POSIX names are not.
    key = name.upper() if sys.platform == "win32" else name
    if key in engine_switches or key in _INTERPRETER_NAMES:
        return True
    return key in (_WINDOWS_NAMES if sys.platform == "win32" else _POSIX_NAMES)


def _outside_the_engine_namespace(name: str) -> bool:
    # Upper-cased on every platform. Windows reads `mefor_x` and `MEFOR_X` as one variable, and on
    # POSIX dropping the lower-case spelling costs a hook nothing.
    upper = name.upper()
    return (
        not upper.startswith(ENGINE_ENV_PREFIX) and upper not in _ENGINE_SECRETS_OUTSIDE_THE_PREFIX
    )


def _package_root() -> str:
    """The directory that holds this ``messagefoundry`` package."""
    return str(Path(__file__).resolve().parent.parent)


def _site_directories() -> set[str]:
    """The site-packages directories every interpreter started from this one searches by itself."""
    found = [*site.getsitepackages(), site.getusersitepackages()]
    return {str(Path(entry).resolve()) for entry in found if entry}


def _with_import_path(env: dict[str, str]) -> dict[str, str]:
    """Set the ``PYTHONPATH`` of a ``python -m`` child started with :data:`SAFE_PATH_FLAG`.

    Two things, both so that the child still starts and imports the build its parent is running:

    * **Only absolute entries of the inherited ``PYTHONPATH`` cross.** An empty or relative entry
      names the working directory, which is what the flag takes off the child's import path.
    * **This package's location goes first, unless it is in site-packages.** An engine run from a
      source checkout that is not installed found its own package in the working directory, so its
      child would fail to import it. Putting it first also keeps another copy, further down the
      path, from answering in the child when it did not in the parent. Site-packages is left off:
      every child searches it already, and a ``PYTHONPATH`` entry is searched ahead of the standard
      library.

    **So the flag keeps the working directory off the child's path only when that directory is not
    the engine's own checkout.** For an engine run or installed from a checkout, the checkout is
    named here, ahead of the standard library, as the working directory was before.
    """
    root = _package_root()
    inherited = env.pop("PYTHONPATH", "")
    entries = [entry for entry in inherited.split(os.pathsep) if os.path.isabs(entry)]
    if root not in _site_directories():
        entries = [root, *(entry for entry in entries if str(Path(entry).resolve()) != root)]
    if entries:
        env["PYTHONPATH"] = os.pathsep.join(entries)
    return env


def _source(environ: Mapping[str, str] | None) -> Mapping[str, str]:
    return os.environ if environ is None else environ


def worker_environment(
    environ: Mapping[str, str] | None = None, *, engine_switches: Collection[str] = ()
) -> dict[str, str]:
    """The environment for a ``python -m`` child that runs code the engine does not fully trust.

    An allowlist over ``environ`` (default :data:`os.environ`): the platform's start-up names, the
    interpreter's own variables, and ``engine_switches``. Code in the child that reads any other
    variable finds it unset, which is a difference from running in the engine process.

    ``engine_switches`` names the ``MEFOR_*`` variables the child's own code reads to make a decision
    its parent already made. It is for a switch, never for a secret: whatever is named here is in
    the environment of the code this builder exists to keep secrets from.
    """
    if isinstance(engine_switches, str):
        # A bare string is a collection of its characters, so no switch would cross and nothing
        # would say why.
        raise TypeError("engine_switches takes a collection of names, not one string")
    switches = frozenset(engine_switches)
    return _with_import_path(
        {n: v for n, v in _source(environ).items() if _allowed_for_a_worker(n, switches)}
    )


def hook_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for a command an operator configured: everything outside the engine's own
    ``MEFOR_*`` namespace, less :data:`_ENGINE_SECRETS_OUTSIDE_THE_PREFIX`.

    ``PYTHONPATH`` crosses as this process has it. In an engine shard started from a checkout that
    includes the engine's package location, which :func:`engine_environment` put there."""
    return {n: v for n, v in _source(environ).items() if _outside_the_engine_namespace(n)}


def engine_environment(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment for a ``python -m`` child that is itself a full engine: all of it."""
    return _with_import_path(dict(_source(environ)))
