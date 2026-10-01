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
#: imports. :func:`_with_import_path` hands the child the package location that flag takes away.
SAFE_PATH_FLAG: Final = "-P"

#: Interpreter variables cross as a namespace, not one by one. They are settings of the interpreter
#: (encoding, hash seed, warnings, the import path), and a child started without one the parent has
#: would run the same Handler differently from ``[sandbox].mode = "off"``.
_INTERPRETER_PREFIX: Final = "PYTHON"

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

#: The POSIX equivalent. ``LD_LIBRARY_PATH`` is here because an interpreter built against a shared
#: library outside the default search path cannot start without it. Every ``LC_*`` name crosses too.
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
    }
)
_POSIX_LOCALE_PREFIX: Final = "LC_"

#: Secrets the engine may rely on that are not named ``MEFOR_*``, because a library it uses reads
#: them when the engine's own setting is unset. At least these two: hvac falls back to
#: ``VAULT_TOKEN`` when ``MEFOR_STORE_VAULT_TOKEN`` or ``MEFOR_SECRETS_VAULT_TOKEN`` is unset, and
#: asyncpg falls back to ``PGPASSWORD`` when ``[store].password`` is unset. A list of names, so it
#: can be incomplete; the module docstring says what that leaves.
_ENGINE_SECRETS_OUTSIDE_THE_PREFIX: Final = frozenset({"VAULT_TOKEN", "PGPASSWORD"})


def _allowed_for_a_worker(name: str, engine_switches: Collection[str]) -> bool:
    # Windows names are case-insensitive; POSIX names are not.
    key = name.upper() if sys.platform == "win32" else name
    if key in engine_switches or key.startswith(_INTERPRETER_PREFIX):
        return True
    if sys.platform == "win32":
        return key in _WINDOWS_NAMES
    return key in _POSIX_NAMES or key.startswith(_POSIX_LOCALE_PREFIX)


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


def _searches_the_working_directory() -> bool:
    """Whether THIS process was started without :data:`SAFE_PATH_FLAG`, so that its own import of
    this package may have come from the working directory or the script's directory."""
    return not sys.flags.safe_path


def _with_import_path(env: dict[str, str]) -> dict[str, str]:
    """Set the ``PYTHONPATH`` of a ``python -m`` child started with :data:`SAFE_PATH_FLAG`.

    Two things, both so that the flag means what it says and the child still starts:

    * **Only absolute entries of the inherited ``PYTHONPATH`` cross.** An empty or relative entry
      names the working directory, which is what the flag takes off the child's import path.
    * **This package's location goes first, when the child would not find it otherwise.** An engine
      run from a source checkout that is not installed found its own package in the working
      directory, so its child would fail to import it. That is the case when this process searches
      the working directory and the package is outside site-packages. A process started with the
      flag found the package without the working directory, so its child does too; and
      site-packages is left off, because a ``PYTHONPATH`` entry is searched ahead of the standard
      library.

    For an editable install the entry is redundant, and it puts the checkout ahead of the standard
    library and site-packages in the child. The working directory already did that for a child of
    an engine started from its checkout.
    """
    root = _package_root()
    inherited = env.pop("PYTHONPATH", "")
    entries = [entry for entry in inherited.split(os.pathsep) if os.path.isabs(entry)]
    if (
        _searches_the_working_directory()
        and root not in entries
        and root not in _site_directories()
    ):
        entries.insert(0, root)
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
