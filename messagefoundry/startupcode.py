# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""How the engine's interpreter was started, and what code ran in it before the engine did (vault
BACKLOG #2701).

**What this is about.** Two things put code inside a Python process before its first line runs.

* The ``PYTHON*`` environment variables. ``PYTHONPATH`` and ``PYTHONHOME`` change where the
  interpreter imports from, so one left in a service's environment decides what the engine loads.
  Isolated mode (``-I``) makes the interpreter ignore all of them. It also keeps the working
  directory and the user's own site directory off the import path.
* Start-up code in the directories the ``site`` module reads. ``site`` runs every line of a
  ``.pth`` file that begins with ``import``, and it imports a module named ``sitecustomize`` (and
  ``usercustomize``, where the user site is on) from anywhere on the import path. **Isolated mode
  does not stop either.** So whoever can write one of those directories gets code inside the
  engine at its next start.

**What this does.** :func:`read_startup_posture` reads three things from the running process:

1. The launch flags (:class:`InterpreterLaunch`): whether the interpreter is isolated, and which
   of the ``PYTHON*`` variables that change where code loads from are set.
2. The start-up code (:class:`StartupCodeItem`): each ``.pth`` file with an ``import`` line in a
   site directory, and each ``sitecustomize`` or ``usercustomize`` module on the import path. Each
   one is *expected* or it is not, by the rule under :data:`Verdict`.
3. Whether this process can add a file to a site directory. That is the prevention; the inventory
   is only detection.

``serve`` and ``supervise`` read it at start. Under ``[security].enforcement = "enforce"`` they
refuse to start on start-up code that is not expected (:func:`startup_refusal`). Everything else
is reported as a loosening (:func:`startup_loosenings`), through ``security_loosenings()`` and
``GET /security/posture``.

**What "expected" means, and where the list comes from.** There is no list of file names in this
module, apart from one (:data:`_PACKAGING_TOOL_PTH`). A file is expected when an installed
distribution in the same directory names it in its ``RECORD`` with a matching hash
(:func:`messagefoundry.integrity.record_verdict`). So a ``.pth`` that came with a package, which
includes the one an editable install of the engine writes and the one setuptools ships, is
expected on any install, and a file somebody dropped beside them is not. A ``sitecustomize`` in the
interpreter's own standard library directory is expected too: some operating-system builds ship
one, and whoever can write that directory can replace the standard library itself.

**What this is not.** Start-up code runs first. A planted ``.pth`` line runs before any engine
code, with the engine's rights, and could change what this module reads or skip it. The baseline
has the same limit ``messagefoundry/integrity.py`` records for its own: ``RECORD`` sits in the
directory it describes, so whoever can write the directory can write a matching row. The inventory
catches an honest mistake and a careless plant. A site directory the service account cannot write
is what stops a plant, which is why the third reading exists.

**Not covered.** A ``.pth`` file with no ``import`` line only adds directories to the import
path. It is not start-up code and is not listed, though a module found through it may be. Nor is a
package's own import-time code: that is ``messagefoundry/integrity.py`` for the engine's files and
nothing for a third-party package. The Python children the engine starts are not isolated; see
:func:`startup_loosenings`.

No engine state. The standard library, ``messagefoundry.controlchars`` and, when a file needs a
``RECORD`` lookup, ``messagefoundry.integrity``.
"""

from __future__ import annotations

import ctypes
import importlib.machinery
import os
import site
import stat
import sys
import sysconfig
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from messagefoundry.controlchars import scrub_log_argument

__all__ = [
    "ISOLATED_LAUNCH_OPTIONS",
    "InterpreterLaunch",
    "StartupCodeItem",
    "StartupPosture",
    "Verdict",
    "read_startup_posture",
    "startup_loosenings",
    "startup_posture",
    "startup_refusal",
]

#: The interpreter options each shipped service launch passes, ahead of ``-m messagefoundry``.
#: ``-I`` is isolated mode. ``-X disable-remote-debug`` turns off the remote-debugging interface
#: (vault BACKLOG #2700): under ``-I`` the ``PYTHON_DISABLE_REMOTE_DEBUG`` variable is ignored, so
#: only the option works. The option is spelled with hyphens; the interpreter accepts and ignores
#: the underscore spelling. ``tests/test_isolated_launch.py`` holds the installer and the image to
#: these, and reads the result off a real interpreter.
ISOLATED_LAUNCH_OPTIONS: Final = ("-I", "-X", "disable-remote-debug")

#: The ``PYTHON*`` variables that change WHERE the interpreter loads code from. The rest change how
#: the same code behaves (encoding, buffering, warnings) and are not reported.
_CODE_PATH_VARIABLES: Final = (
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONPLATLIBDIR",
    "PYTHONPYCACHEPREFIX",
    "PYTHONUSERBASE",
)

#: How one piece of start-up code was classified.
#:
#: * ``recorded``: an installed distribution in the same directory lists the file in its
#:   ``RECORD``, and the bytes match. Expected.
#: * ``interpreter``: the file is in the interpreter's own standard library directory. Expected.
#: * ``packaging_tool``: one of :data:`_PACKAGING_TOOL_PTH`, with exactly the content named there.
#:   Expected.
#: * ``modified``: a distribution lists the file, and its bytes differ from the row. Not expected.
#: * ``unrecorded``: nothing lists the file. Not expected.
Verdict = Literal["recorded", "interpreter", "packaging_tool", "modified", "unrecorded"]

_EXPECTED: Final[frozenset[Verdict]] = frozenset({"recorded", "interpreter", "packaging_tool"})

#: ``.pth`` files a tool writes straight into a site directory, with no distribution to record
#: them, by name and by the one statement each may hold. ``virtualenv`` and ``uv venv`` write
#: ``_virtualenv.pth`` into every environment they create. The name alone is not enough: the file
#: is expected only while its executable content is exactly this.
_PACKAGING_TOOL_PTH: Final = {"_virtualenv.pth": "import _virtualenv"}

#: The module names ``site`` imports at start, when it finds them.
_CUSTOMIZE_MODULES: Final = ("sitecustomize", "usercustomize")

#: A ``.pth`` file larger than this is not read for its lines. It is listed as start-up code
#: without being parsed: no packaging tool writes one this size.
_PTH_READ_LIMIT: Final = 1024 * 1024

#: The most file names one message carries. The count is always exact.
_NAMES_IN_A_MESSAGE: Final = 8

Kind = Literal["pth", "sitecustomize", "usercustomize"]


@dataclass(frozen=True, slots=True)
class InterpreterLaunch:
    """The flags this interpreter was started with, and the code-path variables in its environment."""

    #: ``sys.flags.isolated``: started with ``-I``.
    isolated: bool
    #: ``sys.flags.safe_path``: neither the working directory nor the script's directory is put
    #: first on the import path. ``-I`` and ``-P`` both set it.
    safe_path: bool
    #: ``sys.flags.ignore_environment``: the ``PYTHON*`` variables are not read. ``-I`` and ``-E``.
    ignore_environment: bool
    #: ``sys.flags.no_user_site``: the user's own site directory is off. ``-I`` and ``-s``.
    no_user_site: bool
    #: The names from :data:`_CODE_PATH_VARIABLES` that are set. Names only, never values.
    code_path_variables: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StartupCodeItem:
    """One file that runs, or would run, when this interpreter starts."""

    kind: Kind
    path: str
    verdict: Verdict
    #: The distribution whose ``RECORD`` lists the file, for ``recorded`` and ``modified``.
    owner: str | None = None

    @property
    def expected(self) -> bool:
        return self.verdict in _EXPECTED


@dataclass(frozen=True, slots=True)
class StartupPosture:
    """What :func:`read_startup_posture` read from this process."""

    launch: InterpreterLaunch
    #: Every piece of start-up code found, expected or not, in a stable order.
    items: tuple[StartupCodeItem, ...] = ()
    #: The directories ``site`` reads ``.pth`` files from in this process.
    site_dirs: tuple[str, ...] = ()
    #: The site directories this process can add a file to.
    writable_site_dirs: tuple[str, ...] = ()
    #: The site directories where that could not be determined. Not a clean result.
    unchecked_site_dirs: tuple[str, ...] = ()

    @property
    def unexpected(self) -> tuple[StartupCodeItem, ...]:
        return tuple(item for item in self.items if not item.expected)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def interpreter_launch() -> InterpreterLaunch:
    """The launch flags of THIS process. It says nothing about any other process."""
    flags = sys.flags
    present = {name.upper() for name in os.environ} if sys.platform == "win32" else set(os.environ)
    return InterpreterLaunch(
        isolated=bool(flags.isolated),
        safe_path=bool(flags.safe_path),
        ignore_environment=bool(flags.ignore_environment),
        no_user_site=bool(flags.no_user_site),
        code_path_variables=tuple(name for name in _CODE_PATH_VARIABLES if name in present),
    )


def _site_dirs() -> list[Path]:
    """The directories whose ``.pth`` files ``site`` processed for this interpreter, existing ones
    only. On Windows that includes the installation prefix itself."""
    candidates = list(site.getsitepackages())
    if site.ENABLE_USER_SITE:
        candidates.append(site.getusersitepackages())
    seen: set[str] = set()
    out: list[Path] = []
    for candidate in candidates:
        key = _norm(candidate)
        if key not in seen and os.path.isdir(candidate):
            seen.add(key)
            out.append(Path(os.path.abspath(candidate)))
    return out


def _is_hidden(path: Path) -> bool:
    """Whether ``site`` skips this ``.pth`` file as hidden. Mirrors ``site.addpackage``."""
    if path.name.startswith("."):
        return True
    try:
        st = path.lstat()
    except OSError:
        return False
    return bool(
        getattr(st, "st_flags", 0) & getattr(stat, "UF_HIDDEN", 0)
        or getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0)
    )


def _executable_lines(path: Path) -> list[str] | None:
    """The lines of a ``.pth`` file that ``site`` executes, or None when the file was not read.

    ``site`` executes a line that begins with ``import`` and a space or a tab, exactly, and treats
    every other line as a directory or a comment. Trailing white space is dropped here, so a line
    ending differs from :data:`_PACKAGING_TOOL_PTH` by nothing."""
    try:
        if path.stat().st_size > _PTH_READ_LIMIT:
            return None
        text = path.read_bytes().decode("utf-8-sig", errors="replace")
    except OSError:
        return None
    return [line.rstrip() for line in text.splitlines() if line.startswith(("import ", "import\t"))]


def _recorded(path: Path, directory: Path) -> tuple[Verdict, str | None]:
    # Imported here: the settings module imports this one for its types, and the lookup needs the
    # packaging metadata reader, which is only wanted when there is a file to look up.
    from messagefoundry.integrity import record_verdict

    return record_verdict(path, directory)


def _pth_items(directory: Path) -> list[StartupCodeItem]:
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(".pth"))
    except OSError:
        return []
    items: list[StartupCodeItem] = []
    for name in names:
        path = directory / name
        if _is_hidden(path) or not path.is_file():
            continue
        lines = _executable_lines(path)
        if lines is not None and not lines:
            continue  # directories only: not start-up code (see the module docstring)
        if lines is not None and [_PACKAGING_TOOL_PTH.get(name)] == lines:
            items.append(StartupCodeItem("pth", str(path), "packaging_tool"))
            continue
        verdict, owner = _recorded(path, directory)
        items.append(StartupCodeItem("pth", str(path), verdict, owner))
    return items


def _interpreter_dirs() -> frozenset[str]:
    """The interpreter's own standard library directories. In a virtual environment these are the
    base interpreter's, which is the point: the environment's own directories are not in here."""
    found = (sysconfig.get_path(name) for name in ("stdlib", "platstdlib"))
    return frozenset(_norm(path) for path in found if path)


def _customize_items(site_dirs: list[Path]) -> list[StartupCodeItem]:
    """Each ``sitecustomize`` and ``usercustomize`` module findable on the import path.

    Every entry is searched, not only the first that answers: a module on a later entry runs the
    day the earlier one is removed. Nothing is imported. A module found on an entry that was added
    after start-up, such as the working directory under ``python -m``, did not run at this start
    and is listed anyway."""
    interpreter_dirs = _interpreter_dirs()
    site_keys = {_norm(str(directory)): directory for directory in site_dirs}
    items: list[StartupCodeItem] = []
    seen: set[str] = set()
    for entry in sys.path:
        root = os.path.abspath(entry or os.getcwd())
        key = _norm(root)
        if key in seen:
            continue
        seen.add(key)
        for name in _CUSTOMIZE_MODULES:
            try:
                spec = importlib.machinery.PathFinder.find_spec(name, [root])
            except (ImportError, OSError, ValueError):
                spec = None
            if spec is None or spec.origin is None or not spec.has_location:
                continue  # nothing there, or a namespace package, which runs no code
            origin = spec.origin
            kind: Kind = "sitecustomize" if name == "sitecustomize" else "usercustomize"
            if key in interpreter_dirs:
                items.append(StartupCodeItem(kind, origin, "interpreter"))
                continue
            # A distribution can only record a file under the directory its metadata sits in.
            directory = site_keys.get(key, Path(root))
            verdict, owner = _recorded(Path(origin), directory)
            items.append(StartupCodeItem(kind, origin, verdict, owner))
    return items


#: ``FILE_ADD_FILE``: the right to create a file in a directory.
_FILE_ADD_FILE: Final = 0x0002
_FILE_SHARE_ALL: Final = 0x0007
_OPEN_EXISTING: Final = 3
#: Needed to open a directory at all.
_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_ERROR_ACCESS_DENIED: Final = 5


def _can_add_files(directory: Path) -> bool | None:
    """Whether this process may create a file in ``directory``. None when that cannot be told.

    Nothing is created. On Windows the directory is opened asking for the add-file right, which
    makes the system run its own access check against this process's token, a write-restricted
    service token included. ``os.access`` cannot answer there: it reads the read-only attribute
    and no permission. Elsewhere ``os.access`` asks the kernel, with the effective ids where the
    platform supports that, and a read-only file system answers no."""
    if sys.platform != "win32":
        try:
            effective = os.access in os.supports_effective_ids
            return os.access(directory, os.W_OK | os.X_OK, effective_ids=effective)
        except OSError:
            return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return None
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create_file.restype = ctypes.c_void_p
    handle = create_file(
        str(directory),
        _FILE_ADD_FILE,
        _FILE_SHARE_ALL,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle is None or handle == invalid:
        return False if ctypes.get_last_error() == _ERROR_ACCESS_DENIED else None
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle(handle)
    return True


def read_startup_posture() -> StartupPosture:
    """Read the launch flags, the start-up code and the site directories of THIS process, now.

    Blocking file reads: directory listings, and one hash for each ``.pth`` or customize module
    that needs a ``RECORD`` lookup. Never raises for a file it cannot read. An interpreter started
    with ``-S`` ran none of this, and reports no start-up code."""
    launch = interpreter_launch()
    if sys.flags.no_site:
        return StartupPosture(launch=launch)
    site_dirs = _site_dirs()
    items = [item for directory in site_dirs for item in _pth_items(directory)]
    items.extend(_customize_items(site_dirs))
    writable: list[str] = []
    unchecked: list[str] = []
    for directory in site_dirs:
        answer = _can_add_files(directory)
        if answer is None:
            unchecked.append(str(directory))
        elif answer:
            writable.append(str(directory))
    return StartupPosture(
        launch=launch,
        items=tuple(items),
        site_dirs=tuple(str(directory) for directory in site_dirs),
        writable_site_dirs=tuple(writable),
        unchecked_site_dirs=tuple(unchecked),
    )


_cache_lock = threading.Lock()
_cached: StartupPosture | None = None


def startup_posture() -> StartupPosture:
    """The reading for this process, taken once and kept.

    Start-up code runs when the interpreter starts, so the reading that matters is the one taken
    then: a file added later has not run in this process. ``serve`` and ``supervise`` take it as
    they start, and ``GET /security/posture`` reports that same reading for the life of the
    process. Restart the engine to read again."""
    global _cached
    with _cache_lock:
        if _cached is None:
            _cached = read_startup_posture()
        return _cached


def _named(paths: tuple[str, ...]) -> str:
    shown = ", ".join(scrub_log_argument(path) for path in paths[:_NAMES_IN_A_MESSAGE])
    more = len(paths) - _NAMES_IN_A_MESSAGE
    return f"{shown} and {more} more" if more > 0 else shown


def _named_items(items: tuple[StartupCodeItem, ...]) -> str:
    return _named(tuple(f"{item.path} ({item.verdict})" for item in items))


_WHAT_STARTUP_CODE_IS: Final = (
    "A .pth line that begins with `import`, and a sitecustomize or usercustomize module, run each "
    "time the interpreter starts, before any engine code and with everything the engine holds"
)


def startup_refusal(posture: StartupPosture) -> str | None:
    """Why ``serve`` or ``supervise`` must not start under the enforcing posture, or None.

    Only start-up code that is not expected refuses. A launch that is not isolated and a writable
    site directory are reported and never refused: a plain ``messagefoundry serve`` from a
    developer's own environment is both, by construction."""
    unexpected = posture.unexpected
    if not unexpected:
        return None
    return (
        f"start-up code the engine does not know is installed in its interpreter "
        f"({len(unexpected)}): {_named_items(unexpected)}. {_WHAT_STARTUP_CODE_IS}. `recorded` "
        "files are the ones an installed package lists with a matching hash; these are not. "
        "Remove each file, or install it as part of a package so that its distribution records "
        'it. To start anyway with it reported, set [security].enforcement = "warn". See '
        "docs/SECURITY-LOOSENING.md"
    )


def startup_loosenings(posture: StartupPosture) -> list[tuple[str, str]]:
    """The ``(name, plain-language risk)`` entries for ``posture``. One place for the wording, so
    ``security_loosenings()`` and the ``supervise`` start-up lines cannot say different things."""
    out: list[tuple[str, str]] = []
    launch = posture.launch
    variables = ", ".join(launch.code_path_variables)
    if not launch.isolated:
        honoured = (
            f" {variables} is set in its environment now."
            if variables and not launch.ignore_environment
            else ""
        )
        path = (
            "The working directory is kept off its import path (-P)."
            if launch.safe_path
            else "Its import path may start with the working directory or the script's directory."
        )
        out.append(
            (
                "interpreter_not_isolated",
                "the engine's interpreter was not started in isolated mode (-I), so it reads "
                "the PYTHON* environment variables, PYTHONPATH and PYTHONHOME included, and one "
                f"left in the service's environment decides what the engine imports.{honoured} "
                f"{path} The shipped service launches pass -I. An engine shard that `supervise` "
                "starts is not isolated: the supervisor starts it with -P and hands it the "
                "variables. Start the engine as `python -I -X disable-remote-debug -m "
                "messagefoundry serve ...`",
            )
        )
    elif variables:
        out.append(
            (
                "python_variables_reach_children",
                f"{variables} is set in the engine's environment. The engine ignores it (isolated "
                "mode), but the Python children it starts (the sandbox worker, and each engine "
                "shard under `supervise`) are not isolated and would import from where it "
                "points. Remove it from the service's environment",
            )
        )
    if posture.unexpected:
        out.append(
            (
                "startup_code_unexpected",
                f"start-up code the engine does not know is installed in its interpreter "
                f"({len(posture.unexpected)}): {_named_items(posture.unexpected)}. "
                f'{_WHAT_STARTUP_CODE_IS}. Under [security].enforcement = "enforce" the engine '
                "refuses to start on it. Remove each file, or install it as part of a package",
            )
        )
    if posture.writable_site_dirs:
        out.append(
            (
                "site_packages_writable",
                f"the engine's own account can add files to {len(posture.writable_site_dirs)} of "
                "the directories its interpreter reads start-up code from "
                f"({_named(posture.writable_site_dirs)}). Code running as that account could plant "
                "a .pth file or a sitecustomize module there, and it would run inside the engine "
                "at the next start, ahead of the check that looks for it. Install the engine "
                "where the service account can read and cannot write",
            )
        )
    if posture.unchecked_site_dirs:
        out.append(
            (
                "site_packages_unchecked",
                "the engine could not tell whether its own account can add files to "
                f"{len(posture.unchecked_site_dirs)} of the directories its interpreter reads "
                f"start-up code from ({_named(posture.unchecked_site_dirs)}), so nothing here "
                "says they are protected. Check their permissions by hand",
            )
        )
    return out
