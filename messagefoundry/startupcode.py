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
   site directory, and each customize module on the import path. Each one is *expected* or it is
   not, by the rule under :data:`Verdict`.
3. Whether this process can add a file to a directory start-up code is read from. That is the
   prevention; the inventory is only detection.

``serve`` and ``supervise`` read it at start. Under ``[security].enforcement = "enforce"`` they
refuse to start on start-up code that is not expected (:func:`startup_refusal`). Everything else
is reported as a loosening (:func:`startup_loosenings`), through ``security_loosenings()`` and
``GET /security/posture``.

**What "expected" means, and where the list comes from.** There is no list of file names in this
module, apart from one (:data:`_PACKAGING_TOOL_PTH`). A file is expected when an installed
distribution names it in its ``RECORD`` with a matching hash
(:func:`messagefoundry.integrity.record_verdict`). So a ``.pth`` that came with a package, which
includes the one an editable install of the engine writes and the one setuptools ships, is
expected on any install, and a file somebody dropped beside them is not. A ``sitecustomize`` in the
BASE interpreter's standard library directory is expected too: some operating-system builds ship
one, and whoever can write that directory can replace the standard library itself.

**The children's import path is searched too.** The engine hands its Python children the absolute
entries of ``PYTHONPATH`` (``messagefoundry/childenv.py``), and they are not isolated. So a
``sitecustomize`` there runs in the sandbox worker and in each engine shard even when the engine
itself ignores the variable. Those entries are searched beside the engine's own import path.

**What this is not.** Start-up code runs first. A planted ``.pth`` line runs before any engine
code, with the engine's rights, and could change what this module reads or skip it. The baseline
has the same limit ``messagefoundry/integrity.py`` records for its own: ``RECORD`` sits in the
directory it describes, so whoever can write the directory can write a matching row. The inventory
catches an honest mistake and a careless plant. A directory the service account cannot write is
what stops a plant, which is why the third reading exists.

**Not covered**, at least:

* A ``.pth`` file with no ``import`` line. It only adds directories to the import path, so it is
  not start-up code and is not listed. A customize module found through it is.
* A package's own import-time code. That is ``messagefoundry/integrity.py`` for the engine's files
  and nothing for a third-party package.
* The module a packaging tool's ``.pth`` imports (:data:`_PACKAGING_TOOL_PTH`): only the ``.pth``
  line is compared.
* A child's user site directory. Outside a virtual environment a child that is not isolated has
  one, and an isolated engine does not look there.
* An import-path entry that is an archive. Only directories are checked for write access.

No engine state. The standard library, ``messagefoundry.controlchars`` and, when a file needs a
``RECORD`` lookup, ``messagefoundry.integrity``.
"""

from __future__ import annotations

import ctypes
import importlib.machinery
import locale
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
    "Kind",
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
#: * ``recorded``: an installed distribution lists the file in its ``RECORD``, and the bytes
#:   match. Expected.
#: * ``interpreter``: the file is in the base interpreter's standard library directory. Expected.
#: * ``packaging_tool``: one of :data:`_PACKAGING_TOOL_PTH`, with exactly the content named there,
#:   in an environment that tool made. Expected.
#: * ``modified``: a distribution lists the file, and its bytes differ from the row. Not expected.
#: * ``unrecorded``: nothing lists the file. Not expected.
Verdict = Literal["recorded", "interpreter", "packaging_tool", "modified", "unrecorded"]

_EXPECTED: Final[frozenset[Verdict]] = frozenset({"recorded", "interpreter", "packaging_tool"})

#: ``.pth`` files a tool writes straight into a site directory, with no distribution to record
#: them, by name and by the one statement each may hold. ``virtualenv`` and ``uv venv`` write
#: ``_virtualenv.pth`` into every environment they create. The name alone is not enough. The file
#: is expected only while its executable content is exactly this, and only in an environment
#: whose ``pyvenv.cfg`` says one of :data:`_PACKAGING_TOOL_KEYS` made it: ``python -m venv`` writes
#: no such file, so one found there was put there by something else.
_PACKAGING_TOOL_PTH: Final = {"_virtualenv.pth": "import _virtualenv"}

#: The ``pyvenv.cfg`` keys the tools above leave behind.
_PACKAGING_TOOL_KEYS: Final = frozenset({"virtualenv", "uv"})

#: What kind of start-up code a file is: a ``.pth`` file, or one of the two modules ``site``
#: imports at start when it finds them.
Kind = Literal["pth", "sitecustomize", "usercustomize"]

#: A ``.pth`` file larger than this is not read for its lines. It is listed as start-up code
#: without being parsed: no packaging tool writes one this size.
_PTH_READ_LIMIT: Final = 1024 * 1024

#: The most file names one message carries. The count is always exact.
_NAMES_IN_A_MESSAGE: Final = 8


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
    #: The names from :data:`_CODE_PATH_VARIABLES` that are set to something. Names only, never
    #: values.
    code_path_variables: tuple[str, ...] = ()
    #: The ones among them a Python child of the engine is handed with something in it. That
    #: leaves out a ``PYTHONPATH`` with no absolute entry, which the child builders drop.
    reaching_children: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class StartupCodeItem:
    """One file that runs, or would run, when this interpreter or one of its children starts."""

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
    #: The directories start-up code is read from: the site directories, whose ``.pth`` files
    #: ``site`` reads, and every directory on the import path, where it looks for a customize
    #: module.
    startup_dirs: tuple[str, ...] = ()
    #: The ones this process can add a file to.
    writable_startup_dirs: tuple[str, ...] = ()
    #: The ones where that could not be determined. Not a clean result.
    unchecked_startup_dirs: tuple[str, ...] = ()

    @property
    def unexpected(self) -> tuple[StartupCodeItem, ...]:
        return tuple(item for item in self.items if not item.expected)


def _norm(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


def _unique(paths: list[str]) -> list[str]:
    """``paths`` made absolute, in order, without repeats. A relative path that cannot be made
    absolute, because the working directory is gone, is left out: nothing can be found in it."""
    seen: set[str] = set()
    out: list[str] = []
    for path in paths:
        try:
            absolute = os.path.abspath(path)
        except OSError:
            continue
        key = os.path.normcase(absolute)
        if key not in seen:
            seen.add(key)
            out.append(absolute)
    return out


def _inherited_pythonpath() -> list[str]:
    """The ``PYTHONPATH`` entries the engine hands a Python child: the absolute ones.
    ``messagefoundry/childenv.py`` drops the rest."""
    entries = os.environ.get("PYTHONPATH", "").split(os.pathsep)
    return [entry for entry in entries if os.path.isabs(entry)]


def _interpreter_launch() -> InterpreterLaunch:
    """The launch flags of THIS process. It says nothing about any other process."""
    flags = sys.flags
    present = tuple(name for name in _CODE_PATH_VARIABLES if os.environ.get(name))
    return InterpreterLaunch(
        isolated=bool(flags.isolated),
        safe_path=bool(flags.safe_path),
        ignore_environment=bool(flags.ignore_environment),
        no_user_site=bool(flags.no_user_site),
        code_path_variables=present,
        reaching_children=tuple(
            name for name in present if name != "PYTHONPATH" or _inherited_pythonpath()
        ),
    )


def _site_dirs() -> list[Path]:
    """The directories whose ``.pth`` files ``site`` processed for this interpreter, existing ones
    only. On Windows that includes the installation prefix itself."""
    candidates = list(site.getsitepackages())
    if site.ENABLE_USER_SITE:
        candidates.append(site.getusersitepackages())
    return [Path(path) for path in _unique(candidates) if os.path.isdir(path)]


def _search_path() -> list[str]:
    """The import path a customize module is looked for on: this process's, then the absolute
    ``PYTHONPATH`` entries the engine hands its Python children. A process that reads the
    variable has them on its own path already. An entry that is not text is left out, as the
    import system leaves it out."""
    own = [entry or os.curdir for entry in sys.path if isinstance(entry, str)]
    return _unique(own + _inherited_pythonpath())


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

    This mirrors ``site.addpackage``, so that it splits the file into the lines ``site`` saw. The
    bytes are read as UTF-8 and, where that fails, in the locale's encoding, as ``site`` does: a
    different decoding can put a line break in a different place. ``site`` executes a line that
    begins with ``import`` and a space or a tab, exactly. Trailing white space is dropped here,
    so a line ending differs from :data:`_PACKAGING_TOOL_PTH` by nothing."""
    try:
        if path.stat().st_size > _PTH_READ_LIMIT:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw.decode(locale.getencoding())
        except (UnicodeDecodeError, LookupError):
            return None
    return [line.rstrip() for line in text.splitlines() if line.startswith(("import ", "import\t"))]


def _recorded(path: Path, roots: list[Path]) -> tuple[Verdict, str | None]:
    """The ``RECORD`` verdict for ``path`` against the distributions installed in each of
    ``roots``, first answer wins. ``unrecorded`` when none of them lists it."""
    # Imported here: the settings module imports this one for its types, and the lookup needs the
    # packaging metadata reader, which is only wanted when there is a file to look up.
    from messagefoundry.integrity import record_verdict

    for root in roots:
        verdict, owner = record_verdict(path, root)
        if verdict != "unrecorded":
            return verdict, owner
    return "unrecorded", None


def _made_by_a_packaging_tool() -> bool:
    """Whether this environment's ``pyvenv.cfg`` carries one of :data:`_PACKAGING_TOOL_KEYS`."""
    try:
        text = (Path(sys.prefix) / "pyvenv.cfg").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    keys = {line.partition("=")[0].strip().lower() for line in text.splitlines() if "=" in line}
    return bool(keys & _PACKAGING_TOOL_KEYS)


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
        # None is a file that was not read. It is neither of the two cases below, so it is
        # listed, and judged by its RECORD row alone.
        lines = _executable_lines(path)
        if lines == []:
            continue  # directories only: not start-up code (see the module docstring)
        if lines == [_PACKAGING_TOOL_PTH.get(name)] and _made_by_a_packaging_tool():
            items.append(StartupCodeItem("pth", str(path), "packaging_tool"))
            continue
        verdict, owner = _recorded(path, [directory])
        items.append(StartupCodeItem("pth", str(path), verdict, owner))
    return items


def _interpreter_dirs() -> frozenset[str]:
    """The BASE interpreter's standard library directories.

    Asked for with the base prefixes on purpose. In a virtual environment the plain
    ``platstdlib`` answer is the environment's own library folder, which the environment's owner
    can write, and a module planted there must not read as the interpreter's."""
    base = {"base": sys.base_prefix, "platbase": sys.base_exec_prefix}
    found = (sysconfig.get_path(name, vars=base) for name in ("stdlib", "platstdlib"))
    return frozenset(_norm(path) for path in found if path)


def _customize_modules() -> tuple[Kind, ...]:
    """The module names ``site`` imports at start. ``usercustomize`` only where the user site is
    on, which is the only place ``site`` imports it."""
    return ("sitecustomize", "usercustomize") if site.ENABLE_USER_SITE else ("sitecustomize",)


def _customize_items(site_dirs: list[Path], search: list[str]) -> list[StartupCodeItem]:
    """Each customize module findable on ``search`` (:func:`_search_path`).

    Every entry is searched, not only the first that answers: a module on a later entry runs the
    day the earlier one is removed. Nothing is imported. A module found on an entry that was added
    after start-up, such as the working directory under ``python -m``, did not run at this start
    and is listed anyway.

    A package may ship the module in a directory of its own and put that directory on the import
    path, so the ``RECORD`` lookup also asks each site directory the file sits under."""
    interpreter_dirs = _interpreter_dirs()
    names = _customize_modules()
    items: list[StartupCodeItem] = []
    for root in search:
        for name in names:
            try:
                spec = importlib.machinery.PathFinder.find_spec(name, [root])
            except (ImportError, OSError, ValueError):
                spec = None
            if spec is None or spec.origin is None or not spec.has_location:
                continue  # nothing there, or a namespace package, which runs no code
            if _norm(root) in interpreter_dirs:
                items.append(StartupCodeItem(name, spec.origin, "interpreter"))
                continue
            origin = Path(spec.origin)
            holders = [d for d in site_dirs if d != Path(root) and origin.is_relative_to(d)]
            verdict, owner = _recorded(origin, [Path(root), *holders])
            items.append(StartupCodeItem(name, spec.origin, verdict, owner))
    return items


#: ``FILE_ADD_FILE`` and ``FILE_ADD_SUBDIRECTORY``: the rights to create a file and a folder in a
#: directory. A customize module may be a package, so either one is enough to plant it.
_ADD_RIGHTS: Final = (0x0002, 0x0004)
_FILE_SHARE_ALL: Final = 0x0007
_OPEN_EXISTING: Final = 3
#: Needed to open a directory at all.
_FILE_FLAG_BACKUP_SEMANTICS: Final = 0x02000000
_ERROR_ACCESS_DENIED: Final = 5


def _can_add_files(directory: Path) -> bool | None:
    """Whether this process may create a file or a folder in ``directory``. None when that cannot
    be told.

    Nothing is created. On Windows the directory is opened asking for each add right in turn,
    which makes the system run its own access check against this process's token, a
    write-restricted service token included. ``os.access`` cannot answer there: it reads the
    read-only attribute and no permission. Elsewhere ``os.access`` asks the kernel, with the
    effective ids where the platform supports that, and a read-only file system answers no.

    It does not ask whether an EXISTING file in the directory can be rewritten. A start-up file
    the account owns inside a directory it cannot add to is not seen here."""
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
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    invalid = ctypes.c_void_p(-1).value
    every_right_denied = True
    for right in _ADD_RIGHTS:
        handle = create_file(
            str(directory),
            right,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if handle is not None and handle != invalid:
            kernel32.CloseHandle(handle)
            return True
        if ctypes.get_last_error() != _ERROR_ACCESS_DENIED:
            every_right_denied = False
    # Not writable only when the system refused each right. Any other failure settles nothing.
    return False if every_right_denied else None


def read_startup_posture() -> StartupPosture:
    """Read the launch flags, the start-up code and its directories for THIS process, now.

    Blocking file reads: directory listings, and one hash for each ``.pth`` or customize module
    that needs a ``RECORD`` lookup. Never raises for a file it cannot read. An interpreter started
    with ``-S`` ran none of this, and reports no start-up code."""
    launch = _interpreter_launch()
    if sys.flags.no_site:
        return StartupPosture(launch=launch)
    site_dirs = _site_dirs()
    search = _search_path()
    items = [item for directory in site_dirs for item in _pth_items(directory)]
    items.extend(_customize_items(site_dirs, search))
    # An import-path entry that is an archive, or that does not exist, holds no file to plant.
    startup_dirs = [
        path for path in _unique([*(str(d) for d in site_dirs), *search]) if os.path.isdir(path)
    ]
    writable: list[str] = []
    unchecked: list[str] = []
    for path in startup_dirs:
        answer = _can_add_files(Path(path))
        if answer is None:
            unchecked.append(path)
        elif answer:
            writable.append(path)
    return StartupPosture(
        launch=launch,
        items=tuple(items),
        startup_dirs=tuple(startup_dirs),
        writable_startup_dirs=tuple(writable),
        unchecked_startup_dirs=tuple(unchecked),
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


def _unexpected_summary(unexpected: tuple[StartupCodeItem, ...]) -> str:
    """What the refusal and the loosening entry both open with, so they name the files alike."""
    files = _named(tuple(f"{item.path} ({item.verdict})" for item in unexpected))
    return (
        "start-up code the engine does not know is installed where its interpreter, or a Python "
        f"child it starts, would run it ({len(unexpected)}): {files}. A .pth line that begins "
        "with `import`, and a sitecustomize or usercustomize module, run each time the "
        "interpreter starts, before any engine code and with everything the engine holds"
    )


def startup_refusal(posture: StartupPosture) -> str | None:
    """Why ``serve`` or ``supervise`` must not start under the enforcing posture, or None.

    Only start-up code that is not expected refuses. A launch that is not isolated and a writable
    start-up directory are reported and never refused: a plain ``messagefoundry serve`` from a
    developer's own environment is both, by construction."""
    if not posture.unexpected:
        return None
    return (
        f"{_unexpected_summary(posture.unexpected)}. `recorded` files are the ones an installed "
        "package lists with a matching hash; these are not. Remove each file, or install it as "
        "part of a package so that its distribution records it. To start anyway with it "
        'reported, set [security].enforcement = "warn". See docs/SECURITY-LOOSENING.md'
    )


def startup_loosenings(posture: StartupPosture) -> list[tuple[str, str]]:
    """The ``(name, plain-language risk)`` entries for ``posture``. One place for the wording, so
    ``security_loosenings()`` and the ``supervise`` start-up lines cannot say different things."""
    out: list[tuple[str, str]] = []
    launch = posture.launch
    variables = ", ".join(launch.code_path_variables)
    if not launch.isolated:
        if launch.ignore_environment:
            reads = "It was told to ignore the PYTHON* environment variables (-E)."
        else:
            reads = (
                "It reads the PYTHON* environment variables, PYTHONPATH and PYTHONHOME included, "
                "so one left in the service's environment decides what the engine imports."
                + (f" {variables} is set in its environment now." if variables else "")
            )
        path = (
            "The working directory is kept off its import path (-P)."
            if launch.safe_path
            else "Its import path may start with the working directory or the script's directory."
        )
        out.append(
            (
                "interpreter_not_isolated",
                "the engine's interpreter was not started in isolated mode (-I). "
                f"{reads} {path} The shipped service launches pass -I. An engine shard that "
                "`supervise` starts is not isolated: the supervisor starts it with -P and hands "
                "it the variables. Start the engine as "
                f"`python {' '.join(ISOLATED_LAUNCH_OPTIONS)} -m messagefoundry serve ...`",
            )
        )
    if launch.ignore_environment and launch.reaching_children:
        out.append(
            (
                "python_variables_reach_children",
                f"{', '.join(launch.reaching_children)} is set in the engine's environment. The "
                "engine ignores it, but the "
                "Python children it starts (the sandbox worker, and each engine shard under "
                "`supervise`) are not isolated and would import from where it points. Remove it "
                "from the service's environment",
            )
        )
    if posture.unexpected:
        out.append(
            (
                "startup_code_unexpected",
                f"{_unexpected_summary(posture.unexpected)}. Under [security].enforcement = "
                '"enforce" the engine refuses to start on it. Remove each file, or install it as '
                "part of a package",
            )
        )
    if posture.writable_startup_dirs:
        out.append(
            (
                "startup_directory_writable",
                "the engine's own account can add files to "
                f"{len(posture.writable_startup_dirs)} of the directories its interpreter reads "
                f"start-up code from ({_named(posture.writable_startup_dirs)}). Code running as "
                "that account could plant a .pth file or a sitecustomize module there, and it "
                "would run inside the engine at the next start, ahead of the check that looks "
                "for it. Install the engine where the service account can read and cannot write",
            )
        )
    if posture.unchecked_startup_dirs:
        out.append(
            (
                "startup_directory_unchecked",
                "the engine could not tell whether its own account can add files to "
                f"{len(posture.unchecked_startup_dirs)} of the directories its interpreter reads "
                f"start-up code from ({_named(posture.unchecked_startup_dirs)}), so nothing here "
                "says they are protected. Check their permissions by hand",
            )
        )
    return out
