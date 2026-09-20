# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One profile lookup, shared by the three profile schemas under ``harness/load`` (BACKLOG #1837).

``harness/load/profiles/`` holds THREE unrelated TOML schemas: ``[load]``
(:mod:`harness.load.profile`), ``[connscale]`` (:mod:`harness.load.connscale.profile`) and
``[estate]`` (:mod:`harness.load.estate.profile`). Each carried its own copy of the same lookup —
try the argument as a path, else ``<name>.toml`` in the shipped directory, else raise listing the
known names.

BACKLOG #1835 added a second directory to that search for ``[load]`` alone: an operator's own
profiles under ``migration-local/profiles/``, because the shipped directory is force-included into
the harness wheel and a file dropped there ships even when ``.gitignore`` names it. A site-specific
``[connscale]`` or ``[estate]`` profile was left with nowhere to live but a full path — the same gap,
still open on two of the three.

Extracting the body is what closes it, and keeps it closed: the escape hatch is now a property of
the lookup rather than of one caller, so a schema cannot have the lookup and lack the hatch.

This module names all three schemas' filename conventions (:data:`CONNSCALE_PATTERNS`,
:data:`ESTATE_PATTERNS`). That is deliberate and is not the parent reaching into its children: the
conventions PARTITION one shared directory, so they are a property of the directory rather than of
any single schema, and ``[load]`` owning "whatever the others do not claim" cannot be stated at all
unless the claims sit in one place.
"""

from __future__ import annotations

import tomllib
from collections.abc import Callable, Sequence
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Protocol

#: The one shipped profile directory, shared by all three schemas.
PROFILES_DIR = Path(__file__).resolve().parent / "profiles"

#: Filename globs the non-``[load]`` schemas own inside :data:`PROFILES_DIR`. One directory holds
#: three schemas, so the FILENAME is what tells a listing which files are its own — there is no other
#: discriminator short of parsing every file with every parser.
CONNSCALE_PATTERNS: tuple[str, ...] = (
    "connscale*.toml",
    "pooled*.toml",
    "fuse*.toml",
    "batch*.toml",
)
ESTATE_PATTERNS: tuple[str, ...] = ("estate*.toml",)
#: ``[load]`` owns whatever the others do not claim.
LOAD_PATTERNS: tuple[str, ...] = ("*.toml",)
SIBLING_PATTERNS: tuple[str, ...] = CONNSCALE_PATTERNS + ESTATE_PATTERNS

#: Where an operator's OWN profiles live, relative to the current working directory. Deliberately
#: outside the package: :data:`PROFILES_DIR` is force-included whole into the harness wheel, and
#: hatchling's ``recurse_forced_files`` walks the filesystem without reading ``.gitignore``, so a
#: file dropped in there ships to everyone who installs the harness even when git is told to skip it
#: (BACKLOG #1835).
#:
#: ``migration-local/`` rather than a new directory: it is already this repository's ignored tree for
#: real-numbers, site-specific material, named as such by docs/LOAD-TESTING.md, profiles/README.md
#: and docs/CI-SELFHOSTED-RUNNER.md. A second location for the same thing is how two conventions
#: start disagreeing. What is new is only the ``profiles/`` subdirectory and the lookup below, which
#: give the bare name somewhere to resolve; running one by full path already worked and still does.
#:
#: Relative to the CWD rather than the package, because an installed harness has no checkout: the
#: operator runs it from their own directory.
LOCAL_PROFILES_SUBPATH = Path("migration-local") / "profiles"

#: What a listing appends to an operator-local entry.
LOCAL_LABEL = "(operator-local)"


def local_profiles_dir(cwd: Path | None = None) -> Path:
    """The operator-local profile directory under ``cwd``, defaulting to the process's own.

    A function, not a module constant: the CWD can change between import and call (pytest's
    ``monkeypatch.chdir``, a harness launched from elsewhere), and a constant would freeze whichever
    directory happened to be current at import time. The optional ``cwd`` matches the idiom every
    other CWD-dependent entry point in ``harness/load`` already uses (``connscale/runner.py``,
    ``estate/runner.py``, ``failover.py``, ``multishard.py``, ``shardcert.py``).
    """
    return (cwd or Path.cwd()) / LOCAL_PROFILES_SUBPATH


class NamedProfile(Protocol):
    """The two attributes every schema's profile dataclass carries, and all a listing reads.

    Read-only members, so a ``frozen=True`` dataclass satisfies it.
    """

    @property
    def name(self) -> str: ...

    @property
    def description(self) -> str: ...


def read_profile_toml(path: Path, *, error: type[Exception]) -> dict[str, Any]:
    """Read and parse one profile TOML, raising ``error`` on any problem.

    Decodes ``utf-8-sig``. PowerShell's ``Set-Content -Encoding utf8`` — the natural way to author a
    profile on Windows, and now the way an operator authors a local one — writes a BOM, which bare
    ``tomllib`` rejects with an opaque ``Invalid statement (line 1, col 1)``. ``[connscale]`` and
    ``[estate]`` already tolerated it and ``[load]`` did not; one shared reader settles that in
    favour of tolerance, which only ever accepts input the strict form rejected. UTF-8 itself is
    still enforced.
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise error(f"cannot read {path.name}: {exc}") from exc
    try:
        text = raw.decode("utf-8-sig")  # strips a UTF-8 BOM if present; still enforces UTF-8
    except UnicodeDecodeError as exc:
        raise error(f"cannot read {path.name}: not valid UTF-8 ({exc})") from exc
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise error(f"cannot read {path.name}: {exc}") from exc


def scan_profiles[ProfileT: NamedProfile](
    *,
    include: Sequence[str],
    exclude: Sequence[str] = (),
    load: Callable[[Path], ProfileT],
    error: type[Exception],
) -> dict[str, str]:
    """Profile name to description, across the shipped directory and the operator-local one.

    An operator-local entry is LABELLED as one. The two sets are listed together because that is the
    menu a reader needs, but a profile sized for one site is not a shipped built-in and a listing
    that hid the difference would invite treating it as one.

    A file that matches ``include`` but fails to ``load`` is reported as ``(invalid profile)`` rather
    than dropped, so a typo'd key shows up on the menu instead of making the profile disappear.

    The same globs apply to BOTH directories. The naming convention is how three schemas share one
    directory, and the local directory is shared exactly the same way, so an operator's own
    ``[connscale]`` profile is named ``connscale-<site>.toml`` for the same reason a shipped one is.
    """
    out: dict[str, str] = {}
    for directory, label in ((PROFILES_DIR, ""), (local_profiles_dir(), f" {LOCAL_LABEL}")):
        if not directory.is_dir():
            continue
        for path in sorted(_matching(directory, include, exclude)):
            try:
                profile = load(path)
            except error:
                out[path.stem] = f"(invalid profile){label}"
                continue
            out[profile.name] = f"{profile.description}{label}".lstrip()
    return out


def resolve_profile[ProfileT: NamedProfile](
    name_or_path: str,
    *,
    load: Callable[[Path], ProfileT],
    listing: Callable[[], dict[str, str]],
    error: type[Exception],
    label: str,
) -> ProfileT:
    """Resolve a filesystem path, an operator-local profile name, or a built-in name.

    A name carried by BOTH directories raises rather than picking one. Either precedence is a silent
    wrong answer half the time: built-in-wins ignores the file the operator just wrote, and
    local-wins reshapes a named run (``smoke`` is a CI gate) for anyone who happens to be standing in
    the wrong directory. A full path is always unambiguous and stays available.

    ``label`` names the schema in the two error messages (``"profile"``, ``"connscale profile"``,
    ``"estate profile"``), because the three entry points sit behind three different CLI flags and a
    bare "profile" would not say which one refused.
    """
    candidate = Path(name_or_path)
    if candidate.exists():
        return load(candidate)
    builtin = PROFILES_DIR / f"{name_or_path}.toml"
    local = local_profiles_dir() / f"{name_or_path}.toml"
    if builtin.is_file() and local.is_file():
        raise error(
            f"{label} {name_or_path!r} is ambiguous: it is both a built-in ({builtin}) and an "
            f"operator-local profile ({local}). Rename the local one, or pass a full path."
        )
    if local.is_file():
        return load(local)
    if builtin.is_file():
        return load(builtin)
    # "known profiles", not "built-ins": since BACKLOG #1835 this listing also carries the operator's
    # own, so naming it after the shipped set would describe a set it does not report.
    choices = ", ".join(sorted(listing())) or "(none)"
    raise error(f"unknown {label} {name_or_path!r}; known profiles: {choices}")


def _matching(directory: Path, include: Sequence[str], exclude: Sequence[str]) -> set[Path]:
    """Files in ``directory`` matching any ``include`` glob and no ``exclude`` glob.

    A set, because the ``include`` globs overlap by construction (``connscale*`` and ``batch*`` would
    both claim a hypothetical ``batch-connscale.toml``) and a file must be listed once.
    """
    hits = {path for pattern in include for path in directory.glob(pattern)}
    return {path for path in hits if not any(fnmatch(path.name, pat) for pat in exclude)}
