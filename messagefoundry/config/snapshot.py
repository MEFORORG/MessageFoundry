# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One read of a config bundle: the bytes a load hashes, compiles and runs (vault BACKLOG #2596).

A load used to read the config directory several times: Python's source loader read each module
(and preferred a matching ``__pycache__`` file to it), the code-set and ``connections.toml`` loaders
read their own files, and the content digest read everything again. So the digest an approval named
and an audit row recorded could describe bytes other than the ones that ran, and a planted cache
file ran under an unchanged digest.

A :class:`ConfigSnapshot` is the one read. :func:`messagefoundry.config.wiring.load_config` compiles
each module from the snapshot's bytes itself, so no cache file is ever consulted, and parses the
code sets and ``connections.toml`` from the same snapshot. The ADR 0041 content fingerprint folds
the same bytes (:mod:`messagefoundry.config.fingerprint`), and a ``[sandbox].mode=subprocess``
worker is handed the snapshot instead of a directory, so a respawn runs what the engine loaded.

This module reads and classifies bytes; it hashes nothing, so it adds no entry to the crypto
inventory."""

from __future__ import annotations

import errno
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from types import MappingProxyType

from messagefoundry.config.code_sets import CODESETS_DIR_NAME, is_code_set_name

__all__ = [
    "CONNECTIONS_REL",
    "ConfigDirMissing",
    "ConfigSnapshot",
    "NotInSnapshot",
    "config_py_files",
    "is_missing_directory",
    "read_config_snapshot",
    "with_value_file",
]

#: The relative path ``connections.toml`` is recorded under, whichever file was read for it (the live
#: one, or the candidate an edit is validating).
CONNECTIONS_REL = "connections.toml"

#: The folder of per-environment value files the ADR 0041 fingerprint has always covered under the
#: config directory. **Covered, never loaded:** the loader reads none of them. The value file a serve
#: start actually reads sits under ``[environments].base_dir``, which by default is not the config
#: directory. Where it is this folder, a reload's value provider parses the bytes this snapshot read
#: for it (:meth:`ConfigSnapshot.environment_file`); a value file elsewhere is read into the snapshot
#: by :func:`with_value_file`, under :data:`_VALUE_FILE_DIR`.
_ENVIRONMENTS_DIR = "environments"

#: The folder name a value file outside ``environments/`` is recorded under, with its file name
#: alone, so the digest stays independent of where the bundle sits. No listing returns it: a listed
#: entry is a top-level module or ``connections.toml``, or sits in one of :data:`_FOLDERS`. Covered
#: and never loaded, like ``environments/`` (vault BACKLOG #2596).
_VALUE_FILE_DIR = "@value-file"
_VALUE_FILE_PREFIX = f"{_VALUE_FILE_DIR}/"

#: The folders a snapshot lists, beside the directory itself.
_FOLDERS: tuple[str, ...] = (CODESETS_DIR_NAME, _ENVIRONMENTS_DIR)


class NotInSnapshot(LookupError):
    """A value file outside the snapshot's ``environments/`` folder and not the one
    :func:`with_value_file` read into it, whose bytes the snapshot did not read and its digest does
    not cover (:meth:`ConfigSnapshot.environment_file`)."""


class ConfigDirMissing(FileNotFoundError):
    """The directory a strict read was asked for is not a directory. Its own type, so a caller can
    tell it from a covered file that vanished, which is a plain ``FileNotFoundError``."""


#: The Windows errors that refuse a path's name itself: ERROR_INVALID_NAME (123), ERROR_BAD_PATHNAME
#: (161) and ERROR_FILENAME_EXCED_RANGE (206). Python maps the first to EINVAL, not ENOENT.
_INVALID_NAME_WINERRORS: frozenset[int] = frozenset({123, 161, 206})

#: The Windows errors that say a network path or share cannot be reached, so nothing is known about
#: what is there: ERROR_BAD_NETPATH (53) and ERROR_BAD_NET_NAME (67). Python maps both to ENOENT, so
#: each arrives as a ``FileNotFoundError``. ERROR_PATH_NOT_FOUND (3) and ERROR_INVALID_DRIVE (15) map
#: the same way and stay absence, so a drive letter this process does not have reads as missing,
#: even where it is mapped in another session.
_UNREACHABLE_WINERRORS: frozenset[int] = frozenset({53, 67})


def _is_absent(exc: OSError) -> bool:
    """Whether ``exc`` says nothing is at the path, as against saying the path cannot be reached."""
    unreachable = getattr(exc, "winerror", None) in _UNREACHABLE_WINERRORS
    return not unreachable and isinstance(exc, FileNotFoundError)


def is_missing_directory(exc: OSError) -> bool:
    """Whether ``exc``, raised resolving or listing a directory, says no directory can be opened by
    that path: nothing by that name, a file rather than a directory, a name or whole path too long
    for the filesystem (ENAMETOOLONG, or Windows error 206), or a name Windows refuses, such as
    ``sub?``. ``Path.is_dir`` answers ``False`` for all of them, so a caller that lists the
    directory instead reports them as missing too (vault BACKLOG #2596). Any other error is not a
    missing directory: at least access denied, and a share Windows cannot reach (errors 53 and 67),
    which is a fault in reaching the folder and says nothing about what it holds, though
    ``Path.is_dir`` answers ``False`` for that too."""
    return (
        _is_absent(exc)
        or isinstance(exc, NotADirectoryError)
        or exc.errno == errno.ENAMETOOLONG
        or getattr(exc, "winerror", None) in _INVALID_NAME_WINERRORS
    )


def config_py_files(directory: Path) -> list[Path]:
    """Every ``*.py`` in ``directory`` the loader may run or import, sorted: dot-named files excluded.

    ``Path.glob("*.py")`` matches ``.IB_OLD.py`` (an editor or manual backup) and ``._IB_ACME_ADT.py``
    (a macOS AppleDouble file left by an SMB copy) too, because pathlib has no hidden-file rule. Neither
    is config, so the loader, both config-source trust checks and the fingerprint skip a dot-named
    module the same way (vault BACKLOG #2781). The ``_``-helper skip is the loader's own rule on top of
    this, not part of it: a helper is still run when a sibling imports it, so the trust check and the
    fingerprint keep it.

    Raises the ``OSError`` of a directory it cannot list, a missing one included. It globbed, and
    ``Path.glob`` drops a listing error, so a share lost at that moment answered ``[]`` and ADR 0036's
    trust check vetted no module of a bundle the load then listed and ran (vault BACKLOG #5117)."""
    with os.scandir(directory) as entries:
        return sorted(directory / e.name for e in entries if _covered_name(".", e.name))


def _covered_name(folder: str, name: str) -> bool:
    """Whether a snapshot reads ``name`` from ``folder``. For the directory itself (``.``) that is
    :func:`config_py_files`'s rule for one name: the suffix in the case the platform matches it
    (without case on Windows), and not dot-named."""
    if folder == ".":
        return os.path.normcase(name).endswith(".py") and not name.startswith(".")
    if folder == CODESETS_DIR_NAME:
        return is_code_set_name(name)
    return Path(name).suffix.lower() == ".toml"


def _covered_only(rel: str) -> bool:
    """Whether ``rel`` (a file, or a folder that could not be listed) is one the fingerprint
    covers and no load reads."""
    return rel == _ENVIRONMENTS_DIR or rel.startswith((f"{_ENVIRONMENTS_DIR}/", _VALUE_FILE_PREFIX))


def _is_module_rel(rel: str) -> bool:
    return "/" not in rel and rel.lower().endswith(".py") and not rel.startswith(".")


def _plain_name(part: str) -> bool:
    """Whether ``part`` names one entry of a folder on this platform, and nothing else: joined to
    a directory it stays in that directory, and its ``name`` is itself. On Windows that refuses a
    backslash and a drive (``C:x.py``); on POSIX both are ordinary characters, and a file so named
    is one the listing can return, so it is accepted there."""
    return part not in ("", ".", "..") and PurePath(part).name == part and not PurePath(part).anchor


def _check_rel(rel: object) -> str:
    """``rel`` when it is a relative path a snapshot can hold, else ``ValueError``. A snapshot can
    arrive from another process (the sandbox boot frame), so its names are checked, not trusted:
    a module at the top level, ``connections.toml``, or one file in ``codesets/`` or
    ``environments/``, each part a plain name on this platform (:func:`_plain_name`). Nothing here
    is ever opened, but a module's name is joined to the snapshot's directory and looked up again
    by that path's ``name``, so a part that is not a plain name could select another file's bytes.
    Every name :func:`read_config_snapshot` lists on a platform passes there."""
    if not isinstance(rel, str) or not rel or "\0" in rel:
        raise ValueError(f"config snapshot path {rel!r} is not a plain relative path")
    parts = rel.split("/")
    if not all(_plain_name(part) for part in parts):
        raise ValueError(f"config snapshot path {rel!r} is not a plain relative path")
    if len(parts) == 1 and (rel == CONNECTIONS_REL or _is_module_rel(rel)):
        return rel
    if (
        len(parts) == 2
        and parts[0] in (*_FOLDERS, _VALUE_FILE_DIR)
        and _covered_name(parts[0], parts[1])
    ):
        return rel
    raise ValueError(f"config snapshot path {rel!r} is not a file a config load reads")


@dataclass(frozen=True, slots=True, eq=False)
class ConfigSnapshot:
    """The bytes of every file one load of a config directory reads, keyed by relative path.

    ``directory`` is the absolute path the bytes were read from: config modules are compiled under
    ``directory / name``, so a traceback and a diagnostic name the file an author edits.
    ``files`` maps each relative path (``cfg.py``, ``_helpers.py``, ``connections.toml``,
    ``codesets/diets.csv``, ``environments/dev.toml``) to its bytes. ``unreadable`` names each file,
    or folder, that could not be read and is left out; a strict read raises instead, so it is empty
    there. The ``environments/`` files are covered by the fingerprint and never loaded as config;
    a reload's value provider may parse one (:meth:`environment_file`).

    ``value_file`` is the absolute path of a value file outside ``environments/`` that
    :func:`with_value_file` read into ``files`` as ``@value-file/<name>``, or tried to. It is
    covered and never loaded, like ``environments/``, and ``None`` when there is no such file."""

    directory: Path
    files: Mapping[str, bytes]
    unreadable: tuple[str, ...] = ()
    value_file: Path | None = None
    _modules: tuple[str, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        checked = {_check_rel(rel): bytes(data) for rel, data in self.files.items()}
        object.__setattr__(self, "files", MappingProxyType(dict(sorted(checked.items()))))
        # In path order, as the loader ran them when it globbed the directory: without case on
        # Windows, so a bundle's load order, and which file a duplicate-name refusal names, stay
        # what they were.
        modules = (rel for rel in self.files if _is_module_rel(rel))
        object.__setattr__(self, "_modules", tuple(sorted(modules, key=PurePath)))

    @property
    def modules(self) -> tuple[str, ...]:
        """Every config module's file name, in path order (without case on Windows),
        ``_``-prefixed helpers included."""
        return self._modules

    @property
    def connections(self) -> bytes | None:
        """The bytes of ``connections.toml``, or ``None`` when there is none."""
        return self.files.get(CONNECTIONS_REL)

    @property
    def code_set_files(self) -> dict[str, bytes]:
        """Each table in ``codesets/``, by its file name there."""
        prefix = f"{CODESETS_DIR_NAME}/"
        return {
            rel[len(prefix) :]: data for rel, data in self.files.items() if rel.startswith(prefix)
        }

    @property
    def unreadable_loaded(self) -> tuple[str, ...]:
        """The unreadable entries a load would have read, as against those only the fingerprint
        covers. A load refuses when there is any: it cannot run bytes it does not have."""
        return tuple(rel for rel in self.unreadable if not _covered_only(rel))

    def covers_environment_file(self, path: str | Path) -> bool:
        """Whether ``path`` is in this snapshot's ``environments/`` folder, or is its
        :attr:`value_file`, so the snapshot's digest covers the file there, or that there is none
        (:func:`_same_folder`)."""
        return self._folder_of(Path(path)) is not None

    def _folder_of(self, path: Path) -> str | None:
        """The folder this snapshot records the value file ``path`` under, or ``None`` when it does
        not cover it."""
        if _same_folder(path.parent, self.directory / _ENVIRONMENTS_DIR):
            return _ENVIRONMENTS_DIR
        held = self.value_file
        if (
            held is not None
            and os.path.normcase(path.name) == os.path.normcase(held.name)
            and _same_folder(path.parent, held.parent)
        ):
            return _VALUE_FILE_DIR
        return None

    def environment_file(self, path: str | Path) -> bytes | None:
        """The bytes this snapshot read for the value file ``path``, which
        :meth:`covers_environment_file` must accept, or ``None`` when it read no such file and none
        is there now. A caller reading values for a reload parses these instead of reading the file
        again, so the values it applies are the bytes the digest covered (vault BACKLOG #2596).

        Raises :class:`NotInSnapshot` for a path the snapshot does not cover. Raises ``OSError``
        where the bytes cannot stand for the file now: the snapshot could not read it or its
        folder, read a file that is gone now, or read no file by its name while one is there now,
        created since. The caller refuses then; the values are read again on the next reload."""
        value_file = Path(path)
        folder = self._folder_of(value_file)
        if folder is None:
            raise NotInSnapshot(f"{value_file} is not a value file the config snapshot read")
        prefix = f"{folder}/"
        want = os.path.normcase(prefix + value_file.name)
        if any(rel == folder or os.path.normcase(rel) == want for rel in self.unreadable):
            raise OSError(errno.EACCES, "the config snapshot could not read this value file")
        # A regular file, following links, as a start judges it (``Path.is_file``) and as the
        # snapshot read it: a folder or a dangling link by that name is no value file to either.
        present = os.path.isfile(value_file)
        data = self.files.get(prefix + value_file.name)
        if data is None and present and os.path.normcase("A") != "A":
            # Windows names files without case, so the open of this path reads a file the listing
            # spelled otherwise. Only where the path names a file now: in a folder set to tell case
            # apart, it does not, and a start would read no file.
            data = next(
                (data for rel, data in self.files.items() if os.path.normcase(rel) == want), None
            )
        if data is None and present:
            raise OSError(errno.EEXIST, "the value file was created after the config snapshot")
        if data is not None and not present:
            # The file's own access list was vetted only if it is still there, so bytes from a
            # file gone since are not used.
            raise OSError(errno.ENOENT, "the value file the config snapshot read is gone")
        return data

    def loaded(self, *, code_sets: bool = True) -> ConfigSnapshot:
        """This snapshot without the files only the fingerprint covers: what a sandbox worker
        needs to run the same graph, and no more. Without ``code_sets``, the ``codesets/`` tables
        are left out too, for a worker handed the engine's parsed tables instead."""
        codesets = f"{CODESETS_DIR_NAME}/"
        return ConfigSnapshot(
            directory=self.directory,
            files={
                rel: data
                for rel, data in self.files.items()
                if not _covered_only(rel) and (code_sets or not rel.startswith(codesets))
            },
        )


def with_value_file(
    snapshot: ConfigSnapshot, value_file: str | Path | None, *, strict: bool
) -> ConfigSnapshot:
    """``snapshot`` with the value file ``value_file`` read into it, so its digest covers those
    bytes and a reload parses them (:meth:`ConfigSnapshot.environment_file`; vault BACKLOG #2596).

    ``value_file`` is the path a start reads, ``<base_dir>/<dir>/<env>.toml``, wherever
    ``[environments].base_dir`` puts it; it is read and recorded by its resolved path. Returns
    ``snapshot`` itself when ``value_file`` is ``None``, sits in the snapshot's ``environments/``
    folder, which the snapshot already read, or is the file the snapshot already holds. A file that is not there is
    held as absent, so creating one changes the digest. With ``strict`` a fault reading it raises
    its ``OSError``; without, it is named in :attr:`ConfigSnapshot.unreadable`. It is read as
    :func:`read_config_snapshot` reads a file, following links. Its access list is not vetted
    here: a caller that gates on the bytes vets the file and its folder before this read."""
    if value_file is None:
        return snapshot
    # Resolved as an open resolves it, links before ``..``, so the file read here is the file a
    # provider's open of the same path reads; ``abspath`` folds ``..`` as text and can name another.
    path = Path(os.path.realpath(value_file))
    if snapshot.covers_environment_file(path):
        return snapshot
    files = {k: v for k, v in snapshot.files.items() if not k.startswith(_VALUE_FILE_PREFIX)}
    unreadable = {rel for rel in snapshot.unreadable if not rel.startswith(_VALUE_FILE_PREFIX)}
    rel = _check_rel(_VALUE_FILE_PREFIX + path.name)
    _read_into(files, unreadable, rel, path, strict=strict)
    return ConfigSnapshot(
        directory=snapshot.directory,
        files=files,
        unreadable=tuple(sorted(unreadable)),
        value_file=path,
    )


def read_config_snapshot(directory: str | Path, *, strict: bool) -> ConfigSnapshot:
    """Read every file a load of ``directory`` reads, once, into a :class:`ConfigSnapshot`.

    The config modules, by :func:`_covered_name`, which gives the list a load digests and runs (of
    the reads a load makes, only its trust check lists by :func:`config_py_files`),
    ``connections.toml`` (or the candidate an edit is validating), each table in ``codesets/``
    (:func:`~messagefoundry.config.code_sets.is_code_set_name`), and each ``environments/*.toml``,
    which the fingerprint covers and the loader never reads. Only regular
    files, following links, are read: a link is read through, and its target's bytes are what a
    load would run. Never a ``__pycache__`` file.

    With ``strict`` a fault raises: :class:`ConfigDirMissing` when ``directory`` is not a directory
    at its first listing, and the ``OSError`` when a folder cannot be listed or a file cannot be
    stat'ed or read. A directory removed after that listing raises nothing and reads as the files
    still found, down to none. Without ``strict``, a missing directory reads as an empty snapshot
    and each fault is recorded in :attr:`ConfigSnapshot.unreadable` instead. A file removed before
    its stat is dropped, with or without ``strict``. One removed after its stat raises with
    ``strict``, and without it is gone, not unreadable. A share Windows reports as unreachable is a
    fault in each case, not a missing folder or a removed file (:func:`is_missing_directory`)."""
    # Lazy: connections_file imports the loader, which imports this module.
    from messagefoundry.config.connections_file import connections_file_path

    base = Path(directory)
    unreadable: set[str] = set()
    try:
        listable = _list_folders(base, unlistable=None if strict else unreadable)
    except ConfigDirMissing:
        if strict:
            raise
        return ConfigSnapshot(directory=Path(os.path.abspath(base)), files={})
    candidates: list[tuple[str, Path]] = [(CONNECTIONS_REL, connections_file_path(base))]
    for folder in (".", *_FOLDERS):
        if folder not in listable:
            continue
        # Listed here and not by config_py_files, so that a lax read records the folder it cannot
        # list as unreadable rather than raise.
        try:
            names = sorted(entry.name for entry in os.scandir(base / folder))
        except OSError as exc:
            if is_missing_directory(exc):
                continue  # removed since it was listed: nothing in it to read
            if strict:
                raise
            unreadable.add(folder)
            continue
        candidates += [
            (name if folder == "." else f"{folder}/{name}", base / folder / name)
            for name in names
            if _covered_name(folder, name)
        ]
    files: dict[str, bytes] = {}
    for rel, path in candidates:
        _read_into(files, unreadable, rel, path, strict=strict)
    return ConfigSnapshot(
        directory=Path(os.path.abspath(base)), files=files, unreadable=tuple(sorted(unreadable))
    )


def _read_into(
    files: dict[str, bytes], unreadable: set[str], rel: str, path: Path, *, strict: bool
) -> None:
    """Read ``path`` into ``files`` as ``rel`` if it is a regular file. A fault raises with
    ``strict``; without, it adds ``rel`` to ``unreadable``. A file that is gone is neither."""
    try:
        # A stat that fails for any reason but absence is an unreadable file, not a missing
        # one: Path.is_file would answer False and the file would drop out unremarked.
        if _is_file(path):
            files[rel] = _read(path)
    except OSError as exc:
        if strict:
            raise
        # Absent means removed since the listing: gone, as _is_file judges a gone path.
        if not _is_absent(exc):
            unreadable.add(rel)


def _list_folders(base: Path, *, unlistable: set[str] | None) -> set[str]:
    """Which of ``base`` (``.``) and each folder a snapshot reads in it exist and can be listed.

    Raise unless each can be listed, or, with ``unlistable``, add each that cannot to it by its
    path relative to ``base`` instead. ``glob`` swallows a listing error, so a missing or unlistable
    directory would read as an empty bundle. A missing ``base`` raises :class:`ConfigDirMissing`,
    and so does one whose name no directory can have (:func:`is_missing_directory`); any other fault
    raises its own ``OSError``. A sub-folder that is missing by the same rule is fine: there is
    nothing in it to leave out."""
    missing = False
    try:
        with os.scandir(base):
            pass
    except OSError as exc:
        if not is_missing_directory(exc):
            if unlistable is None:
                raise
            unlistable.add(".")  # nothing under it can be listed either
            return set()
        missing = True
    if missing:
        # Raised after the handler, so the error it replaces does not ride __context__.
        raise ConfigDirMissing(errno.ENOENT, "config directory not found", str(base))
    listable = {"."}
    for folder in _FOLDERS:
        try:
            with os.scandir(base / folder):
                pass
        except OSError as exc:
            # The same rule as base: a folder no path can open holds nothing the loader reads.
            if not is_missing_directory(exc):
                if unlistable is None:
                    raise
                unlistable.add(folder)
            continue
        listable.add(folder)
    return listable


def _same_folder(one: Path, other: Path) -> bool:
    """Whether ``one`` and ``other`` name the same folder: the same path after following links
    (without case on Windows), which needs neither to exist, or else the same file system object,
    which catches a spelling the path comparison misses, such as a second mount point."""
    if os.path.normcase(os.path.realpath(one)) == os.path.normcase(os.path.realpath(other)):
        return True
    try:
        return os.path.samefile(one, other)
    except OSError:
        return False


def _is_file(path: Path) -> bool:
    """Whether ``path`` is a regular file, following links. ``Path.is_file`` answers ``False`` for a
    path it cannot stat, so this stats it instead and raises that error. A path that is gone (a
    dangling link, or a file removed since the listing) is not a file."""
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except OSError as exc:
        if _is_absent(exc):
            return False
        raise


def _read(path: Path) -> bytes:
    """The bytes of ``path``, which :func:`_is_file` just accepted. ``open`` reports the C runtime's
    errno and no Windows error, so a share lost since the stat fails as a plain file-not-found. A
    second stat tells them apart: it raises the Windows error for a lost share and absence for a
    file removed since. One that finds the file there means the read failed and the file is not
    gone, so that raises as a fault too."""
    try:
        return path.read_bytes()
    except FileNotFoundError as exc:
        path.stat()
        raise OSError(errno.EIO, "a config file that exists could not be read", str(path)) from exc
