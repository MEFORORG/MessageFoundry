# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File driver: drop each payload into the directory an engine File inbound polls.

Writes are atomic -- a hidden ``.part`` temp, then one link or rename onto the final name -- so the
engine never polls a half-written file. That is the same guarantee the engine's own File
destination gives, and the GUI's File tab drops through :func:`drop_atomic` too.

A drop name the GUI builds from a message's own MSH-10 is untrusted: :func:`drop_name` reduces it to
one safe file name, the way the engine's File destination reduces a rendered name, and
:func:`drop_atomic` refuses any ``name`` that is not a single file name inside ``directory`` (ASVS
5.3.2).
"""

from __future__ import annotations

import contextlib
import errno
import ntpath
import os
import re
import tempfile
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints

KIND = "file"

#: Characters a drop name may not carry: path separators, the Windows-reserved punctuation, control
#: characters (NUL included) and lone surrogates. The same class as ``_UNSAFE`` in the engine's
#: ``transports/file.py``, duplicated because a harness module may not import ``transports``
#: (``tests/test_dependency_boundaries.py``); ``tests/test_harness_file_drop_name.py`` pins the two equal.
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f\ud800-\udfff]')

#: The longest drop name, suffix included, in UTF-8 bytes: the engine File destination's
#: ``FILENAME_MAX_BYTES`` (ADR 0204), duplicated and pinned for the same reason as :data:`_UNSAFE`.
MAX_DROP_NAME_BYTES = 200

#: The stem a drop takes when the one it was given reduces to nothing usable.
FALLBACK_STEM = "message"


def drop_name(stem: str, suffix: str = ".hl7", *, fallback: str = FALLBACK_STEM) -> str:
    """``stem`` reduced to ONE safe file name, with ``suffix`` appended: never a path.

    ``stem`` is untrusted (the Compose tab passes a message's own MSH-10). Mirrors the engine File
    destination's ``render_filename`` reduction: unsafe characters become ``_``, leading dots go (no
    hidden file, no ``.``/``..``), trailing dots and spaces go (Windows drops them when it opens a
    name), and an empty result, a Windows reserved device name, or a final name over
    :data:`MAX_DROP_NAME_BYTES` takes ``fallback`` instead. ``fallback`` and ``suffix`` are the
    caller's own constants, so they are trusted."""
    name = _UNSAFE.sub("_", stem).lstrip(".").rstrip(". ")
    if not name or ntpath.isreserved(name) or ntpath.isreserved(name + suffix):
        return fallback + suffix
    final = name + suffix
    if len(final.encode("utf-8", "surrogatepass")) > MAX_DROP_NAME_BYTES:
        return fallback + suffix
    return final


def _check_contained(directory: Path, name: str) -> None:
    """Raise :class:`OSError` (``EINVAL``) unless ``name`` is a single file name whose target is a
    direct child of ``directory``. Lexical on purpose: the final component is never followed, and
    :func:`drop_atomic` never writes through an existing name anyway (``os.link`` refuses one).
    The refusal does not quote ``name``, which came from a message."""
    resolved = Path(os.path.abspath(directory))
    target = Path(os.path.normpath(resolved / name)) if name else resolved
    if (
        not name
        or name in (".", "..")
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or target.parent != resolved
        or target.name != name
    ):
        raise OSError(errno.EINVAL, "drop name is not a single file name inside the drop directory")


def unique_path(target: Path) -> Path:
    """``target`` if free, else ``stem-1.hl7``, ``stem-2.hl7``, ... (never clobber a prior drop)."""
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    n = 1
    while True:
        candidate = target.with_name(f"{stem}-{n}{suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def drop_atomic(directory: Path, name: str, data: bytes) -> Path:
    """Publish ``data`` as ``directory/name`` (or ``name-1``, ``name-2``, ... when taken), complete,
    in one step. Raises :class:`OSError`.

    The bytes go to a uniquely named hidden temp first (``.*.part`` matches no poll pattern), which is
    then HARD-LINKED to the first free name. ``os.link`` refuses a name that exists, so there is no
    window between checking a name is free and taking it -- the race the engine's own File destination
    retired (``_claim_unique``). A filesystem without hard links falls back to a rename onto a name
    checked free, which is the best that filesystem allows. The temp is removed either way.

    ``name`` must be one file name inside ``directory``; anything else (a separator, ``..``, an
    absolute path, NUL, empty) raises :class:`OSError` before a byte is written. Reduce an
    untrusted name with :func:`drop_name` first."""
    _check_contained(directory, name)
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".", suffix=".part")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        target = directory / name
        n = 0
        while True:
            candidate = target if n == 0 else target.with_name(f"{target.stem}-{n}{target.suffix}")
            try:
                os.link(tmp, candidate)
                return candidate
            except FileExistsError:
                n += 1
            except OSError:
                candidate = unique_path(target)
                os.replace(tmp, candidate)
                return candidate
    finally:
        with contextlib.suppress(OSError):
            tmp.unlink()


class FileDriver(Driver):
    kind = KIND

    def __init__(self, directory: str | Path, *, suffix: str = ".hl7") -> None:
        self.directory = Path(directory)
        self.suffix = suffix

    def inject(self, payloads: Sequence[bytes]) -> list[Injection]:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return [Injection(error=str(exc)) for _ in payloads]
        outcomes: list[Injection] = []
        for payload in payloads:
            try:
                drop_atomic(self.directory, f"{uuid4().hex}{self.suffix}", payload)
                outcomes.append(Injection())
            except OSError as exc:
                outcomes.append(Injection(error=str(exc)))
        return outcomes


def build(endpoints: Endpoints, key: str) -> Driver:
    return FileDriver(endpoints.value(key))
