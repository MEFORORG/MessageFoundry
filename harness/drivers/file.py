# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File driver: drop each payload into the directory an engine File inbound polls.

Writes are atomic -- a hidden ``.part`` temp, then one link or rename onto the final name -- so the
engine never polls a half-written file. That is the same guarantee the engine's own File
destination gives, and the GUI's File tab drops through :func:`drop_atomic` too.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from uuid import uuid4

from harness.drivers import Driver, Injection
from harness.endpoints import Endpoints

KIND = "file"


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
    checked free, which is the best that filesystem allows. The temp is removed either way."""
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
