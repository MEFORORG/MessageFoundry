# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""File driver: drop each payload into the directory an engine File inbound polls.

Writes are atomic -- a hidden ``.part`` temp, then ``os.replace`` -- so the engine never polls a
half-written file. That is the same guarantee the engine's own File destination gives, and the GUI's
File tab drops through :func:`drop_atomic` too.
"""

from __future__ import annotations

import os
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
    """Publish ``data`` as ``directory/name`` (uniquified) in one rename. Raises :class:`OSError`."""
    target = unique_path(directory / name)
    # Hidden and not *.hl7, so the engine's poll pattern cannot pick up the half-written temp.
    tmp = target.with_name(f".{target.name}.part")
    tmp.write_bytes(data)
    os.replace(tmp, target)
    return target


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
