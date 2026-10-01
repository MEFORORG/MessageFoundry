# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Confinement of a request-supplied filesystem path to configured roots (vault BACKLOG #2581).

Two routes take a path from a request: ``POST /config/reload`` (``config_dir``) and
``POST /dr/activate`` (``archive``). Each confines it to operator-configured roots. Resolving a path
is itself a filesystem act: it opens the path and each parent. So a check that resolves first has
already touched whatever the caller named, before the allow-list is read.

A caller therefore runs two lines, in this order, and refuses with ONE message on either:

1. :func:`lexically_within` reads the TEXT of the path. It makes no filesystem call on it, so a
   path that is not under a root as written is never opened.
2. :func:`resolves_within` resolves the path and compares again. Only a resolve can see a link
   inside a root that points out of it.

What "no filesystem call" covers. :func:`os.path.abspath` reads the process's current directory to
anchor a relative path. It opens nothing, and it never reads the path it was handed.

The first line fails closed. A second spelling of an allowed directory (a link to it, an 8.3 short
name, a different mapped drive) is refused unless it matches a root as the caller handed it to
:func:`lexical_roots`. The remedy is to name the path the way the root is configured.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path, PurePath

__all__ = ["lexical_roots", "lexically_within", "resolves_within"]

_SEPARATORS = "\\/"


def _has_device_prefix(text: str) -> bool:
    r"""Is ``text`` a Windows device-namespace or NT object path: ``\\?\``, ``\\.\`` or ``\??\``?

    Either separator counts, in any mix, since Win32 accepts both. Judged on every platform, so a
    refusal does not depend on where the engine runs. The comparison below already places such a
    path outside an ordinary root; this makes the refusal hold however a root is spelled."""
    if len(text) < 3 or text[0] not in _SEPARATORS:
        return False
    win32_device = text[1] in _SEPARATORS and text[2] in "?."
    if not (win32_device or text[1:3] == "??"):
        return False
    return len(text) == 3 or text[3] in _SEPARATORS


def _lexical(path: str | os.PathLike[str]) -> PurePath:
    """``path`` made absolute, with ``.`` and ``..`` collapsed and case folded where the platform
    folds it. No filesystem call is made on ``path``."""
    return PurePath(os.path.normcase(os.path.abspath(os.fspath(path))))


def lexical_roots(roots: Iterable[str | os.PathLike[str]]) -> tuple[PurePath, ...]:
    """The comparison form of each configured root.

    Pass a root both as configured and as resolved when the two can differ (a link, a mapped
    drive), so a request may use either spelling."""
    return tuple(_lexical(root) for root in roots)


def lexically_within(candidate: str | os.PathLike[str], roots: Iterable[PurePath]) -> bool:
    """The first line: is ``candidate`` at or under one of ``roots``, judged from its text alone?

    ``roots`` come from :func:`lexical_roots`. A device-namespace path is never within a root. A
    UNC path is within a root only when that root is itself the same share, so the host is always
    one the operator configured. Makes no filesystem call on ``candidate``."""
    text = os.fspath(candidate)
    if _has_device_prefix(text):
        return False
    lexical = _lexical(text)
    return any(lexical.is_relative_to(root) for root in roots)


def resolves_within(candidate: str | os.PathLike[str], roots: Iterable[Path]) -> Path | None:
    """The second line: ``candidate`` resolved, if that lands at or under one of ``roots``.

    ``roots`` are already resolved. Returns ``None`` when the resolved path is outside every root.
    This touches the filesystem, so call it only after :func:`lexically_within` has passed, and off
    the event loop."""
    path = Path(candidate).resolve()
    return path if any(path == root or root in path.parents for root in roots) else None
