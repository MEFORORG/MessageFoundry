# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Confinement of a request-supplied filesystem path to configured roots (vault BACKLOG #2581).

Two routes take a path from a request: ``POST /config/reload`` (``config_dir``) and
``POST /dr/activate`` (``archive``). Each confines it to operator-configured roots. Resolving a path
is itself a filesystem act: it opens the path and each parent. So a check that resolves first has
already touched whatever the caller named, before the allow-list is read.

:func:`confine` therefore runs two lines, in this order:

1. The TEXT of the path (:func:`lexically_within`). No filesystem call is made on it, so a path
   that is not under a root as written is refused without being opened.
2. The resolve, and the comparison again. Only a resolve can see a link inside a root that points
   out of it. A path refused here HAS been resolved.

A caller answers either refusal with ONE message, so the two cannot be told apart from outside.

What "no filesystem call" covers. :func:`os.path.abspath` reads the process's current directory to
anchor a relative path. It opens nothing, and it never reads the path it was handed.

The first line fails closed. A second spelling of an allowed directory (a link to it, an 8.3 short
name, a different mapped drive) is refused unless it matches a root as the caller handed it to
:func:`lexical_roots`. The remedy is to name the path the way the root is configured.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path, PurePath

__all__ = ["confine", "lexical_roots", "lexically_within"]

log = logging.getLogger(__name__)

_SEPARATORS = "\\/"


def _is_nt_object_path(text: str) -> bool:
    r"""Does ``text`` open with the NT object prefix ``\??\``, in either separator?

    This is the one spelling the comparison below cannot judge. Read as text it is an ordinary
    rooted path on the current drive. Opened, Windows takes what follows the prefix as the real
    path. So the text and the open would disagree about where it points, and it is refused on
    every platform. The Win32 device forms ``\\?\`` and ``\\.\`` need no rule of their own: each
    parses as its own drive, so one is under a root only when that root is spelled the same way."""
    return (
        len(text) >= 3
        and text[0] in _SEPARATORS
        and text[1:3] == "??"
        and (len(text) == 3 or text[3] in _SEPARATORS)
    )


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

    ``roots`` come from :func:`lexical_roots`. A network share or a device-namespace path is
    within a root only when that root is itself spelled that way, so the host or device is always
    one the operator configured. Makes no filesystem call on ``candidate``."""
    text = os.fspath(candidate)
    if _is_nt_object_path(text):
        return False
    lexical = _lexical(text)
    return any(lexical.is_relative_to(root) for root in roots)


def confine(
    candidate: str | os.PathLike[str],
    *,
    lexical: Iterable[PurePath],
    resolved: Iterable[Path],
    what: str,
) -> Path | None:
    """``candidate`` resolved, if both lines place it at or under a root; ``None`` if either refuses.

    ``lexical`` are the roots from :func:`lexical_roots` and ``resolved`` the same roots resolved.
    ``what`` names the request in the server-side log line, which is the only place a refusal says
    which line refused and, for the second, where the path really led. The second line touches the
    filesystem, so call this off the event loop."""
    text = os.fspath(candidate)
    if not lexically_within(text, lexical):
        log.warning("refused %s %r: outside the configured roots as written", what, text)
        return None
    path = Path(text).resolve()
    if not any(path.is_relative_to(root) for root in resolved):
        log.warning(
            "refused %s %r: it resolves to %s, outside the configured roots", what, text, path
        )
        return None
    return path
