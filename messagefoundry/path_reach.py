# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whether a ``FileNotFoundError`` says nothing is at a path, or that the path could not be
reached. A leaf: it imports only the standard library, so ``config/``, the uploads store and any
other engine package can share the one answer (BACKLOG #5388 added item 3)."""

from __future__ import annotations

from typing import Final

#: The Windows errors that say a network path or share cannot be reached, so nothing is known about
#: what is there: ERROR_BAD_NETPATH (53) and ERROR_BAD_NET_NAME (67). Python maps both to ENOENT, so
#: each arrives as a ``FileNotFoundError``. ERROR_PATH_NOT_FOUND (3) and ERROR_INVALID_DRIVE (15) map
#: the same way and stay absence, so a drive letter this process does not have reads as missing,
#: even where it is mapped in another session.
UNREACHABLE_WINERRORS: Final = frozenset({53, 67})


def is_unreachable(exc: OSError) -> bool:
    """Whether ``exc`` is a Windows error saying the path's share or network path could not be
    reached (:data:`UNREACHABLE_WINERRORS`)."""
    winerror = getattr(exc, "winerror", None)
    return isinstance(winerror, int) and winerror in UNREACHABLE_WINERRORS


def is_absent(exc: OSError) -> bool:
    """Whether ``exc`` says nothing is at the path, as against saying the path cannot be reached."""
    return isinstance(exc, FileNotFoundError) and not is_unreachable(exc)
