# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Whether a ``FileNotFoundError`` says nothing is at a path, or that the path could not be
reached. A leaf: it imports only the standard library, so ``config/``, the uploads store and any
other engine package can share the one answer (BACKLOG #5388 added item 3)."""

from __future__ import annotations

import errno
from typing import Final

#: The Windows errors that say a network path or share cannot be reached, so nothing is known about
#: what is there: ERROR_BAD_NETPATH (53) and ERROR_BAD_NET_NAME (67). Python maps both to ENOENT, so
#: each arrives as a ``FileNotFoundError``. ERROR_PATH_NOT_FOUND (3) and ERROR_INVALID_DRIVE (15) map
#: the same way and stay absence, so a drive letter this process does not have reads as missing,
#: even where it is mapped in another session.
UNREACHABLE_WINERRORS: Final = frozenset({53, 67})

#: Windows errors that say a share or the network went away under an open path, which CPython
#: raises with other errnos, at least EINVAL: ERROR_REM_NOT_LIST (51), ERROR_UNEXP_NET_ERR (59),
#: ERROR_NETNAME_DELETED (64), ERROR_NO_NETWORK (1222), ERROR_NETWORK_UNREACHABLE (1231) and
#: ERROR_HOST_UNREACHABLE (1232), as winerror.h names them (BACKLOG #5388 added item 3).
NETWORK_LOSS_WINERRORS: Final = frozenset({51, 59, 64, 1222, 1231, 1232})

#: POSIX errnos that say the same of a network filesystem: at least a stale NFS handle (ESTALE), a
#: host that is down (EHOSTDOWN) and a network that is down or unreachable (ENETDOWN,
#: ENETUNREACH). EIO is not one: it is a device fault too, and stays an error.
NETWORK_LOSS_ERRNOS: Final = frozenset(
    code
    for code in (
        getattr(errno, name, None) for name in ("ESTALE", "EHOSTDOWN", "ENETDOWN", "ENETUNREACH")
    )
    if code is not None
)


def is_unreachable(exc: OSError) -> bool:
    """Whether ``exc`` says the path's share, network path or network could not be reached
    (:data:`UNREACHABLE_WINERRORS`, :data:`NETWORK_LOSS_WINERRORS`, :data:`NETWORK_LOSS_ERRNOS`),
    so nothing is known about what is there."""
    winerror = getattr(exc, "winerror", None)
    if isinstance(winerror, int):
        return winerror in UNREACHABLE_WINERRORS or winerror in NETWORK_LOSS_WINERRORS
    return exc.errno in NETWORK_LOSS_ERRNOS


def is_absent(exc: OSError) -> bool:
    """Whether ``exc`` says nothing is at the path, as against saying the path cannot be reached."""
    return isinstance(exc, FileNotFoundError) and not is_unreachable(exc)


def is_name_absent(exc: OSError) -> bool:
    """:func:`is_absent`, narrowed for a caller that deletes on the answer: the parent directory
    answered and holds no such name. On Windows only ERROR_FILE_NOT_FOUND (2) says that, so a
    missing parent (3) or drive (15) is not absence here. POSIX has one ENOENT for both, so there
    this cannot tell a missing name from a missing parent."""
    return isinstance(exc, FileNotFoundError) and getattr(exc, "winerror", None) in (None, 2)
