# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read one file another party wrote, bounded, for the harness's file receivers (ASVS 5.1.1).

The File tab's watch pane, the File sink (and the remote-file sink, which reuses its scan) and the
reconcile loader all read files the harness did not write. Each must refuse an over-cap file rather
than read it whole, and must not let the file change between the size check and the read. This is
the one reader they share, modelled on the engine's ``dryrun`` fixture reader: size from a stat
first, so an over-cap file is never opened; then the stat is repeated on the OPEN handle, so a file
swapped or grown in between is judged by what is actually being read; then a read of at most one
byte past the cap. Stdlib only, and Qt-free, so the GUI pane and the headless sinks share it.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

#: The refusal for a directory, FIFO, device or (when not followed) symlink. A FIFO reports size 0
#: and would block a plain open, which is why the handle is opened non-blocking where the OS has it.
NOT_REGULAR = "not a regular file; not read"


def _over(size: int, cap: int) -> str:
    return f"{size} bytes, over the {cap}-byte cap; not read"


def read_capped(path: Path, cap: int, *, follow_symlinks: bool = True) -> tuple[bytes, str]:
    """``(data, "")`` for a regular file of at most ``cap`` bytes, else ``(b"", reason)``.

    ``reason`` is :data:`NOT_REGULAR`, an over-cap refusal naming the size, or a refusal for a file
    that grew past ``cap`` while it was read; none quotes the file's content. Raises ``OSError`` for
    a transient failure (the file vanished, is locked, or, where the OS has ``O_NOFOLLOW``, was
    swapped for a symlink after the ``lstat`` when ``follow_symlinks`` is false), which a caller
    retries on its next scan. Windows has no ``O_NOFOLLOW``, so there the ``lstat`` is the only
    symlink check.
    """
    st = path.stat() if follow_symlinks else path.lstat()
    if not stat.S_ISREG(st.st_mode):
        return b"", NOT_REGULAR
    if st.st_size > cap:
        return b"", _over(st.st_size, cap)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if not follow_symlinks:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        fh = os.fdopen(fd, "rb")
    except OSError:
        os.close(fd)
        raise
    with fh:
        # Judge what is open, not what was stat'ed: the path may name a different file by now.
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            return b"", NOT_REGULAR
        if st.st_size > cap:
            return b"", _over(st.st_size, cap)
        # One byte past the size it reported, then top up to one past the cap only if it grew, so
        # a small file costs a small read and a growing one is caught without reading it whole.
        data = fh.read(st.st_size + 1)
        if len(data) > st.st_size:
            data += fh.read(cap + 1 - len(data))
    if len(data) > cap:
        return b"", f"grew past the {cap}-byte cap while read; not kept"
    return data, ""
