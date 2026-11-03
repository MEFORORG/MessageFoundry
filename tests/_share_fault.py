# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The error Windows raises for a share it cannot reach, and a real folder that cannot be listed,
for the tests that need them."""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

#: A share no test machine serves. Measured on Windows (Python 3.14): listing it raises error 67,
#: ``Path.is_dir`` answers ``False``, and ``Path.glob`` answers ``[]`` with nothing raised.
UNREACHABLE_SHARE = Path(r"\\127.0.0.1\nosuchshare\cfg")


def _share_fault(winerror: int = 53) -> OSError:
    """The error Windows raises for a share it cannot reach, which Python on Windows maps to a
    ``FileNotFoundError``. POSIX ignores the code and builds a plain ``OSError``, which would
    pass on the old code, so there the same error is built by hand."""
    fault = OSError(None, "share unreachable", None, winerror)
    if not isinstance(fault, FileNotFoundError):
        fault = FileNotFoundError(2, "share unreachable")
        fault.winerror = winerror  # type: ignore[attr-defined]
    return fault


@contextmanager
def unlistable_dir(tmp_path: Path) -> Iterator[Path]:
    """A real folder this process cannot list, with no patched call between it and the test: the
    unreachable share on Windows, and a mode-000 directory holding a module on POSIX, which
    ``Path.is_dir`` still answers ``True`` for. ``Path.glob`` answers ``[]`` for both (vault
    BACKLOG #5117). Skipped where root would list the directory anyway, and where this host's
    redirector answers the share with an error other than the two that say it cannot be reached,
    since the path then proves nothing."""
    if sys.platform == "win32":
        try:
            os.scandir(UNREACHABLE_SHARE).close()
        except OSError as exc:
            if getattr(exc, "winerror", None) not in (53, 67):
                pytest.skip(f"this host answers {exc!r}")
        else:
            pytest.skip("this host lists the share")
        yield UNREACHABLE_SHARE
        return
    if os.geteuid() == 0:
        pytest.skip("root lists a mode-000 directory")
    folder = tmp_path / "cfg"
    folder.mkdir()
    (folder / "graph.py").write_text("X = 1\n", encoding="utf-8")
    folder.chmod(0)
    try:
        yield folder
    finally:
        folder.chmod(0o700)  # so the tmp_path cleanup can remove it
