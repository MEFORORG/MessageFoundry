# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The error Windows raises for a share it cannot reach, for the tests that need it."""

from __future__ import annotations


def _share_fault(winerror: int = 53) -> OSError:
    """The error Windows raises for a share it cannot reach, which Python on Windows maps to a
    ``FileNotFoundError``. POSIX ignores the code and builds a plain ``OSError``, which would
    pass on the old code, so there the same error is built by hand."""
    fault = OSError(None, "share unreachable", None, winerror)
    if not isinstance(fault, FileNotFoundError):
        fault = FileNotFoundError(2, "share unreachable")
        fault.winerror = winerror  # type: ignore[attr-defined]
    return fault
