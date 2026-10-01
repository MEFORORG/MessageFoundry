# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A spy on the calls that touch the filesystem, for tests that must prove a path was NOT touched.

``install`` wraps the calls a path resolve or an open goes through and records each one with the
path it was handed. A test then asks which recorded calls name its own marker.

Two rules keep a zero honest:

* Pair every zero with a control in the same test module: an ALLOWED path must leave at least one
  recorded call. A spy that sees nothing proves nothing, and which internal call a resolve uses
  differs by platform and by Python version.
* A path naming :data:`UNREACHABLE_HOST` is answered by the spy itself and never handed on. So a
  test may use a network-shaped path, and a failing run still reaches no network.
"""

from __future__ import annotations

import builtins
import functools
import ntpath
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

#: A host under the reserved ``.invalid`` top-level domain (RFC 6761). The spy never passes on a
#: call that names it.
UNREACHABLE_HOST = "host.invalid"

#: A network share on that host, and the device-namespace spellings, for a refused-path test. Every
#: one names ``probe``, so ``naming(calls, "probe")`` finds any call made on it.
SHARE = rf"\\{UNREACHABLE_HOST}\share\probe"
DEVICE_SHAPES = (
    r"\\?\C:\probe",
    r"\\.\pipe\probe",
    "//?/C:/probe",
    "//./pipe/probe",
    r"\/?\C:/probe",
    rf"\\?\UNC\{UNREACHABLE_HOST}\share\probe",
    r"\??\C:\probe",
)
#: The share in both separators, then every device shape: what no local root admits.
NON_LOCAL_SHAPES = (SHARE, SHARE.replace("\\", "/"), *DEVICE_SHAPES)

_TARGETS: tuple[tuple[Any, str], ...] = (
    (Path, "resolve"),
    (Path, "exists"),
    (Path, "is_dir"),
    (Path, "is_file"),
    (Path, "stat"),
    (Path, "lstat"),
    (os.path, "realpath"),
    (os.path, "exists"),
    (os.path, "isdir"),
    (os.path, "isfile"),
    (os, "stat"),
    (os, "lstat"),
    (os, "readlink"),
    (os, "scandir"),
    (os, "listdir"),
    (os, "open"),
    (builtins, "open"),
    # What the Windows resolve calls underneath. Absent elsewhere, and skipped there.
    (ntpath, "_getfinalpathname"),
)


def _subject(args: tuple[Any, ...]) -> str:
    """The path a call was handed, as text; empty when it was handed none (a file descriptor)."""
    if not args:
        return ""
    try:
        subject = os.fspath(args[0])
    except TypeError:
        return ""
    return os.fsdecode(subject)


def install(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Wrap the filesystem calls for this test and return the live list of ``(call, path)``."""
    calls: list[tuple[str, str]] = []

    def wrap(owner: Any, name: str) -> None:
        original: Callable[..., Any] | None = getattr(owner, name, None)
        if original is None:
            return
        label = f"{getattr(owner, '__name__', owner)}.{name}"

        @functools.wraps(original)
        def spy(*args: Any, **kwargs: Any) -> Any:
            subject = _subject(args)
            calls.append((label, subject))
            if UNREACHABLE_HOST in subject.lower():
                raise OSError("the filesystem spy does not pass on a call naming its test host")
            return original(*args, **kwargs)

        monkeypatch.setattr(owner, name, spy)

    for owner, name in _TARGETS:
        wrap(owner, name)
    return calls


def naming(calls: list[tuple[str, str]], marker: str) -> list[tuple[str, str]]:
    """The recorded calls whose path names ``marker``, compared without regard to case."""
    return [call for call in calls if marker.lower() in call[1].lower()]
