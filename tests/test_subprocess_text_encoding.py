# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every text-mode subprocess call in the engine and the harness names its encoding.

``text=True`` with no ``encoding=`` decodes with the locale code page on Python 3.14 and with UTF-8
on 3.15 (PEP 686). Neither matches what a Windows console tool writes when piped: ``icacls``, ``sc``
and Windows PowerShell 5.1 write the OEM code page, and measured on a stock en-US box, the cp437
byte 0x81 (u-umlaut) is undefined in BOTH cp1252 and UTF-8. On Windows the failed decode happens in
subprocess's reader thread, so ``run()`` returns ``stdout=None`` and prints a traceback; on POSIX it
raises UnicodeDecodeError from ``run()``. Neither is caught by an ``except OSError``. So the encoding
is a per-site decision, and this guard makes it one nobody can skip.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

import messagefoundry
from tests._ast_sites import callee_name, parse_source

_ROOT = Path(messagefoundry.__file__).resolve().parent.parent
_SCANNED = (_ROOT / "messagefoundry", _ROOT / "harness")
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "check_output", "call", "check_call"})
_TEXT_FLAGS = ("text", "universal_newlines")


def unencoded_text_calls(source: str) -> list[int]:
    """Line numbers of subprocess calls that ask for text mode and name no ``encoding=``.

    Matches on the attribute or bare name (``subprocess.run``, ``run``), so an aliased import is
    still seen. A ``**kwargs`` splat is skipped: its keys are not visible to a static read."""
    hits: list[int] = []
    for node in ast.walk(parse_source(source)):
        if not isinstance(node, ast.Call) or callee_name(node) not in _SUBPROCESS_FUNCS:
            continue
        kwargs = {kw.arg: kw.value for kw in node.keywords}
        if None in kwargs or "encoding" in kwargs:
            continue
        if any(getattr(kwargs.get(f), "value", None) is True for f in _TEXT_FLAGS):
            hits.append(node.lineno)
    return hits


@pytest.mark.parametrize(
    ("source", "fires"),
    [
        ("subprocess.run(['x'], capture_output=True, text=True)", True),
        ("run(['x'], universal_newlines=True)", True),
        ("subprocess.check_output(['x'], text=True)", True),
        ("subprocess.run(['x'], text=True, encoding='oem', errors='replace')", False),
        ("subprocess.run(['x'], capture_output=True)", False),
        ("subprocess.run(['x'], text=False)", False),
        ("subprocess.run(['x'], **opts)", False),
    ],
)
def test_the_detector_on_planted_sources(source: str, fires: bool) -> None:
    """Positive and negative controls, so a clean tree is a reading and not a dead needle."""
    assert bool(unencoded_text_calls(source)) is fires


def test_every_text_mode_subprocess_call_names_its_encoding() -> None:
    files = sorted(p for d in _SCANNED for p in d.rglob("*.py"))
    assert len(files) > 50, f"scanned only {len(files)} files under {_SCANNED}; the glob is wrong"
    sources = {p: p.read_text(encoding="utf-8") for p in files}
    offenders = [
        f"{p.relative_to(_ROOT).as_posix()}:{line}"
        for p, src in sources.items()
        # Substring prefilter: parsing all ~380 files costs about 2 s; only a handful hold a flag.
        if any(f"{flag}=" in src for flag in _TEXT_FLAGS)
        for line in unencoded_text_calls(src)
    ]
    assert not offenders, (
        "text-mode subprocess call with no encoding= (the default is the locale code page on 3.14 "
        "and UTF-8 on 3.15, and a Windows console tool writes neither). Name the encoding the tool "
        f"writes, with errors='replace' where only ASCII is parsed: {offenders}"
    )


@pytest.mark.skipif(os.name != "nt", reason="icacls is Windows-only")
@pytest.mark.filterwarnings("error::pytest.PytestUnhandledThreadExceptionWarning")
def test_icacls_output_for_a_non_ascii_path_decodes(tmp_path: Path) -> None:
    """The measured case end to end: icacls echoes the path in the OEM code page, and cp437 0x81
    (u-umlaut) decodes under neither cp1252 nor UTF-8. Before the explicit encoding, each call's
    reader thread died on UnicodeDecodeError. ``run()`` still returned, so the only trace is that
    thread exception, which the filter above turns into a failure."""
    from messagefoundry.store import store as store_mod

    target = tmp_path / "caf\u00e9_\u00fc.db"
    target.write_bytes(b"")
    store_mod._grant_read(target, "*S-1-5-32-545")  # BUILTIN\Users, a well-known SID
    store_mod._secure_file(target)
