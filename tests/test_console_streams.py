# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runtime half of the cp1252 console gate (BACKLOG #1875).

``tests/test_cp1252_console_safety.py`` reads SOURCE. A path an operator types is not source, so no
walk there can prove a runtime value survives the console. This module does: it drives the real
``harness.reconcile`` CLI under streams built the way Windows builds a REDIRECTED stdout and stderr
(cp1252; strict on stdout, backslashreplace on stderr), feeds it values cp1252 cannot encode, and
reads the bytes back.

Each runtime test has a PAIRED control with the hardening call patched out, which must show the
failure. Without it a green here could mean only that the fake streams were never cp1252 at all.
The controls reproduce the pre-fix behaviour of ``harness/reconcile/__main__.py``: ``capture``
turned the path into backslash escapes, and ``compare`` raised UnicodeEncodeError on every run,
because its result line always carries a check or a cross mark cp1252 has no byte for.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import harness.reconcile.__main__ as reconcile_cli
import harness.reconcile.capture as capture_mod
from messagefoundry.console_streams import harden_console_streams

#: Two characters cp1252 cannot encode, built with chr() so this file stays printable on the console
#: it tests: the arrow PR 1403 scrubbed from the capture banner, and a CJK character a real Windows
#: user profile path can hold.
_ARROW = chr(0x2192)
_CJK = chr(0x6587)


class _Cp1252Console:
    """A stdout and stderr pair built the way Windows builds them when output is redirected."""

    def __init__(self) -> None:
        self._out = io.BytesIO()
        self._err = io.BytesIO()
        self.stdout = io.TextIOWrapper(self._out, encoding="cp1252", errors="strict")
        self.stderr = io.TextIOWrapper(self._err, encoding="cp1252", errors="backslashreplace")

    def read(self) -> tuple[bytes, bytes]:
        self.stdout.flush()
        self.stderr.flush()
        return self._out.getvalue(), self._err.getvalue()


@contextlib.contextmanager
def _swapped_streams(stdout: object, stderr: object) -> Iterator[None]:
    """Swap sys.stdout and sys.stderr for part of a test body, and always put them back.

    Not a fixture and not monkeypatch: pytest's own capture re-installs its streams when the call
    phase starts, which silently undoes a swap made at setup, and it restores them at teardown
    BEFORE monkeypatch would, which would leave pytest's capture stream installed afterwards.
    """
    saved = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = stdout, stderr
    try:
        yield
    finally:
        sys.stdout, sys.stderr = saved


@contextlib.contextmanager
def _cp1252_console() -> Iterator[_Cp1252Console]:
    fake = _Cp1252Console()
    with _swapped_streams(fake.stdout, fake.stderr):
        yield fake


class _NoNetworkSink:
    """Stands in for CaptureSink so `capture` prints its banner without binding a port.

    ``start`` cancels the running task, so the CLI's wait-until-Ctrl-C returns at once through the
    same CancelledError path a real Ctrl-C takes, and the closing summary prints too.
    """

    captured = 0
    unparseable = 0
    refused = 0
    bound_ports = (2800,)

    def __init__(self, *_args: Any, **_kwargs: Any) -> None:
        pass

    async def start(self) -> None:
        task = asyncio.current_task()
        assert task is not None
        task.cancel()

    async def stop(self) -> None:
        pass


def _capture_stderr(out: Path) -> bytes:
    """Run `capture` under a cp1252 console and return the bytes it wrote to stderr."""
    with _cp1252_console() as console:
        rc = reconcile_cli.main(["capture", "--port", "2800", "--out", str(out)])
        _stdout, stderr = console.read()
    assert rc == 0
    return stderr


def _compare_args(tmp_path: Path, *extra: str) -> list[str]:
    for side in ("mefor", "corepoint"):
        (tmp_path / side).mkdir()
    return [
        "compare",
        "--mefor",
        str(tmp_path / "mefor"),
        "--corepoint",
        str(tmp_path / "corepoint"),
        *extra,
    ]


def _unhardened(monkeypatch: pytest.MonkeyPatch) -> None:
    """Put the reconcile CLI back to its pre-fix state for a control."""
    monkeypatch.setattr(reconcile_cli, "harden_console_streams", lambda **_kw: None)


# --- the reconcile CLI, the file this item names ------------------------------------------------


def test_capture_echoes_a_non_cp1252_out_path_intact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(capture_mod, "CaptureSink", _NoNetworkSink)
    out = tmp_path / f"shadow {_ARROW} {_CJK}.jsonl"
    banner = _capture_stderr(out).decode("utf-8")  # the hardened stream writes UTF-8
    assert f"-> {out} (Ctrl-C to stop)" in banner
    assert "captured 0 message(s)" in banner
    assert "\\u2192" not in banner and "\\u6587" not in banner, "the path came back escaped"


def test_control_capture_corrupts_the_path_without_the_hardening(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The pre-fix behaviour, reproduced: the same run with the hardening patched out."""
    monkeypatch.setattr(capture_mod, "CaptureSink", _NoNetworkSink)
    _unhardened(monkeypatch)
    out = tmp_path / f"shadow {_ARROW} {_CJK}.jsonl"
    banner = _capture_stderr(out).decode("cp1252")  # the unhardened stream is still cp1252
    assert str(out) not in banner
    assert "\\u2192" in banner and "\\u6587" in banner


def test_compare_prints_its_report_and_a_non_cp1252_label(tmp_path: Path) -> None:
    label = f"IB_{_CJK}_ADT {_ARROW}"
    with _cp1252_console() as console:
        rc = reconcile_cli.main(_compare_args(tmp_path, "--connection", label))
        stdout, _stderr = console.read()
    assert rc == 0
    text = stdout.decode("utf-8")
    assert repr(label) in text
    assert "RESULT: CLEAN" in text


def test_control_compare_aborts_without_the_hardening(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The pre-fix behaviour: an ASCII label and empty inputs still abort, because the report's own
    result line carries a mark cp1252 cannot encode. No source scan saw it: the character lives in
    harness/reconcile/report.py and reaches print() through a variable."""
    _unhardened(monkeypatch)
    args = _compare_args(tmp_path)
    with _cp1252_console(), pytest.raises(UnicodeEncodeError):
        reconcile_cli.main(args)


# --- the chokepoint itself ------------------------------------------------------------------------


def test_default_keeps_the_codec_and_replaces_rather_than_raising() -> None:
    """The engine CLI's choice: lossy, never fatal. Its JSON output is ASCII by construction."""
    with _cp1252_console() as console:
        harden_console_streams()
        print(f"a {_ARROW} b")
        print(f"a {_ARROW} b", file=sys.stderr)
        stdout, stderr = console.read()
    # rstrip: a TextIOWrapper writes the platform newline, so Windows gives CRLF here.
    assert stdout.decode("cp1252").rstrip() == "a ? b"
    assert stderr.decode("cp1252").rstrip() == "a ? b"


def test_utf8_keeps_every_character() -> None:
    with _cp1252_console() as console:
        harden_console_streams(encoding="utf-8")
        print(f"a {_ARROW} {_CJK} b")
        stdout, _stderr = console.read()
    assert stdout.decode("utf-8").rstrip() == f"a {_ARROW} {_CJK} b"


class _Refuses:
    """A wrapper whose reconfigure raises, the way some capture wrappers do."""

    def reconfigure(self, **_kwargs: Any) -> None:
        raise ValueError("cannot reconfigure this stream")


@pytest.mark.parametrize(
    "stream", [None, io.StringIO(), _Refuses()], ids=["pythonw-none", "no-reconfigure", "refuses"]
)
def test_a_stream_it_cannot_harden_is_left_alone(stream: object) -> None:
    """Hardening must never itself crash the tool it protects."""
    with _swapped_streams(stream, stream):
        harden_console_streams(encoding="utf-8")
        assert sys.stdout is stream
