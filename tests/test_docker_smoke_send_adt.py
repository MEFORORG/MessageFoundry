# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The container smoke sender passes only on MSA-1 exactly AA or CA (BACKLOG #5303).

``docker/smoke/send_adt.py`` is copied into the smoke image and run by the CI docker smoke step,
so its exit code is the gate. A prefix test on 'A' would have passed a negative AE or AR
acknowledgement and refused a valid CA commit accept.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.parsing.peek import Peek

_SCRIPT = Path(__file__).resolve().parents[1] / "docker" / "smoke" / "send_adt.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("docker_smoke_send_adt", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


send_adt = _load()


def test_the_sender_reads_the_ack_through_the_engines_peek() -> None:
    """The script parses the ACK with the engine's own Peek, so this stays an engine test: the
    direct import above is what the tooling partition reads (tests/test_tooling_partition.py)."""
    assert send_adt.Peek is Peek


def _ack(msa: str) -> str:
    return f"MSH|^~\\&|MEFOR|MEFOR|SMOKE_APP|SMOKE_FAC|20260101000000||ACK^A01|A1|P|2.5.1\r{msa}\r"


@pytest.mark.parametrize("code", ["AA", "CA"])
def test_positive_codes_pass(code: str) -> None:
    assert send_adt.ack_exit_code(_ack(f"MSA|{code}|SMOKE0001")) == 0


@pytest.mark.parametrize("code", ["AE", "AR", "CE", "CR", "A", "AAX", "aa", " AA", ""])
def test_every_other_code_fails(code: str) -> None:
    assert send_adt.ack_exit_code(_ack(f"MSA|{code}|SMOKE0001")) == 1


def test_missing_msa_segment_fails(capsys: pytest.CaptureFixture[str]) -> None:
    ack = "MSH|^~\\&|MEFOR|MEFOR|SMOKE_APP|SMOKE_FAC|20260101000000||ACK^A01|A1|P|2.5.1\r"
    assert send_adt.ack_exit_code(ack) == 1
    assert "no MSA-1 in ACK" in capsys.readouterr().err


def test_unparseable_ack_fails() -> None:
    assert send_adt.ack_exit_code("MSA|AA|SMOKE0001\r") == 1


def test_separators_come_from_msh() -> None:
    """MSA-1 is read with the ACK's own field separator and tolerates CRLF terminators."""
    msh = "MSH#^~\\&#MEFOR#MEFOR#SMOKE_APP#SMOKE_FAC#20260101000000##ACK^A01#A1#P#2.5.1\r\n"
    assert send_adt.ack_exit_code(msh + "MSA#AA#SMOKE0001\r\n") == 0
    assert send_adt.ack_exit_code(msh + "MSA#AE#SMOKE0001\r\n") == 1


@pytest.mark.parametrize(("code", "expected"), [("AA", 0), ("CA", 0), ("AE", 1), ("AR", 1)])
def test_main_exit_code_follows_msa1(
    code: str, expected: int, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Drive ``main`` end to end with the socket send replaced, so the exit code the CI step reads
    is what is pinned, not only the helper."""

    async def _fake_send(host: str, port: int, payload: str, timeout: float) -> bytes:
        return _ack(f"MSA|{code}|SMOKE0001").encode("utf-8")

    monkeypatch.setattr(send_adt, "_send", _fake_send)
    monkeypatch.setattr(send_adt.sys, "argv", ["send_adt.py", "127.0.0.1", "2575"])
    assert send_adt.main() == expected
    said = capsys.readouterr().err
    assert ("is not AA or CA" in said) is (expected == 1)
