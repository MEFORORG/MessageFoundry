# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5390 (its last limb) and #5391 added items 2 and 4: the start AUDIT records on a
refused start, and the supervisor's own keyless-start record.

A start refused, or stopped by a raise, before ``configure`` returns still writes the AUDIT lines it
had queued, as the old decision-time log call did, but each now says it was not applied: the lines
are worded as a posture the start took ("starting keyless"), and a refused start took none. A
start that passes writes them unqualified. ``supervise`` writes a keyless-start line of its own
when the at-rest opt-out lets the fleet start with no store key.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from tests.test_b5391_serve_audit_after_logging import (
    _SECURE,
    SAMPLES_CONFIG,
    _recorded,
    _serve,
)

_NOT_APPLIED = cli._START_AUDIT_NOT_APPLIED


def _lines(seen: list[tuple[str, bool]], needle: str) -> list[str]:
    return [message for message, _ in seen if message.startswith("AUDIT: ") and needle in message]


def test_the_not_applied_note_names_the_refusal() -> None:
    assert "Not applied" in _NOT_APPLIED and "refused" in _NOT_APPLIED


def test_a_refused_write_marks_each_line_and_a_passing_one_does_not(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.__main__"):
        cli._write_start_audit(["AUDIT: one", "AUDIT: two"], refused=True)
        cli._write_start_audit(["AUDIT: three"])
    assert [r.getMessage() for r in caplog.records] == [
        f"AUDIT: one{_NOT_APPLIED}",
        f"AUDIT: two{_NOT_APPLIED}",
        "AUDIT: three",
    ]


def test_a_start_refused_in_start_logging_marks_the_egress_audit_not_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Under enforce with no collector, _start_logging refuses before configure_logging.
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = false\n" + _SECURE,
        env="prod",
        key=True,
    )
    assert rc == 2
    (line,) = _lines(seen, "block_unlisted_outbound=false")
    assert line.endswith(_NOT_APPLIED)


def test_a_posture_refusal_in_serve_marks_the_keyless_audit_not_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Keyless under the warn-mode opt-out, then production refuses DEBUG in
    # _forwarder_posture_refused: the keyless line was queued, and the start never ran keyless.
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n' + _SECURE,
        env="prod",
        key=False,
        extra=("--log-level", "DEBUG"),
    )
    assert rc == 2
    (line,) = _lines(seen, "starting keyless")
    assert line.endswith(_NOT_APPLIED)


def test_a_start_that_passes_writes_the_keyless_audit_unmarked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control for the two above: the same line on a start that goes on carries no note.
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n',
        env="staging",
        key=False,
    )
    assert rc == 0
    (line,) = _lines(seen, "starting keyless")
    assert _NOT_APPLIED not in line


def _supervise_keyless(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str
) -> tuple[int, list[tuple[str, bool]]]:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    return _recorded(["supervise", "--config", str(SAMPLES_CONFIG), "--env", "staging"], [])


_KEYLESS_WARN = 'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n'


def _supervise_to_the_renewal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, key: bool
) -> list[tuple[str, bool]]:
    """``supervise`` up to its pair renewal, which is stood in with a clean refusal, so nothing is
    minted or spawned. The renewal runs after ``_start_logging`` has written its queue, so
    reaching it is the positive control for an absence check."""
    from messagefoundry.restricted_file import RestrictedFileError

    reached: list[bool] = []

    def _refuse(*_a: object, **_k: object) -> str:
        reached.append(True)
        raise RestrictedFileError("synthetic renewal refusal")

    monkeypatch.setattr(cli, "_renew_api_tls_before_spawning", _refuse)
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(_KEYLESS_WARN + _SECURE, encoding="utf-8")
    rc, seen = _recorded(["supervise", "--config", str(SAMPLES_CONFIG), "--env", "staging"], [])
    assert rc == 2
    assert reached == [True]
    return seen


def test_supervise_writes_its_own_keyless_audit_line_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #5391 item 4: the opt-out lets the fleet start keyless, and the supervisor's own log gets the
    # record, once and unmarked, since its start had passed every gate the line records.
    (line,) = _lines(
        _supervise_to_the_renewal(tmp_path, monkeypatch, key=False), "starting the fleet keyless"
    )
    assert "[security].allow_unencrypted_phi=true" in line
    assert _NOT_APPLIED not in line


def test_supervise_with_a_store_key_writes_no_keyless_audit_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control: a keyed fleet start has no such record.
    assert _lines(_supervise_to_the_renewal(tmp_path, monkeypatch, key=True), "keyless") == []


def test_a_raise_in_supervise_marks_its_keyless_audit_not_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_a: object, **_k: object) -> str:
        raise RuntimeError("spool directory evaluation failed")

    monkeypatch.setattr(cli, "_supervisor_forward_spool_dir", boom)
    rc, seen = _supervise_keyless(tmp_path, monkeypatch, _KEYLESS_WARN + _SECURE)
    assert rc != 0
    (line,) = _lines(seen, "starting the fleet keyless")
    assert line.endswith(_NOT_APPLIED)
