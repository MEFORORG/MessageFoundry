# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 added item 4: ``supervise`` writes a keyless-start AUDIT line of its own.

Each engine shard's ``serve`` writes its own keyless-start record to its own handlers. The
supervisor's pair renewal opens the store keyless in its own process, so when the at-rest opt-out
lets the fleet start with no store key, the supervisor records that too, once, through
``_start_logging``'s queue. Like every queued start line it is a decision-time record, written on
a refused or raised start as well (BACKLOG #5390's reviewed not-a-bug).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from tests.test_b5391_serve_audit_after_logging import _SECURE, SAMPLES_CONFIG, _recorded

_KEYLESS_WARN = 'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n'
_FLEET_KEYLESS = "AUDIT: starting the fleet keyless"


def _supervise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, key: bool
) -> tuple[int, list[tuple[str, bool]]]:
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(_KEYLESS_WARN + _SECURE, encoding="utf-8")
    return _recorded(["supervise", "--config", str(SAMPLES_CONFIG), "--env", "staging"], [])


def _stop_at_the_renewal(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """Stand the pair renewal in with a clean refusal, so nothing is minted or spawned. It runs
    after ``_start_logging`` has written its queue, so reaching it is the positive control for an
    absence check."""
    from messagefoundry.restricted_file import RestrictedFileError

    reached: list[bool] = []

    def _refuse(*_a: object, **_k: object) -> str:
        reached.append(True)
        raise RestrictedFileError("synthetic renewal refusal")

    monkeypatch.setattr(cli, "_renew_api_tls_before_spawning", _refuse)
    return reached


def _fleet_keyless(seen: list[tuple[str, bool]]) -> list[str]:
    return [message for message, _ in seen if message.startswith(_FLEET_KEYLESS)]


def test_supervise_writes_its_own_keyless_audit_line_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached = _stop_at_the_renewal(monkeypatch)
    rc, seen = _supervise(tmp_path, monkeypatch, key=False)
    assert rc == 2
    assert reached == [True]
    (line,) = _fleet_keyless(seen)
    assert "because [security].allow_unencrypted_phi=true" in line
    assert "UNENCRYPTED at rest" in line


def test_supervise_with_a_store_key_writes_no_keyless_audit_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control: a keyed fleet start has no such record, though it got as far as the renewal.
    reached = _stop_at_the_renewal(monkeypatch)
    rc, seen = _supervise(tmp_path, monkeypatch, key=True)
    assert rc == 2
    assert reached == [True]
    assert [message for message, _ in seen if "keyless" in message] == []


def test_a_raise_in_supervise_still_writes_its_keyless_audit_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Queued before the guarded span, so a raise in it writes the line on its way out, once.
    def boom(*_a: object, **_k: object) -> str:
        raise RuntimeError("spool directory evaluation failed")

    monkeypatch.setattr(cli, "_supervisor_forward_spool_dir", boom)
    rc, seen = _supervise(tmp_path, monkeypatch, key=False)
    assert rc != 0
    assert len(_fleet_keyless(seen)) == 1


def test_serve_and_supervise_share_the_keyless_line_text() -> None:
    serve_line = cli._keyless_start_audit_line(
        "[security].allow_unencrypted_phi=true", env_name="prod", production=True, enforcing=True
    )
    assert serve_line.startswith("AUDIT: starting keyless on a production PHI instance")
    assert "+ [security].allow_unencrypted_phi_under_strict_enforcement=true" in serve_line
    fleet_line = cli._keyless_start_audit_line(
        "[security].allow_unencrypted_phi=true",
        env_name="staging",
        production=False,
        enforcing=False,
        what="starting the fleet keyless",
    )
    assert fleet_line.startswith(f"{_FLEET_KEYLESS} on a PHI instance")
    assert "strict_enforcement" not in fleet_line
