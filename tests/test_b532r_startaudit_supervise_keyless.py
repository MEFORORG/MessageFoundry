# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 added item 4: ``supervise`` writes a keyless-start AUDIT line of its own.

Each engine shard's ``serve`` writes its own keyless-start record to its own handlers. The
supervisor's pair renewal opens the store keyless in its own process, so when the at-rest opt-out
lets the fleet through with no store key, the supervisor records that too, once, through
``_start_logging``'s queue, so after its handlers and forwarder are installed. Like every queued
start line it is a decision-time record, written on a refused or raised start as well (BACKLOG
#5390's reviewed not-a-bug).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.logging_setup import configure_logging
from tests.test_b5391_serve_audit_after_logging import _SECURE, SAMPLES_CONFIG, _recorded, _serve

_KEYLESS_WARN = 'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n'
_OPT_OUT = "[security].allow_unencrypted_phi=true"
_FLEET_LINE = cli._keyless_start_audit_line(
    _OPT_OUT,
    env_name="staging",
    production=False,
    enforcing=False,
    what="the at-rest opt-out accepts a keyless fleet start",
)


def _supervise(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, key: bool
) -> tuple[int, list[tuple[str, bool]]]:
    """``supervise`` with each record marked by whether ``_start_logging``'s ``configure_logging``
    call, the one that is handed the forwarder, had run. The bare call at the top of supervise
    passes no ``forward`` and does not count."""
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(_KEYLESS_WARN + _SECURE, encoding="utf-8")
    configured: list[bool] = []

    def configure(*args: object, **kwargs: object) -> bool:
        live = configure_logging(*args, **kwargs)  # type: ignore[arg-type]
        if "forward" in kwargs:
            configured.append(True)
        return live

    monkeypatch.setattr(cli, "configure_logging", configure)
    argv = ["supervise", "--config", str(SAMPLES_CONFIG), "--env", "staging"]
    return _recorded(argv, configured)


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


def _keyless(seen: list[tuple[str, bool]]) -> list[tuple[str, bool]]:
    return [(m, after) for m, after in seen if m.startswith("AUDIT:") and "keyless" in m]


def test_supervise_writes_its_own_keyless_audit_line_once_after_configure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reached = _stop_at_the_renewal(monkeypatch)
    rc, seen = _supervise(tmp_path, monkeypatch, key=False)
    assert rc == 2
    assert reached == [True]
    assert _keyless(seen) == [(_FLEET_LINE, True)]


def test_supervise_with_a_store_key_writes_no_keyless_audit_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control: a keyed fleet start has no such record, though it got as far as the renewal.
    reached = _stop_at_the_renewal(monkeypatch)
    rc, seen = _supervise(tmp_path, monkeypatch, key=True)
    assert rc == 2
    assert reached == [True]
    assert _keyless(seen) == []


def test_a_raise_in_supervise_still_writes_its_keyless_audit_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Queued before the guarded span, so a raise in it writes the line on its way out, once,
    # to the handlers the process has then.
    def boom(*_a: object, **_k: object) -> str:
        raise RuntimeError("spool directory evaluation failed")

    monkeypatch.setattr(cli, "_supervisor_forward_spool_dir", boom)
    rc, seen = _supervise(tmp_path, monkeypatch, key=False)
    assert rc != 0
    assert _keyless(seen) == [(_FLEET_LINE, False)]


def test_serve_writes_the_shared_keyless_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # serve's line comes from the same helper, so the two records share one text.
    rc, seen = _serve(tmp_path, monkeypatch, _KEYLESS_WARN, env="staging", key=False)
    assert rc == 0
    serve_line = cli._keyless_start_audit_line(
        _OPT_OUT, env_name="staging", production=False, enforcing=False
    )
    assert serve_line.startswith("AUDIT: starting keyless on a PHI instance")
    assert _keyless(seen) == [(serve_line, True)]
