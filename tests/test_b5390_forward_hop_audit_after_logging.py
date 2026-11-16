# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5390: the warn-mode AUDIT record for an unverified off-box forwarding hop is logged by
``_start_logging`` only once its ``configure`` has installed the handlers and the forwarder.

Logged before it, the record missed ``[logging].file`` and the collector, and was logged even when
a later gate in ``_start_logging`` refused the start. The stderr warning is still printed where
the hop is decided, so a refused start names it.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.config.settings import ServiceSettings, load_settings
from messagefoundry.logging_setup import SyslogForward

_HOST = "10.0.0.9"


def _settings() -> ServiceSettings:
    # Plaintext UDP to a non-loopback collector under enforcement = warn: the hop WARNs.
    return load_settings(
        environ={
            "MEFOR_SECURITY_ENFORCEMENT": "warn",
            "MEFOR_AI_ENVIRONMENT": "staging",
            "MEFOR_LOGGING_FORWARD_ENABLED": "true",
            "MEFOR_LOGGING_FORWARD_HOST": _HOST,
        },
        default_file=False,
    )


def _listed() -> ServiceSettings:
    settings = _settings()
    return settings.model_copy(
        update={"egress": settings.egress.model_copy(update={"allowed_syslog": [_HOST]})}
    )


class _Recorder(logging.Handler):
    def __init__(self, configured: list[SyslogForward | None]) -> None:
        super().__init__(logging.WARNING)
        self.configured = configured
        self.seen: list[tuple[str, bool]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.seen.append((record.getMessage(), bool(self.configured)))


def _start(
    settings: ServiceSettings, tmp_path: Path, *, live: bool = True
) -> tuple[int | None, list[tuple[str, bool]]]:
    configured: list[SyslogForward | None] = []

    def configure(forward: SyslogForward | None) -> bool:
        configured.append(forward)
        return live

    recorder = _Recorder(configured)
    logger = logging.getLogger("messagefoundry.__main__")
    logger.addHandler(recorder)
    try:
        # The positive control for every absence check below: the recorder sees this logger.
        logger.warning("recorder probe")
        assert recorder.seen == [("recorder probe", False)]
        recorder.seen.clear()
        rc = cli._start_logging(
            settings,
            env_name="staging",
            enforcing=False,
            spool_dir=str(tmp_path / "spool"),
            configure=configure,
            deferred_ca_refusals=[],
        )
    finally:
        logger.removeHandler(recorder)
    return rc, recorder.seen


def _hop_audit(seen: list[tuple[str, bool]]) -> list[bool]:
    return [
        after
        for message, after in seen
        if message.startswith("AUDIT: off-box log/audit forwarding")
    ]


def test_hop_audit_is_logged_once_after_configure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, seen = _start(_listed(), tmp_path)
    assert rc is None
    assert _hop_audit(seen) == [True]
    err = capsys.readouterr().err
    assert f"warning: off-box log/audit forwarding to {_HOST}:" in err
    assert f"AUDIT: off-box log/audit forwarding to {_HOST}:" in err


def test_no_hop_audit_when_no_forwarder_came_up(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # configure skipped the collector, so no record crosses the hop and none is audited for it.
    rc, seen = _start(_listed(), tmp_path, live=False)
    assert rc is None
    assert _hop_audit(seen) == []
    assert "AUDIT: off-box" not in capsys.readouterr().err


def test_a_later_refusal_logs_no_hop_audit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The collector is not in [egress].allowed_syslog, so the egress gate refuses after the hop
    # check. The hop is still warned on stderr, but no AUDIT record is logged.
    rc, seen = _start(_settings(), tmp_path)
    assert rc == 2
    err = capsys.readouterr().err
    assert f"warning: off-box log/audit forwarding to {_HOST}:" in err
    assert "allowed_syslog" in err
    assert _hop_audit(seen) == []
