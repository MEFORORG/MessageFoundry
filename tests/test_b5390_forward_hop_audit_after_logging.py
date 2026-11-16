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
from tests._log_absence import assert_capture_sees

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
    settings: ServiceSettings, tmp_path: Path, *, live: bool = True, level: int = logging.NOTSET
) -> tuple[int | None, list[tuple[str, bool]]]:
    configured: list[SyslogForward | None] = []

    def configure(forward: SyslogForward | None) -> bool:
        configured.append(forward)
        return live

    recorder = _Recorder(configured)
    logger = logging.getLogger("messagefoundry.__main__")
    logger.addHandler(recorder)
    previous = logger.level
    try:
        # The positive control for every absence check below: the recorder sees this logger.
        logger.warning("recorder probe")
        assert recorder.seen == [("recorder probe", False)]
        recorder.seen.clear()
        logger.setLevel(level)
        rc = cli._start_logging(
            settings,
            env_name="staging",
            enforcing=False,
            spool_dir=str(tmp_path / "spool"),
            configure=configure,
            deferred_ca_refusals=[],
        )
    finally:
        logger.setLevel(previous)
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
    # The record states the posture the start accepted, not that a record crossed.
    assert "would cross the network unprotected" in next(m for m, _ in seen if "AUDIT:" in m)
    err = capsys.readouterr().err
    assert f"warning: off-box log/audit forwarding to {_HOST}:" in err
    # The handlers took it, so it is not written to stderr a second time.
    assert "AUDIT:" not in err


def test_hop_audit_is_logged_when_the_collector_was_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # configure built the forwarder but skipped a collector that was down: the accepted posture is
    # still recorded, since it governs the next start as much as this one.
    rc, seen = _start(_listed(), tmp_path, live=False)
    assert rc is None
    assert _hop_audit(seen) == [True]
    assert "AUDIT:" not in capsys.readouterr().err


def test_hop_audit_reaches_stderr_through_the_filter_chain_when_warning_is_filtered(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # [logging].level = ERROR leaves the logger disabled for WARNING, so the record goes to stderr
    # once, formatted and filtered like any MessageFoundry stderr sink, rather than to no handler.
    import messagefoundry.logging_setup as logging_setup

    chained: list[logging.Handler] = []
    real = logging_setup.build_stderr_handler

    def build() -> logging.Handler:
        handler = real()
        chained.append(handler)
        return handler

    monkeypatch.setattr(cli, "build_stderr_handler", build)
    rc, seen = _start(_listed(), tmp_path, level=logging.ERROR)
    assert rc is None
    assert seen == []
    assert len(chained) == 1 and chained[0].filters
    lines = [line for line in capsys.readouterr().err.splitlines() if "AUDIT: off-box" in line]
    assert len(lines) == 1 and "WARNING" in lines[0]


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
    assert "AUDIT:" not in err
    assert _hop_audit(seen) == []


def test_a_start_logging_refusal_logs_the_pending_audit_but_not_the_hop(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # supervise's path (no deferred CA refusals): a refused start writes the caller's AUDIT lines
    # to the handlers the process has, as the decision-time log call did, and leaves out the
    # warn-mode hop's, since no record took that hop. The collector is unlisted, so the egress
    # gate refuses after the hop has warned.
    settings = _settings()
    configured: list[object] = []

    def configure(forward: object) -> bool:
        configured.append(forward)
        return True

    with caplog.at_level(logging.WARNING, logger="messagefoundry.__main__"):
        assert_capture_sees(caplog, "messagefoundry.__main__")
        rc = cli._start_logging(
            settings,
            env_name="staging",
            enforcing=False,
            spool_dir=str(tmp_path / "spool"),
            configure=configure,
            pending_audit=["AUDIT: the posture line"],
        )
    assert rc == 2
    assert configured == []
    assert [r.getMessage() for r in caplog.records if "AUDIT" in r.getMessage()] == [
        "AUDIT: the posture line"
    ]
