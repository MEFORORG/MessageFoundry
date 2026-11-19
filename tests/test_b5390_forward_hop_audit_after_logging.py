# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5390: the warn-mode AUDIT record for an unverified off-box forwarding hop is logged by
``_start_logging`` once its ``configure`` has installed the handlers and the forwarder.

Logged before it, the record missed ``[logging].file`` and the collector. A start that a later
gate refuses still logs it, once, to the handlers the process has then, as the old decision-time
log call did: ``supervise``'s stdout handler, or ``serve``'s lastResort. There the line ends with
``_START_AUDIT_NOT_APPLIED``, because the refused start never took the posture it records (the
row's last limb). The stderr warning is still printed where the hop is decided.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.config.settings import ServiceSettings, SyslogProtocol, load_settings
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


_HOP_AUDIT_PREFIX = "AUDIT: off-box log/audit forwarding"


def _hop_audit(seen: list[tuple[str, bool]]) -> list[bool]:
    return [after for message, after in seen if message.startswith(_HOP_AUDIT_PREFIX)]


def test_hop_audit_is_logged_once_after_configure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, seen = _start(_listed(), tmp_path)
    assert rc is None
    assert _hop_audit(seen) == [True]
    # The record states the posture the start accepted, not that a record crossed.
    assert "crosses the network unprotected, in cleartext over UDP" in next(
        m for m, _ in seen if "AUDIT:" in m
    )
    # The control for the refused tests below: a start that goes on writes it unmarked.
    assert cli._START_AUDIT_NOT_APPLIED not in next(m for m, _ in seen if "AUDIT:" in m)
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


def test_hop_audit_reaches_the_root_handlers_when_the_logger_filters_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # [logging].level = ERROR leaves the logger disabled for WARNING. The record is still handed to
    # every handler on the way up, the root's (the configured sinks) among them, and not to stderr.
    root_seen: list[str] = []

    class _Root(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            root_seen.append(record.getMessage())

    root_handler = _Root()
    logging.getLogger().addHandler(root_handler)
    try:
        rc, seen = _start(_listed(), tmp_path, level=logging.ERROR)
    finally:
        logging.getLogger().removeHandler(root_handler)
    assert rc is None
    assert _hop_audit(seen) == [True]
    assert len([m for m in root_seen if m.startswith("AUDIT: off-box")]) == 1
    assert "AUDIT:" not in capsys.readouterr().err


def test_a_filtered_warning_on_an_empty_root_reaches_the_filtered_last_resort(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A filtered WARNING and no handler anywhere: the line goes to main()'s filtered lastResort,
    # the redaction and control-character chain on stderr, once, rather than to no sink.
    from messagefoundry.logging_setup import _FilteredLastResort

    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    monkeypatch.setattr(logging, "lastResort", _FilteredLastResort())
    logger = logging.getLogger("messagefoundry.__main__")
    previous = logger.level
    logger.setLevel(logging.ERROR)
    pending = ["AUDIT: the posture line"]
    try:
        cli._write_start_audit(pending)
    finally:
        logger.setLevel(previous)
    assert pending == []
    lines = [ln for ln in capsys.readouterr().err.splitlines() if "AUDIT: the posture line" in ln]
    assert len(lines) == 1 and "WARNING" in lines[0]


def test_a_later_refusal_still_logs_the_hop_audit_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The collector is not in [egress].allowed_syslog, so the egress gate refuses after the hop
    # check. The hop is warned on stderr, and its AUDIT record is logged once, before any configure,
    # to the handlers the process already has, as origin/main's decision-time log call wrote it.
    rc, seen = _start(_settings(), tmp_path)
    assert rc == 2
    err = capsys.readouterr().err
    assert f"warning: off-box log/audit forwarding to {_HOST}:" in err
    assert "allowed_syslog" in err
    # The handlers took it, so it is not written to stderr a second time.
    assert "AUDIT:" not in err
    assert _hop_audit(seen) == [False]
    # The record says the refused start did not take the posture (#5390 last limb).
    (line,) = [m for m, _ in seen if m.startswith(_HOP_AUDIT_PREFIX)]
    assert line.endswith(cli._START_AUDIT_NOT_APPLIED)


def test_a_supervise_refusal_after_a_warn_hop_logs_the_hop_audit(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # supervise's path (no deferred CA refusals): a refused start writes the caller's AUDIT lines
    # and then the warn-mode hop's, once each, to the handlers the process has (supervise's stdout
    # handler), as origin/main's decision-time log call wrote the hop's. The collector is unlisted,
    # so the egress gate refuses after the hop has warned.
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
    audit = [r.getMessage() for r in caplog.records if "AUDIT" in r.getMessage()]
    assert len(audit) == 2
    # A refused or failed start never took the posture, so each line says so (#5390 last limb).
    assert audit[0] == f"AUDIT: the posture line{cli._START_AUDIT_NOT_APPLIED}"
    assert audit[1].startswith(_HOP_AUDIT_PREFIX)
    assert audit[1].endswith(cli._START_AUDIT_NOT_APPLIED)


def test_a_raise_out_of_configure_still_logs_the_pending_audit(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # An exception _start_logging does not catch, such as a ValueError from the forwarder's TLS
    # context, still writes the caller's AUDIT lines on its way out, then the hop line, once each.
    def configure(forward: object) -> bool:
        raise ValueError("synthetic configure failure")

    pending = ["AUDIT: the posture line"]
    with caplog.at_level(logging.WARNING, logger="messagefoundry.__main__"):
        assert_capture_sees(caplog, "messagefoundry.__main__")
        with pytest.raises(ValueError, match="synthetic configure failure"):
            cli._start_logging(
                _listed(),
                env_name="staging",
                enforcing=False,
                spool_dir=str(tmp_path / "spool"),
                configure=configure,
                deferred_ca_refusals=[],
                pending_audit=pending,
            )
    assert pending == []
    audit = [r.getMessage() for r in caplog.records if "AUDIT" in r.getMessage()]
    assert len(audit) == 2
    # A refused or failed start never took the posture, so each line says so (#5390 last limb).
    assert audit[0] == f"AUDIT: the posture line{cli._START_AUDIT_NOT_APPLIED}"
    assert audit[1].startswith(_HOP_AUDIT_PREFIX)
    assert audit[1].endswith(cli._START_AUDIT_NOT_APPLIED)


def test_a_refusal_on_an_empty_root_reaches_stderr_through_the_filtered_last_resort(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # serve's real shape before configure_logging: no handler anywhere, and main()'s filtered
    # lastResort. A refused start's AUDIT line reaches stderr through it, once.
    from messagefoundry.logging_setup import _FilteredLastResort

    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    monkeypatch.setattr(logging, "lastResort", _FilteredLastResort())

    def configure(forward: object) -> bool:
        raise AssertionError("configure must not run on a refused start")

    rc = cli._start_logging(
        _settings(),
        env_name="staging",
        enforcing=False,
        spool_dir=str(tmp_path / "spool"),
        configure=configure,
        deferred_ca_refusals=[],
        pending_audit=["AUDIT: the posture line"],
    )
    assert rc == 2
    err = capsys.readouterr().err.splitlines()
    assert len([line for line in err if "AUDIT: the posture line" in line]) == 1
    # serve's lastResort is where origin/main's decision-time call wrote the hop's record too.
    assert len([line for line in err if _HOP_AUDIT_PREFIX in line]) == 1


def _with_protocol(protocol: SyslogProtocol, *, verify: bool = True) -> ServiceSettings:
    settings = _listed()
    return settings.model_copy(
        update={
            "logging": settings.logging.model_copy(
                update={"forward_protocol": protocol, "forward_tls_verify": verify}
            )
        }
    )


@pytest.mark.parametrize(
    ("protocol", "verify", "how"),
    [
        (SyslogProtocol.UDP, True, "unprotected, in cleartext over UDP with no connection needed."),
        (SyslogProtocol.TCP, True, "unprotected, in cleartext over TCP."),
        (
            SyslogProtocol.TLS,
            False,
            "encrypted, but to a collector whose certificate is not verified",
        ),
    ],
)
def test_hop_audit_names_how_each_protocol_crosses(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    protocol: SyslogProtocol,
    verify: bool,
    how: str,
) -> None:
    # WARN is reached for plaintext udp and tcp and for tls with verification off; the AUDIT line
    # and the stderr warning name the transport this start accepted, not always UDP.
    rc, seen = _start(_with_protocol(protocol, verify=verify), tmp_path)
    assert rc is None
    (audit,) = [m for m, _ in seen if m.startswith(_HOP_AUDIT_PREFIX)]
    assert how in audit
    assert how in capsys.readouterr().err
    if protocol is not SyslogProtocol.UDP:
        # The control: the UDP clause is not carried onto a hop that is not UDP.
        assert "UDP" not in audit
        assert "no connection needed" not in audit


def test_a_deferred_collector_ca_refusal_still_logs_the_hop_audit_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # serve's path: a refused collector CA turns forwarding off and hands the refusal to the
    # audited preflight. The hop's AUDIT record is still written once, after configure, as
    # origin/main's decision-time log call had written it.
    from messagefoundry.auth import trust_anchors

    sentinel = trust_anchors.TrustAnchorError("synthetic CA refusal")
    monkeypatch.setattr(trust_anchors, "log_forward_anchor_spec", lambda _logging: object())
    monkeypatch.setattr(trust_anchors, "anchor_refusal", lambda *_a, **_k: sentinel)
    configured: list[SyslogForward | None] = []
    deferred: list[trust_anchors.TrustAnchorError] = []

    def configure(forward: SyslogForward | None) -> bool:
        configured.append(forward)
        return False

    recorder = _Recorder(configured)
    logger = logging.getLogger("messagefoundry.__main__")
    logger.addHandler(recorder)
    try:
        rc = cli._start_logging(
            _listed(),
            env_name="staging",
            enforcing=False,
            spool_dir=str(tmp_path / "spool"),
            configure=configure,
            deferred_ca_refusals=deferred,
        )
    finally:
        logger.removeHandler(recorder)
    assert rc is None
    assert deferred == [sentinel]
    assert configured == [None]
    assert _hop_audit(recorder.seen) == [True]


def test_a_stderr_write_that_raises_still_logs_the_hop_audit(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The hop's AUDIT record is queued before its stderr warning, so a failing stderr cannot
    # lose it: the guard writes it on the way out of the raise.
    class _Broken:
        def write(self, _text: str) -> int:
            raise OSError("synthetic stderr failure")

        def flush(self) -> None:
            pass

    monkeypatch.setattr("sys.stderr", _Broken())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.__main__"):
        assert_capture_sees(caplog, "messagefoundry.__main__")
        with pytest.raises(OSError, match="synthetic stderr failure"):
            cli._start_logging(
                _listed(),
                env_name="staging",
                enforcing=False,
                spool_dir=str(tmp_path / "spool"),
                configure=lambda forward: True,
                deferred_ca_refusals=[],
            )
    audit = [r.getMessage() for r in caplog.records if r.getMessage().startswith(_HOP_AUDIT_PREFIX)]
    assert len(audit) == 1
