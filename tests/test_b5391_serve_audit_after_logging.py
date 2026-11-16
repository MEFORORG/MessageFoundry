# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391: ``serve`` logs its keyless and ``block_unlisted_outbound=false`` AUDIT records
once ``configure_logging`` has installed the handlers, never before.

Logged before it, a record reaches only the filtered lastResort on stderr, never ``[logging].file``,
the structured stdout handler or the off-box collector. Each test records, for every AUDIT record,
whether ``configure_logging`` had run when it was emitted.
"""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.auth.trust_anchors import TrustAnchorError
from messagefoundry.config.settings import load_settings
from messagefoundry.logging_setup import configure_logging
from tests._log_absence import assert_capture_sees

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

_SECURE = (
    "security.delete_message_bodies_after_days = 30\n"
    '[egress]\nallowed_mllp = ["10.0.0.5"]\n'
    "[retention]\ndead_letter_days = 30\n"
    '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
    'email_to = ["ops@example.org"]\n'
)


class _Recorder(logging.Handler):
    def __init__(self, configured: list[bool]) -> None:
        super().__init__(logging.WARNING)
        self.configured = configured
        self.seen: list[tuple[str, bool]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.seen.append((record.getMessage(), bool(self.configured)))


def _serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str,
    *,
    env: str,
    key: bool,
    extra: tuple[str, ...] = (),
) -> tuple[int, list[tuple[str, bool]]]:
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    configured: list[bool] = []
    real = configure_logging

    def configure(*args: object, **kwargs: object) -> bool:
        live = real(*args, **kwargs)  # type: ignore[arg-type]
        configured.append(True)
        return live

    monkeypatch.setattr("messagefoundry.__main__.configure_logging", configure)
    recorder = _Recorder(configured)
    logger = logging.getLogger("messagefoundry.__main__")
    logger.addHandler(recorder)
    try:
        # The positive control for every absence check below: the recorder sees this logger.
        logger.warning("recorder probe")
        assert recorder.seen == [("recorder probe", False)]
        recorder.seen.clear()
        rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", env, *extra])
    finally:
        logger.removeHandler(recorder)
    return rc, recorder.seen


def _audit(seen: list[tuple[str, bool]], needle: str) -> list[bool]:
    return [after for message, after in seen if message.startswith("AUDIT: ") and needle in message]


def test_keyless_audit_is_logged_after_configure_logging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n',
        env="staging",
        key=False,
    )
    assert rc == 0
    assert _audit(seen, "starting keyless") == [True]


def test_block_unlisted_outbound_audit_is_logged_after_configure_logging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.block_unlisted_outbound = false\n' + _SECURE,
        env="staging",
        key=True,
    )
    assert rc == 0
    assert _audit(seen, "block_unlisted_outbound=false") == [True]
    # The control: a start that writes no keyless opt-out has no such record.
    assert _audit(seen, "starting keyless") == []


def test_a_start_refused_before_logging_is_configured_still_logs_the_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Under enforce with no collector, _start_logging refuses before configure_logging. The
    # refusal does not lose the record: it goes to the handlers the process has then, here the
    # recorder. In a real serve no handler exists yet and it reaches main()'s filtered lastResort
    # on stderr, which test_b5390's empty-root test pins.
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = false\n" + _SECURE,
        env="prod",
        key=True,
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "block_unlisted_outbound=false on a production PHI instance" in err
    assert "must forward its logs off-box" in err
    assert _audit(seen, "block_unlisted_outbound=false") == [False]


def test_posture_helper_hands_the_audit_back_instead_of_logging_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # One body for serve and supervise: neither may see the line logged before its handlers exist.
    settings = load_settings(
        environ={
            "MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND": "false",
            "MEFOR_EGRESS_ALLOWED_MLLP": '["10.0.0.5"]',
        },
        default_file=False,
    )
    audit: list[str] = []
    with caplog.at_level(logging.WARNING, logger="messagefoundry.__main__"):
        assert_capture_sees(caplog, "messagefoundry.__main__")
        refused = cli._forwarder_posture_refused(
            settings, production=False, env_name="staging", enforcing=True, audit=audit
        )
    assert refused is False
    assert len(audit) == 1 and audit[0].startswith("AUDIT: [security].block_unlisted_outbound")
    assert not [r for r in caplog.records if "AUDIT" in r.getMessage()]


def test_keyless_audit_reaches_the_configured_handlers_when_the_level_filters_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # [logging].level = ERROR filters WARNING at the logger, so the record is handed to the
    # handlers configure_logging installed, the structured stdout one among them, once.
    rc, _seen = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n',
        env="staging",
        key=False,
        extra=("--log-level", "ERROR"),
    )
    assert rc == 0
    captured = capsys.readouterr()
    out = captured.out.splitlines()
    assert len([line for line in out if "AUDIT: starting keyless" in line]) == 1
    assert "AUDIT: starting keyless" not in captured.err


def test_a_posture_refusal_in_serve_still_logs_the_egress_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Production refuses DEBUG after the block_unlisted_outbound=false AUDIT line was decided, so
    # _forwarder_posture_refused refuses; serve still writes the line on its way out.
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        "security.block_unlisted_outbound = false\n" + _SECURE,
        env="prod",
        key=True,
        extra=("--log-level", "DEBUG"),
    )
    assert rc == 2
    assert "DEBUG" in capsys.readouterr().err
    assert _audit(seen, "block_unlisted_outbound=false") == [False]


@pytest.mark.parametrize(
    "raised",
    [
        ssl.SSLError(9, "[SSL] PEM lib" + chr(10) + "forged line"),
        TrustAnchorError("pin mismatch" + chr(10) + "forged line"),
    ],
)
def test_api_tls_context_failure_is_a_clean_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    raised: Exception,
) -> None:
    # S19-28 (#5391 item 1): bad API TLS material or a refused client-CA anchor is exit 2 with the
    # reason, not the uncaught CRITICAL floor's exit 1, and is logged as well as printed. The
    # printed reason is scrubbed, so a newline in it cannot forge a line.
    built: list[bool] = []

    def refuse(*args: object, **kwargs: object) -> ssl.SSLContext:
        built.append(True)
        raise raised

    monkeypatch.setattr("messagefoundry.api.tls.build_api_ssl_context", refuse)
    rc, seen = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"' + chr(10) + _SECURE,
        env="staging",
        key=True,
    )
    assert built == [True]
    assert rc == 2
    err = capsys.readouterr().err
    assert "error: the API TLS context was not built:" in err
    assert chr(10) + "forged line" not in err
    assert [m for m, _ in seen if "the TLS context of the API listener was not built" in m]
