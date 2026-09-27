# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""tray.log carries the PHI, credential and control-character chain (BACKLOG #2092).

Every planted value below is synthetic. The control test clears the filter from the same handler
and logs the same record, which is what ``tray.log`` held before this change.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.tray import __main__ as tray_main
from messagefoundry.tray.logscrub import TrayLogScrubFilter
from tests.test_dependency_boundaries import _TRAY_FORBIDDEN

# Synthetic only. Each needle is a value the chain must remove, and each is unique to this file.
_PATIENT_ID = "SYNPID48213"
_PATIENT_NAME = "SYNTHLAST^SYNTHFIRST"
_HL7 = (
    "MSH|^~\\&|SYNAPP|SYNFAC|RCV|RCV|20260927120000||ADT^A01|SYNCTL001|P|2.5\r"
    f"PID|1||{_PATIENT_ID}^^^SYNHOSP||{_PATIENT_NAME}||19700101|F"
)
_SECRET = "SynthClientSecret7731"
_DSN_PASSWORD = "dsn-needle-dsn-needle"
_FORGED = "FORGED-RECORD-9931"

_NEEDLES = (_PATIENT_ID, _PATIENT_NAME, _SECRET, _DSN_PASSWORD)


class _EngineReplyError(RuntimeError):
    """Stands in for an exception whose text quotes an engine reply or a connection string."""


def _raise_planted() -> None:
    try:
        raise ValueError(f"engine replied with {_HL7}")
    except ValueError as inner:
        raise _EngineReplyError(
            f"client_secret={_SECRET} postgres://svc:{_DSN_PASSWORD}@db.example/mefor"
            f"\r\n{_FORGED} INFO messagefoundry.tray: all clear"
        ) from inner


@pytest.fixture
def tray_log(tmp_path: Path) -> Iterator[tuple[Path, logging.Handler]]:
    """Run the real ``_setup_logging`` and hand back ``tray.log`` and the handler it installed."""
    root = logging.getLogger()
    before = list(root.handlers)
    levels = {name: logging.getLogger(name).level for name in ("", "httpx", "httpcore")}
    tray_main._setup_logging(tmp_path)
    added = [h for h in root.handlers if h not in before]
    assert len(added) == 1, added
    try:
        yield tmp_path / "tray.log", added[0]
    finally:
        root.removeHandler(added[0])
        added[0].close()
        for name, level in levels.items():
            logging.getLogger(name).setLevel(level)


def _log_planted(handler: logging.Handler) -> None:
    # Straight to the tray's handler, not through a logger. A record dispatched through root
    # also reaches any filtered handler an earlier test left there, and that handler rewrites the
    # shared record in place first, which made the control below pass or fail by test order.
    handler.handle(
        _record("tray status poll raised: %s", (f"reply {_HL7} secret={_SECRET}",), with_exc=True)
    )
    handler.flush()


def test_tray_log_scrubs_a_planted_exception(tray_log: tuple[Path, logging.Handler]) -> None:
    path, handler = tray_log
    assert any(isinstance(f, TrayLogScrubFilter) for f in handler.filters)
    _log_planted(handler)
    text = path.read_text(encoding="utf-8")

    for needle in _NEEDLES:
        assert needle not in text, needle
    # The line survives as a diagnostic: the operational text and the exception type are kept.
    assert "tray status poll raised" in text
    assert "_EngineReplyError" in text
    # The CR LF in the exception did not start a new line. Every traceback line is indented, so
    # the forged record text sits inside a continuation line, never at column 0.
    assert _FORGED in text
    assert not any(line.startswith(_FORGED) for line in text.splitlines())
    assert "\n    | Traceback (most recent call last):" in text


def test_the_same_record_leaks_without_the_filter(tray_log: tuple[Path, logging.Handler]) -> None:
    # The control. The same handler with its filter removed is what tray.log was before #2092,
    # and the same record then writes every needle and a forged line at column 0.
    path, handler = tray_log
    handler.filters.clear()
    _log_planted(handler)
    text = path.read_text(encoding="utf-8")

    for needle in _NEEDLES:
        assert needle in text, needle
    assert any(line.startswith(_FORGED) for line in text.splitlines())


def _engine_chain() -> list[logging.Filter]:
    from messagefoundry import logging_setup

    handler = logging.NullHandler()
    logging_setup._install_phi_filters(handler)
    return [f for f in handler.filters if isinstance(f, logging.Filter)]


def test_the_engine_chain_is_still_the_one_this_filter_stands_in_for() -> None:
    # The drift alarm, the same shape as the log write guard's (BACKLOG #1591). The tray cannot
    # import logging_setup, so it composes the leaves itself. A filter added to the engine chain
    # and not here would otherwise pass silently.
    installed = [type(f).__name__ for f in _engine_chain()]
    accounted = [
        "RedactionFilter",  # redact_untrusted, after the traceback is rendered
        "CredentialQueryScrubFilter",  # carve-out: see the tray.logscrub docstring
        "CredentialScrubFilter",  # scrub_credentials
        "ControlCharScrubFilter",  # scrub_control_chars, last
    ]
    assert installed == accounted, (
        f"the engine's handler filter chain has moved: {installed}. messagefoundry.tray.logscrub "
        "composes that chain for tray.log, so update it (or its carve-out) to match"
    )


def _record(
    msg: str, args: tuple[object, ...], *, with_exc: bool, stack: str | None = None
) -> logging.LogRecord:
    exc_info = None
    if with_exc:
        try:
            _raise_planted()
        except _EngineReplyError:
            exc_info = sys.exc_info()
    record = logging.LogRecord(
        "messagefoundry.tray.poller", logging.ERROR, __file__, 1, msg, args, exc_info
    )
    record.stack_info = stack
    return record


@pytest.mark.parametrize(
    ("msg", "args", "with_exc", "stack"),
    [
        ("tray status poll raised: %s", (f"reply {_HL7}",), True, None),
        ("secret=%s bearer %s", (_SECRET, "SynthBearerTok8812"), False, None),
        ("line one\r\n%s", (_FORGED,), False, None),
        (
            "engine certificate %s changed",
            ("C:\\ProgramData\\MessageFoundry\\api.pem",),
            False,
            None,
        ),
        ("plain operational line", (), True, None),
        ("with a stack", (), False, f"Stack (most recent call last):\n  {_HL7}\r\n{_FORGED}"),
    ],
)
def test_the_tray_filter_writes_what_the_engine_chain_writes(
    msg: str, args: tuple[object, ...], with_exc: bool, stack: str | None
) -> None:
    # Same record in, same fields out. None of these inputs carries a URL query credential, the
    # one filter the tray leaves out, so any difference here is drift in the composition.
    engine = _record(msg, args, with_exc=with_exc, stack=stack)
    for f in _engine_chain():
        f.filter(engine)
    tray = _record(msg, args, with_exc=with_exc, stack=stack)
    TrayLogScrubFilter().filter(tray)

    assert tray.getMessage() == engine.getMessage()
    assert tray.exc_text == engine.exc_text
    assert tray.stack_info == engine.stack_info
    assert tray.exc_info is None
    assert engine.exc_info is None


@pytest.mark.parametrize(
    "line",
    [
        "MessageFoundry tray 0.1.0 starting (python 3.14.0)",
        "another tray instance is already running; exiting",
        "engine_url=https://127.0.0.1:8765 service=MessageFoundry monitor_only=False",
        "Console not opened: engine_url in tray.toml is not a plain http or https URL with a host",
        "Service log not opened: log_path must name an existing .log or .txt file",
        "tray status poll raised; publishing UNKNOWN for this tick",
        "branded launcher ready: C:\\mefor\\.venv\\Scripts\\MessageFoundryTray.exe",
    ],
)
def test_the_trays_own_lines_pass_unchanged(line: str) -> None:
    # Over-redaction is the other failure: an operator line the redactor eats is lost evidence.
    record = logging.LogRecord("messagefoundry.tray", logging.INFO, __file__, 1, line, (), None)
    TrayLogScrubFilter().filter(record)
    assert record.getMessage() == line


def test_the_tray_entrypoint_adds_no_engine_logging_or_config_import() -> None:
    # ADR 0113 section 1 keeps the tray off engine config. logging_setup imports config, so the
    # scrub reaches only the stdlib leaves. The shared boundary probe loads tray.app, never
    # __main__, so this checks the entrypoint in a fresh interpreter of its own.
    code = (
        "import json, sys\n"
        "import messagefoundry.tray.__main__\n"
        "print('MEFOR-TRAY-MAIN:' + json.dumps(sorted(sys.modules)))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=300
    )
    assert result.returncode == 0, result.stderr
    marked = [ln for ln in result.stdout.splitlines() if ln.startswith("MEFOR-TRAY-MAIN:")]
    assert len(marked) == 1, result.stdout
    loaded = set(json.loads(marked[0].removeprefix("MEFOR-TRAY-MAIN:")))
    assert "messagefoundry.tray.logscrub" in loaded
    for leaf in (
        "messagefoundry.redaction",
        "messagefoundry.secretscrub",
        "messagefoundry.controlchars",
    ):
        assert leaf in loaded, leaf
    # The shared probe's absence list, plus logging_setup, matched the same way: exact or dotted.
    banned = ("messagefoundry.logging_setup", *_TRAY_FORBIDDEN)
    forbidden = {m for m in loaded for b in banned if m == b or m.startswith(b + ".")}
    assert forbidden == set(), sorted(forbidden)


class _RaisingRepr:
    def __repr__(self) -> str:
        raise RuntimeError(f"repr failed near {_SECRET}")


@pytest.mark.parametrize(
    ("msg", "args"),
    [("two %s %s", ("one",)), ("%r", (_RaisingRepr(),))],
)
def test_a_record_that_cannot_render_is_dropped_not_raised(
    msg: str, args: tuple[object, ...]
) -> None:
    # logging does not guard Handler.filter, so a raise here would reach the call site and could
    # end the poller thread. The filter fails closed to a fixed line instead.
    record = _record(msg, args, with_exc=True)
    assert TrayLogScrubFilter().filter(record) is True
    assert record.getMessage().startswith("[tray log record dropped: ")
    assert record.exc_text is None
    assert record.exc_info is None
    assert _SECRET not in record.getMessage()


def test_setup_holds_httpx_request_lines_back(tray_log: tuple[Path, logging.Handler]) -> None:
    # httpx logs each request URL at INFO. The query-string carve-out depends on these staying out.
    path, handler = tray_log
    logging.getLogger("httpx").info("HTTP Request: GET https://127.0.0.1:8765/health?state=abc")
    handler.flush()
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert "HTTP Request" not in path.read_text(encoding="utf-8")
