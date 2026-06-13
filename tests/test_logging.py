"""Tests for logging setup and the serve ``--log-level`` flag."""

from __future__ import annotations

import logging
from typing import Any, Iterator

import pytest

from messagefoundry import __main__
from messagefoundry.logging_setup import configure_logging


@pytest.fixture(autouse=True)
def _restore_root_logger() -> Iterator[None]:
    """configure_logging mutates the global root logger; snapshot and restore it."""
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    try:
        yield
    finally:
        for handler in root.handlers[:]:
            root.removeHandler(handler)
        for handler in saved_handlers:
            root.addHandler(handler)
        root.setLevel(saved_level)


# --- configure_logging -------------------------------------------------------


def test_installs_single_stdout_handler() -> None:
    configure_logging("INFO")
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0], logging.StreamHandler)
    assert root.level == logging.INFO


def test_level_is_case_insensitive() -> None:
    configure_logging("debug")
    assert logging.getLogger().level == logging.DEBUG


def test_idempotent_does_not_stack_handlers() -> None:
    configure_logging("INFO")
    configure_logging("WARNING")
    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert root.level == logging.WARNING


def test_unknown_level_raises() -> None:
    with pytest.raises(ValueError):
        configure_logging("LOUD")


def test_routes_uvicorn_loggers_to_root() -> None:
    configure_logging("INFO")
    uvicorn_logger = logging.getLogger("uvicorn.error")
    assert uvicorn_logger.handlers == []
    assert uvicorn_logger.propagate is True


# --- serve --log-level -------------------------------------------------------


# --- C-1: python-hl7 PHI-to-log suppression ----------------------------------


def test_silences_hl7_value_loggers_phi_leak() -> None:
    import hl7
    import hl7.containers  # noqa: F401  (so hl7.containers.__file__ resolves)
    import hl7.util  # noqa: F401

    from messagefoundry.logging_setup import silence_phi_prone_dependency_loggers

    util_logger = logging.getLogger(hl7.util.__file__)
    containers_logger = logging.getLogger(hl7.containers.__file__)
    # Reset to permissive so this proves the silencer, not parsing-import's side effect.
    util_logger.setLevel(logging.NOTSET)
    containers_logger.setLevel(logging.NOTSET)

    silence_phi_prone_dependency_loggers()
    assert util_logger.level == logging.CRITICAL
    assert containers_logger.level == logging.CRITICAL

    # Behavior: an unmapped escape makes python-hl7's unescape() log the WHOLE field at ERROR; with
    # the loggers silenced, no such record (and no PHI) reaches a handler.
    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    root = logging.getLogger()
    handler = _Capture(logging.DEBUG)
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        msg = hl7.parse(
            "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\rPID|1||MRN123||DOE\\Z9\\JANE\r"
        )
        msg.unescape("DOE\\Z9\\JANE")  # → "Error decoding value [Z9], field [DOE\\Z9\\JANE]…"
    finally:
        root.removeHandler(handler)

    leaked = [r for r in captured if "DOE" in r.getMessage() or "JANE" in r.getMessage()]
    assert leaked == [], f"python-hl7 leaked PHI to logs: {[r.getMessage() for r in leaked]}"


# --- serve --log-level -------------------------------------------------------


def test_serve_rejects_unknown_log_level() -> None:
    # argparse choices -> SystemExit(2) before any work happens.
    with pytest.raises(SystemExit):
        __main__.main(["serve", "--log-level", "LOUD"])


def test_serve_applies_log_level(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    import uvicorn

    captured: dict[str, Any] = {}

    # serve imports these lazily, so patch them at the source (looked up at call time).
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kw))

    rc = __main__.main(
        [
            "serve",
            "--config",
            str(tmp_path),
            "--db",
            str(tmp_path / "x.db"),
            "--log-level",
            "DEBUG",
        ]
    )

    assert rc == 0
    assert logging.getLogger().level == logging.DEBUG
    # uvicorn must defer to our root handler, not install its own.
    assert captured["log_config"] is None
