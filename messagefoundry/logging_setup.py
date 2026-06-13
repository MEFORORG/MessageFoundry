"""Process-wide logging setup for the engine service.

Stdlib ``logging`` only: a single stdout stream handler with a timestamped format,
with uvicorn's own loggers routed through the same handler. When the engine runs under
NSSM as a Windows service, NSSM captures stdout/stderr to rotating files, so we
deliberately do **not** add file handlers here. Richer structured logging
(structlog + PHI redaction) is a later item.
"""

from __future__ import annotations

import logging
import os
import sys
import time

__all__ = [
    "configure_logging",
    "silence_phi_prone_dependency_loggers",
    "ControlCharScrubFilter",
    "LOG_LEVELS",
]

# Timestamps in UTC with a trailing 'Z' so log correlation across hosts/timezones is unambiguous
# (ASVS 16.2.2); the handler's formatter converter is set to time.gmtime below.
_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

#: Accepted ``--log-level`` values (used for argparse choices too).
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Logger names uvicorn configures itself; we route them through the root handler.
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")

# C0 control characters (and DEL) escaped to keep one log record on one line. CR/LF are the
# log-injection vector; tab (0x09) is left intact as benign whitespace.
_CTRL_TRANSLATION: dict[int, str] = {0x0A: "\\n", 0x0D: "\\r"}
for _i in range(0x20):
    if _i not in (0x09, 0x0A, 0x0D):
        _CTRL_TRANSLATION[_i] = f"\\x{_i:02x}"
_CTRL_TRANSLATION[0x7F] = "\\x7f"


class ControlCharScrubFilter(logging.Filter):
    """Neutralize CR/LF and other control characters in the rendered log message to prevent log
    injection / forging (ASVS 16.4.1).

    Untrusted MLLP peer data and HL7-derived exception text reach the general log; without this a
    crafted value containing a newline could inject a forged log line into NSSM's captured stdout.
    We render the message (applying ``%`` args) once, escape any control characters, and only then
    replace ``record.msg`` — clean messages keep their lazy ``msg``/``args`` untouched."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        scrubbed = message.translate(_CTRL_TRANSLATION)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


def _resolve_level(level: str) -> int:
    resolved = logging.getLevelName(level.upper())
    if not isinstance(resolved, int):
        raise ValueError(f"unknown log level: {level!r}")
    return resolved


def configure_logging(level: str = "INFO") -> None:
    """Install a single stdout handler on the root logger and route uvicorn through it.

    Idempotent: replaces any handlers a previous call installed, so it is safe to call
    from tests as well as the CLI. Pair with ``uvicorn.run(..., log_config=None)`` so
    uvicorn's loggers propagate to this handler instead of installing their own.
    """
    numeric = _resolve_level(level)

    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)
    formatter.converter = time.gmtime  # emit UTC timestamps (16.2.2)
    handler.setFormatter(formatter)
    handler.addFilter(ControlCharScrubFilter())  # log-injection defense (16.4.1)

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric)

    # Let uvicorn's loggers flow to the root handler (one shared format/stream).
    for name in _UVICORN_LOGGERS:
        uvicorn_logger = logging.getLogger(name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True
        uvicorn_logger.setLevel(numeric)

    silence_phi_prone_dependency_loggers()


def silence_phi_prone_dependency_loggers() -> None:
    """Silence third-party loggers that emit raw HL7 field values (PHI) into the general log.

    ``python-hl7`` (0.4.5) logs the **whole field** at ERROR on benign-but-unmapped escape sequences
    (``hl7/util.py`` ``unescape``: ``"Error decoding value [%s], field [%s]…"``; also a full segment
    line at ``util.py:64``) — a PHI leak hit on every message via :func:`~messagefoundry.parsing.summary.summarize`,
    landing in NSSM's captured stdout/stderr and violating the "never log full bodies at INFO+" rule
    (review finding C-1). Those loggers are named by module ``__file__`` (``getLogger(__file__)``), so
    ``logging.getLogger("hl7")`` does **not** reach them — we match by the package directory instead.

    We drop these records entirely (level ``CRITICAL``): they carry no operational signal the engine
    doesn't already record as an ``ERROR`` disposition with non-PHI text, and they are PHI by
    construction. Idempotent and best-effort (a missing/renamed dependency must never break logging).
    """
    try:
        import hl7
        import hl7.containers  # noqa: F401  (registers its __file__-named logger)
        import hl7.util  # noqa: F401
    except ImportError:
        return
    pkg_dir = os.path.normcase(os.path.dirname(os.path.abspath(hl7.__file__)))
    for name in list(logging.Logger.manager.loggerDict):
        # hl7 names its loggers getLogger(__file__) → an absolute path inside the hl7 package dir.
        if os.path.normcase(name).startswith(pkg_dir):
            logging.getLogger(name).setLevel(logging.CRITICAL)
