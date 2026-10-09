# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Entry point for the MessageFoundry tray: ``pythonw -m messagefoundry.tray`` (ADR 0113).

Single-instance guarded, config loaded from ``%LOCALAPPDATA%\\MessageFoundry\\tray.toml`` + the
service registry hints. Windows-only at runtime (the shell needs the notification area); a friendly
message is printed elsewhere. A top-level guard logs any crash, removes the icon, and exits nonzero
so a wedged pump never leaves a ghost icon (ADR 0113 §9/§10).
"""

from __future__ import annotations

# PEP 810 (BACKLOG #2514; inert on 3.14, see tests/test_startup_import_budget.py). The first process
# returns after relaunch_branded() and never takes the mutex. logscrub stays eager on purpose: it is
# tray.log's PHI and credential filter, and the log-scrub chain is kept out of every lazy list.
__lazy_modules__ = ["messagefoundry.tray.instance"]

import logging
import logging.handlers
import sys
import time
from pathlib import Path

from messagefoundry.tray import __version__
from messagefoundry.tray.config import default_config_dir, load_config
from messagefoundry.tray.instance import SingleInstance
from messagefoundry.tray.logscrub import TrayLogScrubFilter

log = logging.getLogger("messagefoundry.tray")

# Must match messagefoundry.logging_setup._DATE_FORMAT. The literal Z is true only with gmtime.
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _setup_logging(config_dir: Path) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        config_dir / "tray.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8"
    )
    # UTC with a trailing Z, so a tray.log line sorts against the engine's log on the same clock
    # reading (BACKLOG #2349). The tray cannot import logging_setup (ADR 0113), so the format is
    # spelled here; tests/test_tray_logscrub.py fails if it stops matching the engine's.
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s", datefmt=_DATE_FORMAT
    )
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    # A handler filter, so it covers every record that reaches tray.log, tracebacks included
    # (BACKLOG #2092). See messagefoundry.tray.logscrub for why it is not the engine's chain.
    handler.addFilter(TrayLogScrubFilter())
    # httpx logs every request line, URL included, at INFO. That is one line per probe tick, which
    # would rotate tray.log's evidence out, and a request URL the scrub is not built for.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def main() -> int:
    if sys.platform != "win32":
        print("The MessageFoundry tray is Windows-only (it needs the notification area).")
        return 1

    config_dir = default_config_dir()

    # Re-exec through the branded launcher so Windows lists us as "MessageFoundry Tray", not "Python"
    # (ADR 0113 — the tray-icon list names the process's executable, not the tooltip). Done BEFORE
    # logging + the mutex so the transient parent never opens tray.log or takes the mutex — only the
    # survivor (the branded child, or this process when branding is unavailable) does. Fail-soft: if
    # branding is unavailable, or the branded child dies at once, relaunch_branded() returns False and
    # we fall through to run unbranded here.
    from messagefoundry.tray import branding

    if not branding.is_branded_process() and branding.relaunch_branded():
        return 0

    _setup_logging(config_dir)
    log.info("MessageFoundry tray %s starting (python %s)", __version__, sys.version.split()[0])

    instance = SingleInstance()
    if not instance.acquire():
        log.info("another tray instance is already running; exiting")
        return 0

    # Imported here so a non-Windows import of this module (docs tooling) doesn't pull the shell.
    from messagefoundry.tray.app import TrayApp
    from messagefoundry.tray.config import WinregReader

    try:
        config = load_config(config_dir, WinregReader())
        log.info(
            "engine_url=%s service=%s monitor_only=%s",
            config.engine_url,
            config.service_name,
            config.monitor_only,
        )
        TrayApp(config, config_dir=config_dir).run()
        return 0
    except Exception:  # top-level backstop: log, then let the shell's cleanup run on the way out
        log.exception("tray crashed")
        return 1
    finally:
        instance.release()


if __name__ == "__main__":
    raise SystemExit(main())
