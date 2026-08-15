# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Entry point for the MessageFoundry tray: ``pythonw -m messagefoundry.tray`` (ADR 0113).

Single-instance guarded, config loaded from ``%LOCALAPPDATA%\\MessageFoundry\\tray.toml`` + the
service registry hints. Windows-only at runtime (the shell needs the notification area); a friendly
message is printed elsewhere. A top-level guard logs any crash, removes the icon, and exits nonzero
so a wedged pump never leaves a ghost icon (ADR 0113 §9/§10).
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

from messagefoundry.tray import __version__
from messagefoundry.tray.config import default_config_dir, load_config
from messagefoundry.tray.instance import SingleInstance

log = logging.getLogger("messagefoundry.tray")


def _setup_logging(config_dir: Path) -> None:
    config_dir.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        config_dir / "tray.log", maxBytes=1_000_000, backupCount=2, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
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
