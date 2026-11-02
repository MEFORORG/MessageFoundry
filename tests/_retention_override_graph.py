# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A two-connection graph with a retention override on either side (vault BACKLOG #2368).

Shared by ``tests/test_retention_override_gate.py``, which owns the guard's behaviour, and the doc
guards in ``tests/test_security_doc_drift.py``, which the docs-only CI leg runs. It is its own file
so that leg never imports the first of those, and what that one imports.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path

from messagefoundry.config.retention_classification import make_retention_override_guard
from messagefoundry.config.wiring import Registry, load_config


def override_guard(
    log: logging.Logger, *, acknowledged: bool, enforcing: bool
) -> Callable[[Registry], None]:
    """The guard ``serve`` would build for environment ``prod``, writing to ``log``."""
    return make_retention_override_guard(
        acknowledged=acknowledged, enforcing=enforcing, env_name="prod", log=log
    )


def override_graph(cfg: Path, *, inbound_days: int | None, outbound_days: int | None) -> Registry:
    """Write and load the graph under ``cfg``. ``None`` leaves that override unset (inherit)."""
    cfg.mkdir()
    ib = "" if inbound_days is None else f", messages_days={inbound_days}"
    ob = "" if outbound_days is None else f", dead_letter_days={outbound_days}"
    (cfg / "feed.py").write_text(
        "from messagefoundry import MLLP, Send, handler, inbound, outbound, router\n"
        f"inbound('IB_FEED', MLLP(port=2611), router='r'{ib})\n"
        f"outbound('OB_FEED', MLLP(host='127.0.0.1', port=2612){ob})\n"
        "@router('r')\n"
        "def route(msg):\n"
        "    return ['h']\n"
        "@handler('h')\n"
        "def handle(msg):\n"
        "    return Send('OB_FEED', msg)\n",
        encoding="utf-8",
    )
    return load_config(cfg)
