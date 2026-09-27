# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Silence the third-party loggers that write raw HL7 field values, stdlib only (BACKLOG #1596).

``parsing/__init__.py`` calls :func:`silence_phi_prone_dependency_loggers` on import, so a CLI or
embedded path that never runs ``configure_logging()`` is covered too (review finding C-1). It used to
import the function from ``logging_setup``, which loaded ``config.tls_policy``, ``redaction``,
``secretscrub`` and ``logging_guard`` behind it. That pulled the configuration layer into a package a
client may import (CLAUDE.md section 4). The function lives here now and imports only ``logging`` and
``os``; ``logging_setup`` re-exports it and still calls it from ``configure_logging()``.
"""

from __future__ import annotations

import logging
import os

__all__ = ["silence_phi_prone_dependency_loggers"]


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
