# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Off-box audit tee — the single PHI-redaction path shared by every store backend (sec-offbox-log).

Each store backend (SQLite, Postgres, SQL Server) calls :func:`emit_audit_tee` immediately after a
``record_audit`` row is durably committed, so a **PHI-safe metadata** copy of the audit record is
shipped off-box via the ``messagefoundry.audit`` logger — which propagates to the root stdout +
optional syslog/SIEM forwarder configured by :mod:`messagefoundry.logging_setup`. So the audit trail
survives a host/DB compromise (ASVS 16.x).

One helper means there is exactly **one** place the off-box PHI-redaction guarantee lives, identical
across all three backends — not three copies that could drift.
"""

from __future__ import annotations

import json
import logging

from messagefoundry.redaction import safe_text

__all__ = ["audit_logger", "emit_audit_tee"]

log = logging.getLogger(__name__)

# Pinned to INFO so audit evidence forwards regardless of the deployment's general log level: the
# logging_setup root handlers are NOTSET, so a record's only level gate is this logger's own level.
# It propagates to those root handlers, so no logging_setup change is needed to reach the forwarder.
audit_logger = logging.getLogger("messagefoundry.audit")
audit_logger.setLevel(logging.INFO)


def emit_audit_tee(
    *,
    action: str,
    actor: str | None,
    channel_id: str | None,
    detail: str | None,
    ts: float,
) -> None:
    """Tee a just-persisted ``audit_log`` record off-box as PHI-safe metadata (sec-offbox-log, ASVS
    16.x). Emits actor / action / channel / timestamp plus a **redacted** ``detail`` to the
    ``messagefoundry.audit`` logger.

    **Never emits a raw message body.** ``detail`` can embed raw HL7 fragments from an exception
    message (it is a cipher column at rest for exactly that reason), so it is run through
    :func:`~messagefoundry.redaction.safe_text` — which scrubs HL7-shaped spans and bounds length —
    before it leaves the process. The handler-level ``RedactionFilter`` re-scrubs as a backstop, but
    redacting here keeps the off-box guarantee independent of handler config and **identical across
    every backend**.

    Best-effort: a logging failure must never fail the audit write (already committed), so it is
    caught and logged, not raised. Callers invoke this **after commit** and **outside any write
    lock/transaction**, so a synchronous syslog send can't block the event loop under a lock."""
    record = {
        "event": "audit",
        "ts": ts,
        "action": action,
        "actor": actor,
        "channel_id": channel_id,
        # PHI chokepoint: redact HL7-shaped content + bound length before it ships off-box.
        "detail": safe_text(detail) if detail else None,
    }
    try:
        audit_logger.info(json.dumps(record, ensure_ascii=False))
    except Exception:  # noqa: BLE001 — the audit row is durable; the off-box tee is best-effort
        log.warning("off-box audit tee failed for action=%s", action, exc_info=True)
