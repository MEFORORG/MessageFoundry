# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Off-box audit tee — the single PHI-redaction path shared by every store backend (sec-offbox-log).

Each store backend's ``record_audit`` (``SqliteStore``, ``PostgresStore``, ``SqlServerStore``) calls
:func:`emit_audit_tee` immediately after the row is durably committed, so a **PHI-safe metadata** copy
of the audit record is shipped off-box via the ``messagefoundry.audit`` logger — which propagates to
the root stdout + optional syslog/SIEM forwarder configured by :mod:`messagefoundry.logging_setup`.
So the audit trail survives a host/DB compromise (ASVS 16.x).

One helper means there is exactly **one** place the off-box PHI-redaction guarantee lives, identical
across all three backends — not three copies that could drift.

**Propagation is only half the guarantee.** A record reaches that forwarder only if the process
installed a handler for it to propagate to, which is a property of the *process*, not of this module
— so :func:`~messagefoundry.logging_setup.ensure_logger_sink` supplies one when nothing else has
(BACKLOG #1199; that function states the defect, and this file does not restate it). The copy still
only reaches an operator and whatever the service manager captures: nothing here transmits off the
host, and the durable off-box forwarder remains unbuilt.
"""

from __future__ import annotations

import json
import logging

from messagefoundry.logging_setup import ensure_logger_sink
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
    client: str | None = None,
) -> None:
    """Tee a just-persisted ``audit_log`` record off-box as PHI-safe metadata (sec-offbox-log, ASVS
    16.x). Emits actor / action / channel / client address / timestamp plus a **redacted** ``detail``
    to the ``messagefoundry.audit`` logger.

    ``client`` (ADR 0150) is the caller's network address, or ``None`` for an engine-internal write. It
    is forwarded verbatim — it is an infrastructure identifier, not message content, and the whole point
    of the off-box copy is that attribution survives a host/DB compromise, which it cannot do if the
    "from where" is dropped on the way out. It is emitted as a discrete field (never folded into
    ``detail``) so a SIEM can index it without parsing the redacted blob.

    **Never emits a raw message body.** ``detail`` can embed raw HL7 fragments from an exception
    message, and **it is NOT a cipher column at rest** -- `audit_log` is absent from
    ``SqliteStore._CIPHER_COLUMNS`` on every backend, while the comment block in that same tuple names
    ``message_events.detail``, ``connection_event.reason`` and ``alert_instance.reason`` as covered. So
    on an encrypted store the security log's free-text column is the plaintext outlier and three lesser
    operational logs are sealed. (This docstring asserted the opposite until 2026-08-22, which made the
    redaction below look like defence in depth over an already-sealed column. It is not: it is the only
    thing standing between an HL7 fragment and the off-box copy.) Covering the column is not a one-line
    change and must not be attempted as one -- ``audit_row_hash`` hashes the PLAINTEXT ``detail`` into
    the tamper-evident chain, and key rotation rewrites every cipher column, so naive coverage would
    break chain verification on the first rekey. See BACKLOG #1198. Because of all that, ``detail`` is
    run through
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
        "client": client,
        # PHI chokepoint: redact HL7-shaped content + bound length before it ships off-box.
        "detail": safe_text(detail) if detail else None,
    }
    try:
        # Inside the guard: a sink that cannot be built must not fail the caller's audit write either.
        ensure_logger_sink(audit_logger)
        audit_logger.info(json.dumps(record, ensure_ascii=False))
    except Exception:  # noqa: BLE001 — the audit row is durable; the off-box tee is best-effort
        log.warning("off-box audit tee failed for action=%s", action, exc_info=True)
