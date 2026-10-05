# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Off-box audit tee — the single PHI-redaction path shared by every store backend (sec-offbox-log).

Each store backend's ``record_audit`` (``SqliteStore``, ``PostgresStore``, ``SqlServerStore``) calls
:func:`emit_audit_tee` immediately after the row is durably committed. So does a write that
commits an audit row in its own transaction, through ``AuditAppend.tee`` (BACKLOG #2100). At least
those paths reach it. So a **PHI-safe metadata** copy
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

#: Whether this process has logged a tee failure; see the handler in :func:`emit_audit_tee`.
_TEE_FAILURE_LOGGED = False


def emit_audit_tee(
    *,
    action: str,
    actor: str | None,
    channel_id: str | None,
    detail: str | None,
    ts: float,
    row_id: int,
    seq: int,
    row_hash: str,
    client: str | None = None,
) -> None:
    """Tee a just-persisted ``audit_log`` record off-box as PHI-safe metadata (sec-offbox-log, ASVS
    16.x). Emits actor / action / channel / client address / timestamp / chain anchor plus a
    **redacted** ``detail`` to the ``messagefoundry.audit`` logger.

    ``seq`` and ``row_hash`` are the just-committed row's sequence number and its chain hash -- the
    ANCHOR fields (BACKLOG #1198). ``seq`` is the row's position in the chain and is inside its MAC,
    so it is the SAME number ``audit-anchor`` prints and ``audit-verify`` takes: a collector's last
    ``seq`` and ``row_hash`` can be passed back as an anchor unchanged (vault BACKLOG #2594). They
    are required, not optional: an anchor that could be omitted silently would make an off-box copy
    with no anchor indistinguishable from one whose writer chose not to send it. ``row_id`` is the
    row's primary key, sent so a reader can find the row; it is not a chain coordinate, and it may
    skip numbers where ``seq`` never does. None of the three carries PHI directly or discloses a key:
    two are counters and ``row_hash`` is a digest, or on a keyed chain an HMAC.

    **One residual, stated because "the head hash carries nothing" is very slightly too strong.** In
    the keyless posture ``row_hash`` is a plain SHA-256 over a canonical list whose every other
    member -- the previous row's hash, ``ts``, ``actor``, ``action``, ``channel_id``, ``client`` --
    travels in this same record or the one before it. So for a record whose ``detail`` ``safe_text``
    actually cut, a reader of the log can TEST guesses at the removed span offline, one hash per guess
    (``seq`` travels in the record too).
    That is narrow (it needs an exact byte-for-byte reconstruction of a redacted exception string, and
    an audit ``detail`` that was not HL7-shaped is forwarded unredacted anyway, so there is nothing left
    to guess). It does not arise for a row written by a process that holds a key, where the digest is
    an HMAC under a DEK-derived subkey or a Transit MAC. Keyless is not the shipped default. A row
    written without a key keeps its plain SHA-256: no later open re-keys it, and a keyed process
    reports it as a break. The "Audit chain" row in ``docs/ASVS-L2-PHASE0-CHANGES.md`` says when a
    chain is keyed. It is recorded here rather than left for a reader to rediscover.

    **What the anchor fields do and do not buy, stated here so nobody over-reads them.** A within-store
    chain walk cannot see TAIL truncation -- deleting the newest rows leaves a prefix that still
    verifies -- so an off-box record of ``(seq, row_hash)`` is the witness that the chain once
    reached that length with that head. That witness is only as good as the hop it travels. The default
    forwarder is lossy by
    :func:`~messagefoundry.logging_setup.configure_logging`'s own account: UDP is fire-and-forget; a
    TCP or TLS collector unreachable at startup is skipped for the process lifetime when the on-disk
    spool is off, and deferred when it is on; and even with the spool, delivery is best effort, not at
    least once (ADR 0200: a peer reset can lose a record, a restart can resend one). Over that transport a gap in the collector's copy is
    AMBIGUOUS (dropped in flight, or truncated in the store) and a forged anchor line is injectable, so
    these fields close tail truncation only over an authenticated, gap-detecting hop. Do not describe
    them as making the audit log unmodifiable.

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

    **The record survives the scrub, and the scrub is what makes it so.** A failed sign-in sets
    ``actor`` to the typed name, so a client chooses its characters. ``ControlCharScrubFilter``
    runs last on every configured handler, and since vault BACKLOG #3012 every escape it writes is
    valid inside a JSON string (``controlchars._log_escape``). So this serializes with plain
    ``json.dumps`` and leaves every character raw for the filters. Escaping here instead, BEFORE the
    redaction and credential filters, hid a name or a password from them: an escape such as
    ``\\u007f`` ends in a word character, so ``\\b``-anchored patterns no longer matched the next
    word. ``ensure_ascii=True`` is the same mistake, for every non-ASCII character.

    **At least one residual is separate from this.** The redaction and credential filters rewrite
    spans of this document, and a span can take a closing quote with it. An ASCII ``actor`` of
    ``a%7Cb%7Cc`` breaks the JSON.

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
        # Anchor fields (BACKLOG #1198): the row's position in the chain and its head hash. Discrete
        # fields so a SIEM can index them without parsing the redacted blob. See the docstring for
        # what they close and what the default transport leaves open.
        "row_id": row_id,
        "seq": seq,
        "row_hash": row_hash,
        # PHI chokepoint: redact HL7-shaped content + bound length before it ships off-box.
        "detail": safe_text(detail) if detail else None,
    }
    try:
        # Inside the guard: a sink that cannot be built must not fail the caller's audit write either.
        ensure_logger_sink(audit_logger)
        # Not ensure_ascii, and no escaping here: see "The record survives the scrub" above.
        audit_logger.info(json.dumps(record, ensure_ascii=False))
    except Exception:  # noqa: BLE001 — the audit row is durable; the off-box tee is best-effort
        # Once per process, and never naming the row (BACKLOG #1131). A line per failed row named
        # its action, and its COUNT tracked the rows, the hidden lock rows included; ``GET
        # /logs/tail`` serves this log to ``logs:view``, which the Operator holds without
        # ``users:manage``. The first failure is what an operator needs: the sink is broken, and
        # every row is still in the store's ``audit_log``.
        global _TEE_FAILURE_LOGGED
        if not _TEE_FAILURE_LOGGED:
            _TEE_FAILURE_LOGGED = True
            log.warning(
                "off-box audit tee failed; the rows are still in the audit_log table, and further "
                "tee failures in this process are not logged",
                exc_info=True,
            )
