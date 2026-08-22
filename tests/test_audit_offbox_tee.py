# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Off-box audit tee (sec-offbox-log, ASVS 16.x).

Every persisted ``audit_log`` record is also emitted as PHI-safe metadata to the
``messagefoundry.audit`` logger, which propagates to the root handlers configured by
``logging_setup`` (stdout + the optional syslog/SIEM forwarder) so the audit trail survives a
host/DB compromise. The hard guarantee under test: the off-box copy carries actor/action/channel/
timestamp + a **redacted** detail — never a raw HL7 body.

Split in two: direct unit tests of :func:`~messagefoundry.store.audit_tee.emit_audit_tee` (the ONE
shared redaction path every backend uses — so they cover Postgres/SQL Server too, which can't run
without a live DB), plus a SQLite end-to-end test that the ``record_audit`` write wires into it.
"""

from __future__ import annotations

import json
import logging

import pytest

from messagefoundry.store import MessageStore, audit_tee
from messagefoundry.store.audit_tee import emit_audit_tee


class _ListHandler(logging.Handler):
    """Capture each record's rendered message (what would be shipped) into a list."""

    def __init__(self) -> None:
        super().__init__()
        self.messages: list[str] = []
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.messages.append(record.getMessage())


@pytest.fixture
async def store():
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


@pytest.fixture
def audit_capture():
    handler = _ListHandler()
    logger = logging.getLogger("messagefoundry.audit")
    logger.addHandler(handler)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)


def _only(handler: _ListHandler) -> dict:
    assert len(handler.messages) == 1, handler.messages
    return json.loads(handler.messages[0])


async def test_record_audit_tees_metadata_off_box(store, audit_capture) -> None:
    await store.record_audit(
        "auth.login",
        actor="alice",
        channel_id="IB_ACME_ADT",
        detail=None,
        client="10.4.2.9",
        now=123.0,
    )
    rec = _only(audit_capture)
    assert rec == {
        "event": "audit",
        "ts": 123.0,
        "action": "auth.login",
        "actor": "alice",
        "channel_id": "IB_ACME_ADT",
        "client": "10.4.2.9",  # ADR 0150: the recorded address travels off-box with the row
        "detail": None,
    }
    assert audit_capture.records[0].levelno == logging.INFO


async def test_audit_tee_redacts_hl7_in_detail(store, audit_capture) -> None:
    # detail can embed a raw HL7 fragment from an exception message — it MUST be scrubbed before it
    # ships off-box (the whole point of the guardrail).
    phi = "PID|1||123456^^^HOSP^MR||DOE^JANE^Q||19800101|F"
    await store.record_audit("message.error", actor="svc", detail=phi, now=1.0)

    line = audit_capture.messages[0]
    assert "DOE" not in line and "JANE" not in line and "123456" not in line
    assert "[redacted]" in line
    # The segment ID itself is non-PHI and is kept (useful for triage); only the field data is cut.
    assert json.loads(line)["detail"].startswith("PID|[redacted]")


async def test_audit_tee_keeps_non_phi_metadata_detail_readable(store, audit_capture) -> None:
    detail = json.dumps({"permission": "messages:view_raw", "path": "/messages/abc/raw"})
    await store.record_audit("auth.permission_denied", actor="bob", detail=detail, now=2.0)
    assert json.loads(audit_capture.messages[0])["detail"] == detail  # no HL7 shapes → unchanged


async def test_audit_logger_is_pinned_info_and_propagates() -> None:
    # Pinned to INFO so audit evidence forwards regardless of the deployment's general log level, and
    # propagates so it reaches the root-attached syslog/SIEM forwarder (sec-offbox-log).
    assert audit_tee.audit_logger.level == logging.INFO
    assert audit_tee.audit_logger.propagate is True


async def test_audit_tee_is_best_effort_and_never_fails_the_write(
    store, audit_capture, monkeypatch
) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("forwarder exploded")

    monkeypatch.setattr(audit_tee.audit_logger, "info", boom)
    # Must not raise even though the tee fails — the audit row is the durable record.
    await store.record_audit("auth.login", actor="carol", now=5.0)

    rows = await store.list_audit()
    assert [r["action"] for r in rows] == ["auth.login"]


async def test_audit_row_persists_and_tee_emits_together(store, audit_capture) -> None:
    await store.record_audit("admin.user_create", actor="root", detail=None, now=9.0)
    # DB row written…
    rows = await store.list_audit()
    assert [r["action"] for r in rows] == ["admin.user_create"]
    # …and the off-box copy emitted.
    assert _only(audit_capture)["action"] == "admin.user_create"


# --- the shared redaction path, tested directly (covers Postgres + SQL Server, which wire into the
# same emit_audit_tee but can't run here without a live DB) ---------------------------------------


def test_emit_audit_tee_shape_is_metadata_only(audit_capture) -> None:
    emit_audit_tee(
        action="auth.login",
        actor="alice",
        channel_id="IB_ACME_ADT",
        detail=None,
        client="10.4.2.9",
        ts=10.0,
    )
    assert _only(audit_capture) == {
        "event": "audit",
        "ts": 10.0,
        "action": "auth.login",
        "actor": "alice",
        "channel_id": "IB_ACME_ADT",
        # ADR 0150: the "from where" travels off-box as a DISCRETE field, so a SIEM can index the
        # source address without parsing the redacted detail blob. It is an infrastructure
        # identifier, not message content, so it is forwarded verbatim (never through safe_text).
        "client": "10.4.2.9",
        "detail": None,
    }
    assert audit_capture.records[0].levelno == logging.INFO


def test_emit_audit_tee_client_defaults_to_none_for_engine_internal_writes(audit_capture) -> None:
    """An engine-internal write omits ``client`` entirely; the field must ship as null, never as a
    stale address inherited from whatever request happened to run last (ADR 0150)."""
    emit_audit_tee(action="retention.purge", actor="system", channel_id=None, detail=None, ts=3.0)
    assert _only(audit_capture)["client"] is None


def test_emit_audit_tee_redacts_hl7_in_detail(audit_capture) -> None:
    emit_audit_tee(
        action="message.error",
        actor="svc",
        channel_id=None,
        detail="PID|1||123456^^^HOSP^MR||DOE^JANE^Q||19800101|F",
        ts=1.0,
    )
    line = audit_capture.messages[0]
    assert "DOE" not in line and "JANE" not in line and "123456" not in line
    assert json.loads(line)["detail"].startswith("PID|[redacted]")


def test_emit_audit_tee_redacts_bare_delimiter_run_without_segment(audit_capture) -> None:
    # A field/component dump that is PHI even without a segment header (≥2 HL7 delimiters) must also
    # be scrubbed before it ships off-box.
    emit_audit_tee(action="x", actor=None, channel_id=None, detail="DOE^JANE^M^MR", ts=1.0)
    line = audit_capture.messages[0]
    assert "DOE" not in line and "JANE" not in line
    assert "[redacted]" in line


def test_emit_audit_tee_is_best_effort_on_logging_failure(audit_capture, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("forwarder exploded")

    monkeypatch.setattr(audit_tee.audit_logger, "info", boom)
    # Must swallow the logging failure — the caller's audit row is already durable.
    emit_audit_tee(action="auth.login", actor="z", channel_id=None, detail=None, ts=1.0)


def test_tee_docstring_and_cipher_registry_agree_about_audit_log() -> None:
    """The tee's docstring makes a claim about ``audit_log.detail`` at rest; pin it to the registry.

    Until 2026-08-22 the docstring said ``detail`` "is a cipher column at rest", which was FALSE --
    ``audit_log`` appears nowhere in ``_CIPHER_COLUMNS``, while that tuple's own comment block names
    ``message_events.detail``, ``connection_event.reason`` and ``alert_instance.reason`` as covered.
    The error mattered because it made the redaction in :func:`emit_audit_tee` read as defence in
    depth over an already-sealed column, when it is the only thing standing between an HL7 fragment
    and the off-box copy.

    This guard fails in BOTH directions, which is the point: revert the docstring and it goes red;
    add ``audit_log`` to ``_CIPHER_COLUMNS`` without updating the prose and it goes red too. Coverage
    is not a one-line change -- ``audit_row_hash`` hashes the PLAINTEXT ``detail`` into the
    tamper-evident chain and key rotation rewrites every cipher column, so naive coverage breaks
    verification on the first rekey (BACKLOG #1198).
    """
    from messagefoundry.store.store import MessageStore

    covered = {table for table, _column in MessageStore._CIPHER_COLUMNS}
    doc = audit_tee.emit_audit_tee.__doc__ or ""

    # POSITIVE CONTROL: the registry must be readable and non-trivial, or an empty `covered` would
    # make the branch below pass vacuously.
    assert "messages" in covered, (
        "cipher registry unreadable or empty -- the assertion below is void"
    )

    if "audit_log" in covered:  # pragma: no cover - fires only once someone adds coverage
        assert "NOT a cipher column at rest" not in doc, (
            "audit_log is now cipher-covered but audit_tee's docstring still says it is not. "
            "Update the prose, and check audit_row_hash/rekey against the chain (BACKLOG #1198)."
        )
    else:
        assert "NOT a cipher column at rest" in doc, (
            "audit_log is NOT cipher-covered and the docstring no longer says so. It previously "
            "claimed the opposite, which hid an at-rest gap (BACKLOG #1198)."
        )
