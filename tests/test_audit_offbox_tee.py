# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Off-box audit tee (sec-offbox-log, ASVS 16.x).

Every persisted ``audit_log`` record is also emitted as PHI-safe metadata to the
``messagefoundry.audit`` logger, which propagates to the root handlers configured by
``logging_setup`` (stdout + the optional syslog/SIEM forwarder) so the audit trail survives a
host/DB compromise. The hard guarantee under test: the off-box copy carries actor/action/channel/
timestamp + a **redacted** detail — never a raw HL7 body.

Split in three: direct unit tests of :func:`~messagefoundry.store.audit_tee.emit_audit_tee` (the ONE
shared redaction path every backend uses — so they cover Postgres/SQL Server too, which can't run
without a live DB), a SQLite end-to-end test that the ``record_audit`` write wires into it, and the
**reachability** guards (BACKLOG #1199) that pin the record actually landing on a handler in a
subcommand process that never calls ``configure_logging``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.config.settings import ApprovalsSettings
from messagefoundry.controlchars import has_lone_surrogate
from messagefoundry.logging_setup import build_stderr_handler, configure_logging
from messagefoundry.store import MessageStore, audit_tee
from messagefoundry.store.audit_tee import emit_audit_tee
from tests._phi_gate_provisions import AT_REST_OPT_OUT_TOML
from tests.test_logging import _decoded_from_the_log

# A stand-in chain head for the direct-call cases. Shape only: a real one comes from `audit_row_hash`.
_HASH = "a" * 64


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
    cur = await store._db.execute("SELECT id, seq, row_hash FROM audit_log")
    row = await cur.fetchone()
    assert row is not None
    rec = _only(audit_capture)
    assert rec == {
        "event": "audit",
        "ts": 123.0,
        "action": "auth.login",
        "actor": "alice",
        "channel_id": "IB_ACME_ADT",
        "client": "10.4.2.9",  # ADR 0150: the recorded address travels off-box with the row
        # BACKLOG #1198 anchor fields, taken from the row that actually committed.
        "row_id": row["id"],
        # The chain coordinate: the number inside the row's MAC, and the one an anchor names.
        "seq": row["seq"],
        "row_hash": row["row_hash"],
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


async def test_tee_anchor_fields_name_the_row_that_was_actually_committed(
    store, audit_capture
) -> None:
    """BACKLOG #1198: the anchor fields must be READ BACK from the committed row, not guessed.

    An anchor whose id or hash did not match the store would be worse than none — a collector holding
    it would report a break on an untouched chain, or miss one on a truncated chain. So this compares
    each emitted record against the row the store persisted, over three appends, so an off-by-one in
    the id (or a hash taken from the previous row) cannot pass.
    """
    for i in range(3):
        await store.record_audit("act", actor="u", detail=f'{{"n":{i}}}', now=float(i))

    cur = await store._db.execute("SELECT id, seq, row_hash FROM audit_log ORDER BY seq")
    persisted = [(r["id"], r["seq"], r["row_hash"]) for r in await cur.fetchall()]
    teed = [
        (json.loads(m)["row_id"], json.loads(m)["seq"], json.loads(m)["row_hash"])
        for m in audit_capture.messages
    ]

    # POSITIVE CONTROL: an empty chain would make the comparison below pass vacuously.
    assert len(persisted) == 3, persisted
    assert teed == persisted
    assert [seq for _id, seq, _h in teed] == [1, 2, 3]  # gapless, from 1
    assert (
        len({h for _id, _seq, h in persisted}) == 3
    )  # three distinct hashes, so equality is not trivial


async def test_a_teed_record_is_an_anchor_the_verifier_takes_unchanged(
    store, audit_capture
) -> None:
    """The collector and the verifier share one coordinate (vault BACKLOG #2594): a teed record's
    ``(seq, row_hash)`` is an anchor. The second record, held off the host, still matches as a
    prefix after a third row is appended, and reports the chain once its tail is cut back past it.
    The control is the same anchor against the untouched chain."""
    for i in range(3):
        await store.record_audit("act", actor="u", detail=f'{{"n":{i}}}', now=float(i))
    second = json.loads(audit_capture.messages[1])
    anchor = (second["seq"], second["row_hash"])

    ok, message = await store.verify_audit_chain(expected_prefix=anchor)
    assert ok, message
    await store._db.execute("DELETE FROM audit_log WHERE seq >= 2")
    await store._db.commit()
    ok, message = await store.verify_audit_chain()
    assert ok, "the walk alone cannot see a cut tail"
    ok, message = await store.verify_audit_chain(expected_prefix=anchor)
    assert not ok and "truncated or rewritten" in (message or "")


async def test_a_long_listings_tee_line_keeps_the_count_the_cut_would_lose(
    store, audit_capture
) -> None:
    """Vault BACKLOG #3747: the tee bounds ``detail``, so a long ``approval.standing_shown`` row
    reaches the wire cut and is no longer JSON. Its ``count`` comes first so the cut copy still says
    how many requests the listing showed; the on-box row keeps every id. The ids hold no digit
    run, so nothing here depends on what the redaction chain does to one."""
    ids = [f"{i:02x}" + "feedface" * 3 + "abcdef" for i in range(12)]
    gate = ApprovalGate(store, ApprovalsSettings())
    await gate.record_standing_shown(ids, actor="checker", client="10.4.2.9")

    shipped = _only(audit_capture)["detail"]
    assert shipped.startswith('{"count": 12, "approval_ids": ["')
    assert "(+" in shipped  # the cut happened, or this test proves nothing
    assert [i for i in ids if i in shipped] == ids[:4]

    [row] = await store.list_audit(action="approval.standing_shown")
    on_box = json.loads(str(row["detail"]))
    assert list(on_box) == ["count", "approval_ids"]
    assert on_box == {"count": 12, "approval_ids": ids}


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
        row_id=7,
        seq=7,
        row_hash=_HASH,
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
        # BACKLOG #1198 anchor fields: the row's chain position and head hash, also discrete. A
        # counter and a digest — no PHI, no key material. Whole-dict equality is what keeps this a
        # real shape guard: a field added later must be declared here or the assertion fails.
        "row_id": 7,
        "seq": 7,
        "row_hash": _HASH,
        "detail": None,
    }
    assert audit_capture.records[0].levelno == logging.INFO


def test_emit_audit_tee_client_defaults_to_none_for_engine_internal_writes(audit_capture) -> None:
    """An engine-internal write omits ``client`` entirely; the field must ship as null, never as a
    stale address inherited from whatever request happened to run last (ADR 0150)."""
    emit_audit_tee(
        action="retention.purge",
        actor="system",
        channel_id=None,
        detail=None,
        ts=3.0,
        row_id=1,
        seq=1,
        row_hash=_HASH,
    )
    assert _only(audit_capture)["client"] is None


def test_emit_audit_tee_redacts_hl7_in_detail(audit_capture) -> None:
    emit_audit_tee(
        action="message.error",
        actor="svc",
        channel_id=None,
        detail="PID|1||123456^^^HOSP^MR||DOE^JANE^Q||19800101|F",
        ts=1.0,
        row_id=1,
        seq=1,
        row_hash=_HASH,
    )
    line = audit_capture.messages[0]
    assert "DOE" not in line and "JANE" not in line and "123456" not in line
    assert json.loads(line)["detail"].startswith("PID|[redacted]")


def test_emit_audit_tee_redacts_bare_delimiter_run_without_segment(audit_capture) -> None:
    # A field/component dump that is PHI even without a segment header (≥2 HL7 delimiters) must also
    # be scrubbed before it ships off-box.
    emit_audit_tee(
        action="x",
        actor=None,
        channel_id=None,
        detail="DOE^JANE^M^MR",
        ts=1.0,
        row_id=1,
        seq=1,
        row_hash=_HASH,
    )
    line = audit_capture.messages[0]
    assert "DOE" not in line and "JANE" not in line
    assert "[redacted]" in line


# --- the record must still be JSON after the configured handlers' filters run ---------------------
#
# Spelled with chr() so this file carries no raw control character of its own. One sample per
# class, named, beside the tee; `tests/test_logging.py`'s `_LOG_ESCAPED_CLASSES` covers more code
# points per class through the generic logger.
_LOG_ALPHABET_SAMPLES = {
    "del": chr(0x7F),
    "c1_nel": chr(0x85),
    "soft_hyphen": chr(0xAD),
    "bidi_rlo": chr(0x202E),
    "line_separator": chr(0x2028),
    "lone_surrogate": chr(0xDCFF),
    "astral_tag": chr(0xE0001),
    "astral_private_use": chr(0xF0000),
}


def _as_read_back(text: str) -> str:
    """``text`` as a collector decodes it from the tee: each character as itself, except a lone
    surrogate, which reads back as the visible six characters ``\\udcff``."""
    return "".join(_decoded_from_the_log(ord(ch)) for ch in text)


def _teed_through_configured_stdout(
    fmt: str, actor: str, detail: str, capsys
) -> tuple[str, str, dict]:
    """Emit one tee record through the stdout handler ``serve`` installs, with every filter on it.

    Returns the physical stdout line, the inner audit document as a collector receives it, and that
    document parsed. Inside ``_handlerless_process`` so the configured handler does not outlive the
    test."""
    with _handlerless_process():
        configure_logging("INFO", fmt=fmt)
        capsys.readouterr()  # drop anything configuring logging printed
        emit_audit_tee(
            action="auth.login_failed",
            actor=actor,
            channel_id=None,
            detail=detail,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "auth.login_failed" in ln]
    assert len(lines) == 1, lines
    line = lines[0]
    if fmt == "json":
        inner = json.loads(line)["message"]
    else:
        inner = line.split("messagefoundry.audit: ", 1)[1]
    return line, inner, json.loads(inner)


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("kind", sorted(_LOG_ALPHABET_SAMPLES))
def test_the_tee_parses_as_json_after_the_log_scrub(fmt: str, kind: str, capsys) -> None:
    """The handlers' control-character scrub must leave the tee's document valid JSON.

    Until vault BACKLOG #3012 it spelled part of the log alphabet as ``\\x7f`` or ``\\U000e0001``,
    which is not JSON, so a DEL, C1, soft hyphen or astral code point in a typed sign-in name would
    have left a collector unable to parse the record. Each character must now come back from
    ``json.loads`` as it went in, and a lone surrogate as visible text, never as an unpaired
    ``\\udcff`` escape, which a strict decoder refuses. The rest of the sample is ASCII, so the
    physical line must be printable ASCII: the character travelled as an escape, never raw."""
    char = _LOG_ALPHABET_SAMPLES[kind]
    actor = f"user{char}name"
    detail = f"refused {char} here"
    line, _inner, record = _teed_through_configured_stdout(fmt, actor, detail, capsys)

    assert record["actor"] == _as_read_back(actor)
    # Through `safe_text`, which leaves these characters alone.
    assert record["detail"] == _as_read_back(detail)
    # Strict: Python's json decodes an unpaired surrogate escape to a surrogate; jiter refuses it.
    assert not has_lone_surrogate(record["actor"] + record["detail"])
    assert all(0x20 <= ord(ch) < 0x7F for ch in line), ascii(line)


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    ("actor", "spelled"),
    [
        ("alice", '"actor": "alice"'),
        # Ordinary non-ASCII is not in the log alphabet, so it stays raw on the line.
        (f"Jos{chr(0xE9)} {chr(0x5F20)}{chr(0x4F1F)}", f'"actor": "Jos{chr(0xE9)} {chr(0x5F20)}'),
        # The form `ensure_ascii=True` would have broken: with the accent escaped, the name-run
        # pattern found a word boundary before it and redacted "Ana Luc".
        (f"Ana Luc{chr(0xED)}a", f'"actor": "Ana Luc{chr(0xED)}a"'),
    ],
)
def test_a_clean_or_plain_non_ascii_actor_round_trips(
    fmt: str, actor: str, spelled: str, capsys
) -> None:
    _line, inner, record = _teed_through_configured_stdout(fmt, actor, "ok", capsys)
    assert record["actor"] == actor
    assert spelled in inner


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    ("actor", "needle"),
    [
        # The control: nothing in front, so the filters redact what follows as they always have.
        ("DOE JANE", "DOE"),
        ("password=hunter2", "hunter2"),
        # Not in the log alphabet: `ensure_ascii=True` escaped it and the name shipped.
        (f"DOE{chr(0xA0)}JANE", "DOE"),
        # In the log alphabet. Escaped before the filters, each escape ends in a word character,
        # so `\b` found no boundary and the name or the credential value shipped (vault BACKLOG
        # #3012, the first fix's defect, measured through this chain).
        (f"{chr(0x7F)}DOE JANE", "DOE"),
        (f"{chr(0x7F)}password=hunter2", "hunter2"),
        (f"{chr(0x85)}DOE JANE", "DOE"),
        (f"{chr(0x85)}password=hunter2", "hunter2"),
        (f"{chr(0xAD)}DOE JANE", "DOE"),
        (f"{chr(0xAD)}password=hunter2", "hunter2"),
        (f"{chr(0x200E)}DOE JANE", "DOE"),
        (f"{chr(0x200E)}password=hunter2", "hunter2"),
        # Raw, this separator kept the encoded-separator pass off; escaped early, the pass ran and
        # took the closing quote, so the record stopped parsing.
        (f"x%7Cy%7Cz{chr(0x2028)}", None),
    ],
)
def test_the_redaction_filters_fire_across_an_escaped_character(
    fmt: str, actor: str, needle: str | None, capsys
) -> None:
    """The filters run before the scrub and see these characters unescaped, so they redact what
    follows each exactly as they redact the same text with nothing in front. A C0 control, which
    ``json.dumps`` escapes first, is covered by the field scrub; the tests below pin that.
    Synthetic values; the helper's ``json.loads`` is the parse check."""
    line, _inner, _record = _teed_through_configured_stdout(fmt, actor, "ok", capsys)
    if needle is not None:
        assert needle not in line, line


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    ("actor", "needle"),
    [
        (f"{chr(0x01)}DOE JANE", "DOE"),
        (f"{chr(0x01)}password=hunter2", "hunter2"),
        (f"{chr(0x09)}password=hunter2", "hunter2"),
        (f"{chr(0x01)}05/05/1980", "1980"),
        (f"DOE{chr(0x09)}JANE", "DOE"),
        (f"Bearer{chr(0x09)}abcdefgh", "abcdefgh"),
        (f"MRN{chr(0x09)}12345678", "12345678"),
    ],
)
def test_a_c0_control_no_longer_hides_text_from_the_filters(
    fmt: str, actor: str, needle: str, capsys
) -> None:
    """``json.dumps`` escapes a C0 control as ``\\u0001`` or ``\\t``, which ends in a word
    character, so the handler chain alone missed the text beside it. Each field is now scrubbed
    before it is encoded (BACKLOG #3045). These were strict xfails until then; the control test
    below asserts the same text is redacted without the control."""
    line, _inner, _record = _teed_through_configured_stdout(fmt, actor, "ok", capsys)
    assert needle not in line, line


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize(
    ("actor", "needle"),
    [
        ("05/05/1980", "1980"),
        ("DOE JANE", "DOE"),
        ("Bearer abcdefgh", "abcdefgh"),
        ("MRN 12345678", "12345678"),
    ],
)
def test_the_c0_cases_are_redacted_without_the_control(
    fmt: str, actor: str, needle: str, capsys
) -> None:
    """The control for the test above: the same text with a space, or nothing, in place of the
    C0 control is redacted, so the test above measures the control and not the pattern."""
    line, _inner, _record = _teed_through_configured_stdout(fmt, actor, "ok", capsys)
    assert needle not in line, line


# --- BACKLOG #3045: each field is scrubbed before json.dumps escapes a C0 control in it ----------


def _tee_lines(cases: list[dict[str, str | None]], capsys) -> list[str]:
    """Tee each case through the stdout handler ``serve`` installs, configured once, and return
    the physical line of each, in order. Not parsed: a line here may legitimately be broken JSON,
    a residual ``emit_audit_tee`` states."""
    with _handlerless_process():
        configure_logging("INFO", fmt="text")
        capsys.readouterr()
        defaults = {"action": "auth.login_failed", "actor": "alice", "detail": "ok"}
        for fields in cases:
            emit_audit_tee(
                ts=1.0,
                row_id=1,
                seq=1,
                row_hash=_HASH,
                **{"channel_id": None, "client": None, **defaults, **fields},  # type: ignore[arg-type]
            )
    lines = [ln for ln in capsys.readouterr().out.splitlines() if "messagefoundry.audit: " in ln]
    assert len(lines) == len(cases), lines
    return lines


#: Where a C0 control goes: ``{c}`` before, after, between a label and its value or between the
#: parts of a name, after an HL7-shaped run, and inside a token. The third member is what stands
#: in the control's place for the control case, a space or nothing; with it, each is redacted,
#: which the sweep checks first, so a leak measures the control and not the pattern.
_C0_SWEEP_TEMPLATES = (
    ("{c}DOE JANE", "DOE", " "),
    ("DOE JANE{c}", "DOE", " "),
    ("DOE{c}JANE", "DOE", " "),
    ("SMITH,{c}JOHN", "SMITH", " "),
    ("a|b|c{c}DOE JANE", "JANE", " "),
    ("{c}password=hunter2", "hunter2", " "),
    ("password=hunter2{c}", "hunter2", " "),
    ("pass{c}word=hunter2", "hunter2", ""),
    ("password{c}=hunter2", "hunter2", ""),
    ("{c}05/05/1980", "1980", " "),
    ("05/05/1980{c}", "1980", " "),
    ("05{c}/05/1980", "1980", ""),
    ("{c}Bearer abcdefgh", "abcdefgh", " "),
    ("Bearer{c}abcdefgh", "abcdefgh", " "),
    ("{c}MRN 12345678", "12345678", " "),
    ("MRN{c}12345678", "12345678", " "),
    ("MRN 12345678{c}", "12345678", " "),
    ("MRN 1234{c}5678", "5678", ""),
    ("{c}token=abc123xyz", "abc123xyz", " "),
)

#: The tee fields a writer's text reaches. ``detail-as-json`` is ``detail`` as most of its writers
#: hand it over, already through ``json.dumps``, so the control arrives as an escape.
_SWEEP_FIELDS = ("actor", "channel_id", "client", "action", "detail", "detail-as-json")


def _sweep_case(field: str, value: str) -> dict[str, str | None]:
    if field == "detail-as-json":
        return {"detail": json.dumps({"error": value})}
    return {field: value}


def _sweep_keys() -> list[tuple[int, str, str]]:
    """Every C0 code point, and -1 for the control case, in every template."""
    return [
        (code, template.format(c=chr(code) if code >= 0 else stand_in), needle)
        for code in [-1, *range(0x20)]
        for template, needle, stand_in in _C0_SWEEP_TEMPLATES
    ]


@pytest.mark.parametrize("field", _SWEEP_FIELDS)
def test_every_c0_control_beside_or_inside_the_text_of_each_field_is_redacted(
    field: str, capsys
) -> None:
    """The sweep the review of engine PR 2040 used, all 32 C0 code points, widened to put the
    control inside the text as well as on either side, in every text field of the record
    (BACKLOG #3045). The control case comes first: with a space or nothing in the control's
    place, each needle is redacted. A leak names the code point and the value. Synthetic values.

    A control the patterns read as whitespace, ``\\s`` in Python (tab, LF, VT, FF, CR and U+001C
    to U+001F), is never read as nothing, because gluing two lines into one word made names and
    dates that were not there. Inside a word it splits the word, as it does on any plain log
    line, so for those the bar is the handler chain's own verdict on the same text unencoded."""
    from messagefoundry.logging_setup import scrub_log_text

    whitespace = {c for c in range(0x20) if re.fullmatch(r"\s", chr(c))}
    keys = _sweep_keys()
    lines = _tee_lines([_sweep_case(field, value) for _code, value, _needle in keys], capsys)
    leaks = [
        (hex(code), ascii(value), needle)
        for (code, value, needle), line in zip(keys, lines, strict=True)
        if needle in line and (code not in whitespace or needle not in scrub_log_text(value))
    ]
    assert not leaks, leaks
    # The carve-out is not vacuous, and covers only what the plain chain itself misses.
    assert whitespace == {0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1C, 0x1D, 0x1E, 0x1F}


@pytest.mark.parametrize(
    "value",
    [
        "a\x01DOE JANE\x02x",
        "line one\nDOE\x01JANE",
        "DOE\x01JANE\tnext",
        "a\r\nDOE\x1fJANE",
        'q"DOE\x01JANE',
        "Bearer\x01abcdefgh pass\x01word=hunter2",
        "password=hun\x01ter2 DOE\x01JANE\x01SMITH",
    ],
)
def test_a_serialised_detail_with_a_control_still_parses(value: str, capsys) -> None:
    """A ``detail`` its writer ran through ``json.dumps`` parses after the field scrub, and the
    text beside the control is gone. Synthetic values."""
    (line,) = _tee_lines([{"detail": json.dumps({"error": value})}], capsys)
    detail = json.loads(line.split("messagefoundry.audit: ", 1)[1])["detail"]
    json.loads(detail)
    for needle in ("JANE", "abcdefgh", "hunter2", "ter2"):
        assert needle not in detail, detail


#: Values the earlier design of this fix leaked, in review: in the first, reading the controls as
#: spaces before the plain passes exposed a credential tail they hid; in the second, each of two
#: controls needed a different reading.
_REVIEW_LEAKS = (
    ("password=hun\x01ter2 DOE\x01JANE\x01SMITH", ("ter2", "DOE", "JANE")),
    ("Bearer\x01abcdefgh pass\x01word=hunter2", ("abcdefgh", "hunter2")),
    ("Authorization:\x01Bearer abcdefgh IB_ACME_ADT", ("abcdefgh",)),
    ("password: hunter2 MRN 1234\x015678", ("hunter2", "5678")),
    # Review round 2: the plain pass's name run took the ``Bearer`` label, so the credential the
    # handler chain alone hid would have shipped; and a ``password=`` value the chain hid.
    ("rejected:\nInvalid Bearer abc123def", ("abc123def",)),
    ("05/\x1btoken=password= DOE", ("DOE",)),
)


@pytest.mark.parametrize(
    ("value", "kept"),
    [
        ("user alice\nrole Admin\nscope All", "user alice\nrole Admin\nscope All"),
        ("count 2025\n0101 rows", "count 2025\n0101 rows"),
    ],
)
def test_a_reading_does_not_glue_lines_into_a_name(value: str, kept: str) -> None:
    """Review round 2: removing a line break glued two lines into a name or a date that was not
    there, so the whole field went. Synthetic values."""
    assert audit_tee._scrub_field(value).startswith(kept)


@pytest.mark.parametrize("field", ["actor", "detail", "detail-as-json"])
@pytest.mark.parametrize(("value", "needles"), _REVIEW_LEAKS)
def test_a_control_reading_never_exposes_what_another_hides(
    field: str, value: str, needles: tuple[str, ...], capsys
) -> None:
    (line,) = _tee_lines([_sweep_case(field, value)], capsys)
    assert not [needle for needle in needles if needle in line], line


def _corpus() -> list[str]:
    """The single-control sweep, two templates in one value with a control each, and the review
    leaks, for the comparisons with the field scrub switched off."""
    values = [value for _code, value, _needle in _sweep_keys()]
    for first, _n1, _s1 in _C0_SWEEP_TEMPLATES:
        for second, _n2, _s2 in _C0_SWEEP_TEMPLATES:
            for code_1, code_2 in ((0x01, 0x01), (0x00, 0x1F), (0x1B, 0x09)):
                values.append(f"{first.format(c=chr(code_1))} {second.format(c=chr(code_2))}")
    values += [value for value, _needles in _REVIEW_LEAKS]
    return values


def _before_and_after(
    cases: list[dict[str, str | None]], capsys, monkeypatch
) -> tuple[list[str], list[str]]:
    """Each case teed with the field scrub switched off, which is the code before #3045, then as
    shipped."""
    real = audit_tee._scrub_field
    monkeypatch.setattr(audit_tee, "_scrub_field", lambda value, **_kw: value)
    before = _tee_lines(cases, capsys)
    monkeypatch.setattr(audit_tee, "_scrub_field", real)
    return before, _tee_lines(cases, capsys)


# An oracle independent of audit_tee's own word and escape patterns, on purpose.
_WORD = re.compile(r"[A-Za-z0-9]+")
#: A JSON escape's text, counted as a word break on both sides of the comparison below.
_ESCAPE_TEXT = re.compile(r"\\u[0-9a-fA-F]{4}|\\.")


@pytest.mark.parametrize("field", ["actor", "client", "detail", "detail-as-json"])
def test_the_field_scrub_shows_no_word_the_line_chain_alone_hides(
    field: str, capsys, monkeypatch
) -> None:
    """Closing step 3 of BACKLOG #3045: the change redacts no less than the handler chain did on
    its own. Engine PR 2040's first version lost a redaction that way. No word of a value that the
    line hid before may show after, over the sweep and the two-control corpus. Synthetic values."""
    values = _corpus()
    before, after = _before_and_after(
        [_sweep_case(field, value) for value in values], capsys, monkeypatch
    )
    before = [_ESCAPE_TEXT.sub(" ", line) for line in before]
    after = [_ESCAPE_TEXT.sub(" ", line) for line in after]
    hidden_before = 0
    shown = []
    for value, old, new in zip(values, before, after, strict=True):
        old_words, new_words = set(_WORD.findall(old)), set(_WORD.findall(new))
        for word in _WORD.findall(value):
            if word not in old_words:
                hidden_before += 1
                if word in new_words:
                    shown.append((ascii(value), word))
    # The control: the line chain alone hides words in this corpus, so the rule is not vacuous.
    assert hidden_before
    assert not shown, shown[:20]


@pytest.mark.parametrize(
    "value",
    [
        "alice",
        "CORP\\bJONES",
        "CORP\\mefor-svc$",
        "DOE JANE",
        "password=hunter2",
        "a|b|c",
        f"Jos{chr(0xE9)}",
        f"user{chr(0x7F)}name",
        'q"uote',
    ],
)
def test_a_value_with_no_c0_control_ships_byte_identical(value: str, capsys, monkeypatch) -> None:
    """A field with no C0 control is not touched, so its line is the line before #3045, byte for
    byte; a domain account's backslash is not read as an escape. Synthetic values."""
    cases: list[dict[str, str | None]] = [
        {"actor": value},
        {"detail": value},
        {"detail": json.dumps({"user": value})},
    ]
    before, after = _before_and_after(cases, capsys, monkeypatch)
    assert after == before


def test_a_reading_that_hides_one_of_two_equal_words_is_seen() -> None:
    """The words are counted, so a name hidden by a reading is caught even when each of its words
    also stands alone, unredacted, elsewhere in the value. Synthetic values."""
    value = f"x DOE y JANE z DOE{chr(0x01)}JANE"
    assert f"DOE{chr(0x01)}JANE" not in audit_tee._scrub_field(value)


def test_a_deeply_nested_detail_does_not_fail_the_tee(audit_capture) -> None:
    """``json.loads`` raises ``RecursionError`` on a deep nest, which is not a ``ValueError``. The
    tee must still ship, and never raise into the committed audit write (review round 1)."""
    deep = "[" * 20000 + '"x\\n"' + "]" * 20000
    emit_audit_tee(
        action="x",
        actor=None,
        channel_id=None,
        detail=deep,
        ts=1.0,
        row_id=1,
        seq=1,
        row_hash=_HASH,
    )
    assert len(audit_capture.messages) == 1


def test_a_json_detail_with_an_escape_and_nothing_to_redact_ships_unchanged(
    capsys, monkeypatch
) -> None:
    """A multi-line JSON detail with nothing to redact is not re-encoded, so ``safe_text`` cuts
    it no sooner than before and it still parses (review round 1: ``\\n`` grew to ``\\u000a``
    and pushed a 191-character detail past the 200-character bound). Synthetic values."""
    detail = json.dumps({"error": "\n".join(["step ok"] * 20)})
    cases: list[dict[str, str | None]] = [{"detail": detail}]
    before, after = _before_and_after(cases, capsys, monkeypatch)
    assert after == before
    json.loads(json.loads(after[0].split("messagefoundry.audit: ", 1)[1])["detail"])


def test_a_long_value_with_no_control_is_not_touched() -> None:
    """The window's own cut ends its note with a newline of its own, which is not the value's
    control (review round 1)."""
    value = "word " * 20000
    assert audit_tee._scrub_field(value) is value


class _MixedReadingLeak(Exception):
    """The one failure the xfail below expects."""


@pytest.mark.xfail(
    strict=True,
    raises=_MixedReadingLeak,
    reason="KNOWN RESIDUAL of BACKLOG #3045: every control in a value is read the same way, so "
    "text that needs one control as a space and another as nothing is missed by every reading. "
    "See emit_audit_tee's docstring.",
)
def test_text_that_needs_two_controls_read_differently_is_redacted() -> None:
    value = f"on{chr(0x01)}05/05/19{chr(0x02)}80"
    if "80" in audit_tee._scrub_field(value):
        raise _MixedReadingLeak(ascii(value))


def test_a_long_backslash_run_is_scanned_in_linear_time() -> None:
    """Review round 3: the line-escape pattern backtracked quadratically on a run of backslashes
    at the end of its input, which ``json.dumps(...)[1:-1]`` always gives a field ending in one,
    on the event loop. The control is the old pattern, slow on a run the new one walks at once."""
    import time

    old = re.compile(r"\\+(?:u[0-9a-fA-F]{4}|[^\\])")
    run = "x " + "\\" * 3000

    def took(fn) -> float:
        start = time.perf_counter()
        fn()
        return time.perf_counter() - start

    old_t = took(lambda: old.sub(" ", run))
    new_t = took(lambda: audit_tee._LINE_ESCAPE.sub(" ", run))
    assert old_t > 20 * new_t, (old_t, new_t)
    # The field scrub as a whole, on a field near the window that ends in a long run.
    value = f"password=hunter2{chr(0x01)} " + "\\" * 60000
    assert took(lambda: audit_tee._scrub_field(value)) < 1.0
    assert "hunter2" not in audit_tee._scrub_field(value)


def test_the_line_escape_pattern_still_reads_each_escape_as_a_break() -> None:
    line = 'a\\nb \\\\u0001c \\"d e\\\\'
    assert audit_tee._LINE_ESCAPE.sub(" ", line).split() == ["a", "b", "c", "d", "e"]


def test_a_fault_on_a_json_detail_ships_a_json_string(monkeypatch) -> None:
    """Review round 3: every other whole-field path for a JSON detail ships the JSON string."""

    def boom(_text: str) -> str:
        raise RuntimeError("synthetic")

    monkeypatch.setattr(audit_tee, "scrub_log_text", boom)
    out = audit_tee._scrub_field(json.dumps({"error": "a\nb"}), detail=True)
    assert json.loads(out) == "[redacted]"


def test_a_control_with_nothing_to_redact_keeps_the_actor() -> None:
    """Attribution survives: a typed name holding a control, with nothing a reading redacts, ships
    as typed, and the handler chain escapes the control. Synthetic values."""
    for value in (f"ali{chr(0x01)}ce", f"bob{chr(0x09)}", f"{chr(0x1B)}[31mcarol"):
        assert audit_tee._scrub_field(value) == value


def test_scrub_log_text_is_the_handler_chain_without_the_control_scrub() -> None:
    """The field scrub stands for the filters, so it must be them: each value through
    ``scrub_log_text`` reads as the three text filters leave a record's message. Synthetic."""
    from messagefoundry.logging_setup import (
        CredentialQueryScrubFilter,
        CredentialScrubFilter,
        RedactionFilter,
        scrub_log_text,
    )

    filters = (RedactionFilter(), CredentialQueryScrubFilter(), CredentialScrubFilter())
    values = ["DOE JANE", "password=hunter2", "GET /cb?code=abc&state=x", "PID|1||123^^^H", "ok"]
    values += [f"{chr(0x01)}DOE JANE", "MRN 12345678 Bearer abcdefgh"]
    for value in values:
        record = logging.LogRecord("t", logging.INFO, __file__, 1, value, None, None)
        for f in filters:
            f.filter(record)
        assert scrub_log_text(value) == record.getMessage(), value
        assert scrub_log_text(value) != value or value == "ok"


def test_a_field_scrub_fault_ships_the_field_redacted(monkeypatch, caplog) -> None:
    """Fail closed: a fault in the passes ships the field as the placeholder, logged once, by
    type and never with the value."""

    def boom(_text: str) -> str:
        raise RuntimeError("synthetic DOE JANE")

    monkeypatch.setattr(audit_tee, "scrub_log_text", boom)
    monkeypatch.setattr(audit_tee, "_FIELD_SCRUB_FAULT_LOGGED", False)
    with caplog.at_level(logging.WARNING, logger=audit_tee.__name__):
        assert audit_tee._scrub_field(f"{chr(0x01)}DOE JANE") == "[redacted]"
        assert audit_tee._scrub_field(f"{chr(0x01)}x") == "[redacted]"
    faults = [r for r in caplog.records if "field scrub failed" in r.getMessage()]
    assert len(faults) == 1
    assert "DOE" not in faults[0].getMessage() and "RuntimeError" in faults[0].getMessage()


def _tee_line(text: str) -> str:
    (line,) = (ln for ln in text.splitlines() if "auth.login_failed" in ln)
    return line.split("messagefoundry.audit: ", 1)[1]


@pytest.mark.xfail(
    strict=True,
    raises=json.JSONDecodeError,
    reason="KNOWN RESIDUAL, not built here: every handler re-filters the one shared LogRecord, so "
    "the file handler and the forwarder re-run the chain over the first handler's escaped text, "
    "and a field-run pass takes the closing quote. See emit_audit_tee's docstring.",
)
@pytest.mark.parametrize("separator", [chr(0x7F), chr(0x2028)])
def test_a_later_handler_keeps_the_tee_json(separator: str, tmp_path: Path, capsys) -> None:
    """The second sink must parse too. It does not yet; when it does, this flips to a failure
    and the marker comes off. The first sink, stdout, parses, and that is asserted first, so the
    expected failure can only come from the later sink."""
    from messagefoundry.logging_setup import LogFile

    log_path = tmp_path / "engine.log"
    with _handlerless_process():
        try:
            configure_logging("INFO", fmt="text", log_file=LogFile(path=str(log_path)))
            capsys.readouterr()
            emit_audit_tee(
                action="auth.login_failed",
                actor=f"x%7Cy%7Cz{separator}",
                channel_id=None,
                detail="ok",
                ts=1.0,
                row_id=1,
                seq=1,
                row_hash=_HASH,
            )
            for handler in logging.getLogger().handlers:
                handler.flush()
            stdout_text = capsys.readouterr().out
            file_text = log_path.read_text(encoding="utf-8")
        finally:
            for handler in list(logging.getLogger().handlers):
                handler.close()
    try:
        json.loads(_tee_line(stdout_text))
    except json.JSONDecodeError as exc:  # not the residual, so not the expected failure
        raise AssertionError(f"the FIRST sink broke too: {stdout_text!r}") from exc
    json.loads(_tee_line(file_text))


class _Collector(logging.Handler):
    """Stands in for the syslog socket handler behind the forwarder's queue."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def test_each_sink_gets_each_tee_line_once_redacted(tmp_path: Path, capsys, monkeypatch) -> None:
    """Vault BACKLOG #2612: the audit lane changed how a tee line reaches the forwarder, so this
    pins what must not change. Each tee line reaches stdout, the file and the off-box forwarder
    exactly once, with the HL7 in ``detail`` redacted and a DEL in ``actor`` escaped on every sink.

    The forwarder is the one ``configure_logging`` builds, with its socket handler replaced by an
    in-memory collector, so the lanes, the near-side filters and the listener thread are the
    shipped ones."""
    from messagefoundry import logging_setup
    from messagefoundry.logging_setup import LogFile, SyslogForward

    collector = _Collector()
    monkeypatch.setattr(logging_setup, "_build_syslog_handler", lambda *_a, **_k: collector)
    # configure_logging sets these; put them back for the tests that read them.
    for name in ("_forward_configured", "_forward_start_failure", "_forward_delivery_confirmed"):
        monkeypatch.setattr(logging_setup, name, getattr(logging_setup, name))
    log_path = tmp_path / "engine.log"
    hl7 = "PID|1||100^^^H^MR||DOE^JANE^Q||19800101|F"
    with _handlerless_process():
        try:
            installed = configure_logging(
                "INFO",
                fmt="text",
                log_file=LogFile(path=str(log_path)),
                forward=SyslogForward(host="collector.invalid", port=6514, protocol="tcp"),
            )
            assert installed
            capsys.readouterr()
            emit_audit_tee(
                action="auth.login_failed",
                actor=f"ali{chr(0x7F)}ce",
                channel_id=None,
                detail=f"transform failed on {hl7}",
                ts=1.0,
                row_id=1,
                seq=1,
                row_hash=_HASH,
            )
        finally:
            for handler in list(logging.getLogger().handlers):
                handler.close()  # the forwarder's close() drains its queue to the collector
        stdout_text = capsys.readouterr().out
        file_text = log_path.read_text(encoding="utf-8")
    sinks = {
        "stdout": stdout_text.splitlines(),
        "file": file_text.splitlines(),
        "forwarder": collector.lines,
    }
    for sink, lines in sinks.items():
        tee = [ln for ln in lines if "auth.login_failed" in ln]
        assert len(tee) == 1, (sink, tee)
        assert chr(0x7F) not in tee[0], sink
        assert "DOE" not in tee[0] and "19800101" not in tee[0], sink
        # Not parsed as JSON: the HL7 redaction cuts to the end of the line and takes the closing
        # quote with it on every sink, a residual emit_audit_tee's docstring names and #2612 does
        # not touch. The anchor fields come before ``detail``, so they survive it. The forwarder
        # renders JSON by default, which escapes the tee document's quotes inside its own.
        assert f'"seq": 1, "row_hash": "{_HASH}"' in tee[0].replace('\\"', '"'), sink


def test_emit_audit_tee_is_best_effort_on_logging_failure(audit_capture, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("forwarder exploded")

    monkeypatch.setattr(audit_tee.audit_logger, "info", boom)
    # Must swallow the logging failure — the caller's audit row is already durable.
    emit_audit_tee(
        action="auth.login",
        actor="z",
        channel_id=None,
        detail=None,
        ts=1.0,
        row_id=1,
        seq=1,
        row_hash=_HASH,
    )


def test_tee_docstring_and_cipher_registry_agree_about_audit_log() -> None:
    """The tee's docstring makes a claim about ``audit_log.detail`` at rest; pin it to the registry.

    Until 2026-08-22 the docstring said ``detail`` "is a cipher column at rest", which was FALSE --
    ``audit_log`` appears nowhere in ``_CIPHER_COLUMNS``, while that tuple's own comment block names
    ``message_events.detail``, ``connection_event.reason`` and ``alert_instance.reason`` as covered.
    The error mattered because it made the redaction in :func:`emit_audit_tee` read as defence in
    depth over an already-sealed column, when it is the only thing standing between an HL7 fragment
    and the off-box copy.

    This guard fails in BOTH directions, and until 2026-09-06 the second direction was UNREACHABLE.

    It read only ``_CIPHER_COLUMNS``, the ID-KEYED registry. ``audit_log.id`` is ``AUTOINCREMENT``
    (SQLite), ``BIGSERIAL`` (Postgres) and ``IDENTITY`` (SQL Server), and ``store.py`` states the rule
    that follows from that: "The autoincrement-id tables bind cell_aad to natural columns (see
    _CIPHER_COLUMNS)". So ``audit_log`` could never legitimately enter that tuple, and the branch
    testing for it was ruled out by the schema rather than merely untriggered -- while this docstring
    told a reader the claim was pinned in both directions. A control that cannot produce a different
    answer is decoration, and an assurance broader than its control is the SDS-3.7 shape.

    The tell was in this same docstring: the three columns it names as cipher-covered
    (``message_events.detail``, ``connection_event.reason``, ``alert_instance.reason``) are absent
    from ``_CIPHER_COLUMNS`` too, for exactly that reason. The mechanism that would actually cover
    ``audit_log.detail`` is the one this guard could not see.

    It now reads BOTH mechanisms via ``_cipher_registry.covered_tables()``. Settled by adversarial
    review, where both sides recommended widening and the side arguing to keep it narrow conceded on
    the schema fact above.

    Coverage is still not a one-line change -- ``audit_row_hash`` hashes the PLAINTEXT ``detail`` into
    the tamper-evident chain and key rotation rewrites every cipher column, so naive coverage breaks
    verification on the first rekey. The red below therefore says VERIFY rather than "edit the
    prose": a single literal on one backend is work in progress, and instructing a coverage claim
    into the docstring from it would recreate the false statement this guard exists to prevent
    (BACKLOG #1198).
    """
    from messagefoundry.store.store import MessageStore
    from tests._cipher_registry import covered_tables

    narrow = {table for table, _column in MessageStore._CIPHER_COLUMNS}
    covered = covered_tables()
    doc = audit_tee.emit_audit_tee.__doc__ or ""

    # POSITIVE CONTROL 1: the derivation must be readable and non-trivial, or an empty `covered`
    # would make the branch below pass vacuously.
    assert "messages" in covered, (
        "cipher registry unreadable or empty -- the assertion below is void"
    )

    # POSITIVE CONTROL 2, AND IT IS THE ONE THAT PROVES THE WIDENING HAPPENED. These three tables are
    # cipher-covered by composite passes and appear in NO id-keyed registry. If this fails, the guard
    # has silently reverted to reading `_CIPHER_COLUMNS` alone and its `audit_log` branch is
    # unreachable again -- which is the exact defect being fixed, and it would otherwise look green.
    composite_only = {"message_events", "connection_event", "alert_instance"}
    assert composite_only <= covered, (
        f"the widened derivation lost the composite mechanism: {sorted(composite_only - covered)} "
        "are cipher-covered but not seen. The audit_log branch below is unreachable in this state."
    )
    assert not (composite_only & narrow), (
        "these tables have entered the id-keyed registry, which the store's own design note says "
        "cannot work for a server-assigned id -- re-read _CIPHER_COLUMNS before trusting this guard"
    )

    if "audit_log" in covered:  # pragma: no cover - fires only once someone adds coverage
        assert "NOT a cipher column at rest" not in doc, (
            "audit_log now appears cipher-covered somewhere, and audit_tee's docstring still says it "
            "is not. VERIFY BEFORE EDITING THE PROSE: confirm the column is covered on ALL THREE "
            "backends, not just the one you touched, and check audit_row_hash and rekey against the "
            "tamper-evident chain. A single literal on one backend is work in progress, and writing "
            "a coverage claim into the docstring from it recreates the false statement this guard "
            "exists to prevent (BACKLOG #1198)."
        )
    else:
        assert "NOT a cipher column at rest" in doc, (
            "audit_log is NOT cipher-covered and the docstring no longer says so. It previously "
            "claimed the opposite, which hid an at-rest gap (BACKLOG #1198)."
        )


# --- the record has to REACH a handler, not merely be emitted (BACKLOG #1199) ---------------------
#
# The defect and its measurement are stated once, on `logging_setup.ensure_logger_sink`.
#
# What is local to the tests: these guards run the REAL subcommand in a REAL child process, because
# the defect is a property of the process's logging state and nothing smaller reproduces it -- pytest
# installs FOUR root handlers of its own (measured 2026-09-03), so an in-process test sees a
# configured sink until it takes them away, which `_handlerless_process` does reversibly.


def _audit_records_in(stream: str) -> list[dict]:
    """Every off-box audit record carried on ``stream``, whatever formatter prefixed it.

    The tee emits ``json.dumps(record)`` as the log MESSAGE, so a text formatter prefixes it with a
    timestamp/level/logger and a JSON formatter wraps it. Parsing from the first brace covers both
    without pinning either rendering, and the ``event == "audit"`` check keeps the probe specific --
    a looser scan would match any JSON the subcommand happens to print.
    """
    records: list[dict] = []
    for line in stream.splitlines():
        brace = line.find("{")
        if brace == -1:
            continue
        try:
            payload = json.loads(line[brace:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and payload.get("event") == "audit":
            records.append(payload)
    return records


async def _provision_store(db: Path) -> None:
    store = await MessageStore.open(db)
    await store.close()


def _run_backup(tmp_path: Path, *, allow_unencrypted: bool) -> subprocess.CompletedProcess[str]:
    """Run the real ``messagefoundry backup`` subcommand in a child process and capture both streams.

    A child process, not ``main(argv)`` in-process: the whole question is what the PROCESS did about
    handlers, and running it in-process would answer it against pytest's handlers instead of the
    subcommand's own. (That was an empty list when this was written. This run passes ``--json``, so
    main() now installs a filtered stderr sink first, per BACKLOG #1489, and the record must still
    reach a handler.)
    """
    config = tmp_path / "config"
    config.mkdir()
    (config / "feed.py").write_text("# a router lives here\n", encoding="utf-8")
    toml = tmp_path / "messagefoundry.toml"
    # A keyless box, so it takes the audited at-rest opt-out, which BACKLOG #1916 requires of every
    # command that opens a fresh store with no key. Dotted keys, so they precede the first table.
    body = AT_REST_OPT_OUT_TOML + "[store]\n"
    if allow_unencrypted:
        body += "\n[backup]\nallow_unencrypted = true\n"
    toml.write_text(body, encoding="utf-8")
    # backup backs up a store and no longer creates the one it is pointed at (BACKLOG #1780), so the
    # store exists before the child runs, as it would after serve's first run.
    asyncio.run(_provision_store(tmp_path / "msg.db"))
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "messagefoundry",
            "backup",
            "--config",
            str(config),
            "--service-config",
            str(toml),
            "--db",
            str(tmp_path / "msg.db"),
            "--destination",
            str(tmp_path / "dest"),
            "--json",
        ],
        capture_output=True,
        text=True,
        # Pinned rather than left to the locale: the child writes UTF-8 and a cp1252 default mojibakes
        # `safe_text`'s truncation marker. Everything asserted below is ASCII either way; this just
        # keeps a failure message readable when one fires.
        encoding="utf-8",
        errors="replace",
        cwd=tmp_path,
        # A real run measures 3.5-5s, so this is ~25x headroom for a slow runner while still failing
        # a hung child fast instead of stalling the job for minutes.
        timeout=120,
    )


def test_backup_subcommand_ships_its_success_audit_row_off_box(tmp_path) -> None:
    """The measured instance: ``messagefoundry backup`` writes a ``dr_backup`` audit row from a
    process that never calls ``configure_logging``, so its off-box copy must still reach a handler."""
    proc = _run_backup(tmp_path, allow_unencrypted=True)

    # POSITIVE CONTROL: the backup really ran and really wrote the row whose tee we are looking for.
    # Without this, a subcommand that died at argument parsing would produce an empty stderr too and
    # this test would read the same as a genuine drop.
    assert proc.returncode == 0, f"backup did not run: {proc.stdout}\n{proc.stderr}"
    payload = [ln for ln in proc.stdout.splitlines() if ln.strip().startswith("{")]
    assert payload, f"no JSON object on stdout, so the backup summary is missing: {proc.stdout!r}"
    assert Path(json.loads(payload[-1])["archive"]).exists()

    records = _audit_records_in(proc.stderr)
    assert [r["action"] for r in records] == ["dr_backup"], (
        f"the dr_backup audit row's off-box copy never reached a handler; stderr was:\n{proc.stderr}"
    )
    assert records[0]["actor"] == "system"


def test_backup_subcommand_ships_its_failure_audit_row_off_box(tmp_path) -> None:
    """The failure row travels too. A backup that refuses to write an unencrypted archive records a
    ``dr_backup`` ERROR audit row, and a detection signal that never leaves the box is the exact
    shape ASVS 16.4.3 is about."""
    proc = _run_backup(tmp_path, allow_unencrypted=False)

    # POSITIVE CONTROL, and it is the discriminating one: this WARNING is emitted by the SAME
    # process through the SAME root handler the audit record would reach. That root was
    # handler-less when this test was written; this run passes `--json`, so it now gets main()'s
    # filtered stderr sink (BACKLOG #1489). So stderr demonstrably works here,
    # and an absent audit record is a real drop rather than a stream nobody could write to.
    assert proc.returncode == 1
    assert "ALERT backup_failed" in proc.stderr, proc.stderr

    records = _audit_records_in(proc.stderr)
    assert [r["action"] for r in records] == ["dr_backup"], (
        "the WARNING on this process reached stderr but the tee's INFO record did not -- an "
        "INFO record needs a handler below WARNING, and the stdlib's last resort is warning-only. "
        f"stderr was:\n{proc.stderr}"
    )
    # A prefix, not a nested `json.loads`: `safe_text` bounds `detail`'s LENGTH, so this row reaches
    # the wire truncated mid-string and is no longer parseable JSON. The content still travelled.
    assert records[0]["detail"].startswith('{"error": "BackupError')


@contextlib.contextmanager
def _handlerless_process():
    """Put the process into the handler-less shape: no root handler and no handler on
    ``messagefoundry.audit``. When written, every subcommand except serve and supervise dispatched in
    this shape. Since BACKLOG #1441 ``__main__.main`` installs a root sink first, so this now models
    a process that logs without going through ``main()``, such as a library caller or a script. Both handler lists are restored on the way
    out, so no later test inherits the stripped shape. (Only those two lists -- a test that calls
    ``configure_logging`` inside the block also re-levels the uvicorn loggers, which is the steady
    state any other caller leaves behind anyway.)

    A context manager entered inside the test BODY, deliberately not a fixture: pytest's logging
    plugin installs its capture handler on the root logger at the start of each test PHASE, so a
    fixture that strips them during setup watches them come straight back for the call. Measured --
    the first draft of these guards was a fixture and every record still landed in pytest's capture
    with `audit_logger.handlers` empty, which is the configured shape, not the defect's.
    """
    root = logging.getLogger()
    saved_root, saved_level = list(root.handlers), root.level
    saved_audit = list(audit_tee.audit_logger.handlers)
    root.handlers.clear()
    audit_tee.audit_logger.handlers.clear()
    try:
        yield
    finally:
        audit_tee.audit_logger.handlers[:] = saved_audit
        root.handlers[:] = saved_root
        root.setLevel(saved_level)


def test_the_handlerless_shape_is_the_one_the_defect_needs() -> None:
    """The control for every guard below: confirm the shape they are built on is the measured one --
    no reachable handler, and a standard-library last resort that is WARNING-only, so an INFO record
    with no handler is dropped rather than degraded."""
    with _handlerless_process():
        assert logging.getLogger().handlers == []
        assert audit_tee.audit_logger.propagate is True
        assert logging.lastResort is not None
        assert logging.lastResort.level == logging.WARNING


def test_the_tee_reaches_a_handler_with_no_root_handler_installed(capsys) -> None:
    with _handlerless_process():
        emit_audit_tee(
            action="auth.login",
            actor="alice",
            channel_id=None,
            detail=None,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )

    captured = capsys.readouterr()
    assert [r["action"] for r in _audit_records_in(captured.err)] == ["auth.login"]
    # Stdout stays clean, for the reason `ensure_logger_sink` gives: `_print_json` is a bare `print`,
    # so a `--json` payload and a log line share the stream.
    assert _audit_records_in(captured.out) == []


def test_the_tee_does_not_double_emit_when_a_sink_is_already_configured(audit_capture) -> None:
    """A configured process must be untouched. The fallback exists for the ``found == 0`` case the
    standard library diverts to its last resort, so a process that configured a sink keeps exactly
    one copy -- serve and supervise included."""
    emit_audit_tee(
        action="auth.login",
        actor="alice",
        channel_id=None,
        detail=None,
        ts=1.0,
        row_id=1,
        seq=1,
        row_hash=_HASH,
    )

    assert [json.loads(m)["action"] for m in audit_capture.messages] == ["auth.login"]
    assert audit_tee.audit_logger.handlers == [audit_capture]


def test_the_fallback_sink_carries_the_identical_redaction_chain() -> None:
    """The off-box guarantee is a property of the HANDLER's filters, so a fallback that skipped them
    would ship what the configured path scrubs. Pinned against the shared builder, which is the one
    definition both the configured stderr sink and this fallback are built from."""
    with _handlerless_process():
        emit_audit_tee(
            action="auth.login",
            actor="alice",
            channel_id=None,
            detail=None,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )
        installed = list(audit_tee.audit_logger.handlers)
        assert len(installed) == 1, installed
        chain = [type(f).__name__ for f in installed[0].filters]
        expected = [type(f).__name__ for f in build_stderr_handler().filters]

    # POSITIVE CONTROL: an empty expectation would make the comparison below pass vacuously.
    assert "RedactionFilter" in expected, (
        "the shared filter chain is empty; the check below is void"
    )
    assert chain == expected


def test_the_fallback_sink_renders_phi_exactly_as_the_configured_sink_does(capsys) -> None:
    """Redaction is not relaxed, reordered or bypassed to make emission work: for a PHI-bearing
    record the fallback emits the SAME BYTES the configured ``serve`` path emits.

    Byte identity rather than an assertion about the redacted shape, because the shape is a property
    of the shared chain and not of this module. Measured 2026-09-03: the handler-level
    ``RedactionFilter`` re-scrubs the already-``safe_text``'d line, sees ``PID|`` in the rendered JSON
    as a segment run, and cuts to end-of-line -- so the record ships with its closing brace gone, on
    the configured stdout path and the syslog forwarder exactly as here. That is inherited behaviour,
    it errs toward MORE redaction rather than less, and correcting the framing is a separate subject.
    What this guard pins is that the fallback did not diverge from it.
    """
    phi = "PID|1||123456^^^HOSP^MR||DOE^JANE^Q||19800101|F"
    with _handlerless_process():
        emit_audit_tee(
            action="message.error",
            actor="svc",
            channel_id=None,
            detail=phi,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )
        # The same record through the handler `serve` installs, for a side-by-side rendering.
        configure_logging("INFO")
        emit_audit_tee(
            action="message.error",
            actor="svc",
            channel_id=None,
            detail=phi,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )

    captured = capsys.readouterr()
    assert "DOE" not in captured.err and "JANE" not in captured.err
    assert "123456" not in captured.err

    marker = "messagefoundry.audit: "
    fallback = captured.err.split(marker, 1)[1].strip()
    configured = captured.out.split(marker, 1)[1].strip()

    # POSITIVE CONTROL: an empty rendering on either side would make the comparison vacuous.
    assert '"action": "message.error"' in configured, "no configured rendering to compare against"
    assert fallback == configured


def test_the_fallback_sink_is_removed_once_the_process_configures_logging() -> None:
    """Self-correcting in both directions. A process that installs a sink AFTER its first audit write
    must not then get every later record twice."""
    late = _ListHandler()
    with _handlerless_process():
        emit_audit_tee(
            action="first",
            actor=None,
            channel_id=None,
            detail=None,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )
        assert len(audit_tee.audit_logger.handlers) == 1  # the fallback went in

        audit_tee.audit_logger.addHandler(late)
        emit_audit_tee(
            action="second",
            actor=None,
            channel_id=None,
            detail=None,
            ts=2.0,
            row_id=1,
            seq=1,
            row_hash=_HASH,
        )

        assert audit_tee.audit_logger.handlers == [late]
    assert [json.loads(m)["action"] for m in late.messages] == ["second"]
