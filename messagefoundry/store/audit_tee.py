# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Off-box audit tee — the single redaction path shared by every store backend (sec-offbox-log).

Each store backend's ``record_audit`` (``SqliteStore``, ``PostgresStore``, ``SqlServerStore``) calls
:func:`emit_audit_tee` immediately after the row is durably committed. So does a write that
commits an audit row in its own transaction, through ``AuditAppend.tee`` (BACKLOG #2100). At least
those paths reach it. So a **metadata** copy of the audit record, with HL7-shaped spans scrubbed
from its ``detail``, is emitted for off-box shipping. That scrub is best-effort and does not make
the copy PHI-free (BACKLOG #1133). The copy goes via the ``messagefoundry.audit`` logger — which
propagates to the root stdout + optional syslog/SIEM forwarder configured by
:mod:`messagefoundry.logging_setup`. So the records a collector has already received survive a
host/DB compromise (ASVS 16.x).

One helper means there is exactly **one** place the off-box redaction lives, identical
across all three backends — not three copies that could drift.

**Propagation is only half the guarantee.** A record reaches that forwarder only if the process
installed a handler for it to propagate to, which is a property of the *process*, not of this module
— so :func:`~messagefoundry.logging_setup.ensure_logger_sink` supplies one when nothing else has
(BACKLOG #1199; that function states the defect, and this file does not restate it). This module
transmits nothing itself. The copy reaches every handler the process installed. The one built to
ship it off the host is the syslog forwarder that :mod:`messagefoundry.logging_setup` installs when
forwarding is configured and the forwarder comes up. The forwarder's protocol is whatever
``[logging].forward_protocol`` says: TLS is ADR 0080, and the on-disk spool for a collector that is
down is ADR 0200. The other handlers keep the copy on the host, though a copy in the engine's log file
can still leave through ``GET /logs/tail`` or a support bundle.

The forwarder carries the copy in its own lane of the in-memory hand-off queue, so a flood of
general log lines cannot drop it from that queue (vault BACKLOG #2612). The on-disk spool behind the
queue is shared and size-capped, so a flood there can still cost audit lines; ``docs/CONFIGURATION.md``
says how. No handler is attached to the ``messagefoundry.audit`` logger for that, so each sink still
sees the copy once, through propagation.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from collections.abc import Callable
from typing import overload

from messagefoundry.controlchars import scrub_control_chars
from messagefoundry.logging_setup import (
    AUDIT_LOGGER_NAME,
    FinishedAuditLine,
    ensure_logger_sink,
    scrub_log_text,
    sink_readings,
)
from messagefoundry.redaction import (
    _REDACT_WINDOW,
    _REDACTED,
    clamp_untrusted,
    safe_text,
    safe_text_bound,
)

__all__ = [
    "AuditObserver",
    "add_audit_observer",
    "audit_logger",
    "emit_audit_tee",
    "remove_audit_observer",
]

log = logging.getLogger(__name__)

#: A synchronous callable told about each committed audit row: ``(action, actor, channel_id, client,
#: detail)``. ``detail`` is the row's own, unredacted; an observer must not forward it anywhere.
AuditObserver = Callable[[str, str | None, str | None, str | None, str | None], None]

#: The observers this process has registered (vault BACKLOG #2613). A tuple, rebound whole on each
#: change, so a call iterates a snapshot and needs no lock.
_OBSERVERS: tuple[AuditObserver, ...] = ()
#: Whether this process has logged an observer failure; see :func:`emit_audit_tee`.
_OBSERVER_FAILURE_LOGGED = False


def add_audit_observer(observer: AuditObserver) -> None:
    """Tell ``observer`` about each audit row this process tees, after its commit (#2613).

    The tap the security-signal rule layer reads, chosen so it costs the request path no store
    round trip: the row is already committed, and the observer sees it in memory. It is per
    PROCESS, like the tee: an engine shard's rows reach that shard's observers only."""
    global _OBSERVERS
    _OBSERVERS = (*_OBSERVERS, observer)


def remove_audit_observer(observer: AuditObserver) -> None:
    """Undo one :func:`add_audit_observer`; a no-op when ``observer`` is not registered."""
    global _OBSERVERS
    remaining = list(_OBSERVERS)
    if observer in remaining:
        remaining.remove(observer)
    _OBSERVERS = tuple(remaining)


# Pinned to INFO so audit evidence forwards regardless of the deployment's general log level: the
# logging_setup root handlers are NOTSET, so a record's only level gate is this logger's own level.
# It propagates to those root handlers, so no logging_setup change is needed to reach the forwarder.
audit_logger = logging.getLogger(AUDIT_LOGGER_NAME)
audit_logger.setLevel(logging.INFO)

#: Whether this process has logged a tee failure; see the handler in :func:`emit_audit_tee`.
_TEE_FAILURE_LOGGED = False


#: What a field scrubbed whole is shipped as: the redactor's own placeholder.
_FIELD_REDACTED = _REDACTED
#: A raw C0 control, U+0000 to U+001F, which ``json.dumps`` escapes.
_RAW_C0 = re.compile(r"[\x00-\x1f]")
#: One JSON string escape, matched from the left, so the second half of an escaped backslash is
#: never read as the start of an escape: in a JSON text, ``CORP\\bJONES`` is a backslash and a
#: letter, not a backspace.
_JSON_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|.)", re.DOTALL)
#: The JSON escapes that spell a C0 control: the short forms and ``\u0000`` to ``\u001f``.
_C0_ESCAPE = re.compile(r"\\(?:[btnfr]|u00[01][0-9a-fA-F])")
#: The C0 controls Python's ``\s`` does not match: all but tab, LF, VT, FF, CR and U+001C to
#: U+001F.
_NONSPACE_C0 = re.compile(r"[\x00-\x08\x0e-\x1b]")
#: A JSON escape on the tee line, its backslash itself escaped any number of times. LINEAR: a
#: match starts only at the first backslash of a run and takes the run possessively, so a long
#: run, at the end of the text above all, is walked once, not once per backslash in it. The
#: unanchored ``\\+`` form was quadratic there.
_LINE_ESCAPE = re.compile(r"(?<!\\)\\++(?:u[0-9a-fA-F]{4}|[^\\]|\Z)")
#: Placeholders the passes write, which are not text of the value: :data:`_FIELD_REDACTED`
#: and :data:`~messagefoundry.secretscrub.CREDENTIAL_PLACEHOLDER`. Spelled out so the static regex
#: scan can read it; ``tests/test_audit_offbox_tee.py`` holds it to the two constants.
_PLACEHOLDERS = re.compile(r"\[redacted\]|<redacted>")
#: A run of letters or digits: a word.
_WORD = re.compile(r"[^\W_]+")
#: Whether this process has logged a field scrub fault; see :func:`_scrub_field`.
_FIELD_SCRUB_FAULT_LOGGED = False
#: The most passes :func:`_settled` runs before it gives up on a value that is still changing.
#: The handler chain is not idempotent, and a later handler used to get those extra passes.
_SETTLE_PASSES = 12
#: The record's free-text fields, the ones :func:`_tee_line` may cut to keep the line bounded.
_TEXT_FIELDS = ("action", "actor", "channel_id", "client", "detail")


def _read(text: str, stand_in: str) -> str:
    """``text`` read with every C0 control as a space, or, for ``""``, with every control the
    patterns do not already read as whitespace removed. Removing a tab or a line break would
    glue two lines into one word, a name or a date that is not in the text."""
    return (_RAW_C0 if stand_in else _NONSPACE_C0).sub(stand_in, text)


def _words(text: str, stand_in: str) -> Counter[str]:
    """The words ``text`` shows outside the placeholders, read as :func:`_read` reads it.
    Counted, so a reading that hides one of two equal words is seen to hide it."""
    return Counter(_WORD.findall(_read(_PLACEHOLDERS.sub(" ", text), stand_in)))


def _letters(words: Counter[str]) -> Counter[str]:
    """The letters and digits of ``words``, counted, whatever the breaks between them."""
    letters: Counter[str] = Counter()
    for word, count in words.items():
        for ch in word:
            letters[ch] += count
    return letters


def _line_words(line: str) -> tuple[Counter[str], Counter[str]]:
    """The words a tee line shows outside the placeholders, counted, in two readings: each JSON
    escape on it, however many backslashes encode it, read as a break; and the line read as JSON
    text, left to right, so an escaped backslash is one break and what follows it is text, as in
    a literal ``\\\\u1234``, whose digits the first reading takes as part of an escape."""
    text = _PLACEHOLDERS.sub(" ", line)
    return (
        Counter(_WORD.findall(_LINE_ESCAPE.sub(" ", text))),
        Counter(_WORD.findall(_JSON_ESCAPE.sub(" ", text))),
    )


def _shows_no_more(line: str, bar: tuple[Counter[str], Counter[str]]) -> bool:
    """Whether ``line`` shows no word, counted, beyond ``bar``, a :func:`_line_words` reading, in
    either reading: a word the bar's line hid in one reading is not let through by the other."""
    return all(shown <= limit for shown, limit in zip(_line_words(line), bar, strict=True))


def _parses(text: str) -> bool:
    try:
        json.loads(text)
    except (ValueError, RecursionError):  # a deep nest raises the second
        return False
    return True


def _decode_c0_escapes(text: str) -> str:
    """``text`` with each JSON escape that spells a C0 control replaced by that control."""
    return _JSON_ESCAPE.sub(
        lambda m: json.loads(f'"{m.group()}"') if _C0_ESCAPE.fullmatch(m.group()) else m.group(),
        text,
    )


#: Each C0 control as ``json.dumps`` spells it inside a string.
_C0_SPELLING = {chr(code): json.dumps(chr(code))[1:-1] for code in range(0x20)}


def _encode_c0(text: str) -> str:
    """The inverse of :func:`_decode_c0_escapes`, for a text that held no raw control before it.
    Each control is spelled as ``json.dumps`` spells it, ``\\n`` rather than ``\\u000a``."""
    return _RAW_C0.sub(lambda m: _C0_SPELLING[m.group()], text)


def _window(value: str, *, detail: bool) -> tuple[str, str]:
    """``(head, note)``: the part of ``value`` the field scrub reads, and the note naming what it
    left unread, ``""`` when the value fit and ``head is value``. A ``detail``'s window is
    :func:`~messagefoundry.redaction.safe_text`'s; any other field's is the handler chain's,
    :func:`~messagefoundry.redaction.clamp_untrusted`, and its note keeps that cut's newline
    joiner."""
    if detail:
        return safe_text_bound(value)
    clamped = clamp_untrusted(value)
    if clamped is value:
        return value, ""
    cut = clamped.rfind("\n")  # the cut appends its note after a newline of its own
    return clamped[:cut], clamped[cut:]


def _bounded_detail(kept: str, note: str, old: str) -> str:
    """``kept``, the scrubbed detail, bounded by :func:`~messagefoundry.redaction.safe_text` as
    the value was, with ``note``, the bound note ``safe_text`` gave the value, which the scrub's
    own window cut off. Where ``old``, the value's own ``safe_text`` form, parses as JSON and the
    bounded result does not, it ships as the JSON string ``"[redacted]"`` instead."""
    shipped = safe_text(kept) + note
    if _parses(old) and not _parses(shipped):
        return json.dumps(_FIELD_REDACTED)
    return shipped


@overload
def _scrub_field(value: str, *, detail: bool = False) -> str: ...
@overload
def _scrub_field(value: None, *, detail: bool = False) -> None: ...
def _scrub_field(value: str | None, *, detail: bool = False) -> str | None:
    """One tee field, scrubbed by the handlers' text passes before ``json.dumps`` escapes a C0
    control in it (BACKLOG #3045). A value the scrub finds no C0 control in, within the window
    :func:`_window` names, is returned unchanged.

    Otherwise the windowed value is scrubbed as written, the plain result. Two readings, every
    control as a space and every control the patterns do not read as whitespace removed
    (:func:`_read`), are scrubbed too, of the plain result and, where the plain pass changed
    anything, of the value. If a reading of the plain result shows fewer of its letters and
    digits, or a reading of the value does not show every word the plain result shows, counted,
    the whole field is returned as :data:`_FIELD_REDACTED`.

    Where the plain result changed nothing, the value is returned. Otherwise the plain result is
    returned only if, encoded, it shows no word, counted, beyond what the handler chain alone
    leaves of the encoded value, and the whole field is returned if not. A field other than
    ``detail`` gets the window's note appended to its plain result; :func:`_bounded_detail`
    appends a ``detail``'s.

    With ``detail``, a value that parses as JSON and holds no raw control has each JSON escape
    that spells a C0 control decoded first and encoded again after, and the whole field is then
    the JSON string ``"[redacted]"``, as it is where the result no longer parses. On a fault the
    whole field is returned. :func:`_finished` then scrubs what this returns, control or none."""
    if value is None:
        return None
    as_json = False
    try:
        probe, note = _window(value, detail=detail)
        as_json = (
            detail
            and _C0_ESCAPE.search(probe) is not None
            and not _RAW_C0.search(probe)
            and _parses(probe)
        )
        written = probe
        if as_json:
            probe = _decode_c0_escapes(probe)
        if not _RAW_C0.search(probe):
            return value
        whole = json.dumps(_FIELD_REDACTED) if as_json else _FIELD_REDACTED
        first = scrub_log_text(probe)
        # A reading of the plain result keeps its placeholders, so it can only hide more, and a
        # drop in the letters it shows says so whatever the word breaks. A reading of the value
        # can also show what the plain result hid, so it is compared word for word.
        for stand_in in (" ", ""):
            shown = _words(first, stand_in)
            if not _letters(shown) <= _letters(
                _words(scrub_log_text(_read(first, stand_in)), stand_in)
            ):
                return whole
        if first != probe and any(
            not _words(first, stand_in) <= _words(scrub_log_text(_read(probe, stand_in)), stand_in)
            for stand_in in (" ", "")
        ):
            return whole
        if first == probe:
            return value
        result = _encode_c0(first) if as_json else first
        if as_json and not _parses(result):
            return whole
        # This result must hide every word the handler chain alone hides. The plain pass can
        # redact a span the chain read differently, a name run that takes a ``Bearer`` label with
        # it, and leave the credential the chain would have caught.
        alone = scrub_log_text(json.dumps(written, ensure_ascii=False)[1:-1])
        if not _shows_no_more(json.dumps(result, ensure_ascii=False)[1:-1], _line_words(alone)):
            return whole
        # A detail's note goes on after safe_text bounds it, in _bounded_detail.
        return result if detail else result + note
    except Exception as exc:  # noqa: BLE001 - fail closed; the tee must still ship the record
        _log_scrub_fault(exc)
        return json.dumps(_FIELD_REDACTED) if as_json else _FIELD_REDACTED


def _log_scrub_fault(exc: Exception) -> None:
    """Log a fault in the field scrub once per process, by type and never with the value."""
    global _FIELD_SCRUB_FAULT_LOGGED
    if not _FIELD_SCRUB_FAULT_LOGGED:
        _FIELD_SCRUB_FAULT_LOGGED = True
        log.warning(
            "the audit tee's field scrub failed (%s); the text it was scrubbing is hidden whole, "
            "and further faults in this process are not logged",
            type(exc).__name__,
        )


def _settled(text: str) -> str | None:
    """``text`` once the handlers' text passes change it no more, or ``None`` if they still do
    after :data:`_SETTLE_PASSES`. A further pass can redact more than the first."""
    for _ in range(_SETTLE_PASSES):
        out = scrub_log_text(text)
        if out == text:
            return out
        text = out
    return None


def _finished(key: str, written: str, scrubbed: str) -> str:
    """The text to ship for field ``key``, written as ``written`` and scrubbed so far to
    ``scrubbed`` (BACKLOG #5649). No filter reads the finished line, so this must hide what they
    would have.

    ``scrubbed`` is run to :func:`_settled`. Unless that left the field as written, with nothing
    for ``json.dumps`` or the control scrub to escape, the result must also show no word, counted,
    beyond what each modelled sink leaves of the field alone as a JSON member, the form the
    handler chain used to read (:func:`~messagefoundry.logging_setup.sink_readings`). If it shows
    more, or a reading does not settle, the whole field is :data:`_FIELD_REDACTED`."""
    settled = _settled(scrubbed)
    if settled is None:
        return _FIELD_REDACTED
    encoded = json.dumps(written, ensure_ascii=False)[1:-1]
    if settled == written and encoded == written and scrub_control_chars(written) == written:
        return written
    # Spelled as the line will be, so an escape splits words here as it does in the readings.
    shown = scrub_control_chars(json.dumps(settled, ensure_ascii=False)[1:-1])
    member = json.dumps({key: written}, ensure_ascii=False)
    if not all(_shows_no_more(shown, _line_words(r)) for r in sink_readings(member)):
        return _FIELD_REDACTED
    return settled


def _finished_detail(detail: str) -> str:
    """``detail`` scrubbed and bounded for the line. It keeps its bound note, and where the
    :func:`~messagefoundry.redaction.safe_text` form parses as JSON the result parses too."""
    # safe_text(head) + note is safe_text(detail); the note is kept for a scrubbed detail.
    head, note = safe_text_bound(detail)
    bounded = safe_text(head) + note
    kept = _scrub_field(detail, detail=True)
    # Judged before safe_text bounds it: the bound's own "(+N chars)" is not text of the value.
    scrubbed = _finished("detail", head, head if kept is detail else kept)
    if scrubbed == _FIELD_REDACTED:
        return _bounded_detail(_FIELD_REDACTED, note, bounded)
    shipped = bounded if scrubbed == head else _bounded_detail(scrubbed, note, bounded)
    final = _settled(shipped)
    if final is None:
        return _bounded_detail(_FIELD_REDACTED, note, bounded)
    if _parses(bounded) and not _parses(final):
        return json.dumps(_FIELD_REDACTED)
    return final


def _tee_line(record: dict[str, object]) -> FinishedAuditLine:
    """``record`` as the finished line, no longer than the handler chain's redaction window.

    The chain bounded the whole line, and it no longer reads this one, so the bound moves here.
    A line over the window has its longest text field cut, with the clamp's note, until it fits.
    Each field stays present, so the line still parses and keeps its anchors."""
    fields = dict(record)
    for _ in _TEXT_FIELDS:
        line = FinishedAuditLine(json.dumps(fields, ensure_ascii=False))
        excess = len(line) - _REDACT_WINDOW
        if excess <= 0:
            return line
        key = max(_TEXT_FIELDS, key=lambda k: len(str(fields[k] or "")))
        value = str(fields[key] or "")
        cut = clamp_untrusted(value, window=max(len(value) - excess, 0))
        fields[key] = cut if len(cut) < len(value) else _FIELD_REDACTED
    line = FinishedAuditLine(json.dumps(fields, ensure_ascii=False))
    if len(line) <= _REDACT_WINDOW:
        return line
    hidden = {k: _FIELD_REDACTED for k in _TEXT_FIELDS if record[k] is not None}
    return FinishedAuditLine(json.dumps({**record, **hidden}, ensure_ascii=False))


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
    """Tee a just-persisted ``audit_log`` record off-box as metadata (sec-offbox-log, ASVS 16.x).
    Emits actor / action / channel / client address / timestamp / chain anchor plus a best-effort
    **redacted** ``detail`` to the ``messagefoundry.audit`` logger; the copy is not PHI-free
    (BACKLOG #1133).

    ``seq`` and ``row_hash`` are the just-committed row's sequence number and its chain hash -- the
    ANCHOR fields (BACKLOG #1198). ``seq`` is the row's position in the chain and is inside its MAC,
    so it is the SAME number ``audit-anchor`` prints and ``audit-verify`` takes: a collector's last
    ``seq`` and ``row_hash`` can be passed back as an anchor unchanged (vault BACKLOG #2594). They
    are required, not optional: an anchor that could be omitted silently would make an off-box copy
    with no anchor indistinguishable from one whose writer chose not to send it. ``row_id`` is the
    row's primary key, sent so a reader can find the row; it is not a chain coordinate, and it may
    skip numbers where ``seq`` never does. None of the three carries PHI directly or discloses a key:
    two are counters and ``row_hash`` is a digest, or on a keyed chain an HMAC.

    **One residual, stated because "the head hash carries nothing" is too strong.** In
    the keyless posture ``row_hash`` is a plain SHA-256 over a canonical list. So a reader of the
    log can TEST guesses offline, one hash per guess (``seq`` travels in the record too).
    The same holds for at least any field the C0 scrub below rewrote or shipped as
    ``[redacted]``, ``actor`` included.
    It does not arise for a row written by a process that holds a key, where the digest is
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
    is forwarded verbatim unless it holds a C0 control, which the field scrub below can rewrite or
    hide as ``[redacted]`` — it is an infrastructure identifier, not message content, and the whole point
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

    **Each field is scrubbed, then the record is serialized, and no filter rewrites the result
    (BACKLOG #5649).** A failed sign-in sets ``actor`` to the typed name, so a client chooses its
    characters. The handler filters read a line as plain text, so a span they redacted could take a
    closing quote with it: a typed name of ``password=`` or ``a|b|c`` broke the document, and every
    handler re-ran them over the one shared record. So ``action``, ``actor``, ``channel_id``,
    ``client`` and ``detail`` each go through the same text passes here (:func:`_finished`), and
    the line is a :class:`~messagefoundry.logging_setup.FinishedAuditLine`, which the handlers' text
    passes leave alone on this logger. Its control characters are escaped when it is built, with
    escapes valid inside a JSON string (:mod:`messagefoundry.controlchars`). A fault in the scrub
    hides the text fields whole and never ships them raw.

    **A C0 control in a text field is read before it is encoded (BACKLOG #3045).** ``json.dumps``
    escapes the 32 C0 controls, and each escape ends in a word character, so a pattern needing a
    word boundary or whitespace would miss the text beside one. :func:`_scrub_field` says how the
    field is read. What the field scrub leaves, at least:

    * A control only past the scanned window is not seen.
    * All controls in a value are read the same way, as a space or as nothing, so text that needs
      one read each way is missed. The tests pin one such case as a strict xfail.
    * A pattern that misses the text with a space, or nothing, in the control's place misses it
      here too. A control the patterns read as whitespace, at least tab, LF and CR, is not
      removed in either reading, so inside a word it splits the word, as on a plain log line.
    * The comparisons count words, runs of letters and digits, so punctuation can ship.
    * A field holding a control can ship whole as ``[redacted]``, so a client can make its own
      typed sign-in name ship that way.
    * In a JSON ``detail``, an escape is decoded only where it spells a C0 control, one level deep,
      and where the detail parses as JSON within the bound and holds no raw control.

    **Fields are read one at a time.** A pattern that would have needed text from two fields of
    the line no longer sees them together, so a value split across two fields is not redacted as
    one. The line is bounded by :func:`_tee_line`. A reader that re-redacts the stored line as
    text, such as ``GET /logs/tail`` or a support bundle, is outside this guarantee.

    Best-effort: a logging failure must never fail the audit write (already committed), so it is
    caught and logged, not raised. Callers invoke this **after commit** and **outside any write
    lock/transaction**, so a synchronous syslog send can't block the event loop under a lock."""
    texts: dict[str, str | None] = {
        "action": action,
        "actor": actor,
        "channel_id": channel_id,
        "client": client,
    }
    try:
        scrubbed: dict[str, str | None]
        try:
            scrubbed = {
                k: None if v is None else _finished(k, v, _scrub_field(v)) for k, v in texts.items()
            }
            # PHI chokepoint: redact HL7-shaped content + bound length before it ships off-box.
            # ``is None``, not truthiness: the chain's MAC tells "" from None, so the copy must.
            scrubbed["detail"] = None if detail is None else _finished_detail(detail)
        except Exception as exc:  # noqa: BLE001 - no filter reads this line, so never ship it raw
            _log_scrub_fault(exc)
            scrubbed = {
                k: None if v is None else _FIELD_REDACTED
                for k, v in {**texts, "detail": detail}.items()
            }
        line = _tee_line(
            {
                "event": "audit",
                "ts": ts,
                "action": scrubbed["action"],
                "actor": scrubbed["actor"],
                "channel_id": scrubbed["channel_id"],
                "client": scrubbed["client"],
                # Anchor fields (BACKLOG #1198): the row's position in the chain and its head hash.
                # Discrete fields so a SIEM can index them without parsing the redacted blob. See
                # the docstring for what they close and what the default transport leaves open.
                "row_id": row_id,
                "seq": seq,
                "row_hash": row_hash,
                "detail": scrubbed["detail"],
            }
        )
        # Inside the guard: a sink that cannot be built must not fail the caller's audit write either.
        ensure_logger_sink(audit_logger)
        audit_logger.info(line)
    except Exception as exc:  # noqa: BLE001 — the audit row is durable; the off-box tee is best-effort
        # Once per process, and never naming the row (BACKLOG #1131). A line per failed row named
        # its action, and its COUNT tracked the rows, the hidden lock rows included; ``GET
        # /logs/tail`` serves this log to ``logs:view``, which the Operator holds without
        # ``users:manage``. The first failure is what an operator needs: the sink is broken, and
        # every row is still in the store's ``audit_log``. The exception's type only: its message
        # and a traceback's source lines can carry text the filters do not catch (BACKLOG #5649).
        global _TEE_FAILURE_LOGGED
        if not _TEE_FAILURE_LOGGED:
            _TEE_FAILURE_LOGGED = True
            log.warning(
                "off-box audit tee failed (%s); the rows are still in the audit_log table, and "
                "further tee failures in this process are not logged",
                type(exc).__name__,
            )
    # After the tee, so an observer fault cannot cost the off-box copy. Each is guarded on its own.
    for observer in _OBSERVERS:
        try:
            observer(action, actor, channel_id, client, detail)
        except Exception as exc:  # noqa: BLE001 - the row is durable; an observer is best-effort
            # Once per process and never the action, for the reason the tee's handler above gives:
            # a line per row would count the hidden lock rows for `logs:view` (#1131).
            global _OBSERVER_FAILURE_LOGGED
            if not _OBSERVER_FAILURE_LOGGED:
                _OBSERVER_FAILURE_LOGGED = True
                log.warning(
                    "an audit observer failed (%s); further observer failures in this process are "
                    "not logged",
                    type(exc).__name__,
                )
