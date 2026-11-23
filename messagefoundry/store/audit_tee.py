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

from messagefoundry.logging_setup import (
    AUDIT_LOGGER_NAME,
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


#: The keys of a JSON ``detail`` whose values the tee withholds, in the objects
#: :func:`_withhold_detail` reaches; its docstring names at least what it misses. ``recovery_wrap`` is
#: the store master key wrapped under the recovery key, which a host-provider store's genesis row
#: keeps (``store.store.audit_genesis_detail``). The row keeps it, behind the audit read gates; the
#: tee's copy does not. ``tests/test_audit_tee_recovery_wrap.py`` holds this name to the writer's.
_WITHHELD_DETAIL_FIELDS = frozenset({"recovery_wrap"})
#: The action of the audit chain's genesis and range rows, ``store.store.AUDIT_KEY_EPOCH_ACTION``,
#: which only the engine writes. Only these rows' details are withheld from. A literal, since
#: ``store.store`` imports this module; ``tests/test_audit_tee_recovery_wrap.py`` holds it to the
#: constant.
_KEY_EPOCH_ACTION = "audit.key_epoch"
#: What a withheld value ships as, so a reader sees the field exists.
_DETAIL_WITHHELD = "<withheld>"
#: What a ``detail`` ships as, whole, when withholding a field in it faults.
_DETAIL_WITHHELD_WHOLE = json.dumps({"withheld": _DETAIL_WITHHELD})
#: What a field scrubbed whole is shipped as: the redactor's own placeholder.
_FIELD_REDACTED = _REDACTED


#: Whether this process has logged a fault while withholding; see :func:`_withhold_detail`.
_WITHHOLD_FAULT_LOGGED = False


def _names_a_withheld_field(text: str) -> bool:
    return any(name in text for name in _WITHHELD_DETAIL_FIELDS)


def _withhold_detail(detail: str | None) -> str | None:
    """``detail`` as the tee may copy it: where it is JSON holding a withheld key in any object it
    nests, with each such key's value as :data:`_DETAIL_WITHHELD`, and otherwise unchanged.

    The text is parsed only where it holds a withheld field's name, and re-encoded only where a
    value was replaced, by ``json.dumps``'s defaults. That is the genesis writer's encoder, and the
    parse keeps its sorted key order; another writer's separators or number forms can change. An
    object's string value that is itself such a JSON text, and a detail that is a JSON string
    holding one, is withheld the same way. What is not matched includes at least a key spelled
    with a JSON escape, unless the name also appears unescaped elsewhere in the text, a JSON text
    held in a string inside a list or in an object key, and text that strict JSON parsing refuses, such as one with a raw control character, a byte order mark or trailing text;
    no engine writer writes the wrap in any of those. Any other fault, such as a nest too deep to
    read or an integer too long to parse, ships the text being read as
    :data:`_DETAIL_WITHHELD_WHOLE`, since the value may still be in it: the whole detail, or, for
    a fault in a JSON text held in a string value, that value. It is logged once per process. A
    detail longer than the redaction window, :data:`~messagefoundry.redaction._REDACT_WINDOW`, that
    holds a withheld field's name is not parsed, and ships whole as withheld."""
    if not detail or not _names_a_withheld_field(detail):
        return detail
    if len(detail) > _REDACT_WINDOW:
        # Bound the work as the other passes are: a longer detail naming a field is not parsed.
        return _DETAIL_WITHHELD_WHOLE
    changed = False

    def hook(obj: dict[str, object]) -> dict[str, object]:
        nonlocal changed
        for key, value in obj.items():
            if key in _WITHHELD_DETAIL_FIELDS:
                obj[key], changed = _DETAIL_WITHHELD, True
            elif isinstance(value, str) and (inner := _withhold_detail(value)) is not value:
                obj[key], changed = inner, True
        return obj

    try:
        try:
            parsed = json.loads(detail, object_hook=hook)
        except json.JSONDecodeError:  # not JSON; an over-long integer is a plain ValueError
            return detail
        if isinstance(parsed, str) and (inner := _withhold_detail(parsed)) is not parsed:
            parsed, changed = inner, True
        return json.dumps(parsed) if changed else detail
    except Exception as exc:  # noqa: BLE001 - fail closed; the tee must still ship the record
        global _WITHHOLD_FAULT_LOGGED
        if not _WITHHOLD_FAULT_LOGGED:
            _WITHHOLD_FAULT_LOGGED = True
            log.warning(
                "the audit tee could not withhold a field in a detail (%s); the text it was "
                "reading ships whole as withheld, and further such faults in this process are not "
                "logged",
                type(exc).__name__,
            )
        return _DETAIL_WITHHELD_WHOLE


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
#: Whether this process has logged a fault that ships the line before #3045; see
#: :func:`_log_line_fault`.
_LINE_SCRUB_FAULT_LOGGED = False
#: The reasons for shipping a record as the line before #3045 that this process has logged, so
#: a warning naming none but these is not logged again; see :func:`_tee_line`.
_OLD_LINE_REASONS_LOGGED: set[str] = set()
_SHOWS_A_WORD = "show a word the line before it hid"
_UNPARSED = "leave a sink's reading unparseable where the line before it parsed"


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
    own window cut off. Where ``old``, the detail the line before #3045 shipped, parses as JSON
    and the bounded result does not, it ships as the JSON string ``"[redacted]"`` instead."""
    shipped = safe_text(kept, note=note)
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
    whole field is returned. :func:`_tee_line` chooses what ships."""
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
    """Log a fault in the C0 field scrub once per process, by type and never with the value."""
    global _FIELD_SCRUB_FAULT_LOGGED
    if not _FIELD_SCRUB_FAULT_LOGGED:
        _FIELD_SCRUB_FAULT_LOGGED = True
        log.warning(
            "the audit tee's field scrub failed (%s); the field is hidden whole, unless the "
            "record then ships as the line before the scrub, and further faults in this process "
            "are not logged",
            type(exc).__name__,
        )


def _log_line_fault(exc: Exception) -> None:
    """Log a fault that ships a record as the line before #3045, once per process, by type and
    never with the value. Apart from :func:`_log_scrub_fault`, a fault in one field's scrub."""
    global _LINE_SCRUB_FAULT_LOGGED
    if not _LINE_SCRUB_FAULT_LOGGED:
        _LINE_SCRUB_FAULT_LOGGED = True
        log.warning(
            "the audit tee's C0 scrub failed (%s); the record ships without it, as the line "
            "before the scrub, and further such faults in this process are not logged",
            type(exc).__name__,
        )


def _tee_line(
    before: dict[str, object],
    after: dict[str, object],
    whole_detail: Callable[[], str] = lambda: _FIELD_REDACTED,
) -> str:
    """The line to log for a record whose fields the C0 scrub turned from ``before`` into
    ``after`` (BACKLOG #3045). ``before`` is the record as the code before #3045 built it, the old
    line. A scrubbed candidate ships only if its reading parses as JSON on each sink where the old
    line's did.

    The candidates, in order: the line with every scrubbed field; the old line with each changed
    field as :data:`_FIELD_REDACTED` and a changed ``detail`` as what ``whole_detail`` returns;
    then the old line. A sink's reading is :func:`~messagefoundry.logging_setup.sink_readings`, a
    model, not the formatter's output. Where the scrubbed candidates fail, a warning names why the
    last one failed, unless this process has logged each of those reasons. On a fault the old
    line ships."""
    old_line = json.dumps(before, ensure_ascii=False)
    if after == before:
        return old_line
    try:
        # Only a changed detail calls whole_detail; a fault building it ships the old line.
        whole = {
            k: v if after[k] == v else whole_detail() if k == "detail" else _FIELD_REDACTED
            for k, v in before.items()
        }
        bars = [(_line_words(r), _parses(r)) for r in sink_readings(old_line)]
        candidates = (after,) if whole == after else (after, whole)
        reasons: list[str] = []
        for candidate in candidates:
            line = json.dumps(candidate, ensure_ascii=False)
            paired = list(zip(sink_readings(line), bars, strict=True))
            shows = not all(_shows_no_more(r, words) for r, (words, _) in paired)
            # Only the last checked candidate's reasons are reported, so an earlier one that shows
            # a word is rejected without its parses.
            if shows and candidate is not candidates[-1]:
                continue
            unparsed = not all(not parsed or _parses(r) for r, (_, parsed) in paired)
            if not (shows or unparsed):
                return line
            # The last checked candidate's reasons are the ones that ship the old line.
            reasons = [_SHOWS_A_WORD] if shows else []
            if unparsed:
                reasons.append(_UNPARSED)
    except Exception as exc:  # noqa: BLE001 - the tee must still ship the record
        _log_line_fault(exc)
        return old_line
    if not _OLD_LINE_REASONS_LOGGED.issuperset(reasons):
        _OLD_LINE_REASONS_LOGGED.update(reasons)
        log.warning(
            "an off-box audit record shipped without the C0 field scrub, because hiding its "
            "changed fields whole would still %s; later cases are logged only where they name "
            "a reason not yet logged in this process",
            " and ".join(reasons),
        )
    return old_line


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

    **A withheld field ships as a placeholder (owner ruling 2026-11-22).** On a row whose
    ``action`` is :data:`_KEY_EPOCH_ACTION`, which only the engine writes, where ``detail`` is JSON
    holding a key in :data:`_WITHHELD_DETAIL_FIELDS` in an object it nests, that key's value ships
    as ``<withheld>``, before the passes below read it. The genesis row of a store minted under
    ``[store].key_provider = "host"`` holds one, ``recovery_wrap``. The row in ``audit_log`` keeps
    the value, and the observers are passed it. :func:`_withhold_detail` names at least what it
    does not match, and says what a fault there ships. Any other row's ``detail`` is not read for
    this, so it ships as it did before the placeholder existed.

    **The record survives the scrub, and the scrub is what makes it so.** A failed sign-in sets
    ``actor`` to the typed name, so a client chooses its characters. ``ControlCharScrubFilter``
    runs last on every configured handler, and since vault BACKLOG #3012 every escape it writes is
    valid inside a JSON string (:mod:`messagefoundry.controlchars` says why). So this serializes
    with plain ``json.dumps`` and adds no escaping of its own. The first handler's filters see each
    character of the record unescaped, except those ``json.dumps`` must escape in a string: the
    quote, the backslash and the 32 C0 controls, U+0000 to U+001F. Escaping more here, BEFORE the
    redaction and credential filters, hid a name or a password from them: an escape such as
    ``\\u007f`` ends in a word character, so ``\\b``-anchored patterns no longer matched the next
    word. ``ensure_ascii=True`` is the same mistake, for every non-ASCII character.

    **A C0 control in a text field is scrubbed before it is encoded (BACKLOG #3045).**
    ``json.dumps`` escapes the 32 C0 controls, and each escape ends in a word character, as
    ``\\u0001`` and ``\\t`` do, so a pattern that needs a word boundary or whitespace missed the
    text beside one when only the handler chain ran. So ``action``, ``actor``, ``channel_id``,
    ``client`` and ``detail`` are first scrubbed by the same text passes where they hold a C0
    control in the window :func:`_scrub_field` scans. :func:`_scrub_field` says how, and
    :func:`_tee_line` chooses the line that ships. What that leaves, at least:

    * A control only past the scanned window is not seen.
    * All controls in a value are read the same way, as a space or as nothing, so text that needs
      one read each way is missed. The tests pin one such case as a strict xfail.
    * A pattern that misses the text with a space, or nothing, in the control's place misses it
      here too. A control the patterns read as whitespace, at least tab, LF and CR, is not
      removed in either reading, so inside a word it splits the word, as on a plain log line.
    * The comparisons count words, runs of letters and digits, so punctuation the old line hid
      can ship.
    * A field holding a control can ship whole as ``[redacted]``, so a client can make its own
      typed sign-in name ship that way. A record can ship as the line before #3045, losing the
      scrub; a segment-shaped token such as ``ABC|`` after a control in a field can cause that,
      so a client can turn the scrub off for its own record.
    * A record whose line is longer than the handler chain's redaction window can ship the line
      from before #3045, losing the C0 field scrub. At least a large ``action``, ``actor``,
      ``channel_id`` or ``client`` can make one.
    * In a JSON ``detail``, an escape is decoded only where it spells a C0 control, one level deep,
      and where the detail parses as JSON within the bound and holds no raw control. Elsewhere,
      as for ``\\u00a0``, the text beside an escape is read by the handler chain alone.

    **At least two residuals remain, and both can break the JSON a collector receives.** The
    first can also alter it silently.

    * The redaction and credential filters rewrite spans of this document as text, and a span can
      take a closing quote with it. A typed name of ``password=`` or ``a|b|c`` does that on every
      sink, with no escaped character involved. When two fields carry attacker-influenced text,
      the document can instead still parse, with the fields between them missing. Those can be
      at least ``channel_id``, ``client``, ``detail`` and the row anchors. A field that survives,
      such as ``actor``, can then carry another field's text. The field scrub adds a case: a
      credential placeholder it writes just before an escape can be taken, with the escape's
      backslash, as one credential value, and a quote that backslash escaped then ends the string.
      :func:`_tee_line` checks the parse only on the modelled sinks.
    * Every handler re-filters the one shared ``LogRecord``, so the file handler and the forwarder
      run the chain again over the first handler's escaped text (``_install_phi_filters``). Then
      ``x%7Cy%7Cz`` followed by DEL, or by U+2028, parses on stdout and not on the later sinks,
      the forwarder included. ``tests/test_audit_offbox_tee.py`` pins that as a strict xfail.

    Running the chain once per record, rather than once per handler, would close the second. The
    first needs filters that do not rewrite this document as plain text.

    Best-effort: a logging failure must never fail the audit write (already committed), so it is
    caught and logged, not raised. Callers invoke this **after commit** and **outside any write
    lock/transaction**, so a synchronous syslog send can't block the event loop under a lock."""
    # On the engine's key epoch rows only, the line copies the row's detail with any withheld
    # field's value replaced, before any other pass reads it. Every other row's detail is not read
    # for withholding, so text a client writes cannot use this pass to change its copy; the C0
    # field scrub below still can. The observers below are passed the row's own.
    tee_detail = detail
    if action == _KEY_EPOCH_ACTION:
        try:
            tee_detail = _withhold_detail(detail)
        except Exception:  # noqa: BLE001 - its fault warning can raise; the row is committed
            tee_detail = _DETAIL_WITHHELD_WHOLE
    # safe_text(head, note=note) is safe_text(tee_detail); the note is kept for a scrubbed detail.
    head, note = safe_text_bound(tee_detail) if tee_detail else ("", "")
    old_detail = safe_text(head, note=note)
    texts: dict[str, str | None] = {
        "action": action,
        "actor": actor,
        "channel_id": channel_id,
        "client": client,
    }
    record: dict[str, object] = {
        "event": "audit",
        "ts": ts,
        **texts,
        # Anchor fields (BACKLOG #1198): the row's position in the chain and its head hash. Discrete
        # fields so a SIEM can index them without parsing the redacted blob. See the docstring for
        # what they close and what the default transport leaves open.
        "row_id": row_id,
        "seq": seq,
        "row_hash": row_hash,
        # PHI chokepoint: redact HL7-shaped content + bound length before it ships off-box.
        "detail": old_detail if tee_detail else None,
    }
    try:
        # Each text field is scrubbed before json.dumps escapes a C0 control in the window it
        # scans (#3045).
        try:
            scrubbed: dict[str, object] = {k: _scrub_field(v) for k, v in texts.items()}
            if tee_detail:
                kept = _scrub_field(tee_detail, detail=True)
                scrubbed["detail"] = (
                    old_detail if kept is tee_detail else _bounded_detail(kept, note, old_detail)
                )
            # A detail hidden whole keeps its bound note, and its JSON-ness where it parsed before.
            # Built lazily, so a record whose detail the scrub left alone never pays for it.
            line = _tee_line(
                record,
                {**record, **scrubbed},
                lambda: _bounded_detail(_FIELD_REDACTED, note, old_detail),
            )
        except Exception as exc:  # noqa: BLE001 - a scrub fault ships the line before #3045
            _log_line_fault(exc)
            line = json.dumps(record, ensure_ascii=False)
        # Inside the guard: a sink that cannot be built must not fail the caller's audit write either.
        ensure_logger_sink(audit_logger)
        # Not ensure_ascii, and no escaping here: see "The record survives the scrub" above.
        audit_logger.info(line)
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
