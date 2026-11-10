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

from messagefoundry.controlchars import json_unicode_escape
from messagefoundry.logging_setup import AUDIT_LOGGER_NAME, ensure_logger_sink, scrub_log_text
from messagefoundry.redaction import _REDACTED, clamp_untrusted, safe_text
from messagefoundry.secretscrub import CREDENTIAL_PLACEHOLDER

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
#: A raw C0 control, U+0000 to U+001F: exactly what ``json.dumps`` escapes, so DEL and the rest
#: of the log alphabet in :mod:`messagefoundry.controlchars` are deliberately not in it.
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
#: The two placeholders the passes write, which are not text of the value.
_PLACEHOLDERS = re.compile(re.escape(_FIELD_REDACTED) + "|" + re.escape(CREDENTIAL_PLACEHOLDER))
#: A run of letters or digits: a word, for the check in :func:`_scrub_field`.
_WORD = re.compile(r"[^\W_]+")
#: Whether this process has logged a field scrub fault; see :func:`_scrub_field`.
_FIELD_SCRUB_FAULT_LOGGED = False


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


def _line_words_of_line(line: str) -> Counter[str]:
    """As :func:`_line_words`, for text that is already the line's encoding."""
    return Counter(_WORD.findall(_LINE_ESCAPE.sub(" ", _PLACEHOLDERS.sub(" ", line))))


def _line_words(text: str) -> Counter[str]:
    """The words ``text`` shows on the tee line, where ``json.dumps`` has encoded it: each JSON
    escape, however many backslashes encode it, read as a break."""
    return _line_words_of_line(json.dumps(text, ensure_ascii=False)[1:-1])


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


def _encode_c0(text: str) -> str:
    """The inverse of :func:`_decode_c0_escapes`, for a text that held no raw control before it."""
    return _RAW_C0.sub(lambda m: json_unicode_escape(ord(m.group())), text)


@overload
def _scrub_field(value: str, *, detail: bool = False) -> str: ...
@overload
def _scrub_field(value: None, *, detail: bool = False) -> None: ...
def _scrub_field(value: str | None, *, detail: bool = False) -> str | None:
    """One tee field, scrubbed by the handlers' text passes before ``json.dumps`` escapes a C0
    control in it (BACKLOG #3045). A value with no C0 control in the part the handler chain scans
    (:func:`~messagefoundry.redaction.clamp_untrusted`'s window) is returned unchanged.

    Otherwise the value, cut to that window, is scrubbed as written, which the patterns read with
    a control as a break, as they read any non-word character. Then two readings, every control
    as a space, and every control the patterns do not read as whitespace removed (:func:`_read`),
    are scrubbed, each taken from that plain result and, where the plain pass changed anything,
    from the value. A reading of the plain result has found more when it shows fewer of its
    letters and digits; a reading of the value, which can also show what the plain result hid,
    when it does not show every word the plain result shows, equal words counted apart. If one
    has, the whole field ships as :data:`_FIELD_REDACTED`: a reading changes the text's length,
    so its redactions cannot be merged into the plain result without mapping spans between the
    two texts, and that mapping is where an earlier design of this fix leaked. The word check
    also fires where a removed control glues a kept word to a redacted one, so it can cost a
    field that hid nothing more.

    Otherwise, where the plain result changed nothing, the value itself ships, so its line is the
    line before this scrub and the handler chain treats it as it did. Where the plain result
    changed something, it ships only if it hides every word the handler chain alone hides over the
    value as the line carries it, encoded. The plain pass can read a span differently from that
    chain, as a name run that takes a ``Bearer`` label with it and leaves the token, and where it
    does the whole field ships as :data:`_FIELD_REDACTED` instead.

    So, at least, the whole field ships as :data:`_FIELD_REDACTED` where a reading found more,
    where the plain result shows a word the chain alone hides, and on a fault; a JSON ``detail``
    ships as the JSON string ``"[redacted]"`` in those cases and where the passes leave it
    unparseable.

    With ``detail``, where the value parses as JSON and holds no raw control, which is how most
    writers hand ``detail`` over, each JSON escape that spells a C0 control is decoded to the
    control first and encoded again after, read left to right so an escaped backslash is never
    half of one. Such a ``detail`` that the passes leave unparseable ships as the JSON string
    ``"[redacted]"``, as it does on a fault; any other field ships as :data:`_FIELD_REDACTED` on a
    fault.
    :func:`emit_audit_tee` states what this covers and what it leaves."""
    if value is None:
        return None
    as_json = False
    try:
        probe = clamp_untrusted(value)
        if probe is not value:  # the cut appends its note after a newline of its own
            probe = probe[: probe.rfind("\n")]
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
        # No less than before: the handler chain alone, over the value as the line carried it,
        # must hide every word this result hides. The plain pass can redact a span the chain
        # read differently, a name run that takes a ``Bearer`` label with it, and leave the
        # credential the chain would have caught.
        alone = scrub_log_text(json.dumps(written, ensure_ascii=False)[1:-1])
        return result if _line_words(result) <= _line_words_of_line(alone) else whole
    except Exception as exc:  # noqa: BLE001 - fail closed; the tee must still ship the record
        global _FIELD_SCRUB_FAULT_LOGGED
        if not _FIELD_SCRUB_FAULT_LOGGED:
            _FIELD_SCRUB_FAULT_LOGGED = True
            log.warning(
                "the audit tee's field scrub failed (%s); the field ships redacted, and further "
                "faults in this process are not logged",
                type(exc).__name__,
            )
        return json.dumps(_FIELD_REDACTED) if as_json else _FIELD_REDACTED


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

    **One residual, stated because "the head hash carries nothing" is very slightly too strong.** In
    the keyless posture ``row_hash`` is a plain SHA-256 over a canonical list whose every other
    member -- the previous row's hash, ``ts``, ``actor``, ``action``, ``channel_id``, ``client`` --
    travels in this same record or the one before it. So for a record whose ``detail`` ``safe_text``
    actually cut, a reader of the log can TEST guesses at the removed span offline, one hash per guess
    (``seq`` travels in the record too). The same holds for any field the C0 scrub below cut or
    shipped as ``[redacted]``, ``actor`` included, such as a typed sign-in name.
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
    valid inside a JSON string (:mod:`messagefoundry.controlchars` says why). So this serializes
    with plain ``json.dumps`` and adds no escaping of its own. The first handler's filters see each
    character of the record unescaped, except those ``json.dumps`` must escape in a string: the
    quote, the backslash and the 32 C0 controls, U+0000 to U+001F. Escaping more here, BEFORE the
    redaction and credential filters, hid a name or a password from them: an escape such as
    ``\\u007f`` ends in a word character, so ``\\b``-anchored patterns no longer matched the next
    word. ``ensure_ascii=True`` is the same mistake, for every non-ASCII character.

    **A C0 control beside a name or a credential no longer hides it, in the cases measured
    (BACKLOG #3045).** ``json.dumps`` escapes the 32 C0 controls, and each escape ends in a word
    character, as ``\\u0001`` and ``\\t`` do, so a pattern that needs a word boundary or
    whitespace missed the text on either side when only the handler chain ran. So each text field,
    ``action``, ``actor``, ``channel_id``, ``client`` and ``detail``, is first scrubbed by the same
    text passes before it is encoded, wherever it holds a C0 control; :func:`_scrub_field` says
    how. ``tests/test_audit_offbox_tee.py`` sweeps all 32 code points, placed at least before,
    after and inside a name, a ``password=`` or ``token=`` value, a date, a bearer token, an MRN
    and an HL7-shaped run, in each of those fields, and ``detail`` as a JSON document too. It finds
    no leak there, and no word the handler chain alone hid comes back. What that leaves, at least:

    * Every control in a value is read the same way, as a space or as nothing. Text that needs one
      control read as a space and another as nothing, such as a date split by two controls after a
      word glued to it by a third, is missed by every reading and ships beside its escapes. The
      tests pin one such case as a strict xfail.
    * A pattern that misses the same text with a space, or nothing, in the control's place misses
      it here too.
    * Where a reading finds more than the plain passes, the whole field ships as ``[redacted]``, so
      that record loses its ``actor`` or its ``detail``. A typed sign-in name of ``CORP`` and
      ``JONES`` joined by a control is one: it reads as the two-word name the patterns redact.
      A client can use this on purpose: a failed sign-in sets ``actor`` to the typed name, so a
      client that types a control beside a name- or credential-shaped word makes its own typed
      name ship as ``[redacted]`` in the off-box copy, and that copy then holds no typed name to
      attribute the attempt by. The ``client`` address and the rest of the record still ship.
      ``detail`` is scrubbed before ``safe_text`` bounds it, so that holds for a control
      anywhere in the scanned window, even in text past the 200 characters that would ship.
    * The comparisons that decide it count words, runs of letters and digits, so a redaction that
      hides only punctuation is not counted, and a reading of the plain result that hides some
      letters while showing others it hid is not seen.
    * A control the patterns read as whitespace, at least tab, LF, VT, FF, CR and U+001C to
      U+001F, is never read as nothing, because gluing two lines made names and dates that were
      not in the text. Inside a word it splits the word, as it does on any plain log line.
    * In a JSON ``detail``, only an escape that spells a C0 control is decoded. Most writers call
      ``json.dumps`` with its default ``ensure_ascii=True``, so a non-ASCII character, such as a
      no-break space between the parts of a name, arrives as an escape such as ``\\u00a0``,
      which ends in a word character too, and the text beside it is read by the handler chain
      alone, as before.
    * In ``detail``, a JSON escape is read as the control it spells only where the detail parses as
      JSON within the handler chain's bound and holds no raw control, which is how ``json.dumps``
      writes it. Elsewhere, at least a pretty-printed JSON detail or a longer one, the escape is
      read by the handler chain alone, as before.

    **At least two residuals remain, and both can break the JSON a collector receives.** The
    first can also alter it silently.

    * The redaction and credential filters rewrite spans of this document as text, and a span can
      take a closing quote with it. A typed name of ``password=`` or ``a|b|c`` does that on every
      sink, with no escaped character involved. When two fields carry attacker-influenced text,
      the document can instead still parse, with the fields between them missing. Those can be
      at least ``channel_id``, ``client``, ``detail`` and the row anchors. A field that survives,
      such as ``actor``, can then carry another field's text.
    * Every handler re-filters the one shared ``LogRecord``, so the file handler and the forwarder
      run the chain again over the first handler's escaped text (``_install_phi_filters``). Then
      ``x%7Cy%7Cz`` followed by DEL, or by U+2028, parses on stdout and not on the later sinks,
      the forwarder included. ``tests/test_audit_offbox_tee.py`` pins that as a strict xfail.

    Running the chain once per record, rather than once per handler, would close the second. The
    first needs filters that do not rewrite this document as plain text.

    Best-effort: a logging failure must never fail the audit write (already committed), so it is
    caught and logged, not raised. Callers invoke this **after commit** and **outside any write
    lock/transaction**, so a synchronous syslog send can't block the event loop under a lock."""
    record = {
        "event": "audit",
        "ts": ts,
        # Each text field is scrubbed before json.dumps escapes a C0 control in it (#3045).
        "action": _scrub_field(action),
        "actor": _scrub_field(actor),
        "channel_id": _scrub_field(channel_id),
        "client": _scrub_field(client),
        # Anchor fields (BACKLOG #1198): the row's position in the chain and its head hash. Discrete
        # fields so a SIEM can index them without parsing the redacted blob. See the docstring for
        # what they close and what the default transport leaves open.
        "row_id": row_id,
        "seq": seq,
        "row_hash": row_hash,
        # PHI chokepoint: redact HL7-shaped content + bound length before it ships off-box.
        "detail": safe_text(_scrub_field(detail, detail=True)) if detail else None,
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
