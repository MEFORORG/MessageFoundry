# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The control-character alphabets, each written once: the C0/DEL test (BACKLOG #1253) and the
wider log alphabet built on it (vault BACKLOG #2815). Beside them sits :func:`has_lone_surrogate`,
the other test a mail header value needs, which the C0/DEL test does not cover. The log alphabet
does cover it, through category ``Cs`` (vault BACKLOG #2842).

WHAT THIS REPLACES. ``ord(ch) < 0x20 or ord(ch) == 0x7F`` was written out seven times across six
files -- two in ``transports/fhir.py`` and one each in ``config/codeset_edit.py``,
``config/impact.py``, ``transports/dicomweb.py``, ``transports/remotefile.py`` and
``transports/rest.py``. Every copy agreed, so nothing was mis-screened. The cost was future-tense
and is the one #1239 named: a later hardening applied to one copy silently does not apply to the
rest, and nothing reports the omission.

THE REFUSALS STAY AT THEIR CALL SITES; THE PREDICATE AND THE NEUTRALISERS LIVE HERE. #1239 ruled
out "collapsing the call sites into one helper with a flag" because the differing wrappers are
appropriate: a raise suits a path context, a bool suits a filter, and the exceptions differ by layer
(``WiringError`` in config, a PHI-safe negative ACK in FHIR). So each call site keeps its own
refusal and its own message. A flag parameter would have re-created the coupling the item exists to
remove, one indirection further away. What a call site CANNOT sensibly keep its own copy of is the
alphabet, or a neutraliser derived from it -- so :func:`strip_control_chars` and
:func:`scrub_control_chars` are here beside :func:`has_control_char`, all three built on the one
predicate, which the escape widens. (This paragraph replaced a "shares the predicate, not the
action" thesis that its own module had already outgrown: a reader taking that literally puts the next neutraliser elsewhere,
which is how the escape table came to live in ``logging_setup``.)

THE NEUTRALISERS ARE DIFFERENT AND ONE MUST NEVER BE "SIMPLIFIED" INTO ANOTHER. Beside the
refusals, that makes three actions built on one predicate. QUOTE, a fourth, escapes by an
allowlist rather than by the predicate; its bullet below gives the encoding. The actions:

  * REJECT -- six sites. A control character in a value that reaches a URL path, a header, a
    filename or a config field is refused outright.
  * STRIP -- ``transports/rest.py`` only, on a message-derived header VALUE. That is defensible
    rather than a second instance of the mutation pattern the owner ruled against in #1238: that
    ruling turns on ``basename()`` converting a path into a valid-but-DIFFERENT target, handing an
    attacker a real file. A header value has no such property -- removing CR/LF cannot redirect a
    request anywhere -- and ``rest.py`` already REJECTS a header NAME failing its RFC 7230 token
    check. Name-rejected, value-stripped, which is principled. **"Only" is stale:** at least
    the toolkit's ``corepoint_import.py`` and the engine's ``uploads.py`` strip too. The upload
    filename is display-only and never locates a file, so the #1238 ruling does not reach it
    either.
  * ESCAPE -- every log line, :func:`scrub_control_chars`. Neither refuses nor deletes: it renders
    the code point as a readable backslash escape, so one record cannot become two. Its alphabet is
    WIDER than the other two arms' (vault BACKLOG #2815); :func:`_escapes_in_a_log_line` states it.
    Every escape it writes is also valid inside a JSON string (:func:`_log_escape`), so a
    document from ``json.dumps`` without ``indent`` still parses after it (vault BACKLOG #3012):
    that output holds no character of the alphabet outside a string. A document with a CR or LF
    between tokens, an indented one for example, does not, because ``\\n`` is not JSON there.
  * QUOTE -- one ``key=value`` field of a log line, :func:`log_field_token`. ESCAPE keeps a value on
    one line but leaves its spaces, quotes and ``=`` alone, so a value logged before another field
    can still write a field of its own. QUOTE writes everything but a safe alphabet as ``_uXXXX_``
    and wraps the result in quotes, so the value holds no space, quote, ``:`` or ``=`` with which to
    end its field or write another, nor any separator a handler filter's match needs to reach past
    its quotes (BACKLOG #3770). A filter may still rewrite a run of kept characters inside the
    field, a date for example. :func:`quote_log_text` is a separate JSON-quoted form for text
    printed to a terminal, such as a check line, which no handler filter reads; a credential scrub
    can close it early, so it is not for any text a handler filter reads, a last field or a whole
    message included. QUOTE changes the value's spelling, so it does not replace ESCAPE on a whole
    line.

WHY ESCAPE LIVES HERE, WHICH IS THE ONE FACT WORTH STATING ONCE (BACKLOG #1591). It was defined in
``logging_setup`` until ``logging_guard`` needed it, and ``logging_setup`` imports
``logging_guard`` -- so reaching upwards is a cycle and copying the table down is the two-copy drift
``_is_control_char`` below exists to close. This module imports only the standard library, so it is
the one place both can reach. Nothing else about that move is load-bearing; the other files cite
this paragraph.

DELIBERATELY NOT FOLDED IN. ``parsing/sniff.py``'s ``nontext_upload_reason`` counts the same code
points, but it is a different predicate. It works on bytes, not characters. It also subtracts its
own allowlist of controls a text file may carry. Folding it in would change its behaviour. The same
file's archive member-name check does import :func:`has_control_char`; only the density count is
carved out.

At least two more sites spell an overlapping range on purpose, and a widening here must not reach
them. This is not a survey of every such site; these two were read under BACKLOG #1273.

  * ``spreadsheet.py``'s ``_LEADING_NOISE`` is C0 plus DEL plus a zero-width/BOM family. It models
    what a spreadsheet importer drops before it judges a cell. That is a fact about importers, not
    about an injection alphabet. It has a harness mirror, and its own docstring says why.
  * ``transports/soap.py``'s ``_XML_ILLEGAL_RE`` is the C0 slice of XML 1.0's ``Char`` rule. It
    leaves out tab, LF and CR, and it has no DEL, which XML allows. That standard fixes the set.

THE POINT IS THE COPYING PRACTICE, not the seven known lines. If you need this test, import it.
"""

from __future__ import annotations

import unicodedata

#: The Unicode general categories a reader of TEXT may act on rather than show: the C0 and C1
#: controls and DEL (``Cc``), the bidirectional and other format controls (``Cf``), the line and
#: paragraph separators (``Zl``, ``Zp``), a lone surrogate (``Cs``), and the private-use and
#: unassigned code points (``Co``, ``Cn``), which this interpreter's Unicode tables cannot vouch
#: for. At least two rules escape these: the log (:func:`_escapes_in_a_log_line`) and
#: :mod:`messagefoundry.terminal_text`'s ``keep_printable_unicode`` mode, which imports it from
#: here. ``scripts/service/import-db-ca.ps1`` mirrors the set by hand, so change it there too.
#: Defined here, not there, so this module keeps importing nothing from the engine.
CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})


#: C0 controls (U+0000-U+001F) plus DEL (U+007F). NOT a general "is this printable" test: it is
#: deliberately blind to C1 (U+0080-U+009F) and to Unicode separators, because every call site
#: screens values destined for byte-oriented sinks -- a request line, a header, a path -- where C0
#: and DEL are the injection alphabet. Widening it is a behaviour change at seven call sites at
#: once, and at the log escape, which is built on it; that is exactly the leverage this module
#: exists to provide, so make it deliberately. The log is the one sink read back as TEXT, so it
#: escapes more than this; see :func:`_escapes_in_a_log_line`.
def _is_control_char(ch: str) -> bool:
    """THE ONE DEFINITION of the alphabet this module screens for (BACKLOG #1273).

    It was previously written out TWICE -- once in each public arm -- inside the module whose whole
    purpose is to state it once. The module docstring above records that this replaced the same
    expression written seven times across six files; it then kept two copies of its own.

    That is not a cosmetic duplication, and the risk is ASYMMETRIC -- measured on the two-copy
    structure before this change, not predicted:

    * widening the **predicate** arm alone was **CAUGHT** -- 4 tests red, because
      ``test_c1_and_unicode_separators_are_deliberately_NOT_caught`` pins the alphabet directly;
    * widening the **strip** arm alone was **NOT CAUGHT** -- 47 passed, exit 0.

    So the copies were partly bound and partly not, and the unguarded direction is the one that
    matters: **widening the alphabet is the stated reason this module exists** ("a behaviour change
    at seven call sites at once ... make it deliberately"), and a deliberate widening applied to the
    neutraliser would silently strip more than the screen refuses -- a screen and its neutraliser
    disagreeing about their own alphabet, with every test green.

    One definition closes both directions by construction rather than by a test noticing.
    """
    return ord(ch) < 0x20 or ord(ch) == 0x7F


def has_control_char(text: str) -> bool:
    """True if ``text`` contains any C0 control character or DEL."""
    return any(_is_control_char(ch) for ch in text)


def _is_surrogate(code: int) -> bool:
    """True for a surrogate code point, U+D800 to U+DFFF: the one statement of that range here."""
    return 0xD800 <= code <= 0xDFFF


def has_lone_surrogate(text: str) -> bool:
    """True if ``text`` holds a surrogate code point (U+D800 to U+DFFF), which strict UTF-8 cannot
    write. That includes each half of an adjacent pair, which ``str`` holds as two code points only
    after a ``surrogatepass`` decode or an escape. TOML refuses one, but at least Python config and
    an environment value can carry one: a ``surrogateescape`` decode makes U+DC80 to U+DCFF.
    :func:`has_control_char` passes it, so a mail header needs both tests (vault BACKLOG #2842). In
    a header most surrogates raise ``UnicodeEncodeError`` at build; U+DC80 to U+DCFF go out as a
    garbled ``unknown-8bit`` word."""
    return any(_is_surrogate(ord(ch)) for ch in text)


def strip_control_chars(text: str) -> str:
    """``text`` with every C0 control and DEL removed.

    The strip arm, used where a value must be neutralised rather than refused. See the module
    docstring: this is NOT the general remedy and must not be substituted for a rejection.
    """
    return "".join(ch for ch in text if not _is_control_char(ch))


def _escapes_in_a_log_line(ch: str) -> bool:
    """THE LOG ALPHABET, the one statement of it (vault BACKLOG #2815): what
    :func:`_is_control_char` screens for, plus every character whose Unicode category is in
    :data:`CONTROL_CATEGORIES`, minus TAB.

    THIS REVERSES THE OLD DESIGN, ON PURPOSE. Until #2815 the log escaped exactly
    ``_is_control_char`` minus tab (BACKLOG #1273, limb 3, closed as a refactor; no owner ruling set
    that alphabet). But a log is read back as TEXT, by tools the engine does not control, so C1,
    the explicit bidirectional controls and U+2028/U+2029 reaching the file raw let a reader split
    one record or have its order overridden. (Right-to-left LETTERS are printable and stay; a
    bidi-aware viewer still reorders digits beside them, which no escape of controls can stop.)
    Widening ``_is_control_char`` instead would change what seven call sites REFUSE
    (a URL path, a header, a file name, a config field), which is a different and larger change.
    So this function names its two sources and adds nothing of its own; ``tests/test_logging.py``
    pins that relationship.

    What it costs: an invisible character with a legitimate textual use is shown as an escape, at
    least the soft hyphen (U+00AD), the zero-width joiners (U+200C, U+200D) and the byte-order mark
    (U+FEFF). So is a code point this interpreter's Unicode tables do not assign (category ``Cn``).
    Accented letters, CJK and every other printable character are unchanged."""
    return ch != "\t" and (_is_control_char(ch) or unicodedata.category(ch) in CONTROL_CATEGORIES)


def json_unicode_escape(code: int) -> str:
    """JSON's own escape for one code point inside a string: ``\\u2028``, or past U+FFFF a
    surrogate pair, ``\\udb40\\udc01`` for U+E0001. A caller that may hold a lone surrogate decides
    its spelling itself, because ``\\udc80`` alone is not valid for a strict JSON decoder."""
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    code -= 0x10000
    return f"\\u{0xD800 + (code >> 10):04x}\\u{0xDC00 + (code & 0x3FF):04x}"


def _log_escape(code: int) -> str:
    """The log's escape for one code point, written so it is also valid inside a JSON string.

    CR and LF are ``\\r`` and ``\\n``. A lone surrogate is ``\\\\udc80``, a doubled backslash and
    the hex (see below). Every other code point is :func:`json_unicode_escape`: ``\\u007f``,
    ``\\u0085``, ``\\u2028``, and a surrogate pair past U+FFFF. So a document from ``json.dumps``
    without ``indent``, such as the off-box audit record, still parses after the scrub. So the
    audit tee need not escape early (vault BACKLOG #3012). On the first handler, the redaction
    filters run before its scrub. They see a character unescaped unless something escaped it
    before logging, as ``json.dumps`` does to the C0 controls in the audit record. A later
    handler re-runs them over text the first scrub escaped. ``emit_audit_tee`` lists both as
    residuals.
    Python's ``ascii`` spelling, used until then, wrote ``\\x7f`` and ``\\U000e0001``, which JSON
    does not define.

    A LONE SURROGATE IS SPELLED AS TEXT, NOT AS A CHARACTER. ``\\udc80`` alone is accepted by
    Python's ``json`` and refused by a strict decoder such as jiter. Worse, a lone high surrogate
    next to a lone low one would decode as ONE astral character that the text never held. With
    the backslash doubled, the line holds the seven characters ``\\\\udc80``, and every JSON
    decoder reads them as the six characters of text ``\\udc80``: the code point is still shown,
    and nothing is invented.

    One ambiguity is accepted. A backslash in the text is not doubled, as it never was. So peer
    text that spells an escape reads the same as an escaped character. In a decoded JSON document,
    a lone surrogate likewise reads the same as a peer who typed its six characters.

    One limit is accepted too. I-JSON (RFC 7493) forbids a noncharacter such as U+FFFF however it
    is written. A collector that enforces I-JSON would refuse a record holding one; jiter and
    Python's ``json`` accept it."""
    if code == 0x0A:
        return "\\n"
    if code == 0x0D:
        return "\\r"
    if _is_surrogate(code):
        return f"\\\\u{code:04x}"
    return json_unicode_escape(code)


# The log alphabet up to U+00FF, as a ``str.translate`` table: the whole table for ASCII text, and
# the seed of :class:`_LogTranslation` for the rest. :func:`_log_escape` spells CR and LF as the
# readable ``\r`` and ``\n``; tab is absent because the predicate leaves it out. RANGE 0x100 SO THE
# C1 BLOCK IS SEEDED, and a widening of ``_is_control_char`` anywhere in it reaches the table by
# construction (BACKLOG #1273, limb 3). A comprehension rather than a ``for`` loop so the index does
# not survive as a module global: this is a leaf every other module imports, and it should export
# nothing it did not mean to.
_CTRL_TRANSLATION: dict[int, str] = {
    cp: _log_escape(cp) for cp in range(0x100) if _escapes_in_a_log_line(chr(cp))
}

#: How many code points past U+FFFF :class:`_LogTranslation` remembers.
_ASTRAL_MEMO_LIMIT = 0x1000


class _LogTranslation(dict[int, str | int]):
    """The log alphabet over every code point, as a ``str.translate`` table that fills itself.

    The category set is too large to tabulate at import, so a code point the table has not seen is
    decided on first lookup and remembered. A character that stays is remembered as its own code
    point, which ``str.translate`` reads as "unchanged" without a string per entry. The Basic
    Multilingual Plane is remembered whole, at most 65,536 entries. Past U+FFFF at most
    :data:`_ASTRAL_MEMO_LIMIT` are remembered, so a peer sending many distinct astral code points
    cannot grow the table, and filling that share slows only later astral text, never the rest.
    One C-level translate pass then serves CJK, Greek or Cyrillic text at about the cost of
    Latin-1."""

    def __init__(self, seed: dict[int, str]) -> None:
        super().__init__(seed)
        self._astral = 0

    def __missing__(self, code: int) -> str | int:
        value: str | int = _log_escape(code) if _escapes_in_a_log_line(chr(code)) else code
        if code <= 0xFFFF:
            self[code] = value
        elif self._astral < _ASTRAL_MEMO_LIMIT:
            self._astral += 1
            self[code] = value
        return value


_LOG_TRANSLATION = _LogTranslation(_CTRL_TRANSLATION)


def scrub_control_chars(text: str) -> str:
    """Escape every character in the log alphabet (:func:`_escapes_in_a_log_line`; tab kept as
    benign whitespace) so no part of ``text`` can begin a new physical line, override the order a
    reader sees with a bidirectional control, or drive a terminal.

    The single definition of that translation, reached for at least three kinds of call site.
    ``logging_setup.ControlCharScrubFilter`` applies it to every record on a configured handler. A
    caller that assembles a record's content from an untrusted BYTE stream needs it at the point of
    assembly, because "one peer write is one log record" is that caller's own framing contract and
    cannot depend on how the host process configured logging -- the ADR 0176 sandbox stderr relay.
    :mod:`messagefoundry.logging_guard` needs it because its recovery notices bypass
    ``Handler.handle`` by design, so no filter chain ever sees them (BACKLOG #1591).

    Idempotent: every escape is printable ASCII. One ``str.translate`` pass, deliberately: ASCII
    text over the exact table, anything else over :class:`_LogTranslation`. No regex engine and no
    backtracking. A code point the table has not remembered costs one shallow Python call; if even
    that fails on the log write guard's failure path, ``logging_guard._guarded`` substitutes its
    placeholder rather than raising."""
    if text.isascii():
        return text.translate(_CTRL_TRANSLATION)
    return text.translate(_LOG_TRANSLATION)


def escape_lone_surrogates(text: str) -> str:
    """``text`` with each surrogate code point spelled as the log spells it (:func:`_log_escape`),
    and every other character, line breaks included, left as it is. ``text`` itself when it holds
    none, so the common case costs one scan. For text that must stay as rendered but still has to
    survive a strict UTF-8 encode: the off-box forwarder's replay of a spooled line (BACKLOG
    #2279)."""
    if not has_lone_surrogate(text):
        return text
    return "".join(_log_escape(ord(ch)) if _is_surrogate(ord(ch)) else ch for ch in text)


def scrub_log_argument(text: str) -> str:
    """:func:`scrub_control_chars` for one argument of a log call, with CR and LF escaped first.

    The result equals ``scrub_control_chars(text)`` for every input, which
    ``tests/test_controlchars.py`` pins. The two ``replace`` calls use the same escapes as the
    table, and :func:`scrub_control_chars` then escapes the rest of the log alphabet.

    WHY A CALL SITE NEEDS IT WHEN EVERY HANDLER ALREADY SCRUBS. ``ControlCharScrubFilter`` escapes
    the whole record on every configured handler, so on a shipped handler this changes nothing a
    reader sees. It matters in two places. A handler with no filter chain gets the escaped value
    anyway. And CodeQL's ``py/log-injection`` query cannot see a handler filter: it accepts a
    ``replace`` of a line break as the neutraliser, and it does not accept ``translate``."""
    return scrub_control_chars(
        text.replace("\r", _CTRL_TRANSLATION[0x0D]).replace("\n", _CTRL_TRANSLATION[0x0A])
    )


def quote_log_text(text: str) -> str:
    """``text`` as one double-quoted token that its own content cannot close or extend, in text no
    handler filter reads.

    JSON string quoting escapes every quote and backslash, writes ``\\n``, ``\\r``, ``\\t``, ``\\b``
    and ``\\f`` for those controls, and every other character outside printable ASCII, DEL included,
    as ``\\uXXXX``, a character past U+FFFF as a surrogate pair of them. So, in text no handler
    filter reads, a value cannot end its token and write a separator, a second entry or a mark after
    it, and a lookalike quote such as U+02BA or U+FF02, or a right-to-left letter, cannot fake that
    end for a human reader (vault BACKLOG #3139). The output is printable ASCII, and
    :func:`scrub_log_argument` changes nothing in it. It stays as a guard should the ``json.dumps``
    call ever drop ``ensure_ascii``, and because CodeQL's ``py/log-injection`` accepts its
    line-break ``replace`` as the neutraliser and does not see ``json.dumps``.

    NOT FOR ANY TEXT A CONFIGURED HANDLER'S FILTERS READ, WHEREVER IT SITS IN THE LINE. At least
    the credential scrub and the redaction filters can close the token early or erase its closing
    quote, and the text after it then reads as fields of its own (BACKLOG #3770). For a logged
    field, use :func:`log_field_token`."""
    # Imported here, not at the top: the remote-debug guard imports this module before its hook
    # goes in, and json, with re and enum under it, would lengthen that window.
    import json

    return scrub_log_argument(json.dumps(text))


#: The characters :func:`log_field_token` writes as they are: letters, digits and ``-./``
#: (BACKLOG #3770). Every other character is escaped, at least the space and every other
#: whitespace, both quotes, the backslash, ``_``, ``:``, ``=``, ``;``, ``,``, ``#``, ``%``, ``|``,
#: ``^``, ``&``, ``~``, ``<``, ``{``, ``(`` and ``[``. So the value holds nothing with which to end its
#: field or start one, and no separator a shipped handler filter's match needs to run past the
#: closing quote: no credential label can reach its ``:`` or ``=``, no HL7 run its separator, no
#: name run its space. A filter can still match a run of kept characters, a date of digits, ``-``
#: and ``/`` for one, and rewrite it as ``[redacted]`` inside the field. ``:`` goes too, because a
#: kept ``password:`` let the credential scrub take the closing quote and the next key; ``_`` goes
#: because it starts and ends every escape.
_LOG_FIELD_KEPT = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-./")

#: What :func:`log_field_token` puts in place of the cut tail of a token over its bound. It starts
#: with "_%", which neither the escape nor a kept run writes, so a bounded token cannot read as a
#: kept one, and it holds no HL7 separator, so a cut head cannot gain one. Both its ends are word
#: characters, so it gives the date pass no word boundary: not after a cut head's digits, and not
#: before the checksum's.
_LOG_FIELD_CUT_MARK = "_%crc32x"
_LOG_FIELD_CUT_LENGTH = len(_LOG_FIELD_CUT_MARK) + 8

#: What a literal :func:`log_field_token` keeps whole may hold: the kept alphabet and the
#: placeholder brackets. Nothing in it closes a field or completes a filter's match.
_LOG_FIELD_LITERAL = _LOG_FIELD_KEPT | frozenset("<>[]")


def _unit_escape(ch: str) -> str:
    """``ch`` itself when kept, else one ``_uXXXX_`` per UTF-16 code unit, four upper-case hex
    digits between ``_u`` and ``_``. Not ``%XX``: a ``%`` and two hex digits is where the credential
    scrub starts a label (``secretscrub._LABEL_START``) and how the HL7 pass spells an encoded
    separator (``redaction._ENCODED_SEPARATOR``), so ``%20password`` read as a label and ``%7C`` as
    a separator. An escape starts and ends in ``_``, a word character that is not a digit, so it
    gives the date and SSN passes no word boundary and no digit to join to a kept one: ``%u00E9``
    before ``12-34-5678`` read as an SSN, and ``%`` after a kept date as its end."""
    if ch in _LOG_FIELD_KEPT:
        return ch
    units = ch.encode("utf-16-be", "surrogatepass")
    return "".join(f"_u{units[i]:02X}{units[i + 1]:02X}_" for i in range(0, len(units), 2))


def log_field_token(text: str, limit: int, *, literals: tuple[str, ...] = ()) -> str:
    """``text`` as one double-quoted ``key=value`` field value of a log line, which no part of
    ``text`` can close, extend or join to another field, before or after the shipped handler
    filters, however many handlers run them in turn (BACKLOG #3770).

    Every character outside :data:`_LOG_FIELD_KEPT` is written by :func:`_unit_escape`, so the token
    holds no space, quote, backslash or separator, and an ``_uXXXX_`` decode gives ``text`` back,
    except that two lone surrogates that spell a pair decode to its character. Each
    occurrence of a string in ``literals`` is kept whole instead, which is how the redaction
    placeholders stay searchable as themselves; a literal may hold only :data:`_LOG_FIELD_LITERAL`.
    A text that already holds a placeholder's spelling therefore logs it as it is, so a value can
    claim of itself that something was redacted, though never of another field. The handler filters
    still read the token, and one may rewrite a run inside it, a date for example, as
    ``[redacted]``, which holds no space or quote. They anchor on less than they would in raw text,
    so a caller does not call this directly: it calls ``logging_setup.redacted_log_field``, which
    redacts first.

    The escaped text is at most ``limit`` characters, counted after the escape, so the field is at
    most ``limit`` plus its two quotes whatever ``text`` holds. That is the token's bound; a handler
    filter's rewrite inside it can lengthen the logged field, at least by up to two characters for
    each date of eight characters it reads as ``[redacted]``. Longer text keeps whole leading
    pieces, a character's escapes or a literal, and :data:`_LOG_FIELD_CUT_MARK` with the CRC-32 of
    all of ``text``, so two honest long texts that share the head almost never read alike. A
    checksum, not a digest, as in ``pipeline.intake_bound.shorten_with_checksum``: the field is read
    by a person and is never a key, so it has no forged collision to resist, and this leaf module
    stays out of the crypto inventory. ``limit`` must leave room for the mark, 16 characters."""
    if limit < _LOG_FIELD_CUT_LENGTH:
        raise ValueError(
            f"limit {limit} leaves no room for the {_LOG_FIELD_CUT_LENGTH}-character cut mark"
        )
    for literal in literals:
        if not literal or not set(literal) <= _LOG_FIELD_LITERAL:
            raise ValueError(f"literal {literal!r} holds a character a field must not")
    # Each piece is at least one character, so pieces past `limit + 1` characters are never needed,
    # and the head is built a whole piece at a time, so a cut never splits an escape or a literal.
    starts = {literal[0] for literal in literals}
    pieces: list[str] = []
    length = 0
    i = 0
    while i < len(text) and length <= limit:
        piece = None
        if text[i] in starts:
            piece = next((lit for lit in literals if text.startswith(lit, i)), None)
        if piece is None:
            piece = _unit_escape(text[i])
            i += 1
        else:
            i += len(piece)
        length += len(piece)
        pieces.append(piece)
    if length <= limit:
        return scrub_log_argument(f'"{"".join(pieces)}"')
    import binascii  # lazily, for the reason quote_log_text imports json lazily

    budget = limit - _LOG_FIELD_CUT_LENGTH
    head: list[str] = []
    for piece in pieces:
        budget -= len(piece)
        if budget < 0:
            break
        head.append(piece)
    checksum = binascii.crc32(text.encode("utf-8", "surrogatepass"))
    # Printable ASCII already, so the scrub changes nothing; it is here for CodeQL, as in
    # quote_log_text.
    return scrub_log_argument(f'"{"".join(head)}{_LOG_FIELD_CUT_MARK}{checksum:08x}"')
