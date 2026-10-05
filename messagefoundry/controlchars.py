# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The control-character alphabets, each written once: the C0/DEL test (BACKLOG #1253) and the
wider log alphabet built on it (vault BACKLOG #2815). Beside them sits :func:`has_lone_surrogate`,
the other test a mail header value needs, which is not a control character (vault BACKLOG #2842).

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

THE TWO NEUTRALISERS ARE DIFFERENT AND ONE MUST NEVER BE "SIMPLIFIED" INTO THE OTHER. Beside the
refusals, that makes three actions built on one predicate:

  * REJECT -- six sites. A control character in a value that reaches a URL path, a header, a
    filename or a config field is refused outright.
  * STRIP -- ``transports/rest.py`` only, on a message-derived header VALUE. That is defensible
    rather than a second instance of the mutation pattern the owner ruled against in #1238: that
    ruling turns on ``basename()`` converting a path into a valid-but-DIFFERENT target, handing an
    attacker a real file. A header value has no such property -- removing CR/LF cannot redirect a
    request anywhere -- and ``rest.py`` already REJECTS a header NAME failing its RFC 7230 token
    check. Name-rejected, value-stripped, which is principled. **"Only" is stale:** at least
    ``corepoint_import.py`` and ``uploads.py`` strip too. The upload filename is display-only and
    never locates a file, so the #1238 ruling does not reach it either.
  * ESCAPE -- every log line, :func:`scrub_control_chars`. Neither refuses nor deletes: it renders
    the code point as a readable backslash escape, so one record cannot become two. Its alphabet is
    WIDER than the other two arms' (vault BACKLOG #2815); :func:`_escapes_in_a_log_line` states it.
    Its ``\\xNN`` and ``\\UXXXXXXXX`` spellings are not JSON, so a JSON document logged as a
    message is serialized with :func:`json_dumps_for_log`, which spells those characters as JSON.

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

import json
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


def has_lone_surrogate(text: str) -> bool:
    """True if ``text`` holds a surrogate code point (U+D800 to U+DFFF), which strict UTF-8 cannot
    write. That includes each half of an adjacent pair, which ``str`` holds as two code points only
    after a ``surrogatepass`` decode or an escape. TOML refuses one, but at least Python config and an environment value can carry one: a
    ``surrogateescape`` decode makes U+DC80 to U+DCFF. :func:`has_control_char` passes it, so a mail
    header needs both tests (vault BACKLOG #2842). In a header most surrogates raise
    ``UnicodeEncodeError`` at build; U+DC80 to U+DCFF go out as a garbled ``unknown-8bit`` word."""
    return any("\ud800" <= ch <= "\udfff" for ch in text)


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


def _log_escape(code: int) -> str:
    """Python's own escape for one code point (``\\x85``, ``\\u2028``, ``\\U000e0001``).
    ``ascii`` spells it, not this module. A backslash in the text is not doubled, as it never was
    for C0, so peer text that spells an escape reads the same as an escaped character."""
    return ascii(chr(code))[1:-1]


# The log alphabet up to U+00FF, as a ``str.translate`` table: the whole table for ASCII text, and
# the seed of :class:`_LogTranslation` for the rest. ``ascii`` spells CR and LF as the readable
# ``\r`` and ``\n``; tab is absent because the predicate leaves it out. RANGE 0x100 SO THE C1 BLOCK
# IS SEEDED, and a widening of ``_is_control_char`` anywhere in it reaches the table by construction
# (BACKLOG #1273, limb 3). A comprehension rather than a ``for`` loop so the index does not survive
# as a module global: this is a leaf every other module imports, and it should export nothing it did
# not mean to.
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


#: The log alphabet up to U+00FF, spelled as JSON escapes. :func:`scrub_control_chars` spells these
#: ``\xNN``, which JSON does not define. Above U+00FF the scrub's ``\uXXXX`` is already JSON, except
#: past U+FFFF, which :func:`json_dumps_for_log` handles itself.
_JSON_SPELLING: dict[int, str] = {cp: json.dumps(chr(cp))[1:-1] for cp in _CTRL_TRANSLATION}


def json_dumps_for_log(obj: object) -> str:
    """``json.dumps(obj, ensure_ascii=False)`` that stays valid JSON after
    :func:`scrub_control_chars`, for a JSON document logged as a message (the off-box audit tee).

    The scrub spells the log alphabet the way ``ascii()`` does. Up to U+00FF that is ``\\xNN`` and
    past U+FFFF it is ``\\UXXXXXXXX``, and JSON defines neither, so a raw DEL, C1, soft hyphen or
    astral format code point left the document unparseable. This spells exactly those characters
    as JSON escapes (an astral one as a surrogate pair) before any filter runs. ``json.dumps``
    already escapes C0 inside a string, and the alphabet can occur nowhere else in its output.

    EVERY OTHER CHARACTER IS LEFT RAW, ON PURPOSE. The scrub still spells the BMP part of the
    alphabet as ``\\uXXXX``, which is JSON. So a filter that runs before the scrub, such as the
    redaction filter, sees those characters as it always did. An escape there would join the
    following word (``\\u200eDOE`` has no word boundary), and redaction would miss the name. The
    characters this does escape left the record unparseable before, so the redaction filter now
    sees different text only in a record that could not be read anyway, or where it had removed
    that character itself. That second case is at least a name joined by U+0085."""
    document = json.dumps(obj, ensure_ascii=False).translate(_JSON_SPELLING)
    # `max` is one C-level pass; the per-character walk runs only for text past U+FFFF.
    if document.isascii() or max(document) <= chr(0xFFFF):
        return document
    return "".join(
        json.dumps(ch)[1:-1] if ord(ch) > 0xFFFF and _escapes_in_a_log_line(ch) else ch
        for ch in document
    )


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
