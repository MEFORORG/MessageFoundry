# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The C0/DEL control-character test, written once (BACKLOG #1253).

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
:func:`scrub_control_chars` are here beside :func:`has_control_char`, all three built from the one
predicate. (This paragraph replaced a "shares the predicate, not the action" thesis that its own
module had already outgrown: a reader taking that literally puts the next neutraliser elsewhere,
which is how the escape table came to live in ``logging_setup``.)

THE TWO NEUTRALISERS ARE DIFFERENT AND ONE MUST NEVER BE "SIMPLIFIED" INTO THE OTHER. Beside the
refusals, that makes three actions over one predicate:

  * REJECT -- six sites. A control character in a value that reaches a URL path, a header, a
    filename or a config field is refused outright.
  * STRIP -- ``transports/rest.py`` only, on a message-derived header VALUE. That is defensible
    rather than a second instance of the mutation pattern the owner ruled against in #1238: that
    ruling turns on ``basename()`` converting a path into a valid-but-DIFFERENT target, handing an
    attacker a real file. A header value has no such property -- removing CR/LF cannot redirect a
    request anywhere -- and ``rest.py`` already REJECTS a header NAME failing its RFC 7230 token
    check. Name-rejected, value-stripped, which is principled.
  * ESCAPE -- every log line, :func:`scrub_control_chars`. Neither refuses nor deletes: it renders
    the code point as a readable backslash escape, so one record cannot become two.

WHY ESCAPE LIVES HERE, WHICH IS THE ONE FACT WORTH STATING ONCE (BACKLOG #1591). It was defined in
``logging_setup`` until ``logging_guard`` needed it, and ``logging_setup`` imports
``logging_guard`` -- so reaching upwards is a cycle and copying the table down is the two-copy drift
``_is_control_char`` below exists to close. This module imports nothing, so it is the one place both
can reach. Nothing else about that move is load-bearing; the other files cite this paragraph.

DELIBERATELY NOT FOLDED IN. ``parsing/sniff.py`` tests the same code points but is a genuinely
different predicate: it is byte-wise rather than character-wise and subtracts an allowlist, because
a text sniffer must tolerate tab, CR and LF. Folding it in would change its behaviour.

THE POINT IS THE COPYING PRACTICE, not the seven known lines. If you need this test, import it.
"""

from __future__ import annotations


#: C0 controls (U+0000-U+001F) plus DEL (U+007F). NOT a general "is this printable" test: it is
#: deliberately blind to C1 (U+0080-U+009F) and to Unicode separators, because every call site
#: screens values destined for byte-oriented sinks -- a request line, a header, a path -- where C0
#: and DEL are the injection alphabet. Widening it is a behaviour change at seven call sites at
#: once, which is exactly the leverage this module exists to provide; make it deliberately.
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


def strip_control_chars(text: str) -> str:
    """``text`` with every C0 control and DEL removed.

    The strip arm, used where a value must be neutralised rather than refused. See the module
    docstring: this is NOT the general remedy and must not be substituted for a rejection.
    """
    return "".join(ch for ch in text if not _is_control_char(ch))


# C0 control characters (and DEL) escaped to keep one log record on one line. CR/LF are the
# log-injection vector; tab (0x09) is left intact as benign whitespace.
#
# THE ALPHABET IS _is_control_char's, MINUS TAB (BACKLOG #1273, limb 3), and THE SUBTRACTION IS
# WRITTEN AS ONE rather than as a second table. It used to be re-derived in ``logging_setup`` as
# `range(0x20)` plus a separate `0x7F` line. The two agreed, so nothing was mis-escaped; the cost is
# the future-tense one #1239 named and #1253 acted on, that a later widening applied to one copy
# silently does not apply to the other. Measured: _is_control_char 33 code points, this table 32,
# symmetric difference {0x09}. One code point of divergence is a subtraction, not a different
# predicate -- unlike the parsing/sniff.py carve-out the module docstring keeps separate.
_CTRL_TRANSLATION: dict[int, str] = {0x0A: "\\n", 0x0D: "\\r"}
# RANGE 0x100, NOT 0x80, AND THAT IS THE DIFFERENCE BETWEEN A REAL FOLD AND A COSMETIC ONE. The
# alphabet is C0+DEL today, so both bounds produce the identical 32 entries -- proved by the
# byte-identity check in the commit. But `_is_control_char`'s docstring names widening to C1
# (U+0080-U+009F) as the deliberate change this shared module exists to make cheap, and a 0x80 bound
# would silently NOT follow it: the escape table would keep the old alphabet while every other call
# site moved, which is the exact two-copy drift limb 3 removes. Iterating past the current boundary
# costs 128 predicate calls at import and makes the widening propagate by construction.
for _i in range(0x100):
    # TAB IS THE ONLY SUBTRACTION and test_tab_is_the_only_control_character_left_intact pins it.
    # CR/LF are excluded from this loop because they get readable escapes above, not because they
    # are tolerated -- they are the injection vector this whole table exists for.
    if _is_control_char(chr(_i)) and _i not in (0x09, 0x0A, 0x0D):
        _CTRL_TRANSLATION[_i] = f"\\x{_i:02x}"


def scrub_control_chars(text: str) -> str:
    """Escape C0 control characters and DEL (tab kept as benign whitespace) so no part of ``text`` can
    begin a new physical line or drive a terminal.

    The single definition of that translation, with three callers for three reasons.
    ``logging_setup.ControlCharScrubFilter`` applies it to every record on a configured handler. A
    caller that assembles a record's content from an untrusted BYTE stream needs it at the point of
    assembly, because "one peer write is one log record" is that caller's own framing contract and
    cannot depend on how the host process configured logging -- the ADR 0176 sandbox stderr relay.
    :mod:`messagefoundry.logging_guard` needs it because its recovery notices bypass
    ``Handler.handle`` by design, so no filter chain ever sees them (BACKLOG #1591).

    Idempotent: the escaped forms contain no control characters. ``str.translate`` over a dict,
    deliberately -- one C-level pass, no regex engine, no backtracking and no recursion, which is
    what makes it safe on the log write guard's failure path."""
    return text.translate(_CTRL_TRANSLATION)
