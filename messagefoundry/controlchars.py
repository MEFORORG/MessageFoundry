# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The C0/DEL control-character test, written once (BACKLOG #1253).

WHAT THIS REPLACES. ``ord(ch) < 0x20 or ord(ch) == 0x7F`` was written out seven times across six
files -- two in ``transports/fhir.py`` and one each in ``config/codeset_edit.py``,
``config/impact.py``, ``transports/dicomweb.py``, ``transports/remotefile.py`` and
``transports/rest.py``. Every copy agreed, so nothing was mis-screened. The cost was future-tense
and is the one #1239 named: a later hardening applied to one copy silently does not apply to the
rest, and nothing reports the omission.

THIS SHARES THE PREDICATE, NOT THE ACTION, AND THAT DISTINCTION IS THE DESIGN. #1239 ruled out
"collapsing the call sites into one helper with a flag" because the differing wrappers are
appropriate: a raise suits a path context, a bool suits a filter, and the exceptions differ by layer
(``WiringError`` in config, a PHI-safe negative ACK in FHIR). So each call site keeps its own
refusal and its own message; only the TEST moves here. A flag parameter would have re-created the
coupling the item exists to remove, one indirection further away.

TWO ACTIONS ARE PRESERVED ON PURPOSE, and one of them must never be "simplified" into the other:

  * REJECT -- six sites. A control character in a value that reaches a URL path, a header, a
    filename or a config field is refused outright.
  * STRIP -- ``transports/rest.py`` only, on a message-derived header VALUE. That is defensible
    rather than a second instance of the mutation pattern the owner ruled against in #1238: that
    ruling turns on ``basename()`` converting a path into a valid-but-DIFFERENT target, handing an
    attacker a real file. A header value has no such property -- removing CR/LF cannot redirect a
    request anywhere -- and ``rest.py`` already REJECTS a header NAME failing its RFC 7230 token
    check. Name-rejected, value-stripped, which is principled.

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
def has_control_char(text: str) -> bool:
    """True if ``text`` contains any C0 control character or DEL."""
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text)


def strip_control_chars(text: str) -> str:
    """``text`` with every C0 control and DEL removed.

    The strip arm, used where a value must be neutralised rather than refused. See the module
    docstring: this is NOT the general remedy and must not be substituted for a rejection.
    """
    return "".join(ch for ch in text if not (ord(ch) < 0x20 or ord(ch) == 0x7F))
