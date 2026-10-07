# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared instruments for proving an encode refusal is CONTENT-FREE.

A synthetic payload whose non-ASCII characters must never be echoed, every rendering of a character
that could betray it, and the checks that the error and its exception chain carry none of it. Used
by the ``encode_wire_body`` tests and by the connectors that encode through it. Shared here rather
than imported as private names from one test module (vault BACKLOG #3044)."""

from __future__ import annotations

from messagefoundry.redaction import safe_exc

#: A payload whose non-ASCII characters are the thing that must never be echoed. Distinctive enough
#: that a substring scan cannot miss it, and each is un-encodable in ASCII/latin-1 respectively.
SECRET_CHAR = "é"  # é — un-encodable as ASCII
CJK_CHAR = "病"  # 病 — un-encodable as ASCII *and* latin-1
PAYLOAD = f"MSH|^~\\&|SENDER|FAC|RECV|FAC|20260714||ADT^A01|1|P|2.5\rPID|1||42||Zaf{SECRET_CHAR}r^{CJK_CHAR}\r"


def escapes(ch: str) -> list[str]:
    """Every rendering of ``ch`` that could betray it in an error string.

    Asserting only ``ch not in text`` is NOT enough, and getting this wrong would have made every
    test that uses it worthless: ``str(UnicodeEncodeError)`` does not print the literal character, it prints
    the **escaped codepoint** — ``'ascii' codec can't encode character '\\xe9' in position 69``. A test
    that scanned for a literal ``é`` would therefore have passed against the very bug it was written
    to catch. ``\\xe9`` identifies the character exactly; it is a disclosure, not a redaction."""
    return [
        ch,
        ch.encode("unicode_escape").decode(
            "ascii"
        ),  # '\xe9', and a backslash-u escape for CJK_CHAR
        f"{ord(ch):x}",  # 'e9' / '75c5'
        f"\\u{ord(ch):04x}",  # '\\u00e9': a \u escape below U+0100, which unicode_escape never writes
        repr(ch),
    ]


def assert_content_free(exc: BaseException, *, encoding: str) -> None:
    """The raised error, and everything the engine derives from it, is free of message content —
    in EVERY representation of the offending character, not just the literal one."""
    rendered = f"{exc} | {exc!r} | {safe_exc(exc)}"
    for ch in (SECRET_CHAR, CJK_CHAR):
        for form in escapes(ch):
            assert form not in rendered, (
                f"the offending character leaked into the error as {form!r} — "
                "str(UnicodeEncodeError) escapes it rather than printing it, so this is the "
                "representation that actually leaks"
            )
    assert "Zaf" not in rendered and "MSH" not in rendered, "payload content leaked into the error"
    assert encoding in rendered, "the error should name the codec (it is actionable and safe)"
    assert_chain_severed(exc)


def walk_chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from ``exc`` by ATTRIBUTE, ignoring ``__suppress_context__``.

    This is the instrument, and its indifference to the flag is the whole point. A structured-logging
    serializer, a crash reporter, a debugger or any custom formatter reads ``__cause__``/``__context__``
    directly; only the *default* traceback printer consults ``__suppress_context__``. Asserting against
    the default rendering would pass against the very bug this exists to catch."""
    seen: list[BaseException] = []
    node: BaseException | None = exc.__cause__ or exc.__context__
    while node is not None and node not in seen:
        seen.append(node)
        node = node.__cause__ or node.__context__
    return seen


def assert_chain_severed(exc: BaseException) -> None:
    """BOTH chains must be empty, not merely suppressed.

    ``raise ... from None`` clears ``__cause__`` and sets ``__suppress_context__`` — but it LEAVES
    ``__context__`` populated, and a ``UnicodeEncodeError``'s ``.object`` is the *entire payload*. The
    flag only stops the default printer walking; it does not detach the exception. So the refusal must
    be raised from OUTSIDE the ``except`` block, which is the only thing that leaves ``__context__``
    empty (CPython sets it only when the raise happens while an exception is being handled)."""
    assert exc.__cause__ is None, "the UnicodeEncodeError must not be chained on __cause__"
    assert exc.__context__ is None, (
        "the UnicodeEncodeError is still on __context__ — `from None` does NOT remove it, it only "
        "sets __suppress_context__, and `.object` is the WHOLE payload. Raise outside the handler."
    )
    for link in walk_chain(exc):
        assert not isinstance(link, UnicodeEncodeError), (
            f"a UnicodeEncodeError is reachable on the chain via {type(link).__name__}; "
            "its `.object` is the entire payload"
        )
