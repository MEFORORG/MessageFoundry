# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""docs/PHI.md's browser-storage sentence must describe what the web console actually writes.

BACKLOG #1186 (ASVS 14.2.4) asks that the named control domains be implemented as defined in the
documentation for the data's protection level. The fidelity defect this guard closes is the one that
item names in general terms: a sentence in the classification document asserted a posture the shipped
code refuted, drifted undetected because nothing read it, and was corrected by hand.

Measured 2026-09-06 at 744a7a434: the bullet said "Nothing is written to
``localStorage``/``sessionStorage``/``IndexedDB``" while ``static/app.js`` had read and written
column preferences under an ``mfcols:v2:`` prefix since 2026-07-07, and ``_auth.py`` deliberately
sends ``Clear-Site-Data: "cache"`` rather than ``"storage"`` SO THAT those survive a logout. Two
shipped artifacts depended on the behaviour the document denied.

**This binds the CLAIM, not the absence.** A test asserting "the console writes no storage" would
have to be deleted the day a legitimate preference lands, which is how the original sentence became
false. Instead the document names the prefixes it permits and this compares that list to the source,
in both directions: an undeclared prefix reds, and a declared prefix nothing writes reds too.
"""

from __future__ import annotations

import functools
import pathlib
import re

import pytest

from scripts.security.js_lexer import blank_js_comments

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_PHI_MD = _ROOT / "docs" / "PHI.md"
_APP_JS = _ROOT / "messagefoundry_webconsole" / "static" / "app.js"

#: The two APIs the bullet claims nothing at all is written to.
_FORBIDDEN_APIS = ("sessionStorage", "indexedDB")

#: A quoted string-literal prefix handed to a storage setter, e.g. ``var PREFIX = "mfcols:v2:";``.
_PREFIX_LITERAL = re.compile(r'PREFIX\s*=\s*"([^"]+)"')


@functools.cache
def _app_js_code() -> str:
    # Comment-blanked, never raw (BACKLOG #2056): app.js names localStorage in comments, so a raw
    # read stayed True after the real storage calls were deleted.
    return blank_js_comments(_APP_JS.read_text(encoding="utf-8"))


def _storage_bullet() -> str:
    """The 'No PHI in browser storage' bullet, up to the next top-level list item."""
    text = _PHI_MD.read_text(encoding="utf-8")
    start = text.find("- **No PHI in browser storage.**")
    assert start != -1, (
        "docs/PHI.md no longer contains the 'No PHI in browser storage' bullet. If it was renamed, "
        "retarget this guard in the same commit -- do not delete it, the unread sentence is the "
        "defect BACKLOG #1186 names."
    )
    rest = text[start + 1 :]
    end = rest.find("\n- **")
    return rest[:end] if end != -1 else rest


def test_the_console_exists_and_uses_local_storage() -> None:
    """Liveness receipt. Every assertion below is vacuous if the console source moved."""
    assert _APP_JS.is_file(), f"{_APP_JS} is missing -- the comparisons below would prove nothing"
    assert "localStorage" in _app_js_code(), (
        "app.js names localStorage nowhere. Either the preference code moved -- retarget this guard "
        "-- or it was removed, in which case the doc bullet must drop its prefix in the same commit."
    )


def test_every_prefix_the_console_writes_is_named_in_the_doc() -> None:
    """Code-to-doc. A new storage key must be declared in the classification document."""
    written = set(_PREFIX_LITERAL.findall(_app_js_code()))
    assert written, (
        "no storage prefix literal parsed from app.js. The declaration shape changed, so this guard "
        "is matching nothing -- fix the pattern rather than letting it pass empty."
    )
    bullet = _storage_bullet()
    undeclared = sorted(p for p in written if f"`{p}`" not in bullet)
    assert not undeclared, (
        f"the web console writes browser storage under {undeclared}, which docs/PHI.md's "
        f"'No PHI in browser storage' bullet does not name. Add it to the bullet WITH its protection "
        f"argument -- what it holds and why that is PHI-free -- rather than widening this test."
    )


def test_every_prefix_the_doc_names_is_actually_written() -> None:
    """Doc-to-code, the direction that catches a stale permission outliving its feature."""
    bullet = _storage_bullet()
    declared = {m for m in re.findall(r"`([a-z][a-z0-9]*:v?[0-9]*:?)`", bullet) if ":" in m}
    assert declared, (
        "the bullet names no backticked storage prefix, so this direction is asserting nothing. If "
        "the console genuinely stopped writing storage, delete this test and the prefix together."
    )
    source = _app_js_code()
    orphaned = sorted(p for p in declared if p not in source)
    assert not orphaned, (
        f"docs/PHI.md permits browser-storage prefixes {orphaned} that the console does not write. A "
        f"permission outliving its feature reads as a wider posture than the product has."
    )


@pytest.mark.parametrize("api", _FORBIDDEN_APIS)
def test_the_console_writes_neither_session_storage_nor_indexeddb(api: str) -> None:
    """The bullet's remaining absolute claim, which is still absolute and must stay measured."""
    source = _APP_JS.read_text(encoding="utf-8")
    assert api.lower() not in source.lower(), (
        f"docs/PHI.md states nothing at all is written to {api}, and the console source names it. "
        f"Either the write is real -- correct the bullet, do not weaken this -- or it is a comment, "
        f"in which case reword the comment so the claim stays measurable."
    )


def test_js_code_blanks_comments_and_keeps_code() -> None:
    """The instrument, pinned both ways: a comment is ABSENT, a string or a call is PRESENT, and a
    ``//`` inside a string or a regex literal does not start a comment."""
    mention = '// localStorage\n/* var PREFIX = "old:v1:"; */\nvar x = 1;\n'
    assert "localStorage" not in blank_js_comments(mention)
    assert not _PREFIX_LITERAL.findall(blank_js_comments(mention))
    real = (
        r'var u = "http://h/x"; var r = s.replace(/\//g, "_"); var t = `a//b`;' + "\n"
        'var PREFIX = "mfcols:v2:"; localStorage.setItem(PREFIX, "1"); // trailing\n'
    )
    code = blank_js_comments(real)
    assert _PREFIX_LITERAL.findall(code) == ["mfcols:v2:"]
    assert "localStorage.setItem" in code and "trailing" not in code
    assert '"http://h/x"' in code and "`a//b`" in code
    after_keyword = blank_js_comments('function f(s) { return /"/.test(s); } // gone\nvar k = 1;\n')
    assert "gone" not in after_keyword and "var k = 1;" in after_keyword
    assert "localStorage" not in blank_js_comments("var r = obj.in / 2; // localStorage\n")


def test_the_presence_probes_fail_when_the_storage_code_is_gone() -> None:
    """Delete-and-watch-it-fail on the real file (BACKLOG #2056). Remove the storage calls and the
    prefix declaration but keep them as comments: the raw text still names both, which is what kept
    the old probes green, and the code view must name neither."""
    source = _APP_JS.read_text(encoding="utf-8")
    declaration = 'var PREFIX = "mfcols:v2:";'
    assert declaration in source and "localStorage." in source, "anchor moved; re-point"
    mutated = source.replace(declaration, "// " + declaration).replace(
        "localStorage.", "window.noStorage."
    )
    assert "localStorage" in mutated and "mfcols:v2:" in mutated, "the mentions must survive"
    code = blank_js_comments(mutated)
    assert "localStorage" not in code
    assert not _PREFIX_LITERAL.findall(code)
    assert "mfcols:v2:" not in code
