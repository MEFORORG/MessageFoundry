# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No document calls the exception-message convention THE control for a redaction residual (BACKLOG #3464).

The "never put PHI in an exception message" convention binds only the engine's own authors, in text
they write themselves. A diagnostic can quote text a remote peer wrote, which no convention of ours
binds, so "the convention remains the control" was false for peer text. It was said in ten places
across six files. docs/PHI.md section 7 now states the fact once, under *Who the exception-message
convention binds*, and the other places point there.

This pins the absence of the old claim, in the shapes the controls below hold, over ``docs/``,
``messagefoundry/``, ``tests/``, ``packaging/``, ``harness/`` and ``scripts/``. It is a lexical floor:
a paraphrase that never says "the control" passes it. It also pins that the statement the pointers
cite is still in section 7.

**Every match is flagged, whatever marker surrounds it.** A correction note that must quote the old
claim verbatim adds its own entry to :data:`_ALLOWED` in the same change, so a reviewer sees the
exemption beside the quote. An entry is a scanned path and the exact text, folded the way the scan
folds it; it exempts one claim only under the rules :func:`_check` states. **Whether an entry's
text really is a retraction is the reviewer's call: the guard does not read quoting**, because every
quote-reading rule tried here could be bridged. An entry the scan does not use, or a repeated one,
fails :func:`test_no_allowlist_entry_is_stale`, because the scan itself reports which entries it
used. A marker-reading exemption was tried first and failed open in at least seven shapes (PR 2595),
which :func:`test_a_claim_is_flagged_whatever_marker_surrounds_it` pins.
"""

from __future__ import annotations

import functools
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCANNED = ("docs", "messagefoundry", "tests", "packaging", "harness", "scripts")
_SUFFIXES = frozenset({".md", ".py"})
_STATEMENT = "**Who the exception-message convention binds.**"

_CONTROL = r"\s+(?:remains|is)\s+(?:still\s+)?the\s+(?:only\s+)?\W{0,2}control\b"
#: The claim, as it read before BACKLOG #3464. Line breaks and comment or quote markers are folded
#: away first, so a claim wrapped across lines is still one sentence; up to four marks such as a
#: closing quote or Markdown emphasis may sit between the convention's name and the verb.
_CLAIM = re.compile(
    rf"exception\s+message\W{{0,4}}(?:\s+convention\W{{0,4}})?{_CONTROL}"
    rf"|the\s+convention\s+above\W{{0,4}}{_CONTROL}",
    re.IGNORECASE,
)
_LINE_MARKER = re.compile(r"^\s*(?:#:?|>)?\s*", re.MULTILINE)
#: A cheap first look on the raw text: ``\W+`` also spans a line break and its comment marker, so no
#: file that :data:`_CLAIM` would match after folding is skipped. Most files fail it and skip the fold.
_MAYBE = re.compile(r"the\W+(?:only\W+)?control", re.IGNORECASE)

_Entry = tuple[str, str]

#: Reviewed retractions that quote the old claim, one claim each: ``(posix path relative to the
#: repository root, exactly as the scan spells it; the quoting text as folded)``.
_ALLOWED: tuple[_Entry, ...] = ()


def _folded(text: str) -> str:
    return " ".join(_LINE_MARKER.sub("", text).split())


def _check(text: str, path: str, allowed: tuple[_Entry, ...]) -> tuple[list[str], set[_Entry]]:
    """The claims in ``text``, and the entries of ``allowed`` that exempted one.

    An entry exempts a claim only when its path is ``path`` exactly, its text appears exactly once in
    the folded ``text``, that text holds exactly one whole claim, and no other entry also holds that
    claim. So a second copy pasted elsewhere in the file as a fresh claim, an entry spanning two
    claims, or two entries for one claim, exempts nothing."""
    if not _MAYBE.search(text):
        return [], set()
    folded = _folded(text)
    matches = list(_CLAIM.finditer(folded))
    holders: dict[int, list[_Entry]] = {}
    for entry in dict.fromkeys(allowed):
        lo = folded.find(entry[1]) if entry[0] == path else -1
        if lo == -1 or folded.find(entry[1], lo + 1) != -1:
            continue
        hi = lo + len(entry[1])
        inside = [i for i, m in enumerate(matches) if lo <= m.start() and m.end() <= hi]
        if len(inside) == 1:
            holders.setdefault(inside[0], []).append(entry)
    exempt = {i: entries[0] for i, entries in holders.items() if len(entries) == 1}
    claims = [m.group(0) for i, m in enumerate(matches) if i not in exempt]
    return claims, set(exempt.values())


def _claims(text: str, path: str = "", allowed: tuple[_Entry, ...] = ()) -> list[str]:
    return _check(text, path, allowed)[0]


def _sources(root: Path) -> list[Path]:
    me = Path(__file__).resolve()
    return sorted(
        path
        for top in _SCANNED
        for path in (root / top).rglob("*")
        if path.suffix in _SUFFIXES and path.is_file() and path.resolve() != me
    )


def _scan(
    root: Path, sources: list[Path], allowed: tuple[_Entry, ...]
) -> tuple[dict[str, list[str]], list[_Entry]]:
    """The claims found in ``sources``, by path under ``root``, and the stale entries: each one
    that exempted no claim, and each repeat of an earlier entry."""
    hits: dict[str, list[str]] = {}
    used: set[_Entry] = set()
    for path in sources:
        rel = path.relative_to(root).as_posix()
        found, exempting = _check(path.read_text(encoding="utf-8"), rel, allowed)
        used |= exempting
        if found:
            hits[rel] = found
    stale = [e for i, e in enumerate(allowed) if e not in used or e in allowed[:i]]
    return hits, stale


@functools.cache
def _tree() -> tuple[int, dict[str, list[str]], list[_Entry]]:
    """The repository scan, run once for the tests that read it: files scanned, hits, stale."""
    sources = _sources(_ROOT)
    return (len(sources), *_scan(_ROOT, sources, _ALLOWED))


@pytest.mark.parametrize(
    "shipped",
    [
        # docs/PHI.md, the second residual
        "Neither is a completeness claim; the convention above remains the control for both.",
        # messagefoundry/redaction.py, a ``#:`` comment wrapped across two lines
        '#: takes no time; the "never put PHI in an exception message"\n#: convention remains the control.',
        # docs/CONFIGURATION.md, a blockquote with Markdown emphasis
        '> for which *"never put PHI in an exception message"*\n> remains the control. So',
        # tests/test_logging.py, a ``#`` comment
        '# the "never put PHI in an\n# exception message" convention is the control. Pin it.',
        # variants a reword could reach for
        'the "never put PHI in an exception message" convention is still the only control',
        'the "never put PHI in an exception message" convention** remains the **control**',
        # a claim near a correction marker is still the claim: these were flagged before PR 2595's
        # marker-reading exemption was removed, and must stay flagged if one ever returns
        "**CORRECTED 2026-10-01:** this said the gate was per route. Neither is a completeness "
        "claim; the convention above remains the control for both.",
        'An UNCORRECTED fragment, read "x". The convention above remains the control for both.',
        'UNCORRECTED 2026-10-28: this read "the convention above remains the control for both".',
        'Corrected 2026-10-01: this said the gate was per route; the "never put PHI in an exception '
        'message" convention remains the control.',
        'the corrected wording read "the convention above remains the control for both".',
        'corrected 2026-10-28: this read "the convention above remains the control for both".',
        '**CORRECTED 2026-10-28:** this said "never put PHI in an exception message" is the control',
        '**CORRECTED 2026-10-28:** this read "per route\N{RIGHT DOUBLE QUOTATION MARK}. Neither is a '
        "completeness claim; the convention above remains the control for both.",
    ],
)
def test_the_scan_finds_each_shipped_wording(shipped: str) -> None:
    assert _claims(shipped), shipped


#: The shapes the marker-reading exemption at 09c971f14 let through (PR 2595 second hold), each
#: measured exempt there. With no marker reading, each is flagged.
_MARKER_SHAPES = {
    "a quote, then a later quote": '**CORRECTED 2026-10-28:** this read "per route"; it should read '
    '"the convention above remains the control for both".',
    "a later sentence": '**CORRECTED 2026-10-28:** this was per route. The fix said "the convention '
    'above remains the control for both".',
    "prose opening with Corrected": "Corrected ACK handling landed in 2026. The spec said "
    '"the convention above remains the control for both".',
    "NOT CORRECTED": 'NOT CORRECTED: this read "the convention above remains the control for both".',
    "CORRECTED-by-design": 'CORRECTED-by-design: this read "the convention above remains the '
    'control for both".',
    "CORRECTEDLY": 'CORRECTEDLY: this read "the convention above remains the control for both".',
    "a curly close, then a later quote": '**CORRECTED 2026-10-28:** this read "per route'
    "\N{RIGHT DOUBLE QUOTATION MARK}. The convention above remains the control for both; see "
    '"Who binds".',
}


@pytest.mark.parametrize("shape", sorted(_MARKER_SHAPES))
def test_a_claim_is_flagged_whatever_marker_surrounds_it(shape: str) -> None:
    assert _claims(_MARKER_SHAPES[shape]), shape


@pytest.mark.parametrize(
    "prose",
    [
        'The "never put PHI in an exception message" convention covers it only in text the '
        "engine's own authors write.",
        "the SPDX header convention is the control here",  # another convention
        'the "never put PHI in an exception message" convention is the controller',
    ],
)
def test_the_scan_passes_other_prose(prose: str) -> None:
    assert _claims(prose) == []


_RETRACTION = (
    '**CORRECTED 2026-10-28:** this read "the convention above remains the control for both".'
)
_ENTRY = ("docs/EXAMPLE.md", 'this read "the convention above remains the control for both"')


def test_an_allowlisted_quote_passes_only_at_its_own_path() -> None:
    assert _check(_RETRACTION, "docs/EXAMPLE.md", (_ENTRY,)) == ([], {_ENTRY})
    assert _claims(_RETRACTION, "docs/OTHER.md", (_ENTRY,))  # the same text elsewhere
    assert _claims(_RETRACTION, "docs/EXAMPLE.md", ())  # control: no entry, flagged
    # a second claim in the same file, outside the quote, is still flagged, and only it
    second = _RETRACTION + " The convention above remains the control."
    assert _claims(second, _ENTRY[0], (_ENTRY,)) == ["The convention above remains the control"]
    # a second copy of the quoted text: neither copy is exempt
    assert len(_claims(_RETRACTION + "\n" + _RETRACTION, _ENTRY[0], (_ENTRY,))) == 2
    # an entry covering only the head, or only the tail, of a claim exempts nothing
    head = (_ENTRY[0], 'this read "the convention above remains the')
    assert _claims(_RETRACTION, _ENTRY[0], (head,))
    tail = (_ENTRY[0], 'above remains the control for both"')
    assert _claims(_RETRACTION, _ENTRY[0], (tail,))
    # an entry spanning two claims exempts neither
    two = _RETRACTION + ' It also read "the convention above remains the control".'
    assert len(_claims(two, _ENTRY[0], ((_ENTRY[0], _folded(two)),))) == 2
    # two entries holding one claim: neither exempts it
    rival = (_ENTRY[0], 'read "the convention above remains the control for both"')
    assert _check(_RETRACTION, _ENTRY[0], (_ENTRY, rival)) == (
        ["the convention above remains the control"],
        set(),
    )
    # The guard does not read quoting: an entry naming the bare claim exempts it. Only review
    # stands between such an entry and _ALLOWED; this pins that the code claims no more.
    bare = (_ENTRY[0], "the convention above remains the control for both")
    assert _claims(_RETRACTION, _ENTRY[0], (bare,)) == []


def test_an_allowlist_entry_the_scan_never_uses_is_stale(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    example = docs / "EXAMPLE.md"
    example.write_text(_RETRACTION + "\n", encoding="utf-8")
    (tmp_path / "README.md").write_text(_RETRACTION + "\n", encoding="utf-8")

    def scan(*allowed: _Entry) -> tuple[dict[str, list[str]], list[_Entry]]:
        return _scan(tmp_path, _sources(tmp_path), allowed)

    assert scan(_ENTRY) == ({}, [])  # control: used, nothing flagged
    unused = [
        (_ENTRY[0], 'this read "the convention above remains the'),  # no whole claim inside
        ("docs/OTHER.md", _ENTRY[1]),  # no such file
        ("README.md", _ENTRY[1]),  # a file outside the scanned trees
        ("docs/example.md", _ENTRY[1]),  # not the path as the scan spells it
        ("./docs/EXAMPLE.md", _ENTRY[1]),
        ("docs/EXAMPLE.md", "reworded"),
    ]
    for entry in unused:
        assert scan(_ENTRY, entry) == ({}, [entry]), entry
    assert scan(_ENTRY, _ENTRY) == ({}, [_ENTRY])  # the repeat is stale; the first still works
    rival = (_ENTRY[0], 'read "the convention above remains the control for both"')
    hits, stale = scan(_ENTRY, rival)
    assert stale == [_ENTRY, rival]  # two entries for one claim: neither is used
    assert len(hits["docs/EXAMPLE.md"]) == 1
    example.write_text(_RETRACTION + "\n" + _RETRACTION + "\n", encoding="utf-8")
    hits, stale = scan(_ENTRY)
    assert stale == [_ENTRY]  # present twice, so it exempts neither copy
    assert len(hits["docs/EXAMPLE.md"]) == 2
    example.write_text("reworded, no quote left\n", encoding="utf-8")
    assert scan(_ENTRY) == ({}, [_ENTRY])


def test_no_allowlist_entry_is_stale() -> None:
    assert _tree()[2] == []


def test_no_document_names_the_convention_as_the_control() -> None:
    scanned, hits, _ = _tree()
    # A moved root would scan nothing and pass; the floor catches an empty or wrong one.
    assert scanned > 500
    assert not hits, (
        f"{hits} -- the exception-message convention binds only the engine's own authors, never a "
        "remote peer; point at docs/PHI.md section 7, 'Who the exception-message convention binds'. "
        "A correction that must quote the old claim verbatim adds an entry to _ALLOWED."
    )


def test_the_statement_the_pointers_cite_is_in_section_7() -> None:
    phi = (_ROOT / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert phi.count(_STATEMENT) == 1
    section_7 = phi.split("\n## 7.", 1)[1].split("\n## 8.", 1)[0]
    assert _STATEMENT in section_7
