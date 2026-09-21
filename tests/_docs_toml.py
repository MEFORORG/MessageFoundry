# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Shared Markdown fence + TOML-section machinery for the documentation guards.

WHY THIS MODULE EXISTS: ``tests/test_runbook_proxy_tls_floor.py`` imported ``_TOML_FENCE_RE`` and
``_dedent`` FROM ``tests/test_off_loopback_runbook.py`` -- a test importing another test, which also
forced an ordering constraint on that module's skip guard (import the sibling first and this
module's skip becomes an incidental side effect of someone else's guard). Both names live here now,
so the guards share one definition and none of them imports another test.

IT HOLDS TWO DIFFERENT INSTRUMENTS AND THEY ANSWER DIFFERENT QUESTIONS.

:data:`TOML_FENCE_RE` + :func:`dedent` EXTRACT A LOADABLE BODY. A guard that feeds a fence to
``load_settings`` needs the block a reader copies, with the list indent stripped, and it must not
let a nested fence swallow the rest of the page -- hence the anchored ``(?P=indent)`` close.

:func:`line_contexts` ANSWERS "WHAT IS LINE N INSIDE?" for a whole document at once, which is what a
line-oriented scanner needs. It is line-oriented rather than a second whole-document regex because
the ``[section]`` header in force has no regex to find it at all: a header governs every line after
it until the block ends, which is state, not a match.

THE TWO DISAGREE ON ONE POINT, DELIBERATELY. ``TOML_FENCE_RE`` requires the closing fence to carry
the opening fence's indent; :func:`line_contexts` accepts a bare backtick run at any indent. The
asymmetry is chosen by which error each instrument can afford. An extractor that ends a block early
hands a truncated body to a loader, so it must be strict. An annotator that FAILS to end a block
treats the whole rest of the page as fenced, and a scanner that suppresses matches inside a foreign
fence would then silently stop scanning -- an under-report, the one direction a gate must not fail
in. Closing early only ever annotates more lines as prose, which reports more, not less.
``tests/test_docs_cite_no_refused_config_keys.py`` carries the corpus-wide control that the two
still agree on every ```toml fence in ``docs/``.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

# ```toml\n ... \n``` with the block's own indent captured. The optional leading indent matters: a
# fence nested inside a numbered step is indented to stay part of that list item, and a
# column-0-only pattern would silently skip it -- an unguarded block is exactly the defect class the
# runbook guards exist to stop. The closing fence must carry the SAME indent, so a nested fence
# can't swallow the rest of the document.
TOML_FENCE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<indent>[ ]{0,6})```toml[ \t]*$\n(?P<body>.*?)^(?P=indent)```[ \t]*$",
    re.DOTALL | re.MULTILINE,
)


def dedent(body: str, indent: str) -> str:
    """Strip the fence's own list indent from each line, so a guard loads what a reader copies."""
    if not indent:
        return body
    return "".join(
        line.removeprefix(indent) if line.strip() else line
        for line in body.splitlines(keepends=True)
    )


#: A fence OPENER: up to six spaces of list indent, three or more backticks, then the info string
#: whose first word is the language. The indent allowance mirrors ``TOML_FENCE_RE``'s and is not
#: captured -- an annotator reports what a line is inside, never how to dedent it.
_FENCE_OPEN_RE: Final[re.Pattern[str]] = re.compile(r"^[ ]{0,6}`{3,}(?P<info>.*)$")
#: A fence CLOSER: a backtick run and nothing else, at any indent (see the module docstring for why
#: this is deliberately more tolerant than ``TOML_FENCE_RE``'s anchored close).
_FENCE_CLOSE_RE: Final[re.Pattern[str]] = re.compile(r"^[ \t]*`{3,}[ \t]*$")
#: A TOML table header -- ``[table]`` or ``[[array.of.tables]]`` -- alone on its line, with the
#: leading indent a list-nested fence carries and an optional trailing comment. The ``[[...]]``
#: alternative is not decoration: a first draft of the section tracker matched only ``[table]``, and
#: ``[[inbound]]`` in ``docs/CONNECTIONS.md`` read as NO header in force, which is a different
#: answer entirely (measured 2026-09-20).
_SECTION_RE: Final[re.Pattern[str]] = re.compile(
    r"^[ \t]*(?:\[\[(?P<array>[^\[\]]+)\]\]|\[(?P<table>[^\[\]]+)\])[ \t]*(?:#.*)?$"
)
#: An ATX Markdown heading, which ends whatever prose block preceded it. Only consulted outside a
#: fence: inside one, ``# ...`` is a TOML/shell comment, not a heading.
_HEADING_RE: Final[re.Pattern[str]] = re.compile(r"^[ \t]*#{1,6}[ \t]")


class LineContext(NamedTuple):
    """What one line of a Markdown document sits inside.

    ``fence`` is the opener's language, lowercased, or the empty string for an unlabelled fence;
    ``None`` means the line is not inside a fence at all. A fence DELIMITER line reports the state
    it leaves behind, which is the closed state for a closer and the open one for an opener -- a
    delimiter is never content, so no caller reads it for a key.

    ``section`` is the ``[table]`` / ``[[array]]`` header in force, ``None`` when there is none.
    Entering a fence and leaving one both reset it: a block's headers do not reach the prose around
    it, and prose headers do not reach into the next block.
    """

    fence: str | None
    section: str | None


def line_contexts(text: str) -> tuple[LineContext, ...]:
    """One :class:`LineContext` per line of ``text``, in order, 0-indexed."""
    contexts: list[LineContext] = []
    fence: str | None = None
    section: str | None = None
    for line in text.splitlines():
        if fence is not None:
            if _FENCE_CLOSE_RE.match(line):
                fence = None
                section = None
                contexts.append(LineContext(fence, section))
                continue
        else:
            opener = _FENCE_OPEN_RE.match(line)
            if opener is not None:
                # The language is the info string's FIRST word: ```toml title="x" is still toml.
                info = opener.group("info").split()
                fence = info[0].lower() if info else ""
                section = None
                contexts.append(LineContext(fence, section))
                continue
            if _HEADING_RE.match(line):
                section = None
                contexts.append(LineContext(fence, section))
                continue
        header = _SECTION_RE.match(line)
        if header is not None:
            section = (header.group("array") or header.group("table")).strip()
        contexts.append(LineContext(fence, section))
    return tuple(contexts)
