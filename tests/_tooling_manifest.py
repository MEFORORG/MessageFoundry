# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one Python reader of ``tests/tooling_manifest.txt`` (BACKLOG #1434).

Three copies of this rule used to live in three files: ``tests/conftest.py`` (the copy that
applies the ``tooling`` marker), ``tests/test_tooling_partition.py`` (the copy that pins the list
against the tree) and ``tests/test_ci_tooling_gate.py`` (the copy that mirrors ci.yml's path gate).
Nothing pinned them against each other, so the checker could agree with itself while the hook that
actually moves tests between CI legs read the file differently. All three now import from here,
and ``test_the_manifest_has_one_reader`` reds on at least the shapes those copies were written in.

CI.YML READS THE SAME FILE IN SHELL, and it cannot import this module::

    grep -qxFf <(grep -vE '^[[:space:]]*(#|$)' tests/tooling_manifest.txt)

That reader keeps each entry line exactly as written and matches it whole against the paths
``git diff --name-only`` prints. So this reader REFUSES the ways found so far in which the two
would disagree, rather than quietly tidying a line. A line Python tidied and marked would match
nothing in ci.yml, so an edit to that test would never summon the tooling job. At least these are
refused:

* an entry line holding anything outside ``[A-Za-z0-9_./-]``. That covers whitespace, a CR or a
  byte-order mark inside the line, and other control characters. It also covers non-ASCII, quotes
  and backslashes, which git C-quotes in its output;
* a NUL on any line, including a comment, because it flips grep into binary mode for the whole
  file.

Two things are tolerated. A byte-order mark in front of a first line that is a comment or blank
is harmless to both readers. A CR at the end of a line is tolerated because a Windows checkout
under ``core.autocrlf`` writes one on every line. ``.gitattributes`` pins the file to LF, so a
CRLF line cannot reach the committed blob the ubuntu job reads. This is not proof that the two readers agree on every input: the grep
pipeline itself is not executed by any test.

A MISSING, UNREADABLE OR MALFORMED MANIFEST RAISES here, on purpose. See the partition block in
tests/conftest.py for why "mark nothing" is the dangerous fallback.
"""

from __future__ import annotations

import re
from pathlib import Path

MANIFEST = Path(__file__).resolve().parent / "tooling_manifest.txt"

_ENTRY = re.compile(r"[A-Za-z0-9_./-]+")


def _refuse(number: int, line: str, why: str) -> ValueError:
    return ValueError(
        f"{MANIFEST.name} line {number} is {line!r}: {why}. ci.yml's `grep -qxFf` matches each "
        "entry line whole against the changed paths, so a line it reads differently would mark "
        "the test while an edit to it never summoned the tooling job."
    )


def entries_from(text: str) -> list[str]:
    """The manifest's entry lines, in order, with blanks and ``#`` comments dropped.

    Kept as full ``tests/<name>.py`` paths, because that is what ci.yml's path gate matches. A
    list and not a set, so a duplicate stays visible to the check that forbids one. Split on
    ``\\n`` only, as grep does: ``str.splitlines`` would also break a line on a lone CR, ``\\v``,
    ``\\f`` and several Unicode separators that grep treats as ordinary characters.

    Pass the text with its line endings untranslated (``newline=""``), or a lone CR is turned into
    a line break before this function can refuse it. Raises ``ValueError`` on the lines listed in
    the module docstring.
    """
    kept: list[str] = []
    for number, physical in enumerate(text.split("\n"), start=1):
        line = physical.removesuffix("\r")
        if "\x00" in line:
            raise _refuse(number, line, "a NUL makes grep read the whole file as binary")
        probe = line.removeprefix("﻿") if number == 1 else line
        if not probe.strip() or probe.lstrip().startswith("#"):
            continue
        if not _ENTRY.fullmatch(line):
            raise _refuse(
                number, line, "an entry must be a bare path made only of A-Z a-z 0-9 _ . / -"
            )
        kept.append(line)
    return kept


def names_from(text: str) -> list[str]:
    """The basenames the ``tooling`` marker keys on, from the entries in ``text``."""
    return [entry.rsplit("/", 1)[-1] for entry in entries_from(text)]


def _read() -> str:
    return MANIFEST.read_text(encoding="utf-8", newline="")


def entries() -> list[str]:
    """``entries_from`` over the real manifest."""
    return entries_from(_read())


def names() -> list[str]:
    """``names_from`` over the real manifest."""
    return names_from(_read())
