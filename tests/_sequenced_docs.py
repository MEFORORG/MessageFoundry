# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The documents ``docs/README.md`` sequences for a new operator, read from the index itself.

BACKLOG #1749. The index's *Start here* section names six documents, in order, for a first
operator. Two guards hold those six to a stricter bar than the rest of ``docs/``: every install pin
names the version this tree ships (``tests/test_install_docs_pin_the_current_version.py``), and no
line names a config key the loader refuses (``tests/test_docs_cite_no_refused_config_keys.py``).

Both read the list from the index rather than from a hand copy. A hand copy is a second definition,
and the day the index swaps a document the copy would keep guarding the old one while the new one
went unguarded. Reading the index moves both guards with it.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
INDEX = REPO / "docs" / "README.md"

_HEADING = "## Start here"
# A numbered item whose bold lead is a relative link: `1. **[NAME.md](NAME.md)** -- ...`.
_ITEM = re.compile(r"^\d+\. \*\*\[[^\]]+\]\(([^)#\s]+)\)\*\*")

#: The index says "Six documents, in this sequence." A parse that finds another count has stopped
#: fitting the index, and a guard iterating over it would read the wrong set without saying so.
EXPECTED_COUNT = 6


def parse_sequenced_documents(index_text: str) -> list[str]:
    """Repo-relative POSIX paths of the documents the *Start here* section numbers, in order."""
    found: list[str] = []
    inside = False
    for line in index_text.splitlines():
        if line.startswith("## "):
            if inside:
                break
            inside = line.startswith(_HEADING)
            continue
        if inside and (match := _ITEM.match(line)):
            found.append(f"docs/{match.group(1)}")
    return found


def sequenced_documents() -> list[str]:
    """The live list, refused loudly when it no longer has the shape the index states.

    Called inside test bodies rather than at collection, so a broken index fails a test with this
    message instead of erroring the whole module at import.
    """
    docs = parse_sequenced_documents(INDEX.read_text(encoding="utf-8"))
    assert len(docs) == EXPECTED_COUNT, (
        f"{INDEX.relative_to(REPO).as_posix()} *Start here* parsed to {docs}; expected "
        f"{EXPECTED_COUNT} documents. The index or its item shape changed."
    )
    missing = [rel for rel in docs if not (REPO / rel).is_file()]
    assert not missing, f"the index sequences documents that do not exist: {missing}"
    return docs
