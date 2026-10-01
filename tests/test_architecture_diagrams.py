# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hold the architecture diagrams to one home each, and to the tree they describe.

``docs/architecture-diagram.md`` is the index of every architecture diagram. Each diagram is a
Mermaid block in one home doc. This module fails on the four ways that set went stale before:

a. A COPY. ``docs/ARCHITECTURE.md`` once held copies of three blocks. The copies drifted: one said
   the web console may import ``parsing/`` while the source said the harness may. So a block that is
   identical to, or shares most of its lines with, a block in another doc is refused.
b. A FOLDER THAT IS NOT THERE. A token such as ``pipeline/`` inside a block in the index file names
   a folder. It must exist under ``messagefoundry/`` or at the repository root.
c. A DIAGRAM NOBODY CAN FIND. A top-level doc that holds a Mermaid block must be linked from the
   index file.
d. AN EXPORT. Eight ``.svg`` and ``.png`` exports sat beside the source with no link to them, and
   showed an older diagram than the source did. They are deleted, and must not come back.

The scope is the top-level ``docs/*.md`` files. ``docs/adr/`` and ``docs/benchmarks/`` are dated
records and are not scanned. The glob does not recurse, so they are out by construction.

Each rule is a small function over text, and each has a test that feeds it a bad sample. So the
failing case is a permanent test: a rule that stopped firing would fail here, not pass quietly. The
real-tree tests carry floors as well, because every rule passes on an empty corpus.

This module imports no engine code. It reads ``messagefoundry/`` only as a directory listing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = _ROOT / "docs"
_ENGINE = _ROOT / "messagefoundry"

#: The index file: the home of the four core diagrams and the list of every other one.
_HOME = "architecture-diagram.md"

#: The eight exports deleted on 2026-10-01, by name. ``_EXPORT`` below also refuses a new stem.
_DELETED_EXPORTS = tuple(
    f"architecture-{stem}.{ext}"
    for stem in ("components", "config-graph", "message-flow", "topology")
    for ext in ("svg", "png")
)
_EXPORT = re.compile(r"^architecture-[\w.-]+\.(?:svg|png)$", re.IGNORECASE)

_FENCE_OPEN = re.compile(r"^\s*`{3,}\s*mermaid\s*$")
_FENCE_CLOSE = re.compile(r"^\s*`{3,}\s*$")

#: A lower-case name directly followed by a slash that ends the token: ``pipeline/``. The
#: lookbehind drops ``<br/>`` and the middle of a path. The lookahead drops ``FastAPI/uvicorn`` and
#: ``decode/parse``.
_FOLDER = re.compile(r"(?<![\w<./-])([a-z_][a-z0-9_]*)/(?![\w/])")

#: A Markdown link to a ``.md`` file in the same directory, with or without ``./`` or an anchor.
_LINK = re.compile(r"\]\((?:\./)?([^)\s#/]+\.md)(?:#[^)\s]*)?\)")

#: Lines every diagram in the set shares on purpose, so they say nothing about a copy: the shared
#: ``classDef`` palette, comments, the diagram header and ``end``.
_SHARED_LINE = re.compile(r"^(?:classDef\b|%%|end$|(?:flowchart|graph|sequenceDiagram)\b)")

#: Two blocks in different docs that share this fraction of their lines are one diagram, copied and
#: then edited. Measured 2026-10-01 on the three copies this module was written against: 0.79, 0.94
#: and 1.0, so a rule for identical blocks alone would have missed two of the three. The largest
#: ratio between two different diagrams in the index file was 0.0 on the same day.
_NEAR_COPY = 0.6
#: Below this many lines a ratio is noise. An identical block is refused at any size.
_NEAR_COPY_MIN_LINES = 4


def mermaid_blocks(text: str) -> list[str]:
    """The body of every fenced ``mermaid`` block in ``text``, in order. An unclosed block raises."""
    blocks: list[str] = []
    body: list[str] | None = None
    for line in text.splitlines():
        if body is None:
            if _FENCE_OPEN.match(line):
                body = []
        elif _FENCE_CLOSE.match(line):
            blocks.append("\n".join(body))
            body = None
        else:
            body.append(line)
    if body is not None:
        raise ValueError("a mermaid block is opened and never closed")
    return blocks


def _normalised(block: str) -> str:
    return " ".join(block.split())


def _content_lines(block: str) -> frozenset[str]:
    lines = (_normalised(line) for line in block.splitlines())
    return frozenset(line for line in lines if line and not _SHARED_LINE.match(line))


def copied_blocks(docs: Mapping[str, str]) -> list[str]:
    """Rule a. Each pair of blocks, in two different docs, that is one diagram held twice."""
    held = [
        (name, number, block)
        for name in sorted(docs)
        for number, block in enumerate(mermaid_blocks(docs[name]), start=1)
    ]
    found: list[str] = []
    for i, (name_a, number_a, block_a) in enumerate(held):
        for name_b, number_b, block_b in held[i + 1 :]:
            if name_a == name_b:
                continue
            where = f"{name_a} block {number_a} and {name_b} block {number_b}"
            if _normalised(block_a) == _normalised(block_b):
                found.append(f"{where} are identical")
                continue
            lines_a, lines_b = _content_lines(block_a), _content_lines(block_b)
            if min(len(lines_a), len(lines_b)) < _NEAR_COPY_MIN_LINES:
                continue
            shared = len(lines_a & lines_b) / len(lines_a | lines_b)
            if shared >= _NEAR_COPY:
                found.append(f"{where} share {shared:.0%} of their lines")
    return found


def folder_tokens(text: str) -> set[str]:
    """Every folder name, such as ``pipeline``, that a Mermaid block in ``text`` writes as ``name/``."""
    return {name for block in mermaid_blocks(text) for name in _FOLDER.findall(block)}


def missing_folders(text: str, roots: Sequence[Path]) -> list[str]:
    """Rule b. The folder tokens in ``text`` that are a directory under none of ``roots``."""
    return sorted(
        name for name in folder_tokens(text) if not any((root / name).is_dir() for root in roots)
    )


def linked_docs(text: str) -> set[str]:
    """The same-directory ``.md`` files that ``text`` links to."""
    return set(_LINK.findall(text))


def unlinked_holders(docs: Mapping[str, str], home: str) -> list[str]:
    """Rule c. The docs that hold a Mermaid block and that ``home`` does not link to."""
    linked = linked_docs(docs[home])
    return sorted(
        name
        for name, text in docs.items()
        if name != home and mermaid_blocks(text) and name not in linked
    )


def stray_exports(names: Iterable[str]) -> list[str]:
    """Rule d. The file names that are a diagram export: one of the deleted eight, or a new stem."""
    return sorted(name for name in names if name in _DELETED_EXPORTS or _EXPORT.match(name))


def _real_docs() -> dict[str, str]:
    docs = {path.name: path.read_text(encoding="utf-8") for path in sorted(_DOCS.glob("*.md"))}
    # The floor for every real-tree test. A glob that found nothing would pass all four rules.
    assert len(docs) >= 40, f"only {len(docs)} top-level docs were read from {_DOCS}"
    assert _HOME in docs, f"{_HOME} is not among the docs that were read"
    return docs


# --- the real tree ---------------------------------------------------------------------------------


def test_the_index_file_holds_its_four_core_diagrams() -> None:
    blocks = mermaid_blocks(_real_docs()[_HOME])
    assert len(blocks) >= 4, f"{_HOME} holds {len(blocks)} Mermaid blocks, expected at least four"
    for number, block in enumerate(blocks, start=1):
        assert _content_lines(block), f"{_HOME} block {number} is empty"


def test_no_diagram_is_held_in_two_docs() -> None:
    assert copied_blocks(_real_docs()) == [], (
        "a diagram has one home doc. Link to it from the second doc, do not copy the block"
    )


def test_every_folder_the_index_file_names_exists() -> None:
    text = _real_docs()[_HOME]
    assert missing_folders(text, [_ENGINE, _ROOT]) == [], (
        f"{_HOME} names a folder that is not under messagefoundry/ or the repository root"
    )
    # The floor, checked second so a misspelt folder gets the message above. The extractor must
    # find the engine packages the topology diagram names, and the listing must see them on disk.
    tokens = folder_tokens(text)
    assert {"pipeline", "transports", "parsing", "store", "config"} <= tokens, sorted(tokens)
    for name in ("pipeline", "store"):
        assert (_ENGINE / name).is_dir(), f"messagefoundry/{name} is not a directory here"


def test_every_doc_that_holds_a_diagram_is_linked_from_the_index_file() -> None:
    docs = _real_docs()
    # The floor: the link reader must see the index table, which links at least these.
    assert {"SECURITY.md", "DEPLOYMENT.md", "CONNECTIONS.md"} <= linked_docs(docs[_HOME])
    assert unlinked_holders(docs, _HOME) == [], (
        f"add a row for each to the 'Every architecture diagram' table in docs/{_HOME}"
    )


def test_no_diagram_export_is_back() -> None:
    names = [path.name for path in _DOCS.iterdir()]
    # The floor: the listing must see the directory, or an export in it could not be seen either.
    assert _HOME in names
    assert stray_exports(names) == [], (
        "the Mermaid block is the only copy of a diagram. Do not commit an exported image"
    )


# --- each rule, fed a bad sample ---------------------------------------------------------------------

_FENCE = "`" * 3
_BLOCK = "\n".join(
    [
        "flowchart TB",
        "  classDef core fill:#e8f5e9,stroke:#2e7d32,color:#10240f;",
        '  API["api/: FastAPI/uvicorn<br/>HTTP + WebSocket"]:::core',
        '  PIPE["pipeline/: RegistryRunner"]:::core',
        '  STORE[("store/: staged queue")]:::core',
        '  HARNESS["Test harness"]:::core',
        "  API --> PIPE",
        "  PIPE --> STORE",
        '  HARNESS -.->|"decode/parse/validate"| API',
    ]
)


def _doc(*blocks: str) -> str:
    parts = ["# A doc", ""]
    for block in blocks:
        parts += [f"{_FENCE}mermaid", block, _FENCE, ""]
    return "\n".join(parts)


def test_mermaid_blocks_reads_each_block_and_nothing_else() -> None:
    other = f"{_FENCE}python\nprint('flowchart TB')\n{_FENCE}\n"
    text = _doc(_BLOCK) + other + _doc("flowchart LR\n  A --> B")
    assert mermaid_blocks(text) == [_BLOCK, "flowchart LR\n  A --> B"]
    assert mermaid_blocks("# no diagram here\n") == []


def test_an_unclosed_block_is_an_error_not_an_empty_result() -> None:
    with pytest.raises(ValueError, match="never closed"):
        mermaid_blocks(f"{_FENCE}mermaid\nflowchart TB\n  A --> B\n")


def test_a_block_copied_into_a_second_doc_is_refused() -> None:
    reindented = "\n".join("      " + line.strip() + "  " for line in _BLOCK.splitlines())
    found = copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": _doc(reindented)})
    assert found == ["ONE.md block 1 and TWO.md block 1 are identical"]


def test_a_copy_that_has_drifted_is_still_refused() -> None:
    # The measured failure: the copy in the second doc had a label edited after it was copied.
    drifted = _BLOCK.replace("staged queue", "staged queue on SQLite")
    found = copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": _doc(drifted)})
    assert found == ["ONE.md block 1 and TWO.md block 1 share 75% of their lines"]


def test_two_different_diagrams_are_not_a_copy() -> None:
    # They share the header and the classDef palette, as every diagram in the set does on purpose.
    other = "\n".join(
        [
            "flowchart TB",
            "  classDef core fill:#e8f5e9,stroke:#2e7d32,color:#10240f;",
            '  USER(["Operator"]):::core',
            '  LOGIN["Sign-in"]:::core',
            '  RBAC["Permission check"]:::core',
            "  USER --> LOGIN",
            "  LOGIN --> RBAC",
        ]
    )
    assert copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": _doc(other)}) == []
    # And the same block twice in ONE doc is not this rule's subject.
    assert copied_blocks({"ONE.md": _doc(_BLOCK, _BLOCK)}) == []


def test_folder_tokens_takes_folders_and_leaves_the_look_alikes() -> None:
    # Left alone: <br/>, FastAPI/uvicorn, decode/parse/validate, and a folder named outside a block.
    text = _doc(_BLOCK) + "\nThe `transports/` folder is prose, not a block.\n"
    assert folder_tokens(text) == {"api", "pipeline", "store"}


def test_a_folder_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    for name in ("api", "pipeline"):
        (tmp_path / "engine" / name).mkdir(parents=True)
    (tmp_path / "store").mkdir()
    (tmp_path / "engine" / "store.py").write_text("", encoding="utf-8")
    roots = [tmp_path / "engine", tmp_path]
    assert missing_folders(_doc(_BLOCK), roots) == []
    # Under the first root alone, `store` is only a file, and a file of that name is not a folder.
    assert missing_folders(_doc(_BLOCK), roots[:1]) == ["store"]
    renamed = _BLOCK.replace("pipeline/", "pipelne/")
    assert missing_folders(_doc(renamed), roots) == ["pipelne"]


# The three below break the REAL index file, in memory. They read that one file and nothing else
# from the tree, so a defect somewhere else in docs/ fails its own rule above and not these.


def test_a_real_engine_folder_renamed_in_the_index_file_is_refused() -> None:
    text = _real_docs()[_HOME]
    roots = [_ENGINE, _ROOT]
    assert "pipelne" not in missing_folders(text, roots)
    assert "pipelne" in missing_folders(text.replace("pipeline/", "pipelne/"), roots)


def test_a_doc_holding_a_diagram_with_no_link_from_the_index_is_refused() -> None:
    home = "[SECURITY.md](SECURITY.md), [a section](./DEPLOYMENT.md#topologies), `ORPHAN.md`\n"
    docs = {
        "INDEX.md": home + _doc(_BLOCK),
        "SECURITY.md": _doc("flowchart LR\n  A --> B"),
        "DEPLOYMENT.md": _doc("flowchart LR\n  C --> D"),
        "ORPHAN.md": _doc("flowchart LR\n  E --> F"),
        "PROSE.md": "# no diagram, so no link is needed\n",
    }
    assert linked_docs(home) == {"SECURITY.md", "DEPLOYMENT.md"}
    assert unlinked_holders(docs, "INDEX.md") == ["ORPHAN.md"]


def test_a_new_diagram_doc_is_refused_until_the_real_index_links_it() -> None:
    name = "A-NEW-DIAGRAM-DOC.md"
    docs = {_HOME: _real_docs()[_HOME], name: _doc("flowchart LR\n  A --> B")}
    assert unlinked_holders(docs, _HOME) == [name]
    docs[_HOME] += f"\n| New | [{name}]({name}) |\n"
    assert unlinked_holders(docs, _HOME) == []


def test_a_real_block_copied_into_a_second_doc_is_refused() -> None:
    home = _real_docs()[_HOME]
    block = mermaid_blocks(home)[1]
    assert "Postgres" in block
    name = "A-NEW-DIAGRAM-DOC.md"
    assert copied_blocks({_HOME: home, name: _doc(block)}) == [
        f"{name} block 1 and {_HOME} block 2 are identical"
    ]
    drifted = copied_blocks({_HOME: home, name: _doc(block.replace("Postgres", "PostgreSQL"))})
    assert len(drifted) == 1, drifted
    assert drifted[0].startswith(f"{name} block 1 and {_HOME} block 2 share "), drifted


@pytest.mark.parametrize("name", _DELETED_EXPORTS)
def test_each_deleted_export_is_refused_by_name(name: str) -> None:
    assert stray_exports([_HOME, "ARCHITECTURE.md", name]) == [name]


def test_an_export_under_a_new_stem_is_refused_and_other_files_are_not() -> None:
    names = ["architecture-security.SVG", "architecture-diagram.md", "logo.png", "ARCHITECTURE.md"]
    assert stray_exports(names) == ["architecture-security.SVG"]
    assert len(_DELETED_EXPORTS) == 8
