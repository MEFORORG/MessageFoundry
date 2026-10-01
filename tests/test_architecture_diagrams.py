# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hold the architecture diagrams to one home each, and to the tree they describe.

``docs/architecture-diagram.md`` is the index of every architecture diagram. Each diagram is a
Mermaid block in one home doc. This module fails on the four ways that set went stale before:

a. A COPY. ``docs/ARCHITECTURE.md`` once held copies of three blocks. The copies drifted: one said
   the web console may import ``parsing/`` while the source said the harness may. So a block that is
   identical to a block in another doc, or shares most of the smaller block's lines, is refused.
b. A FOLDER THAT IS NOT THERE. A token such as ``pipeline/`` inside a block in the index file names
   a folder. It must exist under ``messagefoundry/`` or at the repository root.
c. A DIAGRAM NOBODY CAN FIND. A top-level doc that holds a Mermaid block must have a row in the
   index file's "Every architecture diagram" table. A link in prose does not count.
d. AN EXPORT. Eight ``.svg`` and ``.png`` exports sat beside the source with no link to them, and
   showed an older diagram than the source did. They are deleted, and must not come back.

Each rule is a small function over text, and each has a test that feeds it a bad sample. So the
failing case is a permanent test: a rule that stopped firing would fail here, not pass quietly. The
real-tree tests carry floors as well, because every rule passes on an empty corpus.

WHAT THIS DOES NOT COVER, at least:

- Rules a and c read the top-level ``docs/*.md`` files. ``docs/adr/`` and ``docs/benchmarks/`` are
  dated records and the glob does not recurse into them. The root ``README.md`` and the package
  READMEs are outside it too, so a block copied there is not refused.
- Rule a compares whole lines. A copy whose node ids were all renamed shares no line and passes.
- Rule c runs one way. A table row whose home doc holds no diagram is not refused.
- Rule b accepts a folder at the repository root, so a root folder can stand in for an engine
  package of the same name.

This module imports no engine code. It reads ``messagefoundry/`` only as a directory listing.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_DOCS = _ROOT / "docs"
_ENGINE = _ROOT / "messagefoundry"

#: The index file: the home of the four core diagrams and the list of every other one.
_HOME = "architecture-diagram.md"
#: The heading of the table in the index file that rule c reads.
_INDEX_HEADING = "## Every architecture diagram"

#: A diagram export, by file name: ``architecture-topology.svg``. Any stem, any image type.
_EXPORT = re.compile(r"^architecture[-_][\w.-]*\.(?:svg|png|jpe?g|gif|webp|pdf)$", re.IGNORECASE)
#: The eight exports deleted on 2026-10-01. Test data only: each must match ``_EXPORT``.
_DELETED_EXPORTS = tuple(
    f"architecture-{stem}.{ext}"
    for stem in ("components", "config-graph", "message-flow", "topology")
    for ext in ("svg", "png")
)

#: A fence line: an optional block-quote prefix, a run of three or more backticks or tildes, and an
#: info string. Group 1 is the prefix, 2 the run, 3 the first word of the info string, 4 the rest.
_FENCE_LINE = re.compile(r"^([ \t>]*)(`{3,}|~{3,})[ \t]*(\S*)(.*)$")
_QUOTE_PREFIX = re.compile(r"^[ \t]*(?:>[ \t]?)+")

#: One or more lower-case path segments, each ending in a slash, that end the token:
#: ``pipeline/``, ``samples/config/``. The lookbehind drops ``<br/>`` and the tail of a longer
#: path. The lookahead drops ``FastAPI/uvicorn`` and ``decode/parse``. A first segment is two
#: characters or more, so ``w/ TLS`` is not a folder.
_FOLDER = re.compile(r"(?<![\w<./-])((?:[a-z_][a-z0-9_-]+/)+)(?!\w)")

#: A Markdown link to a ``.md`` file in the same directory, with or without ``./`` or an anchor.
_LINK = re.compile(r"\]\((?:\./)?([^)\s#/]+\.md)(?:#[^)\s]*)?\)")

#: Lines every diagram in the set shares on purpose, so they say nothing about a copy: the shared
#: ``classDef`` palette, comments, the diagram header and ``end``.
_SHARED_LINE = re.compile(r"^(?:classDef\b|%%|end$|(?:flowchart|graph|sequenceDiagram)\b)")

#: Two blocks in different docs are one diagram, copied and then edited, when this fraction of the
#: SMALLER block's lines is also in the other. Measured against the smaller block, so a lifted
#: excerpt counts. Measured 2026-10-01 on the three copies this module was written against: 0.88,
#: 0.97 and 1.0, so a rule for identical blocks alone would have missed two of the three. The
#: largest ratio between two different diagrams in the index file was 0.0 on the same day.
_NEAR_COPY = 0.6
#: Below this many lines a ratio is noise. An identical block is refused at any size.
_NEAR_COPY_MIN_LINES = 4


def mermaid_blocks(text: str) -> list[str]:
    """The body of every fenced ``mermaid`` block in ``text``, in order.

    Reads backtick and tilde fences, an info string with more after ``mermaid``, any letter case,
    and a fence inside a block quote. A fence closes on a run of the same character that is at
    least as long, so a Mermaid block quoted inside a longer fence is an example, not a diagram.
    An unclosed Mermaid block raises: an empty result there would read as "no diagram".
    """
    blocks: list[str] = []
    run = ""  # the fence run that opened the block being read, or "" outside any block
    quoted = False
    body: list[str] | None = None  # the lines kept, when the open block is a Mermaid block
    for line in text.splitlines():
        fence = _FENCE_LINE.match(line)
        if not run:
            if fence:
                run = fence.group(2)
                quoted = ">" in fence.group(1)
                body = [] if fence.group(3).lower() == "mermaid" else None
            continue
        closes = (
            fence is not None
            and fence.group(2)[0] == run[0]
            and len(fence.group(2)) >= len(run)
            and not fence.group(3)
            and not fence.group(4).strip()
        )
        if closes:
            if body is not None:
                blocks.append("\n".join(body))
            run, body = "", None
        elif body is not None:
            body.append(_QUOTE_PREFIX.sub("", line) if quoted else line)
    if body is not None:
        raise ValueError("a mermaid block is opened and never closed")
    return blocks


def _blocks_by_doc(docs: Mapping[str, str]) -> dict[str, list[str]]:
    held: dict[str, list[str]] = {}
    for name in sorted(docs):
        try:
            held[name] = mermaid_blocks(docs[name])
        except ValueError as exc:
            raise ValueError(f"{name}: {exc}") from exc
    return held


def _normalised(block: str) -> str:
    return " ".join(block.split())


def _content_lines(block: str) -> frozenset[str]:
    lines = (_normalised(line) for line in block.splitlines())
    return frozenset(line for line in lines if line and not _SHARED_LINE.match(line))


def copied_blocks(docs: Mapping[str, str]) -> list[str]:
    """Rule a. Each pair of blocks, in two different docs, that is one diagram held twice."""
    held = [
        (name, number, block)
        for name, blocks in _blocks_by_doc(docs).items()
        for number, block in enumerate(blocks, start=1)
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
            smaller = min(len(lines_a), len(lines_b))
            if smaller < _NEAR_COPY_MIN_LINES:
                continue
            shared = len(lines_a & lines_b) / smaller
            if shared >= _NEAR_COPY:
                found.append(f"{where} share {shared:.0%} of the smaller block's lines")
    return found


def folder_tokens(text: str) -> set[str]:
    """Every folder path, such as ``pipeline``, that a Mermaid block in ``text`` writes as ``name/``."""
    return {path.rstrip("/") for block in mermaid_blocks(text) for path in _FOLDER.findall(block)}


def _is_folder(path: Path) -> bool:
    # A folder git has emptied can linger on disk holding only __pycache__. That is not a folder
    # here: a renamed package would otherwise pass on the machine that renamed it and fail in CI.
    return path.is_dir() and any(child.name != "__pycache__" for child in path.iterdir())


def missing_folders(text: str, roots: Sequence[Path]) -> list[str]:
    """Rule b. The folder tokens in ``text`` that are a folder under none of ``roots``."""
    return sorted(
        name for name in folder_tokens(text) if not any(_is_folder(root / name) for root in roots)
    )


def indexed_docs(text: str) -> set[str]:
    """The docs named in the rows of the index table in ``text``. No such table raises."""
    lines = text.splitlines()
    if _INDEX_HEADING not in lines:
        raise ValueError(f"no {_INDEX_HEADING!r} heading")
    named: set[str] = set()
    for line in lines[lines.index(_INDEX_HEADING) + 1 :]:
        if line.startswith("#") or line.startswith("---"):
            break
        if line.startswith("|"):
            named.update(_LINK.findall(line))
    return named


def unindexed_holders(docs: Mapping[str, str], home: str) -> list[str]:
    """Rule c. The docs that hold a Mermaid block and have no row in the index table of ``home``."""
    indexed = indexed_docs(docs[home])
    return sorted(
        name
        for name, blocks in _blocks_by_doc(docs).items()
        if name != home and blocks and name not in indexed
    )


def stray_exports(names: Iterable[str]) -> list[str]:
    """Rule d. The paths whose file name is a diagram export."""
    return sorted(name for name in names if _EXPORT.match(name.rsplit("/", 1)[-1]))


@functools.cache
def _real_docs() -> Mapping[str, str]:
    docs = {path.name: path.read_text(encoding="utf-8") for path in sorted(_DOCS.glob("*.md"))}
    # The floor for every real-tree test. A glob that found nothing would pass all four rules.
    assert len(docs) >= 40, f"only {len(docs)} top-level docs were read from {_DOCS}"
    assert _HOME in docs, f"{_HOME} is not among the docs that were read"
    return MappingProxyType(docs)


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
        f"a Mermaid label in docs/{_HOME} writes `name/`, and no such folder is under "
        "messagefoundry/ or the repository root. Fix the name, or reword the label if it is not "
        "meant as a folder"
    )
    # The floor, checked second so a misspelt folder gets the message above. The extractor must
    # find the engine packages the topology diagram names, and the listing must see them on disk.
    tokens = folder_tokens(text)
    assert {"pipeline", "transports", "parsing", "store", "config"} <= tokens, sorted(tokens)
    for name in ("pipeline", "store"):
        assert _is_folder(_ENGINE / name), f"messagefoundry/{name} is not a folder here"


def test_every_doc_that_holds_a_diagram_has_a_row_in_the_index_table() -> None:
    docs = _real_docs()
    # The floor: the table reader must see the table. Its first four rows name the index file.
    assert _HOME in indexed_docs(docs[_HOME])
    assert unindexed_holders(docs, _HOME) == [], (
        f"add a row for each to the 'Every architecture diagram' table in docs/{_HOME}"
    )


def test_no_diagram_export_is_back() -> None:
    names = [path.relative_to(_DOCS).as_posix() for path in _DOCS.rglob("*") if path.is_file()]
    # The floor: the walk must see the directory, or an export in it could not be seen either.
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
        '  API["api/: FastAPI/uvicorn<br/>HTTP + WebSocket w/ TLS"]:::core',
        '  PIPE["pipeline/: RegistryRunner"]:::core',
        '  STORE[("store/: staged queue")]:::core',
        '  HARNESS["Test harness"]:::core',
        "  API --> PIPE",
        "  PIPE --> STORE",
        '  HARNESS -.->|"decode/parse/validate"| API',
    ]
)
_SMALL = "flowchart LR\n  A --> B"


def _doc(*blocks: str, fence: str = _FENCE, info: str = "mermaid") -> str:
    parts = ["# A doc", ""]
    for block in blocks:
        parts += [f"{fence}{info}", block, fence, ""]
    return "\n".join(parts)


def test_mermaid_blocks_reads_each_block_and_nothing_else() -> None:
    other = f"{_FENCE}python\nprint('flowchart TB')\n{_FENCE}\n"
    text = _doc(_BLOCK) + other + _doc(_SMALL)
    assert mermaid_blocks(text) == [_BLOCK, _SMALL]
    assert mermaid_blocks("# no diagram here\n") == []


@pytest.mark.parametrize(
    ("fence", "info"),
    [("~~~", "mermaid"), ("````", "mermaid"), (_FENCE, "Mermaid"), (_FENCE, " mermaid {init: {}}")],
)
def test_every_fence_form_that_renders_is_read(fence: str, info: str) -> None:
    assert mermaid_blocks(_doc(_SMALL, fence=fence, info=info)) == [_SMALL]


def test_a_block_inside_a_block_quote_is_read_without_its_markers() -> None:
    quoted = "\n".join("> " + line for line in _doc(_SMALL).splitlines())
    assert mermaid_blocks(quoted) == [_SMALL]


def test_a_block_quoted_inside_a_longer_fence_is_an_example_not_a_diagram() -> None:
    example = "\n".join(["````markdown", _doc(_SMALL), "````", ""])
    assert mermaid_blocks(example) == []
    assert mermaid_blocks(example + _doc(_BLOCK)) == [_BLOCK]


def test_an_unclosed_block_is_an_error_that_names_its_doc() -> None:
    unclosed = f"{_FENCE}mermaid\nflowchart TB\n  A --> B\n"
    with pytest.raises(ValueError, match="never closed"):
        mermaid_blocks(unclosed)
    with pytest.raises(ValueError, match=r"TWO\.md: .*never closed"):
        copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": unclosed})


def test_a_block_copied_into_a_second_doc_is_refused() -> None:
    reindented = "\n".join("      " + line.strip() + "  " for line in _BLOCK.splitlines())
    found = copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": _doc(reindented)})
    assert found == ["ONE.md block 1 and TWO.md block 1 are identical"]


def test_a_copy_that_has_drifted_is_still_refused() -> None:
    # The measured failure: the copy in the second doc had a label edited after it was copied.
    drifted = _BLOCK.replace("staged queue", "staged queue on SQLite")
    found = copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": _doc(drifted)})
    assert found == ["ONE.md block 1 and TWO.md block 1 share 86% of the smaller block's lines"]


def test_an_excerpt_lifted_into_a_second_doc_is_refused() -> None:
    excerpt = "\n".join(["flowchart TB", *_BLOCK.splitlines()[2:6]])
    found = copied_blocks({"ONE.md": _doc(_BLOCK), "TWO.md": _doc(excerpt)})
    assert found == ["ONE.md block 1 and TWO.md block 1 share 100% of the smaller block's lines"]


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
    # Left alone: <br/>, FastAPI/uvicorn, `w/ TLS`, decode/parse/validate, and a folder named in
    # prose outside any block.
    text = _doc(_BLOCK) + "\nThe `transports/` folder is prose, not a block.\n"
    assert folder_tokens(text) == {"api", "pipeline", "store"}
    nested = _doc('flowchart LR\n  A["samples/config/ and net-helper/"] --> B[".github/workflows"]')
    assert folder_tokens(nested) == {"samples/config", "net-helper"}


def test_a_folder_that_does_not_exist_is_refused(tmp_path: Path) -> None:
    for name in ("api", "pipeline"):
        (tmp_path / "engine" / name).mkdir(parents=True)
        (tmp_path / "engine" / name / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "x.db").write_text("", encoding="utf-8")
    (tmp_path / "engine" / "store.py").write_text("", encoding="utf-8")
    roots = [tmp_path / "engine", tmp_path]
    assert missing_folders(_doc(_BLOCK), roots) == []
    # Under the first root alone, `store` is only a file, and a file of that name is not a folder.
    assert missing_folders(_doc(_BLOCK), roots[:1]) == ["store"]
    renamed = _BLOCK.replace("pipeline/", "pipelne/")
    assert missing_folders(_doc(renamed), roots) == ["pipelne"]


def test_a_folder_git_emptied_down_to_its_bytecode_cache_is_refused(tmp_path: Path) -> None:
    (tmp_path / "api" / "__pycache__").mkdir(parents=True)
    (tmp_path / "pipeline").mkdir()
    (tmp_path / "store").mkdir()
    (tmp_path / "store" / "__init__.py").write_text("", encoding="utf-8")
    assert missing_folders(_doc(_BLOCK), [tmp_path]) == ["api", "pipeline"]


def test_a_doc_holding_a_diagram_with_no_row_in_the_index_table_is_refused() -> None:
    home = "\n".join(
        [
            "Prose links do not count: [PROSE-ONLY.md](PROSE-ONLY.md).",
            "",
            _INDEX_HEADING,
            "",
            "| Diagram | Home doc |",
            "|---|---|",
            "| One | [SECURITY.md](SECURITY.md) |",
            "| Two | [a section](./DEPLOYMENT.md#topologies) and `ORPHAN.md` |",
            "",
            "## 1. The next section",
            "",
            "| Not the index | [LATER-TABLE.md](LATER-TABLE.md) |",
            "",
        ]
    )
    docs = {
        "INDEX.md": home + _doc(_BLOCK),
        "SECURITY.md": _doc(_SMALL),
        "DEPLOYMENT.md": _doc(_SMALL.replace("A", "C")),
        "ORPHAN.md": _doc(_SMALL.replace("A", "D")),
        "PROSE-ONLY.md": _doc(_SMALL.replace("A", "E")),
        "LATER-TABLE.md": _doc(_SMALL.replace("A", "F")),
        "NO-DIAGRAM.md": "# no diagram, so no row is needed\n",
    }
    assert indexed_docs(home) == {"SECURITY.md", "DEPLOYMENT.md"}
    assert unindexed_holders(docs, "INDEX.md") == ["LATER-TABLE.md", "ORPHAN.md", "PROSE-ONLY.md"]


def test_an_index_file_with_no_index_table_is_an_error() -> None:
    with pytest.raises(ValueError, match="Every architecture diagram"):
        indexed_docs("# A doc\n\n[SECURITY.md](SECURITY.md)\n")


# The three below break the REAL index file, in memory. They read that one file and nothing else
# from the tree, so a defect somewhere else in docs/ fails its own rule above and not these.


def test_a_real_engine_folder_renamed_in_the_index_file_is_refused() -> None:
    text = _real_docs()[_HOME]
    roots = [_ENGINE, _ROOT]
    assert "pipelne" not in missing_folders(text, roots)
    assert "pipelne" in missing_folders(text.replace("pipeline/", "pipelne/"), roots)


def test_a_new_diagram_doc_is_refused_until_the_real_index_table_names_it() -> None:
    home = _real_docs()[_HOME]
    name = "A-NEW-DIAGRAM-DOC.md"
    docs = {_HOME: home, name: _doc(_SMALL)}
    assert unindexed_holders(docs, _HOME) == [name]
    # A link in prose, outside the table, changes nothing.
    docs[_HOME] = home + f"\nSee [{name}]({name}).\n"
    assert unindexed_holders(docs, _HOME) == [name]
    row = f"| New | [{name}]({name}) |"
    docs[_HOME] = home.replace("| Diagram | Home doc |", f"| Diagram | Home doc |\n{row}", 1)
    assert docs[_HOME] != home
    assert unindexed_holders(docs, _HOME) == []


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


def test_an_export_under_a_new_name_is_refused_and_other_files_are_not() -> None:
    assert len(_DELETED_EXPORTS) == 8
    kept = [_HOME, "ARCHITECTURE.md", "logo.png", "benchmarks/results/run/engine_flame.svg"]
    back = ["architecture-security.SVG", "architecture_topology.pdf", "img/architecture-ha.jpeg"]
    assert stray_exports(kept + back) == sorted(back)
