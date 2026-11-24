# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 item 1, S19-73 and S19-74: two comments in ``_serve`` that stated false things.

Each pin reads one block of own-line comments in the one ``def _serve`` in
``messagefoundry/__main__.py``, lower-cased with comment markers and runs of whitespace
collapsed, so a revert that reflows a line is still caught; a control below shows that. Each
block is found by an anchor, so a pin whose comment moved fails rather than reading nothing. A
pin bans the false wording it names, and a reworded revert can pass it.

* S19-73, the block above ``_serve``'s ``install_remote_debug_guard()`` call. Before engine PR
  3019 it said the window before the hook "stays open"; the module-level call (vault BACKLOG
  #2742) is made ahead of the module's other imports and of argument parsing, and
  ``messagefoundry.remotedebug``'s module docstring says what start-up still runs before it.
  PR 3019's wording said the call covers a caller that reached ``_serve`` "some other way";
  every route imports the module first. The finding's other half, function-local re-imports of
  ``sys`` and ``Path``, was already gone before PR 3019, so that pin guards a return only; its
  control shows it can fail.
* S19-74, the sentence of the posture-B gate's comment that gives the loopback arm's reason.
  Before PR 3019 it cited upgrade breakage on working deployments, a cost ``CLAUDE.md`` section 0
  makes vacuous.
"""

from __future__ import annotations

import ast
import functools
import io
import re
import tokenize
from pathlib import Path

import messagefoundry
from tests._ast_sites import call_sites, named_func, parse_source

_MAIN = Path(messagefoundry.__file__).resolve().parent / "__main__.py"
_LOOPBACK_ARM = "the loopback arm warns rather than refuses"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).lower().strip()


@functools.cache
def _blocks(source: str, func: str) -> tuple[tuple[int, int, str], ...]:
    """Each run of own-line comments inside ``func``: first line, last line, normalised text.
    A comment that trails code on its line is not part of any run."""
    node = named_func(parse_source(source), func)
    end = node.end_lineno or node.lineno
    own: dict[int, str] = {
        tok.start[0]: tok.string.lstrip("#")
        for tok in tokenize.generate_tokens(io.StringIO(source).readline)
        if tok.type == tokenize.COMMENT
        and node.lineno <= tok.start[0] <= end
        and not tok.line[: tok.start[1]].strip()
    }
    runs: list[tuple[int, int, str]] = []
    for line in sorted(own):
        if runs and runs[-1][1] == line - 1:
            first, _last, _text = runs[-1]
            runs[-1] = (first, line, "")
        else:
            runs.append((line, line, ""))
    return tuple(
        (first, last, _norm(" ".join(own[n] for n in range(first, last + 1))))
        for first, last, _ in runs
    )


def _block_above_call(source: str, func: str, callee: str) -> str:
    sites = call_sites(named_func(parse_source(source), func), callee)
    assert len(sites) == 1, f"{func} calls {callee}() {len(sites)} times; re-anchor"
    above = [text for _first, last, text in _blocks(source, func) if last == sites[0].lineno - 1]
    assert above, f"no own-line comment directly above {callee}() in {func}"
    return above[0]


def _sentence_holding(source: str, func: str, anchor: str) -> str:
    """The sentence of ``func``'s comments that holds ``anchor``, up to its full stop."""
    hits = [text for _f, _l, text in _blocks(source, func) if anchor in text]
    assert len(hits) == 1, f"{anchor!r} is in {len(hits)} comment blocks of {func}; re-anchor"
    tail = hits[0][hits[0].index(anchor) :]
    stop = re.search(r"\.(\s|$)", tail)
    return tail[: stop.start() + 1] if stop else tail


@functools.cache
def _main_source() -> str:
    return _MAIN.read_text(encoding="utf-8")


def _reimports(func: ast.AST) -> list[str]:
    """``sys`` or ``Path`` imported inside ``func``, which the module already binds."""
    return [
        alias.name
        for node in ast.walk(func)
        if isinstance(node, ast.Import | ast.ImportFrom)
        and (not isinstance(node, ast.ImportFrom) or node.module == "pathlib")
        for alias in node.names
        if alias.name in ("sys", "Path")
    ]


def _guard_block_is_false(block: str) -> list[str]:
    return [phrase for phrase in ("window stays open", "some other way") if phrase in block]


def test_s19_73_the_guard_comment_states_neither_false_claim() -> None:
    block = _block_above_call(_main_source(), "_serve", "install_remote_debug_guard")
    assert block.startswith("vault backlog #2700: first in this function"), block
    assert _guard_block_is_false(block) == [], block


def test_s19_73_control_a_revert_carrying_the_false_claim_fails() -> None:
    revert = (
        "def _serve():\n"
        "    # Vault BACKLOG #2700: first in this function. It is NOT first in the process: this\n"
        "    # module's own imports and argument parsing come before it, and that window\n"
        "    # stays open.\n"
        "    install_remote_debug_guard()\n"
    )
    block = _block_above_call(revert, "_serve", "install_remote_debug_guard")
    assert _guard_block_is_false(block) == ["window stays open"]


def test_s19_73_serve_does_not_re_import_sys_or_path() -> None:
    assert _reimports(named_func(parse_source(_main_source()), "_serve")) == []


def test_s19_73_control_the_re_import_check_flags_both_names() -> None:
    func = parse_source(
        "def f():\n    import sys\n    from pathlib import Path\n    from os import path\n"
    )
    assert _reimports(func) == ["sys", "Path"]


def test_s19_74_the_loopback_arm_reason_cites_no_upgrade_breakage() -> None:
    sentence = _sentence_holding(_main_source(), "_serve", _LOOPBACK_ARM)
    assert "upgrade" not in sentence, sentence


def test_s19_74_control_only_the_reason_sentence_is_read() -> None:
    source = (
        "def f():\n"
        "    x = 1\n"
        "    # The proxy must forward the WebSocket Upgrade header. The loopback arm WARNS\n"
        "    #   rather than refuses: refusing would break it on UPGRADE. The proxy forwards\n"
        "    # the Upgrade header.\n"
        "    return x\n"
    )
    assert _sentence_holding(source, "f", _LOOPBACK_ARM) == (
        "the loopback arm warns rather than refuses: refusing would break it on upgrade."
    )
