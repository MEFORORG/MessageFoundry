# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Behaviour of the two local patches in the vendored CLA action's bundle (BACKLOG #5644, #5645).

The bundle at ``.github/actions/cla-assistant-lite/dist/index.js`` is a patched fork of the archived
upstream action (owner ruling 2026-11-23, "Fork, patch, re-provenance"). This module runs the two
patched webpack modules under Node, with their imports stubbed, and asserts what they do:

* ``checkAllowList`` (module 3661) anchors an allowlist wildcard to the whole name, so ``bot*``
  no longer matches ``evilbot-x`` mid-string (BACKLOG #5644 item 2).
* ``getCommitters`` (module 5157) follows GraphQL pagination, so an author first seen past the first
  100 commits is in the list a sign comment is recorded against (BACKLOG #5645 item 2).

The provenance gate (``tests/test_cla_action_provenance.py``) is what proves the bundle differs from
upstream by these hunks and nothing else. This module proves the hunks do what they say.

Node is needed to run the modules. Where it is absent the behavioural tests skip and the static
pins below still run.
"""

from __future__ import annotations

import functools
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = REPO_ROOT / "scripts" / "security" / "build_cla_action_provenance.py"


def _load_provenance() -> ModuleType:
    """The provenance builder, loaded by path: it owns the bundle path and the patch list."""
    spec = importlib.util.spec_from_file_location("build_cla_action_provenance", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provenance = _load_provenance()

_NODE = shutil.which("node")
_needs_node = pytest.mark.skipif(_NODE is None, reason="node is not on PATH")


@functools.cache
def _bundle_text() -> str:
    """The bundle, read once: it is 1.18 MB and every test here slices it."""
    return (REPO_ROOT / provenance.BUNDLE_PATH).read_text(encoding="utf-8")


def _module_factory(module_id: int) -> str:
    """The source of one webpack module's factory function, cut out of the bundle by its id.

    ncc emits each module as ``/***/ <id>:`` then ``/***/ (function(...) {`` ... ``/***/ }),``, so
    the factory is the text between the second marker and the closing one.
    """
    text = _bundle_text()
    start_marker = f"\n/***/ {module_id}:\n/***/ ("
    start = text.index(start_marker) + len(start_marker)
    end = text.index("\n/***/ })", start)
    return text[start:end] + "\n}"


def _lodash() -> str:
    """JavaScript that evaluates to the bundle's OWN lodash (module 250), not a stand-in.

    Module 3661 escapes the non-wildcard parts of an entry with lodash's ``escapeRegExp``, so the
    dot-is-literal test is evidence about the shipped bundle only if it runs the shipped lodash.
    """
    return (
        f"(() => {{ const f = ({_module_factory(250)}); "
        "const req = () => { throw new Error('lodash imports nothing'); }; "
        "req.nmd = (m) => m; const mod = { exports: {} }; "
        "f.call(undefined, mod, mod.exports, req); return mod.exports; })()"
    )


def _run_node(tmp_path: Path, script: str) -> Any:
    harness = tmp_path / "harness.js"
    harness.write_text(script, encoding="utf-8")
    assert _NODE is not None
    completed = subprocess.run(  # noqa: S603 - fixed argv, a script this test wrote
        [_NODE, str(harness)], capture_output=True, text=True, timeout=60, check=False
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _allowlist_survivors(tmp_path: Path, allowlist: str, names: list[str]) -> list[str]:
    """Names checkAllowList keeps (i.e. does NOT treat as allowlisted) for *allowlist*."""
    script = f"""
const factory = ({_module_factory(3661)});
const stubs = {{
  250: {_lodash()},
  3611: {{ getAllowListItem: () => {json.dumps(allowlist)} }},
}};
const exports = {{}};
factory.call(undefined, {{}}, exports, (id) => stubs[id]);
const kept = exports.checkAllowList({json.dumps([{"name": n} for n in names])});
process.stdout.write(JSON.stringify(kept.map((c) => c.name)));
"""
    result: list[str] = _run_node(tmp_path, script)
    return result


def _page(names: list[str], has_next: bool, end_cursor: str | None, total: int) -> dict[str, Any]:
    """One synthetic GraphQL page of pull-request commits, each authored by a linked user.

    *total* is the connection's ``totalCount``: the number of commits on the whole pull request,
    the same on every page.
    """
    return {
        "repository": {
            "pullRequest": {
                "commits": {
                    "totalCount": total,
                    "edges": [
                        {
                            "node": {
                                "commit": {
                                    "author": {
                                        "email": f"{n}@example.invalid",
                                        "name": n,
                                        "user": {"id": n, "databaseId": 1000 + i, "login": n},
                                    },
                                    "committer": {"name": n, "user": None},
                                }
                            },
                            "cursor": f"{n}-cursor",
                        }
                        for i, n in enumerate(names)
                    ],
                    "pageInfo": {"endCursor": end_cursor, "hasNextPage": has_next},
                }
            }
        }
    }


def _committers(tmp_path: Path, pages: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Run getCommitters against *pages*, keyed by the cursor each page is served for.

    Returns the logins it resolved (or the error it raised) and the cursors it asked for. A cursor
    with no page behind it raises, so a loop that re-asks forever ends instead of hanging the test.
    """
    script = f"""
const factory = ({_module_factory(5157)});
const pages = {json.dumps(pages)};
const asked = [];
const stubs = {{
  3258: {{ octokit: {{ graphql: async (_query, vars) => {{
    asked.push(vars.cursor);
    if (asked.length > 20) throw new Error('too many pages requested');
    if (!(vars.cursor in pages)) throw new Error('no page for cursor ' + vars.cursor);
    return pages[vars.cursor];
  }} }} }},
  5438: {{ context: {{ repo: {{ owner: 'o', repo: 'r' }}, issue: {{ number: 7 }} }} }},
}};
const exports = {{}};
factory.call(undefined, {{}}, exports, (id) => stubs[id]);
exports.default().then(
  (c) => process.stdout.write(JSON.stringify({{ names: c.map((x) => x.name), asked }})),
  (e) => process.stdout.write(JSON.stringify({{ error: String(e), asked }})),
);
"""
    result: dict[str, Any] = _run_node(tmp_path, script)
    return result


# --- BACKLOG #5644 item 2: the allowlist wildcard is anchored ------------------------------------


@_needs_node
def test_a_wildcard_entry_does_not_match_mid_string(tmp_path: Path) -> None:
    """``bot*`` allowlists ``bot-x`` and no longer ``evilbot-x``; before the patch it did both."""
    kept = _allowlist_survivors(tmp_path, "bot*", ["evilbot-x", "bot-x", "x-bot"])

    assert kept == ["evilbot-x", "x-bot"]


@_needs_node
def test_a_wildcard_entry_still_matches_its_intended_names(tmp_path: Path) -> None:
    """The anchor narrows matching to the whole name; it does not stop a wildcard from working."""
    kept = _allowlist_survivors(
        tmp_path, "dependabot*, *[bot]", ["dependabot[bot]", "renovate[bot]", "alice"]
    )

    assert kept == ["alice"]


@_needs_node
def test_a_dot_in_a_wildcard_entry_is_literal(tmp_path: Path) -> None:
    """The non-wildcard parts are escaped, so ``a.b*`` does not match ``aXb``."""
    kept = _allowlist_survivors(tmp_path, "a.b*", ["aXb-1", "a.b-1"])

    assert kept == ["aXb-1"]


@_needs_node
def test_an_exact_entry_is_unchanged(tmp_path: Path) -> None:
    """An entry with no ``*`` was always an exact comparison, and stays one."""
    kept = _allowlist_survivors(tmp_path, "bot", ["bot", "bot-x", "evilbot"])

    assert kept == ["bot-x", "evilbot"]


# --- BACKLOG #5645 item 2: getCommitters reads every page ----------------------------------------


@_needs_node
def test_an_author_past_page_one_is_listed(tmp_path: Path) -> None:
    """Before the patch the action read one page with an empty cursor and never saw ``bob``."""
    result = _committers(
        tmp_path,
        {
            "": _page(["alice"], has_next=True, end_cursor="C1", total=4),
            "C1": _page(["bob"], has_next=True, end_cursor="C2", total=4),
            "C2": _page(["carol", "alice"], has_next=False, end_cursor="C3", total=4),
        },
    )

    assert result == {"names": ["alice", "bob", "carol"], "asked": ["", "C1", "C2"]}


@_needs_node
def test_a_single_page_pull_request_asks_once(tmp_path: Path) -> None:
    result = _committers(tmp_path, {"": _page(["alice"], has_next=False, end_cursor="C1", total=1)})

    assert result == {"names": ["alice"], "asked": [""]}


@pytest.mark.parametrize("bad_cursor", [None, "", "C1", 7])
@_needs_node
def test_a_next_page_with_no_new_cursor_fails_instead_of_looping(
    tmp_path: Path, bad_cursor: str | int | None
) -> None:
    """``hasNextPage`` with a missing, empty, repeated or non-string cursor raises.

    The action turns the raise into a failed step, so the required ``cla`` check reds rather than
    passing on a list it could not finish reading.
    """
    result = _committers(
        tmp_path,
        {
            "": _page(["alice"], has_next=True, end_cursor="C1", total=3),
            "C1": _page(["bob"], has_next=True, end_cursor=bad_cursor, total=3),  # type: ignore[arg-type]
        },
    )

    assert "error" in result, result
    assert "graphql call to get the committers details failed" in result["error"]
    assert "no new cursor" in result["error"]
    assert result["asked"] == ["", "C1"]


@_needs_node
def test_a_cursor_cycle_fails_instead_of_looping(tmp_path: Path) -> None:
    """A cursor seen two pages back is not new either: C1, C2, C1 raises on the third page."""
    result = _committers(
        tmp_path,
        {
            "": _page(["alice"], has_next=True, end_cursor="C1", total=9),
            "C1": _page(["bob"], has_next=True, end_cursor="C2", total=9),
            "C2": _page(["carol"], has_next=True, end_cursor="C1", total=9),
        },
    )

    assert "no new cursor" in result.get("error", ""), result
    assert result["asked"] == ["", "C1", "C2"]


@_needs_node
def test_a_read_shorter_than_total_count_fails(tmp_path: Path) -> None:
    """A last page that leaves commits unread -- a capped connection, say -- raises.

    Without this a pull request whose commit list stops short of ``totalCount`` would be checked
    against the authors read so far, and an author past the stop would never be asked to sign.
    """
    result = _committers(
        tmp_path, {"": _page(["alice"], has_next=False, end_cursor="C1", total=300)}
    )

    assert "read 1 of 300 pull request commits" in result.get("error", ""), result


# --- Static pins, which run without Node ------------------------------------------------------


def test_the_bundle_carries_the_anchored_pattern() -> None:
    factory = _module_factory(3661)

    assert "new RegExp('^' + regex + '$')" in factory
    assert "new RegExp(regex)" not in factory


def test_the_bundle_follows_pagination() -> None:
    factory = _module_factory(5157)

    assert "while (hasNextPage)" in factory
    assert "cursor: cursor" in factory
    assert "cursor: ''" not in factory


@pytest.mark.parametrize("index", range(len(provenance.BUNDLE_PATCHES)))
def test_every_patch_carries_the_marker_comment(index: int) -> None:
    """The README says a grep for ``MessageFoundry patch`` finds every patched span; hold it to that."""
    upstream, patched = provenance.BUNDLE_PATCHES[index]

    assert b"MessageFoundry patch" in patched
    assert b"MessageFoundry patch" not in upstream
