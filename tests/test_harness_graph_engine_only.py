# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness graphs load without the ``harness`` package (BACKLOG #5850, #5852, #5853, #5854),
and what they inline or copy to do so stays equal to what it was copied from.

A plain ``python -P`` subprocess cannot show the defect in a development environment, because the
editable install's ``.pth`` makes ``harness`` importable anyway. So the child installs a
``sys.meta_path`` finder that refuses ``harness``, and a control config that imports ``harness``
proves that refusal reaches a graph's import.
"""

from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from harness.config.shardcert import _shape as shardcert_shape
from harness.load.ids import SHARDCERT_IDS
from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS, outside_engine_namespace
from tests._ast_sites import named_func, parse_source
from tests.test_dependency_boundaries import _modules_imported_by

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONFIG = _REPO_ROOT / "harness" / "config"
_GRAPHS = ["load", "estate", "shardcert", "connscale", "passthrough", "store_once"]

# Only the finder below raises with this text, so a control can tell its refusal from any other
# missing module.
_BLOCKED = "harness refused by the engine-only finder"

# The engine-only install, simulated: `harness` cannot be imported, whatever the .pth says.
_CHILD = (
    f"BLOCKED = {_BLOCKED!r}\n"
    + """
import importlib.abc, sys

class _NoHarness(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "harness" or name.startswith("harness."):
            raise ModuleNotFoundError(BLOCKED, name=name)
        return None

sys.meta_path.insert(0, _NoHarness())

from messagefoundry.config.wiring import load_config

registry = load_config(sys.argv[1])
print("inbounds", len(registry.inbound))
"""
)


def _load_engine_only(config: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    # Without the knobs of the shell that started pytest, so each graph loads on its defaults.
    env = {
        key: value
        for key, value in os.environ.items()
        if outside_engine_namespace(key) and key != "PYTHONPATH"
    }
    return subprocess.run(
        [sys.executable, *CHILD_INTERPRETER_FLAGS, "-c", _CHILD, str(config)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.parametrize("graph", _GRAPHS)
def test_graph_loads_without_the_harness_package(graph: str, tmp_path: Path) -> None:
    # A copy under tmp_path passes the real config-source check in the child, with no escape set,
    # and a graph that reached for a file beside its directory would fail here.
    config = tmp_path / graph
    shutil.copytree(_CONFIG / graph, config, ignore=shutil.ignore_patterns("__pycache__"))
    done = _load_engine_only(config, tmp_path)
    assert done.returncode == 0, done.stderr
    count = int(done.stdout.split("inbounds", 1)[1].split()[0])
    assert count >= 1


def test_control_the_block_reaches_a_graphs_import(tmp_path: Path) -> None:
    # If this starts passing the load, the block has stopped working and the test above proves nothing.
    config = tmp_path / "needs_harness"
    config.mkdir()
    # The graph reports what it caught, because the loader's own error need not carry the message.
    (config / "graph.py").write_text(
        "try:\n"
        "    import harness\n"
        "except ModuleNotFoundError as exc:\n"
        "    print(f'caught {exc.name}: {exc}', flush=True)\n"
        "    raise\n",
        encoding="utf-8",
    )
    done = _load_engine_only(config, tmp_path)
    assert done.returncode != 0
    assert f"caught harness: {_BLOCKED}" in done.stdout, done.stdout + done.stderr


def _parsed_def(path: Path, name: str) -> str:
    """The one ``def name`` in ``path``, parsed, with positions left out."""
    return ast.dump(named_func(parse_source(path.read_text(encoding="utf-8")), name))


@pytest.mark.parametrize("graph", _GRAPHS)
def test_inlined_refusal_decorator_matches_the_original(graph: str) -> None:
    assert _parsed_def(_CONFIG / graph / "_shape.py", "prints_its_refusal") == _parsed_def(
        _CONFIG / "_refusal.py", "prints_its_refusal"
    )


@pytest.mark.parametrize("graph", ["passthrough", "store_once"])
def test_copied_load_shape_matches_the_load_graphs(graph: str) -> None:
    # Byte for byte, so the copy cannot drift even in a comment: harness/config/load is the one to
    # edit, and its docstring says so.
    assert (_CONFIG / graph / "_shape.py").read_bytes() == (
        _CONFIG / "load" / "_shape.py"
    ).read_bytes()


def test_inlined_id_parser_matches_harness_load_ids() -> None:
    assert _parsed_def(_CONFIG / "shardcert" / "_shape.py", "parse") == _parsed_def(
        _REPO_ROOT / "harness" / "load" / "ids.py", "parse"
    )
    inlined = shardcert_shape.SHARDCERT_IDS
    assert (inlined.prefix, inlined.width) == (SHARDCERT_IDS.prefix, SHARDCERT_IDS.width)
    for seq in (0, 1, 12_345, 10**12 - 1):
        assert inlined.parse(SHARDCERT_IDS.format(seq)) == seq


@pytest.mark.parametrize("module", ["_shape.py", "graph.py"])
@pytest.mark.parametrize("graph", _GRAPHS)
def test_the_graph_does_not_import_the_harness_package(graph: str, module: str) -> None:
    # Walks function bodies too: a Router's or Handler's body does not run in the load test above.
    tree = parse_source((_CONFIG / graph / module).read_text(encoding="utf-8"))
    imported = _modules_imported_by(tree, f"harness.config.{graph}")
    assert not [name for name in imported if name.split(".")[0] == "harness"]
