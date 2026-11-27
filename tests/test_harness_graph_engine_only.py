# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness graphs in ``_GRAPHS`` load without the ``harness`` package (BACKLOG #5850, #5852,
#5853, #5854), and what they inline or copy to do so stays equal to what it was copied from. The
other directories under ``harness/config`` are not covered here.

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
from messagefoundry.checks import CheckResult, run_checks
from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS, outside_engine_namespace
from messagefoundry.config.snapshot import config_py_files
from tests._ast_sites import named_func, parse_source
from tests.test_dependency_boundaries import _is_forbidden, _modules_imported_by

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


def _advisory_mypy(
    graph: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, package: bool = False
) -> CheckResult:
    """``messagefoundry check``'s advisory mypy result on a copy of ``graph`` (BACKLOG #5850).

    It is read from ``run_checks``, so the test follows whatever command check builds. Today that is
    ``mypy --config-file= <config dir>``. A directory holding an ``__init__.py`` is a package to mypy,
    so its ``from _shape import`` is not found there; without one mypy resolves the bare name from
    the directory, as the loader does. The working directory is the copy's parent, and the caller's
    ``MYPY_CACHE_DIR`` and ``MYPYPATH``, which check passes on, are dropped, so each run caches under
    tmp_path. mypy still finds whatever the interpreter can import, the editable ``harness`` among
    it, so this is not an engine-only type check; the AST test below is the one that refuses a
    ``harness`` import."""
    config = tmp_path / graph
    shutil.copytree(_CONFIG / graph, config, ignore=shutil.ignore_patterns("__pycache__"))
    if package:
        (config / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MYPY_CACHE_DIR", raising=False)
    monkeypatch.delenv("MYPYPATH", raising=False)
    [result] = [r for r in run_checks(config, run_lint=True).results if r.name == "mypy"]
    assert not result.skipped, result.detail
    return result


@pytest.mark.parametrize("graph", _GRAPHS)
def test_checks_advisory_mypy_resolves_the_bare_sibling_import(
    graph: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = _advisory_mypy(graph, tmp_path, monkeypatch)
    assert result.ok, result.detail


def test_control_a_package_marker_fails_the_advisory_mypy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If this starts passing, mypy no longer reports the defect and the test above proves nothing.
    result = _advisory_mypy("load", tmp_path, monkeypatch, package=True)
    assert not result.ok
    assert "import-not-found" in result.detail, result.detail


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
    # edit, and its docstring says so. Line endings are left out, because a checkout may write
    # either and the repository stores the same blob for both.
    def lf(path: Path) -> bytes:
        return path.read_bytes().replace(b"\r\n", b"\n")

    assert lf(_CONFIG / graph / "_shape.py") == lf(_CONFIG / "load" / "_shape.py")


def test_inlined_id_parser_matches_harness_load_ids() -> None:
    assert _parsed_def(_CONFIG / "shardcert" / "_shape.py", "parse") == _parsed_def(
        _REPO_ROOT / "harness" / "load" / "ids.py", "parse"
    )
    inlined = shardcert_shape.SHARDCERT_IDS
    assert (inlined.prefix, inlined.width) == (SHARDCERT_IDS.prefix, SHARDCERT_IDS.width)
    for seq in (0, 1, 12_345, 10**12 - 1):
        assert inlined.parse(SHARDCERT_IDS.format(seq)) == seq


def _harness_imports(path: Path, graph: str) -> list[str]:
    """The ``harness`` modules ``path`` imports, read as a module of ``harness/config/<graph>``.

    It reads import statements only. A string import, such as ``importlib.import_module("harness")``
    or ``__import__("harness")``, passes this scan and, in a function body, the load test too."""
    # A graph's _shape.py is also imported as harness.config.<graph>._shape, by the harness runners
    # and by this file, and there a relative import reaches harness. Under the loader, which gives a
    # config module no parent package, the same line raises instead. Either way it is refused here.
    tree = parse_source(path.read_text(encoding="utf-8"))
    imported = _modules_imported_by(tree, f"harness.config.{graph}")
    return sorted(name for name in imported if _is_forbidden(name, ("harness",)))


def _scan_graph_dir(directory: Path) -> tuple[list[str], dict[str, list[str]]]:
    """The files the scan read in ``directory``, by the loader's own file rule, and each of them
    that imports a ``harness`` module, with what it imports. The graph is the directory's name."""
    paths = config_py_files(directory)
    found = {path.name: _harness_imports(path, directory.name) for path in paths}
    return [path.name for path in paths], {name: hits for name, hits in found.items() if hits}


@pytest.mark.parametrize("graph", _GRAPHS)
def test_the_graph_does_not_import_the_harness_package(graph: str) -> None:
    # Every file in the directory, function bodies too: a Router's or Handler's body does not run in
    # the load test above, and a non-_ module such as connscale's gen_toml.py is loaded as config.
    read, found = _scan_graph_dir(_CONFIG / graph)
    assert {"_shape.py", "graph.py"} <= set(read)
    assert found == {}


# Each planted source, and the harness module the scan must name for it in a module of
# harness/config/load. Read with the file's bare stem as its package, the relative forms name none.
_PLANTED_HARNESS_IMPORTS = {
    "import harness.config.x": "harness.config.x",
    "import os, harness": "harness",
    "from harness.config.load._shape import y": "harness.config.load._shape",
    "from . import _shape": "harness.config.load",
    "from ._shape import y": "harness.config.load._shape",
    "from .. import estate": "harness.config",
    "from ..estate._shape import y": "harness.config.estate._shape",
    "from ... import load": "harness",
    "def route(message):\n    from ._shape import y\n": "harness.config.load._shape",
    "try:\n    import harness.load\nexcept ImportError:\n    pass\n": "harness.load",
    "class Shape:\n    def build(self):\n        from .. import estate\n": "harness.config",
}


@pytest.mark.parametrize(("source", "expected"), list(_PLANTED_HARNESS_IMPORTS.items()))
def test_control_the_scan_flags_a_planted_harness_import(
    source: str, expected: str, tmp_path: Path
) -> None:
    # If this starts passing a planted source, the scan has stopped seeing that form and the test
    # above proves nothing for it.
    planted = tmp_path / "graph.py"
    planted.write_text(source + "\n", encoding="utf-8")
    assert expected in _harness_imports(planted, "load")


def test_control_the_directory_scan_names_the_planted_files(tmp_path: Path) -> None:
    # A real graph's copy with files added, so the graph test's directory walk is what is read: a
    # module and a _ helper it must name, and a dot-named backup the loader never runs, which it
    # must not read.
    config = tmp_path / "load"
    shutil.copytree(_CONFIG / "load", config, ignore=shutil.ignore_patterns("__pycache__"))
    for name in ("planted.py", "_planted.py", ".planted.py"):
        (config / name).write_text("from ._shape import y\n", encoding="utf-8")
    read, found = _scan_graph_dir(config)
    assert {"_shape.py", "graph.py", "planted.py", "_planted.py"} <= set(read)
    assert ".planted.py" not in read
    hit = ["harness.config.load._shape"]
    assert found == {"planted.py": hit, "_planted.py": hit}


def test_control_the_scan_passes_a_module_with_no_harness_import(tmp_path: Path) -> None:
    # The bare sibling import the graphs use, and names that only begin with "harness".
    clean = tmp_path / "graph.py"
    clean.write_text(
        "import harnessy\n"
        "from harness_tools import x\n"
        "from _shape import wire_graph\n"
        "from messagefoundry import inbound\n",
        encoding="utf-8",
    )
    assert _harness_imports(clean, "load") == []
