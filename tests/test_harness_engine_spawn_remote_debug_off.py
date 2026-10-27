# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every engine the harness spawns from Python starts with remote debugging off (vault BACKLOG
#2700, owner ruling (b) of 2026-10-16).

``tests/test_ci_serve_starts_remote_debug_off.py`` reads the starts a workflow step spells out. The
rigs that start their engines from Python sit behind a step that names only ``python -m harness``,
so it cannot see them. They all spawn through one seam, ``harness.load.failover.EngineNode._spawn``:
the failover profile, multishard, estate, connscale and its batch box, and the ingress probe.

Two readings. The argument list the seam hands its subprocess call, read off the real method. And a
scan of every Python file under ``harness/`` and ``scripts/`` for an argument list that runs
``-m messagefoundry serve`` or ``supervise``, which must carry the child flags or the option itself
ahead of ``-m``. The scan reads literal lists, tuples and call arguments; an argument list
assembled across statements is missed.
"""

from __future__ import annotations

import ast
import asyncio
import os
from pathlib import Path

import pytest

from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS

_ROOT = Path(__file__).resolve().parents[1]
_SUBCOMMANDS = ("serve", "supervise")
_OPTION = ("-X", "disable-remote-debug")
_FLAG_NAMES = ("CHILD_INTERPRETER_FLAGS", "ISOLATED_LAUNCH_OPTIONS")


def _constant(node: ast.expr) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _sets_the_option(before: list[ast.expr]) -> bool:
    """Whether the elements ahead of ``-m`` turn remote debugging off: the shared flags spread in,
    or the option spelled as two literals."""
    for at, node in enumerate(before):
        if isinstance(node, ast.Starred):
            name = node.value
            attr = name.attr if isinstance(name, ast.Attribute) else getattr(name, "id", None)
            if attr in _FLAG_NAMES:
                return True
        if at + 1 < len(before) and (_constant(node), _constant(before[at + 1])) == _OPTION:
            return True
    return False


def spawn_problems(source: str, filename: str = "<planted>") -> list[str]:
    """``file:line`` of each argument list in ``source`` that runs ``-m messagefoundry serve`` or
    ``supervise`` without remote debugging turned off ahead of ``-m``."""
    problems = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.Call):
            elements = list(node.args)
        elif isinstance(node, (ast.List, ast.Tuple)):
            elements = list(node.elts)
        else:
            continue
        words = [_constant(e) for e in elements]
        for at in range(len(words) - 2):
            starts = (
                words[at : at + 2] == ["-m", "messagefoundry"] and words[at + 2] in _SUBCOMMANDS
            )
            if starts and not _sets_the_option(elements[:at]):
                problems.append(f"{filename}:{node.lineno}")
    return problems


def _python_sources() -> list[Path]:
    return sorted(p for top in ("harness", "scripts") for p in (_ROOT / top).rglob("*.py"))


def test_no_harness_or_script_spawns_the_engine_with_remote_debugging_on() -> None:
    sources = _python_sources()
    assert len(sources) >= 100, f"CONTROL FAILED: only {len(sources)} Python file(s) were read"
    problems = [
        found
        for path in sources
        for found in spawn_problems(path.read_text(encoding="utf-8"), str(path.relative_to(_ROOT)))
    ]
    assert not problems, (
        "pass messagefoundry.childenv.CHILD_INTERPRETER_FLAGS ahead of `-m messagefoundry` "
        f"(vault BACKLOG #2700): {problems}"
    )


@pytest.mark.parametrize(
    "source",
    [
        # The seam's own spawn before this item.
        'exec(sys.executable, "-m", "messagefoundry", "serve", *args)',
        '[sys.executable, "-m", "messagefoundry", "supervise", "--config", c]',
        # Misspelt, or another -X option.
        '(sys.executable, "-X", "disable_remote_debug", "-m", "messagefoundry", "serve")',
        '[sys.executable, "-X", "utf8", "-m", "messagefoundry", "serve"]',
        # The flags after the module are the engine's arguments.
        'exec(sys.executable, "-m", "messagefoundry", "serve", *CHILD_INTERPRETER_FLAGS)',
        # Another tuple spread in.
        'exec(sys.executable, *OTHER_FLAGS, "-m", "messagefoundry", "serve")',
    ],
)
def test_the_scan_objects_to_a_planted_spawn(source: str) -> None:
    assert spawn_problems(source), source


@pytest.mark.parametrize(
    "source",
    [
        'exec(sys.executable, *CHILD_INTERPRETER_FLAGS, "-m", "messagefoundry", "serve", *args)',
        '[sys.executable, *childenv.CHILD_INTERPRETER_FLAGS, "-m", "messagefoundry", "supervise"]',
        '(sys.executable, "-P", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve")',
        # Not an engine start.
        '[sys.executable, "-m", "messagefoundry", "lens", "parse"]',
        '[sys.executable, "-m", "harness", "--load", "smoke"]',
    ],
)
def test_the_scan_passes_a_spawn_with_the_option_and_lists_that_start_nothing(
    source: str,
) -> None:
    assert spawn_problems(source) == [], source


class _Spawned(Exception):
    """Stops the seam at its subprocess call, carrying the argument list it was handed."""


def test_the_engine_node_seam_spawns_with_the_child_flags(tmp_path: Path) -> None:
    """Read off the real ``EngineNode._spawn``, with only the subprocess call replaced."""
    from harness.load.failover import EngineNode

    class Recording(EngineNode):
        async def _exec(self, *argv: str) -> asyncio.subprocess.Process:
            raise _Spawned(argv)

    node = Recording("argv", 1, env=dict(os.environ), config_dir="cfg", cwd=tmp_path)
    try:
        with pytest.raises(_Spawned) as spawned:
            asyncio.run(node._spawn("--config", "cfg"))
    finally:
        node._log.close()
        os.unlink(node._log.name)
    argv = spawned.value.args[0]
    module_at = argv.index("-m")
    assert argv[1:module_at] == CHILD_INTERPRETER_FLAGS, argv
    assert argv[module_at : module_at + 3] == ("-m", "messagefoundry", "serve"), argv
    assert _OPTION in zip(argv[1:module_at], argv[2:module_at], strict=False), argv
