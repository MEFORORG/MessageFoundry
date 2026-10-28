# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every engine the harness spawns from Python starts with remote debugging off (vault BACKLOG
#2700, owner ruling (b) of 2026-10-16).

``tests/test_ci_serve_starts_remote_debug_off.py`` reads the starts a workflow step spells out. The
rigs that start their engines from Python sit behind a step that names only ``python -m harness``,
so it cannot see them. At least the failover profile, multishard, shardcert, estate, connscale and
its batch box, and the ingress probe spawn through one seam,
``harness.load.failover.EngineNode._spawn``.

Two readings. The argument list the seam hands its subprocess call, read off the real method. And a
scan of every Python file under ``harness/`` and ``scripts/`` for an argument list that runs
``-m messagefoundry serve`` or ``supervise``, which must carry the option, or a shared flag tuple
that holds it, among the interpreter's own options ahead of ``-m``. The scan reads literal lists,
tuples and call arguments; an argument list assembled across statements is missed.
"""

from __future__ import annotations

import ast
import asyncio
import itertools
import re
from pathlib import Path

import pytest

from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS
from messagefoundry.startupcode import ISOLATED_LAUNCH_OPTIONS

_ROOT = Path(__file__).resolve().parents[1]
_SUBCOMMANDS = ("serve", "supervise")
_MODULES = ("messagefoundry", "messagefoundry.__main__")
_OPTION = ("-X", "disable-remote-debug")
#: At least these interpreter options take an argument, attached or as the next word, and this
#: long one takes the next word (``python --help``, 3.14).
_TAKES_ARGUMENT = frozenset("WX")
_LONG_TAKES_ARGUMENT = frozenset({"--check-hash-based-pycs"})
#: At least these words and option letters end the interpreter's own options: a program read from
#: stdin, the end-of-options marker (CPython reads the next word as a script), a command, a module.
_ENDS_OPTIONS = frozenset({"-", "--"})
_ENDS_OPTION_LETTERS = frozenset("cm")
#: A word holding ``-m``, alone, closing a cluster (``-Im``), or with the module attached.
_MODULE_FLAG = re.compile(r"-[A-Za-z]*?m(.*)")
#: The shared tuples that hold the option, by the name a spread ``*NAME`` uses, with their words.
#: ``REMOTE_DEBUG_OFF`` is the harness seam's, pinned equal to ``_OPTION`` by a test below.
_FLAG_TUPLES: dict[str, tuple[str, ...]] = {
    "CHILD_INTERPRETER_FLAGS": CHILD_INTERPRETER_FLAGS,
    "ISOLATED_LAUNCH_OPTIONS": ISOLATED_LAUNCH_OPTIONS,
    "REMOTE_DEBUG_OFF": _OPTION,
}


def _constant(node: ast.expr) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _spread_name(node: ast.expr) -> str | None:
    if not isinstance(node, ast.Starred):
        return None
    value = node.value
    return value.attr if isinstance(value, ast.Attribute) else getattr(value, "id", None)


def _words(elements: list[ast.expr]) -> list[str | None]:
    """The argument list as words: a string literal as itself, a spread of a shared flag tuple as
    the words it holds, and anything else (a variable, another spread) as ``None``, not known."""
    words: list[str | None] = []
    for node in elements:
        name = _spread_name(node)
        words += _FLAG_TUPLES[name] if name in _FLAG_TUPLES else [_constant(node)]
    return words


def _sets_the_option(options: list[str | None]) -> bool:
    """Whether the interpreter's own options turn remote debugging off. ``options`` runs from the
    word after the interpreter through the word that holds the start's ``-m``.

    Read as CPython reads them: single-letter options cluster (``-IX...``); ``-W`` and ``-X`` take
    the rest of their word or the next word, and ``--check-hash-based-pycs`` the next word, so
    ``-W ignore`` is one option. Anything that ends the interpreter's options before the start's
    own ``-m`` (a script, another module, ``-c``, ``-``, ``--``, a word not known) makes that ``-m``
    another program's, and an inner interpreter may not inherit the option, so it fails. An option
    that takes the start's ``-m`` as its argument leaves ``messagefoundry`` run as a script path,
    which still starts the engine from a directory holding the package, so it is judged too."""
    found = False
    at = 0
    while at < len(options):
        word = options[at]
        at += 1
        if word is None or word in _ENDS_OPTIONS or not word.startswith("-"):
            return False
        if word.startswith("--"):
            if word in _LONG_TAKES_ARGUMENT:
                at += 1
            continue
        for offset, letter in enumerate(word[1:], 1):
            if letter in _ENDS_OPTION_LETTERS:
                return found and at == len(options)
            if letter in _TAKES_ARGUMENT:
                argument: str | None = word[offset + 1 :]
                if not argument and at < len(options):
                    argument, at = options[at], at + 1
                found = found or (f"-{letter}", argument) == _OPTION
                break
    return found


def spawn_problems(source: str, filename: str = "<planted>") -> list[str]:
    """``file:line`` of each argument list in ``source`` that runs ``-m messagefoundry serve`` or
    ``supervise`` without remote debugging turned off among the interpreter's own options."""
    problems = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.Call):
            elements = list(node.args)
        elif isinstance(node, (ast.List, ast.Tuple)):
            elements = list(node.elts)
        else:
            continue
        words = _words(elements)
        # The first word is the interpreter; its options run from the next word through the -m.
        for at in range(1, len(words) - 1):
            if not (flag := _MODULE_FLAG.fullmatch(words[at] or "")):
                continue
            if attached := flag.group(1):
                module, subcommand = attached, words[at + 1]
            else:
                module, subcommand = words[at + 1], (words[at + 2 : at + 3] or [None])[0]
            starts = module in _MODULES and subcommand in _SUBCOMMANDS
            if starts and not _sets_the_option(words[1 : at + 1]):
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
        "pass `-X disable-remote-debug` ahead of `-m messagefoundry` (vault BACKLOG #2700): "
        f"{problems}"
    )


def test_the_seam_spells_the_option_as_the_engine_children_do() -> None:
    from harness.load.failover import REMOTE_DEBUG_OFF

    assert REMOTE_DEBUG_OFF == _OPTION
    assert _OPTION in itertools.pairwise(CHILD_INTERPRETER_FLAGS)


@pytest.mark.parametrize(
    "source",
    [
        # The seam's own spawn before this item.
        'exec(sys.executable, "-m", "messagefoundry", "serve", *args)',
        '[sys.executable, "-m", "messagefoundry", "supervise", "--config", c]',
        '[sys.executable, "-m", "messagefoundry.__main__", "serve"]',
        # Misspelt, or another -X option.
        '(sys.executable, "-X", "disable_remote_debug", "-m", "messagefoundry", "serve")',
        '[sys.executable, "-X", "utf8", "-m", "messagefoundry", "serve"]',
        # The flags after the module are the engine's arguments.
        'exec(sys.executable, "-m", "messagefoundry", "serve", *CHILD_INTERPRETER_FLAGS)',
        # Another tuple spread in.
        'exec(sys.executable, *OTHER_FLAGS, "-m", "messagefoundry", "serve")',
        # The option belongs to a wrapper module or to -c, not to the interpreter.
        'exec(sys.executable, "-m", "coverage", "run", *REMOTE_DEBUG_OFF, "-m", "messagefoundry", "serve")',
        '(sys.executable, "-c", "x", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve")',
        # An option that takes an argument, with no remote-debug option beside it.
        '[sys.executable, "-W", "ignore", "-m", "messagefoundry", "serve"]',
        # -W takes -X as its argument, so the next word is a script.
        '[sys.executable, "-W", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve"]',
        # A program read from stdin, or the end-of-options marker, ends the options.
        '[sys.executable, "-", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "--", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve"]',
        # The module flag in a cluster, or with the module attached.
        '[sys.executable, "-Im", "messagefoundry", "serve"]',
        '[sys.executable, "-mmessagefoundry", "serve"]',
        # -X takes the m, so messagefoundry runs as a script path: still the engine, still judged.
        '[sys.executable, "-Xm", "messagefoundry", "serve"]',
        # Options end before the start's -m, at a wrapper module or a word not known, so the
        # engine's interpreter may be another one that never saw the option.
        '[sys.executable, *REMOTE_DEBUG_OFF, "-m", "coverage", "run", "-m", "messagefoundry", "serve"]',
        '[sys.executable, *REMOTE_DEBUG_OFF, *extra, "-m", "messagefoundry", "serve"]',
    ],
)
def test_the_scan_objects_to_a_planted_spawn(source: str) -> None:
    assert spawn_problems(source), source


@pytest.mark.parametrize(
    "source",
    [
        'exec(sys.executable, *REMOTE_DEBUG_OFF, "-m", "messagefoundry", "serve", *args)',
        '[sys.executable, *childenv.CHILD_INTERPRETER_FLAGS, "-m", "messagefoundry", "supervise"]',
        '(sys.executable, "-P", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve")',
        # An option's argument is not a script (Greptile, PR 2570).
        '[sys.executable, "-W", "ignore", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "-X", "disable-remote-debug", "-W", "ignore", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "-X", "utf8", "-X", "disable-remote-debug", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "--check-hash-based-pycs", "never", *REMOTE_DEBUG_OFF, "-m", "messagefoundry", "serve"]',
        # Attached and clustered.
        '[sys.executable, "-Wignore", "-Xdisable-remote-debug", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "-IX", "disable-remote-debug", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "-X", "disable-remote-debug", "-Im", "messagefoundry", "serve"]',
        '[sys.executable, *REMOTE_DEBUG_OFF, "-mmessagefoundry", "serve"]',
        # A spread is read as its words: -W takes -P, and the option follows.
        '[sys.executable, "-W", *CHILD_INTERPRETER_FLAGS, "-m", "messagefoundry", "serve"]',
        # An option that takes the -m as its argument leaves messagefoundry run as a script path,
        # with the option already set.
        '[sys.executable, "-X", "disable-remote-debug", "-W", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "-X", "disable-remote-debug", "-IW", "-m", "messagefoundry", "serve"]',
        '[sys.executable, "-X", "disable-remote-debug", "--check-hash-based-pycs", "-m", "messagefoundry", "serve"]',
        '[sys.executable, *REMOTE_DEBUG_OFF, "-Xm", "messagefoundry", "serve"]',
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


def test_the_engine_node_seam_spawns_with_remote_debugging_off(tmp_path: Path) -> None:
    """Read off the real ``EngineNode._spawn``, with only the subprocess call replaced. An empty
    environment, as the neighbouring node tests use, so no ambient variable redirects the log."""
    from harness.load.failover import EngineNode

    class Recording(EngineNode):
        async def _exec(self, *argv: str) -> asyncio.subprocess.Process:
            raise _Spawned(argv)

    node = Recording("argv", 1, env={}, config_dir="cfg", cwd=tmp_path)
    try:
        with pytest.raises(_Spawned) as spawned:
            asyncio.run(node._spawn("--config", "cfg"))
    finally:
        node._log.close()
        Path(node._log.name).unlink()
    argv = spawned.value.args[0]
    module_at = argv.index("-m")
    assert argv[module_at : module_at + 3] == ("-m", "messagefoundry", "serve"), argv
    assert _OPTION in itertools.pairwise(argv[1:module_at]), argv
    assert spawn_problems(f"exec({', '.join(map(repr, argv))})") == [], argv
