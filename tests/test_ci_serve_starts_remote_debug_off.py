# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every engine a workflow step starts by command line starts with remote debugging off (vault
BACKLOG #2700, owner ruling (b) of 2026-10-16).

``serve`` and ``supervise`` refuse to start under ``enforce`` while ``sys.is_remote_debug_enabled()``
is True (engine PR 2394). The ruling: CI launches the interpreter with ``-X disable-remote-debug``,
as the shipped service does, including on the legs that run at ``warn`` for another reason.

The interpreter accepts ``-X disable_remote_debug`` and does nothing with it
(``tests/test_isolated_launch.py`` runs that), so the reader compares the exact spelling.

THESE READ TEXT, NOT A RUN. Most of those legs run on a schedule, on dispatch or in the merge queue,
so a pull request never shows their result, and no step reads the flag back off its running engine.
At least these start an engine where no step text shows it, and nothing here reads them: the
Windows service smoke (NSSM, read by ``tests/test_isolated_launch.py``), the image smoke (the
image's entry point, read there too), and any engine a harness module starts from Python, such as
the failover profile's nodes in ``harness/load/failover.py``.

THE READER IS A TOKEN SCAN, NOT A SHELL PARSER. Some shapes it cannot place read as a problem: at
least an interpreter named through a variable (``"$PY" -m messagefoundry serve``), the
console-script launcher, and a ``-m messagefoundry`` that follows a script or another module. At
least a start assembled from variables, or spread over lines with no continuation, is missed.
"""

from __future__ import annotations

import functools
import itertools
import re
from pathlib import PureWindowsPath
from typing import Any

import pytest

from messagefoundry.startupcode import ISOLATED_LAUNCH_OPTIONS

_SUBCOMMANDS = ("serve", "supervise")
_OPTION = ("-X", "disable-remote-debug")
#: A word, or one of the characters that end a shell command. Quotes, redirections, commas and
#: brackets split words, so ``serve>engine.log``, ``"python`` and ``'-m','messagefoundry'`` still
#: yield the bare words.
_TOKEN = re.compile(r"[^\s;&|()<>\"'`,\[\]{}@]+|[;&|()]")
_SEPARATORS = frozenset(";&|()")
#: A redirection that duplicates a descriptor, such as ``2>&1``: its ``&`` ends no command.
_DUPLICATION = re.compile(r"\d*[<>]&\d*")
#: An interpreter's own name, with any version suffix: ``python``, ``python3.14``, ``python.exe``.
_INTERPRETER = re.compile(r"python[\d.]*(\.exe)?")
#: A line continuation, in bash (a backslash) or in pwsh (a backtick).
_CONTINUATION = re.compile(r"[\\`]\r?\n")
#: Interpreter options that take an argument, attached or as the next word.
_TAKES_ARGUMENT = frozenset("XW")
#: ``-m`` closing a cluster of single-letter options, and the same with the module attached.
_MODULE_FLAG = re.compile(r"-([A-Za-z]*)m")
_MODULE_ATTACHED = re.compile(r"-([A-Za-z]*)m(messagefoundry)")


def _name(token: str) -> str:
    """The last path part, split on either separator, lower-cased."""
    return PureWindowsPath(token).name.lower()


def _options_problem(options: list[str]) -> str | None:
    """What is wrong with the interpreter options before ``-m messagefoundry``, or ``None``.

    Read as CPython reads them: single-letter options cluster (``-IX...``), ``-X`` and ``-W`` take
    the rest of their word or the next word. A word that is no option ends the interpreter's own
    options, and so does ``-c``, so a ``-m messagefoundry`` after either is not the interpreter's."""
    found = False
    words = iter(options)
    for word in words:
        if word.startswith("--"):
            if word == "--check-hash-based-pycs":
                next(words, None)
            continue
        if not word.startswith("-") or word == "-":
            return f"the module follows {word!r}, so it is not the interpreter's own -m"
        for at, letter in enumerate(word[1:], 1):
            if letter in "cm":
                return f"the module follows {word!r}, so it is not the interpreter's own -m"
            if letter in _TAKES_ARGUMENT:
                argument = word[at + 1 :] or next(words, "")
                found = found or (letter, argument) == (_OPTION[0][1], _OPTION[1])
                break
    return None if found else "remote debugging is not turned off"


def _interpreter_before(tokens: list[str], end: int) -> int:
    """The index of the interpreter of the command holding ``tokens[end]``, or -1: the nearest
    interpreter name before it that is not an option's argument, not past a command separator."""
    for i in range(end - 1, -1, -1):
        if tokens[i] in _SEPARATORS:
            return -1
        if tokens[i].startswith("-") or (i > 0 and tokens[i - 1] in ("-X", "-W")):
            continue
        if _INTERPRETER.fullmatch(_name(tokens[i])):
            return i
    return -1


def engine_starts(script: str) -> list[tuple[str, str | None]]:
    """``(line, problem or None)`` for each engine start in ``script``.

    ``script`` is a step's ``run`` text with its comment lines already dropped. Line continuations
    are joined first, so a start split across lines is still one start."""
    starts: list[tuple[str, str | None]] = []
    for line in _CONTINUATION.sub(" ", script).splitlines():
        tokens = _TOKEN.findall(_DUPLICATION.sub(" ", line))
        for at, token in enumerate(tokens[:-1]):
            if tokens[at + 1] not in _SUBCOMMANDS:
                continue
            if attached := _MODULE_ATTACHED.fullmatch(token):
                flag_at, cluster = at, attached.group(1)
            elif _name(token) not in ("messagefoundry", "messagefoundry.exe"):
                continue
            elif at and (flag := _MODULE_FLAG.fullmatch(tokens[at - 1])):
                flag_at, cluster = at - 1, flag.group(1)
            else:
                # The console-script launcher cannot pass an option to the interpreter it starts.
                starts.append((line.strip(), "started through the launcher, not the interpreter"))
                continue
            interpreter = _interpreter_before(tokens, flag_at)
            if interpreter == -1:
                problem: str | None = (
                    "no interpreter named on the command, so no option can be read"
                )
            else:
                options = tokens[interpreter + 1 : flag_at] + ([f"-{cluster}"] if cluster else [])
                problem = _options_problem(options)
            starts.append((line.strip(), problem))
    return starts


def start_problems(script: str) -> list[str]:
    """The engine starts in ``script`` that do not turn remote debugging off, one line each."""
    return [f"{problem}: {line}" for line, problem in engine_starts(script) if problem]


def _scripts_of(steps: list[dict[str, Any]]) -> list[str]:
    """Each step's ``run`` text without its comment lines, for the steps that have one."""
    found = []
    for step in steps:
        run = str(step.get("run") or "")
        script = "\n".join(line for line in run.splitlines() if not line.lstrip().startswith("#"))
        if script:
            found.append(script)
    return found


@functools.cache
def _step_scripts() -> tuple[tuple[str, str, str], ...]:
    """``(file, job, script)`` for every step script of every workflow and composite action,
    parsed once for the module: ci.yml alone takes a measurable share of a second."""
    # A missing PyYAML is a skip, here as in the helper, never a collection error.
    yaml = pytest.importorskip("yaml")
    from tests._workflow_contexts import ROOT, WORKFLOWS, jobs_of

    found: list[tuple[str, str, str]] = []
    for path in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        for key, job in jobs_of(path.name).items():
            found += [(path.name, key, s) for s in _scripts_of(job.get("steps") or [])]
    actions = ROOT / ".github" / "actions"
    for path in sorted([*actions.glob("*/action.yml"), *actions.glob("*/action.yaml")]):
        runs = (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("runs") or {}
        name = path.parent.name
        found += [(name, "runs", s) for s in _scripts_of(runs.get("steps") or [])]
    return tuple(found)


def test_every_command_line_engine_start_turns_remote_debugging_off() -> None:
    problems = {
        f"{where} / {job}": found
        for where, job, script in _step_scripts()
        if (found := start_problems(script))
    }
    assert not problems, (
        f"start the interpreter as `python {' '.join(ISOLATED_LAUNCH_OPTIONS)} -m messagefoundry "
        f"serve ...`, as the shipped service does (vault BACKLOG #2700): {problems}"
    )


def test_the_reader_meets_the_starts_it_was_written_for() -> None:
    """CONTROL: the reader above recognises the five load-leg starts as starts, so a reader that
    matched nothing would fail here rather than pass there."""
    starting = {(where, job) for where, job, script in _step_scripts() if engine_starts(script)}
    expected = {
        ("benchmark.yml", "baseline-sqlite"),
        ("benchmark.yml", "baseline-postgres"),
        ("benchmark.yml", "baseline-sqlserver"),
        ("ci.yml", "load-test"),
        ("ci.yml", "load-test-sqlserver"),
    }
    assert expected <= starting, sorted(expected - starting)


def test_the_option_is_the_one_the_shipped_launch_passes() -> None:
    assert _OPTION in itertools.pairwise(ISOLATED_LAUNCH_OPTIONS)


@pytest.mark.parametrize(
    "start",
    [
        # The bare start the three `warn` legs carried until this item.
        "python -m messagefoundry serve --config harness/config/load --env dev \\\n  --port 8765 &",
        "python -m messagefoundry supervise --config c",
        # Misspelt: the interpreter accepts it and leaves remote debugging on.
        "python -I -X disable_remote_debug -m messagefoundry serve --config c",
        # Another -X option, not this one.
        "python -I -X utf8 -m messagefoundry serve --config c",
        # The option after the module is the engine's argument, not the interpreter's.
        "python -I -m messagefoundry serve -X disable-remote-debug --config c",
        # The launcher cannot pass it at all, on either separator.
        "messagefoundry serve --config c",
        ".venv/bin/messagefoundry serve --config c",
        "& .\\.venv\\Scripts\\messagefoundry.exe serve --config c",
        # Split across a continuation, in bash and in pwsh.
        "python -I \\\n  -m messagefoundry serve --config c",
        "python -I `\n  -m messagefoundry serve --config c",
        # Punctuation attached to the subcommand.
        "python -m messagefoundry serve>engine.log 2>&1 &",
        "python -m messagefoundry serve&",
        "(python -m messagefoundry serve) &",
        # The option belongs to an earlier command on the line, not to the engine's.
        'python -X disable-remote-debug -c pass; "$PY" -m messagefoundry serve',
        "python -X disable-remote-debug -c pass && python -m messagefoundry serve",
        # Arguments separated by commas, as a pwsh array or a Python list writes them.
        "Start-Process python -ArgumentList '-I','-m','messagefoundry','serve'",
        'subprocess.run([sys.executable, "-m", "messagefoundry", "serve"])',
        # The module attached to -m, alone and in a cluster.
        "python -mmessagefoundry serve --config c",
        "python -Im messagefoundry serve --config c",
        # The option belongs to a wrapper module, a script or -c, not to the interpreter.
        "python -m coverage run -X disable-remote-debug -m messagefoundry serve",
        "python script.py -X disable-remote-debug -m messagefoundry serve",
        "python -c pass -X disable-remote-debug -m messagefoundry serve",
    ],
)
def test_the_reader_objects_to_a_planted_start(start: str) -> None:
    assert start_problems("set -e\n" + start + "\n"), start


@pytest.mark.parametrize(
    "start",
    [
        "python -I -X disable-remote-debug -m messagefoundry serve --config c > engine.log 2>&1 &",
        "python -P -X disable-remote-debug -m messagefoundry supervise --config c",
        "python -I -X disable-remote-debug \\\n  -m messagefoundry serve --config c",
        "python -I `\n  -X disable-remote-debug -m messagefoundry serve --config c",
        "python -Xdisable-remote-debug -m messagefoundry serve --config c",
        "python3.14 -X disable-remote-debug -X pycache_prefix=/tmp/python-cache -m messagefoundry serve",
        "C:\\hostedtoolcache\\Python\\python.exe -I -X disable-remote-debug -m messagefoundry serve",
        # A descriptor duplication ends no command.
        "python 2>&1 -I -X disable-remote-debug -m messagefoundry serve",
        # Another -X argument that names a python path, separate and attached.
        "python -X disable-remote-debug -X pycache_prefix=/x/python -m messagefoundry serve",
        "python -X disable-remote-debug -Xpycache_prefix=/x/python -m messagefoundry serve",
        # Clustered options, and the module attached to -m.
        "python -IXdisable-remote-debug -m messagefoundry serve",
        "python -IX disable-remote-debug -mmessagefoundry serve",
        "python -X disable-remote-debug -Im messagefoundry serve",
    ],
)
def test_the_reader_passes_a_start_with_the_option(start: str) -> None:
    starts = engine_starts(start + "\n")
    assert [problem for _, problem in starts] == [None], (start, starts)


@pytest.mark.parametrize(
    "line",
    [
        # Another subcommand, and the image smoke's argument to the image entry point.
        "python -m messagefoundry protect-key --out key.bin",
        "docker run -d --name mefor image \\\n  serve --config /config",
    ],
)
def test_the_reader_sees_no_start_where_none_is(line: str) -> None:
    assert engine_starts(line + "\n") == [], line
