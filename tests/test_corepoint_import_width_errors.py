# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Wide Corepoint branch lists and clean command-line import failures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.corepoint_import import (
    Channel,
    Control,
    CorepointImportError,
    ImportResult,
    _split_branches,
    import_corepoint,
)

# An INPUT chosen clear of CPython's parser width wall, never an assertion about where that wall
# sits -- the measured band and why it must not be pinned are recorded once, in the width note near
# ``_MAX_NESTING`` in messagefoundry/corepoint_import.py. If a future CPython parses this width the
# tests below go red rather than quiet, which is the right way round.
_OVER_THE_WALL = 8000


def _package(body: str) -> str:
    return f'<Package Name="WIDTH"><ActionList Name="T"><List>{body}</List></ActionList></Package>'


def _wide_export(tmp_path: Path, width: int) -> Path:
    """Write an export whose generated module carries ``width`` ``elif False:`` siblings."""
    branches = "".join(
        f'<Line Data="ElseIf branch_{i:04d}"/><Line Data="Unknown body_{i:04d}"/>'
        for i in range(width)
    )
    path = tmp_path / "wide.xml"
    path.write_text(
        _package(f'<If Data="If opening"><List><Line Data="Unknown lead"/>{branches}</List></If>'),
        encoding="utf-8",
    )
    return path


def _small_export(tmp_path: Path) -> Path:
    """Write the smallest export that still produces one channel and one module."""
    path = tmp_path / "small.xml"
    path.write_text(_package('<Line Data="Unknown synthetic"/>'), encoding="utf-8")
    return path


def _refusal_message(export: Path, out: Path) -> str:
    """Import ``export``, require a refusal, and return its message -- asserting nothing reached disk."""
    with pytest.raises(CorepointImportError) as excinfo:
        import_corepoint(export, out)
    assert list(out.glob("*.py")) == []
    return str(excinfo.value)


def _cli_error(args: list[str], capsys: pytest.CaptureFixture[str], as_json: bool) -> str:
    """Run the command, assert the error-envelope shape for the stream in use, and return the text."""
    assert main(args) == 1
    captured = capsys.readouterr()
    if as_json:
        payload = json.loads(captured.out)
        assert set(payload) == {"error"}
        assert captured.err == ""
        # Assert the type rather than coercing it: `str(...)` would launder a regression that put a
        # non-string under the key into a passing test.
        assert isinstance(payload["error"], str)
        error = payload["error"]
    else:
        assert captured.out == ""
        assert captured.err.startswith("error: ")
        error = captured.err
    assert "Traceback" not in error
    return error


def test_wide_branch_list_imports_every_body_in_order(tmp_path: Path) -> None:
    """Sibling width must not consume parser stack or drop later branch bodies.

    Also the over-refusal control for the compile self-check below: a legitimately long ``ElseIf``
    chain still imports, so the guard refuses only what CPython genuinely cannot parse."""
    width = 1500
    export = _wide_export(tmp_path, width)
    result = import_corepoint(export, tmp_path / "out")
    assert result.total_mapped == width + 1
    assert result.total_unmapped == width + 1
    source = (tmp_path / "out" / "IB_WIDTH.py").read_text(encoding="utf-8")
    # Compiles the file as READ BACK, so this still covers the write/read UTF-8 round trip that the
    # pre-write self-check in ``import_corepoint`` cannot see.
    compile(source, "IB_WIDTH.py", "exec")
    positions = [source.index("Unknown lead")]
    for i in range(width):
        positions.extend((source.index(f"branch_{i:04d}"), source.index(f"Unknown body_{i:04d}")))
    assert positions == sorted(positions)


@pytest.mark.parametrize("kind", ["elif", "else", "except", "match"])
def test_split_preserves_empty_branches_and_already_owned_bodies(kind: str) -> None:
    """Only empty markers split the body; a marker with its own body stays intact."""
    lead = Control("block", "Comment", "lead")
    owned = Control(kind, "marker", "owned", body=(lead,))
    first = Control(kind, "marker", "first")
    second = Control(kind, "marker", "second")
    last = Control(kind, "marker", "last")
    body, branches = _split_branches([lead, first, second, owned, last])
    assert body == (lead,)
    assert branches == (
        first,
        Control(kind, "marker", "second", body=(owned,)),
        last,
    )
    assert _split_branches([lead, owned]) == ((lead, owned), ())
    assert _split_branches([]) == ((), ())


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("failure", ["directory", "write", "recursion"])
def test_cli_reports_import_failures_on_the_right_stream(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    as_json: bool,
    failure: str,
) -> None:
    """Filesystem and stack failures must return an error, never escape the CLI."""
    export = _small_export(tmp_path)
    out = tmp_path / "out"
    if failure == "directory":
        out.write_text("existing file", encoding="utf-8")
    elif failure == "write":
        (out / "IB_WIDTH.py").mkdir(parents=True)
    else:
        # Inject this at the importer boundary: sibling width no longer causes recursion,
        # but the command must still report a stack failure from another import stage.
        def fail_import(export_path: str | Path, out_dir: str | Path) -> ImportResult:
            raise RecursionError("synthetic recursion failure")

        monkeypatch.setattr("messagefoundry.corepoint_import.import_corepoint", fail_import)

    args = ["import", "corepoint", str(export), "--out", str(out)]
    if as_json:
        args.append("--json")
    error = _cli_error(args, capsys, as_json)
    if failure == "recursion":
        assert "synthetic recursion failure" in error
    else:
        failed_path = out / "IB_WIDTH.py" if failure == "write" else out
        assert repr(str(failed_path)) in error


def test_unparsable_generated_module_is_refused_instead_of_written(tmp_path: Path) -> None:
    """A module too wide for CPython's parser must raise, not land on disk under a success report.

    Asserts neither the parser's wording nor the exception class: both belong to the CPython build
    rather than to this project."""
    out = tmp_path / "out"
    message = _refusal_message(_wide_export(tmp_path, _OVER_THE_WALL), out)
    assert "IB_WIDTH.py" in message
    assert "could not be compiled and was not written" in message


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_refuses_an_unparsable_generated_module(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], as_json: bool
) -> None:
    """The command must exit non-zero with a clean message, plain and under ``--json``."""
    export = _wide_export(tmp_path, _OVER_THE_WALL)
    out = tmp_path / "out"
    args = ["import", "corepoint", str(export), "--out", str(out)]
    if as_json:
        args.append("--json")
    error = _cli_error(args, capsys, as_json)
    assert "IB_WIDTH.py" in error
    assert "could not be compiled and was not written" in error
    assert list(out.glob("*.py")) == []


# Sources CPython refuses, one per exception class the guard converts. Each is a REAL compiler
# refusal -- nothing here is a double -- so the parametrize is the paired-arms proof that the tuple
# is not one class short. The expected class is asserted, because here the source is chosen rather
# than generated, so the mapping is a property of the input and not of the CPython build's limits.
_UNCOMPILABLE = {
    # A codegen bug: the generator emitted something that is simply not Python.
    "syntax": ("def (\n", "SyntaxError"),
    # A lone surrogate riding into the module. Reachable from a real export: a JSON `\\ud800` escape
    # is plain ASCII on disk, so the file decodes as UTF-8 and `json.loads` yields the surrogate.
    "surrogate": ("x = 1  # \ud800\n", "UnicodeEncodeError"),
    # The compiler re-descending a flat operand chain. `_MAX_NESTING` bounds this module's walk of
    # the EXPORT, not the compiler's walk of the source this module emits.
    "recursion": ("y = " + "+".join(["1"] * 20_000) + "\n", "RecursionError"),
}


def _compiler_refuses(source: str) -> bool:
    """Does THIS CPython build actually refuse this source?

    Only the recursion arm needs asking, and its limit is not a knob this test can turn. Measured
    2026-09-21 on CPython 3.14.6 (Windows): a 20,000-term chain raises and a 5,000-term chain does
    not, and that boundary moves for NEITHER ``sys.setrecursionlimit(100)`` NOR a 256 KB thread
    stack -- so it is a compiled-in C recursion limit, not the interpreter's counter and not a stack
    this process can size. A build whose limit clears the chain (the reported case is the Linux
    default 8 MB stack) compiles it cleanly, and the arm would then assert a refusal that never
    happened.

    Probing keeps the arm a REAL compiler refusal wherever the build produces one, which is the
    property ``_UNCOMPILABLE`` exists to have. The alternatives were worse: monkeypatching
    ``compile`` downgrades every platform to a double, and deleting the arm drops coverage that
    works here. Where the build does not refuse, there is no conversion to test -- the arm is
    vacuous, not failing."""
    try:
        compile(source, "<probe>", "exec")
    except BaseException:  # noqa: BLE001 - any refusal counts; which class is the test's subject
        return True
    return False


@pytest.mark.parametrize("case", sorted(_UNCOMPILABLE))
def test_every_uncompilable_source_class_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    """Each class the compiler can raise becomes a reported error, never an escaping traceback.

    Injecting the SOURCE keeps the real ``compile`` in the loop, so these exercise the guard rather
    than simulate it. The surrogate arm is the one that caught a real gap: ``UnicodeEncodeError`` is
    a ``ValueError``, so a tuple naming only the three obvious classes let it escape."""
    source, expected = _UNCOMPILABLE[case]
    if not _compiler_refuses(source):
        pytest.skip(
            f"this CPython build compiles the {case!r} source, so there is no refusal to convert"
        )

    def broken(channel: Channel) -> str:
        return source

    monkeypatch.setattr("messagefoundry.corepoint_import.generate_module", broken)
    assert expected in _refusal_message(_small_export(tmp_path), tmp_path / "out")
