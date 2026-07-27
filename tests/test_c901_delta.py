"""Tests for scripts/quality/c901_delta.py -- the PR-caused complexity reporter.

The script exists because raw C901 is unshippable as a diff signal (all 122 findings on this tree
anchor on a single `def` line). Its whole value is that it reports ONLY what a PR changed, so the
tests that matter are: pre-existing findings never appear, and a ruff wording change fails loudly
instead of quietly reporting "nothing changed" forever.
"""

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]


def _load() -> ModuleType:
    path = _ROOT / "scripts" / "quality" / "c901_delta.py"
    assert path.is_file(), f"delta script not found at {path}"
    spec = importlib.util.spec_from_file_location("c901_delta", path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


delta = _load()


def _finding(filename: str, function: str, complexity: int, row: int, threshold: int = 10) -> dict:
    """One ruff C901 result, in ruff's real JSON shape (captured from ruff 0.15.22)."""
    return {
        "code": "C901",
        "message": f"`{function}` is too complex ({complexity} > {threshold})",
        "filename": filename,
        "location": {"column": 5, "row": row},
        "end_location": {"column": 5 + len(function), "row": row},
        "fix": None,
        "url": "https://docs.astral.sh/ruff/rules/complex-structure",
    }


def _write(tmp_path: Path, name: str, findings: list[dict]) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(findings), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------------------------
# Classification: the core promise -- unchanged pre-existing debt must never be reported.
# --------------------------------------------------------------------------------------------


def _parse(tmp_path: Path, name: str, findings: list[dict], root: str = "/repo") -> dict:
    return delta._parse_findings(_write(tmp_path, name, findings), root, "messagefoundry")


def test_unchanged_findings_are_never_reported(tmp_path: Path) -> None:
    """The single most important assertion: 122 untouched findings produce zero output."""
    same = [_finding("/repo/messagefoundry/a.py", "f", 30, 10)]
    base = _parse(tmp_path, "base.json", same)
    head = _parse(tmp_path, "head.json", same)

    new, increased, decreased = delta.classify(base, head)

    assert new == []
    assert increased == []
    assert decreased == []


def test_new_function_over_threshold_is_reported(tmp_path: Path) -> None:
    base = _parse(tmp_path, "base.json", [])
    head = _parse(tmp_path, "head.json", [_finding("/repo/messagefoundry/a.py", "fresh", 14, 42)])

    new, increased, decreased = delta.classify(base, head)

    assert [c.key.function for c in new] == ["fresh"]
    assert new[0].before is None
    assert new[0].after == 14
    assert new[0].line == 42
    assert increased == [] and decreased == []


def test_increased_complexity_is_reported_with_both_numbers(tmp_path: Path) -> None:
    """The body-edit case: the `def` line never moved, but complexity rose. This is the case
    SARIF/code-scanning cannot see at all, and the reason the delta exists."""
    base = _parse(tmp_path, "base.json", [_finding("/repo/messagefoundry/a.py", "grow", 12, 7)])
    head = _parse(tmp_path, "head.json", [_finding("/repo/messagefoundry/a.py", "grow", 27, 7)])

    new, increased, decreased = delta.classify(base, head)

    assert new == [] and decreased == []
    assert len(increased) == 1
    assert (increased[0].before, increased[0].after) == (12, 27)


def test_decreased_complexity_is_summary_only(tmp_path: Path) -> None:
    base = _parse(tmp_path, "base.json", [_finding("/repo/messagefoundry/a.py", "shrink", 40, 3)])
    head = _parse(tmp_path, "head.json", [_finding("/repo/messagefoundry/a.py", "shrink", 11, 3)])

    new, increased, decreased = delta.classify(base, head)

    assert new == [] and increased == []
    assert len(decreased) == 1
    markdown = delta._markdown(new, increased, decreased)
    assert "Improved" in markdown
    assert "shrink" in markdown


def test_a_function_dropping_below_threshold_is_not_a_regression(tmp_path: Path) -> None:
    """Fixed entirely: it leaves ruff's output, so it must not read as new/increased."""
    base = _parse(tmp_path, "base.json", [_finding("/repo/messagefoundry/a.py", "fixed", 12, 5)])
    head = _parse(tmp_path, "head.json", [])

    new, increased, decreased = delta.classify(base, head)

    assert new == [] and increased == [] and decreased == []


# --------------------------------------------------------------------------------------------
# Path normalisation -- ruff emits ABSOLUTE paths; annotations need repo-relative POSIX ones.
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("filename", "repo_root", "expected"),
    [
        ("/repo/messagefoundry/api/app.py", "/repo", "messagefoundry/api/app.py"),
        (r"C:\co\messagefoundry\api\app.py", r"C:\co", "messagefoundry/api/app.py"),
        # Casefolded compare: a drive letter differing only in case must still strip.
        (r"c:\co\messagefoundry\a.py", r"C:\co", "messagefoundry/a.py"),
        # JSON captured from a DIFFERENT checkout: fall back to the scan-root segment.
        (r"D:\other\tree\messagefoundry\a.py", "/repo", "messagefoundry/a.py"),
        ("messagefoundry/a.py", "/repo", "messagefoundry/a.py"),
        # THE BASE-TREE CASE. The merge-base run happens in a second checkout under the repo root,
        # so its paths carry an extra segment. If this did not collapse to the same key as HEAD,
        # every function would report as new -- a 122-annotation flood on the very first PR.
        (
            "/home/runner/work/r/r/base-tree/messagefoundry/a.py",
            "/home/runner/work/r/r",
            "messagefoundry/a.py",
        ),
        # A repo root that itself ends in the scanned package name must not confuse the anchor.
        ("/src/messagefoundry/messagefoundry/a.py", "/src/messagefoundry", "messagefoundry/a.py"),
    ],
)
def test_paths_normalise_to_repo_relative_posix(
    filename: str, repo_root: str, expected: str
) -> None:
    assert delta._normalise_path(filename, repo_root, "messagefoundry") == expected


def test_base_tree_and_head_paths_produce_the_SAME_key(tmp_path: Path) -> None:
    """Regression guard for the flood bug: the merge-base checkout lives one directory deeper, and
    if that leaks into the key then nothing ever matches and every finding reads as new."""
    root = "/home/runner/work/r/r"
    head = _parse(
        tmp_path, "head.json", [_finding(f"{root}/messagefoundry/a.py", "f", 30, 10)], root
    )
    base = _parse(
        tmp_path,
        "base.json",
        [_finding(f"{root}/base-tree/messagefoundry/a.py", "f", 30, 10)],
        root,
    )

    assert set(head) == set(base)
    assert delta.classify(base, head) == ([], [], [])


def test_annotation_carries_a_relative_path_and_the_def_line(tmp_path: Path) -> None:
    base = _parse(tmp_path, "base.json", [])
    head = _parse(
        tmp_path, "head.json", [_finding(r"C:\repo\messagefoundry\x.py", "g", 13, 99)], "C:/repo"
    )
    new, _, _ = delta.classify(base, head)

    line = delta._annotation(new[0])

    assert line.startswith("::warning file=messagefoundry/x.py,")
    assert "line=99,endLine=99" in line
    assert "C:" not in line  # an absolute local path must never reach the annotation
    assert "13" in line


# --------------------------------------------------------------------------------------------
# Fail-loud parsing -- a silent zero-finding report is indistinguishable from a clean PR.
# --------------------------------------------------------------------------------------------


def test_unparseable_message_raises_rather_than_reporting_nothing(tmp_path: Path) -> None:
    broken = [
        {
            "code": "C901",
            "message": "`f` has a cyclomatic complexity of 30, over the limit of 10",
            "filename": "/repo/messagefoundry/a.py",
            "location": {"column": 5, "row": 1},
            "end_location": {"column": 6, "row": 1},
        }
    ]
    with pytest.raises(ValueError, match="unrecognised ruff C901 message"):
        _parse(tmp_path, "head.json", broken)


def test_non_c901_results_are_ignored(tmp_path: Path) -> None:
    mixed = [
        {
            "code": "E501",
            "message": "Line too long",
            "filename": "/repo/messagefoundry/a.py",
            "location": {"column": 1, "row": 1},
            "end_location": {"column": 2, "row": 1},
        },
        _finding("/repo/messagefoundry/a.py", "only", 12, 4),
    ]
    parsed = _parse(tmp_path, "head.json", mixed)
    assert [k.function for k in parsed] == ["only"]


def test_key_collision_takes_the_max_complexity(tmp_path: Path) -> None:
    """Two same-named methods in one file share a key. Taking the max keeps the delta
    conservative -- it can under-report an increase, never invent one."""
    collide = [
        _finding("/repo/messagefoundry/a.py", "run", 12, 10),
        _finding("/repo/messagefoundry/a.py", "run", 40, 80),
    ]
    parsed = _parse(tmp_path, "head.json", collide)
    assert len(parsed) == 1
    assert next(iter(parsed.values())).complexity == 40


# --------------------------------------------------------------------------------------------
# Annotation cap + end-to-end main()
# --------------------------------------------------------------------------------------------


def test_annotations_are_capped_and_the_remainder_is_announced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    head = [_finding(f"/repo/messagefoundry/f{i}.py", f"fn{i}", 12, i + 1) for i in range(25)]
    summary = tmp_path / "summary.md"

    rc = delta.main(
        [
            "--base",
            _write(tmp_path, "base.json", []),
            "--head",
            _write(tmp_path, "head.json", head),
            "--repo-root",
            "/repo",
            "--max-annotations",
            "20",
            "--summary-file",
            str(summary),
        ]
    )
    out = capsys.readouterr().out

    assert rc == 0
    assert out.count("::warning ") == 20
    assert "::notice title=Complexity delta truncated::5 further change(s)" in out
    # The summary is ALWAYS complete, even when annotations are dropped.
    assert summary.read_text(encoding="utf-8").count("| `fn") == 25


def test_main_reports_clean_when_nothing_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    same = [_finding("/repo/messagefoundry/a.py", "f", 30, 10)]
    summary = tmp_path / "summary.md"

    rc = delta.main(
        [
            "--base",
            _write(tmp_path, "base.json", same),
            "--head",
            _write(tmp_path, "head.json", same),
            "--repo-root",
            "/repo",
            "--summary-file",
            str(summary),
        ]
    )

    assert rc == 0
    assert "::warning" not in capsys.readouterr().out
    assert "No function was introduced over the threshold" in summary.read_text(encoding="utf-8")


def test_main_appends_rather_than_truncating_the_summary(tmp_path: Path) -> None:
    """GITHUB_STEP_SUMMARY accumulates across steps; overwriting would eat another step's output."""
    summary = tmp_path / "summary.md"
    summary.write_text("## existing content\n", encoding="utf-8")

    delta.main(
        [
            "--base",
            _write(tmp_path, "base.json", []),
            "--head",
            _write(tmp_path, "head.json", []),
            "--repo-root",
            "/repo",
            "--summary-file",
            str(summary),
        ]
    )

    assert "## existing content" in summary.read_text(encoding="utf-8")


def test_workflow_command_metacharacters_are_escaped() -> None:
    change = delta.Change(
        key=delta.Key(path="messagefoundry/a,b.py", function="weird%name"),
        before=1,
        after=2,
        threshold=10,
        line=3,
    )
    line = delta._annotation(change)

    assert "file=messagefoundry/a%2Cb.py" in line
    assert "weird%25name" in line
