# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The `generate` subcommand: synthetic HL7 corpus generation + listing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.parsing import Peek
from messagefoundry_toolkit.__main__ import main


def _out_json(capsys: pytest.CaptureFixture[str]) -> object:
    return json.loads(capsys.readouterr().out)


def test_generate_writes_conformant_files(tmp_path: Path) -> None:
    out = tmp_path / "adt"
    rc = main(
        ["generate", "--type", "ADT", "--triggers", "A01,A04", "--count", "2", "--out", str(out)]
    )
    assert rc == 0
    for trigger in ("A01", "A04"):
        files = sorted((out / trigger).glob("*.hl7"))
        assert [f.name for f in files] == ["0001.hl7", "0002.hl7"]
        peek = Peek.parse(files[0].read_bytes())
        assert peek.message_code == "ADT" and peek.trigger_event == trigger


def test_generate_json_reports_counts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        [
            "generate",
            "--type",
            "adt",
            "--triggers",
            "A01",
            "--count",
            "3",
            "--out",
            str(tmp_path),
            "--json",
        ]
    )
    assert rc == 0
    report = _out_json(capsys)
    assert report["type"] == "ADT"  # type: ignore[index]
    assert report["total"] == 3  # type: ignore[index]
    assert report["by_trigger"] == {"A01": 3}  # type: ignore[index]


def test_generate_list_includes_built_in_types(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["generate", "--list", "--json"]) == 0
    listing = _out_json(capsys)
    assert "ADT" in listing  # type: ignore[operator]
    assert "A01" in listing["ADT"]  # type: ignore[index]


def test_generate_unknown_type_errors(tmp_path: Path) -> None:
    assert main(["generate", "--type", "ZZZ", "--out", str(tmp_path)]) == 2


def test_generate_unknown_trigger_errors(tmp_path: Path) -> None:
    assert main(["generate", "--type", "ADT", "--triggers", "A99", "--out", str(tmp_path)]) == 2


def test_generate_without_type_or_list_errors(tmp_path: Path) -> None:
    assert main(["generate", "--out", str(tmp_path)]) == 2


def test_generate_is_deterministic(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    main(["generate", "--type", "ADT", "--triggers", "A01", "--count", "1", "--out", str(a)])
    main(["generate", "--type", "ADT", "--triggers", "A01", "--count", "1", "--out", str(b)])
    assert (a / "A01" / "0001.hl7").read_bytes() == (b / "A01" / "0001.hl7").read_bytes()


# --- BACKLOG #5819: count range, explicit seed, write failure -------------------


@pytest.mark.parametrize("count", ["0", "-1", "10000"])
def test_generate_refuses_a_count_out_of_range_and_keeps_the_old_corpus(
    tmp_path: Path, count: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # A zero count used to clear the existing NNNN.hl7 files, write nothing and exit 0.
    assert (
        main(
            [
                "generate",
                "--type",
                "ADT",
                "--triggers",
                "A01",
                "--count",
                "1",
                "--out",
                str(tmp_path),
            ]
        )
        == 0
    )
    before = (tmp_path / "A01" / "0001.hl7").read_bytes()
    capsys.readouterr()

    rc = main(
        ["generate", "--type", "ADT", "--triggers", "A01", "--count", count, "--out", str(tmp_path)]
    )

    assert rc == 2
    assert "count must be between 1 and 9999" in capsys.readouterr().err
    assert (tmp_path / "A01" / "0001.hl7").read_bytes() == before


def test_generate_honours_an_explicit_empty_seed(tmp_path: Path) -> None:
    default, empty = tmp_path / "default", tmp_path / "empty"
    main(["generate", "--type", "ADT", "--triggers", "A01", "--count", "1", "--out", str(default)])
    main(
        [
            "generate",
            "--type",
            "ADT",
            "--triggers",
            "A01",
            "--count",
            "1",
            "--seed",
            "",
            "--out",
            str(empty),
        ]
    )
    # An empty seed is the user's choice, not a request for the default seed.
    assert (default / "A01" / "0001.hl7").read_bytes() != (empty / "A01" / "0001.hl7").read_bytes()


def test_generate_reports_a_write_failure_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # --out names an existing FILE, so creating the trigger directory under it raises an OSError.
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")

    rc = main(
        ["generate", "--type", "ADT", "--triggers", "A01", "--count", "1", "--out", str(blocker)]
    )

    assert rc == 1
    assert "error: could not write the corpus" in capsys.readouterr().err


def test_generate_json_reports_a_write_failure_as_a_json_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")

    rc = main(
        [
            "generate",
            "--type",
            "ADT",
            "--triggers",
            "A01",
            "--count",
            "1",
            "--out",
            str(blocker),
            "--json",
        ]
    )

    assert rc == 1
    assert "could not write the corpus" in _out_json(capsys)["error"]  # type: ignore[index]


def test_adt_generator_reports_a_write_failure_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from messagefoundry_toolkit.generators import adt

    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")

    rc = adt.main(["--triggers", "A01", "--count", "1", "--out", str(blocker), "--quiet"])

    assert rc == 1
    assert "could not write the corpus" in capsys.readouterr().err


def test_adt_generator_refuses_a_zero_count_and_keeps_the_old_corpus(tmp_path: Path) -> None:
    from messagefoundry_toolkit.generators import adt

    assert adt.main(["--triggers", "A01", "--count", "1", "--out", str(tmp_path), "--quiet"]) == 0
    with pytest.raises(SystemExit) as excinfo:
        adt.main(["--triggers", "A01", "--count", "0", "--out", str(tmp_path), "--quiet"])
    assert excinfo.value.code == 2
    assert (tmp_path / "A01" / "0001.hl7").exists()
