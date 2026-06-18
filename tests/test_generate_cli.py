# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The `generate` subcommand: synthetic HL7 corpus generation + listing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.parsing import Peek


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
