# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the tee CLI (tee/__main__.py): endpoint parsing + the test-data-only warning."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tee.__main__ import _build_parser, _confirm_test_only, _parse_age, _parse_endpoint, main
from tee.store import RelayStore


async def _seed(db: str) -> None:
    """Put one NAK row in a fresh log DB (for the export/purge CLI tests)."""
    store = await RelayStore.open(db)
    await store.record_leg(
        direction="epic_to_corepoint",
        leg="corepoint",
        control_id="C",
        message_type="ADT^A01",
        size_bytes=10,
        outcome="nak",
        ack_code="AE",
        detail="busy",
    )
    await store.close()


def test_parse_endpoint_valid() -> None:
    assert _parse_endpoint(":6661") == ("", 6661)
    assert _parse_endpoint("corehost:5000") == ("corehost", 5000)
    assert _parse_endpoint("127.0.0.1:2575") == ("127.0.0.1", 2575)


@pytest.mark.parametrize("bad", ["6661", "host:notaport", "host:0", "host:70000"])
def test_parse_endpoint_invalid(bad: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_endpoint(bad)


def test_run_parses_capture_corepoint_copy_flag() -> None:
    # #14: the compare-capture posture is opt-in and independent of --capture-bodies; both default off.
    base = [
        "run",
        "--listen-epic",
        ":6661",
        "--corepoint",
        "h:5000",
        "--mefor",
        "h:2575",
        "--db",
        "x",
    ]
    args = _build_parser().parse_args(base)
    assert args.capture_bodies is False
    assert args.capture_corepoint_copy is False
    args = _build_parser().parse_args([*base, "--capture-corepoint-copy"])
    assert args.capture_corepoint_copy is True
    assert args.capture_bodies is False  # the copy-only posture does NOT imply capturing inputs


def test_confirm_prints_warning_and_yes_bypass(capsys: pytest.CaptureFixture[str]) -> None:
    assert _confirm_test_only(assume_yes=True) is True
    err = capsys.readouterr().err
    assert "FOR TEST DATA ONLY" in err
    assert "do not route production phi" in err.lower()


def test_confirm_non_interactive_proceeds(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A non-tty stdin (the pytest default) can't prompt — the banner stands and the start proceeds.
    assert _confirm_test_only(assume_yes=False) is True
    assert "FOR TEST DATA ONLY" in capsys.readouterr().err


def test_confirm_declined_when_operator_says_no(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr("sys.stdin", _Tty())
    monkeypatch.setattr("builtins.input", lambda _prompt: "no")
    assert _confirm_test_only(assume_yes=False) is False


def test_naks_command_on_empty_db(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["naks", "--db", str(tmp_path / "tee.db")])
    assert rc == 0
    assert "no NAKs" in capsys.readouterr().out


def test_parse_age_relative_and_absolute() -> None:
    now = time.time()
    assert abs(_parse_age("1h") - (now - 3600)) < 1.0
    assert abs(_parse_age("2d") - (now - 2 * 86400)) < 1.0
    assert _parse_age("2026-06-01") == datetime(2026, 6, 1, tzinfo=timezone.utc).timestamp()


@pytest.mark.parametrize("bad", ["7", "7x", "yesterday", "2026-13-01"])
def test_parse_age_invalid(bad: str) -> None:
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_age(bad)


def test_purge_refuses_without_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Non-tty stdin (pytest default) + no -y → refuse a destructive purge (returns 1).
    rc = main(["purge", "--db", str(tmp_path / "tee.db")])
    assert rc == 1
    assert "refusing to purge" in capsys.readouterr().err.lower()


def test_purge_with_yes_empties_db(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "tee.db")
    asyncio.run(_seed(db))
    rc = main(["purge", "--db", db, "-y"])
    assert rc == 0
    assert "purged 1 log row(s)" in capsys.readouterr().out


def test_export_outputs_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = str(tmp_path / "tee.db")
    asyncio.run(_seed(db))
    rc = main(["export", "--db", db])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["total_legs"] == 1
    assert data["summary"]["naks"] == 1
    assert data["rows"][0]["control_id"] == "C"
    assert "raw" not in data["rows"][0]  # metadata only — never a message body


def test_export_to_file(tmp_path: Path) -> None:
    db = str(tmp_path / "tee.db")
    out = tmp_path / "review.json"
    asyncio.run(_seed(db))
    rc = main(["export", "--db", db, "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["total_legs"] == 1


def test_compare_parses_args() -> None:
    args = _build_parser().parse_args(
        [
            "compare",
            "--db",
            "x",
            "--mefor-api",
            "http://h:8000",
            "--token",
            "T",
            "--since",
            "24h",
            "--show-diffs",
            "--dest-alias",
            "CA/CF=MA/MF",
        ]
    )
    assert args.command == "compare"
    assert args.mefor_api == "http://h:8000" and args.token == "T"
    assert args.show_diffs is True
    assert args.dest_alias == ["CA/CF=MA/MF"]


def test_compare_end_to_end(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seed a Corepoint capture, stub the MEFOR API pull, run `tee compare`, and check the summary.
    from tee import mefor_api

    db = str(tmp_path / "tee.db")
    body = (
        "MSH|^~\\&|APP|SF|DOWN|DFAC|20260604120000||ADT^A01|C1|P|2.5.1\r"
        "PID|1||100^^^H^MR||DOE^JANE\r"
    )

    async def _seed_capture() -> None:
        store = await RelayStore.open(db)
        await store.record_capture(direction="corepoint_copy", control_id="C1", raw=body.encode())
        await store.close()

    asyncio.run(_seed_capture())
    monkeypatch.setattr(
        mefor_api,
        "fetch_mefor_outputs",
        lambda get, **kw: [mefor_api.MeforOutput("m1", "C1", "OB", body)],
    )
    rc = main(["compare", "--db", db, "--mefor-api", "http://127.0.0.1:9", "--token", "T"])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["exact"] == 1
    assert report["summary"]["matched"] == 1
    assert "diffs" not in report  # PHI diffs off without --show-diffs
