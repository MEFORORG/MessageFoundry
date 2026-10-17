# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the tee CLI (tee/__main__.py): endpoint parsing + the test-data-only warning."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import functools
import json
import os
import stat
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime
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
    assert _parse_age("2026-06-01") == datetime(2026, 6, 1, tzinfo=UTC).timestamp()


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
    db = _seed_compare(tmp_path, monkeypatch, mefor_name="DOE^JANE")
    rc = main(["compare", "--db", db, "--mefor-api", "http://127.0.0.1:9", "--token", "T"])
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["exact"] == 1
    assert report["summary"]["matched"] == 1
    assert "diffs" not in report  # PHI diffs off without --show-diffs


def _seed_compare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, mefor_name: str = "DOE^JOAN"
) -> str:
    """A capture DB holding one Corepoint message named DOE^JANE, plus a stubbed MEFOR pull of the
    same message named ``mefor_name``. The default DIFFERS, so a ``--show-diffs`` report carries
    field values. Synthetic data only."""
    from tee import mefor_api
    from tee.correlate import MeforOutput

    db = str(tmp_path / "tee.db")
    msh = "MSH|^~\\&|APP|SF|DOWN|DFAC|20260604120000||ADT^A01|C1|P|2.5.1\r"
    corepoint_body = msh + "PID|1||100^^^H^MR||DOE^JANE\r"
    mefor_body = msh + f"PID|1||100^^^H^MR||{mefor_name}\r"

    async def _seed_capture() -> None:
        store = await RelayStore.open(db)
        await store.record_capture(
            direction="corepoint_copy", control_id="C1", raw=corepoint_body.encode()
        )
        await store.close()

    asyncio.run(_seed_capture())
    monkeypatch.setattr(
        mefor_api,
        "fetch_mefor_outputs",
        lambda get, **kw: [MeforOutput("m1", "C1", "OB", mefor_body)],
    )
    return db


def _compare_to(db: str, out: Path) -> int:
    return main(
        [
            "compare",
            "--db",
            db,
            "--mefor-api",
            "http://127.0.0.1:9",
            "--token",
            "T",
            "--show-diffs",
            "--out",
            str(out),
        ]
    )


_POSIX_MODES = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@contextlib.contextmanager
def _umask_022() -> Iterator[None]:
    """The umask under which write_text would create a world-readable file."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


@_POSIX_MODES
def test_compare_show_diffs_out_is_created_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # vault BACKLOG #2792: under a 022 umask, write_text created this report 0644.
    db = _seed_compare(tmp_path, monkeypatch)
    out = tmp_path / "report.json"
    with _umask_022():
        assert _compare_to(db, out) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    # Control: the field values the mode protects really are in the file.
    assert json.loads(out.read_text(encoding="utf-8"))["diffs"]


@_POSIX_MODES
def test_compare_out_replaces_an_existing_readable_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A mode argument applies only at creation, so writing INTO an existing 0644 file would keep
    # 0644. The report is a new file renamed over it, so the old file and its mode are gone.
    db = _seed_compare(tmp_path, monkeypatch)
    out = tmp_path / "report.json"
    out.write_text("stale\n", encoding="utf-8")
    out.chmod(0o644)
    old_inode = out.stat().st_ino
    assert _compare_to(db, out) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert out.stat().st_ino != old_inode
    assert "stale" not in out.read_text(encoding="utf-8")
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


@_POSIX_MODES
def test_compare_out_replaces_a_link_rather_than_following_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A link at the output name would otherwise send the report to whatever file it points at.
    db = _seed_compare(tmp_path, monkeypatch)
    target = tmp_path / "elsewhere.json"
    target.write_text("untouched\n", encoding="utf-8")
    out = tmp_path / "report.json"
    out.symlink_to(target)
    assert _compare_to(db, out) == 0
    assert target.read_text(encoding="utf-8") == "untouched\n"
    assert not out.is_symlink()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


@_POSIX_MODES
def test_compare_out_writes_through_a_pipe_this_account_owns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `--out >(jq .)` and `--out /dev/stdout` name a stream on purpose. Replacing it with a file
    # would break the pipeline, so the report is written into it and nothing is created beside it.
    import threading

    db = _seed_compare(tmp_path, monkeypatch)
    fifo = tmp_path / "report.pipe"
    # Always true here, since the test is skipped on Windows; the check narrows for mypy's win32 leg.
    if sys.platform != "win32":
        os.mkfifo(fifo)
    received: list[str] = []
    reader = threading.Thread(target=lambda: received.append(fifo.read_text(encoding="utf-8")))
    reader.start()
    try:
        assert _compare_to(db, fifo) == 0
    finally:
        reader.join(timeout=10)
    assert stat.S_ISFIFO(fifo.lstat().st_mode), "the pipe was replaced by a file"
    assert json.loads(received[0])["diffs"]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.pipe", "tee.db"]


def test_compare_out_that_cannot_be_written_is_an_error_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A write failure reports like every other _compare failure: an `error:` line and exit 1.
    db = _seed_compare(tmp_path, monkeypatch)
    out = tmp_path / "no-such-dir" / "report.json"
    assert _compare_to(db, out) == 1
    assert "error: could not write the report" in capsys.readouterr().err
    assert not out.parent.exists()


# --- anonymize-captures --out and export --out (vault BACKLOG #3166) ------------------------------

_ANON_SALT = "tee-cli-salt-0123456789abcdef"


def _anonymize_to(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out: Path) -> int:
    """Seed one synthetic capture and run ``anonymize-captures --out`` on it in process. Logging
    setup is stubbed, since it would reconfigure logging for the whole pytest session."""
    db = str(tmp_path / "tee.db")
    raw = (
        "MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260101||ADT^A01|C1|P|2.5.1\r"
        "PID|1||999^^^H^MR||DOE^JOHN||19800101|M"
    )

    async def seed() -> None:
        store = await RelayStore.open(db)
        try:
            await store.record_capture(
                direction="corepoint_copy", control_id="C1", raw=raw.encode()
            )
        finally:
            await store.close()

    asyncio.run(seed())
    monkeypatch.setenv("MEFOR_ANON_SALT", _ANON_SALT)
    monkeypatch.setattr("tee.__main__._configure_logging", lambda level: None)
    return main(["anonymize-captures", "--db", db, "--out", str(out)])


def _export_to(tmp_path: Path, out: Path) -> int:
    db = str(tmp_path / "tee.db")
    asyncio.run(_seed(db))
    return main(["export", "--db", db, "--out", str(out)])


@_POSIX_MODES
def test_anonymize_captures_out_is_created_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Under a 022 umask, write_text would leave an anonymized dataset world-readable on first
    # deployment, beside a capture DB the tee keeps at 0600.
    out = tmp_path / "ds.jsonl"
    with _umask_022():
        assert _anonymize_to(tmp_path, monkeypatch, out) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text(encoding="utf-8").splitlines()[0])["control_id"] == "C1"


@_POSIX_MODES
def test_export_out_is_created_owner_only(tmp_path: Path) -> None:
    out = tmp_path / "review.json"
    with _umask_022():
        assert _export_to(tmp_path, out) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


_OUT_COMMANDS = ["anonymize-captures", "export", "compare"]


def _write_out(command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, out: Path) -> int:
    """Run one of the tee commands that take ``--out``, writing to ``out``."""
    if command == "export":
        return _export_to(tmp_path, out)
    if command == "compare":
        return _compare_to(_seed_compare(tmp_path, monkeypatch), out)
    return _anonymize_to(tmp_path, monkeypatch, out)


@pytest.mark.parametrize("command", _OUT_COMMANDS)
def test_out_goes_through_the_owner_only_writer(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The mode tests above are POSIX-only. This one runs on every platform, so a Windows run still
    # fails if a command goes back to write_text.
    import tee.__main__ as tee_main

    calls: list[str] = []
    real = tee_main._write_owner_only

    def spy(path: str, text: str) -> None:
        calls.append(path)
        real(path, text)

    monkeypatch.setattr(tee_main, "_write_owner_only", spy)
    out = tmp_path / "out.json"
    assert _write_out(command, tmp_path, monkeypatch, out) == 0
    assert calls == [str(out)]


@pytest.mark.parametrize("command", _OUT_COMMANDS)
def test_out_is_lf_on_every_platform(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The dataset is JSONL, read back line by line by the harness corpus. A text layer's default
    # newline is CRLF on Windows, so this discriminates on win32.
    out = tmp_path / "out.json"
    assert _write_out(command, tmp_path, monkeypatch, out) == 0
    data = out.read_bytes()
    assert data.endswith(b"}\n")  # control: the file really has a line ending to translate
    assert b"\r\n" not in data


@pytest.mark.parametrize(
    ("command", "what"), [("anonymize-captures", "dataset"), ("export", "export")]
)
def test_out_that_cannot_be_written_is_an_error_line(
    command: str,
    what: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "no-such-dir" / "out.json"
    assert _write_out(command, tmp_path, monkeypatch, out) == 1
    assert f"error: could not write the {what}" in capsys.readouterr().err
    assert not out.parent.exists()


# --- a hardened --out target keeps its access list on Windows (vault BACKLOG #3166) ---------------

_WINDOWS_ACLS = pytest.mark.skipif(sys.platform != "win32", reason="Windows access lists")


def _win_run(exe: str, *args: str) -> str:
    """Run a System32 tool by its pinned path, never a search-path lookup (BACKLOG #1680)."""
    from messagefoundry.service_status import _system_exe

    done = subprocess.run(
        [_system_exe(exe), *args], capture_output=True, text=True, check=False, encoding="mbcs"
    )
    assert done.returncode == 0, f"{exe} {args}: {done.stderr or done.stdout}"
    return done.stdout


@functools.cache
def _own_sid() -> str:
    line = _win_run("whoami.exe", "/user", "/fo", "csv", "/nh").strip()
    return line.rsplit(",", 1)[1].strip().strip('"')


def _sddl_of(path: Path, scratch: Path) -> str:
    """The DACL of ``path`` as SDDL, read by ``icacls /save``, which does not depend on the
    display language the way icacls's printed listing does."""
    scratch.mkdir(exist_ok=True)
    saved = scratch / f"acl-{path.name}.txt"
    _win_run("icacls.exe", str(path), "/save", str(saved))
    text = saved.read_bytes().decode("utf-16-le").lstrip("\ufeff")
    return [line for line in text.splitlines() if line.strip()][1]


@_WINDOWS_ACLS
@pytest.mark.parametrize("command", _OUT_COMMANDS)
def test_out_keeps_the_access_list_of_a_hardened_target_on_windows(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A file renamed over the target would take the folder's inherited access list, so an export
    # or dataset an operator had hardened would lose that hardening in a looser folder.
    scratch = tmp_path / "acl"
    out = tmp_path / "out.json"
    # Longer than any output, so a write that skipped the truncate would leave stale bytes behind.
    out.write_text("stale\n" * 4000, encoding="utf-8")
    _win_run("icacls.exe", str(out), "/inheritance:r", "/grant:r", f"*{_own_sid()}:F")
    hardened = _sddl_of(out, scratch)
    sibling = tmp_path / "fresh.json"
    sibling.write_text("x\n", encoding="utf-8")
    # Control: the hardening really differs from what a new file in this folder gets.
    assert hardened != _sddl_of(sibling, scratch)
    assert _write_out(command, tmp_path, monkeypatch, out) == 0
    assert _sddl_of(out, scratch) == hardened
    data = out.read_bytes()
    assert b"stale" not in data
    assert data.endswith(b"}\n")
    assert b"\r\n" not in data
    assert not list(tmp_path.glob("*.tmp"))


def test_out_replaces_a_second_hard_link(tmp_path: Path) -> None:
    # Writing in place through a name with a second link would also rewrite the other name.
    other = tmp_path / "elsewhere.json"
    other.write_text("untouched\n", encoding="utf-8")
    out = tmp_path / "out.json"
    os.link(other, out)
    assert _export_to(tmp_path, out) == 0
    assert other.read_text(encoding="utf-8") == "untouched\n"
    assert b"untouched" not in out.read_bytes()


@_WINDOWS_ACLS
def test_out_is_refused_when_the_name_changes_while_it_is_opened_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The lstat names one file and the open reaches another, as a name swapped for a link between
    # the two would: nothing is written and the command fails with its error line.
    out = tmp_path / "out.json"
    out.write_text("untouched\n", encoding="utf-8")
    decoy = tmp_path / "decoy.json"
    decoy.write_text("x\n", encoding="utf-8")
    real_lstat = os.lstat
    monkeypatch.setattr(
        os,
        "lstat",
        lambda path, *a, **k: real_lstat(decoy if str(path) == str(out) else path, *a, **k),
    )
    assert _export_to(tmp_path, out) == 1
    assert "error: could not write the export" in capsys.readouterr().err
    assert out.read_text(encoding="utf-8") == "untouched\n"


@_WINDOWS_ACLS
def test_out_refuses_a_target_hardened_against_this_account_writing_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A replace could still swap a read-only file out through the folder's grant, trading its list
    # for the folder's. It is an error instead, and the file is left as it was.
    scratch = tmp_path / "acl"
    out = tmp_path / "out.json"
    out.write_text("untouched\n", encoding="utf-8")
    _win_run("icacls.exe", str(out), "/inheritance:r", "/grant:r", f"*{_own_sid()}:R")
    hardened = _sddl_of(out, scratch)
    assert _export_to(tmp_path, out) == 1
    assert "error: could not write the export" in capsys.readouterr().err
    assert _sddl_of(out, scratch) == hardened
    assert out.read_text(encoding="utf-8") == "untouched\n"
