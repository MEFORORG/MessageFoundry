# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``python -m tee anonymize-captures`` loads ``anon.toml`` once, before its loop (BACKLOG #2267).

The loop used to hand the overlay path to ``anonymize_checked`` for every row, inside a catch-all
that counts any error as one failed message. So a malformed overlay came out as "N message(s)
failed anonymization", with advice to extend the rule map, and the line naming the real problem
was thrown away.

The same single load is where the tee prints a keep that turns off a default scrub (BACKLOG
#2268). ``tests/test_anon_b193_2268.py`` pins the WARNING both loaders log for it.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

import tee.anon.rules
from tee.__main__ import main as tee_main
from tee.store import RelayStore

_SALT = "b193-salt-0123456789abcdef"
_ROWS = 3
_FAILED = "failed anonymization"


def _raw(control_id: str) -> bytes:
    return (
        f"MSH|^~\\&|SAPP|SFAC|RAPP|RFAC|20260101||ADT^A01|{control_id}|P|2.5.1\r"
        "PID|1||999^^^H^MR||DOE^JOHN||19800101|M"
    ).encode("latin-1")


@pytest.fixture(autouse=True)
def _no_process_logging_setup(monkeypatch: pytest.MonkeyPatch) -> None:
    """An in-process tee run must not reconfigure logging for the whole pytest session. The
    subprocess test below is where the CLI's own setup is exercised."""
    monkeypatch.setattr("tee.__main__._configure_logging", lambda level: None)


@pytest.fixture
def db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A relay store holding ``_ROWS`` captured bodies, with the salt set."""
    path = str(tmp_path / "tee.db")

    async def seed() -> None:
        store = await RelayStore.open(path)
        try:
            for n in range(_ROWS):
                await store.record_capture(
                    direction="corepoint_copy", control_id=f"C{n}", raw=_raw(f"C{n}")
                )
        finally:
            await store.close()

    asyncio.run(seed())
    monkeypatch.setenv("MEFOR_ANON_SALT", _SALT)
    return path


def _overlay(tmp_path: Path, body: str | bytes | None) -> str:
    """Write ``body`` as an overlay and return its path. ``None`` writes nothing: a missing file."""
    path = tmp_path / "anon.toml"
    if isinstance(body, bytes):
        path.write_bytes(body)
    elif body is not None:
        path.write_text(body, encoding="utf-8")
    return str(path)


def _run(db: str, out: Path, *extra: str) -> int:
    return tee_main(["anonymize-captures", "--db", db, "--out", str(out), *extra])


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ('[hl7]\nkeep = ["PID-5"\n', "invalid TOML at line 3, column 1"),
        (b'[hl7]\nkeep = ["EVN-1"]\n# \xff\xfe\n', "UTF-8"),
        ('[hl7]\nkeep = ["PID-5.1"]\n', "PID-5.1"),
        ("[fhir]\n", "fhir"),
        (None, "cannot read anon overlay"),
    ],
    ids=["malformed", "not-utf8", "component-path", "unknown-table", "missing"],
)
def test_a_bad_overlay_refuses_the_run_once(
    body: str | bytes | None,
    reason: str,
    db: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "ds.jsonl"
    overlay = _overlay(tmp_path, body)

    assert _run(db, out, "--overlay", overlay) == 1

    err = capsys.readouterr().err
    errors = [line for line in err.splitlines() if line.startswith("error:")]
    # One refusal that gives the reason, where there used to be a per-row count.
    assert len(errors) == 1
    assert reason in errors[0]
    assert _FAILED not in err
    assert not out.exists()
    assert "DOE" not in err


def _counting(
    monkeypatch: pytest.MonkeyPatch, target: str, real: Callable[..., object]
) -> list[object]:
    calls: list[object] = []

    def wrapper(*args: object, **kwargs: object) -> object:
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(target, wrapper)
    return calls


def test_the_rules_are_loaded_once_for_the_whole_run(
    db: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    overlay = _overlay(tmp_path, '[hl7]\ndrop = ["PID-8"]\n')
    # The run's own load, and the per-row load anonymize_checked falls back to with no rules.
    run_loads = _counting(monkeypatch, "tee.__main__.load_rules", tee.anon.rules.load_rules)
    row_loads = _counting(monkeypatch, "tee.anon.load_rules", tee.anon.rules.load_rules)
    out = tmp_path / "ds.jsonl"

    assert _run(db, out, "--overlay", overlay) == 0

    assert len(run_loads) == 1
    assert row_loads == []
    # And the overlay it loaded is the one each row got: PID-8 is dropped in every record.
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == _ROWS
    for record in records:
        pid = record["raw"].split("\r")[1].split("|")
        assert pid[8] == ""
        assert "DOE" not in record["raw"]


def _warnings(err: str) -> list[str]:
    return [line for line in err.splitlines() if line.startswith("warning:")]


def test_keeping_a_default_scrubbed_field_is_printed(
    db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-5", "EVN-1", "PID-13"]\n')
    out = tmp_path / "ds.jsonl"

    assert _run(db, out, "--overlay", overlay) == 0

    # Once for the run, not once per row, naming each field and the kind of scrub it lost.
    (line,) = _warnings(capsys.readouterr().err)
    assert "PID-5 (name)" in line
    assert "PID-13 (phone)" in line
    assert "EVN-1" not in line
    # What the warning is about: the name really is in the dataset.
    assert "DOE^JOHN" in out.read_text(encoding="utf-8")
    assert "DOE" not in line


@pytest.mark.parametrize(
    "extra_body",
    [None, '[hl7]\nkeep = ["EVN-1"]\n', '[hl7.fields]\n"ZPD-2" = "mrn"\n'],
    ids=["no-overlay", "keep-unmapped", "add-a-rule"],
)
def test_no_default_scrub_lost_means_no_warning(
    extra_body: str | None, db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    extra = [] if extra_body is None else ["--overlay", _overlay(tmp_path, extra_body)]
    out = tmp_path / "ds.jsonl"

    assert _run(db, out, *extra) == 0

    assert _warnings(capsys.readouterr().err) == []
    assert "DOE" not in out.read_text(encoding="utf-8")


def test_the_keep_warning_reaches_real_stderr_at_every_log_level(db: str, tmp_path: Path) -> None:
    # A print, not only a log line: --log-level ERROR hides the loader's WARNING and must not
    # hide this. The CLI's own logging setup runs here, which the in-process tests switch off.
    overlay = _overlay(tmp_path, '[hl7]\nkeep = ["PID-5"]\n')
    env = {**os.environ, "MEFOR_ANON_SALT": _SALT}
    cmd = [sys.executable, "-m", "tee", "anonymize-captures", "--db", db, "--overlay", overlay]

    root = Path(__file__).resolve().parents[1]

    for level, logged in (("ERROR", 0), ("INFO", 1)):
        out = tmp_path / f"ds-{level}.jsonl"
        done = subprocess.run(
            [*cmd, "--out", str(out), "--log-level", level],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert done.returncode == 0, done.stderr
        assert len(_warnings(done.stderr)) == 1, done.stderr
        assert done.stderr.count("WARNING tee.anon.rules") == logged, done.stderr
