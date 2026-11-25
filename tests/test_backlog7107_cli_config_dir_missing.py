# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""`graph` and `dryrun` report a missing ``--config`` directory through the error envelope.

``load_config`` raises ``ConfigDirMissing`` (a ``FileNotFoundError``, not a ``WiringError``) for a
directory that does not exist. Both commands caught only ``WiringError``, so the exception reached
the last-resort floor: a CRITICAL log line, and under ``--json`` the floor's
``"ConfigDirMissing: ..."`` rendering rather than the command's own error (vault BACKLOG #7107,
the remainder of #5810).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main


def _fixture(tmp_path: Path) -> Path:
    msg = tmp_path / "m.hl7"
    msg.write_text("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5.1\r", encoding="utf-8")
    return msg


@pytest.mark.parametrize("command", ["graph", "dryrun"])
def test_missing_config_dir_emits_json_error(
    command: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    missing = tmp_path / "no-such-config"
    argv = [command, "--project-root", str(tmp_path), "--config", str(missing), "--json"]
    if command == "dryrun":
        argv += ["--messages", str(_fixture(tmp_path))]
    rc = main(argv)
    out = capsys.readouterr().out
    assert rc == 1
    payload = json.loads(out.strip().splitlines()[-1])
    # The command's own envelope, not the last-resort floor's "<ExceptionType>: ..." rendering.
    assert payload["error"].startswith("config directory not found")
    assert not [r for r in caplog.records if r.name == "messagefoundry.last_resort"]


@pytest.mark.parametrize("command", ["graph", "dryrun"])
def test_missing_config_dir_text_mode_names_the_directory(
    command: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "no-such-config"
    argv = [command, "--project-root", str(tmp_path), "--config", str(missing)]
    if command == "dryrun":
        argv += ["--messages", str(_fixture(tmp_path))]
    rc = main(argv)
    err = capsys.readouterr().err
    assert rc == 1
    assert "error: config directory not found" in err
