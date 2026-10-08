# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The keyless ``serve`` messages name the at-rest opt-out the operator wrote (vault BACKLOG #2340).

Two ``[security]`` switches set the one store flag the keyless gate reads. The strict refusal, the
AUDIT line and the warning used to name ``allow_unencrypted_phi=true`` whichever was set, so an
operator who wrote only ``encrypt_stored_data = false`` was pointed at a key not in their file.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.__main__ import main

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

_ENCRYPT_OFF = "[security].encrypt_stored_data=false"
_ALLOW_ON = "[security].allow_unencrypted_phi=true"

_SWITCH_CASES = [
    pytest.param(
        "security.encrypt_stored_data = false\n", [_ENCRYPT_OFF], [_ALLOW_ON], id="encrypt"
    ),
    pytest.param(
        "security.allow_unencrypted_phi = true\n", [_ALLOW_ON], [_ENCRYPT_OFF], id="allow"
    ),
    pytest.param(
        "security.encrypt_stored_data = false\nsecurity.allow_unencrypted_phi = true\n",
        [f"{_ENCRYPT_OFF} and {_ALLOW_ON}"],
        [],
        id="both",
    ),
]


def _keyless(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, toml: str) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)


@pytest.mark.parametrize(("switches", "named", "absent"), _SWITCH_CASES)
def test_keyless_warning_and_audit_name_the_switch_that_was_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    switches: str,
    named: list[str],
    absent: list[str],
) -> None:
    _keyless(tmp_path, monkeypatch, 'security.enforcement = "warn"\n' + switches)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.__main__"):
        assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "staging"]) == 0
    warning = next(
        line
        for line in capsys.readouterr().err.splitlines()
        if line.startswith("warning: ") and "keyless" in line
    )
    audit = next(
        r.getMessage() for r in caplog.records if "AUDIT: starting keyless" in r.getMessage()
    )
    for text in (warning, audit):
        for name in named:
            assert name in text
        for name in absent:
            assert name not in text


@pytest.mark.parametrize(("switches", "named", "absent"), _SWITCH_CASES)
def test_strict_refusal_names_the_switch_that_was_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    switches: str,
    named: list[str],
    absent: list[str],
) -> None:
    # Default enforcement is `enforce`, and the second acknowledgement is missing: the refusal must
    # say which opt-out it found, then name the acknowledgement that is absent.
    _keyless(tmp_path, monkeypatch, switches)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 2
    err = capsys.readouterr().err
    assert "allow_unencrypted_phi_under_strict_enforcement is not set" in err
    for name in named:
        assert name in err
    for name in absent:
        assert name not in err
