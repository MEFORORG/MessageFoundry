# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``security show|set`` CLI (ADR 0118): the comment-preserving backend the VS Code ``[security]``
editor shells. Mirrors the ``alert`` CLI — validate-before-persist + roll-back, offline, applies on the
next engine restart."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main


def _show(path: Path, capsys: pytest.CaptureFixture[str]) -> dict:
    assert main(["security", "show", "--service-config", str(path), "--json"]) == 0
    return json.loads(capsys.readouterr().out)  # type: ignore[no-any-return]


def _set(path: Path, updates: dict, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict]:
    rc = main(
        ["security", "set", "--service-config", str(path), "--data", json.dumps(updates), "--json"]
    )
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else {})


def test_show_defaults_when_absent(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    toml = tmp_path / "mf.toml"
    data = _show(toml, capsys)
    assert data["set"] == [] and data["loosenings"] == []
    assert data["values"]["require_mfa"] is True and data["values"]["local_access_only"] is True
    assert data["defaults"]["block_unlisted_outbound"] is True
    assert data["values"]["handles_real_patient_data"] is None  # unset → derived from environment


def test_set_writes_security_and_preserves_other_sections(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    toml.write_text("# my config\n[api]\nport = 9000\n", encoding="utf-8")
    rc, res = _set(toml, {"require_mfa": False}, capsys)
    assert rc == 0 and res["keys"] == ["require_mfa"]
    # the loosening is reported so the editor can warn in place
    assert any(lo["switch"] == "require_mfa" for lo in res["loosenings"])
    text = toml.read_text(encoding="utf-8")
    assert "# my config" in text and "port = 9000" in text  # other sections byte-stable
    assert "[security]" in text and "require_mfa = false" in text
    # show now reflects it
    data = _show(toml, capsys)
    assert data["set"] == ["require_mfa"] and data["values"]["require_mfa"] is False


def test_null_value_resets_to_default_and_drops_emptied_table(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    _set(toml, {"require_mfa": False}, capsys)
    rc, _ = _set(toml, {"require_mfa": None}, capsys)  # null → reset to secure default
    assert rc == 0
    text = toml.read_text(encoding="utf-8")
    assert "[security]" not in text and "require_mfa" not in text  # emptied table dropped


def test_ac3_contradiction_is_rejected_and_rolled_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    toml.write_text("[api]\nport = 9000\n", encoding="utf-8")
    rc, _ = _set(toml, {"local_access_only": True, "listen_address": "0.0.0.0"}, capsys)
    assert rc == 1  # the contradiction (AC-3) fails validation on write
    assert "[security]" not in toml.read_text(encoding="utf-8")  # rolled back, original intact
    assert "port = 9000" in toml.read_text(encoding="utf-8")


def test_set_rejects_a_file_that_still_has_a_relocated_legacy_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A file still carrying a moved key ([auth].enabled) fails validation on write → rolled back.
    toml = tmp_path / "mf.toml"
    toml.write_text("[auth]\nenabled = false\n", encoding="utf-8")
    rc, res = _set(toml, {"require_mfa": False}, capsys)
    assert rc == 1


def test_set_rejects_bad_value_type(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    toml = tmp_path / "mf.toml"
    rc, _ = _set(toml, {"max_session_hours": "not-an-int"}, capsys)
    assert rc == 1
    assert not toml.exists()  # never created a broken file


def test_set_round_trips_a_string_list(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # allowed_client_networks (ADR 0151) is the first LIST-valued [security] switch: tomlkit must emit a
    # native TOML array, and `show` must read it back unchanged.
    toml = tmp_path / "mf.toml"
    rc, _ = _set(toml, {"allowed_client_networks": ["10.20.0.0/16", "fd00::/8"]}, capsys)
    assert rc == 0
    assert 'allowed_client_networks = ["10.20.0.0/16", "fd00::/8"]' in toml.read_text(
        encoding="utf-8"
    )
    assert _show(toml, capsys)["values"]["allowed_client_networks"] == ["10.20.0.0/16", "fd00::/8"]


def test_set_rejects_a_malformed_network_and_rolls_back(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    toml = tmp_path / "mf.toml"
    assert _set(toml, {"allowed_client_networks": ["10.20.0.0/16"]}, capsys)[0] == 0
    rc, _ = _set(toml, {"allowed_client_networks": ["not-a-cidr"]}, capsys)
    assert rc == 1
    # The good value survives — a rejected edit never lands.
    assert 'allowed_client_networks = ["10.20.0.0/16"]' in toml.read_text(encoding="utf-8")


def test_set_rejects_the_allowlist_beside_a_broad_trusted_proxies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The cross-section refusal fires through the CLI's validate-before-persist path too: a range of
    # trusted spoofers would silently nullify the allow-list being set.
    toml = tmp_path / "mf.toml"
    toml.write_text('[api]\ntrusted_proxies = ["10.0.0.0/8"]\n', encoding="utf-8")
    rc, _ = _set(toml, {"allowed_client_networks": ["10.20.0.0/16"]}, capsys)
    assert rc == 1
    assert "[security]" not in toml.read_text(encoding="utf-8")  # rolled back
