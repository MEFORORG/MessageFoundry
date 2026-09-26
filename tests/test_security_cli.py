# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``security show|set`` CLI (ADR 0118): the comment-preserving backend the VS Code ``[security]``
editor shells. Mirrors the ``alert`` CLI — validate-before-persist + roll-back, offline, applies on the
next engine restart."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from messagefoundry import __main__ as cli
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
    #  sat beside this and is retired (BACKLOG #1279); the model no longer
    # carries the field, so  cannot report it and must not invent it.
    assert "handles_real_patient_data" not in data["values"]
    assert data["values"]["production_instance"] is None  # unset → derived from environment


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


def test_show_declares_that_it_cannot_see_connection_scoped_deviations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`security show` reads a SETTINGS file and never loads the connection graph, so it cannot see the
    ADR 0153 per-connection ``cleartext_accepted`` declarations.

    The marker is the whole mitigation: without it this subcommand reports a settings-only list that
    READS as the complete posture, which under "one posture, loosen only" is exactly how a deviation
    stops being visible. Nothing else pins it, so it could otherwise be dropped silently."""
    toml = tmp_path / "mf.toml"
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is False
    assert "cleartext_accepted" in data["loosenings_scope"]
    assert "messagefoundry check" in data["loosenings_scope"]


def test_show_declares_that_it_cannot_see_a_cli_bind_override(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The fourth gap, for the same reason as the three above (BACKLOG #1852).

    ``load_settings`` folds an off-box ``serve --host`` into the ``[security]`` view, so a running
    engine's ``GET /security/posture`` reports ``local_access_only = false`` while this command, which
    reads the AUTHORED file, still shows ``true``. Both are right for what they describe. An unmarked
    disagreement between two operator surfaces on one host reads as a defect in one of them, which is
    what sends an auditor hunting."""
    data = _show(tmp_path / "mf.toml", capsys)
    assert "--host" in data["loosenings_scope"]


def test_show_reports_store_and_auth_deviations_from_the_whole_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The registry reaches into [store]/[auth], so this subcommand must resolve the WHOLE file rather
    than [security] alone — otherwise it under-reports the posture it exists to display."""
    toml = tmp_path / "mf.toml"
    toml.write_text("[store]\naad_bind = false\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert "aad_bind" in [entry["switch"] for entry in data["loosenings"]]


def test_show_declares_a_partial_report_when_the_file_will_not_load(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A file invalid OUTSIDE [security] must not break `security show` — but the degraded report has to
    SAY it is degraded, not quietly fall back to shipped defaults and look complete."""
    toml = tmp_path / "mf.toml"
    # Valid TOML, invalid SETTINGS, and invalid entirely outside [security]: an explicit
    # ad_session_recheck_seconds with no ad_enabled is the ADR 0079 cross-field refusal.
    toml.write_text("[auth]\nad_session_recheck_seconds = 300\n", encoding="utf-8")
    data = _show(toml, capsys)
    assert data["loosenings_partial"] is True
    # ...and it still prints a usable [security] view rather than failing the subcommand.
    assert data["values"]["require_mfa"] is True


# --- operator JSON that nests past the decoder (BACKLOG #1855) --------------------------------
#
# `json.loads` guards its own decode depth and raises `RecursionError`, which is a `RuntimeError` --
# NOT a `JSONDecodeError` and not a `ValueError` -- so the `except json.JSONDecodeError` arm beside
# every operator-JSON decode in `__main__.py` structurally cannot reach it. The reasoning, and why
# the catch is scoped to the `json.loads` call rather than to the wide `try` around it, is stated
# once on `_load_operator_json`; this module carries the anchor test for the behaviour.


def _raise_recursion(*_args: object, **_kwargs: object) -> object:
    raise RecursionError("simulated deep nesting")


def test_cli_set_reports_security_json_nested_past_the_decoder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deeply nested `--data` escaped `security set` uncaught before this arm existed.

    Measured on a real subprocess at engine 40ee1a9cd: exit 1 with **stdout EMPTY**, the whole report
    redacted by the last-resort excepthook (BACKLOG #1674) to one CRITICAL line naming only the
    exception type. That breaks `_emit_error`'s contract that under `--json` the error object IS the
    command's machine-readable output, and it never said which input was at fault.

    THE TRIGGER IS MANUFACTURED, NOT REAL NESTING, AND MUST STAY THAT WAY (BACKLOG #1222): the depth
    where `json`'s C accelerator gives out measures the runner, not this code. Do not "improve" it
    back to real nesting. The argument, the measurements and the type facts
    (`RecursionError` is a `RuntimeError`, not a `ValueError`) are pinned once, in
    `tests/test_sandbox_codec.py::test_recursion_error_is_not_a_value_error`.

    RED when: `_load_operator_json`'s `except RecursionError` arm is dropped, or `_security`'s
    `except _OperatorJsonError` arm is dropped -- the decode escapes to `main`'s dispatch floor
    (BACKLOG #1863), whose JSON error names only the exception type, not the input at fault."""
    monkeypatch.setattr(cli.json, "loads", _raise_recursion)
    rc = main(
        ["security", "set", "--service-config", str(tmp_path / "mf.toml"), "--data", "[]", "--json"]
    )
    out = capsys.readouterr().out
    monkeypatch.undo()  # restore json.loads before parsing the captured payload with it

    assert rc == 1
    error = json.loads(out)["error"]
    assert "is nested too deeply to parse" in error
    # Named per site, so the report says WHICH input was at fault -- the half the CRITICAL line lost.
    assert error.startswith("security update JSON")
    assert not (tmp_path / "mf.toml").exists()  # refused before any write


def test_cli_set_reports_a_malformed_edit_as_json_on_stdout_in_a_real_subprocess(
    tmp_path: Path,
) -> None:
    """`_emit_error`'s `--json` contract, end-to-end in a real process: the error object is the
    command's machine-readable output, on STDOUT, with exit 1 -- so a consumer piping to `jq` reads
    the reason there instead of getting a parse failure on an empty stream.

    A real subprocess measures the real process streams rather than pytest's capture. Before BACKLOG
    #1863 that was the only place an escaping exception's empty stdout was visible; `main` now
    catches the escape at the dispatch and prints a JSON error, so this test pins the ordinary path.

    Driven with ORDINARY malformed JSON, not deep nesting: a subprocess cannot be monkeypatched, and
    real nesting measures the runner rather than the code (BACKLOG #1222 -- see the manufactured
    trigger above). The contract under test does not need a `RecursionError` to demonstrate.

    RED when: `security set` stops routing a decode failure through `_emit_error` -- the payload then
    leaves stdout empty and the reason lands on stderr, if anywhere."""
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "messagefoundry",
            "security",
            "set",
            "--service-config",
            str(tmp_path / "mf.toml"),
            "--data",
            "{not json",
            "--json",
        ],
        cwd=tmp_path,  # away from the repo, so no stray ./messagefoundry.toml is picked up
        capture_output=True,
        text=True,
        # Well under the pytest-timeout watchdog, so a hang is reported HERE, by a readable
        # `TimeoutExpired` naming the CLI, rather than by the watchdog's thread dump. `addopts` sets
        # `--timeout=60` and CI overrides it per leg (60s ubuntu, 120s Windows), so 60 here would tie
        # the ubuntu watchdog and lose that race -- the watchdog's timer starts at test setup.
        timeout=20,
    )
    assert proc.returncode == 1, f"rc={proc.returncode}\n{proc.stderr}"
    assert proc.stdout.strip(), f"stdout was empty; stderr={proc.stderr}"
    assert json.loads(proc.stdout)["error"].startswith("invalid security update JSON:")
    assert "Traceback" not in proc.stderr, "a raw traceback reached the operator"
