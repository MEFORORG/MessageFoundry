# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``messagefoundry ai-policy`` -- the offline projection of the effective AI-assistance policy.

WHY THE PROJECTION EXISTS, because it decides what these tests have to prove. The IDE resolves the
policy before every assistant request: engine first, then the last cached authoritative answer, then
this subcommand, then a fail-closed default (docs/AI.md, ADR 0035 SEC-022). ``ide/src/cli.ts``'s
``runJson`` execs it, reads STDOUT, and turns a ``{"error": ...}`` body into a thrown ``Error``. So
stdout is the whole contract, and the guards here are on the ways it could quietly stop holding:

1. it must actually READ the file it is pointed at -- a config that turns assistance off and one
   that leaves it on must not project the same thing
   (``test_two_configs_do_not_project_the_same_payload``, the positive control for every other case
   here);
2. a config that will not load must be an ERROR the caller can parse, not an empty read or a
   traceback (``test_missing_config...``, ``test_a_directory_at_service_config...``);
3. that error must not carry the values the failing config was given, because the env-supplied
   secrets are among them (``test_a_config_error_never_echoes_an_env_supplied_secret``).

Point 3 is the one that was broken. ``str(ValidationError)`` carries ``input_value=`` for every
failing field, and an ``after``-mode section validator's input is the whole section mapping, so a
``[store]`` missing ``server`` rendered ``MEFOR_STORE_PASSWORD`` onto stdout. BACKLOG #1523 fixed the
identical arm in ``_cluster_vip``, which was written to MIRROR this function and had inherited the
defect from it; this file is the original's guard. ``tests/test_cli_cluster_vip.py`` is the sibling
and the two are deliberately parallel.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import load_settings


def _write(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    return path


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, object]]:
    """Run the subcommand and parse its stdout, which is the IDE bridge's whole contract with it."""
    code = main(["ai-policy", *argv])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert isinstance(parsed, dict)
    return code, parsed


def test_two_configs_do_not_project_the_same_payload(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """THE CONTROL. Two [ai] blocks, through the same code path, must not project the same answer.

    A projection that ignored its ``--service-config`` -- read a stale default, or returned model
    defaults -- would satisfy every other assertion here and still tell the IDE nothing about the
    operator's actual config. This is the only test that would catch that, so it asserts the
    difference itself rather than inferring it from the two halves.
    """
    off = _write(tmp_path / "off.toml", '[ai]\nmode = "off"\nenvironment = "dev"\n')
    byo = _write(tmp_path / "byo.toml", '[ai]\nmode = "byo"\nenvironment = "dev"\n')

    off_code, off_payload = _run(capsys, "--service-config", str(off), "--json")
    byo_code, byo_payload = _run(capsys, "--service-config", str(byo), "--json")

    assert (off_code, byo_code) == (0, 0)
    assert off_payload != byo_payload
    assert off_payload["mode"] == "off"
    assert byo_payload["mode"] == "byo"
    # `assist_permitted` is always null offline -- RBAC is not evaluable without the engine.
    assert off_payload["assist_permitted"] is None
    assert byo_payload["assist_permitted"] is None


def test_missing_config_is_an_error_line_and_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Stdout stays JSON on the failure path, so `parseJsonResult` sees a `{"error": ...}` body it can
    # throw rather than an empty string it would report as "produced no output".
    code, payload = _run(capsys, "--service-config", str(tmp_path / "absent.toml"), "--json")
    assert code == 2
    assert "absent.toml" in str(payload["error"])
    assert "mode" not in payload


def test_a_directory_at_service_config_is_an_error_line_not_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An easy typo: the config DIRECTORY instead of the file inside it.

    ``Path.exists()`` is True and the open raises -- ``IsADirectoryError`` on POSIX,
    ``PermissionError`` on Windows (measured 2026-09-20: "[Errno 13] Permission denied"). Both are
    ``OSError`` and neither is ``FileNotFoundError``, so before ``OSError`` joined the catch the
    exception escaped: exit 1, stdout empty, and the IDE bridge reporting "produced no output"
    instead of the reason. Asserted as BEHAVIOUR rather than exception class, because the class
    differs by platform and this test runs on both legs.
    """
    code, payload = _run(capsys, "--service-config", str(tmp_path), "--json")
    assert code == 2
    assert "error" in payload


#: The value this test plants in the environment and then looks for. Not a credential, and shaped so
#: it cannot be read as one: low entropy and dictionary words, so it does not trip the gitleaks hook
#: and needs no entry in ``.gitleaks.toml``'s allowlist -- an allowlist entry is a scanner blind spot
#: bought for nothing when the fixture can simply not look like a key.
#:
#: SHORT, which is load-bearing, and the same value ``tests/test_cli_cluster_vip.py`` plants for the
#: same reason. Pydantic abbreviates a long ``input_value`` repr FROM THE MIDDLE, so a 32-character
#: value comes back as ``{'backend': 'postgres', '...-A-REAL-ONE-x'}`` and an ``in`` test over the
#: whole string reads False while most of the value is plainly on screen. A real 32-character
#: password leaks its tail exactly that way. Measured at ``19c98e023``, this subcommand rendered
#: ``{'backend': 'postgres', '...word': 'not-a-real-one'}`` -- the KEY abbreviated away and the value
#: entire. The control below is what stops a future repr change from turning this test green for the
#: wrong reason.
_CANARY = "not-a-real-one"


@pytest.mark.parametrize("flags", [("--json",), ()], ids=["machine", "human"])
def test_a_config_error_never_echoes_an_env_supplied_secret(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    flags: tuple[str, ...],
) -> None:
    """A load failure reports the FIELD, never the value the field was given.

    The failing config is a ``[store]`` with ``backend = "postgres"`` and none of the three keys that
    backend requires. ``MEFOR_STORE_PASSWORD`` is set, as it is on any real Postgres node, so the
    store password is in the input mapping ``_require_server_db_fields`` rejects. Note the config
    that fails is NOT the ``[ai]`` block this subcommand projects: ``load_settings`` validates the
    whole file, so any section's failure renders through this arm.

    THE CONTROL IS THE RAW RENDERING, asserted first. A test that only looked for the absence of a
    string would pass just as well against an empty error, a renamed variable, or a value pydantic
    never had -- so it first proves the planted secret IS in ``str(exc)`` on this exact config, which
    is what makes its absence below attributable to the fix.

    Both output spellings are checked because the error path does not branch on ``--json``: the
    payload formatter does, and the failure line is printed before it.
    """
    monkeypatch.setenv("MEFOR_STORE_PASSWORD", _CANARY)
    cfg = _write(tmp_path / "messagefoundry.toml", '[store]\nbackend = "postgres"\n')

    with pytest.raises(ValueError) as caught:  # ValidationError subclasses ValueError
        load_settings(config_path=str(cfg))
    assert _CANARY in str(caught.value), (
        "CONTROL FAILED: str(ValidationError) does not carry the planted secret on this config, so "
        "the absence asserted below would prove nothing -- re-aim this guard at a config whose "
        "rejected input still holds [store].password"
    )

    code = main(["ai-policy", "--service-config", str(cfg), *flags])
    out = capsys.readouterr().out

    assert code == 2
    assert _CANARY not in out, (
        "`ai-policy` echoed an env-supplied secret in its config error. Render the failure with "
        "settings_error_detail(); str(ValidationError) carries input_value= for every failing field."
    )
    error = str(json.loads(out)["error"])
    # Useful, not just quiet: an error that named no field would also pass the assertion above.
    assert "store" in error and "server, database, username" in error


def test_without_json_the_output_is_indented_and_still_parses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # --json is the compact spelling the IDE asks for; the bare form is the one an operator reads.
    # Both are JSON, which is what lets the error handling be the same on both.
    cfg = _write(tmp_path / "messagefoundry.toml", '[ai]\nmode = "byo"\nenvironment = "dev"\n')
    assert main(["ai-policy", "--service-config", str(cfg)]) == 0
    human = capsys.readouterr().out
    assert "\n  " in human
    assert json.loads(human)["mode"] == "byo"
