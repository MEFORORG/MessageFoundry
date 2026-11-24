# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Callers that fall back on a settings load error report the section-name refusal instead
(vault BACKLOG #2600).

Before #2600 a ``MEFOR_<SECTION>`` variable loaded with a warning, so the ``dryrun`` preview and the
``check`` dry-run leg read the file's ``[pipeline].snapshot_on_send``, and ``alert add`` ran its
transport and recipient-override checks against the file's ``[alerts]``. Read as an ordinary load
error, the new refusal sent each of them to its fallback with no message. These tests pin that the
refusal is reported there, and that any other load error still falls back as before.

Synthetic values only."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from messagefoundry import checks
from messagefoundry.__main__ import _snapshot_on_send_setting, main
from messagefoundry.config import alerts_edit
from messagefoundry.config.settings import SectionNameEnvError, load_settings

_TOML_OFF = "[pipeline]\nsnapshot_on_send = false\n"

_ALERTS_EMAIL = textwrap.dedent("""\
    [alerts]
    email_smtp_host = "smtp.example.org"
    email_from = "alerts@example.org"
    email_to = ["oncall@example.org"]
    """)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """No ``MEFOR_*`` variable from the runner's own environment reaches the load."""
    import os

    for name in list(os.environ):
        if name.startswith("MEFOR_"):
            monkeypatch.delenv(name)
    return monkeypatch


def _off_toml(tmp_path: Path) -> Path:
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(_TOML_OFF, encoding="utf-8")
    return toml


# --- dryrun ----------------------------------------------------------------------------------------


def test_dryrun_snapshot_setting_reports_the_section_name_refusal(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    toml = _off_toml(tmp_path)
    clean_env.setenv("MEFOR_STORE", "x")
    with pytest.raises(SectionNameEnvError, match="MEFOR_STORE"):
        _snapshot_on_send_setting(str(toml))


def test_dryrun_snapshot_setting_still_falls_back_on_another_load_error(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    # An unknown key under a section was refused on main too, and fell back there; it still does.
    toml = _off_toml(tmp_path)
    clean_env.setenv("MEFOR_STORE_REQUIRE_ENCRYPTON", "x")
    assert _snapshot_on_send_setting(str(toml)) is True


def test_dryrun_cli_refuses_on_the_section_name_refusal(
    tmp_path: Path, clean_env: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "IB_TEST.py").write_text(
        "from messagefoundry import File, inbound, router\n"
        'inbound("IB_TEST", File(directory="in"), router="r")\n'
        '@router("r")\ndef route(msg):\n    return []\n',
        encoding="utf-8",
    )
    msg = tmp_path / "a.hl7"
    msg.write_text("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1\r", encoding="utf-8")
    toml = _off_toml(tmp_path)
    clean_env.setenv("MEFOR_STORE", "x")
    rc = main(
        [
            "dryrun",
            "--config",
            str(cfg),
            "--messages",
            str(msg),
            "--service-config",
            str(toml),
            "--json",
        ]
    )
    assert rc != 0
    assert "MEFOR_STORE" in json.loads(capsys.readouterr().out)["error"]


# --- check -----------------------------------------------------------------------------------------


def test_check_snapshot_setting_reports_the_section_name_refusal(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    toml = _off_toml(tmp_path)
    clean_env.setenv("MEFOR_STORE", "x")
    with pytest.raises(SectionNameEnvError, match="MEFOR_STORE"):
        checks._resolve_snapshot_on_send(
            tmp_path, service_config=toml, suppress_search=False, env=None
        )


def test_check_snapshot_setting_still_falls_back_on_another_load_error(
    tmp_path: Path, clean_env: pytest.MonkeyPatch
) -> None:
    toml = _off_toml(tmp_path)
    clean_env.setenv("MEFOR_STORE_REQUIRE_ENCRYPTON", "x")
    assert (
        checks._resolve_snapshot_on_send(
            tmp_path, service_config=toml, suppress_search=False, env=None
        )
        is True
    )


# --- alert add -------------------------------------------------------------------------------------


@pytest.fixture
def add_rule_calls(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Records whether ``alert add`` went on to write, so a skipped check shows as a call here."""
    calls: list[object] = []

    def fake_add_rule(*args: object, **kwargs: object) -> dict[str, object]:
        calls.append(args)
        return {"added": True}

    monkeypatch.setattr(alerts_edit, "add_rule", fake_add_rule)
    return calls


def _add(svc: Path, rule: dict[str, object], capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    rc = main(["alert", "add", "--service-config", str(svc), "--data", json.dumps(rule), "--json"])
    return rc, capsys.readouterr().out


def test_alert_add_recipient_check_does_not_skip_on_the_section_name_refusal(
    tmp_path: Path,
    clean_env: pytest.MonkeyPatch,
    add_rule_calls: list[object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(_ALERTS_EMAIL, encoding="utf-8")
    clean_env.setenv("MEFOR_STORE", "x")
    bad = "first" + "/" + "last@example.org"
    rc, out = _add(svc, {"event_type": "connection_stopped", "recipients": [bad]}, capsys)
    assert rc == 1
    assert "MEFOR_STORE" in json.loads(out)["error"]
    assert bad not in out
    assert add_rule_calls == []  # refused before the write, not read as "no settings yet"


def test_alert_add_transport_check_does_not_read_the_refusal_as_none_configured(
    tmp_path: Path,
    clean_env: pytest.MonkeyPatch,
    add_rule_calls: list[object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(_ALERTS_EMAIL, encoding="utf-8")
    clean_env.setenv("MEFOR_STORE", "x")
    rc, out = _add(svc, {"event_type": "connection_stopped", "transports": ["email"]}, capsys)
    assert rc == 1
    error = json.loads(out)["error"]
    assert "MEFOR_STORE" in error and "unconfigured transport" not in error
    assert add_rule_calls == []


def test_alert_add_recipient_check_still_runs_without_the_variable(
    tmp_path: Path,
    clean_env: pytest.MonkeyPatch,
    add_rule_calls: list[object],
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Control: the main path is unchanged, and the check refuses the bad override itself.
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(_ALERTS_EMAIL, encoding="utf-8")
    bad = "first" + "/" + "last@example.org"
    rc, out = _add(svc, {"event_type": "connection_stopped", "recipients": [bad]}, capsys)
    assert rc == 1
    assert "alert rule: a recipient" in out
    assert add_rule_calls == []


# --- the #2600 refusal itself ----------------------------------------------------------------------


def test_the_section_name_refusal_still_refuses_the_load() -> None:
    # Control: the #2600 behaviour holds, now as its own ValueError subclass.
    with pytest.raises(SectionNameEnvError, match="MEFOR_UPDATE_CHECK"):
        load_settings(environ={"MEFOR_UPDATE_CHECK": "false"}, default_file=False)


def test_an_unknown_key_refusal_is_not_the_section_name_class() -> None:
    with pytest.raises(ValueError, match="unrecognized environment variable") as caught:
        load_settings(environ={"MEFOR_STORE_REQUIRE_ENCRYPTON": "x"}, default_file=False)
    assert not isinstance(caught.value, SectionNameEnvError)
