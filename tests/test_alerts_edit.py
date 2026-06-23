# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`messagefoundry alert list|add|remove` — the comment-preserving [[alerts.rules]] editor the VS
Code "New Alert" command shells (ADR 0014). Validates-before-persist and rolls back on failure."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config import alerts_edit
from messagefoundry.config.settings import load_settings


def _svc(tmp_path: Path) -> Path:
    return tmp_path / "messagefoundry.toml"


def _add(svc: Path, rule: dict, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    rc = main(["alert", "add", "--service-config", str(svc), "--data", json.dumps(rule), "--json"])
    return rc, capsys.readouterr().out


def _list(svc: Path, capsys: pytest.CaptureFixture[str]) -> list[dict]:
    rc = main(["alert", "list", "--service-config", str(svc), "--json"])
    out = capsys.readouterr().out
    assert rc == 0
    return json.loads(out)


def test_add_creates_file_and_lists(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(tmp_path)
    rc, _ = _add(svc, {"event_type": "connection_stopped", "severity": "critical"}, capsys)
    assert rc == 0
    text = svc.read_text(encoding="utf-8")
    assert "[[alerts.rules]]" in text
    assert 'event_type = "connection_stopped"' in text and 'severity = "critical"' in text
    rules = _list(svc, capsys)
    assert len(rules) == 1
    assert rules[0]["event_type"] == "connection_stopped" and rules[0]["index"] == 0
    # and it round-trips through the real engine load path
    loaded = load_settings(config_path=svc).alerts.rules
    assert len(loaded) == 1 and loaded[0].severity.value == "critical"


def test_list_absent_file_is_empty(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _list(_svc(tmp_path), capsys) == []


def test_add_appends_in_order(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(tmp_path)
    assert _add(svc, {"event_type": "queue_buildup", "min_depth": 5000}, capsys)[0] == 0
    assert _add(svc, {"connection": "IB_*", "transports": []}, capsys)[0] == 0  # suppress rule
    rules = _list(svc, capsys)
    assert [r["index"] for r in rules] == [0, 1]
    assert rules[0]["event_type"] == "queue_buildup" and rules[0]["min_depth"] == 5000
    # transports = [] (suppress) is a real value and survives the round-trip, not dropped as "absent"
    assert rules[1]["transports"] == []
    assert load_settings(config_path=svc).alerts.rules[1].transports == []


def test_invalid_rule_not_persisted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(tmp_path)
    rc, out = _add(svc, {"event_type": "not_a_real_event"}, capsys)
    assert rc == 1
    assert "invalid alert rule" in out
    assert not svc.exists()  # rejected before any file was written


def test_remove_by_index(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(tmp_path)
    _add(svc, {"event_type": "connection_stopped"}, capsys)
    _add(svc, {"event_type": "queue_buildup", "min_depth": 100}, capsys)
    rc = main(["alert", "remove", "--service-config", str(svc), "--index", "0", "--json"])
    capsys.readouterr()
    assert rc == 0
    rules = _list(svc, capsys)
    assert len(rules) == 1 and rules[0]["event_type"] == "queue_buildup"


def test_remove_out_of_range_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(tmp_path)
    _add(svc, {"event_type": "connection_stopped"}, capsys)
    rc = main(["alert", "remove", "--service-config", str(svc), "--index", "9", "--json"])
    assert rc == 1 and "no alert rule at index 9" in capsys.readouterr().out


def test_remove_missing_file_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    svc = _svc(tmp_path)
    rc = main(["alert", "remove", "--service-config", str(svc), "--index", "0", "--json"])
    assert rc == 1 and "no settings file" in capsys.readouterr().out


def test_comments_and_siblings_survive_add(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    svc = _svc(tmp_path)
    svc.write_text(
        textwrap.dedent(
            """
            # hand-written — keep this header comment
            [alerts]
            webhook_url = "https://hooks.example/abc"  # important inline note
            realert_seconds = 120
            """
        ),
        encoding="utf-8",
    )
    assert _add(svc, {"event_type": "storage_threshold", "severity": "info"}, capsys)[0] == 0
    text = svc.read_text(encoding="utf-8")
    assert "# hand-written — keep this header comment" in text
    assert "# important inline note" in text
    assert 'webhook_url = "https://hooks.example/abc"' in text  # untouched sibling survives
    assert "[[alerts.rules]]" in text
    loaded = load_settings(config_path=svc).alerts
    assert loaded.webhook_url == "https://hooks.example/abc"
    assert loaded.realert_seconds == 120
    assert len(loaded.rules) == 1 and loaded.rules[0].event_type == "storage_threshold"


def test_failed_add_rolls_back_byte_stable(tmp_path: Path) -> None:
    # Directly exercise the rollback path: a validate callback that raises must restore the prior
    # file byte-for-byte (the connections editor guarantees the same for connections.toml).
    svc = _svc(tmp_path)
    alerts_edit.add_rule(svc, {"event_type": "connection_stopped"}, validate=lambda _p: None)
    original = svc.read_text(encoding="utf-8")

    def boom(_p: Path) -> None:
        raise alerts_edit.AlertRuleError("simulated load failure")

    with pytest.raises(alerts_edit.AlertRuleError):
        alerts_edit.add_rule(svc, {"event_type": "queue_buildup"}, validate=boom)
    assert svc.read_text(encoding="utf-8") == original  # rolled back, untouched


def test_add_rejects_index_field(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # A rule round-tripped from `list` carries the read-only `index`; AlertRule forbids extras, so
    # `add` must reject it rather than silently writing a bogus key.
    svc = _svc(tmp_path)
    rc, out = _add(svc, {"event_type": "connection_stopped", "index": 0}, capsys)
    assert rc == 1 and "invalid alert rule" in out
    assert not svc.exists()
