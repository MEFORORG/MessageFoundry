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
from messagefoundry.config.alerts_edit import _RULE_FIELDS
from messagefoundry.config.settings import AlertRule, load_settings


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


# --- #240: reader/writer schema-drift guard + fail-loud unknown keys ----------


def test_rule_fields_parity_with_model() -> None:
    # The CI guard of record (#240, mirroring PR #1076 for connections): the write whitelist must equal
    # the read model's fields, so a field added to AlertRule but not _RULE_FIELDS (which would be
    # SILENTLY DROPPED from every GUI/CLI-authored rule) fails THIS test instead of quietly losing data.
    assert set(_RULE_FIELDS) == set(AlertRule.model_fields)


def test_rule_fields_parity_guard_is_falsifiable() -> None:
    # Demonstrate the guard actually bites: drop a field from the tuple and set-equality with the model
    # breaks — the exact drift (a model field absent from the writer whitelist) the guard is there to
    # catch. mute/content_label/escalate/schedule were the real drift this lane closed.
    drifted = set(_RULE_FIELDS) - {"schedule"}
    assert drifted != set(AlertRule.model_fields)
    for field in ("mute", "content_label", "escalate", "schedule"):
        assert field in set(_RULE_FIELDS)  # the four keys #81/#143 added to the model, once dropped


def test_add_rejects_unknown_key_direct(tmp_path: Path) -> None:
    # A direct add_rule (no CLI model_validate pre-check) must FAIL LOUD on an unknown posted key
    # rather than silently dropping it in _build_table — the #234 data-loss idiom this closes.
    svc = _svc(tmp_path)
    with pytest.raises(alerts_edit.AlertRuleError, match="unknown key.*bogus_field"):
        alerts_edit.add_rule(
            svc, {"event_type": "connection_stopped", "bogus_field": "x"}, validate=lambda _p: None
        )
    assert not svc.exists()  # rejected before any file was written


def test_cli_add_rejects_unknown_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # Via the CLI, AlertRule's extra="forbid" catches it first ("invalid alert rule"); either way the
    # unknown key is refused, never written.
    svc = _svc(tmp_path)
    rc, out = _add(svc, {"event_type": "connection_stopped", "bogus_field": "x"}, capsys)
    assert rc == 1
    assert not svc.exists()


def test_add_writes_and_round_trips_newly_whitelisted_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # #240 root fix: mute/content_label/escalate/schedule were in AlertRule but NOT _RULE_FIELDS, so
    # the writer silently dropped them. Now they must survive a GUI save round-trip through the real
    # engine load path (proving they are no longer stripped before the validate callback runs).
    svc = _svc(tmp_path)
    # The escalation tier below routes to `email`, and `alert add` now cross-checks a rule's routing
    # against the transports this instance actually configures (a rule naming an unconfigured transport
    # refuses the engine at startup, so writing one from the editor is refused here rather than at the
    # next boot). Seed a real email transport — all THREE of host/from/to — so this test keeps testing
    # what it is for: that mute/content_label/escalate/schedule survive the save round-trip.
    svc.write_text(
        textwrap.dedent("""\
            [alerts]
            email_smtp_host = "smtp.example.org"
            email_from = "alerts@example.org"
            email_to = ["oncall@example.org"]
            """),
        encoding="utf-8",
    )
    rule = {
        "event_type": "content_match",
        "mute": True,
        "content_label": "sepsis",
        "escalate": [{"after_count": 3, "severity": "critical", "transports": ["email"]}],
        "schedule": {
            "windows": [
                {"days": [0, 1, 2, 3, 4], "start": "08:00:00", "end": "17:00:00", "timezone": "UTC"}
            ],
            "invert": False,
        },
    }
    rc, _ = _add(svc, rule, capsys)
    assert rc == 0
    loaded = load_settings(config_path=svc).alerts.rules
    assert len(loaded) == 1
    r = loaded[0]
    assert r.mute is True
    assert r.content_label == "sepsis"
    assert len(r.escalate) == 1 and r.escalate[0].after_count == 3
    assert r.schedule is not None and len(r.schedule.windows) == 1


def test_add_refuses_a_rule_routing_to_an_unconfigured_transport(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The editor must not write a rule that only fails at the NEXT start.

    `notifier_from_settings` refuses a rule routing to an unconfigured transport, but that fires at
    startup. Before this gate the VS Code "New Alert" command (and `alert add`) happily persisted such
    a rule, so the operator learned about it when the engine would not come back up. A half-configured
    [alerts] block is the likely shape: `email` needs host + from + TO, and omitting `email_to` leaves
    it looking configured while contributing no transport.
    """
    svc = _svc(tmp_path)
    svc.write_text(
        textwrap.dedent("""\
            [alerts]
            email_smtp_host = "smtp.example.org"
            email_from = "alerts@example.org"
            """),
        encoding="utf-8",
    )
    rc, out = _add(svc, {"event_type": "connection_stopped", "transports": ["email"]}, capsys)
    assert rc == 1
    assert "unconfigured transport(s) ['email']" in out
    # Rolled back: the refused rule was never persisted.
    assert load_settings(config_path=svc).alerts.rules == []


def test_add_allows_a_rule_that_names_no_transport(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate is scoped to rules that ROUTE somewhere.

    A rule naming no transport inherits whatever is configured and is valid on an instance with none,
    so the ordinary "write the rules first, wire the transport later" flow keeps working — and the
    from-scratch create path (no settings file yet) must not need one either.
    """
    svc = _svc(tmp_path)
    rc, _ = _add(svc, {"event_type": "connection_stopped", "severity": "critical"}, capsys)
    assert rc == 0
    assert len(load_settings(config_path=svc).alerts.rules) == 1
