# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The retention start gate reads the same in ``serve`` and in ``messagefoundry check``.

Vault BACKLOG #2280 limb 1: ``serve`` refused a start over an unbounded PHI retention tier, and
``check`` passed the same settings. The decision now lives in
:func:`messagefoundry.config.retention_classification.evaluate_retention_gate`, and both commands
call it.

The ``serve`` half of this module was written against the gate while it was still inline in
``_serve``, and passed there. It pins each line the gate writes, whole, and the order, so the
extraction is held to the text and the exit code it had before.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from messagefoundry.checks import CheckResult, run_checks
from messagefoundry.config import retention_classification
from messagefoundry.config.settings import ServiceSettings, load_settings
from tests._phi_gate_provisions import RETENTION_WINDOWS_ENV
from tests.test_cli import _SECURE_ALERTS, SAMPLES_CONFIG, _run_secure_serve

pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")

_EGRESS = "security.block_unlisted_outbound = true\n"
_ACK = "[security].allow_keeping_phi_indefinitely"
_BODY = "[security].delete_message_bodies_after_days"
_DEAD = "[retention].dead_letter_days"
_REFERENCE = "[retention].reference_snapshot_days"
_STATE_CAVEAT = (
    "a window on it deletes transform state by write time, so a Handler's correlation "
    "entry could vanish while still in use; until state has a non-write-time eviction key, "
    "the acknowledgement is the safe answer here, not a window"
)
_WARN_ONLY_TIERS = (
    "[retention].state_max_age_days (PL-2): set "
    "[security].allow_keeping_transform_state_indefinitely=true rather than a window -- "
    f"{_STATE_CAVEAT}; [retention].search_preset_days (PL-2): set a window, or set "
    "[security].allow_keeping_search_presets_indefinitely=true"
)

#: A phrase from each line the retention gate prints. A stderr line holding one is the gate's.
_GATE_PHRASES = (
    "defaulted ON",
    "data-retention window",
    "retains PHI message bodies indefinitely",
    "classified PHI tiers have no retention window",
    "retention classification has shrunk",
)


def _auto_bound_notice(settings: str, env: str) -> str:
    return (
        f"info: {settings} defaulted ON (30 days) for a PHI instance ({env!r}) — these PHI tiers "
        "are now bounded at rest (secure-by-default, ASVS 14.2.7). Set an explicit window to "
        f"override, or {_ACK}=true to retain indefinitely."
    )


def _gate_lines(err: str) -> list[str]:
    return [line for line in err.splitlines() if any(p in line for p in _GATE_PHRASES)]


def _audit_lines(out: str) -> list[str]:
    """The retention AUDIT records ``serve`` wrote, from the text ``AUDIT:`` on.

    Read from stdout: this gate runs after ``configure_logging``, so the record lands on the
    process log stream, and the formatter's prefix is not the gate's text."""
    return [
        line[line.index("AUDIT: starting a ") :]
        for line in out.splitlines()
        if "AUDIT: starting a " in line and "unbounded" in line
    ]


def _drop_warn_only_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Undo the module's ``bounded_warn_only_retention`` fixture, for a test about those tiers."""
    for name in RETENTION_WINDOWS_ENV:
        monkeypatch.delenv(name, raising=False)


# --- serve: each line, whole, and the exit code ---------------------------------------------------


def test_serve_auto_bound_notice_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, captured = _run_secure_serve(tmp_path, monkeypatch, _EGRESS + _SECURE_ALERTS)
    assert rc == 0
    assert _gate_lines(capsys.readouterr().err) == [
        _auto_bound_notice(f"{_BODY}, {_DEAD}, {_REFERENCE}", "prod")
    ]
    retention = captured["retention_settings"]
    assert retention.messages_days == 30  # type: ignore[attr-defined]
    assert retention.dead_letter_days == 30  # type: ignore[attr-defined]
    assert retention.reference_snapshot_days == 30  # type: ignore[attr-defined]


def test_serve_body_window_refusal_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        _EGRESS
        + "security.delete_message_bodies_after_days = 0\n[retention]\ndead_letter_days = 30\n"
        + _SECURE_ALERTS,
    )
    assert rc == 2
    # The notice for the one unset window comes first, then the refusal for the explicit 0.
    assert _gate_lines(capsys.readouterr().err) == [
        _auto_bound_notice(_REFERENCE, "prod"),
        f"error: a data-retention window is explicitly disabled for {_BODY} on a production PHI "
        "instance ('prod'); refusing to start — PHI message bodies would be retained indefinitely "
        "(unbounded PHI at rest, ASVS 14.2.4/14.2.7). Set the window(s) to a positive number of "
        f"days (e.g. 30); or, to deliberately retain forever, set {_ACK}=true (audited).",
    ]


def test_serve_body_window_warning_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\n'
        + _EGRESS
        + "security.delete_message_bodies_after_days = 0\n"
        + "[retention]\ndead_letter_days = 30\nreference_snapshot_days = 30\n"
        + _SECURE_ALERTS,
        env="staging",
    )
    assert rc == 0
    assert captured["retention_settings"].messages_days == 0  # type: ignore[attr-defined]
    assert _gate_lines(capsys.readouterr().err) == [
        f"warning: no data-retention window is configured for {_BODY} in a PHI-carrying "
        "environment ('staging') — PHI message bodies accumulate without bound. Set the "
        "window(s) to bound PHI at rest (ASVS 14.2.4)."
    ]


def test_serve_acknowledged_body_windows_are_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, captured = _run_secure_serve(
        tmp_path,
        monkeypatch,
        _EGRESS + "security.allow_keeping_phi_indefinitely = true\n" + _SECURE_ALERTS,
    )
    assert rc == 0
    # The acknowledgement turns the auto-bound off, so every unset window stays 0.
    assert captured["retention_settings"].messages_days == 0  # type: ignore[attr-defined]
    windows = f"{_BODY}, {_DEAD}, {_REFERENCE}"
    streams = capsys.readouterr()
    assert _gate_lines(streams.err) == [
        f"warning: {_ACK}=true — a production PHI instance ('prod') retains PHI message bodies "
        f"indefinitely ({windows} unset). Configure a window to bound PHI at rest."
    ]
    assert _audit_lines(streams.out) == [
        "AUDIT: starting a production PHI instance (environment 'prod') with unbounded data "
        f"retention ({_ACK}=true; {windows} = 0) — PHI message bodies are retained INDEFINITELY "
        "(retention opt-out override)."
    ]


def test_serve_warn_only_tier_refusal_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _drop_warn_only_windows(monkeypatch)
    rc, _ = _run_secure_serve(tmp_path, monkeypatch, _EGRESS + _SECURE_ALERTS)
    assert rc == 2
    assert _gate_lines(capsys.readouterr().err) == [
        _auto_bound_notice(f"{_BODY}, {_DEAD}, {_REFERENCE}", "prod"),
        "error: these classified PHI tiers have no retention window on a PHI instance ('prod') "
        "and would accumulate without bound; refusing to start, because each needs a window or "
        f"its own audited acknowledgement (ASVS 14.2.7): {_WARN_ONLY_TIERS}.",
    ]


def test_serve_warn_only_tier_warning_is_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _drop_warn_only_windows(monkeypatch)
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\n' + _EGRESS + _SECURE_ALERTS,
        env="staging",
    )
    assert rc == 0
    assert _gate_lines(capsys.readouterr().err) == [
        _auto_bound_notice(f"{_BODY}, {_DEAD}, {_REFERENCE}", "staging"),
        "warning: these classified PHI tiers have no retention window on a PHI instance "
        "('staging') and will accumulate without bound. They are deliberately NOT defaulted "
        "(owner ruling 2026-07-30); under enforcement=enforce this refuses to start: "
        f"{_WARN_ONLY_TIERS}.",
    ]


def test_serve_acknowledged_warn_only_tiers_are_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _drop_warn_only_windows(monkeypatch)
    rc, _ = _run_secure_serve(
        tmp_path,
        monkeypatch,
        _EGRESS
        + "security.allow_keeping_transform_state_indefinitely = true\n"
        + "security.allow_keeping_search_presets_indefinitely = true\n"
        + _SECURE_ALERTS,
    )
    assert rc == 0
    streams = capsys.readouterr()
    assert _gate_lines(streams.err) == [
        _auto_bound_notice(f"{_BODY}, {_DEAD}, {_REFERENCE}", "prod")
    ]
    assert _audit_lines(streams.out) == [
        "AUDIT: starting a production PHI instance (environment 'prod') with "
        f"[retention].{field} (PL-2) unbounded, permitted because [security].{switch}=true -- "
        "that tier accumulates without bound (retention acknowledgement, ASVS 14.2.7)."
        for field, switch in (
            ("state_max_age_days", "allow_keeping_transform_state_indefinitely"),
            ("search_preset_days", "allow_keeping_search_presets_indefinitely"),
        )
    ]


# --- check: the same verdict, in the same words ---------------------------------------------------

_WARN = 'security.enforcement = "warn"\n'
_ZERO_BODY = "security.delete_message_bodies_after_days = 0\n[retention]\ndead_letter_days = 30\n"
_TIER_ACKS = (
    "security.allow_keeping_transform_state_indefinitely = true\n"
    "security.allow_keeping_search_presets_indefinitely = true\n"
)

#: (id, settings before the alerts table, environment, whether the warn-only tiers keep the
#: module's windows). Each row reaches one arm of the gate.
_SCENARIOS = [
    ("auto-bound", "", "prod", True),
    ("body-zero-refused", _ZERO_BODY, "prod", True),
    ("body-zero-warned", _WARN + _ZERO_BODY, "staging", True),
    ("body-acknowledged", "security.allow_keeping_phi_indefinitely = true\n", "prod", True),
    ("tier-refused", "", "prod", False),
    ("tier-warned", _WARN, "staging", False),
    ("tier-acknowledged", _TIER_ACKS, "prod", False),
]


def _retention_leg(toml: Path) -> CheckResult:
    report = run_checks(SAMPLES_CONFIG, run_lint=False, service_config=toml)
    return next(r for r in report.results if r.name == "retention")


@pytest.mark.parametrize(
    ("body", "env", "windows"),
    [pytest.param(*row[1:], id=row[0]) for row in _SCENARIOS],
)
def test_check_reaches_serves_verdict_in_serves_words(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    body: str,
    env: str,
    windows: bool,
) -> None:
    if not windows:
        _drop_warn_only_windows(monkeypatch)
    # The environment is in the file as well as on serve's --env, because check has no --env.
    toml = f'ai.environment = "{env}"\n' + _EGRESS + body + _SECURE_ALERTS
    rc, _ = _run_secure_serve(tmp_path, monkeypatch, toml, env=env)
    streams = capsys.readouterr()
    served = _gate_lines(streams.err)
    audits = _audit_lines(streams.out)
    assert served or audits, "the row must reach an arm of the gate that writes something"

    leg = _retention_leg(tmp_path / "messagefoundry.toml")

    assert leg.required and not leg.skipped
    if rc == 2:
        refusal = served[-1]
        assert refusal.startswith("error: ")
        assert not leg.ok
        assert leg.detail == "serve would refuse to start (exit 2): " + refusal[len("error: ") :]
    else:
        assert rc == 0 and leg.ok
        assert leg.detail.startswith("serve would start and write: ")
        written = leg.detail.removeprefix("serve would start and write: ").split(" | ")
        # Each line serve wrote, and no other. The two streams interleave, so compare sorted.
        assert sorted(written) == sorted(served + audits)


def test_check_says_so_when_nothing_reads_as_unbounded(tmp_path: Path) -> None:
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(
        'ai.environment = "prod"\nsecurity.delete_message_bodies_after_days = 30\n'
        "[retention]\ndead_letter_days = 30\nreference_snapshot_days = 30\n",
        encoding="utf-8",
    )
    leg = _retention_leg(toml)
    assert leg.ok and not leg.skipped
    assert leg.detail == "serve would start: no classified PHI retention tier reads as unbounded"


def test_check_skips_where_serve_stops_before_the_gate(tmp_path: Path) -> None:
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("security.delete_message_bodies_after_days = 0\n", encoding="utf-8")
    leg = _retention_leg(toml)
    assert leg.skipped and leg.detail == "no active environment set"

    # A custom environment name with no declared tier: serve refuses on the tier, not on retention.
    toml.write_text(
        'ai.environment = "clinic-east"\nsecurity.delete_message_bodies_after_days = 0\n',
        encoding="utf-8",
    )
    leg = _retention_leg(toml)
    assert leg.skipped and "production tier is unresolved" in leg.detail


def test_a_refusal_fails_the_whole_gate(tmp_path: Path) -> None:
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text(
        'ai.environment = "prod"\nsecurity.delete_message_bodies_after_days = 0\n',
        encoding="utf-8",
    )
    report = run_checks(SAMPLES_CONFIG, run_lint=False, service_config=toml)
    assert not report.ok
    assert next(r for r in report.results if r.name == "retention").blocking


# --- the auto-bound notice reads the bound each window took (vault BACKLOG #2369) -----------------


def _dev_settings() -> ServiceSettings:
    return load_settings(default_file=False, cli={"ai": {"environment": "dev"}})


def test_the_notice_names_the_bound_the_window_took(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mutation: put the literal ``(30 days)`` back in the notice. The assertions below fail."""
    windows = tuple(
        dataclasses.replace(w, auto_bound_days=7 if w.field == "dead_letter_days" else 14)
        if w.auto_bound_days is not None
        else w
        for w in retention_classification.PHI_RETENTION_WINDOWS
    )
    monkeypatch.setattr(retention_classification, "PHI_RETENTION_WINDOWS", windows)
    settings = _dev_settings()

    outcome = retention_classification.evaluate_retention_gate(
        settings, enforcing=False, production=False, env_name="dev"
    )

    assert settings.retention.dead_letter_days == 7 and settings.retention.messages_days == 14
    notice = outcome.lines[0].text
    assert (
        f"{_BODY} (14 days), {_DEAD} (7 days), {_REFERENCE} (14 days) defaulted ON for a PHI "
        "instance ('dev')" in notice
    )
    assert "30 days" not in notice

    # One shared bound is named once, in the words the notice has always used.
    same = tuple(
        dataclasses.replace(w, auto_bound_days=14) if w.auto_bound_days is not None else w
        for w in windows
    )
    monkeypatch.setattr(retention_classification, "PHI_RETENTION_WINDOWS", same)
    again = retention_classification.evaluate_retention_gate(
        _dev_settings(), enforcing=False, production=False, env_name="dev"
    )
    assert f"{_BODY}, {_DEAD}, {_REFERENCE} defaulted ON (14 days) for" in again.lines[0].text
