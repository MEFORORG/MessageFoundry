# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The per-tier retention acknowledgement gate (BACKLOG #1967, ASVS 14.2.7).

Owner ruling R4 (b), 2026-09-24: each warn-only retention tier needs either a window or its own
audited acknowledgement, and a PHI instance with neither refuses to start. Before this, ``serve``
printed a warning for such a tier and started anyway.

Each warn-only tier that can read as unbounded is exercised three ways: refused with neither, started
under its acknowledgement with an ``AUDIT:`` line naming it, and started quietly with a window set.
Every instance carries patient data (BACKLOG #1279), so there is no non-PHI arm to test.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.retention_classification import (
    PHI_RETENTION_WINDOWS,
    warn_only_windows,
)
from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    SecretRotationSettings,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)

SAMPLES_CONFIG = Path(__file__).resolve().parent.parent / "samples" / "config"


@dataclass(frozen=True)
class _Tier:
    """One warn-only tier: the TOML that makes it unbounded, and the TOML that bounds it."""

    setting: str
    ack: str
    unbounded: str
    bounded: str


def _tiers(tmp: Path) -> list[_Tier]:
    logs = (tmp / "logs").as_posix()
    backups = (tmp / "backups").as_posix()
    return [
        _Tier(
            "[retention].state_max_age_days",
            "allow_keeping_transform_state_indefinitely",
            "",
            "retention.state_max_age_days = 30\n",
        ),
        _Tier(
            "[retention].search_preset_days",
            "allow_keeping_search_presets_indefinitely",
            "",
            "retention.search_preset_days = 30\n",
        ),
        _Tier(
            "[retention].app_log_days",
            "allow_keeping_app_logs_indefinitely",
            f'logging.log_dir = "{logs}"\n',
            f'logging.log_dir = "{logs}"\nretention.app_log_days = 30\n',
        ),
        _Tier(
            "[backup].retention_keep",
            "allow_keeping_backup_archives_indefinitely",
            f'backup.destination = "{backups}"\nbackup.retention_keep = 0\n',
            f'backup.destination = "{backups}"\n',
        ),
    ]


_TIER_IDS = ["state", "search_presets", "app_logs", "backup_archives"]


def _config(tmp: Path, *, leave: set[str], tier_toml: str, extra: str = "") -> None:
    """A loopback config that reaches a clean exit 0 with nothing on stderr (the fixture
    tests/test_storage_floor.py uses), with every warn-only tier bounded EXCEPT those in ``leave``,
    whose TOML is ``tier_toml``. The disk floor is off so the host's free space never decides the
    result."""
    others = "".join(t.bounded for t in _tiers(tmp) if t.setting not in leave)
    (tmp / "logs").mkdir(exist_ok=True)
    (tmp / "backups").mkdir(exist_ok=True)
    (tmp / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n"
        'alerts.email_smtp_host = "smtp.example.org"\n'
        'alerts.email_from = "sec@example.org"\n'
        'alerts.email_to = ["ops@example.org"]\n'
        "security.delete_message_bodies_after_days = 30\n"
        "retention.dead_letter_days = 30\n"
        "retention.reference_snapshot_days = 30\n"
        "retention.min_free_disk_mb = 0\n"
        "security.local_access_only = true\n" + extra + others + tier_toml,
        encoding="utf-8",
    )


@pytest.fixture
def serve_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return tmp_path


def _serve() -> int:
    return main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])


def _tier(tmp: Path, index: int) -> _Tier:
    return _tiers(tmp)[index]


# --- the classification ---------------------------------------------------------------------------


def test_every_warn_only_tier_that_can_be_unbounded_has_its_own_switch() -> None:
    """Every warn-only tier whose 0 means unbounded names a switch, each switch is a distinct
    ``[security]`` bool, and no tier that can never read as unbounded carries a dead switch.

    Mutation: drop ``acknowledged_by`` from any one tier -- the first assertion reds, and ``serve``
    would refuse that tier with no acknowledgement to offer."""
    switches: list[str] = []
    for window in warn_only_windows():
        if window.zero_is_unbounded:
            assert window.acknowledged_by, f"{window.setting} has no acknowledgement switch"
            field = SecuritySettings.model_fields.get(window.acknowledged_by)
            assert field is not None and field.default is False, window.acknowledged_by
            switches.append(window.acknowledged_by)
        else:
            assert window.acknowledged_by is None, f"{window.setting} can never be unbounded"
    assert len(switches) == len(set(switches)) == 4
    auto = [w for w in PHI_RETENTION_WINDOWS if w.auto_bound_days is not None]
    assert all(w.acknowledged_by is None for w in auto), "the body tiers have their own opt-out"


def test_the_ids_line_up_with_the_tiers(tmp_path: Path) -> None:
    """The parametrised tests index into :func:`_tiers`; this pins that the table names exactly
    the tiers the classification gives a switch, so a new tier cannot go untested."""
    expected = {w.setting: w.acknowledged_by for w in warn_only_windows() if w.acknowledged_by}
    assert {t.setting: t.ack for t in _tiers(tmp_path)} == expected
    assert len(_TIER_IDS) == len(expected)


def test_each_switch_is_a_named_loosening() -> None:
    def names(sec: SecuritySettings) -> list[str]:
        return [
            n
            for n, _ in security_loosenings(
                sec,
                StoreSettings(),
                AuthSettings(),
                AlertsSettings(),
                SecretRotationSettings(),
                cleartext_hops=(),
                expiry_relaxed_hops=(),
                hostname_unchecked_hops=(),
                query_credential_hops=(),
                unverified_db_hops=(),
                attested_hops=(),
                revocation_attested_hops=(),
                api=ApiSettings(),
                approvals=ApprovalsSettings(),
                cert_monitor=CertMonitorSettings(),
                backup=BackupSettings(),
                store_privilege=None,
                audit_chain_unkeyed=None,
                remote_debug=None,
                startup=None,
            )
        ]

    assert names(SecuritySettings()) == []
    for window in warn_only_windows():
        if window.acknowledged_by:
            flipped = SecuritySettings.model_validate({window.acknowledged_by: True})
            assert names(flipped) == [window.acknowledged_by]


# --- the serve gate, per tier ---------------------------------------------------------------------


@pytest.mark.parametrize("index", range(4), ids=_TIER_IDS)
def test_a_tier_with_neither_a_window_nor_its_acknowledgement_refuses(
    serve_env: Path, capsys: pytest.CaptureFixture[str], index: int
) -> None:
    tier = _tier(serve_env, index)
    _config(serve_env, leave={tier.setting}, tier_toml=tier.unbounded)
    assert _serve() == 2
    err = capsys.readouterr().err
    assert "refusing to start" in err
    assert tier.setting in err  # names the tier
    assert f"[security].{tier.ack}=true" in err  # and the switch that answers it
    # Only this tier: the others are bounded, so none of their switches is offered.
    for other in _tiers(serve_env):
        if other.setting != tier.setting:
            assert other.ack not in err


@pytest.mark.parametrize("index", range(4), ids=_TIER_IDS)
def test_a_tier_under_its_acknowledgement_starts_and_writes_an_audit_line(
    serve_env: Path, capsys: pytest.CaptureFixture[str], index: int
) -> None:
    tier = _tier(serve_env, index)
    _config(
        serve_env,
        leave={tier.setting},
        tier_toml=tier.unbounded,
        extra=f"security.{tier.ack} = true\n",
    )
    assert _serve() == 0
    captured = capsys.readouterr()
    assert "refusing to start" not in captured.err
    # serve's own logging handler writes to stdout (NSSM captures it); the gate runs after
    # configure_logging, so the AUDIT line lands there and on any configured forwarder.
    audit = [ln for ln in captured.out.splitlines() if "AUDIT:" in ln and tier.setting in ln]
    assert len(audit) == 1, captured.out
    assert "WARNING" in audit[0] and f"[security].{tier.ack}=true" in audit[0]


@pytest.mark.parametrize("index", range(4), ids=_TIER_IDS)
def test_a_tier_with_a_window_starts_with_no_audit_line(
    serve_env: Path, capsys: pytest.CaptureFixture[str], index: int
) -> None:
    tier = _tier(serve_env, index)
    _config(serve_env, leave={tier.setting}, tier_toml=tier.bounded)
    assert _serve() == 0
    captured = capsys.readouterr()
    assert "refusing to start" not in captured.err
    assert not [ln for ln in captured.out.splitlines() if "AUDIT:" in ln and tier.setting in ln]


# --- what does NOT satisfy it ---------------------------------------------------------------------


def test_the_body_opt_out_does_not_acknowledge_a_warn_only_tier(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``allow_keeping_phi_indefinitely`` covers the auto-bounded body tiers. The ruling asks for a
    PER-WINDOW acknowledgement, so the blanket switch must not open this gate."""
    tier = _tier(serve_env, 0)
    _config(
        serve_env,
        leave={tier.setting},
        tier_toml=tier.unbounded,
        extra="security.allow_keeping_phi_indefinitely = true\n",
    )
    assert _serve() == 2
    assert tier.setting in capsys.readouterr().err


def test_one_tiers_acknowledgement_does_not_cover_another(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Acknowledging transform state leaves search presets unbounded, so the start still refuses,
    and the refusal names only presets."""
    state, presets = _tier(serve_env, 0), _tier(serve_env, 1)
    # Both tiers are unbounded by leaving their windows out; only the state switch is set.
    _config(
        serve_env,
        leave={state.setting, presets.setting},
        tier_toml="",
        extra=f"security.{state.ack} = true\n",
    )
    assert _serve() == 2
    err = capsys.readouterr().err
    assert presets.setting in err and f"[security].{presets.ack}=true" in err
    assert state.setting not in err


def test_the_state_refusal_steers_to_the_acknowledgement_not_a_window(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#1188 records that state needs a non-write-time eviction key before any window is safe. The
    refusal must not send an operator to set one without saying so."""
    tier = _tier(serve_env, 0)
    _config(serve_env, leave={tier.setting}, tier_toml=tier.unbounded)
    assert _serve() == 2
    err = capsys.readouterr().err
    assert "non-write-time eviction key" in err


def test_under_the_warn_dial_a_tier_with_neither_warns_and_starts(
    serve_env: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The refuse/warn split every posture gate shares: ``enforcement = warn`` warns, names the
    tier and its switch, and starts."""
    tier = _tier(serve_env, 1)
    _config(
        serve_env,
        leave={tier.setting},
        tier_toml=tier.unbounded,
        extra='security.enforcement = "warn"\n',
    )
    assert _serve() == 0
    err = capsys.readouterr().err
    assert "refusing to start" not in err
    warn = [ln for ln in err.splitlines() if ln.startswith("warning:") and tier.setting in ln]
    assert len(warn) == 1 and f"[security].{tier.ack}=true" in warn[0]


# BACKLOG #1966: the serve fixtures here test another gate, so they carry verified off-box
# forwarding (tests/conftest.py, verified_log_forwarding).
pytestmark = pytest.mark.usefixtures("verified_log_forwarding")
