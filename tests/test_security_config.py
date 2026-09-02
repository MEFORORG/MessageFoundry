# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0118 acceptance criteria for the ``[security]`` configuration section.

The switches live in one plain-language section, default to the secure position, and desugar into the
internal fields the serve gate + ``checks.py`` mirror already read — so no shipped refusal is loosened
(the gate-parity safety net is ``tests/test_checks_gate_parity.py``). These tests pin AC-1..AC-4 + AC-6;
AC-5 (the read-only posture view) is in ``tests/test_api_security_posture.py``.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.ai_policy import DataClass
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)


def _loosenings(sec: SecuritySettings) -> list[tuple[str, str]]:
    """``security_loosenings`` with the shipped [store]/[auth] defaults and an empty accepted set.

    The registry takes all four inputs as REQUIRED arguments deliberately (ADR 0148: one posture, and a
    deviation the registry cannot see is a second posture by the back door). The tests below are about
    the ``[security]`` switches specifically, so the other three are pinned at shipped values here."""
    return security_loosenings(sec, StoreSettings(), AuthSettings(), AlertsSettings(), (), (), ())


SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def _load(tmp_path: Path, toml: str, environ: dict[str, str] | None = None) -> ServiceSettings:
    cfg = tmp_path / "messagefoundry.toml"
    cfg.write_text(toml, encoding="utf-8")
    return load_settings(config_path=cfg, environ=environ or {})


def _serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str,
    *,
    env: str,
    key: bool = True,
    insecure: bool = False,
) -> int:
    """Run ``serve`` through the gate ladder with the app + uvicorn mocked (no socket opened)."""
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    argv = ["serve", "--config", str(SAMPLES_CONFIG), "--env", env]
    if insecure:
        argv.append("--allow-insecure-bind")
    return main(argv)


# --- AC-1: [security] is the canonical, sole home; legacy keys no longer accepted -----------------


def test_security_section_is_canonical(tmp_path: Path) -> None:
    # Every posture switch resolves FROM [security] into the internal field it replaces...
    s = _load(
        tmp_path,
        "security.require_sign_in = false\n"
        "security.require_mfa = false\n"
        "security.block_unlisted_outbound = true\n"
        "security.serve_web_console = true\n"
        "security.delete_message_bodies_after_days = 45\n"
        "security.allow_keeping_phi_indefinitely = true\n"
        "security.audit_all_authorization_decisions = true\n"
        "security.sign_out_after_idle_minutes = 15\n"
        "security.max_session_hours = 8\n"
        "security.allow_unencrypted_phi = true\n"
        "security.handles_real_patient_data = true\n"
        "security.production_instance = false\n",
    )
    assert s.auth.enabled is False and s.auth.require_mfa is False
    assert s.egress.deny_by_default is True
    assert s.api.serve_ui is True
    assert s.retention.messages_days == 45 and s.retention.allow_unbounded_phi is True
    assert s.diagnostics.audit_all_authz is True
    assert s.auth.session_idle_timeout_minutes == 15 and s.auth.session_absolute_hours == 8
    assert s.store.allow_unencrypted_phi is True
    assert s.ai.data_class is DataClass.PHI and s.ai.production is False

    # ...and the legacy scattered keys are REJECTED in their old sections (file OR env).
    legacy = [
        ('[ai]\ndata_class = "phi"\n', "handles_real_patient_data"),
        ('[api]\nhost = "0.0.0.0"\n', "local_access_only"),
        ("[api]\nserve_ui = true\n", "serve_web_console"),
        ("[auth]\nenabled = false\n", "require_sign_in"),
        ("[auth]\nrequire_mfa = false\n", "require_mfa"),
        ("[egress]\ndeny_by_default = true\n", "block_unlisted_outbound"),
        ("[store]\nallow_unencrypted_phi = true\n", "allow_unencrypted_phi"),
        ("[retention]\nmessages_days = 30\n", "delete_message_bodies_after_days"),
        ("[retention]\nallow_unbounded_phi = true\n", "allow_keeping_phi_indefinitely"),
        ("[diagnostics]\naudit_all_authz = true\n", "audit_all_authorization_decisions"),
    ]
    for toml, replacement in legacy:
        with pytest.raises(ValueError, match=replacement):
            _load(tmp_path, toml)
    # env form is rejected too (MEFOR_AI_DATA_CLASS moved).
    with pytest.raises(ValueError, match="handles_real_patient_data"):
        _load(tmp_path, "", environ={"MEFOR_AI_DATA_CLASS": "phi"})


def test_web_console_on_by_default(tmp_path: Path) -> None:
    # ADR 0143: a bare load (no [security]) leaves the console ON — the ApiSettings.serve_ui default
    # governs because the [security] desugar is PRESENCE-GATED (an absent switch writes nothing).
    assert SecuritySettings().serve_web_console is True
    assert _load(tmp_path, "").api.serve_ui is True
    # ...still on when [security] is present but the switch itself is not set (presence-gating holds).
    assert _load(tmp_path, "security.require_mfa = true\n").api.serve_ui is True
    # Disabling it is the one user lever (a surface-reducing opt-out): serve_web_console=false desugars
    # to [api].serve_ui=False, so no /ui is mounted.
    assert _load(tmp_path, "security.serve_web_console = false\n").api.serve_ui is False
    # The soft-degrade "explicit" marker: set only when serve_web_console is provided (either value),
    # so the serve path can HARD-refuse an explicit true when the console package is absent while the
    # DEFAULT-on path (marker False) instead soft-degrades to JSON-only + a warning.
    assert _load(tmp_path, "security.serve_web_console = true\n").api.serve_ui_explicit is True
    assert _load(tmp_path, "").api.serve_ui_explicit is False


def test_legacy_keys_stay_when_plumbing(tmp_path: Path) -> None:
    # The move-vs-stay boundary: [store].require_encryption and [retention].dead_letter_days are plumbing
    # that stays accepted in its own section (ADR 0118 §1).
    s = _load(tmp_path, "[store]\nrequire_encryption = true\n[retention]\ndead_letter_days = 10\n")
    assert s.store.require_encryption is True and s.retention.dead_letter_days == 10


# --- AC-2: absent switches apply their secure default --------------------------------------------


def test_secure_defaults_applied(tmp_path: Path) -> None:
    # The model defaults ARE the secure position (§1)...
    d = SecuritySettings()
    assert d.local_access_only is True
    assert d.require_encryption_for_remote is True
    # ADR 0143: the browser console is ON by default (it is the operator UI, effectively core);
    # disabling it (serve_web_console=false) SHRINKS the /ui attack surface, so on IS the default here.
    assert d.serve_web_console is True
    assert d.encrypt_stored_data is True and d.allow_unencrypted_phi is False
    assert d.require_sign_in is True and d.require_mfa is True
    assert d.sign_out_after_idle_minutes == 30 and d.max_session_hours == 12
    assert d.block_unlisted_outbound is True
    assert d.delete_message_bodies_after_days == 30
    assert d.allow_keeping_phi_indefinitely is False
    # BACKLOG #1277 reversed the ADR 0118 §5 `false` (delegated by the owner to the Console on
    # 2026-09-02; decided by the Console). The full-trail assertions live in
    # test_authz_grant_trail_defaults_on below.
    assert d.audit_all_authorization_decisions is True
    # Two production-PHI acknowledgment switches (ADR 0140 No-loosen carve-out): default false = byte-identical.
    assert d.allow_single_factor_admin_when_exposed is False
    assert d.allow_unencrypted_phi_under_strict_enforcement is False

    # ...and an ENTIRELY absent [security] section resolves to the secure internal posture (byte-identical
    # to pre-ADR-0118: auth on, MFA on, loopback bind).
    s = _load(tmp_path, "")
    assert s.auth.enabled is True and s.auth.require_mfa is True
    assert s.api.host == "127.0.0.1" and s.api.is_loopback is True
    assert s.security.local_access_only is True


def test_authz_grant_trail_defaults_on(tmp_path: Path) -> None:
    """BACKLOG #1277: both spellings default ON, they agree, and turning it off is a loosening.

    The default is read back through ``load_settings`` on an EMPTY file rather than off the model, and
    that is the whole point of the test. The ``[security]`` desugar is presence-gated, so a
    ``[security]`` default that the ``[diagnostics]`` field does not match would be cosmetic: the
    section is absent, nothing is written through, and the internal field decides. Asserting
    ``SecuritySettings().audit_all_authorization_decisions`` alone cannot see that.
    """
    s = _load(tmp_path, "")
    assert s.diagnostics.audit_all_authz is True  # the field the grant sites actually read
    assert s.security.audit_all_authorization_decisions is True  # the operator-facing spelling
    assert s.diagnostics.audit_all_authz is s.security.audit_all_authorization_decisions

    # The alias carries the OFF direction too. Only this direction is asserted here:
    # test_security_section_is_canonical above already pins the `true` write-through and the refusal of
    # the retired `[diagnostics]` spelling, and a second copy of either would just break in pairs.
    off = _load(tmp_path, "security.audit_all_authorization_decisions = false\n")
    assert off.diagnostics.audit_all_authz is False
    assert off.security.audit_all_authorization_decisions is False

    # Turning the trail off is now a LOOSENING. That it is REPORTED is pinned by the completeness floor
    # in tests/test_security_posture_defaults.py; what that floor cannot check is whether the entry says
    # anything a reader can act on, so the message itself is asserted here.
    named = dict(_loosenings(SecuritySettings(audit_all_authorization_decisions=False)))
    assert "NOT recorded" in named["audit_all_authorization_decisions"]


# --- AC-3: local_access_only=true + non-loopback listen_address refuses ---------------------------


def test_local_access_only_refuses_nonloopback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The contradiction fails closed at load (ValueError) rather than silently picking a bind.
    with pytest.raises(ValueError, match="loopback"):
        _load(tmp_path, 'security.local_access_only = true\nsecurity.listen_address = "0.0.0.0"\n')
    # ...and serve exits 2 (parity with the pre-refactor [api].host non-loopback gate).
    rc = _serve(
        tmp_path,
        monkeypatch,
        'security.local_access_only = true\nsecurity.listen_address = "0.0.0.0"\n',
        env="dev",
    )
    assert rc == 2

    # local_access_only=false binds the listen_address (the exposed gate then applies).
    s = _load(
        tmp_path, 'security.local_access_only = false\nsecurity.listen_address = "10.0.0.5"\n'
    )
    assert s.api.host == "10.0.0.5" and s.api.is_loopback is False


# --- AC-4: loosening warns; a production-PHI weakening still refuses (ADR 0092 clamp intact) -------


def test_loosening_warns_and_prod_phi_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # security_loosenings() names each opt-out in plain language (the serve warning + the posture view
    # both consume it). Since BACKLOG #1277, audit_all_authorization_decisions=false IS one of them —
    # asserted in test_authz_grant_trail_defaults_on below.
    loos = dict(_loosenings(SecuritySettings(require_mfa=False, block_unlisted_outbound=False)))
    assert "require_mfa" in loos and "single-factor" in loos["require_mfa"]
    assert (
        "block_unlisted_outbound" in loos and "any destination" in loos["block_unlisted_outbound"]
    )
    assert _loosenings(SecuritySettings()) == []  # all-secure defaults → nothing named

    # The serve-time consolidated warning fires naming the loosened switch (AC-4). It rides the logging
    # path (post-configure_logging), which routes to stdout — the gate REFUSE messages print to stderr.
    # GIVEN 1 (ADR 0148): dev derives PHI now, so declare synthetic to keep the PHI gates quiet — the
    # loosening WARNING is the subject here.
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\nsecurity.require_mfa = false\n",
        env="dev",
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "posture loosened" in out and "require_mfa" in out

    # A production-PHI weakening still REFUSES where the pre-refactor gate refused: require_mfa off on an
    # exposed production PHI bind (Posture-B) fails closed — the ADR 0092 clamp is unchanged.
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.local_access_only = false\n"
        'security.listen_address = "0.0.0.0"\n'
        "security.require_mfa = false\n"
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        "[retention]\ndead_letter_days = 30\n"
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n',
        env="prod",
    )
    assert rc == 2
    assert "require_mfa off; refusing to start" in capsys.readouterr().err


def test_production_acks_are_loosenings_when_set() -> None:
    # The two ADR 0140 production-PHI acks are surfaced as loosenings (loud + posture-visible) when
    # enabled, and are NOT loosenings at their secure default (off) — mirroring allow_unencrypted_phi /
    # allow_keeping_phi. Each appears exactly once (guards against a duplicate-append bug).
    switches = [
        k
        for k, _ in _loosenings(
            SecuritySettings(
                allow_single_factor_admin_when_exposed=True,
                allow_unencrypted_phi_under_strict_enforcement=True,
            )
        )
    ]
    # Count on the RAW list (not dict(), which would collapse a duplicate-append bug) so "exactly once"
    # is genuinely verified, per ADR 0140 AC-6.
    assert switches.count("allow_single_factor_admin_when_exposed") == 1
    assert switches.count("allow_unencrypted_phi_under_strict_enforcement") == 1
    assert _loosenings(SecuritySettings()) == []  # acks off => nothing named


# --- AC-6: handles_real_patient_data=false relaxes the PHI-only gates (and it is posture-visible) --


def test_synthetic_relaxation_visible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A synthetic instance (handles_real_patient_data=false) relaxes the PHI-only gates: it starts keyless,
    # quietly, with no at-rest-encryption / egress / retention refusal.
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n",
        env="dev",
        key=False,
    )
    assert rc == 0
    err = capsys.readouterr().err
    assert "UNENCRYPTED at rest" not in err and "refusing to start" not in err

    # The SAME config marked as real patient data does NOT relax — the keyless at-rest gate fires. This
    # posture split is what the read-only GET /security/posture view surfaces (AC-5).
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = true\n",
        env="dev",
        key=False,
    )
    assert rc == 2
    assert "UNENCRYPTED at rest" in capsys.readouterr().err


# --- security enforcement dial (this refactor): decoupled REFUSE/WARN from the production tier -------


def test_enforcement_default_and_env_override(tmp_path: Path) -> None:
    from messagefoundry.config.ai_policy import SecurityEnforcement

    # Secure default is ENFORCE, and it is a DIRECT-READ field on [security] (not desugared, not a
    # relocated legacy key), so a bare load carries it and no legacy section is rejected.
    assert SecuritySettings().enforcement is SecurityEnforcement.ENFORCE
    assert _load(tmp_path, "").security.enforcement is SecurityEnforcement.ENFORCE
    # File value coerces the wire string to the enum.
    assert (
        _load(tmp_path, 'security.enforcement = "warn"\n').security.enforcement
        is SecurityEnforcement.WARN
    )
    # MEFOR_SECURITY_ENFORCEMENT works via the standard [security] env path (not a relocated key).
    assert (
        _load(tmp_path, "", environ={"MEFOR_SECURITY_ENFORCEMENT": "warn"}).security.enforcement
        is SecurityEnforcement.WARN
    )


def test_enforcement_warn_is_named_as_a_loosening_once() -> None:
    from messagefoundry.config.ai_policy import SecurityEnforcement

    switches = [k for k, _ in _loosenings(SecuritySettings(enforcement=SecurityEnforcement.WARN))]
    assert switches.count("enforcement") == 1
    # ENFORCE (the secure default) is NOT a loosening.
    assert "enforcement" not in dict(_loosenings(SecuritySettings()))


def test_enforcement_decouples_refuse_warn_from_tier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A representative posture gate (open-egress). At the DEFAULT enforce, a NON-production (staging) PHI
    # instance now REFUSES exactly as production did — the dial is keyed on enforcement, not the tier.
    open_egress = "security.block_unlisted_outbound = false\n"
    rc = _serve(tmp_path, monkeypatch, open_egress, env="staging")
    assert rc == 2
    assert "egress is UNRESTRICTED" in capsys.readouterr().err
    # enforcement=warn reproduces the historical non-production warn+continue (I3).
    rc = _serve(
        tmp_path, monkeypatch, 'security.enforcement = "warn"\n' + open_egress, env="staging"
    )
    assert rc == 0
    assert "egress is UNRESTRICTED in a PHI-carrying environment" in capsys.readouterr().err
    # ...and enforce on a genuine production instance is byte-identical to before (I1): still refuses.
    rc = _serve(tmp_path, monkeypatch, open_egress, env="prod")
    assert rc == 2
    assert "egress is UNRESTRICTED on a production PHI instance" in capsys.readouterr().err


def test_debug_logging_gate_keys_on_tier_not_enforcement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # FIX 3: the DEBUG-logging refusal stays keyed on the PRODUCTION TIER fact, NOT the enforcement dial.
    # A production instance refuses DEBUG even under enforcement=warn...
    debug = '[logging]\nlevel = "DEBUG"\n'
    rc = _serve(
        tmp_path,
        monkeypatch,
        'security.enforcement = "warn"\nsecurity.block_unlisted_outbound = true\n'
        "security.delete_message_bodies_after_days = 30\n[retention]\ndead_letter_days = 30\n"
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n' + debug,
        env="prod",
    )
    assert rc == 2
    assert "DEBUG logging is refused on a production instance" in capsys.readouterr().err
    # ...and a NON-production instance permits DEBUG even at the default ENFORCE (tier, not dial).
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n" + debug,
        env="dev",
        key=False,
    )
    assert rc == 0
    assert "DEBUG logging is refused" not in capsys.readouterr().err


# --- an unknown [security] key is REFUSED, never silently dropped --------------


def test_unknown_security_key_is_refused(tmp_path: Path) -> None:
    """A mistyped posture switch used to load clean and apply NOTHING — a silent fail-open on exactly
    the keys that matter, since the operator then believes a control is on. It now refuses."""
    with pytest.raises(ValueError) as excinfo:
        _load(tmp_path, "security.block_unlisted_outboud = true\nsecurity.require_mfa = true\n")
    message = str(excinfo.value)
    assert "[security].block_unlisted_outboud" in message
    assert "block_unlisted_outbound" in message  # the near-miss suggestion


def test_unknown_security_key_delivered_by_env_is_refused(tmp_path: Path) -> None:
    """The [security] arm covers ENV as well as the file — the file-level check cannot see a
    MEFOR_SECURITY_* variable. Safe for this section specifically: every MEFOR_SECURITY_* name in the
    tree maps to a real field, so there is no out-of-band variable here to collide with."""
    with pytest.raises(ValueError, match=r"\[security\]\.block_unlisted_outboud"):
        _load(
            tmp_path,
            "[security]\nrequire_sign_in = true\n",
            {"MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUD": "true"},
        )


def test_known_security_keys_load_clean(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The negative control: a valid config still loads, with no warning and no refusal — including a
    switch added later (allowed_client_networks) that an older engine would not have recognised."""
    with caplog.at_level(logging.WARNING, logger="messagefoundry.config.settings"):
        s = _load(
            tmp_path,
            "security.block_unlisted_outbound = true\n"
            'security.allowed_client_networks = ["10.20.4.0/24"]\n',
        )
    assert s.egress.deny_by_default is True
    assert "unrecognized" not in caplog.text


def test_open_egress_gate_counts_smtp_and_direct_when_deny_by_default_is_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """[egress] declares EIGHT allowed_* lists; the gate used to count six.

    A mail-only or Direct-only PHI instance could enumerate every destination it actually uses and
    still be refused as "UNRESTRICTED", with nothing in the refusal naming the two lists that did not
    count — while both ARE enforced downstream by `_allowlist_for`. They are counted only when
    [security].block_unlisted_outbound is left UNSET, which is precisely the state the deny-by-default
    flip turns ON, so such an instance still starts fail-closed.
    """
    # Assert on THIS gate, not on the whole startup ladder: a bare prod instance also trips later,
    # unrelated gates (retention, security-notification), so rc == 0 would be testing something else.
    _serve(tmp_path, monkeypatch, 'egress.allowed_smtp = ["smtp.partner.example"]\n', env="prod")
    err = capsys.readouterr().err
    assert "egress is UNRESTRICTED" not in err, "a declared SMTP allowlist must satisfy the gate"
    assert "block_unlisted_outbound defaulted ON" in err, "...and it must still start fail-closed"

    _serve(tmp_path, monkeypatch, 'egress.allowed_direct = ["hisp.example"]\n', env="prod")
    err = capsys.readouterr().err
    assert "egress is UNRESTRICTED" not in err, "a declared Direct allowlist must satisfy the gate"
    assert "block_unlisted_outbound defaulted ON" in err


def test_open_egress_gate_still_refuses_smtp_only_when_deny_by_default_is_opted_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The one case that must NOT loosen.

    With [security].block_unlisted_outbound explicitly false the deny-by-default flip is opted out, so
    an SMTP/Direct-only allowlist would leave every OTHER transport allow-any. That combination is
    still a refusal, and the message names the override so the operator knows which knob caused it.
    """
    toml = (
        'security.block_unlisted_outbound = false\negress.allowed_smtp = ["smtp.partner.example"]\n'
    )
    rc = _serve(tmp_path, monkeypatch, toml, env="prod")
    assert rc == 2
    err = capsys.readouterr().err
    assert "egress is UNRESTRICTED on a production PHI instance" in err
    assert "block_unlisted_outbound" in err
    assert "allowed_smtp" in err
