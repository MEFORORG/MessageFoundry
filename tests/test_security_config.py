# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0118 acceptance criteria for the ``[security]`` configuration section.

The switches live in one plain-language section, default to the secure position, and desugar into the
internal fields the serve gate + ``checks.py`` mirror already read — so no shipped refusal is loosened
(the gate-parity safety net is ``tests/test_checks_gate_parity.py``). These tests pin AC-1..AC-4 + AC-6;
AC-5 (the read-only posture view) is in ``tests/test_api_security_posture.py``.
"""

from __future__ import annotations

import inspect
import json
import logging
import re
from pathlib import Path

import pytest

import messagefoundry.config.settings as settings_module
from messagefoundry.__main__ import main
from messagefoundry.config.settings import (
    KEYLESS_REFUSED_BY_NO_STRICT_ACK,
    KEYLESS_REFUSED_BY_REQUIRE_ENCRYPTION,
    AlertsSettings,
    ApiSettings,
    AuthSettings,
    PipelineSettings,
    SecretRotationSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    keyless_opt_out_refusal,
    load_settings,
    oidc_second_factor_claim_exception,
    security_loosenings,
)


def _loosenings(sec: SecuritySettings) -> list[tuple[str, str]]:
    """``security_loosenings`` with the shipped [store]/[auth] defaults and an empty accepted set.

    The registry takes all four inputs as REQUIRED arguments deliberately (ADR 0148: one posture, and a
    deviation the registry cannot see is a second posture by the back door). The tests below are about
    the ``[security]`` switches specifically, so the other three are pinned at shipped values here."""
    return security_loosenings(
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
        store_privilege=None,
        audit_chain_unkeyed=None,
        remote_debug=None,
        startup=None,
    )


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


#: What a stock instance must PROVIDE to start clean, now that every instance carries patient
#: data (BACKLOG #1279). Before that, one line -- `handles_real_patient_data = false` -- stood in
#: for all of it. Dotted keys throughout so a test can add its own `[section]` headers without
#: TOML redefining a table.
_PHI_PROVISIONS = (
    "security.block_unlisted_outbound = true\n"
    "security.delete_message_bodies_after_days = 30\n"
    "retention.dead_letter_days = 30\n"
    'alerts.email_smtp_host = "smtp.example.org"\n'
    'alerts.email_from = "sec@example.org"\n'
    'alerts.email_to = ["ops@example.org"]\n'
)


# --- AC-1: [security] is the canonical, sole home; legacy keys no longer accepted -----------------


def test_security_section_is_canonical(tmp_path: Path) -> None:
    # Every posture switch resolves FROM [security] into the internal field it replaces...
    s = _load(
        tmp_path,
        "security.require_mfa = false\n"
        "security.block_unlisted_outbound = true\n"
        "security.serve_web_console = true\n"
        "security.delete_message_bodies_after_days = 45\n"
        "security.allow_keeping_phi_indefinitely = true\n"
        "security.audit_all_authorization_decisions = true\n"
        "security.sign_out_after_idle_minutes = 15\n"
        "security.max_session_hours = 8\n"
        "security.allow_unencrypted_phi = true\n"
        "security.production_instance = false\n",
    )
    # Sign-in has no switch any more (vault BACKLOG #2719), so a loaded config always has it on.
    assert s.auth.enabled is True and s.auth.require_mfa is False
    assert s.egress.deny_by_default is True
    assert s.api.serve_ui is True
    assert s.retention.messages_days == 45 and s.retention.allow_unbounded_phi is True
    assert s.diagnostics.audit_all_authz is True
    assert s.auth.session_idle_timeout_minutes == 15 and s.auth.session_absolute_hours == 8
    assert s.store.allow_unencrypted_phi is True
    assert s.ai.production is False

    # ...and the legacy scattered keys are REJECTED in their old sections (file OR env).
    legacy = [
        ('[api]\nhost = "0.0.0.0"\n', "local_access_only"),
        ("[api]\nserve_ui = true\n", "serve_web_console"),
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
    # The two RETIRED keys are refused too, and with a DIFFERENT message: they were removed
    # rather than relocated (BACKLOG #1279), so there is no forwarding address to name. Both
    # spellings, and the env form of each, because a config asserting the PHI gates are off
    # while the engine runs them all is a silent contradiction the next reader resolves wrongly.
    for toml in (
        '[ai]\ndata_class = "phi"\n',
        "security.handles_real_patient_data = false\n",
    ):
        with pytest.raises(ValueError, match="was REMOVED"):
            _load(tmp_path, toml)
    for var in ("MEFOR_AI_DATA_CLASS", "MEFOR_SECURITY_HANDLES_REAL_PATIENT_DATA"):
        with pytest.raises(ValueError, match="was REMOVED"):
            _load(tmp_path, "", environ={var: "phi"})
    # ...and the refusal names the per-gate switches that replaced it, so an operator who wanted
    # ONE of the nineteen gates relaxed can find the one they actually meant.
    with pytest.raises(ValueError, match="allow_unencrypted_phi"):
        _load(tmp_path, "security.handles_real_patient_data = false\n")


def test_the_sign_in_switch_is_refused_as_removed_in_every_form(tmp_path: Path) -> None:
    """``serve`` always requires sign-in (vault BACKLOG #2719). The switch that turned it off, and the
    ``[auth]`` key it had replaced, are refused as REMOVED, from the file and from the environment,
    whatever value they carry. ``true`` is refused too: the key no longer exists to agree with."""
    for toml in (
        "security.require_sign_in = false\n",
        "security.require_sign_in = true\n",
        "[auth]\nenabled = false\n",
        "[auth]\nenabled = true\n",
    ):
        with pytest.raises(ValueError, match=r"was REMOVED.*BACKLOG #2719") as excinfo:
            _load(tmp_path, toml)
        # The unknown-key refusal would offer `require_mfa` as the nearest spelling, which steers an
        # operator from one loosening to another. The removed-key text must not.
        assert "did you mean" not in str(excinfo.value)
        assert "moved to" not in str(excinfo.value)
    for var in ("MEFOR_SECURITY_REQUIRE_SIGN_IN", "MEFOR_AUTH_ENABLED"):
        with pytest.raises(ValueError, match="was REMOVED"):
            _load(tmp_path, "", environ={var: "false"})
    # CONTROL: the same loader accepts the switch beside it, so the refusal is about this key.
    assert _load(tmp_path, "security.require_mfa = true\n").auth.enabled is True


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
    # The soft-degrade "explicit" reading: true only when serve_web_console is provided (either value),
    # so the serve path can HARD-refuse an explicit true when the console package is absent while the
    # DEFAULT-on path (reading False) instead soft-degrades to JSON-only + a warning.
    assert _load(
        tmp_path, "security.serve_web_console = true\n"
    ).security.serve_web_console_explicit
    assert _load(tmp_path, "").security.serve_web_console_explicit is False
    assert (
        _load(tmp_path, "security.require_mfa = true\n").security.serve_web_console_explicit
        is False
    )


def _as_input(surface: str, section: str, key: str, value: str) -> tuple[str, dict[str, str]]:
    """``(toml, environ)`` supplying ``[section].key = value`` through the file or the environment."""
    if surface == "file":
        return f"[{section}]\n{key} = {value}\n", {}
    return "", {f"MEFOR_{section.upper()}_{key.upper()}": value}


@pytest.mark.parametrize("value", ["true", "false"])
@pytest.mark.parametrize("surface", ["file", "env"])
def test_serve_ui_explicit_is_refused_as_operator_input(
    tmp_path: Path, surface: str, value: str
) -> None:
    """BACKLOG #2000: ``[api].serve_ui_explicit`` was loader plumbing that an operator could also set.

    It is no longer a field, and both input surfaces are refused at either value: the file key and
    the ``MEFOR_API_SERVE_UI_EXPLICIT`` variable. The refusal names the key, the variable, and the
    operator setting to use instead. The env arm is the one that needs the named refusal: the
    generic unknown-key check reads the file only, so without it the variable would be ignored."""
    toml, environ = _as_input(surface, "api", "serve_ui_explicit", value)
    with pytest.raises(ValueError, match=r"\[api\]\.serve_ui_explicit was REMOVED") as excinfo:
        _load(tmp_path, toml, environ)
    message = str(excinfo.value)
    assert "MEFOR_API_SERVE_UI_EXPLICIT" in message
    assert "[security].serve_web_console" in message
    assert "serve_ui_explicit" not in ApiSettings.model_fields


@pytest.mark.parametrize("value", ["true", "false"])
@pytest.mark.parametrize("surface", ["file", "env"])
def test_require_rcsi_for_pooled_is_refused_at_load(
    tmp_path: Path, surface: str, value: str
) -> None:
    """BACKLOG #2090 (ADR 0066 section 12): ``[pipeline].require_rcsi_for_pooled`` is retired.

    ``false`` once let a pooled start run with RCSI off. The SQL Server store now refuses to open
    that way and the pooled gate always fails closed, so a key that loaded cleanly would read as a
    control that is not there. Both surfaces are refused at either value, and the message says why
    and what to do instead. The env arm needs the named refusal: the generic unknown-key check reads
    the file only, so without it the variable would be ignored."""
    toml, environ = _as_input(surface, "pipeline", "require_rcsi_for_pooled", value)
    with pytest.raises(
        ValueError, match=r"\[pipeline\]\.require_rcsi_for_pooled was REMOVED"
    ) as excinfo:
        _load(tmp_path, toml, environ)
    message = str(excinfo.value)
    assert "MEFOR_PIPELINE_REQUIRE_RCSI_FOR_POOLED" in message
    assert "READ_COMMITTED_SNAPSHOT" in message
    assert "ADR 0066 section 12" in message
    assert "require_rcsi_for_pooled" not in PipelineSettings.model_fields


@pytest.mark.parametrize("value", ["true", "false"])
@pytest.mark.parametrize("surface", ["file", "env"])
def test_serve_web_console_still_marks_the_console_explicit(
    tmp_path: Path, surface: str, value: str
) -> None:
    """CONTROL for the refusal above: the real knob still marks the console explicit.

    At either value, from the file and from the environment, and it still drives ``serve_ui``. A
    refusal that also broke this would turn every explicit request into the default posture."""
    toml, environ = _as_input(surface, "security", "serve_web_console", value)
    settings = _load(tmp_path, toml, environ)
    assert settings.security.serve_web_console_explicit is True
    assert settings.api.serve_ui is (value == "true")


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
    assert d.require_mfa is True
    assert "require_sign_in" not in SecuritySettings.model_fields  # vault BACKLOG #2719
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


def test_encrypt_stored_data_off_is_the_keyless_opt_out_and_says_so(tmp_path: Path) -> None:
    # BACKLOG #1906: the loosening text said a PHI instance "still refuses unless allow_unencrypted_phi
    # is also set". The desugar folds either key into [store].allow_unencrypted_phi, so
    # encrypt_stored_data=false alone IS the opt-out the keyless gate reads, and the text must say so.
    s = _load(tmp_path, "security.encrypt_stored_data = false\n")
    assert s.store.allow_unencrypted_phi is True
    # The opt-out came from encrypt_stored_data alone.
    assert s.security.allow_unencrypted_phi is False
    # Under the default enforce, the keyless gate then asks only for the strict-enforcement ack, which
    # is what allow_unencrypted_phi alone would leave it asking for...
    assert keyless_opt_out_refusal(s.store, s.security) == KEYLESS_REFUSED_BY_NO_STRICT_ACK
    # ...under warn it lets the keyless start through...
    warn = _load(tmp_path, 'security.enforcement = "warn"\nsecurity.encrypt_stored_data = false\n')
    assert keyless_opt_out_refusal(warn.store, warn.security) is None
    # ...and [store].require_encryption still wins over it.
    forced = warn.store.model_copy(update={"require_encryption": True})
    assert keyless_opt_out_refusal(forced, warn.security) == KEYLESS_REFUSED_BY_REQUIRE_ENCRYPTION

    text = dict(_loosenings(SecuritySettings(encrypt_stored_data=False)))["encrypt_stored_data"]
    assert "may start keyless" in text and "same opt-out" in text
    assert "still refuses" not in text


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


def test_require_mfa_scope_advisory_names_only_the_accounts_it_frees() -> None:
    """Vault BACKLOG #2798. RED when the advisory again says a directory account is single-factor under
    ``require_mfa_scope = "administrators"``.

    The scope reaches only a LOCAL account without the Administrator role: ``_scope_covers`` keeps the
    role in scope, and the directory floor in ``AuthService._unverified_session_owes_factor`` makes an
    unstamped directory session owe a factor under either scope value. An OIDC session is stamped at
    mint only on a checked amr/acr claim. Exact text, so a rewrite has to come past this test."""
    loos = dict(_loosenings(SecuritySettings(require_mfa_scope="administrators")))
    assert loos["require_mfa_scope"] == (
        "a local account without the Administrator role is single-factor until it enrolls a "
        "second factor. Administrators and directory accounts still owe one, unless an OIDC "
        "sign-in carries an amr/acr claim checked while [auth].oidc_require_mfa_claim is on"
    )


def test_require_mfa_advisory_keeps_an_enrolled_factor_and_the_oidc_claim() -> None:
    """Vault BACKLOG #2798. RED when the ``require_mfa = false`` advisory again says EVERY account is
    single-factor, or again says an enrolled account must ALWAYS satisfy its factor.

    With the requirement off, ``AuthService._mfa_required_for`` still holds an ENROLLED account to its
    factor, but only while it keeps one: the last-factor removal guards ask the same helper with
    ``second_factor_enrolled=False``, which answers False here, so the holder may remove the last. The
    OIDC claim gate (``auth/oidc/claims.py:_check_mfa_gate``) reads only
    ``[auth].oidc_require_mfa_claim``, and the OIDC mint stamps the session verified on that setting,
    so the checked claim counts as the second factor whether or not one is enrolled. What the switch
    frees is an account with no factor enrolled, which is where a Kerberos ticket that asserts no
    strength gets in on its own."""
    loos = dict(_loosenings(SecuritySettings(require_mfa=False)))
    assert loos["require_mfa"] == (
        "an account with no second factor enrolled is single-factor, so a Kerberos session enters "
        "on a ticket that asserts no strength. An enrolled account owes its factor only while it "
        "keeps one, and its holder may remove the last. Where an OIDC sign-in carries an amr/acr "
        "claim checked while [auth].oidc_require_mfa_claim is on, that claim counts as the second "
        "factor, whether or not one is enrolled"
    )


@pytest.mark.parametrize(
    ("oidc_enabled", "claim_gate", "expected"),
    [
        (
            True,
            True,
            ", unless an OIDC sign-in carries an amr/acr claim checked while "
            "[auth].oidc_require_mfa_claim is on",
        ),
        (True, False, ""),
        (False, True, ""),
    ],
)
def test_startup_texts_name_the_oidc_exception_only_where_it_exists(
    oidc_enabled: bool, claim_gate: bool, expected: str
) -> None:
    """Vault BACKLOG #1133. The exposed-without-MFA refusal, warnings and AUDIT line describe ONE
    running config. With OIDC off, or its claim gate off, every OIDC session mints unverified, so the
    record must not name an exception this instance does not have. ``model_construct`` skips the
    OIDC-enabled validators (issuer, client secret, endpoints), which are not what is on trial."""
    auth = AuthSettings.model_construct(
        oidc_enabled=oidc_enabled, oidc_require_mfa_claim=claim_gate
    )
    assert oidc_second_factor_claim_exception(auth) == expected


#: CodeQL's password-name heuristic as PR 1959 measured it at 2.27.1: ``mfa`` as a separate word.
_CODEQL_PASSWORD_WORD = re.compile(r"(?:^|[_-])mfa(?:[_-]|$)", re.IGNORECASE)


def _named_like_a_password_and_logged(name: str, value: object) -> bool:
    """A module-level text, or a helper here that returns one, under a name CodeQL reads as a
    password. Such a text reaching a log line raises ``py/clear-text-logging-sensitive-data``."""
    if not _CODEQL_PASSWORD_WORD.search(name):
        return False
    if isinstance(value, str):
        return True
    return (
        inspect.isfunction(value)
        and value.__module__ == settings_module.__name__
        and inspect.signature(value).return_annotation in (str, "str")
    )


def test_no_logged_settings_text_is_named_like_a_password() -> None:
    """Vault BACKLOG #1133. RED when a text constant or a text helper in ``config.settings`` takes
    ``mfa`` as a separate word in its name, as ``OIDC_MFA_CLAIM_EXCEPTION`` did on PR 1959.

    CodeQL is not a required check, so before this test the rule lived only in a comment. Scoped to
    the names bound in this module, ``__all__`` among them. An imported text constant counts too;
    a helper counts only when defined here and annotated ``-> str``. ADR 0034's 2026-10-03
    amendment holds the rule and says what this guard does not see."""
    # Positive control: the two names PR 1959 renamed away from, and the names it chose instead.
    assert _named_like_a_password_and_logged("OIDC_MFA_CLAIM_EXCEPTION", "a fixed sentence")
    assert _named_like_a_password_and_logged(
        "oidc_mfa_claim_exception", oidc_second_factor_claim_exception
    )
    assert not _named_like_a_password_and_logged(
        "OIDC_SECOND_FACTOR_CLAIM_EXCEPTION", "a fixed sentence"
    )
    # The walk must cover something: an empty module namespace would pass the absence below.
    bound = vars(settings_module)
    assert len(bound) >= 20
    offenders = sorted(
        name for name, value in bound.items() if _named_like_a_password_and_logged(name, value)
    )
    assert offenders == []


def test_single_factor_at_exposure_advisory_names_what_the_gate_reads() -> None:
    """Vault BACKLOG #2798 amendment. RED when the advisory again says "production-PHI bind".

    The refusal it lifts (``__main__._serve``, the ``admin_exposed`` arm) reads exposure,
    ``[security].enforcement`` and ``require_mfa``. It reads no production tier and no account kind,
    and with ``require_mfa`` off every un-enrolled account is single-factor, not only an
    Administrator."""
    loos = dict(_loosenings(SecuritySettings(allow_single_factor_admin_when_exposed=True)))
    assert loos["allow_single_factor_admin_when_exposed"] == (
        "an EXPOSED instance under enforcement = enforce may start with [security].require_mfa "
        "off, on an audited warning instead of the refusal. Every account with no second factor "
        "enrolled is then single-factor over the network, unless an OIDC sign-in carries an "
        "amr/acr claim checked while [auth].oidc_require_mfa_claim is on"
    )


@pytest.mark.parametrize(
    ("switch", "sec"),
    [
        ("require_mfa", SecuritySettings(require_mfa=False)),
        (
            "allow_single_factor_admin_when_exposed",
            SecuritySettings(allow_single_factor_admin_when_exposed=True),
        ),
    ],
)
def test_ide_security_editor_risk_mirrors_the_mfa_advisories(
    switch: str, sec: SecuritySettings
) -> None:
    """Vault BACKLOG #1133. RED when the IDE Security Settings page drifts from the engine's text.

    ``ide/src/securityEditorWebview.ts`` says its ``risk`` strings are kept in step with
    ``security_loosenings()``, and nothing checked it: the page still said "the Administrator role is
    single-factor" after the engine text was corrected. TypeScript cannot import the Python, so this
    reads the source. Scoped to the two MFA switches; other risks there are shorter on purpose."""
    source = (
        Path(__file__).resolve().parent.parent / "ide" / "src" / "securityEditorWebview.ts"
    ).read_text(encoding="utf-8")
    # One FIELDS entry is one `{ ... }` with no nested braces, so `[^{}]` keeps the match inside it,
    # and the captured literal is decoded as JSON so a backslash-u escape compares as its character.
    # Whitespace is optional around every token, so reformatting the entry still matches it.
    entry = re.search(rf'\{{\s*key\s*:\s*"{re.escape(switch)}"\s*,[^{{}}]*\}}', source)
    assert entry is not None, f"no FIELDS entry for {switch} in securityEditorWebview.ts"
    risk = re.search(r'\brisk\s*:\s*("(?:[^"\\]|\\.)*")', entry.group(0))
    assert risk is not None, f"the {switch} entry has no risk string"
    assert json.loads(risk.group(1)) == dict(_loosenings(sec))[switch]


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
    # Every instance carries patient data (BACKLOG #1279), so this dev serve SATISFIES the PHI gates
    # rather than declaring itself out of them -- the loosening WARNING is the subject here, and it
    # must name require_mfa and nothing else.
    rc = _serve(
        tmp_path,
        monkeypatch,
        _PHI_PROVISIONS + "security.require_mfa = false\n",
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
        '[api]\ntls_terminated_upstream = true\nplaintext_upstream_hop_acknowledged = true\ntrusted_proxies = ["10.0.0.1"]\n'
        'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
        "[retention]\ndead_letter_days = 30\n"
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
        'email_to = ["ops@example.org"]\n',
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


# --- BACKLOG #1279: no declaration relaxes the PHI gates; only the per-gate switch does -----------


def test_no_declaration_relaxes_the_phi_gates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # This test is the INVERSE of the one it replaces. `handles_real_patient_data = false` used to
    # start a keyless dev box quietly; it is now refused at load, so the keyless gate fires and the
    # operator is told which switch to reach for instead.
    rc = _serve(
        tmp_path,
        monkeypatch,
        "security.handles_real_patient_data = false\n",
        env="dev",
        key=False,
    )
    assert rc == 2
    err = capsys.readouterr().err
    assert "was REMOVED" in err and "allow_unencrypted_phi" in err

    # A bare dev box with no key refuses on the keyless gate itself -- the gate the declaration
    # used to silence, now reachable by every instance.
    rc = _serve(tmp_path, monkeypatch, "", env="dev", key=False)
    assert rc == 2
    assert "UNENCRYPTED at rest" in capsys.readouterr().err

    # The PER-GATE ack is what starts it, and unlike the retired lever it relaxes ONE gate and says
    # so: the AUDIT line fires and every other gate stays live. Under the shipped `enforce` it takes
    # the second acknowledgment too (ADR 0140), which is the point -- keyless PHI under strict
    # enforcement is never one flag away.
    rc = _serve(
        tmp_path,
        monkeypatch,
        _PHI_PROVISIONS
        + "security.allow_unencrypted_phi = true\n"
        + "security.allow_unencrypted_phi_under_strict_enforcement = true\n",
        env="dev",
        key=False,
    )
    assert rc == 0


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
        '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
        'email_to = ["ops@example.org"]\n' + debug,
        env="prod",
    )
    assert rc == 2
    assert "DEBUG logging is refused on a production instance" in capsys.readouterr().err
    # ...and a NON-production instance permits DEBUG even at the default ENFORCE (tier, not dial).
    rc = _serve(
        tmp_path,
        monkeypatch,
        _PHI_PROVISIONS + debug,
        env="dev",
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
            "[security]\nrequire_mfa = true\n",
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
    """[egress] declares EIGHT allowed_* DESTINATION lists; the gate used to count six.

    (`allowed_proxy` is another allowed_* key, and it is not one of them — it gates a transport
    intermediary, not a destination, so it must never satisfy this gate. BACKLOG #1659.)


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
    assert "no outbound destination is declared" not in err, (
        "a declared SMTP allowlist must satisfy the gate"
    )
    assert "block_unlisted_outbound defaulted ON" in err, "...and it must still start fail-closed"

    _serve(tmp_path, monkeypatch, 'egress.allowed_direct = ["hisp.example"]\n', env="prod")
    err = capsys.readouterr().err
    assert "no outbound destination is declared" not in err, (
        "a declared Direct allowlist must satisfy the gate"
    )
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


# BACKLOG #1967: this file's serve fixtures test other gates, so they bound the two warn-only
# retention tiers that ship with no window (tests/conftest.py, bounded_warn_only_retention).
pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")
