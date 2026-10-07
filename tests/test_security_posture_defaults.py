# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shipped-default posture lane: ONE posture, and operators may only LOOSEN from it.

Two defaults moved to the hardened value (ADR 0148 GIVEN 1 — the hardened path is the shipped path, so it
is the path every test, CI leg and dogfood instance exercises, not one first met in production):

* ``[store].aad_bind`` ``false`` → **``true``** (ADR 0019, 2026-07-28 amendment) — at-rest values are
  cell-bound (``mfenc:v2``) by default;
* ``[auth].ad_session_recheck_seconds`` ``0`` → **``300``** (ADR 0079, 2026-07-28 amendment) — directory
  revocation propagates by default.

The governing rule is that every deviation from that one posture is VISIBLE: ``security_loosenings()`` +
``GET /security/posture`` + ``docs/SECURITY-LOOSENING.md``. A deviation the registry cannot see is a
second posture by the back door, so these tests are as much about the REGISTRY as about the defaults —
including a completeness floor, because a registry with no floor is exactly the shape that lets a later
switch be added at an insecure value with nothing reporting it.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.settings import (
    LOCKOUT_THRESHOLD_CEILING,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    EgressSettings,
    SecretRotationSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    _trust_every_peer_entries,
    load_settings,
    security_loosenings,
)
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.pipeline import Engine


def _ad(**over: object) -> AuthSettings:
    """AD-enabled auth settings with the connection essentials the model requires."""
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


def _pairs(
    sec: SecuritySettings | None = None,
    store: StoreSettings | None = None,
    auth: AuthSettings | None = None,
    alerts: AlertsSettings | None = None,
    rotation: SecretRotationSettings | None = None,
    cleartext_hops: tuple[str, ...] = (),
    expiry_hops: tuple[str, ...] = (),
    hostname_hops: tuple[str, ...] = (),
    query_hops: tuple[str, ...] = (),
    db_hops: tuple[str, ...] = (),
    attested_hops: tuple[str, ...] = (),
    revocation_hops: tuple[str, ...] = (),
    api: ApiSettings | None = None,
    approvals: ApprovalsSettings | None = None,
) -> list[tuple[str, str]]:
    """The loosening ``(switch, risk)`` pairs for a settings combination (defaults where not
    overridden)."""
    return security_loosenings(
        sec or SecuritySettings(),
        store or StoreSettings(),
        auth or AuthSettings(),
        alerts or AlertsSettings(),
        rotation or SecretRotationSettings(),
        cleartext_hops=cleartext_hops,
        expiry_relaxed_hops=expiry_hops,
        hostname_unchecked_hops=hostname_hops,
        query_credential_hops=query_hops,
        unverified_db_hops=db_hops,
        attested_hops=attested_hops,
        revocation_attested_hops=revocation_hops,
        api=api or ApiSettings(),
        approvals=approvals or ApprovalsSettings(),
        store_privilege=None,
        audit_chain_unkeyed=None,
        remote_debug=None,
        startup=None,
    )


def _names(**kwargs: object) -> list[str]:
    """The loosening SWITCH NAMES for a settings combination; arguments as :func:`_pairs`."""
    return [name for name, _ in _pairs(**kwargs)]  # type: ignore[arg-type]


def _risks(sec: SecuritySettings, auth: AuthSettings) -> dict[str, str]:
    """Switch name -> risk text, for a [security] and [auth] pair with every other input at default."""
    return dict(_pairs(sec=sec, auth=auth))


# --- the shipped defaults themselves ---------------------------------------------------------


def test_shipped_defaults_are_the_hardened_values() -> None:
    """Both flips, pinned at the model. A default that moves back reds here first."""
    settings = ServiceSettings()
    assert settings.store.aad_bind is True
    assert settings.auth.ad_session_recheck_seconds == 300


def test_the_shipped_defaults_are_not_themselves_loosenings() -> None:
    """The whole point: at the shipped defaults the registry reports NOTHING. If a hardened default
    were reported as a deviation, the list would be noise and operators would stop reading it."""
    assert _names() == []


# --- [store].aad_bind ------------------------------------------------------------------------


def test_aad_bind_off_is_a_named_loosening() -> None:
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(aad_bind=False),
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
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "aad_bind" in named
    # The risk text must say what is actually lost — cell binding, i.e. at-rest INTEGRITY binding — not
    # merely that a switch is off. An operator reading the serve warning gets this sentence and nothing
    # else; "aad_bind is false" would tell them nothing they did not already know.
    assert "cell" in named["aad_bind"]


def test_aad_bind_loosening_names_its_no_op_caveat() -> None:
    """It is a genuine no-op without a store key (the identity cipher has no tag to bind), and the risk
    text says so. Reporting it as a live weakness on a keyless dev box would train operators to ignore
    the list — the failure mode a loosening registry can least afford."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(aad_bind=False),
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
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "no effect without a store key" in named["aad_bind"]


# --- [auth].ad_session_recheck_seconds -------------------------------------------------------


def test_recheck_zero_with_ad_enabled_is_a_named_loosening() -> None:
    auth = _ad(ad_session_recheck_seconds=0)
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            auth,
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
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "ad_session_recheck_seconds" in named
    assert "revocation" in named["ad_session_recheck_seconds"]


def test_recheck_zero_without_ad_is_NOT_a_loosening() -> None:
    """CONDITIONAL, like allowed_client_networks. With no directory to reconcile against, 0 is not a
    weaker choice — it is the only meaningful one.

    This is the detector-can-fire half of the guard: a rule that fired on every non-AD deployment would
    be a permanent false positive, and a permanently-true warning is read as noise, not as signal."""
    assert "ad_session_recheck_seconds" not in _names(
        auth=AuthSettings(ad_session_recheck_seconds=0)
    )


def test_recheck_at_the_default_with_ad_enabled_is_not_a_loosening() -> None:
    assert "ad_session_recheck_seconds" not in _names(auth=_ad())


# --- [auth].admin_new_ip_step_up (BACKLOG #288) ----------------------------------------------


def test_new_ip_step_up_defaults_on() -> None:
    """BACKLOG #288 (owner ruling 2026-09-26): the mid-session new-address step-up ships ON."""
    assert AuthSettings().admin_new_ip_step_up is True
    assert "admin_new_ip_step_up" not in _names()


def test_new_ip_step_up_off_is_a_named_loosening() -> None:
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(admin_new_ip_step_up=False),
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
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "admin_new_ip_step_up" in named
    assert "new client address" in named["admin_new_ip_step_up"].lower()


# --- [auth] anti-automation limits (BACKLOG #1131; ASVS 6.1.1, 6.3.1, 2.3.2) --------------------
# Owner ruling 2026-09-27 (#2006): a silent weakening of an anti-automation control keeps its ASVS
# cell at partial. E16 named each value the code reads as OFF; a vault re-read then measured near-off
# values that were still silent (a 1e-6 s window, a count of 1e9), so every value LOOSER THAN THE
# SHIPPED DEFAULT is named now (Manager decision 2026-09-30), and a stricter one never is.

#: (field, value that turns it off). Zero is the documented off value; the other arms are the values
#: the code also reads as off (a window that prunes every hit, a lock that ends before now, a
#: threshold past NIST's ceiling, which never arms in practice).
_SIGN_IN_OFF_VALUES = [
    ("login_rate_limit_enabled", False),
    ("login_rate_limit_per_ip", 0),
    ("login_rate_limit_global", 0),
    ("login_rate_limit_window_seconds", 0.0),
    ("login_rate_limit_window_seconds", -1.0),
    ("login_rate_limit_window_seconds", float("-inf")),
    ("lockout_minutes", 0),
    ("lockout_minutes", -5),
    ("lockout_threshold", LOCKOUT_THRESHOLD_CEILING + 1),
    ("lockout_threshold", 1_000_000),
]

#: (field, value looser than its shipped default). Each is named ALONE under its own field. The
#: near-off values the vault measured as silent are here: a 1e-6 s window and counts of 1e9.
_LOOSER_THAN_DEFAULT = [
    ("login_rate_limit_per_ip", 11),
    ("login_rate_limit_per_ip", 1_000_000_000),
    ("login_rate_limit_global", 61),
    ("login_rate_limit_global", 1_000_000_000),
    ("login_rate_limit_window_seconds", 59.9),
    ("login_rate_limit_window_seconds", 1e-6),
    ("lockout_minutes", 14),
    ("lockout_minutes", 1),
    ("lockout_threshold", 6),
    ("lockout_threshold", LOCKOUT_THRESHOLD_CEILING),
    ("lockout_max_minutes", 1439),
    ("lockout_max_minutes", 15),  # equal to lockout_minutes: escalation off
    ("phi_read_rate_limit_enabled", False),
    ("phi_read_rate_limit_per_actor", 0),
    ("phi_read_rate_limit_per_actor", 121),
    ("phi_read_rate_limit_per_actor", 1_000_000_000),
    ("phi_read_rate_limit_window_seconds", 0.0),
    ("phi_read_rate_limit_window_seconds", -1.0),
    ("phi_read_rate_limit_window_seconds", 59.0),
    ("phi_read_rate_limit_window_seconds", 1e-6),
    ("admin_write_rate_limit_enabled", False),
    ("admin_write_rate_limit_per_actor", 0),
    ("admin_write_rate_limit_per_actor", 13),
    ("admin_write_rate_limit_per_actor", 1_000_000_000),
    ("admin_write_rate_limit_window_seconds", 14.0),
    ("admin_write_rate_limit_window_seconds", 0.2),  # still above the 0.15 s gap, so it loads
    ("admin_write_min_interval_seconds", 0.0),
    ("admin_write_min_interval_seconds", 0.1),
    ("mfa_verify_min_elapsed_seconds", 0.0),
    ("mfa_verify_min_elapsed_seconds", 0.5),
    ("mfa_verify_min_elapsed_seconds", 1e-6),
    ("max_sessions_per_user", 0),
    ("max_sessions_per_user", -1),
    ("max_sessions_per_user", 6),
    ("max_sessions_per_user", 1_000_000_000),
]

#: (field, value at or stricter than its shipped default). None is named. The defaults are listed
#: too, so a direction flipped to ">=" or "<=" reds here.
_STRICTER_OR_DEFAULT = [
    # A negative count refuses more, and a NaN or +inf window never prunes, so each refuses MORE.
    ("login_rate_limit_per_ip", 10),
    ("login_rate_limit_per_ip", 9),
    ("login_rate_limit_per_ip", 1),
    ("login_rate_limit_per_ip", -1),
    ("login_rate_limit_global", 60),
    ("login_rate_limit_global", 59),
    ("login_rate_limit_global", -1),
    ("login_rate_limit_window_seconds", 60.0),
    ("login_rate_limit_window_seconds", 61.0),
    ("login_rate_limit_window_seconds", float("inf")),
    ("login_rate_limit_window_seconds", float("nan")),
    ("lockout_minutes", 15),
    ("lockout_minutes", 16),
    # 0 or less locks on the FIRST failure.
    ("lockout_threshold", 5),
    ("lockout_threshold", 4),
    ("lockout_threshold", 0),
    ("lockout_threshold", -1),
    ("lockout_max_minutes", 1440),
    ("lockout_max_minutes", 1441),
    ("phi_read_rate_limit_per_actor", 120),
    ("phi_read_rate_limit_per_actor", 119),
    ("phi_read_rate_limit_per_actor", -1),
    # The all-users PHI-read count ships OFF, so no value of it is looser.
    ("phi_read_rate_limit_global", 0),
    ("phi_read_rate_limit_global", 1),
    ("phi_read_rate_limit_window_seconds", 60.0),
    ("phi_read_rate_limit_window_seconds", 61.0),
    ("phi_read_rate_limit_window_seconds", float("inf")),
    ("phi_read_rate_limit_window_seconds", float("nan")),
    ("admin_write_rate_limit_per_actor", 12),
    ("admin_write_rate_limit_per_actor", 11),
    ("admin_write_rate_limit_per_actor", -1),
    ("admin_write_rate_limit_window_seconds", 15.0),
    ("admin_write_rate_limit_window_seconds", 16.0),
    ("admin_write_min_interval_seconds", 0.15),
    ("admin_write_min_interval_seconds", 0.2),
    ("mfa_verify_min_elapsed_seconds", 1.0),
    ("mfa_verify_min_elapsed_seconds", 2.5),
    ("max_sessions_per_user", 5),
    ("max_sessions_per_user", 4),
    ("max_sessions_per_user", 1),
]
_SIGN_IN_FIELDS = {
    field for field, _ in _SIGN_IN_OFF_VALUES + _LOOSER_THAN_DEFAULT + _STRICTER_OR_DEFAULT
}


def _risk(auth: AuthSettings, switch: str) -> str | None:
    """The risk text ``security_loosenings()`` gives ``switch`` for ``auth``, or None."""
    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            auth,
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
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    ).get(switch)


def test_sign_in_limiter_and_lockout_defaults_are_not_loosenings() -> None:
    """The absent arm, at the shipped defaults: none of the new entries fires."""
    auth = AuthSettings()
    assert auth.login_rate_limit_enabled is True
    assert auth.login_rate_limit_per_ip == 10
    assert auth.login_rate_limit_global == 60
    assert auth.login_rate_limit_window_seconds == 60.0
    assert auth.lockout_minutes == 15
    assert auth.lockout_threshold == 5
    assert auth.lockout_max_minutes == 1440
    assert auth.phi_read_rate_limit_enabled is True
    assert auth.phi_read_rate_limit_per_actor == 120
    assert auth.phi_read_rate_limit_global == 0
    assert auth.phi_read_rate_limit_window_seconds == 60.0
    assert auth.admin_write_rate_limit_enabled is True
    assert auth.admin_write_rate_limit_per_actor == 12
    assert auth.admin_write_rate_limit_window_seconds == 15.0
    assert auth.admin_write_min_interval_seconds == 0.15
    assert auth.max_sessions_per_user == 5
    assert auth.oidc_flow_cache_max == 512
    assert not _SIGN_IN_FIELDS & set(_names())


@pytest.mark.parametrize(("field", "value"), _SIGN_IN_OFF_VALUES)
def test_each_sign_in_off_value_is_a_named_loosening(field: str, value: object) -> None:
    """The present arm: each off value is named, alone, under its own switch."""
    auth = AuthSettings(**{field: value})  # type: ignore[arg-type]
    risk = _risk(auth, field)
    assert risk is not None, f"[auth].{field} = {value!r} turns a sign-in control off, silently"
    # Only the switch that was set: an off value must not also report its siblings, and nothing
    # else in the registry may fire for an [auth]-only change.
    assert _names(auth=auth) == [field]


@pytest.mark.parametrize(("field", "value"), _LOOSER_THAN_DEFAULT)
def test_each_value_looser_than_the_default_is_a_named_loosening(field: str, value: object) -> None:
    """The present arm for a weak but non-zero value, which E16 left silent: named, alone."""
    auth = AuthSettings(**{field: value})  # type: ignore[arg-type]
    assert _risk(auth, field) is not None, f"[auth].{field} = {value!r} is looser, silently"
    assert _names(auth=auth) == [field]


@pytest.mark.parametrize(("field", "value"), _STRICTER_OR_DEFAULT)
def test_a_value_at_or_stricter_than_the_default_is_not_a_loosening(
    field: str, value: object
) -> None:
    """A value that refuses as much as the default, or more, is never named. E16 held
    lockout_minutes = 1 and a threshold of 100 here; both are looser than the default, so both moved
    to the list above."""
    assert _names(auth=AuthSettings(**{field: value})) == []  # type: ignore[arg-type]


def test_a_weak_value_says_looser_than_the_default_and_an_off_value_says_off() -> None:
    """One entry per setting, and its text tells the two cases apart."""
    weak = _risk(AuthSettings(login_rate_limit_per_ip=11), "login_rate_limit_per_ip")
    assert weak is not None
    assert "above the default of 10" in weak
    off = _risk(AuthSettings(login_rate_limit_per_ip=0), "login_rate_limit_per_ip")
    assert off is not None
    assert "no per-address sign-in limit" in off
    short = _risk(
        AuthSettings(login_rate_limit_window_seconds=1e-6), "login_rate_limit_window_seconds"
    )
    assert short is not None
    assert "shorter than the default of 60 s" in short
    flat = _risk(AuthSettings(lockout_max_minutes=15), "lockout_max_minutes")
    assert flat is not None
    assert "escalation is OFF" in flat
    lower = _risk(AuthSettings(lockout_max_minutes=60), "lockout_max_minutes")
    assert lower is not None
    assert "below the default of 1440" in lower
    # NIST is cited only past its own ceiling.
    t_weak = _risk(AuthSettings(lockout_threshold=6), "lockout_threshold")
    assert t_weak is not None
    assert "NIST" not in t_weak
    t_nist = _risk(AuthSettings(lockout_threshold=101), "lockout_threshold")
    assert t_nist is not None
    assert "NIST SP 800-63B" in t_nist


def test_the_near_off_values_the_vault_measured_are_named() -> None:
    """The three measured silent cases, together: each named under its own field."""
    named = _names(
        auth=AuthSettings(
            login_rate_limit_window_seconds=1e-6,
            login_rate_limit_global=1_000_000_000,
            login_rate_limit_per_ip=1_000_000_000,
        )
    )
    assert named == [
        "login_rate_limit_window_seconds",
        "login_rate_limit_per_ip",
        "login_rate_limit_global",
    ]
    # The admin-write window refuses 0 at load, so its near-off value is a tiny positive one; the
    # gap must then be shorter still, so it is named beside it.
    admin = _names(
        auth=AuthSettings(
            admin_write_rate_limit_window_seconds=1e-6, admin_write_min_interval_seconds=0
        )
    )
    assert admin == ["admin_write_rate_limit_window_seconds", "admin_write_min_interval_seconds"]


def test_the_threshold_ceiling_is_nists() -> None:
    """A pin, so an edit to the constant is a visible decision: NIST SP 800-63B-4 section 3.2.2 (5.2.2
    in rev. 3) caps consecutive failed attempts on one account at 100."""
    assert LOCKOUT_THRESHOLD_CEILING == 100


async def test_each_limiter_off_value_reaches_the_built_limiters(engine: Engine) -> None:
    """Ground the entries in AuthService's own wiring rather than in literal limiter arguments, so a
    change to how these settings reach the sign-in and ceremony limiters reds here.

    Each value the registry names must let far more than the default budget through the limiter it
    names, and the default must refuse inside that budget."""
    from messagefoundry.auth.service import AuthService

    def admitted(settings: AuthSettings, *, addresses: int, ceremony: bool = False) -> int:
        service = AuthService(engine.store, settings)
        if ceremony:
            return sum(service.allow_reauth_attempt("user-1") for _ in range(200))
        return sum(service.allow_login_attempt(f"10.0.0.{i % addresses}") for i in range(200))

    default = AuthSettings()
    assert admitted(default, addresses=1) == 10  # the per-address limit
    assert admitted(default, addresses=50) == 60  # the all-clients limit
    assert admitted(default, addresses=1, ceremony=True) == 10  # the per-user ceremony limit

    off = AuthSettings(login_rate_limit_enabled=False)
    assert admitted(off, addresses=1) == 200
    assert admitted(off, addresses=1, ceremony=True) == 200

    for window in (0.0, -1.0, float("-inf")):
        no_window = AuthSettings(login_rate_limit_window_seconds=window)
        assert admitted(no_window, addresses=1) == 200
        assert admitted(no_window, addresses=1, ceremony=True) == 200

    no_per_ip = AuthSettings(login_rate_limit_per_ip=0)
    assert admitted(no_per_ip, addresses=1) == 60  # only the all-clients limit holds
    assert admitted(no_per_ip, addresses=1, ceremony=True) == 200  # "the same number sets" it

    no_global = AuthSettings(login_rate_limit_global=0)
    assert admitted(no_global, addresses=50) == 200  # a spread spray is never refused

    # The values the registry does NOT name, because each refuses more: none may admit more than
    # the default does.
    for window in (float("nan"), float("inf")):
        unpruned = AuthSettings(login_rate_limit_window_seconds=window)
        assert admitted(unpruned, addresses=1) <= 10
        assert admitted(unpruned, addresses=50) <= 60
        assert admitted(unpruned, addresses=1, ceremony=True) <= 10
    assert admitted(AuthSettings(login_rate_limit_per_ip=-1), addresses=1) <= 10
    assert admitted(AuthSettings(login_rate_limit_per_ip=-1), addresses=1, ceremony=True) <= 10
    assert admitted(AuthSettings(login_rate_limit_global=-1), addresses=50) <= 60


@pytest.mark.parametrize("escalate", [True, False])
@pytest.mark.parametrize("minutes", [0, -5])
def test_a_zero_lockout_never_refuses_the_next_attempt(minutes: int, escalate: bool) -> None:
    """Ground the lockout entry in next_lockout_state: at 0 or less the lock is set, and the very
    next attempt finds it already lapsed, so the count restarts and no lock is live."""
    from messagefoundry.store.store import next_lockout_state

    locked = next_lockout_state(
        failed_attempts=4,
        locked_until=None,
        lock_cycles=0,
        now=1000.0,
        threshold=5,
        lockout_seconds=minutes * 60,
        max_lockout_seconds=1440 * 60,
        escalate=escalate,
        lockable=True,
    )
    assert locked.just_locked
    assert locked.locked_until is not None
    after = next_lockout_state(
        failed_attempts=locked.attempts,
        locked_until=locked.locked_until,
        lock_cycles=locked.cycles,
        now=1000.001,
        threshold=5,
        lockout_seconds=minutes * 60,
        max_lockout_seconds=1440 * 60,
        escalate=escalate,
        lockable=True,
    )
    # A live lock would keep counting past the threshold; a lapsed one restarts the count.
    assert after.attempts == 1
    assert after.locked_until is None
    assert not after.just_locked


def test_a_disabled_limiter_does_not_also_report_its_zeroed_parts() -> None:
    """With the limiter unbuilt, a zeroed per_ip, global or window changes nothing, so only the
    enable switch is named, as email_tls_verify is not named under a cleartext email_use_tls."""
    named = _names(
        auth=AuthSettings(
            login_rate_limit_enabled=False,
            login_rate_limit_per_ip=0,
            login_rate_limit_global=0,
            login_rate_limit_window_seconds=0.0,
        )
    )
    assert named == ["login_rate_limit_enabled"]


def test_both_zero_counts_are_each_named() -> None:
    named = _names(auth=AuthSettings(login_rate_limit_per_ip=0, login_rate_limit_global=0))
    assert named == ["login_rate_limit_per_ip", "login_rate_limit_global"]


def test_a_short_window_is_named_beside_its_loose_counts() -> None:
    """Only a window of 0 or less stands in for its counts. A merely short one still counts, so a
    loose count beside it is a second, separate loosening."""
    named = _names(
        auth=AuthSettings(login_rate_limit_window_seconds=30.0, login_rate_limit_per_ip=20)
    )
    assert named == ["login_rate_limit_window_seconds", "login_rate_limit_per_ip"]
    off = _names(auth=AuthSettings(login_rate_limit_window_seconds=0.0, login_rate_limit_per_ip=20))
    assert off == ["login_rate_limit_window_seconds"]


def test_a_short_window_over_counts_that_are_all_off_is_not_named() -> None:
    """Review round 2: a window paces only its counts. With every one at 0 it paces nothing, so
    naming it as looser would be a false warning; the zeroed counts are named instead."""
    assert _names(
        auth=AuthSettings(
            login_rate_limit_per_ip=0,
            login_rate_limit_global=0,
            login_rate_limit_window_seconds=1.0,
        )
    ) == ["login_rate_limit_per_ip", "login_rate_limit_global"]
    assert _names(
        auth=AuthSettings(phi_read_rate_limit_per_actor=0, phi_read_rate_limit_window_seconds=1.0)
    ) == ["phi_read_rate_limit_per_actor"]
    assert _names(
        auth=AuthSettings(
            admin_write_rate_limit_per_actor=0, admin_write_rate_limit_window_seconds=1.0
        )
    ) == ["admin_write_rate_limit_per_actor"]
    # One live count is enough for the window to matter again.
    assert _names(
        auth=AuthSettings(login_rate_limit_per_ip=0, login_rate_limit_window_seconds=1.0)
    ) == ["login_rate_limit_window_seconds", "login_rate_limit_per_ip"]
    assert _names(
        auth=AuthSettings(
            phi_read_rate_limit_per_actor=0,
            phi_read_rate_limit_global=50,
            phi_read_rate_limit_window_seconds=1.0,
        )
    ) == ["phi_read_rate_limit_window_seconds", "phi_read_rate_limit_per_actor"]


def test_a_disabled_or_windowless_limiter_does_not_also_report_its_parts() -> None:
    """The PHI-read and admin-write limiters follow the sign-in limiter's rule: with the limiter
    unbuilt, or its window at 0 or less, its parts change nothing and are not named."""
    assert _names(
        auth=AuthSettings(
            phi_read_rate_limit_enabled=False,
            phi_read_rate_limit_per_actor=0,
            phi_read_rate_limit_window_seconds=0.0,
        )
    ) == ["phi_read_rate_limit_enabled"]
    assert _names(
        auth=AuthSettings(
            phi_read_rate_limit_window_seconds=0.0, phi_read_rate_limit_per_actor=1_000_000
        )
    ) == ["phi_read_rate_limit_window_seconds"]
    assert _names(
        auth=AuthSettings(
            admin_write_rate_limit_enabled=False,
            admin_write_rate_limit_per_actor=0,
            admin_write_rate_limit_window_seconds=1.0,
            admin_write_min_interval_seconds=0.0,
        )
    ) == ["admin_write_rate_limit_enabled"]


def test_a_lock_that_never_holds_does_not_also_report_its_ceiling() -> None:
    """At lockout_minutes of 0 or less no lock holds, so the ceiling it doubles to changes nothing."""
    named = _names(auth=AuthSettings(lockout_minutes=0, lockout_max_minutes=0))
    assert named == ["lockout_minutes"]


def test_a_ceiling_at_the_default_or_above_is_not_named_even_with_escalation_off() -> None:
    """With lockout_minutes at or above the default ceiling, every lock already lasts at least as
    long as the default's longest, so a flat ceiling there is not looser than the default."""
    assert _names(auth=AuthSettings(lockout_minutes=1440, lockout_max_minutes=1440)) == []
    assert _names(auth=AuthSettings(lockout_minutes=2000, lockout_max_minutes=2000)) == []


def test_escalation_off_above_the_default_lock_names_only_the_ceiling() -> None:
    """A longer-than-default lock with escalation off: the lock is stricter, the ceiling is not."""
    auth = AuthSettings(lockout_minutes=16, lockout_max_minutes=16)
    assert _names(auth=auth) == ["lockout_max_minutes"]
    risk = _risk(auth, "lockout_max_minutes")
    assert risk is not None
    assert "escalation is OFF" in risk


def test_a_short_lock_with_the_default_ceiling_names_only_the_lock() -> None:
    assert _names(auth=AuthSettings(lockout_minutes=1, lockout_max_minutes=1440)) == [
        "lockout_minutes"
    ]


def _oidc(**over: object) -> AuthSettings:
    """OIDC-enabled auth settings with the fields the model requires (it needs AD for roles)."""
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
        "ad_domain": "test.invalid",  # the UPN suffix the username allow-list falls back to
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.test.invalid",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "synthetic",
        "oidc_authorization_endpoint": "https://idp.test.invalid/authorize",
        "oidc_token_endpoint": "https://idp.test.invalid/token",
        "oidc_jwks_uri": "https://idp.test.invalid/jwks",
        "oidc_allowed_endpoints": ["idp.test.invalid"],
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("cap", "named"),
    [
        (512, False),  # the default
        (511, False),
        (1, False),
        # FlowCache refuses at len >= cap, so 0 or less refuses EVERY flow: stricter, not off.
        (0, False),
        (-1, False),
        (513, True),
        (1_000_000_000, True),  # the value the vault measured as silently lifting the cap
    ],
)
def test_the_oidc_flow_cache_cap_is_named_only_above_its_default(cap: int, named: bool) -> None:
    got = _names(auth=_oidc(oidc_flow_cache_max=cap))
    assert got == (["oidc_flow_cache_max"] if named else [])


@pytest.mark.parametrize(
    ("floor", "named"),
    [
        (1.0, False),  # the default
        (2.5, False),  # stricter; the load keeps it below the flow lifetime
        (0.5, True),
        (1e-6, True),
        (0.0, True),  # off
    ],
)
def test_the_oidc_callback_floor_is_named_only_below_its_default(floor: float, named: bool) -> None:
    got = _names(auth=_oidc(oidc_callback_min_elapsed_seconds=floor))
    assert got == (["oidc_callback_min_elapsed_seconds"] if named else [])


def test_the_oidc_callback_floor_is_not_named_without_oidc() -> None:
    """The flows it floors exist only with OIDC on."""
    assert _names(auth=AuthSettings(oidc_callback_min_elapsed_seconds=0)) == []


def test_a_time_floor_says_off_at_zero_and_looser_below_the_default() -> None:
    off = _risk(AuthSettings(mfa_verify_min_elapsed_seconds=0), "mfa_verify_min_elapsed_seconds")
    assert off is not None
    assert "there is no least time" in off
    weak = _risk(AuthSettings(mfa_verify_min_elapsed_seconds=0.5), "mfa_verify_min_elapsed_seconds")
    assert weak is not None
    assert "shorter than the default of 1 s" in weak


def test_the_second_factor_floor_entry_never_quotes_the_configured_value() -> None:
    """PR 1842: CodeQL reads an mfa_* attribute as a password source, and this entry reaches the
    serve WARNING and stdout, so the configured number must stay out of it. The other floors still
    quote theirs (the control arm), so a text that dropped every value would not pass either."""
    mfa = _risk(AuthSettings(mfa_verify_min_elapsed_seconds=0.37), "mfa_verify_min_elapsed_seconds")
    assert mfa is not None
    assert "0.37" not in mfa
    gap = _risk(
        AuthSettings(admin_write_min_interval_seconds=0.037), "admin_write_min_interval_seconds"
    )
    assert gap is not None
    assert "0.037" in gap


def test_the_oidc_flow_cache_cap_is_not_named_without_oidc() -> None:
    """The cache is built only with OIDC on, so the cap is inert without it."""
    assert _names(auth=AuthSettings(oidc_flow_cache_max=1_000_000_000)) == []


# --- [approvals]: the dual-control dwell floor and expiry ceiling (BACKLOG #2489) -------------------

_HELD = ["dead_letter_replay"]


def _approvals(**over: float) -> ApprovalsSettings:
    """Dual control ON with one held operation, so its limits are live."""
    return ApprovalsSettings(enabled=True, operations=_HELD, **over)


@pytest.mark.parametrize(
    ("floor", "named"),
    [
        (2.0, False),  # the default
        (5.0, False),  # stricter
        (1.9, True),
        (1e-6, True),
        (0.0, True),  # off
    ],
)
def test_the_approval_dwell_is_named_only_below_its_default(floor: float, named: bool) -> None:
    got = _names(approvals=_approvals(min_dwell_seconds=floor))
    assert got == (["min_dwell_seconds"] if named else [])


@pytest.mark.parametrize(
    ("hours", "named"),
    [
        (72.0, False),  # the default
        (1.0, False),  # stricter
        (72.5, True),
        (0.0, True),  # never expires
    ],
)
def test_the_approval_expiry_is_named_only_above_its_default(hours: float, named: bool) -> None:
    got = _names(approvals=_approvals(expiry_hours=hours))
    assert got == (["expiry_hours"] if named else [])


def test_the_approval_limits_are_not_named_while_dual_control_holds_nothing() -> None:
    """Dual control ships OFF, so off is the shipped posture and its limits change nothing. The
    third call is the control: the same values with an operation held are named."""
    off = ApprovalsSettings(min_dwell_seconds=0.0, expiry_hours=0.0)
    assert _names(approvals=off) == []
    no_ops = ApprovalsSettings(enabled=True, operations=[], min_dwell_seconds=0.0, expiry_hours=0.0)
    assert _names(approvals=no_ops) == []
    held = _approvals(min_dwell_seconds=0.0, expiry_hours=0.0)
    assert _names(approvals=held) == ["min_dwell_seconds", "expiry_hours"]


def test_the_approval_entries_say_off_at_zero_and_quote_a_looser_value() -> None:
    def risks(approvals: ApprovalsSettings) -> dict[str, str]:
        return dict(_pairs(approvals=approvals))

    off = risks(_approvals(min_dwell_seconds=0.0, expiry_hours=0.0))
    assert "the moment it is made" in off["min_dwell_seconds"]
    assert "never expires" in off["expiry_hours"]
    weak = risks(_approvals(min_dwell_seconds=0.5, expiry_hours=96.0))
    assert "0.5 s after it is made, sooner than the default of 2 s" in weak["min_dwell_seconds"]
    assert "96 h, longer than the default of 72 h" in weak["expiry_hours"]
    # A value just past the default must not print as the default.
    near = risks(_approvals(min_dwell_seconds=1.9999999, expiry_hours=72.0000001))
    assert "1.9999999 s" in near["min_dwell_seconds"]
    assert "72.0000001 h" in near["expiry_hours"]


async def test_posture_route_reports_the_approval_dwell_the_app_was_built_with(
    engine: Engine,
) -> None:
    """The route reads the [approvals] the app's approval gate enforces, not a default. The
    default app is the control."""

    async def switches(approvals: ApprovalsSettings | None = None) -> list[str]:
        app = create_app(engine, allow_no_auth=True, approvals=approvals)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await client.get("/security/posture")
        assert resp.status_code == 200
        return [entry["switch"] for entry in resp.json()["loosenings"]]

    loose = await switches(_approvals(min_dwell_seconds=0.0, expiry_hours=0.0))
    assert {"min_dwell_seconds", "expiry_hours"} <= set(loose)
    default = await switches()
    assert "min_dwell_seconds" not in default and "expiry_hours" not in default


def test_a_zero_flow_cache_cap_refuses_every_flow() -> None:
    """Ground the direction in FlowCache: 0 is stricter, which is why it is not named."""
    from messagefoundry.auth.oidc.flow import FlowCache, FlowCacheFullError, PendingFlow

    flow = PendingFlow(
        state="s",
        nonce="n",
        code_verifier="v",
        return_to="/ui",
        client_ip="10.0.0.1",
        deadline=0.0,
    )
    FlowCache(global_cap=1).put("flow-0", flow)  # the control: a cap of 1 admits one
    for cap in (0, -1):
        with pytest.raises(FlowCacheFullError):
            FlowCache(global_cap=cap).put("flow-1", flow)


async def test_near_off_values_admit_what_the_default_refuses(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ground the near-off entries in AuthService's own limiters. A fake clock steps 1 ms per call,
    so the measurement does not depend on the host's timer resolution; it replaces the name only
    inside the limiter module, never the event loop's clock."""
    import types

    from messagefoundry.auth import ratelimit
    from messagefoundry.auth.service import AuthService

    ticks = iter(range(10**9))
    monkeypatch.setattr(
        ratelimit, "time", types.SimpleNamespace(monotonic=lambda: next(ticks) / 1000)
    )

    def admitted(settings: AuthSettings, leg: str, *, addresses: int = 1) -> int:
        service = AuthService(engine.store, settings)
        calls = {
            "login": lambda i: service.allow_login_attempt(f"10.0.0.{i % addresses}"),
            "ceremony": lambda i: service.allow_reauth_attempt("user-1"),
            "phi": lambda i: service.allow_phi_read("user-1"),
            "admin": lambda i: service.allow_admin_write("user-1"),
        }
        return sum(calls[leg](i) for i in range(200))

    default = AuthSettings()
    assert admitted(default, "login") == 10
    assert admitted(default, "login", addresses=50) == 60
    assert admitted(default, "ceremony") == 10
    assert admitted(default, "phi") == 120
    assert admitted(default, "admin") == 2  # the 0.15 s gap: t = 0 and t = 0.15 of a 0.2 s burst

    tiny = AuthSettings(login_rate_limit_window_seconds=1e-6)
    assert admitted(tiny, "login") == 200
    assert admitted(tiny, "ceremony") == 200
    assert admitted(AuthSettings(login_rate_limit_per_ip=1_000_000_000), "login") == 60
    assert admitted(AuthSettings(login_rate_limit_per_ip=1_000_000_000), "ceremony") == 200
    huge_global = AuthSettings(login_rate_limit_global=1_000_000_000)
    assert admitted(huge_global, "login", addresses=50) == 200
    assert admitted(AuthSettings(phi_read_rate_limit_window_seconds=1e-6), "phi") == 200
    assert admitted(AuthSettings(phi_read_rate_limit_per_actor=1_000_000_000), "phi") == 200
    no_gap = AuthSettings(admin_write_min_interval_seconds=0)
    assert admitted(no_gap, "admin") == 12
    near_off = AuthSettings(
        admin_write_rate_limit_window_seconds=1e-6, admin_write_min_interval_seconds=0
    )
    assert admitted(near_off, "admin") == 200


# --- [api].trusted_proxies with a prefix of 0 (BACKLOG #1131) ----------------------------------


def _proxied(*entries: str) -> ApiSettings:
    return ApiSettings(tls_terminated_upstream=True, trusted_proxies=list(entries))


@pytest.mark.parametrize("entry", ["0.0.0.0/0", "::/0"])
def test_a_trust_every_peer_proxy_entry_is_a_named_loosening(entry: str) -> None:
    """A prefix of 0 trusts X-Forwarded-For from every peer of its family, as the refused '*' does.
    It still loads (this change names it, it does not refuse it)."""
    api = _proxied("10.0.0.1", entry)
    assert _names(api=api) == ["trusted_proxies"]


@pytest.mark.parametrize(
    "entry",
    [
        "10.0.0.1",
        "10.0.0.0/8",
        "::1",
        "fd00::/8",
    ],
)
def test_a_bounded_proxy_entry_is_not_a_loosening(entry: str) -> None:
    assert _names(api=_proxied(entry)) == []


def test_the_trust_every_peer_check_skips_a_host_bits_entry() -> None:
    """A host-bits entry no longer loads (BACKLOG #2488), so this arm moved off ``ApiSettings``. The
    helper still reads entries as uvicorn does, where ``10.1.2.3/0`` is a literal that trusts no
    peer, so it must not be named as covering every address."""
    assert _trust_every_peer_entries(["10.1.2.3/0"]) == []
    assert _trust_every_peer_entries(["10.1.2.3/0", "0.0.0.0/0"]) == ["0.0.0.0/0"]


def _split(network: str, bits: int) -> list[str]:
    """``network`` cut into 2**bits equal ranges. Built rather than written out, so the file carries
    no routable address literal for the forbidden-content scan to stop on."""
    return [str(n) for n in ipaddress.ip_network(network).subnets(prefixlen_diff=bits)]


@pytest.mark.parametrize(
    "entries",
    [
        _split("0.0.0.0/0", 1),
        _split("::/0", 1),
        ["10.0.0.1", *_split("0.0.0.0/0", 2)],
    ],
)
def test_ranges_whose_union_covers_a_family_are_a_named_loosening(entries: list[str]) -> None:
    """Review round 1: two halves trust every peer as surely as one /0 does."""
    risk = dict(
        security_loosenings(
            SecuritySettings(),
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
            api=_proxied(*entries),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    ).get("trusted_proxies")
    assert risk is not None
    # Every range in the union is named, so a regression naming only one half reds here.
    for entry in entries:
        if ipaddress.ip_network(entry).num_addresses > 1:
            assert entry in risk
    # The single-host proxy entry adds nothing to the union, so it is not blamed.
    assert "10.0.0.1" not in risk


def test_a_repeated_trust_every_peer_entry_is_named_once() -> None:
    risk = dict(
        security_loosenings(
            SecuritySettings(),
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
            api=_proxied("::/0", "::/0"),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )["trusted_proxies"]
    assert risk.count("::/0") == 1


def test_ranges_that_leave_a_gap_are_not_a_loosening() -> None:
    assert _names(api=_proxied(*_split("0.0.0.0/0", 2)[:3])) == []
    # Two families never union into one.
    assert _names(api=_proxied(_split("0.0.0.0/0", 1)[0], _split("::/0", 1)[1])) == []


def test_uvicorn_reads_a_prefix_zero_entry_the_way_the_registry_does() -> None:
    """Ground the discriminator in uvicorn's own parser, which __main__ hands the list verbatim."""
    from uvicorn.middleware.proxy_headers import _TrustedHosts

    assert "203.0.113.9" in _TrustedHosts(["0.0.0.0/0"])
    assert "2001:db8::9" in _TrustedHosts(["::/0"])
    assert "203.0.113.9" not in _TrustedHosts(["10.1.2.3/0"])
    halves = _TrustedHosts(_split("0.0.0.0/0", 1))
    assert "10.9.9.9" in halves
    assert "203.0.113.9" in halves


# --- [api].plaintext_upstream_hop_acknowledged (BACKLOG #1179) --------------------------------
# Owner ruling 2026-09-27 (#2006 question (a)): a silent weakening keeps ASVS 12.3.3 at partial.
# The acknowledgement is therefore a listed loosening, as the #1967 retention acknowledgements are.


def _terminated(*, ack: bool, cert: bool = False) -> ApiSettings:
    """A declared upstream terminator, optionally acknowledged and optionally with an operator cert.

    The cert paths are never opened here: api_tls_source reads only whether one is configured."""
    fields: dict[str, object] = {
        "tls_terminated_upstream": True,
        "trusted_proxies": ["10.0.0.1"],
        "plaintext_upstream_hop_acknowledged": ack,
    }
    if cert:
        fields["tls_cert_file"] = "operator-cert.pem"
        fields["tls_key_file"] = "operator-key.pem"
    return ApiSettings(**fields)  # type: ignore[arg-type]


def test_the_plaintext_hop_acknowledgement_is_a_named_loosening() -> None:
    named = dict(
        security_loosenings(
            SecuritySettings(),
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
            api=_terminated(ack=True),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    risk = named["plaintext_upstream_hop_acknowledged"]
    # What the site gives up, not merely that a switch is set: the hop is plaintext and unprotected.
    assert "PLAINTEXT" in risk
    assert "deploying site's job" in risk
    assert "tls_cert_file" in risk


def test_the_plaintext_hop_acknowledgement_is_not_reported_when_unset() -> None:
    """The negative control. The shipped [api] defaults acknowledge nothing, and a terminator with no
    acknowledgement is not a loosening here: serve REFUSES it, so there is no weakening to report."""
    assert "plaintext_upstream_hop_acknowledged" not in _names()
    assert "plaintext_upstream_hop_acknowledged" not in _names(api=_terminated(ack=False))


def test_the_plaintext_hop_acknowledgement_is_not_reported_when_a_cert_serves_the_hop() -> None:
    """With an operator tls_cert_file the engine serves that hop over TLS (api_tls_source's order), so
    the acknowledgement is inert and reporting it would name a weakening that does not exist."""
    assert "plaintext_upstream_hop_acknowledged" not in _names(api=_terminated(ack=True, cert=True))
    # The control that makes the zero above mean something: the same object without the cert fires.
    assert "plaintext_upstream_hop_acknowledged" in _names(api=_terminated(ack=True))


# --- [auth].ad_allow_insecure_ldap: inert under enforce (vault BACKLOG #2354) -------------------
#
# The MEFOR_ALLOW_INSECURE_TLS escape is clamped under [security].enforcement = enforce. This one used to be
# honoured at any dial, so on a first deployment it would have sent both passwords over a cleartext
# SIMPLE bind. The enforce arm is the one the clamp exists for; the warn arm is the control that shows
# the same config loads when only the dial moves, so the refusal is keyed on the dial.


_PLAIN_LDAP_AUTH = """
[auth]
ad_enabled = true
ad_server = "ldap://dc.test.invalid:389"
ad_user_search_base = "OU=Staff,DC=test,DC=invalid"
ad_bind_dn = "CN=svc-mefor,OU=Service,DC=test,DC=invalid"
ad_allow_insecure_ldap = true
"""

#: The bind password comes from the env, as the docs say, so no file-secret warning is involved.
_BIND_ENV = {"MEFOR_AUTH_AD_BIND_PASSWORD": "synthetic"}


def _load_plain_ldap(tmp_path: Path, enforcement: str) -> ServiceSettings:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(
        f'[security]\nenforcement = "{enforcement}"\n{_PLAIN_LDAP_AUTH}', encoding="utf-8"
    )
    return load_settings(config_path=path, environ=_BIND_ENV)


def test_plain_ldap_with_the_opt_in_is_refused_at_load_under_enforce(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="ad_allow_insecure_ldap is inert under"):
        _load_plain_ldap(tmp_path, "enforce")


@pytest.mark.parametrize(
    ("prefix", "server"),
    [
        # A loopback ldap:// (an on-box LDAPS proxy): the cleartext-hop gradient's loopback ALLOW was
        # deliberately not extended to this hop.
        ("", "ldap://127.0.0.1:389"),
        # The sign-in-off case that sat here went with the switch (vault BACKLOG #2719): no config
        # can turn sign-in off any more.
    ],
    ids=["loopback"],
)
def test_the_enforce_refusal_has_no_loopback_carve_out(
    tmp_path: Path, prefix: str, server: str
) -> None:
    path = tmp_path / "messagefoundry.toml"
    body = _PLAIN_LDAP_AUTH.replace("ldap://dc.test.invalid:389", server)
    path.write_text(prefix + body, encoding="utf-8")
    with pytest.raises(ValueError, match="ad_allow_insecure_ldap is inert under"):
        load_settings(config_path=path, environ=_BIND_ENV)


def test_surrounding_whitespace_does_not_hide_an_ldaps_address() -> None:
    """ldap3 strips the address before it reads the scheme, so the engine must too: otherwise a
    padded ldaps:// address reads as plain here and gets ldap3's unverified default TLS there."""
    from messagefoundry.config.settings import is_ldaps_address

    assert is_ldaps_address("  ldaps://dc.test.invalid ")
    assert not is_ldaps_address(" ldap://dc.test.invalid")
    assert not _ad(ad_server=" ldaps://dc.test.invalid:636").plain_ldap_bind


def test_plain_ldap_with_the_opt_in_loads_under_warn_and_is_named(tmp_path: Path) -> None:
    """The control arm: the same config, with only the dial moved, loads and is reported."""
    settings = _load_plain_ldap(tmp_path, "warn")
    assert settings.auth.plain_ldap_bind is True
    assert "cleartext" in _risks(settings.security, settings.auth)["ad_allow_insecure_ldap"]


def test_a_bare_host_with_no_scheme_is_a_plain_bind(tmp_path: Path) -> None:
    """ldap3 dials a scheme-less host on 389 with no TLS, even one whose name starts with "ldaps"."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(
        _PLAIN_LDAP_AUTH.replace("ldap://dc.test.invalid:389", "ldapsrv01.test.invalid"),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="ad_allow_insecure_ldap is inert under"):
        load_settings(config_path=path, environ=_BIND_ENV)


def test_an_ldaps_server_under_enforce_still_loads(tmp_path: Path) -> None:
    """The refusal keys on the plain bind, not on the flag: beside an ldaps:// address the opt-in does
    nothing, so it neither refuses nor reports."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(_PLAIN_LDAP_AUTH.replace("ldap://", "ldaps://"), encoding="utf-8")
    settings = load_settings(config_path=path, environ=_BIND_ENV)
    assert settings.auth.plain_ldap_bind is False
    assert "ad_allow_insecure_ldap" not in _names(auth=settings.auth)


def test_the_opt_in_with_ad_off_is_not_a_loosening() -> None:
    assert "ad_allow_insecure_ldap" not in _names(auth=AuthSettings(ad_allow_insecure_ldap=True))


def test_the_authenticator_refuses_a_plain_bind_at_the_enforcing_default() -> None:
    """The build-time repeat, for a caller that hands LdapAuthenticator an AuthSettings alone and so
    never passes through ServiceSettings. Its dial defaults to enforce, so omitting it refuses."""
    from messagefoundry.auth.ldap import LdapAuthenticator, LdapError

    auth = _ad(ad_server="ldap://dc.test.invalid:389", ad_allow_insecure_ldap=True)
    with pytest.raises(LdapError, match="inert under"):
        LdapAuthenticator(auth)
    with pytest.raises(LdapError, match="inert under"):
        LdapAuthenticator(auth, enforcing=True)
    # Either dial input saying enforce refuses: a known enforcing posture wins over enforcing=False.
    with pytest.raises(LdapError, match="inert under"):
        LdapAuthenticator(auth, enforcing=False, posture=HopPosture(enforcing=True))
    # A bare host that starts with "ldaps" is still a plain bind.
    with pytest.raises(LdapError, match="inert under"):
        LdapAuthenticator(_ad(ad_server="ldapsrv01.test.invalid", ad_allow_insecure_ldap=True))


def test_a_refused_plain_bind_never_resolves_the_bind_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal runs before the secret fetch, so a build about to refuse holds no password."""
    from messagefoundry.auth import ldap as ldap_module

    calls: list[object] = []
    monkeypatch.setattr(ldap_module, "resolve_connector_secret", lambda *a, **k: calls.append(a))
    auth = _ad(ad_server="ldap://dc.test.invalid:389", ad_allow_insecure_ldap=True)
    with pytest.raises(ldap_module.LdapError, match="inert under"):
        ldap_module.LdapAuthenticator(auth)
    assert calls == []


def test_the_authenticator_wants_the_opt_in_even_with_ad_off() -> None:
    """AuthSettings checks the opt-in only while ad_enabled; a direct build must not assume it."""
    from messagefoundry.auth.ldap import LdapAuthenticator, LdapError

    auth = _ad(ad_enabled=False, ad_server="ldap://dc.test.invalid:389")
    with pytest.raises(LdapError, match="needs ad_allow_insecure_ldap"):
        LdapAuthenticator(auth, enforcing=False)


def test_the_authenticator_honours_a_plain_bind_under_warn_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from messagefoundry.auth.ldap import LdapAuthenticator

    auth = _ad(ad_server="ldap://dc.test.invalid:389", ad_allow_insecure_ldap=True)
    with caplog.at_level("WARNING", logger="messagefoundry.auth.ldap"):
        LdapAuthenticator(auth, enforcing=False)
    assert any(
        r.levelname == "WARNING" and "plain ldap://" in r.getMessage() for r in caplog.records
    )


# --- the cross-field refusal, keyed on model_fields_set ---------------------------------------
#
# These go through load_settings, NOT the constructor. Constructing AuthSettings(...) in Python marks
# every passed field as "set", so a constructor-only test cannot distinguish the shipped default from an
# explicitly-typed 300 — which is the entire distinction the guard turns on. It would pass while proving
# nothing.


def _load(
    tmp_path: Path, toml: str, cli: dict[str, dict[str, object]] | None = None
) -> ServiceSettings:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(toml, encoding="utf-8")
    # environ={} so an ambient MEFOR_* on the developer's box cannot move the posture under the test.
    return load_settings(config_path=path, cli=cli, environ={})


def test_shipped_default_does_not_break_a_non_ad_deployment(tmp_path: Path) -> None:
    """The reason the refusal had to be re-keyed: with a non-zero SHIPPED default, an unconditional
    'requires ad_enabled' rule would fail startup on every deployment that does not use AD."""
    # `local_users` was not an AuthSettings field, so this fixture used to say nothing at all — the very
    # silence the unknown-key refusal now removes. `ad_enabled = false` states "no AD" in a real field.
    settings = _load(tmp_path, "[auth]\nad_enabled = false\n")
    assert settings.auth.ad_session_recheck_seconds == 300
    assert settings.auth.ad_enabled is False


def test_explicit_value_without_ad_still_refuses(tmp_path: Path) -> None:
    """THE test that proves the guard still bites. An operator who typed a value believes directory
    revocation now propagates; a silently-dead security control is worse than one never enabled.

    Note the value is the SAME as the shipped default — so this can only pass if the check keys on
    `model_fields_set` rather than on the value."""
    with pytest.raises(ValueError, match="ad_session_recheck_seconds requires ad_enabled"):
        _load(tmp_path, "[auth]\nad_session_recheck_seconds = 300\n")


def test_explicit_zero_without_ad_loads(tmp_path: Path) -> None:
    """Explicitly disabling the loop on a non-AD box is coherent, not an error — there is nothing to
    reconcile, and the operator has asserted no belief the refusal needs to falsify."""
    settings = _load(tmp_path, "[auth]\nad_session_recheck_seconds = 0\n")
    assert settings.auth.ad_session_recheck_seconds == 0


# --- the CLI bind override, reconciled back into [security] (BACKLOG #1852) --------------------
#
# These pin `_reconcile_effective_bind` in BOTH directions; that helper's docstring carries the defect
# and the reasoning. A fix that simply reported everything would pass the positive arm and be worthless,
# which is what the negative arms below are for.


def _cli_host(host: str) -> dict[str, dict[str, object]]:
    """The exact `cli` shape `serve` builds for `--host` (``__main__``: ``cli["api"]["host"]``)."""
    return {"api": {"host": host}}


def test_off_box_host_override_is_reported_as_a_loosening(tmp_path: Path) -> None:
    """THE defect. With no `[security]` block at all, `--host 0.0.0.0` must name BOTH entries: the bind
    itself, and the empty source-network allow-list that is only a weakness once exposed."""
    settings = _load(tmp_path, "", cli=_cli_host("0.0.0.0"))
    assert settings.api.host == "0.0.0.0"
    assert settings.security.local_access_only is False
    # `listen_address` is documented as the address used once `local_access_only` is false, so leaving
    # it on loopback while the socket is on 0.0.0.0 would have the posture view state a falsehood: an
    # operator reading it would believe the bind is narrower than it is.
    assert settings.security.listen_address == "0.0.0.0"
    names = _names(sec=settings.security)
    assert "local_access_only" in names
    assert "allowed_client_networks" in names


def test_loopback_bind_reports_neither_entry(tmp_path: Path) -> None:
    """The NEGATIVE arm, without which the test above passes on a registry that reports everything
    always. Both an absent `--host` and an explicit loopback one stay quiet."""
    assert _names(sec=_load(tmp_path, "").security) == []
    assert _names(sec=_load(tmp_path, "", cli=_cli_host("127.0.0.1")).security) == []


def test_declared_off_box_posture_survives_a_loopback_bind(tmp_path: Path) -> None:
    """The reconciliation is ONE-WAY. An operator may declare `local_access_only = false` and leave
    `listen_address` at its loopback default; the effective bind is then loopback, and reconciling in
    that direction would SUPPRESS a deviation they declared. The registry must keep reporting it."""
    settings = _load(tmp_path, "[security]\nlocal_access_only = false\n")
    assert settings.api.is_loopback is True
    assert settings.security.local_access_only is False
    assert settings.security.listen_address == "127.0.0.1"
    names = _names(sec=settings.security)
    assert "local_access_only" in names
    assert "allowed_client_networks" in names


def test_off_box_override_still_honours_a_declared_client_allowlist(tmp_path: Path) -> None:
    """The allow-list entry is exposure-GATED, not unconditional: an operator who exposed the bind AND
    listed the networks that may reach it has the guard-rail, so only the bind itself is reported.
    Without this arm the exposure gate could be replaced by an unconditional append and nothing would
    notice."""
    settings = _load(
        tmp_path,
        '[security]\nallowed_client_networks = ["10.20.0.0/16"]\n',
        cli=_cli_host("0.0.0.0"),
    )
    names = _names(sec=settings.security)
    assert "local_access_only" in names
    assert "allowed_client_networks" not in names


# --- registry completeness --------------------------------------------------------------------


def test_every_security_bool_at_its_insecure_value_is_reported() -> None:
    """A COMPLETENESS FLOOR for the registry, which otherwise has none.

    Nothing else asserts that `security_loosenings()` can SEE every switch. Under "one posture, loosen
    only", a registry with no floor is the leak-gate-blindness shape: a switch added later at an insecure
    value would simply never be reported, and the green list would keep saying "no deviations".

    Scope, stated honestly: this covers the BOOLEAN `[security]` switches whose insecure value is the
    negation of their default — the mechanical majority. Non-boolean knobs (timeouts, day counts) and the
    deliberately-conditional entries have their own targeted tests above and below; they are listed here
    as exemptions so the exemption itself is visible rather than an accident of the loop."""
    #: Bools this floor deliberately does NOT require, each with the reason it is exempt.
    exempt = {
        # `audit_all_authorization_decisions` USED TO SIT HERE, and its removal is the point of BACKLOG
        # #1277 rather than a tidy-up. The reason it carried was "turning it ON is the hardening move,
        # not the loosening" — true only while the default was `false`. The default is `true` now, so
        # `false` is the insecure value and the loop below requires the registry to name it.
        # ADR 0152: these ASSERT / REQUIRE a host property rather than giving one up. Neither is a
        # loosening at either value; both are documented as such.
        "memory_encryption_operator_declared",
        "require_memory_encryption_declaration",
        # BACKLOG #1182: the opt-in static-credential refusal TIGHTENS. Its opt-outs are what the
        # registry names (as `static_credential_accepted`), and only while it is on.
        "require_nonstatic_credentials",
        # ADR 0143: disabling the console SHRINKS attack surface — the opposite of a loosening.
        "serve_web_console",
        # The data-class lever has its own entry keyed on the derived posture, not a plain negation.
        "handles_real_patient_data",
        "production_instance",
    }
    for field, info in SecuritySettings.model_fields.items():
        if field in exempt or not isinstance(info.default, bool):
            continue
        flipped = SecuritySettings(**{field: not info.default})
        assert field in _names(sec=flipped), (
            f"[security].{field} at its insecure value ({not info.default}) is NOT named by "
            "security_loosenings(). Add it to the registry, or add it to this test's `exempt` set "
            "with the reason it is not a loosening — silence is not an option."
        )


#: Every per-connection parameter name the connection-factory census below classifies, mapped to the
#: reader that reports it. #333 step 7: the `[security]`/`[store]`/`[auth]` floors iterate
#: `model_fields`, so a CONNECTION-scoped deviation is outside their reach BY CONSTRUCTION — which is
#: exactly why `cleartext_accepted` needed a hand-written entry, why `tls_allow_expired` and the
#: generic-ODBC hop had none for as long as they did, and why nothing would have caught the next one.
_CONNECTION_DEVIATIONS_REPORTED = {
    "cleartext_accepted": "accepted_cleartext_hops",
    "tls_allow_expired": "expiry_relaxed_hops",
    # Owner ruling 2026-09-24: the hop attestation got a factory surface, so it is reported.
    "tls_hop_attested": "attested_secure_hops",
    "tls_revocation_attested": "revocation_attested_hops",
    # ASVS 12.3.2 re-read, 2026-10-01. CORRECTED: this was exempt below as "gated by the same ADR
    # 0092 hop cell", which was false -- that cell keys on cleartext and verify-off, never on the
    # name check, so the flag was accepted with no line on any surface.
    "tls_check_hostname": "hostname_unchecked_hops",
}

#: Per-connection parameters the readers do NOT report, each with the reason. Same discipline as the
#: `[store]`/`[auth]` exemption sets: the gap is a written decision a new parameter cannot silently
#: join, not an accident of a regex.
_CONNECTION_DEVIATIONS_EXEMPT = {
    # Not switches — the reason string beside a declaration, and TLS key/cert material or paths.
    "cleartext_reason": "the reason text for cleartext_accepted, not a second switch",
    "tls_hop_attested_reason": "the reason text for tls_hop_attested, not a second switch",
    "tls_cert_file": "material/path, not a posture switch",
    "tls_key_file": "material/path, not a posture switch",
    "tls_key_password": "material/path, not a posture switch",
    "tls_ca_file": "material/path, not a posture switch",
    # BACKLOG #1142, slice 3. A TIGHTENING, like tls_ciphers below: a set pin refuses any other
    # bytes, and the one thing it relaxes (an unreadable ACL or path loads, with a warning and a
    # pinned=true audit row) is reported by that row rather than by a posture reader.
    "tls_ca_pin": "SHA-256 of tls_ca_file: a tightening; its escape writes an audit row",
    # BACKLOG #1005 added this one. It is exempt for BOTH of the reasons already used above, and
    # stating only the first would be the weaker half: it is a material PATH like tls_ca_file
    # beside it, AND its ABSENCE is GATED rather than reported -- check_inbound_revocation refuses
    # an mTLS listener with no CRL on an enforcing PHI instance, the same way the ADR 0092 hop cell
    # gates tls/tls_verify below. A reader that merely reported "no CRL configured" would be strictly
    # weaker than the refusal that already exists.
    "tls_crl_file": "material/path; its absence is gated by #1005's posture-keyed revocation refusal",
    # ADR 0188. A TIGHTENING, which is why it is exempt rather than reported: setting it applies the
    # strict AEAD allow-list to that one hop, and leaving it unset is the shipped posture every other
    # connection already has. A reader that reported it would be reporting operators who hardened.
    "tls_ciphers": "opt-in AEAD allow-list on one hop -- a tightening, not a deviation to report",
    # Not TLS at all — the regex matches the word 'verify' in an HL7 ACK correlation check.
    "verify_ack_control_id": "HL7 ACK control-id correlation, unrelated to transport TLS",
    # Verify-off and TLS-off are GATED rather than reported: the ADR 0092 posture-keyed cell refuses
    # them on a production-PHI hop unless attested, and ADR 0153's cleartext_accepted is the declared
    # escape that IS reported. A connection-scoped verify-off READER is owed work (it would report the
    # connectors' tls_verify=false the way this pass reports tls_allow_expired), recorded here rather
    # than done silently — #333 scoped itself to the expiry flag and the generic-ODBC hop.
    "tls": "TLS-off is gated by the ADR 0092 hop cell; the declared escape (cleartext_accepted) is reported",
    "use_tls": "same as tls",
    "tls_verify": "verify-off is gated by the ADR 0092 hop cell; a connection-scoped reader is owed",
    "verify_tls": "same as tls_verify",
    "encrypt": "SQL Server preset only — _build_dsn's posture-keyed weakened-TLS refusal gates it",
    # ADR 0173 made tls_revocation_attested authorable; it is REPORTED above, by
    # revocation_attested_hops. Its reason rides in the reader's output, so it is not a second switch.
    "tls_revocation_attested_reason": "the reason text for tls_revocation_attested, not a switch",
}


def test_every_per_connection_tls_parameter_is_reported_or_exempt() -> None:
    """The CONNECTION-scoped completeness floor (#333 step 7).

    The floors above iterate `SecuritySettings` / `StoreSettings` / `AuthSettings` `model_fields`, and a
    per-connection deviation lives in none of those — it is a keyword argument on a connection factory
    that lands in `spec.settings`. So this floor censuses the FACTORIES instead: every parameter whose
    name is TLS-shaped must be either reported by one of the connection-scoped readers or exempt with a
    written reason. A new one is a test failure rather than a re-audit three months later."""
    import inspect
    import re

    from messagefoundry.config import wiring

    shaped = re.compile(r"tls|ssl|cleartext|verify|insecure|encrypt", re.IGNORECASE)
    census: dict[str, list[str]] = {}
    for name in wiring.__all__:
        obj = getattr(wiring, name, None)
        if not callable(obj):
            continue
        try:
            sig = inspect.signature(obj)
        except (
            TypeError,
            ValueError,
        ):  # builtins / C-level callables have no introspectable signature
            continue
        params = [p for p in sig.parameters if shaped.search(p)]
        if params:
            census[name] = params

    # LIVE POSITIVE CONTROL. A census that silently stopped seeing anything — a renamed `__all__`, an
    # import that started failing, a regex typo — would make every assertion below vacuously true. This
    # is the blindness guard: name factories that certainly carry these parameters and require them.
    assert {"MLLP", "Rest", "FHIR", "Soap", "Ftp", "DICOM"} <= set(census), sorted(census)
    for factory in ("MLLP", "Rest", "FHIR", "Soap", "Ftp", "DICOM"):
        assert "tls_allow_expired" in census[factory], (factory, census[factory])

    classified = set(_CONNECTION_DEVIATIONS_REPORTED) | set(_CONNECTION_DEVIATIONS_EXEMPT)
    unclassified = {p for params in census.values() for p in params} - classified
    assert not unclassified, (
        f"per-connection parameter(s) {sorted(unclassified)} are TLS-shaped and are neither reported "
        "by a connection-scoped reader nor exempt with a reason. Report them (extend "
        "config.wiring's readers and security_loosenings), or add them to "
        "_CONNECTION_DEVIATIONS_EXEMPT with the reason — silence is not an option. "
        f"Scanned {len(census)} factories: "
        + "; ".join(f"{k}({', '.join(v)})" for k, v in sorted(census.items()))
    )


def test_the_reported_connection_deviations_are_actually_wired() -> None:
    """The other half of the floor: the map above claims parameters are REPORTED, and a claim that
    nothing executes is exactly what this lane exists to prevent. Drive each through its reader AND
    through `security_loosenings`, so "reported" means reported."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        accepted_cleartext_hops,
        attested_secure_hops,
        build_outbound_connection,
        expiry_relaxed_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_EXPIRED",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "h", "port": 1, "tls_allow_expired": True},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_CLEAR",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "h", "port": 2}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_ATTESTED",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "h", "port": 3}),
            tls_hop_attested=True,
            tls_hop_attested_reason="TLS terminates at the site's stunnel sidecar",
        )
    )
    assert _CONNECTION_DEVIATIONS_REPORTED["tls_allow_expired"] == "expiry_relaxed_hops"
    assert _CONNECTION_DEVIATIONS_REPORTED["tls_hop_attested"] == "attested_secure_hops"
    assert _CONNECTION_DEVIATIONS_REPORTED["cleartext_accepted"] == "accepted_cleartext_hops"
    names = _names(
        expiry_hops=tuple(n for n, _ in expiry_relaxed_hops(reg)),
        cleartext_hops=tuple(n for n, _ in accepted_cleartext_hops(reg)),
        attested_hops=tuple(n for n, _ in attested_secure_hops(reg)),
    )
    assert "tls_allow_expired" in names and "cleartext_accepted" in names
    assert "tls_hop_attested" in names


def test_the_hostname_check_flag_is_actually_wired() -> None:
    """ASVS 12.3.2: driven through its reader AND through `security_loosenings`, with a default
    connection beside it as the control that must not appear."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        hostname_unchecked_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_NAMELESS",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "h", "port": 1, "tls": True, "tls_check_hostname": False},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_CHECKED",
            ConnectionSpec(type=ConnectorType.MLLP, settings={"host": "h", "port": 2, "tls": True}),
        )
    )
    assert _CONNECTION_DEVIATIONS_REPORTED["tls_check_hostname"] == "hostname_unchecked_hops"
    hops = tuple(n for n, _ in hostname_unchecked_hops(reg))
    assert hops == ("OB_NAMELESS",)
    risks = dict(_pairs(hostname_hops=hops))
    assert "OB_NAMELESS" in risks["tls_check_hostname"]
    assert "OB_CHECKED" not in risks["tls_check_hostname"]
    assert "tls_check_hostname" not in _names()  # control: nothing declared, nothing named


def test_the_url_query_credential_is_actually_wired() -> None:
    """ASVS 14.2.1: driven through its reader AND through `security_loosenings`, with a benign query
    beside it as the control that must not appear."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        query_credential_hops,
    )

    reg = Registry()
    for name, url in (
        ("OB_SIGNED", "https://h.example.invalid/x?sig=SYNTHETIC"),
        ("OB_BENIGN", "https://h.example.invalid/x?fmt=json"),
    ):
        reg.add_outbound(
            build_outbound_connection(
                name, ConnectionSpec(type=ConnectorType.REST, settings={"url": url})
            )
        )
    hops = tuple(n for n, _ in query_credential_hops(reg))
    assert hops == ("OB_SIGNED",)
    risk = dict(_pairs(query_hops=hops))["url_query_credential"]
    assert "OB_SIGNED" in risk and "OB_BENIGN" not in risk and "SYNTHETIC" not in risk
    assert "url_query_credential" not in _names()  # control: nothing declared, nothing named


def test_the_expiry_entry_no_longer_promises_the_hostname_unconditionally() -> None:
    """CORRECTED (ASVS 12.3.2 re-read): the entry said the hostname match is "still fully verified"
    for every listed hop. It now conditions that on the hop leaving the name check on."""
    risk = dict(_pairs(expiry_hops=("OB_X",)))["tls_allow_expired"]
    assert "hostname match and key usage are still fully verified" not in risk
    assert "tls_check_hostname=false" in risk


def test_the_revocation_attestation_is_actually_wired() -> None:
    """Another REPORTED entry, driven the same way as the ones above: through its reader AND through
    `security_loosenings`. ADR 0173 made the pair authorable on an outbound, so the reader must see it
    there and the registry must name it."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        revocation_attested_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_ATTESTED",
            ConnectionSpec(type=ConnectorType.REST, settings={"url": "https://c.example.org/"}),
            tls_revocation_attested=True,
            tls_revocation_attested_reason="partner PKI runs OCSP at the edge",
        )
    )
    assert _CONNECTION_DEVIATIONS_REPORTED["tls_revocation_attested"] == "revocation_attested_hops"
    names = _names(revocation_hops=tuple(n for n, _ in revocation_attested_hops(reg)))
    assert "tls_revocation_attested" in names


# --- the API surface: GET /security/posture reports store + auth deviations --------------------


#: ``_posture_body`` reaches the route through the ``allow_no_auth`` open mode, and the route names
#: that mode (vault BACKLOG #3062). So the quiet posture here is that one entry and nothing else. A
#: signed-in read was tried instead: it needs a service whose test settings are themselves loosened,
#: which the route does not read from the service, so it only looked quieter.
_HARNESS_ONLY = ["allow_no_auth"]


async def _posture_body(engine: Engine, **state: object) -> dict[str, object]:
    app = create_app(engine, allow_no_auth=True)
    for key, value in state.items():
        setattr(app.state, key, value)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/security/posture")
    assert resp.status_code == 200
    body: dict[str, object] = resp.json()
    return body


@pytest.fixture
async def engine(tmp_path: Path):
    eng = await Engine.create(
        tmp_path / "posture.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def test_posture_route_reports_the_store_deviation(engine: Engine) -> None:
    body = await _posture_body(engine, store_settings=StoreSettings(aad_bind=False))
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "aad_bind" in switches


async def test_posture_route_reports_the_auth_deviation(engine: Engine) -> None:
    body = await _posture_body(engine, auth_settings=_ad(ad_session_recheck_seconds=0))
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "ad_session_recheck_seconds" in switches


@pytest.mark.usefixtures("remote_debugging_off")  # the process reading, pinned: see the fixture
async def test_posture_route_reports_the_plaintext_hop_acknowledgement(engine: Engine) -> None:
    """BACKLOG #1179: the route reads [api] off the resolved settings serve stashes (#1989)."""
    body = await _posture_body(
        engine, static_credential_settings=ServiceSettings(api=_terminated(ack=True))
    )
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "plaintext_upstream_hop_acknowledged" in switches
    # Negative control: the same stash without the acknowledgement's plaintext hop reports nothing.
    quiet = await _posture_body(
        engine, static_credential_settings=ServiceSettings(api=_terminated(ack=True, cert=True))
    )
    assert [e["switch"] for e in quiet["loosenings"]] == _HARNESS_ONLY  # type: ignore[index,union-attr]


@pytest.mark.usefixtures("remote_debugging_off")
async def test_posture_route_reports_nothing_at_the_shipped_defaults(engine: Engine) -> None:
    """The route must be quiet on a default instance, or its signal is worthless.

    Default SETTINGS, on an interpreter started with remote debugging off. A default launch through
    the console script leaves it on, and the route then names it: see
    ``tests/test_remote_debug_guard.py``."""
    body = await _posture_body(engine)
    assert [e["switch"] for e in body["loosenings"]] == _HARNESS_ONLY  # type: ignore[index,union-attr]


# --- the ONE connection-scoped deviation (ADR 0153) --------------------------------------------


def test_cleartext_accepted_is_a_named_loosening() -> None:
    """ADR 0153's per-connection declaration MUST surface in the same registry as the settings
    switches. It is a deviation from the one shipped posture, and a deviation the registry cannot see is
    a second posture by the back door."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=("OB_LEGACY", "OB_LAB"),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "cleartext_accepted" in named
    risk = named["cleartext_accepted"]
    # It must NAME the connections. "some connections cross a cleartext hop" is not actionable — an
    # operator has to know WHICH, because the remedy is per-connection.
    assert "OB_LEGACY" in risk and "OB_LAB" in risk
    assert "2 connection(s)" in risk


def test_no_declared_hops_is_not_a_loosening() -> None:
    assert "cleartext_accepted" not in _names(cleartext_hops=())
    assert "tls_allow_expired" not in _names(expiry_hops=())
    assert "generic_odbc_tls_unenforced" not in _names(db_hops=())
    assert "tls_revocation_attested" not in _names(revocation_hops=())


# --- the two OTHER connection-scoped deviations (#333) -----------------------------------------


def test_expiry_relaxation_is_a_named_loosening() -> None:
    """#333(a). ``tls_allow_expired`` reached NO reporting surface: it was absent from
    ``config/settings.py``, ``api/app.py``, ``checks.py`` and ``__main__.py``, so an auditor querying
    ``GET /security/posture`` got a list that said nothing about it. The one thing that fired was a
    construction log line, and a log line emitted once at startup is not what anyone reads later."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=("OB_PARTNER_ADT", "OB_LAB_ORU"),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "tls_allow_expired" in named
    risk = named["tls_allow_expired"]
    assert "OB_PARTNER_ADT" in risk and "OB_LAB_ORU" in risk
    # BOTH halves. Omitting the mitigation would overstate it into verify-off (ADR 0094 ORs exactly one
    # flag); omitting the risk would leave an operator thinking a lapsed bridge closes itself.
    assert "EXPIRED" in risk
    assert "nothing that expires the relaxation" in risk
    assert "hostname" in risk and "chain" in risk


def test_generic_odbc_unenforced_tls_is_a_named_loosening() -> None:
    """#333(b). ADR 0092 accepted the generic-ODBC delegation on the strength of ONE mitigation —
    "construction logs it". That mitigation was defeatable (the detector was value-blind), anonymous,
    and lived in a log stream rather than any surface a reviewer reads. This is the surface."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=("OB_PG_RESULTS", "inbound:IB_PG_ORDERS"),
            attested_hops=(),
            revocation_attested_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "generic_odbc_tls_unenforced" in named
    risk = named["generic_odbc_tls_unenforced"]
    assert "OB_PG_RESULTS" in risk and "inbound:IB_PG_ORDERS" in risk
    # The DSN credential rides the same hop as the rows; an operator weighing the risk needs both.
    assert "credential" in risk and "plaintext" in risk


def test_revocation_attestation_is_a_named_loosening() -> None:
    """ADR 0173's per-connection attestation suppresses a posture-keyed REFUSAL, so it is a declared
    departure from the one shipped posture and belongs in the same registry. The construction-time
    WARNING was its only report, and a log line is not the surface anyone queries later."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
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
            revocation_attested_hops=("OB_PARTNER", "inbound:IB_LAB"),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    )
    assert "tls_revocation_attested" in named
    risk = named["tls_revocation_attested"]
    assert "OB_PARTNER" in risk and "inbound:IB_LAB" in risk
    assert "2 connection(s)" in risk
    # BOTH halves: the refusal it lifts, and the cleartext/verify-off refusals it never lifts. Either
    # half alone would mislead an operator weighing the attestation.
    assert "revocation" in risk and "outside the engine" in risk
    assert "never lifts a cleartext or verify-off refusal" in risk
    # It must NOT claim a verified chain: authoring checks only the flag/reason pair, so an attested
    # hop may verify nothing, and a mitigation resting on that premise would be false (SDS-3.7).
    assert "chain" not in risk


def test_revocation_attested_hops_walks_all_three_tables() -> None:
    """The pair is authorable on inbound(), outbound() AND FhirLookup() (ADR 0173), so the reader must
    walk all three. Reading only outbound -- the shape its expiry sibling has -- would report an attested
    mTLS listener and an attested SMART lookup as absent. Each table also carries an UNattested entry,
    so a reader that listed every connection would fail here too."""
    from messagefoundry.config import wiring
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        FhirLookup,
        Registry,
        build_inbound_connection,
        build_outbound_connection,
        revocation_attested_hops,
    )

    mllp = {
        "port": 15099,
        "tls": True,
        "tls_cert_file": "c",
        "tls_key_file": "k",
        "tls_ca_file": "ca",
    }
    rest = {"url": "https://c.example.org/"}
    reg = Registry()
    reg.add_inbound(
        build_inbound_connection(
            "IB_PLAIN", ConnectionSpec(type=ConnectorType.MLLP, settings=dict(mllp)), router="r"
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "IB_LAB",
            ConnectionSpec(type=ConnectorType.MLLP, settings=dict(mllp, port=15100)),
            router="r",
            tls_revocation_attested=True,
            tls_revocation_attested_reason="site CA publishes a CRL the edge enforces",
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_PLAIN", ConnectionSpec(type=ConnectorType.REST, settings=dict(rest))
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_PARTNER",
            ConnectionSpec(type=ConnectorType.REST, settings=dict(rest)),
            tls_revocation_attested=True,
            tls_revocation_attested_reason="partner PKI runs OCSP at the edge",
        )
    )
    prev = wiring._active
    wiring._active = reg
    try:
        FhirLookup("quiet", url="https://fhir.example.org/fhir")
        FhirLookup(
            "epic",
            url="https://fhir.example.org/fhir",
            tls_revocation_attested=True,
            tls_revocation_attested_reason="token endpoint sits behind an OCSP-checking proxy",
        )
    finally:
        wiring._active = prev
    assert revocation_attested_hops(reg) == [
        ("OB_PARTNER", "partner PKI runs OCSP at the edge"),
        ("fhir_lookup:epic", "token endpoint sits behind an OCSP-checking proxy"),
        ("inbound:IB_LAB", "site CA publishes a CRL the edge enforces"),
    ]


def test_expiry_relaxed_hops_reads_the_graph() -> None:
    """The shared reader. The flag lands in ``spec.settings`` (six outbound factories take it), NOT in a
    typed ``OutboundConnection`` field like ``cleartext_accepted`` — so a reader copied from its sibling
    without noticing that would report every graph as clean."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        expiry_relaxed_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_STRICT",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "a.example", "port": 1, "tls_allow_expired": False},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_BRIDGE",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "b.example", "port": 2, "tls_allow_expired": True},
            ),
        )
    )
    assert expiry_relaxed_hops(reg) == [("OB_BRIDGE", "b.example:2")]


def test_expiry_relaxed_hops_never_leaks_a_url_credential() -> None:
    """These labels land in ``GET /security/posture``. A REST/SOAP/FHIR outbound's peer is a ``url``,
    which can carry ``user:password@`` userinfo — the exact hole #1207 closed on the metadata
    serializers. An unresolved ``env()`` shows its KEY, never a resolved value, for the same reason."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        env,
        expiry_relaxed_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_REST",
            ConnectionSpec(
                type=ConnectorType.REST,
                settings={
                    "url": "https://svc:hunter2@api.example/ingest",
                    "tls_allow_expired": True,
                },
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_ENV",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": env("partner_host"), "port": 7, "tls_allow_expired": True},
            ),
        )
    )
    peers = dict(expiry_relaxed_hops(reg))
    assert "hunter2" not in peers["OB_REST"]
    # BACKLOG #1182: the label keeps scheme, host and port only, so the user and the path go too.
    assert peers["OB_REST"] == "https://api.example"
    assert peers["OB_ENV"] == "env(partner_host):7"


def test_unverified_generic_db_hops_walks_inbound_as_well_as_outbound() -> None:
    """``accepted_cleartext_hops`` reads outbound + FHIR lookups; a ``DatabasePoll`` INBOUND crosses the
    same generic hop, in the same dialect, with the same credential in the same DSN. Reading only
    outbound would report a live unenforced hop as absent — the failure this whole registry exists to
    prevent."""
    from messagefoundry.config.wiring import (
        Database,
        DatabasePoll,
        Registry,
        build_inbound_connection,
        build_outbound_connection,
        unverified_generic_db_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_PG_OK",
            Database(
                server="ok.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement="INSERT INTO t (a) VALUES (:a)",
                odbc_params={"SSLmode": "verify-full"},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_PG_BARE",
            Database(
                server="bare.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement="INSERT INTO t (a) VALUES (:a)",
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_SQLSERVER",
            Database(
                server="ss.example",
                database="MFDB",
                statement="INSERT INTO t (a) VALUES (:a)",
            ),
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "IB_PG_ORDERS",
            DatabasePoll(
                server="poll.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                poll_statement="SELECT 1",
                odbc_params={"SSLmode": "disable"},
            ),
            router="R",
        )
    )
    hops = dict(unverified_generic_db_hops(reg))
    # The sqlserver dialect is NOT here: it keeps the byte-identical posture-keyed refusal, so it is
    # gated rather than merely reported, and listing it would be noise.
    assert set(hops) == {"OB_PG_BARE", "inbound:IB_PG_ORDERS"}
    assert "no TLS keyword" in hops["OB_PG_BARE"]
    # The value-blind detector fixed in step 1 is what makes this arm real: `SSLmode=disable` used to
    # read as "the operator has taken TLS ownership".
    assert "SSLmode=disable" in hops["inbound:IB_PG_ORDERS"]


def test_accepted_cleartext_hops_reads_the_graph() -> None:
    """The single shared reader — `messagefoundry check` and the API posture route both use it, so the
    two can never report different accepted sets."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        accepted_cleartext_hops,
        build_outbound_connection,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_PLAIN", ConnectionSpec(type=ConnectorType.TCP, settings={"host": "x", "port": 1})
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_LEGACY",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "y", "port": 2}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    assert accepted_cleartext_hops(reg) == [("OB_LEGACY", "vendor firmware predates TLS")]


async def test_posture_route_reports_declared_cleartext_hops(engine: Engine) -> None:
    """The surface the owner named explicitly. The route reads the LIVE graph off the engine's registry
    runner, so a reload is reflected rather than a startup snapshot going stale."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, Registry, build_outbound_connection

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_LEGACY",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 5099}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    engine.add_registry(reg)
    body = await _posture_body(engine)
    entry = next(
        e
        for e in body["loosenings"]  # type: ignore[union-attr]
        if e["switch"] == "cleartext_accepted"
    )
    assert "OB_LEGACY" in entry["risk"]


def test_declared_fhir_lookup_read_hops_are_named_too() -> None:
    """A ``FhirLookup`` is a connection that crosses a PHI-bearing read hop, and the read executor
    honours the declaration — so if this reader skipped ``registry.fhir_lookups`` a live cleartext hop
    would cross while `check`, `security_loosenings()` and `GET /security/posture` all reported the
    accepted set as EMPTY. That is precisely "a deviation the registry cannot see"."""
    from messagefoundry.config import wiring
    from messagefoundry.config.wiring import FhirLookup, Registry, accepted_cleartext_hops

    reg = Registry()
    prev = wiring._active
    wiring._active = reg
    try:
        FhirLookup("quiet", url="https://fhir.example.org/fhir")
        FhirLookup(
            "legacy",
            url="http://fhir.example.org/fhir",
            cleartext_accepted=True,
            cleartext_reason="on-prem facade has no TLS listener",
        )
    finally:
        wiring._active = prev
    assert accepted_cleartext_hops(reg) == [
        ("fhir_lookup:legacy", "on-prem facade has no TLS listener")
    ]


def test_fhir_lookup_declaration_is_load_validated() -> None:
    """The factory is the ONE authoring surface, so the flag/reason coherence rule must fire there.

    Before this, the only way to declare it on a lookup was mutating ``spec.settings`` by hand — an
    escape with no validation and nothing for the registry to name."""
    from messagefoundry.config import wiring
    from messagefoundry.config.wiring import FhirLookup, Registry, WiringError

    reg = Registry()
    prev = wiring._active
    wiring._active = reg
    try:
        with pytest.raises(WiringError, match="requires cleartext_reason"):
            FhirLookup("x", url="http://f.example.org/fhir", cleartext_accepted=True)
        with pytest.raises(WiringError, match="without cleartext_accepted"):
            FhirLookup("y", url="http://f.example.org/fhir", cleartext_reason="why")
        with pytest.raises(WiringError, match="must be non-empty"):
            FhirLookup(
                "z",
                url="http://f.example.org/fhir",
                cleartext_accepted=True,
                cleartext_reason="   ",
            )
    finally:
        wiring._active = prev


def test_every_store_and_auth_bool_is_reported_or_exempt() -> None:
    """The completeness floor, extended over the two OTHER sections this registry reaches into.

    The floor above covers ``[security]`` only. Without this one, the registry's reach into
    ``[store]``/``[auth]`` would be exactly the leak-gate-blindness shape one section over: a green
    "no deviations" that has never looked. The exemption set below is the honest part — it enumerates
    the switches that are NOT reported today, so the gap is a written decision rather than an
    accident, and a NEW switch in either section cannot silently join it."""
    #: Not reported by security_loosenings() today. Each is gated elsewhere; extending the registry
    #: over them is real work with its own SECURITY-LOOSENING.md entries, and is recorded as owed
    #: rather than done silently here. A new field in either section reds this test until it is
    #: either reported or added here with a reason.
    exempt_store = {
        # Not security switches at all — FIFO-claim performance levers and pool knobs.
        "fifo_claim_fold_reset",
        "fifo_claim_proc",
        "fifo_claim_prepared",
        "multi_subnet_failover",
        "warm_pool",
        # HARDENINGS at their non-default value (turning them ON tightens), so a flip is not a loosening.
        "require_encryption",
        "require_managed_identity",
        # #1008 / ADR 0199: turning it ON adds a REFUSAL on an unobservable store principal and makes
        # the over-grant refusal outrank [security].allow_over_granted_store_principal. The
        # deviation it acts on IS reported — as the OBSERVATION passed in `store_privilege`, not as
        # this switch — so it stays visible either way, and reporting the switch would make a
        # hardening read as a weakening.
        "require_least_privilege",
        # Security-relevant and gated ELSEWHERE, not by this registry. Extending it over them is real
        # work with its own SECURITY-LOOSENING.md entries — recorded as owed, not done silently.
        "encrypt",  # the keyless-PHI serve gate refuses it in its own right
        "trust_server_certificate",  # gated by weakened_tls_escape_permitted (the ADR 0092 clamp)
        "allow_unencrypted_phi",  # reported via [security].allow_unencrypted_phi (ADR 0118 move)
    }
    exempt_auth = {
        # HARDENINGS / topology choices — a flip is not a weakening of the shipped posture.
        "require_action_step_up",
        "ad_enabled",
        "ad_use_nested_groups",
        "kerberos_enabled",
        "oidc_enabled",
        "oidc_username_strip_domain",
        "notify_security_events",
        # Password-policy composition rules: individually neither secure nor insecure (the policy is
        # scored as a whole), and none is a posture switch.
        "password_require_uppercase",
        "password_require_lowercase",
        "password_require_digit",
        "password_require_symbol",
        "password_check_context",
        "password_check_username",
        "password_check_breached",
        # REPORTED, so not an owed gap: named only with a live ldap:// bind, which this loop's lone
        # flip never builds (ad_enabled stays off). The plain-LDAP section above pins it (#2354).
        "ad_allow_insecure_ldap",
        # Security-relevant and gated ELSEWHERE, not by this registry — same owed note as [store].
        # Not reported through THIS field: it is the desugared copy of [security].require_mfa, which
        # a loaded config reports and the [security] floor covers. Off, it is also refused at exposure
        # by the __main__ gates. An embedder that builds AuthSettings itself is not reported.
        "require_mfa",
        "ad_tls_verify",  # gated by weakened_tls_escape_permitted
        # Gated by no serve-time refusal of its own: off, it mints every OIDC session with no factor
        # met, and while require_mfa is on that session owes an engine factor at the access gate.
        "oidc_require_mfa_claim",
        # phi_read_rate_limit_enabled and admin_write_rate_limit_enabled left this set when
        # BACKLOG #1131 (E17) began naming them; the loop below now pins that they are reported.
    }
    for model, exempt, section in (
        (StoreSettings, exempt_store, "store"),
        (AuthSettings, exempt_auth, "auth"),
    ):
        for field, info in model.model_fields.items():
            if field in exempt or not isinstance(info.default, bool):
                continue
            flipped = model(**{field: not info.default})  # type: ignore[arg-type]
            kwargs = {"store": flipped} if section == "store" else {"auth": flipped}
            assert field in _names(**kwargs), (  # type: ignore[arg-type]
                f"[{section}].{field} at its insecure value ({not info.default}) is NOT named by "
                "security_loosenings(). Add it to the registry, or add it to this test's exemption "
                "set with the reason — silence is not an option."
            )


async def test_posture_route_declares_its_scope_when_no_graph_is_loaded(engine: Engine) -> None:
    """An engine with no registry runner cannot see the connection-scoped declarations, so it SAYS so.

    Reporting a settings-only list with no marker is the failure this whole lane exists to prevent:
    a subset that reads as the whole posture. `security show` carries the same marker for the same
    reason, and this pins that the route does not quietly differ from it."""
    body = await _posture_body(engine)
    assert body["loosenings_scope"] is not None
    assert "cleartext_accepted" in str(body["loosenings_scope"])


async def test_posture_route_scope_is_none_once_a_graph_is_loaded(engine: Engine) -> None:
    """The complementary arm — the marker must CLEAR, or it degrades into permanent noise."""
    from messagefoundry.config.wiring import Registry

    engine.add_registry(Registry())
    body = await _posture_body(engine)
    assert body["loosenings_scope"] is None


async def test_managed_app_stashes_auth_settings_for_the_registry(tmp_path: Path) -> None:
    """Drive the REAL wiring: `create_managed_app` must stash `auth_settings` on app.state, or the
    route silently falls back to `AuthSettings()` defaults and the auth deviation is never reported.

    The targeted route test above sets `app.state.auth_settings` by hand, so it cannot fail if the
    stash regresses. This one goes through the lifespan, which is the only thing that proves the
    production path is wired."""
    from messagefoundry.api import create_managed_app
    from messagefoundry.auth import Role
    from tests.test_api_auth import _DEFAULT_PEER, _add, _auth, _login

    app = create_managed_app(
        db_path=tmp_path / "managed_posture.db",
        poll_interval=0.05,
        # Settings always build an auth service now (vault BACKLOG #2825), so the route is read with
        # a session. Notices off skips the ADR 0167 deliverability gate on the empty store.
        auth_settings=_ad(
            ad_session_recheck_seconds=0, require_mfa=False, notify_security_events=False
        ),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    transport = httpx.ASGITransport(app=app, client=_DEFAULT_PEER)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://t") as client,
        app.router.lifespan_context(app),
    ):
        await _add(app.state.auth, "root", Role.ADMINISTRATOR)
        signed_in = await _login(client, "root")
        assert signed_in.status_code == 200, signed_in.text
        resp = await client.get("/security/posture", headers=_auth(signed_in.json()["token"]))
    assert resp.status_code == 200, resp.text
    switches = [entry["switch"] for entry in resp.json()["loosenings"]]
    assert "ad_session_recheck_seconds" in switches
