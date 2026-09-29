# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""AuthService — orchestrates authentication, sessions, role resolution, and role seeding.

Pure engine-side code (no FastAPI): the API layer composes it. It ties together the store (users,
roles, sessions, audit), password hashing/policy, opaque session tokens, and the LDAP/Kerberos
authenticators. Local and AD users share one identity model; an AD user's roles are re-synced from
their directory groups on every login, so :meth:`identity_for_token` can resolve everyone uniformly
from ``user_roles``.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import ipaddress
import json
import logging
import os
import secrets
import time
import unicodedata
import urllib.parse
import urllib.request
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, TypeVar
from uuid import uuid4

from messagefoundry.auth import channel_scope, oidc, reconcile, totp, webauthn
from messagefoundry.auth.audit_visibility import (
    ACCOUNT_LOCKED_ACTION,
    LOCK_NOTICE_ACTION,
    LOCKED_REFUSAL_DETAIL,
    LOGIN_LOCKED_ACTION,
)
from messagefoundry.auth.identity import ALL_CHANNELS, AuthProvider, Identity, SessionMechanism
from messagefoundry.auth.ldap import (
    AdPrincipal,
    DirectoryAnswer,
    LdapAuthenticator,
    LdapError,
    kerberos_principal,
)
from messagefoundry.auth.notifications import (
    ACCOUNT_CREATED,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    ADMIN_NEW_IP,
    EMAIL_CHANGED,
    FEDERATED_IDENTITY_BOUND,
    FEDERATED_IDENTITY_UNBOUND,
    FIRST_ADMINISTRATOR_TAKEOVER,
    LOG_SILENT_EVENT_TYPES,
    LOGIN_AFTER_FAILURES,
    LOGIN_NEW_IP,
    MFA_CREDENTIAL_REMOVED,
    MFA_DISABLED,
    MFA_ENABLED,
    NOTIFY_EMAIL_SET,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    RECOVERY_CODE_USED,
    ROLES_CHANGED,
    SUSPICIOUS_LOGIN_FAILURE_THRESHOLD,
    TEMPORARY_CREDENTIAL_EXPIRING,
    TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
    USERNAME_CHANGED,
    SecurityEvent,
    SecurityNotifier,
)
from messagefoundry.auth.oidc import PendingFlow
from messagefoundry.auth.oidc_http import build_idp_opener, jwks_fetcher
from messagefoundry.auth.passwords import hash_password, needs_rehash, verify_password
from messagefoundry.auth.permissions import (
    CUSTOM_ROLE_ID_PREFIX,
    ROLE_METADATA,
    Permission,
    Role,
    decode_custom_role_permissions,
    is_custom_role_id,
    validate_custom_role_permissions,
)
from messagefoundry.auth.policy import (
    BreachCorpusUnavailable,
    PasswordPolicy,
    _common_passwords,
    _operator_corpus,
)
from messagefoundry.auth.ratelimit import SlidingWindowRateLimiter
from messagefoundry.auth.tokens import hash_bytes, hash_token, mint_token
from messagefoundry.config.models import SignatureAlgorithm
from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.tls_policy import HopPosture, RevocationHopGuard
from messagefoundry.store.base import AdminStore
from messagefoundry.store.store import (
    SCOPE_SOURCE_AD,
    SCOPE_SOURCE_MANUAL,
    AuditAppend,
    ChannelScopeSource,
    FederatedUnbind,
    LockoutCounter,
    LockoutIncrement,
    SessionRecord,
    UserRecord,
    WebAuthnCredential,
    require_notify_email,
    seed_notify_email,
)
from messagefoundry.transports.rest import opener_tls_context

_log = logging.getLogger(__name__)

#: The elevation ceremonies that stamp ``mfa_verified_at`` before they rotate, so the session joins
#: the group of full sessions and the per-user cap must run again (BACKLOG #2076). The re-proof
#: ceremonies (``reauth``, ``reauth_oidc``) are left out on purpose: they do not re-rank the row, and
#: running the cap there could revoke the very session the caller was just handed.
#: ``tests/test_auth_session_lifecycle.py`` pins this set against the ceremonies that stamp.
_FACTOR_CEREMONIES: Final = frozenset(
    {"mfa_enroll_confirm", "mfa_verify", "webauthn_enroll", "webauthn_assert"}
)


def _warn_if_corpus_unreadable(path: str | None) -> None:
    """Eagerly load (and cache) an operator breach corpus at startup so a misconfigured path surfaces
    as a clear warning rather than silently disabling the check on every later password change."""
    if not path:
        return
    try:
        entries, hashed = _operator_corpus(path)
    except OSError as exc:
        _log.warning(
            "password_breach_corpus_file %r could not be read (%s); the larger breach corpus is "
            "disabled (the bundled corpus still applies)",
            path,
            exc,
        )
        return
    _log.info(
        "loaded operator breach corpus from %r (%d %s entries)",
        path,
        len(entries),
        "hashed" if hashed else "plaintext",
    )


def _error_if_bundled_corpus_unusable(check_breached: bool) -> None:
    """Eagerly load (and cache) the BUNDLED breach corpus at startup, so a truncated or missing file
    surfaces in the log at boot, before anyone meets it as a 500 on a password change (BACKLOG
    #1438). The twin of ``_warn_if_corpus_unreadable`` above, at a higher level for a reason.

    The OPERATOR corpus degrades to a warning because it is optional and the bundled list still screens
    underneath it. Nothing screens underneath the BUNDLED list, so its loss is an ERROR: ``check_breached``
    ships ``True``, and a corpus that cannot load means the shipped configuration asserts a check that is
    not running. ``PasswordPolicy.violations`` refuses passwords in that state; this is only the loud
    half. THIS FUNCTION deliberately does not stop the engine -- HL7 flow does not depend on password
    screening, and bricking a message engine over an auth data asset would trade a contained failure for
    an outage. The engine's own ``serve`` lifespan no longer stops either, since BACKLOG #1447: a FIRST
    run used to fail there, and :meth:`AuthService._generate_policy_password` now suppresses this screen
    on its own candidate -- see that call for why. Stated as that ONE path rather than as "nothing
    anywhere": the ``provision-admin`` CLI still refuses on this, as an error message since Wave 2.

    BACKLOG #1886: the message names the forced rotation that cannot finish while the corpus is
    unusable. The chain behind that is stated once, on :class:`BreachCorpusUnavailable`. Since ADR
    0183 Amendment A, Wave 2, a first ``serve`` mints no account, so the first administrator comes
    from ``provision-admin``, and that command fails for this reason too. A repaired file is read
    without a restart, since ``lru_cache`` does not cache an exception. The setting is read once into
    ``PasswordPolicy``, so changing it needs a restart.

    Skipped when the operator has turned screening off: a corpus nobody consults is not a defect.
    """
    if not check_breached:
        return
    try:
        entries = _common_passwords()
    except BreachCorpusUnavailable as exc:
        _log.error(
            "%s; creating or changing a local password by hand will be REFUSED until it is "
            "repaired (ASVS 6.2.4). An account that must change its password therefore cannot "
            "finish that change, and the attempt fails with a server error. An administrator's "
            "password reset leaves its user stuck the same way, and `provision-admin` cannot "
            "create the first administrator for this reason either. To repair it, "
            "reinstall the messagefoundry wheel; a repaired file is read without a restart. Or set "
            "[auth].password_check_breached = false and restart, to accept unscreened passwords "
            "deliberately",
            exc,
        )
        return
    _log.debug("loaded the bundled breach corpus (%d entries)", len(entries))


#: A fixed argon2 hash used to equalize login timing for unknown/disabled accounts (anti-enumeration).
_DUMMY_PASSWORD_HASH = hash_password("mf-login-timing-equalizer")

#: Cap on concurrent argon2 hashes/verifies so an unauthenticated login flood can't exhaust the
#: thread-pool executor (and starve all login/AD/password work). Argon2 is deliberately CPU-heavy.
_ARGON2_MAX_CONCURRENCY = max(2, min(8, os.cpu_count() or 2))

# Bound on the per-process new-client-IP dedup cache (WP-L3-13). It only debounces the audit/notify
# side effects of the 8.4.2 signal; the step-up decision never depends on it, so eviction is harmless.
_NEW_IP_DEDUP_MAX = 4096

# The first-seen login-address signal (BACKLOG #288, ASVS 8.2.4). It reads the account's own
# ``auth.login_success`` audit rows at every session mint, so both bounds are there to keep that read
# cheap: at most this many rows, from at most this far back. An address last used before the window,
# or beyond the newest rows, reads as NEW -- the signal answers "seen RECENTLY", and erring that way
# costs one challenge and one notice, never a refused login.
_LOGIN_ADDRESS_LOOKBACK_SECONDS = 90 * 86400
_LOGIN_ADDRESS_HISTORY_ROWS = 200
# One ``login_new_ip`` notice per account per this many seconds (see ``_login_new_ip_notice_due``).
_LOGIN_NEW_IP_NOTICE_SECONDS = 900.0


class _LoginAddress(Enum):
    """What the first-seen login-address signal concluded for one sign-in (BACKLOG #288).

    Only ``NEW`` challenges. The two ``UNEVALUATED_*`` members are the fail-open cases: the signal
    had nothing to compare, so it lets the login mint as it would have and audits that it could not
    judge."""

    KNOWN = "known"
    NEW = "new"
    # The account has never completed a sign-in and holds no ``auth.login_success`` row with an
    # address, so every address would be "first seen". Challenging and notifying here would fire on
    # every account's first login, which is noise, not signal.
    UNEVALUATED_NO_BASELINE = "no_baseline"
    # The caller passed no client address (an in-process caller, or an ASGI scope with no client).
    UNEVALUATED_UNKNOWN_ADDRESS = "unknown_address"
    # The history read raised. A store fault must not turn this signal into a refused login.
    UNEVALUATED_READ_FAILED = "read_failed"


def _unmapped(address: str) -> str:
    """An IPv4-mapped IPv6 address as its IPv4 form, so a bind change between ``0.0.0.0`` and
    ``::`` does not make every stored address read as new. Anything else is returned unchanged."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return address


def _owed_a_factor(detail: object) -> bool:
    """Whether an ``auth.login_success`` detail records a sign-in that still owed a second factor.

    Only the local leg writes the ``mfa_required`` key. A detail that does not parse counts as not
    owed, which keeps the row in the baseline: the fail-open direction for a challenge-only signal."""
    if not isinstance(detail, str):
        return False
    try:
        parsed = json.loads(detail)
    except ValueError:
        return False
    return isinstance(parsed, dict) and parsed.get("mfa_required") is True


# Bounds on the per-session re-proof failure counts (BACKLOG #1138). A count is NEVER evicted while
# its entry is younger than the absolute session lifetime, because evicting it would hand that session
# a fresh budget. When the map is full, entries older than that lifetime go first; if it is still
# full, a session with no entry yet is revoked on its first failed re-proof instead (fail closed). One
# account may hold at most _REPROOF_SESSION_PER_USER entries, dropping its own oldest, so a single
# account cannot fill the map.
_REPROOF_SESSION_MAX = 4096
_REPROOF_SESSION_PER_USER = 64

#: ASVS 6.3.8 — the fixed budget every FAILED authentication response is held to, so the branch a
#: challenge took cannot be read off its latency (BACKLOG #1140). Successes are never padded: a valid
#: credential already tells the caller the account exists, and enumeration is about telling two
#: FAILURES apart.
#:
#: 0.5 s is sized from measurement, not taste. Measured 2026-09-05 in-process against a real SQLite
#: store, warmed and interleaved, 25 samples per branch: every local failure branch lands at 46-50 ms
#: median with a p90 of 57 ms, dominated by the one argon2id verify (~40 ms at the pinned t=3, 64 MiB,
#: p=4 parameters). 0.5 s is roughly 9x that p90, which leaves room for a slower CPU and for the
#: `_argon2_sem` queue under a login flood. It is a MODULE constant rather than an operator setting on
#: purpose: an operator who could lower it could silently disable the control, and no site-specific
#: fact the right value depends on is left unfixed by the argon2 parameters.
_FAILURE_BUDGET_SECONDS = 0.5

#: Per-process, per-seam latch for the budget-overrun warning. Deliberately module-level and not
#: per-instance: the warning reports that THIS DEPLOYMENT's budget is too small for its hardware,
#: which is a fact about the process, not about one service object. One warning per seam per process
#: — the login surface is unauthenticated, so warning on every overrun would be the same unbounded
#: log amplifier the rate-limited audit paths already exist to avoid.
_BUDGET_OVERRUN_WARNED: set[str] = set()


def _failure_deadline(started: float, now: float, budget: float | None = None) -> float:
    """The instant a failed challenge that began at ``started`` is allowed to answer.

    Returns the first whole multiple of ``budget`` after ``started`` that is strictly later than
    ``now`` — normally the first slot, since the budget is sized above every failure branch.

    **The quantization is the fail-SAFE, and it is why this is not simply ``started + budget``.** A
    pad that gives up once the work has outrun its budget fails open exactly when it matters: under
    the load that made the work slow, the raw elapsed goes back on the wire. Rounding up to the next
    slot instead means an overrun discloses only WHICH SLOT the work landed in, never the elapsed
    itself, and it cannot fail open at all — the returned deadline is always strictly ahead of ``now``.

    Quantizing does mean a pair of branches that straddle a slot boundary stay distinguishable, and
    more visibly than their raw few-millisecond gap would be. That is not extra disclosure: a slot
    index is a lossy function of the elapsed, so it cannot carry more than the elapsed already did,
    and the budget is sized so that every branch lands in slot 1 with an order of magnitude to spare.

    ``budget`` reads :data:`_FAILURE_BUDGET_SECONDS` at CALL time when omitted, so a test can lower
    it; it must be > 0. ``now`` before ``started`` (a clock that ran backwards — ``time.monotonic``
    does not, but a caller can still hand one in) collapses to slot 1 rather than to a past deadline.
    """
    span = _FAILURE_BUDGET_SECONDS if budget is None else budget
    slots = max(1, int((now - started) // span) + 1)
    return started + slots * span


@dataclass
class _PadClock:
    """The instant a failed federated challenge's deadline counts from (BACKLOG #1947).

    It starts at the call and :meth:`AuthService._authenticate_oidc` moves it to the end of the IdP
    round trip. That round trip's latency is the IdP's, not the account's, and it can run past the
    whole budget. Counting from the call would then split the refusals that follow it across slots
    by their own store and directory work, which is the difference the pad exists to hide. Counting
    from the end of the round trip still fixes the deadline before any account-dependent work runs.
    """

    started: float


async def _sleep_until(deadline: float) -> None:
    """Await until the monotonic instant ``deadline``, returning at once if it has already passed.

    A named module-level function so the pad has exactly one sleep site to audit, and so a test can
    replace it and read back the deadline a seam computed without paying a wall-clock wait.
    """
    remaining = deadline - time.monotonic()
    if remaining > 0:
        await asyncio.sleep(remaining)


# Global safety bound on outstanding single-use per-action step-up grants (ADR 0077). Each grant is
# consumed on the next matching sensitive request (or expires with the step-up window), so the live set
# is normally tiny; this only caps a pathological accumulation. On overflow the OLDEST grant is evicted
# (fail-safe: a dropped grant just re-prompts, never a bypass), mirroring `_new_ip_seen`'s self-eviction.
_ACTION_STEP_UP_GRANT_MAX = 4096

# Action identifiers for the per-action step-up grants (ADR 0077). Named constants so the JSON API deps,
# the /ui twins, and the tests all reference the SAME grant string (a typo would only ever fail closed —
# an unmatched grant re-prompts — but the shared constants keep the wiring legible). WP245 (ASVS 7.5.1)
# wired the browser /ui factor-binding lanes onto these (mfa enroll/confirm/disable + webauthn
# enroll/delete) and bound the JSON admin-user-update PATCH, retiring the ADR 0077 deferral.
STEP_UP_ACTION_MFA_ENROLL = "mfa_enroll"
STEP_UP_ACTION_MFA_CONFIRM = "mfa_confirm"
STEP_UP_ACTION_MFA_DISABLE = "mfa_disable"
STEP_UP_ACTION_WEBAUTHN_ENROLL = "webauthn_enroll"
STEP_UP_ACTION_WEBAUTHN_DELETE = "webauthn_delete"
STEP_UP_ACTION_ADMIN_USER_UPDATE = "admin_user_update"
# BACKLOG #1149 (ASVS 7.5.2). Terminating a session is bound to an ACTION rather than to the shared
# session window, because 7.5.2's verb is "having authenticated AGAIN" — an authentication event
# SUBSEQUENT to the one that established the session. A window seeded by the login ceremony satisfies
# a recency test the moment a session exists, so `require_reauth_only` alone let a caller mass-revoke
# every other session of the account with no proof beyond the sign-in they already had.
STEP_UP_ACTION_SESSION_TERMINATE = "session_terminate"
# BACKLOG #1148 (ASVS 7.5.1). The verb asks for full re-authentication before modifications to
# attributes that affect authentication, naming MFA configuration verbatim and NOT qualifying whose.
# The self-service half already satisfies it; the ADMIN half did not -- both reset lanes rode the
# plain login-seeded window, so an administrator who signed in under step_up_max_age_seconds ago
# could act with ZERO fresh proof. What that gate protects is the most complete modification
# available to the named attribute: admin_reset_mfa disables TOTP and deletes every passkey, and
# disable_totp NULLs the recovery codes alongside the secret -- one call clears the second factor,
# every recovery code and every passkey, on someone else's account.
STEP_UP_ACTION_ADMIN_RESET_MFA = "admin_reset_mfa"
STEP_UP_ACTION_ADMIN_RESET_PASSWORD = "admin_reset_password"  # nosec B105 — step-up action id, not a credential; echoed publicly in X-Step-Up-Action
# BACKLOG #1143 / #295 (ADR 0184). Binding, rebinding or unbinding a federated identity decides who
# may sign in as the account, so it is the same class of change as an admin password reset: an
# attribute that affects authentication (ASVS 7.5.1). Bound to its own action and single-use, and
# MFA-gated, for the same reason `admin_reset_password` is.
STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY = "admin_federated_identity"

#: The closed-set reason a federated login is refused with when its verified ``(issuer, sub)`` is
#: bound to no account (ADR 0184 AC-4). Named because the browser layer maps it to a login-page code.
FEDERATED_SUBJECT_NOT_BOUND = "federated_subject_not_bound"

#: The closed-set reason :meth:`AuthService.bind_federated_subject` refuses an account with when the
#: account carries no ``directory_object_id`` (BACKLOG #1143 slice C, ADR 0184 AC-5). Written into the
#: ``auth.federated_bind_refused`` audit row and carried on :class:`DirectoryObjectIdMissing`. Also the
#: reason a federated login refuses an already-bound id-less row, and a reconciliation pass skips one
#: (BACKLOG #2027). Deliberately absent from the browser layer's code map, so it shows as generic.
DIRECTORY_OBJECT_ID_MISSING = "directory_object_id_missing"

#: The code that opens :class:`FederatedBindingChanged`'s message (BACKLOG #2026), so a caller can
#: tell that refusal from the other 409 on the federated-identity routes without matching prose.
FEDERATED_BINDING_CHANGED = "federated_binding_changed"

#: The closed-set reason a password re-proof is refused with on a session the federated login
#: minted (BACKLOG #296, ADR 0142 Amendment B). Its step-up goes back to the IdP, so the password is
#: never checked and nothing is charged to the lockout. Carried on ``Elevation.idp_step_up_required``.
IDP_STEP_UP_REQUIRED = "idp_step_up_required"

#: The closed-set reason :meth:`AuthService.verify_mfa` refuses a directory account with when the
#: directory does not confirm it is present and enabled (BACKLOG #2023). Written into the
#: ``auth.mfa_failed`` audit row beside the probe's outcome, and carried on
#: ``Elevation.directory_unconfirmed``. The code is never checked and nothing is charged.
DIRECTORY_UNCONFIRMED = "directory_unconfirmed"

#: The closed-set reasons the federated step-up leg refuses with (BACKLOG #296), on the
#: ``auth.reauth`` audit row and on :class:`OidcStepUp`. A claims-ladder slug can also appear there.
STEP_UP_NOT_FRESH = "step_up_not_fresh"
STEP_UP_SUBJECT_MISMATCH = "step_up_subject_mismatch"
FLOW_PURPOSE_MISMATCH = "flow_purpose_mismatch"

#: Operator-readable text for the step-up leg's refusals. None of it echoes anything the IdP sent.
#: A slug not listed here reads as the generic line in ``_step_up_refused``.
_STEP_UP_ERRORS: Final[Mapping[str, str]] = MappingProxyType(
    {
        STEP_UP_NOT_FRESH: (
            "The identity provider did not ask you to sign in again, so it could not confirm it's"
            " you. Try again. If this repeats, the provider is ignoring max_age=0 and prompt=login."
        ),
        STEP_UP_SUBJECT_MISMATCH: (
            "The identity provider signed in a different account from the one this session belongs"
            " to. Sign in at the provider as yourself, then try again."
        ),
        "session_gone": "Your session ended. Sign in again.",
        "state_unknown": "The confirmation expired. Try again.",
        "state_mismatch": "The confirmation could not be matched to this browser. Try again.",
        "idp_unavailable": "The identity provider is unavailable. Try again later.",
        "not_configured": "Federated sign-in is not configured.",
        "idp_error": "The identity provider did not complete the sign-in. Try again.",
        "malformed_callback": "The identity provider's answer was incomplete. Try again.",
        "not_in_directory": (
            "Your directory account could not be found or is disabled. Ask an administrator."
        ),
        "directory_unavailable": "The directory is unavailable. Try again later.",
    }
)

#: The text ``POST /users`` answers a taken username with, from its pre-check and from
#: :class:`UsernameTaken` alike (BACKLOG #1808).
USERNAME_TAKEN = "username already exists"

_T = TypeVar("_T")


@dataclass(frozen=True)
class LoginOutcome:
    """Result of a login attempt. ``error`` is for logs/audit — never leak the reason to clients."""

    ok: bool
    token: str | None = None
    identity: Identity | None = None
    must_change_password: bool = False
    error: str | None = None
    #: The credential was accepted but the session still owes a second factor before it may reach an
    #: authorized route — the client should prompt for a code and call ``POST /auth/mfa-verify``, or
    #: enrol a factor first if it has none (WP-14, ASVS 6.3.3). It used to be documented as always
    #: False for a directory login; that stopped being true when the Kerberos leg began minting at the
    #: minimum (BACKLOG #1144), and reporting False there would tell a JSON client no factor is needed
    #: seconds before the gate refuses it with ``X-MFA-Required: 1``.
    mfa_required: bool = False
    #: A CLOSED-SET reject slug, so the browser layer can pick an allow-listed error code without
    #: parsing ``error`` (free prose) or seeing any IdP-supplied text. Introduced for the federated
    #: path (ADR 0142) and **no longer federated-only**: the directory-identity refusal (BACKLOG
    #: #1471) is reached by every directory mechanism, Kerberos included, so this line used to say
    #: "always ``None`` on the local/AD/Kerberos paths" and stopped being true. A slug the browser
    #: layer's map does not know collapses to its generic code, which is the safe default.
    reason: str | None = None


@dataclass(frozen=True)
class Elevation:
    """The outcome of a session-elevating ceremony, carrying the ROTATED session token (ASVS 7.2.4).

    Every ceremony that raises a session's authentication state -- re-auth, TOTP verify, TOTP
    enrollment confirm, passkey registration, passkey assertion -- re-keys the session to a fresh
    token instead of stamping the elevation onto the token the caller already holds. One shape for
    all five, deliberately: three different shapes is exactly the defect that makes a caller adopt
    the new token on some legs and quietly keep the dead one on others.

    Three states, and a caller must be able to tell them apart:

    * ``ok`` -- elevated. ``token`` is the caller's NEW session token and is never ``None`` here;
      the token they presented has stopped authenticating. The caller MUST hand it back (response
      body, cookie), or it has just made the session it elevated unreachable.
    * not ``ok``, ``session_lost`` False -- the proof was wrong (bad password, bad code, bad
      assertion). Nothing rotated, and the token the caller presented still authenticates.
    * not ``ok``, ``session_lost`` True -- the session is gone, so the caller must sign in again.
      Either the proof was GOOD but the session was revoked or expired underneath the ceremony, or
      (password re-auth only, BACKLOG #1138) the session is revoked because it spent its re-proof
      budget, in which case the proof was wrong or never checked. Fails CLOSED: no token is handed
      back. Held apart from a wrong proof so a route answers 401 rather than re-prompting on a
      session that no longer exists. The ``auth.reauth`` row's ``session_revoked`` says which.

    ``recovery_codes`` is populated only by :meth:`AuthService.confirm_mfa_enrollment` (shown once).

    ``locked`` is set only by :meth:`AuthService.verify_mfa`, on a refusal made because the account
    is locked. It qualifies the wrong-proof state, so a route can say "locked" rather than report a
    correct code as incorrect. A password re-proof is never refused for a lock (BACKLOG #1138).

    ``ok`` is DERIVED, not stored, and that is load-bearing rather than tidiness. Held as a field it
    was a second spelling of ``token is not None`` -- true of all 19 constructions -- so the type
    could represent a state the system never produces, mypy could not narrow ``token`` from ``ok``,
    and every consuming site paid ``if not elevation.ok or elevation.token is None``: a second clause
    whose only job was to re-derive the first in a form the checker accepts. As a property the
    impossible combination cannot be constructed and one clause narrows.
    """

    token: str | None = None
    session_lost: bool = False
    recovery_codes: tuple[str, ...] = ()
    locked: bool = False
    #: Set only by :meth:`AuthService.reauth`, on a session the federated login minted (BACKLOG #296,
    #: ADR 0142 Amendment B). Such a session steps up at the IdP, never by a password, so nothing was
    #: checked and nothing was charged. It qualifies the wrong-proof state: the token still
    #: authenticates, and the caller must send the operator to the IdP leg rather than re-prompt.
    idp_step_up_required: bool = False
    #: Set only by :meth:`AuthService.verify_mfa`, on a directory account the directory did not
    #: confirm as present and enabled, including when it could not be reached (BACKLOG #2023). The
    #: code was never checked and nothing was charged. It qualifies the wrong-proof state: the token
    #: still authenticates, and the caller must say the directory could not confirm the account
    #: rather than call the code wrong.
    directory_unconfirmed: bool = False

    @property
    def ok(self) -> bool:
        """Elevated: a new session token was minted. See the class docstring for the three states."""
        return self.token is not None


@dataclass(frozen=True)
class OidcStepUp:
    """The outcome of the federated step-up leg's callback (BACKLOG #296, ADR 0142 Amendment B).

    ``elevation`` has :class:`Elevation`'s three states. ``return_to`` is the continuation the start
    leg staged, handed back so the route never trusts the callback's query for it. On a refusal,
    ``reason`` is a closed-set slug for the audit row and ``error`` is operator-readable text that
    carries nothing the IdP supplied.
    """

    elevation: Elevation
    return_to: str = "/ui"
    reason: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Elevated: the staged session was rotated to a new token."""
        return self.elevation.ok


class CurrentPasswordCheck(Enum):
    """The answer :meth:`AuthService.verify_current_password` gives ``POST /me/password``.

    ``SESSION_ENDED`` is held apart from ``WRONG`` for the reason :class:`Elevation` holds
    ``session_lost`` apart: the route must answer 401 and send the caller to sign in, not re-prompt
    for a password on a session that no longer exists (BACKLOG #1138)."""

    OK = "ok"
    WRONG = "wrong"
    SESSION_ENDED = "session_ended"
    #: BACKLOG #2009 (ASVS 6.4.1): the account holds an admin-issued temporary credential whose
    #: deadline has passed. The sign-in gate refuses it past that instant; this refuses the rotation
    #: a session opened before the instant would otherwise still perform with it.
    EXPIRED = "expired"


@dataclass(frozen=True)
class MfaEnrollment:
    """A staged (not-yet-confirmed) TOTP enrollment: the base32 secret to render as a QR + the
    ``otpauth://`` URI. Returned **once**; confirmed by proving a live code."""

    secret: str
    otpauth_uri: str


@dataclass(frozen=True)
class MfaStatus:
    """A local user's current MFA posture, for ``GET /me/mfa``.

    ``enabled`` stays == TOTP-enabled on the wire (the desktop console's boolean view is
    untouched); ``webauthn_enrolled`` is the ADR 0068 additive field — ``required`` accounts for
    EITHER factor being enrolled (enrolled-any-factor ⇒ always required)."""

    enabled: bool
    enrolled_at: float | None
    recovery_codes_remaining: int
    required: bool
    webauthn_enrolled: bool = False


class FirstAdministratorRefused(RuntimeError):
    """:meth:`AuthService.provision_first_administrator` declined. The message is operator-facing."""


class TemporaryPasswordUnavailable(RuntimeError):
    """No generated temporary password cleared the active policy. It points at the site's context
    words, the one setting that can make a random string fail the screen nearly every time."""


#: How many random tokens the temporary-password generator tries before it refuses. A 32-character
#: token misses the shipped list about 99.96% of the time, and misses 200 three-character site terms
#: about 86% of the time (both measured 2026-09-28, 20,000 tokens each). Even a list refusing half of
#: all tokens fails 64 tries about once in 10**19. Those rates are for 32 characters, the length
#: at the shipped ``min_length``. A longer token meets more terms: the generator cuts each one to
#: ``_temporary_password_chars``, which removes the ``token_urlsafe`` overshoot, but above 32 the
#: length still follows ``min_length``. So the refusal means the site's list refuses nearly every
#: random string as long as the passphrase a user must type: a setting to fix, not bad luck.
#: The refusal logs this constant, and CodeQL's clear-text-logging rule flags a logged value by its
#: NAME (alert 227, BACKLOG #1132). So keep every word its sensitive-data heuristics match out of
#: the name: at least "password", "passphrase", "secret", "token", "account" and "cert".
_RESET_GENERATION_ATTEMPTS = 64


def _temporary_password_chars(min_length: int) -> int:
    """The generated password's length: the policy minimum, but never under 32 characters.
    ``token_urlsafe`` carries 6 bits per character, so 32 characters keep the 192-bit floor of BACKLOG
    #1172, and any longer minimum carries more."""
    return max(32, min_length)


# Characters that let one address field name more than one mailbox, or smuggle a display name or a
# header, when ``send_plain_email`` joins the recipients into ``To``. Checked by hand, not by a regex.
_ADDRESS_FORBIDDEN_CHARS = frozenset(',;<>"()[]:\\')


def _is_single_mailbox(address: str) -> bool:
    """Whether ``address`` reads as exactly one plain ``local@domain`` mailbox (BACKLOG #1139).

    A shape check, not proof of delivery: nothing here can tell that the holder reads it. It exists so
    the self-service fill cannot be satisfied by ``x``, and cannot fan every later notice out to two
    mailboxes with ``a@b.org, c@d.org``. The address cannot be changed again without an administrator,
    so a typo caught here is one the holder can still fix.
    """
    local, at, domain = address.partition("@")
    return (
        bool(at)
        and bool(local)
        and "@" not in domain
        and "." in domain.strip(".")
        and not domain.startswith(".")
        and not domain.endswith(".")
        and all(ch.isprintable() and not ch.isspace() for ch in address)
        and not any(ch in _ADDRESS_FORBIDDEN_CHARS for ch in address)
    )


def _is_adoptable_directory_address(address: str) -> bool:
    """Whether a stripped, directory-supplied ``address`` may stand as a notification address.

    One plain mailbox (:func:`_is_single_mailbox`), pure ASCII, and no ``xn--`` domain label, so a
    directory writer cannot pass off a homoglyph lookalike of the holder's real address. It does
    NOT catch an all-ASCII lookalike such as ``examp1e``.

    Two decisions share it, and neither may loosen it for itself: what the address form offers
    (:meth:`AuthService.suggested_notify_email`, BACKLOG #1139) and whether a directory account's
    birth seeds ``notify_email`` from its ``mail`` (BACKLOG #2014).
    """
    if not _is_single_mailbox(address) or not address.isascii():
        return False
    domain = address.rpartition("@")[2]
    return not any(label.lower().startswith("xn--") for label in domain.split("."))


def _adopts_directory_mail(principal: AdPrincipal) -> bool:
    """Whether a directory birth seeds ``notify_email`` from ``principal``'s ``mail`` (BACKLOG #2014).

    ``True`` for an absent ``mail`` too: there is nothing to refuse, and the seed is NULL. The one
    predicate both the birth and the administrator's create ask (BACKLOG #2021)."""
    directory_mail = (principal.email or "").strip()
    return not directory_mail or _is_adoptable_directory_address(directory_mail)


class InvalidNotifyEmail(ValueError):
    """A notification address was refused before anything was written (BACKLOG #1139).

    A ``ValueError``, so a caller that catches that still does. Its own type lets a route turn
    exactly this refusal into a ``400``, and not some other ``ValueError`` raised after a write."""


def _require_single_mailbox(value: str) -> str:
    """``value`` stripped, when it may become a notification address; else :class:`InvalidNotifyEmail`.

    The check both engine surfaces that take a typed address apply: the holder's own fill and an
    administrator's explicit change. Not blank (:func:`require_notify_email`), and one plain
    mailbox (:func:`_is_single_mailbox`)."""
    try:
        address = require_notify_email(value)
    except ValueError as exc:
        raise InvalidNotifyEmail(str(exc)) from exc
    if not _is_single_mailbox(address):
        raise InvalidNotifyEmail("enter one email address, such as name@example.org")
    return address


class NotifyEmailAlreadySet(RuntimeError):
    """:meth:`AuthService.fill_own_notify_email` declined: the account already has a different
    notification address. The self-service route only fills a missing one (BACKLOG #1139)."""


class _DirectoryLoginRefused(Exception):
    """The mirror row a directory login resolved is not eligible to sign in.

    Raised by :meth:`AuthService._upsert_ad_user`, caught by its ONE caller
    :meth:`AuthService._complete_ad_login`, which renders it as the audited refusal.

    **Why the resolver signals by raising rather than by returning.** The id-keyed lookup that finds
    a directory-side RENAMED row runs inside the resolver, below the caller's own name-keyed read,
    and the refusal has to land BEFORE the resolver's profile, name and role writes. A resolver that
    reported the condition in its ``UserRecord`` return value would have done those writes already,
    which is the half of BACKLOG #1637 a check on the returned value cannot close.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _FederatedBindingWithdrawn(Exception):
    """An admin unbound the account's federated identity while this login was still in flight.

    Raised by :meth:`AuthService._issue_session` when the store refuses the conditional insert, and
    caught by :meth:`AuthService._complete_ad_login`, which renders it as an audited refusal
    (BACKLOG #1474).

    **Signalled by raising because the alternative loses the race it exists to close.** The store
    refuses inside the same transaction that re-reads the binding, so there is no point at which the
    caller could have asked "is it still bound?" and acted on the answer — a second call would be a
    second transaction. The exception carries the refusal out of a method whose whole contract is
    "returns the token", without giving every other caller a ``None`` to handle.
    """


class FederatedSubjectHeld(RuntimeError):
    """:meth:`AuthService.bind_federated_subject` declined on a conflict (BACKLOG #1143): a DIFFERENT
    account already holds the ``(issuer, sub)`` it was asked to bind, or another request bound THIS
    account while a REBIND ran, after its clear had removed the old pair. The message is
    operator-facing and says which. A bind that wrote nothing because the pair changed raises
    :class:`FederatedBindingChanged` instead (BACKLOG #2026).

    Refused rather than moved. Moving a binding hands the subject the newer account and strands the
    older one, which is the takeover shape the #1256 exclusivity guard exists to prevent. An operator
    who means to move it unbinds the holder first, and that act is audited on its own.
    """


class FederatedBindingChanged(RuntimeError):
    """A federated bind or unbind was refused because the account's stored ``(issuer, sub)`` is no
    longer the pair the caller said it saw (BACKLOG #2026). Nothing was written and no session was
    revoked. The routes answer it 409; the message opens with :data:`FEDERATED_BINDING_CHANGED`.

    Without it, two administrators acting in turn let the second, working from a stale read,
    replace or remove a binding the first wrote and the second never saw. The store makes the
    comparison under the clear's own row lock, so no write can land between it and the clear.
    """

    def __init__(self, *args: object) -> None:
        # Defaulted rather than argument-free, so pickling and copying, which rebuild the exception
        # from ``args``, still work.
        super().__init__(
            *(
                args
                or (
                    f"{FEDERATED_BINDING_CHANGED}: the account's federated binding changed after"
                    " you read it, so nothing was changed; read it again and retry",
                )
            )
        )


class ChannelScopeSourceConflict(RuntimeError):
    """:meth:`AuthService.set_channel_scope` refused a write on who owns the scope (BACKLOG #2098).
    ``PUT /users/{id}/channel-scope`` answers it 409 with the message, which names the conflict and
    never the scope.

    Three causes. The stored scope is the directory's and the caller did not send
    ``expected_source="ad"``, so the write would make it manual without anyone saying so. The
    caller's ``expected_source`` does not match the stored one. Or an AD sign-in changed the source
    between this write's read and its compare-and-set."""


class UsernameTaken(RuntimeError):
    """:meth:`AuthService.create_local_user` lost a concurrent create's race for its username
    (BACKLOG #1808). ``POST /users`` answers it 409, with its own pre-check's text.
    :meth:`AuthService.create_directory_account` raises it too, when a row already holds the
    directory account's name or id (BACKLOG #2021)."""


class DirectoryAccountNotFound(ValueError):
    """:meth:`AuthService.create_directory_account` found no enabled directory account by the name
    given (BACKLOG #2021). ``POST /users/directory`` answers it 404."""


class DirectoryAccountRefused(ValueError):
    """:meth:`AuthService.create_directory_account` refused before its lookup: no directory is
    configured, or the name is blank (BACKLOG #2021). ``POST /users/directory`` answers it 400."""


class DirectoryObjectIdMissing(ValueError):
    """:meth:`AuthService.bind_federated_subject` refused an account that carries no
    ``directory_object_id`` (BACKLOG #1143 slice C, ADR 0184 AC-5).

    A ``ValueError`` so every caller that already maps the bind's refusals keeps doing so: the API
    route answers 400 with the message, and the console screen shows it. ``reason`` is the
    closed-set code the audit row carries.

    **WHY A ROW WITH NO ID MAY NOT TAKE A BINDING.** Such a row is re-resolved by its USERNAME, by
    the federated login's re-resolve and on every ``reconcile_directory_sessions`` pass, because the
    engine has no other key for it. A directory may reissue a freed name to a different person. The
    bound row would then take the new person's groups, and the pair's holder would sign in with
    them. AC-5 says a bound row is not re-resolved from its username in the reconciler.

    **WHAT THE REFUSAL MAKES HOLD, AND WHAT IT DOES NOT.** Every binding the administrative bind
    writes sits on a row carrying an id, and the id is written at the row's creation and never
    cleared, so both re-resolves above ask by the id for it. It does not reach at least these: a
    direct ``set_user_federated_subject`` call, which checks no id, and whose one caller is the
    bind; the step-up re-proof, which binds by name; and a Windows SSO sign-in, which finds an
    id-less row by its name whether or not the row is bound. For a binding already on an id-less
    row, written before this refusal existed or planted through that setter, the two re-resolves
    above no longer ask by name (BACKLOG #2027): the federated login refuses it with this same
    reason, and the reconciler skips it (``_holds_unkeyed_federated_binding``).
    **The cost:** on a directory that returns no readable ``objectGUID``, no account can be bound.

    :meth:`AuthService.create_directory_account` raises it too, before any write, when the directory
    returns no readable ``objectGUID`` for the account named: the row it would create could never
    take a binding (BACKLOG #2021).
    """

    reason = DIRECTORY_OBJECT_ID_MISSING


@dataclass(frozen=True)
class FederatedBinding:
    """What :meth:`AuthService.bind_federated_subject` wrote (BACKLOG #1143).

    ``previous_*`` are ``None`` for a first bind. ``sessions_revoked`` is non-zero only on a rebind,
    where the prior identity's sessions end in the same transaction that clears its binding.
    """

    issuer: str
    subject: str
    previous_issuer: str | None
    previous_subject: str | None
    sessions_revoked: int


def _is_integrity_refusal(exc: BaseException) -> bool:
    """Whether ``exc`` is a backend's integrity refusal, matched by MRO NAME.

    It matches a foreign-key refusal as well as a UNIQUE one. sqlite3 raises the same
    ``IntegrityError`` for both (measured). asyncpg's ``ForeignKeyViolationError`` sits under
    ``IntegrityConstraintViolationError`` in its documented hierarchy, not measured here because
    asyncpg is an optional install. ``finish_webauthn_registration`` depends on this, since it tells
    the two apart only after this returns true (BACKLOG #1807).

    Each backend raises its own class -- ``sqlite3.IntegrityError``, asyncpg's
    ``UniqueViolationError``, pyodbc's ``IntegrityError`` -- and naming them would make this module
    import-aware of every driver and silently stop covering a backend added later. The ONE copy of
    this test. At least these call it: the webauthn duplicate-label race (ADR 0068 section 4), the
    cached-username refresh, the federated bind, and the local-account username race (BACKLOG
    #1808). ``_refresh_cached_username`` records why the test is on "Integrity" and not
    "IntegrityError", and the one engine class the name test would wrongly absorb.
    """
    mro = "".join(t.__name__ for t in type(exc).__mro__)
    return "Integrity" in mro or "UniqueViolation" in mro


def _reproof_refusal_reason(proof: _Reproof) -> str:
    """The closed-set ``reason`` a refused password-change re-proof is audited with."""
    if proof.session_revoked:
        return "session_revoked"
    if proof.session_gone:
        return "session_gone"
    return "bad_password"


def _live_lock(user: UserRecord, now: float) -> bool:
    """Whether ``user``'s SIGN-IN lock has not yet expired at ``now`` (ADR 0197: the counter the
    re-proofs feed). The second-step lock is :meth:`UserRecord.second_step_locked`."""
    return user.locked_until is not None and now < user.locked_until


#: The ONE audit reason a refused sign-in on an existing, enabled local account records, combined or
#: password-only, whichever factor was wrong and whatever lock refused it (BACKLOG #1131). It must not name which factor verified: the
#: ``auth.login_failed`` row is read by an ``audit:read`` holder who is not an administrator (the
#: built-in ``AUDITOR`` role), and a per-factor slug there was a password oracle -- the sign-in lock
#: does not refuse a combined sign-in, so such a reader could arm the lock, send candidate passwords
#: with any six digits, and read off the trail, ONE request per candidate, which candidate was
#: right. The uniform slug removes that per-request oracle. The COUNTER routing below still splits
#: by factor (ADR 0197): the failure COUNTS are read only through the ``users:manage`` lock-state
#: surface, and the counting is what stops a password holder guessing codes uncounted, so it must
#: not collapse.
#:
#: **The coarser lock-event oracle is closed by owner ruling 2026-09-28.** The second-step counter is
#: fed only by a right factor, so sending one candidate ``lockout_threshold`` times locks that
#: counter iff the password was right. The lock rows that follow are now read only with
#: ``users:manage`` (:mod:`messagefoundry.auth.audit_visibility`), and a refusal BY a lock writes the
#: same ``auth.login_failed`` row as a wrong credential, before its users:manage-only
#: ``auth.login_locked`` (:func:`_local_refusal_detail`). So a reader without ``users:manage`` sees
#: one identical row per refused attempt in every lock state. It is also why a PASSWORD-ONLY refusal
#: uses this reason and not ``bad_password``: a refusal by a live lock never checked the password,
#: and a slug saying it was wrong would be false in the administrator's view, while a different
#: slug would show everyone else that a lock was live.
_LOCAL_REFUSAL_REASON = "bad_credentials"


async def _run_in_order(writes: Sequence[Callable[[], Awaitable[None]]]) -> None:
    """Run deferred audit writes one after another, in the order they were queued."""
    for write in writes:
        await write()


def _local_refusal_detail(reason: str, *, combined: bool) -> str:
    """The ``auth.login_failed`` detail of a refused local credential sign-in (BACKLOG #1131).

    The one builder for both the verified refusal and the refusal by a lock, so the row a reader
    without ``users:manage`` sees cannot differ between them by a key, a value or their order."""
    detail: dict[str, Any] = {"provider": "local", "reason": reason}
    if combined:
        detail["combined"] = True
    return _json(detail)


def _route_combined_failure(
    *, password_ok: bool, code_ok: bool
) -> tuple[LockoutCounter, str, str | None]:
    """Where one refused COMBINED sign-in counts: ``(counter, audit reason, factor that was right)``.

    ADR 0197's routing table. Exactly one factor right counts on the SECOND-STEP counter, since only
    a caller holding the password or the TOTP device can get one right; neither right counts on the
    SIGN-IN counter, which a live sign-in lock leaves unextended.

    The audit reason is :data:`_LOCAL_REFUSAL_REASON` for ALL THREE arms, so the
    ``auth.login_failed`` row an ``audit:read`` holder reads is identical whichever factor was wrong
    (BACKLOG #1131). The ``factor`` still names which factor verified, but it feeds only the
    ``ACCOUNT_LOCKED`` notice, which reaches the account's own holder out of band, never the audit
    trail. The caller learns nothing either: every refusal is the one fixed answer."""
    if password_ok:
        return "second_step", _LOCAL_REFUSAL_REASON, "password"
    if code_ok:
        return "second_step", _LOCAL_REFUSAL_REASON, "code"
    return "sign_in", _LOCAL_REFUSAL_REASON, None


def _holds_lockout_state(user: UserRecord) -> bool:
    """Whether any of the six lockout columns is off its "no history" value, so a full
    authentication has something to clear (ADR 0197 AC-8)."""
    return bool(
        user.failed_attempts
        or user.locked_until is not None
        or user.lock_cycles
        or user.second_step_failed_attempts
        or user.second_step_locked_until is not None
        or user.second_step_lock_cycles
    )


#: How the reconciler reads each directory refusal (ADR 0195 rule item 1). FOUND is absent on
#: purpose: a found account carries a principal and never reaches this map.
_REFUSED_OUTCOMES: dict[DirectoryAnswer, reconcile.ProbeOutcome] = {
    DirectoryAnswer.NOT_FOUND: reconcile.ProbeOutcome.ABSENT,
    DirectoryAnswer.DISABLED: reconcile.ProbeOutcome.DISABLED,
    DirectoryAnswer.UNDETERMINED: reconcile.ProbeOutcome.UNDETERMINED,
}


def _holds_unkeyed_federated_binding(user: UserRecord) -> bool:
    """Whether ``user`` carries a federated binding but no ``directory_object_id`` (BACKLOG #2027).

    Either half of the pair counts as a binding, matching the unbind's own predicate. Such a row's
    only directory key is its username, and ADR 0184 AC-5 forbids re-resolving a bound row by that,
    so the engine has no key it may ask the directory with.
    """
    has_binding = user.oidc_issuer is not None or user.oidc_subject is not None
    return has_binding and not user.directory_object_id


def _directory_login_refusal(user: UserRecord, now: float) -> str | None:
    """The closed-set reason a directory login must refuse ``user``'s mirror row, or ``None``.

    BACKLOG #1637 (``disabled``) and #1638 (``locked``). Both states used to be invisible to a
    directory sign-in: ``_complete_ad_login`` checked provider and directory id and neither of these,
    so an engine-disabled mirror row completed Kerberos or OIDC login with an ``auth.login_success``
    row and a live session, and a lock set by five wrong TOTP codes was cleared by one re-login.

    The slugs are literals from a closed set, never directory- or IdP-supplied text, because they are
    stored on the audit row and read by the browser layer.
    """
    if user.disabled:
        return "disabled"
    # ADR 0197 AC-5: EITHER lock refuses a directory sign-in. The sign-in lock is read first, so a
    # caller holding only that attribute pair (a test's stand-in row) still gets its answer.
    if user.locked_until is not None and now < user.locked_until:
        return "locked"
    if user.second_step_locked_until is not None and now < user.second_step_locked_until:
        return "locked"
    return None


@dataclass(frozen=True)
class _Reproof:
    """The outcome of one post-session credential re-proof, checked under the login leg's lockout.

    ``user`` is the row read BEFORE the verify, so ``user.failed_attempts`` is the count as it stood
    at the start of the attempt -- the login leg's ``prior_failures``. ``just_locked`` and
    ``attempts`` come from the one atomic store call; the caller audits its own row first and only
    then records the lockout, so the order in the trail matches the login leg's. ``cleared`` says a
    success reset the counter, which happens only at full authentication. ``session_revoked`` says
    this attempt spent the session's re-proof budget; the caller audits it and then revokes the
    session with :meth:`AuthService._revoke_for_budget`."""

    ok: bool
    session_revoked: bool = False
    #: The session was already gone (revoked or rotated away) when the attempt got the lock. It was
    #: not verified and this attempt revoked nothing.
    session_gone: bool = False
    user: UserRecord | None = None
    attempts: int = 0
    just_locked: bool = False
    #: The sign-in lock's cycle count after this attempt (ADR 0197), carried to the lock notice.
    cycles: int = 0
    cleared: bool = False


@dataclass
class _KeyedLock:
    """One entry of a per-account lock table, with a count of the tasks holding or awaiting it so the
    entry can be dropped when the last one leaves. The re-proof table and the credential table both
    use it (:func:`_hold_keyed_lock`)."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


@asynccontextmanager
async def _hold_keyed_lock(table: dict[str, _KeyedLock], key: str) -> AsyncIterator[None]:
    """Hold ``table``'s lock for ``key``, creating the entry on first use and dropping it once no
    task holds or awaits it, so the table never outgrows the attempts in flight.

    ``asyncio.Lock`` wakes its waiters in arrival order, so the attempts queued on one key run in the
    order they arrived."""
    entry = table.get(key)
    if entry is None:
        entry = table[key] = _KeyedLock()
    entry.users += 1
    try:
        async with entry.lock:
            yield
    finally:
        entry.users -= 1
        if entry.users == 0:
            del table[key]


#: How much of a typed username :func:`_credential_lock_key` reads (BACKLOG #1943). Four times the
#: 256-character column the store keeps, so no real name is cut.
_CREDENTIAL_KEY_INPUT_MAX = 1024


def _credential_lock_key(username: str) -> str:
    """The key that queues sign-in attempts on one account (BACKLOG #1943): the username with outer
    spaces, accents, width, case and invisible format characters folded away.

    **It must be at least as coarse as each shipped backend's username match**, or two spellings
    of one account would get two queues and a burst split between them would overshoot the lockout
    again. SQLite and PostgreSQL compare bytes, and SQL Server's ``username`` column is binary
    (BIN2, BACKLOG #1268), but SQL Server's ``=`` still ignores trailing spaces under any
    collation. So the key must at least fold outer spaces.

    The other folds are margin, for a SQL Server ``users`` table created before #1268 under a
    case- or accent-insensitive default collation (ADR 0169). Such a collation also gives zero
    weight to format characters (Unicode category Cf, such as a soft hyphen or a zero-width
    space), so the key drops those too. **The margin is not a model of every collation.** It does
    not fold kana, for one, and a collation may weigh other characters as equal.

    Coarser costs something, and it is not only latency. Names that fold together share a queue,
    so a flood of spellings that miss an account (``ADMIN`` for ``admin`` on a byte-matching store)
    still holds that account's queue, one padded slot per attempt, without counting a failure.
    The sign-in limiter bounds it, as it bounds a flood of the exact name.

    **Only the first** ``_CREDENTIAL_KEY_INPUT_MAX`` **characters count.** This runs on the event
    loop before any check, and NFKD can expand one character eighteenfold, so an unbounded name
    would stall the loop. A stored username is far shorter, so the cut only merges long names into
    one queue, which is coarser and therefore safe. Spaces are stripped LAST, after the dropped
    characters are gone, so a space before a dropped character cannot survive as a trailing one."""
    decomposed = unicodedata.normalize("NFKD", username[:_CREDENTIAL_KEY_INPUT_MAX])
    kept = "".join(
        c for c in decomposed if not unicodedata.combining(c) and unicodedata.category(c) != "Cf"
    )
    return kept.strip().casefold()


@dataclass(frozen=True)
class ProvisionedAdministrator:
    """The outcome of an offline first-administrator provision (BACKLOG #1136).

    ``repaired`` distinguishes a fresh provision from completing one an earlier run left half-written,
    so the CLI can say which happened rather than reporting both as "created".

    ``holder_notice`` is what happened to the takeover notice owed to a repaired account's earlier
    holder (BACKLOG #2019), and is the same value the audit row records: ``None`` on a fresh create,
    which has no earlier holder, else one of :data:`HOLDER_NOTICE_DISPATCHED`,
    :data:`HOLDER_NOTICE_NO_PRIOR_ADDRESS` or :data:`HOLDER_NOTICE_NO_CHANNEL`.
    """

    user_id: str
    username: str
    repaired: bool
    holder_notice: str | None = None


# BACKLOG #2019: the three outcomes of the notice a repair owes the account's earlier holder. They are
# recorded on the `auth.first_administrator_provisioned` audit row and returned to the CLI.
#: The notice was handed to the notifier. NOT a delivery receipt: the send is best-effort and a failed
#: one is only logged.
HOLDER_NOTICE_DISPATCHED = "dispatched"
#: The account had no notification address before the repair, so there was nobody to tell.
HOLDER_NOTICE_NO_PRIOR_ADDRESS = "no_prior_address"
#: The account had an address, but nothing was handed off: no channel was wired, notices are turned
#: off, or the notifier raised (each logged where it applies).
HOLDER_NOTICE_NO_CHANNEL = "no_channel"


@dataclass(frozen=True)
class IssuedCredential:
    """An admin-issued one-time credential and the instant it stops working.

    BACKLOG #1141 (ASVS 6.4.5). The renewal instruction for an expiring mechanism has to be *sent*
    with the mechanism, and :meth:`AuthService.admin_reset_password` used to return the password
    alone -- so the one artifact that reaches the issuing administrator carried no deadline, and
    neither did anything downstream of it. Pairing the two in the return type means a caller cannot
    surface the credential and forget the deadline: there is nothing else to unpack.

    ``expires_at`` is :meth:`AuthService.initial_credential_deadline` over the STORED
    ``password_changed_at``, which is the value the login gate itself refuses on -- not a fresh clock
    read and not a second computation. ``None`` means ``[auth].initial_password_expiry_hours`` is 0,
    i.e. the credential genuinely has no deadline, which is what the gate does in that case too.
    """

    password: str
    expires_at: float | None = None


@dataclass(frozen=True)
class CustomRoleInfo:
    """An admin-defined custom role and its resolved permission subset (ADR 0045)."""

    id: str
    display_name: str
    description: str | None
    permissions: frozenset[Permission]


def _row_builtin(row: Any) -> bool:
    """Whether a ``roles`` row is a built-in. Tolerant of each backend's truthy representation of the
    ``builtin`` column (SQLite ``int`` 0/1, Postgres ``bool``, SQL Server ``bit``)."""
    return bool(row["builtin"])


def _roles_from_ids(ids: Iterable[str]) -> frozenset[Role]:
    """Map stored role ids to :class:`Role`; silently drop unknown ids (deny-by-default)."""
    out: set[Role] = set()
    for rid in ids:
        try:
            out.add(Role(rid))
        except ValueError:
            continue
    return frozenset(out)


def _json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True)


# BACKLOG #1138, ASVS 6.3.5: the audit action each suspicious-sign-in event is recorded under. A fixed
# map, not ``f"auth.{event_type}"``, so the action names stay greppable and no other notice kind can
# be passed in and double-audit an event its own call site already audits.
#: ADR 0197 Decision item 7: the audit row a mailed ``ACCOUNT_LOCKED`` notice writes, and the window
#: it throttles over. See :meth:`AuthService._lock_notice_due`.
_LOCK_NOTICE_ACTION: Final = LOCK_NOTICE_ACTION
_LOCK_NOTICE_WINDOW_SECONDS: Final = 24 * 3600.0

#: BACKLOG #2007, ASVS 6.4.5: how :meth:`AuthService._temporary_credential_issuer` finds the audit row
#: that issued an account's current temporary password. The two issuing paths stamp
#: ``password_changed_at`` first and write their audit row a moment later, both off the same Python
#: clock, so the row sits just after the stamp; only one or two store writes lie between them. The
#: window allows a slow store on the late side and a clock step on the early side, and no more,
#: because every create and reset in it counts against the page. A page that comes back full may
#: have dropped the row that matters, so a full page is treated as unresolved rather than read. Each
#: action maps to the detail key that names the account: ``user.created`` carries only the username.
_ISSUE_ROW_KEYS: Final[Mapping[str, str]] = MappingProxyType(
    {"user.created": "username", "auth.password_reset": "user_id"}
)
_ISSUE_ROW_EARLY_SECONDS: Final = 5.0
_ISSUE_ROW_LATE_SECONDS: Final = 60.0
_ISSUE_ROW_PAGE: Final = 200
#: The audit rows the reminders write, one per recipient told (BACKLOG #2007). Each names its
#: recipient as the actor, so the reminder shows in that account's ``/me/security-events`` feed.
_REMINDER_HOLDER_ACTION: Final = "auth.temporary_credential_expiring"
_REMINDER_ISSUER_ACTION: Final = "auth.temporary_credential_expiring_issuer"

_SUSPICIOUS_LOGIN_ACTIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        ACCOUNT_LOCKED: ACCOUNT_LOCKED_ACTION,
        LOGIN_AFTER_FAILURES: "auth.login_after_failures",
    }
)


def _allowed_channels(user: UserRecord, roles: frozenset[Role]) -> frozenset[str] | None:
    """Resolve a user's stored per-channel RBAC scope to a frozenset, or ``None`` for all channels.

    **An ABSENT scope denies (BACKLOG #1152, ASVS 8.2.2).** ``create_user``'s INSERT does not list
    ``channel_scope``, so every account is minted with SQL NULL there; NULL used to resolve to
    ``None`` = every channel, which made every per-channel check in the API narrow nobody on a
    default install. It now resolves to the empty set, so a freshly minted non-administrator reaches
    no connection until an administrator grants one.

    Unrestricted is still reachable, and both ways are a deliberate grant: the ADMINISTRATOR role,
    or :data:`~messagefoundry.auth.identity.ALL_CHANNELS` present in the stored list. A JSON list is
    otherwise exactly those connections, and anything malformed is no channels. The stored value is
    parsed by :func:`~messagefoundry.auth.channel_scope.scope_channels`, which the directory
    reconciler's scope decision also uses (ADR 0198)."""
    if Role.ADMINISTRATOR in roles:
        return None
    return channel_scope.scope_channels(user.channel_scope)


#: The IdP legs' OWN way across. The connection-shaped default cannot reach this opener, which
#: resolves no trust anchor; see :attr:`~messagefoundry.config.tls_policy.RevocationHopGuard.ways_across`.
_IDP_WAYS_ACROSS = (
    "Set [auth].oidc_tls_crl_file to a PEM file holding a CRL from each CA that issues the token "
    "and JWKS endpoint certificates, so the engine checks revocation on both legs. Put only CRLs "
    "in it: a certificate not already in the hop's trust store refuses start."
)

#: Stands in for a URL with no host. NOT the empty string: `is_loopback_hop_host("")` is True, so an
#: empty host would take the on-box carve-out and a guard that cannot name its host would ALLOW.
_NO_HOST = "(no host)"


def idp_revocation_guards(
    settings: AuthSettings, opener: urllib.request.OpenerDirector, posture: HopPosture | None
) -> tuple[RevocationHopGuard, ...]:
    """Capture the #201 revocation guard for each OIDC leg, token endpoint first (BACKLOG #1887).

    Pure: it decides nothing and logs nothing. :func:`_refuse_idp_revocation` enforces what it
    returns, and ``messagefoundry verify`` reads each guard's
    :meth:`~messagefoundry.config.tls_policy.RevocationHopGuard.disposition` (BACKLOG #1923), so the
    report and the engine read one rule rather than two copies of it."""
    context = opener_tls_context(opener, connector="OIDC identity provider (token + JWKS)")
    legs = (
        (
            settings.oidc_token_endpoint,
            "token endpoint",
            "the client secret and authorization code",
        ),
        (settings.oidc_jwks_uri, "jwks_uri endpoint", "the identity provider's signing keys"),
    )
    return tuple(
        RevocationHopGuard.capture(
            # _NO_HOST is reached only by unvalidated settings: the validator refuses a missing URL.
            host=urllib.parse.urlsplit(url or "").hostname or _NO_HOST,
            cell=f"[auth] OIDC {leg} (verified TLS, no revocation check)",
            description=(
                f"carries {carries} over verified TLS but performs no certificate revocation checking"
            ),
            attested=False,
            context=context,
            posture=posture,
            ways_across=_IDP_WAYS_ACROSS,
            connection=None,  # an IdP leg, not a connection
        )
        for url, leg, carries in legs
    )


def _refuse_idp_revocation(
    settings: AuthSettings, opener: urllib.request.OpenerDirector, posture: HopPosture | None
) -> None:
    """Apply the #201 posture-keyed revocation guard to BOTH OIDC legs (BACKLOG #1887, ADR 0173 §4.3).

    **Two guards, never one.** The token endpoint and the JWKS URI are validated one URL at a time
    and nothing requires them to share a host (#1158), so they may differ in loopback status. A single
    guard keyed on the token host would let an off-box JWKS cross unguarded. Each leg derives its own
    ``host=`` from its own URL; both read the ONE context the shared opener carries.

    Called with the FINISHED opener, which is the point of ``context=``: an ``oidc_tls_crl_file`` that
    really loaded sets ``VERIFY_CRL_CHECK_LEAF`` on that context, and the guard reads the flag rather
    than the setting. Guarding before the opener exists would refuse an operator who had already
    closed the gap, while telling them to set the CRL they had set.

    ``posture`` is PASSED, never read ambiently: ``AuthService`` is built in the API lifespan, outside
    every ``active_hop_posture`` scope, which is the position ``auth/ldap.py`` is already in. ``None``
    leaves both guards the shipped no-op.

    ``attested=False`` because no per-hop revocation attestation exists for these legs. There is no
    ``[auth]`` key for one, and borrowing another hop's claim is how a flag silently widens.

    The API lifespan builds ``AuthService`` before ``engine.start()`` (BACKLOG #1923), so this refusal
    comes before any connection starts. ``messagefoundry check`` still does not reach it; ADR 0173
    AC-4 records that limit. Two more are recorded only here: when both legs refuse, only the token
    leg is named, because it is checked first; and the WARN arm logs with no audit sink after
    ``configure_logging`` has set the root level, so a level above WARNING would likely filter it, as
    ``logging_setup._refuse_forward_revocation`` measured for its hop."""
    for guard in idp_revocation_guards(settings, opener, posture):
        guard.enforce_construction()


class AuthService:
    """Authentication + RBAC orchestration over an :class:`AuthStore` and the configured directory."""

    def __init__(
        self,
        store: AdminStore,
        settings: AuthSettings,
        *,
        ldap: LdapAuthenticator | None = None,
        security_notifier: SecurityNotifier | None = None,
        secret_provider: SecretProvider | None = None,
        enforcing: bool = True,
        hop_posture: HopPosture | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        self.enabled = settings.enabled
        # #285 (ASVS 6.7.1): the ADR 0148 [security].enforcement dial, threaded in by the caller
        # (the lifespan passes trust_anchors_enforcing). It gates the OIDC anchor's construction-site
        # ACL preflight in build_idp_opener below so a group/world-writable anchor WARNS (not refuses)
        # in warn mode — matching the central run_anchor_preflight and build_api_ssl_context. The LDAP
        # authenticator's AD CA check reads it too (BACKLOG #2034). AuthSettings carries no
        # [security] block, so the dial cannot be read off settings here; it must be passed.
        # Defaults enforce (fail-closed).
        self._trust_anchors_enforcing = enforcing
        # Out-of-band security-event push (ASVS 6.3.5/6.3.7), injected by the API lifespan. None = no
        # email push. What the /me/security-events pull feed still shows is stated once, in
        # auth/notifications.py. Best-effort.
        self._security_notifier = security_notifier
        self._policy = PasswordPolicy.from_settings(settings)
        _warn_if_corpus_unreadable(settings.password_breach_corpus_file)
        _error_if_bundled_corpus_unusable(settings.password_check_breached)
        if ldap is not None:
            self._ldap: LdapAuthenticator | None = ldap
        elif settings.ad_enabled:
            # Thread the connector SecretProvider (ADR 0019 §5) so an ad_bind_password_secret reference
            # resolves the bind password from the external backend (fail-closed) at construction. #329:
            # thread the instance hop posture too — LDAPS is built out of the connector-construction gate,
            # so its ad_tls_verify=false escape clamp is inert unless the posture arrives explicitly here.
            # BACKLOG #2034: the enforcement dial too, since the authenticator now checks its CA anchor.
            self._ldap = LdapAuthenticator(
                settings,
                secret_provider=secret_provider,
                posture=hop_posture,
                enforcing=self._trust_anchors_enforcing,
            )
        else:
            self._ldap = None
        # Instance-scoped (one event loop per AuthService) so it never crosses loops in tests.
        self._argon2_sem = asyncio.Semaphore(_ARGON2_MAX_CONCURRENCY)
        self._login_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.login_rate_limit_per_ip,
                glob=settings.login_rate_limit_global,
                window_seconds=settings.login_rate_limit_window_seconds,
            )
            if settings.login_rate_limit_enabled
            else None
        )
        # Per-actor anti-automation throttle for the PHI-read endpoints (WP-8, ASVS 2.4.1).
        self._phi_read_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.phi_read_rate_limit_per_actor,
                glob=settings.phi_read_rate_limit_global,
                window_seconds=settings.phi_read_rate_limit_window_seconds,
            )
            if settings.phi_read_rate_limit_enabled
            else None
        )
        # Per-actor anti-automation pacing for the state-changing admin surface (BACKLOG #193, ASVS
        # 2.4.2). Built like _phi_read_limiter but consulted from the step-up gate for NON-GET sensitive
        # ops. glob=0 (no cross-actor dimension): one operator's write burst must never throttle
        # another's, and a single unified engine has no need for a global write ceiling here.
        self._admin_write_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.admin_write_rate_limit_per_actor,
                glob=0,
                window_seconds=settings.admin_write_rate_limit_window_seconds,
            )
            if settings.admin_write_rate_limit_enabled
            else None
        )
        # Per-ACTOR budget for the POST-session credential ceremonies (re-auth, password change, MFA
        # enrolment confirm). These used to draw on _login_limiter, whose `glob` is a single budget
        # shared with the UNAUTHENTICATED sign-in surface — so anyone able to reach the login page
        # could exhaust it and lock every signed-in operator out of re-authenticating (and therefore
        # out of every step-up action) without holding a credential. Same knobs as login (no new
        # config), but keyed on the acting USER and glob=0: one account's ceremony burst can never
        # throttle another's, and an unauthenticated flood can no longer reach these at all.
        # Entry-to-session legs (login, negotiate, /ui/sso, the OIDC legs, JSON /auth/mfa-verify)
        # deliberately STAY on _login_limiter. The console's POST /ui/mfa and /ui/reauth* legs
        # charge THIS budget (docs/SECURITY.md lists them): a sign-in flood cannot reach them. It
        # can still refuse an oidc session's IdP step-up, whose return lands on the OIDC callback
        # and draws _login_limiter (the residual in docs/SECURITY.md, ASVS 6.1.1).
        self._reauth_limiter: SlidingWindowRateLimiter | None = (
            SlidingWindowRateLimiter(
                per_key=settings.login_rate_limit_per_ip,
                glob=0,
                window_seconds=settings.login_rate_limit_window_seconds,
            )
            if settings.login_rate_limit_enabled
            else None
        )
        # Per-process dedup of the WP-L3-13 new-client-IP audit/notify side effects: token_hash → the
        # last new client address already flagged for that session. Bounded (_NEW_IP_DEDUP_MAX).
        self._new_ip_seen: dict[str, str] = {}
        # BACKLOG #288: (user id, address) -> monotonic time of the last ``login_new_ip`` notice.
        self._login_new_ip_noticed: dict[tuple[str, str], float] = {}
        # In-flight WebAuthn ceremony challenges (ADR 0068 §2): bounded, TTL'd, process-local —
        # the rate-limiter precedent (single API process is structural). Keys are token-hashes the
        # SERVICE computes; the cache module never sees a session token.
        self._webauthn_challenges = webauthn.ChallengeCache()
        # Single-use per-action step-up grants (ADR 0077): (token_hash, action) -> monotonic deadline.
        # Bounded, TTL'd, process-local — the same shape as the WebAuthn ceremony cache above (and the
        # same accepted per-process caveat). Minted ONLY by reauth(purpose=...) — never by login or
        # verify_mfa — so a login-seeded step-up window can't authorize a durable factor-binding action.
        self._action_step_up_grants: dict[tuple[str, str], float] = {}
        # One in-flight post-session re-proof per account (BACKLOG #1138): user_id -> [lock, users].
        # Process-local like the caches above; an entry lives only while someone holds or awaits it.
        self._reproof_locks: dict[str, _KeyedLock] = {}
        # One in-flight credential check per account on the sign-in and second-step legs (BACKLOG
        # #1943): normalized username -> [lock, users]. See login(). Per API process, with the
        # same caveat as the re-proof table above: engine shards serving their own API ports each
        # keep their own table, so the bound holds per process, not across them.
        self._credential_locks: dict[str, _KeyedLock] = {}
        # Per-SESSION failed re-proofs (BACKLOG #1138): token_hash -> (failures charged to that
        # session, monotonic time of the first, the account's user id). At lockout_threshold the session is revoked, so a stolen session gets that many
        # guesses in total however often the account lock expires. Bounded (_REPROOF_SESSION_MAX,
        # oldest evicted) and carried across a rotation by _rekey_token_state. PROCESS-LOCAL, with the
        # same accepted caveat as _action_step_up_grants: a restart forgets the counts, and a topology
        # that serves the API from more than one process gives each process its own budget.
        self._reproof_session_failures: dict[str, tuple[int, float, str]] = {}
        # Boot-time Kerberos acceptor preflight outcome (ADR 0068 §9): None = usable (or the
        # preflight never ran); a reason string = browser SSO degraded until restart.
        self._kerberos_unavailable_reason: str | None = None
        # Directory session reconciliation (ADR 0079 mechanism 2). Process-local, like the rate
        # limiters and the action step-up grants above — a restart resets the strike counts, which
        # costs at most one extra interval of exposure and is biased toward NOT revoking.
        #: user_id -> consecutive passes the principal failed to resolve.
        self._reconcile_strikes: dict[str, int] = {}
        #: user_id -> monotonic clock of its last probe; orders the per-pass bind budget.
        self._reconcile_last_probed: dict[str, float] = {}
        #: Latched mass-revoke circuit-breaker trip, cleared by the next clean pass.
        self._reconcile_alert: str | None = None
        #: user_id -> the outcome of that candidate's latest probe that reached the directory (ADR
        #: 0195 rule item 3). The undetermined-wave hold counts UNDETERMINED entries here across the
        #: probe rotation, so two unreadable accounts sampled on different passes are still two.
        self._reconcile_outcomes: dict[str, reconcile.ProbeOutcome] = {}
        #: The undetermined-wave hold's operator message (ADR 0195). Its own latch, because a held
        #: pass is not an aborted one and so clears `_reconcile_alert`. Set on a pass that holds,
        #: cleared on the next pass that judges and does not. A pass with no candidates, or a
        #: directory outage, leaves it as it is (rule item 9).
        self._reconcile_hold_alert: str | None = None
        #: The hold's hysteresis latch (`reconcile.hold_latches`). CONTROL state, kept apart from the
        #: message above: it is released as soon as the pruned outcome record holds no UNDETERMINED
        #: entry, including on a pass with no candidates, where the message deliberately stays.
        self._reconcile_hold_latched = False
        #: user_ids of bound id-less rows the reconciler has already reported as skipped (BACKLOG
        #: #2027), so each is logged and audited once per process rather than once per pass.
        self._reconcile_unkeyed_reported: set[str] = set()
        # Advisory, NON-STICKY federated-IdP health (ADR 0142 AC-8) — see the oidc_available docstring.
        self._oidc_unavailable_reason: str | None = None
        self._oidc_client_secret: str | None = None
        self._oidc_jwks: oidc.JwksCache | None = None
        self._oidc_flows: oidc.FlowCache | None = None
        if settings.oidc_enabled:
            # A SEPARATE branch from the ldap one above: secret_provider is otherwise consumed only
            # inside `elif settings.ad_enabled`, so every test that injects ldap= would skip secret
            # resolution entirely and the reference would be dead in tests but live in production.
            self._oidc_client_secret = resolve_connector_secret(
                secret_provider,
                ref=settings.oidc_client_secret_ref,
                literal=settings.oidc_client_secret,
                label="[auth].oidc_client_secret",
            )
            # Eager: a bad CA path or an unresolvable secret must refuse startup, exactly as the AD
            # bind password does. NO network I/O happens here — JwksCache opens no socket until its
            # first get_key — so an UNREACHABLE IdP still constructs cleanly (AC-8).
            # #285 (ASVS 6.7.1): thread the pin + the enforcement dial so the construction-site anchor
            # preflight honors [security].enforcement (warn ≠ refuse) — a pin mismatch always refuses,
            # a group/world-writable DACL refuses only at enforce. Without the dial this seam would
            # hardcode enforce and make warn-mode startup unreachable for the OIDC anchor.
            self._oidc_opener = build_idp_opener(
                settings.oidc_tls_ca_cert_file,
                pin=settings.oidc_tls_ca_cert_pin,
                enforcing=self._trust_anchors_enforcing,
                # BACKLOG #299: revocation checking against the IdP certificate. This hop resolves no
                # trust anchor, so it carries its own CRL setting rather than inheriting [tls].crl_file.
                crl_file=settings.oidc_tls_crl_file,
            )
            # BACKLOG #1887: must follow the opener, whose finished context it reads.
            _refuse_idp_revocation(settings, self._oidc_opener, hop_posture)
            self._oidc_jwks = oidc.JwksCache(
                jwks_fetcher(settings.oidc_jwks_uri or "", self._oidc_opener),
                ttl_seconds=settings.oidc_jwks_ttl_seconds,
                min_refetch_seconds=settings.oidc_jwks_min_refetch_seconds,
            )
            self._oidc_flows = oidc.FlowCache(
                ttl_seconds=settings.oidc_flow_ttl_seconds,
                global_cap=settings.oidc_flow_cache_max,
            )

    async def _argon2(self, fn: Callable[..., _T], *args: Any) -> _T:
        """Run a (CPU-heavy) argon2 hash/verify off-thread under the concurrency cap."""
        async with self._argon2_sem:
            return await asyncio.to_thread(fn, *args)

    def allow_login_attempt(self, client: str | None) -> bool:
        """Rate-limit gate for the unauthenticated auth surface (AUTH-RATE). True = proceed."""
        if self._login_limiter is None:
            return True
        return self._login_limiter.allow(client or "unknown")

    def allow_reauth_attempt(self, actor: str) -> bool:
        """Rate-limit gate for the POST-session credential ceremonies, keyed on the acting user.

        Distinct from :meth:`allow_login_attempt`, whose global budget is shared with the
        unauthenticated sign-in surface, so anyone who can reach the login page can exhaust it. The
        password and re-bind step-up legs (``POST /me/reauth``, ``POST /ui/reauth``) and the passkey
        leg (``POST /ui/reauth/webauthn``) draw this budget instead, so such a flood cannot deny them.

        An ``oidc`` session's step-up is only partly covered. Its start, ``POST /ui/reauth/oidc``,
        draws this budget, but the IdP's return lands on ``GET /ui/oidc/callback``, which draws the
        sign-in window before it tells a step-up from a sign-in. So a flood that fills that window
        refuses the IdP step-up too: a residual, stated in docs/SECURITY.md under the ASVS 6.1.1
        protection set. True = proceed; always True when the limiter is disabled."""
        if self._reauth_limiter is None:
            return True
        return self._reauth_limiter.allow(actor)

    def allow_phi_read(self, actor: str) -> bool:
        """Per-actor anti-automation gate for the PHI-read endpoints (WP-8, ASVS 2.4.1). True =
        proceed; False = throttle. Always True when the limiter is disabled."""
        if self._phi_read_limiter is None:
            return True
        return self._phi_read_limiter.allow(actor)

    def allow_admin_write(self, actor: str) -> bool:
        """Per-actor anti-automation pacing for the state-changing admin surface (BACKLOG #193, ASVS
        2.4.2). True = proceed; False = throttle. Always True when the limiter is disabled."""
        if self._admin_write_limiter is None:
            return True
        return self._admin_write_limiter.allow(actor)

    @property
    def policy(self) -> PasswordPolicy:
        return self._policy

    @property
    def ad_enabled(self) -> bool:
        """Whether this engine can BIND to the directory -- what Kerberos SSO, federated OIDC and the
        session reconciler each need.

        This is a DIRECTORY-BIND capability, never a statement that a user may present a directory
        password: that pathway is retired (BACKLOG #1137). The step-up re-bind still uses the bind,
        so this staying true is correct and is not a leftover."""
        return self._ldap is not None

    @property
    def action_step_up_required(self) -> bool:
        """Whether the durable-takeover routes gate on a per-action step-up grant (ADR 0077, default)
        vs. the legacy session-window step-up. Drives the ``require_step_up_action`` /
        ``require_reauth_only_action`` fallback so an org can opt out via
        ``[auth].require_action_step_up = false``."""
        return self._settings.require_action_step_up

    @property
    def kerberos_enabled(self) -> bool:
        return self._settings.kerberos_enabled and self._ldap is not None

    @property
    def kerberos_available(self) -> bool:
        """``kerberos_enabled`` AND the boot-time acceptor preflight (when run) passed. Drives
        /auth/providers' ``kerberos`` flag, the /ui/login SSO link, and GET /ui/sso — a degraded
        acceptor turns browser SSO off legibly instead of failing per-request. Boot-once: a
        transient DC/SPN failure at start sticks until restart (ADR 0068 §9 open item). The JSON
        /auth/negotiate deliberately keeps its per-request attempt (additive-only)."""
        return self.kerberos_enabled and self._kerberos_unavailable_reason is None

    def mark_kerberos_unavailable(self, reason: str) -> None:
        """Record a failed boot-time SPNEGO acceptor preflight (app lifespan, ADR 0068 §9)."""
        self._kerberos_unavailable_reason = reason

    async def audit_kerberos_reject(self, reason: str) -> None:
        """AUTH-K-AUDIT for route-level SSO rejects that never reach ``authenticate_kerberos``
        (cross-site hygiene, rate-limit exhaustion, malformed base64) — every reject path of a
        Windows-SSO attempt must be visible to a defender."""
        await self._directory_reject_audit("<kerberos>", "kerberos", reason)

    @property
    def oidc_enabled(self) -> bool:
        """Static config: federation is on AND a directory exists to resolve roles against. This is
        the gate the route registrar reads, so ``oidc_enabled=false`` means the ``/ui/oidc/*`` routes
        are never registered at all (ADR 0142 AC-1)."""
        return self._settings.oidc_enabled and self._ldap is not None

    @property
    def oidc_issuer(self) -> str | None:
        """The configured ``[auth].oidc_issuer``, or ``None`` when unset: the only issuer
        :meth:`bind_federated_subject` binds under. Read by the console's federated-identity screen,
        so it offers no Link form that can only be refused (BACKLOG #1143, ADR 0184 slice B)."""
        return self._settings.oidc_issuer or None

    @property
    def oidc_available(self) -> bool:
        """``oidc_enabled`` AND the last IdP interaction did not fail.

        **Deliberately NOT the same shape as** :attr:`kerberos_available`, which is boot-once and
        sticky-until-restart (ADR 0068 §9). This flag is **advisory and non-sticky**: it is set by a
        failed login and cleared by the next successful one, and *no login path gates on it* — the
        start leg always attempts. That is what satisfies AC-8's "SHALL recover without an engine
        restart"; a copy of the Kerberos latch would leave one IdP blip disabling federated login
        until a restart, which is exactly what AC-8 forbids. It exists to drive the login-page link
        and ``/auth/providers``, nothing more. Do not "fix" the asymmetry with the Kerberos twin.

        "A failed login" means an IdP OUTAGE, never a refusal the caller chose: a token endpoint
        refusing a bad ``code`` leaves the flag alone (BACKLOG #1948).
        """
        return self.oidc_enabled and self._oidc_unavailable_reason is None

    def mark_oidc_unavailable(self, reason: str) -> None:
        """Record that an IdP interaction failed. Advisory only — see :attr:`oidc_available`.

        Only for a failure no caller can cause. A token endpoint refusing a bad ``code`` is not one:
        the IdP answered, and a signed-out caller chooses the code (BACKLOG #1948)."""
        self._oidc_unavailable_reason = reason

    def clear_oidc_unavailable(self) -> None:
        """Record that the IdP answered. This is the half that makes recovery restart-free (AC-8)."""
        self._oidc_unavailable_reason = None

    async def audit_oidc_reject(self, reason: str) -> None:
        """Route-level federated-login rejects that never reach :meth:`authenticate_oidc` (flow-cookie
        binding failures, rate-limit exhaustion, a non-navigation fetch). ``reason`` must be a
        closed-set slug chosen by the route — never IdP-supplied text."""
        await self._directory_reject_audit("<oidc>", "oidc", reason)

    # --- lifecycle -----------------------------------------------------------

    async def initialize(self) -> None:
        """Seed the built-in roles. It creates no account (ADR 0183 Amendment A, BACKLOG #1136).

        ASVS 6.3.2 asks that default accounts are not present or are disabled, and this takes the
        first arm: until an operator acts, a store holds no account at all. Three paths create one,
        and each needs a person first: ``messagefoundry provision-admin`` at the host,
        :meth:`create_local_user` behind ``USERS_MANAGE``, and a directory sign-in, which assigns no
        role. The first-run account this used to mint went in Wave 2, and the WP-3 lifecycle that
        retired it went with it.
        """
        await self._seed_roles()

    async def _seed_roles(self) -> None:
        for role in Role:
            label, description = ROLE_METADATA[role]
            await self._store.upsert_role(
                role_id=role.value, display_name=label, description=description, builtin=True
            )

    def _generate_policy_password(self, username: str | None = None) -> str:
        """A random password that satisfies the active policy — so an administrator-issued temporary
        credential is held to the same bar operators are. ``token_urlsafe(n)`` yields about 1.33 times
        n characters, cut to :func:`_temporary_password_chars`, so the length is at least
        ``min_length``. The loop covers a context hit or an opt-in character-class requirement a given
        token happens to miss.

        Every clause except the breach screen, which is suppressed per-call for the reason stated at
        the call below (BACKLOG #1447).

        ``username`` is the account the password is for, so the own-username clause applies too.

        Raises :class:`TemporaryPasswordUnavailable` when no candidate clears the policy. It never
        returns an unscreened password. The old last-resort return appended ``aA1!`` without a screen,
        so a site context word inside it would have issued a credential the policy refuses (BACKLOG
        #1132)."""
        # At least 32 CHARACTERS (192 bits). token_urlsafe's argument is a byte count and min_length
        # is a CHARACTER count, so the bytes are derived from the characters: 3 bytes make 4
        # characters, and the cut below never pads, so a short byte count would silently lower the
        # entropy floor (BACKLOG #1172).
        policy = self._policy
        chars = _temporary_password_chars(policy.min_length)
        length = -(-chars * 3 // 4)  # ceiling: enough bytes for `chars` characters
        # The suffixed form exists only for an opt-in character class the bare token happens to miss.
        # With every class rule off it cannot help: the bare token then fails only on a context word
        # or the username, and the suffix keeps either one.
        class_rules = (
            policy.require_uppercase
            or policy.require_lowercase
            or policy.require_digit
            or policy.require_symbol
        )
        for _ in range(_RESET_GENERATION_ATTEMPTS):
            token = secrets.token_urlsafe(length)[:chars]
            # The bare token first. The suffixed form is screened like the token: a site term can sit
            # inside it too.
            candidates = (token, token + "aA1!") if class_rules else (token,)
            # THE ONE PLACE THIS REASONING IS WRITTEN OUT (BACKLOG #1447). The candidate is a 192-bit
            # CSPRNG token, not a human-chosen password, so a corpus OF human-chosen passwords cannot
            # contain it -- the breach clause is inert on this input by construction. Honouring
            # `check_breached` here therefore converts a screen that can never FIRE into one that
            # always BLOCKS: the corpus load raises on an unusable install (BACKLOG #1438). While this
            # also generated the first-run account (retired by ADR 0183), the raise escaped an
            # unguarded lifespan call and the engine did not start at all.
            #
            # Scoped to this ONE call on purpose. Every other caller of `violations` screens an
            # operator- or user-supplied password, where the corpus is the whole point and refusing is
            # right -- so do NOT widen this to the policy field or the `[auth]` setting.
            for candidate in candidates:
                if not policy.violations(candidate, username=username, suppress_breach_check=True):
                    return candidate
        _log.error(
            "no temporary password cleared the password policy in %d tries; the likely cause is "
            "[auth].password_extra_context_words holding so many short terms that nearly every "
            "random string contains one, which would refuse most passphrases too",
            _RESET_GENERATION_ATTEMPTS,
        )
        raise TemporaryPasswordUnavailable(
            "could not generate a temporary password that clears the password policy; check "
            "[auth].password_extra_context_words for short or very common terms, then restart the "
            "engine, which reads [auth] only at start"
        )

    async def _other_enabled_admin_exists(self, exclude_id: str | None = None) -> bool:
        """True iff some enabled administrator other than ``exclude_id`` exists.

        ``exclude_id`` is optional so :meth:`has_enabled_administrator` can ask the unrestricted
        question without a sentinel value.
        """
        for user in await self._store.list_users():
            if user.disabled or user.id == exclude_id:
                continue
            if Role.ADMINISTRATOR.value in await self._store.get_user_role_ids(user.id):
                return True
        return False

    async def has_enabled_administrator(self) -> bool:
        """True iff some enabled account holds Administrator.

        The provisioning refusal below asks this, and so does ``provision-admin`` before it prompts.
        (Further open-coded copies of that enumeration exist -- see :meth:`has_notifiable_admin` --
        and unifying them is its own item, not this one.)
        """
        return await self._other_enabled_admin_exists()

    async def provision_first_administrator(
        self,
        *,
        username: str,
        password: str,
        display_name: str | None = None,
        notify_email: str | None = None,
        actor: str,
    ) -> ProvisionedAdministrator:
        """Create the first administrator from an operator-supplied name and credential (#1136).

        THIS IS THE "NOT PRESENT" ARM OF ASVS 6.3.2, and it is the half that has to exist before the
        other half can be built. The verb asks that default user accounts "are not present in the
        application or are disabled". The disabled arm is unexpressible at two altitudes --
        ``Store.create_user`` carries no ``disabled`` parameter and all three backends hardcode the
        column -- so the honest route is that no account is minted at all until an operator names one.
        Since ADR 0183 Amendment A, Wave 2, :meth:`initialize` mints nothing, so this is how the first
        administrator of an install comes to exist.

        **The way in is filesystem authority over the store, not an account** -- the host gate argued
        once on :func:`messagefoundry.__main__._admin_unlock` and in ADR 0171, and not restated here.

        **THE REFUSAL ASKS FOR AN ENABLED ADMINISTRATOR, NOT AN EMPTY TABLE, AND THE DIFFERENCE IS
        THIS ITEM'S OWN NAMED RISK.** ``count_users() == 0`` is safe only while nothing else can put
        the first row in; a directory sign-in can. ``_upsert_ad_user`` calls ``create_user`` and
        assigns no role, so one completed sign-in leaves a roleless row, a non-empty table, and no
        administrator -- reached entirely through shipped code. A command guarded on emptiness would
        refuse exactly there, which is the state where the install has no way in. That refusal is
        wider than an emptiness guard by design: it makes this a standing recovery path whenever
        every administrator is lost, which overlaps BACKLOG #1236's subject on the same host boundary.

        **THE CREDENTIAL IS CLAIMED AT BIRTH, so there is no half-claimed state to restart into.**
        The password is typed by the operator at a TTY and reaches no file, no argv and no log, so
        "the holder set their own credential" is already true and ``users.password_claimed_at`` is
        stamped here rather than deferred to a forced rotation. ASVS 6.4.6's one-time temp governs an
        admin-ISSUED credential handed to a second party; there is no second party here. Before Wave 2
        the stamp also kept an account the operator named ``admin`` out of the WP-3 retirement sweep.
        That sweep is gone, and the stamp stays because the fact it records is still true.

        **EVERY INTERRUPTION POINT LEAVES A RECOVERABLE STORE, and the test for that is HOLDS NO
        ROLES -- one signal, chosen because it is the only one true at both of them.** The row is
        created with no password hash, then the credential is set, then the role is assigned, so the
        two states a crash can leave are *no hash, no roles* and *hash, no roles*. An earlier draft
        also refused a stamped ``password_claimed_at``, which is set by the credential write: that
        refused the SECOND state, leaving a row this command could never complete -- a stranded
        install, which is exactly the risk the design exists to avoid. Roleless
        is also what makes the takeover safe rather than merely convenient: the account holds no
        permission to inherit, and this branch is reachable only when the store has no enabled
        administrator at all, which is already the state an operator needs recovering from. Safe is
        not silent, though: a roleless account can still be somebody's, so a repair tells the
        address it held before (BACKLOG #2019).

        Not reused from :meth:`create_local_user`, which does the same four writes: that method
        creates WITH a hash and forces a rotation, and the ordering above is a durability property
        rather than a preference. The divergence is deliberate and is recorded in ADR 0183.

        Raises :class:`FirstAdministratorRefused` on every declined case, with operator-facing text.
        """
        username = username.strip()
        # Normalized ONCE, so the three later readers cannot disagree about what "an address was
        # supplied" means: a whitespace-only --email must not reach `users.email` untrimmed on the
        # create, and must not audit as `"notified": true`.
        notify_email = (notify_email or "").strip() or None
        if not username:
            raise FirstAdministratorRefused("a username is required and must not be blank")
        if await self.has_enabled_administrator():
            raise FirstAdministratorRefused(
                "this store already has an enabled Administrator, so there is nothing to provision "
                "-- create further accounts from the web console, and use `admin-unlock` if the "
                "administrator is locked out"
            )
        violations = self._policy.violations(password, username=username)
        if violations:
            raise FirstAdministratorRefused("; ".join(violations))

        existing = await self._store.get_user_by_username(username)
        repaired = existing is not None
        # BACKLOG #2019: read BEFORE any write, because `--email` below may replace it and the new
        # address belongs to the operator running this command, not to the holder being told.
        # Blank counts as absent, as it does everywhere else in this service: a legacy row can hold
        # "" and the notifier drops it, so "dispatched" would be a false record.
        prior_notify_email = ((existing.notify_email if existing else None) or "").strip() or None
        if existing is not None:
            # A directory identity draws its authority from the directory, so it is never promoted
            # here whatever its role state -- provision a separate local account instead.
            if existing.auth_provider != AuthProvider.LOCAL.value:
                raise FirstAdministratorRefused(
                    f"{username!r} is a {existing.auth_provider} account -- provision a separate "
                    "local administrator under a different name"
                )
            # Refused rather than re-enabled: an operator who disabled this account did so on
            # purpose, and silently reviving it under a new credential is not a recovery.
            if existing.disabled:
                raise FirstAdministratorRefused(
                    f"the account named {username!r} is disabled -- re-enable it from the web "
                    "console, or provision under a different username"
                )
            if await self._store.get_user_role_ids(existing.id):
                raise FirstAdministratorRefused(
                    f"an account named {username!r} already exists and holds roles -- choose "
                    "another username"
                )
            user_id = existing.id
        else:
            user_id = uuid4().hex
            await self._store.create_user(
                user_id=user_id,
                username=username,
                auth_provider=AuthProvider.LOCAL.value,
                display_name=display_name,
                # Seeds `notify_email` too (see `store.seed_notify_email`), which is the column the
                # PHI security-notice start gate reads.
                email=notify_email,
                # No hash yet, deliberately: an account with no credential cannot be signed into, so
                # the window before `set_password` below admits nobody. The flag is therefore
                # unobservable until that write, which is what actually decides it.
                password_hash=None,
                must_change_password=True,
            )
        await self._seed_roles()
        await self._store.set_password(
            user_id,
            password_hash=await self._argon2(hash_password, password),
            must_change_password=False,
        )
        if notify_email is not None:
            # Unconditional rather than fresh-path-only, because the invariant "the supplied address
            # always lands" is simpler than the case analysis. On the fresh path `create_user` already
            # seeded the same value; on a REPAIRED row an earlier run created the account, so this
            # write is the only one that carries it.
            await self._store.set_user_notify_email(user_id, email=notify_email)
        await self._store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by=actor)
        # BACKLOG #2019: a repair can take over an account somebody else holds -- one an administrator
        # created with no roles, say -- so its earlier holder is told, at the address they held. Told
        # rather than refused, because an address is no sign of a second holder: a run given --email
        # that crashed after `create_user` leaves its own address on the roleless row, and refusing
        # it would strand exactly the half-written provision this branch exists to complete.
        #
        # The notice goes out BEFORE the audit row, so the row records its real outcome rather than a
        # forecast: `_notify_security` swallows a notifier failure, and a row written first would then
        # claim a hand-off that never happened.
        moved = (
            repaired
            and prior_notify_email is not None
            and notify_email is not None
            and notify_email != prior_notify_email
        )
        holder_notice: str | None = None
        if repaired:
            if prior_notify_email is None:
                holder_notice = HOLDER_NOTICE_NO_PRIOR_ADDRESS
            elif await self._notify_security(
                FIRST_ADMINISTRATOR_TAKEOVER,
                username=username,
                email=prior_notify_email,
                detail={"new_notify_email": notify_email} if moved else None,
            ):
                holder_notice = HOLDER_NOTICE_DISPATCHED
            else:
                holder_notice = HOLDER_NOTICE_NO_CHANNEL
        await self._audit(
            "auth.first_administrator_provisioned",
            actor=actor,
            detail=_json(
                {
                    "username": username,
                    "repaired": repaired,
                    # UNCHANGED MEANING: an address was supplied with --email. It says nothing about
                    # the notice to an earlier holder, which is `holder_notice`.
                    "notified": bool(notify_email),
                    "holder_notice": holder_notice,
                    # The earlier address itself is not recorded here; the notice went to it.
                    "notify_email_moved": moved,
                }
            ),
        )
        return ProvisionedAdministrator(
            user_id=user_id, username=username, repaired=repaired, holder_notice=holder_notice
        )

    def initial_credential_deadline(self, password_changed_at: float | None) -> float | None:
        """The instant an admin-issued must-change credential stops working, or ``None`` when
        ``[auth].initial_password_expiry_hours`` is 0 (no expiry) or the account carries no
        ``password_changed_at`` stamp.

        BACKLOG #1141 (ASVS 6.4.5). THE ONE COMPUTATION OF THE 6.4.1 CREDENTIAL DEADLINE. The login
        gate refuses on it, :meth:`admin_reset_password` surfaces it to the issuing administrator, and
        the lifespan's reminder warns ahead of it. Those were once four open-coded copies of one
        arithmetic, which is precisely the shape BACKLOG #1245 already cost this file once: two copies
        of one lifecycle test let the warn path drift from the gate silently. A surfaced deadline that
        can disagree with the enforced one is worse than no deadline at all, because the holder plans
        around a date the gate does not honour.

        The gate's own comparison is ``now > deadline`` (strictly after), so a login AT the returned
        instant still succeeds -- stating it as the moment the credential stops working is exact.
        """
        hours = self._settings.initial_password_expiry_hours
        if hours <= 0 or password_changed_at is None:
            return None
        return password_changed_at + hours * 3600.0

    # --- login ---------------------------------------------------------------

    async def _equalize_failure(
        self, outcome: LoginOutcome, started: float, *, seam: str, queued: float = 0.0
    ) -> LoginOutcome:
        """Hold a FAILED ``outcome`` until this challenge's deadline, then return it unchanged.

        ASVS 6.3.8 asks that valid users not be deducible from failed challenges, *including by
        different response times*. Messages and status codes on the challenge seams are already
        collapsed; this closes the remaining channel by making every failure answer at an instant
        fixed before dispatch, so the latency is a function of ``started`` and nothing else — not of
        which branch ran, and so not of anything about the username.

        ``started`` is the call's start on the ``login`` and ``kerberos`` seams. On the ``oidc`` seam
        it is the end of the IdP round trip for a refusal after it (see :class:`_PadClock`): still
        fixed before any account-dependent work, but not before dispatch.

        **Successes return unpadded, deliberately.** A valid credential has already told the caller
        the account exists; enumeration is about telling two FAILURES apart, and padding the success
        path would only make every real sign-in slower.

        **Exceptions propagate unpadded, also deliberately.** An unhandled store or directory error
        becomes a 500, which is a far louder signal than any timing difference, so padding it would
        buy nothing while delaying a genuine fault.

        The pad is an ``asyncio.sleep``, so it holds a connection open but never the event loop; the
        sign-in rate limiter bounds how many a caller can hold at once.

        ``queued`` is the time the attempt waited in its account's credential queue (BACKLOG #1943).
        It is left out of the overrun WARNING, since a burst on one account queues, and its wait says
        nothing about whether the budget suits this hardware.

        **A queued failure is also held for at least half a budget after it leaves the queue.**
        Counted from ``started`` alone, the slot a queued attempt answers in would depend on its own
        work: an attacker who sends a second attempt on the name a little after the first controls
        how much of the slot the wait eats, and by sweeping that offset reads the second attempt's
        work time, and so its branch. With the floor, the slot depends on the wait and not on the
        work, so long as the work stays under half the budget; the budget is sized far above every
        branch. Half, not a whole budget, because an attempt leaves the queue just after the one
        ahead of it answered on a slot boundary: a whole budget from there would always cross the
        next boundary and double each queued attempt's wait.
        """
        if outcome.ok:
            return outcome
        now = time.monotonic()
        elapsed = now - started
        work = elapsed - queued
        # For an attempt that did not queue the floor sits inside slot 1, so it changes nothing.
        span = _FAILURE_BUDGET_SECONDS
        floor = started + queued + span / 2
        # Whether the work, and not the wait, decided the slot: ``now`` lies in a later slot than
        # the floor. Worked out here rather than by a second ``_failure_deadline`` call, so the
        # pad's arithmetic runs once per failure.
        moved = now > floor and (now - started) // span != (floor - started) // span
        deadline = _failure_deadline(started, max(now, floor))
        if moved and seam not in _BUDGET_OVERRUN_WARNED:
            # The work alone moved this failure to a later slot than its wait put it in, so the
            # budget is too small for this hardware. It still cannot fail open (`_failure_deadline`
            # always rounds up), but a pair of branches straddling the slot boundary would stay
            # distinguishable. For an attempt that did not queue this is work over one budget; for
            # a queued one, work over the half budget the floor leaves it.
            _BUDGET_OVERRUN_WARNED.add(seam)
            _log.warning(
                "auth: a failed %s challenge took %.3fs, over the %.3fs anti-enumeration budget; "
                "responses are being padded to a later slot (further overruns are not logged)",
                seam,
                work,
                _FAILURE_BUDGET_SECONDS,
            )
        await _sleep_until(deadline)
        return outcome

    async def login(
        self,
        username: str,
        password: str,
        *,
        provider: AuthProvider = AuthProvider.LOCAL,
        client: str | None = None,
        supersedes: str | None = None,
        totp_code: str | None = None,
    ) -> LoginOutcome:
        """The credential sign-in seam, with every failed outcome held to a fixed deadline.

        ``totp_code`` is the optional authenticator code of the COMBINED sign-in (ADR 0197, BACKLOG
        #1131): the password and a TOTP code in one request. Absent or blank means today's two-step
        flow, unchanged. :meth:`_login_local` states when a code changes anything.

        ``supersedes`` is the session token the caller is replacing, if any: the one a browser
        presented, or the one a bearer client names. On success it is
        ended as part of the new session's mint (see :meth:`_issue_session`). Only a caller whose
        response REPLACES that token passes it: at least the console legs always do, and
        ``POST /auth/login`` does when its body names one (BACKLOG #2096).

        A wrapper rather than a pad threaded through the dispatch's returns, so that a failure branch
        added there later inherits the equaliser instead of quietly escaping it (BACKLOG #1140).

        **The inner method is ``_dispatch_login`` and NOT ``_login``, which is load-bearing.**
        ``tests/test_docs_security_pathways.py`` treats every ``_login*`` coroutine returning a
        ``LoginOutcome`` as a per-provider authentication pathway owing a comparative-strength row in
        ``docs/SECURITY.md`` (ASVS 6.1.3). Naming this one ``_login`` would have made a pure
        refactoring look like a new pathway and forced that guard to be loosened to accommodate it —
        which is how a guard stops catching the thing it was built for. Staying out of the namespace
        keeps ``_login*`` meaning exactly what it meant.

        **ONE ATTEMPT PER ACCOUNT AT A TIME, PAD INCLUDED (BACKLOG #1943).** The local sign-in reads
        the row, checks the lock, verifies, and only then counts a failure. The count is atomic in
        the store, but without a queue every attempt already past the check when the lock was set
        was still verified, so a burst of N concurrent guesses got N verdicts rather than
        ``lockout_threshold``. Held across the check, the verify and the count, the queue makes the
        attempt after the locking one re-read a locked row and be refused before any verify.

        * **The pad runs INSIDE the queue**, so a failure holds its account's queue until its own
          padded deadline. Each queued failure then answers on a whole slot counted from its own
          start, whatever branch it took. Padded outside the queue, the attempts' raw work would add
          up along it, and a burst's last answers would move to a later slot on a name whose branch
          does a little more work: a way to tell a real name from an unknown one. The cost is that
          failures on one account are answered about a slot apart. With the floor below, an
          attacker who spaces attempts can make each hold the queue for up to one and a half
          slots, which is the most the owner waits per queued attempt; the sign-in limiter bounds
          how many queue, and with it off nothing does.
        * **The queue is itself a signal, and the pad only partly hides it.** A probe that waits
          behind someone else answers later, and an unknown name never has anyone ahead of it. The
          pad absorbs a wait of up to half a slot. A longer one, such as the owner's own
          :meth:`verify_mfa` walking the recovery codes, shows that the name is real and in use.
        * **The key is the username as typed, normalized** (:func:`_credential_lock_key`), taken
          BEFORE the account lookup, so an unknown name queues exactly like a real one.
          :meth:`verify_mfa` takes the same key, since both legs feed the second-step lock. It
          takes it only after a directory account's lookup, so a slow directory stalls no queue.
        * The overrun warning leaves the queue wait out (``queued``), so a burst cannot spend it.
          The pad holds a queued failure at least half a budget past its turn, so its answer slot
          does not show its own work (:meth:`_equalize_failure`).
        * **A combined sign-in's code is judged at the moment the request arrived** (``arrived``),
          not when it leaves the queue. A queue of padded failures can last longer than a TOTP
          step, and a code judged after it would count as wrong on the second-step counter.
        * **The re-proofs are not in this queue**, and the sign-in lock does not refuse them; the
          per-session cap bounds them (:meth:`_reproof`). They feed the sign-in counter, so one
          can set the lock while a sign-in is mid-verify. That still leaves the sign-ins within
          ``lockout_threshold`` verifies, because the re-proof's failure took one of the count.
        * **Per API process.** Engine shards serving their own API ports keep their own queues, so
          up to one attempt per such process can be past the check when the lock lands: the
          overshoot drops from the burst size to at most the process count minus one. A cancelled
          attempt releases the queue while its argon2 verify may still run in a worker thread, but
          that verdict reaches nobody.
        * **A combined sign-in with BOTH factors wrong is not bounded by this.** The sign-in lock does
          not refuse a combined sign-in (:meth:`_login_local`), so each such attempt is still
          verified; the sign-in limiter bounds it, and a guess must also carry a live TOTP code.
        """
        started = time.monotonic()
        arrived = totp.wall_clock()  # the instant a combined sign-in's code is judged at
        async with self._account_credential_lock(username):
            queued = time.monotonic() - started
            # A refused local sign-in's audit rows, written AFTER the pad (BACKLOG #1131, Manager
            # decision 2026-09-28). Written before it, a row's ``ts`` showed how much work its branch
            # did: a refusal by a live lock does one dummy verify, a verified refusal also reads the
            # TOTP secret and counts the failure, and only a right candidate arms the second-step
            # lock. After the pad, every refusal's rows land on its padded slot. The COUNT still
            # happens before the pad, inside the queue, so counting is unchanged.
            after_pad: list[Callable[[], Awaitable[None]]] = []
            try:
                outcome = await self._dispatch_login(
                    username,
                    password,
                    provider=provider,
                    client=client,
                    supersedes=supersedes,
                    totp_code=totp_code,
                    arrived=arrived,
                    after_pad=after_pad,
                )
                return await self._equalize_failure(outcome, started, seam="login", queued=queued)
            finally:
                # In ``finally`` and shielded, so a caller who drops the request during the pad
                # cannot also drop the audit trail (count-and-log).
                if after_pad:
                    await asyncio.shield(_run_in_order(after_pad))

    async def _dispatch_login(
        self,
        username: str,
        password: str,
        *,
        provider: AuthProvider = AuthProvider.LOCAL,
        client: str | None = None,
        supersedes: str | None = None,
        totp_code: str | None = None,
        arrived: float | None = None,
        after_pad: list[Callable[[], Awaitable[None]]] | None = None,
    ) -> LoginOutcome:
        if provider is AuthProvider.AD:
            # RETIRED (BACKLOG #1137, owner ruling 2026-08-22). The engine no longer accepts a
            # directory password: current good practice is that an application does not collect
            # directory credentials, and supporting AD is not the same as supporting simple bind --
            # every real AD deployment already provides Kerberos, so the replacement is in place
            # wherever the pathway was.
            #
            # Refused here rather than deleted from the dispatch, because falling through to the
            # local path would authenticate an AD username against the LOCAL credential store, which
            # is a worse failure than a refusal: a directory name that happens to collide with a
            # local account would silently log in as that account.
            #
            # THE STEP-UP RE-BIND (`_reauth_ad`) DELIBERATELY SURVIVES THIS. It is the only step-up
            # path any AD-stamped identity has -- Kerberos and OIDC logins are stamped AD too -- so
            # removing it in the same change would lock every AD operator out of factor enrolment
            # and MFA-disable. See docs/research/ad-step-up-after-simple-bind-retirement.md.
            await self._directory_reject_audit(username, "simple_bind", "pathway_retired")
            return LoginOutcome(
                ok=False,
                error="Directory password sign-in has been retired; use Windows SSO or OIDC",
            )
        return await self._login_local(
            username,
            password,
            client=client,
            supersedes=supersedes,
            totp_code=totp_code,
            arrived=arrived,
            after_pad=after_pad,
        )

    def _account_credential_lock(self, username: str) -> AbstractAsyncContextManager[None]:
        """Hold the per-account queue that runs sign-in and second-step checks one at a time (BACKLOG
        #1943). :meth:`login` and :meth:`verify_mfa` take it; see :meth:`login` for why."""
        return _hold_keyed_lock(self._credential_locks, _credential_lock_key(username))

    async def _login_local(
        self,
        username: str,
        password: str,
        *,
        client: str | None,
        supersedes: str | None = None,
        totp_code: str | None = None,
        arrived: float | None = None,
        after_pad: list[Callable[[], Awaitable[None]]] | None = None,
    ) -> LoginOutcome:
        """The local password sign-in, and inside it the COMBINED sign-in (ADR 0197, BACKLOG #1131).
        It runs inside :meth:`login`'s per-account queue, which is what keeps the check below and
        the count after the verify one step apart for a burst (BACKLOG #1943). ``arrived`` is the
        wall-clock instant the request arrived (:func:`totp.wall_clock`), so a combined sign-in's
        code is judged as of then and not after its wait in the queue.

        **THE COMBINED SIGN-IN EXISTS ONLY FOR A LOCAL ACCOUNT WITH TOTP ENROLLED, judged on the row
        read before any verify (AC-2a).** On any other account a code changes nothing: it is refused
        under a live lock exactly as a password-only request is, after the same dummy argon2, and
        otherwise ignored. Without that condition any six digits would turn a locked sign-in on a
        passkey-only or not-yet-enrolled account into a live password check.

        **What each lock refuses, before any verify.** The second-step lock refuses every sign-in
        here. The sign-in lock refuses a password-only request and does NOT refuse a combined one,
        because a caller who knows only the username can set that lock and the owner holding both
        factors must still get in. That is the whole of the 6.1.1 property this buys.

        **The combined sign-in always checks BOTH factors, whatever the first returns** (see
        :meth:`_check_both_factors`), then routes the outcome: both right completes the sign-in with
        the second factor satisfied; exactly one right counts on the SECOND-STEP counter; neither
        counts on the SIGN-IN counter. Every refusal is the same ``invalid credentials``, and the
        ``login`` wrapper holds every one to the same padded deadline, so the caller learns a verdict
        only when both factors are right.

        Kept inside this method on purpose rather than in a ``_login*`` sibling:
        ``tests/test_docs_security_pathways.py`` treats every ``_login*`` coroutine as a new 6.1.3
        pathway, and this is the local pathway with a second factor, not a new one.

        **A refusal's audit rows go to ``after_pad``** when the caller passes one, and :meth:`login`
        writes them after its failure pad, so their ``ts`` does not show which branch refused.
        Everything else, the failure count included, runs here as before."""
        code = totp_code.strip() if totp_code else ""

        async def later(write: Callable[[], Awaitable[None]]) -> None:
            if after_pad is None:
                await write()
            else:
                after_pad.append(write)

        user = await self._store.get_user_by_username(username)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value or user.disabled:
            # Equalize timing with the real-password path so a missing/disabled/AD account is not
            # distinguishable from a wrong password (defeats username enumeration via latency).
            await self._argon2(verify_password, _DUMMY_PASSWORD_HASH, password)

            async def unknown_row() -> None:
                await self._audit(
                    "auth.login_failed",
                    actor=username,
                    detail=_json({"provider": "local", "reason": "unknown_or_disabled"}),
                    client=client,
                )

            await later(unknown_row)
            return LoginOutcome(ok=False, error="invalid credentials")
        now = time.time()
        combined = bool(code) and user.totp_enabled
        if user.second_step_locked(now) or (user.sign_in_locked(now) and not combined):
            await self._argon2(verify_password, _DUMMY_PASSWORD_HASH, password)

            # Owner ruling 2026-09-28 (BACKLOG #1131): first the row every reader sees, byte-identical
            # to a wrong credential's, then the lock row only ``users:manage`` reads. Without the
            # first, a live second-step lock -- which only a right candidate can set -- would show a
            # reader without ``users:manage`` a missing row where a wrong candidate leaves one.
            async def locked_rows() -> None:
                await self._audit(
                    "auth.login_failed",
                    actor=username,
                    detail=_local_refusal_detail(_LOCAL_REFUSAL_REASON, combined=combined),
                    client=client,
                )
                await self._audit(LOGIN_LOCKED_ACTION, actor=username, client=client)

            await later(locked_rows)
            return LoginOutcome(ok=False, error="account locked")
        refused: tuple[LockoutCounter, str, str | None] | None = None
        if combined:
            password_ok, code_ok = await self._check_both_factors(
                user, password, code, arrived=arrived
            )
            if not (password_ok and code_ok):
                refused = _route_combined_failure(password_ok=password_ok, code_ok=code_ok)
        elif user.password_hash is None or not await self._argon2(
            verify_password, user.password_hash, password
        ):
            refused = ("sign_in", _LOCAL_REFUSAL_REASON, None)
        if refused is not None:
            counter, reason, factor = refused
            failure = await self._register_failure(user, now, counter=counter)

            async def refused_rows() -> None:
                await self._audit(
                    "auth.login_failed",
                    actor=username,
                    detail=_local_refusal_detail(reason, combined=combined),
                    client=client,
                )
                # The lock this failure set, if any: its row, and its notice.
                await self._record_lock(
                    user,
                    counter,
                    failure,
                    client=client,
                    audit_detail={"provider": "local"},
                    factor=factor,
                )

            await later(refused_rows)
            return LoginOutcome(ok=False, error="invalid credentials")
        # ASVS 6.4.1: an admin-issued initial/reset credential that was never claimed EXPIRES — the
        # password verified, but a `must_change_password` temp that is older than
        # `initial_password_expiry_hours` is refused like any other invalid login (a generic error, so
        # it is indistinguishable from a wrong password) and audited. A user who set their own
        # password has `must_change_password=False` and is never gated here.
        #
        # There is no per-account carve-out here. BACKLOG #1245 removed the one the first-run account
        # had, because retiring an ACCOUNT and expiring a CREDENTIAL are different controls and one
        # is not a substitute for the other; ADR 0183 then retired that account. BACKLOG #1141: the deadline comes from initial_credential_deadline, the SAME call
        # admin_reset_password surfaces to the issuing administrator — so the instant the response
        # states and the instant this gate refuses on are one computation, not two that agree today.
        expiry_hours = self._settings.initial_password_expiry_hours
        deadline = self.initial_credential_deadline(user.password_changed_at)
        if user.must_change_password and deadline is not None and now > deadline:

            async def expired_row() -> None:
                await self._audit(
                    "auth.temp_password_expired",
                    actor=username,
                    detail=_json({"provider": "local", "expiry_hours": expiry_hours}),
                    client=client,
                )

            await later(expired_row)
            return LoginOutcome(ok=False, error="invalid credentials")
        # ``user.password_hash`` is not None past this point: the combined path's verify refuses a
        # row with no hash, and the password path's ``or`` does.
        if user.password_hash is not None and await asyncio.to_thread(
            needs_rehash, user.password_hash
        ):
            # ADR 0197 AC-10b: the HASH-ONLY write. ``set_password`` clears the lockout columns, so
            # a password holder could shed a run of second-step failures once per argon2 parameter
            # change.
            await self._store.set_password_hash(
                user.id, password_hash=await self._argon2(hash_password, password)
            )
        # Captured off the row read before the verify, so it is the count as it stood at the start of
        # this attempt whether or not the clear below runs. Both counters, since either kind of
        # failure run followed by a success is the 6.3.5 signal.
        prior_failures = user.failed_attempts + user.second_step_failed_attempts
        identity = await self._build_identity(user)
        # A second factor (TOTP / recovery code / passkey) is pending for an enrolled user — or an
        # Administrator when require_mfa is on. Issue the session un-MFA'd; the client completes via
        # /auth/mfa-verify (or the browser passkey leg at /ui/reauth, ADR 0068). A COMBINED sign-in
        # has already proved the TOTP factor in this request, so it owes nothing more (ADR 0197).
        mfa_required = not combined and self._mfa_required_for(
            user, identity.roles, second_factor_enrolled=await self._second_factor_enrolled(user)
        )
        # BACKLOG #288. Classified BEFORE record_login_success and the mint: both write state this
        # sign-in would otherwise find (``last_login_at``, then its own ``auth.login_success`` row).
        address = await self._classify_login_address(user, client)
        if not mfa_required:
            # BACKLOG #1638. CLEARED AT FULL AUTHENTICATION, NOT AT THE PASSWORD STEP. This call
            # zeroes ``failed_attempts`` and NULLs ``locked_until``; it used to run above, before the
            # second factor was proven, so a password holder could shed a run of wrong TOTP codes just
            # by logging in again -- three cycles of password plus four wrong codes never locked the
            # account. It is the MFA leg (``verify_mfa`` / ``finish_webauthn_assertion``) that clears
            # it when a factor is owed; this branch covers the accounts that owe none.
            await self._store.record_login_success(user.id, now=now)
        token = await self._issue_session(
            user.id,
            client,
            mfa_verified=not mfa_required,
            # The sudo-timestamp model, for the local leg only: a sign-in that owes no factor opens
            # the step-up window, and one that still owes a factor does not (WP-14). A sign-in from
            # a first-seen address does not either (BACKLOG #288): that is the whole of its
            # challenge, and the login itself still succeeds.
            #
            # A COMBINED sign-in seeds the window the way ``verify_mfa`` does, which marks the
            # session re-authenticated once the code is proved whatever the address (ADR 0197).
            seed_reauth=combined or (not mfa_required and address is not _LoginAddress.NEW),
            mechanism=SessionMechanism.PASSWORD,
            supersedes_hash=hash_token(supersedes) if supersedes else None,
        )
        await self._record_login_address(address, user, client=client, provider="local")
        success_detail: dict[str, Any] = {"provider": "local", "mfa_required": mfa_required}
        if combined:
            success_detail["second_factor"] = "totp"
        await self._audit(
            "auth.login_success",
            actor=user.username,
            detail=_json(success_detail),
            client=client,
        )
        if prior_failures >= SUSPICIOUS_LOGIN_FAILURE_THRESHOLD:
            # A successful login right after a run of failures is the classic compromised/attacked
            # signal (ASVS 6.3.5) — notify the owner out-of-band so they can react if it wasn't them.
            await self._record_suspicious_login(
                LOGIN_AFTER_FAILURES,
                user,
                client=client,
                audit_detail={"provider": "local"},
                notice_detail={"failed_attempts": prior_failures},
            )
        return LoginOutcome(
            ok=True,
            token=token,
            identity=identity,
            must_change_password=user.must_change_password,
            mfa_required=mfa_required,
        )

    async def _register_failure(
        self, user: UserRecord, now: float, *, counter: LockoutCounter
    ) -> LockoutIncrement:
        """Record a failed attempt on ``counter``; return ``(attempts, just_locked, cycles)``.
        ``just_locked`` is True only on the attempt that sets that counter's lock, so it fires exactly
        one lockout notification per lock.

        ``counter`` is ``"sign_in"`` for a caller who has proved nothing (a wrong password, a combined
        sign-in with both factors wrong, a failed re-proof) and ``"second_step"`` for a caller who
        has proved one factor (a wrong code on ``verify_mfa``, a combined sign-in with exactly one
        factor right). ADR 0197 Decision item 1.

        **THE COUNT, THE POLICY AND THE WRITE ARE ONE STORE CALL, AND THAT IS THE WHOLE OF THIS
        METHOD.** It used to read ``user.failed_attempts`` off a row fetched before the argon2 verify,
        add one in Python, then write the sum back -- three steps with awaits between them. Every one
        of those awaits is a window in which another attempt reads the SAME pre-increment count, so N
        wrong passwords submitted in parallel all wrote 1, the account never reached the threshold,
        and an attacker who parallelizes would evade the lockout entirely on a first deployment. The
        lapsed-window reset, the increment and the crossing test now run inside the store, against the
        row the store re-read under the lock that also carries the write.

        ``user`` is therefore read for its id alone. **Do not recompute ``just_locked`` out here** --
        outside the atomic section it is the stale read again, which is the defect rather than a
        cheaper way to reach the same answer."""
        return await self._store.increment_login_failure(
            user.id,
            counter=counter,
            threshold=self._policy.lockout_threshold,
            lockout_seconds=self._policy.lockout_minutes * 60,
            max_lockout_seconds=self._policy.lockout_max_minutes * 60,
            now=now,
        )

    async def _check_both_factors(
        self, user: UserRecord, password: str, code: str, *, arrived: float | None = None
    ) -> tuple[bool, bool]:
        """The combined sign-in's verify: ``(password_ok, code_ok)``, with BOTH always checked.

        Checking both closes a hole each way (ADR 0197 Decision item 3). Were the code checked only
        after a right password, a caller holding the TOTP device but not the password could replay
        one code across its 30-second step and guess passwords at the sign-in limiter's rate. Were
        the code checked first and a wrong one not counted, a password holder could set the sign-in
        lock on purpose and then guess codes uncounted.

        **The code check is ``totp.verify_totp_step`` and ``consume_totp_step``, and NEVER
        ``_verify_second_factor``.** On a TOTP miss that method walks the recovery codes, about ten
        argon2 verifies at the defaults, and that extra time would mark the "right password, wrong
        code" outcome against the others. So the combined path takes a TOTP code only. A code that
        matches is CONSUMED whatever the password was, so one valid code beside many wrong passwords
        is accepted as a code exactly once (AC-4).

        A row with no hash still runs one argon2 verify, against the dummy hash, so the refusal
        costs what a wrong password costs."""
        stored = user.password_hash
        verified = await self._argon2(verify_password, stored or _DUMMY_PASSWORD_HASH, password)
        password_ok = stored is not None and verified
        # A stored secret that will not decrypt or decode is a wrong code, logged, and never an
        # exception: this read is reachable WITHOUT the password here, so an unpadded 500 would name
        # the account as enrolled to anyone who knows the username. The catch is broad on purpose,
        # as in ``_classify_login_address``: each backend's cipher and driver raise their own
        # classes, which ``auth/`` does not import, and every arm fails CLOSED (the code is wrong).
        try:
            secret = await self._store.get_totp_secret(user.id)
            step = (
                totp.verify_totp_step(
                    secret,
                    code,
                    window=self._settings.totp_skew_steps,
                    now=arrived,
                )
                if secret
                else None
            )
        except Exception:
            _log.exception(
                "combined sign-in: the stored TOTP secret for %s could not be read; treating the "
                "code as wrong",
                user.username,
            )
            step = None
        code_ok = step is not None and await self._store.consume_totp_step(user.id, step)
        return password_ok, code_ok

    async def _record_lock(
        self,
        user: UserRecord,
        counter: LockoutCounter,
        failure: LockoutIncrement,
        *,
        client: str | None,
        audit_detail: dict[str, Any] | None = None,
        factor: str | None = None,
    ) -> None:
        """Announce a lock ``failure`` just set on ``counter``, and do nothing when it set none.

        The notice carries which lock it was and its cycle count (ADR 0197 Decision item 7), as a
        closed-set detail on the one ``ACCOUNT_LOCKED`` event type. ``factor`` names the factor a
        second-step failure proved right (``"password"`` or ``"code"`` on a combined sign-in,
        ``"first_step"`` on ``verify_mfa``), so the notice can tell the owner which one to replace;
        only the owner receives it. A sign-in lock on a local account with TOTP enrolled tells the
        owner the combined sign-in gets them in now."""
        if not failure.just_locked:
            return
        notice: dict[str, Any] = {
            "failed_attempts": failure.attempts,
            "lock": counter,
            "cycle": failure.cycles,
        }
        if counter == "second_step":
            # A second step on an existing session proved the FIRST step, which for a directory
            # account is its directory sign-in, not a password this engine can reset.
            first = "first_step" if user.auth_provider == AuthProvider.LOCAL.value else "directory"
            notice["factor_right"] = factor if factor in ("password", "code") else first
        elif user.totp_enabled and user.auth_provider == AuthProvider.LOCAL.value:
            notice["combined_sign_in"] = True
        await self._record_suspicious_login(
            ACCOUNT_LOCKED, user, client=client, audit_detail=audit_detail, notice_detail=notice
        )

    async def authenticate_kerberos(
        self,
        token: bytes,
        *,
        client: str | None = None,
        supersedes: str | None = None,
    ) -> LoginOutcome:
        """The browser/API Windows-SSO seam, with every failed outcome held to a fixed deadline.

        **This is the SECOND challenge seam, and siting the pad here is what covers it** (BACKLOG
        #1140). ``GET /ui/sso`` calls this method directly and never touches :meth:`login`, so a pad
        on the sign-in seam alone would have left this one open; putting it on the service method
        rather than in the route means every caller inherits it, the JSON API leg included.

        **What the pad buys here.** The route already collapses every reject to one 303 to
        ``/ui/login?e=sso_failed``, so latency was the last channel separating them: an unresolvable
        principal costs a directory search, a like-named local account costs that search plus a store
        lookup, a directory outage costs the full ``ad_connect_timeout``, and "SSO is not configured"
        costs nothing. They now answer together.

        **What it does NOT buy, and this is the honest limit.** The attacker does not choose the
        username on this path — SPNEGO supplies it from a ticket the KDC issued — so equalizing these
        branches is not username enumeration protection in 6.3.8's sense. What it removes is a caller
        learning, about the one principal it can present, which of the reject branches it landed in.
        It also does not cover ``kerberos_available == False``: the route redirects with a *different*
        error code before reaching the service, and that is a server-wide configuration fact,
        identical for every principal and already disclosed in the redirect.
        """
        started = time.monotonic()
        outcome = await self._authenticate_kerberos(token, client=client, supersedes=supersedes)
        return await self._equalize_failure(outcome, started, seam="kerberos")

    async def _authenticate_kerberos(
        self,
        token: bytes,
        *,
        client: str | None = None,
        supersedes: str | None = None,
    ) -> LoginOutcome:
        # Audit every reject path so blocked/failed Windows-SSO attempts are not invisible to a
        # defender (AUTH-K-AUDIT). A sentinel actor is used until the principal is known.
        if self._ldap is None or not self._settings.kerberos_enabled:
            await self._directory_reject_audit("<kerberos>", "kerberos", "not_configured")
            return LoginOutcome(ok=False, error="Windows SSO is not configured")
        try:
            username = await asyncio.to_thread(kerberos_principal, token, self._settings)
            if username is None:
                await self._directory_reject_audit("<kerberos>", "kerberos", "no_principal")
                return LoginOutcome(ok=False, error="SSO authentication failed")
            principal = await asyncio.to_thread(self._ldap.resolve_principal, username)
        except LdapError as exc:
            await self._audit(
                "auth.login_error",
                actor="<kerberos>",
                detail=_json({"provider": "ad", "mech": "kerberos", "error": str(exc)}),
                client=client,
            )
            return LoginOutcome(ok=False, error="directory unavailable")
        if principal is None:
            await self._directory_reject_audit(username, "kerberos", "not_in_directory")
            return LoginOutcome(ok=False, error="user not found in directory")
        # MINT AT THE MINIMUM (BACKLOG #1144, ASVS 6.8.4). A Kerberos service ticket carries no
        # factor-strength assertion that pyspnego surfaces, so the engine learns NOTHING about what
        # the domain enforced. It used to pass a hard True here under the signed delegated-directory
        # relaxation, which is the inverted fallback: the requirement's clause says an application
        # that receives no assertion must assume the MINIMUM mechanism was used, and minting verified
        # assumes the maximum. False is that minimum -- one factor proven, none asserted -- so the
        # session is MFA-pending and the engine's own second factor decides the rest.
        #
        # This is only safe CO-LANDED with directory-account engine-factor enrollment (the same item):
        # a minimum-minted directory session reaches nothing outside api/security.py's six-entry
        # MFA-exempt set, so without an enrollment ceremony that accepts a directory account it is a
        # lockout rather than a control.
        return await self._complete_ad_login(
            principal,
            client,
            mfa_verified=False,
            session_mechanism=SessionMechanism.KERBEROS,
            supersedes_hash=hash_token(supersedes) if supersedes else None,
        )

    def _oidc_policy(self, nonce: str) -> oidc.OidcClaimPolicy:
        s = self._settings
        return oidc.OidcClaimPolicy(
            issuer=s.oidc_issuer or "",
            client_id=s.oidc_client_id or "",
            signing_algorithms=[SignatureAlgorithm(a) for a in s.oidc_signing_algorithms],
            nonce=nonce,
            max_age_seconds=s.oidc_max_age_seconds,
            username_claim=s.oidc_username_claim,
            username_strip_domain=s.oidc_username_strip_domain,
            allowed_username_domains=frozenset(s.effective_oidc_username_domains),
            require_mfa_claim=s.oidc_require_mfa_claim,
            mfa_amr_values=s.oidc_mfa_amr_values,
            required_acr_values=s.oidc_required_acr_values,
            clock_skew_seconds=s.oidc_clock_skew_seconds,
        )

    def _exchange_and_validate(
        self, code: str, flow: PendingFlow, redirect_uri: str
    ) -> oidc.FederatedPrincipal:
        """The whole synchronous IdP interaction, run in ONE ``to_thread`` hop.

        Both halves live here so the authorization ``code`` and the ``id_token`` never cross back
        into route code (AC-10): every extra frame holding one is another place a future debug log or
        an exception repr could leak it.
        """
        assert self._oidc_jwks is not None  # guarded by oidc_enabled at the call site
        payload = oidc.exchange_code(
            token_endpoint=self._settings.oidc_token_endpoint or "",
            client_id=self._settings.oidc_client_id or "",
            client_secret=self._oidc_client_secret,
            code=code,
            redirect_uri=redirect_uri,
            code_verifier=flow.code_verifier,
            opener=self._oidc_opener,
        )
        id_token = payload["id_token"]
        if not isinstance(id_token, str):
            raise oidc.FlowError("token endpoint returned a non-string id_token")
        return oidc.validate_id_token(id_token, self._oidc_policy(flow.nonce), self._oidc_jwks)

    @property
    def oidc_flow_ttl_seconds(self) -> int:
        """The staged-flow lifetime, so the browser cookie's max-age matches the server-side TTL."""
        return self._settings.oidc_flow_ttl_seconds

    def _oidc_redirect_uri(self, public_origin: str) -> str:
        return public_origin.rstrip("/") + self._settings.oidc_redirect_path

    async def begin_oidc_login(
        self, *, client: str | None, public_origin: str, prior_session: str | None = None
    ) -> tuple[str, str]:
        """Stage a federated flow and return ``(flow_id, authorization_url)``.

        The PKCE verifier, ``state`` and ``nonce`` are minted here and stay SERVER-side in the flow
        cache; only the opaque ``flow_id`` goes to the browser. Raises
        :class:`~messagefoundry.auth.oidc.FlowCacheFullError` when the bounded cache is full — the
        caller must treat that as a flood signal, not an error to audit per request.

        ``prior_session`` is the session token the browser presented on this start leg, if any. Only
        its hash is staged, and nothing is revoked here: the callback's mint supersedes it once the
        IdP proof succeeds (ASVS 7.2.4). Why the start leg: see ``PendingFlow.prior_session_hash``.
        """
        if not self.oidc_enabled or self._oidc_flows is None:
            raise oidc.FlowError("federated sign-in is not configured")
        flow_id, flow = oidc.start_flow(
            self._oidc_flows,
            return_to="/ui",
            client_ip=client or "",
            ttl_seconds=self._settings.oidc_flow_ttl_seconds,
            prior_session_hash=hash_token(prior_session) if prior_session else None,
        )
        challenge = oidc.pkce_challenge(flow.code_verifier)
        url = oidc.build_authorization_url(
            authorization_endpoint=self._settings.oidc_authorization_endpoint or "",
            client_id=self._settings.oidc_client_id or "",
            redirect_uri=self._oidc_redirect_uri(public_origin),
            state=flow.state,
            nonce=flow.nonce,
            code_challenge=challenge,
            scopes=self._settings.oidc_scopes,
            max_age=self._settings.oidc_max_age_seconds,
            acr_values=self._settings.oidc_acr_values,
            prompt=self._settings.oidc_prompt,
        )
        return flow_id, url

    async def complete_oidc_login(
        self,
        *,
        flow_id: str,
        state: str,
        code: str,
        client: str | None,
        public_origin: str,
    ) -> LoginOutcome:
        """Redeem a staged flow: pop it (single-use), constant-time-compare ``state``, then run the
        full exchange + verification through :meth:`_authenticate_oidc`.

        The flow cache stays private to the service, so route code never holds the PKCE verifier or
        the nonce. A missing/expired flow and a ``state`` mismatch are both audited with closed-set
        slugs and are deliberately indistinguishable to the caller.

        **This is the THIRD challenge seam, and every failed outcome is held to a fixed deadline**
        (BACKLOG #1947, ASVS 6.3.8), the same wrapper shape as :meth:`login` and
        :meth:`authenticate_kerberos`. ``GET /ui/oidc/callback`` reaches the service only through
        this method, so the pad is sited here rather than in the route. The route's own earlier
        refusals (no flow cookie, an IdP error, a malformed callback) read only the request and are
        not padded, as ``/ui/sso``'s are not. The inner leg calls :meth:`_authenticate_oidc`, not
        the public wrapper, so one challenge is padded once.

        What it removes: the refusals after the IdP round trip (``federated_subject_not_bound``, the
        disabled and locked checks, ``not_in_directory``, the directory outage) cost different store
        and directory work, and each now answers at one deadline counted from the end of that round
        trip (see :class:`_PadClock`). What it does NOT remove: the round trip itself, so those
        refusals answer later than ``state_unknown`` and ``state_mismatch``. That split tells the
        caller whether its own flow cookie and ``state`` were good, which it already knows.
        """
        clock = _PadClock(time.monotonic())
        outcome = await self._complete_oidc_login(
            flow_id=flow_id,
            state=state,
            code=code,
            client=client,
            public_origin=public_origin,
            clock=clock,
        )
        return await self._equalize_failure(outcome, clock.started, seam="oidc")

    async def _complete_oidc_login(
        self,
        *,
        flow_id: str,
        state: str,
        code: str,
        client: str | None,
        public_origin: str,
        clock: _PadClock,
    ) -> LoginOutcome:
        if not self.oidc_enabled or self._oidc_flows is None:
            await self._directory_reject_audit("<oidc>", "oidc", "not_configured")
            return LoginOutcome(
                ok=False, error="federated sign-in is not configured", reason="not_configured"
            )
        flow = self._oidc_flows.pop(flow_id)
        if flow is None:
            await self._directory_reject_audit("<oidc>", "oidc", "state_unknown")
            return LoginOutcome(
                ok=False, error="federated sign-in expired; start again", reason="state_unknown"
            )
        if not oidc.state_matches(flow.state, state):
            await self._directory_reject_audit("<oidc>", "oidc", "state_mismatch")
            return LoginOutcome(ok=False, error="federated sign-in failed", reason="state_mismatch")
        # The INNER leg: the public wrapper would pad a second time inside this challenge's pad.
        return await self._authenticate_oidc(
            code,
            flow,
            redirect_uri=self._oidc_redirect_uri(public_origin),
            client=client,
            clock=clock,
        )

    async def authenticate_oidc(
        self,
        code: str,
        flow: PendingFlow,
        *,
        redirect_uri: str,
        client: str | None = None,
    ) -> LoginOutcome:
        """Complete a federated login, with every failed outcome held to a fixed deadline.

        A public entry point in its own right, so it pads its own failures (BACKLOG #1947, ASVS
        6.3.8) rather than relying on :meth:`complete_oidc_login` to do it. The body is
        :meth:`_authenticate_oidc`; the wrapper shape is :meth:`login`'s, so a refusal added there
        later inherits the pad instead of quietly escaping it.
        """
        clock = _PadClock(time.monotonic())
        outcome = await self._authenticate_oidc(
            code, flow, redirect_uri=redirect_uri, client=client, clock=clock
        )
        return await self._equalize_failure(outcome, clock.started, seam="oidc")

    async def _authenticate_oidc(
        self,
        code: str,
        flow: PendingFlow,
        *,
        redirect_uri: str,
        client: str | None = None,
        clock: _PadClock,
    ) -> LoginOutcome:
        """Complete a federated login: exchange the code, verify the ``id_token``, then resolve the
        principal against on-prem AD and hand off to the shared directory-login path.

        The session is born with NO step-up window, as every directory login's is: a federated proof
        is ambient. Its first window-gated action steps up at the IdP (``POST /ui/reauth/oidc``,
        BACKLOG #296) unless a TOTP or recovery code at the MFA gate already stamped the window.
        :meth:`_complete_ad_login` decides that for every directory leg, and no caller overrides it.

        Roles come from ``resolve_principal`` — the same password-free LDAP lookup Kerberos uses —
        and NEVER from a token claim, so a claims-parsing bug degrades to wrong-user login rather
        than privilege escalation.
        """
        if not self.oidc_enabled or self._ldap is None:
            await self._directory_reject_audit("<oidc>", "oidc", "not_configured")
            return LoginOutcome(
                ok=False, error="federated sign-in is not configured", reason="not_configured"
            )
        if flow.step_up_session_hash is not None:
            # BACKLOG #296. A STEP-UP flow never mints a session. It was staged to elevate one live
            # session, and signing in on it would hand the browser a second, fresh session instead.
            # Refused before the code is redeemed, so the IdP proof is spent on nothing.
            await self._directory_reject_audit("<oidc>", "oidc", FLOW_PURPOSE_MISMATCH)
            return LoginOutcome(
                ok=False, error="federated sign-in failed", reason=FLOW_PURPOSE_MISMATCH
            )
        try:
            try:
                principal_claims = await asyncio.to_thread(
                    self._exchange_and_validate, code, flow, redirect_uri
                )
            finally:
                # Every refusal from here on is padded from the end of the IdP round trip, however
                # the round trip ended (see _PadClock).
                clock.started = time.monotonic()
        except oidc.ClaimsError as exc:
            # A verification-rung failure: the token was reachable but did not satisfy the ladder.
            # exc.reason is closed-set, so nothing IdP-influenced reaches the audit row.
            await self._directory_reject_audit("<oidc>", "oidc", exc.reason)
            return LoginOutcome(ok=False, error="federated sign-in failed", reason=exc.reason)
        except oidc.TokenRefusedError as exc:
            # BACKLOG #1948. The token endpoint ANSWERED with a 4xx, which a signed-out caller
            # causes by presenting a bad code. It must not mark the IdP unavailable: that flag
            # hides the federated link on /ui/login and in /auth/providers for everyone, so marking
            # here would let any caller switch federated sign-in off. Nor does it clear the flag, as
            # no sign-in succeeded. It is a FlowError, so this arm must stay above the outage arm.
            # Audited with the client address, as the outage arm is: a spray of junk codes is the
            # abuse this arm exists for, and the operator needs to see where it comes from. The
            # status is the only other thing recorded, and it is what tells a spray (400) from the
            # engine's own misconfiguration (a 401 on every sign-in). Never the IdP's body.
            await self._audit(
                "auth.login_failed",
                actor="<oidc>",
                detail=_json(
                    {
                        "provider": "ad",
                        "mech": "oidc",
                        "reason": "token_refused",
                        "status": exc.status,
                    }
                ),
                client=client,
            )
            return LoginOutcome(ok=False, error="federated sign-in failed", reason="token_refused")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            # IdP unreachable / a 3xx or 5xx / malformed response. JwksCache's injected fetch raises
            # RAW urllib errors (not wrapped in JwksError), so a narrow `except JwksError` here
            # would let an IdP outage escape as an unhandled 500 instead of a degraded login.
            # http.client.HTTPException is neither an OSError nor a ValueError: a proxy answering the
            # token POST with a non-HTTP status line raises BadStatusLine, which would otherwise
            # escape uncaught — a 500 with the IdP's bytes rendered into the traceback log, no audit
            # row, and oidc_available left stale. The exception TYPE is audited, never str(exc).
            self.mark_oidc_unavailable(type(exc).__name__)
            await self._audit(
                "auth.login_error",
                actor="<oidc>",
                detail=_json({"provider": "ad", "mech": "oidc", "error": type(exc).__name__}),
                client=client,
            )
            return LoginOutcome(
                ok=False, error="identity provider unavailable", reason="idp_unavailable"
            )

        # The claimed username selects nothing. It is kept only as a hint in the not-bound refusal.
        username = principal_claims.username

        # BACKLOG #1143 / #295 (ADR 0184, ASVS 6.8.1): THE ACCOUNT IS SELECTED BY THE VERIFIED
        # (issuer, sub) PAIR, BEFORE ANY USERNAME IS READ.
        #
        # This replaces two username-keyed steps that stood here. The first resolved the directory
        # principal from the token's username claim. The second was the #1015 continuity guard, which
        # fetched the account by that principal's username and compared its pair -- and short-
        # circuited on `bound.oidc_subject is not None`, so it passed every account that had never
        # federated. That is every account on a fresh deployment, so a principal the IdP would mint
        # an allow-listed name for could land on a never-federated directory account and take its
        # roles. The guard's job is now done by construction: the account IS the pair's account.
        #
        # So `federated_subject_conflict` is no longer emitted. A reassigned username that presents a
        # new subject now meets the refusal below, because the new subject is bound to nothing.
        presented = (principal_claims.issuer, principal_claims.subject)
        bound = await self._store.get_user_by_federated_subject(*presented)
        if bound is not None and (bound.oidc_issuer, bound.oidc_subject) != presented:
            # BYTE-EXACT, whatever the backend's collation. SQL Server compares these columns under
            # the database default, usually case-insensitive, so `abc` can find the row bound to `ABC`.
            # That was harmless while the lookup only vetoed; now it SELECTS the account, so a pair
            # that differs in any byte is not this account's pair.
            bound = None
        if bound is None:
            # ADR 0184 AC-4, and the owner ruling it rests on (2026-09-06): the administrative
            # binding surface is the ONLY path that may create a binding. So first contact is refused
            # and binds nothing. Before this, `_complete_ad_login` recorded the pair on the account's
            # first federated login, which is the bind-on-first-presentation the ruling forbids.
            #
            # The visitor has proved control of this IdP identity and nothing else, so saying it is
            # not linked tells them nothing about any MessageFoundry account. It is refused before the
            # directory is consulted, so it says nothing about the directory either.
            #
            # Audited under a NEUTRAL actor: the claimed name selects nothing, so filing the row under
            # it would put a stranger's refusal in that person's security-events feed. The row
            # carries the presented pair, because the only remedy is an admin bind that needs the
            # exact `sub`, and the claimed name as a hint to whom it belongs.
            await self._audit(
                "auth.login_failed",
                actor="<oidc>",
                detail=_json(
                    {
                        "provider": "ad",
                        "mech": "oidc",
                        "reason": FEDERATED_SUBJECT_NOT_BOUND,
                        "issuer": principal_claims.issuer,
                        "subject": principal_claims.subject,
                        "claimed_username": username,
                    }
                ),
                client=client,
            )
            return LoginOutcome(
                ok=False,
                error=(
                    "this identity provider sign-in is not linked to an account; an administrator"
                    " must bind it with PUT /users/{user_id}/federated-identity"
                ),
                reason=FEDERATED_SUBJECT_NOT_BOUND,
            )
        # From here on every refusal concerns the SELECTED account, so it is audited under that
        # account's name, not the claimed one.
        username = bound.username
        if bound.auth_provider != AuthProvider.AD.value:
            # ADR 0184 part 3 and AC-3. The bind route refuses a LOCAL row, so this is the second
            # layer: a binding placed on one by any other means still never signs a LOCAL account in
            # through the directory path.
            await self._directory_reject_audit(username, "oidc", "local_account_conflict")
            return LoginOutcome(ok=False, error="account conflict", reason="local_account_conflict")
        if not bound.directory_object_id:
            # BACKLOG #2027 (ADR 0184 AC-5). A BOUND ROW WITH NO IMMUTABLE ID IS REFUSED, NOT
            # RE-RESOLVED BY NAME. The bind refuses such a row since BACKLOG #1143 slice C, so this
            # reaches only a binding written before that, or planted in the store. Its only
            # directory key is its username, and a directory may reissue a freed name to another
            # person; the re-resolve below would then hand the pair's holder that person's groups.
            #
            # Refused before the directory is consulted, and the binding is left in place rather
            # than cleared. Clearing is the audited admin unbind's act, and a login that wrote it
            # would sign the account out and notify its holder on the say-so of whoever presented
            # the pair. Refusing writes nothing and leaves the remedy to an administrator: unbind,
            # then follow DirectoryObjectIdMissing's steps to re-create the account with an id.
            #
            # The error is the generic one, and the web console collapses this slug to
            # `oidc_failed`. The precise reason is on the audit row, for the operator.
            await self._directory_reject_audit(username, "oidc", DIRECTORY_OBJECT_ID_MISSING)
            return LoginOutcome(
                ok=False, error="federated sign-in failed", reason=DIRECTORY_OBJECT_ID_MISSING
            )

        # ADR 0184 part 2 and AC-2: RE-RESOLVE THE DIRECTORY PRINCIPAL FROM THE BOUND ROW, never from
        # the claim. Carrying on with a principal resolved from the claimed username is the half-done
        # re-ordering the ADR warns about: `_upsert_ad_user` would touch the claimed name's row and
        # `roles_for_ad_groups` would write that name's groups onto the bound account. The row's own
        # object id is handed over as the reconciler hands it, so a directory-side rename still
        # resolves (BACKLOG #1532). The branch above guarantees the row carries one, so this
        # re-resolve is never keyed on the name alone (BACKLOG #2027).
        try:
            principal = await asyncio.to_thread(
                self._ldap.resolve_principal, bound.username, object_id=bound.directory_object_id
            )
        except LdapError as exc:
            await self._audit(
                "auth.login_error",
                actor="<oidc>",
                detail=_json({"provider": "ad", "mech": "oidc", "error": str(exc)}),
                client=client,
            )
            return LoginOutcome(
                ok=False, error="directory unavailable", reason="directory_unavailable"
            )
        if principal is None:
            # Hybrid-only by design: a bound account with no on-prem AD object is refused.
            await self._directory_reject_audit(username, "oidc", "not_in_directory")
            return LoginOutcome(
                ok=False, error="user not found in directory", reason="not_in_directory"
            )

        now = time.time()
        max_expires_at = principal_claims.expires_at
        if self._settings.oidc_session_max_hours:
            max_expires_at = min(max_expires_at, now + self._settings.oidc_session_max_hours * 3600)
        if max_expires_at <= now:
            # The ladder accepts an exp up to clock_skew_seconds in the PAST, so a token inside the
            # grace window would otherwise mint an already-dead session: the user "logs in" and is
            # revoked on their first request, with no audited reason. Refuse loudly instead.
            await self._directory_reject_audit(username, "oidc", "expired")
            return LoginOutcome(ok=False, error="federated sign-in failed", reason="expired")
        # BACKLOG #1150 (ASVS 6.8.4 / 7.6.1): the session also ends max_age after the user last
        # authenticated AT THE IdP. The ladder checks recency only at login. The IdP step-up leg
        # (BACKLOG #296) re-proves one sensitive action and deliberately does not extend the
        # session, so without this cap the time since the sign-in's IdP authentication would grow
        # unbounded for the session's whole life.
        # auth_time is clamped to now first: the ladder accepts an IdP clock up to clock_skew_seconds
        # AHEAD, and without the clamp that lead would extend the session past now + max_age. The
        # ladder already refuses a deadline behind its own clock; this branch is the backstop for
        # time spent between that check and here (the LDAP round trip), so a deadline already
        # behind now is refused under its own slug rather than minted dead.
        recency_deadline = (
            min(principal_claims.auth_time, now) + self._settings.oidc_max_age_seconds
        )
        if recency_deadline <= now:
            await self._directory_reject_audit(username, "oidc", "auth_time_stale")
            return LoginOutcome(
                ok=False, error="federated sign-in failed", reason="auth_time_stale"
            )
        max_expires_at = min(recency_deadline, max_expires_at)

        self.clear_oidc_unavailable()
        # ASVS 6.3.4, the one directory leg the engine can actually verify. Keyed on the SETTING, not
        # on mech == "oidc": when the claim gate is on (default), _check_mfa_gate has already refused
        # any token lacking a configured amr/acr, so a principal reaching this line provably carried
        # one and the grant is engine-verified. When the operator opted out, the engine verified
        # nothing, the session mints unverified, and mfa_satisfied refuses it (see :mfa_satisfied).
        # A load-time validator guarantees the gate can never be on-but-unmatchable, so the flag
        # alone is a sound predicate.
        mfa_verified = self._settings.oidc_require_mfa_claim
        return await self._complete_ad_login(
            principal,
            client,
            mfa_verified=mfa_verified,
            session_mechanism=SessionMechanism.OIDC,
            mech="oidc",
            evidence={
                "amr": list(principal_claims.amr),
                "acr": principal_claims.acr,
                "sub": principal_claims.subject,
                "mfa_verified": mfa_verified,
            },
            max_expires_at=max_expires_at,
            federated_subject=(principal_claims.issuer, principal_claims.subject),
            # ASVS 7.2.4: the session the START leg saw (see PendingFlow.prior_session_hash).
            supersedes_hash=flow.prior_session_hash,
        )

    # --- the federated step-up leg (BACKLOG #296, ADR 0142 Amendment B) ---------------------------

    async def session_steps_up_at_idp(self, token: str | None) -> bool:
        """Whether this session's step-up goes back to the IdP rather than to a password.

        True exactly when the session was minted by the federated login (``sessions.auth_mechanism``,
        ADR 0184 item (iv)). The SESSION decides, not the account: a hybrid directory account can also
        sign in by Kerberos, and that session keeps its existing step-up. PUBLIC because the web
        console's ``/ui/reauth`` asks it to choose which page to render. :meth:`reauth` asks it too,
        so a caller that forgot to would still never verify a password for an OIDC session.
        """
        if not token:
            return False
        session = await self._store.get_session(hash_token(token))
        return session is not None and session.auth_mechanism == SessionMechanism.OIDC.value

    async def begin_oidc_step_up(
        self,
        token: str,
        *,
        return_to: str,
        purpose: str | None,
        client: str | None,
        public_origin: str,
    ) -> tuple[str, str]:
        """Stage a STEP-UP flow for the caller's OIDC session; return ``(flow_id, authorization_url)``.

        The request carries ``max_age=0`` and ``prompt=login`` (ADR 0142 Amendment B), so the IdP
        must authenticate the user afresh. The flow stages the session's HASH, never its token, for
        the reason ``PendingFlow.prior_session_hash`` gives. ``return_to`` must already be a
        validated continuation. The callback hands it back from the flow, never from its own query.

        Raises :class:`~messagefoundry.auth.oidc.FlowError` when federation is off or the session
        was not minted by it, and :class:`~messagefoundry.auth.oidc.FlowCacheFullError` when the
        bounded cache is full, exactly as :meth:`begin_oidc_login` does.
        """
        if not self.oidc_enabled or self._oidc_flows is None:
            raise oidc.FlowError("federated sign-in is not configured")
        token_hash = hash_token(token)
        session = await self._store.get_session(token_hash)
        if (
            session is None
            or session.revoked_at is not None
            or session.auth_mechanism != SessionMechanism.OIDC.value
        ):
            raise oidc.FlowError("this session was not signed in through the identity provider")
        flow_id, flow = oidc.start_flow(
            self._oidc_flows,
            return_to=return_to,
            client_ip=client or "",
            ttl_seconds=self._settings.oidc_flow_ttl_seconds,
            step_up_session_hash=token_hash,
            step_up_purpose=purpose,
        )
        url = oidc.build_authorization_url(
            authorization_endpoint=self._settings.oidc_authorization_endpoint or "",
            client_id=self._settings.oidc_client_id or "",
            redirect_uri=self._oidc_redirect_uri(public_origin),
            state=flow.state,
            nonce=flow.nonce,
            code_challenge=oidc.pkce_challenge(flow.code_verifier),
            scopes=self._settings.oidc_scopes,
            max_age=self._settings.oidc_max_age_seconds,
            acr_values=self._settings.oidc_acr_values,
            step_up=True,
        )
        return flow_id, url

    def oidc_flow_is_step_up(self, flow_id: str) -> bool:
        """Whether the live flow behind this cookie is a step-up flow, WITHOUT consuming it.

        The callback route uses it to pick the completion. Each completion pops the flow and
        re-checks its kind, so a wrong answer here refuses. It never elevates or mints on the wrong
        leg. An unknown or expired flow answers False and the sign-in completion refuses it.
        """
        if self._oidc_flows is None:
            return False
        flow = self._oidc_flows.peek(flow_id)
        return flow is not None and flow.step_up_session_hash is not None

    async def abandon_oidc_step_up(
        self, flow_id: str, *, state: str | None, reason: str, client: str | None
    ) -> OidcStepUp:
        """End a step-up flow the IdP returned WITHOUT a usable code: the user cancelled at the IdP
        (an ``error`` on the callback) or the callback was malformed. Nothing is elevated.

        ``state`` must match before the flow is consumed. An error redirect carries it (RFC 6749,
        the authorization error response), and the flow cookie is SameSite=Lax, so without the
        check any page could cancel a step-up in flight by navigating the browser to the callback
        with ``error=``. A
        missing or wrong ``state`` is refused and the flow is left for the real IdP return.

        On a match the flow is consumed and a closed-set ``reason`` is audited (the route passes
        ``idp_error`` or ``malformed_callback``, never the IdP's own text), so the operator lands back
        on the step-up page they started from, still signed in."""
        flows = self._oidc_flows
        flow = flows.peek(flow_id) if flows is not None else None
        if flows is None or flow is None:
            return await self._step_up_refused("state_unknown", actor="<oidc>", client=client)
        if state is None or not oidc.state_matches(flow.state, state):
            # Filed under the NEUTRAL actor: nothing has been verified, and any page can send this
            # callback, so naming the account would let a stranger fill that person's security
            # events with step-ups they never attempted. The sign-in leg does the same.
            return await self._step_up_refused(
                "state_mismatch", actor="<oidc>", client=client, return_to=flow.return_to
            )
        flows.pop(flow_id)
        actor = await self._step_up_actor(flow)
        if flow.step_up_session_hash is None:
            return await self._step_up_refused(FLOW_PURPOSE_MISMATCH, actor=actor, client=client)
        return await self._step_up_refused(
            reason, actor=actor, client=client, return_to=flow.return_to
        )

    async def complete_oidc_step_up(
        self,
        *,
        flow_id: str,
        state: str,
        code: str,
        client: str | None,
        public_origin: str,
    ) -> OidcStepUp:
        """Redeem a step-up flow and, when the IdP proof holds, elevate the staged session.

        Checks, in order, each failing CLOSED with nothing elevated: the flow exists and ``state``
        matches; it is a step-up flow; the code exchange and the whole claims ladder pass (the nonce,
        the pinned issuer, ``auth_time`` present and within ``oidc_max_age_seconds``, and the MFA
        claim when that gate is on); the session is still live by every test
        :meth:`identity_for_token` applies, and still an OIDC session; ``auth_time`` is fresh (see
        the inline note); the account is enabled, still a directory account, and still in the
        directory; and the token's verified ``(issuer, sub)`` is byte-for-byte the pair bound to the
        account. Then it elevates through :meth:`_elevated_hash`, so rotation, the MFA carry and the
        single-use grant follow the password leg's rules exactly.

        Refusals are audited under the staged session's account wherever the flow names one, so they
        appear in that person's security events rather than under an anonymous actor.

        Not padded to a deadline, unlike the sign-in callback: the caller already holds a session,
        and the step-up leg does not choose between accounts.
        """
        if not self.oidc_enabled or self._oidc_flows is None or self._oidc_jwks is None:
            return await self._step_up_refused("not_configured", actor="<oidc>", client=client)
        flow = self._oidc_flows.peek(flow_id)
        if flow is None:
            return await self._step_up_refused("state_unknown", actor="<oidc>", client=client)
        return_to = flow.return_to
        if not oidc.state_matches(flow.state, state):
            # PEEKED, not popped: a forged callback carrying a code and a wrong state must not
            # consume the step-up in flight. Neutral actor, as in abandon_oidc_step_up.
            return await self._step_up_refused(
                "state_mismatch", actor="<oidc>", client=client, return_to=return_to
            )
        self._oidc_flows.pop(flow_id)
        actor = await self._step_up_actor(flow)
        token_hash = flow.step_up_session_hash
        if token_hash is None:
            return await self._step_up_refused(FLOW_PURPOSE_MISMATCH, actor=actor, client=client)
        try:
            principal_claims = await asyncio.to_thread(
                self._exchange_and_validate, code, flow, self._oidc_redirect_uri(public_origin)
            )
        except oidc.ClaimsError as exc:
            # exc.reason is closed-set, so nothing IdP-influenced reaches the audit row.
            return await self._step_up_refused(
                exc.reason, actor=actor, client=client, return_to=return_to
            )
        except oidc.TokenRefusedError:
            # The endpoint answered a 4xx. As on the sign-in leg, that is not an outage (#1948).
            return await self._step_up_refused(
                "token_refused", actor=actor, client=client, return_to=return_to
            )
        except (OSError, ValueError, http.client.HTTPException) as exc:
            # The sign-in leg's outage arm, for the same reasons. Only the exception TYPE is kept.
            self.mark_oidc_unavailable(type(exc).__name__)
            return await self._step_up_refused(
                "idp_unavailable", actor=actor, client=client, return_to=return_to
            )
        now = time.time()
        session = await self._store.get_session(token_hash)
        if (
            session is None
            or session.revoked_at is not None
            or session.auth_mechanism != SessionMechanism.OIDC.value
            # The rest of identity_for_token's liveness tests: absolute expiry, idle expiry and a
            # backward clock step. A session any of them would refuse on its next request is not
            # stepped up, so the operator is not told "verified" and then signed out.
            or not session.is_live(now=now, idle_seconds=self.session_idle_seconds)
        ):
            return await self._step_up_refused(
                "session_gone", actor=actor, client=client, return_to=return_to, lost=True
            )
        # FRESHNESS. max_age=0 and prompt=login ask the IdP to authenticate the user afresh, so a
        # conforming IdP's auth_time postdates this request. auth_time is IdP clock and issued_at
        # is ours, so the floor allows the configured skew for an IdP clock that runs behind.
        # RESIDUAL, stated exactly: an IdP that ignores max_age=0 still passes when its last
        # sign-in for this user is within oidc_clock_skew_seconds of this request. Closing that
        # needs the sign-in's own IdP auth_time stored on the session, so the comparison is IdP
        # clock against IdP clock; engine timestamps such as created_at would mix the two clocks.
        skew = self._settings.oidc_clock_skew_seconds
        if flow.issued_at <= 0 or principal_claims.auth_time < flow.issued_at - skew:
            return await self._step_up_refused(
                STEP_UP_NOT_FRESH, actor=actor, client=client, return_to=return_to
            )
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled or user.auth_provider != AuthProvider.AD.value:
            return await self._step_up_refused(
                "session_gone", actor=actor, client=client, return_to=return_to, lost=True
            )
        if (user.oidc_issuer, user.oidc_subject) != (
            principal_claims.issuer,
            principal_claims.subject,
        ):
            # BYTE-EXACT in Python, whatever the backend's collation (see _authenticate_oidc). The
            # IdP signed in SOMEONE, but not the identity this session's account is bound to: a
            # shared browser, or another person's IdP session. Nothing is elevated. The session is
            # left as it was rather than revoked, because whoever holds this flow cookie already
            # holds the session cookie in the same browser.
            return await self._step_up_refused(
                STEP_UP_SUBJECT_MISMATCH, actor=actor, client=client, return_to=return_to
            )
        # The DIRECTORY still has the account. The password re-bind this leg replaces failed for a
        # disabled or deleted AD object, and the sign-in leg refuses one as not_in_directory. An IdP
        # can still sign such a user in (sync lag, or its own credential store), so the engine asks
        # the directory itself, by the row's immutable id as the sign-in leg does (BACKLOG #1532).
        if self._ldap is None:
            return await self._step_up_refused(
                "not_configured", actor=actor, client=client, return_to=return_to
            )
        if not user.directory_object_id:
            # Never a name-only lookup: a directory may reissue a freed name to someone else. The
            # sign-in leg refuses such a row for the same reason (BACKLOG #2027).
            return await self._step_up_refused(
                DIRECTORY_OBJECT_ID_MISSING, actor=actor, client=client, return_to=return_to
            )
        try:
            principal = await asyncio.to_thread(
                self._ldap.resolve_principal, user.username, object_id=user.directory_object_id
            )
        except LdapError as exc:
            _log.warning(
                "directory lookup failed during a federated step-up: %s", type(exc).__name__
            )
            return await self._step_up_refused(
                "directory_unavailable", actor=actor, client=client, return_to=return_to
            )
        if principal is None:
            return await self._step_up_refused(
                "not_in_directory", actor=actor, client=client, return_to=return_to
            )
        purpose = flow.step_up_purpose
        # The password leg's three ORDER-CRITICAL steps (see :meth:`reauth`), against the hash.
        # (1) Every stamp against the OLD hash, re-anchoring the session to this client address.
        await self._store.mark_session_reauthed(token_hash, client=client)
        grant_refused = purpose is not None and await self._factor_binding_is_blocked_hash(
            token_hash, purpose
        )
        # (2) Rotate. Past this line the staged hash no longer resolves.
        elevation = await self._elevated_hash(
            token_hash, ceremony="reauth_oidc", actor=user.username, client=client
        )
        if purpose is not None and not grant_refused and elevation.token is not None:
            # (3) The purpose-bound grant, against the NEW hash.
            self._grant_action_step_up(hash_token(elevation.token), purpose)
        self.clear_oidc_unavailable()
        await self._audit(
            "auth.reauth",
            actor=user.username,
            detail=_json(
                {
                    "ok": elevation.ok,
                    "provider": AuthProvider.AD.value,
                    "mech": "oidc",
                    "purpose": purpose,
                    "session_lost": elevation.session_lost,
                    "grant_refused": grant_refused,
                    "session_revoked": False,
                }
            ),
            client=client,
        )
        return OidcStepUp(elevation=elevation, return_to=return_to)

    async def _step_up_actor(self, flow: PendingFlow) -> str:
        """The account a step-up refusal is filed under: the staged session's user, else ``<oidc>``.

        A step-up flow names its session, so a refusal on it belongs in that person's security
        events. A sign-in flow, or a session already gone, has no account to name."""
        if flow.step_up_session_hash is None:
            return "<oidc>"
        session = await self._store.get_session(flow.step_up_session_hash)
        user = await self._store.get_user(session.user_id) if session is not None else None
        return user.username if user is not None else "<oidc>"

    async def _step_up_refused(
        self,
        reason: str,
        *,
        actor: str,
        client: str | None,
        return_to: str = "/ui",
        lost: bool = False,
    ) -> OidcStepUp:
        """Audit and package one refusal of the federated step-up leg. ``reason`` is closed-set."""
        await self._audit(
            "auth.reauth",
            actor=actor,
            detail=_json(
                {"ok": False, "provider": AuthProvider.AD.value, "mech": "oidc", "reason": reason}
            ),
            client=client,
        )
        return OidcStepUp(
            elevation=Elevation(session_lost=lost),
            return_to=return_to,
            reason=reason,
            error=_STEP_UP_ERRORS.get(reason, "The identity provider could not confirm it's you."),
        )

    async def _refuse_directory_row(
        self, username: str, reason: str, *, client: str | None
    ) -> LoginOutcome:
        """Audit and render the refusal of an ineligible mirror row (BACKLOG #1637 / #1638).

        **Audited in the shape of the ``local_account_conflict`` refusal, NOT through
        :meth:`_directory_reject_audit`.** That helper requires a mechanism slug, and the Kerberos
        leg reaches this decision point without one -- ``mech`` is optional on
        :meth:`_complete_ad_login` and defaults to ``None``. The reason is a closed-set literal
        either way, so no directory-supplied text is stored.

        ``error`` is the generic string on purpose: an unauthenticated caller learns that the attempt
        failed and nothing about whether the account exists, is disabled, or is locked.
        """
        await self._audit(
            "auth.login_failed",
            actor=username,
            detail=_json({"provider": "ad", "reason": reason}),
            client=client,
        )
        return LoginOutcome(ok=False, error="invalid credentials", reason=reason)

    async def _directory_reject_audit(self, actor: str, mech: str, reason: str) -> None:
        """Audit a rejected directory-SSO attempt. ``mech`` is the mechanism slug ("kerberos" /
        "oidc"); ``reason`` must come from a closed set so no IdP-influenced text is ever stored."""
        await self._audit(
            "auth.login_failed",
            actor=actor,
            detail=_json({"provider": "ad", "mech": mech, "reason": reason}),
        )

    async def _complete_ad_login(
        self,
        principal: AdPrincipal,
        client: str | None,
        *,
        mfa_verified: bool,
        # ADR 0184 item (iv). Both production callers pass it explicitly. The default serves the
        # many direct test callers of the Kerberos shape. An OIDC mint cannot fall to it silently:
        # the federated caller also passes ``federated_subject``, and the body refuses the pair
        # unless the two agree.
        session_mechanism: SessionMechanism = SessionMechanism.KERBEROS,
        mech: str | None = None,
        evidence: Mapping[str, object] | None = None,
        max_expires_at: float | None = None,
        federated_subject: tuple[str, str] | None = None,
        supersedes_hash: str | None = None,
    ) -> LoginOutcome:
        # ``federated_subject`` is the verified OIDC ``(issuer, sub)`` and is passed ONLY by the
        # federated path (BACKLOG #1015). It defaults to None, so the Kerberos caller stays
        # byte-identical -- no extra store read, no changed audit row. The federated caller has
        # already SELECTED the account by that pair and re-resolved ``principal`` from the selected
        # row (ADR 0184), so the name read below finds that row unless the directory renamed it.
        federated = federated_subject is not None or mech == "oidc"
        if federated != (session_mechanism is SessionMechanism.OIDC):
            # A programming error, not a login outcome: a verified federated pair minted under any
            # other mechanism would let that OIDC session step up by password (ADR 0142 Amendment B).
            raise ValueError(
                "a federated login (federated_subject or mech='oidc') needs the OIDC session"
                " mechanism, and only a federated login may use it"
            )
        existing = await self._store.get_user_by_username(principal.username)
        if existing is not None and existing.auth_provider != AuthProvider.AD.value:
            # Never let an AD login adopt/overwrite a like-named LOCAL account (provider confusion).
            await self._audit(
                "auth.login_failed",
                actor=principal.username,
                detail=_json({"provider": "ad", "reason": "local_account_conflict"}),
                client=client,
            )
            return LoginOutcome(ok=False, error="account conflict")
        if existing is not None and existing.directory_object_id != principal.directory_object_id:
            # BACKLOG #1471. THE ROW HOLDING THIS NAME MUST AGREE WITH THE PRESENTED IDENTITY.
            #
            # **THIS IS NOT WHAT CLOSES THE RECYCLE** -- say so plainly, because the obvious reading
            # is wrong and would send the next reader looking for the control in the wrong place.
            # ``_upsert_ad_user`` no longer ASKS by name, so a reissued ``sAMAccountName`` presenting
            # a new id misses the id lookup and gets its own row whether or not this branch exists.
            # What this branch does is narrower, and both halves are load-bearing:
            #
            #   - it refuses an id-LESS login against a BOUND row, the one state where the name
            #     fallback below could still adopt somebody else's account. An identity that cannot
            #     be checked is not an identity that matches;
            #   - it turns the ``UNIQUE(username)`` collision that a recycle would otherwise hit into
            #     an ordered, audited refusal instead of an integrity error surfacing as a 500 -- the
            #     same move the federated bind makes forty lines below.
            #
            # The third state it catches is an UNBOUND row meeting a login that presents an id: a row
            # that predates the column. Refused rather than backfilled, because adopt-and-backfill on
            # first sight leaves the window open for every account that has not signed in since the
            # column landed, which is the hole. (Section 0: zero deployments, so there are none.)
            #
            # THE COST, STATED: a site whose directory stops returning ``objectGUID`` refuses every
            # AD login for an already-bound account until the attribute is readable again, and a
            # recycled name needs an administrator to remove the stale MessageFoundry row before the
            # new holder can sign in. Both are audited, loud, and recoverable; the alternative failure
            # is silent privilege transfer.
            #
            # Audited in the shape of the ``local_account_conflict`` refusal above rather than
            # through ``_directory_reject_audit``: this is the same decision point, it is reached by
            # every directory mechanism including the one that passes no ``mech``, and the reason
            # slug is a closed-set literal either way. No directory-supplied text is stored.
            await self._audit(
                "auth.login_failed",
                actor=principal.username,
                detail=_json({"provider": "ad", "reason": "directory_identity_conflict"}),
                client=client,
            )
            return LoginOutcome(
                ok=False, error="account conflict", reason="directory_identity_conflict"
            )
        # BACKLOG #1637 / #1638. IS THIS ROW ELIGIBLE TO SIGN IN AT ALL.
        #
        # THIS ARM IS FOR THE READER, NOT FOR THE CONTROL -- said plainly, because a guard documented
        # as load-bearing when it is not is the false-premise shape SDS-3.7 names. The gate inside
        # ``_upsert_ad_user`` runs on ``by_name`` as well, so it already covers every row this branch
        # covers: delete these four lines and no outcome changes. What they buy is that the refusal
        # is VISIBLE in the login method a reviewer reads, and that the common case is refused before
        # the resolver is entered.
        #
        # THE ARM THAT CLOSES THE DEFECT IS THE OTHER ONE, and this read's KEY is why: it is keyed by
        # NAME, so on a directory-side rename it misses, ``existing`` is None, and the row the login
        # lands on comes from the id-keyed lookup the resolver does. A check written only here would
        # look complete and close nothing on that path.
        #
        # ORDERED AFTER THE TWO CONFLICT BRANCHES ABOVE, DELIBERATELY. A recycled ``sAMAccountName``
        # meeting a stale disabled row is a ``directory_identity_conflict`` and not a ``disabled``
        # login: the new holder's account is neither disabled nor locked, and telling them otherwise
        # would misdirect the operator reading the audit row.
        if existing is not None:
            refusal = _directory_login_refusal(existing, time.time())
            if refusal is not None:
                return await self._refuse_directory_row(principal.username, refusal, client=client)
        try:
            user = await self._upsert_ad_user(principal, by_name=existing, client=client)
        except _DirectoryLoginRefused as exc:
            # The resolver refused before it wrote anything. Rendered here rather than there so the
            # audit row carries the caller's ``client`` and every directory refusal in this method
            # has one shape.
            return await self._refuse_directory_row(principal.username, exc.reason, client=client)
        if (
            federated_subject is not None
            and (
                user.oidc_issuer,
                user.oidc_subject,
            )
            != federated_subject
        ):
            # THE ROW THIS LOGIN REACHED DOES NOT HOLD THE PAIR THAT SELECTED IT. The caller chose the
            # account by the pair and re-resolved ``principal`` from it, so on the ordinary path this
            # never fires. It fires when the directory leads somewhere else: the re-resolved
            # principal maps, by name or by object id, to a different mirror row. That row must not
            # be signed in, and above all must not take the pair's roles, which the role write below
            # would give it. So refuse, BEFORE the role write.
            #
            # BACKLOG #1256: this was the subject-exclusivity guard, and its refusal slug is kept for
            # the case it still names -- the subject is held by a DIFFERENT account than the one
            # reached. `ux_users_federated_subject` still makes that holder unique on all three
            # backends.
            #
            # BACKLOG #1143 / #295: IT NO LONGER BINDS. When no account holds the pair any more, this
            # used to record the pair on the row reached -- bind on first presentation, the path the
            # owner's 2026-09-06 ruling forbids. The only way the pair can be unheld here is an
            # admin unbind or rebind landing after the caller's read, so it is refused as first
            # contact is (ADR 0184 AC-4), and nothing is written.
            holder = await self._store.get_user_by_federated_subject(*federated_subject)
            reason = (
                FEDERATED_SUBJECT_NOT_BOUND if holder is None else "federated_subject_already_bound"
            )
            await self._directory_reject_audit(principal.username, "oidc", reason)
            return LoginOutcome(ok=False, error="federated sign-in failed", reason=reason)
        role_ids = sorted(await self._store.roles_for_ad_groups(principal.groups))
        previous = set(await self._store.get_user_role_ids(user.id))
        await self._store.set_user_roles(user.id, role_ids, assigned_by="ad-sync")
        if set(role_ids) != previous:
            # Directory-side role change (often a downgrade): revoke the user's other live sessions
            # so stale elevated tokens don't linger until expiry (AUTH-AD-REVOKE). The new session
            # is issued below, after this, so the current login is unaffected.
            await self._store.revoke_user_sessions(user.id)
            await self._audit(
                "auth.ad_roles_resynced",
                actor=user.username,
                detail=_json({"from": sorted(previous), "to": role_ids}),
                client=client,
            )
            # A directory-pushed privilege change is the same privilege change to the same user as a
            # local one, so notify the affected user out-of-band too (ASVS 6.3.7), matching set_roles().
            # Best-effort; the change is also visible in the audited /me/security-events feed.
            await self._notify_security(
                ROLES_CHANGED,
                username=user.username,
                email=user.notify_email,
                client=client,
                detail={"roles": role_ids},
            )
        ad_roles = _roles_from_ids(role_ids)
        ad_custom_permissions = await self._custom_permissions_for_ids(role_ids)
        user = await self._sync_ad_channel_scope(user, ad_roles, principal.groups, client=client)
        identity = Identity.build(
            user_id=user.id,
            username=user.username,
            auth_provider=AuthProvider.AD,
            roles=ad_roles,
            must_set_notify_email=self.notify_email_required(user),
            allowed_channels=_allowed_channels(user, ad_roles),
            extra_permissions=ad_custom_permissions,
        )
        # BACKLOG #288: the first-seen address signal, classified before the mint for the same
        # reason as on the local leg. There is no seed to withhold here: every directory login
        # already mints with seed_reauth=False below, so a NEW verdict is challenged by construction
        # and this leg adds the audit row and the notice.
        address = await self._classify_login_address(user, client)
        # ASVS 6.3.4 / 6.8.4: the second-factor grant is the CALLER's per-mechanism decision, not a
        # blanket literal. Kerberos passes False -- a ticket asserts nothing about directory-side
        # strength, so the engine assumes the minimum (BACKLOG #1144); the federated leg passes the
        # engine-verified amr/acr result. See the callers for each rationale.
        try:
            token = await self._issue_session(
                user.id,
                client,
                mfa_verified=mfa_verified,
                # NO DIRECTORY LOGIN SEEDS THE STEP-UP WINDOW (BACKLOG #1144 step 5, ASVS 6.8.4). A
                # ticket or a federated redirect is an AMBIENT proof, and seeding would let the
                # engine's own login stamp satisfy `has_recent_step_up` for the whole
                # `step_up_max_age_seconds` window with no directory interaction. So the first
                # window-gated action demands a real step-up: a directory re-bind for a `kerberos`
                # session, the IdP for an `oidc` one (`/ui/reauth/oidc`, BACKLOG #296), or an engine
                # TOTP or recovery code at the MFA gate, since `verify_mfa` stamps the window.
                #
                # A CONSTANT, NOT A PARAMETER. This used to be `seed_reauth: bool = True`, and the
                # two Kerberos routes disagreed: `GET /ui/sso` passed False while `POST
                # /auth/negotiate` took the seeding default. One pathway, two postures. Taking the
                # choice away from the caller is what keeps them one.
                seed_reauth=False,
                # ADR 0184 item (iv): stated by each caller, never inferred from the audit-only
                # ``mech``, which the Kerberos leg leaves unset to keep its audit row unchanged.
                mechanism=session_mechanism,
                max_expires_at=max_expires_at,
                # BACKLOG #1474. THE UNBIND'S SESSION SWEEP CANNOT SEE A SESSION THAT DOES NOT EXIST
                # YET, which is the race this closes: an admin unbinding this account mid-login
                # revokes what is live at that instant, and without the guard this login's own
                # INSERT lands just after it. The Kerberos and password legs pass nothing here, so
                # they take no extra read and no extra statement.
                require_federated_subject=federated_subject,
                supersedes_hash=supersedes_hash,
            )
        except _FederatedBindingWithdrawn:
            await self._directory_reject_audit(
                principal.username, "oidc", "federated_subject_unbound"
            )
            return LoginOutcome(
                ok=False,
                error="federated sign-in failed",
                reason="federated_subject_unbound",
            )
        # The password-AD and Kerberos paths must keep emitting EXACTLY {"provider","roles"}: _json is
        # json.dumps(sort_keys=True), so a null-valued key is a different stored string, not a no-op.
        # Only the federated path passes mech/evidence, so it alone grows the row.
        detail: dict[str, object] = {"provider": "ad", "roles": role_ids}
        if mech is not None:
            detail["mech"] = mech
        if evidence:
            detail["evidence"] = dict(evidence)
        await self._record_login_address(address, user, client=client, provider="ad")
        await self._audit(
            "auth.login_success", actor=user.username, detail=_json(detail), client=client
        )
        # Ask the GATE, not the grant (BACKLOG #1144). A leg that granted nothing has not necessarily
        # left a debt: with require_mfa off and no factor enrolled the shared rule still admits the
        # session, so `not mfa_verified` would over-report and prompt for a factor the caller does not
        # owe. One extra read on a rare path buys a single source for the answer.
        mfa_required = not await self.mfa_satisfied(token)
        if not mfa_required:
            # BACKLOG #1638. THE COUNTER IS CLEARED AT FULL AUTHENTICATION, NEVER AT THE FIRST STEP.
            # ``record_login_success`` zeroes ``failed_attempts`` and NULLs ``locked_until`` in one
            # UPDATE, so running it here unconditionally -- which is what this method used to do,
            # forty lines above -- handed a holder of the first factor an unlimited supply of second-
            # factor guesses: every re-login wiped the run of wrong codes, and five wrong codes
            # followed by one re-login cleared the lock outright. When a second factor is still owed
            # the session is not authenticated yet, so there is nothing to record.
            #
            # ``verify_mfa`` and ``finish_webauthn_assertion`` are the two legs that finish the job,
            # and both clear the counter themselves.
            await self._store.record_login_success(user.id)
        return LoginOutcome(
            ok=True,
            token=token,
            identity=identity,
            mfa_required=mfa_required,
        )

    async def _sync_ad_channel_scope(
        self,
        user: UserRecord,
        roles: frozenset[Role],
        groups: Iterable[str],
        *,
        client: str | None = None,
    ) -> UserRecord:
        """Persist a user's AD-group-derived per-channel scope (C3) so it's durable for later
        requests (mirrors role sync). Returns the (possibly refreshed) user record.

        **The rule is** :func:`~messagefoundry.auth.channel_scope.decide_ad_channel_scope` **and is
        stated there once**; this method applies what it decides. The directory reconciler plans its
        revocations with the same function (ADR 0198). A copy here could drift from it, and a pass
        that revokes for a scope this login never writes would revoke again on every pass (the
        BACKLOG #1532 loop).

        History worth keeping: before BACKLOG #1927 this path returned early for every no-match
        login, so a user removed from their last scope-mapped group kept the directory's channels
        for as long as the account existed."""
        administrator = Role.ADMINISTRATOR in roles
        decision = channel_scope.decide_ad_channel_scope(
            channel_scope.ScopeInput(
                stored_scope=user.channel_scope,
                stored_source=user.channel_scope_source,
                # An administrator's groups are not read: the decision ignores them.
                mapped=frozenset()
                if administrator
                else frozenset(await self._store.channels_for_ad_groups(groups)),
                administrator=administrator,
            )
        )
        if not decision.write:
            return user
        if decision.scope_json is None:
            if user.channel_scope is None:
                # The decision never withdraws a NULL scope, which already denies. This narrows
                # the type for the compare-and-set below, which needs a stored value to compare.
                return user
            # Compare-and-set against the value read: an administrator or a concurrent login may
            # have written the scope since ``user`` was read.
            if not await self._store.withdraw_ad_channel_scope(user.id, user.channel_scope):
                return await self._store.get_user(user.id) or user
            await self._store.revoke_user_sessions(user.id)
            # ``withdrawn`` keeps the removed grant, which the row itself no longer holds.
            await self._audit(
                "auth.ad_scope_resynced",
                actor=user.username,
                detail=_json({"channels": None, "withdrawn": user.channel_scope}),
                client=client,
            )
            return await self._store.get_user(user.id) or user
        await self._store.set_user_channel_scope(
            user.id, decision.scope_json, source=SCOPE_SOURCE_AD
        )
        # Drop stale-scope tokens; the new one is issued after. Skipped when only the provenance
        # moved -- the directory taking over an identical manual scope changes no decision, so
        # there is nothing stale to drop -- but that write is still audited below.
        if decision.changes:
            await self._store.revoke_user_sessions(user.id)
        await self._audit(
            "auth.ad_scope_resynced",
            actor=user.username,
            detail=_json(
                {"channels": ALL_CHANNELS if decision.wildcard else list(decision.channels)}
            ),
            client=client,
        )
        return await self._store.get_user(user.id) or user

    async def _upsert_ad_user(
        self,
        principal: AdPrincipal,
        *,
        by_name: UserRecord | None,
        client: str | None = None,
    ) -> UserRecord:
        """Resolve the mirror row for a directory principal, creating it on first sight.

        **IDENTIFIES BY THE DIRECTORY'S IMMUTABLE ID, NOT BY THE NAME (BACKLOG #1471).** A
        ``sAMAccountName`` is a label a directory may free and reissue; ``objectGUID`` is minted once
        per account object and survives a rename or an OU move. So a principal carrying an id is
        resolved by that id, and a reissued name that presents a different id misses and gets its own
        row with its own ``user_id`` -- which is what keeps uploaded-file ownership, the per-uploader
        quota and saved search presets pointed at the person who earned them.

        ``by_name`` is the row holding ``principal.username``, which the caller has already read and
        already checked against the presented id. It is passed rather than re-read: taking it as a
        parameter is what makes the dependency on that check visible in the signature instead of only
        in prose, and it saves a second ``SELECT`` on every directory sign-in. The id-keyed lookup
        then runs only when the name misses -- the directory-side RENAME, the one state a name-keyed
        read cannot answer.

        A directory returning no id at all falls back to the name, which is the behaviour that shipped
        before the column existed. The engine cannot key on an identifier it is not given; the LDAP
        layer logs each such read.

        **A DIRECTORY-SIDE RENAME IS PROPAGATED, ONTO A ROW THAT NEVER MOVES (BACKLOG #1532).** The id
        finds the account, and the directory's current ``sAMAccountName`` is then copied down onto the
        row's cached ``username``. The ``user_id`` is untouched, so uploaded-file ownership, the
        per-uploader quota and saved search presets stay pointed at the same person; only the label
        follows the directory, which owns it.

        **WHY THAT REFRESH IS HERE AND NOT ONLY IN THE RECONCILER.** The ADR 0079 reconciler refreshes
        the same label on its own pass, but it is not always running: ``ad_session_recheck_seconds``
        can be set to 0, and a pass reaches only accounts holding a live session. This path reaches
        every directory sign-in, so the cached name is correct from the first login after a rename
        rather than up to one interval later. The two writers agree by construction -- both copy the
        directory's answer, neither invents one.

        **THE HISTORY IS KEPT BECAUSE IT NAMES A DEFECT CLASS, NOT BECAUSE IT IS STILL LIVE.** Before
        BACKLOG #1471 a rename resolved to nothing and minted a SECOND account, silently orphaning the
        uploads and presets keyed to the first. #1471 fixed identification and left the reconciler
        probing by the old name, so a renamed account read as ABSENT on every pass and had its sessions
        revoked on a roughly ten-minute cycle a deploying site could not break out of -- an earlier
        draft of this docstring said that lasted "until an administrator corrects the stored name", and
        no such operation existed. That was a compensating control resting on a false premise, which is
        worse than naming no remedy. #1532 re-keyed the probe and added the refresh above. Both
        spellings of the bug were the same mistake: reading a recyclable label as an identity.

        Raises :class:`_DirectoryLoginRefused` when the resolved row is engine-disabled or locked
        (BACKLOG #1637 / #1638), before any write. See the gate below the id-keyed lookup for why the
        condition is signalled from here rather than checked on the returned record.
        """
        if by_name is not None and by_name.directory_object_id != principal.directory_object_id:
            # Defensive, and deliberately a RAISE rather than a silent re-read. The caller's check is
            # what stops a row being adopted by a principal it does not belong to, so a caller that
            # skipped it must fail loudly here: an unnoticed adoption is the defect this item exists
            # to remove, and a 500 on a misuse that no shipped path can reach is the cheap side of
            # that trade. Not reachable from ``_complete_ad_login``, which refuses first.
            raise ValueError("directory principal does not match the row holding its username")
        existing = by_name
        if existing is None and principal.directory_object_id is not None:
            existing = await self._store.get_user_by_directory_object_id(
                principal.directory_object_id
            )
        # BACKLOG #1637 / #1638. THE ELIGIBILITY GATE THAT ACTUALLY CLOSES THE DEFECT, and its
        # POSITION is the whole of it: immediately after the id-keyed read, BEFORE the first write.
        #
        # The caller checks the row it read BY NAME. On a directory-side rename that read misses, and
        # the row this login lands on is the one the id lookup above just returned -- which the caller
        # has never seen. A check sited on this method's RETURN VALUE would be too late by then: the
        # rename refresh, the profile write and the caller's role resync have all already run against
        # a row that must not be signing in.
        if existing is not None:
            refusal = _directory_login_refusal(existing, time.time())
            if refusal is not None:
                raise _DirectoryLoginRefused(refusal)
        if existing is None:
            user_id = await self._create_directory_row(principal, client=client)
        else:
            user_id = existing.id
            if principal.username != existing.username:
                # BACKLOG #1532. Reachable only through the id-keyed lookup above: a name-keyed hit
                # matched on this very column, and a `by_name` row whose id disagrees already raised.
                # So arriving here means the directory renamed an account the engine has identified
                # by its immutable id, and the cached label is what is stale.
                #
                # `held=by_name` rather than a fresh read, and it is provably None on this path: this
                # branch needs the id lookup to have run, which needs `by_name` to have missed. That
                # is why the collision branch inside is the reconciler's alone.
                await self._refresh_cached_username(
                    user_id=user_id,
                    old_username=existing.username,
                    new_username=principal.username,
                    held=by_name,
                    client=client,
                )
            # BACKLOG #1139. AN ABSENT DIRECTORY ATTRIBUTE IS NOT AN INSTRUCTION TO ERASE.
            # ``update_user_profile``'s write is unconditional, so passing ``principal.email``
            # straight through let a directory that returned no ``mail`` blank the stored address on
            # the next login -- and "returned no mail" covers an unset attribute, one the bind
            # account cannot read, and one trimmed from the search attribute list, none of which is
            # a site saying "remove this address".
            #
            # The address is this account's ONLY notification target, so that erase also excluded the
            # account from every later notice: ``SecurityEventNotifier.notify`` returns early on an
            # empty address. A directory that has nothing to say now leaves the stored value alone.
            #
            # THE COST, STATED: a site that deliberately clears ``mail`` in the directory no longer
            # propagates that clear on the next login. An administrator can still clear the address
            # through ``PATCH /users/{id}``, which is audited and notified, so nothing becomes
            # unreachable -- only the silent path is closed.
            display_name = principal.display_name or existing.display_name
            email = principal.email or existing.email
            await self._store.update_user_profile(user_id, display_name=display_name, email=email)
            if email != existing.email:
                # BACKLOG #1139, ASVS 6.3.7. The directory owns the attribute, but repointing it
                # decides where every later security notice on this account is delivered -- so it is
                # an update to the account's authentication details, and it gets the same two records
                # the local sibling ``update_user`` emits: an audit row and an out-of-band notice.
                #
                # This method sits on the SHARED directory completion path, so this covers the
                # simple-bind, Kerberos and federated legs alike, not AD alone.
                await self._audit(
                    "auth.ad_profile_email_changed",
                    actor=principal.username,
                    detail=_json({"user_id": user_id, "source": "directory"}),
                    client=client,
                )
                # ADDRESSED TO THE ENGINE-OWNED ``notify_email`` FIRST (BACKLOG #1139, ADR 0182).
                # This read used to start at ``existing.email``, the profile mirror, which is the one
                # column a directory repoint is free to move -- so the notice about a repoint could
                # be delivered to an address an earlier repoint had installed. That is ADR 0182
                # option 3, rejected in terms: "whoever repointed the attribute is the party the
                # notice would reach". Two ways it came apart, both driven rather than argued:
                #
                #   - the SECOND consecutive repoint, where the mirror holds what the first one
                #     wrote while ``notify_email`` still holds the address the account was born
                #     with; and
                #   - any repoint after an administrator clears the profile address, where the empty
                #     mirror falls through to the directory's NEW value even though the engine-owned
                #     address is standing and deliverable (ADR 0182 AC-4 guarantees it survives).
                #
                # The fallbacks are ordered by what the directory cannot reach. ``notify_email`` is
                # engine-owned and no directory-sync statement names it, so it is the target while it
                # exists -- which is the OLD-HOLDER PRINCIPLE the local sibling ``update_user``
                # follows when it addresses its own EMAIL_CHANGED to ``before.notify_email``.
                #
                # THE MIRROR FALLBACK IS NOT DEAD, AND IT IS NOT WHAT ``update_user`` DOES -- that
                # sibling reads one term. It is reachable in at least two states, which only this
                # method can produce. One is an account created with NO address, which later acquired
                # one from the directory, because ``update_user_profile`` writes the mirror and never
                # seeds ``notify_email``. On that account's next repoint the mirror is the prior
                # holder. Failing both terms the account has never carried an address at all, so the
                # incoming value is the only reachable party and there is no earlier holder to
                # protect -- it is the target rather than announcing a first set to nobody.
                #
                # THE MIRROR IS READ THROUGH THE BIRTH TEST, SO A VALUE IT REFUSES IS NO HOLDER
                # (BACKLOG #2100). A refused value reaches the mirror of an account with no
                # ``notify_email`` in at least two ways. The birth refused the directory's ``mail``
                # (#2014), or the account was born with none and the directory filled the mirror
                # later, unchecked. Announcing to that value would hand the corrected address, in
                # ``new_email``, to whoever planted it, on a first deployment. So the chain falls
                # through to the new value, which learns only its own address.
                #
                # WHY NOT THE OTHER FORMS THE ITEM NAMED. Dropping ``new_email`` still sends a
                # notice to the planted address, and the renderer reads an EMAIL_CHANGED with no
                # ``new_email`` as a REMOVAL (``pipeline/security_notify.py``), which is false.
                # Skipping only a mirror the birth refused needs a marker read on each such
                # repoint, and still misses the filled-later case, which leaves no marker.
                #
                # THE COST, STATED: an administrator's non-ASCII, Punycode or malformed profile
                # address on a directory account with no ``notify_email`` is also read as no
                # holder. That address is not told of the repoint; the new value is.
                #
                # WHAT THIS DOES NOT CLOSE: the test refuses only non-ASCII, Punycode and
                # malformed values. An all-ASCII lookalike such as ``examp1e`` passes it, as it
                # passes the birth, so a planted one of those in the mirror is still told the
                # corrected address. No shape test can tell it from a real address.
                #
                # The same test the address form's suggestion applies, so the two cannot drift.
                prior_holder = self.suggested_notify_email(existing.email)
                await self._notify_security(
                    EMAIL_CHANGED,
                    username=principal.username,
                    email=existing.notify_email or prior_holder or email,
                    client=client,
                    detail={"new_email": email, "source": "directory"},
                )
        user = await self._store.get_user(user_id)
        assert user is not None  # just upserted
        return user

    async def _create_directory_row(
        self,
        principal: AdPrincipal,
        *,
        client: str | None,
        actor: str | None = None,
        typed_notify_email: str | None = None,
    ) -> str:
        """Insert the mirror row for a directory principal the store does not hold, and return its id.

        The one directory birth, shared by a directory sign-in (:meth:`_upsert_ad_user`) and an
        administrator's create (:meth:`create_directory_account`, BACKLOG #2021), so the two cannot
        disagree about what a new directory account carries. The caller has already established that
        no row holds the principal's id or name.

        ``typed_notify_email`` is the administrator's checked address for a row whose ``mail`` is
        not adopted (#2021 only). It is bound in the same INSERT, so no crash leaves that row with
        no address. The profile mirror still gets the directory's ``mail``.
        """
        user_id = uuid4().hex
        # BACKLOG #2014, ASVS 6.3.7. The birth seed is the one time the directory's `mail` can
        # become `notify_email`, where every later security notice goes. So it must pass the test
        # the address form applies before it suggests the same value; the form never sees an
        # account born with an address. Someone who can write `mail` but cannot sign in could
        # otherwise plant a lookalike before the holder's first sign-in. A refused value stays
        # in the profile mirror, and the account is born with no target, which confines it
        # until the holder chooses one (`notify_email_required`). Refused in the same INSERT
        # rather than cleared after, so no crash can leave the lookalike seeded.
        adopt = _adopts_directory_mail(principal)
        # The address stays out of the audit row and the log. It is directory-supplied and may be a
        # lookalike of someone's real one. The row is written IN THE INSERT'S TRANSACTION (BACKLOG
        # #2100): as a second write, a crash between the two kept the account and lost the record.
        refusal = (
            None
            if adopt
            else AuditAppend(
                "auth.ad_notify_email_not_adopted",
                # The sign-in's own holder, or the administrator whose create this is (#2021).
                actor=actor or principal.username,
                detail=_json({"user_id": user_id, "source": "directory"}),
                client=client,
            )
        )
        await self._store.create_user(
            user_id=user_id,
            username=principal.username,
            auth_provider=AuthProvider.AD.value,
            display_name=principal.display_name,
            email=principal.email,
            # Written AT CREATION rather than by a follow-up setter, so the row cannot exist in an
            # unbound state. A crash between the two writes would have left a row no id-carrying
            # login may adopt and no operator asked for -- a self-inflicted lockout.
            directory_object_id=principal.directory_object_id,
            adopt_notify_email=adopt,
            notify_email=typed_notify_email,
            audit=refusal,
        )
        if not adopt:
            if typed_notify_email is None:
                _log.warning(
                    "directory account %s created without a notification address: the directory "
                    "mail is not one plain ASCII mailbox with no Punycode label",
                    user_id,
                )
            else:
                _log.warning(
                    "directory account %s: the directory mail is not one plain ASCII mailbox with "
                    "no Punycode label, so an administrator gave its notification address",
                    user_id,
                )
        return user_id

    async def create_directory_account(
        self,
        username: str,
        *,
        actor: str,
        client: str | None = None,
        notify_email: str | None = None,
    ) -> str:
        """Admin: create the mirror row for a directory (AD) account without a sign-in (BACKLOG #2021).

        Before this, only a Kerberos sign-in created one, so a site without Windows SSO had no row
        that ``PUT /users/{id}/federated-identity`` could bind, and nobody could sign in through its
        IdP (ADR 0184 slice A).

        **THE ROW'S DIRECTORY IDENTITY COMES FROM THE DIRECTORY, NEVER FROM THE CALLER.** The
        administrator names the account; a service-account lookup
        (:meth:`~messagefoundry.auth.ldap.LdapAuthenticator.resolve_principal`, the one a Kerberos
        sign-in makes) supplies its ``objectGUID``, current ``sAMAccountName``, display name and
        ``mail``. An administrator-typed id would let one account's row claim another's identity,
        which is the recycle the id exists to stop (BACKLOG #1471). The birth is
        :meth:`_create_directory_row`, the one a sign-in uses, #2014's address rule included.

        **THE ROW IS NEVER BORN WITHOUT A NOTIFICATION ADDRESS (ASVS 6.3.7, as #2018 rules for a
        local create).** Its holder is not present, and the next thing done to it is usually a
        federated binding, whose notice goes to that address. So the directory's ``mail`` is the
        address when #2014's rule adopts it, and ``notify_email`` must then be omitted: the
        administrator does not get to point the holder's notices elsewhere. When the directory
        supplies no adoptable ``mail``, ``notify_email`` is required and is checked as
        ``POST /users`` checks its address (:func:`_require_single_mailbox`). Both refusals are
        :class:`InvalidNotifyEmail`.

        Refuses, before any write: no directory configured or a blank name
        (:class:`DirectoryAccountRefused`), a name the directory does not return or returns disabled
        (:class:`DirectoryAccountNotFound`), an entry
        with no readable ``objectGUID`` (:class:`DirectoryObjectIdMissing`, since such a row could
        never take a binding), a name or id a row already holds (:class:`UsernameTaken`), and the
        address rule above. :class:`~messagefoundry.auth.ldap.LdapError` propagates when the
        directory is unreachable.

        The row carries no roles. A directory account's roles come from the AD-group map at each
        sign-in, and no administrator route sets them. Audited as ``user.created`` with
        ``"provider": "ad"`` and where the address came from. The address is told the account was
        created (``ACCOUNT_CREATED``).
        """
        if self._ldap is None:
            raise DirectoryAccountRefused("no directory (AD) is configured ([auth].ad_enabled)")
        name = username.strip()
        if not name:
            raise DirectoryAccountRefused("a directory account name is required")
        principal = await asyncio.to_thread(self._ldap.resolve_principal, name)
        if principal is None:
            raise DirectoryAccountNotFound("the directory returned no enabled account by that name")
        if not principal.directory_object_id:
            raise DirectoryObjectIdMissing(
                f"{DIRECTORY_OBJECT_ID_MISSING}: the directory returned no readable objectGUID for"
                " this account, so an account created from it could never take a federated binding."
                " Make the directory return objectGUID to the service account, then retry"
            )
        if await self._store.get_user_by_username(principal.username) is not None:
            raise UsernameTaken(USERNAME_TAKEN)
        if (
            await self._store.get_user_by_directory_object_id(principal.directory_object_id)
            is not None
        ):
            # A row already mirrors this directory account under an older name (a rename its
            # holder has not signed in since). Its next sign-in or reconciler pass refreshes it.
            raise UsernameTaken("an account already mirrors that directory account")
        # The predicate the birth below applies, asked here so every refusal precedes the INSERT.
        directory_mail = (principal.email or "").strip()
        if directory_mail and _adopts_directory_mail(principal):
            if notify_email is not None:
                raise InvalidNotifyEmail(
                    "the directory supplies this account's notification address; omit notify_email"
                )
            typed: str | None = None
            address = directory_mail
        else:
            if notify_email is None or not notify_email.strip():
                raise InvalidNotifyEmail(
                    "the directory supplies no usable notification address for this account;"
                    " give one as notify_email, such as name@example.org"
                )
            typed = address = _require_single_mailbox(notify_email)
        try:
            user_id = await self._create_directory_row(
                principal, client=client, actor=actor, typed_notify_email=typed
            )
        except Exception as exc:
            if not _is_integrity_refusal(exc):
                raise
            # Re-read rather than assume the name index fired, as create_local_user does.
            if await self._store.get_user_by_username(principal.username) is None:
                raise
            raise UsernameTaken(USERNAME_TAKEN) from exc
        await self._audit(
            "user.created",
            actor=actor,
            detail=_json(
                {
                    "username": principal.username,
                    "roles": [],
                    "provider": "ad",
                    "notify_email_source": "directory" if typed is None else "administrator",
                }
            ),
            client=client,
        )
        await self._notify_security(
            ACCOUNT_CREATED, username=principal.username, email=address, detail={"roles": []}
        )
        return user_id

    # --- directory session reconciliation (ADR 0079 mechanism 2) --------------

    @property
    def directory_reconcile_enabled(self) -> bool:
        """Whether a reconciliation pass would do anything: the interval is set AND a directory is
        wired. Drives whether the API lifespan creates the loop at all — at
        ``ad_session_recheck_seconds = 0`` no task exists.

        **The default is 300, not 0.** This docstring said 0 and called that "the default"; the field
        has shipped at 300 since the reconciler was turned on by default, which
        ``test_reconciler_is_on_by_default`` pins. The distinction is load-bearing rather than
        cosmetic: reading it as off-by-default makes every defect in this loop sound like it needs an
        operator to opt in first, when in fact the loop runs on any instance that wires a directory.
        """
        return bool(self._settings.ad_session_recheck_seconds) and self._ldap is not None

    @property
    def directory_reconcile_alert(self) -> str | None:
        """The last mass-revoke circuit-breaker trip, or ``None``. Latches until a pass completes
        without tripping, so an operator who missed the log line still sees the standing condition."""
        return self._reconcile_alert

    @property
    def directory_reconcile_hold(self) -> str | None:
        """The engaged undetermined-wave hold's operator message, or ``None`` (ADR 0195). Latches
        while the hold is engaged, so an operator who missed the log line still sees it."""
        return self._reconcile_hold_alert

    async def _probe_principal(self, user: UserRecord) -> reconcile.Probe:
        """One directory probe, off the event loop (``ldap3`` is blocking).

        **THE KEY IS THE DIRECTORY LAYER'S CHOICE, NOT THIS METHOD'S (BACKLOG #1532).** Everything the
        row knows about its own identity is handed over -- the cached name and the immutable id -- and
        ``resolve_principal`` prefers the id when there is one. This method deliberately carries no
        branch: a per-caller key preference is exactly how the reconciler came to ask a different
        question from the login path in the first place.

        **What the name-keyed probe did to a renamed account, and why it is not a small defect.**
        BACKLOG #1471 made a directory login resolve by the immutable id, so a renamed person keeps
        signing in to their own row. This probe kept asking the directory about the name that row was
        created with -- a name the directory no longer answers to -- so it read ABSENT, which is the
        same answer a deleted or disabled account gives. After ``ad_session_recheck_strikes`` passes
        the sessions were revoked and the holder was emailed a security notice. They could sign back in
        immediately, which returned them to the candidate set, and the next pass revoked them again:
        at the shipped ``ad_session_recheck_seconds`` of 300 a deploying site would have seen roughly a
        ten-minute cycle with no end and no administrative escape, because nothing in the engine could
        write ``users.username``. The fix is to stop asking a question whose answer has stopped
        meaning what the caller reads it as.

        A row whose ``directory_object_id`` is NULL still probes by name. That is a **directory's**
        property rather than a choice here: one that returns no readable ``objectGUID`` leaves every
        row unbound, and the engine cannot key on an identifier it is never given. Such a site keeps
        the old behaviour, rename wart included; ``auth/ldap.py`` warns once per distinct shape so an
        operator can find out. **Except a row that carries a federated binding** (ADR 0184 AC-5,
        BACKLOG #2027): :meth:`reconcile_directory_sessions` never hands one here, and
        :meth:`_report_unkeyed_bindings` says why and what it costs.

        ``probe_principal`` is the password-free service-account lookup the Kerberos path uses, with
        the reason kept. It returns the group set, so the role re-diff below costs no extra round
        trip. It also says why an account did not resolve, which the sign-in paths never see: a
        search that matched nothing reads ABSENT, a set disabled bit DISABLED, and an unreadable
        ``userAccountControl`` UNDETERMINED (ADR 0195 rule items 1 and 2). An unreadable attribute
        must never come back as UNAVAILABLE, which never revokes; that would reopen BACKLOG #1639.
        """
        # Guarded by directory_reconcile_enabled, and by _directory_step_up_refusal (BACKLOG #2023).
        assert self._ldap is not None
        try:
            probe = await asyncio.to_thread(
                self._ldap.probe_principal, user.username, object_id=user.directory_object_id
            )
        except LdapError as exc:
            # FAIL OPEN, for the reconciler. verify_mfa reads the same UNAVAILABLE as a refusal and
            # fails closed, because it grants rather than revokes (BACKLOG #2023). It writes an audit
            # row per refusal, so it adds no log line here either.
            # An unreachable DC must never revoke: a fail-closed re-check would turn a
            # directory blip into a total console outage during exactly the incident when operators
            # need the console. Debug-level — a flapping DC must not flood the log at one line per
            # user per pass; the pass-level summary below reports the count at WARNING.
            _log.debug("directory probe failed for %s: %s", user.username, exc)
            return reconcile.Probe(user.id, user.username, reconcile.ProbeOutcome.UNAVAILABLE)
        principal = probe.principal
        if principal is None:
            return reconcile.Probe(user.id, user.username, _REFUSED_OUTCOMES[probe.answer])
        return reconcile.Probe(
            user.id,
            user.username,
            reconcile.ProbeOutcome.PRESENT,
            groups=principal.groups,
            # ONLY AN ID-KEYED PROBE MAY REPORT A RENAME. A rename is evidence of a rename only when
            # the question asked cannot be answered by a different principal, and the name-keyed
            # fallback's question can be: `_find_user` searches
            # `(|(sAMAccountName=<name>)(userPrincipalName=<name>@<domain>))` and takes entries[0], so
            # an account that sets its own UPN to the victim's `<name>@<domain>` matches the same
            # filter. On a pass where the directory returns that entry first, the probe would report
            # the attacker's `sAMAccountName` as this row's new name -- and the refresh would write it
            # onto the victim's row, moving the ONLY key an unbound login path has onto the attacker's
            # label. Their next sign-in then resolves to the victim's `user_id` (both ids are NULL, so
            # the BACKLOG #1471 conflict guard compares None to None and passes), taking the victim's
            # uploaded files, per-uploader quota and saved search presets with it.
            #
            # That is exactly the privilege transfer #1471 exists to close, arriving on the rows #1471
            # could not bind. The UPN ambiguity and the role re-diff that rides on it are older than
            # this item and unchanged; what #1532 must not do is make the wrong answer PERSISTENT.
            # `None` here leaves the residual no-objectGUID site on genuinely unchanged behaviour.
            directory_username=principal.username if user.directory_object_id is not None else None,
        )

    async def reconcile_directory_sessions(self) -> reconcile.ReconcilePlan:
        """Run one reconciliation pass and apply it; return what it did (for the loop + tests).

        Re-resolves every directory-backed principal that still holds a **live** session and revokes
        the sessions of accounts that have been disabled or deleted, so an AD disable takes effect
        within one interval instead of at the 12-hour absolute cap. Safe by construction:

        * a probe that could not reach the directory contributes nothing (fail-open);
        * a principal must come back absent, disabled or undetermined ``ad_session_recheck_strikes``
          passes running;
        * a PRESENT principal whose directory groups would change its roles, or withdraw or narrow
          its channel scope, is revoked on one pass, and the scope itself is left for the next login
          to write (ADR 0198);
        * a wave of undetermined answers is held, not revoked, and alerts (ADR 0195);
        * a pass that would revoke too many at once aborts wholesale and alerts.

        The pass is **planned in full before anything is written**, so an abort leaves the store
        byte-identical — including the role re-diff.
        """
        if not self.directory_reconcile_enabled:
            return reconcile.ReconcilePlan()
        settings = self._settings

        # Candidates: AD-provider users that are not already locally disabled AND still hold at least
        # one live session. Nobody signed in => zero binds. Derived from list_users + list_sessions
        # rather than a new store method, so this control needs no schema change on any backend.
        candidates: list[tuple[str, str]] = []
        users: dict[str, UserRecord] = {}
        unkeyed: list[UserRecord] = []
        still_unkeyed: set[str] = set()
        for user in await self._store.list_users():
            if user.auth_provider != AuthProvider.AD.value or user.disabled:
                continue
            is_unkeyed = _holds_unkeyed_federated_binding(user)
            if is_unkeyed:
                # Recorded BEFORE the session filter, so an account whose sessions lapse between
                # passes keeps its "already reported" mark and is not reported again on its next
                # sign-in.
                still_unkeyed.add(user.id)
            if not await self._store.list_sessions(user.id):
                continue
            if is_unkeyed:
                # BACKLOG #2027 (ADR 0184 AC-5): never probed by name. Filtered HERE rather than
                # answered as UNAVAILABLE by the probe, so it neither inflates the pass's
                # "directory unreachable" count nor, as a pass's only candidate, reads as an outage.
                unkeyed.append(user)
                continue
            candidates.append((user.id, user.username))
            users[user.id] = user
        reconcile.prune_ledger(self._reconcile_strikes, users, rank=float)
        reconcile.prune_ledger(self._reconcile_last_probed, users, rank=float)
        reconcile.prune_ledger(self._reconcile_outcomes, users, rank=reconcile.outcome_rank)
        if reconcile.ProbeOutcome.UNDETERMINED not in self._reconcile_outcomes.values():
            # u is 0: every held account has left the record, so the hysteresis has nothing to hold.
            self._reconcile_hold_latched = False
        if not candidates:
            # Nobody signed in: a no-op pass. A latched breaker alert is deliberately NOT cleared
            # here — this pass learned nothing about the directory, and clearing a standing alarm on
            # an absence of information would hide a misconfiguration that is still there.
            await self._report_unkeyed_bindings(unkeyed, still_unkeyed=still_unkeyed)
            return reconcile.ReconcilePlan()

        selected = reconcile.select_candidates(
            candidates,
            last_probed=self._reconcile_last_probed,
            budget=settings.ad_session_recheck_max_users,
        )
        now = time.monotonic()
        probes: list[reconcile.Probe] = []
        for user_id, _username in selected:
            probes.append(await self._probe_principal(users[user_id]))
            self._reconcile_last_probed[user_id] = now

        # Resolve the role sets for the role re-diff, and the scope inputs for the scope re-diff (ADR
        # 0198). Store reads only — no extra directory traffic.
        current_roles: dict[str, frozenset[str]] = {}
        target_roles: dict[str, frozenset[str]] = {}
        scopes: dict[str, channel_scope.ScopeInput] = {}
        for probe in probes:
            if probe.outcome is not reconcile.ProbeOutcome.PRESENT:
                continue
            current_roles[probe.user_id] = frozenset(
                await self._store.get_user_role_ids(probe.user_id)
            )
            target = frozenset(await self._store.roles_for_ad_groups(probe.groups))
            target_roles[probe.user_id] = target
            # RE-READ, after the probes, like the roles above. The row listed at the top of the
            # pass can be up to a whole pass of LDAP round trips old, and a login that landed in
            # that time has already written the new scope: judging the old one would revoke the
            # session that login just minted. A login landing after this read can still be revoked
            # once; the next pass reads the row it wrote and finds nothing to do.
            row = await self._store.get_user(probe.user_id)
            if row is None:
                continue  # deleted mid-pass: nothing to decide, and the role re-diff still runs
            # The TARGET roles decide the Administrator short-circuit, as they do at login, which
            # decides with the roles it is about to write.
            administrator = Role.ADMINISTRATOR.value in target
            scopes[probe.user_id] = channel_scope.ScopeInput(
                stored_scope=row.channel_scope,
                stored_source=row.channel_scope_source,
                mapped=(
                    frozenset()
                    if administrator
                    else frozenset(await self._store.channels_for_ad_groups(probe.groups))
                ),
                administrator=administrator,
            )

        plan = reconcile.plan_pass(
            probes,
            prior_strikes=self._reconcile_strikes,
            current_roles=current_roles,
            target_roles=target_roles,
            strike_threshold=settings.ad_session_recheck_strikes,
            max_absolute=settings.ad_session_revoke_max,
            max_fraction=settings.ad_session_revoke_max_fraction,
            prior_outcomes=self._reconcile_outcomes,
            latched=self._reconcile_hold_latched,
            scopes=scopes,
        )
        # Strike bookkeeping is process-local, not store state, so it is recorded even for an aborted
        # pass — that is what makes a standing misconfiguration trip the breaker on EVERY pass rather
        # than oscillating. Merge, never replace: an UNAVAILABLE probe is absent from plan.strikes,
        # so the user keeps whatever strike they already carried rather than having an outage clear it.
        # The outcome record merges the same way, for the same reason (ADR 0195 rule item 4).
        self._reconcile_strikes.update(plan.strikes)
        self._reconcile_outcomes.update(plan.outcomes)
        self._reconcile_hold_latched = plan.latched
        if plan.aborted is not None:
            await self._abort_reconcile_pass(plan)
            if not plan.directory_outage:
                # A held pass writes its own row even when the breaker also aborts it (ADR 0195 rule
                # item 9). An outage judged nothing, so it leaves the hold's message alone.
                await self._record_reconcile_hold(plan)
            await self._report_unkeyed_bindings(unkeyed, still_unkeyed=still_unkeyed)
            return plan

        self._reconcile_alert = None
        if plan.unavailable:
            _log.warning(
                "directory reconcile: %d of %d principals could not be resolved (directory "
                "unreachable) — those sessions were left alone (fail-open)",
                plan.unavailable,
                plan.probed,
            )
        applied: list[reconcile.SessionRevocation] = []
        for revocation in plan.revocations:
            if await self._apply_reconcile_revocation(revocation):
                applied.append(revocation)
        for refresh in plan.renames:
            # BACKLOG #1532. Applied only on a pass that was NOT aborted, with every other write the
            # plan carries: the reconciler's invariant is that an aborted pass leaves the store
            # byte-identical, and a rename is a store write like any other.
            #
            # AFTER the revocations, and the order is load-bearing. `_apply_reconcile_revocation`
            # audits with the name the PLAN captured and notifies with the name it RE-READS from the
            # row, so renaming first would put two different names on one account's records for one
            # pass -- reachable whenever an account is renamed and role-demoted in the same pass.
            # Both reads see the pre-rename name this way, and the rename still lands on this pass.
            await self._refresh_cached_username(
                user_id=refresh.user_id,
                old_username=refresh.old_username,
                new_username=refresh.new_username,
                held=await self._store.get_user_by_username(refresh.new_username),
            )
        # ADR 0195. After the revocations, so a held-row audit write that fails cannot stop a
        # genuine disable or demotion in the same pass from being applied.
        await self._record_reconcile_hold(plan)
        # BACKLOG #2027. Reported LAST, on every exit, so an audit write that keeps failing costs
        # only this report and never stops the probes and revocations above from running.
        await self._report_unkeyed_bindings(unkeyed, still_unkeyed=still_unkeyed)
        # What the pass DID, which is what the caller alerts on: a scope revocation skipped at apply
        # time (ADR 0198) was audited as nothing, so it must page as nothing too.
        return replace(plan, revocations=tuple(applied))

    async def _refresh_cached_username(
        self,
        *,
        user_id: str,
        old_username: str,
        new_username: str,
        held: UserRecord | None,
        client: str | None = None,
    ) -> None:
        """Copy a directory-reported rename down onto a row's cached ``username`` (BACKLOG #1532).

        **ONE implementation for two callers, deliberately.** The login path
        (:meth:`_upsert_ad_user`) and the ADR 0079 reconciler pass both reach a renamed account and
        both must resolve the collision case the same way. Two copies of this decision would be two
        policies, and the one that ran less often would be the one nobody noticed drifting.

        ``held`` is the row currently holding ``new_username``, read by the caller. Passed rather than
        re-read for the reason :meth:`_upsert_ad_user` gives about ``by_name``: it puts the dependency
        in the signature instead of only in prose, and here it also saves a query the login caller
        **provably** already has the answer to. ``_complete_ad_login`` reads that exact row before it
        calls down, and refuses outright when it exists with a different id -- so the login path
        reaches this method only with ``held=None``, and the collision branch below is reachable from
        the **reconciler alone**, which probes an account it has already identified and has no such
        guard.

        **THE CHECK-THEN-ACT RACE IS REAL AND IS ABSORBED BELOW, NOT PREVENTED BY THE STORE.** This
        docstring used to say the store's in-statement guard made "a row claiming the name between
        this check and that write a no-op rather than an integrity error". That is false: measured on
        live PostgreSQL 16, in the autocommit shape the store actually uses, **about 60% of contended
        pairs raise** (counts and caveats: ``store/postgres.py``). The store guard still earns its
        place -- it makes the SEQUENTIAL taken-name case a clean no-op, which is the common one, and
        it never lost a row or double-renamed across that whole run -- but it is not a concurrency
        control and must not be described as one.

        So this method absorbs the residual itself, by MRO name, exactly as the ADR 0068 section 4
        duplicate-label race and the BACKLOG #1256 federated-subject bind do. That matters more here
        than at either of those: the caller is a background reconciler pass, so an unabsorbed
        integrity error would take down the whole pass and with it every OTHER account's revocation in
        it -- turning a cosmetic label collision into a missed directory disable.

        On the SUCCESS path the account keeps its ``user_id``, its sessions, its roles and everything
        keyed to them, and only the label moves -- which is what makes this the end of the revocation
        cycle rather than a gentler version of it.

        **The conflict path is different and must not be read as the same outcome**: the row keeps its
        id and its current session, but its next sign-in is refused with ``directory_identity_conflict``
        until an operator removes the row holding the name. See the comment on that branch.
        """

        async def _refuse(held_by: str | None, detected: str) -> None:
            # A DIFFERENT ROW ALREADY HOLDS THE NAME. Two accounts cannot share one; refusing the
            # write is the only safe move, and it is audited rather than logged-and-forgotten because
            # an operator has to resolve it. The likely cause is a stale row for a departed operator
            # whose name the directory has now reissued -- BACKLOG #1471's recycle case, arriving
            # through a rename instead of through a fresh login.
            #
            # **THIS IS A PENDING LOCKOUT, NOT A COSMETIC DEFECT, AND THIS WARNING IS THE ONLY SIGNAL
            # AN OPERATOR GETS.** An earlier version of this comment said the person "keeps signing
            # in" and called a stale label "a display defect rather than a lockout". That is wrong,
            # and `tests/test_ad_directory_identity.py::test_a_login_renamed_onto_a_taken_name_is_
            # refused` -- added by this same item -- asserts the opposite.
            #
            # What actually happens: the row keeps its id, so the CURRENT session survives. But the
            # next sign-in reads `get_user_by_username(<the directory's new name>)`, finds the other
            # row, sees an id that disagrees, and returns `directory_identity_conflict`. So the person
            # is locked out from their next login, bounded only by `session_absolute_hours` (12h) on
            # the session they already hold, and the state never clears on its own -- the stale row
            # holds no live session, so the reconciler never probes it.
            #
            # Framing that as cosmetic in the one message an operator sees is the compensating-control-
            # on-a-false-premise shape section 11 forbids: it tells them not to act on the thing they
            # must act on. The remedy is theirs -- remove the stale row -- and it is BACKLOG #1471's
            # stated residual, unchanged here.
            #
            # ``detected`` separates the two ways one condition arrives -- the pre-check saw the
            # holder, or the write lost a race to it. The OUTCOME is deliberately identical, which is
            # the whole point of absorbing the race; the discriminator is recorded because an operator
            # reading a run of these wants to know whether they are looking at one stale row or at
            # concurrent writers, and those want different fixes.
            await self._audit(
                "auth.ad_username_refresh_conflict",
                actor=old_username,
                detail=_json(
                    {
                        "user_id": user_id,
                        "held_by_user_id": held_by,
                        "detected": detected,
                        "source": "directory",
                    }
                ),
                client=client,
            )
            _log.warning(
                "AD account %s was renamed in the directory but the new name is already held by "
                "another account (%s). The stored name is left as-is, and this account will be "
                "refused at its next sign-in (directory_identity_conflict) until the stale row is "
                "removed; the session it holds now survives only to the absolute cap (BACKLOG #1532)",
                old_username,
                detected,
            )

        if held is not None and held.id != user_id:
            await _refuse(held.id, "pre_check")
            return
        # BACKLOG #2017. The row as it stands, read before the write, because the caller's
        # ``old_username`` can be stale by now: the reconciler captured it when it planned, and a
        # directory sign-in may have renamed the row since. Two things follow from that read.
        #
        # A row that already carries the new name has nothing to change, so it gets no second audit
        # row and no second notice. The read-back below cannot tell that case apart, because the
        # store's guard excludes only OTHER rows and so the UPDATE matches this one. And the notice
        # names the name the row actually had, not the plan's.
        before = await self._store.get_user(user_id)
        if before is None:
            # Deleted between the plan and the apply. Refused as the read-back below refuses it, without
            # an UPDATE that can only match nothing.
            await _refuse(user_id, "row_gone")
            return
        if before.username == new_username:
            return
        try:
            await self._store.set_user_username(user_id, new_username)
        except Exception as exc:
            # THE RESIDUAL RACE, absorbed here because the store's in-statement guard cannot close it
            # (see this method's docstring and the measured note in `store/postgres.py`).
            #
            # MRO BY NAME, matching the BACKLOG #1256 federated-subject bind and the ADR 0068 section 4
            # duplicate-label race: each backend raises its own integrity class -- sqlite3
            # IntegrityError, asyncpg's UniqueViolationError, pyodbc's IntegrityError -- and naming
            # them here would make this module import-aware of every driver and silently stop covering
            # a backend added later. Anything that is NOT an integrity violation re-raises untouched,
            # so a genuine store fault still reaches the caller.
            #
            # THE TEST IS ON "Integrity", NOT ON "IntegrityError", AND THAT IS LOAD-BEARING. Measured
            # against the three real driver classes on this interpreter:
            #     asyncpg.UniqueViolationError  -> UniqueViolationError, IntegrityConstraintViolation-
            #                                      Error, PostgresError, ...   NO class named
            #                                      "IntegrityError" anywhere in the MRO
            #     pyodbc.IntegrityError         -> IntegrityError, DatabaseError, Error, ...
            #     sqlite3.IntegrityError        -> IntegrityError, DatabaseError, Error, ...
            # So tightening this to "IntegrityError" would cover the two backends that need it LEAST
            # and miss PostgreSQL -- the one where the race was measured firing 60% of contended pairs
            # (store/postgres.py). The "UniqueViolation" arm catches asyncpg a second way, which is
            # belt-and-braces rather than redundancy: either term alone covers it, both together mean
            # a rename of one asyncpg class cannot silently drop the backend.
            #
            # THIS APPLIES TO THE TWO SIBLING SITES TOO, and since BACKLOG #1143 there is one copy:
            # `_is_integrity_refusal`, which at least this site, the webauthn label race, the
            # federated bind and the local-account create (BACKLOG #1808) call. `__mro__` appears
            # once in the engine, inside it. Until #1143 it appeared three times, all in this
            # module, all in this substring form.
            #
            # THE COST OF A NAME TEST, NAMED ONCE: it matches on a string, so an unrelated class whose
            # name happens to contain "Integrity" would be swallowed here. The engine HAS one --
            # `messagefoundry.integrity.IntegrityError`, the startup attestation's fail-closed drift
            # error -- and this predicate does absorb it. It is NOT reachable today: its only raise
            # site is inside `run_startup_attestation`, which runs before any listener binds, and
            # neither `store/` nor `auth/` imports the module. Recorded because the day something
            # raises it from a store or auth path, every handler that calls this predicate could
            # silently report a conflict instead of a refused attestation -- a fail-closed control
            # absorbed by a fail-open one. If that class ever moves, test on identity here, not on a
            # name.
            if not _is_integrity_refusal(exc):
                raise
            # Re-read rather than guess who won: this is an error path, the cost is irrelevant, and an
            # audit row naming the holder is what makes the collision actionable.
            winner = await self._store.get_user_by_username(new_username)
            await _refuse(winner.id if winner is not None else None, "write_race")
            return
        # READ BACK BEFORE AUDITING SUCCESS. The guarded UPDATE can match zero rows and raise nothing
        # -- that is the whole point of the NOT EXISTS -- so an unconditional success audit would
        # report a rename that did not happen. Reachable two ways: the race where the losing side's
        # guard HOLDS (81 of 200 pairs on PostgreSQL, `store/postgres.py`) rather than raising, and a
        # row deleted between the plan and the apply.
        #
        # An audit trail that says a name moved when it did not is worse than a missing row: an
        # operator reconciling "who is this account" against the directory would take the engine's
        # word for a state neither side is in.
        written = await self._store.get_user(user_id)
        if written is None or written.username != new_username:
            await _refuse(
                None if written is not None else user_id,
                "write_noop" if written is not None else "row_gone",
            )
            return
        await self._audit(
            "auth.ad_username_refreshed",
            actor=new_username,
            detail=_json({"user_id": user_id, "source": "directory"}),
            client=client,
        )
        # BACKLOG #2017, ASVS 6.3.7: a username change is an update to the account's authentication
        # details, so the holder is told out of band as well as audited. THIS IS THE ONE PLACE THE
        # RULE FOR WHEN IT IS SENT LIVES: only here, after the pre-read showed a different name and
        # the read-back proved the new one landed. Every refused path above returns first, so a lost
        # race sends none, and so does a rename another caller already applied.
        #
        # **IN SEQUENCE ONLY.** The pre-read and the write are not one statement. Two refreshes of the
        # SAME row running at once, a sign-in and a reconciler pass, can both read the old name, both
        # write and both read back the new one, so both audit and both notify. The second notice is
        # a duplicate, not a false one: the name did change. Closing it needs a compare-and-set in
        # ``set_user_username`` on every store backend, which this item did not take on.
        #
        # Both callers send it. The reconciler notifies its revocations too, so it has no rule that
        # holds notices back. Addressed to the engine-owned ``notify_email`` of the row just read, as
        # the reconciler's own notices are; a rename moves no address, so no old holder needs the
        # fallback the directory email repoint in ``_upsert_ad_user`` carries.
        await self._notify_security(
            USERNAME_CHANGED,
            username=new_username,
            email=written.notify_email,
            client=client,
            detail={
                "old_username": before.username,
                "new_username": new_username,
                "source": "directory",
            },
        )

    async def _report_unkeyed_bindings(
        self, unkeyed: Sequence[UserRecord], *, still_unkeyed: set[str]
    ) -> None:
        """Log and audit, once per account per process, each bound id-less row a pass skipped
        (BACKLOG #2027). ``still_unkeyed`` is every such row, signed in or not; a mark is dropped
        only when its row stops being one (unbound, disabled or removed).

        **Its own audit action, ``auth.ad_reconcile_binding_unkeyed``, not the outage row.**
        ``auth.ad_reconcile_skipped`` means the directory was unreachable and the accounts are fine.
        This row means one account's directory disable will not be enforced, which is the opposite
        reading, so a rule filing the outage row as benign must not also file this one.

        **THE SKIP HAS A COST, AND THIS IS WHERE IT IS MADE VISIBLE.** ADR 0184 AC-5 forbids a name
        probe of a bound row, and this row has no other key, so a directory disable or demotion no
        longer ends its sessions within one interval; they end at their own expiry. That follows the pass's
        convention for an account it cannot ask about, the fail-open UNAVAILABLE arm, rather than
        revoking: revoking on every pass would sign a Windows SSO holder out each interval with no
        end. The remedy is the audited admin unbind. The row is then an ordinary id-less account,
        probed by name as any such row on that directory is.

        The row is left bound on purpose. Clearing a binding is an administrator's audited act,
        and this loop has no administrator behind it.
        """
        self._reconcile_unkeyed_reported &= still_unkeyed
        for user in unkeyed:
            if user.id in self._reconcile_unkeyed_reported:
                continue
            _log.warning(
                "directory reconcile: %s carries a federated binding but no directory object id, "
                "so it is not probed by name and a directory disable will not end its sessions "
                "before they expire. Unbind it (DELETE /users/%s/federated-identity) to return it "
                "to the reconciler.",
                user.username,
                user.id,
            )
            await self._audit(
                "auth.ad_reconcile_binding_unkeyed",
                actor="<reconciler>",
                detail=_json(
                    {
                        "reason": DIRECTORY_OBJECT_ID_MISSING,
                        "user_id": user.id,
                        "username": user.username,
                    }
                ),
            )
            # Marked only once the audit row is written, so a failed write is retried next pass.
            self._reconcile_unkeyed_reported.add(user.id)

    async def _record_reconcile_hold(self, plan: reconcile.ReconcilePlan) -> None:
        """Latch, log and audit an engaged undetermined-wave hold, or release a latched one.

        ADR 0195 rule item 9. **Its own audit action, ``auth.ad_reconcile_held``, and its own alert
        type**, apart from the breaker's ``auth.ad_reconcile_aborted``. A held pass is not an aborted
        one: the rest of the estate was reconciled, so the pass clears the breaker's latch, and a
        shared latch would clear the hold's message while the hold still stood. Neither the row nor
        the message carries the breaker's revocation ceiling, which means nothing for a hold.

        Written once per pass that holds, like the breaker's row, so the audit log shows how long it
        lasted. The counts are all it carries: the held accounts' own sign-ins are refused and
        audited on their own rows. The message is latched before the row is written, so a failing
        audit write still leaves the operator-visible condition set.
        """
        if not plan.hold:
            if self._reconcile_hold_alert is not None:
                self._reconcile_hold_alert = None
                _log.warning(
                    "directory reconcile: the undetermined userAccountControl hold is RELEASED "
                    "(%d signed-in account(s) still read undetermined and are struck as usual)",
                    plan.undetermined,
                )
            return
        self._reconcile_hold_alert = (
            f"undetermined userAccountControl hold ENGAGED: {plan.undetermined} signed-in directory "
            f"account(s) returned no readable userAccountControl, so their sessions are held and "
            f"not revoked. Sign-in stays refused for them. Check that the [auth].ad_bind_dn service "
            f"account can read userAccountControl on every account in [auth].ad_user_search_base."
        )
        _log.error("directory reconcile: %s", self._reconcile_hold_alert)
        await self._audit(
            "auth.ad_reconcile_held",
            actor="<reconciler>",
            detail=_json(
                {
                    "reason": reconcile.HOLD_REASON,
                    "undetermined": plan.undetermined,
                    "held": len(plan.held),
                    "readable": plan.readable,
                    "probed": plan.probed,
                }
            ),
        )

    async def _abort_reconcile_pass(self, plan: reconcile.ReconcilePlan) -> None:
        """Record an aborted pass. Applies NOTHING — the point of the abort."""
        if plan.directory_outage:
            # Not a breaker trip: the accounts are fine, the directory is not. Loud but not latched.
            _log.warning(
                "directory reconcile: ALL %d probes failed — the directory is unreachable. No "
                "session was revoked (fail-open).",
                plan.probed,
            )
            await self._audit(
                "auth.ad_reconcile_skipped",
                actor="<reconciler>",
                detail=_json({"reason": plan.aborted, "probed": plan.probed}),
            )
            return
        # Held probes were left out of the breaker's denominator (ADR 0195 rule item 7), so the
        # ceiling it quotes is taken over the same count. `probed` keeps its meaning in the row.
        ceiling = reconcile.breaker_ceiling(
            probed=plan.judged,
            max_absolute=self._settings.ad_session_revoke_max,
            max_fraction=self._settings.ad_session_revoke_max_fraction,
        )
        self._reconcile_alert = (
            f"mass-revoke circuit breaker TRIPPED: a directory reconciliation pass would have "
            f"revoked more than {ceiling} of the {plan.judged} signed-in directory principals it "
            f"judged ({len(plan.held)} held account(s) left out). No "
            f"session was revoked. Check [auth].ad_user_search_base, the OU layout, and the "
            f"ad_bind_dn service account's read rights."
        )
        _log.error("directory reconcile: %s", self._reconcile_alert)
        await self._audit(
            "auth.ad_reconcile_aborted",
            actor="<reconciler>",
            detail=_json(
                {
                    "reason": plan.aborted,
                    "probed": plan.probed,
                    "judged": plan.judged,
                    "ceiling": ceiling,
                }
            ),
        )

    async def _apply_reconcile_revocation(self, revocation: reconcile.SessionRevocation) -> bool:
        """Apply one planned revocation: persist a role re-diff (when that is why), drop the user's
        live sessions, audit, and notify the affected user out-of-band (ASVS 6.3.7). A scope
        revocation writes no scope (ADR 0198): the next login does. Returns whether it applied."""
        user = await self._store.get_user(revocation.user_id)
        if revocation.reason == reconcile.SCOPE_CHANGED and (
            user is None or user.channel_scope != revocation.scope_from
        ):
            # The stored scope moved after the pass read it. Earlier revocations in this pass await
            # audit writes and notices, so a login can land in between, write the new scope and
            # mint a fresh session; revoking now would sign that user straight back out. The next
            # pass decides again from what is stored. A role revocation is not skipped: its role
            # delta stands whatever happened to the scope.
            _log.debug(
                "directory reconcile: scope revocation for %s skipped; the stored scope changed",
                revocation.username,
            )
            return False
        if revocation.role_ids is not None:
            await self._store.set_user_roles(
                revocation.user_id, list(revocation.role_ids), assigned_by="ad-reconcile"
            )
        revoked = await self._store.revoke_user_sessions(revocation.user_id)
        await self._audit(
            "auth.ad_session_revoked",
            actor=revocation.username,
            detail=_json(
                {
                    "reason": revocation.reason,
                    "sessions": revoked,
                    **(
                        {"roles": list(revocation.role_ids)}
                        if revocation.role_ids is not None
                        else {}
                    ),
                    # ADR 0198. Only on a scope delta, so every other row keeps its exact stored
                    # string (``_json`` sorts keys; a new key is a new row). The reconciler writes no
                    # scope, so this row is the only record of what the directory took away until
                    # the next login writes it.
                    **(
                        {
                            "scope_changed": True,
                            "scope_from": revocation.scope_from,
                            "scope_to": revocation.scope_to,
                        }
                        if revocation.scope_changed
                        else {}
                    ),
                }
            ),
        )
        _log.info(
            "directory reconcile: revoked %d session(s) for %s (%s)",
            revoked,
            revocation.username,
            revocation.reason,
        )
        # A directory-pushed disable or demotion is the same event to the user as a local one, so it
        # gets the same out-of-band notice the login-path re-sync sends (best-effort).
        #
        # A scope-only revocation sends none (ADR 0198). The account is not disabled, so
        # ``account_disabled`` would be a false statement in a security notice, and the login-path
        # scope re-sync this mirrors sends no notice either. The audit row and the
        # ``ad_session_revoked`` alert record it.
        if user is not None and revocation.reason != reconcile.SCOPE_CHANGED:
            await self._notify_security(
                ACCOUNT_DISABLED if revocation.role_ids is None else ROLES_CHANGED,
                username=user.username,
                email=user.notify_email,
                detail={"reason": revocation.reason},
            )
        return True

    # --- sessions ------------------------------------------------------------

    async def _issue_session(
        self,
        user_id: str,
        client: str | None,
        *,
        mfa_verified: bool,
        seed_reauth: bool,
        mechanism: SessionMechanism,
        max_expires_at: float | None = None,
        require_federated_subject: tuple[str, str] | None = None,
        supersedes_hash: str | None = None,
    ) -> str:
        """Mint a session token and persist the row. Callers passing
        ``require_federated_subject`` must handle :class:`_FederatedBindingWithdrawn`.

        ``supersedes_hash`` names the session this sign-in REPLACES in the caller's browser (ASVS
        7.2.4, login side). It is ended after the new
        row is safely written and BEFORE the per-user cap runs. That order is the point: ending it
        after the cap would let the cap evict another device's oldest session to make room for a
        session that was about to go anyway.
        """
        token = mint_token()
        token_hash = hash_token(token)
        expires_at = time.time() + self._settings.session_absolute_hours * 3600
        if max_expires_at is not None:
            # ADR 0079 mechanism 1 / ADR 0142 AC-6: an externally-asserted deadline (today only the
            # signature-verified federated `id_token.exp`) caps the local absolute lifetime, never
            # extends it. Local and AD/Kerberos callers pass nothing and are byte-identical.
            expires_at = min(expires_at, max_expires_at)
        issued = await self._store.create_session(
            token_hash=token_hash,
            user_id=user_id,
            expires_at=expires_at,
            client=client,
            # REQUIRED, with no default (BACKLOG #1144 step 5): every caller states whether this login
            # opens the step-up window. It used to fall back to `mfa_verified`, so a new caller that
            # named nothing seeded whenever it granted the factor -- the federated case among them.
            # The local leg seeds only a fully-authenticated session: an MFA-pending one gets no
            # step-up freshness, so a stolen pre-MFA token can't ride login's freshness to bind an
            # attacker-controlled authenticator (WP-14). Every directory login passes False, because
            # its proof is AMBIENT (ADR 0068 s9). See _login_local and _complete_ad_login.
            seed_reauth=seed_reauth,
            # BACKLOG #1474: on the federated leg the INSERT is conditional on the account still
            # carrying this verified pair, checked in the store's own transaction. See
            # ``Store.create_session`` for why the check cannot live out here.
            require_federated_subject=require_federated_subject,
            # ADR 0184 item (iv): REQUIRED, with no default, so a new mint path cannot forget it. The
            # step-up leg reads it (ADR 0142 Amendment B), and rotation carries it forward.
            auth_mechanism=mechanism.value,
        )
        if not issued:
            # Only reachable with a guard requested: an unbind revoked this account's sessions while
            # this login was in flight, so issuing now would hand back a token the revocation could
            # never have seen. Nothing was written, so there is nothing to undo.
            raise _FederatedBindingWithdrawn()
        if mfa_verified:
            # No second factor pending (MFA is not required for this user, or the federated IdP
            # asserted one): mark the session's 2nd factor satisfied at issuance so the step-up gate
            # never blocks it. An MFA-required login leaves it NULL until POST /auth/mfa-verify
            # (WP-14) -- including the Kerberos leg, which asserts nothing and mints at the minimum.
            await self._store.mark_session_mfa_verified(token_hash)
        if supersedes_hash is not None:
            await self._supersede_session_hash(supersedes_hash, client=client)
        await self._enforce_session_cap(user_id)
        return token

    async def _enforce_session_cap(self, user_id: str) -> None:
        """Apply ``[auth].max_sessions_per_user`` to one user (AUTH-SESS-CAP).

        Runs after a sign-in mints a row, and again after a ceremony in ``_FACTOR_CEREMONIES``
        stamps a session's second factor, because that moves the row into the group of full
        sessions (BACKLOG #2076). A re-proof ceremony does not run it.

        Keeps the newest ``cap`` LIVE sessions and revokes the lapsed ones. A row ranks from its
        latest second-factor stamp, or from its creation when it has none. A just-created or
        just-stamped row survives: it is the newest in its group, or, if the clock stepped back
        since it was stamped, it is ahead of the cap's ``now`` and left alone. The idle timeout is
        the one ``identity_for_token`` validates against, so a row it would refuse never costs a
        live device its place (BACKLOG #1900).

        When an unstamped session of this user still owes a second factor, the store ranks those
        rows apart from the full sessions, so a caller holding only the password cannot evict a
        fully signed-in device by signing in over and over (BACKLOG #2076). A pending sign-in gets
        no shorter life: a user who must enrol a factor does it on that session.

        The price is a bound of twice the cap. If the user later stops owing a factor (MFA turned
        off, the last factor removed, a role change under the administrators scope), the pending
        rows count as full ones until the next cap run, which then keeps the newest ``cap``.
        """
        cap = self._settings.max_sessions_per_user
        if not cap or cap <= 0:
            return
        user = await self._store.get_user(user_id)
        # A user row that has gone owes nothing more; splitting is then the closed choice, since it
        # can only protect full sessions.
        split = True if user is None else await self._unverified_session_owes_factor(user)
        await self._store.enforce_session_cap(
            user_id,
            keep=cap,
            idle_seconds=self.session_idle_seconds,
            split_mfa_pending=split,
        )

    @property
    def session_idle_seconds(self) -> float:
        """The idle timeout every liveness check validates against, in seconds (AUTH-IDLE). One
        conversion, so no caller can pass minutes where seconds are meant (BACKLOG #2096). The
        API lifespan's session reaper reads it too, so it purges by the validator's own number."""
        return float(self._settings.session_idle_timeout_minutes * 60)

    def _rekey_token_state(self, old_hash: str, new_hash: str) -> None:
        """Move every PROCESS-LOCAL entry keyed on a session's token hash onto the new hash.

        The store row is re-keyed atomically by ``rotate_session``; these in-memory maps are not,
        and each strands differently if missed — so the set is enumerated here rather than
        handled at each call site:

        * ``_action_step_up_grants`` — a single-use ADR 0077 grant. Stranded ⇒ the ceremony the user
          just completed silently no-ops and the next route demands another step-up.
        * ``_webauthn_challenges`` — a live ceremony. Stranded ⇒ a passkey registration/assertion
          started before the rotation can never be finished, which is a dead end, not a retry.
        * ``_new_ip_seen`` — the WP-L3-13 dedupe. Stranded ⇒ a *second* new-IP step-up + audit row
          for an address the session already re-verified from.
        * ``_reproof_session_failures`` — the BACKLOG #1138 per-session re-proof budget. Stranded,
          any rotation would hand the session a fresh budget of guesses.

        Deadlines and values are carried, never refreshed: a rotation must not extend anything.
        """
        for (h, action), deadline in list(self._action_step_up_grants.items()):
            if h == old_hash:
                del self._action_step_up_grants[(h, action)]
                self._action_step_up_grants[(new_hash, action)] = deadline
        self._webauthn_challenges.rekey(old_hash, new_hash)
        seen = self._new_ip_seen.pop(old_hash, None)
        if seen is not None:
            self._new_ip_seen[new_hash] = seen
        failures = self._reproof_session_failures.pop(old_hash, None)
        if failures is not None:
            self._reproof_session_failures[new_hash] = failures

    async def _rotate_session_token(self, token: str) -> str | None:
        """Re-key the caller's session to a FRESH token (ASVS 7.2.4); returns the new token.

        Returns ``None`` when the row could not be re-keyed — revoked or gone underneath us — so
        every caller fails CLOSED rather than handing back a token that authenticates nothing.

        **Ordering is the whole control** (see each call site): every store stamp for this elevation
        must already have been written against the OLD hash before this runs, because the re-key
        carries those columns forward, and every session UPDATE except ``revoke_session`` and
        ``rotate_session`` is rowcount-blind — a stamp issued *after* the rotation silently writes
        nothing. Any purpose-bound grant must be minted AFTER, against the NEW hash.
        """
        return await self._rotate_session_hash(hash_token(token))

    async def _rotate_session_hash(self, old_hash: str) -> str | None:
        """:meth:`_rotate_session_token` keyed on the session's HASH, for the one ceremony that holds
        no token: the federated step-up callback, which the SameSite=Strict cookie never reaches
        (BACKLOG #296). Same contract, same lock, same re-key."""
        session = await self._store.get_session(old_hash)
        if session is None:
            return None
        # Under the account's re-proof lock (BACKLOG #1138), so no rotation lands while a password
        # re-proof on this session is mid-verify. Otherwise the re-proof would charge its failure to
        # the hash the rotation just retired, and the live session would never count it.
        async with self._account_reproof_lock(session.user_id):
            new_token = mint_token()
            if not await self._store.rotate_session(old_hash, new_token_hash=hash_token(new_token)):
                return None
            self._rekey_token_state(old_hash, hash_token(new_token))
            return new_token

    async def _elevated(
        self,
        token: str,
        *,
        ceremony: str,
        actor: str | None,
        client: str | None = None,
        recovery_codes: tuple[str, ...] = (),
    ) -> Elevation:
        """Rotate the caller's session and package the :class:`Elevation` (ASVS 7.2.4).

        **The single place the five elevation sites rotate.** The ordering invariant that makes
        rotation safe (see :meth:`_rotate_session_token`) is subtle and silent when broken, so it is
        enforced by having exactly one caller of the primitive rather than nine route handlers each
        getting it right. Every store stamp for the elevation must ALREADY be written against the
        old hash when this runs; anything purpose-bound is minted after, against the new hash.

        A ``None`` rotate means the session was revoked or expired underneath a ceremony that
        otherwise succeeded, so this fails CLOSED -- ``ok=False`` with no token, flagged
        ``session_lost`` so the route can say "sign in again" rather than "wrong password".

        Both outcomes are audited. The in-place re-key would otherwise leave no store trace at all:
        a session's token changing is exactly the event an operator reconstructing a timeline needs,
        and the fail-closed branch is the more interesting of the two (a good proof landing on a
        session that just vanished).

        **A rotation drops any open ``/ws/stats`` socket, and that is accepted.** The socket
        authenticates once at handshake and its keepalive re-validates the token CAPTURED there, so
        on a first deployment a rotation would make that captured token stop resolving and the server
        would close the socket at the next revalidation tick -- indistinguishable from a revoke,
        which is the fail-closed direction and the right one. ``app.js`` wires ``ws.onclose`` to
        resume the 5-second HTTP poll and to re-open the socket a bounded number of times, and the
        new handshake carries the NEW cookie, so the live push survives the rotation. That is a
        client reconnect, never a server-side grace window for the old token.
        """
        return await self._elevated_hash(
            hash_token(token),
            ceremony=ceremony,
            actor=actor,
            client=client,
            recovery_codes=recovery_codes,
        )

    async def _elevated_hash(
        self,
        token_hash: str,
        *,
        ceremony: str,
        actor: str | None,
        client: str | None = None,
        recovery_codes: tuple[str, ...] = (),
    ) -> Elevation:
        """The body of :meth:`_elevated`, keyed on the session's hash. Its one direct caller besides
        :meth:`_elevated` is the federated step-up callback, which holds the hash it staged at the
        start leg and never the token (BACKLOG #296). The ordering rule is :meth:`_elevated`'s."""
        rotated = await self._rotate_session_hash(token_hash)
        if rotated is None:
            await self._audit(
                "auth.session_rotation_failed",
                actor=actor,
                detail=_json({"ceremony": ceremony, "reason": "session_gone"}),
                client=client,
            )
            return Elevation(session_lost=True)
        await self._audit(
            "auth.session_rotated",
            actor=actor,
            detail=_json({"ceremony": ceremony}),
            client=client,
        )
        if ceremony in _FACTOR_CEREMONIES:
            # The session just joined the full ones, so the cap runs again (BACKLOG #2076). With
            # `cap` full sessions already live, the oldest of those goes, never the one just
            # completed: its fresh stamp ranks it newest.
            await self._enforce_session_cap_after_elevation(rotated)
        return Elevation(token=rotated, recovery_codes=recovery_codes)

    async def _enforce_session_cap_after_elevation(self, token: str) -> None:
        """Run the cap for the owner of a session that has ALREADY been rotated.

        A failure here is logged, never raised. The old token is gone by now, and the ceremony has
        committed its own writes (an enabled factor, stored recovery codes, a consumed code), so an
        exception would strand the user with neither token and lose recovery codes they never saw.
        Skipping one cap run costs at most one session over the cap until the next sign-in runs it.
        """
        try:
            session = await self._store.get_session(hash_token(token))
            if session is not None:
                await self._enforce_session_cap(session.user_id)
        except Exception:
            _log.exception("session cap after a completed second factor failed; skipped this run")

    async def identity_for_token(
        self, token: str | None, *, activity: bool = True
    ) -> Identity | None:
        """Validate a bearer token (existence, revocation, clock, absolute + idle timeout) and
        resolve the caller's :class:`Identity`.

        ``activity=True`` (the default, for user-driven requests) refreshes the session's idle
        clock; pass ``activity=False`` for background re-checks (e.g. a long-lived WebSocket) so a
        passively-polled token still ages out against real user activity (AUTH-IDLE).
        """
        if not token:
            return None
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return None
        now = time.time()
        # Revoke on any of: a backward wall-clock step (NTP step-back, VM snapshot revert), where a
        # session stamped in the "future" can't be aged correctly, so it fails closed rather than
        # silently reviving an already-expired one or resetting its idle window (AUTH-CLOCK); the
        # absolute expiry; the idle timeout. One helper, shared with the session cap's SQL
        # (BACKLOG #2096).
        if not session.is_live(now=now, idle_seconds=self.session_idle_seconds):
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if activity:
            await self._store.touch_session(session.token_hash, now=now)
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled:
            return None
        return await self._build_identity(user)

    async def identity_for_cert_user_id(self, user_id: str) -> Identity | None:
        """Resolve the users-row id a verified client cert maps to, or ``None`` when that account is
        unknown or disabled — WITHOUT a bearer session (BACKLOG #2238, ADR 0083).

        The mTLS map targets the row id, not the username, because a username can be released by a
        rename and taken by another row: a map keyed by name would then hand the cert to that other
        account. The id never moves. This replaced ``identity_for_username``, which resolved the old
        name-keyed map. A disabled account grants no identity (fail-closed), exactly as the token path
        treats it (:meth:`identity_for_token`); unlike :meth:`identity_for_user_id`, which the
        permission inspector uses and which resolves a disabled account on purpose.

        No directory check, the same as the name-keyed path before it: the engine row's ``disabled``
        flag is the one this path has always read. Asking the directory per request is a separate
        control change, not this key change."""
        user = await self._store.get_user(user_id)
        if user is None or user.disabled:
            return None
        return await self._build_identity(user)

    async def identity_for_user_id(self, user_id: str) -> Identity | None:
        """Resolve a user id directly to its :class:`Identity` (roles + custom-role overlay), or
        ``None`` when no such user exists — WITHOUT a bearer session.

        Used by the effective-permission inspector (BACKLOG #177): an admin resolves the FLATTENED
        effective permission set (built-in-role ∪ custom-role ∪ extras) for an arbitrary user via the
        same :meth:`Identity.build` path :meth:`identity_for_token` uses for the caller. Unlike the
        token / username auth paths, a *disabled* user still resolves here — the point is to inspect a
        user's grants for troubleshooting (including a locked-out account), not to authenticate them."""
        user = await self._store.get_user(user_id)
        if user is None:
            return None
        return await self._build_identity(user)

    async def logout(self, token: str | None, *, actor: str | None = None) -> None:
        if token:
            await self._store.revoke_session(hash_token(token))
            # Emit the documented auth.logout event (SECURITY.md, ASVS 16.3.3) — previously the
            # session was revoked silently, contradicting the doc and leaving a gap in the trail.
            await self._audit("auth.logout", actor=actor)

    async def _supersede_session_hash(self, prior_hash: str, *, client: str | None) -> bool:
        """End the session a browser presented at a fresh sign-in (ASVS 7.2.4, login side).

        A console sign-in answers with a ``Set-Cookie`` that REPLACES the browser's session cookie, so
        the server itself strands the prior session: this browser can never present it again, yet it
        stays valid until idle or absolute expiry. The verb asks for the current token to be
        terminated, and overwriting a cookie terminates nothing server-side.

        Reached only from :meth:`_issue_session`, so only after a credential proof succeeded. It ends
        exactly the one presented session and never the user's others: a whole-user revoke would
        turn every sign-in into a forced sign-out of every other device.

        The prior session may belong to a different user, for example on a shared workstation. It is
        still ended. Anyone holding that token could already end it with ``POST /auth/logout``, so
        this grants no new power. The audit row's actor is the session's OWNER, not whoever signed
        in: ``/me/security-events`` selects rows by actor, so the event belongs in the feed of the
        user whose session ended, and must not put that user's ids in anyone else's.

        An unrevoked row is ALWAYS revoked, even one already over by expiry or idle: ending the
        presented token is the whole point, whatever its state. (The per-user cap no longer relies on
        this. Since BACKLOG #1900 it counts only live rows and revokes lapsed ones itself.) Only a
        session that was still LIVE gets an audit row, so the trail does
        not record the ending of something that had already ended. ``revoke_session`` reports no
        rowcount, so the row is read back: a rotation that re-keyed it between the read and the
        revoke leaves the old hash absent, and then no row claims a revoke that never happened.
        Returns True when it audited.
        """
        prior = await self._store.get_session(prior_hash)
        if prior is None or prior.revoked_at is not None:
            return False
        now = time.time()
        # The validator's own test, clock-step checks included (BACKLOG #2096): a row stamped ahead
        # of `now` is one the validator would refuse, so ending it is not the end of a live session.
        was_live = prior.is_live(now=now, idle_seconds=self.session_idle_seconds)
        await self._store.revoke_session(prior_hash, now=now)
        if not was_live:
            return False
        after = await self._store.get_session(prior_hash)
        if after is None or after.revoked_at is None:
            return False
        owner = await self._store.get_user(prior.user_id)
        await self._audit(
            "auth.session_revoked",
            actor=owner.username if owner is not None else None,
            detail=_json({"scope": "superseded", "session": prior_hash[:12]}),
            client=client,
        )
        return True

    # --- session inventory + targeted revoke (WP-10, ASVS 7.5.2/7.4.5) -------

    async def list_sessions(self, user_id: str) -> list[SessionRecord]:
        """A user's active sessions — the self-service session inventory. Idle-expired rows are
        hidden too, since the validator refuses them on presentation (BACKLOG #2096)."""
        return await self._store.list_sessions(user_id, idle_seconds=self.session_idle_seconds)

    async def revoke_own_session(self, identity: Identity, session_id: str, *, actor: str) -> bool:
        """Revoke one of ``identity``'s **own** sessions by id (its ``token_hash``). Returns ``False``
        if the session doesn't exist or isn't the caller's — so the API answers 404 without revealing
        or letting a user touch another's session. Audited."""
        session = await self._store.get_session(session_id)
        if session is None or session.user_id != identity.user_id:
            return False
        await self._store.revoke_session(session_id)
        await self._audit(
            "auth.session_revoked",
            actor=actor,
            detail=_json({"scope": "self", "session": session_id[:12]}),
        )
        return True

    async def revoke_other_sessions(
        self, identity: Identity, current_token_hash: str, *, actor: str
    ) -> int:
        """Revoke all of ``identity``'s sessions **except** the caller's current one ("sign out
        everywhere else"). Returns the count revoked. Audited when any were revoked."""
        revoked = await self._store.revoke_user_sessions(
            identity.user_id, except_token_hash=current_token_hash
        )
        if revoked:
            await self._audit(
                "auth.session_revoked",
                actor=actor,
                detail=_json({"scope": "self_others", "count": revoked}),
            )
        return revoked

    async def revoke_sessions_for_user(self, user_id: str, *, actor: str) -> int:
        """Admin: revoke **all** of a user's sessions (force sign-out everywhere). Returns the count.
        Audited."""
        revoked = await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "auth.session_revoked",
            actor=actor,
            detail=_json({"scope": "admin", "user_id": user_id, "count": revoked}),
        )
        return revoked

    async def _custom_permissions_for_ids(self, role_ids: Iterable[str]) -> frozenset[Permission]:
        """Resolve the permission overlay for any custom (``custom:``-prefixed) role ids the user holds
        (ADR 0045 D3). Each is looked up in the ``roles`` table and its persisted ``permissions`` JSON
        defensively decoded (unknown/forbidden values dropped — deny-by-default). A built-in id, an
        unknown id, or a row with no permissions contributes nothing."""
        granted: set[Permission] = set()
        for rid in role_ids:
            if not is_custom_role_id(rid):
                continue
            row = await self._store.get_role(rid)
            if row is None:
                continue  # custom role deleted since assignment → grants nothing (deny-by-default)
            granted |= decode_custom_role_permissions(row["permissions"])
        return frozenset(granted)

    async def _build_identity(self, user: UserRecord) -> Identity:
        role_ids = await self._store.get_user_role_ids(user.id)
        roles = _roles_from_ids(role_ids)
        custom_permissions = await self._custom_permissions_for_ids(role_ids)
        provider = (
            AuthProvider(user.auth_provider)
            if user.auth_provider in (AuthProvider.LOCAL.value, AuthProvider.AD.value)
            else AuthProvider.LOCAL
        )
        return Identity.build(
            user_id=user.id,
            username=user.username,
            auth_provider=provider,
            roles=roles,
            must_change_password=user.must_change_password,
            must_set_notify_email=self.notify_email_required(user),
            allowed_channels=_allowed_channels(user, roles),
            extra_permissions=custom_permissions,
        )

    def notify_email_required(self, user: UserRecord) -> bool:
        """Whether ``user`` is confined to setting a notification address before anything else.

        BACKLOG #1139 (ASVS 6.3.7). An account with no ``notify_email`` is told nothing out of band
        about a change to its authentication details, because the notifier drops a notice with no
        address. At least three paths give birth to such an account: ``create_local_user`` with no
        email, ``provision-admin`` with no ``--email``, and a directory sign-in whose directory returns
        no ``mail``. (A fourth, the first-run bootstrap administrator, was retired by ADR 0183.) So the
        first sign-in sets one, in the shape of the ``must_change_password`` confinement.

        **ONLY WHEN A SECURITY-NOTICE CHANNEL IS WIRED**, which is ``[auth].notify_security_events``
        on and an ``[alerts]`` SMTP relay configured. Without one, no account is notified whatever it
        holds, so confining it would lock out a site with no mail server and buy nothing. A PHI
        instance under ``enforce`` already refuses to start without that channel (ADR 0167).

        Derived on every resolve rather than stored, so it ends the moment an address lands, and
        no store backend carries a flag for it.
        """
        return self._security_notifier is not None and not (user.notify_email or "").strip()

    @staticmethod
    def suggested_notify_email(profile_email: str | None) -> str | None:
        """The profile ``email`` to offer on the console's address form, or ``None``.

        BACKLOG #1139. Stripped, and only when it passes the shape check
        :meth:`fill_own_notify_email` applies, so the form never offers a value its own submit
        refuses. On a directory account the profile address is the last ``mail`` the directory
        supplied, which is why this is a suggestion only. It writes nothing; the holder's submit is
        the only thing that fills ``notify_email``.

        **ONLY A PURE-ASCII ADDRESS IS OFFERED, AND NO PUNYCODE DOMAIN.** A directory writer could
        store a homoglyph lookalike of the holder's real address, such as a Cyrillic ``a`` for a
        Latin one. An ``xn--`` label is the same lookalike in ASCII form, and a browser may show it
        decoded. This refuses both. It does NOT refuse an all-ASCII lookalike such as ``examp1e``;
        the line under the input asks the holder to check the value. The submit is not narrowed: a
        holder may still type any address :meth:`fill_own_notify_email` accepts.

        A method rather than a module function so the console reaches it through the service it
        already holds, where seam discovery sees it and moves ``ENGINE_UI_SEAM``.
        """
        address = (profile_email or "").strip()
        return address if _is_adoptable_directory_address(address) else None

    async def fill_own_notify_email(
        self, identity: Identity, email: str, *, client: str | None = None
    ) -> bool:
        """Set the caller's own notification address where it has none (BACKLOG #1139).

        This is the way out of the confinement :meth:`notify_email_required` describes. Returns
        ``True`` when it wrote, ``False`` when the same address was already on file. The value must
        read as one plain mailbox (:func:`_is_single_mailbox`).

        **IT FILLS A MISSING ADDRESS AND NOTHING ELSE**, like ``admin-set-notify-email``. Changing an
        existing one here would move where notices go without telling the old address, and a
        session is all it would take. Raises :class:`NotifyEmailAlreadySet` for that, and
        :class:`ValueError` for a blank value (:func:`require_notify_email`).

        **THE FIRST ADDRESS IS TRUSTED AS SUBMITTED.** Whoever holds this session (password, and the
        factor where one is enrolled) chooses where notices go. Nothing checks that the holder
        receives mail there. The console form may start with :meth:`suggested_notify_email`, which a
        directory writer can influence; the holder still has to submit it. The audit row names the
        change in the holder's own ``/me/security-events`` feed, and the notice goes to the address
        just set.

        The fill-only check is a read, then an unconditional write. Two concurrent calls from the
        same account can both pass it; the later write wins and both are audited.
        """
        address = _require_single_mailbox(email)
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such account")
        if user.notify_email == address:
            return False
        if (user.notify_email or "").strip():
            raise NotifyEmailAlreadySet(
                "this account already has a notification address; an administrator changes it"
            )
        await self._store.set_user_notify_email(user.id, email=address)
        # The address itself stays out of the row, as provision-admin and admin-set-notify-email
        # record only that one was set.
        await self._audit("auth.notify_email_set", actor=user.username, client=client)
        await self._notify_security(
            NOTIFY_EMAIL_SET, username=user.username, email=address, client=client
        )
        return True

    # --- password management -------------------------------------------------

    def password_violations(self, password: str, *, username: str | None = None) -> list[str]:
        return self._policy.violations(password, username=username)

    async def verify_current_password(
        self,
        identity: Identity,
        password: str,
        *,
        token: str | None,
        client: str | None = None,
    ) -> CurrentPasswordCheck:
        """Check the current-password proof ``POST /me/password`` demands before a change.

        **It counts toward the account lockout and is charged to the session (BACKLOG #1138, owner
        ruling 2026-09-23).** It used to do neither and write no audit row, so a session holder could
        guess here without limit and without trace. See :meth:`_reproof`. A failure is audited once,
        as ``auth.password_change_failed``, and the attempt that crosses the threshold adds
        ``auth.account_locked``, as a sign-in does; the lockout row carries no detail, because the
        attempt's own row carries none beyond its reason. ``token`` is the caller's session, the one
        the failure is charged to. Without one there is nothing to charge, so it fails closed.

        It raises no ``auth.login_after_failures`` on success and leaves the counter to
        ``set_password``: a completed change clears it and sends its own ``PASSWORD_CHANGED`` notice,
        while a change refused by policy after a good proof would otherwise re-flag on every retry.

        ``EXPIRED`` answers a lapsed temporary credential (BACKLOG #2009), both before the verify
        and again after a good one; see :meth:`_temporary_credential_lapsed`."""
        if token is None:
            # No session to charge a failure to, so no budget: refuse without verifying. Held apart
            # from a revocation in the audit row, because nothing was revoked.
            await self._audit(
                "auth.password_change_failed",
                actor=identity.username,
                detail=_json({"reason": "no_session"}),
                client=client,
            )
            return CurrentPasswordCheck.SESSION_ENDED
        if await self._temporary_credential_lapsed(identity, client=client, password_checked=False):
            return CurrentPasswordCheck.EXPIRED
        proof = await self._reproof(identity, password, directory=False, token=token, clear=False)
        if proof.ok:
            # Asked again after the verify: a request that passed the first check can wait in the
            # per-account re-proof queue, and the deadline can pass while it waits.
            if await self._temporary_credential_lapsed(
                identity, client=client, password_checked=True
            ):
                return CurrentPasswordCheck.EXPIRED
            return CurrentPasswordCheck.OK
        await self._audit(
            "auth.password_change_failed",
            actor=identity.username,
            detail=_json({"reason": _reproof_refusal_reason(proof)}),
            client=client,
        )
        await self._record_reproof_lockout(proof, client=client, audit_detail=None)
        if proof.session_revoked:
            await self._revoke_for_budget(hash_token(token))
        if proof.session_revoked or proof.session_gone:
            return CurrentPasswordCheck.SESSION_ENDED
        return CurrentPasswordCheck.WRONG

    async def _temporary_credential_lapsed(
        self, identity: Identity, *, client: str | None, password_checked: bool
    ) -> bool:
        """Whether ``identity`` holds an admin-issued temporary credential past its deadline.

        BACKLOG #2009 (ASVS 6.4.1). The sign-in gate refuses such a credential, but a session opened
        a second before the deadline outlives it, and that session could still rotate with the
        lapsed password. So the credential stopped signing in at the deadline without dying there.
        This applies the sign-in gate's own test to the rotation, from the same
        :meth:`initial_credential_deadline` and the same stored stamp, and audits the refusal under
        the gate's own ``auth.temp_password_expired`` action.

        The first ask runs BEFORE the current password is verified. A credential already lapsed
        cannot succeed whatever is typed, so that ask charges no lockout for a guess that could not
        work, and it names only the deadline, which says nothing about the password.

        The caller asks again after a good verify, because the deadline can pass while the request
        waits for the per-account re-proof lock. That second ask is reached only by a correct
        password, so a wrong guess that races the deadline this way is charged as ``WRONG``. The
        window is the lock wait, and the credential cannot sign in after the deadline either way. ``password_checked`` records which ask refused. At
        sign-in this audit action always means the right password was presented; here it may not,
        so the row says which."""
        if not identity.must_change_password:
            return False
        user = await self._store.get_user(identity.user_id)
        if user is None or not user.must_change_password:
            return False
        deadline = self.initial_credential_deadline(user.password_changed_at)
        if deadline is None or time.time() <= deadline:
            return False
        await self._audit(
            "auth.temp_password_expired",
            actor=identity.username,
            detail=_json(
                {
                    "provider": "local",
                    "expiry_hours": self._settings.initial_password_expiry_hours,
                    "at": "password_change",
                    "password_checked": password_checked,
                }
            ),
            client=client,
        )
        return True

    async def _reproof(
        self,
        identity: Identity,
        password: str,
        *,
        directory: bool,
        token: str,
        clear: bool = True,
    ) -> _Reproof:
        """Verify a post-session credential re-proof: counted on the ACCOUNT, capped per SESSION.

        BACKLOG #1138 (ASVS 6.3.5), owner ruling 2026-09-23: *"Yes, count them. Engine lockout does
        not lock the AD account itself, and unbounded guessing behind a stolen session is the worse
        risk."* How this reads it (design E):

        * A rejected credential goes through the login leg's atomic counter,
          :meth:`_register_failure`, so it can lock the account and fire ``ACCOUNT_LOCKED``.
        * Neither account lock refuses a re-proof on a session that already exists (ADR 0197:
          the sign-in lock gates sign-in, the second-step lock gates sign-in and the second factor). If it did, anyone who knows a username could lock the account from the sign-in
          page every lock window and hold the owner's live sessions out of step-up, the password
          change and session termination indefinitely. That is the harm ``_reauth_limiter`` was
          split out to prevent.
        * Each session may fail ``lockout_threshold`` re-proofs; the one that reaches it revokes the
          session. So a stolen session gets that many guesses in total, not that many per lock
          window. The budget lives in ``_reproof_session_failures`` and is process-local.
        * During a live SIGN-IN lock a failure is charged to the session only. Registering it on the
          account would re-arm or extend a lock the login leg's own pre-check never extends. A live
          second-step lock does not stop the charge: the failure still counts on the sign-in counter.

        **ONE RE-PROOF PER ACCOUNT AT A TIME, in this process.** The body reads the session and the
        account before the verify, and the verify waits for an argon2 slot or a directory round
        trip. Serialized, a burst on one session is checked one at a time against its budget, and
        requests queued behind the revoking one find the session gone and are never verified. It
        does not order re-proofs across processes, and a cancelled request can release the lock
        while its directory bind still runs in a worker thread. Both are reported with BACKLOG #1138.

        ``directory`` re-proves by a live bind (:meth:`_reauth_ad`) instead of the stored hash;
        nothing here writes to the directory. A directory that cannot be asked, or that cannot find
        the principal, is a refusal but NOT a failure, on the account or the session: counting an
        outage would lock every operator who tried to step up while a domain controller was down.

        ``clear`` marks the re-auth leg, whose success rotates the session: only there does a success
        reset the session's budget and the account counter. The account counter resets only at FULL
        authentication (BACKLOG #1638's rule for the login leg): the session must have met its
        second-factor requirement, and no lock may be live. The password-change leg leaves both to
        the change itself, which revokes every session and clears the counter when it commits.

        **The cap covers these password re-proofs only.** A wrong TOTP or recovery code
        (``verify_mfa``) still counts on the account alone."""
        async with self._account_reproof_lock(identity.user_id):
            return await self._reproof_serialized(
                identity, password, directory=directory, token=token, clear=clear
            )

    def _account_reproof_lock(self, user_id: str) -> AbstractAsyncContextManager[None]:
        """Hold the per-account lock that orders password re-proofs and session rotations."""
        return _hold_keyed_lock(self._reproof_locks, user_id)

    def _session_reproof_failures(self, token_hash: str) -> int:
        """How many failed re-proofs this session has been charged."""
        entry = self._reproof_session_failures.get(token_hash)
        return 0 if entry is None else entry[0]

    def _charge_reproof_failure(self, token_hash: str, user_id: str) -> int:
        """Charge one failed re-proof to a session; return its total. Synchronous on purpose: it runs
        before any await after the verdict, so a store error later in the attempt cannot leave an
        evaluated guess uncharged.

        A live count is never evicted (see :data:`_REPROOF_SESSION_MAX`). When there is no room, the
        answer is the cap itself, so the caller revokes this session rather than track it."""
        now = time.monotonic()
        failures = self._reproof_session_failures
        existing = failures.get(token_hash)
        if existing is not None:
            count, first, _ = existing
            failures[token_hash] = (count + 1, first, user_id)
            return count + 1
        mine = [h for h, (_, _, uid) in failures.items() if uid == user_id]
        if len(mine) >= _REPROOF_SESSION_PER_USER:
            # This account's own oldest entry goes; no other account's count is touched.
            del failures[mine[0]]
        if len(failures) >= _REPROOF_SESSION_MAX:
            lifetime = self._settings.session_absolute_hours * 3600
            for stale in [h for h, (_, seen, _) in failures.items() if now - seen > lifetime]:
                del failures[stale]
        if len(failures) >= _REPROOF_SESSION_MAX:
            return max(self._policy.lockout_threshold, 1)
        failures[token_hash] = (1, now, user_id)
        return 1

    async def _revoke_for_budget(self, token_hash: str, now: float | None = None) -> None:
        """Revoke a session that spent its re-proof budget. The count is dropped only AFTER the revoke
        commits: if the write fails, the count stays at the cap and the next attempt revokes again
        instead of starting a fresh budget."""
        await self._store.revoke_session(token_hash, now=now)
        self._reproof_session_failures.pop(token_hash, None)

    async def _reproof_serialized(
        self,
        identity: Identity,
        password: str,
        *,
        directory: bool,
        token: str,
        clear: bool,
    ) -> _Reproof:
        """The body of :meth:`_reproof`, run under its per-account lock."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            return _Reproof(ok=False)
        token_hash = hash_token(token)
        session = await self._store.get_session(token_hash)
        if session is None or session.revoked_at is not None or session.user_id != user.id:
            # Revoked or rotated away while this attempt waited behind the lock -- by the budget,
            # or by anything else. It is not verified, so a queued burst cannot outrun the budget.
            self._reproof_session_failures.pop(token_hash, None)
            return _Reproof(ok=False, session_gone=True, user=user)
        # At least one guess, so a lockout_threshold of 0 (documented as "locks on the first
        # failure") revokes on the first failure rather than on every re-proof.
        threshold = max(self._policy.lockout_threshold, 1)
        if self._session_reproof_failures(token_hash) >= threshold:
            # Already at the cap with the session still live: the attempt that reached the cap has
            # not revoked it yet, or its revoke failed. Revoke without verifying. The revocation is
            # that earlier attempt's, so this one reports the session gone.
            await self._revoke_for_budget(token_hash, time.time())
            return _Reproof(ok=False, session_gone=True, user=user)
        verdict: bool | None
        if directory:
            verdict = await self._reauth_ad(identity.username, password)
        else:
            verdict = user.password_hash is not None and await self._argon2(
                verify_password, user.password_hash, password
            )
        if verdict is None:
            return _Reproof(ok=False, user=user)
        charged = self._charge_reproof_failure(token_hash, user.id) if not verdict else 0
        # A fresh read and a fresh clock: the verify may have taken seconds, and another leg may have
        # set a lock meanwhile.
        now = time.time()
        current = await self._store.get_user(user.id)
        locked = current is not None and _live_lock(current, now)
        if not verdict:
            attempts, just_locked, cycles = 0, False, 0
            if current is not None and not locked:
                # The SIGN-IN counter, per R4 of 2026-09-23 and ADR 0197 Decision item 1.
                attempts, just_locked, cycles = await self._register_failure(
                    user, now, counter="sign_in"
                )
            if charged >= threshold:
                # The caller audits this attempt, records any lockout, and only then revokes, so a
                # failed revoke cannot lose those rows. Until the revoke lands the count stays at the
                # cap, and any attempt that gets the lock first revokes the session unverified.
                return _Reproof(
                    ok=False,
                    session_revoked=True,
                    user=user,
                    attempts=attempts,
                    just_locked=just_locked,
                    cycles=cycles,
                )
            return _Reproof(
                ok=False, user=user, attempts=attempts, just_locked=just_locked, cycles=cycles
            )
        if current is None:
            return _Reproof(ok=False, user=user)
        if not clear:
            # The password-change leg: nothing rotates here, and a change refused by policy leaves the
            # session as it was, budget included.
            return _Reproof(ok=True, user=current)
        # The re-auth leg: a good proof resets this session's budget, and the success rotates it.
        self._reproof_session_failures.pop(token_hash, None)
        # ADR 0197: neither lock live, and any of the six lockout columns to clear.
        cleared = (
            not locked
            and not current.second_step_locked(now)
            and _holds_lockout_state(current)
            and await self.mfa_satisfied(token)
        )
        if cleared:
            await self._store.record_login_success(user.id, now=now)
        # The FRESH row, so the caller's login-after-failures check sees failures other legs added
        # during the verify.
        return _Reproof(ok=True, user=current, cleared=cleared)

    async def _record_reproof_lockout(
        self, proof: _Reproof, *, client: str | None, audit_detail: dict[str, Any] | None
    ) -> None:
        """Record the lockout a failed re-proof crossed. Called AFTER the attempt's own audit row,
        which is the order the login leg writes them in. ``audit_detail`` mirrors that row."""
        if proof.user is not None:
            await self._record_lock(
                proof.user,
                "sign_in",
                LockoutIncrement(proof.attempts, proof.just_locked, proof.cycles),
                client=client,
                audit_detail=audit_detail,
            )

    async def reauth(
        self,
        identity: Identity,
        password: str,
        *,
        token: str,
        client: str | None = None,
        purpose: str | None = None,
    ) -> Elevation:
        """Step-up re-verification (ASVS 7.5.3): re-prove the caller's credential and, on success,
        refresh the current session's ``reauth_at`` so it may perform highly sensitive operations for
        the configured window. Local accounts re-verify the password (argon2); **AD accounts do a live
        re-bind** against the directory so AD operators aren't locked out. A session the federated
        login minted is refused before either (see the first branch): it steps up at the IdP through
        :meth:`complete_oidc_step_up`. Always audited.

        ``purpose`` (ADR 0077) additionally mints a **single-use, action-bound** step-up grant for that
        named action, so a durable-takeover route (TOTP enroll/confirm, disable-MFA) can require a fresh
        proof tied to *it* rather than riding the broad session window. It is purely
        additive — the session-window refresh above is unchanged (the broad admin/replay/config routes
        keep using it). The grant is minted by a step-up and never by login or ``verify_mfa``: here
        for the password leg, and in :meth:`complete_oidc_step_up` for an OIDC session's IdP leg.

        Returns an :class:`Elevation`: on success the session is re-keyed (ASVS 7.2.4) and the NEW
        token is in ``Elevation.token``. The three steps below are ORDER-CRITICAL -- see the inline
        notes and :meth:`_rotate_session_token`.

        **A failure counts toward the account lockout on BOTH providers, and each session may fail
        at most ``lockout_threshold`` re-proofs before it is revoked (BACKLOG #1138).** See
        :meth:`_reproof`. Neither account lock refuses this. A revoked session answers
        ``session_lost``. A success clears the counter only when the session has met its
        second-factor requirement and no lock is live (BACKLOG #1638's rule for the login leg), and a
        success that clears a run of failures is labelled ``auth.login_after_failures``."""
        if await self.session_steps_up_at_idp(token):
            # BACKLOG #296, ADR 0142 Amendment B: a session the federated login minted steps up at the
            # IdP and NEVER by a password. Refused before any verify, so the password is not sent to
            # the directory and nothing is charged to the session budget or the account lockout: the
            # caller did not guess wrong, it asked the wrong leg. Audited so the refusal is visible.
            await self._audit(
                "auth.reauth",
                actor=identity.username,
                detail=_json(
                    {
                        "ok": False,
                        "provider": identity.auth_provider.value,
                        "purpose": purpose,
                        "reason": IDP_STEP_UP_REQUIRED,
                    }
                ),
                client=client,
            )
            return Elevation(idp_step_up_required=True)
        # The counter-clearing decision is made inside, against the OLD token, before the rotation
        # below retires it.
        proof = await self._reproof(
            identity,
            password,
            directory=identity.auth_provider is AuthProvider.AD,
            token=token,
        )
        ok = proof.ok
        elevation = Elevation(session_lost=proof.session_revoked or proof.session_gone)
        grant_refused = False
        if ok:
            # (1) Every stamp for this elevation, against the OLD hash. The rotation carries these
            # columns forward; a stamp issued after it would silently write nothing.
            # Re-anchor the session to the address it re-verified from, so a forced step-up triggered
            # by a roamed/new client IP (WP-L3-13) clears once the caller re-proves from there.
            await self._store.mark_session_reauthed(hash_token(token), client=client)
            # `_factor_binding_is_blocked` resolves the session BY THE OLD TOKEN and fails closed when
            # it cannot find it, so it is decided here, BEFORE the rotation retires that token --
            # asking after would refuse every such grant on a session that is perfectly fine. It
            # covers every action in _PENDING_REFUSED_ACTIONS, session_terminate too (#1951).
            grant_refused = purpose is not None and await self._factor_binding_is_blocked(
                token, purpose
            )
            # (2) Rotate. Past this line `token` no longer authenticates.
            elevation = await self._elevated(
                token, ceremony="reauth", actor=identity.username, client=client
            )
            if purpose is not None and not grant_refused and elevation.token is not None:
                # (3) Purpose-bound grants are minted AFTER, against the NEW hash -- minted against the
                # old one they would be stranded on a hash nothing resolves any more.
                # Bind THIS fresh proof to the single action named by `purpose` (single-use), so a broad
                # login-seeded window can never authorize a factor-binding action (ASVS 7.5.1 / 8.2.4).
                self._grant_action_step_up(hash_token(elevation.token), purpose)
        await self._audit(
            "auth.reauth",
            actor=identity.username,
            detail=_json(
                {
                    "ok": ok,
                    "provider": identity.auth_provider.value,
                    "purpose": purpose,
                    # The session is gone: a good password on a session that vanished mid-ceremony,
                    # or (with session_revoked) one revoked by its re-proof budget.
                    "session_lost": elevation.session_lost,
                    # A good password whose purpose grant was refused (a pending session on an
                    # account with a factor). Without it the row reads as a granted re-proof.
                    "grant_refused": grant_refused,
                    # This failure spent the session's re-proof budget, so it is revoked
                    # (BACKLOG #1138). A session already gone reads session_lost alone.
                    "session_revoked": proof.session_revoked,
                }
            ),
            client=client,
        )
        provider_detail = {"provider": identity.auth_provider.value}
        await self._record_reproof_lockout(proof, client=client, audit_detail=provider_detail)
        if proof.session_revoked:
            await self._revoke_for_budget(hash_token(token))
        # Flagged only on the success that CLEARED the counter. On a session still owing its second
        # factor nothing clears, so flagging there would repeat the row and the notice on every
        # re-auth. That session's clear happens later in verify_mfa, which flags nothing: the gap
        # BACKLOG #1138 already records for a success after second-factor failures.
        # Both counters, as the login leg sums them (ADR 0197): a run of wrong codes is on the
        # second-step counter now.
        prior_failures = (
            proof.user.failed_attempts + proof.user.second_step_failed_attempts
            if proof.user is not None
            else 0
        )
        if (
            proof.cleared
            and proof.user is not None
            and prior_failures >= SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        ):
            await self._record_suspicious_login(
                LOGIN_AFTER_FAILURES,
                proof.user,
                client=client,
                audit_detail=provider_detail,
                notice_detail={"failed_attempts": prior_failures},
            )
        return elevation

    #: The step-up actions a pending session may NOT be granted once its account HAS a factor. Every
    #: one of them rides a ``*_reauth_only_action`` gate (``mfa_gate=False``), which exists so an
    #: account with no factor is not locked out of it. For an account that already has one:
    #:
    #: - binding a new factor (``mfa_enroll``, ``mfa_confirm``, ``webauthn_enroll``) is a promotion
    #:   path, because both ceremonies mark the session MFA-satisfied on success;
    #: - ending sessions (``session_terminate``, BACKLOG #1951, ASVS 7.5.2) through the terminate
    #:   routes would let a password holder sign the real user out without the second factor.
    #:
    #: Changing the password does both at once, but it takes no grant and rides no reauth-only gate,
    #: so it asks the same rule through :meth:`password_change_owes_factor` instead (BACKLOG #1954).
    #:
    #: A new action on either reauth-only action gate belongs here too. A test in
    #: ``tests/test_mfa_access_gate.py`` catches at least a missing one wired in the engine or
    #: console packages. The action-less ``require_ui_reauth_only`` gate never consults it.
    _PENDING_REFUSED_ACTIONS = frozenset(
        {
            STEP_UP_ACTION_MFA_ENROLL,
            STEP_UP_ACTION_MFA_CONFIRM,
            STEP_UP_ACTION_WEBAUTHN_ENROLL,
            STEP_UP_ACTION_SESSION_TERMINATE,
        }
    )

    async def _factor_binding_is_blocked(self, token: str | None, purpose: str) -> bool:
        """Whether a step-up grant for ``purpose`` must be REFUSED for this session (ASVS 6.3.3).

        Named for its first case, binding a factor; :data:`_PENDING_REFUSED_ACTIONS` lists them all.
        Closes a bypass the 6.3.3 access gate would otherwise leave open. The gate's carve-out
        (``mfa_gate=False`` on the ``*_reauth_only*`` factories, plus ``POST /me/reauth`` being
        MFA-exempt) is justified solely by "an un-enrolled user cannot satisfy a gate standing in
        front of the route it needs" — a condition that is FALSE for an account that already has a
        factor. Without this check, an attacker holding only the password could take a pending
        session, re-auth with the password alone, enrol a NEW authenticator, and be promoted to
        MFA-satisfied by ``confirm_mfa_enrollment`` / ``finish_webauthn_registration`` — defeating
        the second factor entirely and durably binding an attacker-controlled authenticator.

        So: if the session has not satisfied its second factor and the account already has one, the
        existing factor must be proven first (``POST /auth/mfa-verify``). First enrolment is
        untouched: an account with NO factor still enrols, and ends sessions, from a password-only
        session, which is exactly the deadlock carve-out. Disable/delete actions are NOT listed:
        they run behind ``require_step_up_action``, which keeps its own ``mfa_satisfied`` check.
        """
        if purpose not in self._PENDING_REFUSED_ACTIONS:
            return False
        return await self._owes_enrolled_factor(token)

    async def _factor_binding_is_blocked_hash(self, token_hash: str, purpose: str) -> bool:
        """:meth:`_factor_binding_is_blocked` keyed on the session's hash (see
        :meth:`_elevated_hash`)."""
        if purpose not in self._PENDING_REFUSED_ACTIONS:
            return False
        return await self._owes_enrolled_factor_hash(token_hash)

    async def _owes_enrolled_factor(self, token: str | None, *, local_only: bool = False) -> bool:
        """Whether the session is MFA-pending on an account that already HAS a second factor.

        Fails closed (True) when the session or its user cannot be found. ``local_only`` answers
        False for a directory account, whose password the engine does not hold. It names AD rather
        than excluding everything that is not LOCAL: ``_build_identity`` maps an unrecognized
        provider back to LOCAL, so the password handler treats that row as local and changes it."""
        if not token:
            return True  # no session to act on, so fail closed (as below)
        return await self._owes_enrolled_factor_hash(hash_token(token), local_only=local_only)

    async def _owes_enrolled_factor_hash(
        self, token_hash: str, *, local_only: bool = False
    ) -> bool:
        """:meth:`_owes_enrolled_factor` keyed on the session's hash (see :meth:`_elevated_hash`)."""
        if await self._mfa_satisfied_hash(token_hash):
            return False
        session = await self._store.get_session(token_hash)
        if session is None:
            return True  # no session to act on, so fail closed
        user = await self._store.get_user(session.user_id)
        if user is None:
            return True
        if local_only and user.auth_provider == AuthProvider.AD.value:
            return False
        return await self._second_factor_enrolled(user)

    async def password_change_owes_factor(self, token: str | None) -> bool:
        """Whether this session must prove its second factor before it may change the password.

        BACKLOG #1954 (ASVS 6.3.3). A change revokes every session, so a password holder on a
        pending session must not reach it on the password alone. True for a pending session on
        an account that holds a factor, unless it is a directory (AD) account, and when the session
        or its user cannot be found. An account with no factor has nothing to prove and
        rotates as before, and a directory account is left to the route's 400, which changes
        nothing. PUBLIC for the reason :meth:`factor_binding_is_blocked` gives: the JSON gate and
        the web console's password and factor pages all ask it, so the planes cannot drift."""
        return await self._owes_enrolled_factor(token, local_only=True)

    async def factor_binding_is_blocked(self, token: str | None, action: str) -> bool:
        """PUBLIC contract boundary over :meth:`_factor_binding_is_blocked`, for the ROUTE gates.

        Public on purpose, not as a convenience alias. Both step-up decision helpers must apply the
        refusal -- ``api.security._action_step_up_ok`` and the web console's
        ``_ui_action_step_up_ok`` -- and the console reaches the engine only across its PUBLISHED
        surface. Without this method that console-side copy is written from scratch, and a rule
        living in two packages is a rule that drifts in one of them.

        ``action`` is the route's step-up action, which is the same vocabulary ``POST /me/reauth``
        spells ``purpose``, so it passes straight through rather than being fixed per call site --
        which would mean exporting :data:`_PENDING_REFUSED_ACTIONS` or shutting the other lanes
        with it."""
        return await self._factor_binding_is_blocked(token, action)

    def _grant_action_step_up(self, token_hash: str, action: str) -> None:
        """Mint a single-use per-action step-up grant (ADR 0077), bounded + TTL'd, process-local.

        The deadline reuses ``[auth].step_up_max_age_seconds`` so a minted-but-unconsumed grant expires
        on the same clock as the session window. On the global-bound overflow the OLDEST grant is
        evicted (fail-safe: a dropped grant just re-prompts, never a bypass)."""
        now = time.monotonic()
        self._prune_action_step_up_grants(now)
        key = (token_hash, action)
        if key not in self._action_step_up_grants and (
            len(self._action_step_up_grants) >= _ACTION_STEP_UP_GRANT_MAX
        ):
            oldest = min(self._action_step_up_grants, key=self._action_step_up_grants.__getitem__)
            del self._action_step_up_grants[oldest]
        self._action_step_up_grants[key] = now + self._settings.step_up_max_age_seconds

    def _prune_action_step_up_grants(self, now: float) -> None:
        """Drop expired per-action grants (monotonic clock — a wall-clock step can't widen the window)."""
        expired = [k for k, deadline in self._action_step_up_grants.items() if deadline <= now]
        for key in expired:
            del self._action_step_up_grants[key]

    async def has_action_step_up(self, token: str | None, action: str) -> bool:
        """Whether the caller holds a fresh step-up grant BOUND to ``action`` — and **consume** it
        (single-use). ADR 0077. A grant is minted only by a step-up: ``reauth(purpose=action)`` (POST
        /me/reauth or /ui/reauth), or :meth:`complete_oidc_step_up` for an OIDC session's IdP leg. Never
        by login or ``verify_mfa``, so a login-seeded step-up window cannot bind a
        new authenticator. Returns False for a missing token / no grant / an expired grant."""
        if not token:
            return False
        now = time.monotonic()
        self._prune_action_step_up_grants(now)
        # pop = single-use: the grant is gone whether or not it was still live (a stale pop is harmless).
        deadline = self._action_step_up_grants.pop((hash_token(token), action), None)
        return deadline is not None and deadline > now

    async def _reauth_ad(self, username: str, password: str) -> bool | None:
        """Re-verify an AD credential via a live directory re-bind (no session adopted).

        Three answers, because only one of the two refusals is a guess (BACKLOG #1138): ``True`` =
        bound; ``False`` = the directory REJECTED the password, which :meth:`_reproof` counts toward
        the engine lockout; ``None`` = it could not be asked (no directory, an :class:`LdapError`)
        or it has no such principal. Both refusals fail closed; only ``False`` is counted.

        The principal check matters because ``authenticate`` answers ``None`` for a missing, renamed
        or disabled principal as well as for a wrong password. Counting that would lock the engine
        row of a user whose every re-bind fails whatever they type, and the lock is then enforced at
        their Kerberos and OIDC sign-in. The extra lookup runs only after a refusal. A correct
        password the DC refuses as expired still counts, which nothing here can tell apart."""
        if self._ldap is None:
            return None
        try:
            principal = await asyncio.to_thread(self._ldap.authenticate, username, password)
        except LdapError:
            return None
        if principal is not None:
            return True
        try:
            known = await asyncio.to_thread(self._ldap.resolve_principal, username)
        except LdapError:
            # ``authenticate`` also answers None where no real bind was judged (an empty password, an
            # unfound principal's equalizing bind, a DC too busy to answer the bind), so a lookup
            # that then fails cannot show the password was checked. Not counted, like an outage.
            return None
        return False if known is not None else None

    async def has_recent_step_up(self, token: str | None) -> bool:
        """Whether the caller's session re-verified its credential within
        ``[auth].step_up_max_age_seconds`` -- the gate for sensitive operations (ASVS 7.5.3).

        A LOCAL login that owes no second factor is the first verification. No directory login is:
        Kerberos and OIDC sessions are born with no window (BACKLOG #1144 step 5), and open one only
        by a step-up or a code at the MFA gate."""
        if not token:
            return False
        session = await self._store.get_session(hash_token(token))
        if session is None or session.reauth_at is None:
            return False
        return (time.time() - session.reauth_at) <= self._settings.step_up_max_age_seconds

    @staticmethod
    def _same_host(a: str, b: str) -> bool:
        """Whether two client addresses denote the same host: an exact match, **or** both loopback (so a
        dual-stack box that presents ``::1`` on one connection and ``127.0.0.1`` on another is treated as
        one host — this keeps the loopback default a genuine no-op rather than a string mismatch).
        Unparseable values fall back to exact match."""
        if a == b:
            return True
        try:
            return ipaddress.ip_address(a).is_loopback and ipaddress.ip_address(b).is_loopback
        except ValueError:
            return False

    def _remember_new_ip(self, token_hash: str, client_ip: str) -> None:
        """Record the last new client IP flagged for a session — best-effort, per-process dedup of the
        audit/notify side effects only. Bounded so session/address churn can't grow it without limit;
        the step-up decision never depends on this cache (eviction only risks one extra audit row)."""
        if len(self._new_ip_seen) >= _NEW_IP_DEDUP_MAX and token_hash not in self._new_ip_seen:
            self._new_ip_seen.pop(next(iter(self._new_ip_seen)))
        self._new_ip_seen[token_hash] = client_ip

    async def _classify_login_address(self, user: UserRecord, client: str | None) -> _LoginAddress:
        """The first-seen login-address signal's verdict for one sign-in (BACKLOG #288, ASVS 8.2.4).

        Call it BEFORE the mint and before this login's own ``auth.login_success`` row is written,
        or the login would always find itself. There is no new query and no schema change: the
        baseline is read through the ``list_audit`` filter all three store backends implement, and
        ADR 0150 put the address on every row.

        **THE BASELINE IS ADDRESSES THAT FINISHED AUTHENTICATING, not addresses that got past the
        password.** ``auth.login_success`` is written at the password step even when a second
        factor is still owed, so a row whose detail says ``mfa_required: true`` is skipped: counting
        it would let a holder of the password alone plant an address as known. The factor legs'
        own rows, ``auth.mfa_verified`` and ``auth.webauthn_verified``, supply those addresses
        instead, and are read only when the first read found no match. A directory row carries no
        such marker, so on the directory leg a password-step row still counts; that residual is
        recorded in docs/SECURITY.md.

        Each read is bounded by ``_LOGIN_ADDRESS_HISTORY_ROWS`` and by a floor of the later of
        ``_LOGIN_ADDRESS_LOOKBACK_SECONDS`` ago and the account's ``created_at``. The second bound
        keeps a re-created account from inheriting a deleted namesake's addresses, since the audit
        actor is a username. Addresses compare as :meth:`_same_host` does, so ``127.0.0.1`` and
        ``::1`` are one host here too.

        ``user.last_login_at`` separates the two empty-history cases. None means the account has
        never completed a sign-in, so there is no baseline and the verdict fails open. A set value
        with no matching address means the account is known but this address is not: NEW.

        A failed read fails open as ``UNEVALUATED_READ_FAILED``. The exception classes differ per
        store backend (sqlite3, asyncpg, pyodbc), none of which ``auth/`` may import, so the catch
        is broad; it is logged, and the caller audits the verdict."""
        if not client:
            return _LoginAddress.UNEVALUATED_UNKNOWN_ADDRESS
        since = max(time.time() - _LOGIN_ADDRESS_LOOKBACK_SECONDS, user.created_at)
        seen = False
        try:
            for action in ("auth.login_success", "auth.mfa_verified", "auth.webauthn_verified"):
                rows = await self._store.list_audit(
                    actor=user.username,
                    action=action,
                    since=since,
                    limit=_LOGIN_ADDRESS_HISTORY_ROWS,
                )
                addresses = [
                    str(row["client"])
                    for row in rows
                    if row["client"] and not _owed_a_factor(row["detail"])
                ]
                seen = seen or bool(addresses)
                if any(
                    self._same_host(_unmapped(client), _unmapped(address)) for address in addresses
                ):
                    return _LoginAddress.KNOWN
        except Exception:
            _log.exception(
                "first-seen login-address read failed for %s; the sign-in proceeds unchallenged",
                user.username,
            )
            return _LoginAddress.UNEVALUATED_READ_FAILED
        if not seen and user.last_login_at is None:
            return _LoginAddress.UNEVALUATED_NO_BASELINE
        return _LoginAddress.NEW

    def _login_new_ip_notice_due(self, user_id: str, client: str | None) -> bool:
        """At most one ``login_new_ip`` notice per (account, address) per
        ``_LOGIN_NEW_IP_NOTICE_SECONDS``. Keyed on the address too, so a second, different
        first-seen address inside the window is still reported.

        The mid-session signal debounces its notices for the same reason (``_new_ip_seen``). Here a
        holder of the password alone, signing in from a fresh address each time, would otherwise
        mail the account once per attempt. The audit row is still written every time; only the
        mail is held back. Per process and bounded, so eviction can only ever send one extra
        notice."""
        now = time.monotonic()
        key = (user_id, client or "")
        last = self._login_new_ip_noticed.get(key)
        if last is not None and now - last < _LOGIN_NEW_IP_NOTICE_SECONDS:
            return False
        self._login_new_ip_noticed.pop(key, None)
        if len(self._login_new_ip_noticed) >= _NEW_IP_DEDUP_MAX:
            self._login_new_ip_noticed.pop(next(iter(self._login_new_ip_noticed)))
        self._login_new_ip_noticed[key] = now
        return True

    async def _record_login_address(
        self, verdict: _LoginAddress, user: UserRecord, *, client: str | None, provider: str
    ) -> None:
        """Write what :meth:`_classify_login_address` decided, after the session is minted.

        Called after the mint so a login that then fails (a withdrawn federated binding) leaves no
        row claiming a sign-in happened, and before the ``auth.login_success`` row so that row stays
        the newest one for the login. ``KNOWN`` writes nothing. ``NEW`` audits
        ``auth.login_new_ip`` and sends the ``login_new_ip`` notice, debounced per account. The
        fail-open verdicts audit ``auth.login_address_unevaluated`` with the reason and notify
        nobody. This never refuses a login: the challenge is the session minted without step-up
        freshness, which the caller arranges."""
        if verdict is _LoginAddress.KNOWN:
            return
        if verdict is _LoginAddress.NEW:
            await self._audit(
                "auth.login_new_ip",
                actor=user.username,
                detail=_json({"provider": provider}),
                client=client,
            )
            if self._login_new_ip_notice_due(user.id, client):
                await self._notify_security(
                    LOGIN_NEW_IP,
                    username=user.username,
                    email=user.notify_email,
                    client=client,
                    detail={"provider": provider},
                )
            return
        await self._audit(
            "auth.login_address_unevaluated",
            actor=user.username,
            detail=_json({"provider": provider, "reason": verdict.value}),
            client=client,
        )

    async def flag_new_client_ip(
        self, token: str | None, client_ip: str | None, *, path: str
    ) -> bool:
        """Admin-interface contextual-risk signal (ASVS 8.4.2, WP-L3-13): return ``True`` when this
        sensitive request arrives from a client address that differs from the one the caller's session
        last verified from. On the **first** observation of a given (session, address) it emits an
        ``auth.admin_action_new_ip`` audit event + a best-effort out-of-band notice; **repeat** hits from
        the same un-cleared address still return ``True`` (so the step-up stays forced) but only log to
        the rotating ops log — so a token replayed in a tight loop from one address cannot inflate the
        audit table / notification channel (mirrors the ``_rate_limited`` precedent). The step-up
        dependencies treat ``True`` as "force a fresh step-up"; a successful re-verify (``POST
        /me/reauth`` **or** ``/auth/mfa-verify``) re-anchors the session to the new address (see
        :meth:`reauth` / :meth:`verify_mfa`), so the signal clears and the caller proceeds. An
        ``oidc`` session, which :meth:`reauth` refuses, can re-anchor through the IdP step-up
        (:meth:`complete_oidc_step_up`). It is
        **advisory + step-up-forcing only** — it never changes an authorization decision and never
        blocks the non-admin request path.

        Disabled (returns ``False`` with no side effects) when ``[auth].admin_new_ip_step_up`` is off.
        It is ON by default since BACKLOG #288, and off is a named loosening. Even on, a single-host
        loopback session never trips it because the request and the session resolve to the same loopback host (IPv4 or
        IPv6 — see :meth:`_same_host`)."""
        if not self._settings.admin_new_ip_step_up or not token:
            return False
        token_hash = hash_token(token)
        session = await self._store.get_session(token_hash)
        if session is None or session.revoked_at is not None:
            return False
        # No baseline address (older session / unknown login source) or the same host → not new. A
        # session with no recorded address is not penalized, to avoid spurious admin friction.
        if not session.client or not client_ip or self._same_host(client_ip, session.client):
            return False
        # New address → force a step-up (return True unconditionally). Emit the audit + notice once per
        # (session, address); suppress repeats from the same un-cleared address so a replayed token
        # cannot amplify the audit log / notifications.
        if self._new_ip_seen.get(token_hash) == client_ip:
            _log.warning(
                "admin action from already-flagged new client IP (repeat suppressed): path=%s", path
            )
            return True
        self._remember_new_ip(token_hash, client_ip)
        user = await self._store.get_user(session.user_id)
        username = user.username if user is not None else session.user_id
        await self._audit(
            "auth.admin_action_new_ip",
            actor=username,
            detail=_json({"path": path, "known_ip": session.client, "seen_ip": client_ip}),
        )
        await self._notify_security(
            ADMIN_NEW_IP,
            username=username,
            email=user.notify_email if user is not None else None,
            client=client_ip,
            detail={"known_ip": session.client},
        )
        return True

    async def change_password(
        self,
        identity: Identity,
        new_password: str,
        *,
        must_change: bool = False,
        client: str | None = None,
    ) -> list[str]:
        """Set a local user's password (after policy check) and revoke their other sessions.

        Returns policy violations (empty list = changed). No-op-safe for AD identities at the API
        layer, which rejects password changes for AD users before calling this.
        """
        violations = self._policy.violations(new_password, username=identity.username)
        if violations:
            return violations
        await self._store.set_password(
            identity.user_id,
            password_hash=await self._argon2(hash_password, new_password),
            must_change_password=must_change,
        )
        await self._store.revoke_user_sessions(identity.user_id)
        await self._audit("auth.password_changed", actor=identity.username, client=client)
        user = await self._store.get_user(identity.user_id)
        await self._notify_security(
            PASSWORD_CHANGED,
            username=identity.username,
            email=user.notify_email if user is not None else None,
            client=client,
        )
        return []

    # --- MFA: native TOTP second factor (every account, WP-14, ASVS 6.3.3) -----

    async def _second_factor_enrolled(self, user: UserRecord) -> bool:
        """Any second factor enrolled — TOTP **or** ≥1 WebAuthn passkey (ADR 0068 decision 5). The
        store round-trip only runs when TOTP alone doesn't already answer."""
        return user.totp_enabled or await self._store.has_webauthn_credentials(user.id)

    def _mfa_required_for(
        self, user: UserRecord, roles: frozenset[Role], *, second_factor_enrolled: bool
    ) -> bool:
        """Whether ``user`` must satisfy a second factor. An enrolled user (either factor — the caller
        pre-resolves ``second_factor_enrolled`` via :meth:`_second_factor_enrolled`, keeping this hot
        boolean logic sync and the store round-trip visible at each call site) always must; an
        un-enrolled user must when ``[security].require_mfa`` is on and
        ``[security].require_mfa_scope`` covers them — ``every_local_account`` (default, ASVS
        6.3.3) or, under ``administrators``, only the Administrator role.

        **THE RULE READS NO PROVIDER (BACKLOG #1144, ASVS 6.8.4),** which is what keeps it closed
        against an unrecognized value — :meth:`_identity_for_user` maps one back to ``LOCAL`` when it
        builds the :class:`Identity`, so a row that skipped the factor here would present as local
        everywhere else. It used to open with a blanket ``auth_provider == ad -> False`` exemption; a
        ticket or a bind asserts nothing about what the directory enforced, so that exempted on no
        evidence, and the enrollment ceremonies now accept a directory account."""
        if second_factor_enrolled:
            return True
        if not self._settings.require_mfa:
            return False
        return (
            self._settings.require_mfa_scope == "every_local_account" or Role.ADMINISTRATOR in roles
        )

    async def mfa_satisfied(self, token: str | None) -> bool:
        """Whether the caller's session has met its second-factor requirement — True when the session
        is MFA-verified, **or** when MFA isn't required for this user. Composed with
        :meth:`has_recent_step_up` by the API to gate sensitive operations (WP-14). A required-but-
        unverified session returns False, so the step-up routes 403 until ``POST /auth/mfa-verify``."""
        if not token:
            return False
        return await self._mfa_satisfied_hash(hash_token(token))

    async def _mfa_satisfied_hash(self, token_hash: str) -> bool:
        """:meth:`mfa_satisfied` keyed on the session's hash (see :meth:`_elevated_hash` for why)."""
        session = await self._store.get_session(token_hash)
        if session is None or session.revoked_at is not None:
            return False
        if session.mfa_verified_at is not None:
            return True
        user = await self._store.get_user(session.user_id)
        if user is None:
            return False
        # The extra store reads only execute for sessions not already MFA-verified (the
        # mfa_verified_at early-return above short-circuits the common case).
        return not await self._unverified_session_owes_factor(user)

    async def _unverified_session_owes_factor(self, user: UserRecord) -> bool:
        """Whether a session of ``user`` with no ``mfa_verified_at`` stamp still owes a second
        factor. Every unstamped session of one user gets the same answer at one moment, so the
        session cap can ask it once per user (BACKLOG #2076); :meth:`_mfa_satisfied_hash` asks it
        per session. One rule, so the gate and the cap cannot disagree about which rows are
        pending."""
        if user.auth_provider == AuthProvider.AD.value and self._settings.require_mfa:
            # THE DIRECTORY FLOOR, decided per SESSION rather than per user (ASVS 6.3.4 / 6.8.4).
            # Reaching here means the session was minted with NO factor asserted at all -- every
            # Kerberos session, and any federated one issued while oidc_require_mfa_claim was off.
            #
            # It decides exactly one case the shared rule below would decide differently:
            # require_mfa_scope="administrators" + a non-Administrator + no factor enrolled. A LOCAL
            # non-admin is satisfied there, having at least proven a password to the ENGINE; this
            # session proved nothing to the engine, so the scope dial does not reach it. Every other
            # combination is already produced by the shared rule, and when require_mfa is off this
            # falls through to it -- an enrolled directory account satisfies the factor it enrolled.
            #
            # Kept apart from _mfa_required_for on purpose: that helper answers "is this person
            # exempt" for mfa_status and the last-factor-delete guard, and only an UNSTAMPED session
            # (what this helper is asked about) carries the fact that nothing was proven at mint.
            return True
        roles = _roles_from_ids(await self._store.get_user_role_ids(user.id))
        enrolled = await self._second_factor_enrolled(user)
        return self._mfa_required_for(user, roles, second_factor_enrolled=enrolled)

    async def begin_mfa_enrollment(self, identity: Identity) -> MfaEnrollment:
        """Stage a fresh TOTP secret and return it + the ``otpauth://`` URI for the QR. Not active
        until proven via :meth:`confirm_mfa_enrollment`. Raises :class:`ValueError` for an unknown
        account or when MFA is already enabled (disable it first to re-enroll).

        **A DIRECTORY ACCOUNT MAY ENROLL (BACKLOG #1144, ASVS 6.8.4).** This refused anything but
        ``LOCAL``, which made the delegated-directory relaxation self-sealing: the engine could not
        assume the minimum on a leg that asserts nothing, because assuming it locked out every
        directory operator. The secret and its recovery codes are engine-held state on the engine's
        own user row, which a directory account already has (``_upsert_ad_user``); nothing here reads
        or writes the directory. The step-up in front of this ceremony re-proves a directory
        credential by a live bind (:meth:`_reauth_ad`), so the proof is real on both providers."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such user")
        if user.totp_enabled:
            raise ValueError("MFA is already enabled; disable it before re-enrolling")
        secret = totp.generate_secret()
        await self._store.set_totp_secret(identity.user_id, secret=secret)
        await self._audit("auth.mfa_enroll_started", actor=identity.username)
        return MfaEnrollment(secret=secret, otpauth_uri=totp.otpauth_uri(secret, identity.username))

    async def confirm_mfa_enrollment(
        self, identity: Identity, code: str, *, token: str, client: str | None = None
    ) -> Elevation:
        """Confirm a staged enrollment by proving a live TOTP code. On success: activate MFA, mint the
        single-use recovery codes (returned **once**, plaintext, for the user to save), mark the
        current session MFA-verified, re-key the session (ASVS 7.2.4), audit + notify. Raises
        :class:`ValueError` for an unknown account or when no enrollment is staged. Accepts a
        directory account, for the reason :meth:`begin_mfa_enrollment` states.

        Returns an :class:`Elevation` whose ``recovery_codes`` carry the plaintext codes; a wrong code
        (or a time-step already consumed -- single-use, BACKLOG #1021) elevates nothing and carries
        none. A good code on a session revoked before the rotation returns ``session_lost`` with MFA
        still OFF (BACKLOG #1902), so a lost session never leaves MFA on with codes nobody saw.

        This is one of the two legs that turn an MFA-pending session into an MFA-satisfied one for a
        FIRST enrolment, so it rotates for the same reason ``verify_mfa`` does: without it a pre-MFA
        token captured before the ceremony would be elevated in place on a first deployment."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such user")
        secret = await self._store.get_totp_secret(identity.user_id)
        if not secret:
            raise ValueError("no enrollment in progress")
        # Verify the enrollment proof under the SAME configured clock-skew window as a login (BACKLOG
        # #187): default 0 = strict current-step only. Enrolling under the same window a login uses
        # avoids the trap of a skewed-clock authenticator that confirms enrollment yet then fails every
        # login (the mismatch surfaces at enroll time instead). The matched step is then CONSUMED
        # (BACKLOG #1021), single-use per ASVS 6.5.1, mirroring _verify_second_factor's verify-then-
        # consume so the activating code can't be replayed on POST /auth/mfa-verify inside its step
        # window (verify_totp alone discarded the step, which would leave a second-factor replay window
        # at enrollment on first deployment). Consume BEFORE minting recovery codes / enable_totp keeps
        # enable atomic: a step that no longer advances the high-water mark fails on the same
        # phase=enroll branch and MFA is not enabled.
        matched_step = totp.verify_totp_step(
            secret, code.strip(), window=self._settings.totp_skew_steps
        )
        if matched_step is None or not await self._store.consume_totp_step(
            identity.user_id, matched_step
        ):
            await self._audit(
                "auth.mfa_failed",
                actor=identity.username,
                detail=_json({"phase": "enroll"}),
                client=client,
            )
            return Elevation()
        plain = totp.generate_recovery_codes(self._settings.mfa_recovery_code_count)
        hashes = [await self._argon2(hash_password, c) for c in plain]
        # ROTATE BEFORE ENABLING (BACKLOG #1902). The plaintext codes reach the user only inside the
        # Elevation, and a session revoked mid-ceremony yields a lost one that carries nothing. Enabled
        # first, that left MFA ON with recovery codes nobody ever saw. So enable_totp commits only once
        # the rotation has succeeded; on a lost session MFA stays off and the staged secret stays put,
        # and the user signs in again and confirms with a code from a later step (this one is spent).
        # The cost: if enable_totp itself fails after a good rotation, the new token is never handed
        # back, so the user is signed out with MFA still off. That fails closed, and a retry works.
        # Stamp against the OLD hash, then rotate — never the other way round.
        await self._store.mark_session_mfa_verified(hash_token(token))
        elevation = await self._elevated(
            token,
            ceremony="mfa_enroll_confirm",
            actor=identity.username,
            client=client,
            recovery_codes=tuple(plain),
        )
        if not elevation.ok:
            return elevation
        await self._store.enable_totp(identity.user_id, recovery_code_hashes=hashes)
        await self._audit("auth.mfa_enrolled", actor=identity.username, client=client)
        await self._notify_security(
            MFA_ENABLED, username=user.username, email=user.notify_email, client=client
        )
        return elevation

    async def verify_mfa(
        self, token: str | None, code: str, *, client: str | None = None
    ) -> Elevation:
        """Validate a TOTP code (or a single-use recovery code) for the caller's session and, on
        success, mark the session's second factor satisfied and re-key the session (ASVS 7.2.4).
        Always audited; the API gates this behind the login rate limiter. Returns a not-``ok``
        :class:`Elevation` (never raises) for any invalid input.

        This is the leg the 7.2.4 verb is really about: without the rotation, a pre-MFA token captured
        before the second factor would be elevated in place to a fully authenticated session on a
        first deployment.

        **One code check per account at a time (BACKLOG #1943), under the same queue as the
        sign-in.** The lock check runs before the verify and the count after it, so without the
        queue every code already past the check when the lock is set is still verified. The key is
        the account's username, as :meth:`login` keys it, because both legs feed the second-step
        lock. Inside the queue the body re-reads the session, the account and its lock, so a queued
        attempt sees a lock or a revocation that landed while it waited.

        **The directory lookup runs BEFORE the queue, never inside it.** It is a network round
        trip, and one slow lookup held in the queue would stall every attempt queued on that
        account. It only adds a refusal and counts nothing, so running it concurrently cannot let a
        burst past the lock: the check that bounds the burst is the one inside the queue.

        The TOTP code is judged at the moment the request ARRIVED, not when it leaves the queue
        (``arrived``). Otherwise a caller who knows only the username could queue padded failures
        until the owner's live code went stale, and each stale code would count on the second-step
        counter, which that caller has no business reaching.

        A success still rotates the session inside the queue, and the rotation waits for the
        account's re-proof lock, which a directory re-proof holds across its bind. So a slow
        directory can still hold this queue through a concurrent re-proof, one success at a time."""
        arrived = totp.wall_clock()
        if not token:
            return Elevation()
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return Elevation()
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled or not user.totp_enabled:
            return Elevation()
        if await self._mfa_lock_refused(user, client=client):
            return Elevation(locked=True)
        if user.auth_provider == AuthProvider.AD.value:
            # BACKLOG #2023: a good code below renews the step-up window, so a DIRECTORY account must
            # still be in the directory before the code is even checked. Asked first, so a refusal
            # spends no TOTP step or recovery code and charges nothing to the lockout: the caller
            # did not guess wrong, the directory could not vouch for the account. This branch only
            # ADDS a refusal; a confirmed directory account meets the same lock and lockout feed.
            refusal = await self._directory_step_up_refusal(user)
            if refusal is not None:
                await self._audit(
                    "auth.mfa_failed",
                    actor=user.username,
                    detail=_json({"reason": DIRECTORY_UNCONFIRMED, "outcome": refusal}),
                    client=client,
                )
                return Elevation(directory_unconfirmed=True)
        async with self._account_credential_lock(user.username):
            # Read the session, the account and its lock again. For a directory account the lookup
            # above was a network round trip, and for any account the queue may have been a wait, so
            # what was read before either may be stale: a session revoked meanwhile would still spend
            # its code, and a lock set by the attempt ahead in the queue would go unseen.
            session = await self._store.get_session(hash_token(token))
            if session is None or session.revoked_at is not None:
                return Elevation()
            user = await self._store.get_user(session.user_id)
            if user is None or user.disabled or not user.totp_enabled:
                return Elevation()
            if await self._mfa_lock_refused(user, client=client):
                return Elevation(locked=True)
            now = time.time()
            if await self._verify_second_factor(user, code, client=client, arrived=arrived):
                # ORDER-CRITICAL: this whole three-write group lands against the OLD hash, and only
                # then does the session rotate. Moving any of them after the rotation writes NOTHING
                # and reports success — every session UPDATE but revoke/rotate is rowcount-blind.
                # The 2nd factor is now satisfied; also seed the step-up window (the session has
                # completed password + MFA) and clear the failure counter. (Initial enrollment has no
                # factor to verify, so this never fires there — keeping the enrollment step-up gate
                # honest, WP-14.)
                await self._store.mark_session_mfa_verified(hash_token(token))
                # Re-anchor the session to the address that completed the second factor (parity with
                # reauth), so an MFA-required admin who roamed clears the WP-L3-13 new-client-IP
                # signal with one credential proof rather than being forced into a separate password
                # step-up.
                await self._store.mark_session_reauthed(hash_token(token), client=client)
                await self._store.record_login_success(user.id, now=now)
                await self._audit("auth.mfa_verified", actor=user.username, client=client)
                return await self._elevated(
                    token, ceremony="mfa_verify", actor=user.username, client=client
                )
            # Wrong code: register the failure through the SAME machinery the password path uses, so
            # the per-account lockout + ACCOUNT_LOCKED notification fire on sustained MFA guessing.
            # On the SECOND-STEP counter: the caller holds a session, so it has proved the first step.
            failure = await self._register_failure(user, now, counter="second_step")
            await self._audit("auth.mfa_failed", actor=user.username, client=client)
            await self._record_lock(
                user, "second_step", failure, client=client, audit_detail=None, factor="first_step"
            )
            return Elevation()

    async def _mfa_lock_refused(self, user: UserRecord, *, client: str | None) -> bool:
        """Whether :meth:`verify_mfa` must refuse ``user`` as locked, auditing the refusal if so.

        Per-account lockout covers the SECOND factor too: a run of wrong codes locks the account, so
        MFA guessing isn't bounded only by the shared per-IP login limiter (which IP-rotation can
        sidestep). ADR 0197: this leg feeds, and is refused by, the SECOND-STEP lock only. The
        sign-in lock is the one a caller who knows only the username can set, and a session holder
        has already passed the step it guards. A locked account is refused before any verify."""
        if not user.second_step_locked(time.time()):
            return False
        await self._audit(
            "auth.mfa_failed",
            actor=user.username,
            # The shared constant, so the users:manage-only exclusion matches it exactly (#1131).
            detail=LOCKED_REFUSAL_DETAIL,
            client=client,
        )
        return True

    async def _directory_step_up_refusal(self, user: UserRecord) -> str | None:
        """Why the directory cannot vouch for directory account ``user`` before :meth:`verify_mfa`
        renews its step-up window, or ``None`` when it can (BACKLOG #2023). Called only for an AD
        row; a local account is never asked.

        Without this, an account disabled in the directory kept renewing its window with a good code
        until the reconciliation pass revoked its sessions. The engine row's ``disabled`` flag is
        only as fresh as that pass.

        **FAILS CLOSED, UNLIKE THE RECONCILER.** The reconciler REVOKES, so it fails open on an
        unreachable directory and wants two strikes for an ambiguous answer. This GRANTS, so any
        answer short of a present, enabled account refuses: absent, disabled, undetermined and
        unavailable alike. The directory step-up legs already refuse this way: ``_reauth_ad`` on a
        failed bind, and the federated step-up on ``directory_unavailable``. A refusal revokes
        nothing, so the next attempt asks again. An AD row on an engine with no directory
        configured is refused as ``not_configured``, because nothing can confirm it.

        A row with a federated binding and no ``directory_object_id`` is refused unasked. ADR 0184
        AC-5 forbids asking the directory about a bound row by its name, and it has no other key.
        An id-less row with no binding is still asked by name, as the reconciler and the Windows SSO
        sign-in ask it. A name is the weaker key (BACKLOG #1532), but it is a stronger check than
        the no lookup this path made before.
        """
        if self._ldap is None:
            return "not_configured"
        if _holds_unkeyed_federated_binding(user):
            return DIRECTORY_OBJECT_ID_MISSING
        # The reconciler's own probe, so both ask the same question by the same key, off the loop.
        probe = await self._probe_principal(user)
        if probe.outcome is reconcile.ProbeOutcome.PRESENT:
            return None
        return str(probe.outcome.value)

    async def _verify_second_factor(
        self,
        user: UserRecord,
        code: str,
        *,
        client: str | None = None,
        arrived: float | None = None,
    ) -> bool:
        """True iff ``code`` is the user's current TOTP **or** an unused recovery code (consumed on
        match). TOTP is checked first (fast, no argon2); recovery codes are argon2id-hashed and
        single-use. Codes never collide (TOTP is 6 digits; recovery codes are dashed alphanumerics).

        ``client`` is the caller's address, carried onto the recovery-code audit row and notice
        (BACKLOG #1139) so the holder can tell their own use from someone else's."""
        code = code.strip()
        if not code:
            return False
        secret = await self._store.get_totp_secret(user.id)
        if secret:
            # Clock-skew window is operator-configurable (BACKLOG #187; ASVS 6.5.5). Default
            # totp_skew_steps=0 accepts only the current 30 s step (strict, tightest replay window);
            # 1/2 is the documented opt-out restoring RFC-6238 network-delay tolerance. verify_totp_step
            # still clamps a tolerated fast-clock future code to the current step (SEC-014), so a wider
            # window never advances the single-use high-water mark past now.
            matched_step = totp.verify_totp_step(
                secret, code, window=self._settings.totp_skew_steps, now=arrived
            )
            if matched_step is not None:
                # Single-use within the step window (ASVS 6.5.1): the store advances the user's
                # highest-consumed time-step atomically, so a code captured and replayed inside its
                # ~30 s verify window resolves to a non-greater step and is rejected. Mirrors the
                # recovery-code compare-and-set; a genuine code always advances the step as time
                # moves forward, so a legitimate later login is unaffected. verify_totp_step clamps a
                # tolerated future (fast-clock) code to the CURRENT step (SEC-014), so consuming it
                # can't advance the high-water mark past now and lock the user out of their own next
                # legitimate code.
                return await self._store.consume_totp_step(user.id, matched_step)
        normalized = code.upper()  # recovery codes are minted uppercase
        real = list(await self._store.get_recovery_code_hashes(user.id))
        # ASVS 11.2.4 (BACKLOG #1149's sibling, #1167; ADR 0170). This walk used to `return` on the
        # first argon2id match, so the NUMBER of ~64 MiB verifications was a function of which code
        # was presented -- and, on the failure path, of how many codes REMAINED. Timing a single
        # failed attempt therefore leaked the user's remaining recovery-code count.
        #
        # Constant WORK, not a short-circuit: always run exactly the configured slot count, padding
        # with the same fixed dummy hash the local login leg uses, and pick the winner afterwards.
        #
        # THIS ADDS NO AMPLIFICATION CEILING, WHICH IS THE OBJECTION THE OBVIOUS FIX DESERVES AND
        # THIS ONE DOES NOT. The failure path ALREADY verified every remaining hash, so the cost here
        # is today's WORST CASE made unconditional -- bounded by `mfa_recovery_code_count` (default
        # 10, validator-capped at 50), which is the same bound that already shipped. `_argon2` also
        # holds a semaphore, so this cannot widen the concurrent-argon2 footprint either.
        slots = max(self._settings.mfa_recovery_code_count, len(real))
        matched = -1
        for i in range(slots):
            h = real[i] if i < len(real) else _DUMMY_PASSWORD_HASH
            ok = await self._argon2(verify_password, h, normalized)
            if ok and i < len(real) and matched < 0:
                matched = i  # recorded, NOT returned -- returning here restores the leak
        if matched < 0:
            return False
        # Atomic compare-and-delete: only the caller that actually removes the hash wins, so a
        # concurrent verify of the same single-use code can't double-spend it (WP-14).
        if not await self._store.consume_recovery_code_hash(user.id, real[matched]):
            # Lost the race to a concurrent verify of the SAME code. That caller removed the hash and
            # writes the records below; writing them here too would report one consumption twice.
            return False
        # BACKLOG #1139, ASVS 6.3.7. Spending a recovery code PERMANENTLY DELETES a stored
        # credential, so it is an update to the account's authentication details and earns its own
        # records. Before this the only row was the generic ``auth.mfa_verified`` the caller writes,
        # which carries no detail -- leaving a recovery-code burn byte-indistinguishable from an
        # ordinary TOTP verify, on precisely the event that usually means either the holder lost
        # their authenticator or somebody else has their codes.
        # RE-READ RATHER THAN ``len(real) - 1``. The arithmetic is off by one for every code a
        # concurrent caller spent between this method's read and its own consume, and this notice
        # exists to be acted on -- an overstated count tells the holder they have a spare they do
        # not. One extra store read, on a path that only runs when a code is actually burned.
        remaining = len(await self._store.get_recovery_code_hashes(user.id))
        await self._audit(
            "auth.mfa_recovery_code_used",
            actor=user.username,
            detail=_json({"remaining": remaining}),
            client=client,
        )
        # THE REMAINING COUNT, NEVER THE CODE OR ITS HASH. The holder needs to know a code was spent
        # and how close they are to none left; an operator gets everything else from the audit row,
        # which is stored somewhere better protected than a mailbox.
        await self._notify_security(
            RECOVERY_CODE_USED,
            username=user.username,
            email=user.notify_email,
            client=client,
            detail={"remaining": remaining},
        )
        return True

    async def disable_mfa(self, identity: Identity, *, client: str | None = None) -> None:
        """Self-service: turn off the caller's TOTP MFA (the API gates this behind step-up). Audited +
        the user is notified out-of-band (ASVS 6.3.7).

        Raises :class:`ValueError` when TOTP is the caller's LAST second factor and MFA is still
        required — the same refusal, on the same condition, as
        :meth:`delete_webauthn_credential` (ADR 0068 decision 5). BACKLOG #1022: these are two
        self-service routes to zero factors behind one step-up gate, and only one of them asked.

        This is NOT the admin escape hatch — that is :meth:`admin_reset_mfa`, which clears TOTP and
        every passkey and is deliberately unguarded. Nothing here narrows it.
        """
        user = await self._store.get_user(identity.user_id)
        if user is not None and user.totp_enabled:
            creds = await self._store.list_webauthn_credentials(identity.user_id)
            # Dropping to zero factors while MFA is required is not a lockout — it lands the user in
            # the enroll-required flow. So NEITHER self-service path is a recovery path, which is
            # precisely why both must refuse identically rather than one being an escape hatch.
            if not creds and self._mfa_required_for(
                user, identity.roles, second_factor_enrolled=False
            ):
                raise ValueError(
                    "this is your last second factor and MFA is required for your account — "
                    "enroll another factor first"
                )
        await self._store.disable_totp(identity.user_id)
        await self._audit(
            "auth.mfa_disabled",
            actor=identity.username,
            detail=_json({"scope": "self"}),
            client=client,
        )
        await self._notify_security(
            MFA_DISABLED,
            username=identity.username,
            email=user.notify_email if user is not None else None,
            client=client,
        )

    async def admin_reset_mfa(self, user_id: str, *, actor: str) -> None:
        """Admin: clear a user's MFA — TOTP **and** every WebAuthn passkey (lost authenticator + no
        recovery path; ADR 0068 extends this to credentials) — and revoke their sessions so they
        re-enroll. The always-available recovery for a locked-out passkey user. Raises
        :class:`ValueError` for an unknown user.

        **IT COVERS A DIRECTORY ACCOUNT (BACKLOG #1144).** The non-local refusal that stood here was
        true while no directory account could hold an engine factor. Once one can, keeping it would
        make enrollment a one-way door: a directory user who lost the authenticator would have no
        recovery at all, because every route that could help stands behind the factor they lost. This
        is the widest of the refusals the item names, and it is included for that reason."""
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        await self._store.disable_totp(user_id)
        removed = await self._store.delete_all_webauthn_credentials(user_id)
        await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "auth.mfa_reset",
            actor=actor,
            detail=_json(
                {
                    "user_id": user_id,
                    "username": user.username,
                    "webauthn_credentials_removed": removed,
                }
            ),
        )
        await self._notify_security(
            MFA_DISABLED, username=user.username, email=user.notify_email, detail={"reset": True}
        )

    async def mfa_status(self, identity: Identity) -> MfaStatus:
        """The caller's current MFA posture for ``GET /me/mfa``."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            return MfaStatus(
                enabled=False, enrolled_at=None, recovery_codes_remaining=0, required=False
            )
        remaining = (
            len(await self._store.get_recovery_code_hashes(identity.user_id))
            if user.totp_enabled
            else 0
        )
        webauthn_enrolled = await self._store.has_webauthn_credentials(identity.user_id)
        return MfaStatus(
            enabled=user.totp_enabled,
            enrolled_at=user.totp_enrolled_at,
            recovery_codes_remaining=remaining,
            required=self._mfa_required_for(
                user,
                identity.roles,
                second_factor_enrolled=user.totp_enabled or webauthn_enrolled,
            ),
            webauthn_enrolled=webauthn_enrolled,
        )

    # --- MFA: WebAuthn passkeys second factor (every account, WP-14b / ADR 0068) ---

    def webauthn_available(self) -> bool:
        """Whether the optional ``[webauthn]`` extra is installed (the UI hides the passkey surface
        with a message — never a crash — when it isn't)."""
        return webauthn.available()

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    #: Ceremony-miss message — names the LB-stickiness caveat so a multi-node operator can
    #: self-diagnose intermittent failures (ADR 0068 §2).
    _CEREMONY_EXPIRED = (
        "passkey ceremony expired or not found — start it again (on a multi-node deployment "
        "behind a load balancer, begin and finish must reach the same node)"
    )
    _WEBAUTHN_LABEL_MAX = 100  # matches the column cap (ADR 0068 §4)

    async def begin_webauthn_registration(
        self, identity: Identity, *, token: str, rp_id: str, rp_name: str
    ) -> str:
        """Stage a passkey registration ceremony; returns the browser creation-options JSON. The
        API gates this behind the password-only re-proof (``require_ui_reauth_only`` — WP-14: a
        stolen pre-MFA cookie must never bind an attacker's passkey). Raises :class:`ValueError`
        for an unknown account; a full challenge cache raises
        :class:`webauthn.ChallengeCacheFullError` (cause-naming, rendered legibly). Accepts a
        directory account, in parity with :meth:`begin_mfa_enrollment` and for its stated reason."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such user")
        existing = await self._store.list_webauthn_credentials(identity.user_id)
        challenge = webauthn.new_challenge()
        options = webauthn.registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user.id,
            user_name=user.username,
            challenge=challenge,
            exclude_credential_ids=[self._b64url_decode(c.credential_id) for c in existing],
        )
        self._webauthn_challenges.put((hash_token(token), "register"), user.id, challenge)
        await self._audit("auth.webauthn_enroll_started", actor=identity.username)
        return options

    async def finish_webauthn_registration(
        self,
        identity: Identity,
        response_json: str,
        *,
        label: str,
        token: str,
        client: str | None = None,
        rp_id: str,
        origin: str,
    ) -> Elevation:
        """Verify an attestation response and persist the passkey. Returns a not-``ok``
        :class:`Elevation` when the response fails verification (audited — parity with a wrong TOTP
        code); raises :class:`ValueError` for flow errors with safe, renderable messages (unknown
        account, bad label, expired ceremony, duplicate label/credential). On success the enrolling
        session is marked MFA-verified and re-keyed (exact :meth:`confirm_mfa_enrollment` parity,
        ASVS 7.2.4) — **no recovery codes are minted** (ADR 0068 decision 5). Accepts a directory
        account, for the reason :meth:`begin_mfa_enrollment` states.

        The other first-enrolment promotion leg. For a passkey-only account this and
        :meth:`finish_webauthn_assertion` are the ONLY ways a session becomes MFA-satisfied, so a
        7.2.4 build that rotated the TOTP legs alone would miss the passkey path entirely."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such user")
        label = label.strip()
        if not label or len(label) > self._WEBAUTHN_LABEL_MAX:
            raise ValueError("label must be 1-100 characters")
        pending = self._webauthn_challenges.pop((hash_token(token), "register"))
        if pending is None or pending.user_id != user.id:
            raise ValueError(self._CEREMONY_EXPIRED)
        try:
            result = webauthn.verify_registration(
                response_json=response_json,
                challenge=pending.challenge,
                rp_id=rp_id,
                origin=origin,
            )
        except webauthn.WebAuthnVerificationError:
            await self._audit(
                "auth.webauthn_failed",
                actor=identity.username,
                detail=_json({"phase": "enroll"}),
                client=client,
            )
            return Elevation()
        credential_id_hash = hash_bytes(result.credential_id)
        if await self._store.get_webauthn_credential(credential_id_hash) is not None:
            raise ValueError("this passkey is already enrolled")
        now = time.time()
        cred = WebAuthnCredential(
            credential_id_hash=credential_id_hash,
            credential_id=self._b64url_encode(result.credential_id),
            user_id=user.id,
            rp_id=rp_id,
            public_key=self._b64url_encode(result.public_key),
            sign_count=result.sign_count,
            transports=result.transports,
            device_type=result.device_type,
            backed_up=result.backed_up,
            label=label,
            aaguid=result.aaguid,
            created_at=now,
        )
        try:
            await self._store.add_webauthn_credential(cred)
        except Exception as exc:
            # The concurrent duplicate-label race (ADR 0068 §4): each backend raises its own
            # integrity class (sqlite3.IntegrityError / asyncpg UniqueViolationError / pyodbc
            # IntegrityError) — rendered as the same legible error as a pre-checked duplicate.
            if not _is_integrity_refusal(exc):
                raise
            # BACKLOG #1807: the same classes carry the user_id foreign-key refusal, raised when the
            # account is deleted mid-enrolment. Told apart by re-reading the account, never by the
            # driver's message: that text can echo the operator-chosen label.
            if await self._store.get_user(user.id) is None:
                raise ValueError("no such user") from exc
            raise ValueError("label already in use") from exc
        # Parity with confirm_mfa_enrollment: the enrolling session is now MFA-verified (it just
        # proved possession of the freshly-bound authenticator). Stamped against the OLD hash, then
        # rotated — the reverse order writes nothing and still reports success.
        await self._store.mark_session_mfa_verified(hash_token(token))
        elevation = await self._elevated(
            token, ceremony="webauthn_enroll", actor=identity.username, client=client
        )
        await self._audit(
            "auth.webauthn_enrolled",
            actor=identity.username,
            detail=_json({"label": label}),
            client=client,
        )
        await self._notify_security(
            MFA_ENABLED, username=user.username, email=user.notify_email, client=client
        )
        return elevation

    async def begin_webauthn_assertion(self, token: str | None, *, rp_id: str) -> str | None:
        """Stage an assertion ceremony for the caller's session; returns the browser request-options
        JSON, or ``None`` when the user has no credentials minted under the CURRENT ``rp_id``
        (an origin migration renders old credentials visibly unusable — ADR 0068 §7). Allowed for
        MFA-pending sessions: the assertion is exactly what proves the second factor."""
        if not token:
            return None
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return None
        creds = [
            c
            for c in await self._store.list_webauthn_credentials(session.user_id)
            if c.rp_id == rp_id
        ]
        if not creds:
            return None
        challenge = webauthn.new_challenge()
        options = webauthn.assertion_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credential_ids=[self._b64url_decode(c.credential_id) for c in creds],
        )
        self._webauthn_challenges.put((hash_token(token), "assert"), session.user_id, challenge)
        return options

    async def finish_webauthn_assertion(
        self,
        token: str | None,
        response_json: str,
        *,
        client: str | None = None,
        rp_id: str,
        origin: str,
    ) -> Elevation:
        """Verify an assertion for the caller's session; on success mark the session's second
        factor satisfied and re-key the session (ASVS 7.2.4) — **`mfa_verified` ONLY** (ADR 0068
        decision 1: ``reauth_at`` + the WP-L3-13 client re-anchor come from the password leg of
        ``POST /ui/reauth``, never from the assertion — the loop-class defense). Returns a
        not-``ok`` :class:`Elevation` (never raises) for any invalid input, always audited.

        For a passkey-only account this is the ONLY leg of ``POST /ui/mfa``, so the rotation here is
        what keeps the 7.2.4 claim honest rather than TOTP-shaped. **Deliberate divergence from :meth:`verify_mfa`** (recorded in ADR
        0068): assertion failures do NOT feed ``_register_failure`` — signatures are not guessable
        secrets and a flaky authenticator must not lock the account; abuse is bounded by the
        route's ``allow_reauth_attempt`` gate + cookie-holder-only reachability + these audits.

        A successful assertion DOES clear the failure counter (BACKLOG #1638). That is the other
        direction and the divergence does not cover it — see the call site."""
        if not token:
            return Elevation()
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return Elevation()
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled:
            return Elevation()
        now = time.time()
        # A locked account is refused BEFORE any verify (verify_mfa parity). ADR 0197: the SECOND-STEP
        # lock, as on verify_mfa; the sign-in lock guards the step this session already passed.
        if user.second_step_locked(now):
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                # The shared constant, so the users:manage-only exclusion matches it exactly (#1131).
                detail=LOCKED_REFUSAL_DETAIL,
                client=client,
            )
            return Elevation()
        pending = self._webauthn_challenges.pop((hash_token(token), "assert"))
        if pending is None or pending.user_id != user.id:
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"reason": "expired"}),
                client=client,
            )
            return Elevation()
        try:
            raw_id = webauthn.credential_id_from_response(response_json)
        except webauthn.WebAuthnVerificationError:
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"reason": "malformed"}),
                client=client,
            )
            return Elevation()
        cred = await self._store.get_webauthn_credential(hash_bytes(raw_id))
        if cred is None or cred.user_id != user.id or cred.rp_id != rp_id:
            # Unknown credential, another user's, or minted under a different origin — same
            # refusal either way (no oracle distinguishing the three).
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"reason": "unknown_credential"}),
                client=client,
            )
            return Elevation()
        try:
            new_count = webauthn.verify_assertion(
                response_json=response_json,
                challenge=pending.challenge,
                rp_id=rp_id,
                origin=origin,
                public_key=self._b64url_decode(cred.public_key),
                current_sign_count=cred.sign_count,
            )
        except webauthn.StoredKeyRefusedError:
            # BACKLOG #1963. The STORED key breaks the registration rule (ADR 0068, 2026-09-24
            # amendment), so this passkey will never sign in again. Audited as a bad signature, an
            # admin could not see why a passkey-only user is stuck. The reason goes to the audit
            # row and the log only; the caller gets the same refusal as any failed assertion. The
            # detail carries a fixed slug and never the refusal text, which can quote the key.
            _log.warning(
                "passkey sign-in refused for %s: stored credential %r fails the registration key "
                "check and must be registered again",
                user.username,
                cred.label,
            )
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"reason": "stored_key_refused", "label": cred.label}),
                client=client,
            )
            return Elevation()
        except webauthn.WebAuthnVerificationError as exc:
            # py_webauthn's own counter-regression rejection IS a clone signal (ADR 0068 §4).
            clone = "sign count" in str(exc).lower()
            await self._audit(
                "auth.webauthn_clone_suspected" if clone else "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"label": cred.label}) if clone else None,
                client=client,
            )
            return Elevation()
        if not await self._store.update_webauthn_sign_count(
            cred.credential_id_hash, expected=cred.sign_count, new=new_count, used_at=now
        ):
            # CAS miss: a concurrent assertion consumed the same counter — the clone signal.
            await self._audit(
                "auth.webauthn_clone_suspected",
                actor=user.username,
                detail=_json({"label": cred.label}),
                client=client,
            )
            return Elevation()
        await self._store.mark_session_mfa_verified(hash_token(token))
        # BACKLOG #1638. A SUCCESSFUL ASSERTION CLEARS THE FAILURE COUNTER, and that is NOT a reversal
        # of the ADR 0068 divergence recorded above. That divergence is about not FEEDING
        # ``_register_failure`` on assertion failure, and it stands. It says nothing about success,
        # and the counter has to be cleared by whichever leg completes the authentication: since
        # #1638 the password step no longer clears it, so without this line a passkey-only account's
        # password failures would shed only by waiting the lockout window out.
        #
        # Sited before ``_elevated`` rotates the session for the same reason the group in
        # ``verify_mfa`` is -- though this write targets the USER row, not the session, so it is
        # ordering by parity rather than by necessity.
        await self._store.record_login_success(user.id, now=now)
        await self._audit("auth.webauthn_verified", actor=user.username, client=client)
        return await self._elevated(
            token, ceremony="webauthn_assert", actor=user.username, client=client
        )

    async def delete_webauthn_credential(
        self, identity: Identity, credential_id_hash: str, *, client: str | None = None
    ) -> bool:
        """Self-service: remove one of the caller's own passkeys (the API gates this behind the
        full step-up). Returns ``False`` for an unknown/foreign credential (self-scoped). Raises
        :class:`ValueError` when this is the last remaining second factor while MFA is still
        required — "enroll another factor first" (ADR 0068 decision 5).

        EVERY successful removal notifies out of band (ASVS 6.3.7, BACKLOG #1139), on the event type
        that describes the resulting state: MFA_DISABLED where this was the last factor and MFA was
        not required, MFA_CREDENTIAL_REMOVED where at least one other factor remains."""
        user = await self._store.get_user(identity.user_id)
        if user is None:
            return False
        creds = await self._store.list_webauthn_credentials(identity.user_id)
        target = next((c for c in creds if c.credential_id_hash == credential_id_hash), None)
        if target is None:
            return False
        last_second_factor = len(creds) == 1 and not user.totp_enabled
        if last_second_factor and self._mfa_required_for(
            user, identity.roles, second_factor_enrolled=False
        ):
            raise ValueError(
                "this is your last second factor and MFA is required for your account — "
                "enroll another factor first"
            )
        if not await self._store.delete_webauthn_credential(identity.user_id, credential_id_hash):
            return False  # pragma: no cover - raced with a concurrent delete of the same row
        await self._audit(
            "auth.webauthn_removed",
            actor=identity.username,
            detail=_json({"label": target.label}),
            client=client,
        )
        # BACKLOG #1139 (ASVS 6.3.7): EVERY removal notifies, not only the last one. This used to
        # emit under ``if last_second_factor`` alone, so removing a passkey while another factor
        # remained wrote the audit row above and nothing else — leaving the audit log as the sole
        # record of precisely the removal someone holding a stolen session makes, stripping the
        # holder's own authenticator while keeping their own. Losing one of several factors is still
        # an update to the account's authentication details, which is the requirement's own verb.
        #
        # TWO EVENT TYPES RATHER THAN ONE CARRYING A FLAG, because they are different statements
        # about the resulting state. MFA_DISABLED asserts the account has no second factor left;
        # emitting it while another passkey stands would be false, and consumers already read it as
        # that state change. The last-factor arm is therefore untouched.
        #
        # WHICH ARM IS DECIDED BY A READ TAKEN AFTER THE DELETE, not by ``last_second_factor``. That
        # flag comes from the read above, so two concurrent removals of an account's only two
        # passkeys would each see one left and each send the "another factor remains" wording to an
        # account that now has none. The flag still gates the refusal above, which is about intent.
        after = await self._store.get_user(identity.user_id)
        factor_remains = bool(
            await self._store.list_webauthn_credentials(identity.user_id)
        ) or bool(after is not None and after.totp_enabled)
        if not factor_remains:
            await self._notify_security(
                MFA_DISABLED,
                username=user.username,
                email=user.notify_email,
                client=client,
                detail={"factor": "webauthn"},
            )
        else:
            # No remaining-factor COUNT in the detail. ``len(creds) - 1`` is off by one for every
            # credential a concurrent caller removed between this method's read and its own delete,
            # and the recovery-code sibling pays a re-read to avoid exactly that. Here the count buys
            # the reader nothing the fixed wording does not already give them, so it is not carried
            # rather than carried wrong.
            await self._notify_security(
                MFA_CREDENTIAL_REMOVED,
                username=user.username,
                email=user.notify_email,
                client=client,
                detail={"factor": "webauthn"},
            )
        return True

    # --- administration (audited) -------------------------------------------

    @property
    def store(self) -> AdminStore:
        """Read access to the backing store for admin list/read endpoints (users + audit)."""
        return self._store

    async def security_events_for(self, username: str, *, limit: int = 100) -> list[dict[str, Any]]:
        """The caller's own security-event history (audited ``auth.*`` actions, most-recent-first) for
        ``GET /me/security-events`` — normalized to plain dicts so the API doesn't see backend Row
        types. PHI-free (the audit ``detail`` carries metadata only)."""
        rows = await self._store.security_events_for_user(username, limit=limit)
        return [
            {"ts": float(r["ts"]), "action": str(r["action"]), "detail": r["detail"]} for r in rows
        ]

    async def create_local_user(
        self,
        *,
        username: str,
        password: str,
        display_name: str | None,
        email: str | None,
        roles: Sequence[str],
        actor: str,
        client: str | None = None,
    ) -> str:
        """Create a local account with an admin-set, must-change initial password.

        ``client`` is the creating administrator's address. It lands on the ``user.created`` row
        (ADR 0150, BACKLOG #315), so the step that can mint a second dual-control approver is
        attributed to a host like the approval rows are. The new account's notification address is
        told it was created (``ACCOUNT_CREATED``).

        **``email`` IS CHECKED BEFORE ANYTHING IS WRITTEN (BACKLOG #2018, ASVS 6.3.7).** It seeds
        ``notify_email``, so it must pass the check an administrator's explicit ``notify_email``
        change passes (:func:`_require_single_mailbox`). A blank or malformed value raises
        :class:`InvalidNotifyEmail`. ``None`` is still accepted here, for internal callers: both admin
        surfaces require an address before they reach this method (``UserCreateRequest.email``).

        Raises :class:`UsernameTaken` when a concurrent create took ``username`` after the caller's
        own check (BACKLOG #1808)."""
        if email is not None:
            if not email.strip():
                raise InvalidNotifyEmail(
                    "a new account needs a notification address, such as name@example.org"
                )
            email = _require_single_mailbox(email)
        user_id = uuid4().hex
        # Hashed before the insert so the handler below covers the store call alone.
        password_hash = await self._argon2(hash_password, password)
        try:
            await self._store.create_user(
                user_id=user_id,
                username=username,
                auth_provider=AuthProvider.LOCAL.value,
                display_name=display_name,
                email=email,
                password_hash=password_hash,
                # Admin-set the credential is a one-time temp: force rotation on first login so the
                # operator never sets a lasting password the user keeps (ASVS 6.4.6 / WP-L3-12).
                must_change_password=True,
            )
        except Exception as exc:
            if not _is_integrity_refusal(exc):
                raise
            # Re-read rather than assume the name index fired: only a row now holding the name
            # makes this a username conflict. Anything else re-raises untouched.
            if await self._store.get_user_by_username(username) is None:
                raise
            raise UsernameTaken(USERNAME_TAKEN) from exc
        await self._store.set_user_roles(user_id, roles, assigned_by=actor)
        await self._audit(
            "user.created",
            actor=actor,
            detail=_json({"username": username, "roles": list(roles)}),
            client=client,
        )
        # The address create_user seeded. None means nobody to tell yet: the holder is asked for one
        # at first sign-in (the NOTIFY_EMAIL_SET path) rather than told about this afterwards. Only an
        # internal caller reaches that arm now; both admin surfaces require an address (#2018).
        notify = seed_notify_email(email)
        if notify:
            await self._notify_security(
                ACCOUNT_CREATED,
                username=username,
                email=notify,
                # No `client`: the address is admin-typed and unverified, and no other admin-initiated
                # notice sends the administrator's address to the account's mailbox.
                detail={"roles": list(roles)},
            )
        return user_id

    async def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None,
        email: str | None,
        disabled: bool | None,
        actor: str,
        notify_email: str | None = None,
    ) -> None:
        """Apply an administrator's edit to an account's profile, disabled flag and notification
        address.

        **THE NOTIFICATION ADDRESS MOVES ONLY WHEN ``notify_email`` NAMES A DIFFERENT ONE (BACKLOG
        #1139, ADR 0182 Amendment A).** ``None`` leaves it alone, and the profile ``email`` never
        touches it. It used to: any non-blank ``email`` was copied in, and both admin surfaces post
        the stored profile email back on every save. So a display-name edit copied the directory's
        ``mail`` into the engine-owned column with no notice, and filled a blank one from it.

        The stored address, posted back, is a no-op and is not re-checked, so an address another
        writer stored cannot block an unrelated save. Any other value is checked before anything is
        written (:func:`_require_single_mailbox`), so a refusal leaves the whole save undone. Raises
        :class:`InvalidNotifyEmail` for it.
        """
        before = await self._store.get_user(user_id)  # capture old email/disabled for notifications
        stored_notify = ((before.notify_email if before is not None else None) or "").strip()
        new_notify: str | None = None
        if notify_email is not None and (
            not notify_email.strip() or notify_email.strip() != stored_notify
        ):
            new_notify = _require_single_mailbox(notify_email)
        await self._store.update_user_profile(user_id, display_name=display_name, email=email)
        # The profile write above never names `notify_email`: it is the same call `_upsert_ad_user`
        # makes, and on a directory account `email` is the directory's.
        if before is not None and new_notify is not None:
            # AUDITED BEFORE THE WRITE, as admin-set-notify-email is. Of the two orders that can
            # leave the row and the column disagreeing, an unaudited move is the worse. The row
            # holds no address, as every other write of the column records it.
            await self._audit(
                "user.notify_email_changed",
                actor=actor,
                detail=_json({"user_id": user_id, "had_address": bool(stored_notify)}),
            )
            await self._store.set_user_notify_email(user_id, email=new_notify)
            if stored_notify:
                # Tell the address notices are moving AWAY from. It is the one the legitimate holder
                # still reads when the move was hostile or mistaken (ADR 0182, option 3).
                await self._notify_security(
                    EMAIL_CHANGED,
                    username=before.username,
                    email=stored_notify,
                    detail={"new_email": new_notify, "field": "notify_email"},
                )
            else:
                # No earlier address, so nobody else to tell: the notice goes to the one just set,
                # as the holder's own fill does (`fill_own_notify_email`).
                await self._notify_security(
                    NOTIFY_EMAIL_SET,
                    username=before.username,
                    email=new_notify,
                    detail={"set_by": "administrator"},
                )
        if disabled is not None:
            await self._store.set_user_disabled(user_id, disabled=disabled)
            if disabled:
                await self._store.revoke_user_sessions(user_id)
        await self._audit("user.updated", actor=actor, detail=_json({"user_id": user_id}))
        # The rest of this save's notices go where the account's notices went before it, so a move
        # in the same save cannot take them away from the previous holder. An account that had no
        # address is the exception: the one this save set is then the only one reachable.
        notice_to = stored_notify or new_notify
        if before is not None:
            if email != before.email:
                # Notify the OLD address — so the legitimate owner is alerted even if an attacker (or a
                # mistaken admin) repointed the account's email to one they control (ASVS 6.3.7).
                #
                # BACKLOG #1139: this guard used to also require `email is not None`, which silently
                # skipped the CLEAR. update_user_profile's write is unconditional, so a null removes
                # the stored address — and that is the ONE update to an account's authentication
                # details that must be announced, because it is the last moment the old address is
                # reachable. After it, SecurityEventNotifier.notify returns early on the empty address
                # and the account is structurally excluded from every later notice.
                #
                # `email` is the intended FINAL state here, not a patch fragment: PATCH /users/{id}
                # resolves an omitted field to the account's current value before calling (see
                # api/auth_routes.py's admin_user_update), and the console form posts the whole
                # profile with a blanked field as None (messagefoundry_webconsole/routes/admin.py).
                # So `email != before.email` is exactly "the stored address changed", with no
                # partial-update ambiguity to inherit — which is why dropping the conjunct is safe
                # rather than merely wider.
                await self._notify_security(
                    EMAIL_CHANGED,
                    username=before.username,
                    email=notice_to,
                    detail={"new_email": email},
                )
            if disabled and not before.disabled:
                await self._notify_security(
                    ACCOUNT_DISABLED, username=before.username, email=notice_to
                )

    async def delete_user(self, user_id: str, *, actor: str) -> None:
        await self._store.delete_user(user_id)
        await self._audit("user.deleted", actor=actor, detail=_json({"user_id": user_id}))

    async def set_roles(self, user_id: str, roles: Sequence[str], *, actor: str) -> None:
        user = await self._store.get_user(user_id)  # for the notification address
        await self._store.set_user_roles(user_id, roles, assigned_by=actor)
        await self._store.revoke_user_sessions(user_id)  # re-resolve permissions on next login
        await self._audit(
            "user.roles_changed",
            actor=actor,
            detail=_json({"user_id": user_id, "roles": list(roles)}),
        )
        if user is not None:
            await self._notify_security(
                ROLES_CHANGED,
                username=user.username,
                email=user.notify_email,
                detail={"roles": list(roles)},
            )

    # --- custom RBAC roles (ADR 0045, gated by USERS_MANAGE) -----------------

    async def list_custom_roles(self) -> list[CustomRoleInfo]:
        """Every admin-defined custom role with its (defensively-decoded) permission set. Built-in rows
        are excluded — they resolve from ``BUILTIN_ROLE_PERMISSIONS``, not the ``permissions`` column."""
        out: list[CustomRoleInfo] = []
        for row in await self._store.list_roles():
            if _row_builtin(row):
                continue
            perms = decode_custom_role_permissions(row["permissions"])
            out.append(
                CustomRoleInfo(
                    id=str(row["id"]),
                    display_name=str(row["display_name"]),
                    description=(None if row["description"] is None else str(row["description"])),
                    permissions=frozenset(perms),
                )
            )
        return out

    async def create_custom_role(
        self,
        *,
        display_name: str,
        description: str | None,
        permissions: Sequence[str],
        actor: str,
    ) -> CustomRoleInfo:
        """Define a new custom role: a named SUBSET of the existing ``Permission`` catalog (ADR 0045).

        The permission set is validated (recognized catalog perms only, non-empty, no carved-out
        escalation primitive); a :class:`CustomRoleError` is raised otherwise. The role id is namespaced
        with ``custom:`` so it can never collide with a built-in. Audited (records the permission
        *names*, never PHI)."""
        perms = validate_custom_role_permissions(permissions)  # raises CustomRoleError
        role_id = CUSTOM_ROLE_ID_PREFIX + uuid4().hex
        await self._store.upsert_role(
            role_id=role_id,
            display_name=display_name,
            description=description,
            builtin=False,
            permissions=_json([p.value for p in perms]),
        )
        await self._audit(
            "role.created",
            actor=actor,
            detail=_json({"role_id": role_id, "permissions": [p.value for p in perms]}),
        )
        return CustomRoleInfo(
            id=role_id,
            display_name=display_name,
            description=description,
            permissions=frozenset(perms),
        )

    async def update_custom_role(
        self,
        role_id: str,
        *,
        display_name: str,
        description: str | None,
        permissions: Sequence[str],
        actor: str,
    ) -> CustomRoleInfo:
        """Edit a custom role's name/description/permission set. Validates the new permission subset and
        rejects editing a built-in (or unknown) role. A permission *reduction* takes effect immediately:
        every user holding the role has their live sessions revoked so a narrowed set can't linger on an
        active token (ADR 0045 D3, mirroring :meth:`set_roles`). Audited. Raises :class:`ValueError` for
        an unknown/built-in role and :class:`CustomRoleError` for an invalid permission set."""
        existing = await self._store.get_role(role_id)
        if existing is None or _row_builtin(existing):
            raise ValueError("no such custom role")
        perms = validate_custom_role_permissions(permissions)  # raises CustomRoleError
        await self._store.upsert_role(
            role_id=role_id,
            display_name=display_name,
            description=description,
            builtin=False,
            permissions=_json([p.value for p in perms]),
        )
        await self._revoke_sessions_for_role(role_id)
        await self._audit(
            "role.updated",
            actor=actor,
            detail=_json({"role_id": role_id, "permissions": [p.value for p in perms]}),
        )
        return CustomRoleInfo(
            id=role_id,
            display_name=display_name,
            description=description,
            permissions=frozenset(perms),
        )

    async def delete_custom_role(self, role_id: str, *, actor: str) -> None:
        """Delete a custom role; its user/AD-group assignments are removed in the same transaction, and
        every assigned user's live sessions are revoked so the now-gone permissions don't linger on an
        active token. Raises :class:`ValueError` for an unknown or built-in role. Audited."""
        existing = await self._store.get_role(role_id)
        if existing is None or _row_builtin(existing):
            raise ValueError("no such custom role")
        await self._revoke_sessions_for_role(role_id)  # before the rows are gone
        await self._store.delete_custom_role(role_id)
        await self._audit("role.deleted", actor=actor, detail=_json({"role_id": role_id}))

    async def _revoke_sessions_for_role(self, role_id: str) -> None:
        """Revoke the live sessions of every user currently holding ``role_id`` so a permission
        reduction / role deletion re-resolves on their next request (ADR 0045 D3)."""
        for user in await self._store.list_users():
            if role_id in await self._store.get_user_role_ids(user.id):
                await self._store.revoke_user_sessions(user.id)

    async def admin_reset_password(self, user_id: str, *, actor: str) -> IssuedCredential:
        """Admin-initiated password reset (ASVS 6.4.6 / WP-L3-12). Generate a CSPRNG one-time password
        through the active policy, set it with ``must_change_password`` (forces a change on first
        login), and revoke the user's sessions. Returns the one-time credential **once** so the caller
        can convey it out-of-band — the administrator never sets a lasting password the user keeps. The
        affected user is also notified out-of-band by email. Raises :class:`ValueError` for an unknown
        user or a non-local (AD) account; the API maps these to 4xx.

        BACKLOG #1141 (ASVS 6.4.5) is why this returns an :class:`IssuedCredential` rather than the
        bare password: the renewal instruction for an expiring mechanism has to travel WITH the
        mechanism, and this return value is the only thing that reaches the issuing administrator.
        ``expires_at`` is read back from the STORED ``password_changed_at`` the write above just
        stamped rather than from a fresh clock, so the surfaced instant is the one the login gate will actually refuse on.
        """
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        if user.auth_provider != AuthProvider.LOCAL.value:
            raise ValueError("only local users have a password to reset")
        temp = self._generate_policy_password(username=user.username)
        await self._store.set_password(
            user_id,
            password_hash=await self._argon2(hash_password, temp),
            must_change_password=True,
        )
        await self._store.revoke_user_sessions(user_id)  # invalidate any live sessions on reset
        await self._audit(
            "auth.password_reset",
            actor=actor,
            detail=_json({"user_id": user_id, "username": user.username}),
        )
        stamped = await self._store.get_user(user_id)
        expires_at = self.initial_credential_deadline(
            None if stamped is None else stamped.password_changed_at
        )
        # BACKLOG #1141 slice 2: the notice goes to the HOLDER, the one party the return value never
        # reaches, so it carries the same instant. It is sent after the read-back so the two cannot
        # differ; sending it first left the only holder-facing surface with no deadline at all. A
        # DISABLED account gets no deadline line: it tells the holder to sign in, and they cannot.
        await self._notify_security(
            PASSWORD_RESET,
            username=user.username,
            email=user.notify_email,
            detail=None if expires_at is None or user.disabled else {"expires_at": expires_at},
        )
        return IssuedCredential(password=temp, expires_at=expires_at)

    async def remind_expiring_initial_credential(
        self, user: UserRecord, *, deadline: float
    ) -> None:
        """Tell the holder of an unreplaced temporary password, and the administrator who issued it,
        that it stops working at ``deadline`` (ASVS 6.4.5, BACKLOG #2007).

        The API lifespan's reminder pass calls this once per credential, beside its ``[alerts]``
        operator reminder, and its ``warned`` map is what keeps each notice to one per credential per
        engine process. A restart inside the warn window therefore reminds again, as the operator
        alert does; a mark that outlived the process would be a second once-only mechanism. This
        method keeps no state of its own and makes one attempt: a failed read is logged and not
        retried, because a retry would repeat the notices that did go out. It never has the
        password, so no notice can carry it.

        The holder's notice goes to the account's own ``notify_email``. The issuer's goes to the
        issuing administrator's ``notify_email``, and names the holder's account. Who the issuer is
        comes from :meth:`_temporary_credential_issuer`. When it cannot be told reliably, the issuer is
        not told, and one INFO line says why, naming only the holder's username. Each reminder is
        audited first, with its recipient as the actor, so it is in that account's
        ``/me/security-events`` feed even when no mail can go, including on a site with no notifier.
        A directory account has no temporary password here, so it gets nothing. Delivery is
        best-effort, as for every security notice: :meth:`_notify_security` logs and swallows a
        failure.

        ``user`` comes from a pass that read every account first, so the row is read again here. A
        credential claimed, replaced or disabled since that read is not reminded about."""
        fresh = await self._store.get_user(user.id)
        if (
            fresh is None
            or fresh.disabled
            or fresh.auth_provider != AuthProvider.LOCAL.value
            or not fresh.must_change_password
            or self.initial_credential_deadline(fresh.password_changed_at) != deadline
        ):
            return
        user = fresh
        await self._audit(
            _REMINDER_HOLDER_ACTION,
            actor=user.username,
            detail=_json({"user_id": user.id, "expires_at": deadline}),
        )
        await self._notify_security(
            TEMPORARY_CREDENTIAL_EXPIRING,
            username=user.username,
            email=user.notify_email,
            detail={"expires_at": deadline},
        )
        issuer, reason = await self._temporary_credential_issuer(user)
        if issuer is None:
            _log.info(
                "temporary credential reminder for %s: the issuing administrator was not told, "
                "because %s",
                user.username,
                reason,
            )
            return
        await self._audit(
            _REMINDER_ISSUER_ACTION,
            actor=issuer.username,
            detail=_json({"holder": user.username, "user_id": user.id, "expires_at": deadline}),
        )
        await self._notify_security(
            TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
            username=issuer.username,
            email=issuer.notify_email,
            detail={"expires_at": deadline, "holder": user.username},
        )

    async def _temporary_credential_issuer(self, user: UserRecord) -> tuple[UserRecord | None, str]:
        """The account that issued ``user``'s current temporary password and can still act on a
        reminder, or ``None`` with a short reason (BACKLOG #2007).

        Read from the AUDIT row the issuing path wrote, and not from ``user_roles.assigned_by``:
        ``set_user_roles`` rewrites every row of the account on each role change, so that column
        names whoever last set the roles, not whoever issued the credential. Two paths issue one:
        :meth:`create_local_user` writes ``user.created``, and :meth:`admin_reset_password` writes
        ``auth.password_reset``. Each stamps ``password_changed_at`` just before its row, so the row
        is found in a short window after the stamp; ``_ISSUE_ROW_*`` states the window.

        The matching rows in that window must all name ONE actor. None, or two different actors,
        is reported as unresolved rather than guessed: two administrators resetting the same account
        moments apart would otherwise name the wrong one. The actor is a USERNAME, and a username
        can move, so the account it names now must also be the one that wrote the row. It must have
        existed when the row was written, and no directory rename may have landed the name on an
        account since. It must also be enabled, not be the holder, and still hold
        ``users:manage``, the permission a reset needs, since the notice asks it to reset again. A
        failed read, of the audit rows or of the account, is logged and reported as unresolved
        rather than raised."""
        stamp = user.password_changed_at
        if stamp is None:
            return None, "the credential carries no issue time"
        actors: set[str] = set()
        issued_at = stamp
        ids = {"username": user.username, "user_id": user.id}
        try:
            for action, key in _ISSUE_ROW_KEYS.items():
                rows = await self._store.list_audit(
                    action=action,
                    since=stamp - _ISSUE_ROW_EARLY_SECONDS,
                    until=stamp + _ISSUE_ROW_LATE_SECONDS,
                    limit=_ISSUE_ROW_PAGE,
                )
                if len(rows) >= _ISSUE_ROW_PAGE:
                    return None, "too many accounts were issued credentials at that time to tell"
                for row in rows:
                    try:
                        detail = json.loads(row["detail"] or "{}")
                    except (TypeError, ValueError):
                        # Said, not swallowed: an unreadable issuing row would otherwise read as
                        # "no audit row" with nothing pointing at it.
                        _log.warning(
                            "temporary credential reminder: skipped an unreadable %s audit row "
                            "while looking for who issued %s's credential",
                            action,
                            user.username,
                        )
                        continue
                    if isinstance(detail, dict) and detail.get(key) == ids[key]:
                        actors.add(str(row["actor"] or ""))
                        # The earliest matching row, so the account must predate all of them.
                        issued_at = min(issued_at, float(row["ts"]))
            if not actors:
                return None, "no audit row records who issued it"
            if "" in actors:
                return None, "an issuing audit row names no actor"
            if len(actors) != 1:
                return None, "more than one administrator could have issued it"
            (actor,) = actors
            issuer = await self._store.get_user_by_username(actor)
            if issuer is None or issuer.created_at > issued_at:
                # The second test: the name was freed and taken again after the row was written.
                return None, "the issuing actor names no current account"
            if await self._store.list_audit(
                action="auth.ad_username_refreshed", actor=actor, since=issued_at, limit=1
            ):
                # A directory rename moved this name onto an account after the row was written.
                return None, "the issuing name has moved to an account since"
            if issuer.id == user.id:
                return None, "the holder issued it"
            if issuer.disabled:
                return None, "the issuing account is disabled"
            if not (await self._build_identity(issuer)).has(Permission.USERS_MANAGE):
                return None, "the issuing account no longer holds users:manage"
        except Exception:
            # Broad for the reason the first-seen login-address read gives: each backend raises its
            # own driver's errors, and ``auth/`` may import none of them.
            _log.exception(
                "temporary credential reminder: the issuer read failed for %s", user.username
            )
            return None, "the issuer read failed"
        return issuer, ""

    async def unbind_federated_subject(
        self,
        user_id: str,
        *,
        expected_issuer: str | None,
        expected_subject: str | None,
        actor: str,
    ) -> int:
        """Admin: remove an account's federated ``(issuer, sub)`` binding and revoke every live
        session it holds (BACKLOG #1474). Returns the number of sessions revoked.

        ``expected_issuer`` and ``expected_subject`` are the pair the caller saw. The store removes
        the binding only if the row still holds exactly that pair, and otherwise writes nothing and
        this raises :class:`FederatedBindingChanged` (BACKLOG #2026).

        The account keeps ``auth_provider='ad'``. A federated account is an AD row carrying an extra
        pair, so a NULL pair is exactly the state every AD account is in before its first federated
        login: a coherent directory account, still swept by :meth:`reconcile_directory_sessions`.
        A federated login presenting the old subject afterwards is refused as unbound (ADR 0184
        AC-4), and so is any other: only :meth:`bind_federated_subject` gives the account a subject
        again. **Until BACKLOG #1143 this said the next federated login binds whatever subject then
        presents.** That was true, and it was why no unbind caller could ship before the refusal.

        The store clears the pair and revokes the sessions in one transaction, so a session issued
        under the old binding cannot outlive it. The audit row carries the prior pair and the
        revoked count, so an operator can SEE that the unbind killed sessions rather than infer it.

        **EVERY FIELD IN THAT ROW COMES OUT OF THE UNBIND'S OWN TRANSACTION**, which is why nothing
        here reads the account first. A ``get_user`` above would be a separate read, and a rebind
        landing between it and the write would produce an audit row naming a binding this call never
        cleared — a false record of who was unbound, which is worse than none.

        Raises :class:`ValueError` for an unknown user, and for an account with no binding: an
        unbind of nothing would still revoke sessions, and a no-op should not sign anybody out. The
        store decides both, inside the transaction, and writes nothing in either case.
        """
        outcome = await self._store.clear_user_federated_subject(
            user_id, expected_issuer=expected_issuer, expected_subject=expected_subject
        )
        if outcome is None:
            raise ValueError("no such user")
        if outcome.changed:
            raise FederatedBindingChanged()
        # BOTH halves, matching the store's own predicate: either one set means the row had
        # something to clear and the store cleared it, so raising here would report "nothing to
        # remove" about a write that just happened.
        if outcome.issuer is None and outcome.subject is None:
            raise ValueError("the account has no federated binding to remove")
        await self._record_federated_unbind(user_id, outcome, actor=actor)
        return outcome.sessions_revoked

    async def _record_federated_unbind(
        self, user_id: str, outcome: FederatedUnbind, *, actor: str
    ) -> None:
        """Audit a cleared binding from the clear's own record, and tell the holder (BACKLOG #1143).

        Shared by the unbind and by a rebind whose second write failed after its clear committed, so
        a binding never disappears without an ``auth.federated_subject_unbound`` row. The notice is
        ASVS 6.3.7, as on the bind: the holder's federated sign-in stopped working and their
        sessions ended. The account is read for its address only AFTER the clear, and only for that;
        every audited field comes out of the clear's transaction.
        """
        await self._audit(
            "auth.federated_subject_unbound",
            actor=actor,
            detail=_json(
                {
                    "user_id": user_id,
                    "username": outcome.username,
                    "issuer": outcome.issuer,
                    "subject": outcome.subject,
                    "sessions_revoked": outcome.sessions_revoked,
                }
            ),
        )
        holder = await self._store.get_user(user_id)
        await self._notify_security(
            FEDERATED_IDENTITY_UNBOUND,
            username=outcome.username,
            email=None if holder is None else holder.notify_email,
            detail={"issuer": outcome.issuer},
        )

    async def bind_federated_subject(
        self,
        user_id: str,
        subject: str,
        *,
        expected_issuer: str | None,
        expected_subject: str | None,
        actor: str,
    ) -> FederatedBinding:
        """Admin: bind an account to a federated ``sub`` under the configured issuer, or rebind it
        to a new one (BACKLOG #1143 / #295, ADR 0184).

        ``expected_issuer`` and ``expected_subject`` are the pair the caller saw, both ``None`` for
        an account it saw unbound. The clear below runs only if the row still holds exactly that
        pair; otherwise nothing is written and this raises :class:`FederatedBindingChanged`
        (BACKLOG #2026), so a rebind never replaces a binding its caller did not see.

        **This is the only path that creates a federated binding.** Owner ruling 2026-09-06, recorded
        in ADR 0184: a federated login never binds, and an unbound login is refused (AC-4).

        The issuer is the configured ``[auth].oidc_issuer`` and nothing else. The claims ladder
        refuses any token whose ``iss`` differs from it, so a binding under another issuer could never
        be presented; taking the issuer from the caller would only add a way to write a dead one.

        Refuses, as :class:`ValueError` with an operator-facing message: no configured issuer, an
        unknown user, a non-directory account (ADR 0184 part 3), and a pair the account already
        holds -- a no-op should not sign anybody out. Refuses as :class:`FederatedSubjectHeld` when a
        different account holds the pair.

        **Refuses as :class:`DirectoryObjectIdMissing` an account with no ``directory_object_id``**,
        and writes an ``auth.federated_bind_refused`` audit row naming the actor (BACKLOG #1143
        slice C). That class's docstring holds the reason, what it makes hold, and the cost.

        **EVERY BIND CLEARS FIRST, THEN BINDS.** The clear is the unbind's own transaction, so the prior
        pair and every live session of the account go together and the audit row names the pair that
        transaction cleared. On an unbound account the clear writes nothing and revokes nothing, so a
        first bind revokes no session: it adds a way in and withdraws none. On a rebind the account is
        unbound between the two writes, and a federated login in that gap is refused rather than
        admitted. If the bind is then refused because another account took the pair in the gap, the
        account is left unbound, and the error says so.

        Emits ``auth.federated_subject_bound`` or ``auth.federated_subject_rebound`` naming the
        actor, and notifies the account holder naming the issuer but not the subject (ASVS 6.3.7).
        """
        issuer = self._settings.oidc_issuer
        if not issuer:
            raise ValueError("no OIDC issuer is configured ([auth].oidc_issuer)")
        # The pair is exact-matched against the verified token, so a stray space or a control
        # character makes a binding nobody can ever present. Refused here rather than stored dead.
        # ASCII because OpenID Connect Core requires it of `sub`, and because the narrowest column
        # (SQL Server NVARCHAR(256)) counts UTF-16 units, so 255 non-ASCII characters could overflow.
        if (
            not subject
            or subject != subject.strip()
            or not subject.isascii()
            or not subject.isprintable()
        ):
            raise ValueError(
                "the subject must be the IdP's exact sub: printable ASCII, no surrounding spaces"
            )
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        # First, and whatever pair the caller expected: a retried bind whose first try landed
        # changes nothing, and must not be told that a competing change happened.
        if (user.oidc_issuer, user.oidc_subject) == (issuer, subject):
            raise ValueError("the account already holds that identity")
        # A caller whose pair is already stale gets the stale answer, not whichever refusal below
        # this read happens to trip. The locked compare in the clear is still the authority.
        if (user.oidc_issuer, user.oidc_subject) != (expected_issuer, expected_subject):
            raise FederatedBindingChanged()
        if user.auth_provider != AuthProvider.AD.value:
            raise ValueError("only a directory (AD) account can take a federated binding")
        if not user.directory_object_id:
            # BACKLOG #1143 slice C: see DirectoryObjectIdMissing. After the no-op check, so a
            # legacy binding resubmitted as it stands gets the harmless answer above, while moving
            # it to another pair is still refused. Unbinding it stays open.
            await self._audit(
                "auth.federated_bind_refused",
                actor=actor,
                detail=_json(
                    {
                        "user_id": user_id,
                        "username": user.username,
                        "issuer": issuer,
                        "subject": subject,
                        "reason": DIRECTORY_OBJECT_ID_MISSING,
                    }
                ),
            )
            raise DirectoryObjectIdMissing(
                f"{DIRECTORY_OBJECT_ID_MISSING}: this account has no immutable directory identifier"
                " (objectGUID), so it cannot take a federated binding, and it never gains one."
                " An account gets one at creation, from a directory that returns a readable"
                " objectGUID: through POST /users/directory, or when the person signs in once with"
                " Windows SSO. To link this person: make the directory return objectGUID, remove"
                " this account, create it again one of those two ways, then bind the new account."
                " Removing the account discards its user_id and what is keyed on it"
            )
        holder = await self._store.get_user_by_federated_subject(issuer, subject)
        if holder is not None and holder.id != user_id:
            raise FederatedSubjectHeld(
                "that identity is already bound to another account; unbind it there first"
            )
        # ALWAYS THROUGH THE CLEAR, and the transaction's own answer decides bind versus rebind -- not
        # the `user` read above. The clear writes nothing and revokes nothing on an unbound account,
        # so a first bind costs one statement. Deciding from the earlier read would let a binding
        # another administrator wrote in between be overwritten with its sessions left live. The
        # clear compares the CALLER's pair, not that read's: the read is this request's, and the
        # decision to replace a binding was made on whatever the caller's page showed (#2026).
        cleared = await self._store.clear_user_federated_subject(
            user_id, expected_issuer=expected_issuer, expected_subject=expected_subject
        )
        if cleared is None:
            raise ValueError("no such user")
        if cleared.changed:
            raise FederatedBindingChanged()
        previous_issuer, previous_subject = cleared.issuer, cleared.subject
        revoked = cleared.sessions_revoked
        rebind = previous_issuer is not None or previous_subject is not None
        try:
            # CONDITIONAL ON THE ROW STILL BEING UNBOUND, in the same statement. The clear above and
            # this write are two transactions, so a second bind of this account can land between
            # them; an unconditional write would overwrite it with no audit row and leave the
            # sessions it admitted live.
            written = await self._store.set_user_federated_subject(
                user_id, issuer, subject, expect_unbound=True
            )
        except Exception as exc:
            # A binding this call removed is recorded whatever happens next, so it never disappears
            # without an audit row or a notice to its holder.
            if rebind:
                await self._record_federated_unbind(user_id, cleared, actor=actor)
            # `ux_users_federated_subject` refused it: another account took the pair after the read
            # above. Rendered as the same refusal the sequential check gives; anything else re-raises.
            if not _is_integrity_refusal(exc):
                raise
            raise FederatedSubjectHeld(
                "that identity is already bound to another account"
                + (
                    "; the account's previous binding was removed and it is now unbound"
                    if rebind
                    else ""
                )
            ) from exc
        if not written:
            if not rebind:
                # Nothing was written: the caller saw the account unbound and another bind landed
                # first. That is the changed-pair refusal, with its code (BACKLOG #2026).
                raise FederatedBindingChanged()
            await self._record_federated_unbind(user_id, cleared, actor=actor)
            # This request DID write: its clear removed the pair it expected. So not the
            # changed-pair refusal, whose promise is that nothing changed.
            raise FederatedSubjectHeld(
                "another request bound this account while this one ran; read it and retry"
                "; this request removed its previous binding first"
            )
        detail: dict[str, object] = {
            "user_id": user_id,
            "username": user.username,
            "issuer": issuer,
            "subject": subject,
        }
        if rebind:
            detail.update(
                {
                    "previous_issuer": previous_issuer,
                    "previous_subject": previous_subject,
                    "sessions_revoked": revoked,
                }
            )
        await self._audit(
            "auth.federated_subject_rebound" if rebind else "auth.federated_subject_bound",
            actor=actor,
            detail=_json(detail),
        )
        # BACKLOG #1248. Binding an external identity decides WHO MAY SIGN IN as this account, so the
        # holder hears of it out of band (ASVS 6.3.7). THE NOTICE CARRIES THE ISSUER AND NOT THE
        # SUBJECT: the audit row needs the exact ``sub`` to tell two bindings apart; the holder needs
        # to know which provider was linked, and an opaque identifier in an email tells them nothing
        # while putting it somewhere less protected than the audit store.
        await self._notify_security(
            FEDERATED_IDENTITY_BOUND,
            username=user.username,
            email=user.notify_email,
            detail={"issuer": issuer},
        )
        return FederatedBinding(
            issuer=issuer,
            subject=subject,
            previous_issuer=previous_issuer,
            previous_subject=previous_subject,
            sessions_revoked=revoked,
        )

    async def set_channel_scope(
        self,
        user_id: str,
        channels: Sequence[str] | None,
        *,
        actor: str,
        expected_source: ChannelScopeSource | None = None,
    ) -> None:
        """Set a user's per-channel RBAC scope. Revokes their sessions so the new scope takes effect
        immediately, and audits the change.

        Three writable states, and ``None`` is no longer the wide one (BACKLOG #1152): ``None``
        clears the scope back to unset, which now DENIES every channel; ``[]`` denies too, and says
        somebody chose it; a list containing
        :data:`~messagefoundry.auth.identity.ALL_CHANNELS` grants the whole estate. Administrators
        are all-channels by role, so a scope set on one still has no effect.

        **The write marks the scope manual, so taking over the directory's needs explicit intent
        (BACKLOG #2098, owner ruling 2026-09-27).** The login sync never withdraws a manual scope, so
        re-saving a directory scope pins it. When the stored source is ``"ad"``, the caller must
        pass ``expected_source="ad"``. When ``expected_source`` is given it must match the stored
        source. Either failure raises :class:`ChannelScopeSourceConflict`. The write itself is a
        compare-and-set against the source read here, so an AD sign-in that changes it before the
        write lands raises the same error instead of being overwritten. A caller that leaves
        ``expected_source`` unset on a scope the directory does not own is unaffected.

        Raises ``ValueError("no such user")`` when the account does not exist."""
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        stored = user.channel_scope_source
        if expected_source is None and stored == SCOPE_SOURCE_AD:
            raise ChannelScopeSourceConflict(
                "the directory owns this channel scope; send expected_source='ad' to confirm "
                "that saving it makes it manual"
            )
        if expected_source is not None and expected_source != stored:
            raise ChannelScopeSourceConflict(
                "expected_source does not match who last wrote this channel scope; re-read the "
                "user and retry, and omit expected_source where no writer is recorded"
            )
        scope_json = None if channels is None else _json(sorted(set(channels)))
        if not await self._store.set_user_channel_scope_if_source(
            user_id, scope_json, source=SCOPE_SOURCE_MANUAL, expected_source=stored
        ):
            if await self._store.get_user(user_id) is None:
                raise ValueError("no such user")
            raise ChannelScopeSourceConflict(
                "this channel scope changed hands while the write ran; re-read the user and retry"
            )
        await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "user.channel_scope_changed",
            actor=actor,
            detail=_json(
                {
                    "user_id": user_id,
                    "channels": None if channels is None else sorted(set(channels)),
                }
            ),
        )

    async def is_last_enabled_admin(self, user_id: str) -> bool:
        """True iff ``user_id`` is an enabled administrator and the only one remaining.

        Guards the role-removal path so the deployment can never be left with no usable admin
        account. Nothing regenerates one: since ADR 0183 the way back is ``provision-admin`` at the
        host.
        """
        admins: set[str] = set()
        for user in await self._store.list_users():
            if user.disabled:
                continue
            if Role.ADMINISTRATOR.value in await self._store.get_user_role_ids(user.id):
                admins.add(user.id)
        return admins == {user_id}

    async def has_notifiable_admin(self) -> bool:
        """True iff at least one ENABLED administrator carries a NOTIFICATION address.

        BACKLOG #1020. The PHI startup gate computes notification readiness from the SMTP transport
        alone (``notify_security_events`` + ``email_smtp_host`` + ``email_from``), which answers
        *"is a transport configured"* and never *"can the account that matters actually receive"*.
        Those come apart whenever an Administrator has no address -- ``provision-admin`` without
        ``--email``, or an account made in the web console without one -- and
        ``SecurityEventNotifier.notify`` starts ``if not event.email: return``, so every notice about
        the most privileged account on the instance no-ops while the gate reports a healthy channel.

        Deliberately scoped to the ROLE, not to one account: ``email`` is optional in
        ``UserCreateRequest`` and is not required for the Administrator role. The item was found on
        the first-run account ADR 0183 has since retired, and keying on that account alone would have
        closed the instance and left the class open.

        **Reads ``notify_email``, not ``email`` (BACKLOG #1139).** Those are two columns now: ``email``
        is the profile address and, on a directory account, a mirror the next AD login overwrites,
        while ``notify_email`` is where the notice is actually addressed. Asking about ``email`` would
        be the instrument answering the adjacent question (SDS-3.8) -- an administrator whose mirror
        the directory had just repointed would read as notifiable on an address no notice uses.

        Enumerates as :meth:`is_last_enabled_admin` and :meth:`_other_enabled_admin_exists` do --
        same store calls, same disabled-skip, same role test. **That agreement is a convention, not
        a mechanism, and this docstring must not claim otherwise:** these are now THREE independent
        copies of "who is an enabled administrator", and nothing binds them. If one gains a
        condition -- a lockout check, an auth_provider filter -- the others keep the old answer
        silently. Extracting a shared enumeration is worth its own item; it is deliberately not done
        here, because it would rewrite two guards this change has no business touching.
        """
        for user in await self._store.list_users():
            if user.disabled or not user.notify_email:
                continue
            if Role.ADMINISTRATOR.value in await self._store.get_user_role_ids(user.id):
                return True
        return False

    async def _revoke_ad_sessions(self) -> int:
        """Revoke every live session held by a directory account. Returns the number revoked.

        BACKLOG #1154 (ASVS 8.3.2). The two AD map setters below are authorization-value mutators:
        the group maps resolve to role sets and to channel scope, which is exactly what an
        authorization decision reads. Every SIBLING mutator already revokes -- :meth:`set_roles`,
        :meth:`set_channel_scope`, custom-role update and delete, disable, password reset -- so an
        edit here was the one that did not apply until the affected principals happened to log in
        again. On a first deployment that would leave a session running on the pre-edit mapping for
        as long as it stayed alive, which the requirement's first arm ("applied immediately") does
        not allow and which no mitigating control covered.

        **Scoped to AD accounts, and deliberately not narrowed further.** Resolving which principals
        a map edit actually affects would mean re-binding to the directory, and both a removed
        mapping and an added one change an outcome, so the affected set is not derivable from the
        entries alone. Local accounts read neither map and are left alone.

        Enumerates the way the reconciler does -- ``list_users`` filtered on provider and disabled,
        then ``list_sessions`` -- so this needs no schema change on any backend. Unlike the
        reconciler this is NOT counted against the mass-revoke breaker: that breaker exists to catch
        a directory the engine cannot read, and this is an administrator's own step-up-gated edit.
        """
        revoked = 0
        for user in await self._store.list_users():
            if user.auth_provider != AuthProvider.AD.value or user.disabled:
                continue
            if not await self._store.list_sessions(user.id):
                continue
            revoked += await self._store.revoke_user_sessions(user.id)
        return revoked

    async def set_ad_group_map(self, entries: Sequence[tuple[str, str]], *, actor: str) -> None:
        """Replace the AD-group → role map (C3). Revokes directory sessions so it applies at once."""
        await self._store.set_ad_group_role_map(entries)
        revoked = await self._revoke_ad_sessions()
        await self._audit(
            "ad_group_map.updated",
            actor=actor,
            detail=_json({"count": len(entries), "sessions_revoked": revoked}),
        )

    async def set_ad_group_scope_map(
        self, entries: Sequence[tuple[str, str]], *, actor: str
    ) -> None:
        """Replace the AD-group → channel-scope map (C3). Revokes directory sessions so it applies
        at once. This docstring used to end "Takes effect on each AD user's next login", which was
        an accurate description of the defect BACKLOG #1154 names and is no longer true."""
        await self._store.set_ad_group_scope_map(entries)
        revoked = await self._revoke_ad_sessions()
        await self._audit(
            "ad_group_scope_map.updated",
            actor=actor,
            detail=_json({"count": len(entries), "sessions_revoked": revoked}),
        )

    # --- audit ---------------------------------------------------------------

    async def audit_permission_denied(
        self,
        identity: Identity,
        permission: Permission,
        path: str,
        *,
        client: str | None = None,
    ) -> None:
        """Audit an access refused because the caller lacks ``permission``.

        ``client`` is the caller's address; :meth:`_audit` states what a NULL one asserts. The three
        authorization methods gained it because they are only ever reached FROM a request, so every
        row they wrote used to assert the false half of that contract (BACKLOG #1644). It defaults to
        NULL for a caller that genuinely has none — which means a caller that HAS an address and omits
        it writes the very row this exists to stop."""
        await self._audit(
            "auth.permission_denied",
            actor=identity.username,
            detail=_json({"permission": permission.value, "path": path}),
            client=client,
        )

    async def audit_mfa_denied(
        self, identity: Identity, path: str, *, client: str | None = None
    ) -> None:
        """Audit an access refused because the session's second factor is still PENDING (ASVS 6.3.3).

        Needed because the MFA gate sits ABOVE the permission loop: without its own row, a stolen
        password-only token could enumerate the whole authenticated surface and leave the audit log
        completely silent — :meth:`audit_permission_denied` never fires, since the request is refused
        before any permission is evaluated. The gate must stay above the loop (below it, the refusal
        would leak whether the caller holds the permission), so the audit row is the fix.

        ``client``: see :meth:`audit_permission_denied`. It carries more weight here than there — by
        the paragraph above, this row is the only evidence a stolen password-only token was used at
        all, so the address is the half of it an incident responder acts on."""
        await self._audit(
            "auth.mfa_denied",
            actor=identity.username,
            detail=_json({"path": path}),
            client=client,
        )

    async def audit_permission_granted(
        self,
        identity: Identity,
        permission: Permission,
        path: str,
        *,
        client: str | None = None,
    ) -> None:
        """Twin of :meth:`audit_permission_denied` for the authorization-GRANT side (BACKLOG #195a,
        ASVS 16.3.2). Writes one hash-chained audit row naming who was allowed to reach a route.

        ``client``: see :meth:`audit_permission_denied`. The shipped default writes this row on EVERY
        authenticated request (the ``audit_all_authz`` paragraph below), so its NULL client was not a
        margin case — it was the bulk of the table.

        WHICH grants arrive here is the API layer's call, and ``[diagnostics].audit_all_authz``
        governs it. On the shipped default that is the authenticated surface at large, reads and
        polls included; with the switch false it narrows to the sensitive
        ``_GRANT_AUDIT_PERMISSIONS`` set in ``api/security.py``, which was the only audited scope
        before BACKLOG #1277. That set and its exclusions are documented there, and the reasoning
        for the default is written once on the ``audit_all_authz`` field in ``config/settings.py``.
        Do not restate either here."""
        await self._audit(
            "auth.permission_granted",
            actor=identity.username,
            detail=_json({"permission": permission.value, "path": path}),
            client=client,
        )

    async def _audit(
        self,
        action: str,
        *,
        actor: str | None = None,
        detail: str | None = None,
        client: str | None = None,
    ) -> None:
        """``client`` (ADR 0150) is the caller's address where the calling flow has one — the login,
        MFA, reauth and credential paths already receive it for ``sessions.client`` / the out-of-band
        notice, so the audit row now records the SAME address those use. Flows with no address in hand
        (token-only or engine-internal) leave it NULL rather than inheriting an unrelated one."""
        await self._store.record_audit(action, actor=actor, detail=detail, client=client)

    async def _record_suspicious_login(
        self,
        event_type: str,
        user: UserRecord,
        *,
        client: str | None,
        audit_detail: dict[str, Any] | None,
        notice_detail: dict[str, Any],
    ) -> None:
        """Audit one ASVS 6.3.5 event under its own action name, then send the out-of-band notice.

        The rows are ``auth.account_locked`` and ``auth.login_after_failures``, from the fixed
        :data:`_SUSPICIOUS_LOGIN_ACTIONS` map. Each is written with the account's stored username as
        actor, so the event reaches the user's own feed (``auth/notifications.py`` states the rule).

        **WHY THE AUDIT ROW EXISTS (BACKLOG #1138).** Before it, neither event wrote a row of its own:
        the crossing attempt left an ordinary ``auth.login_failed`` and the flagged success an ordinary
        ``auth.login_success``. The label lived only inside the notice, which the notifier drops for an
        account with no address and which does not exist at all without a mail relay. The feed is the
        one channel that reaches both of those accounts, so the label has to be written where it reads.

        The row is written whether or not a notifier is wired, for that reason. It is written BEFORE
        the notice, and the action is resolved before either, so the notifier's "the event is still in
        the audit log" is true when it says it and an unknown kind fails before any side effect.

        **``audit_detail`` MIRRORS THE ATTEMPT'S OWN ROW, never ``notice_detail``.** The failure count
        goes in the notice only. The audit row carries no more than the ``auth.login_failed``,
        ``auth.mfa_failed`` or ``auth.login_success`` row beside it. The attempt itself stays audited
        once, by that row; this adds the event the attempt caused."""
        action = _SUSPICIOUS_LOGIN_ACTIONS[event_type]
        await self._audit(
            action,
            actor=user.username,
            detail=_json(audit_detail) if audit_detail is not None else None,
            client=client,
        )
        if event_type == ACCOUNT_LOCKED and not await self._lock_notice_due(
            user, str(notice_detail.get("lock", "sign_in"))
        ):
            return
        await self._notify_security(
            event_type,
            username=user.username,
            email=user.notify_email,
            client=client,
            detail=notice_detail,
        )

    async def _lock_notice_due(self, user: UserRecord, lock: str) -> bool:
        """Whether an ``ACCOUNT_LOCKED`` mail for this ``lock`` kind is due, and if so, record it.

        ADR 0197 Decision item 7 (BACKLOG #1131): at most one mail per lock kind per account per
        :data:`_LOCK_NOTICE_WINDOW_SECONDS`, and always a mail for the first lock after a quiet window.
        Throttled by TIME, not by cycle: the cycle count survives ``admin-unlock`` and never decays, so
        a cycle throttle would go quiet for a new campaign starting at a high count.

        **It cannot key on the ``auth.account_locked`` row**, which ``_record_suspicious_login`` writes
        for every lock before this runs, so the newest one is always the current lock and a 15-minute
        campaign would look mailed forever. So a due notice writes its OWN row,
        ``auth.lock_notice``, with the closed-set lock kind as detail, and the next lock reads the
        newest of those through ``list_audit``, as the first-seen login-address check reads its
        baseline. No column needed.

        **With no notifier wired the row is still written, as ``mailed: false`` with
        ``reason: no_notifier``, and nothing is throttled** (BACKLOG #1131, owner ruling 2026-09-28).
        It is the one record that a lock notice went undelivered: the general-log line that used to
        say so is gone, because a ``logs:view`` reader could read a lock off it. The row is read only
        with ``users:manage``. Not written when ``[auth].notify_security_events`` is off, a documented
        choice rather than a failure. With a notifier wired, the row records whether a mail could go
        out (``mailed``): an account with
        no notification address is throttled too, which spares the log the notifier's drop warning
        every 15 minutes, but its row says ``mailed: false``, so once an address is set the next
        lock of that kind IS mailed rather than held back by a notice nobody received. A failed read
        fails OPEN, sending the mail, and is logged: a duplicate notice is the cheap failure here, a
        missing one the costly."""
        if self._security_notifier is None:
            if self._settings.notify_security_events:
                await self._audit(
                    _LOCK_NOTICE_ACTION,
                    actor=user.username,
                    detail=_json({"lock": lock, "mailed": False, "reason": "no_notifier"}),
                )
            return True
        mailable = bool(user.notify_email)
        now = time.time()
        since = max(now - _LOCK_NOTICE_WINDOW_SECONDS, user.created_at)
        try:
            rows = await self._store.list_audit(
                actor=user.username, action=_LOCK_NOTICE_ACTION, since=since, limit=50
            )
        except Exception:
            _log.exception(
                "lock-notice throttle read failed for %s; sending the notice", user.username
            )
            rows = []
        for row in rows:
            try:
                detail = json.loads(row["detail"] or "{}")
                kind, mailed = detail.get("lock"), detail.get("mailed", True)
            except (TypeError, ValueError, AttributeError):
                continue
            # A row that mailed nothing holds back only another addressless notice.
            if kind == lock and (mailed is not False or not mailable):
                return False
        await self._audit(
            _LOCK_NOTICE_ACTION,
            actor=user.username,
            detail=_json({"lock": lock, "mailed": mailable}),
        )
        return True

    async def _notify_security(
        self,
        event_type: str,
        *,
        username: str,
        email: str | None,
        client: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> bool:
        """Best-effort out-of-band security-event push (ASVS 6.3.5/6.3.7). A missing notifier and a
        notifier failure are each WARNED and then swallowed — a notification must never break a login
        or an admin action. The caller writes the audit row, not this method: see
        :meth:`_record_suspicious_login` for the two 6.3.5 events.

        Returns ``True`` only when the notifier took the event without raising (BACKLOG #2019), so a
        caller that audits the outcome can record what happened. That is a hand-off, not a delivery.
        Most callers ignore it.

        The docstring used to promise both arms were logged while only the failure arm was (BACKLOG
        #1139), so read the branches rather than this paragraph if they ever diverge again."""
        if self._security_notifier is None:
            # BACKLOG #1139: SAY SO, matching the sibling drop in ``pipeline/security_notify.py``
            # (CLAUDE.md §6 forbids the silent swallow independently of ASVS).
            #
            # THIS DROP IS WIDER THAN THAT SIBLING, which loses one account.
            # ``security_notifier_from_settings`` returns ``None`` whenever ``[alerts]`` names no SMTP
            # host or sender, so an instance running with ``notify_security_events`` on and no relay
            # configured would drop every notice for every account on a first deployment — and the
            # lifespan wiring reports nothing either. Neither the serve gate nor
            # ``_assert_security_notice_is_deliverable`` covers that on a non-PHI instance, so
            # without this line the whole channel would be undetectably absent rather than merely
            # unconfigured.
            #
            # Per occurrence rather than once per process, matching the sibling and the two drops it
            # matched in turn: each line is a distinct notice nobody received, and collapsing them
            # would hide the count — which is the figure that separates a missing relay from a quiet
            # instance.
            #
            # **Never ``detail``** — an EMAIL_CHANGED carries the new address in it.
            #
            # NOT when the operator turned notices off: ``[auth].notify_security_events = false`` is a
            # documented choice, and the lifespan wires no notifier for it, so a warning per event
            # there would report the setting working as a fault.
            if not self._settings.notify_security_events:
                return False
            # Not for a lock notice (BACKLOG #1131, LOG_SILENT_EVENT_TYPES): a line per lock would
            # show a logs:view reader when one landed. ``_lock_notice_due`` records it instead, on the
            # users:manage-only ``auth.lock_notice`` row, and the serve gate reports the missing
            # relay at startup.
            if event_type in LOG_SILENT_EVENT_TYPES:
                return False
            _log.warning(
                "security notice %s for %s dropped: no security-event notifier is configured, so "
                "the account was not told out of band (the /me/security-events feed still records "
                "it)",
                event_type,
                username,
            )
            return False
        try:
            await self._security_notifier.notify(
                SecurityEvent(
                    event_type=event_type,
                    username=username,
                    email=email,
                    client_ip=client,
                    detail=detail or {},
                )
            )
        except Exception:  # noqa: BLE001 - best-effort; never propagate into auth
            # Silent for a lock notice, for the reason on the no-notifier arm above.
            if event_type not in LOG_SILENT_EVENT_TYPES:
                _log.warning(
                    "security-event notification failed (%s for %s)",
                    event_type,
                    username,
                    exc_info=True,
                )
            return False
        return True
