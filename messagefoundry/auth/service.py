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
import urllib.parse
import urllib.request
from collections.abc import AsyncIterator, Callable, Iterable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Final, TypeVar
from uuid import uuid4

from messagefoundry.auth import oidc, reconcile, totp, webauthn
from messagefoundry.auth.identity import ALL_CHANNELS, AuthProvider, Identity
from messagefoundry.auth.ldap import AdPrincipal, LdapAuthenticator, LdapError, kerberos_principal
from messagefoundry.auth.notifications import (
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    ADMIN_NEW_IP,
    EMAIL_CHANGED,
    FEDERATED_IDENTITY_BOUND,
    LOGIN_AFTER_FAILURES,
    MFA_CREDENTIAL_REMOVED,
    MFA_DISABLED,
    MFA_ENABLED,
    NOTIFY_EMAIL_SET,
    PASSWORD_CHANGED,
    PASSWORD_RESET,
    RECOVERY_CODE_USED,
    ROLES_CHANGED,
    SUSPICIOUS_LOGIN_FAILURE_THRESHOLD,
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
    SessionRecord,
    UserRecord,
    WebAuthnCredential,
    require_notify_email,
)
from messagefoundry.transports.rest import opener_tls_context

_log = logging.getLogger(__name__)


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

    @property
    def ok(self) -> bool:
        """Elevated: a new session token was minted. See the class docstring for the three states."""
        return self.token is not None


class CurrentPasswordCheck(Enum):
    """The answer :meth:`AuthService.verify_current_password` gives ``POST /me/password``.

    ``SESSION_ENDED`` is held apart from ``WRONG`` for the reason :class:`Elevation` holds
    ``session_lost`` apart: the route must answer 401 and send the caller to sign in, not re-prompt
    for a password on a session that no longer exists (BACKLOG #1138)."""

    OK = "ok"
    WRONG = "wrong"
    SESSION_ENDED = "session_ended"


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


def _reproof_refusal_reason(proof: _Reproof) -> str:
    """The closed-set ``reason`` a refused password-change re-proof is audited with."""
    if proof.session_revoked:
        return "session_revoked"
    if proof.session_gone:
        return "session_gone"
    return "bad_password"


def _live_lock(user: UserRecord, now: float) -> bool:
    """Whether ``user`` is under a lockout that has not yet expired at ``now``."""
    return user.locked_until is not None and now < user.locked_until


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
    if user.locked_until is not None and now < user.locked_until:
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
    cleared: bool = False


@dataclass
class _ReproofLock:
    """The per-account lock that serializes re-proofs, with a count of the tasks holding or awaiting
    it so the entry can be dropped when the last one leaves."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


@dataclass(frozen=True)
class ProvisionedAdministrator:
    """The outcome of an offline first-administrator provision (BACKLOG #1136).

    ``repaired`` distinguishes a fresh provision from completing one an earlier run left half-written,
    so the CLI can say which happened rather than reporting both as "created".
    """

    user_id: str
    username: str
    repaired: bool


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
_SUSPICIOUS_LOGIN_ACTIONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        ACCOUNT_LOCKED: "auth.account_locked",
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
    otherwise exactly those connections, and anything malformed is no channels."""
    if Role.ADMINISTRATOR in roles:
        return None
    if user.channel_scope is None:
        return frozenset()
    try:
        names = json.loads(user.channel_scope)
    except (ValueError, TypeError):
        return frozenset()
    if not isinstance(names, list):
        return frozenset()
    if ALL_CHANNELS in names:
        return None
    return frozenset(str(n) for n in names)


#: The IdP legs' OWN way across. The connection-shaped default cannot reach this opener, which
#: resolves no trust anchor; see :attr:`~messagefoundry.config.tls_policy.RevocationHopGuard.ways_across`.
_IDP_WAYS_ACROSS = (
    "Set [auth].oidc_tls_crl_file to a PEM file holding a CRL from each CA that issues the token "
    "and JWKS endpoint certificates, so the engine checks revocation on both legs. Put only CRLs "
    "in it: a certificate in that file becomes a trusted root for this hop."
)

#: Stands in for a URL with no host. NOT the empty string: `is_loopback_hop_host("")` is True, so an
#: empty host would take the on-box carve-out and a guard that cannot name its host would ALLOW.
_NO_HOST = "(no host)"


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

    Known limits of this placement (it fires after ``engine.start()``, and ``check``/``verify`` do
    not reach it) are recorded once, in ADR 0173 AC-4. Two more are recorded only here: when both
    legs refuse, only the token leg is named, because it is checked first; and the WARN arm logs with
    no audit sink after ``configure_logging`` has set the root level, so a level above WARNING would
    likely filter it, as ``logging_setup._refuse_forward_revocation`` measured for its hop."""
    context = opener_tls_context(opener, connector="OIDC identity provider (token + JWKS)")
    for url, leg, carries in (
        (
            settings.oidc_token_endpoint,
            "token endpoint",
            "the client secret and authorization code",
        ),
        (settings.oidc_jwks_uri, "JWKS endpoint", "the identity provider's signing keys"),
    ):
        # _NO_HOST is reached only by unvalidated settings: the validator refuses a missing URL.
        RevocationHopGuard.capture(
            host=urllib.parse.urlsplit(url or "").hostname or _NO_HOST,
            cell=f"[auth] OIDC {leg} (verified TLS, no revocation check)",
            description=(
                f"carries {carries} over verified TLS but performs no certificate revocation checking"
            ),
            attested=False,
            context=context,
            posture=posture,
            ways_across=_IDP_WAYS_ACROSS,
        ).enforce_construction()


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
        # in warn mode — matching the central run_anchor_preflight and build_api_ssl_context, which is
        # the only place AuthService needs the dial. AuthSettings carries no [security] block, so the
        # dial cannot be read off settings here; it must be passed. Defaults enforce (fail-closed).
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
            self._ldap = LdapAuthenticator(
                settings, secret_provider=secret_provider, posture=hop_posture
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
        # Entry-to-session ceremonies (login, negotiate, SSO/OIDC, the mid-login MFA challenge)
        # deliberately STAY on _login_limiter — throttling sign-in during a sign-in flood is the
        # intended behaviour.
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
        self._reproof_locks: dict[str, _ReproofLock] = {}
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
        unauthenticated sign-in surface: an attacker who can reach the login page must not be able to
        exhaust it and deny re-authentication (and hence every step-up action) to signed-in operators.
        True = proceed; always True when the limiter is disabled."""
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
    def oidc_available(self) -> bool:
        """``oidc_enabled`` AND the last IdP interaction did not fail.

        **Deliberately NOT the same shape as** :attr:`kerberos_available`, which is boot-once and
        sticky-until-restart (ADR 0068 §9). This flag is **advisory and non-sticky**: it is set by a
        failed login and cleared by the next successful one, and *no login path gates on it* — the
        start leg always attempts. That is what satisfies AC-8's "SHALL recover without an engine
        restart"; a copy of the Kerberos latch would leave one IdP blip disabling federated login
        until a restart, which is exactly what AC-8 forbids. It exists to drive the login-page link
        and ``/auth/providers``, nothing more. Do not "fix" the asymmetry with the Kerberos twin.
        """
        return self.oidc_enabled and self._oidc_unavailable_reason is None

    def mark_oidc_unavailable(self, reason: str) -> None:
        """Record that an IdP interaction failed. Advisory only — see :attr:`oidc_available`."""
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

    def _generate_policy_password(self) -> str:
        """A random password that satisfies the active policy — so an administrator-issued temporary
        credential is held to the same bar operators are. ``token_urlsafe(n)`` yields ~1.33·n chars (so length is
        guaranteed ≥ ``min_length``); the loop covers the astronomically-unlikely context hit or an
        opt-in character-class requirement a given token happens to miss.

        Every clause except the breach screen, which is suppressed per-call for the reason stated at
        the call below (BACKLOG #1447)."""
        # 24 BYTES (192 bits), not 16. token_urlsafe's argument is a byte count, and the floor is
        # raised here rather than left at the policy minimum because min_length is a CHARACTER count
        # -- passing it as bytes happens to be safe but ties an entropy floor to a legibility knob an
        # operator may lower (BACKLOG #1172).
        length = max(24, self._policy.min_length)
        for _ in range(16):
            candidate = secrets.token_urlsafe(length)
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
            if not self._policy.violations(candidate, suppress_breach_check=True):
                return candidate
        return secrets.token_urlsafe(length) + "aA1!"  # defensive: satisfies any class requirement

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
        administrator at all, which is already the state an operator needs recovering from.

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
        await self._audit(
            "auth.first_administrator_provisioned",
            actor=actor,
            detail=_json(
                {"username": username, "repaired": repaired, "notified": bool(notify_email)}
            ),
        )
        return ProvisionedAdministrator(user_id=user_id, username=username, repaired=repaired)

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
        self, outcome: LoginOutcome, started: float, *, seam: str
    ) -> LoginOutcome:
        """Hold a FAILED ``outcome`` until this challenge's deadline, then return it unchanged.

        ASVS 6.3.8 asks that valid users not be deducible from failed challenges, *including by
        different response times*. Messages and status codes on the challenge seams are already
        collapsed; this closes the remaining channel by making every failure answer at an instant
        fixed before dispatch, so the latency is a function of ``started`` and nothing else — not of
        which branch ran, and so not of anything about the username.

        **Successes return unpadded, deliberately.** A valid credential has already told the caller
        the account exists; enumeration is about telling two FAILURES apart, and padding the success
        path would only make every real sign-in slower.

        **Exceptions propagate unpadded, also deliberately.** An unhandled store or directory error
        becomes a 500, which is a far louder signal than any timing difference, so padding it would
        buy nothing while delaying a genuine fault.

        The pad is an ``asyncio.sleep``, so it holds a connection open but never the event loop; the
        sign-in rate limiter bounds how many a caller can hold at once.
        """
        if outcome.ok:
            return outcome
        now = time.monotonic()
        elapsed = now - started
        if elapsed > _FAILURE_BUDGET_SECONDS and seam not in _BUDGET_OVERRUN_WARNED:
            # The budget is too small for this hardware, so failures are landing in a later slot than
            # the control assumes. It still cannot fail open (`_failure_deadline` always rounds up),
            # but a pair of branches straddling the slot boundary would stay distinguishable.
            _BUDGET_OVERRUN_WARNED.add(seam)
            _log.warning(
                "auth: a failed %s challenge took %.3fs, over the %.3fs anti-enumeration budget; "
                "responses are being padded to a later slot (further overruns are not logged)",
                seam,
                elapsed,
                _FAILURE_BUDGET_SECONDS,
            )
        await _sleep_until(_failure_deadline(started, now))
        return outcome

    async def login(
        self,
        username: str,
        password: str,
        *,
        provider: AuthProvider = AuthProvider.LOCAL,
        client: str | None = None,
        supersedes: str | None = None,
    ) -> LoginOutcome:
        """The credential sign-in seam, with every failed outcome held to a fixed deadline.

        ``supersedes`` is the session token the caller's browser presented, if any. On success it is
        ended as part of the new session's mint (see :meth:`_issue_session`). Only a caller whose
        response REPLACES that token passes it: the console legs do, the bearer routes never do.

        A wrapper rather than a pad threaded through the dispatch's returns, so that a failure branch
        added there later inherits the equaliser instead of quietly escaping it (BACKLOG #1140).

        **The inner method is ``_dispatch_login`` and NOT ``_login``, which is load-bearing.**
        ``tests/test_docs_security_pathways.py`` treats every ``_login*`` coroutine returning a
        ``LoginOutcome`` as a per-provider authentication pathway owing a comparative-strength row in
        ``docs/SECURITY.md`` (ASVS 6.1.3). Naming this one ``_login`` would have made a pure
        refactoring look like a new pathway and forced that guard to be loosened to accommodate it —
        which is how a guard stops catching the thing it was built for. Staying out of the namespace
        keeps ``_login*`` meaning exactly what it meant.
        """
        started = time.monotonic()
        outcome = await self._dispatch_login(
            username, password, provider=provider, client=client, supersedes=supersedes
        )
        return await self._equalize_failure(outcome, started, seam="login")

    async def _dispatch_login(
        self,
        username: str,
        password: str,
        *,
        provider: AuthProvider = AuthProvider.LOCAL,
        client: str | None = None,
        supersedes: str | None = None,
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
        return await self._login_local(username, password, client=client, supersedes=supersedes)

    async def _login_local(
        self, username: str, password: str, *, client: str | None, supersedes: str | None = None
    ) -> LoginOutcome:
        user = await self._store.get_user_by_username(username)
        if user is None or user.auth_provider != AuthProvider.LOCAL.value or user.disabled:
            # Equalize timing with the real-password path so a missing/disabled/AD account is not
            # distinguishable from a wrong password (defeats username enumeration via latency).
            await self._argon2(verify_password, _DUMMY_PASSWORD_HASH, password)
            await self._audit(
                "auth.login_failed",
                actor=username,
                detail=_json({"provider": "local", "reason": "unknown_or_disabled"}),
                client=client,
            )
            return LoginOutcome(ok=False, error="invalid credentials")
        now = time.time()
        if user.locked_until is not None and now < user.locked_until:
            await self._argon2(verify_password, _DUMMY_PASSWORD_HASH, password)
            await self._audit("auth.login_locked", actor=username, client=client)
            return LoginOutcome(ok=False, error="account locked")
        if user.password_hash is None or not await self._argon2(
            verify_password, user.password_hash, password
        ):
            attempts, just_locked = await self._register_failure(user, now)
            await self._audit(
                "auth.login_failed",
                actor=username,
                detail=_json({"provider": "local", "reason": "bad_password"}),
                client=client,
            )
            if just_locked:
                await self._record_suspicious_login(
                    ACCOUNT_LOCKED,
                    user,
                    client=client,
                    audit_detail={"provider": "local"},
                    notice_detail={"failed_attempts": attempts},
                )
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
            await self._audit(
                "auth.temp_password_expired",
                actor=username,
                detail=_json({"provider": "local", "expiry_hours": expiry_hours}),
                client=client,
            )
            return LoginOutcome(ok=False, error="invalid credentials")
        if await asyncio.to_thread(needs_rehash, user.password_hash):
            await self._store.set_password(
                user.id,
                password_hash=await self._argon2(hash_password, password),
                must_change_password=user.must_change_password,
            )
        # Captured off the row read before the verify, so it is the count as it stood at the start of
        # this attempt whether or not the clear below runs.
        prior_failures = user.failed_attempts
        identity = await self._build_identity(user)
        # A second factor (TOTP / recovery code / passkey) is pending for an enrolled user — or an
        # Administrator when require_mfa is on. Issue the session un-MFA'd; the client completes via
        # /auth/mfa-verify (or the browser passkey leg at /ui/reauth, ADR 0068).
        mfa_required = self._mfa_required_for(
            user, identity.roles, second_factor_enrolled=await self._second_factor_enrolled(user)
        )
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
            supersedes_hash=hash_token(supersedes) if supersedes else None,
        )
        await self._audit(
            "auth.login_success",
            actor=user.username,
            detail=_json({"provider": "local", "mfa_required": mfa_required}),
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

    async def _register_failure(self, user: UserRecord, now: float) -> tuple[int, bool]:
        """Record a failed attempt; return ``(attempts, just_locked)``. ``just_locked`` is True only on
        the attempt that takes the account from unlocked to locked, so it fires exactly one lockout
        notification per lockout.

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
            threshold=self._policy.lockout_threshold,
            lockout_seconds=self._policy.lockout_minutes * 60,
            now=now,
        )

    async def authenticate_kerberos(
        self,
        token: bytes,
        *,
        client: str | None = None,
        seed_reauth: bool = True,
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
        outcome = await self._authenticate_kerberos(
            token, client=client, seed_reauth=seed_reauth, supersedes=supersedes
        )
        return await self._equalize_failure(outcome, started, seam="kerberos")

    async def _authenticate_kerberos(
        self,
        token: bytes,
        *,
        client: str | None = None,
        seed_reauth: bool = True,
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
            seed_reauth=seed_reauth,
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
        full exchange + verification through :meth:`authenticate_oidc`.

        The flow cache stays private to the service, so route code never holds the PKCE verifier or
        the nonce. A missing/expired flow and a ``state`` mismatch are both audited with closed-set
        slugs and are deliberately indistinguishable to the caller.
        """
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
        return await self.authenticate_oidc(
            code,
            flow,
            redirect_uri=self._oidc_redirect_uri(public_origin),
            client=client,
        )

    async def authenticate_oidc(
        self,
        code: str,
        flow: PendingFlow,
        *,
        redirect_uri: str,
        client: str | None = None,
        seed_reauth: bool = False,
    ) -> LoginOutcome:
        """Complete a federated login: exchange the code, verify the ``id_token``, then resolve the
        principal against on-prem AD and hand off to the shared directory-login path.

        ``seed_reauth`` defaults **False**, unlike :meth:`authenticate_kerberos`: a federated proof is
        ambient (the browser was redirected back holding a token), so the session must not be born
        with a free step-up window — the first sensitive action forces an explicit re-auth. This
        mirrors browser Kerberos SSO's explicit ``seed_reauth=False``, not its default.

        Roles come from ``resolve_principal`` — the same password-free LDAP lookup Kerberos uses —
        and NEVER from a token claim, so a claims-parsing bug degrades to wrong-user login rather
        than privilege escalation.
        """
        if not self.oidc_enabled or self._ldap is None:
            await self._directory_reject_audit("<oidc>", "oidc", "not_configured")
            return LoginOutcome(
                ok=False, error="federated sign-in is not configured", reason="not_configured"
            )
        try:
            principal_claims = await asyncio.to_thread(
                self._exchange_and_validate, code, flow, redirect_uri
            )
        except oidc.ClaimsError as exc:
            # A verification-rung failure: the token was reachable but did not satisfy the ladder.
            # exc.reason is closed-set, so nothing IdP-influenced reaches the audit row.
            await self._directory_reject_audit("<oidc>", "oidc", exc.reason)
            return LoginOutcome(ok=False, error="federated sign-in failed", reason=exc.reason)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            # IdP unreachable / non-2xx / malformed response. JwksCache's injected fetch raises RAW
            # urllib errors (it is not wrapped in JwksError), so a narrow `except JwksError` here
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

        username = principal_claims.username
        try:
            principal = await asyncio.to_thread(self._ldap.resolve_principal, username)
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
            # Hybrid-only by design: a federated principal with no on-prem AD object is refused.
            await self._directory_reject_audit(username, "oidc", "not_in_directory")
            return LoginOutcome(
                ok=False, error="user not found in directory", reason="not_in_directory"
            )

        # BACKLOG #1015 (ADR 0142): subject-continuity guard. The AD-backed account is still RESOLVED by
        # its username (roles stay LDAP-sourced), but its federated identity is PINNED to the non-
        # reassignable OIDC (issuer, sub). If a local account for this resolved username is already bound
        # to a DIFFERENT verified subject, an IdP has reassigned the username to a new person — refuse
        # rather than hand the new subject the prior holder's account (the account-takeover-without-
        # credential-compromise this item closes). An unbound account (never federated-logged-in) binds
        # on first login below, in _complete_ad_login.
        bound = await self._store.get_user_by_username(principal.username)
        if (
            bound is not None
            and bound.oidc_subject is not None
            and (bound.oidc_issuer, bound.oidc_subject)
            != (principal_claims.issuer, principal_claims.subject)
        ):
            await self._directory_reject_audit(username, "oidc", "federated_subject_conflict")
            return LoginOutcome(
                ok=False, error="federated sign-in failed", reason="federated_subject_conflict"
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
        # authenticated AT THE IdP. The ladder checks recency only at login, and /ui/reauth never
        # returns to the IdP, so without this cap the time since the IdP authentication event would
        # grow unbounded for the session's whole life.
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
            seed_reauth=seed_reauth,
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
        seed_reauth: bool = True,
        mech: str | None = None,
        evidence: Mapping[str, object] | None = None,
        max_expires_at: float | None = None,
        federated_subject: tuple[str, str] | None = None,
        supersedes_hash: str | None = None,
    ) -> LoginOutcome:
        # ``federated_subject`` is the verified OIDC ``(issuer, sub)`` and is passed ONLY by the
        # federated path (BACKLOG #1015). It defaults to None, so the Kerberos caller stays
        # byte-identical — no extra store write, no changed audit row. The federated
        # caller has already enforced the subject-continuity guard before reaching here.
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
            # BACKLOG #1256: SUBJECT-EXCLUSIVITY, the direction #1015's guard cannot look. That guard
            # resolves by username and asks whether THIS ACCOUNT holds a different subject; it is
            # structurally incapable of seeing a SECOND ACCOUNT already bound to the subject now
            # presenting.
            #
            # This is the FRIENDLY half of a two-layer control, not the only thing standing here.
            # `ux_users_federated_subject` carries the same rule on all three backends and is the
            # layer that holds under concurrency; the except-block below renders its refusal as this
            # same outcome. This check exists so the sequential case gets a clean answer rather than
            # an integrity error.
            #
            # Until BACKLOG #1472 this said, with a measurement, that no UNIQUE constraint named
            # these columns on any backend. True when taken and false once the index landed -- and
            # by then it invited the one wrong reading: that nothing but this check-then-act stood
            # between one subject and two accounts.
            #
            # Without this, one verified identity could come to own two accounts: bind as `alice`,
            # have the directory resolve you to `bob` later, and both rows carry your subject with
            # #1015 refusing neither, because each account's own binding is self-consistent.
            #
            # Refused rather than re-pointed: silently moving a binding would hand the subject the
            # newer account and strand the older one, which is the account-takeover-without-
            # credential-compromise shape #1015 exists to prevent, arriving from the other side.
            holder = await self._store.get_user_by_federated_subject(*federated_subject)
            if holder is not None and holder.id != user.id:
                await self._directory_reject_audit(
                    principal.username, "oidc", "federated_subject_already_bound"
                )
                return LoginOutcome(
                    ok=False,
                    error="federated sign-in failed",
                    reason="federated_subject_already_bound",
                )
            # First federated login for this account (or an unbound AD account's first): record the
            # (issuer, sub) binding so a later reassigned-username login carrying a different subject is
            # refused by the guard above. A matching binding is left untouched (no updated_at churn).
            try:
                await self._store.set_user_federated_subject(
                    user.id, federated_subject[0], federated_subject[1]
                )
            except Exception as exc:
                # BACKLOG #1256. THE GUARD ABOVE IS CHECK-THEN-ACT: its read and this write are
                # separate awaits, so two concurrent FIRST logins for one subject can both see
                # `holder is None` and both reach here. `ux_users_federated_subject` refuses the
                # loser on all three backends, and this renders that refusal as the SAME outcome the
                # sequential path returns -- otherwise the race loser gets a 500 for a condition the
                # gate handles cleanly one microsecond earlier.
                #
                # MRO BY NAME, matching the duplicate-label race at `_enroll_webauthn` (ADR 0068 4):
                # each backend raises its own integrity class -- sqlite3.IntegrityError, asyncpg's
                # UniqueViolationError, pyodbc's IntegrityError -- and naming them here would make
                # this module import-aware of every driver and silently stop covering a backend added
                # later. Anything that is NOT an integrity violation re-raises untouched.
                mro = "".join(t.__name__ for t in type(exc).__mro__)
                if "Integrity" not in mro and "UniqueViolation" not in mro:
                    raise
                await self._directory_reject_audit(
                    principal.username, "oidc", "federated_subject_already_bound"
                )
                return LoginOutcome(
                    ok=False,
                    error="federated sign-in failed",
                    reason="federated_subject_already_bound",
                )
            # BACKLOG #1248. Binding an external identity decides WHO MAY SIGN IN as this account
            # from now on, so it is a privilege change and gets the same two records the role
            # resync below emits: an audit row, and an out-of-band notice to the account holder
            # (ASVS 6.3.7). Before this it was the only silent write in the method.
            await self._audit(
                "auth.federated_subject_bound",
                actor=user.username,
                detail=_json({"issuer": federated_subject[0], "subject": federated_subject[1]}),
                client=client,
            )
            # THE NOTICE CARRIES THE ISSUER AND NOT THE SUBJECT, deliberately. The audit row needs
            # the exact ``sub`` so an operator can tell two bindings apart; the account holder needs
            # to know WHICH PROVIDER was linked, and an opaque identifier in an email tells them
            # nothing while putting it somewhere less protected than the audit store.
            await self._notify_security(
                FEDERATED_IDENTITY_BOUND,
                username=user.username,
                email=user.notify_email,
                client=client,
                detail={"issuer": federated_subject[0]},
            )
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
        # ASVS 6.3.4 / 6.8.4: the second-factor grant is the CALLER's per-mechanism decision, not a
        # blanket literal. Kerberos passes False -- a ticket asserts nothing about directory-side
        # strength, so the engine assumes the minimum (BACKLOG #1144); the federated leg passes the
        # engine-verified amr/acr result. See the callers for each rationale.
        try:
            token = await self._issue_session(
                user.id,
                client,
                mfa_verified=mfa_verified,
                seed_reauth=seed_reauth,
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
        requests (mirrors role sync). Administrators are always all-channels. Returns the (possibly
        refreshed) user record.

        **A matching group is authoritative**: its scope replaces whatever is stored, an
        administrator's included, and the scope is then the directory's.

        **When no mapped group matches, the outcome depends on who wrote the stored scope (BACKLOG
        #1927).** A scope an administrator set is left untouched, so on this branch the map stays
        opt-in. Any other scope is WITHDRAWN to NULL, which denies (BACKLOG #1152); the rule is
        stated on ``UserRecord.channel_scope_source``. This path used to return early for every
        no-match login, so a user removed from their last scope-mapped group kept the channels the
        directory had granted for as long as the account existed. A scope that already denies is
        left as it is, because rewriting ``[]`` to NULL changes no decision and would revoke
        sessions for nothing.

        A wildcard group row persists the explicit ``["*"]`` grant. It used to persist SQL NULL and
        rely on NULL meaning "all"; with an absent scope now denying, that collapse would have
        inverted a deliberate all-channels mapping into a deny-everything one."""
        if Role.ADMINISTRATOR in roles:
            return user
        channels = await self._store.channels_for_ad_groups(groups)
        if not channels:
            if user.channel_scope_source == SCOPE_SOURCE_MANUAL:
                return user
            if user.channel_scope is None or _allowed_channels(user, roles) == frozenset():
                return user  # already a deny; nothing to withdraw
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
        wildcard = ALL_CHANNELS in channels
        specific = sorted(c for c in channels if c != ALL_CHANNELS)
        scope_json = _json([ALL_CHANNELS]) if wildcard else _json(specific)
        if user.channel_scope == scope_json and user.channel_scope_source == SCOPE_SOURCE_AD:
            return user
        await self._store.set_user_channel_scope(user.id, scope_json, source=SCOPE_SOURCE_AD)
        # Drop stale-scope tokens; the new one is issued after. Skipped when only the provenance
        # moved -- the directory taking over an identical manual scope changes no decision, so
        # there is nothing stale to drop -- but that write is still audited below.
        if scope_json != user.channel_scope:
            await self._store.revoke_user_sessions(user.id)
        await self._audit(
            "auth.ad_scope_resynced",
            actor=user.username,
            detail=_json({"channels": ALL_CHANNELS if wildcard else specific}),
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
            user_id = uuid4().hex
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
            )
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
                # sibling reads one term. It is reachable in exactly one state, which only this
                # method can produce: an account created with NO address, which later acquired one
                # from the directory, because ``update_user_profile`` writes the mirror and never
                # seeds ``notify_email``. On that account's next repoint the mirror is the prior
                # holder. Failing both terms the account has never carried an address at all, so the
                # incoming value is the only reachable party and there is no earlier holder to
                # protect -- it is the target rather than announcing a first set to nobody.
                await self._notify_security(
                    EMAIL_CHANGED,
                    username=principal.username,
                    email=existing.notify_email or existing.email or email,
                    client=client,
                    detail={"new_email": email, "source": "directory"},
                )
        user = await self._store.get_user(user_id)
        assert user is not None  # just upserted
        return user

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
        operator can find out.

        ``resolve_principal`` is the password-free service-account lookup the Kerberos path uses. It
        already rejects a disabled account (``userAccountControl & 0x2``) by returning ``None`` on
        either key, and returns the group set, so the role re-diff below costs no extra round trip.
        """
        assert self._ldap is not None  # guarded by directory_reconcile_enabled
        try:
            principal = await asyncio.to_thread(
                self._ldap.resolve_principal, user.username, object_id=user.directory_object_id
            )
        except LdapError as exc:
            # FAIL OPEN. An unreachable DC must never revoke: a fail-closed re-check would turn a
            # directory blip into a total console outage during exactly the incident when operators
            # need the console. Debug-level — a flapping DC must not flood the log at one line per
            # user per pass; the pass-level summary below reports the count at WARNING.
            _log.debug("directory reconcile: probe failed for %s: %s", user.username, exc)
            return reconcile.Probe(user.id, user.username, reconcile.ProbeOutcome.UNAVAILABLE)
        if principal is None:
            return reconcile.Probe(user.id, user.username, reconcile.ProbeOutcome.ABSENT)
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
        * a principal must come back absent ``ad_session_recheck_strikes`` passes running;
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
        for user in await self._store.list_users():
            if user.auth_provider != AuthProvider.AD.value or user.disabled:
                continue
            if not await self._store.list_sessions(user.id):
                continue
            candidates.append((user.id, user.username))
            users[user.id] = user
        reconcile.prune_ledger(self._reconcile_strikes, users)
        reconcile.prune_ledger(self._reconcile_last_probed, users)
        if not candidates:
            # Nobody signed in: a no-op pass. A latched breaker alert is deliberately NOT cleared
            # here — this pass learned nothing about the directory, and clearing a standing alarm on
            # an absence of information would hide a misconfiguration that is still there.
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

        # Resolve the role sets for the role re-diff. Store reads only — no extra directory traffic.
        current_roles: dict[str, frozenset[str]] = {}
        target_roles: dict[str, frozenset[str]] = {}
        for probe in probes:
            if probe.outcome is not reconcile.ProbeOutcome.PRESENT:
                continue
            current_roles[probe.user_id] = frozenset(
                await self._store.get_user_role_ids(probe.user_id)
            )
            target_roles[probe.user_id] = frozenset(
                await self._store.roles_for_ad_groups(probe.groups)
            )

        plan = reconcile.plan_pass(
            probes,
            prior_strikes=self._reconcile_strikes,
            current_roles=current_roles,
            target_roles=target_roles,
            strike_threshold=settings.ad_session_recheck_strikes,
            max_absolute=settings.ad_session_revoke_max,
            max_fraction=settings.ad_session_revoke_max_fraction,
        )
        # Strike bookkeeping is process-local, not store state, so it is recorded even for an aborted
        # pass — that is what makes a standing misconfiguration trip the breaker on EVERY pass rather
        # than oscillating. Merge, never replace: an UNAVAILABLE probe is absent from plan.strikes,
        # so the user keeps whatever strike they already carried rather than having an outage clear it.
        self._reconcile_strikes.update(plan.strikes)
        if plan.aborted is not None:
            await self._abort_reconcile_pass(plan)
            return plan

        self._reconcile_alert = None
        if plan.unavailable:
            _log.warning(
                "directory reconcile: %d of %d principals could not be resolved (directory "
                "unreachable) — those sessions were left alone (fail-open)",
                plan.unavailable,
                plan.probed,
            )
        for revocation in plan.revocations:
            await self._apply_reconcile_revocation(revocation)
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
        return plan

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
                "another account (%s). The stored name is left as-is, AND THIS ACCOUNT WILL BE "
                "REFUSED AT ITS NEXT SIGN-IN (directory_identity_conflict) until the stale row is "
                "removed; the session it holds now survives only to the absolute cap (BACKLOG #1532)",
                old_username,
                detected,
            )

        if held is not None and held.id != user_id:
            await _refuse(held.id, "pre_check")
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
            # THIS APPLIES TO THE TWO SIBLING SITES TOO. Censused rather than assumed: `__mro__`
            # appears exactly three times in the engine, all in this module, all using this substring
            # form. So anyone "fixing" the predicate here should not fix it there either.
            #
            # THE COST OF A NAME TEST, NAMED ONCE: it matches on a string, so an unrelated class whose
            # name happens to contain "Integrity" would be swallowed here. The engine HAS one --
            # `messagefoundry.integrity.IntegrityError`, the startup attestation's fail-closed drift
            # error -- and this predicate does absorb it. It is NOT reachable today: its only raise
            # site is inside `run_startup_attestation`, which runs before any listener binds, and
            # neither `store/` nor `auth/` imports the module. Recorded because the day something
            # raises it from a store or auth path, all three of these handlers would silently report a
            # username conflict instead of a refused attestation -- a fail-closed control absorbed by
            # a fail-open one. If that class ever moves, test on identity here, not on a name.
            mro = "".join(t.__name__ for t in type(exc).__mro__)
            if "Integrity" not in mro and "UniqueViolation" not in mro:
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
        ceiling = reconcile.breaker_ceiling(
            probed=plan.probed,
            max_absolute=self._settings.ad_session_revoke_max,
            max_fraction=self._settings.ad_session_revoke_max_fraction,
        )
        self._reconcile_alert = (
            f"mass-revoke circuit breaker TRIPPED: a directory reconciliation pass would have "
            f"revoked more than {ceiling} of {plan.probed} signed-in directory principals. No "
            f"session was revoked. Check [auth].ad_user_search_base, the OU layout, and the "
            f"ad_bind_dn service account's read rights."
        )
        _log.error("directory reconcile: %s", self._reconcile_alert)
        await self._audit(
            "auth.ad_reconcile_aborted",
            actor="<reconciler>",
            detail=_json({"reason": plan.aborted, "probed": plan.probed, "ceiling": ceiling}),
        )

    async def _apply_reconcile_revocation(self, revocation: reconcile.SessionRevocation) -> None:
        """Apply one planned revocation: persist a role re-diff (when that is why), drop the user's
        live sessions, audit, and notify the affected user out-of-band (ASVS 6.3.7)."""
        user = await self._store.get_user(revocation.user_id)
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
        if user is not None:
            await self._notify_security(
                ACCOUNT_DISABLED if revocation.role_ids is None else ROLES_CHANGED,
                username=user.username,
                email=user.notify_email,
                detail={"reason": revocation.reason},
            )

    # --- sessions ------------------------------------------------------------

    async def _issue_session(
        self,
        user_id: str,
        client: str | None,
        *,
        mfa_verified: bool,
        seed_reauth: bool | None = None,
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
            # Seed the step-up window from login ONLY for a fully-authenticated session. An MFA-pending
            # session gets no step-up freshness, so enrolling a first authenticator (or any step-up op)
            # requires an explicit password re-verify — a stolen pre-MFA token can't ride login's
            # freshness to bind an attacker-controlled authenticator (WP-14).
            # seed_reauth=False overrides that for browser Kerberos SSO (ADR 0068 §9): the session's
            # proof is AMBIENT, so it must not be born with a free step-up window — the first
            # sensitive action forces the directory-password step-up.
            seed_reauth=mfa_verified if seed_reauth is None else seed_reauth,
            # BACKLOG #1474: on the federated leg the INSERT is conditional on the account still
            # carrying this verified pair, checked in the store's own transaction. See
            # ``Store.create_session`` for why the check cannot live out here.
            require_federated_subject=require_federated_subject,
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
        cap = self._settings.max_sessions_per_user
        if cap and cap > 0:
            # Evict the oldest sessions beyond the cap (the just-created one is newest, so survives).
            await self._store.enforce_session_cap(user_id, keep=cap)
        return token

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
        old_hash = hash_token(token)
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
        rotated = await self._rotate_session_token(token)
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
        return Elevation(token=rotated, recovery_codes=recovery_codes)

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
        # Fail closed on a backward wall-clock step (NTP step-back, VM snapshot revert): a session
        # stamped in the "future" can't be aged correctly, so revoke rather than silently revive an
        # already-expired one or reset its idle window (AUTH-CLOCK).
        if now < session.created_at or now < session.last_used_at:
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if now > session.expires_at:
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if now - session.last_used_at > self._settings.session_idle_timeout_minutes * 60:
            await self._store.revoke_session(session.token_hash, now=now)
            return None
        if activity:
            await self._store.touch_session(session.token_hash, now=now)
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled:
            return None
        return await self._build_identity(user)

    async def identity_for_username(self, username: str) -> Identity | None:
        """Resolve a username directly to its :class:`Identity` (roles + custom-role overlay), or
        ``None`` when the user is unknown or disabled — WITHOUT a bearer session.

        Used by the mTLS-client-cert → principal path (#200, ADR 0002): a VERIFIED peer cert whose
        subject maps (via ``[api].tls_client_cert_identities``) to a username is resolved here to the
        principal whose RBAC then authorizes the service-to-service request. A disabled account grants
        no identity (fail-closed), exactly as the token path treats it (:meth:`identity_for_token`)."""
        user = await self._store.get_user_by_username(username)
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

        An unrevoked row is ALWAYS revoked, even one already over by expiry or idle: the per-user
        cap counts every unrevoked row, so leaving a lapsed one would let the cap evict a live
        device in its place. Only a session that was still LIVE gets an audit row, so the trail does
        not record the ending of something that had already ended. ``revoke_session`` reports no
        rowcount, so the row is read back: a rotation that re-keyed it between the read and the
        revoke leaves the old hash absent, and then no row claims a revoke that never happened.
        Returns True when it audited.
        """
        prior = await self._store.get_session(prior_hash)
        if prior is None or prior.revoked_at is not None:
            return False
        now = time.time()
        was_live = (
            now <= prior.expires_at
            and now - prior.last_used_at <= self._settings.session_idle_timeout_minutes * 60
        )
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
        """A user's active sessions — the self-service session inventory."""
        return await self._store.list_sessions(user_id)

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
        if not _is_single_mailbox(address) or not address.isascii():
            return None
        domain = address.rpartition("@")[2]
        if any(label.lower().startswith("xn--") for label in domain.split(".")):
            return None
        return address

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
        address = require_notify_email(email)
        if not _is_single_mailbox(address):
            raise ValueError("enter one email address, such as name@example.org")
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
        while a change refused by policy after a good proof would otherwise re-flag on every retry."""
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
        proof = await self._reproof(identity, password, directory=False, token=token, clear=False)
        if proof.ok:
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
        * The account lock gates SIGN-IN. It does not refuse a re-proof on a session that already
          exists. If it did, anyone who knows a username could lock the account from the sign-in
          page every lock window and hold the owner's live sessions out of step-up, the password
          change and session termination indefinitely. That is the harm ``_reauth_limiter`` was
          split out to prevent.
        * Each session may fail ``lockout_threshold`` re-proofs; the one that reaches it revokes the
          session. So a stolen session gets that many guesses in total, not that many per lock
          window. The budget lives in ``_reproof_session_failures`` and is process-local.
        * During a live lock a failure is charged to the session only. Registering it on the account
          would re-arm or extend a lock the login leg's own pre-check never extends.

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

    @asynccontextmanager
    async def _account_reproof_lock(self, user_id: str) -> AsyncIterator[None]:
        """Hold the per-account lock that orders password re-proofs and session rotations."""
        entry = self._reproof_locks.setdefault(user_id, _ReproofLock())
        entry.users += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0:
                del self._reproof_locks[user_id]

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
            attempts, just_locked = 0, False
            if current is not None and not locked:
                attempts, just_locked = await self._register_failure(user, now)
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
                )
            return _Reproof(ok=False, user=user, attempts=attempts, just_locked=just_locked)
        if current is None:
            return _Reproof(ok=False, user=user)
        if not clear:
            # The password-change leg: nothing rotates here, and a change refused by policy leaves the
            # session as it was, budget included.
            return _Reproof(ok=True, user=current)
        # The re-auth leg: a good proof resets this session's budget, and the success rotates it.
        self._reproof_session_failures.pop(token_hash, None)
        cleared = (
            not locked
            and (current.failed_attempts > 0 or current.locked_until is not None)
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
        if proof.just_locked and proof.user is not None:
            await self._record_suspicious_login(
                ACCOUNT_LOCKED,
                proof.user,
                client=client,
                audit_detail=audit_detail,
                notice_detail={"failed_attempts": proof.attempts},
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
        re-bind** against the directory so AD operators aren't locked out. Always audited.

        ``purpose`` (ADR 0077) additionally mints a **single-use, action-bound** step-up grant for that
        named action, so a durable-takeover route (TOTP enroll/confirm, disable-MFA) can require a fresh
        proof tied to *it* rather than riding the broad session window. It is purely
        additive — the session-window refresh above is unchanged (the broad admin/replay/config routes
        keep using it), and the grant is minted ONLY here, never by login or ``verify_mfa``.

        Returns an :class:`Elevation`: on success the session is re-keyed (ASVS 7.2.4) and the NEW
        token is in ``Elevation.token``. The three steps below are ORDER-CRITICAL -- see the inline
        notes and :meth:`_rotate_session_token`.

        **A failure counts toward the account lockout on BOTH providers, and each session may fail
        at most ``lockout_threshold`` re-proofs before it is revoked (BACKLOG #1138).** See
        :meth:`_reproof`. The account lock itself gates sign-in, not this. A revoked session answers
        ``session_lost``. A success clears the counter only when the session has met its
        second-factor requirement and no lock is live (BACKLOG #1638's rule for the login leg), and a
        success that clears a run of failures is labelled ``auth.login_after_failures``."""
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
        if (
            proof.cleared
            and proof.user is not None
            and proof.user.failed_attempts >= SUSPICIOUS_LOGIN_FAILURE_THRESHOLD
        ):
            await self._record_suspicious_login(
                LOGIN_AFTER_FAILURES,
                proof.user,
                client=client,
                audit_detail=provider_detail,
                notice_detail={"failed_attempts": proof.user.failed_attempts},
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
        existing factor must be proven first (``POST /auth/mfa-verify``). Bootstrap is untouched — an
        account with NO factor still enrols, and still ends sessions, from a password-only session,
        which is exactly the deadlock carve-out. Disable/delete actions are NOT listed: they run
        behind ``require_step_up_action``, which keeps its own ``mfa_satisfied`` check.
        """
        if purpose not in self._PENDING_REFUSED_ACTIONS:
            return False
        return await self._owes_enrolled_factor(token)

    async def _owes_enrolled_factor(self, token: str | None, *, local_only: bool = False) -> bool:
        """Whether the session is MFA-pending on an account that already HAS a second factor.

        Fails closed (True) when the session or its user cannot be found. ``local_only`` answers
        False for a directory account, whose password the engine does not hold. It names AD rather
        than excluding everything that is not LOCAL: ``_build_identity`` maps an unrecognized
        provider back to LOCAL, so the password handler treats that row as local and changes it."""
        if not token:
            return True  # no session to act on, so fail closed (as below)
        if await self.mfa_satisfied(token):
            return False
        session = await self._store.get_session(hash_token(token))
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
        (single-use). ADR 0077. A grant is minted only by ``reauth(purpose=action)`` (POST /me/reauth
        or /ui/reauth), never by login or ``verify_mfa``, so a login-seeded step-up window cannot bind a
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
        ``[auth].step_up_max_age_seconds`` (login is the first verification) — the gate for sensitive
        operations (ASVS 7.5.3)."""
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
        :meth:`reauth` / :meth:`verify_mfa`), so the signal clears and the caller proceeds. It is
        **advisory + step-up-forcing only** — it never changes an authorization decision and never
        blocks the non-admin request path.

        Disabled (returns ``False`` with no side effects) unless ``[auth].admin_new_ip_step_up`` is on,
        so loopback behavior is byte-identical by default; and even on, a single-host loopback session
        never trips it because the request and the session resolve to the same loopback host (IPv4 or
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
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return False
        if session.mfa_verified_at is not None:
            return True
        user = await self._store.get_user(session.user_id)
        if user is None:
            return False
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
            # Keyed on the SESSION rather than folded into _mfa_required_for on purpose: that helper
            # answers "is this person exempt" for mfa_status and the last-factor-delete guard, and
            # only the session knows what was actually proven at mint time.
            return False
        roles = _roles_from_ids(await self._store.get_user_role_ids(user.id))
        # The extra store read only executes for sessions not already MFA-verified (the
        # mfa_verified_at early-return above short-circuits the common case).
        enrolled = await self._second_factor_enrolled(user)
        return not self._mfa_required_for(user, roles, second_factor_enrolled=enrolled)

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
        none.

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
        await self._store.enable_totp(identity.user_id, recovery_code_hashes=hashes)
        # Stamp against the OLD hash, then rotate — never the other way round.
        await self._store.mark_session_mfa_verified(hash_token(token))
        elevation = await self._elevated(
            token,
            ceremony="mfa_enroll_confirm",
            actor=identity.username,
            client=client,
            recovery_codes=tuple(plain),
        )
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
        first deployment."""
        if not token:
            return Elevation()
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return Elevation()
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled or not user.totp_enabled:
            return Elevation()
        now = time.time()
        # Per-account lockout covers the SECOND factor too (parity with the password path): a run of
        # wrong codes locks the account, so MFA guessing isn't bounded only by the shared per-IP login
        # limiter (which IP-rotation can sidestep). A locked account is refused before any verify.
        if user.locked_until is not None and now < user.locked_until:
            await self._audit(
                "auth.mfa_failed",
                actor=user.username,
                detail=_json({"reason": "locked"}),
                client=client,
            )
            return Elevation(locked=True)
        if await self._verify_second_factor(user, code, client=client):
            # ORDER-CRITICAL: this whole three-write group lands against the OLD hash, and only then
            # does the session rotate. Moving any of them after the rotation writes NOTHING and reports
            # success — every session UPDATE but revoke/rotate is rowcount-blind.
            # The 2nd factor is now satisfied; also seed the step-up window (the session has completed
            # password + MFA) and clear the failure counter. (Initial enrollment has no factor to verify,
            # so this never fires there — keeping the enrollment step-up gate honest, WP-14.)
            await self._store.mark_session_mfa_verified(hash_token(token))
            # Re-anchor the session to the address that completed the second factor (parity with
            # reauth), so an MFA-required admin who roamed clears the WP-L3-13 new-client-IP signal with
            # one credential proof rather than being forced into a separate password step-up.
            await self._store.mark_session_reauthed(hash_token(token), client=client)
            await self._store.record_login_success(user.id, now=now)
            await self._audit("auth.mfa_verified", actor=user.username, client=client)
            return await self._elevated(
                token, ceremony="mfa_verify", actor=user.username, client=client
            )
        # Wrong code: register the failure through the SAME machinery the password path uses, so the
        # per-account lockout + ACCOUNT_LOCKED notification fire on sustained MFA guessing.
        attempts, just_locked = await self._register_failure(user, now)
        await self._audit("auth.mfa_failed", actor=user.username, client=client)
        if just_locked:
            await self._record_suspicious_login(
                ACCOUNT_LOCKED,
                user,
                client=client,
                audit_detail=None,
                notice_detail={"failed_attempts": attempts},
            )
        return Elevation()

    async def _verify_second_factor(
        self, user: UserRecord, code: str, *, client: str | None = None
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
                secret, code, window=self._settings.totp_skew_steps
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
            mro = "".join(t.__name__ for t in type(exc).__mro__)
            if "Integrity" in mro or "UniqueViolation" in mro:
                raise ValueError("label already in use") from exc
            raise
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
        route's ``allow_login_attempt`` gate + cookie-holder-only reachability + these audits.

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
        # A locked account is refused BEFORE any verify (verify_mfa parity).
        if user.locked_until is not None and now < user.locked_until:
            await self._audit(
                "auth.webauthn_failed",
                actor=user.username,
                detail=_json({"reason": "locked"}),
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
    ) -> str:
        user_id = uuid4().hex
        await self._store.create_user(
            user_id=user_id,
            username=username,
            auth_provider=AuthProvider.LOCAL.value,
            display_name=display_name,
            email=email,
            password_hash=await self._argon2(hash_password, password),
            # Admin-set the credential is a one-time temp: force rotation on first login so the
            # operator never sets a lasting password the user keeps (ASVS 6.4.6 / WP-L3-12).
            must_change_password=True,
        )
        await self._store.set_user_roles(user_id, roles, assigned_by=actor)
        await self._audit(
            "user.created", actor=actor, detail=_json({"username": username, "roles": list(roles)})
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
    ) -> None:
        before = await self._store.get_user(user_id)  # capture old email/disabled for notifications
        await self._store.update_user_profile(user_id, display_name=display_name, email=email)
        # THE ENGINE-OWNED NOTIFICATION ADDRESS MOVES ONLY HERE, AND ONLY UPWARDS (BACKLOG #1139).
        # This is an administrator acting on the engine's own surface, so it is the one write allowed
        # to repoint where notices go — the directory sync above (`update_user_profile`, which
        # `_upsert_ad_user` also calls) is not.
        #
        # A BLANK ADDRESS FALLS THROUGH DELIBERATELY, and that is the durability rule in force: the
        # profile mirror clears, and the notification address stands. Requiring an address at creation
        # would not have achieved this on its own, because an explicit null still strips it afterwards
        # — and an account with no address is excluded from every later notice, which is exactly the
        # structural exclusion this item was filed against. `set_user_notify_email` takes `str`, so
        # there is no way to spell the clear even by mistake.
        if email is not None and email.strip():
            await self._store.set_user_notify_email(user_id, email=email)
        if disabled is not None:
            await self._store.set_user_disabled(user_id, disabled=disabled)
            if disabled:
                await self._store.revoke_user_sessions(user_id)
        await self._audit("user.updated", actor=actor, detail=_json({"user_id": user_id}))
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
                    email=before.notify_email,
                    detail={"new_email": email},
                )
            if disabled and not before.disabled:
                await self._notify_security(
                    ACCOUNT_DISABLED, username=before.username, email=before.notify_email
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
        temp = self._generate_policy_password()
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

    async def unbind_federated_subject(self, user_id: str, *, actor: str) -> int:
        """Admin: remove an account's federated ``(issuer, sub)`` binding and revoke every live
        session it holds (BACKLOG #1474). Returns the number of sessions revoked.

        The account keeps ``auth_provider='ad'``. A federated account is an AD row carrying an extra
        pair, so a NULL pair is exactly the state every AD account is in before its first federated
        login: a coherent directory account, still swept by :meth:`reconcile_directory_sessions`.
        The next federated login for it binds whatever subject then presents, which is what an
        operator unbinding it wants.

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
        outcome = await self._store.clear_user_federated_subject(user_id)
        if outcome is None:
            raise ValueError("no such user")
        # BOTH halves, matching the store's own predicate: either one set means the row had
        # something to clear and the store cleared it, so raising here would report "nothing to
        # remove" about a write that just happened.
        if outcome.issuer is None and outcome.subject is None:
            raise ValueError("the account has no federated binding to remove")
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
        return outcome.sessions_revoked

    async def set_channel_scope(
        self, user_id: str, channels: Sequence[str] | None, *, actor: str
    ) -> None:
        """Set a user's per-channel RBAC scope. Revokes their sessions so the new scope takes effect
        immediately, and audits the change.

        Three writable states, and ``None`` is no longer the wide one (BACKLOG #1152): ``None``
        clears the scope back to unset, which now DENIES every channel; ``[]`` denies too, and says
        somebody chose it; a list containing
        :data:`~messagefoundry.auth.identity.ALL_CHANNELS` grants the whole estate. Administrators
        are all-channels by role, so a scope set on one still has no effect."""
        scope_json = None if channels is None else _json(sorted(set(channels)))
        await self._store.set_user_channel_scope(user_id, scope_json, source=SCOPE_SOURCE_MANUAL)
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
        await self._notify_security(
            event_type,
            username=user.username,
            email=user.notify_email,
            client=client,
            detail=notice_detail,
        )

    async def _notify_security(
        self,
        event_type: str,
        *,
        username: str,
        email: str | None,
        client: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        """Best-effort out-of-band security-event push (ASVS 6.3.5/6.3.7). A missing notifier and a
        notifier failure are each WARNED and then swallowed — a notification must never break a login
        or an admin action. The caller writes the audit row, not this method: see
        :meth:`_record_suspicious_login` for the two 6.3.5 events.

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
                return
            _log.warning(
                "security notice %s for %s dropped: no security-event notifier is configured, so "
                "the account was not told out of band (the /me/security-events feed still records "
                "it)",
                event_type,
                username,
            )
            return
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
            _log.warning(
                "security-event notification failed (%s for %s)",
                event_type,
                username,
                exc_info=True,
            )
