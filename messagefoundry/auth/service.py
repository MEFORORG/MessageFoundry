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
import math
import os
import secrets
import sqlite3
import time
import unicodedata
import urllib.request
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Coroutine,
    Iterable,
    Mapping,
    Sequence,
)
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import cache
from types import MappingProxyType
from typing import Any, Final, Literal, TypeVar
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
    LdapReferralError,
    kerberos_principal,
    normalise_object_guid,
)
from messagefoundry.auth.notifications import (
    ACCOUNT_CREATED,
    ACCOUNT_DISABLED,
    ACCOUNT_LOCKED,
    ADMIN_NEW_IP,
    DIRECTORY_SESSIONS_ENDED,
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
    notice_kind_log_label,
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
from messagefoundry.config.secretprovider import (
    SecretProvider,
    SecretProviderError,
    resolve_connector_secret,
)
from messagefoundry.config.settings import AuthSettings
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    hop_url_host,
)
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.credential import constant_time_equal
from messagefoundry.store.base import AdminStore, store_driver_errors
from messagefoundry.store.crypto import MARKER_PREFIX, CipherError
from messagefoundry.store.store import (
    SCOPE_SOURCE_AD,
    SCOPE_SOURCE_MANUAL,
    AdminRemoval,
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
from messagefoundry.transports.email import envelope_address_problem
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


@cache
def _audit_write_errors() -> tuple[type[Exception], ...]:
    """What a refused audit write raises, at least on the store backends and key modes named here
    (BACKLOG #2137).

    The drivers' own errors, plus the two that :func:`~messagefoundry.store.base.store_driver_errors`
    asks a caller to add: ``RuntimeError`` for the engine's own refusals (the acquire timeout, a
    keyless audit append) and ``OSError`` for a connection lost at the socket. And ``CipherError``,
    which a ``vault_transit`` store raises when Transit cannot compute the audit-chain MAC (ADR
    0138). Built on first use, because naming a server driver imports it; an ``AuthService`` that
    runs the reconciler builds it at construction, so that import never runs on the event loop in
    the middle of a store incident."""
    return (RuntimeError, OSError, CipherError, *store_driver_errors())


#: The classes inside :func:`_audit_write_errors` that a reconciler audit write raises rather than
#: passes over (BACKLOG #2137). ``RuntimeError`` has to stay in that catch,
#: because the store raises it for its own refusals; ``NotImplementedError`` and ``RecursionError``
#: are its subclasses that never mean one. ``sqlite3.ProgrammingError`` is a bad statement or bind:
#: the SQLite store reaches sqlite3 through aiosqlite, which refuses a closed connection with its
#: own ``ValueError`` first. pyodbc's ``ProgrammingError`` stays caught, because pyodbc raises it
#: for a closed connection too, and raising that would cost the pass's alerts, the harm BACKLOG
#: #2137 removed.
_AUDIT_WRITE_DEFECTS: Final = (NotImplementedError, RecursionError, sqlite3.ProgrammingError)


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
    run used to fail there, and :func:`generate_policy_password` now suppresses this screen
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

#: Cap on concurrent directory probes from the mTLS certificate path (BACKLOG #2316). Each probe
#: holds a worker thread for up to the LDAP connect and receive timeouts, so a burst of certificate
#: requests during a slow directory must not drain the thread pool every other leg shares.
_CERT_PROBE_MAX_CONCURRENCY = 8
#: How long a certificate request waits for a probe slot before it is refused. Short on purpose: a
#: full cap means the directory is slow, and a service caller retries, so queueing without a bound
#: would only stack requests behind a stalled directory. A refusal fails closed.
_CERT_PROBE_SLOT_WAIT_SECONDS = 2.0
#: The refusal reason when no probe slot freed in time. Not a directory answer.
CERT_PROBE_SATURATED = "probe_capacity_saturated"
#: Refusals that say the directory could not be asked, not what it said about the account. The
#: certificate path logs these once per outage rather than once per request.
_CERT_DIRECTORY_OUTAGES = frozenset(
    {
        reconcile.ProbeOutcome.UNAVAILABLE.value,
        reconcile.ProbeOutcome.REFERRED.value,
        CERT_PROBE_SATURATED,
    }
)
#: The least time between two certificate-path outage WARNINGs, so a flapping outage cannot log
#: one WARNING and INFO pair per request.
_CERT_OUTAGE_LOG_INTERVAL_SECONDS = 60.0
#: The level ``_probe_principal`` logs an unexpected directory fault at. WARNING for the reconciler
#: and step-up; the certificate path sets DEBUG in its probe task's own context (BACKLOG #2316).
_PROBE_FAULT_LOG_LEVEL: ContextVar[int] = ContextVar(
    "_PROBE_FAULT_LOG_LEVEL", default=logging.WARNING
)
#: Outcomes the directory itself gave. Any of them ends a logged outage.
_CERT_DIRECTORY_ANSWERS = frozenset(
    outcome.value
    for outcome in (
        reconcile.ProbeOutcome.PRESENT,
        reconcile.ProbeOutcome.ABSENT,
        reconcile.ProbeOutcome.DISABLED,
        reconcile.ProbeOutcome.UNDETERMINED,
    )
)

# Bound on the per-process new-client-IP dedup cache (WP-L3-13). It only debounces the audit/notify
# side effects of the 8.4.2 signal; the step-up decision never depends on it, so eviction is harmless.
_NEW_IP_DEDUP_MAX = 4096

# BACKLOG #2159: the most new addresses one session may have audited between two re-verifications.
# The signal runs on every sensitive request, so this, plus one row saying the cap is reached, is the
# ceiling on audit rows and notices one token can cause before its holder proves the credential
# again. A real operator roams across a few networks, not eight; a token used from more hosts than
# that has already been reported nine times, and the step-up stays forced for every further address.
# With _NEW_IP_DEDUP_MAX it bounds the cache at 4096 x 9 address keys.
_NEW_IP_PER_SESSION_MAX = 8

# The first-seen login-address signal (BACKLOG #288, ASVS 8.2.4). Its baseline is the store's
# per-account ``known_login_addresses`` record (vault BACKLOG #2145), read at every session mint with
# one primary-key lookup. An address last seen before this window reads as NEW -- the signal answers
# "seen RECENTLY", and erring that way costs one challenge and one notice, never a refused login. The
# same window is the record's retention: each write prunes that account's rows older than it.
_LOGIN_ADDRESS_LOOKBACK_SECONDS = 90 * 86400
# The longest host key the record keeps, in UTF-16 code units, matching the SQL Server NVARCHAR(256)
# column. An IP address's key is at most 45 characters; a longer key is not remembered, so it reads as
# NEW at every sign-in.
_LOGIN_ADDRESS_KEY_MAX = 256
# One ``login_new_ip`` notice per account and address per this many seconds, in each engine process
# (see ``_login_new_ip_notice_due``). The audit row is not debounced.
_LOGIN_NEW_IP_NOTICE_SECONDS = 900.0


class _LoginAddress(Enum):
    """What the first-seen login-address signal concluded for one sign-in (BACKLOG #288).

    Only ``NEW`` challenges. The two ``UNEVALUATED_*`` members are the fail-open cases: the signal
    had nothing to compare, so it lets the login mint as it would have and audits that it could not
    judge."""

    KNOWN = "known"
    NEW = "new"
    # The account has never completed a sign-in and has no known address, so every address would be
    # "first seen". Challenging and notifying here would fire on every account's first login, which is
    # noise, not signal.
    UNEVALUATED_NO_BASELINE = "no_baseline"
    # The caller passed no client address (an in-process caller, or an ASGI scope with no client).
    UNEVALUATED_UNKNOWN_ADDRESS = "unknown_address"
    # The baseline read raised. A store fault must not turn this signal into a refused login.
    UNEVALUATED_READ_FAILED = "read_failed"


#: The verdicts under which a LOCAL sign-in that owes no factor adds its address to the known record,
#: and under which a factor enrolment does (vault BACKLOG #2145). Not ``NEW``: on the local leg that verdict withholds the step-up window, which
#: is the challenge, and writing the address would let the next sign-in from it skip that challenge.
#: Not ``UNEVALUATED_READ_FAILED``: a sign-in the signal could not judge is no evidence about its
#: address. See ``_mark_login_address_known``.
_LOGIN_VERDICTS_THAT_SEED_THE_BASELINE = frozenset(
    {_LoginAddress.KNOWN, _LoginAddress.UNEVALUATED_NO_BASELINE}
)


def _host_key(address: str) -> str:
    """One string per host, for comparing and remembering client addresses.

    An IPv4-mapped IPv6 address folds to its IPv4 form, so a bind change between ``0.0.0.0`` and
    ``::`` does not make every stored address read as new. Every loopback address folds to ``::1``,
    so a dual-stack box that presents ``127.0.0.1`` on one connection and ``::1`` on the next is one
    host. Any other address takes its canonical text, so ``2001:DB8::1`` and ``2001:db8::1`` match.
    Text that does not parse as an address is its own key, which is an exact-match fallback."""
    try:
        parsed: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    if parsed.is_loopback:
        return "::1"
    return str(parsed)


#: What :meth:`AuthService._first_new_ip_flag` decided for one request: write the ordinary row, write
#: the one row that says the session's cap is now reached, or write nothing because the address is a
#: repeat or the cap was already reached.
_NewIpFlag = Literal["audit", "audit_cap_reached", "repeat", "over_cap"]
#: `AuthService._reconcile_hold_standing`: whether this process may resolve a hold (BACKLOG #2136).
_HoldStanding = Literal["fresh", "held", "forfeit", "settled"]
#: The standings under which a pass may resolve the durable hold instance.
_HOLD_RELEASABLE: Final[frozenset[_HoldStanding]] = frozenset({"held", "settled"})
#: `AuthService._reconcile_breaker_standing`: whether this process may resolve a trip (BACKLOG
#: #2136). Only ``"tripped"`` may.
_BreakerStanding = Literal["fresh", "tripped", "forfeit"]
#: `AuthService._reconcile_referral_standing`, the same rule for the referral's own instance
#: (BACKLOG #2538). Only ``"referred"`` may resolve it.
_ReferralStanding = Literal["fresh", "referred", "forfeit"]


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

#: The share of the budget a refused sign-in's deferred audit writes are guaranteed before its answer
#: (BACKLOG #2467, ASVS 6.3.8). The answer's deadline is fixed BEFORE those writes run, and it is the
#: first slot boundary at least this far past the write point, so the writes cannot move it. Without
#: the room, a caller who queues a second attempt on the name picks how close that boundary sits to
#: the write point, and a branch that writes more rows than another would cross it. A quarter keeps
#: an attempt that did not queue in slot 1: its write point is half a budget in, so it reaches only
#: three quarters.
_WRITE_ROOM_SHARE = 0.25

#: Per-process, per-seam latch for the budget-overrun warning. Deliberately module-level and not
#: per-instance: the warning reports that THIS DEPLOYMENT's budget is too small for its hardware,
#: which is a fact about the process, not about one service object. One warning per seam per process
#: — the login surface is unauthenticated, so warning on every overrun would be the same unbounded
#: log amplifier the rate-limited audit paths already exist to avoid.
_BUDGET_OVERRUN_WARNED: set[str] = set()


def _warn_budget_overrun(seam: str, took: float, *, writes: bool = False) -> None:
    """Warn, once per seam and cause per process, that a failure on ``seam`` answered a slot late.

    The budget is then too small for this hardware. The answer still cannot fail open
    (:func:`_failure_deadline` always rounds up), but a pair of branches straddling the slot boundary
    would stay distinguishable. ``took`` is the work, leaving out any wait in the account's queue,
    or with ``writes`` the deferred audit writes alone (BACKLOG #2467). The two causes latch apart,
    so the first to fire does not hide the other."""
    key = f"{seam}:writes" if writes else seam
    if key in _BUDGET_OVERRUN_WARNED:
        return
    _BUDGET_OVERRUN_WARNED.add(key)
    if writes:
        _log.warning(
            "auth: a failed %s challenge's audit writes took %.3fs, over the %.3fs room the pad "
            "leaves them; responses are being padded to a later slot (further write overruns are "
            "not logged)",
            seam,
            took,
            _FAILURE_BUDGET_SECONDS * _WRITE_ROOM_SHARE,
        )
        return
    _log.warning(
        "auth: a failed %s challenge took %.3fs, over the %.3fs anti-enumeration budget; "
        "responses are being padded to a later slot (further overruns are not logged)",
        seam,
        took,
        _FAILURE_BUDGET_SECONDS,
    )


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


def _prune_grants(grants: dict[tuple[str, str], float], now: float) -> None:
    """Drop every expired entry from a per-action grant map (monotonic clock)."""
    for key in [k for k, deadline in grants.items() if deadline <= now]:
        del grants[key]


def _bounded_grant_put(
    grants: dict[tuple[str, str], float], key: tuple[str, str], deadline: float, now: float
) -> None:
    """Prune ``grants``, evict its OLDEST entry at :data:`_ACTION_STEP_UP_GRANT_MAX` (fail-safe: a
    dropped grant just re-prompts, never a bypass), then store ``key``."""
    _prune_grants(grants, now)
    if key not in grants and len(grants) >= _ACTION_STEP_UP_GRANT_MAX:
        del grants[min(grants, key=grants.__getitem__)]
    grants[key] = deadline


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
# Vault BACKLOG #2625. The routes that inject a message, send a stored body to another partner,
# export bodies in bulk, cancel queued deliveries or swap the live graph. Each takes a proof bound to
# its own action, so one live session inside the step-up window is not enough to do any of them.
# Only these: the rest of the step-up surface keeps the shared window, because a proof per action is
# a typed password, and an operator replaying dead letters during an incident would type it per message.
STEP_UP_ACTION_MESSAGE_RESEND = "message_resend"
STEP_UP_ACTION_MESSAGE_EDIT_RESEND = "message_edit_resend"
STEP_UP_ACTION_UPLOAD_RESEND = "upload_resend"
STEP_UP_ACTION_MESSAGE_EXPORT = "message_export"
STEP_UP_ACTION_CONNECTION_PURGE = "connection_purge"
STEP_UP_ACTION_CONFIG_RELOAD = "config_reload"

#: The actions whose spent grant :meth:`AuthService.refund_action_step_up` may give back: the two
#: routes that issue a generated credential and can refuse BEFORE any side effect (ADR 0197
#: Amendment A, Manager decision 2026-09-29). No other action's grant is recorded, so no other
#: route can restore one, whatever it calls.
_REFUNDABLE_ACTIONS = frozenset(
    {STEP_UP_ACTION_ADMIN_RESET_PASSWORD, STEP_UP_ACTION_ADMIN_RESET_MFA}
)

#: The grant THIS REQUEST spent on a refundable action, as ``(service id, key, deadline)``, or
#: ``None``. A context variable, not a map on the service: the route gate spends the grant and the
#: handler that may refund it run in one request's context, so a refund can only ever restore the
#: grant its own request spent -- never one a concurrent request of the same session spent, which a
#: map keyed by (token, action) could not tell apart. The service id binds it to the instance that
#: issued the grant, so no other instance can take it. Every
#: :meth:`AuthService.has_action_step_up` call overwrites it, so every action-bound gate starts its
#: request from a clean record; a successful action leaves its spend in place, which is harmless
#: because a refund is reached only after a gate that has just overwritten it. It does NOT rely on
#: a task boundary between requests.
_SPENT_REFUNDABLE_GRANT: ContextVar[tuple[int, tuple[str, str], float] | None] = ContextVar(
    "_SPENT_REFUNDABLE_GRANT", default=None
)

#: The closed-set reason a federated login is refused with when its verified ``(issuer, sub)`` is
#: bound to no account (ADR 0184 AC-4). Named because the browser layer maps it to a login-page code.
FEDERATED_SUBJECT_NOT_BOUND = "federated_subject_not_bound"

#: The closed-set reason a Windows SSO sign-in is refused with when the account it resolves to holds
#: a federated binding (vault BACKLOG #2609). That account signs in through its identity provider.
#: Written on the ``auth.login_failed`` audit row. Deliberately absent from the browser layer's code
#: map, and the Windows SSO routes read no reason at all, so a caller sees the generic failure.
FEDERATED_SIGN_IN_REQUIRED = "federated_sign_in_required"

#: The closed-set reason :meth:`AuthService.bind_federated_subject` refuses an account with when the
#: account carries no ``directory_object_id`` (BACKLOG #1143 slice C, ADR 0184 AC-5). Written into the
#: ``auth.federated_bind_refused`` audit row and carried on :class:`DirectoryObjectIdMissing`. Also the
#: reason a federated login refuses an already-bound id-less row, and a reconciliation pass skips one
#: (BACKLOG #2027). So do a Windows SSO sign-in whose principal carries no id, and an AD step-up
#: re-bind or ``verify_mfa`` directory check on a row with none. Deliberately absent from the
#: browser layer's code map, so it shows as generic.
DIRECTORY_OBJECT_ID_MISSING = "directory_object_id_missing"

#: The closed-set reason a directory answer is refused with when it names another directory object
#: than the row's own (BACKLOG #1471 at sign-in, #2027 at the step-up re-bind).
DIRECTORY_IDENTITY_CONFLICT = "directory_identity_conflict"

#: The code that opens :class:`FederatedBindingChanged`'s message (BACKLOG #2026), so a caller can
#: tell that refusal from the other 409 on the federated-identity routes without matching prose.
FEDERATED_BINDING_CHANGED = "federated_binding_changed"

#: The closed-set reason a password re-proof is refused with on a session the federated login
#: minted (BACKLOG #296, ADR 0142 Amendment B). Its step-up goes back to the IdP, so the password is
#: never checked and nothing is charged to the lockout. Carried on ``Elevation.idp_step_up_required``.
IDP_STEP_UP_REQUIRED = "idp_step_up_required"

#: The closed-set reason :meth:`AuthService.verify_mfa` (BACKLOG #2023) and
#: :meth:`AuthService.finish_webauthn_assertion` (BACKLOG #2239) refuse a directory account with
#: when the directory does not confirm it is present and enabled. Written into the
#: ``auth.mfa_failed`` or ``auth.webauthn_failed`` audit row beside the probe's outcome, and carried
#: on ``Elevation.directory_unconfirmed``. The code or assertion is never checked and nothing is
#: charged.
DIRECTORY_UNCONFIRMED = "directory_unconfirmed"

#: The ``auth.reauth`` reason for a directory step-up re-bind sent with an empty password (BACKLOG
#: #2434). The directory is never asked and nothing is charged; the caller sees a refused password.
EMPTY_PASSWORD = "empty_password"  # nosec B105 -- an audit reason slug, not a credential

#: The outcome :meth:`AuthService._directory_step_up_refusal` gives a present, enabled directory
#: account whose stored roles are not all among the roles its current groups map to (BACKLOG #2240).
#: Audited beside :data:`DIRECTORY_UNCONFIRMED`, like the probe's own outcomes. The federated
#: step-up leg refuses with it too, as its own closed-set reason (BACKLOG #2154).
DIRECTORY_ROLES_DEMOTED = "directory_roles_demoted"

#: The closed-set reasons the federated step-up leg refuses with (BACKLOG #296), on the
#: ``auth.reauth`` audit row and on :class:`OidcStepUp`. A claims-ladder slug can also appear there.
STEP_UP_NOT_FRESH = "step_up_not_fresh"
STEP_UP_SUBJECT_MISMATCH = "step_up_subject_mismatch"
#: The IdP-clock freshness test's two refusals (BACKLOG #2143), kept apart from the engine-clock
#: :data:`STEP_UP_NOT_FRESH`. MISSING never clears on a retry against the same session, which holds
#: no IdP ``auth_time`` to compare. NOT_LATER clears once the IdP answers with a later one, for
#: example after a stepped-back IdP clock passes the held value. It does not clear while the IdP
#: keeps answering from an earlier sign-in, or while a slower IdP node answers.
STEP_UP_IDP_AUTH_TIME_MISSING = "step_up_idp_auth_time_missing"
STEP_UP_IDP_AUTH_TIME_NOT_LATER = "step_up_idp_auth_time_not_later"
FLOW_PURPOSE_MISMATCH = "flow_purpose_mismatch"

#: The audit reason for a second step refused under its ASVS 2.4.2 minimum-elapsed floor (BACKLOG
#: #2301): an MFA code or passkey too soon after sign-in, or an IdP callback too soon after its flow
#: started. Audit only. The caller sees its leg's ordinary failure, which says nothing about timing.
TOO_EARLY = "too_early"

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
        # A new sign-in stores a new IdP auth_time, which is what the next step-up is compared
        # with. MISSING says only that, because a retry on this session cannot pass. NOT_LATER
        # offers a retry first, because a later IdP answer can pass it (see the reasons above).
        STEP_UP_IDP_AUTH_TIME_MISSING: (
            "This session holds no sign-in time from the identity provider, so the provider cannot"
            " confirm it's you here. Sign out, then sign in again."
        ),
        STEP_UP_IDP_AUTH_TIME_NOT_LATER: (
            "The identity provider's answer is no newer than this session's last confirmation, so"
            " it could not confirm it's you. Try again. If it repeats, sign out, then sign in again."
            " If it still repeats, the provider may be ignoring max_age=0 and prompt=login, or its"
            " clocks may disagree."
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
        # The documented fix is a new sign-in, which takes its roles from the current groups
        # (BACKLOG #2154). An administrator has nothing to change.
        DIRECTORY_ROLES_DEMOTED: (
            "Your directory groups no longer grant the roles this session holds. Sign out, then"
            " sign in again to take the roles your groups grant now."
        ),
    }
)

#: The text ``POST /users`` answers a taken username with, from its pre-check and from
#: :class:`UsernameTaken` alike (BACKLOG #1808).
USERNAME_TAKEN = "username already exists"

_T = TypeVar("_T")


@dataclass(frozen=True)
class RolesGained:
    """The roles a directory sign-in's role sync NEWLY gave an account (vault BACKLOG #2610).

    ``username`` is the account the sync wrote to, which is not always the name the directory
    presented, so a caller keys on this and never on the sign-in's input. ``roles`` holds role ids
    and is never empty: a sync that gained nothing reports no :class:`RolesGained` at all."""

    username: str
    roles: frozenset[str]


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
    #: Set only by a directory sign-in whose role sync newly gave the account a role (vault BACKLOG
    #: #2610). ``auth/`` raises no alert (CLAUDE.md section 4), so every route that completes a
    #: directory sign-in reads this and raises ``administrator_granted`` when Administrator is among
    #: the roles. Set on a refused outcome too: a bind landing between the sync and the mint refuses
    #: the session after the roles were written, and that grant happened all the same.
    roles_gained: RolesGained | None = None


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
      budget, in which case the proof was wrong or never checked; or (any ceremony, BACKLOG #2298)
      the session was ended because its temporary password lapsed, with the proof checked or not,
      as that ``auth.temp_password_expired`` row records; or (``confirm_mfa_enrollment`` only,
      BACKLOG #2224) the proof was good but turning TOTP on matched no row, so the confirm ended
      the session it had just rotated, as its ``auth.mfa_enroll_refused`` row records. Fails
      CLOSED: no token is handed back. Held apart from a wrong proof so a route answers 401 rather than re-prompting on a
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
    #: Set by :meth:`AuthService.verify_mfa`, on a directory account the directory did not confirm
    #: as present and enabled, including when it could not be reached (BACKLOG #2023), or a row with
    #: no directory id (BACKLOG #2027). Set by :meth:`AuthService.reauth` when the directory re-bind
    #: could not judge the password, for at least these causes: no directory, no enabled entry for
    #: the row's id, an unreachable one, a row with no id, or an entry that is not provably the
    #: row's own (BACKLOG #2027). Set by :meth:`AuthService.finish_webauthn_assertion` on the same
    #: answers as ``verify_mfa`` (BACKLOG #2239). In every case the proof was never checked and
    #: nothing was charged. It qualifies the wrong-proof state: the token still authenticates, and
    #: the caller must say the directory could not confirm the account rather than call the code,
    #: the password or the passkey wrong. The cause goes to the audit row (``reason`` on
    #: ``auth.reauth``, ``outcome`` on ``auth.mfa_failed`` or ``auth.webauthn_failed``) and never
    #: to the caller.
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
    #: a session opened before the instant would otherwise still perform with it. The session is
    #: ended with the answer (BACKLOG #2298), so the caller's token no longer authenticates.
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


class LastAdministratorRefused(RuntimeError):
    """An administrator's change would have left no enabled administrator (vault BACKLOG #2779).
    Raised before anything is written. The message is the operator-facing refusal."""


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

#: The username the generator probe screens against: synthetic, long, and unlike any real account
#: name, so the own-username clause cannot be the reason the probe fails.
_PROBE_USERNAME = "mf-startup-credential-probe"

#: What to do about a generator refusal, in one string so the ERROR log, the raised message (the 503
#: detail) and the docs cannot drift apart (BACKLOG #2359). It names the environment variable because
#: it overrides the TOML key, and it names every engine process because each builds its policy once,
#: at start: a fix applied to one shard or one cluster node leaves the others refusing. No trailing
#: period, because :func:`credential_generation_problem` appends its own sentence after it.
SITE_TERMS_FIX_ADVICE: Final = (
    "Check [auth].password_extra_context_words, or MEFOR_AUTH_PASSWORD_EXTRA_CONTEXT_WORDS, which "
    "overrides it, for short or very common terms. Then restart every engine process: each engine "
    "shard and each cluster node reads [auth] only at start, and a /config/reload does not re-read it"
)


def credential_generation_problem(policy: PasswordPolicy) -> str | None:
    """Try the temporary-credential generator once under ``policy`` and a synthetic username (ADR 0197
    Amendment A, Manager decision 2026-09-29). ``None`` when it can issue; otherwise the refusal,
    followed by what it breaks. The generated value is discarded. The one probe behind both the
    engine's startup check and ``messagefoundry verify``'s ``auth.credential_generation``."""
    try:
        # Quiet: each caller reports the failure once, in its own words.
        generate_policy_password(policy, username=_PROBE_USERNAME, log_failure=False)
    except TemporaryPasswordUnavailable as exc:
        return (
            f"{exc}. Creating an account, resetting a password and resetting an account's factors "
            "will answer 503 until it is fixed."
        )
    except Exception as exc:  # noqa: BLE001 -- a probe reports; it never stops `serve` or `verify`
        return (
            f"the credential generator raised {type(exc).__name__}, so creating an account and both "
            "resets would fail too"
        )
    return None


def _temporary_password_chars(min_length: int) -> int:
    """The generated password's length: the policy minimum, but never under 32 characters.
    ``token_urlsafe`` carries 6 bits per character, so 32 characters keep the 192-bit floor of BACKLOG
    #1172, and any longer minimum carries more."""
    return max(32, min_length)


def generate_policy_password(
    policy: PasswordPolicy, *, username: str | None = None, log_failure: bool = True
) -> str:
    """A random password that satisfies the active policy — so an administrator-issued temporary
    credential is held to the same bar operators are. ``token_urlsafe(n)`` yields about 1.33 times
    n characters, cut to :func:`_temporary_password_chars`, so the length is at least
    ``min_length``. The loop covers a context hit or an opt-in character-class requirement a given
    token happens to miss.

    Every clause except the breach screen, which is suppressed per-call for the reason stated at
    the call below (BACKLOG #1447).

    ``username`` is the account the password is for, so the own-username clause applies too.
    ``log_failure=False`` is for :func:`credential_generation_problem`, whose callers log or print
    the failure themselves; every issuing path keeps the ERROR.

    Raises :class:`TemporaryPasswordUnavailable` when no candidate clears the policy. It never
    returns an unscreened password. The old last-resort return appended ``aA1!`` without a screen,
    so a site context word inside it would have issued a credential the policy refuses (BACKLOG
    #1132)."""
    # At least 32 CHARACTERS (192 bits). token_urlsafe's argument is a byte count and min_length
    # is a CHARACTER count, so the bytes are derived from the characters: 3 bytes make 4
    # characters, and the cut below never pads, so a short byte count would silently lower the
    # entropy floor (BACKLOG #1172).
    chars = _temporary_password_chars(policy.min_length)
    length = -(-chars * 3 // 4)  # ceiling: enough bytes for `chars` characters
    # The suffixed form exists only for an opt-in character class the bare token happens to miss.
    # With every class rule off it cannot help: the bare token then fails only on a context word
    # or the username, and the suffix keeps either one. Read from the policy, not from four field
    # names, so a class rule added later is not skipped here (BACKLOG #2359). The suffix still
    # covers only the four classes today: a new class it misses needs the suffix extended too, and
    # until then the screen refuses that candidate rather than issuing it.
    class_rules = policy.requires_character_class
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
    if log_failure:
        _log.error(
            "no temporary password cleared the password policy in %d tries; the likely cause is "
            "[auth].password_extra_context_words holding so many short terms that nearly every "
            "random string contains one, which would refuse most passphrases too. %s",
            _RESET_GENERATION_ATTEMPTS,
            SITE_TERMS_FIX_ADVICE,
        )
    raise TemporaryPasswordUnavailable(
        "could not generate a temporary password that clears the password policy. "
        + SITE_TERMS_FIX_ADVICE
    )


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
        # The rule send_plain_email applies to every notice's RCPT TO (vault BACKLOG #2870). Without
        # it, an address accepted here could never be sent to, and every later notice would fail.
        and envelope_address_problem(address) is None
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

    The check that surfaces taking a typed address apply. They include at least the holder's own
    fill, an administrator's change, and the host commands ``admin-set-notify-email`` and
    ``provision-admin --email`` (vault BACKLOG #2870). Not blank (:func:`require_notify_email`),
    and one plain mailbox (:func:`_is_single_mailbox`). When the send rule is what refuses it, the
    message carries that rule's reason, which never quotes the address."""
    try:
        address = require_notify_email(value)
    except ValueError as exc:
        raise InvalidNotifyEmail(str(exc)) from exc
    if not _is_single_mailbox(address):
        message = "enter one email address, such as name@example.org"
        problem = envelope_address_problem(address)
        if problem is not None:
            message += f"; this one {problem}"
        raise InvalidNotifyEmail(message)
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


class _DirectoryAccountConflict(Exception):
    """A directory login lost the first-sight create race to a row it may not adopt (BACKLOG #2697).

    Raised by :meth:`AuthService._upsert_ad_user` when its INSERT met the username index and the row
    that won is LOCAL, or carries a different immutable id. Caught by
    :meth:`AuthService._complete_ad_login`, which renders it as the conflict refusals it already
    makes before the resolver runs: an ``account conflict`` outcome, audited with ``reason``.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _BindingChangedMidLogin(Exception):
    """An admin changed the account's federated binding while this login was still in flight.

    Two directions, one signal. A federated login whose account was UNBOUND under it (BACKLOG
    #1474), and a Windows SSO login whose account was BOUND under it (vault BACKLOG #2609).

    Raised by :meth:`AuthService._issue_session` when the store refuses the conditional insert, and
    caught by :meth:`AuthService._complete_ad_login`, which renders it as an audited refusal.

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
    caller's ``expected_source`` does not match the stored one. Or another write changed the source
    between this write's read and its compare-and-set: at least an AD sign-in, or another
    administrator's save. "The directory's" and "the stored one" both
    mean :func:`_effective_scope_source`, not the raw column (BACKLOG #2252).

    Each refusal writes one :data:`CHANNEL_SCOPE_CHANGE_REFUSED_ACTION` row first (BACKLOG #2271)."""


#: BACKLOG #2271: the row a refused :meth:`AuthService.set_channel_scope` writes. Its detail names the
#: account, the caller's ``expected_source``, the raw stored source the write read
#: (``read_source``), the scope's ``owner`` and a ``reason`` from :data:`ChannelScopeRefusal`. Never
#: the scope itself. On ``source_changed`` the owner is the one read after the write failed, so it
#: names whoever took the scope: at least a directory sign-in or another administrator's save. A
#: legacy AD scope reads ``read_source`` null and ``owner`` ``"ad"`` (BACKLOG #2252). A store that
#: refuses the row leaves an ERROR log line instead, and the 409 still stands.
CHANNEL_SCOPE_CHANGE_REFUSED_ACTION: Final = "user.channel_scope_change_refused"
ChannelScopeRefusal = Literal["directory_owned", "expected_source_mismatch", "source_changed"]


def _effective_scope_source(user: UserRecord) -> ChannelScopeSource | None:
    """Who owns ``user``'s stored channel scope, for the save's intent check (BACKLOG #2252).

    **This is the one statement of the rule; other comments point here.** The stored source,
    except on an AD account whose scope was stored before the source column existed (#1927): there
    it is NULL, and nothing backfilled it. The login sync manages such a scope as it manages a
    directory one: with no mapped group, :func:`channel_scope.decide_ad_channel_scope` withdraws
    any grant that is not manual. So a save, which makes the scope manual and takes it out of the
    sync's hands, needs the same ``expected_source="ad"``. That holds for a stored scope that
    already denies, too: the sync keeps it only because withdrawing it changes nothing, and the
    save's new value is what gets pinned. A local account never meets the sync, and a NULL scope
    has nothing stored, so both keep their NULL.

    The web console's ``needs_manual_scope_confirm`` asks the same three questions through
    ``UserSummary``, because the console cannot import this module. A test in the console's suite
    compares the two."""
    stored = user.channel_scope_source
    if (
        stored is None
        and user.channel_scope is not None
        and user.auth_provider == AuthProvider.AD.value
    ):
        return SCOPE_SOURCE_AD
    return stored


#: The ONE detail every refusal of ADR 0197 Amendment A's first-sign-in order carries (N-B2 part 4):
#: a password change, a passkey registration and a TOTP removal refused because the account would
#: hold no factor with a way past the sign-in lock. Fixed, so it tells a caller nothing it did not
#: already know from holding the session.
ENROL_AUTHENTICATOR_FIRST = "enrol an authenticator app first"


#: The detail ``disable_mfa`` refuses with while ``[security].require_mfa`` covers the account (ADR
#: 0197 Amendment A, AC-A3a). In wave 1 TOTP is the only way past the sign-in lock, so a covered
#: account keeps it; an administrator's factor reset remains the recovery.
TOTP_REMOVAL_REFUSED = (
    "your authenticator app is the last second factor that gets you past a sign-in lock, and MFA "
    "is required for your account, so it cannot be removed -- an administrator can reset it"
)


class FactorEnrolmentRequired(ValueError):
    """The account ``[security].require_mfa`` covers holds no factor with a way past the sign-in lock,
    so this step must wait until it enrols one (ADR 0197 Amendment A, N-B2 part 4). In wave 1 only
    TOTP is such a factor. A ``ValueError`` so every route that already renders a flow refusal renders
    this one too; the password routes map it to 403 with :data:`ENROL_AUTHENTICATOR_FIRST`."""

    def __init__(self) -> None:
        super().__init__(ENROL_AUTHENTICATOR_FIRST)


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
    bind. The step-up re-proof, ``verify_mfa``'s directory check and a Windows SSO sign-in no
    longer reach an id-less row at all: each refuses it with this reason (BACKLOG #2027). For a
    binding already on an id-less row, written before this refusal existed or planted through that
    setter, the two re-resolves above no longer ask by name (BACKLOG #2027): the federated login
    refuses it with this same reason, and the reconciler skips it
    (``_holds_unkeyed_federated_binding``).
    **The cost:** on a directory that returns no readable ``objectGUID``, no account can be bound.

    :meth:`AuthService.create_directory_account` raises it too, before any write, when the directory
    returns no readable ``objectGUID`` for the account named: the row it would create could never
    take a binding (BACKLOG #2021).
    """

    reason = DIRECTORY_OBJECT_ID_MISSING


@dataclass(frozen=True)
class FederatedBinding:
    """What :meth:`AuthService.bind_federated_subject` wrote (BACKLOG #1143).

    ``previous_*`` are ``None`` for a first bind. ``sessions_revoked`` counts every session the bind
    ended: the ones a rebind's clear swept, plus the ones the write's own transaction swept. Every
    bind ends every session of the account, a first bind included (vault BACKLOG #2609).
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


async def _sleep_until_write_point(deadline: float) -> None:
    """Await the monotonic instant a refused sign-in writes its audit rows (BACKLOG #1131).

    Kept apart from :func:`_sleep_until`, which is the answer's pad: tests replace that one to read
    back the one deadline each seam computes, and this wait is not a second pad."""
    remaining = deadline - time.monotonic()
    if remaining > 0:
        await asyncio.sleep(remaining)


async def _write_through_cancellation(writes: Sequence[Callable[[], Awaitable[None]]]) -> None:
    """Run ``writes`` to completion even if the caller is cancelled, then re-raise the cancel.

    Shielded, and awaited again after each cancel, so a repeated cancellation neither abandons the
    writes nor lets the caller leave (and release the account's queue) before they finish. A write
    that fails raises as it did when the rows were written inline."""
    task = asyncio.ensure_future(_run_in_order(writes))
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            # Recorded before anything else, so a cancel that lands in the turn the writes finish
            # is still re-raised rather than swallowed.
            cancelled = True
    if cancelled:
        if not task.cancelled() and task.exception() is not None:
            # Nobody else will read it: the caller is leaving with the cancel.
            _log.error(
                "a refused sign-in's audit write failed while the request was cancelled",
                exc_info=task.exception(),
            )
        raise asyncio.CancelledError
    task.result()


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
    # Vault BACKLOG #2778. Fail closed: no entry is provably this account, so its sessions end
    # after the strikes, as for a missing one. A wave of these is not held the way UNDETERMINED is.
    DirectoryAnswer.AMBIGUOUS: reconcile.ProbeOutcome.ABSENT,
}

#: The ``auth.reauth`` reason for each step-up re-bind whose lookup judged no password (BACKLOG
#: #2434). None is counted toward the lockout. ``None`` means no lookup ran. ``_reauth_ad`` refuses
#: an empty password before it asks, so ``None`` from a directory reads as one that could not be
#: asked, never as ``empty_password``. The disabled and undetermined slugs are the reconciler's.
_REBIND_REFUSALS: Final[Mapping[DirectoryAnswer | None, str]] = MappingProxyType(
    {
        None: "directory_unavailable",
        DirectoryAnswer.NOT_FOUND: "not_in_directory",
        DirectoryAnswer.DISABLED: reconcile.REVOKE_REASONS[reconcile.ProbeOutcome.DISABLED],
        DirectoryAnswer.UNDETERMINED: reconcile.REVOKE_REASONS[reconcile.ProbeOutcome.UNDETERMINED],
        # Vault BACKLOG #2778. The id-keyed search shares `_search_user`, so a directory that
        # answers two entries for one objectGUID is refused as AMBIGUOUS there too. No entry is
        # provably the row's own, which is what `not_in_directory` already means, and the
        # reconciler reads the same answer as ABSENT. Without this arm the lookup raised KeyError.
        DirectoryAnswer.AMBIGUOUS: "not_in_directory",
    }
)


#: The pair a session insert requires of a row that must hold NO federated binding (vault BACKLOG
#: #2609). Passed as ``require_federated_subject`` by the Windows SSO mint.
_UNBOUND: Final[tuple[None, None]] = (None, None)


def _holds_federated_binding(user: UserRecord) -> bool:
    """Whether ``user`` carries a federated binding. Either half of the pair counts as one, matching
    the unbind's own predicate, so a row holding half a pair is never read as unbound."""
    return user.oidc_issuer is not None or user.oidc_subject is not None


def _holds_directory_key(user: UserRecord) -> bool:
    """Whether the reconciler may ask the directory about ``user``: it carries a
    ``directory_object_id`` (BACKLOG #2434).

    **The reconcile pass's one statement of the rule**; the sign-in, step-up and bind refusals
    still test the column inline. A row without one is never asked about by name, so it is no
    directory evidence: the pass reads it as UNKEYED without a lookup, and a trip or a referral
    leaves it unmarked, because no pass can ever read it PRESENT. ``reconcile.plan_pass`` sees only
    the UNKEYED outcome this produces, and counts what was asked from that.
    """
    return bool(user.directory_object_id)


def _holds_unkeyed_federated_binding(user: UserRecord) -> bool:
    """Whether ``user`` carries a federated binding but no ``directory_object_id`` (BACKLOG #2027).

    Such a row's only directory key is its username, and ADR 0184 AC-5 forbids re-resolving a bound
    row by that, so the engine has no key it may ask the directory with.
    """
    return _holds_federated_binding(user) and not _holds_directory_key(user)


def _directory_login_refusal(user: UserRecord, now: float, *, federated: bool) -> str | None:
    """The closed-set reason a directory login must refuse ``user``'s mirror row, or ``None``.

    BACKLOG #1637 (``disabled``) and #1638 (``locked``). Both states used to be invisible to a
    directory sign-in: ``_complete_ad_login`` checked provider and directory id and neither of these,
    so an engine-disabled mirror row completed Kerberos or OIDC login with an ``auth.login_success``
    row and a live session, and a lock set by five wrong TOTP codes was cleared by one re-login.

    **A ROW THAT HOLDS A FEDERATED BINDING SIGNS IN THROUGH ITS IDENTITY PROVIDER ONLY** (vault
    BACKLOG #2609). ``federated`` says whether the login asking is the federated one. An
    administrator binds an account to put it behind the identity provider's own sign-in, and a
    Windows SSO ticket asserts nothing about factor strength. So a bound row that Windows SSO still
    admitted would keep a sign-in that never meets the identity provider. The keyword is required,
    so every caller states which pathway it is.

    THE COST: the binding decides, not ``oidc_enabled``, so a settings change does not reopen
    Windows SSO for a bound account. ``docs/SECURITY.md``, *Federated sign-in*, states what that
    costs a site and is the source of record for it.

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
    # Last, so a disabled or locked row keeps the reason an operator already acts on.
    if not federated and _holds_federated_binding(user):
        return FEDERATED_SIGN_IN_REQUIRED
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
    #: A closed-set slug for an uncounted directory refusal that judged no password (BACKLOG #2027):
    #: at least a row with no id, or any :class:`_DirectoryRebind` reason. Written onto the
    #: ``auth.reauth`` row. ``None`` for every other outcome, which the row describes.
    reason: str | None = None
    #: A directory re-proof the directory could not decide, so no password was judged and nothing
    #: was charged; ``reason`` says why. Carried to ``Elevation.directory_unconfirmed`` so a caller
    #: does not report the password as wrong.
    directory_unconfirmed: bool = False


@dataclass(frozen=True)
class _DirectoryRebind:
    """The outcome of :meth:`AuthService._reauth_ad`.

    ``verdict`` keeps the three answers that method documents. ``reason`` is a closed-set slug set
    whenever ``verdict`` is ``None``, naming why the directory could not judge the password
    (BACKLOG #2027): ``empty_password``, ``not_configured``, ``directory_unavailable``,
    ``not_in_directory``, ``directory_disabled`` or ``directory_undetermined``, and, from a
    directory implementation that does not check the id itself, ``directory_object_id_missing`` or
    ``directory_identity_conflict`` (``None`` whether or not the bind succeeded).
    ``not_in_directory`` means no entry for the row's id, an entry that does not read the id
    back, or more than one entry for it (vault BACKLOG #2778). Since BACKLOG #2434 a disabled entry
    and an unreadable account state have their own slugs, read from the bind's own lookup."""

    verdict: bool | None
    reason: str | None = None


def _directory_answer_mismatch(principal: AdPrincipal, object_id: str) -> str | None:
    """Why ``principal`` is not provably the directory object ``object_id`` names, or ``None``."""
    if not principal.directory_object_id:
        return DIRECTORY_OBJECT_ID_MISSING
    # Both sides canonical: the search parsed ``object_id`` leniently, so compare the same way.
    if principal.directory_object_id != (normalise_object_guid(object_id) or object_id):
        return DIRECTORY_IDENTITY_CONFLICT
    return None


@dataclass
class _KeyedLock:
    """One entry of a per-account lock table, with a count of the tasks holding or awaiting it so the
    entry can be dropped when the last one leaves. The re-proof table, the credential table and the
    lock-notice table (BACKLOG #2216) each use it (:func:`_hold_keyed_lock`)."""

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
    #: The single-use recovery codes minted with the TOTP enrolment (ADR 0197 Amendment A, N-A),
    #: plaintext, for the command to print ONCE to the operator's terminal. Empty when the command
    #: enrolled no TOTP (``--no-totp``, which only a site with ``require_mfa`` off may pass). Never
    #: in ``--json`` output, never logged, never audited.
    recovery_codes: tuple[str, ...] = ()


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
class CreatedLocalAccount:
    """What :meth:`AuthService.create_local_user` returns: the new row's id and its engine-generated
    birth credential, handed to the creating administrator **once** (ADR 0197 Amendment A, N-B2
    part 1). The administrator never chooses the password, so nothing a caller guesses can be the
    credential, and wrong passwords arm no lock while it stands."""

    user_id: str
    credential: IssuedCredential


@dataclass(frozen=True)
class LockableAccountCensus:
    """What :meth:`AuthService.lockable_account_census` found (ADR 0197 Amendment A, N-B2 part 6).

    ``no_way_past`` names every local account ``[security].require_mfa`` covers that holds a chosen
    credential (``password_generated`` unset) and no factor with a way past the sign-in lock -- TOTP,
    in wave 1. ``undecryptable_totp`` names every account whose ENABLED TOTP secret the engine cannot
    decrypt, which turns the owner's combined sign-in into "right password, wrong code". Both are
    usernames only, sorted; neither carries a secret."""

    no_way_past: tuple[str, ...] = ()
    undecryptable_totp: tuple[str, ...] = ()

    @property
    def clean(self) -> bool:
        return not self.no_way_past and not self.undecryptable_totp


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


def _scope_covers(settings: AuthSettings, roles: frozenset[Role]) -> bool:
    """Whether ``[security].require_mfa`` and its scope cover an account holding ``roles``, before
    any factor is counted. The one statement of the scope rule: ``AuthService._mfa_required_for``,
    the enrol-first gates and :func:`lockable_account_census` all ask it."""
    if not settings.require_mfa:
        return False
    return settings.require_mfa_scope == "every_local_account" or Role.ADMINISTRATOR in roles


def _requirement_covers(settings: AuthSettings, user: UserRecord, roles: frozenset[Role]) -> bool:
    """Whether the requirement covers ``user`` as a LOCAL account, enrolled or not (ADR 0197
    Amendment A): :func:`_scope_covers`, restricted to local accounts."""
    return user.auth_provider == AuthProvider.LOCAL.value and _scope_covers(settings, roles)


class CensusNeedsTheStoreKey(RuntimeError):
    """The census read a TOTP cell that is still ciphertext: the store was opened without the key it
    was written under (a keyless open passes cells through unchanged). That is a fact about the
    shell, not about any account, so the census stops rather than naming every enrolled account
    (ADR 0197 Amendment A). ``messagefoundry verify`` reports it as an ERROR naming the key."""


async def _totp_secret_usable(store: AdminStore, user: UserRecord) -> bool:
    """Whether ``user``'s enabled TOTP secret decrypts to a key the engine can compute codes with.

    Two ways to fail. The cipher refuses the cell (:class:`CipherError`), which is logged, naming
    the account and never the value. Or a keyless open hands the stored ciphertext through unchanged,
    which is not base32, so computing a code from it fails. Any other store error propagates: it
    says nothing about this secret, and filing it as "undecryptable" would send an operator to reset
    a healthy account."""
    try:
        secret = await store.get_totp_secret(user.id)
    except CipherError:
        _log.warning(
            "the TOTP secret of account %r does not decrypt under this store key", user.username
        )
        return False
    if not secret:
        return False
    if secret.startswith(MARKER_PREFIX):
        raise CensusNeedsTheStoreKey(
            "a TOTP secret is still ciphertext: this shell opened the store without the key it was "
            "written under. Set the service's store key here and run again."
        )
    try:
        totp.totp(secret)
    except ValueError:  # binascii.Error is a ValueError: not base32, so no key
        return False
    return True


async def lockable_account_census(
    store: AdminStore, settings: AuthSettings
) -> LockableAccountCensus:
    """Name every account that is still lockable with no way past the sign-in lock (ADR 0197
    Amendment A, N-B2 part 6, AC-A9).

    Two populations. **A covered local account holding a chosen credential and no TOTP**: the gates
    of part 4 never let a holder reach that state under the shipped defaults, so one that exists got
    there another way -- for instance while the site ran with ``require_mfa`` off, or from before
    this change. **An enabled TOTP secret the engine cannot use**, on any account, directory accounts
    included: the owner's combined sign-in then reads as "right password, wrong code", which feeds
    the second-step lock, so the owner's way past has become a way to lock themselves out.

    Read-only, and it needs no :class:`AuthService`, so ``messagefoundry verify`` runs it without the
    trust-anchor preflights or a directory client. Disabled accounts are read too: one cannot sign in
    now, but it is lockable the moment it is re-enabled. A local row with no password hash is
    skipped: nobody can sign into it, so there is nothing to lock (an interrupted
    ``provision-admin`` leaves one). Raises :class:`CensusNeedsTheStoreKey` when a TOTP cell is
    still ciphertext, which means this shell lacks the store key. Usernames only; each secret is
    dropped at once. :meth:`AuthService.report_lockable_account_census` warns and audits;
    ``verify`` reports. Neither refuses to start, since refusing would hand an account-level fact a
    site-wide veto."""
    no_way_past: list[str] = []
    undecryptable: list[str] = []
    for user in await store.list_users():
        # Disabled accounts are read too: one re-enabled later is lockable at once, and the census
        # runs only at startup and in verify.
        if user.totp_enabled:
            if not await _totp_secret_usable(store, user):
                undecryptable.append(user.username)
            continue
        if (
            user.password_generated
            or user.password_hash is None
            or user.auth_provider != AuthProvider.LOCAL.value
            or not settings.require_mfa
        ):
            continue
        # The role read only where the scope depends on it.
        roles = (
            frozenset()
            if settings.require_mfa_scope == "every_local_account"
            else _roles_from_ids(await store.get_user_role_ids(user.id))
        )
        if _requirement_covers(settings, user, roles):
            no_way_past.append(user.username)
    return LockableAccountCensus(
        no_way_past=tuple(sorted(no_way_past)), undecryptable_totp=tuple(sorted(undecryptable))
    )


def _json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True)


# BACKLOG #1138, ASVS 6.3.5: the audit action each suspicious-sign-in event is recorded under. A fixed
# map, not ``f"auth.{event_type}"``, so the action names stay greppable and no other notice kind can
# be passed in and double-audit an event its own call site already audits.
#: ADR 0197 Decision item 7: the audit row a mailed ``ACCOUNT_LOCKED`` notice writes, and the window
#: it throttles over. See :meth:`AuthService._lock_notice_due`.
_LOCK_NOTICE_ACTION: Final = LOCK_NOTICE_ACTION
_LOCK_NOTICE_WINDOW_SECONDS: Final = 24 * 3600.0
#: BACKLOG #2216: how long the API lifespan's :meth:`AuthService.drain_background` lets the
#: service's background tasks finish at shutdown before it cancels the rest, and how long it then
#: waits for the cancelled ones to unwind. Both are shares of the service's graceful-stop window,
#: whose budget is stated at ``DRAIN_TIMEOUT_SECONDS`` in ``api/approvals.py``; keep the sum inside
#: it. A task still running at the first bound is queued behind other throttle reads, or stuck on
#: the store. A task still unwinding at the second is left to finish or fail on its own.
_BACKGROUND_DRAIN_SECONDS: Final = 2.0
_BACKGROUND_CANCEL_GRACE_SECONDS: Final = 0.5

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
#: BACKLOG #2359: the row a refused credential issue writes, when the generator raises
#: :class:`TemporaryPasswordUnavailable` on account creation or either reset. A name of its own, and
#: never ``user.created`` or ``auth.password_reset``: :data:`_ISSUE_ROW_KEYS` reads those two as
#: "this administrator issued the credential", so a refusal written under either would name an issuer
#: for a credential that was never set. Its detail's ``op`` says which of the three refused.
CREDENTIAL_ISSUE_REFUSED_ACTION: Final = "auth.credential_issue_refused"
#: The ``op`` values that row carries, one per issuing operation.
CredentialIssueOp = Literal["create", "password_reset", "mfa_reset"]
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


def _cert_narrowed_scope(
    user: UserRecord, mapped: frozenset[str], *, administrator: bool
) -> UserRecord:
    """``user`` with the channel scope its current directory groups leave it, for one certificate
    request (BACKLOG #2316). Writes nothing.

    The rule is :func:`~messagefoundry.auth.channel_scope.decide_ad_channel_scope`, the one login
    and the reconciler share. Only a narrowing applies, and only as far as the stored scope reaches:
    the result is the stored channels intersected with what the groups now map to. A scope the groups
    would widen stays as stored, because this path must not grant, so a widening still waits for a
    sign-in to write it."""
    decision = channel_scope.decide_ad_channel_scope(
        channel_scope.ScopeInput(
            stored_scope=user.channel_scope,
            stored_source=user.channel_scope_source,
            mapped=mapped,
            administrator=administrator,
        )
    )
    if not decision.narrows:
        return user
    before = channel_scope.scope_channels(user.channel_scope)
    # A narrowing always has a bounded target: an empty set for a withdrawal, else the channels.
    after = channel_scope.scope_channels(decision.scope_json) or frozenset()
    reach = after if before is None else before & after
    return replace(user, channel_scope=json.dumps(sorted(reach)))


#: The IdP legs' OWN way across. The connection-shaped default cannot reach this opener, which
#: resolves no trust anchor; see :attr:`~messagefoundry.config.tls_policy.RevocationHopGuard.ways_across`.
_IDP_WAYS_ACROSS = (
    "Set [auth].oidc_tls_crl_file to a PEM file holding a CRL from each CA that issues the token "
    "and JWKS endpoint certificates, so the engine checks revocation on both legs. Put only CRLs "
    "in it: a certificate not already in the hop's trust store refuses start."
)


def _idp_leg_host(url: str | None, leg: str) -> str:
    """The host of one OIDC leg, read by the shared hop check (BACKLOG #2207).

    A URL that names no host raises :class:`InsecureHopRefused`, whatever the posture. A stand-in
    host used to go to the guard instead, which refused it under ``enforce`` and only warned
    outside it. The type is the one this hop's other refusal raises, so ``serve`` and
    ``provision-admin`` report it as they report that one. ``messagefoundry verify`` shows it as an
    ERROR on its revocation row, because it is raised while the guards are captured. The text is
    the shared check's own and names no part of the URL."""
    try:
        return hop_url_host(url or "", cell=f"[auth] OIDC {leg}")
    except ValueError as exc:
        raise InsecureHopRefused(str(exc)) from exc


def idp_revocation_guards(
    settings: AuthSettings, opener: urllib.request.OpenerDirector, posture: HopPosture | None
) -> tuple[RevocationHopGuard, ...]:
    """Capture the #201 revocation guard for each OIDC leg, token endpoint first (BACKLOG #1887).

    Apart from the refusal below, it decides nothing and logs nothing.
    :func:`_refuse_idp_revocation` enforces what it returns, and ``messagefoundry verify`` reads each
    guard's
    :meth:`~messagefoundry.config.tls_policy.RevocationHopGuard.disposition` (BACKLOG #1923), so the
    report and the engine read one rule rather than two copies of it.

    A leg whose URL names no host is refused here, whatever the posture (:func:`_idp_leg_host`,
    BACKLOG #2207). Only unvalidated settings reach that: the ``[auth]`` validator refuses a
    missing URL and a host outside the allow-list."""
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
            host=_idp_leg_host(url, leg),
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
    comes before any connection starts. ``messagefoundry check`` reports it in its required
    ``oidc-revocation`` leg, through the same :func:`idp_revocation_guards` (BACKLOG #2131, ADR 0173
    AC-4). Two limits are recorded only here: when both legs refuse, only the token leg is named,
    because it is checked first; and the WARN arm logs with no audit sink after
    ``configure_logging`` has set the root level, so a level above WARNING would likely filter it, as
    ``logging_setup._refuse_forward_revocation`` measured for its hop."""
    for guard in idp_revocation_guards(settings, opener, posture):
        guard.enforce_construction()


def _resolve_oidc_credential(
    provider: SecretProvider | None, *, ref: str | None, literal: str | None, setting: str
) -> str:
    """Resolve one ``[auth]`` OIDC client credential, naming the setting the operator wrote.

    ``resolve_connector_secret`` names a reference ``<label>_secret``, which is the AD and SMTP
    spelling. These references are ``<setting>_ref``, so its no-provider refusal is worded here
    instead. A credential that resolves empty is refused too, since it would send no credential.
    """
    if ref and provider is None:
        raise SecretProviderError(
            f"[auth].{setting}_ref is set but [secrets].provider is unset ('none'). Set "
            "[secrets].provider (e.g. 'vault'), or remove the reference to use the "
            "environment-sourced value."
        )
    value = resolve_connector_secret(provider, ref=ref, literal=literal, label=f"[auth].{setting}")
    if not value:
        named = f"{setting}_ref" if ref else setting
        raise SecretProviderError(f"[auth].{named} resolved to an empty value")
    return value


def oidc_client_auth_from_settings(
    settings: AuthSettings, secret_provider: SecretProvider | None
) -> oidc.ClientAuthentication:
    """The configured OIDC client credential, resolved and checked (BACKLOG #296).

    The ONE construction, shared by :class:`AuthService` and ``messagefoundry verify --section
    federation``, so the check resolves exactly what the engine sends. Only the configured method's
    credential is resolved, which may call the ``[secrets]`` provider.

    Raises :class:`SecretProviderError` for a reference that does not resolve, a credential that
    resolves empty, or a key reference that resolves to anything but a PEM key, and :class:`~messagefoundry.transports.signing.SigningError` for a key or
    certificate that cannot be read, parsed or used with the configured algorithm. None of these
    messages carries a credential.
    """
    if not settings.oidc_private_key_jwt:
        secret = _resolve_oidc_credential(
            secret_provider,
            ref=settings.oidc_client_secret_ref,
            literal=settings.oidc_client_secret,
            setting="oidc_client_secret",
        )
        return oidc.ClientSecretPost(secret)
    key = _resolve_oidc_credential(
        secret_provider,
        ref=settings.oidc_client_private_key_ref,
        literal=settings.oidc_client_private_key,
        setting="oidc_client_private_key",
    )
    # The signer reads a value with no PEM header as a file path. A secret-store value must be the
    # key itself, never a path the store chooses, so a reference that resolves to anything else is
    # refused here, naming the reference rather than a file.
    if settings.oidc_client_private_key_ref and "-----BEGIN" not in key:
        raise SecretProviderError(
            "[auth].oidc_client_private_key_ref did not resolve to a PEM key; the referenced "
            "secret must hold the key itself"
        )
    audience = (
        settings.oidc_issuer
        if settings.oidc_client_assertion_audience == "issuer"
        else settings.oidc_token_endpoint
    )
    # Unreachable while the settings validator holds, since both callers run only with oidc_enabled
    # set. Kept so a future caller's gap fails here, by name, not in the signer as an empty string.
    if not settings.oidc_client_id or not audience:
        raise ValueError(
            "private_key_jwt needs oidc_client_id and the assertion audience "
            f"(oidc_{settings.oidc_client_assertion_audience})"
        )
    return oidc.PrivateKeyJwtClientAuth(
        client_id=settings.oidc_client_id,
        audience=audience,
        private_key=key,
        algorithm=settings.oidc_client_assertion_algorithm,
        private_key_password=settings.oidc_client_private_key_password,
        key_id=settings.oidc_client_assertion_key_id,
        certificate=settings.oidc_client_certificate,
    )


class AuthService:
    """Authentication + RBAC orchestration over an :class:`AuthStore` and the configured directory."""

    @property
    def enabled(self) -> bool:
        """Always True: a service that exists requires sign-in (vault BACKLOG #2825).

        The open mode is NO service, opted into with the app factories' ``allow_no_auth=True``; both
        factories refuse that opt-in beside a service. No setting turns a built service off, and the
        property has no setter. So the ``auth is None or not auth.enabled`` guards in the API and
        the web console mean ``auth is None``."""
        return True

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
            # Vault BACKLOG #2354: the same dial decides whether a plain ldap:// bind is refused, so it
            # is a transport control here and not only an anchor-ACL knob. Pass the real dial.
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
        # BACKLOG #2316: the certificate path's directory probes, capped like argon2 above.
        # Bounded, so a release with no matching acquire raises instead of widening the cap.
        self._cert_probe_slots = asyncio.BoundedSemaphore(_CERT_PROBE_MAX_CONCURRENCY)
        #: Probe tasks still running, held so none is collected while its caller has gone.
        self._cert_probe_tasks: set[asyncio.Task[reconcile.Probe | str]] = set()
        #: The certificate path's current outage reason, or None (`_note_cert_directory_answer`).
        self._cert_directory_outage: str | None = None
        #: Monotonic time of its last outage WARNING, and whether the current outage logged one.
        self._cert_outage_warned_at: float | None = None
        self._cert_outage_announced = False
        #: Monotonic time of the last INFO saying the current outage changed its reason.
        self._cert_outage_kind_noted_at: float | None = None
        #: Configuration refusals already logged by this process.
        self._cert_config_refusals_logged: set[str] = set()
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
                # BACKLOG #2301: the per-actor gap floor, beside the count.
                min_interval_seconds=settings.admin_write_min_interval_seconds,
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
        # host keys already flagged since the session's last re-verification (BACKLOG #2159). Every
        # re-anchor drops the entry (_restart_new_ip_dedupe). Bounded twice: _NEW_IP_DEDUP_MAX sessions,
        # and _NEW_IP_PER_SESSION_MAX + 1 keys each (the last is the cap-reached row's address).
        self._new_ip_seen: dict[str, set[str]] = {}
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
        # BACKLOG #2216: one in-flight ACCOUNT_LOCKED notice per (user id, lock kind), so two locks of
        # one kind landing together read the throttle one after the other and mail once. Its own table:
        # the credential queue above is held across a sign-in's pad, and the notice runs off it. Per
        # API process, like that queue: engine shards serving their own API ports each keep one, so
        # two locks landing on two of them at once can still mail twice.
        self._lock_notice_locks: dict[str, _KeyedLock] = {}
        # BACKLOG #2216: strong references to the service's background tasks, so a running one is not
        # garbage-collected. Each removes itself when done; drain_background() awaits the rest.
        self._background_tasks: set[asyncio.Task[None]] = set()
        # Set by drain_background(close=True) at shutdown. After it, a lock notice runs inline,
        # since a task started then would outlive the drain and meet a closed store.
        self._background_closed = False
        # One throttle read at a time (BACKLOG #2216); see _lock_notice_held_back.
        self._lock_notice_read_slots = asyncio.Semaphore(1)
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
        #: Latched LDAP referral (BACKLOG #2538). Its own latch, like the hold's, because a pass with
        #: a referral beside other answers is not aborted and so clears `_reconcile_alert`. Set on a
        #: pass with a referral. Cleared by `_mark_reconcile_clears` on the referral clear's test.
        self._reconcile_referral_alert: str | None = None
        #: user_ids signed in at the last pass with a referral and not read PRESENT since (BACKLOG
        #: #2538). `_mark_reconcile_clears` states the test that reads it.
        self._reconcile_referred: set[str] = set()
        #: Whether THIS process may resolve the referral's durable ``ad_reconcile_aborted``
        #: instance (BACKLOG #2538), on the breaker's rule (`_reconcile_breaker_standing`).
        #: ``"fresh"``: no pass here saw a referral. ``"referred"``: one did. ``"forfeit"``: see
        #: `_forfeit_clears_on_attrition`. Only `_advance_referral_standing` moves it.
        self._reconcile_referral_standing: _ReferralStanding = "fresh"
        #: user_ids a breaker trip has not yet seen read PRESENT on a pass that was not aborted
        #: (BACKLOG #2136). `_mark_reconcile_clears` reports no breaker clear while one is signed in.
        self._reconcile_unconfirmed: set[str] = set()
        #: Whether THIS process may resolve the durable ``ad_reconcile_aborted`` instance (BACKLOG
        #: #2136), on the rule `_mark_reconcile_clears` states for both alerts: a process clears
        #: only what it watched open. ``"fresh"``: no pass here has tripped, so it resolves no
        #: trip, whatever an earlier run left open. ``"tripped"``: a pass here tripped, so a clear
        #: it then sees is of a trip it watched. ``"forfeit"``: an account signed in at a trip left
        #: before a pass here read it clean (`_forfeit_clears_on_attrition`), so it resolves no
        #: trip until it restarts. Only `_advance_breaker_standing` moves it.
        self._reconcile_breaker_standing: _BreakerStanding = "fresh"
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
        #: Whether THIS process may resolve the durable ``ad_reconcile_held`` instance (BACKLOG
        #: #2136). The instance outlives the process and the latch does not, so a fresh process
        #: cannot tell whether an earlier run's latch was still holding an account.
        #: ``"fresh"``: no pass here has held, so it resolves no hold. ``"held"``: a pass here held,
        #: so a release it then sees is its own. ``"forfeit"``: an undetermined account left the
        #: candidate set before a release, by revocation or otherwise, and nothing re-reads it, so
        #: it resolves no hold until it restarts. ``"settled"``: a pass here found the hold gone
        #: with an answer from this process on record for every signed-in account, so its records
        #: now cover what an earlier run held, and no pass here has held since. Only
        #: `_advance_hold_standing` moves it.
        self._reconcile_hold_standing: _HoldStanding = "fresh"
        #: user_ids of bound id-less rows the reconciler has already reported as skipped (BACKLOG
        #: #2027), so each is logged and audited once per process rather than once per pass.
        self._reconcile_unkeyed_reported: set[str] = set()
        #: user_ids whose skip report the store refused, in the order of their latest refusal, oldest
        #: first: a dict used as an ordered set (BACKLOG #2137). Refused accounts go last, the
        #: longest-refused first, so a row the store keeps refusing starves neither the reports
        #: behind it nor another refused row.
        self._reconcile_unkeyed_refused: dict[str, None] = {}
        if self.directory_reconcile_enabled:
            # Built now, at startup, so a reconciler's first refused audit write does not import
            # the server drivers on the event loop (see `_audit_write_errors`).
            _audit_write_errors()
        # Advisory, NON-STICKY federated-IdP health (ADR 0142 AC-8) — see the oidc_available docstring.
        self._oidc_unavailable_reason: str | None = None
        self._oidc_client_auth: oidc.ClientAuthentication | None = None
        self._oidc_jwks: oidc.JwksCache | None = None
        self._oidc_flows: oidc.FlowCache | None = None
        if settings.oidc_enabled:
            # A SEPARATE branch from the ldap one above: secret_provider is otherwise consumed only
            # inside `elif settings.ad_enabled`, so every test that injects ldap= would skip secret
            # resolution entirely and the reference would be dead in tests but live in production.
            # BACKLOG #296: exactly one client credential is resolved, the one the configured method
            # sends. Under private_key_jwt the key is read and checked here, so a missing,
            # unreadable, weak or wrong-curve key refuses startup like an unresolvable secret.
            self._oidc_client_auth = oidc_client_auth_from_settings(settings, secret_provider)
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

    def attach_security_notifier(self, notifier: SecurityNotifier | None) -> None:
        """Wire the out-of-band notice channel after construction (BACKLOG #2081).

        For ``provision-admin`` alone, which builds this service before its password prompt so that
        building it -- the anchor checks and the directory secrets -- can refuse first, but decides
        whether it owes a takeover notice only at the write, against the store it writes to. The
        API lifespan passes the notifier to the constructor and never calls this. Call it before
        the first operation that could notify; it replaces whatever channel was wired."""
        self._security_notifier = notifier

    def _start_background(self, work: Coroutine[Any, Any, None]) -> None:
        """Run ``work`` as a task this service owns (BACKLOG #2216).

        The set holds a strong reference, since the event loop keeps only a weak one and a running
        task with no other holder can be garbage-collected. ``work`` must log its own failures: the
        task's result is read by nobody but :meth:`drain_background`."""
        task = asyncio.create_task(work)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def close_background(self) -> None:
        """The shutdown drain (BACKLOG #2216): :meth:`drain_background` with ``close=True`` and
        the :data:`_BACKGROUND_DRAIN_SECONDS` bound. The API lifespan calls it; so must any app
        that owns its engine some other way, before it stops the engine."""
        await self.drain_background(timeout=_BACKGROUND_DRAIN_SECONDS, close=True)

    async def drain_background(self, *, timeout: float | None = None, close: bool = False) -> None:
        """Let the service's background tasks finish. With ``timeout``, cancel any still running
        at it, and give those at most :data:`_BACKGROUND_CANCEL_GRACE_SECONDS` to unwind.

        BACKLOG #2216. The API lifespan calls this at shutdown with ``close=True`` and
        :data:`_BACKGROUND_DRAIN_SECONDS`, BEFORE the engine closes the store and before the
        security notifier stops. A pending ``ACCOUNT_LOCKED`` notice still reads the audit log,
        hands its mail to that notifier and writes its row. ``close`` also makes every later
        notice run inline, so none starts after the drain and meets a closed store. A task
        cancelled here logs a line that names no account, so a notice cut off at shutdown is on
        record as cut off. **An app that owns its engine some other way than the managed lifespan
        calls this itself, the same way, before it stops the engine.**

        With no ``timeout`` it is a join and cancels nothing, which is what tests await instead of
        sleeping. A task started while it waits is waited for too. Safe to call more than once."""
        if close:
            self._background_closed = True
        deadline = None if timeout is None else time.monotonic() + timeout
        while pending := set(self._background_tasks):
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is None or remaining > 0:
                await asyncio.wait(pending, timeout=remaining)
                continue  # re-read the set: some finished, and new ones may have started
            for task in pending:
                task.cancel()
            await asyncio.wait(pending, timeout=_BACKGROUND_CANCEL_GRACE_SECONDS)
            return

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

    async def audit_kerberos_reject(self, reason: str, *, client: str | None) -> None:
        """AUTH-K-AUDIT for route-level SSO rejects that never reach ``authenticate_kerberos``, such
        as cross-site hygiene and malformed base64, so a defender sees them. Rate-limit exhaustion
        is a log line at the route, never a row. ``client`` is the route's address for the caller
        (BACKLOG #2132)."""
        await self._directory_reject_audit("<kerberos>", "kerberos", reason, client=client)

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

    async def audit_oidc_reject(self, reason: str, *, client: str | None) -> None:
        """Route-level federated-login rejects that never reach :meth:`authenticate_oidc`, such as
        flow-cookie binding failures, a malformed callback and a non-navigation fetch. Rate-limit
        exhaustion is a log line at the route, never a row. ``reason`` must be a closed-set slug
        chosen by the route — never IdP-supplied text. ``client`` is the route's address for the
        caller (BACKLOG #2132)."""
        await self._directory_reject_audit("<oidc>", "oidc", reason, client=client)

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
        totp_secret: str | None = None,
        totp_code: str | None = None,
        totp_code_read_at: float | None = None,
    ) -> ProvisionedAdministrator:
        """Create the first administrator from an operator-supplied name and credential (#1136).

        **IT ENROLS TOTP FROM BIRTH (ADR 0197 Amendment A, N-A, AC-A5).** ``totp_secret`` is the
        secret the command generated and showed at the terminal, and ``totp_code`` the code the
        operator read back from their authenticator. Both are checked HERE, before any store write,
        with the pure :func:`totp.verify_totp_step` at the configured skew, so a mistyped code writes
        nothing and cannot leave a half-built row. Then the writes run in ADR 0183's order with the
        enrolment before the role: row, password, TOTP secret with its step consumed and its recovery
        codes, address, role LAST. The account is born with option E's way past the sign-in lock.
        ``totp_code_read_at`` is the instant the command read the code, so this check judges the code
        against the step it was read in rather than failing a correct code that crossed a step
        boundary while the store opened. ``None`` means now.
        While ``[security].require_mfa`` is on, a call with no secret is refused, because the scope
        always covers an administrator.

        **THE REPAIR BRANCH CLEARS EVERYTHING THE EARLIER HOLDER COULD STILL USE**, first: TOTP, its
        recovery codes, every passkey, and every session on the row. Before this, the branch revoked
        no session, and ``_build_identity`` re-reads roles on every request, so a live session the
        earlier holder kept became an Administrator session when the role was written -- an ADR 0183
        defect this amendment fixes because it edits this branch.

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
        address it held before (BACKLOG #2019). And a row that holds an address is completed only
        when ``notify_email`` is given (BACKLOG #2288), so the sole Administrator's notices never
        go to an address nobody chose.

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
        # ADR 0197 Amendment A (N-A): the code is proved in memory, before any write.
        matched_step: int | None = None
        if totp_secret is None:
            if self._settings.require_mfa:
                raise FirstAdministratorRefused(
                    "MFA is required ([security].require_mfa), so the first Administrator enrols an "
                    "authenticator app at the terminal; --no-totp is only for a site that turned "
                    "the requirement off"
                )
        else:
            matched_step = totp.verify_totp_step(
                totp_secret,
                (totp_code or "").strip(),
                now=totp_code_read_at,
                window=self._settings.totp_skew_steps,
            )
            if matched_step is None:
                raise FirstAdministratorRefused(
                    "the authenticator code did not match; nothing was written"
                )

        existing = await self._store.get_user_by_username(username)
        repaired = existing is not None
        # BACKLOG #2019: read BEFORE any write, because `--email` below may replace it and the new
        # address belongs to the operator running this command, not to the holder being told.
        # Blank counts as absent, as it does everywhere else in this service: a legacy row can hold
        # "" and the notifier drops it, so "dispatched" would be a false record.
        prior_notify_email = ((existing.notify_email if existing else None) or "").strip() or None
        if existing is not None:
            refusal = await self._existing_row_refusal(
                existing, username, notify_email=notify_email
            )
            if refusal is not None:
                raise FirstAdministratorRefused(refusal)
            user_id = existing.id
            # ADR 0197 Amendment A (AC-A5): a row somebody else held must not carry their factor,
            # or a session of theirs, onto the new Administrator. Cleared BEFORE anything is
            # written for the new holder, and before the role that would make a kept session an
            # Administrator session.
            await self._store.disable_totp(user_id)
            await self._store.delete_all_webauthn_credentials(user_id)
            await self._store.revoke_user_sessions(user_id)
        else:
            user_id = uuid4().hex
            try:
                await self._store.create_user(
                    user_id=user_id,
                    username=username,
                    auth_provider=AuthProvider.LOCAL.value,
                    display_name=display_name,
                    # Seeds `notify_email` too (see `store.seed_notify_email`), which is the column
                    # the PHI security-notice start gate reads.
                    email=notify_email,
                    # No hash yet, deliberately: an account with no credential cannot be signed into,
                    # so the window before `set_password` below admits nobody. The flag is therefore
                    # unobservable until that write, which is what actually decides it.
                    password_hash=None,
                    must_change_password=True,
                    password_generated=False,
                )
            except Exception as exc:
                if not _is_integrity_refusal(exc):
                    raise
                # BACKLOG #2697: another run, or a directory sign-in, took the name after the read
                # above. Refused rather than repaired in place: a re-run reads the row and takes the
                # repair branch, so `_existing_row_refusal`'s rules (#2288) stay in one place. This
                # INSERT was the run's first account write, so no account row was written. A
                # refusal with no row holding the name is some other fault and re-raises untouched.
                if await self._store.get_user_by_username(username) is None:
                    raise
                raise FirstAdministratorRefused(
                    "an account with that username was created while this command ran, so this run "
                    "wrote no account; remove any authenticator entry it showed. If another "
                    "provision-admin run is in progress, let it finish. Then run the command again: "
                    "it reads that account and either completes it or says why it cannot"
                ) from exc
        await self._seed_roles()
        # ADR 0197 Amendment A (N-A): the step is consumed FIRST, before the credential or the
        # secret is written, so a code this row already spent (an interrupted earlier run in the
        # same 30 seconds) is refused with no password written. The row itself stays roleless.
        if matched_step is not None and not await self._store.consume_totp_step(
            user_id, matched_step
        ):
            raise FirstAdministratorRefused(
                "that authenticator code was already used on this account; no password was set. "
                "Wait for the next code and run the command again"
            )
        await self._store.set_password(
            user_id,
            password_hash=await self._argon2(hash_password, password),
            must_change_password=False,
            password_generated=False,
        )
        plain_codes: tuple[str, ...] = ()
        if totp_secret is not None and matched_step is not None:
            # Enrolled BEFORE the role, which stays last, so every interruption still leaves a
            # roleless row a re-run completes -- and the repair branch above clears a half-enrolled
            # one before this runs again.
            await self._store.set_totp_secret(user_id, secret=totp_secret)
            plain_codes = tuple(
                totp.generate_recovery_codes(self._settings.mfa_recovery_code_count)
            )
            hashes = [await self._argon2(hash_password, c) for c in plain_codes]
            # Conditional (BACKLOG #2224): a factor clear by another run's repair branch, or another
            # run that enabled TOTP first, since the secret was staged above makes it match no row.
            # Refused before the role, so the row stays roleless and a re-run completes it.
            if not await self._store.enable_totp(user_id, recovery_code_hashes=hashes):
                raise FirstAdministratorRefused(
                    "the authenticator enrolment was changed while this command ran, so this run "
                    "did not turn TOTP on and granted no role; remove the authenticator entry it "
                    "showed. "
                    "If another provision-admin run is in progress, let it finish. Then run the "
                    "command again"
                )
        if notify_email is not None:
            # Unconditional rather than fresh-path-only, because the invariant "the supplied address
            # always lands" is simpler than the case analysis. On the fresh path `create_user` already
            # seeded the same value; on a REPAIRED row an earlier run created the account, so this
            # write is the only one that carries it.
            await self._store.set_user_notify_email(user_id, email=notify_email)
        await self._store.set_user_roles(user_id, [Role.ADMINISTRATOR.value], assigned_by=actor)
        if repaired:
            # AGAIN, after the role (ADR 0197 Amendment A, AC-A5). The earlier holder's password
            # still worked until ``set_password`` above, so a sign-in in that window minted a session
            # the first revoke never saw, and roles are re-read on every request. Revoking once more
            # here ends it before it can act as an Administrator.
            await self._store.revoke_user_sessions(user_id)
        # BACKLOG #2019: a repair can take over an account somebody else holds -- one an administrator
        # created with no roles, say -- so its earlier holder is told, at the address they held.
        # The repair is not refused outright, because an address is no sign of a second holder: a
        # run given --email that crashed after `create_user` leaves its own address on the roleless
        # row, and a flat refusal would strand exactly the half-written provision this branch
        # exists to complete. BACKLOG #2288 asks for the address instead: `_existing_row_refusal`
        # declines such a row until --email is given, and the crashed run's own command already
        # carries it, so the same command run again completes the row.
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
                    "totp_enrolled": totp_secret is not None,
                }
            ),
        )
        return ProvisionedAdministrator(
            user_id=user_id,
            username=username,
            repaired=repaired,
            holder_notice=holder_notice,
            recovery_codes=plain_codes,
        )

    async def _existing_row_refusal(
        self, existing: UserRecord, username: str, *, notify_email: str | None
    ) -> str | None:
        """Why ``provision_first_administrator`` would refuse to complete ``existing``, or ``None``.

        A directory identity draws its authority from the directory, so it is never promoted here
        whatever its role state -- provision a separate local account instead. A disabled account is
        refused rather than re-enabled: an operator who disabled it did so on purpose, and silently
        reviving it under a new credential is not a recovery. An account holding roles is somebody's
        in use.

        BACKLOG #2288: a row that already holds a notification address is completed only when
        ``notify_email`` (``--email``) is given. Kept silently, that address would receive every
        security notice for the sole Administrator, and it may be an earlier holder's. Giving the
        same address again is allowed: it is then the operator's stated choice. A blank
        ``notify_email`` counts as none, and so does a blank stored address. The text never prints
        the stored address, which may be somebody else's."""
        if existing.auth_provider != AuthProvider.LOCAL.value:
            return (
                f"{username!r} is a {existing.auth_provider} account -- provision a separate "
                "local administrator under a different name"
            )
        if existing.disabled:
            return (
                f"the account named {username!r} is disabled -- re-enable it from the web "
                "console, or provision under a different username"
            )
        if await self._store.get_user_role_ids(existing.id):
            return (
                f"an account named {username!r} already exists and holds roles -- choose "
                "another username"
            )
        if (existing.notify_email or "").strip() and not (notify_email or "").strip():
            return (
                f"the account named {username!r} already holds a notification address, and "
                "this Administrator's security notices would go there -- run the command again "
                "with --email <address> to say where they go"
            )
        return None

    async def provision_refusal(self, username: str, *, notify_email: str | None) -> str | None:
        """What ``provision_first_administrator`` would refuse ``username`` for, asked BEFORE any
        prompt (ADR 0197 Amendment A): an enabled Administrator exists, or the named row is one this
        command will not complete. ``provision-admin`` asks it first, so an operator is never shown
        an authenticator key for an account the store then refuses. The service still refuses on its
        own; this is the courtesy, that is the control. ``notify_email`` is the ``--email`` value,
        required here so the pre-check cannot disagree with the write about BACKLOG #2288."""
        name = username.strip()
        if await self.has_enabled_administrator():
            return (
                "this store already has an enabled Administrator, so there is nothing to provision "
                "-- create further accounts from the web console, and use `admin-unlock` if the "
                "administrator is locked out"
            )
        existing = await self._store.get_user_by_username(name)
        if existing is None:
            return None
        return await self._existing_row_refusal(existing, name, notify_email=notify_email)

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

    def _credential_lapsed(self, user: UserRecord, now: float) -> bool:
        """Whether ``user`` holds an admin-issued must-change credential past its deadline at ``now``.

        The sign-in gate's own test, over :meth:`initial_credential_deadline`, for a session opened
        before the deadline (BACKLOG #2009, #2298). :meth:`identity_for_token` asks it under every
        gate. :meth:`verify_current_password` and :meth:`verify_mfa` ask again inside the request,
        and :meth:`_elevated_hash` asks before any ceremony re-keys a session. The gate in
        ``_login_local`` open-codes the same comparison, so change the two together. Strictly
        after, like the gate: the credential still works AT the deadline."""
        if not user.must_change_password:
            return False
        deadline = self.initial_credential_deadline(user.password_changed_at)
        return deadline is not None and now > deadline

    async def _end_lapsed_session(
        self,
        token_hash: str,
        username: str,
        *,
        at: str,
        client: str | None,
        proof: str | None = None,
        proof_checked: bool = False,
    ) -> None:
        """Revoke a session whose temporary credential lapsed under it, and audit why (BACKLOG #2298).

        The credential stopped signing in at its deadline, so the session it opened ends too, the
        first time it is presented after that. Ending it is also what keeps a retry from writing
        another row: the next presentation finds a revoked session and stops before any check.

        The revoke is :meth:`AuthStore.supersede_session`, the store's one atomic revoke that says
        whether it ended the row, so presentations racing each other write one row between them,
        and a row a rotation re-keyed first is not reported as ended.

        Audited under the sign-in gate's own ``auth.temp_password_expired`` action, so one query
        finds every refusal of a lapsed credential. ``at`` names the leg. ``proof`` names the proof
        the leg asks for (``password`` or ``factor``), and the row records ``<proof>_checked``: at
        sign-in this action always means the right password was presented, and here it may not;
        with ``at`` set to ``session`` none was presented."""
        if await self._store.supersede_session(token_hash, now=time.time()) is None:
            return
        detail: dict[str, object] = {
            "provider": "local",
            "expiry_hours": self._settings.initial_password_expiry_hours,
            "at": at,
        }
        if proof is not None:
            detail[f"{proof}_checked"] = proof_checked
        await self._audit(
            "auth.temp_password_expired", actor=username, detail=_json(detail), client=client
        )

    async def _rotation_lapsed(self, token_hash: str, *, ceremony: str, client: str | None) -> bool:
        """Whether :meth:`_elevated_hash` must end this session because its temporary credential
        lapsed, ending it and auditing the refusal when so (BACKLOG #2298). A session already gone
        answers False: the rotation then fails closed on its own."""
        session = await self._store.get_session(token_hash)
        if session is None:
            return False
        user = await self._store.get_user(session.user_id)
        if user is None or not self._credential_lapsed(user, time.time()):
            return False
        await self._end_lapsed_session(token_hash, user.username, at=ceremony, client=client)
        return True

    # --- login ---------------------------------------------------------------

    async def _equalize_failure(
        self,
        outcome: LoginOutcome,
        started: float,
        *,
        seam: str,
        queued: float = 0.0,
        writes: Sequence[Callable[[], Awaitable[None]]] = (),
        write_room: bool = False,
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

        **``writes`` are a refused sign-in's deferred audit rows (BACKLOG #1131), and the deadline is
        fixed BEFORE they run (BACKLOG #2467).** Only :meth:`login` passes them, and it sets
        ``write_room`` on every refusal, rows or none, so the room applies to every sign-in refusal
        alike. The writes run at the floor, the write point, and with ``write_room`` the answer's
        deadline is the first slot boundary at least :data:`_WRITE_ROOM_SHARE` of a budget past
        it, whenever the work fits in the half budget the floor leaves. Read after the writes
        instead, the clock carried their length into the slot, and a refusal by a live lock writes
        more rows than an unknown name does. The room counts from the floor and not from ``now``,
        so an attempt that did not queue still overruns only at a whole budget of work. Writes that
        outrun their room still cannot fail open: the answer waits to the next slot boundary after
        they finish, and the overrun warning fires, as it does for work over the budget.
        """
        if outcome.ok:
            # No success defers a row today; one that did must still write it (count-and-log).
            if writes:
                await _write_through_cancellation(writes)
            return outcome
        now = time.monotonic()
        elapsed = now - started
        work = elapsed - queued
        # For an attempt that did not queue the floor sits inside slot 1, so it changes nothing.
        span = _FAILURE_BUDGET_SECONDS
        floor = started + queued + span / 2
        # The earliest instant the answer may go out: the floor, plus the deferred writes' room.
        earliest = floor + (span * _WRITE_ROOM_SHARE if write_room else 0.0)
        # Whether the work, and not the wait, decided the slot: ``now`` lies in a later slot than
        # ``earliest``. Worked out here rather than by a second ``_failure_deadline`` call, so the
        # pad's arithmetic runs once per failure.
        moved = now > earliest and (now - started) // span != (earliest - started) // span
        deadline = _failure_deadline(started, max(now, earliest))
        if moved:
            # The work alone moved this failure to a later slot than its wait put it in. For an
            # attempt that did not queue this is work over one budget; for a queued one, work over
            # the half budget the floor leaves it, plus any write room.
            _warn_budget_overrun(seam, work)
        if writes:
            try:
                await _sleep_until_write_point(floor)
            except asyncio.CancelledError:
                # A caller who drops the request here does not drop the audit trail
                # (count-and-log), and the account's queue is held until the rows are in. A write
                # that fails is logged rather than raised, so the cancel still reaches the caller.
                try:
                    await _write_through_cancellation(writes)
                except Exception:
                    _log.exception("a refused sign-in's audit write failed after a cancel")
                raise
            writing = time.monotonic()
            await _write_through_cancellation(writes)
            written = time.monotonic()
            if written >= deadline:
                # The rows outran their room. Rounding up keeps the raw elapsed off the wire.
                deadline = _failure_deadline(started, written)
                _warn_budget_overrun(seam, written - writing, writes=True)
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
          failures on one account are answered about a slot apart. With the floor below and the
          room left for the audit writes (BACKLOG #2467), an attacker who spaces attempts can make
          each hold the queue for up to one and three quarter slots, which is the most the owner
          waits per queued attempt; the sign-in limiter bounds how many queue, and with it off
          nothing does.
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
            # A refused local sign-in's audit rows are written at a FIXED point of the padded
            # window, not as its branch finishes (BACKLOG #1131, Manager decision 2026-09-28).
            # Written as the branch finished, a row's ``ts``, and the moment it appeared to a reader
            # polling ``GET /audit``, showed how much work the branch did: a refusal by a live lock
            # does one dummy verify, a verified refusal also reads the TOTP secret and counts the
            # failure, and only a right candidate arms the second-step lock. The point is the
            # equalizer's own floor, half a budget past the attempt's turn in the queue, so the rows
            # land there on every branch whose work fits in half a budget (the same condition the
            # answer's slot already rests on). The writes run INSIDE the padded window, and the
            # answer's deadline is fixed before they start, with room left for them
            # (:meth:`_equalize_failure`, BACKLOG #2467), so their length cannot move its slot.
            # Written after the pad instead, the answer would wait for the writes, and the branches
            # write different numbers of rows. The COUNT still runs before this, so counting is
            # unchanged.
            after_pad: list[Callable[[], Awaitable[None]]] = []
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
            # The room is set on every branch, whether it deferred rows or not, so every refusal
            # answers on the same slot.
            return await self._equalize_failure(
                outcome, started, seam="login", queued=queued, writes=after_pad, write_room=True
            )

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
            await self._directory_reject_audit(
                username, "simple_bind", "pathway_retired", client=client
            )
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
        writes them at a fixed point inside its failure pad, so their ``ts`` does not show which
        branch refused.
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
        #
        # This line stays open-coded on purpose: ASVS scorecard anchors quote it. _credential_lapsed
        # is the same test for the session legs (BACKLOG #2298); change the two together.
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
        # BACKLOG #288. Classified BEFORE record_login_success and the mint: ``last_login_at`` is state
        # this sign-in would otherwise find, and so is the known-address row it may write below.
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
            idp_auth_time=None,
            supersedes_hash=hash_token(supersedes) if supersedes else None,
        )
        await self._record_login_address(
            address, user, client=client, provider="local", mechanism=None
        )
        # vault BACKLOG #2145: a sign-in that still owes a factor writes nothing here; the factor
        # leg that finishes it does. A combined sign-in has proved its code, as verify_mfa would.
        if not mfa_required and (combined or address in _LOGIN_VERDICTS_THAT_SEED_THE_BASELINE):
            await self._mark_login_address_known(user.id, client)
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
            await self._directory_reject_audit(
                "<kerberos>", "kerberos", "not_configured", client=client
            )
            return LoginOutcome(ok=False, error="Windows SSO is not configured")
        try:
            username = await asyncio.to_thread(kerberos_principal, token, self._settings)
            if username is None:
                await self._directory_reject_audit(
                    "<kerberos>", "kerberos", "no_principal", client=client
                )
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
            await self._directory_reject_audit(
                username, "kerberos", "not_in_directory", client=client
            )
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
            client_auth=self._oidc_client_auth,
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
            await self._directory_reject_audit("<oidc>", "oidc", "not_configured", client=client)
            return LoginOutcome(
                ok=False, error="federated sign-in is not configured", reason="not_configured"
            )
        flow = self._oidc_flows.pop(flow_id)
        if flow is None:
            await self._directory_reject_audit("<oidc>", "oidc", "state_unknown", client=client)
            return LoginOutcome(
                ok=False, error="federated sign-in expired; start again", reason="state_unknown"
            )
        if not oidc.state_matches(flow.state, state):
            await self._directory_reject_audit("<oidc>", "oidc", "state_mismatch", client=client)
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
            await self._directory_reject_audit("<oidc>", "oidc", "not_configured", client=client)
            return LoginOutcome(
                ok=False, error="federated sign-in is not configured", reason="not_configured"
            )
        if flow.step_up_session_hash is not None:
            # BACKLOG #296. A STEP-UP flow never mints a session. It was staged to elevate one live
            # session, and signing in on it would hand the browser a second, fresh session instead.
            # Refused before the code is redeemed, so the IdP proof is spent on nothing.
            await self._directory_reject_audit(
                "<oidc>", "oidc", FLOW_PURPOSE_MISMATCH, client=client
            )
            return LoginOutcome(
                ok=False, error="federated sign-in failed", reason=FLOW_PURPOSE_MISMATCH
            )
        # BACKLOG #2301: the callback's age is read as it arrives, so the engine's own round trip to
        # the token endpoint below never counts as time the person spent. Whether the floor applies
        # needs the verified auth_time, so the decision waits for the exchange.
        arrived_too_early = self._oidc_callback_too_early(flow)
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
            await self._directory_reject_audit("<oidc>", "oidc", exc.reason, client=client)
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
        # BACKLOG #2301 (ASVS 2.4.2): the minimum-elapsed floor, only when the person signed in at
        # the IdP during THIS flow, which the verified auth_time says. An IdP holding a live single
        # sign-on session answers with no human step, so there is nothing to floor, and flooring it
        # would refuse that sign-in on every retry. auth_time is whole seconds, so it is compared
        # with the flow's start rounded down: a sign-in in the same second as the start is the fast
        # case this floor exists for. An IdP clock that runs ahead can make an older sign-on look
        # fresh; the refusal then clears once the skew has passed, and it never lets a flow through.
        signed_in_during_flow = principal_claims.auth_time >= math.floor(flow.issued_at)
        if signed_in_during_flow and arrived_too_early:
            # With the client address, as the token_refused arm records it: a run of these is
            # automation, and the operator needs to see where it comes from.
            await self._audit(
                "auth.login_failed",
                actor="<oidc>",
                detail=_json({"provider": "ad", "mech": "oidc", "reason": TOO_EARLY}),
                client=client,
            )
            return LoginOutcome(ok=False, error="federated sign-in failed", reason=TOO_EARLY)

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
            await self._directory_reject_audit(
                username, "oidc", "local_account_conflict", client=client
            )
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
            await self._directory_reject_audit(
                username, "oidc", DIRECTORY_OBJECT_ID_MISSING, client=client
            )
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
            await self._directory_reject_audit(username, "oidc", "not_in_directory", client=client)
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
            await self._directory_reject_audit(username, "oidc", "expired", client=client)
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
            await self._directory_reject_audit(username, "oidc", "auth_time_stale", client=client)
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
            # BACKLOG #2143: the RAW verified auth_time, not the clamped value the cap above uses.
            # The step-up compares the IdP's next auth_time with it, IdP clock against IdP clock.
            idp_auth_time=principal_claims.auth_time,
            # ASVS 7.2.4: the session the START leg saw (see PendingFlow.prior_session_hash).
            supersedes_hash=flow.prior_session_hash,
        )

    # --- the federated step-up leg (BACKLOG #296, ADR 0142 Amendment B) ---------------------------

    async def session_steps_up_at_idp(self, token: str | None) -> bool:
        """Whether this session's step-up goes back to the IdP rather than to a password.

        True exactly when the session was minted by the federated login (``sessions.auth_mechanism``,
        ADR 0184 item (iv)). The SESSION decides, not the account, so a Kerberos session keeps its
        existing step-up. (A bind ends the account's sessions and Windows SSO refuses it
        afterwards, vault BACKLOG #2609; ``docs/SECURITY.md``, *Federated sign-in*, is the source
        of record for that rule.) PUBLIC because the web
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

    def _oidc_callback_too_early(self, flow: PendingFlow) -> bool:
        """Whether ``flow``'s callback came back sooner than ``[auth].oidc_callback_min_elapsed_seconds``
        after the flow started, on the flow cache's own clock (BACKLOG #2301). The caller decides
        whether the floor applies."""
        floor = self._settings.oidc_callback_min_elapsed_seconds
        flows = self._oidc_flows
        return floor > 0 and flows is not None and flows.age(flow) < floor

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
        matches; it is a step-up flow; the callback is not too soon after the flow started (BACKLOG
        #2301); the code exchange and the whole claims ladder pass (the nonce, the pinned issuer,
        ``auth_time`` present and within ``oidc_max_age_seconds``, and the MFA claim when that gate
        is on); the session is still live by every test :meth:`identity_for_token` applies, and
        still an OIDC session; the account is enabled and still a directory account; the token's
        verified ``(issuer, sub)`` is byte-for-byte the pair bound to the account; ``auth_time`` is
        fresh by our clock (see the inline note); the session holds an IdP ``auth_time``, and the
        new one is later; the directory still has the account; and every role stored on the
        account is among the roles its current groups map to (BACKLOG #2154). Then it elevates through :meth:`_elevated_hash`, so
        rotation, the MFA carry and the single-use grant follow the password leg's rules exactly.

        Refusals are audited under the staged session's account wherever the flow names one, so they
        appear in that person's security events rather than under an anonymous actor.

        The session is re-anchored to the callback's address when the callback has one. The
        ``auth.reauth`` row a completed step-up writes, including one whose rotation lost the
        session, also records the start leg's address as ``start_client`` and whether the two are
        different hosts as ``client_moved`` (BACKLOG #2160). The refusal rows above carry neither.
        A move is recorded, never refused. Behind a proxy the engine does not trust, both legs carry
        the proxy's address, so ``client_moved`` reads false there.

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
        # BACKLOG #2301 (ASVS 2.4.2): max_age=0 and prompt=login make the person authenticate at the
        # IdP, so a step-up callback faster than a person can do that is refused. Before the code is
        # redeemed, so the refused flow spends nothing at the token endpoint.
        if self._oidc_callback_too_early(flow):
            return await self._step_up_refused(
                TOO_EARLY, actor=actor, client=client, return_to=return_to
            )
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
            # BEFORE both freshness tests (BACKLOG #2143), so another person's answer that passed
            # the claims ladder is filed as a subject mismatch whatever its auth_time. Both tests
            # below judge this session's identity, so neither is the right name for someone else.
            return await self._step_up_refused(
                STEP_UP_SUBJECT_MISMATCH, actor=actor, client=client, return_to=return_to
            )
        # FRESHNESS, two tests, and both must pass. max_age=0 and prompt=login ask the IdP to
        # authenticate the user afresh, so a conforming IdP's auth_time postdates this request.
        # (a) Against our clock: auth_time is IdP clock and issued_at is ours, so the floor allows
        # the configured skew for an IdP clock that runs behind.
        skew = self._settings.oidc_clock_skew_seconds
        if flow.issued_at <= 0 or principal_claims.auth_time < flow.issued_at - skew:
            return await self._step_up_refused(
                STEP_UP_NOT_FRESH, actor=actor, client=client, return_to=return_to
            )
        # (b) Against the IdP's own clock (BACKLOG #2143): auth_time must be LATER than the one the
        # session holds, which is the sign-in's or the last step-up's. No skew applies, because
        # both values come from the IdP. This closes most of what (a) alone left: an IdP that
        # ignores max_age=0 and answers from the sign-in, or from the last step-up, within the skew.
        # A NULL (an oidc row written before the column existed) cannot be compared, so it refuses.
        # RESIDUAL, stated exactly: an IdP that ignores max_age=0 still passes when its last
        # sign-in for this user is later than the value the session holds and within
        # oidc_clock_skew_seconds of this request. The cost of (b): an IdP clock that steps back, or
        # IdP nodes whose clocks disagree, refuse a real re-authentication until it passes the value.
        # Each arm has its own closed-set reason, apart from (a)'s STEP_UP_NOT_FRESH, so the audit
        # row and the operator's text say which one refused.
        held_auth_time = session.idp_auth_time
        if held_auth_time is None:
            return await self._step_up_refused(
                STEP_UP_IDP_AUTH_TIME_MISSING, actor=actor, client=client, return_to=return_to
            )
        if principal_claims.auth_time <= held_auth_time:
            return await self._step_up_refused(
                STEP_UP_IDP_AUTH_TIME_NOT_LATER, actor=actor, client=client, return_to=return_to
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
        # BACKLOG #2154: the account's stored roles must all be among the roles its current groups
        # map to, the same test _directory_step_up_refusal applies on the TOTP and passkey legs
        # (#2240). Inline rather than through that helper, because its probe would change this
        # leg's not_in_directory reason. Only a LOST role refuses; refusing writes nothing, and the
        # reconciler or the next sign-in re-syncs the roles.
        held = set(await self._store.get_user_role_ids(user.id))
        if not held <= await self._store.roles_for_ad_groups(principal.groups):
            return await self._step_up_refused(
                DIRECTORY_ROLES_DEMOTED, actor=actor, client=client, return_to=return_to
            )
        purpose = flow.step_up_purpose
        # The password leg's three ORDER-CRITICAL steps (see :meth:`reauth`), against the hash.
        # (1) Every stamp against the OLD hash, re-anchoring the session to this client address.
        # The accepted auth_time is written in the same statement (BACKLOG #2143), so the next
        # step-up must show a later one: this answer replayed by the IdP is then refused.
        await self._store.mark_session_reauthed(
            token_hash, client=client, idp_auth_time=principal_claims.auth_time
        )
        self._restart_new_ip_dedupe(token_hash)
        grant_refused = purpose is not None and await self._factor_binding_is_blocked_hash(
            token_hash, purpose
        )
        # (2) Rotate. Past this line the staged hash no longer resolves.
        elevation = await self._elevated_hash(
            token_hash, ceremony="reauth_oidc", actor=user.username, client=client
        )
        if elevation.ok:
            # vault BACKLOG #2145, as in reauth.
            await self._mark_login_address_known(user.id, client, step_up=True)
        if purpose is not None and not grant_refused and elevation.token is not None:
            # (3) The purpose-bound grant, against the NEW hash.
            self._grant_action_step_up(hash_token(elevation.token), purpose)
        self.clear_oidc_unavailable()
        # BACKLOG #2160: the start leg staged its caller's address, and the session is re-anchored
        # to the callback's above. Record whether the address moved mid-ceremony, compared as the
        # new-address signal compares. Recorded only: refusing a move, or anchoring to the start
        # address, would change ADR 0142 Amendment B and needs a ruling first. None when either
        # address is unknown, since an empty string matches nothing and proves no move.
        start_client = flow.client_ip or None
        client_moved = (
            not self._same_host(start_client, client) if start_client and client else None
        )
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
                    "start_client": start_client,
                    "client_moved": client_moved,
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

    async def _directory_reject_audit(
        self, actor: str, mech: str, reason: str, *, client: str | None
    ) -> None:
        """Audit a rejected directory-SSO attempt. ``mech`` is the mechanism slug ("kerberos" /
        "oidc"); ``reason`` must come from a closed set so no IdP-influenced text is ever stored.

        ``client`` is keyword-only with no default, so every caller must name it (BACKLOG #2132).
        The type still accepts ``None``, so this forces a decision and does not enforce an address.
        A run of refusals is how a spray shows, and the operator needs to see its source."""
        await self._audit(
            "auth.login_failed",
            actor=actor,
            detail=_json({"provider": "ad", "mech": mech, "reason": reason}),
            client=client,
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
        # BACKLOG #2143: the federated sign-in's verified auth_time, stored on the session. Only the
        # federated caller passes it; a Kerberos session has no IdP clock to compare.
        idp_auth_time: float | None = None,
    ) -> LoginOutcome:
        # ``federated_subject`` is the verified OIDC ``(issuer, sub)`` and is passed ONLY by the
        # federated path (BACKLOG #1015). It defaults to None, so the Kerberos caller's audit row is
        # unchanged. (Its session insert is guarded since vault BACKLOG #2609, which is one read
        # inside that insert's transaction.) The federated caller has
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
        if federated and idp_auth_time is None:
            # BACKLOG #2143, also a programming error. An OIDC session minted with no IdP auth_time
            # stores NULL, and every IdP step-up on it is then refused. Fail at the mint instead.
            raise ValueError("a federated login needs the verified IdP auth_time")
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
        if not principal.directory_object_id:
            # BACKLOG #2027 (ADR 0184 AC-5), THE DIRECTORY HALF. A PRINCIPAL WITH NO IMMUTABLE ID
            # SIGNS NOTHING IN. The only key left to join it to a row is the username, and a
            # directory may reissue a freed name to another person, so resolving by it would hand
            # that person the row, its ``user_id`` and, through the role resync below, their groups.
            #
            # First sight is refused too, not only a returning row. A row minted here would carry no
            # id, and this branch would refuse its every later sign-in, so creating it buys one
            # session and an account nothing can bind (``create_directory_account`` refuses the
            # same entry as :class:`DirectoryObjectIdMissing`).
            #
            # ORDERED ABOVE THE #1471 CONFLICT BRANCH so the audit names the cause. A directory that
            # stops returning ``objectGUID`` would otherwise file every returning account as a
            # name-recycle conflict, whose remedy (remove the stale row) is the wrong one here.
            #
            # THE COST, STATED: a directory that returns no readable ``objectGUID`` to the service
            # account signs nobody in through Windows SSO. The LDAP layer warns once per shape, and
            # the remedy is to make the attribute readable. The caller sees the generic failure; the
            # precise reason is on the ``auth.login_failed`` row. The federated leg re-resolves by
            # the bound row's id, and the shipped LDAP client answers an entry that does not read
            # that id back as no match (``not_in_directory``, BACKLOG #2027). So the federated arm
            # below is reached only through a directory implementation that does not check it.
            if federated:
                await self._directory_reject_audit(
                    principal.username, "oidc", DIRECTORY_OBJECT_ID_MISSING, client=client
                )
                return LoginOutcome(
                    ok=False, error="federated sign-in failed", reason=DIRECTORY_OBJECT_ID_MISSING
                )
            return await self._refuse_directory_row(
                principal.username, DIRECTORY_OBJECT_ID_MISSING, client=client
            )
        if existing is not None and existing.directory_object_id != principal.directory_object_id:
            # BACKLOG #1471. THE ROW HOLDING THIS NAME MUST AGREE WITH THE PRESENTED IDENTITY.
            #
            # **THIS IS NOT WHAT CLOSES THE RECYCLE** -- say so plainly, because the obvious reading
            # is wrong and would send the next reader looking for the control in the wrong place.
            # ``_upsert_ad_user`` no longer ASKS by name, so a reissued ``sAMAccountName`` presenting
            # a new id misses the id lookup and gets its own row whether or not this branch exists.
            # What this branch does is narrower, and both halves are load-bearing:
            #
            #   - it refuses an id-bearing login against an id-LESS row, and a login whose id is not
            #     the row's. (An id-LESS login never gets here since BACKLOG #2027: the branch above
            #     refuses it first.) An identity that cannot be checked is not one that matches;
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
                detail=_json({"provider": "ad", "reason": DIRECTORY_IDENTITY_CONFLICT}),
                client=client,
            )
            return LoginOutcome(
                ok=False, error="account conflict", reason=DIRECTORY_IDENTITY_CONFLICT
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
        #
        # vault BACKLOG #2609: the same helper refuses a row that holds a federated binding when the
        # login asking is not the federated one, so Windows SSO never signs a bound account in. Both
        # arms pass ``federated``, and the paragraph above about which arm closes it holds for this
        # refusal too.
        if existing is not None:
            refusal = _directory_login_refusal(existing, time.time(), federated=federated)
            if refusal is not None:
                return await self._refuse_directory_row(principal.username, refusal, client=client)
        try:
            user = await self._upsert_ad_user(
                principal, by_name=existing, federated=federated, client=client
            )
        except _DirectoryAccountConflict as exc:
            # BACKLOG #2697: a concurrent create took the name, and the row that won is not this
            # principal's. Audited as the two conflict branches above audit. The outcome names the
            # reason in both cases, as the federated leg's local conflict does; the local branch
            # above names none.
            await self._audit(
                "auth.login_failed",
                actor=principal.username,
                detail=_json({"provider": "ad", "reason": exc.reason}),
                client=client,
            )
            return LoginOutcome(ok=False, error="account conflict", reason=exc.reason)
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
            await self._directory_reject_audit(principal.username, "oidc", reason, client=client)
            return LoginOutcome(ok=False, error="federated sign-in failed", reason=reason)
        role_ids = sorted(await self._store.roles_for_ad_groups(principal.groups))
        previous = set(await self._store.get_user_role_ids(user.id))
        await self._store.set_user_roles(user.id, role_ids, assigned_by="ad-sync")
        # vault BACKLOG #2610: only a role this sync ADDED is reported, so an account that already
        # held Administrator pages nobody on each sign-in.
        gained = frozenset(role_ids) - previous
        roles_gained = RolesGained(user.username, gained) if gained else None
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
                #
                # vault BACKLOG #2609. THE WINDOWS SSO LEG NOW PASSES THE MIRROR GUARD, so the
                # sentence above holds for the password leg only. The refusal further up read
                # the row before this mint, and a bind can commit between the two: its sweep
                # runs in the bind's own transaction and cannot see a session inserted after
                # it. So the insert itself requires an unbound row, under the lock the bind
                # takes. That also covers a rebind's gap, where the row is unbound between the
                # clear and the write.
                require_federated_subject=federated_subject if federated else _UNBOUND,
                idp_auth_time=idp_auth_time,
                supersedes_hash=supersedes_hash,
            )
        except _BindingChangedMidLogin:
            if not federated:
                # A bind landed between the refusal check and the insert, so no session was
                # minted. The caller gets the answer the check gives. NOT THE SAME AS THAT
                # CHECK IN ONE WAY: the role, scope and profile sync above already ran, so a
                # directory role change in this window is applied and audited, and it ends
                # the account's other sessions as that sync always does. The reason is
                # also written for a row deleted in the same window, which the guard
                # refuses too; that row has no binding to look for.
                refused = await self._refuse_directory_row(
                    principal.username, FEDERATED_SIGN_IN_REQUIRED, client=client
                )
                return replace(refused, roles_gained=roles_gained)
            await self._directory_reject_audit(
                principal.username, "oidc", "federated_subject_unbound", client=client
            )
            return LoginOutcome(
                ok=False,
                error="federated sign-in failed",
                reason="federated_subject_unbound",
                roles_gained=roles_gained,
            )
        # The password-AD and Kerberos paths must keep emitting EXACTLY {"provider","roles"}: _json is
        # json.dumps(sort_keys=True), so a null-valued key is a different stored string, not a no-op.
        # Only the federated path passes mech/evidence, so it alone grows the row.
        detail: dict[str, object] = {"provider": "ad", "roles": role_ids}
        if mech is not None:
            detail["mech"] = mech
        if evidence:
            detail["evidence"] = dict(evidence)
        # vault BACKLOG #2156: the address rows name the session mechanism, because ``provider`` is
        # ``ad`` on both directory legs and could not tell a Kerberos sign-in from an OIDC one.
        await self._record_login_address(
            address, user, client=client, provider="ad", mechanism=session_mechanism
        )
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
            # vault BACKLOG #2145, closing the #2156 review's R1-1: only a directory sign-in that owes
            # nothing more marks its address known. The audit baseline this replaced counted a
            # directory row that still owed a factor, because that row carries no marker of it.
            # NEW is written too: no directory session is ever seeded, so withholding the write
            # would challenge nothing and would only repeat the notice at every sign-in from an
            # address its owner keeps using. A failed read is no evidence, so it writes nothing.
            if address is not _LoginAddress.UNEVALUATED_READ_FAILED:
                await self._mark_login_address_known(user.id, client)
        return LoginOutcome(
            ok=True,
            token=token,
            identity=identity,
            mfa_required=mfa_required,
            roles_gained=roles_gained,
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
        federated: bool,
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

        A principal with no id never reaches this method: ``_complete_ad_login`` refuses it as
        ``directory_object_id_missing`` (BACKLOG #2027). Before that, such a principal fell back to
        the name here, which is the recycle this docstring's first paragraph exists to stop.

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
        (BACKLOG #1637 / #1638), or holds a federated binding while the login is not the federated
        one (vault BACKLOG #2609, which is what ``federated`` is for), before any write. See the gate
        below the id-keyed lookup for why the condition is signalled from here rather than checked
        on the returned record.

        A first sign-in that loses the create race to a concurrent one adopts the row that won
        (BACKLOG #2697), after the same conflict and eligibility checks the caller makes on a row it
        read. Raises :class:`_DirectoryAccountConflict` when that row is LOCAL or carries a different
        immutable id.
        """
        if by_name is not None and by_name.directory_object_id != principal.directory_object_id:
            # Defensive, and deliberately a RAISE rather than a silent re-read. The caller's check is
            # what stops a row being adopted by a principal it does not belong to, so a caller that
            # skipped it must fail loudly here: an unnoticed adoption is the defect this item exists
            # to remove, and a 500 on a misuse that no shipped path can reach is the cheap side of
            # that trade. Not reachable from ``_complete_ad_login``, which refuses first.
            raise ValueError("directory principal does not match the row holding its username")
        if not principal.directory_object_id:
            # The same defensive raise, for BACKLOG #2027: with no id, the only key left is the name.
            # Not reachable from ``_complete_ad_login``, which refuses such a principal first.
            raise ValueError(
                "a directory principal with no immutable id cannot be resolved to a row"
            )
        existing = by_name or await self._store.get_user_by_directory_object_id(
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
            refusal = _directory_login_refusal(existing, time.time(), federated=federated)
            if refusal is not None:
                raise _DirectoryLoginRefused(refusal)
        if existing is None:
            try:
                user_id = await self._create_directory_row(principal, client=client)
            except Exception as exc:
                if not _is_integrity_refusal(exc):
                    raise
                # BACKLOG #2697. A CONCURRENT FIRST SIGN-IN TOOK THE NAME BETWEEN THE READS ABOVE AND
                # THIS INSERT. Two sign-ins of one person at once is ordinary, so the loser adopts the
                # winner's row rather than failing. The username index is the only one that can fire
                # here: `directory_object_id` carries no UNIQUE index on any backend. So the name is
                # what is re-read, and a refusal with no row holding it is some other fault.
                winner = await self._store.get_user_by_username(principal.username)
                if winner is None:
                    raise
                # The checks `_complete_ad_login` makes on a row it read by name, in its order. That
                # read ran before the winner existed, so nothing has asked them of this row yet. A
                # check added there belongs here too.
                #
                # NOT CLOSED HERE: both sign-ins then run the caller's role resync on one new row.
                # When the groups map to a role, each can read no prior roles and revoke the
                # account's sessions, which can end the other's new session. On the server backends
                # the two `set_user_roles` transactions can also meet the `user_roles` key, by
                # reading (not measured), and the second would raise. Two concurrent sign-ins of an
                # existing account meet both races too, so they belong to the resync.
                if winner.auth_provider != AuthProvider.AD.value:
                    raise _DirectoryAccountConflict("local_account_conflict") from exc
                if winner.directory_object_id != principal.directory_object_id:
                    raise _DirectoryAccountConflict(DIRECTORY_IDENTITY_CONFLICT) from exc
                # BACKLOG #1637 / #1638: the eligibility gate stays before the first write, for the
                # adopted row as for one the reads found. The winner may already be disabled.
                refusal = _directory_login_refusal(winner, time.time(), federated=federated)
                if refusal is not None:
                    raise _DirectoryLoginRefused(refusal) from exc
                existing = winner
        if existing is not None:
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
            # BACKLOG #1139, ASVS 6.3.7. The directory owns the attribute, but repointing it decides
            # where every later security notice on this account is delivered -- so it is an update
            # to the account's authentication details, and it gets the same two records the local
            # sibling ``update_user`` emits: an audit row and an out-of-band notice.
            #
            # This method sits on the SHARED directory completion path, so this covers the
            # simple-bind, Kerberos and federated legs alike, not AD alone.
            #
            # The row commits in the UPDATE's transaction (BACKLOG #2221; ``AuditAppend`` says why).
            email_changed = email != existing.email
            repoint: list[AuditAppend] = []
            if email_changed:
                repoint.append(
                    AuditAppend(
                        "auth.ad_profile_email_changed",
                        actor=principal.username,
                        detail=_json({"user_id": user_id, "source": "directory"}),
                        client=client,
                    )
                )
            await self._store.update_user_profile(
                user_id, display_name=display_name, email=email, audits=repoint
            )
            if email_changed:
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
        audits: Sequence[AuditAppend] = (),
    ) -> str:
        """Insert the mirror row for a directory principal the store does not hold, and return its id.

        The one directory birth, shared by a directory sign-in (:meth:`_upsert_ad_user`) and an
        administrator's create (:meth:`create_directory_account`, BACKLOG #2021), so the two cannot
        disagree about what a new directory account carries. The caller has already established that
        no row holds the principal's id or name.

        ``typed_notify_email`` is the administrator's checked address for a row whose ``mail`` is
        not adopted (#2021 only). It is bound in the same INSERT, so no crash leaves that row with
        no address. The profile mirror still gets the directory's ``mail``.

        ``audits`` are the caller's own rows for this birth. They commit in the INSERT's
        transaction, after any not-adopted row (BACKLOG #2221).
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
        # #2100).
        rows: list[AuditAppend] = []
        if not adopt:
            rows.append(
                AuditAppend(
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
            audits=[*rows, *audits],
            password_generated=False,
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
        # Committed with the INSERT, not after it (BACKLOG #2221).
        created = AuditAppend(
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
        try:
            user_id = await self._create_directory_row(
                principal, client=client, actor=actor, typed_notify_email=typed, audits=(created,)
            )
        except Exception as exc:
            if not _is_integrity_refusal(exc):
                raise
            # Re-read rather than assume the name index fired, as create_local_user does.
            if await self._store.get_user_by_username(principal.username) is None:
                raise
            raise UsernameTaken(USERNAME_TAKEN) from exc
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
    def directory_reconcile_referral(self) -> str | None:
        """The standing LDAP referral's operator message, or ``None`` (BACKLOG #2538). Latches until
        a pass marks ``referral_clear``, the test the referral's alert resolves on, which
        ``_mark_reconcile_clears`` states."""
        return self._reconcile_referral_alert

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

        No caller hands this a row whose ``directory_object_id`` is NULL (BACKLOG #2434). Such a row
        would probe by name, and a name probe can read another account's entry. The step-up legs
        refuse it first, and :meth:`reconcile_directory_sessions` reads it as UNKEYED unasked,
        or skips it when it carries a federated binding (:meth:`_report_unkeyed_bindings`).

        ``probe_principal`` is the password-free service-account lookup the Kerberos path uses, with
        the reason kept. It returns the group set, so the role re-diff below costs no extra round
        trip. It also says why an account did not resolve, which the sign-in paths never see: a
        search that matched nothing reads ABSENT, a set disabled bit DISABLED, and an unreadable
        ``userAccountControl`` UNDETERMINED (ADR 0195 rule items 1 and 2). An unreadable attribute
        must never come back as UNAVAILABLE, which never revokes; that would reopen BACKLOG #1639.
        """
        # Guarded by directory_reconcile_enabled, and by _directory_presence (BACKLOG #2023, #2316).
        assert self._ldap is not None
        try:
            probe = await asyncio.to_thread(
                self._ldap.probe_principal, user.username, object_id=user.directory_object_id
            )
        except LdapReferralError as exc:
            # BACKLOG #2538. Ahead of LdapError, which it subclasses. A referral is not an outage:
            # it recurs on every pass until the search base is fixed, so read as UNAVAILABLE it
            # would stop revocation for the referred accounts without a page. REFERRED never
            # strikes or revokes this account, the rest of the pass is still judged, the pass
            # alerts, and verify_mfa refuses on it like any other non-PRESENT answer. DEBUG here: a
            # referring base refers every account on every pass, so the reconciler logs one ERROR
            # per pass carrying the first referral's text instead, and verify_mfa audits its own
            # refusal. ldap.py warns once per process too. The text names the operation and the
            # referred hosts only (BACKLOG #2530), which is what makes it safe to carry and log.
            _log.debug("directory probe of %s was referred: %s", user.username, exc)
            return reconcile.Probe(
                user.id, user.username, reconcile.ProbeOutcome.REFERRED, detail=str(exc)
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
        except Exception as exc:
            # BACKLOG #2241. Anything else the directory layer raised: a KeyError or ValueError on a
            # malformed entry, an OSError, a fault in a test double. Uncaught, it was a 500 from
            # verify_mfa instead of an audited refusal, and it ended the WHOLE reconcile pass, so one
            # account that always raised stopped revocation for every account. Read as UNAVAILABLE:
            # verify_mfa refuses on it (fail closed), and the reconciler skips this one account.
            #
            # NOT LIKE #1639, AND THE COST IS NAMED. An unreadable userAccountControl is an answer
            # the directory gave, so it strikes as UNDETERMINED. This is the engine failing to read
            # whatever came back, which says nothing about the account, so it must not strike; and
            # UNDETERMINED would move the ADR 0195 hold. The price is that an account whose entry
            # raises every time is never revoked by the reconciler while that lasts. So this logs
            # at WARNING on every probe, unlike the debug-level outage above: a repeat here is a
            # standing gap for one named account, not a blip. CancelledError is not an Exception.
            # The WARNING names the type only: the message can quote a directory value, which
            # ldap.py never logs. The traceback, with the message, goes to DEBUG for diagnosis.
            # The certificate path lowers this to DEBUG in its own task's context (BACKLOG #2316):
            # it probes per request, not per pass, and reports the fault once as an outage.
            _log.log(
                _PROBE_FAULT_LOG_LEVEL.get(),
                "directory probe of %s raised %s; read as unavailable, so this account's "
                "sessions are not revoked and its step-up is refused while this repeats",
                user.username,
                type(exc).__name__,
            )
            _log.debug("directory probe of %s raised", user.username, exc_info=True)
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
            # `(|(sAMAccountName=<name>)(userPrincipalName=<name>@<domain>))`, so an account that
            # sets its own UPN to the victim's `<name>@<domain>` matches the same filter. Since vault
            # BACKLOG #2778 two matches are refused as AMBIGUOUS, but a directory where the victim's
            # own entry is gone answers with the attacker's entry alone. Then the probe would report
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
        * a probe the directory referred contributes nothing either, and the pass alerts, while
          every other account is still judged (BACKLOG #2538);
        * a principal must come back absent, disabled, undetermined or unkeyed
          ``ad_session_recheck_strikes`` passes running;
        * a PRESENT principal whose directory groups would change its roles, or withdraw or narrow
          its channel scope, is revoked on one pass, and the scope itself is left for the next login
          to write (ADR 0198);
        * a wave of undetermined answers is held, not revoked, and alerts (ADR 0195);
        * a row with no directory id is never asked about by name: it reads as unkeyed without a
          lookup, so it strikes like an absent account and writes no roles (BACKLOG #2434);
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
            # Deliberately WITHOUT the idle timeout (BACKLOG #2283). An idle row can come back: a
            # backward clock step or a raised idle setting makes the validator accept it again. So
            # an account holding only idle rows is still probed, and a disabled one keeps accruing
            # strikes. An idle filter would also let a forward step of more than the idle window
            # empty the candidates, and the prunes below would drop every strike and the hold. The
            # read still filters on absolute expiry, so a step past the absolute lifetime does
            # that today. That predates BACKLOG #2283, and #2283 leaves it open.
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
        # Before the prunes, which drop the outcomes it reads. And before the no-candidate return
        # below, so a pass with nobody signed in still records who left.
        self._forfeit_clears_on_attrition(users)
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
        # No early stop on a referral (BACKLOG #2538): a referral leaves only its own account
        # unjudged, so every other account in the sample is still probed and judged.
        for user_id, _username in selected:
            user = users[user_id]
            if _holds_directory_key(user):
                probes.append(await self._probe_principal(user))
            else:
                # BACKLOG #2434, ADR 0184 amendment 2026-10-06. An id-less row is never asked about
                # by name. A name probe could read another account's entry and write that
                # account's roles onto this row, and no sign-in or step-up admits such a row any
                # more, so a session it holds is anomalous. UNKEYED, unasked, writes no roles and
                # strikes like ABSENT. Not UNDETERMINED: that would feed the ADR 0195 hold, which
                # would hold these rows and forfeit a later hold alert's clear.
                probes.append(
                    reconcile.Probe(user.id, user.username, reconcile.ProbeOutcome.UNKEYED)
                )
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
        if plan.hold:
            self._advance_hold_standing("held")
        # BACKLOG #2136. A trip makes every candidate unconfirmed until a pass that is not aborted
        # reads it clean, PRESENT, so a probe sample that missed the accounts behind the trip is no
        # clear. Only PRESENT confirms. A held account's probe judged neither its roles nor its
        # scope, and its strike went back to 0. An ABSENT, DISABLED or lone undetermined read is a
        # strike, and the strike ledger forgets it once the account leaves. So each of those stays
        # unconfirmed, and its leaving forfeits the clear. An account that left has already been
        # dropped from the set (`_forfeit_clears_on_attrition`). Kept as it stood before this pass,
        # for the revocation loop below.
        unconfirmed = frozenset(self._reconcile_unconfirmed)
        # BACKLOG #2434. An id-less row is never probed, so no pass can read it PRESENT. Marked, it
        # would stay unconfirmed until its UNKEYED revocation forfeits the clear, every time.
        keyed = {uid for uid, user in users.items() if _holds_directory_key(user)}
        if plan.aborted is None:
            present = reconcile.ProbeOutcome.PRESENT
            self._reconcile_unconfirmed.difference_update(
                uid for uid, outcome in plan.outcomes.items() if outcome is present
            )
        elif not plan.judged_nothing:
            self._reconcile_unconfirmed = set(keyed)
            self._advance_breaker_standing("tripped")
        # BACKLOG #2538. The same for a referral, on its own record and its own standing.
        # `_mark_reconcile_clears` states why every candidate is marked and why only PRESENT
        # confirms; `_forfeit_clears_on_attrition` states the forfeit.
        if plan.referred:
            self._reconcile_referred = set(keyed)
            self._advance_referral_standing("referred")
        else:
            present = reconcile.ProbeOutcome.PRESENT
            self._reconcile_referred.difference_update(
                uid for uid, outcome in plan.outcomes.items() if outcome is present
            )
        referral = next((p for p in probes if p.outcome is reconcile.ProbeOutcome.REFERRED), None)
        if plan.aborted is not None:
            if not plan.directory_referral:
                await self._abort_reconcile_pass(plan)
            if not plan.directory_outage:
                # A pass of referrals only is recorded as a referral and nothing else (#2538).
                await self._record_reconcile_referral(plan, first=referral)
            if not plan.judged_nothing:
                # A held pass writes its own row even when the breaker also aborts it (ADR 0195 rule
                # item 9). An outage or a pass of referrals only judged nothing, so it leaves the
                # hold's message alone and marks no clear (BACKLOG #2538).
                await self._record_reconcile_hold(plan)
                plan = self._mark_reconcile_clears(plan, users)
            await self._report_unkeyed_bindings(unkeyed, still_unkeyed=still_unkeyed)
            return plan

        self._reconcile_alert = None
        if plan.unavailable:
            _log.warning(
                "directory reconcile: %d of %d principals asked could not be resolved (directory "
                "unreachable, or a probe raised, which is warned per account) — those sessions "
                "were left alone (fail-open)",
                plan.unavailable,
                plan.asked,
            )
        applied: list[reconcile.SessionRevocation] = []
        for revocation in plan.revocations:
            if (
                self._reconcile_outcomes.get(revocation.user_id)
                is reconcile.ProbeOutcome.UNDETERMINED
            ):
                # BEFORE the sessions go, so a pass that raises part-way cannot lose it (BACKLOG
                # #2136): the next pass no longer sees this account.
                self._advance_hold_standing("forfeit")
            if revocation.user_id in unconfirmed:
                # The same, for the breaker. The account was signed in at the trip and has not read
                # clean since. It is about to leave, so nothing will read it clean again.
                self._advance_breaker_standing("forfeit")
            if revocation.user_id in self._reconcile_referred:
                # The same, for the referral (BACKLOG #2538; `_forfeit_clears_on_attrition`).
                self._advance_referral_standing("forfeit")
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
        # BACKLOG #2538. After the revocations, like the hold below: the referred accounts were left
        # unjudged, and every other account's revocation above has already been applied.
        await self._record_reconcile_referral(plan, first=referral)
        # ADR 0195. After the revocations, so a held-row audit write that fails cannot stop a
        # genuine disable or demotion in the same pass from being applied. And that failure is
        # logged rather than raised (BACKLOG #2137), so the pass still returns its plan and the
        # lifespan task still raises an alert for each revocation above and for the hold.
        await self._record_reconcile_hold(plan)
        # BACKLOG #2027. Reported LAST, on every exit, so an audit write that keeps failing costs
        # only this report and never stops the probes and revocations above from running. A
        # failed write is logged, not raised (BACKLOG #2137), for the same reason as the hold's.
        await self._report_unkeyed_bindings(unkeyed, still_unkeyed=still_unkeyed)
        # What the pass DID, which is what the caller alerts on: a scope revocation skipped at apply
        # time (ADR 0198) was audited as nothing, so it must page as nothing too. Marked after that,
        # so the account a skipped revocation left signed in still counts toward the evidence.
        return self._mark_reconcile_clears(replace(plan, revocations=tuple(applied)), users)

    def _mark_reconcile_clears(
        self, plan: reconcile.ReconcilePlan, users: Mapping[str, UserRecord]
    ) -> reconcile.ReconcilePlan:
        """Say on the plan whether this pass is EVIDENCE that each standing condition has cleared.

        BACKLOG #2136. The lifespan task resolves the durable ``ad_reconcile_aborted`` and
        ``ad_reconcile_held`` alert instances on these, on every pass that sets them, and the
        referral's own ``ad_reconcile_aborted`` instance (BACKLOG #2538). Those instances outlive
        the process, and the strike and outcome records and the hold's latch here do not. So "not
        aborted" or "not held" is not enough: after a restart, or before the probe budget has
        reached every account, a pass can read clear while the condition stands.

        **The rule for every alert, and the one statement of it: a process clears only what it
        watched open.** A restart forgets which accounts were behind a trip, a hold or a referral,
        and an account that leaves across it is not seen to leave. Two layers keep the rule.

        * Here: a pass marks a trip clear only after a pass of this process tripped, a hold clear
          only after one held, and a referral clear only after one saw a referral
          (``_reconcile_breaker_standing``, ``_reconcile_hold_standing``,
          ``_reconcile_referral_standing``), and then only on a pass that passes the tests below.
        * In the lifespan task: ``api/app.py::_without_inherited_clears`` drops a clear while the
          instance it would resolve is one that was already open when the task first read alert
          state. Each alert has one instance row, so a trip, hold or referral of this process's
          own folds into an earlier run's open instance, and resolving that would rest on
          accounts the earlier run saw and this process never did.

        So a fresh process never resolves an instance an earlier run left open, however clean its
        estate reads, and that instance stays open for an operator. Within one process, an account
        behind any of the alerts that leaves before it reads clean forfeits that clear until a
        restart (`_forfeit_clears_on_attrition`).

        * All three need an answer on record, from this process, for every signed-in account the
          pass did not just revoke. A probe that could not reach the directory leaves none.
        * A pass in which any probe was referred marks none of the three (BACKLOG #2538). A
          referred account has no answer from this pass, and an older one on record may predate
          the referral.
        * The referral's own instance is clear when, on top of the first test, every account signed
          in at the last referral has since read PRESENT on a pass with no referral
          (``_reconcile_referred``), and ``_reconcile_referral_standing`` is ``"referred"``: a
          pass here saw a referral, and has not forfeited. Any referral marks every candidate, not
          only the referred ones, because a probe sample can miss accounts that would also be
          referred. Only a PRESENT answer confirms: it alone ran every search a referral can come
          from. A pass of referrals only, or an outage, is never evidence. The latched message is
          released on this same test, so on a sole reconciler the log and the instance agree.
          Where the lifespan task drops the flag, the latch is released and the instance stays.
        * The hold is clear when, on top of that, the pass did not hold and these tests pass.
          None of those answers is undetermined; this is the record, across the rotation. No
          account the pass just revoked read undetermined either. At least one probe of THIS pass
          read the attribute (PRESENT or DISABLED, ADR 0195's readable answer, ``plan.readable``):
          an answer from an earlier pass, or one that found no entry (ABSENT), says nothing about
          whether it is readable now. And ``_reconcile_hold_standing`` is ``"held"`` or
          ``"settled"``: a pass here held, and has not forfeited.
        * A restart also loses the hysteresis latch. A lone undetermined account beside readable
          ones revokes only because no hold engaged, and an earlier run's latch may still have
          held it. Revoking an undetermined account first forfeits the release until a restart,
          because nothing re-reads the account. The forfeit is recorded before the sessions go, so
          a pass that raises part-way keeps it. Leaving any other way forfeits on the same rule
          (`_forfeit_clears_on_attrition`). Once a pass here has found the hold gone
          (``"settled"``), every signed-in account had an answer from this process. Its latch then
          covers what an earlier run held, and a later lone revocation is ADR 0195's own, until a
          pass here holds again.
        * The breaker is clear when the pass was not aborted, none of those answers is undetermined,
          every one of those accounts carries no strike, and every account still signed in since
          the last trip has read PRESENT on a pass that was not aborted.
          A pending strike is a revocation the breaker has not judged yet, so it says nothing
          either way. A held account's probe judged neither its roles nor its scope, and a trip
          on role or scope changes leaves no strike, so a probe sample that missed or held the
          accounts behind a trip proves nothing. And ``_reconcile_breaker_standing`` is
          ``"tripped"``: a pass here tripped, and has not forfeited.

        ``users`` is this pass's candidate set, and a clear rests on reading every one of them.

        **This is one process's evidence, and the instances are the store's.** Where
        ``api/app.py::_is_sole_reconciler`` says another reconciler may run, at least on a
        ``[cluster]`` node or in an engine that runs more than one engine shard, the lifespan task
        raises no inverse; ``api/app.py::_without_clears`` says why. That gate does not see every
        reconciler on the store. The code states what it misses here, in the next paragraph, and
        the other code sites point here; ``docs/CONFIGURATION.md`` tells operators.

        **The usual cost is a missed clear, with one reconciler on the store.** An account that
        never answers keeps every instance open while it is signed in. So does a hold, for the
        breaker's instance. So does a reconciler that is switched off, and so does every cluster
        or multi-shard engine. A fresh process keeps both instances an earlier run left open, and
        a forfeited one keeps the instance it forfeited (`_forfeit_clears_on_attrition` says
        when). An operator resolves those by hand. **At least this case can still clear
        falsely.** Any engine that declares neither ``[cluster]`` nor more than one shard clears
        on its own evidence, whatever else shares its store: two plain ``serve`` processes, two
        one-shard ``supervise`` fleets, or a plain engine beside a cluster node or a multi-shard
        engine on the same store. It cannot see the others, and ``serve`` records a second engine
        on one store as unguarded (the engine shard guard's comment in ``__main__.py``).
        """
        undetermined = reconcile.ProbeOutcome.UNDETERMINED
        revoked = {r.user_id for r in plan.revocations}
        revoked_undetermined = undetermined in (self._reconcile_outcomes.get(u) for u in revoked)
        ids = [uid for uid in users if uid not in revoked]
        outcomes = [self._reconcile_outcomes.get(uid) for uid in ids]
        covered = bool(ids) and None not in outcomes and not plan.referred
        settled = covered and undetermined not in outcomes
        # Called only on a pass that judged something, so a pass of referrals only never gets here.
        referral_clear = (
            covered
            and self._reconcile_referral_standing == "referred"
            and self._reconcile_referred.isdisjoint(ids)
        )
        if referral_clear and self._reconcile_referral_alert is not None:
            self._reconcile_referral_alert = None
            _log.warning(
                "directory reconcile: every account signed in at the last LDAP referral has since "
                "been read without one; the referral cleared"
            )
        hold_clear = (
            settled
            and not plan.hold
            and not revoked_undetermined
            and plan.readable > 0
            and self._reconcile_hold_standing in _HOLD_RELEASABLE
        )
        if hold_clear:
            self._advance_hold_standing("settled")
        breaker_clear = (
            settled
            and plan.aborted is None
            and self._reconcile_breaker_standing == "tripped"
            and all(self._reconcile_strikes.get(uid, 0) == 0 for uid in ids)
            and self._reconcile_unconfirmed.isdisjoint(ids)
        )
        return replace(
            plan,
            breaker_clear=breaker_clear,
            hold_clear=hold_clear,
            referral_clear=referral_clear,
        )

    def _forfeit_clears_on_attrition(self, users: Mapping[str, UserRecord]) -> None:
        """Give up a clear when an account behind it leaves the candidate set (BACKLOG #2136).

        **The one statement of the attrition forfeit; the other sites point here.** A pass judges
        only accounts that hold a session, and nothing reads one again once it has left. So when
        the accounts behind a trip or a hold leave, the next pass would read clear on the rest
        while the fault stands. Every account a wrong search base strikes is one that cannot sign
        back in, so its sessions only drain. This turns that false clear into a missed one.

        * An account a trip left unconfirmed forfeits the breaker's clear until a restart. The
          reconciler revoking such an account forfeits it too, in the pass's revocation loop, before
          its sessions go.
        * An account whose last answer was undetermined forfeits the hold's release, on the same
          rule as revoking one: unless this process has settled and has not held since.
        * An account signed in at a referral that has not since read PRESENT on a pass with no
          referral forfeits the referral's clear until a restart (BACKLOG #2538). The revocation
          loop forfeits for an account the reconciler revokes, as for the breaker. A pass with a
          referral marks every candidate, so an account that pass itself revokes forfeits too.

        At least these take an account out: it signs out or reaches the session cap, the reconciler
        revokes it, an operator disables it locally, or its row is deleted. The cost is a missed
        clear when an account leaves for an ordinary reason while the evidence is pending. A trip
        or a referral marks every candidate unconfirmed, healthy ones too, so a sign-out during a
        long trip or referral forfeits its clear. This is one process's memory: what leaves across
        a restart is not seen here. The rule in `_mark_reconcile_clears` covers that case, because
        a fresh process resolves nothing an earlier run left open.
        """
        if not self._reconcile_unconfirmed <= users.keys():
            self._advance_breaker_standing("forfeit")
        self._reconcile_unconfirmed.intersection_update(users)
        if not self._reconcile_referred <= users.keys():
            self._advance_referral_standing("forfeit")
        self._reconcile_referred.intersection_update(users)
        undetermined = reconcile.ProbeOutcome.UNDETERMINED
        if any(
            outcome is undetermined
            for user_id, outcome in self._reconcile_outcomes.items()
            if user_id not in users
        ):
            self._advance_hold_standing("forfeit")

    def _advance_breaker_standing(self, event: _BreakerStanding) -> None:
        """Move ``_reconcile_breaker_standing`` on ``event`` (BACKLOG #2136), the only place it moves.

        ``"tripped"``: a pass here tripped, so this process watched a trip open. It moves a fresh
        process to ``"tripped"``. ``"forfeit"``: an account signed in at a trip is about to be
        revoked, or has left, before a pass read it clean; see
        :meth:`_forfeit_clears_on_attrition`. ``"forfeit"`` is never left. The warning is said
        aloud because the in-process breaker message still clears on the next pass that is not
        aborted, while the durable instance stays open for an operator.
        """
        current = self._reconcile_breaker_standing
        if event == "tripped" and current == "fresh":
            self._reconcile_breaker_standing = "tripped"
        elif event == "forfeit" and current != "forfeit":
            self._reconcile_breaker_standing = "forfeit"
            _log.warning(
                "directory reconcile: an account signed in at the last breaker trip left before a "
                "pass read it clean, so this process will not resolve ad_reconcile_aborted itself "
                "until it restarts; an operator resolves it once the directory reads clean"
            )

    def _advance_referral_standing(self, event: _ReferralStanding) -> None:
        """Move ``_reconcile_referral_standing`` on ``event`` (BACKLOG #2538), the only place it
        moves. The breaker's rule (:meth:`_advance_breaker_standing`), for the referral's instance.

        ``"referred"``: a pass here saw a referral, so this process watched one open. It moves a
        fresh process to ``"referred"``. ``"forfeit"``: an account signed in at a referral is about
        to be revoked, or has left, before a pass with no referral read it PRESENT; see
        :meth:`_forfeit_clears_on_attrition`. ``"forfeit"`` is never left. The latched referral
        message is then kept until a restart too, because the test that releases it is the clear's.
        """
        current = self._reconcile_referral_standing
        if event == "referred" and current == "fresh":
            self._reconcile_referral_standing = "referred"
        elif event == "forfeit" and current != "forfeit":
            self._reconcile_referral_standing = "forfeit"
            _log.warning(
                "directory reconcile: an account signed in at the last LDAP referral left before a "
                "pass read it without one, so this process will not resolve the referral's "
                "ad_reconcile_aborted instance itself until it restarts; an operator resolves it "
                "once the search bases are fixed"
            )

    def _advance_hold_standing(self, event: _HoldStanding) -> None:
        """Move ``_reconcile_hold_standing`` on ``event`` (BACKLOG #2136), the only place it moves.

        ``"held"``: a pass here held. That moves a fresh process to ``"held"``, and a settled one
        back to it, because this hold's accounts can still leave before it releases.
        ``"forfeit"``: an undetermined account is about to be revoked, or has left; see
        :meth:`_forfeit_clears_on_attrition`. It forfeits unless this process has settled.
        ``"settled"``: a pass here found the hold gone. ``"forfeit"`` is never left.
        """
        current = self._reconcile_hold_standing
        if event == "held" and current in ("fresh", "settled"):
            self._reconcile_hold_standing = "held"
        elif event == "forfeit" and current not in ("settled", "forfeit"):
            self._reconcile_hold_standing = "forfeit"
            _log.warning(
                "directory reconcile: an account whose userAccountControl read undetermined left "
                "before this process released a hold, so it will not resolve ad_reconcile_held "
                "itself "
                "until it restarts; an operator resolves it once the attribute reads clean"
            )
        elif event == "settled" and current in _HOLD_RELEASABLE:
            self._reconcile_hold_standing = "settled"

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

        async def _refuse(held_by: str | None, detected: str, holds: str) -> None:
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
            # ``detected`` separates the ways the taken-name condition arrives -- the pre-check saw
            # the holder (``pre_check``), or the write lost a race to it (``write_race``, or
            # ``write_noop`` where the store's guard held). The OUTCOME is deliberately identical,
            # which is the whole point of absorbing the race; the discriminator is recorded because
            # an operator reading a run of these wants to know whether they are looking at one stale
            # row or at concurrent writers, and those want different fixes.
            #
            # ``row_gone`` is a DIFFERENT condition that shares this audit action: the row was
            # deleted, so no other row holds anything and nobody is locked out. It gets its own
            # warning below rather than the lockout one, which would send an operator looking for a
            # stale holder that does not exist (BACKLOG #2291).
            #
            # ``holds`` is the name the row holds as this method read it, not the caller's
            # ``old_username`` (BACKLOG #2291). The reconciler captured that at plan time, and a
            # sign-in may have renamed the row since, so it can name an account that no longer
            # exists. The audit actor and the warning both use the name an operator would find.
            await self._audit(
                "auth.ad_username_refresh_conflict",
                actor=holds,
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
            if detected == "row_gone":
                _log.warning(
                    "AD account %s was renamed in the directory but its row was removed before the "
                    "new name could be written, so nothing was written (BACKLOG #2291)",
                    scrub_log_argument(holds),
                )
                return
            if held_by is None:
                # The write lost to another writer, but the re-read found no row holding the name
                # now. Nothing is locked out, and the next sign-in or pass copies the name down
                # again, so the lockout warning below would be false (BACKLOG #2291).
                _log.warning(
                    "AD account %s was renamed in the directory but the write lost to another "
                    "writer (detected %s), and no row holds the new name now; nothing was written, "
                    "and the next sign-in or reconcile pass retries it (BACKLOG #2291)",
                    scrub_log_argument(holds),
                    detected,
                )
                return
            _log.warning(
                "AD account %s was renamed in the directory but the new name is already held by "
                "another account (id %s, detected %s). The stored name is left as-is, and this "
                "account will be refused at its next sign-in (directory_identity_conflict) until "
                "the stale row is removed; the session it holds now survives only to the absolute "
                "cap (BACKLOG #1532)",
                scrub_log_argument(holds),
                held_by,
                detected,
            )

        # BACKLOG #2017. The row as it stands, read before the write, because the caller's
        # ``old_username`` can be stale by now: the reconciler captured it when it planned, and a
        # directory sign-in may have renamed the row since. At least four things follow from that
        # read.
        #
        # A row that already carries the new name has nothing to change, so it gets no second audit
        # row and no second notice. The notice names the name the row actually had, not the plan's.
        # The write below compares on this name (BACKLOG #2290), so a refresh that read it just
        # before another refresh of this row wrote cannot write as well. And each refusal after
        # this read audits under this name (BACKLOG #2291), so the read comes BEFORE the ``held``
        # pre-check.
        #
        # WHY THE READ STAYS ON THE LOGIN PATH TOO (BACKLOG #2291 step 4). That caller already holds
        # ``existing``, so the read costs it one ``SELECT``. It runs only on a sign-in that carries a
        # new name, so about once per directory rename, not once per sign-in. Keeping one read site
        # for both callers keeps them on one path, which is the point of this method; the
        # post-write read-back the item also counted went with BACKLOG #2290.
        before = await self._store.get_user(user_id)
        if before is None:
            # Deleted between the plan and the apply. Refused as a write that finds the row gone is
            # refused below, without an UPDATE that can only match nothing. With no row there is
            # no name it holds, so the caller's is the last one known for it. No holder either:
            # ``held_by_user_id`` is None, since the audit's ``user_id`` already names the row.
            await _refuse(None, "row_gone", old_username)
            return
        if before.username == new_username:
            # Another caller applied this rename first, in sequence (BACKLOG #2291). Nothing is
            # wrong, so INFO: the line shows why no audit row or notice followed.
            #
            # BEFORE the ``held`` pre-check, because this read is newer than the caller's: the name
            # is unique, so a row that holds it now means a ``held`` naming another row is stale.
            _log.info(
                "AD account %s already holds its directory name, so the rename refresh wrote "
                "nothing and sends no second audit row or notice (BACKLOG #2291)",
                user_id,
            )
            return
        if held is not None and held.id != user_id:
            await _refuse(held.id, "pre_check", before.username)
            return
        try:
            # BACKLOG #2290. A compare-and-set on the name just read, so of two refreshes of this
            # row running at once only one writes.
            written = await self._store.set_user_username(
                user_id, new_username, expected_username=before.username
            )
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
            await _refuse(winner.id if winner is not None else None, "write_race", before.username)
            return
        # AUDIT SUCCESS ONLY ON A WRITE THAT LANDED. The UPDATE can match zero rows and raise
        # nothing, so an unconditional success audit would report a rename that did not happen. An
        # audit trail that says a name moved when it did not is worse than a missing row: an operator
        # reconciling "who is this account" against the directory would take the engine's word for a
        # state neither side is in.
        #
        # ``False`` covers three cases, and the re-read below tells them apart.
        #   - The row is gone, deleted between the pre-read and the write: ``row_gone``.
        #   - The row still holds the name read before, so the compare matched and the NOT EXISTS
        #     guard is what stopped the write: another row holds the new name. That is the race
        #     where the losing side's guard HOLDS (81 of 200 pairs on PostgreSQL,
        #     `store/postgres.py`) rather than raising: ``write_noop``. The holder is looked up, as
        #     the ``write_race`` arm does, because the operator who must remove it needs its id.
        #   - The row's name moved after the pre-read, so the compare failed: another refresh of
        #     this same row wrote first (BACKLOG #2290). That caller audits and notifies, so this one
        #     does neither. It is not a conflict either, because no other row holds anything. The
        #     first writer wins, so when two refreshes carry DIFFERENT new names the stored one can
        #     be the older of the two until the next sign-in or pass copies the directory's name
        #     down again. Logged at INFO so the skipped write is visible without paging anyone.
        if not written:
            after = await self._store.get_user(user_id)
            if after is None:
                await _refuse(None, "row_gone", before.username)
            elif after.username == before.username:
                holder = await self._store.get_user_by_username(new_username)
                await _refuse(
                    holder.id if holder is not None else None, "write_noop", before.username
                )
            else:
                _log.info(
                    "AD account %s: another refresh already changed the stored name (now %s), "
                    "so this one wrote nothing and sends no second audit row or notice "
                    "(BACKLOG #2290)",
                    user_id,
                    scrub_log_argument(after.username),
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
        # the compare-and-set on that name reported a write. Every refused path above returns first,
        # so a lost race sends none, and so does a rename another caller already applied.
        #
        # That holds for two refreshes of the SAME row running at once too, a sign-in and a
        # reconciler pass (BACKLOG #2290). Both can read the old name, but the store writes only
        # while the row still holds it, so exactly one of them gets ``True`` and sends.
        #
        # Both callers send it. The reconciler notifies its revocations too, so it has no rule that
        # holds notices back. Addressed to the engine-owned ``notify_email`` of the row read before
        # the write, as the reconciler's own notices are; a rename moves no address, so no old holder
        # needs the fallback the directory email repoint in ``_upsert_ad_user`` carries. No second
        # read for a fresher address: it would run after the rename committed and was audited, so a
        # store fault there would fail a sign-in, or abort a reconciler pass, over a notice.
        await self._notify_security(
            USERNAME_CHANGED,
            username=new_username,
            email=before.notify_email,
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
        which the pass reads as UNKEYED without a lookup, so its sessions end at the strike
        threshold (BACKLOG #2434). No sign-in admits an id-less row, so nothing signs it back in.

        The row is left bound on purpose. Clearing a binding is an administrator's audited act,
        and this loop has no administrator behind it.
        """
        self._reconcile_unkeyed_reported &= still_unkeyed
        refused = self._reconcile_unkeyed_refused
        for user_id in [uid for uid in refused if uid not in still_unkeyed]:
            del refused[user_id]
        # An account the store has not refused goes first (-1), so one row it keeps refusing cannot
        # starve the rest. Refused accounts follow, the longest-refused first, so two rows the store
        # keeps refusing take turns. sorted() is stable, so the rest keep list_users' order.
        turn = {uid: i for i, uid in enumerate(refused)}
        pending = sorted(
            (u for u in unkeyed if u.id not in self._reconcile_unkeyed_reported),
            key=lambda u: turn.get(u.id, -1),
        )
        for user in pending:
            _log.warning(
                "directory reconcile: %s carries a federated binding but no directory object id, "
                "so it is not probed by name and a directory disable will not end its sessions "
                "before they expire. Unbind it (DELETE /users/%s/federated-identity) so the "
                "reconciler ends its sessions; it cannot sign in again until it is removed and "
                "re-created with a directory id.",
                user.username,
                user.id,
            )
            written = await self._audit_reconciler_row(
                "auth.ad_reconcile_binding_unkeyed",
                detail=_json(
                    {
                        "reason": DIRECTORY_OBJECT_ID_MISSING,
                        "user_id": user.id,
                        "username": user.username,
                    }
                ),
            )
            # Marked only once the audit row is written, so a failed write is retried next pass.
            if not written:
                # Stop at the first refusal: one ERROR and one WARNING per pass, and no second
                # acquire timeout behind a store that is refusing every write.
                refused.pop(user.id, None)  # re-inserted at the end: refused most recently
                refused[user.id] = None
                break
            refused.pop(user.id, None)
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
        audit write still leaves the operator-visible condition set. That failure is logged and not
        raised (BACKLOG #2137; see :meth:`_audit_reconciler_row`).
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
        await self._audit_reconciler_row(
            "auth.ad_reconcile_held",
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
            # Counted over the probes ASKED (BACKLOG #2434): an UNKEYED row never reached the
            # directory, so it is no part of what failed.
            _log.warning(
                "directory reconcile: ALL %d probes failed — the directory is unreachable. No "
                "session was revoked (fail-open).",
                plan.asked,
            )
            await self._audit_reconciler_row(
                "auth.ad_reconcile_skipped",
                detail=_json({"reason": plan.aborted, "asked": plan.asked}),
            )
            return
        # Held probes were left out of the breaker's denominator (ADR 0195 rule item 7), so the
        # ceiling it quotes is taken over the same count. `probed` keeps its meaning in the row. A
        # pass of referrals only never reaches here: it is not a trip (BACKLOG #2538).
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
        # Latched above, before the write, as the hold's message is: a failed write is logged and
        # not raised, so the breaker's alert still fires and its status still shows (BACKLOG #2137).
        await self._audit_reconciler_row(
            "auth.ad_reconcile_aborted",
            detail=_json(
                {
                    "reason": plan.aborted,
                    "probed": plan.probed,
                    "judged": plan.judged,
                    "ceiling": ceiling,
                }
            ),
        )

    async def _record_reconcile_referral(
        self, plan: reconcile.ReconcilePlan, *, first: reconcile.Probe | None
    ) -> None:
        """Latch, log and audit a pass in which the directory referred probes.

        BACKLOG #2538. Called on every pass that judged something, and on a pass of referrals
        only; an outage pass does not call it. On one with a referral,
        whatever else the pass did, it latches the message, logs it at ERROR with the first
        referral's search and hosts, and writes an ``auth.ad_reconcile_referred`` row. Its own audit
        action, because a pass with a referral beside other answers is not an aborted one, and an
        ``auth.ad_reconcile_aborted`` row is read as "nothing was revoked". The row's ``aborted``
        field says what else the pass did. On a pass with no referral it does nothing:
        ``_mark_reconcile_clears`` releases the latched message on the referral clear's test.

        **Its own latch and its own alert instance**, apart from the breaker's: the lifespan task
        raises it as ``ad_reconcile_aborted`` under its own source label. A shared instance would
        let an operator who acknowledges or suspends a standing referral also silence a later
        breaker trip, and would let one detail hide the other. An ``[alerts]`` rule keyed on the
        event type alone still matches both; only a rule naming the exact source keeps them apart.

        The message is the alert's detail, so it names the settings to change FIRST: the store
        keeps only the first 200 characters of an alert instance's reason. It carries counts and
        no username. It is latched before the row is written, so a failed write leaves it set.
        """
        if not plan.referred:
            # The latch is released in `_mark_reconcile_clears`, on the referral clear's own test.
            return
        others = (
            "The pass revoked nothing."
            if plan.aborted is not None
            else "Accounts that answered without a referral were judged as usual."
        )
        if plan.unavailable:
            # A pass of referrals and failures is recorded here and not as an outage, so the
            # failures are counted here, or a near-total outage would read as a search-base fault.
            others = (
                f"{plan.unavailable} could not be read (the directory was unreachable, or the "
                f"probe raised). {others}"
            )
        self._reconcile_referral_alert = (
            "LDAP referral: check [auth].ad_user_search_base and, for nested groups, "
            "[auth].ad_group_search_base; one names a base in another domain of the forest. "
            f"{len(plan.referred)} of {plan.probed} signed-in directory account(s) probed were "
            f"referred and left unjudged. {others} A referred account is never revoked while it "
            "is referred, because the engine does not follow referrals. Use a base in the bound "
            "domain controller's own domain, or a global catalog. The ERROR log line for each such "
            "pass names the first referred search and its hosts."
        )
        # The username and the refusal's text go to the log only: the refusal names the search
        # and the referred hosts and nothing else (BACKLOG #2530). One line per pass, not one per
        # referred account, because a referring base refers every account on every pass.
        _log.error(
            "directory reconcile: %s First referral: %s: %s",
            self._reconcile_referral_alert,
            first.username if first is not None else "?",
            first.detail if first is not None else "?",
        )
        await self._audit_reconciler_row(
            "auth.ad_reconcile_referred",
            detail=_json(
                {
                    "reason": reconcile.REFERRAL_ABORT,
                    "referred": len(plan.referred),
                    "unavailable": plan.unavailable,
                    "probed": plan.probed,
                    "aborted": plan.aborted,
                }
            ),
        )

    async def _audit_reconciler_row(self, action: str, *, detail: str) -> bool:
        """Write one of the reconcile pass's own rows, and say whether it was written.

        BACKLOG #2137. These rows are the held row, the breaker's aborted row, the outage's skipped
        row, the referral's row (BACKLOG #2538) and the unkeyed-binding report. Each is written
        after the pass's revocations, or on a pass that applies none. **A failed write here does
        not end the pass.** If it raised, the pass would return no plan, and the lifespan task
        would raise no alert for the revocations already applied, nor for the hold, the breaker or
        the referral. So a store refusal is logged at ERROR, naming the action, and the pass goes
        on. The log line is then the only record of that row. A per-revocation audit write is not routed through here: that one
        still raises.

        A defect is raised, not passed over (:data:`_AUDIT_WRITE_DEFECTS`).
        """
        try:
            await self._audit(action, actor="<reconciler>", detail=detail)
        except _AUDIT_WRITE_DEFECTS:
            raise
        except _audit_write_errors():
            _log.exception(
                "directory reconcile: the %s audit row could not be written; the pass goes on, "
                "so its alerts still fire",
                action,
            )
            return False
        return True

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
        #
        # ACCOUNT_DISABLED only when the pass READ the disabled bit (vault BACKLOG #2140). That
        # notice says an administrator disabled the account, which an absent account or an unreadable
        # attribute does not establish, so every other whole-account reason, including any added
        # later, gets the neutral DIRECTORY_SESSIONS_ENDED.
        if revocation.role_ids is not None:
            kind = ROLES_CHANGED
        elif revocation.reason == reconcile.REVOKE_REASONS[reconcile.ProbeOutcome.DISABLED]:
            kind = ACCOUNT_DISABLED
        else:
            kind = DIRECTORY_SESSIONS_ENDED
        if user is not None and revocation.reason != reconcile.SCOPE_CHANGED:
            await self._notify_security(
                kind,
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
        idp_auth_time: float | None,
        max_expires_at: float | None = None,
        require_federated_subject: tuple[str | None, str | None] | None = None,
        supersedes_hash: str | None = None,
    ) -> str:
        """Mint a session token and persist the row. Callers passing
        ``require_federated_subject`` must handle :class:`_BindingChangedMidLogin`.

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
            # BACKLOG #2143: REQUIRED here, with no default, like the mechanism. The IdP step-up
            # compares the next auth_time with it, and a NULL on an oidc session refuses that
            # step-up. _complete_ad_login defaults it to None for its Kerberos callers, and raises
            # ValueError when a federated mint arrives without one.
            idp_auth_time=idp_auth_time,
        )
        if not issued:
            # Only reachable with a guard requested: an unbind or a bind revoked this account's
            # sessions while this login was in flight, so issuing now would hand back a token the
            # revocation could never have seen. Nothing was written, so there is nothing to undo.
            raise _BindingChangedMidLogin()
        if mfa_verified:
            # No second factor pending (MFA is not required for this user, or the federated IdP
            # asserted one): mark the session's 2nd factor satisfied at issuance so the step-up gate
            # never blocks it. An MFA-required login leaves it NULL until POST /auth/mfa-verify
            # (WP-14) -- including the Kerberos leg, which asserts nothing and mints at the minimum.
            await self._store.mark_session_mfa_verified(token_hash)
        if supersedes_hash is not None:
            await self._supersede_session_hash(supersedes_hash, client=client)
        await self._enforce_session_cap(user_id, client=client)
        return token

    async def _enforce_session_cap(self, user_id: str, *, client: str | None = None) -> None:
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

        That caller can still push the real user's own pending sign-in out of the pending group,
        and that stands (BACKLOG #2283). Until the factor is proven the two sign-ins are the same
        to the engine, so no rank can favour one. The user loses a half-finished sign-in and signs
        in again, while the caller holding the password gains no access from it.

        The price is a bound of twice the cap. If the user later stops owing a factor (MFA turned
        off, the last factor removed, a role change under the administrators scope), the pending
        rows count as full ones until the next cap run, which then keeps the newest ``cap``.

        **A run that revoked anything is audited (BACKLOG #2283):** one ``auth.session_revoked`` row
        with scope ``cap`` and the count, under the owner's name and with the address of the
        sign-in or ceremony that ran the cap, as the supersession row is. So it lands in that
        user's own security-event feed. A count, not hashes, as the other
        multi-session revocations record it. The count includes lapsed rows the cap ended, which
        the validator already refused; the store returns one count for both.
        """
        cap = self._settings.max_sessions_per_user
        if not cap or cap <= 0:
            return
        user = await self._store.get_user(user_id)
        # A user row that has gone owes nothing more; splitting is then the closed choice, since it
        # can only protect full sessions.
        split = True if user is None else await self._unverified_session_owes_factor(user)
        revoked = await self._store.enforce_session_cap(
            user_id,
            keep=cap,
            idle_seconds=self.session_idle_seconds,
            split_mfa_pending=split,
        )
        if revoked > 0:
            await self._audit(
                "auth.session_revoked",
                actor=user.username if user is not None else None,
                detail=_json({"scope": "cap", "count": revoked, "cap": cap}),
                client=client,
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
        * ``_new_ip_seen`` — the WP-L3-13 dedupe. Only the audit row and notice depend on it, never
          the step-up. A re-verification drops the entry before it rotates (BACKLOG #2159), so a
          strand costs something on a rotation WITHOUT one, such as a passkey assertion or an
          enrolment confirm: every address already reported would be audited and notified again.
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
        carries those columns forward, and every session stamp UPDATE is rowcount-blind (which
        session writes report what they changed is :meth:`AuthStore.rotate_session`'s docstring to
        say) — a stamp issued *after* the rotation silently writes nothing. Any purpose-bound grant must be minted AFTER, against the NEW hash.
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
        start leg and never the token (BACKLOG #296). The ordering rule is :meth:`_elevated`'s.

        A session whose temporary credential lapsed during the ceremony is ended rather than re-keyed
        (BACKLOG #2298). The gate refused it at the deadline, but a ceremony that passed the gate
        just before can run past it, for example while confirming an enrolment hashes its recovery
        codes. Refused here, before the rotation, so a confirming enrolment refused here does not
        turn MFA on. The ask is made before the rotation waits for the account's re-proof lock, so
        a deadline that passes during that wait is not caught."""
        if await self._rotation_lapsed(token_hash, ceremony=ceremony, client=client):
            return Elevation(session_lost=True)
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
            await self._enforce_session_cap_after_elevation(rotated, client=client)
        return Elevation(token=rotated, recovery_codes=recovery_codes)

    async def _enforce_session_cap_after_elevation(
        self, token: str, *, client: str | None = None
    ) -> None:
        """Run the cap for the owner of a session that has ALREADY been rotated.

        A failure here is logged, never raised. The old token is gone by now, and the ceremony has
        committed its own writes (an enabled factor, stored recovery codes, a consumed code), so an
        exception would strand the user with neither token and lose recovery codes they never saw.
        Skipping one cap run costs at most one session over the cap until the next sign-in runs it.

        **The catch is broad on purpose (BACKLOG #2283).** Every call inside is a store read or
        write, and each backend raises its own driver's errors, which ``auth/`` may not import, as
        the first-seen login-address read says. A cancellation is not an ``Exception``, so it still
        propagates.
        """
        try:
            session = await self._store.get_session(hash_token(token))
            if session is not None:
                await self._enforce_session_cap(session.user_id, client=client)
        except Exception:  # noqa: BLE001 -- driver errors vary by backend; see the docstring
            # The run may have revoked sessions before its audit write failed, so the log does not
            # claim the run was skipped (BACKLOG #2283).
            _log.exception(
                "session cap after a completed second factor failed; it may not have run, or its"
                " audit row may be missing"
            )

    async def identity_for_token(
        self, token: str | None, *, activity: bool = True
    ) -> Identity | None:
        """Validate a bearer token (existence, revocation, clock, absolute + idle timeout) and
        resolve the caller's :class:`Identity`.

        ``activity=True`` (the default, for user-driven requests) refreshes the session's idle
        clock; pass ``activity=False`` for background re-checks (e.g. a long-lived WebSocket) so a
        passively-polled token still ages out against real user activity (AUTH-IDLE).

        **A session whose admin-issued temporary credential has passed its deadline is ended here**
        (BACKLOG #2298, ASVS 6.4.1). The sign-in gate stops that credential at the deadline, and a
        session opened a second before it would otherwise keep reaching what a must-change session
        may reach, the second-factor step included. Every gate resolves the caller through this
        method, so this one check refuses it at ``require()``, ``require_ui`` and the console's
        hand-authenticated pages alike. See :meth:`_end_lapsed_session`.
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
        user = await self._store.get_user(session.user_id)
        # A disabled account is refused below for that reason, not audited as a lapse.
        if user is not None and not user.disabled and self._credential_lapsed(user, now):
            # Asked before the touch below, so a session about to end is not first marked used.
            await self._end_lapsed_session(
                session.token_hash, user.username, at="session", client=None
            )
            return None
        if activity:
            await self._store.touch_session(session.token_hash, now=now)
        if user is None or user.disabled:
            return None
        return await self._build_identity(user)

    async def identity_for_cert_user_id(self, user_id: str) -> Identity | None:
        """Resolve the users-row id a verified client cert maps to, or ``None`` when that account is
        unknown, disabled, or a directory account the directory does not confirm — WITHOUT a bearer
        session (BACKLOG #2238, #2316, ADR 0083).

        The mTLS map targets the row id, not the username, because a username can be released by a
        rename and taken by another row: a map keyed by name would then hand the cert to that other
        account. The id never moves. This replaced ``identity_for_username``, which resolved the old
        name-keyed map. A disabled account grants no identity (fail-closed), exactly as the token path
        treats it (:meth:`identity_for_token`); unlike :meth:`identity_for_user_id`, which the
        permission inspector uses and which resolves a disabled account on purpose.

        **A DIRECTORY ACCOUNT IS ASKED ABOUT ON EVERY REQUEST, AND FAILS CLOSED (BACKLOG #2316).**
        The engine row's ``disabled`` flag and roles are not enough for an AD row: the reconciler
        probes only accounts holding a live session, and a certificate caller holds none, so nothing
        ever refreshed them and a directory-side disable or group removal never reached this path.
        So an AD row gets the same probe and the same refusals as directory step-up
        (:meth:`_directory_presence`): anything short of a present, enabled account in the directory
        returns ``None``. That includes an unreachable or referring directory, no directory wired,
        and a row with no ``directory_object_id``. A local row is never probed.

        **Roles NARROW rather than refuse.** The identity carries the stored roles that the
        account's current groups still map to: never more than the row holds, because this path
        writes nothing and must not grant, and never more than the directory now grants. So an
        account removed from one of two mapped groups keeps the other role on its next request,
        where step-up refuses outright. An empty result returns ``None``. The channel scope narrows
        on the same groups, by the rule sign-in uses (:func:`_cert_narrowed_scope`), so a scope an
        administrator set is kept when no scope-mapped group matches. Nothing is written: only a
        sign-in, or a reconciler pass while the account holds a session, re-syncs the row.

        **No cache, and a bounded wait.** A cached answer would bring back the staleness this
        closes. Concurrent probes are capped at :data:`_CERT_PROBE_MAX_CONCURRENCY`; a request that
        cannot get a slot within :data:`_CERT_PROBE_SLOT_WAIT_SECONDS` is refused. Refusals do not
        log one line per request; :meth:`_note_cert_directory_answer` says what they log."""
        user = await self._store.get_user(user_id)
        if user is None or user.disabled:
            return None
        if user.auth_provider != AuthProvider.AD.value:
            return await self._build_identity(user)
        answer = await self._cert_directory_presence(user)
        self._note_cert_directory_answer(answer)
        if not isinstance(answer, reconcile.Probe):
            return None
        # Everything below is read after the probe, as step-up does: the round trip can be seconds,
        # and a local disable, a scope edit or a sign-in's role re-sync may have landed meanwhile.
        # The answer vouches only for the account it asked about, so a row whose immutable id or
        # provider moved during the round trip is refused rather than judged on another's answer.
        asked = user
        user = await self._store.get_user(user_id)
        if (
            user is None
            or user.disabled
            or user.auth_provider != asked.auth_provider
            or user.directory_object_id != asked.directory_object_id
        ):
            return None
        granted = await self._store.roles_for_ad_groups(answer.groups)
        held = await self._store.get_user_role_ids(user.id)
        kept = [role_id for role_id in held if role_id in granted]
        if not kept:
            return None
        # The scope narrows on the same groups, by the rule login and the reconciler share. Its
        # TARGET roles decide the Administrator short-circuit there; here that is the kept set.
        administrator = Role.ADMINISTRATOR.value in kept
        mapped = (
            frozenset()
            if administrator
            else frozenset(await self._store.channels_for_ad_groups(answer.groups))
        )
        return await self._build_identity(
            _cert_narrowed_scope(user, mapped, administrator=administrator), role_ids=kept
        )

    async def _cert_directory_presence(self, user: UserRecord) -> reconcile.Probe | str:
        """:meth:`_directory_presence` under the certificate path's probe cap (BACKLOG #2316), or
        :data:`CERT_PROBE_SATURATED` when no slot frees within the wait bound.

        The slot is held until the probe itself ends, not until this caller stops waiting. The
        probe's worker thread cannot be cancelled, so releasing on a cancelled request would let
        the threads outnumber the cap. The probe therefore runs as its own task, shielded, and
        releases its slot when it finishes."""
        try:
            async with asyncio.timeout(_CERT_PROBE_SLOT_WAIT_SECONDS):
                await self._cert_probe_slots.acquire()
        except TimeoutError:
            return CERT_PROBE_SATURATED
        try:
            task = asyncio.create_task(self._cert_probe(user))
        except BaseException:
            self._cert_probe_slots.release()
            raise
        self._cert_probe_tasks.add(task)
        task.add_done_callback(self._cert_probe_done)
        return await asyncio.shield(task)

    async def _cert_probe(self, user: UserRecord) -> reconcile.Probe | str:
        # This task's own context, so the DEBUG level never reaches the reconciler or step-up. A
        # fault on one account's entry would otherwise log a WARNING naming it on every request;
        # the outage line below reports it once instead.
        token = _PROBE_FAULT_LOG_LEVEL.set(logging.DEBUG)
        try:
            return await self._directory_presence(user)
        except Exception:
            # Returned, never raised: a raise from a probe whose caller was cancelled would reach
            # the loop's exception handler through the shield, one ERROR per orphaned request.
            # Read as an outage, which fails closed and logs by the outage rules. The traceback can
            # quote a directory value, so it goes to DEBUG and names no account.
            _log.debug("certificate-path directory probe raised", exc_info=True)
            return reconcile.ProbeOutcome.UNAVAILABLE.value
        finally:
            _PROBE_FAULT_LOG_LEVEL.reset(token)

    def _cert_probe_done(self, task: asyncio.Task[reconcile.Probe | str]) -> None:
        self._cert_probe_slots.release()
        self._cert_probe_tasks.discard(task)
        if not task.cancelled():
            # Only a BaseException that is not an Exception can end here; _cert_probe returns
            # everything else. Retrieved so it is not also reported as never retrieved.
            task.exception()

    def _note_cert_directory_answer(self, answer: reconcile.Probe | str) -> None:
        """Log the certificate path's directory refusals without logging one line per request.

        An outage is a refusal that says the directory could not be asked: unreachable, referring,
        a fault reading the entry, or the probe cap full. It logs one WARNING per outage and, if that
        WARNING was logged, one INFO on the next answer the directory actually gave, whatever it
        said about the account. WARNINGs are at least :data:`_CERT_OUTAGE_LOG_INTERVAL_SECONDS`
        apart, so an outage that flaps (a full cap turning over, or one referring account beside a
        healthy one) still logs about once a minute. An outage that starts inside that interval
        logs its WARNING on its first refusal after the interval ends, so a long one is never
        silent. A logged outage whose reason changes logs the change at INFO, at most once per
        interval, and the closing INFO names the latest reason.

        A configuration refusal (no directory wired, a row with no immutable id) asks nothing and
        moves neither way. It logs one WARNING per reason per process instead.

        The lines name no account. Every service request during an outage is refused the same way,
        and the username is not the useful fact."""
        outcome = answer.outcome.value if isinstance(answer, reconcile.Probe) else answer
        if outcome in _CERT_DIRECTORY_OUTAGES:
            now = time.monotonic()
            latched = self._cert_directory_outage
            self._cert_directory_outage = outcome
            if latched is not None and self._cert_outage_announced:
                if outcome != latched:
                    self._note_cert_outage_kind_change(latched, outcome, now)
                return
            last = self._cert_outage_warned_at
            if last is not None and now - last < _CERT_OUTAGE_LOG_INTERVAL_SECONDS:
                if latched is None:
                    _log.debug("certificate-path directory check returned %s again", outcome)
                return
            self._cert_outage_announced = True
            self._cert_outage_warned_at = now
            self._cert_outage_kind_noted_at = None
            _log.warning(
                "mTLS certificate identities for directory accounts are refused: the directory "
                "check returned %s. Logged once until a check reaches the directory again",
                outcome,
            )
        elif outcome in _CERT_DIRECTORY_ANSWERS:
            if self._cert_directory_outage is None:
                return
            if self._cert_outage_announced:
                _log.info(
                    "mTLS certificate identities for directory accounts: the directory check "
                    "reaches the directory again (it last returned %s)",
                    self._cert_directory_outage,
                )
            self._cert_directory_outage = None
            self._cert_outage_announced = False
        elif outcome not in self._cert_config_refusals_logged:
            self._cert_config_refusals_logged.add(outcome)
            _log.warning(
                "an mTLS certificate identity for a directory account was refused: %s. Logged "
                "once per process for this reason",
                outcome,
            )

    def _note_cert_outage_kind_change(self, before: str, after: str, now: float) -> None:
        """Log that a logged certificate-path outage changed its reason, at INFO at most once per
        :data:`_CERT_OUTAGE_LOG_INTERVAL_SECONDS` and otherwise at DEBUG. A full cap and an
        unreachable directory can alternate request by request, and must not log a line each."""
        last = self._cert_outage_kind_noted_at
        if last is not None and now - last < _CERT_OUTAGE_LOG_INTERVAL_SECONDS:
            _log.debug("certificate-path directory check now returns %s (was %s)", after, before)
            return
        self._cert_outage_kind_noted_at = now
        _log.info(
            "mTLS certificate identities for directory accounts are still refused: the directory "
            "check now returns %s (it had returned %s)",
            after,
            before,
        )

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
        not record the ending of something that had already ended.

        **The read and the revoke are one atomic store operation (BACKLOG #2146).** Why that closes
        the race with a concurrent rotation is :meth:`AuthStore.supersede_session`'s to say. It holds
        across engine processes too, because engine shards serve the API from one shared store.

        **A rotation that committed BEFORE that operation is a stated limit, not a race this
        closes.** The presented hash then names no session, so this ends nothing, and the session
        lives on under its new token. docs/SECURITY.md (ASVS 7.2.4, the supersession paragraphs)
        states how wide that window is.
        Returns True when it audited.
        """
        before = time.time()
        prior = await self._store.supersede_session(prior_hash, now=before)
        if prior is None:
            return False
        after = time.time()
        # The validator's own test, clock-step checks included (BACKLOG #2096): a row stamped ahead
        # of the clock is one the validator would refuse, so ending it is not the end of a live
        # session. The revoke landed somewhere between `before` and `after`, so the row is judged at
        # the latest moment it can show to have been used, clamped to that span. A touch that
        # committed inside the call is then not mistaken for a clock step, a stamp past `after`
        # still is one, and a session already over at `before` is not judged live by waiting.
        moment = min(max(before, prior.last_used_at), after)
        if not prior.is_live(now=moment, idle_seconds=self.session_idle_seconds):
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

    async def _build_identity(
        self, user: UserRecord, *, role_ids: Iterable[str] | None = None
    ) -> Identity:
        """The account's :class:`Identity`. ``role_ids`` replaces the stored role ids when given, so
        a caller that narrowed them (:meth:`identity_for_cert_user_id`) gets the same built-in,
        custom-role and channel treatment as every other path."""
        if role_ids is None:
            role_ids = await self._store.get_user_role_ids(user.id)
        role_ids = list(role_ids)
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
        and again after a good one, and ends the session (BACKLOG #2298); see
        :meth:`_temporary_credential_lapsed`."""
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
        if await self._temporary_credential_lapsed(
            identity, token=token, client=client, password_checked=False
        ):
            return CurrentPasswordCheck.EXPIRED
        proof = await self._reproof(identity, password, directory=False, token=token, clear=False)
        if proof.ok:
            # Asked again after the verify: a request that passed the first check can wait in the
            # per-account re-proof queue, and the deadline can pass while it waits.
            if await self._temporary_credential_lapsed(
                identity, token=token, client=client, password_checked=True
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
        self, identity: Identity, *, token: str, client: str | None, password_checked: bool
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
        window is the lock wait, and the credential cannot sign in after the deadline either way.
        ``password_checked`` records which ask refused. At sign-in this audit action always means
        the right password was presented; here it may not, so the row says which.

        A refusal also ends the caller's session (``token``), as :meth:`identity_for_token` ends one
        presented after the deadline (BACKLOG #2298). So a retry is refused at the gate and writes
        no second row."""
        if not identity.must_change_password:
            return False
        user = await self._store.get_user(identity.user_id)
        if user is None or not self._credential_lapsed(user, time.time()):
            return False
        await self._end_lapsed_session(
            hash_token(token),
            identity.username,
            at="password_change",
            client=client,
            proof="password",
            proof_checked=password_checked,
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
        reason: str | None = None
        if directory:
            if not user.directory_object_id:
                # BACKLOG #2027, ADR 0184 AC-5. The re-bind finds its entry by the row's id, and a
                # row with none has only its name, which a directory may have reissued to someone
                # else whose password would then step this session up. Refused before the directory
                # is asked, so no password leaves the engine and nothing is charged -- the caller
                # did not guess wrong.
                verdict, reason = None, DIRECTORY_OBJECT_ID_MISSING
            else:
                rebind = await self._reauth_ad(
                    user.username, password, object_id=user.directory_object_id
                )
                verdict, reason = rebind.verdict, rebind.reason
        else:
            verdict = user.password_hash is not None and await self._argon2(
                verify_password, user.password_hash, password
            )
        if verdict is None:
            # Only the directory leg answers None: it could not judge the password at all. An empty
            # password is the caller's malformed submission, not a directory that could not confirm
            # the account, so it reads as a refused password (BACKLOG #2434). Neither is charged.
            return _Reproof(
                ok=False, user=user, reason=reason, directory_unconfirmed=reason != EMPTY_PASSWORD
            )
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
        elevation = Elevation(
            session_lost=proof.session_revoked or proof.session_gone,
            directory_unconfirmed=proof.directory_unconfirmed,
        )
        grant_refused = False
        if ok:
            # (1) Every stamp for this elevation, against the OLD hash. The rotation carries these
            # columns forward; a stamp issued after it would silently write nothing.
            # Re-anchor the session to the address it re-verified from, so a forced step-up triggered
            # by a roamed/new client IP (WP-L3-13) clears once the caller re-proves from there.
            await self._store.mark_session_reauthed(hash_token(token), client=client)
            self._restart_new_ip_dedupe(hash_token(token))
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
            if elevation.ok:
                # vault BACKLOG #2145: a step-up on an account that owes no factor is how a
                # first-seen address passes its challenge, so it becomes known.
                await self._mark_login_address_known(identity.user_id, client, step_up=True)
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
                    # A refusal that judged no credential names itself (BACKLOG #2027). Only when
                    # set, so every other row keeps its shape.
                    **({"reason": proof.reason} if proof.reason is not None else {}),
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
        or its user cannot be found. An account with no factor has nothing to prove here; whether
        it may rotate is :meth:`change_password`'s call, which refuses a covered local account
        until it has TOTP (ADR 0197 Amendment A). A directory account is left to the route's 400,
        which changes nothing. PUBLIC for the reason :meth:`factor_binding_is_blocked` gives: the JSON gate and
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
        _bounded_grant_put(
            self._action_step_up_grants,
            (token_hash, action),
            now + self._settings.step_up_max_age_seconds,
            now,
        )

    def _prune_action_step_up_grants(self, now: float) -> None:
        """Drop expired per-action grants (monotonic clock — a wall-clock step can't widen the window)."""
        _prune_grants(self._action_step_up_grants, now)

    async def has_action_step_up(self, token: str | None, action: str) -> bool:
        """Whether the caller holds a fresh step-up grant BOUND to ``action`` — and **consume** it
        (single-use). ADR 0077. A grant is minted only by a step-up: ``reauth(purpose=action)`` (POST
        /me/reauth or /ui/reauth), or :meth:`complete_oidc_step_up` for an OIDC session's IdP leg. Never
        by login or ``verify_mfa``, so a login-seeded step-up window cannot bind a
        new authenticator. Returns False for a missing token / no grant / an expired grant.

        SIDE EFFECT, for :meth:`refund_action_step_up`: every call overwrites the request's
        :data:`_SPENT_REFUNDABLE_GRANT` record, with this spend when ``action`` is refundable and
        with nothing otherwise. So a second call in the same request, for any action, ends the
        first spend's refund; a path that wants the refund must reach it with no call between."""
        _SPENT_REFUNDABLE_GRANT.set(None)
        if not token:
            return False
        now = time.monotonic()
        self._prune_action_step_up_grants(now)
        # pop = single-use: the grant is gone whether or not it was still live (a stale pop is harmless).
        key = (hash_token(token), action)
        deadline = self._action_step_up_grants.pop(key, None)
        if deadline is None or deadline <= now:
            return False
        if action in _REFUNDABLE_ACTIONS:
            _SPENT_REFUNDABLE_GRANT.set((id(self), key, deadline))
        return True

    async def holds_action_step_up(self, token: str | None, action: str) -> bool:
        """Whether the caller holds a live grant bound to ``action``, WITHOUT spending it.

        For a web console page that opens an action rather than performing it (vault BACKLOG
        #2625): the message editor asks for the proof before the operator types an edit, because a
        re-auth demanded at submit time re-opens the editor and drops the edit. Only
        :meth:`has_action_step_up` spends a grant, so this never authorizes the action itself, and
        it leaves the refund record alone."""
        if not token:
            return False
        deadline = self._action_step_up_grants.get((hash_token(token), action))
        return deadline is not None and deadline > time.monotonic()

    def refund_action_step_up(self, action: str) -> bool:
        """Give back the step-up grant THIS REQUEST spent on ``action``, when the route it opened
        then failed BEFORE any side effect (ADR 0197 Amendment A, Manager decision 2026-09-29).

        The action-bound gate runs as a route dependency, so it spends the single-use grant before
        the handler can learn that no credential can be issued. Without a refund, a request that
        changed nothing would still cost the administrator their proof. What the refund buys is a
        retry IN THE SAME PROCESS -- the case of a borderline list that fails at random. Fixing
        ``[auth].password_extra_context_words`` needs a restart, which forgets every grant anyway.

        It restores only the grant this request's gate spent (:data:`_SPENT_REFUNDABLE_GRANT`), and
        only with its ORIGINAL deadline, so it can never mint a grant, never extend one, and never
        restore one that has expired. A second refund finds nothing. Only
        :data:`_REFUNDABLE_ACTIONS` are ever recorded, so no other action's grant can be restored.
        A live grant the session minted since (a fresh re-authentication) is left as it is rather than
        overwritten. Returns whether a grant was restored."""
        spent = _SPENT_REFUNDABLE_GRANT.get()
        if spent is None or spent[0] != id(self) or spent[1][1] != action:
            return False  # nothing spent here, by another instance, or for another action: kept
        _SPENT_REFUNDABLE_GRANT.set(None)
        _, key, deadline = spent
        now = time.monotonic()
        if deadline <= now or key in self._action_step_up_grants:
            return False
        _bounded_grant_put(self._action_step_up_grants, key, deadline, now)
        return True

    async def _reauth_ad(self, username: str, password: str, *, object_id: str) -> _DirectoryRebind:
        """Re-verify an AD credential via a live directory re-bind (no session adopted).

        Three verdicts, because only one of the two refusals is a guess (BACKLOG #1138): ``True`` =
        bound; ``False`` = the directory REJECTED the password, which :meth:`_reproof` counts toward
        the engine lockout; ``None`` = it could not be asked (no directory, an :class:`LdapError`),
        it has no enabled entry for the row, or the password was empty. Every refusal fails closed;
        only ``False`` is counted.

        **AN EMPTY PASSWORD IS REFUSED FIRST, AND IS NOT A GUESS (BACKLOG #2434).** The directory
        never judges one, since an empty simple bind is an anonymous bind. Counting it would charge
        the account for a malformed submission. It is refused before any directory call as
        ``empty_password``, which :meth:`_reproof_serialized` refuses like a wrong password but
        does not charge.

        **``authenticate`` says what its lookup found (BACKLOG #2434).** Its :class:`DirectoryBind`
        tells a refused bind on an enabled entry (``False``, counted) from an absent entry
        or an ambiguous one (``not_in_directory``, vault BACKLOG #2778), a disabled one
        (``directory_disabled``) and an unreadable account state (``directory_undetermined``),
        none of them counted. Counting those would lock the
        engine row of a user whose every re-bind fails whatever they type, and the lock is then
        enforced at their Kerberos and OIDC sign-in. Before #2434 a second lookup after every
        refusal told absent from present, and could not tell absent from disabled. A correct
        password the DC refuses as expired still counts, which nothing here can tell apart.

        **THE BIND IS KEYED BY THE ROW'S OWN OBJECT, NOT BY ITS NAME (BACKLOG #2027).** ``username``
        is a label a directory may free and reissue, so ``object_id``, the row's stored
        ``objectGUID``, picks both the entry the password is bound as and the entry the refusal arm
        asks about. The typed password therefore never reaches whoever the directory has since given
        the name to, a wrong guess is judged against this account and counted as before, and a
        renamed account still steps up. **This costs no extra directory read:** each call is the
        same one round trip it was, keyed on the id instead of the name.

        The entry's own id is read separately from the search that found it. ``LdapAuthenticator``
        answers an id-keyed entry that does not read back the id it was found by as no match, and
        never binds the typed password as it (BACKLOG #2027). Such an entry is therefore
        ``not_in_directory`` here and is not counted.
        Each answer is still checked against ``object_id``, for any other directory implementation:
        an answer carrying no readable id is ``None`` with reason ``directory_object_id_missing``,
        and one about another object is ``None`` with ``directory_identity_conflict``. Neither is
        counted. A refused bind on an entry the id-keyed lookup found is counted, because that bind
        was judged against this account. ``object_id`` is required, so no caller can re-bind a row
        that has none; :meth:`_reproof_serialized` refuses that row first."""
        if not password:
            return _DirectoryRebind(None, EMPTY_PASSWORD)
        if self._ldap is None:
            return _DirectoryRebind(None, "not_configured")
        try:
            bind = await asyncio.to_thread(
                self._ldap.authenticate, username, password, object_id=object_id
            )
        except LdapError:
            return _DirectoryRebind(None, "directory_unavailable")
        if bind.principal is not None:
            mismatch = _directory_answer_mismatch(bind.principal, object_id)
            return _DirectoryRebind(None, mismatch) if mismatch else _DirectoryRebind(True)
        if bind.answer is DirectoryAnswer.FOUND:
            # Found by the row's own id, so the bind that failed was judged against this account:
            # it counts. That includes a DC too busy to answer the bind, which nothing here can
            # tell from a wrong password.
            return _DirectoryRebind(False)
        # No bind was judged, so nothing is counted.
        return _DirectoryRebind(None, _REBIND_REFUSALS[bind.answer])

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
        """Whether two client addresses denote the same host, by :func:`_host_key`. At least these
        match: an exact match, both loopback (this keeps the loopback default a genuine no-op
        rather than a string mismatch), and one the IPv4-mapped IPv6 form of the other. Both
        address signals compare by :func:`_host_key`, so they agree on when two addresses are one
        host (BACKLOG #2159). They share no baseline, so they can disagree about which address is
        new; docs/SECURITY.md, item 6 of the administrative-interface defense-in-depth list, says
        when and why (vault BACKLOG #2145)."""
        return _host_key(a) == _host_key(b)

    def _first_new_ip_flag(self, token_hash: str, address_key: str) -> _NewIpFlag:
        """Record a new address for a session, and say whether this request should audit it.

        Best-effort, per-process dedup of the audit/notify side effects only; the step-up decision
        never depends on it. An address audits the first time it shows up since the session last
        re-anchored, because every re-anchor drops the session's entry (:meth:`_restart_new_ip_dedupe`,
        BACKLOG #2159). The first address past ``_NEW_IP_PER_SESSION_MAX`` audits once more, as the
        row that says the cap is reached; after that the session audits nothing until it re-anchors.

        Bounded so session churn cannot grow it without limit: past ``_NEW_IP_DEDUP_MAX`` sessions
        the oldest entry goes, which only risks re-auditing that session's addresses once more."""
        flagged = self._new_ip_seen.get(token_hash)
        if flagged is None:
            if len(self._new_ip_seen) >= _NEW_IP_DEDUP_MAX:
                self._new_ip_seen.pop(next(iter(self._new_ip_seen)))
            flagged = self._new_ip_seen[token_hash] = set()
        if address_key in flagged:
            return "repeat"
        if len(flagged) > _NEW_IP_PER_SESSION_MAX:
            return "over_cap"
        flagged.add(address_key)
        return "audit" if len(flagged) <= _NEW_IP_PER_SESSION_MAX else "audit_cap_reached"

    def _restart_new_ip_dedupe(self, token_hash: str) -> None:
        """Start the new-address dedupe over for a session that just re-anchored, so an address
        reported before the re-anchor is reported again (BACKLOG #2159).

        Every leg that calls ``mark_session_reauthed`` calls this straight after it, before it
        rotates the token; tests/test_admin_new_ip.py pins the pairing. Keying the reset on the
        re-anchor rather than on ``reauth_at`` keeps it free of the wall clock, which can step
        back."""
        self._new_ip_seen.pop(token_hash, None)

    async def _classify_login_address(self, user: UserRecord, client: str | None) -> _LoginAddress:
        """The first-seen login-address signal's verdict for one sign-in (BACKLOG #288, ASVS 8.2.4).

        Call it BEFORE the mint and before :meth:`_mark_login_address_known` can run for this sign-in,
        or the login could find itself.

        **THE BASELINE IS THE ACCOUNT'S KNOWN-ADDRESS RECORD** (vault BACKLOG #2145): the host keys
        that :meth:`_mark_login_address_known` writes, which says when, read through the record's
        primary key on the account id. It replaced a baseline read from ``audit_log``, which has no
        actor index and could not tell a finished sign-in from one that stopped at the password on
        the directory leg. Keyed on the
        account id, so a re-created namesake inherits nothing, and the account's deletion removes it.

        Only rows seen within ``_LOGIN_ADDRESS_LOOKBACK_SECONDS`` count. Addresses compare by
        :func:`_host_key`, so ``127.0.0.1`` and ``::1`` are one host, and so are ``10.0.0.1`` and
        ``::ffff:10.0.0.1``.

        With no match, the verdict is NEW unless the account has no baseline at all: no
        ``last_login_at`` and no row of any age. Both are needed. A first sign-in finished through
        factor enrolment writes a row but never stamps ``last_login_at``, so an account that did that
        and then sat idle past the lookback still has a baseline, and its next sign-in is judged
        rather than failed open. That case costs the one extra read, outside the lookback.

        A failed read fails open as ``UNEVALUATED_READ_FAILED``. The exception classes differ per
        store backend (sqlite3, asyncpg, pyodbc), none of which ``auth/`` may import, so the catch
        is broad; it is logged, and the caller audits the verdict."""
        if not client:
            return _LoginAddress.UNEVALUATED_UNKNOWN_ADDRESS
        since = time.time() - _LOGIN_ADDRESS_LOOKBACK_SECONDS
        try:
            known = await self._store.list_known_login_addresses(user.id, since=since)
            if _host_key(client) in known:
                return _LoginAddress.KNOWN
            if (
                not known
                and user.last_login_at is None
                and not await self._store.list_known_login_addresses(user.id, since=0.0)
            ):
                return _LoginAddress.UNEVALUATED_NO_BASELINE
        except Exception:
            # Worded for both callers: a sign-in goes on unchallenged, and an enrolment
            # (``_mark_login_address_known``) records nothing.
            _log.exception(
                "first-seen login-address read failed for %s; the address is left unevaluated: "
                "it is not challenged, and only a proved factor will record it",
                user.username,
            )
            return _LoginAddress.UNEVALUATED_READ_FAILED
        return _LoginAddress.NEW

    async def _mark_login_address_known(
        self,
        user_id: str,
        client: str | None,
        *,
        step_up: bool = False,
        enrolment: UserRecord | None = None,
    ) -> None:
        """Add ``client`` to the account's known-address record, the baseline
        :meth:`_classify_login_address` reads (vault BACKLOG #2145).

        **CALL IT ONLY WHERE A SIGN-IN HAS FINISHED EVERY FACTOR IT OWES, AND PASSED THE FIRST-SEEN
        CHALLENGE IF IT HAD ONE.** Writing any earlier lets a holder of the first factor alone plant
        an address as known. So it is called at:

        * a local sign-in that owes no factor, when its address was KNOWN or there was no baseline
          yet, or when it was a combined sign-in that proved a TOTP code in the same request. A NEW
          address is not written there: that sign-in's challenge is the step-up it has not done yet;
        * a directory sign-in that owes nothing more, NEW included, because no directory session is
          seeded whatever the verdict, so there is no challenge to bypass. Not after a failed read.
          Under the shipped ``require_mfa`` every Kerberos session owes a factor, and so does an
          OIDC one minted while ``oidc_require_mfa_claim`` is off. Such a sign-in writes nothing
          here, and the factor leg below writes for it;
        * a second factor proved at the MFA gate (``verify_mfa``, ``finish_webauthn_assertion``),
          once the session has rotated, whether it finishes a sign-in or a step-up. Only
          ``verify_mfa`` also moves the session's anchor (see :meth:`_same_host`);
        * a factor enrolment confirmed, first or later (``confirm_mfa_enrollment``,
          ``finish_webauthn_registration``); a first one is how a first sign-in under
          ``require_mfa`` finishes. Those callers pass the account as ``enrolment``, and an address
          that classifies NEW is not written: ADR 0197 Amendment A lets a holder of the password
          alone enrol an authenticator they control, so the enrolment proves nothing about the
          address. That only delays such a holder: a code from their own authenticator at the MFA
          gate then records it, and the enrolment's own notice is the alarm for that case;
        * a step-up re-proof (``reauth``, ``complete_oidc_step_up``), once the session has rotated,
          with ``step_up`` set. It writes only for an account that owes no second factor. That is
          how a first-seen address on a no-factor sign-in passes its challenge. An account that owes
          a factor passes it at the factor legs instead, so a password-only step-up from a roamed
          session cannot plant its address. "Owes" is asked of the ACCOUNT, as an unverified
          session of it would be, never of this session's own stamp. So under ``require_mfa`` no
          directory step-up writes, even an IdP step-up that re-proved the MFA claim. A later sign-in
          from that host records it once that sign-in finishes, at the cost of one more notice.

        Best-effort and never refusing: a failed read or write is logged, and the sign-in it records
        has already succeeded. A lost write costs a challenge and notice at the next sign-in from
        that address, and on the local no-factor leg at every one until a step-up records it. A host
        key longer than ``_LOGIN_ADDRESS_KEY_MAX`` UTF-16 code units is not written. Each write is
        followed by a prune of the account's rows older than the lookback, the record's only
        retention, in its own call, so a failed prune never reads as a lost write.

        The catches are broad for the reason :meth:`_classify_login_address` states, except that a
        programming error (``AttributeError``, ``TypeError``) is re-raised rather than logged."""
        if not client:
            return
        try:
            key = _host_key(client)
            if len(key.encode("utf-16-le")) // 2 > _LOGIN_ADDRESS_KEY_MAX:
                return
            if step_up:
                user = await self._store.get_user(user_id)
                if user is None or await self._unverified_session_owes_factor(user):
                    return
            if enrolment is not None and (
                await self._classify_login_address(enrolment, client)
                not in _LOGIN_VERDICTS_THAT_SEED_THE_BASELINE
            ):
                return
            now = time.time()
            await self._store.remember_login_address(user_id, key, now=now)
        except (AttributeError, TypeError):
            raise
        except Exception:
            _log.exception(
                "could not record a known sign-in address; the ceremony it records stands"
            )
            return
        try:
            await self._store.forget_login_addresses(
                user_id, before=now - _LOGIN_ADDRESS_LOOKBACK_SECONDS
            )
        except (AttributeError, TypeError):
            raise
        except Exception:
            _log.warning(
                "could not prune old known sign-in addresses; the address itself was recorded",
                exc_info=True,
            )

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
        key = (user_id, _host_key(client) if client else "")
        last = self._login_new_ip_noticed.get(key)
        if last is not None and now - last < _LOGIN_NEW_IP_NOTICE_SECONDS:
            return False
        self._login_new_ip_noticed.pop(key, None)
        if len(self._login_new_ip_noticed) >= _NEW_IP_DEDUP_MAX:
            self._login_new_ip_noticed.pop(next(iter(self._login_new_ip_noticed)))
        self._login_new_ip_noticed[key] = now
        return True

    async def _record_login_address(
        self,
        verdict: _LoginAddress,
        user: UserRecord,
        *,
        client: str | None,
        provider: str,
        mechanism: SessionMechanism | None,
    ) -> None:
        """Write what :meth:`_classify_login_address` decided, after the session is minted.

        Called after the mint so a login that then fails (a withdrawn federated binding) leaves no
        row claiming a sign-in happened, and before the ``auth.login_success`` row so that row stays
        the newest one for the login. ``KNOWN`` writes nothing. ``NEW`` audits
        ``auth.login_new_ip`` and sends the ``login_new_ip`` notice, debounced by
        :meth:`_login_new_ip_notice_due`. The fail-open verdicts audit ``auth.login_address_unevaluated`` with the reason and notify
        nobody. This never refuses a login: the challenge is the session minted without step-up
        freshness, which the caller arranges.

        ``mechanism`` is required so that a directory caller cannot drop it by omission. The
        directory leg passes its session mechanism, because ``provider`` is ``ad`` for Kerberos and
        OIDC alike; it lands in every row and in the notice's event detail as ``mech``, the key and
        spellings the directory leg's other audit rows already use (vault BACKLOG #2156). The local
        leg passes None, so its rows keep exactly ``{provider}``."""
        if verdict is _LoginAddress.KNOWN:
            return
        detail: dict[str, object] = {"provider": provider}
        if mechanism is not None:
            detail["mech"] = mechanism.value
        if verdict is _LoginAddress.NEW:
            await self._audit(
                "auth.login_new_ip",
                actor=user.username,
                detail=_json(detail),
                client=client,
            )
            if self._login_new_ip_notice_due(user.id, client):
                await self._notify_security(
                    LOGIN_NEW_IP,
                    username=user.username,
                    email=user.notify_email,
                    client=client,
                    detail=dict(detail),
                )
            return
        await self._audit(
            "auth.login_address_unevaluated",
            actor=user.username,
            detail=_json({**detail, "reason": verdict.value}),
            client=client,
        )

    async def flag_new_client_ip(
        self, token: str | None, client_ip: str | None, *, path: str
    ) -> bool:
        """Admin-interface contextual-risk signal (ASVS 8.4.2, WP-L3-13): return ``True`` when this
        sensitive request arrives from a client address that differs from the one the caller's session
        last verified from. On the **first** observation of a given (session, address) since the
        session's last re-verification it emits an ``auth.admin_action_new_ip`` audit event + a
        best-effort out-of-band notice; **repeat** hits from an address already flagged in that
        epoch still return ``True`` (so the step-up stays forced) but only log to the rotating ops
        log — so a token replayed in a tight loop, from one address or alternating between several,
        cannot inflate the audit table / notification channel (mirrors the ``_rate_limited``
        precedent). One epoch audits at most ``_NEW_IP_PER_SESSION_MAX`` addresses, plus one row
        carrying ``cap_reached`` for the first address past that, because this runs on every
        sensitive request (BACKLOG #2159). The step-up
        dependencies treat ``True`` as "force a fresh step-up"; a successful re-verify (``POST
        /me/reauth`` **or** ``/auth/mfa-verify``) re-anchors the session to the new address (see
        :meth:`reauth` / :meth:`verify_mfa`), so the signal clears and the caller proceeds. An
        ``oidc`` session, which :meth:`reauth` refuses, can re-anchor through the IdP step-up
        (:meth:`complete_oidc_step_up`). It is
        **step-up-forcing only** — it never changes an RBAC allow or deny, and a ``True`` is cleared
        by a re-verification from the new address. Its callers include at least the step-up gates
        and, since vault BACKLOG #2620, the PHI reads (``require_phi_read``, the HTTP ``reveal``
        reads, the console's ``phi=True`` arm) and the paced writes (``require_paced``, the
        console's write gate), which refuse on ``True``. Not every caller refuses: the console's
        reauth-only action gate records the signal on a request it is refusing for another reason.
        The base gate never calls it, so the monitoring polls are not refused.

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
        if not session.client or not client_ip:
            return False
        if self._same_host(client_ip, session.client):
            return False
        seen_key = _host_key(client_ip)
        # New address → force a step-up (return True unconditionally). Emit the audit + notice once per
        # (session, address) between re-verifications, and for at most _NEW_IP_PER_SESSION_MAX
        # addresses, so a replayed token cannot amplify the audit log / notifications even when it
        # alternates between addresses (BACKLOG #2159).
        flag = self._first_new_ip_flag(token_hash, seen_key)
        if flag == "repeat":
            _log.warning(
                "admin action from a new client IP already flagged since the session's last "
                "re-verification (audit suppressed): path=%s",
                path,
            )
            return True
        if flag == "over_cap":
            # Past the cap no row is written, so this line is the only record of where the token
            # is being used from. The address is attacker-supplied text on a proxied hop.
            _log.warning(
                "admin action from a new client IP past the per-session cap of %d (audit "
                "suppressed): path=%s seen_ip=%s",
                _NEW_IP_PER_SESSION_MAX,
                path,
                scrub_log_argument(client_ip),
            )
            return True
        detail: dict[str, object] = {
            "path": path,
            "known_ip": session.client,
            "seen_ip": client_ip,
        }
        if flag == "audit_cap_reached":
            # The last row before the session re-verifies, so it says why the next new address
            # will write none.
            detail["cap_reached"] = _NEW_IP_PER_SESSION_MAX
        written = False
        try:
            user = await self._store.get_user(session.user_id)
            username = user.username if user is not None else session.user_id
            await self._audit("auth.admin_action_new_ip", actor=username, detail=_json(detail))
            written = True
        finally:
            if not written:
                # No row, so the address must not count as reported: the next request from it
                # tries again (BACKLOG #2159). A ``finally`` rather than a catch, so nothing is
                # swallowed and a cancellation is covered too.
                flagged = self._new_ip_seen.get(token_hash)
                if flagged is not None:
                    flagged.discard(seen_key)
        notice: dict[str, object] = {"known_ip": session.client}
        if flag == "audit_cap_reached":
            notice["cap_reached"] = _NEW_IP_PER_SESSION_MAX
        await self._notify_security(
            ADMIN_NEW_IP,
            username=username,
            email=user.notify_email if user is not None else None,
            client=client_ip,
            detail=notice,
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

        **Raises :class:`FactorEnrolmentRequired` while ``[security].require_mfa`` covers the account
        and it holds no factor with a way past the sign-in lock** (ADR 0197 Amendment A, N-B2 part 4).
        The rotation ends every session, the holder's own included, so without this a holder who does
        everything right passes through "a password they chose, no factor, no session", and anyone
        who knows the username can lock them out at that moment. The refusal is HERE and not only in
        the route gate, because the web console's password form calls the JSON handler in-process,
        past its ``Depends`` gate. And the write carries the condition itself (``require_totp``), so
        an ``admin_reset_mfa`` that clears TOTP between this read and the write makes the write match
        no row, and the change is refused rather than landing on an account with no way past.
        """
        violations = self._policy.violations(new_password, username=identity.username)
        if violations:
            return violations
        user = await self._store.get_user(identity.user_id)
        covered = user is not None and self._covered_by_requirement(user, identity.roles)
        if covered and user is not None and not self._has_way_past(user):
            raise FactorEnrolmentRequired()
        written = await self._store.set_password(
            identity.user_id,
            password_hash=await self._argon2(hash_password, new_password),
            must_change_password=must_change,
            password_generated=False,
            require_totp=covered,
        )
        if not written and covered:
            raise FactorEnrolmentRequired()
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

    def _covered_by_requirement(self, user: UserRecord, roles: frozenset[Role]) -> bool:
        """Whether ``user`` is a LOCAL account that ``[security].require_mfa`` covers, enrolled or not
        (ADR 0197 Amendment A). The gates of N-B2 part 4 key on this and on
        :meth:`_has_way_past`, never on ``must_change_password``: a site that ran with the requirement
        off and then turned it on holds accounts with a chosen password, no factor and no must-change
        flag, and the gates must reach those too."""
        return _requirement_covers(self._settings, user, roles)

    @staticmethod
    def _has_way_past(user: UserRecord) -> bool:
        """Whether ``user`` holds a factor with a way past the SIGN-IN lock (ADR 0197 Amendment A).

        WAVE 1: TOTP ONLY, because only TOTP has a combined sign-in (option E). A passkey counts as a
        second factor everywhere else, but the engine cannot use it to get past the lock, and a
        passkey registered without a discoverable-credential request may never get a way past at all
        (the amendment's fact 11). Wave 2 adds a passkey recorded as discoverable."""
        return user.totp_enabled

    async def must_enrol_before_rotating(self, identity: Identity) -> bool:
        """Whether a password change by ``identity`` would be refused with
        :class:`FactorEnrolmentRequired` right now. The route and the console ask it FIRST, so they
        send the holder to enrolment before asking for a password the service would then refuse.
        The service still refuses on its own; this is a courtesy, not the control."""
        user = await self._store.get_user(identity.user_id)
        return (
            user is not None
            and self._covered_by_requirement(user, identity.roles)
            and not self._has_way_past(user)
        )

    async def lockable_account_census(self) -> LockableAccountCensus:
        """:func:`lockable_account_census` over this service's store and settings."""
        return await lockable_account_census(self._store, self._settings)

    def probe_credential_generation(self) -> bool:
        """Run the temporary-credential generator once, at startup, under the configured policy and a
        synthetic username (ADR 0197 Amendment A, Manager decision 2026-09-29, prompted by PR 1761).

        Account creation, the password reset and the factor reset all issue a generated credential.
        Since BACKLOG #1132 the generator screens the site's own context words, and a pathological
        ``[auth].password_extra_context_words`` list can make it fail every time. Those paths refuse
        harmlessly (they generate before any write, and the route refunds the spent step-up grant),
        but an operator should learn of it at start, not at the first account creation. So this logs
        an ERROR and returns ``False``; it never raises and never refuses the start. The credential
        is discarded. A borderline list can still pass this one run and fail a later one."""
        problem = credential_generation_problem(self._policy)
        if problem is not None:
            _log.error("startup probe: %s", problem)
        return problem is None

    async def administrators_needing_an_outside_service(self) -> tuple[str, ...]:
        """The enabled Administrators, by username, when NONE of them can sign in without an outside
        identity service; empty otherwise (vault BACKLOG #2711, step 2).

        An Administrator counts as self-sufficient when it is a local account holding a password the
        login gate would still accept: not a must-change credential past its
        :meth:`initial_credential_deadline`. A directory account needs the directory (a federated
        binding is only ever on one), and a local row with no password hash, or an expired
        temporary one, cannot sign in at all. ``provision-admin`` refuses while any enabled
        Administrator exists, whichever kind, so such a site has no host command to get back in
        while the outside service is down. Empty too when there is no enabled Administrator at all:
        the first-run notices of ADR 0183 cover that case."""
        now = time.time()
        admins: list[str] = []
        for user in await self._store.list_users():
            if user.disabled:
                continue
            if Role.ADMINISTRATOR.value not in await self._store.get_user_role_ids(user.id):
                continue
            if user.auth_provider == AuthProvider.LOCAL.value and user.password_hash is not None:
                deadline = self.initial_credential_deadline(user.password_changed_at)
                expired = user.must_change_password and deadline is not None and now > deadline
                if not expired:
                    return ()
            admins.append(user.username)
        return tuple(sorted(admins))

    async def report_administrators_needing_an_outside_service(self) -> tuple[str, ...]:
        """Run :meth:`administrators_needing_an_outside_service` at startup: WARN and write one audit
        row when it names anyone, and do nothing more. Usernames only. Never refuses the start: a
        directory-only site is a choice, and the notice exists so it is an informed one."""
        names = await self.administrators_needing_an_outside_service()
        if not names:
            return names
        _log.warning(
            "no enabled Administrator can sign in without an outside identity service (the "
            "directory or a federated identity provider); each is a directory account or a local "
            "one with no usable password: %s. If that service is down, no Administrator can sign "
            "in to manage this engine, and `messagefoundry provision-admin` will not create a local "
            "Administrator while these accounts exist. Create a local Administrator now, before "
            "an outage (docs/SECURITY.md, 'Keep a local Administrator').",
            ", ".join(names),
        )
        await self._audit(
            "auth.no_local_administrator",
            actor="system",
            detail=_json({"administrators": list(names)}),
        )
        return names

    async def report_lockable_account_census(self) -> LockableAccountCensus:
        """Run :meth:`lockable_account_census` at startup: WARN and write one audit row when it
        names anyone, and do nothing more (AC-A9). Usernames only, never a secret.

        It also runs :meth:`report_administrators_needing_an_outside_service`, the start notice of
        vault BACKLOG #2711, because this is the one account census the lifespan already calls at
        start. That notice is guarded on its own, so its failure cannot cost this census."""
        try:
            await self.report_administrators_needing_an_outside_service()
        except Exception:  # noqa: BLE001 -- a start notice must never cost the census or the start
            _log.exception("the local-Administrator notice could not run; startup continues")
        census = await self.lockable_account_census()
        if census.clean:
            return census
        if census.no_way_past:
            _log.warning(
                "ADR 0197: %d local account(s) the MFA requirement covers hold a chosen password and "
                "no authenticator app, so anyone who knows the username can lock them out with no "
                "way past: %s. Ask each holder to enrol an authenticator app, or reset the account's "
                "factors (POST /users/{id}/reset-mfa) to issue a generated credential.",
                len(census.no_way_past),
                ", ".join(census.no_way_past),
            )
        if census.undecryptable_totp:
            _log.warning(
                "ADR 0197: %d account(s) have an enabled TOTP secret this engine cannot decrypt, so "
                "their combined sign-in cannot pass a lock: %s. Check the store key, or reset the "
                "account's factors (POST /users/{id}/reset-mfa).",
                len(census.undecryptable_totp),
                ", ".join(census.undecryptable_totp),
            )
        await self._audit(
            "auth.lockable_account_census",
            actor="system",
            detail=_json(
                {
                    "no_way_past": list(census.no_way_past),
                    "undecryptable_totp": list(census.undecryptable_totp),
                }
            ),
        )
        return census

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
        return _scope_covers(self._settings, roles)

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
        still OFF (BACKLOG #1902), so a lost session never leaves MFA on with codes nobody saw. So
        does a good code whose activation matches no row, because a reset cleared the staged secret
        or a second confirm enabled first (BACKLOG #2224). That confirm ends the session it rotated,
        hands back no codes, and audits ``auth.mfa_enroll_refused``.

        This is one of the two legs that turn an MFA-pending session into an MFA-satisfied one for a
        FIRST enrolment, so it rotates for the same reason ``verify_mfa`` does: without it a pre-MFA
        token captured before the ceremony would be elevated in place on a first deployment.

        **So the login-to-MFA floor covers it too** (BACKLOG #2389): see
        :meth:`_enrolment_too_early`. A confirm that would satisfy a pending session too soon after
        sign-in is refused as a wrong code, before the code is checked, so no TOTP step is spent."""
        arrived_at = time.time()  # the floor's clock, read before any await
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such user")
        secret = await self._store.get_totp_secret(identity.user_id)
        if not secret:
            raise ValueError("no enrollment in progress")
        if await self._enrolment_too_early(
            token, user, arrived_at, event="auth.mfa_failed", client=client
        ):
            return Elevation()
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
        if elevation.token is None:  # not ``ok``, spelled so mypy narrows the token below
            return elevation
        if not await self._store.enable_totp(identity.user_id, recovery_code_hashes=hashes):
            # BACKLOG #2224: the conditional enable matched no row, because an administrator's
            # reset cleared the staged secret inside the rotation window, or a second confirm
            # enabled TOTP first. This confirm turns nothing on and its codes are dropped. The
            # rotated session was stamped MFA-verified against a factor that is gone or not this
            # ceremony's, so it is ended rather than handed back: ``session_lost``, the same
            # fail-closed answer as a session revoked before the rotation.
            #
            # Known cost: ``_elevated`` already ran the session cap for the rotated session, so
            # at the cap that run may have ended the account's oldest full session, and it stays
            # ended. The order is #1902's, rotate first and enable last, and is kept.
            await self._store.revoke_session(hash_token(elevation.token))
            # The reason is the row's state read AFTER the refusal, not the write's own verdict,
            # so a later write can blur it; it is a pointer for an operator, not a proof.
            after = await self._store.get_user(identity.user_id)
            if after is None:
                reason = "account_gone"
            elif after.totp_enabled:
                reason = "already_enabled"
            else:
                reason = "secret_cleared"
            await self._audit(
                "auth.mfa_enroll_refused",
                actor=identity.username,
                detail=_json({"reason": reason, "session_ended": True}),
                client=client,
            )
            return Elevation(session_lost=True)
        await self._audit("auth.mfa_enrolled", actor=identity.username, client=client)
        # ADR 0197 Amendment A: enrolment now comes BEFORE the first rotation, so whoever intercepts
        # an issued credential can enrol their own authenticator without rotating. The notice to a
        # must-change account says so, and says what to do.
        await self._notify_security(
            MFA_ENABLED,
            username=user.username,
            email=user.notify_email,
            client=client,
            detail={"issued_credential": True} if user.must_change_password else None,
        )
        # vault BACKLOG #2145: a first sign-in under require_mfa finishes HERE, so without this it
        # left no baseline and the account's next sign-in failed open again. Not for a NEW
        # address: see _mark_login_address_known. Last, after the audit row and the notice, so a
        # programming error it re-raises cannot drop either.
        await self._mark_login_address_known(identity.user_id, client, enrolment=user)
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
        directory can still hold this queue through a concurrent re-proof, one success at a time.

        **A code that completes an MFA-pending session too soon after sign-in is refused** (BACKLOG
        #2301): see :meth:`_second_factor_too_early`.

        **A session whose temporary credential has lapsed is ended, not elevated** (BACKLOG #2298,
        ASVS 6.4.1). The route's gate already ends it through :meth:`identity_for_token`, but a
        request can pass that gate before the deadline and wait in the account's queue past it.
        So the deadline is asked again inside the queue BEFORE the code, which charges nothing,
        and again after a good code, before the writes that mark the factor, zero the failure
        counters and re-key the session. The rotation leg of the same credential does the same
        (:meth:`verify_current_password`)."""
        arrived = totp.wall_clock()
        arrived_at = time.time()  # the service's clock, for the floor; `arrived` is the TOTP clock
        if not token:
            return Elevation()
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None:
            return Elevation()
        user = await self._store.get_user(session.user_id)
        if user is None or user.disabled or not user.totp_enabled:
            return Elevation()
        if await self._mfa_lapsed(token, user, client=client, factor_checked=False):
            return Elevation(session_lost=True)
        if await self._mfa_lock_refused(user, client=client):
            return Elevation(locked=True)
        if await self._second_factor_too_early(
            session, user, arrived_at, event="auth.mfa_failed", client=client
        ):
            return Elevation()
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
            if await self._mfa_lapsed(token, user, client=client, factor_checked=False):
                return Elevation(session_lost=True)
            if await self._mfa_lock_refused(user, client=client):
                return Elevation(locked=True)
            now = time.time()
            if await self._verify_second_factor(user, code, client=client, arrived=arrived):
                # Asked again after the verify, on the stored row read afresh: a recovery-code walk
                # is argon2 work off the loop, and the deadline can pass during it. This ask guards
                # the writes below; the rotation asks once more. Only a must-change account has a
                # deadline to pass, so no other account pays the read. A row gone meanwhile fails
                # closed.
                if user.must_change_password:
                    fresh = await self._store.get_user(user.id)
                    if fresh is None or await self._mfa_lapsed(
                        token, fresh, client=client, factor_checked=True
                    ):
                        return Elevation(session_lost=True)
                # ORDER-CRITICAL: this whole three-write group lands against the OLD hash, and only
                # then does the session rotate. Moving any of them after the rotation writes NOTHING
                # and reports success — every session stamp UPDATE is rowcount-blind.
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
                self._restart_new_ip_dedupe(hash_token(token))
                await self._store.record_login_success(user.id, now=now)
                await self._audit("auth.mfa_verified", actor=user.username, client=client)
                elevation = await self._elevated(
                    token, ceremony="mfa_verify", actor=user.username, client=client
                )
                if elevation.ok:
                    # vault BACKLOG #2145: the factor is proved from this address. Recorded INSIDE
                    # the account's queue: a local ``login`` classifies under the same queue, so a
                    # sign-in queued behind this one finds the address written rather than reading
                    # NEW and writing a spurious ``auth.login_new_ip`` row and notice. Kerberos, OIDC
                    # and passkey legs take no queue, so on those that race stays open.
                    await self._mark_login_address_known(user.id, client)
                return elevation
            # Wrong code: register the failure through the SAME machinery the password path uses, so
            # the per-account lockout + ACCOUNT_LOCKED notification fire on sustained MFA guessing.
            # On the SECOND-STEP counter: the caller holds a session, so it has proved the first step.
            failure = await self._register_failure(user, now, counter="second_step")
            await self._audit("auth.mfa_failed", actor=user.username, client=client)
            await self._record_lock(
                user, "second_step", failure, client=client, audit_detail=None, factor="first_step"
            )
            return Elevation()

    async def _second_factor_too_early(
        self,
        session: SessionRecord,
        user: UserRecord,
        now: float,
        *,
        event: str,
        client: str | None,
        phase: str | None = None,
    ) -> bool:
        """Whether a second factor arrived too soon after sign-in, auditing the refusal if so.

        The ASVS 2.4.2 floor on the login-then-MFA pair (BACKLOG #2301). It applies only while the
        session's factor is PENDING, measured from the session's mint, which is the sign-in. A
        step-up on a session whose factor is already satisfied is not floored. The caller answers
        with its leg's ordinary failure, so the refusal says nothing about timing, and nothing is
        charged: no lockout count, no TOTP step, no recovery code, no passkey challenge. The floor
        and why it sits where it does: ``[auth].mfa_verify_min_elapsed_seconds``.

        Called by :meth:`verify_mfa` and :meth:`finish_webauthn_assertion`, the legs that prove an
        ENROLLED factor, and through :meth:`_enrolment_too_early` by the two enrolment legs,
        :meth:`confirm_mfa_enrollment` and :meth:`finish_webauthn_registration`, which can also
        satisfy a pending session (BACKLOG #2389). A new leg that can satisfy a pending session
        calls one of the two."""
        floor = self._settings.mfa_verify_min_elapsed_seconds
        if floor <= 0 or session.mfa_verified_at is not None:
            return False
        if now - session.created_at >= floor:
            return False
        # An enrolment leg names its phase, as its own wrong-code row does, so an investigator can
        # tell someone binding a NEW authenticator from someone proving an enrolled one.
        detail = {"reason": TOO_EARLY} if phase is None else {"reason": TOO_EARLY, "phase": phase}
        await self._audit(event, actor=user.username, detail=_json(detail), client=client)
        return True

    async def _enrolment_too_early(
        self,
        token: str,
        user: UserRecord,
        now: float,
        *,
        event: str,
        client: str | None,
    ) -> bool:
        """Whether an enrolment leg would satisfy a PENDING session too soon after sign-in
        (BACKLOG #2389), auditing the refusal if so, with ``phase=enroll``.

        An enrolment stamps the session MFA-verified, so on a session that still owes its factor it
        completes the same login-then-MFA pair :meth:`_second_factor_too_early` floors on the verify
        legs. Unlike a verify leg, an enrolment can also run on a session that carries no stamp yet
        owes NO factor. A Kerberos session always mints unstamped, and with ``[security].require_mfa``
        off it owes nothing while its account has no factor. A local session reaches the same state
        only when its roles or the settings change after it was minted, since a local sign-in that
        owes nothing mints stamped. Such a session already passes every gate that reads
        :meth:`mfa_satisfied`, so a fast enrolment on it gains nothing the floor exists to stop, and
        the floor is skipped, as the floor's own rule skips a stamped session. "Owes a factor" is
        :meth:`_unverified_session_owes_factor`, the one rule the access gate reads.

        The cheap checks run first, so an enrolment that comes after the floor pays one session read,
        and one on a site with the floor at ``0`` pays none. A missing or revoked session is not
        refused here: the leg then fails the way it always did. The caller answers a refusal with
        its ordinary failure and the service charges nothing. Under the default
        ``[auth].require_action_step_up``, the route in front of ``POST /me/mfa/confirm`` has
        already spent its single-use password step-up, exactly as it has for a wrong code, so a
        refusal there costs the person one password re-proof."""
        floor = self._settings.mfa_verify_min_elapsed_seconds
        if floor <= 0:
            return False
        session = await self._store.get_session(hash_token(token))
        if session is None or session.revoked_at is not None or session.mfa_verified_at is not None:
            return False
        if now - session.created_at >= floor:
            return False
        if not await self._unverified_session_owes_factor(user):
            return False
        return await self._second_factor_too_early(
            session, user, now, event=event, client=client, phase="enroll"
        )

    async def _mfa_lapsed(
        self,
        token: str,
        user: UserRecord,
        *,
        client: str | None,
        factor_checked: bool,
        at: str = "mfa_verify",
    ) -> bool:
        """Whether a second-factor leg must end this session because its temporary credential
        lapsed: :meth:`verify_mfa`, or ``at="webauthn_assert"`` for
        :meth:`finish_webauthn_assertion`.

        Ends it and audits the refusal when so (BACKLOG #2298). Checked against the clock NOW, not
        the request's arrival: the point is a deadline that passed while the request waited."""
        if not self._credential_lapsed(user, time.time()):
            return False
        await self._end_lapsed_session(
            hash_token(token),
            user.username,
            at=at,
            client=client,
            proof="factor",
            proof_checked=factor_checked,
        )
        return True

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
        renews its step-up window (BACKLOG #2023) or :meth:`finish_webauthn_assertion` marks its
        factor met (BACKLOG #2239), or ``None`` when it can. Called only for an AD row; a local
        account is never asked.

        Without this, an account disabled in the directory kept renewing its window with a good code
        until the reconciliation pass revoked its sessions. The engine row's ``disabled`` flag is
        only as fresh as that pass.

        **FAILS CLOSED, UNLIKE THE RECONCILER.** The reconciler REVOKES, so it fails open on an
        unreachable directory and wants two strikes for an ambiguous answer. This GRANTS, so any
        answer short of a present, enabled account refuses: absent, disabled, undetermined,
        unavailable and referred (BACKLOG #2538) alike. The directory step-up legs already refuse this way: ``_reauth_ad`` on a
        failed bind, and the federated step-up on ``directory_unavailable``. A refusal revokes
        nothing, so the next attempt asks again. An AD row on an engine with no directory
        configured is refused as ``not_configured``, because nothing can confirm it.

        **A row with no ``directory_object_id`` is refused unasked, whether or not it holds a
        federated binding** (ADR 0184 AC-5, BACKLOG #2027). Its only other key is its name, and a
        directory may reissue a freed name to someone else, whose account would then vouch for this
        row. The Windows SSO sign-in and the password step-up refuse the same row the same way.
        This leg used to ask an id-less row with no binding by its name.

        **A present account that lost a role in the directory is refused too (BACKLOG #2240).** Its
        stored roles must all be among the roles its current groups map to, the same pair the
        reconciler diffs. Otherwise a demoted operator would renew its window, or clear the MFA
        gate, with roles it no longer holds until the reconciler's role pass. Only a lost role
        refuses: an added role leaves the account holding fewer roles than the directory grants, not
        more. Roles are compared by id, not by permission, so a move from one role to another
        refuses even when the new role grants more. This refuses and writes nothing; the reconciler
        or the next sign-in re-syncs the roles. Channel scope is not compared here.
        """
        answer = await self._directory_presence(user)
        if not isinstance(answer, reconcile.Probe):
            return answer
        # The groups came back with the probe, so this costs store reads only. Read after the probe,
        # so a sign-in that re-synced the roles during the round trip is judged on what it wrote.
        held = set(await self._store.get_user_role_ids(user.id))
        if not held <= await self._store.roles_for_ad_groups(answer.groups):
            return DIRECTORY_ROLES_DEMOTED
        return None

    async def _directory_presence(self, user: UserRecord) -> reconcile.Probe | str:
        """Ask the directory whether AD row ``user`` is a present, enabled account. Returns the
        PRESENT probe, which carries the account's current groups, or the refusal reason string.

        The fail-closed half :meth:`_directory_step_up_refusal` and
        :meth:`identity_for_cert_user_id` share. Every answer short of PRESENT is a reason:
        ``not_configured`` with no directory wired, :data:`DIRECTORY_OBJECT_ID_MISSING` for a row
        with no immutable id (asked nothing, see the step-up docstring), and otherwise the probe's
        own outcome value.
        """
        if self._ldap is None:
            return "not_configured"
        if not user.directory_object_id:
            return DIRECTORY_OBJECT_ID_MISSING
        # The reconciler's own probe, so both ask the same question by the same key, off the loop.
        # They differ on an id-less row only: this leg refuses it above, and the reconciler still
        # probes an unbound one by name (BACKLOG #2027).
        probe = await self._probe_principal(user)
        if probe.outcome is not reconcile.ProbeOutcome.PRESENT:
            return str(probe.outcome.value)
        return probe

    async def _verify_second_factor(
        self,
        user: UserRecord,
        code: str,
        *,
        client: str | None = None,
        arrived: float | None = None,
    ) -> bool:
        """True iff ``code`` is the user's current TOTP **or** an unused recovery code (consumed on
        match). TOTP is checked first, and a TOTP success does no argon2 work; a refused TOTP
        replay still pays the recovery-code walk (ADR 0170). Recovery codes are argon2id-hashed and
        single-use. Codes never collide (TOTP is 6 digits; recovery codes are dashed alphanumerics).

        ``client`` is the caller's address, carried onto the recovery-code audit row and notice
        (BACKLOG #1139) so the holder can tell their own use from someone else's."""
        code = code.strip()
        if not code:
            return False
        totp_refused = False
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
                if await self._store.consume_totp_step(user.id, matched_step):
                    return True
                # ASVS 11.2.4 (BACKLOG #1167, ADR 0170 amendment). The step was already consumed:
                # a replay, or a second use inside the same step. Returning here cost no argon2
                # work, while a WRONG code falls through to the recovery-code walk below. Both answer
                # False, so the wall clock was the only thing telling them apart. So fall through
                # to the SAME walk (same store read, same hashes, same slot count) and refuse after
                # it. A success stays fast: it already reveals its outcome.
                totp_refused = True
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
        if matched < 0 or totp_refused:
            # A refused TOTP code never spends a recovery code, even one it somehow matched.
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

        Raises :class:`ValueError` (:data:`TOTP_REMOVAL_REFUSED`) whenever ``[security].require_mfa``
        covers the caller as a local account and TOTP is on, passkeys or not: in wave 1 TOTP is the
        only way past the sign-in lock (ADR 0197 Amendment A, AC-A3a). Otherwise it raises when TOTP
        is the caller's LAST second factor and MFA is still required, the refusal
        :meth:`delete_webauthn_credential` also makes (ADR 0068 decision 5). BACKLOG #1022: these
        were two self-service routes to zero factors behind one step-up gate, and only one of them
        asked. The two no longer refuse on the same condition: passkey removal adds no wave-1 rule.

        This is NOT the admin escape hatch — that is :meth:`admin_reset_mfa`, which clears TOTP and
        every passkey and is deliberately unguarded. Nothing here narrows it.
        """
        user = await self._store.get_user(identity.user_id)
        # ADR 0197 Amendment A, AC-A3a: removing TOTP removes the account's way past the sign-in lock
        # (wave 1: nothing else is one), so a covered account may not remove it, passkeys or not.
        if (
            user is not None
            and user.totp_enabled
            and self._covered_by_requirement(user, identity.roles)
        ):
            raise ValueError(TOTP_REMOVAL_REFUSED)
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

    async def admin_reset_mfa(self, user_id: str, *, actor: str) -> IssuedCredential | None:
        """Admin: clear a user's MFA — TOTP **and** every WebAuthn passkey (lost authenticator + no
        recovery path; ADR 0068 extends this to credentials) — and revoke their sessions so they
        re-enroll. The always-available recovery for a locked-out passkey user. Raises
        :class:`ValueError` for an unknown user.

        **IT COVERS A DIRECTORY ACCOUNT (BACKLOG #1144).** The non-local refusal that stood here was
        true while no directory account could hold an engine factor. Once one can, keeping it would
        make enrollment a one-way door: a directory user who lost the authenticator would have no
        recovery at all, because every route that could help stands behind the factor they lost. This
        is the widest of the refusals the item names, and it is included for that reason.

        **ON A LOCAL ACCOUNT IT ALSO ISSUES A GENERATED CREDENTIAL, AND RETURNS IT ONCE** (ADR 0197
        Amendment A, N-B2 part 5, AC-A4). Without it the lost-authenticator recovery would leave a
        chosen password, no factor and no session, which anyone who knows the username can lock
        before the holder signs in to enrol again. **The credential is written FIRST**, before TOTP
        and the passkeys are cleared, so a crash between the writes leaves a generated credential
        with factors, never a chosen password without them. A directory account has no engine
        password and gets ``None``."""
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        issued: IssuedCredential | None = None
        temp_hash: str | None = None
        if user.auth_provider == AuthProvider.LOCAL.value:
            temp = await self._generate_issued_credential(
                "mfa_reset", username=user.username, actor=actor, user_id=user_id
            )
            temp_hash = await self._argon2(hash_password, temp)
            await self._store.set_password(
                user_id,
                password_hash=temp_hash,
                must_change_password=True,
                password_generated=True,
            )
        await self._store.disable_totp(user_id)
        removed = await self._store.delete_all_webauthn_credentials(user_id)
        if temp_hash is not None:
            # WRITTEN AGAIN, now that the factors are gone. A holder's rotation whose conditional
            # write ran between the first write and ``disable_totp`` matched ``totp_enabled = 1`` and
            # replaced the generated credential with a chosen one; the factor clear then left that
            # chosen password with no factor -- the lockable state. This second, unconditional write
            # restores the generated credential, so the reset always ends where it says it does.
            await self._store.set_password(
                user_id,
                password_hash=temp_hash,
                must_change_password=True,
                password_generated=True,
            )
            stamped = await self._store.get_user(user_id)
            issued = IssuedCredential(
                password=temp,
                expires_at=self.initial_credential_deadline(
                    None if stamped is None else stamped.password_changed_at
                ),
            )
        await self._store.revoke_user_sessions(user_id)
        await self._audit(
            "auth.mfa_reset",
            actor=actor,
            detail=_json(
                {
                    "user_id": user_id,
                    "username": user.username,
                    "webauthn_credentials_removed": removed,
                    "credential_issued": issued is not None,
                }
            ),
        )
        await self._notify_security(
            MFA_DISABLED, username=user.username, email=user.notify_email, detail={"reset": True}
        )
        if issued is not None:
            # The password changed too, so the holder is told as for an administrator's password
            # reset, with the new credential's deadline (BACKLOG #1141).
            await self._notify_security(
                PASSWORD_RESET,
                username=user.username,
                email=user.notify_email,
                detail=(
                    None
                    if issued.expires_at is None or user.disabled
                    else {"expires_at": issued.expires_at}
                ),
            )
        return issued

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
        # ADR 0197 Amendment A, AC-A3: a covered account's FIRST factor must be one with a way past
        # the sign-in lock, and in wave 1 a passkey is not, so registration waits for TOTP.
        if self._covered_by_requirement(user, identity.roles) and not self._has_way_past(user):
            raise FactorEnrolmentRequired()
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
        7.2.4 build that rotated the TOTP legs alone would miss the passkey path entirely.

        **So the login-to-MFA floor covers it too** (BACKLOG #2389): see
        :meth:`_enrolment_too_early`. A registration that would satisfy a pending session too soon
        after sign-in fails as a failed verification, before the challenge is popped, so the
        ceremony stays in flight."""
        arrived_at = time.time()  # the floor's clock, read before any await
        user = await self._store.get_user(identity.user_id)
        if user is None:
            raise ValueError("no such user")
        label = label.strip()
        if not label or len(label) > self._WEBAUTHN_LABEL_MAX:
            raise ValueError("label must be 1-100 characters")
        # No staged ceremony is answered BEFORE the floor, as confirm_mfa_enrollment answers "no
        # enrollment in progress" before it: otherwise the same request would get "verification
        # failed" inside the floor and "ceremony expired" outside it, which tells timing. A peek,
        # so a floor refusal still leaves the ceremony in flight.
        staged = self._webauthn_challenges.peek((hash_token(token), "register"))
        if staged is None or staged.user_id != user.id:
            self._webauthn_challenges.pop((hash_token(token), "register"))
            raise ValueError(self._CEREMONY_EXPIRED)
        if await self._enrolment_too_early(
            token, user, arrived_at, event="auth.webauthn_failed", client=client
        ):
            return Elevation()
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
        if elevation.ok:
            # vault BACKLOG #2145, as in confirm_mfa_enrollment, and last for the same reason.
            await self._mark_login_address_known(identity.user_id, client, enrolment=user)
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
        direction and the divergence does not cover it — see the call site.

        **A directory account must be confirmed by the directory first** (BACKLOG #2239), through
        the same :meth:`_directory_step_up_refusal` :meth:`verify_mfa` asks. A refusal returns
        ``directory_unconfirmed`` and spends neither the challenge nor the sign count."""
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
        # BACKLOG #2301: the login-then-MFA floor, as on verify_mfa. Before the challenge is popped,
        # so a refusal leaves the ceremony in flight rather than spending it.
        if await self._second_factor_too_early(
            session, user, now, event="auth.webauthn_failed", client=client
        ):
            return Elevation()
        if user.auth_provider == AuthProvider.AD.value:
            # BACKLOG #2239: a good assertion below marks the factor met, so a DIRECTORY account
            # must still be in the directory first, as verify_mfa asks (#2023). Without this an
            # account disabled in the directory would clear the MFA gate with its passkey until the
            # reconciler revoked it. Asked before the challenge is popped and before the sign count
            # moves, so a refusal leaves the ceremony in flight and charges nothing; assertion
            # failures feed no lockout here anyway (ADR 0068).
            refusal = await self._directory_step_up_refusal(user)
            if refusal is not None:
                await self._audit(
                    "auth.webauthn_failed",
                    actor=user.username,
                    detail=_json({"reason": DIRECTORY_UNCONFIRMED, "outcome": refusal}),
                    client=client,
                )
                return Elevation(directory_unconfirmed=True)
            # The lookup was a network round trip, so read the session, the account and its lock
            # again, as verify_mfa does. A revocation, a disable or a second-step lock that landed
            # meanwhile must stop this assertion before it marks the factor or clears the counters.
            # A session or account gone meanwhile is ``session_lost``: the token no longer
            # authenticates, so the caller must not report a wrong passkey.
            session = await self._store.get_session(hash_token(token))
            if session is None or session.revoked_at is not None:
                return Elevation(session_lost=True)
            user = await self._store.get_user(session.user_id)
            if user is None or user.disabled:
                return Elevation(session_lost=True)
            now = time.time()
            if user.second_step_locked(now):
                await self._audit(
                    "auth.webauthn_failed",
                    actor=user.username,
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
        # BACKLOG #2298: the passkey leg of /ui/mfa, asked as verify_mfa asks after a good code, so
        # an assertion that straddles the deadline marks nothing and clears no counter.
        if user.must_change_password and await self._mfa_lapsed(
            token, user, client=client, factor_checked=True, at="webauthn_assert"
        ):
            return Elevation(session_lost=True)
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
        elevation = await self._elevated(
            token, ceremony="webauthn_assert", actor=user.username, client=client
        )
        if elevation.ok:
            # vault BACKLOG #2145, as in verify_mfa.
            await self._mark_login_address_known(user.id, client)
        return elevation

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
        # ASVS 11.2.4 (BACKLOG #1167). Every credential is compared, and each compare is constant-time:
        # a `next(... == ...)` search stopped at the matching slot and its `==` stopped at the first
        # differing character. The store delete below still matches the row by SQL equality.
        target: WebAuthnCredential | None = None
        for cred in creds:
            same = constant_time_equal(cred.credential_id_hash, credential_id_hash)
            if same and target is None:
                target = cred  # recorded, NOT returned -- the walk runs to the end
        if target is None:
            return False
        # ADR 0197 Amendment A, AC-A3a asks whether a removal would take the account's last way
        # past the sign-in lock. In wave 1 a passkey is never one (``_has_way_past``), so removing
        # one cannot, and this path adds no refusal: a holder must stay able to revoke a lost or
        # stolen passkey. From wave 2 a discoverable passkey is a way past, and the check belongs
        # here.
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

    async def _generate_issued_credential(
        self,
        op: CredentialIssueOp,
        *,
        username: str,
        actor: str,
        user_id: str | None = None,
        roles: Sequence[str] | None = None,
        client: str | None = None,
    ) -> str:
        """Generate the credential account creation or a reset issues, off the event loop, and audit
        a refusal (BACKLOG #2359).

        The generator is CPU-bound: a site list that makes it refuse costs up to
        ``2 * _RESET_GENERATION_ATTEMPTS`` full policy screens. So it runs through :meth:`_argon2`,
        in a worker thread under the same cap as the hash beside it. Each caller calls this before
        it touches the account, so a refusal here has changed nothing.

        A refusal writes one :data:`CREDENTIAL_ISSUE_REFUSED_ACTION` row, with ``op`` naming the
        operation. It is written here, not in the routes, so the JSON API and the console both get
        it. A refused audit write is logged and does not replace the refusal: the route must still
        answer 503 and give back the step-up grant."""
        try:
            return await self._argon2(
                lambda: generate_policy_password(self._policy, username=username)
            )
        except TemporaryPasswordUnavailable:
            detail: dict[str, object] = {"op": op, "username": username}
            if user_id is not None:
                detail["user_id"] = user_id
            if roles is not None:
                detail["roles"] = list(roles)
            try:
                await self._audit(
                    CREDENTIAL_ISSUE_REFUSED_ACTION,
                    actor=actor,
                    detail=_json(detail),
                    client=client,
                )
            except _audit_write_errors():
                # A store refusal only: a bug in the call above still raises. The refusal below is
                # the answer either way, and the traceback says why the row is missing.
                _log.exception(
                    "could not write the %s audit row for a refused %s by %s",
                    CREDENTIAL_ISSUE_REFUSED_ACTION,
                    op,
                    actor,
                )
            raise

    async def create_local_user(
        self,
        *,
        username: str,
        display_name: str | None,
        email: str | None,
        roles: Sequence[str],
        actor: str,
        client: str | None = None,
    ) -> CreatedLocalAccount:
        """Create a local account with an ENGINE-GENERATED, must-change initial credential, returned
        once (ADR 0197 Amendment A, N-B2 part 1, AC-A2).

        The administrator no longer chooses it. The credential is the 192-bit
        :func:`generate_policy_password` the password reset already issues, written with
        ``password_generated`` set, so wrong passwords arm no sign-in lock until the holder replaces
        it. That is what stops anyone who knows the username locking the account before its first
        sign-in. The returned :class:`CreatedLocalAccount` carries the deadline the login gate will
        refuse on, as :meth:`admin_reset_password` does.

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
        temp = await self._generate_issued_credential(
            "create", username=username, actor=actor, roles=roles, client=client
        )
        # Hashed before the insert so the handler below covers the store call alone.
        password_hash = await self._argon2(hash_password, temp)
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
                password_generated=True,
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
        stamped = await self._store.get_user(user_id)
        return CreatedLocalAccount(
            user_id=user_id,
            credential=IssuedCredential(
                password=temp,
                expires_at=self.initial_credential_deadline(
                    None if stamped is None else stamped.password_changed_at
                ),
            ),
        )

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

        **Disabling the last enabled administrator is refused (vault BACKLOG #2779)**, with
        :class:`LastAdministratorRefused`. The guard is the disable write itself: the store checks
        and writes in one transaction (``remove_unless_last_admin``). That write stays after the
        profile write and before its audit row, so a later failure cannot leave an unaudited
        lock-out. A read up front refuses the ordinary case before anything is written. Only a
        removal racing this one gets past that read; then the profile edit has landed, so it is
        still audited and announced, with ``disable_refused`` on the audit row, and the refusal is
        raised after that.
        """
        before = await self._store.get_user(user_id)  # capture old email/disabled for notifications
        if before is not None:
            # The stored spelling of the id. A store whose id column compares case-insensitively
            # (SQL Server) finds the row from a different spelling, and the early read below
            # compares ids in Python, so it must be given the one the store holds.
            user_id = before.id
        stored_notify = ((before.notify_email if before is not None else None) or "").strip()
        new_notify: str | None = None
        if notify_email is not None and (
            not notify_email.strip() or notify_email.strip() != stored_notify
        ):
            new_notify = _require_single_mailbox(notify_email)
        if disabled and await self.is_last_enabled_admin(user_id):
            raise LastAdministratorRefused("cannot disable the last administrator")
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
        refused = False
        if disabled:
            refused = not await self._store.remove_unless_last_admin(
                user_id, AdminRemoval.DISABLE, admin_role_id=Role.ADMINISTRATOR.value
            )
            if not refused:
                await self._store.revoke_user_sessions(user_id)
        elif disabled is not None:
            await self._store.set_user_disabled(user_id, disabled=False)
        updated: dict[str, Any] = {"user_id": user_id}
        if refused:
            updated["disable_refused"] = True
        await self._audit("user.updated", actor=actor, detail=_json(updated))
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
            if disabled and not refused and not before.disabled:
                await self._notify_security(
                    ACCOUNT_DISABLED, username=before.username, email=notice_to
                )
        if refused:
            raise LastAdministratorRefused("cannot disable the last administrator")

    async def delete_user(self, user_id: str, *, actor: str) -> None:
        """Delete an account. Raises :class:`LastAdministratorRefused`, having written nothing, when
        it is the last enabled administrator; the check and the delete are one store transaction
        (vault BACKLOG #2779)."""
        if not await self._store.remove_unless_last_admin(
            user_id, AdminRemoval.DELETE, admin_role_id=Role.ADMINISTRATOR.value
        ):
            raise LastAdministratorRefused("cannot delete the last administrator")
        await self._audit("user.deleted", actor=actor, detail=_json({"user_id": user_id}))

    async def set_roles(self, user_id: str, roles: Sequence[str], *, actor: str) -> None:
        """Replace an account's roles. Raises :class:`LastAdministratorRefused`, having written
        nothing, when that would take Administrator from the last enabled administrator; the check
        and the write are one store transaction (vault BACKLOG #2779). Self-target is allowed."""
        user = await self._store.get_user(user_id)  # for the notification address
        if not await self._store.remove_unless_last_admin(
            user_id,
            AdminRemoval.SET_ROLES,
            admin_role_id=Role.ADMINISTRATOR.value,
            role_ids=list(roles),
            assigned_by=actor,
        ):
            raise LastAdministratorRefused("cannot remove the last administrator")
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
        temp = await self._generate_issued_credential(
            "password_reset", username=user.username, actor=actor, user_id=user_id
        )
        await self._store.set_password(
            user_id,
            password_hash=await self._argon2(hash_password, temp),
            must_change_password=True,
            password_generated=True,
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

        A :class:`FederatedBindingChanged` refusal changes nothing but is still audited, as
        ``auth.federated_unbind_refused`` naming the actor and the pair it expected (BACKLOG #2331).
        """
        outcome = await self._store.clear_user_federated_subject(
            user_id, expected_issuer=expected_issuer, expected_subject=expected_subject
        )
        if outcome is None:
            raise ValueError("no such user")
        if outcome.changed:
            raise await self._audit_binding_changed(
                "auth.federated_unbind_refused",
                {"user_id": user_id, "username": outcome.username},
                actor=actor,
                expected_issuer=expected_issuer,
                expected_subject=expected_subject,
            )
        # BOTH halves, matching the store's own predicate: either one set means the row had
        # something to clear and the store cleared it, so raising here would report "nothing to
        # remove" about a write that just happened.
        if outcome.issuer is None and outcome.subject is None:
            raise ValueError("the account has no federated binding to remove")
        await self._record_federated_unbind(user_id, outcome, actor=actor)
        return outcome.sessions_revoked

    async def _audit_binding_changed(
        self,
        action: str,
        detail: dict[str, object],
        *,
        actor: str,
        expected_issuer: str | None,
        expected_subject: str | None,
    ) -> FederatedBindingChanged:
        """Audit a :class:`FederatedBindingChanged` refusal, and return the exception to raise
        (BACKLOG #2331).

        Nothing was written, but an attempt to change who may sign in as an account is worth a row
        even when it is refused. The row records what the caller expected, and says nothing about
        why the pair differed: another administrator's change, or a retry of the caller's own call
        that had already landed, look the same here. It does not carry the pair the row holds,
        because one refusal arm finds it changed without reading it.
        """
        await self._audit(
            action,
            actor=actor,
            detail=_json(
                {
                    **detail,
                    "expected_issuer": expected_issuer,
                    "expected_subject": expected_subject,
                    "reason": FEDERATED_BINDING_CHANGED,
                }
            ),
        )
        return FederatedBindingChanged()

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
        holds -- a no-op should not sign anybody out. An account deleted while the bind runs is the
        unknown user too, not a conflict (BACKLOG #2331). Refuses as :class:`FederatedSubjectHeld`
        when a different account holds the pair. A :class:`FederatedBindingChanged` refusal writes
        an ``auth.federated_bind_refused`` row with reason ``federated_binding_changed`` and the pair
        the caller expected (BACKLOG #2331).

        **Refuses as :class:`DirectoryObjectIdMissing` an account with no ``directory_object_id``**,
        and writes an ``auth.federated_bind_refused`` audit row naming the actor (BACKLOG #1143
        slice C). That class's docstring holds the reason, what it makes hold, and the cost.

        **EVERY BIND CLEARS FIRST, THEN BINDS.** The clear is the unbind's own transaction, so the prior
        pair and every live session of the account go together and the audit row names the pair that
        transaction cleared. On an unbound account the clear writes nothing and revokes nothing. On a
        rebind the account is unbound between the two writes, and a federated login in that gap is
        refused rather than admitted. If the bind is then refused because another account took the
        pair in the gap, the account is left unbound, and the error says so.

        **EVERY BIND THEN ENDS THE ACCOUNT'S SESSIONS, A FIRST BIND INCLUDED** (vault BACKLOG #2609).
        A bind adds the federated way in and withdraws Windows SSO, which
        ``_directory_login_refusal`` refuses for a bound row. So a session minted before the bind
        is one the account could no longer get, and it must not outlive the bind. This docstring
        used to say a first bind "adds a way in and withdraws none" and revoked nothing.

        The sweep is the write's own transaction (``Store.set_user_federated_subject``), so there
        is no moment at which the pair is written and the earlier sessions are live. A Windows SSO
        sign-in that read the row unbound either inserts its session before that transaction,
        which ends it, or after, and then its guarded insert in :meth:`_complete_ad_login` finds
        the row bound and is refused. The account's own session never performs the bind: both
        routes refuse a caller binding its own account.

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

        async def audit_changed(username: str) -> FederatedBindingChanged:
            # BACKLOG #2331: each of the three changed-pair refusals below writes this one row.
            return await self._audit_binding_changed(
                "auth.federated_bind_refused",
                {"user_id": user_id, "username": username, "issuer": issuer, "subject": subject},
                actor=actor,
                expected_issuer=expected_issuer,
                expected_subject=expected_subject,
            )

        # A caller whose pair is already stale gets the stale answer, not whichever refusal below
        # this read happens to trip. The locked compare in the clear is still the authority.
        if (user.oidc_issuer, user.oidc_subject) != (expected_issuer, expected_subject):
            raise await audit_changed(user.username)
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
        # so on a first bind it costs one statement. Deciding from the earlier read would let a binding
        # another administrator wrote in between be overwritten with its sessions left live. The
        # clear compares the CALLER's pair, not that read's: the read is this request's, and the
        # decision to replace a binding was made on whatever the caller's page showed (#2026).
        cleared = await self._store.clear_user_federated_subject(
            user_id, expected_issuer=expected_issuer, expected_subject=expected_subject
        )
        if cleared is None:
            raise ValueError("no such user")
        if cleared.changed:
            raise await audit_changed(cleared.username)
        previous_issuer, previous_subject = cleared.issuer, cleared.subject
        revoked = cleared.sessions_revoked
        rebind = previous_issuer is not None or previous_subject is not None
        try:
            # CONDITIONAL ON THE ROW STILL BEING UNBOUND, in the same statement. The clear above and
            # this write are two transactions, so a second bind of this account can land between
            # them; an unconditional write would overwrite it with no audit row and leave the
            # sessions it admitted live.
            swept = await self._store.set_user_federated_subject(
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
        if swept is None:
            # The set also matches no row when the account was deleted after the clear. That is the
            # unknown-user answer, 404 at the route, not a conflict to retry (BACKLOG #2331). The
            # clear's own removal of a previous binding is still recorded first.
            if await self._store.get_user(user_id) is None:
                if rebind:
                    await self._record_federated_unbind(user_id, cleared, actor=actor)
                raise ValueError("no such user")
            if not rebind:
                # Nothing was written: the caller saw the account unbound and another bind landed
                # first. That is the changed-pair refusal, with its code (BACKLOG #2026).
                raise await audit_changed(cleared.username)
            await self._record_federated_unbind(user_id, cleared, actor=actor)
            # This request DID write: its clear removed the pair it expected. So not the
            # changed-pair refusal, whose promise is that nothing changed.
            raise FederatedSubjectHeld(
                "another request bound this account while this one ran; read it and retry"
                "; this request removed its previous binding first"
            )
        # The write swept in its own transaction. On a rebind the clear already swept, so this
        # adds only what was minted in the gap between the clear and the write.
        revoked += swept
        detail: dict[str, object] = {
            "user_id": user_id,
            "username": user.username,
            "issuer": issuer,
            "subject": subject,
            "sessions_revoked": revoked,
        }
        if rebind:
            detail.update(
                {"previous_issuer": previous_issuer, "previous_subject": previous_subject}
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
            detail={"issuer": issuer, "sessions_revoked": revoked},
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
        compare-and-set against the source read here, so a write that changes it before this one
        lands raises the same error instead of being overwritten: at least an AD sign-in, or another
        administrator's save. A caller that leaves
        ``expected_source`` unset on a scope the directory does not own is unaffected. Each of the
        three refusals is audited first (BACKLOG #2271); see
        :data:`CHANNEL_SCOPE_CHANGE_REFUSED_ACTION`.

        "The stored source" in both checks is :func:`_effective_scope_source`, which counts an AD
        account's stored scope with no recorded writer as the directory's (BACKLOG #2252). The
        compare-and-set still expects the raw stored value, which is what the row holds.

        Raises ``ValueError("no such user")`` when the account does not exist."""
        user = await self._store.get_user(user_id)
        if user is None:
            raise ValueError("no such user")
        stored = user.channel_scope_source
        owner = _effective_scope_source(user)
        if expected_source is None and owner == SCOPE_SOURCE_AD:
            await self._audit_channel_scope_refusal(
                user,
                reason="directory_owned",
                expected_source=expected_source,
                read_source=stored,
                actor=actor,
            )
            raise ChannelScopeSourceConflict(
                "the directory owns this channel scope; send expected_source='ad' to confirm "
                "that saving it makes it manual"
            )
        if expected_source is not None and expected_source != owner:
            await self._audit_channel_scope_refusal(
                user,
                reason="expected_source_mismatch",
                expected_source=expected_source,
                read_source=stored,
                actor=actor,
            )
            raise ChannelScopeSourceConflict(
                "expected_source does not match who owns this channel scope; re-read the user and "
                "retry. Where no writer is recorded, a directory account's stored scope needs "
                "'ad'; omit expected_source when no scope is stored or the account is local"
            )
        scope_json = None if channels is None else _json(sorted(set(channels)))
        if not await self._store.set_user_channel_scope_if_source(
            user_id, scope_json, source=SCOPE_SOURCE_MANUAL, expected_source=stored
        ):
            now = await self._store.get_user(user_id)
            if now is None:
                raise ValueError("no such user")
            # The re-read row, so ``owner`` names who holds the scope now, not what this write saw.
            await self._audit_channel_scope_refusal(
                now,
                reason="source_changed",
                expected_source=expected_source,
                read_source=stored,
                actor=actor,
            )
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

    async def _audit_channel_scope_refusal(
        self,
        user: UserRecord,
        *,
        reason: ChannelScopeRefusal,
        expected_source: ChannelScopeSource | None,
        read_source: ChannelScopeSource | None,
        actor: str,
    ) -> None:
        """Write the :data:`CHANNEL_SCOPE_CHANGE_REFUSED_ACTION` row for a refused
        :meth:`set_channel_scope` (BACKLOG #2271). A store that refuses the row is logged at ERROR and
        the refusal still stands, so the caller gets its 409 rather than a 500. A defect is raised,
        not passed over (:data:`_AUDIT_WRITE_DEFECTS`)."""
        try:
            await self._audit(
                CHANNEL_SCOPE_CHANGE_REFUSED_ACTION,
                actor=actor,
                detail=_json(
                    {
                        "user_id": user.id,
                        "username": user.username,
                        "reason": reason,
                        "expected_source": expected_source,
                        "read_source": read_source,
                        "owner": _effective_scope_source(user),
                    }
                ),
            )
        except _AUDIT_WRITE_DEFECTS:
            raise
        except _audit_write_errors():
            _log.exception(
                "could not write the %s audit row for a refused save by %s",
                CHANNEL_SCOPE_CHANGE_REFUSED_ACTION,
                actor,
            )

    async def is_last_enabled_admin(self, user_id: str) -> bool:
        """True iff ``user_id`` is an enabled administrator and the only one remaining.

        Nothing regenerates a lost administrator: since ADR 0183 the way back is ``provision-admin``
        at the host.

        **A READ, NOT THE GUARD (vault BACKLOG #2779).** Asked in one await and acted on in the next,
        it let two concurrent removals each see two administrators and both pass. The guard is now
        the store's ``remove_unless_last_admin``, which :meth:`update_user`, :meth:`delete_user` and
        :meth:`set_roles` call. :meth:`update_user` also asks this first, only so the ordinary
        refusal comes before its profile write; never let it stand in for the guarded write.
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
        """Revoke every unrevoked session held by an enabled directory account, lapsed ones
        included. Returns the number revoked, which is the ``sessions_revoked`` the two map audit
        rows record; it counts rows, not live sessions.

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

        Enumerates with ``list_users`` filtered on provider and disabled, then revokes each
        account's unrevoked rows, so this needs no schema change on any backend. The count it
        returns includes rows already past their limits, which the revoke ends too. Unlike the
        reconciler this is NOT counted against the mass-revoke breaker: that breaker exists to catch
        a directory the engine cannot read, and this is an administrator's own step-up-gated edit.
        """
        revoked = 0
        for user in await self._store.list_users():
            if user.auth_provider != AuthProvider.AD.value or user.disabled:
                continue
            # Unconditional (BACKLOG #2283). It used to revoke only when ``list_sessions`` found a
            # row, and that read filters on the wall clock: after a forward clock step past the
            # absolute lifetime it found none, and those rows would come back on the old mapping
            # once the clock was set right. ``revoke_user_sessions`` matches every unrevoked row,
            # whatever the clock says, and costs one statement where the read cost one too.
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
        once, by that row; this adds the event the attempt caused.

        **AN ``ACCOUNT_LOCKED`` NOTICE WITH A NOTIFIER WIRED RUNS OFF THE REQUEST PATH (BACKLOG
        #2216).** Its throttle reads the audit log (:meth:`_lock_notice_due`), and every caller is
        a refusal: the sign-in's deferred rows, which must fit the write room of its padded slot,
        and the second-step and re-proof refusals. So the throttle and the mail run as one task the
        service owns (:meth:`_send_lock_notice`), and this returns once the ``auth.account_locked``
        row is in. The row stays inline, since it is the record the feed reads. With no notifier
        the throttle reads nothing and writes one row, so that arm stays inline too."""
        action = _SUSPICIOUS_LOGIN_ACTIONS[event_type]
        await self._audit(
            action,
            actor=user.username,
            detail=_json(audit_detail) if audit_detail is not None else None,
            client=client,
        )
        if event_type == ACCOUNT_LOCKED:
            lock = str(notice_detail.get("lock", "sign_in"))
            if self._security_notifier is not None:
                send = self._send_lock_notice(user, lock, client=client, detail=dict(notice_detail))
                if self._background_closed:
                    await send  # shutting down: a task would outlive the drain
                else:
                    self._start_background(send)
                return
            if not await self._lock_notice_due(user, lock):
                return
        await self._notify_security(
            event_type,
            username=user.username,
            email=user.notify_email,
            client=client,
            detail=notice_detail,
        )

    async def _send_lock_notice(
        self, user: UserRecord, lock: str, *, client: str | None, detail: dict[str, Any]
    ) -> None:
        """Decide whether an ``ACCOUNT_LOCKED`` notice is due and send it, off the request path.

        BACKLOG #2216. :meth:`_record_suspicious_login` starts this as a background task, or awaits
        it once :meth:`drain_background` has closed the service to new ones.

        **Serialized per account and lock kind** (``_lock_notice_locks``). Off the request path two
        locks of one kind can land together, for example a sign-in lock set by a re-proof while a
        sign-in sets it too. Each would read the throttle before the other wrote its row, and the
        owner would get two mails. Under the lock the second reads the first's row.

        **The mail goes before its ``auth.lock_notice`` row.** A row write that fails or is cut off
        then costs at most a duplicate mail at the next lock, which the throttle already treats as
        the cheap failure.

        **Its failures are logged by exception class only, and its log lines name no account,
        user id or lock kind.** ``GET /logs/tail`` serves the log to ``logs:view``, and a lock
        notice is silent there by design (``LOG_SILENT_EVENT_TYPES``). A store error raised here
        used to fail the request; now nobody would read it, so it is logged instead. A task
        cancelled before it finishes, at shutdown, logs a line saying the notice may be neither
        mailed nor recorded, as :func:`_write_through_cancellation` does for a refused sign-in's
        rows. These lines still show a ``logs:view`` reader WHEN some lock's notice failed, though
        not whose: the residual ``docs/SECURITY.md`` states."""
        try:
            async with _hold_keyed_lock(self._lock_notice_locks, f"{user.id}\x00{lock}"):
                # Read once: ``attach_security_notifier`` can detach the channel while this waits.
                # Without one, _lock_notice_due writes the no-notifier row itself.
                wired = self._security_notifier is not None
                if not await self._lock_notice_due(user, lock):
                    return
                # The mail BEFORE its row, and the row says whether the notifier took it. A
                # cut-off or failed row write, or a refused hand-off, then costs at most a
                # duplicate mail at the next lock, the cheap failure. The other order could leave
                # a row saying a mail went out that never did, holding the next one back a day.
                handed = await self._notify_security(
                    ACCOUNT_LOCKED,
                    username=user.username,
                    email=user.notify_email,
                    client=client,
                    detail=detail,
                )
                if wired:
                    await self._record_lock_notice(user, lock, handed=handed)
        except asyncio.CancelledError:
            _log.warning(
                "a security notice was cancelled before it finished; it may be neither mailed "
                "nor recorded"
            )
            raise
        except Exception as exc:  # noqa: BLE001 - nobody awaits this task; log and stop
            _log.error(
                "a security notice failed off the request path (%s); it may be neither mailed "
                "nor recorded",
                type(exc).__name__,
            )

    async def _lock_notice_due(self, user: UserRecord, lock: str) -> bool:
        """Whether an ``ACCOUNT_LOCKED`` mail for this ``lock`` kind is due.

        With a notifier wired, the caller records a due notice AFTER the mail, through
        :meth:`_record_lock_notice` (BACKLOG #2216). With none, this writes the row itself.

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
        missing one the costly.

        **With a notifier wired this runs in :meth:`_send_lock_notice`'s task, never on a request
        (BACKLOG #2216)**, so the read cannot overrun a refusal's padded slot however large the
        audit log grows. Without one it runs inline and reads nothing."""
        if self._security_notifier is None:
            if self._settings.notify_security_events:
                await self._audit(
                    _LOCK_NOTICE_ACTION,
                    actor=user.username,
                    detail=_json({"lock": lock, "mailed": False, "reason": "no_notifier"}),
                )
            return True
        return not await self._lock_notice_held_back(user, lock)

    async def _lock_notice_held_back(self, user: UserRecord, lock: str) -> bool:
        """The throttle's READ: whether a notice of this ``lock`` kind already went out in the window.

        Kept apart from the row write, so the background task can send the mail between this read
        and :meth:`_record_lock_notice` (BACKLOG #2216). One such read runs at a time per
        service (``_lock_notice_read_slots``). It walks every recent ``auth.lock_notice`` row of
        every account, since the audit log has no actor index. Many locks at once would otherwise
        fill the store's read pool, which sign-ins wait on too.

        A failed read fails OPEN (``False``) and is logged by exception class alone. The line names
        neither the account nor the notice kind (BACKLOG #1131): it runs only when a lock lands,
        and ``GET /logs/tail`` serves the log to ``logs:view``. A traceback would carry the
        driver's message, which can quote the bound username."""
        mailable = bool(user.notify_email)
        since = max(time.time() - _LOCK_NOTICE_WINDOW_SECONDS, user.created_at)
        try:
            async with self._lock_notice_read_slots:
                rows = await self._store.list_audit(
                    actor=user.username, action=_LOCK_NOTICE_ACTION, since=since, limit=50
                )
        except Exception as exc:  # noqa: BLE001 - fails open by design, and is logged
            _log.error(
                "a security-notice throttle read failed (%s); the notice was sent unthrottled",
                type(exc).__name__,
            )
            return False
        for row in rows:
            try:
                detail = json.loads(row["detail"] or "{}")
                kind, mailed = detail.get("lock"), detail.get("mailed", True)
            except (TypeError, ValueError, AttributeError):
                continue
            # A row that mailed nothing holds back only another addressless notice.
            if kind == lock and (mailed is not False or not mailable):
                return True
        return False

    async def _record_lock_notice(self, user: UserRecord, lock: str, *, handed: bool) -> None:
        """Write the ``auth.lock_notice`` row the throttle reads, after the mail.

        ``mailed`` is true only when the account had an address AND the notifier took the event
        (``handed``, BACKLOG #2019). A refused hand-off then writes ``mailed: false``, which holds
        back no later mailable notice, so the next lock mails again rather than staying quiet for
        a day."""
        await self._audit(
            _LOCK_NOTICE_ACTION,
            actor=user.username,
            detail=_json({"lock": lock, "mailed": bool(user.notify_email) and handed}),
        )

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
            # The kind comes from ``notice_kind_log_label`` and the username through
            # ``scrub_log_argument``, on both warnings here, and each one's docstring says why. The
            # username can carry a line break, since an administrator chooses it freely at create.
            _log.warning(
                "security notice %s for %s dropped: no security-event notifier is configured, so "
                "the account was not told out of band (the /me/security-events feed still records "
                "it)",
                notice_kind_log_label(event_type),
                scrub_log_argument(username),
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
        except Exception as exc:  # noqa: BLE001 - best-effort; never propagate into auth
            # Silent for a lock notice, for the reason on the no-notifier arm above.
            #
            # The exception's CLASS only, never its text or traceback. The shipped notifier only
            # enqueues here, but the seam takes any ``SecurityNotifier``, and one that raised with
            # the event in its message would put the address, or an EMAIL_CHANGED ``detail``, in
            # the general log -- the same thing the no-notifier arm refuses to log.
            if event_type not in LOG_SILENT_EVENT_TYPES:
                _log.warning(
                    "security-event notification failed (%s for %s): %s",
                    notice_kind_log_label(event_type),
                    scrub_log_argument(username),
                    type(exc).__name__,
                )
            return False
        return True
