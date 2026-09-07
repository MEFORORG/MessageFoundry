# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DATABASE transport: a SQL destination that runs one parameterized statement per payload.

The **destination** executes the operator-declared ``statement`` (an INSERT/UPDATE or a stored-procedure
call) against an outbound database, binding the payload's fields to the statement's ``:name``
parameters. The transport rides **``aioodbc``** (ADR 0003) — the ``[sqlserver]`` extra
(``pip install 'messagefoundry[sqlserver]'``), **lazily imported** so SQLite-only installs never touch it.

**Two dialects (#66).** ``dialect='sqlserver'`` (default) is the **SQL Server preset** — the Microsoft ODBC
Driver 18, T-SQL-flavoured DSN with the ``Encrypt``/``TrustServerCertificate`` TLS posture and its
weakened-TLS refusal (:func:`_build_dsn`); **production / supported**, exercised by the CI SQL Server
job. ``dialect='generic'`` is a **generic ODBC path** decoupled from Driver-18/T-SQL: the operator names
any OS-installed ODBC driver (PostgreSQL / Oracle / MySQL) + supplies driver-specific keywords via
``odbc_params`` (:func:`_build_odbc_dsn`), so no new Python DB-driver dependency is needed. On the generic
path TLS is the operator's responsibility (configured through the driver's own keyword) — MessageFoundry
cannot introspect an arbitrary driver's TLS posture, so the SQL-Server weakened-TLS refusal does not apply.
Construction logs the delegation as a fail-safe (a WARNING when no TLS keyword is set — see
:func:`_warn_generic_tls_unenforced`) and **gates it**: a generic hop whose ``odbc_params`` say TLS is not
required goes through the shared cleartext-hop authority like every other cleartext transport, so an
enforcing instance refuses it off-loopback rather than crossing in the clear (BACKLOG #1178 — see
:func:`generic_cleartext_hop_guard`). The live aioodbc round-trip is exercised by the CI SQL Server service-container job
(``tests/test_database_connector_integration.py``); the connector logic is also unit-tested with a
faked driver. The SQL Server *store* backend is a **separate** (also production) layer — this
connector does not depend on it.

**Parameters.** The Handler produces a **JSON object** body; the connector binds its keys to the
``:name`` placeholders in ``statement`` (translated to positional ODBC ``?`` — always parameterized,
never string-built, so a value can't inject SQL). A ``:name`` must not appear inside a quoted string
literal in the statement (bind dynamic strings as parameters, which is the correct practice anyway).

**Error mapping.** A *transient* DB failure (connection drop / deadlock / timeout — SQLSTATE class
``08``/``40`` or ``HYTxx``) → :class:`DeliveryError` (the lane retries). A *permanent* failure
(constraint / data / syntax) and a payload that doesn't match the statement → :class:`NegativeAckError`
(``permanent=True``) → dead-letter, since a retry can't fix it.

**Idempotency.** Delivery is at-least-once, so a retry **re-executes** the statement. Use an idempotent
write (``MERGE``/upsert on a natural key, or a de-dup) so a retry doesn't double-apply. See
docs/CONNECTIONS.md.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from collections.abc import Callable, Mapping
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    hop_insecure_escape_downgrades,
    insecure_tls_allowed,
)
from messagefoundry.config.tls_policy import InsecureHopRefused, current_hop_posture
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    register_destination,
    register_source,
)
from messagefoundry.transports.mllp import InsecureHopGuard

__all__ = ["DatabaseDestination", "DatabaseLookupExecutor", "DatabaseSource"]

logger = logging.getLogger(__name__)

# A `:name` parameter, but not `::` (a PostgreSQL-style cast) and not a `:` preceded by a word char
# (so a time literal like '12:30' inside the SQL is left alone). String-literal colons are otherwise
# the operator's responsibility — bind dynamic strings as parameters, not inline literals.
_PARAM_RE = re.compile(r"(?<![:\w]):(\w+)")

# SQLSTATE classes that are worth retrying: 08 = connection exception, 40 = transaction rollback /
# deadlock (40001); plus the ODBC connect/operation timeouts.
_TRANSIENT_PREFIXES = ("08", "40")
_TRANSIENT_STATES = frozenset({"HYT00", "HYT01"})


def _odbc_brace(value: str) -> str:
    """ODBC-quote a value in braces, doubling any internal ``}`` — neutralizes ``; { } =`` inside it so
    an attacker-influenced value (e.g. a password) can't inject extra connection keywords (mirrors the
    store's ``connection_string`` hardening)."""
    return "{" + value.replace("}", "}}") + "}"


def _weakened_tls_permitted(*, attested: bool) -> bool:
    """Whether a weakened (verify-off) customer-DB TLS posture may be used, routed through the ONE
    shared hop authority (#200, ADR 0092).

    A per-connection ``tls_hop_attested`` ALLOWs it (the operator affirms the hop is secure by other
    means — a proxy-terminated / trusted-segment DB link). Otherwise this stays a **STRICT verify-off
    cell** (decision 5): refused for **both staging and prod PHI** unless the global
    ``MEFOR_ALLOW_INSECURE_TLS`` escape applies, and that escape is **CLAMPED to non-production**
    (decision 2 — :func:`hop_insecure_escape_downgrades`) so it can never relax a production hop.

    Keyed on the construction-time posture (:func:`current_hop_posture`, stamped by
    ``build_check_registry`` — the ENFORCED gate at ``messagefoundry check`` / dry-run / serve-start /
    reload). When unstamped (``None`` — a runtime delivery build or a direct embedding outside that
    gate) it falls back to the **unclamped** escape, so a legitimately-escaped non-production instance
    is not refused at delivery time; the enforced gate already vetted the production case against the
    real posture, so this fallback never loosens the clamp."""
    if attested:
        return True
    posture = current_hop_posture()
    if posture is None:
        return insecure_tls_allowed()
    return hop_insecure_escape_downgrades(enforcing=posture.enforcing)


def _audit_attested_weakened_tls(cell: str) -> None:
    """Loud-log a per-connection attestation that suppresses a would-be **production-PHI** weakened-TLS
    refusal (#200 decision 3 — attestation is AUDITED when it crosses a prod-PHI hop). No-op on a
    non-prod / non-PHI / unstamped posture (nothing was suppressed there)."""
    posture = current_hop_posture()
    if posture is not None and posture.is_phi and posture.enforcing:
        logger.warning(
            "%s: weakened TLS permitted by per-connection tls_hop_attested on a production-PHI "
            "instance (operator attests the hop is secure by other means)",
            cell,
        )


def _assert_send_hop(*, weakened: bool, attested: bool) -> None:
    """Zero-I/O byte-crossing re-assertion (#200 decision 4): before a payload crosses a weakened-TLS
    DB hop, re-confirm the posture-keyed authority still permits it. Raises :class:`InsecureHopRefused`
    (a ``ValueError``) otherwise — a fail-closed tripwire behind the construction-time gate. No-op for
    a non-weakened (verifying-TLS) hop."""
    if weakened and not _weakened_tls_permitted(attested=attested):
        raise InsecureHopRefused(
            "DATABASE destination: refusing to put a payload on a weakened-TLS DB hop "
            "(posture-keyed refusal, #200)"
        )


def _build_dsn(s: dict[str, Any], *, read_only: bool = False, attested: bool = False) -> str:
    """Build the ODBC connection string for SQL Server from the connection settings.

    Free-text values are brace-quoted (injection guard) and the ``Encrypt``/``TrustServerCertificate``
    flags are emitted **last** (ODBC is last-wins, so nothing earlier can downgrade TLS). A weakened
    TLS posture is **refused** via the shared posture-keyed authority (:func:`_weakened_tls_permitted`,
    #200) — a STRICT verify-off cell that stays refused for staging AND prod PHI, with the global escape
    clamped so it can never relax a production hop; ``attested`` (the per-connection ``tls_hop_attested``)
    is the surgical, audited per-hop opt-in.

    ``read_only`` (only the db_lookup pool sets it; destination/source omit it, keeping their DSN
    byte-identical) appends ``ApplicationIntent=ReadOnly`` so the connection advertises read-only intent
    — defense-in-depth for the ADR 0010 read-only carve-out, layered with the statement guard in
    :func:`_require_read_only` (note: ApplicationIntent is only honored by a SQL Server Always-On read
    replica, a no-op otherwise — the statement guard is the load-bearing control)."""
    encrypt = bool(s.get("encrypt", True))
    trust = bool(s.get("trust_server_certificate", False))
    if (trust or not encrypt) and not _weakened_tls_permitted(attested=attested):
        raise ValueError(
            "DATABASE connection TLS is weakened (trust_server_certificate=true or encrypt=false), "
            "which is MITM-able. Use a trusted server certificate, set tls_hop_attested=true on this "
            "connection if the hop is secure by other means (a proxy-terminated / trusted segment), or "
            f"set {INSECURE_TLS_ESCAPE_ENV}=1 on a NON-PRODUCTION instance to allow it for a trusted-"
            "network dev/test bind (the escape can no longer relax a production-PHI hop)."
        )
    if (trust or not encrypt) and attested:
        _audit_attested_weakened_tls("DATABASE connection")
    auth = str(s.get("auth", "sql")).lower()
    if auth not in ("sql", "integrated", "entra"):
        raise ValueError(f"DATABASE destination auth must be sql|integrated|entra, got {auth!r}")
    # SERVER must be emitted UNBRACED so the driver parses the ",port" suffix and resolves the host for
    # the TLS handshake — a brace-quoted "SERVER={host},port" is malformed ODBC (content after the
    # closing brace) and breaks certificate handling against a real SQL Server. So the host is
    # *validated* for connection-string metacharacters instead of brace-quoted (the guard used for every
    # other free-text value), exactly like the store backend's connection_string.
    server = str(s["server"])
    if any(ch in server for ch in ";{}=\r\n"):
        raise ValueError(
            "DATABASE server must not contain ';', '{', '}', '=', or newlines (ODBC injection risk)"
        )
    parts = [
        f"DRIVER={_odbc_brace(str(s.get('odbc_driver', 'ODBC Driver 18 for SQL Server')))}",
        f"SERVER={server},{int(s.get('port', 1433))}",
        f"DATABASE={_odbc_brace(str(s['database']))}",
        f"Connection Timeout={int(s.get('connect_timeout', 15))}",
        f"APP={_odbc_brace(str(s.get('app_name', 'messagefoundry')))}",
    ]
    if auth == "sql":
        parts.append(f"UID={_odbc_brace(str(s.get('username') or ''))}")
        parts.append(f"PWD={_odbc_brace(str(s.get('password') or ''))}")
    elif auth == "integrated":
        parts.append("Trusted_Connection=yes")
    else:  # entra
        parts.append("Authentication=ActiveDirectoryDefault")
    if read_only:
        # Advertise read-only intent for the db_lookup pool (ADR 0010). Emitted before the TLS flags so
        # the last-wins Encrypt/TrustServerCertificate posture is unchanged.
        parts.append("ApplicationIntent=ReadOnly")
    parts.append(f"Encrypt={'yes' if encrypt else 'no'}")
    parts.append(f"TrustServerCertificate={'yes' if trust else 'no'}")
    return ";".join(parts) + ";"


# A valid ODBC connection-string keyword: a letter then letters/digits/spaces/underscores. Rejecting the
# metacharacters (`; { } =`) and newlines is the STORE-5 guard for the operator-supplied generic keys
# (the VALUES are additionally brace-quoted), so message-influenced data can't smuggle extra keywords.
_ODBC_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _]*$")

# odbc_params must not re-declare a keyword the connector emits from its own settings (driver/server/
# database/the credential keys) — that would silently duplicate/conflict a keyword.
_ODBC_RESERVED_KEYS = frozenset({"driver", "server", "database"})

# A best-effort hint that the operator configured driver-level TLS via an odbc_params keyword (anything
# ssl/tls/encrypt-ish — psqlODBC `SSLmode`, MySQL `SSLMODE`, some drivers' `Encrypt`). Used ONLY to tune
# the severity of the generic-path construction-time TLS reminder (WARNING vs DEBUG) — never to gate or
# alter the connection. It cannot prove the value *verifies* the cert, only that TLS was addressed.
_ODBC_TLS_HINT_RE = re.compile(r"ssl|tls|encrypt", re.IGNORECASE)

# The VALUES of a TLS-ish keyword that mean TLS is NOT REQUIRED on the hop, so the connection may cross
# in plaintext (#333). Matching the key alone was the whole detector, which read `SSLmode=disable` — the
# explicit *no TLS* spelling — as "the operator has taken TLS ownership" and dropped the reminder to
# DEBUG. A deny-list, not an allow-list, and deliberately so: an arbitrary driver's verifying spellings
# are unbounded (`verify-full`, `VERIFY_IDENTITY`, `yes`, `1`, a numeric level), so demanding a known
# GOOD value would warn on every legitimate driver this path exists to support. The known BAD values are
# few, stable and vendor-documented:
#   psqlODBC `sslmode`  : disable (never) / allow (plaintext first) / prefer (opportunistic, silent fallback)
#   MySQL    `SSLMODE`  : DISABLED / PREFERRED (same two shapes)
#   assorted `Encrypt`  : no / 0 / false / off
#
# KNOWN RESIDUAL, written down rather than implied: an ENCRYPTED-BUT-UNVERIFIED value — psqlODBC
# `require`, MySQL `REQUIRED`, `Encrypt=yes` beside a trust-everything keyword — is NOT on this list and
# stays in the DEBUG branch. It is a real weakening, but a different one: the payload is not in
# plaintext, so the warning's own sentence ("so PHI is not sent in plaintext") would not be true of it,
# and the per-driver spellings for "verified" vs "encrypted only" are not consistent enough to classify
# without guessing. The generic path delegates TLS to the operator by design (ADR 0092); this detector
# exists to make the PLAINTEXT case impossible to miss, not to grade the operator's cipher policy.
_ODBC_NO_TLS_VALUE_RE = re.compile(
    r"^(?:disabled?|allow|prefer(?:red)?|no|off|false|0)$", re.IGNORECASE
)


def generic_odbc_no_tls_params(params: Mapping[str, Any]) -> list[str]:
    """Every ``odbc_params`` TLS keyword that is set to a value meaning "TLS not required", as
    ``["KEY=VALUE", ...]`` (#333). Empty when the operator set no such value.

    The SINGLE classifier for the generic-ODBC cleartext-risk question, shared by this module's
    construction-time reminder (:func:`_warn_generic_tls_unenforced`) and by the posture readers that
    report the hop to an operator (``config.wiring.unverified_generic_db_hops`` ->
    ``security_loosenings`` / ``GET /security/posture`` / ``messagefoundry check``). One definition, so a
    surface can never report a hop as clean that the log warns about, or the reverse.

    Pure — it reads a mapping and touches nothing else."""
    return [
        f"{key}={str(value).strip()}"
        for key, value in params.items()
        if _ODBC_TLS_HINT_RE.search(str(key)) and _ODBC_NO_TLS_VALUE_RE.match(str(value).strip())
    ]


def generic_odbc_tls_unenforced(params: Mapping[str, Any]) -> str | None:
    """Why this generic-ODBC hop may cross in plaintext, or ``None`` when the operator addressed TLS.

    Two ways to be at risk, and they read differently to an operator, so they are reported differently:
    no TLS keyword at all, or a TLS keyword pinned to a no-TLS value (the latter names the offenders).
    Shares :func:`generic_odbc_no_tls_params` with the construction reminder — see that docstring for
    why a value deny-list, and for the encrypted-but-unverified residual this deliberately does not
    classify.

    Since BACKLOG #1178 this predicate also decides whether the hop is GATED, not just reported: a
    non-``None`` reason is what builds :func:`generic_cleartext_hop_guard`. Same single definition, so
    the log line, the operator report and the refusal can never disagree about which hops are at risk —
    but widening it now widens a refusal, which the deny-list's deliberate narrowness should be read
    against."""
    disabling = generic_odbc_no_tls_params(params)
    if disabling:
        return "TLS is explicitly not required: " + ", ".join(sorted(disabling))
    if any(_ODBC_TLS_HINT_RE.search(str(k)) for k in params):
        return None
    return "no TLS keyword is set in odbc_params"


def _odbc_keyword(key: str, *, what: str) -> str:
    """Validate an ODBC keyword token (STORE-5) and return it, or raise a clear ValueError."""
    if not _ODBC_KEY_RE.match(key):
        raise ValueError(
            f"DATABASE {what} {key!r} is not a valid ODBC keyword "
            "(letters, digits, spaces, underscores; must start with a letter)"
        )
    return key


def _build_odbc_dsn(s: dict[str, Any], *, connection: str | None = None) -> str:
    """Build a GENERIC ODBC connection string (``dialect='generic'``, #66) — decoupled from the ODBC
    Driver 18 / T-SQL preset so any ODBC-reachable DB (PostgreSQL / Oracle / MySQL via that DB's own ODBC
    driver) works. The operator installs the target ODBC driver at the OS level and names it here.

    The operator supplies the ODBC ``odbc_driver`` name + an ``odbc_params`` mapping of driver-specific
    keywords (PORT, SSLmode, …). ``server`` (the ``[egress].allowed_db`` allowlist key) is emitted as the
    near-universal ``SERVER`` keyword and ``database`` as ``DATABASE`` when set; credentials come from the
    top-level ``username``/``password`` settings (``env()``-resolved + secret-redacted) under the
    operator-chosen ``odbc_user_key``/``odbc_password_key`` keyword names (default ``UID``/``PWD``). Every
    ``odbc_params`` value is brace-quoted (STORE-5 injection guard) and its key validated to a safe ODBC
    keyword, so message-influenced data can never inject an extra connection keyword.

    **TLS is the operator's responsibility on this path.** MessageFoundry cannot introspect an arbitrary
    driver's TLS posture the way it reads SQL Server's ``Encrypt``/``TrustServerCertificate``, so the
    weakened-TLS refusal (:func:`_build_dsn`) does not apply here — configure verifying TLS via the
    driver's own keyword in ``odbc_params`` (e.g. psqlODBC ``SSLmode=verify-full``, MySQL
    ``SSLMODE=VERIFY_IDENTITY``). Because that delegation is otherwise invisible, construction logs it
    (:func:`_warn_generic_tls_unenforced`): a **WARNING** when no TLS keyword is present, DEBUG when one
    is.

    Delegating TLS is not the same as declining to gate the hop. A connection whose ``odbc_params`` say
    TLS is **not required** is refused off-loopback on an enforcing instance by
    :func:`generic_cleartext_hop_guard` (BACKLOG #1178), which the connectors call beside this builder.
    What stays delegated is the case this path genuinely cannot judge: a driver keyword IS set, and the
    engine cannot tell whether its value verifies anything. See docs/CONNECTIONS.md."""
    driver = str(s.get("odbc_driver") or "").strip()
    if not driver:
        raise ValueError("DATABASE generic dialect requires an 'odbc_driver' setting")
    # SERVER is emitted UNBRACED (validated, not brace-quoted) so a driver that parses a ",port"/":port"
    # suffix in SERVER can resolve the host — mirrors the SQL Server preset's rationale.
    server = str(s["server"])
    if any(ch in server for ch in ";{}=\r\n"):
        raise ValueError(
            "DATABASE server must not contain ';', '{', '}', '=', or newlines (ODBC injection risk)"
        )
    parts = [f"DRIVER={_odbc_brace(driver)}", f"SERVER={server}"]
    if s.get("database"):
        parts.append(f"DATABASE={_odbc_brace(str(s['database']))}")
    username = s.get("username")
    if username:
        user_key = _odbc_keyword(str(s.get("odbc_user_key", "UID")), what="odbc_user_key")
        parts.append(f"{user_key}={_odbc_brace(str(username))}")
    password = s.get("password")
    if password:
        pwd_key = _odbc_keyword(str(s.get("odbc_password_key", "PWD")), what="odbc_password_key")
        parts.append(f"{pwd_key}={_odbc_brace(str(password))}")
    params = s.get("odbc_params") or {}
    if not isinstance(params, Mapping):
        raise ValueError("DATABASE odbc_params must be a mapping of ODBC keyword -> value")
    for key, value in params.items():
        k = _odbc_keyword(str(key), what="odbc_params key")
        if k.lower() in _ODBC_RESERVED_KEYS:
            raise ValueError(
                f"DATABASE odbc_params must not set {k!r} — use the 'odbc_driver' / 'server' / "
                "'database' settings instead"
            )
        parts.append(f"{k}={_odbc_brace(str(value))}")
    _warn_generic_tls_unenforced(params, connection=connection)
    return ";".join(parts) + ";"


def _warn_generic_tls_unenforced(
    params: Mapping[str, Any], *, connection: str | None = None
) -> None:
    """Fail-safe visibility for the generic ODBC dialect (#66 review): unlike the SQL Server preset, this
    path **cannot introspect the driver's TLS posture**, so the posture-keyed weakened-TLS refusal
    (#200 / ADR 0092) does not apply and :func:`_build_connection` reports the hop as non-weakened. That
    is a deliberate operator-owned-TLS model, and it must not be *silent*.

    So at construction we log the delegation loudly: a **WARNING** when :func:`generic_odbc_tls_unenforced`
    says the hop may cross in plaintext — no ssl/tls/encrypt-ish keyword in ``odbc_params``, or one
    pinned to a no-TLS value like ``SSLmode=disable`` — dropped to **DEBUG** when the operator has taken
    TLS ownership.

    **This line is visibility, not the control.** It never gates or changes the connection, and until
    BACKLOG #1178 it was the whole of what stood between a generic PHI connection with no TLS keyword
    and a plaintext crossing. The refusal now lives in :func:`generic_cleartext_hop_guard`, which puts
    the same classifier's verdict through the shared hop authority. This still fires beside that gate,
    and it is the ONLY report on the arm the gate no-ops: an unstamped posture (a direct embedding, or
    a live-serve rebuild after the enforced pre-flight already vetted the config).

    ``connection`` names the declaring connection (#333). Without it a site running several generic DB
    connections gets a line it cannot act on — the remedy is per-connection, so the report must be too.
    It stays optional because :func:`_build_odbc_dsn` is also called directly (tests, DSN-shape checks)
    where there is no connection to name; every engine construction path supplies it."""
    where = (
        f"DATABASE connection {connection!r} (generic ODBC dialect)"
        if connection
        else "DATABASE generic ODBC dialect"
    )
    reason = generic_odbc_tls_unenforced(params)
    if reason is None:
        logger.debug(
            "%s: TLS is delegated to the driver (a TLS keyword is set in odbc_params); "
            "MessageFoundry does not enforce or verify it on this path",
            where,
        )
    else:
        logger.warning(
            "%s: TLS verification is NOT enforced by MessageFoundry on this path and %s — configure "
            "verifying TLS via the driver's own keyword (e.g. SSLmode=verify-full) so PHI is not sent "
            "in plaintext",
            where,
            reason,
        )


# --- the generic-ODBC dialect's cleartext hop, GATED (BACKLOG #1178) ---------------------------
#
# :func:`_warn_generic_tls_unenforced` above is visibility, not a control — it logs and returns. Before
# this gate the generic dialect reached no TLS gate of any family: :func:`_build_connection` reports it
# non-weakened, which also disarms the :func:`_assert_send_hop` tripwire, and the SQL Server preset's
# refusal never runs on this path. A deploying site would put a DB hop on the wire in the clear with
# nothing refusing it — cleartext by absence, not by a signed per-connection relaxation.
#
# The arm is routed through the SAME shared authority every other cleartext transport consumes
# (:class:`~messagefoundry.transports.mllp.InsecureHopGuard` ->
# :func:`~messagefoundry.config.tls_policy.insecure_hop_disposition`), exactly as ``TcpDestination`` and
# ``X12Destination`` do. One owner-ratified gradient, applied in one place, never re-forked. It can only
# refuse or warn where the shipped code was silent, so ADR 0092 decision 5 (no-loosen) holds by
# construction.
#
# SCOPE IS DELIBERATE: the generic dialect only, and only when the classifier returns a reason. The SQL
# Server preset keeps its own posture-keyed weakened-TLS refusal (:func:`_build_dsn`) — moving that arm
# onto this gradient would ADD the loopback and ``cleartext_accepted`` relaxations to a path that
# refuses today, which is a loosening.


def _port_or_zero(text: str) -> int:
    """``text`` as a port number, or 0 when it is not one — the ONE definition of "is this a port",
    used at both places :func:`_generic_hop_endpoint` looks for one.

    The five-digit bound is what a port is, and it also keeps ``int()`` away from CPython's
    string-to-int digit limit on an absurd operator value, which would turn a log detail into a crash."""
    text = text.strip()
    return int(text) if text.isdigit() and len(text) <= 5 else 0


def _generic_hop_endpoint(server: str, params: Mapping[str, Any]) -> tuple[str, int]:
    """Split a generic-dialect ``server`` setting into ``(host, port)`` for the hop guard.

    The loopback carve-out is decided on the HOST alone and
    :func:`~messagefoundry.config.tls_policy.is_loopback_hop_host` never resolves DNS, so a
    ``host,port`` / ``host:port`` / ``[v6]:port`` suffix has to come off first: left on,
    ``"127.0.0.1,5432"`` parses as a name rather than an address, is treated as remote, and a genuinely
    on-box dev hop is refused.

    A port the ``server`` string does not carry is read from the documented generic ``PORT`` keyword,
    and falls back to 0 when neither says. The port is REPORT-ONLY — it never changes the disposition —
    so an unknown port is a cosmetic gap in one log line, never a gap in the gate."""
    host = server.strip()
    port_text = ""
    if host.startswith("["):  # a bracketed IPv6 literal, optionally followed by ":port"
        close = host.find("]")
        if close != -1:
            host, rest = host[1:close], host[close + 1 :]
            port_text = rest[1:] if rest.startswith(":") else ""
    elif "," in host:  # the SQL-Server-style "host,port"
        host, _, port_text = host.partition(",")
    elif host.count(":") == 1:  # "host:port" — a bare IPv6 literal carries more than one colon
        host, _, port_text = host.partition(":")
    # A usable port in `server` wins; otherwise the PORT keyword; otherwise unknown. 0 is the "neither
    # said" value, so `or` reads correctly here — a port is never legitimately 0.
    keyword = next((str(v) for k, v in params.items() if str(k).strip().lower() == "port"), "")
    return host.strip(), _port_or_zero(port_text) or _port_or_zero(keyword)


def generic_cleartext_hop_guard(
    settings: Mapping[str, Any],
    *,
    cell: str,
    attested: bool,
    attested_reason: str | None,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
    connection: str | None = None,
) -> InsecureHopGuard | None:
    """The cleartext-hop guard for a generic-ODBC ``DATABASE`` connection, or ``None`` when there is
    nothing on this arm to gate (BACKLOG #1178).

    ``None`` covers two different situations. A non-``generic`` dialect is not this arm at all — the SQL
    Server preset keeps its own posture-keyed weakened-TLS refusal in :func:`_build_dsn`. A generic
    connection whose ``odbc_params`` addressed TLS returns ``None`` because
    :func:`generic_odbc_tls_unenforced` found no reason to think the hop crosses in plaintext; the
    engine still cannot VERIFY an arbitrary driver's keyword, and that residual is unchanged and
    written down in :func:`generic_odbc_no_tls_params`.

    Otherwise the hop is decided by the one shared authority, identically to every other cleartext
    transport: an on-box hop ALLOWs, a per-connection ``tls_hop_attested`` ALLOWs (audited),
    ``cleartext_accepted`` WARNs (audited), a non-enforcing instance WARNs, and an enforcing instance
    REFUSES. The authority reads no data label — ADR 0153 removed ``is_phi`` from it — so an enforcing
    instance refuses this hop whether or not it is declared PHI-carrying.

    ``cleartext_accepted`` is an outbound-only declaration on the config model, so an inbound
    ``DatabasePoll`` reaches the gate with the attestation as its only per-connection relaxation. That
    asymmetry is inherited, not introduced here.

    Pure — it reads the settings plus the ambient hop posture, and touches nothing else."""
    if str(settings.get("dialect", "sqlserver")).lower() != "generic":
        return None
    params = settings.get("odbc_params") or {}
    if not isinstance(params, Mapping):
        # A malformed odbc_params is :func:`_build_odbc_dsn`'s own ValueError, not a hop decision —
        # guessing a disposition off a value that will not load would report the wrong cause.
        return None
    reason = generic_odbc_tls_unenforced(params)
    if reason is None:
        return None
    host, port = _generic_hop_endpoint(str(settings.get("server") or ""), params)
    return InsecureHopGuard.capture(
        host=host,
        port=port,
        cell=cell,
        # The classifier's reason rides in the description so the refusal names WHAT is unset, not just
        # that something is: the remedy is a specific driver keyword.
        description=f"cleartext generic-ODBC DATABASE hop ({reason})",
        attested=attested,
        attested_reason=attested_reason,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
        connection=connection,
    )


def _build_connection(
    s: dict[str, Any],
    *,
    attested: bool = False,
    read_only: bool = False,
    connection: str | None = None,
) -> tuple[str, bool]:
    """Dispatch on ``dialect`` and return ``(dsn, weakened_tls)`` (#66). ``dialect='sqlserver'`` (default)
    runs the byte-identical SQL Server preset (:func:`_build_dsn`, weakened-TLS refusal + optional
    read-only intent); ``dialect='generic'`` runs :func:`_build_odbc_dsn` (operator-owned TLS, so never
    reported weakened — a construction-time WARNING flags the unenforced-TLS delegation instead).

    ``weakened_tls`` is the SQL-Server-preset flag only, and a ``False`` from the generic arm has never
    meant "this hop is safe" — it means "this preset's TLS keywords are not what governs it". The
    generic arm's own refusal is :func:`generic_cleartext_hop_guard`, called by the connectors beside
    this dispatcher rather than from inside it, so a direct DSN-shape caller (tests, checks) still gets
    a string back without a hop decision it did not ask for.

    ``connection`` names the declaring connection in that WARNING (#333); it is used on the generic path
    only, since the SQL Server preset refuses rather than warns."""
    dialect = str(s.get("dialect", "sqlserver")).lower()
    if dialect == "sqlserver":
        weakened = bool(s.get("trust_server_certificate", False)) or not bool(
            s.get("encrypt", True)
        )
        return _build_dsn(s, read_only=read_only, attested=attested), weakened
    if dialect == "generic":
        return _build_odbc_dsn(s, connection=connection), False
    raise ValueError(f"DATABASE dialect must be 'sqlserver' or 'generic', got {dialect!r}")


# A leading SQL line comment (`-- ...` to end of line) or block comment (`/* ... */`). Stripped (with
# leading whitespace) before the read-only check so a commented preamble can't mask a write statement.
_SQL_LEADING_COMMENT_RE = re.compile(r"^\s*(?:--[^\n]*\n|/\*.*?\*/)", re.DOTALL)


def _require_read_only(statement: str) -> None:
    """Enforce the ADR 0010 db_lookup read-only carve-out at the statement layer (defense-in-depth with
    ``ApplicationIntent=ReadOnly`` + a recommended ``db_datareader``-only login).

    After stripping any leading SQL comments/whitespace the statement must begin (case-insensitive) with
    ``SELECT`` or ``WITH`` and must not chain a second statement (a ``;`` followed by more SQL). This is
    a conservative lightweight gate, not a full SQL parser: it blocks ``INSERT``/``UPDATE``/``DELETE``/
    ``MERGE``/``EXEC`` and multi-statement smuggling so a crash-replay of the transform can't silently
    double-apply a write the at-least-once reliability model assumes is impossible. Raises
    :class:`DbLookupError` (PHI-free — never echoes the statement text) on violation."""
    stripped = statement
    while True:
        m = _SQL_LEADING_COMMENT_RE.match(stripped)
        if not m:
            break
        stripped = stripped[m.end() :]
    stripped = stripped.lstrip()
    head = stripped[:6].upper()
    if not (head.startswith("SELECT") or head.startswith("WITH")):
        raise DbLookupError(
            "db_lookup statement must be a read-only SELECT/WITH query "
            "(no writes, no EXEC, no multiple statements)"
        )
    # Reject a chained second statement: any ';' followed by non-whitespace/non-comment text. A single
    # trailing ';' (optionally followed by whitespace/comments) is fine.
    for idx, ch in enumerate(stripped):
        if ch != ";":
            continue
        rest = stripped[idx + 1 :]
        while True:
            m = _SQL_LEADING_COMMENT_RE.match(rest)
            if not m:
                break
            rest = rest[m.end() :]
        if rest.strip():
            raise DbLookupError(
                "db_lookup statement must be a read-only SELECT/WITH query "
                "(no writes, no EXEC, no multiple statements)"
            )
    return None


def _parse_named_params(statement: str) -> tuple[str, list[str]]:
    """Translate ``:name`` placeholders to positional ``?`` and return ``(sql, ordered_names)``."""
    names: list[str] = []

    def repl(m: re.Match[str]) -> str:
        names.append(m.group(1))
        return "?"

    return _PARAM_RE.sub(repl, statement), names


def _bind_params(payload: str, names: list[str]) -> tuple[Any, ...]:
    """Bind a JSON-object payload to the statement's ``names`` (positional order).

    A payload that isn't a JSON object, or that's missing a parameter, is a **permanent** data error
    (a retry can't fix it) → :class:`NegativeAckError`."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise NegativeAckError(
            f"DATABASE payload is not valid JSON: {exc}", code="payload", permanent=True
        ) from exc
    if not isinstance(data, dict):
        raise NegativeAckError(
            "DATABASE payload must be a JSON object mapping parameter names to values",
            code="payload",
            permanent=True,
        )
    try:
        return tuple(data[n] for n in names)
    except KeyError as exc:
        raise NegativeAckError(
            f"DATABASE payload is missing parameter {exc}", code="payload", permanent=True
        ) from exc


def _is_transient(sqlstate: str) -> bool:
    return sqlstate[:2] in _TRANSIENT_PREFIXES or sqlstate in _TRANSIENT_STATES


def _classify_db_error(sqlstate: str, message: str) -> DeliveryError:
    """Map a DB error's SQLSTATE to a transient :class:`DeliveryError` (retry) or a permanent
    :class:`NegativeAckError` (dead-letter)."""
    if _is_transient(sqlstate):
        return DeliveryError(f"database transient error [{sqlstate}]: {message}")
    return NegativeAckError(
        f"database rejected the statement [{sqlstate}]: {message}",
        code=sqlstate or "db",
        permanent=True,
    )


def _sqlstate(exc: BaseException) -> str | None:
    """The 5-character SQLSTATE a DB driver error carries in ``args[0]`` (pyodbc/aioodbc), or ``None``
    if ``exc`` isn't shaped like a DB error — letting a genuine bug propagate as an internal error
    rather than being misread as a transport failure."""
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], str) and len(args[0]) == 5 and args[0].isalnum():
        return args[0]
    return None


def _import_aioodbc() -> Any:
    """Import the optional ``aioodbc`` driver, raising a clear install hint if the ``[sqlserver]`` extra
    isn't present — so a SQLite-only install never touches it until a DATABASE connector is actually used."""
    try:
        import aioodbc
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "DATABASE connector requires the 'sqlserver' extra: "
            "pip install 'messagefoundry[sqlserver]' (plus the Microsoft ODBC Driver 18)"
        ) from exc
    return aioodbc


async def _make_pool(dsn: str, pool_max: int, *, autocommit: bool) -> Any:
    """Create an aioodbc connection pool for ``dsn`` (lazy driver import). The destination wraps
    execute+commit itself (``autocommit=False``); the source marks each row in its own auto-committed
    statement (``autocommit=True``)."""
    aioodbc = _import_aioodbc()
    return await aioodbc.create_pool(
        dsn=dsn, minsize=1, maxsize=max(1, pool_max), autocommit=autocommit
    )


# WP-L3-07 (ASVS 13.1.2/13.2.6): bound a pooled-connection borrow. One delivery/poll worker per
# connection means pool_max is never legitimately exhausted, so an acquire that can't be satisfied
# within the timeout means the pool is wedged or the DB is unresponsive — fail it transiently rather
# than block the worker forever (which would let the queue back up unbounded). Override per connection
# with the ``acquire_timeout`` setting.
_DEFAULT_DB_ACQUIRE_TIMEOUT = 30.0


async def _acquire(pool: Any, timeout: float) -> Any:
    """Acquire a connection from ``pool`` within ``timeout`` seconds, or raise a transient
    :class:`DeliveryError` with a clear, PHI-free message. Wraps the driver's own ``acquire`` so a
    hung/exhausted pool surfaces as a retryable failure instead of an unbounded await."""
    try:
        return await asyncio.wait_for(pool.acquire(), timeout)
    except TimeoutError as exc:
        raise DeliveryError(
            f"DATABASE pool acquire timed out after {timeout:g}s (pool exhausted or DB unresponsive)"
        ) from exc


async def _close_cursor(cur: Any) -> None:
    """Close a cursor BEFORE its connection goes back to the pool (BACKLOG #1104).

    aioodbc/pyodbc keep the ODBC statement handle open until the cursor is closed, and a connection
    released with an open handle is handed to the NEXT caller still busy. That caller's first command
    then fails with ``HY000 Connection is busy with results for another command`` — a failure with no
    relationship to the statement it lands on, which is what made this hard to attribute. An ``UPDATE``
    leaves a row count pending, so the DATABASE source's ``mark`` is the usual victim, and a failed
    mark **re-emits the row as a DUPLICATE** (see ``_poll_once``). So this is delivery semantics, not
    tidiness.

    Never raises. A close failure must not mask the caller's real error, and must not skip the pool
    release that follows it — leaking a connection to save a cursor would be the worse trade.
    """
    if cur is None:
        return
    try:
        await cur.close()
    except Exception as exc:  # noqa: BLE001 - hygiene only; the caller's outcome always wins
        logger.debug("DATABASE: cursor close failed, ignored: %s", exc)


async def _probe_db(
    get_pool: Callable[[], Any], *, timeout: float = _DEFAULT_DB_ACQUIRE_TIMEOUT
) -> None:
    """Open the pool and run ``SELECT 1`` — a no-data, no-write reachability probe shared by the
    DATABASE source and destination's ``test_connection``. A driver error is mapped via
    :func:`_classify_db_error` (transient vs permanent); a non-driver failure (e.g. an unreachable host
    before any SQLSTATE) becomes a transient :class:`DeliveryError`. Triggers the connector's lazy pool;
    the caller closes it with ``aclose()``."""
    try:
        pool = await get_pool()
        conn = await _acquire(pool, timeout)
    except Exception as exc:
        state = _sqlstate(exc)
        raise (
            _classify_db_error(state, str(exc))
            if state
            else DeliveryError(f"DATABASE connect failed: {exc}")
        ) from exc
    cur: Any = None
    try:
        cur = await conn.cursor()
        await cur.execute("SELECT 1")
    except Exception as exc:
        state = _sqlstate(exc)
        raise (
            _classify_db_error(state, str(exc))
            if state
            else DeliveryError(f"DATABASE probe failed: {exc}")
        ) from exc
    finally:
        await _close_cursor(cur)
        await pool.release(conn)


def _json_default(value: Any) -> Any:
    """JSON-serialize DB column types ``json.dumps`` can't handle natively (dates, ``Decimal``, bytes),
    so a polled row becomes a JSON-object body. An unknown type raises ``TypeError`` (surfaced as a
    poll error and logged) rather than silently dropping data."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        return base64.b64encode(bytes(value)).decode("ascii")
    raise TypeError(
        f"DATABASE source cannot serialize a {type(value).__name__} column value to JSON"
    )


class DatabaseDestination(DestinationConnector):
    """Execute one parameterized statement per payload against a SQL database (SQL Server today)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        # `database` is required only for the SQL Server preset; the generic ODBC dialect (#66) may omit
        # it (Oracle names a service, not a DATABASE keyword) and carries it via odbc_params if needed.
        self._dialect = str(s.get("dialect", "sqlserver")).lower()
        required = (
            ("server", "statement")
            if self._dialect == "generic"
            else ("server", "database", "statement")
        )
        for req in required:
            if not s.get(req):
                raise ValueError(f"DATABASE destination requires a {req!r} setting")
        # Per-connection insecure-hop attestation (#200) — surfaced to _build_dsn and captured for the
        # send-time byte-crossing re-assertion below.
        self._hop_attested = config.tls_hop_attested
        self._dsn, self._weakened_tls = _build_connection(
            s, attested=self._hop_attested, connection=config.name
        )  # fail fast on a weakened-TLS / bad-auth / bad-generic config
        # BACKLOG #1178: the generic dialect's cleartext arm, which reaches none of the refusals above.
        # Built AFTER _build_connection so a malformed server/keyword keeps reporting its own shape
        # error rather than a TLS refusal — the operator's first fix is the one that will not load.
        self._cleartext_guard = generic_cleartext_hop_guard(
            s,
            cell="DATABASE outbound",
            attested=self._hop_attested,
            attested_reason=config.tls_hop_attested_reason,
            cleartext_accepted=config.cleartext_accepted,
            cleartext_reason=config.cleartext_reason,
            connection=config.name,
        )
        if self._cleartext_guard is not None:
            self._cleartext_guard.enforce_construction()
        self._sql, self._param_names = _parse_named_params(str(s["statement"]))
        self._pool_max = int(s.get("pool_max", 5))
        self._acquire_timeout = float(s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT))
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()
        # ADR 0013: capture the statement's result-set (its RETURNING/OUTPUT rows). Default False →
        # returns None, byte-identical. Capture MUST be a RETURNING/OUTPUT clause of the write itself
        # (fetched from the SAME cursor BEFORE commit) — a separate post-commit SELECT would re-run on a
        # crash-replay against changed state. Wiring rejects a capturing statement with no RETURNING/
        # OUTPUT. The result-set is JSON-serialized and bounded by row/byte caps (over-cap →
        # outcome='unparseable' with an empty body, never an unbounded blob).
        # #67 (ADR 0013 amendment): capture a stored-proc call's OUT parameters + scalar RETURN value
        # (not just a RETURNING/OUTPUT result-set). It is read back pre-commit from the SAME cursor via a
        # trailing readback SELECT in the proc batch (pyodbc/aioodbc do not support native ODBC
        # output-param binding), so it inherits the same re-run-stability as the result-set path.
        # Setting it IMPLIES capture (the connector self-consistently captures when OUT params are
        # requested, regardless of whether the wiring gate ran). Default False → byte-identical.
        self.capture_out_params: bool = bool(s.get("capture_out_params", False))
        self.capture_response: bool = (
            bool(s.get("capture_response", False)) or self.capture_out_params
        )
        self._capture_max_rows = int(s.get("capture_max_rows", 100))
        self._capture_max_bytes = int(s.get("capture_max_bytes", 256 * 1024))

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                self._pool = await _make_pool(self._dsn, self._pool_max, autocommit=False)
        return self._pool

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # #200 decision 4: zero-I/O byte-crossing re-assertion of the posture-keyed hop decision, so a
        # payload never crosses a weakened-TLS DB hop the shared authority would refuse. Defense-in-depth
        # BEHIND the construction-time _build_dsn gate (which already refused a prod-PHI weakened hop),
        # catching a reload / build that reached send() around it. Fixed DSN target → this only ever
        # fires as a tripwire.
        _assert_send_hop(weakened=self._weakened_tls, attested=self._hop_attested)
        # BACKLOG #1178: the generic dialect's twin of the line above. That tripwire is keyed on
        # `weakened`, which the generic path never sets, so this arm needed its own re-assertion at the
        # byte crossing. None when there is no cleartext arm to re-assert.
        if self._cleartext_guard is not None:
            self._cleartext_guard.assert_send()
        params = _bind_params(payload, self._param_names)  # NegativeAckError(permanent) on bad data
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        cur: Any = None
        try:
            cur = await conn.cursor()
            try:
                await cur.execute(self._sql, params)
                # Capture the RETURNING/OUTPUT rows from the SAME cursor BEFORE commit (re-run-stable:
                # a separate post-commit SELECT could read changed state on a crash-replay). _capture
                # never raises — a capture problem must not roll back an otherwise-successful write.
                captured = await self._capture(cur) if self.capture_response else None
                await conn.commit()
            except Exception as exc:
                await conn.rollback()
                state = _sqlstate(exc)
                if state is None:
                    raise  # not a DB driver error → an internal/code error, let the runner handle it
                raise _classify_db_error(state, str(exc)) from exc
        finally:
            await _close_cursor(cur)
            await pool.release(conn)
        return captured

    async def _capture(self, cur: Any) -> DeliveryResponse:
        """Serialize the statement's RETURNING/OUTPUT result-set to a bounded JSON body (ADR 0013).

        Never raises (capture must not un-succeed a committed write): a missing result set / over-cap
        becomes ``no_reply`` / ``unparseable`` with an empty body. Generated ids in a RETURNING are
        only as stable as the write's idempotency — a non-idempotent INSERT re-derives a new id on a
        crash-re-send (the standing 'outbounds must be idempotent' requirement; see the connector docs).

        With ``capture_out_params`` (a stored-proc call, #67) it delegates to :meth:`_capture_merged`,
        which walks EVERY result set so a proc's OUT/return readback SELECT isn't dropped."""
        if self.capture_out_params:
            return await self._capture_merged(cur)
        try:
            rows = await cur.fetchall()
        except Exception:  # noqa: BLE001 - statement produced no result set; capture nothing, keep the write
            return DeliveryResponse(body="", outcome="no_reply", detail="no result set")
        if not rows:
            return DeliveryResponse(body="", outcome="no_reply", detail="0 rows")
        if len(rows) > self._capture_max_rows:
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set exceeded capture_max_rows={self._capture_max_rows}",
            )
        try:
            cols = [d[0] for d in cur.description] if cur.description else []
            data = [dict(zip(cols, tuple(row))) for row in rows]  # noqa: B905
            body = json.dumps(data, default=_json_default)
        except Exception as exc:  # noqa: BLE001 - an unserializable column type must NOT fail the write
            # _json_default raises TypeError on a column type it can't encode; serializing must never
            # propagate (it runs pre-commit and would roll back an otherwise-successful write).
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set not serializable ({type(exc).__name__})",
            )
        if len(body.encode("utf-8")) > self._capture_max_bytes:
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set exceeded capture_max_bytes={self._capture_max_bytes}",
            )
        return DeliveryResponse(body=body, outcome="accepted", detail=f"{len(rows)} row(s)")

    async def _capture_merged(self, cur: Any) -> DeliveryResponse:
        """Capture a stored-proc call's OUT parameters + scalar RETURN value (BACKLOG #67, ADR 0013
        amendment).

        A proc can emit data result-set(s) **and** a trailing readback SELECT of its OUT/return values
        (``DECLARE @rv INT; EXEC @rv = dbo.proc :mrn; SELECT @rv AS status;``), so this walks EVERY
        result set (``cursor.nextset()``) and merges each set's rows into one bounded JSON body — reading
        only the first set (as :meth:`_capture` does) would drop the OUT/return values. Read pre-commit
        from the same cursor, so it is re-run-stable to the same degree as the write's idempotency (see
        the atomicity caveat for a proc that COMMIT/ROLLBACKs internally). Bounded by
        ``capture_max_rows``/``capture_max_bytes`` like the single-set path.

        Never raises (capture must not un-succeed a committed write): a problem degrades to
        ``no_reply``/``unparseable`` with an empty body."""
        merged: list[dict[str, Any]] = []
        advance = getattr(cur, "nextset", None)
        while True:
            try:
                rows = await cur.fetchall()
            except Exception:  # noqa: BLE001 - this set is not a query (INSERT/EXEC) → nothing to fetch
                rows = []
            if rows:
                try:
                    cols = [d[0] for d in cur.description] if cur.description else []
                    merged.extend(dict(zip(cols, tuple(row))) for row in rows)  # noqa: B905
                except Exception:  # noqa: BLE001 - malformed description → skip this set, keep the write
                    pass
            if len(merged) > self._capture_max_rows:
                return DeliveryResponse(
                    body="",
                    outcome="unparseable",
                    detail=f"result-set exceeded capture_max_rows={self._capture_max_rows}",
                )
            if advance is None:
                break  # a driver/cursor with no nextset() → single set only
            try:
                has_next = await advance()
            except Exception:  # noqa: BLE001 - driver can't advance → stop with what we have
                break
            if not has_next:
                break
        if not merged:
            return DeliveryResponse(
                body="", outcome="no_reply", detail="no OUT params / return value"
            )
        try:
            body = json.dumps(merged, default=_json_default)
        except Exception as exc:  # noqa: BLE001 - an unserializable column type must NOT fail the write
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set not serializable ({type(exc).__name__})",
            )
        if len(body.encode("utf-8")) > self._capture_max_bytes:
            return DeliveryResponse(
                body="",
                outcome="unparseable",
                detail=f"result-set exceeded capture_max_bytes={self._capture_max_bytes}",
            )
        return DeliveryResponse(body=body, outcome="accepted", detail=f"{len(merged)} row(s)")

    async def test_connection(self) -> None:
        await _probe_db(self._get_pool, timeout=self._acquire_timeout)

    async def aclose(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None


class DatabaseSource(SourceConnector):
    """Poll a SQL table on an interval, hand each row to the pipeline handler, then mark it processed.

    The File source's *process-then-mark-done* shape (at-least-once), with a query instead of a
    directory: a cooperatively-cancellable background loop runs the operator-declared ``poll_statement``
    (a ``SELECT`` of the next batch), hands each row to the handler as a body, and — **only after the
    handler returns** — runs the optional ``mark_statement`` (an ``UPDATE``/``DELETE`` bound from that
    row's columns) so the row isn't re-read. A crash before the mark re-emits the row next poll
    (at-least-once); the downstream pipeline must tolerate duplicates. Poll errors are logged-not-fatal
    (a bad poll never kills the poller, mirroring the File source).

    **Body shape (payload-agnostic ingress, ADR 0004).** With ``body_column`` set, the body is that one
    column's value verbatim (e.g. a queue column holding an HL7 message → pair with ``content_type``
    ``hl7v2`` and it flows through the full HL7 path); unset, the body is the whole row as a JSON object
    ``{column: value}`` (pair with ``content_type=json`` so the Handler can ``.json()`` it).

    **Under ``[cluster].enabled`` (multi-node)** this source is leader-gated (only the leader polls,
    Track B Step 4b) — but unlike the File/RemoteFile sources, where the engine owns the atomic rename
    that bounds the leadership-transition duplicate window, the engine can't enforce row claim/mark
    atomicity here: it's on the operator's SQL. Write ``poll_statement``/``mark_statement`` to claim
    rows atomically (a status flag, or ``UPDATE ... RETURNING`` that both selects and marks) so the
    brief transition window stays at the same at-least-once duplicate class as a crash mid-poll.
    """

    polls_shared_resource = True  # a DB table is a shared external resource — leader-gate it

    def __init__(self, config: Source) -> None:
        s = config.settings
        # `database` is required only for the SQL Server preset; the generic ODBC dialect (#66) may omit it.
        self._dialect = str(s.get("dialect", "sqlserver")).lower()
        required = (
            ("server", "poll_statement")
            if self._dialect == "generic"
            else ("server", "database", "poll_statement")
        )
        for req in required:
            if not s.get(req):
                raise ValueError(f"DATABASE source requires a {req!r} setting")
        # Per-connection insecure-hop attestation (#200): the customer-DB poll link rides the same
        # posture-keyed verify-off refusal as the destination (a read still crosses the wire).
        self._dsn, _ = _build_connection(
            s, attested=config.tls_hop_attested, connection=config.name
        )  # fail fast on a weakened-TLS / bad-auth / bad-generic config
        # BACKLOG #1178: the poll link dials OUT on the same generic-dialect hop the destination does,
        # with the same credential in the same DSN, so it is gated identically. Construction only —
        # there is no per-payload byte crossing here to backstop, and `_run` swallows-and-retries a poll
        # failure, so raising per tick would produce log noise rather than a second control. `Source`
        # carries no `cleartext_accepted`, so an inbound's only per-connection relaxation is the
        # attestation.
        self._cleartext_guard = generic_cleartext_hop_guard(
            s,
            cell="DATABASE inbound poll",
            attested=config.tls_hop_attested,
            attested_reason=config.tls_hop_attested_reason,
            connection=config.name,
        )
        if self._cleartext_guard is not None:
            self._cleartext_guard.enforce_construction()
        self._poll_sql = str(s["poll_statement"])
        mark = s.get("mark_statement")
        # mark_statement is optional (a read-only/idempotent feed may omit it); its :name params bind
        # from the polled row's columns, reusing the destination's named-parameter translation.
        self._mark_sql: str | None
        self._mark_sql, self._mark_names = _parse_named_params(str(mark)) if mark else (None, [])
        self._body_column: str | None = s.get("body_column") or None
        self._poll_seconds = float(s.get("poll_seconds", 5.0))
        self._encoding: str = s.get("encoding", "utf-8")
        self._pool_max = int(s.get("pool_max", 5))
        self._acquire_timeout = float(s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT))
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, the poll table (a shared external resource) is
        # polled/marked only while the gate returns True, so in a cluster exactly one node ingests
        # its rows. None = always poll (single-node / direct callers / tests) — byte-identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            # return_exceptions: a faulted poll task must not re-raise here — stop() runs during reload
            # quiesce, outside its rollback (mirrors the File source's belt-and-suspenders).
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None
        await self.aclose()

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                # autocommit: each mark is its own committed statement, giving per-row mark durability.
                self._pool = await _make_pool(self._dsn, self._pool_max, autocommit=True)
        return self._pool

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._may_poll():
                    await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A poll error (connection drop, a bad poll_statement, an unserializable column) must
                # NOT kill the poller — that would silently stop the connection from receiving while it
                # still reports running. Log and retry on the next interval (mirrors the File source).
                logger.exception("DATABASE source poll failed; retrying next interval")
            try:  # noqa: SIM105
                await asyncio.wait_for(self._stop.wait(), self._poll_seconds)
            except TimeoutError:
                pass  # poll interval elapsed; poll again

    def _may_poll(self) -> bool:
        """Whether this tick may run poll_statement (and mark rows). False on a follower (leader-
        gated, Step 4b): a non-leader must NOT execute poll_statement or mark any rows, since the
        table is shared and two nodes polling it would duplicate intake. The loop still ticks, so a
        node that becomes leader polls on its next tick (reactive-by-polling, no restart). When the
        gate is None or True, behaves exactly as before. Logged once on each transition (never per
        skipped tick — that would spam a follower's log every poll interval)."""
        if self._leader_gate is None or self._leader_gate():
            if self._skipping:
                self._skipping = False
                logger.debug("DATABASE source resuming polling (now leader)")
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug("DATABASE source skipping polling (not leader; another node ingests it)")
        return False

    async def _poll_once(self) -> None:
        assert self._handler is not None
        columns, rows = await self._select()
        for row in rows:
            if self._stop.is_set():
                break  # shutting down — leave the rest unmarked for the next start (at-least-once)
            record = dict(zip(columns, row))  # noqa: B905
            try:
                body = self._body(record)
            except (ValueError, TypeError) as exc:
                # A row we can't turn into a body (missing body_column, unserializable value) is a
                # config/data error for that row — log and skip it rather than wedging the batch.
                logger.error("DATABASE source: %s; skipping row", exc)
                continue
            try:
                await self._handler(body.encode(self._encoding))
            except Exception as exc:
                # The handler records every message-level outcome itself (parse/route → ERROR) and
                # returns, so an exception here is an infrastructure failure (the durable store write
                # failed). Leave the row UNMARKED so the next poll re-emits it (at-least-once) — marking
                # it now would drop a received-but-unrecorded message (mirrors the File source's M-15).
                logger.warning(
                    "DATABASE source handler failed (row left unmarked, will retry): %s", exc
                )
                continue
            try:
                await self._mark(record)
            except Exception as exc:
                # The handler already ingested the message; a mark failure means the row re-emits next
                # poll (a duplicate — at-least-once). Log and move on rather than abort the batch tail.
                logger.warning(
                    "DATABASE source mark failed (row will re-emit, a duplicate): %s", exc
                )

    async def _select(self) -> tuple[list[str], list[Any]]:
        """Run ``poll_statement`` and return ``(column_names, rows)``. The connection is released before
        the rows are handed to the (possibly slow) handler, so a batch never holds a pool connection
        hostage to downstream store I/O."""
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        cur: Any = None
        try:
            cur = await conn.cursor()
            await cur.execute(self._poll_sql)
            columns = [d[0] for d in cur.description]
            rows = list(await cur.fetchall())
        finally:
            await _close_cursor(cur)
            await pool.release(conn)
        return columns, rows

    def _body(self, record: dict[str, Any]) -> str:
        """The body for one row: a single column verbatim (``body_column``) or the whole row as JSON."""
        if self._body_column is not None:
            try:
                value = record[self._body_column]
            except KeyError:
                raise ValueError(
                    f"body_column {self._body_column!r} is not in the poll_statement result columns"
                ) from None
            if isinstance(value, (bytes, bytearray)):
                return bytes(value).decode(self._encoding)
            return value if isinstance(value, str) else str(value)
        return json.dumps(record, default=_json_default)

    async def _mark(self, record: dict[str, Any]) -> None:
        if self._mark_sql is None:
            return
        try:
            params = tuple(record[n] for n in self._mark_names)
        except KeyError as exc:
            # mark_statement references a column the poll_statement didn't select — a static config
            # error. Log loudly and leave the row unmarked (it re-emits) rather than crash the poller.
            logger.error(
                "DATABASE source mark_statement references unknown column %s; row left unmarked",
                exc,
            )
            return
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        cur: Any = None
        try:
            cur = await conn.cursor()
            await cur.execute(self._mark_sql, params)
        finally:
            await _close_cursor(cur)
            await pool.release(conn)

    async def test_connection(self) -> None:
        await _probe_db(self._get_pool, timeout=self._acquire_timeout)

    async def aclose(self) -> None:
        if self._pool is not None:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None


register_destination(ConnectorType.DATABASE, DatabaseDestination)
register_source(ConnectorType.DATABASE, DatabaseSource)


def _bind_lookup_params(
    params: Mapping[str, Any], names: list[str], connection: str
) -> tuple[Any, ...]:
    """Bind a params mapping to the statement's ordered ``:name`` placeholders (positional). A missing
    name is a permanent author error → :class:`DbLookupError` (PHI-free: names the key, never its value)."""
    try:
        return tuple(params[n] for n in names)
    except KeyError as exc:
        raise DbLookupError(f"db_lookup on {connection!r}: missing parameter {exc}") from exc


class DatabaseLookupExecutor:
    """Pooled executor for handler-callable **live** lookups (``db_lookup``, ADR 0010).

    Built by the :class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` from the graph's
    ``DatabaseLookup`` specs (``env()``-resolved + ``[egress].allowed_db``-checked by the runner). Lazily
    opens one read-only ``aioodbc`` pool per named connection; :meth:`query` runs on the engine loop,
    while ``db_lookup`` bridges to it from the handler's worker thread via ``run_coroutine_threadsafe``.
    Reuses the DATABASE connector's DSN build / named-parameter translation / SQLSTATE extraction. Pools
    are autocommit — a lookup is read-only, so each query is its own implicit transaction; nothing here
    writes. **Read-only is enforced** (ADR 0010), not merely documented: every statement is gated by
    :func:`_require_read_only` (must begin SELECT/WITH, no chained writes/EXEC) and the pool DSN carries
    ``ApplicationIntent=ReadOnly`` (``_build_dsn(read_only=True)``). Production / supported (SQL Server
    via the ``[sqlserver]`` extra), like the DATABASE connector."""

    def __init__(self, connections: Mapping[str, Mapping[str, Any]]) -> None:
        # connections: name -> already-env-resolved settings (the runner substitutes env() first).
        self._dsn: dict[str, str] = {}
        self._pool_max: dict[str, int] = {}
        self._acquire_timeout: dict[str, float] = {}
        for cname, s in connections.items():
            for req in ("server", "database"):
                if not s.get(req):
                    raise ValueError(f"DatabaseLookup {cname!r} requires a {req!r} setting")
            # read_only=True: advertise ApplicationIntent=ReadOnly on the lookup pool (ADR 0010). Fail
            # fast on weakened-TLS / bad-auth config.
            self._dsn[cname] = _build_dsn(dict(s), read_only=True)
            self._pool_max[cname] = int(s.get("pool_max", 5))
            self._acquire_timeout[cname] = float(
                s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT)
            )
        self._pools: dict[str, Any] = {}
        self._locks: dict[str, asyncio.Lock] = {c: asyncio.Lock() for c in self._dsn}

    @property
    def connections(self) -> frozenset[str]:
        """The declared lookup connection names."""
        return frozenset(self._dsn)

    async def _get_pool(self, connection: str) -> Any:
        pool = self._pools.get(connection)
        if pool is not None:
            return pool
        async with self._locks[connection]:
            if connection not in self._pools:
                self._pools[connection] = await _make_pool(
                    self._dsn[connection], self._pool_max[connection], autocommit=True
                )
        return self._pools[connection]

    async def query(
        self, connection: str, statement: str, params: Mapping[str, Any] | None
    ) -> list[dict[str, Any]]:
        """Run ``statement`` against ``connection`` and return rows as ``{column: value}`` dicts.

        Always parameterized (``:name`` → positional ``?``, bound from ``params`` — a value can never
        inject SQL) and **read-only enforced** (the statement must be a SELECT/WITH query — see
        :func:`_require_read_only`). Raises :class:`DbLookupError` (PHI-free) on an unknown connection, a
        non-read-only statement, a missing parameter, or a DB/driver error — the transform worker turns
        it into that message's ``ERROR`` /
        dead-letter disposition. Runs on the engine loop (the handler thread bridges in via
        ``run_coroutine_threadsafe``), so a slow query never blocks the loop, only its own worker thread."""
        if connection not in self._dsn:
            known = ", ".join(sorted(self._dsn)) or "(none declared)"
            raise DbLookupError(
                f"db_lookup: no DatabaseLookup connection named {connection!r} (declared: {known})"
            )
        # ADR 0010: enforce the read-only carve-out at the statement layer before anything executes, so a
        # write/EXEC never reaches the autocommit pool (which would silently commit and re-apply on a
        # crash-replay of the transform). PHI-free — never echoes the statement.
        _require_read_only(statement)
        sql, names = _parse_named_params(statement)
        bound = _bind_lookup_params(params or {}, names, connection)
        pool = await self._get_pool(connection)
        try:
            conn = await _acquire(pool, self._acquire_timeout[connection])
        except DeliveryError as exc:
            # Map the transient pool-timeout onto the lookup's own PHI-free error type so the transform
            # worker dead-letters/errors this message consistently with other lookup failures.
            raise DbLookupError(f"db_lookup on {connection!r}: {exc}") from exc
        cur: Any = None
        try:
            cur = await conn.cursor()
            await cur.execute(sql, bound)
            columns = [d[0] for d in cur.description] if cur.description else []
            rows = list(await cur.fetchall())
        except DbLookupError:
            raise
        except Exception as exc:
            state = _sqlstate(exc)
            # PHI-free: name the connection + SQLSTATE (if any) only — never the statement/params/rows.
            raise DbLookupError(
                f"db_lookup query on {connection!r} failed" + (f" [{state}]" if state else "")
            ) from exc
        finally:
            await _close_cursor(cur)
            await pool.release(conn)
        return [dict(zip(columns, row)) for row in rows]  # noqa: B905

    async def aclose(self) -> None:
        """Close every opened pool (idempotent; safe if no pool was ever opened)."""
        for pool in self._pools.values():
            pool.close()
            await pool.wait_closed()
        self._pools.clear()
