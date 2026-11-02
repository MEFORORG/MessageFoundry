# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DATABASE transport: a SQL destination that runs one parameterized statement per payload.

The **destination** executes the operator-declared ``statement`` (an INSERT/UPDATE or a stored-procedure
call) against an outbound database, binding the payload's fields to the statement's ``:name``
parameters. The transport rides **``aioodbc``** (ADR 0003) — the ``[sqlserver]`` extra
(``pip install 'messagefoundry[sqlserver]'``), **lazily imported** so SQLite-only installs never touch it.

**Two dialects (#66).** ``dialect='sqlserver'`` (default) is the **SQL Server preset** — the Microsoft ODBC
Driver 18, T-SQL-flavoured DSN with the ``Encrypt``/``TrustServerCertificate`` TLS posture and its
weakened-TLS refusal (:func:`_build_dsn`); **production / supported**, exercised by the CI SQL Server
job. ``dialect='generic'`` is a **generic ODBC path** decoupled from Driver-18/T-SQL: the operator names
any OS-installed ODBC driver (PostgreSQL / MySQL) + supplies driver keywords via ``odbc_params``
(:func:`_build_odbc_dsn`), so no new Python DB-driver dependency is needed. ``odbc_params`` takes a fixed
list of keywords (:data:`_ODBC_PARAM_ALLOWLIST`): the list is hand-chosen, no keyword is on it in order to
name a host, and a file keyword's value is screened separately by spelling.
``[egress].allowed_db`` reads the host from the ``server`` setting (vault BACKLOG #2577). The list covers
keywords only, and relies on at least a driver named on the escape list reading the ``}}`` escape in a
braced password (:func:`_odbc_password`), and the driver reading ``SERVER`` as its target
(docs/CONNECTIONS.md, *Accepted ``odbc_params`` keywords*). On the generic path TLS is the operator's responsibility (configured through
the driver's own keyword) — MessageFoundry
cannot introspect an arbitrary driver's TLS posture, so the SQL-Server weakened-TLS refusal does not apply.
Construction logs the delegation as a fail-safe (a WARNING when no TLS mode is set, or one says no TLS — see
:func:`_warn_generic_tls_unenforced`) and **gates it**: a generic hop whose ``odbc_params`` say TLS is not
required, or set no mode, goes through the shared cleartext-hop authority like every other cleartext transport, so an
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
import contextlib
import json
import logging
import os
import re
import sys
import weakref
from collections.abc import Callable, Coroutine, Generator, Iterator, Mapping
from datetime import date, datetime
from decimal import Decimal
from functools import partial
from typing import Any, NamedTuple

from messagefoundry.auth.anchor_path import WinProbe, _win_probe, windows_chain
from messagefoundry.auth.trust_anchors import (
    ENCRYPTION_HEADER_SCOPE,
    PRIVATE_KEY_SCOPE,
    has_encryption_header_bytes,
    has_private_key_label_bytes,
    read_if_regular,
)
from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.models import (
    DEFAULT_DB_CONNECT_TIMEOUT,
    ConnectorType,
    Destination,
    Source,
    bool_setting,
    check_db_connect_timeout,
    hop_attestation_from_settings,
)
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    EgressSettings,
    weakened_tls_escape_permitted,
)
from messagefoundry.config.tls_policy import (
    HOP_ATTESTATION_LEVER,
    HopPosture,
    InsecureHopRefused,
    current_hop_posture,
    hop_name_prefix,
)
from messagefoundry.config.wiring import _is_text_codec
from messagefoundry.connection_names import inbound_record_name
from messagefoundry.controlchars import has_control_char
from messagefoundry.keywrap import KeyWrapRefused, refuse_weak_key_wrap
from messagefoundry.odbc_call_gate import CallGate, call_gate, install_call_gate
from messagefoundry.odbc_dsn import odbc_brace, odbc_connection_string
from messagefoundry.odbc_env import disable_driver_manager_pooling
from messagefoundry.redaction import prints_a_codec_error, safe_exc
from messagefoundry.transports.base import (
    DEFAULT_MAX_ITEMS_PER_POLL,
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    count_setting,
    float_setting,
    intake_open,
    poll_interval,
    positive_cap,
    register_destination,
    register_source,
    resolve_poll_ceiling,
)
from messagefoundry.transports.db_endpoint import (
    SQLSERVER_DEFAULT_PORT,
    generic_hop_endpoint,
    odbc_keyword_name,
    odbc_param,
)
from messagefoundry.transports.framing import declared_encoding
from messagefoundry.transports.mllp import InsecureHopGuard

__all__ = [
    "AutocommitNotConfirmed",
    "DatabaseDestination",
    "DatabaseLookupExecutor",
    "DatabaseSource",
]

logger = logging.getLogger(__name__)

# A `:name` parameter, but not `::` (a PostgreSQL-style cast) and not a `:` preceded by a word char
# (so a time literal like '12:30' inside the SQL is left alone). String-literal colons are otherwise
# the operator's responsibility — bind dynamic strings as parameters, not inline literals.
_PARAM_RE = re.compile(r"(?<![:\w]):(\w+)")

# SQLSTATE classes that are worth retrying: 08 = connection exception, 40 = transaction rollback /
# deadlock (40001); plus the ODBC connect/operation timeouts.
_TRANSIENT_PREFIXES = ("08", "40")
_TRANSIENT_STATES = frozenset({"HYT00", "HYT01"})


def _weakened_tls_permitted(*, attested: bool, posture: HopPosture | None) -> bool:
    """Whether a weakened (verify-off) customer-DB TLS posture may be used, routed through the ONE
    shared hop authority (#200, ADR 0092).

    A per-connection ``tls_hop_attested`` ALLOWs it (the operator affirms the hop is secure by other
    means — a proxy-terminated / trusted-segment DB link). Otherwise this stays a **STRICT verify-off
    cell** (decision 5): refused unless the global ``MEFOR_ALLOW_INSECURE_TLS`` escape applies, and
    that escape works only at ``[security].enforcement = warn`` (decision 2), so it can never relax
    an enforcing hop.

    The escape question is the shared :func:`~messagefoundry.config.settings.weakened_tls_escape_permitted`,
    so this cell and every other weakened-TLS cell answer it in one place. ``posture`` is the
    construction-time posture; the send-time tripwire passes the one its connector captured, because
    a delivery worker runs outside the scope that stamped it. ``None`` fails closed (vault BACKLOG
    #2354). CORRECTED: an unstamped call used to fall back to the unclamped escape, on the premise
    that the enforced gate had already vetted the real posture; callers the gate never reaches made
    that false."""
    return attested or weakened_tls_escape_permitted(posture)


def _audit_attested_weakened_tls(cell: str, *, connection: str | None = None) -> None:
    """Loud-log a per-connection attestation that suppresses a would-be **production-PHI** weakened-TLS
    refusal (#200 decision 3 — attestation is AUDITED when it crosses a prod-PHI hop). No-op on a
    non-prod / non-PHI / unstamped posture (nothing was suppressed there)."""
    posture = current_hop_posture()
    if posture is not None and posture.enforcing:
        logger.warning(
            "%s%s: weakened TLS permitted by per-connection tls_hop_attested on a production-PHI "
            "instance (operator attests the hop is secure by other means)",
            hop_name_prefix(connection),
            cell,
        )


def _assert_send_hop(
    *,
    weakened: bool,
    attested: bool,
    posture: HopPosture | None,
    connection: str | None = None,
) -> None:
    """Zero-I/O byte-crossing re-assertion (#200 decision 4): before a payload crosses a weakened-TLS
    DB hop, re-confirm the posture-keyed authority still permits it. Raises :class:`InsecureHopRefused`
    (a ``ValueError``) otherwise — a fail-closed tripwire behind the construction-time gate. No-op for
    a non-weakened (verifying-TLS) hop. ``posture`` is the one the connector captured when it was
    built."""
    if weakened and not _weakened_tls_permitted(attested=attested, posture=posture):
        raise InsecureHopRefused(
            f"{hop_name_prefix(connection)}DATABASE destination: refusing to put a payload on a "
            "weakened-TLS database hop "
            "(posture-keyed refusal, #200)"
        )


def _build_dsn(
    s: dict[str, Any],
    *,
    read_only: bool = False,
    attested: bool = False,
    connection: str | None = None,
) -> str:
    """Build the ODBC connection string for SQL Server from the connection settings.

    Quoting and the TLS tail: :mod:`messagefoundry.odbc_dsn` (BACKLOG #3714). It sends no
    ``ServerCertificate`` pin. A weakened TLS posture is **refused** via the shared posture-keyed
    authority (:func:`_weakened_tls_permitted`, #200) — a STRICT verify-off cell that stays refused
    for staging AND prod PHI, with the global escape clamped so it can never relax a production hop;
    ``attested`` (the per-connection ``tls_hop_attested``) is the surgical, audited per-hop opt-in.

    ``read_only`` (the db_lookup pool and, since BACKLOG #2617, the ``DatabaseRef`` sync set it;
    destination/source omit it, keeping their DSN byte-identical) appends ``ApplicationIntent=ReadOnly``
    so the connection advertises read-only intent. Against an Always On availability-group listener
    with read-only routing, that intent sends the connection to a readable secondary, whose data can
    lag the primary's. It is defense-in-depth for the ADR 0010 read-only carve-out, layered with the
    statement guard in :func:`_require_read_only`. **Neither layer is read-only authority.**
    ApplicationIntent is read at least by an Always On availability group, where read-only routing
    or a replica's ``ALLOW_CONNECTIONS`` setting acts on it and a primary set to ``READ_WRITE``
    refuses it, and by Azure SQL read scale-out, which sends it to a read-only replica. Where nothing
    reads it, it changes nothing. A statement guard is a shape test on text. The control that
    actually refuses a write is the privilege of the account this DSN dials, which only the operator
    can set (``docs/CONNECTIONS.md``, BACKLOG #1574)."""
    encrypt = bool_setting(s, "encrypt", default=True)
    trust = bool(s.get("trust_server_certificate", False))
    if (trust or not encrypt) and not _weakened_tls_permitted(
        attested=attested, posture=current_hop_posture()
    ):
        raise ValueError(
            f"{hop_name_prefix(connection)}DATABASE connection TLS is weakened "
            "(trust_server_certificate=true or encrypt=false), "
            "which is MITM-able. Use a trusted server certificate with encrypt=true; set "
            f"{HOP_ATTESTATION_LEVER} on the connection if the hop is "
            "secure by other means (a proxy-terminated or isolated segment; reported as a loosening); "
            f"or set {INSECURE_TLS_ESCAPE_ENV}=1 on an instance at [security].enforcement = warn to "
            "allow it for a trusted-network dev/test bind (the escape has no effect while enforcing, "
            "the default, or with no posture)."
        )
    if (trust or not encrypt) and attested:
        _audit_attested_weakened_tls("DATABASE connection", connection=connection)
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
        f"DRIVER={odbc_brace(str(s.get('odbc_driver', 'ODBC Driver 18 for SQL Server')))}",
        f"SERVER={server},{int(s.get('port', SQLSERVER_DEFAULT_PORT))}",
        f"DATABASE={odbc_brace(str(s['database']))}",
        # No login-timeout keyword here, on purpose: see :func:`_login_timeout` (BACKLOG #2089).
        f"APP={odbc_brace(str(s.get('app_name', 'messagefoundry')))}",
    ]
    if auth == "sql":
        parts.append(f"UID={odbc_brace(str(s.get('username') or ''))}")
        parts.append(f"PWD={odbc_brace(str(s.get('password') or ''))}")
    elif auth == "integrated":
        parts.append("Trusted_Connection=yes")
    else:  # entra
        parts.append("Authentication=ActiveDirectoryDefault")
    if read_only:
        # Advertise read-only intent; the docstring says who asks for it. Not a TLS keyword, so it
        # goes in the head, before the TLS tail (messagefoundry.odbc_dsn).
        parts.append("ApplicationIntent=ReadOnly")
    return odbc_connection_string(parts, encrypt=encrypt, trust_server_certificate=trust)


# A valid ODBC connection-string keyword: a letter then letters/digits/spaces/underscores. Rejecting the
# metacharacters (`; { } =`) and newlines is the STORE-5 guard for the operator-supplied generic keys
# (the VALUES are checked by _odbc_literal), so message-influenced data can't smuggle extra keywords.
_ODBC_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _]*$")

# The ONLY keywords ``odbc_params`` may set on the generic dialect (vault BACKLOG #2577), in the form
# :func:`odbc_keyword_name` compares them in.
#
# WHY A LIST OF WHAT IS ACCEPTED. ``[egress].allowed_db`` is checked against the ``server`` setting, so
# that check means something only while a keyword cannot hand the driver another host. Every ODBC
# driver has its own keywords for a host, an address, a data source name, a socket or a whole option
# string, and a new driver release can add another. A list of refused names would always trail the
# drivers. Here the list is hand-chosen, no keyword is on it in order to name a host,
# and a file keyword's value is screened separately by spelling. :func:`_build_odbc_dsn` refuses
# everything else when the connection is built.
#
# WHAT EARNS A PLACE. A keyword whose value is a port, a TLS mode, a local file the driver verifies or
# authenticates with, or a session setting. Nothing that names a host, a service, a data source or a
# socket, and nothing that hands the driver an option string, SQL to run or a library to load. The
# connector's own typed settings (driver, server, database, the two credentials) are absent as well:
# a second copy here would leave the driver to choose between the two. A keyword whose only use is
# to stop certificate verification is absent too.
#
# WHAT THE LIST DOES NOT SETTLE. It is a rule about keywords, and relies on at least a driver named
# on the escape list reading the ``}}`` escape in a braced password, and the driver reading
# ``SERVER`` as its target (docs/CONNECTIONS.md, *Accepted ``odbc_params`` keywords*). Which driver ``odbc_driver`` names,
# and what that driver does with the keywords it is sent, are outside it.
#
# ``port`` is here because the generic dialect has no other way to send one. It moves the port and
# never the host.
#
# docs/CONNECTIONS.md prints this list, and tests/test_generic_odbc_param_allowlist.py fails when the
# two differ. Adding a keyword is a reviewed code change, on purpose.
_ODBC_PARAM_ALLOWLIST = frozenset(
    {
        "port",
        # TLS mode, and the local files a driver verifies or authenticates with.
        "sslmode",
        "sslca",
        "sslcapath",
        "sslcert",
        "sslkey",
        "sslpassword",
        "sslcipher",
        "encrypt",
        # Session behaviour.
        "charset",
        "readonly",
        "readtimeout",
        "writetimeout",
        "fetch",
        "usedeclarefetch",
        "boolsaschar",
        "keepalivetime",
        "keepaliveinterval",
    }
)

# The keywords ``odbc_user_key`` / ``odbc_password_key`` may name. Those two settings choose the
# keyword a credential is sent under, so a free name there would be a free keyword with an
# operator-chosen value, which is what the list above exists to refuse.
_ODBC_USER_KEYS = frozenset({"uid", "user", "username", "user id"})
_ODBC_PASSWORD_KEYS = frozenset({"pwd", "password"})

# The listed keywords whose value is a file or directory path, which :func:`_refuse_remote_path`
# screens. A path keyword added to the list above belongs here too; a test holds this a subset.
_ODBC_PATH_KEYS = frozenset({"sslca", "sslcapath", "sslcert", "sslkey"})

# The ONLY keywords the engine counts as setting a generic hop's TLS mode, in the form
# :func:`odbc_keyword_name` compares them in (BACKLOG #2483). A value on one of these is what counts
# as the operator owning TLS. A key, certificate or CA file, or a cipher list, does not count.
# docs/CONNECTIONS.md records what the drivers read so far do with one.
#
# `encrypt` IS UNPROVEN. It is here for a driver that reads it. docs/CONNECTIONS.md records that
# neither psqlODBC's keyword parser nor MySQL Connector/ODBC's parameter page has it. On a driver
# that ignores it, `Encrypt=yes` would clear this gate and leave the driver at its own default, so
# treat that spelling as the operator's claim, not a tested control.
_ODBC_TLS_MODE_KEYWORDS = frozenset({"sslmode", "encrypt"})

# Names an odbc_params keyword as about TLS at all (anything ssl/tls/encrypt-ish). A name says nothing
# about the hop, so presence is never ownership: this picks which keywords' values are read against
# :data:`_ODBC_NO_TLS_VALUES`, and tells "no TLS keyword" from "no TLS mode" in the reason an operator
# reads. Since BACKLOG #1178 a no-TLS value found this way also gates the hop, so this is not
# report-only. It can never clear a hop.
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
#   Microsoft ODBC `Encrypt` : optional (version 18 documents it as a synonym for `no`)
#
# Since BACKLOG #2705 the build also holds `sslmode` to libpq's six lower-case spellings on every
# driver but MySQL Connector/ODBC (_refuse_unread_sslmode), so for a built hop this list's open end
# matters for `encrypt`, and for `sslmode` on MySQL's driver. The posture readers classify specs
# that were never built, so they still apply the list alone.
#
# KNOWN RESIDUAL, written down rather than implied: an ENCRYPTED-BUT-UNVERIFIED value — psqlODBC
# `require`, MySQL `REQUIRED`, `Encrypt=yes` beside a trust-everything keyword — is NOT on this list and
# stays in the DEBUG branch. It is a real weakening, but a different one: the payload is not in
# plaintext, so the warning's own sentence ("so PHI is not sent in plaintext") would not be true of it,
# and the per-driver spellings for "verified" vs "encrypted only" are not consistent enough to classify
# without guessing. The generic path delegates TLS to the operator by design (ADR 0092); this detector
# exists to make the PLAINTEXT case impossible to miss, not to grade the operator's cipher policy.
_ODBC_NO_TLS_VALUES: tuple[str, ...] = (
    "disable",
    "disabled",
    "allow",
    "prefer",
    "preferred",
    "no",
    "optional",
    "off",
    "false",
    "0",
)


def _no_tls_label(value: object) -> str | None:
    """The word from :data:`_ODBC_NO_TLS_VALUES` that ``value`` spells, matched case-insensitively
    as the earlier regex did, or ``None``. Returns the table's own string, never the caller's."""
    spelled = str(value).strip()
    return next((w for w in _ODBC_NO_TLS_VALUES if re.fullmatch(w, spelled, re.IGNORECASE)), None)


# A keyword that carries a SECRET, never a TLS mode, although `ssl` in its name matches the hint
# (libpq `sslpassword`, BACKLOG #1352). It is not a TLS keyword for either question below: its
# value is never classified or rendered, and its presence is not TLS ownership. Before this, a
# passphrase spelled `off` or `0` was rendered as `sslpassword=off` into the warning, the refusal
# text and every posture report that quotes the classifier's reason.
# Same words as config.wiring._SECRET_ODBC_SUBSTRINGS, which masks these keywords in /metadata.
_ODBC_SECRET_KEY_RE = re.compile(
    r"password|passwd|passphrase|pwd|secret|token|credential", re.IGNORECASE
)


def _is_tls_keyword(name: str) -> bool:
    """True for an ``odbc_params`` keyword about TLS: it matches the TLS hint and is not a
    secret-bearing keyword. Being one sets no mode; :func:`_sets_tls_mode` asks that."""
    return bool(_ODBC_TLS_HINT_RE.search(name)) and not _ODBC_SECRET_KEY_RE.search(name)


def _sets_tls_mode(params: Mapping[str, Any]) -> bool:
    """True when a keyword in :data:`_ODBC_TLS_MODE_KEYWORDS` has a non-blank string value with no
    blank at either end. Anything else sets nothing: the engine has no evidence of how a driver reads
    it, and :func:`_no_tls_label` cannot see a no-TLS word inside a list. Whether the value is a good
    one is :func:`generic_odbc_no_tls_params`'s question, not this one.

    A padded value does not count because a driver that does not trim would read something other
    than the word judged here: psqlODBC switches on the first character, so ``" require"`` would
    select its default. Since BACKLOG #2705 :func:`_build_odbc_dsn` refuses a blank, padded or
    boolean value outright, on any posture, so this matters for the posture readers, which classify
    specs that were never built. :func:`_odbc_keyword` refuses a padded keyword for the same reason.

    Every key is read, not the first spelling of each, so the answer for a table that names a mode
    keyword twice in different case does not depend on key order. The build refuses such a table;
    the posture readers classify specs that were never built."""
    return any(
        odbc_keyword_name(str(key)) in _ODBC_TLS_MODE_KEYWORDS
        and isinstance(value, str)
        and value.strip()
        and value == value.strip()
        for key, value in params.items()
    )


def generic_odbc_no_tls_params(params: Mapping[str, Any]) -> list[str]:
    """Every ``odbc_params`` TLS keyword that is set to a value meaning "TLS not required", as
    ``["KEY=value", ...]`` (#333). Empty when the operator set no such value. The value is rendered
    as the lower-case constant from :data:`_ODBC_NO_TLS_VALUES` it matched, never as supplied, and a
    keyword :data:`_ODBC_SECRET_KEY_RE` names is skipped. What a report can carry is therefore a
    keyword name and one of those words; a secret keyword that regex does not name could still
    be reported as ``KEY=<word>`` when its value is one of them.

    One half of :func:`generic_odbc_tls_unenforced`, the verdict shared by this module's
    construction-time reminder (:func:`_warn_generic_tls_unenforced`) and by the posture readers that
    report the hop to an operator (``config.wiring.unverified_generic_db_hops`` ->
    ``security_loosenings`` / ``GET /security/posture`` / ``messagefoundry check``). One definition, so a
    surface can never report a hop as clean that the log warns about, or the reverse.

    Pure — it reads a mapping and touches nothing else."""
    found: list[str] = []
    for key, value in params.items():
        name = str(key)
        if not _is_tls_keyword(name):
            continue
        label = _no_tls_label(value)
        if label is not None:
            found.append(f"{name}={label}")
    return found


def generic_odbc_tls_unenforced(params: Mapping[str, Any]) -> str | None:
    """Why this generic-ODBC hop may cross in plaintext, or ``None`` when :func:`_sets_tls_mode`
    finds a usable mode value and no TLS keyword holds a no-TLS word. A blank, padded or non-string
    mode value is not usable, so it does not clear the hop.

    Three ways to be at risk, and they read differently to an operator, so they are reported
    differently: a TLS keyword pinned to a no-TLS value (this names the offenders), a TLS keyword with
    no mode beside it, such as a lone ``sslcert`` or a blank ``sslmode`` (BACKLOG #2483), or no TLS
    keyword at all. Only :data:`_ODBC_TLS_MODE_KEYWORDS` can clear a hop. Shares
    :func:`generic_odbc_no_tls_params` with the construction reminder — see the comment above
    :data:`_ODBC_NO_TLS_VALUES` for why a value deny-list, and for the encrypted-but-unverified residual
    this deliberately does not classify. An unrecognized mode value stays delegated here for the same
    reason, though since BACKLOG #2705 the build refuses an ``sslmode`` spelling
    :func:`_refuse_unread_sslmode` rejects before this verdict is used.

    Since BACKLOG #1178 this predicate also decides whether the hop is GATED, not just reported: a
    non-``None`` reason is what builds :func:`generic_cleartext_hop_guard`. Same single definition, so
    the log line, the operator report and the refusal can never disagree about which hops are at risk —
    but widening it now widens a refusal, which the deny-list's deliberate narrowness should be read
    against."""
    disabling = generic_odbc_no_tls_params(params)
    if disabling:
        return "TLS is explicitly not required: " + ", ".join(sorted(disabling))
    if _sets_tls_mode(params):
        return None
    if any(_is_tls_keyword(str(k)) for k in params):
        return "a TLS keyword is set in odbc_params, but no TLS mode has a usable value"
    return "no TLS keyword is set in odbc_params"


def _odbc_keyword(key: str, *, what: str, connection: str | None = None) -> str:
    """Validate an ODBC keyword token (STORE-5) and return it, or raise a clear ValueError.

    ``fullmatch``, not ``match``: ``$`` also matches before a trailing line break, so ``match`` let a
    keyword ending in one through.

    A blank at the end, or two in a row, is refused as well. The keyword is sent as the operator
    spelled it, and not every driver trims it. One that does not would ignore a keyword the engine
    had read and judged, so the engine only accepts a spelling that needs no trimming."""
    if not _ODBC_KEY_RE.fullmatch(key) or key != " ".join(key.split()):
        raise ValueError(
            f"{hop_name_prefix(connection)}DATABASE {what} {key!r} is not a valid ODBC keyword "
            "(letters, digits, underscores and single spaces; must start with a letter and must "
            "not end with a space)"
        )
    return key


def generic_odbc_param(settings: Mapping[str, Any], keyword: str) -> object | None:
    """The value a generic-dialect connection's ``odbc_params`` gives ``keyword``, a name in the
    form :func:`odbc_keyword_name` gives, or ``None`` (vault BACKLOG #3090, step 7).

    ``None`` too for the SQL Server preset, which sends no ``odbc_params``, and for a table that is
    not a mapping, which the build refuses. The keyword is matched in any case and spacing, as the
    build matches it, and the build refuses a keyword given twice, so the first match is the copy
    the driver reads."""
    if str(settings.get("dialect", "sqlserver")).lower() != "generic":
        return None
    params = settings.get("odbc_params")
    return odbc_param(params, keyword) if isinstance(params, Mapping) else None


def generic_odbc_tls_off(settings: Mapping[str, Any]) -> bool:
    """Whether a generic-dialect connection's ``sslmode`` turns TLS off, so its driver reads no CA:
    libpq's ``disable`` or MySQL's ``DISABLED``, as :func:`_no_tls_label` spells them, in any case.
    ``allow`` and ``prefer`` may still go to TLS, so they do not count (vault BACKLOG #3090)."""
    mode = generic_odbc_param(settings, "sslmode")
    return mode is not None and _no_tls_label(mode) in ("disable", "disabled")


def _odbc_credential_keyword(
    value: object, setting: str, allowed: frozenset[str], *, connection: str | None
) -> str:
    """The keyword ``setting`` names for a credential, or a ValueError when it is not one of
    ``allowed`` (vault BACKLOG #2577). Returned as the operator spelled it."""
    key = _odbc_keyword(str(value), what=setting, connection=connection)
    name = odbc_keyword_name(key)
    if name not in allowed:
        raise ValueError(
            f"{hop_name_prefix(connection)}DATABASE {setting} must be one of "
            f"{', '.join(sorted(allowed))} (in any case), got '{name}'"
        )
    return key


def _odbc_unsafe_text(text: str, refused: str) -> bool:
    """True when ``text`` is not printable ASCII, or holds a ``refused`` character.

    WHY ASCII ONLY. pyodbc hands the connection string to the driver manager as Unicode. For a driver
    built on the narrow ODBC interface the manager converts it, and how it converts depends on the
    platform, the code page and the manager. Some conversions turn a non-ASCII character into an
    ASCII delimiter, after this builder has finished quoting. ASCII goes through every one of them
    unchanged, so that is the only alphabet whose delimiters this builder can account for."""
    return not text.isascii() or has_control_char(text) or any(ch in refused for ch in text)


def _refuse_unsafe_text(text: str, *, what: str, connection: str | None, refused: str) -> None:
    """A ValueError when ``text`` is not printable ASCII or holds a ``refused`` character
    (vault BACKLOG #2577). The refusal names the setting and never the value."""
    if _odbc_unsafe_text(text, refused):
        # repr, so a quote character prints readably: ';' stays ';', and ' prints as "'".
        listed = ", ".join(repr(ch) for ch in refused)
        raise ValueError(
            f"{hop_name_prefix(connection)}DATABASE {what} must hold only printable ASCII characters"
            + (f", and none of {listed}" if refused else "")
        )


def _refuse_none(value: object, *, what: str, connection: str | None) -> None:
    """A ValueError when ``value`` is ``None`` (BACKLOG #2705). An unbraced setting is sent as its
    ``str()``, so a ``None`` would reach the driver as the four letters ``None`` rather than as no
    value. An unset ``database``, ``username`` or ``password`` is left out of the string instead,
    and an ``odbc_params`` keyword with no value should be left out of the table."""
    if value is None:
        raise ValueError(f"{hop_name_prefix(connection)}DATABASE {what} must not be None")


# The characters a value sent WITHOUT braces must not hold (BACKLOG #2705): the three that end a
# value or open a braced one, ``=``, and both quote characters. The quotes sat inside braces on
# main, and how a driver reads one in a plain value has not been measured.
_ODBC_UNBRACED_REFUSED = ";{}=\"'"


def _odbc_literal(value: object, *, what: str, connection: str | None) -> str:
    """``value`` as the generic connection string sends it, WITHOUT braces, or a ValueError (BACKLOG
    #2705). Used for ``database``, ``username`` and every ``odbc_params`` value.

    Braced values were measured to be misread (psqlODBC ran ``SSLmode={verify-full}`` with no TLS).
    A plain value cannot be quoted, so at least these are refused instead: the characters in
    :data:`_ODBC_UNBRACED_REFUSED`, a value that is not printable ASCII, ``None``, and an empty,
    blank or padded value. docs/CONNECTIONS.md, *Values on the generic dialect*, holds the rules,
    the reasons and the measurements; this docstring does not restate them.

    The refusal names the setting and never the value. A password follows its own rule
    (:func:`_odbc_password`), and the driver name stays braced."""
    _refuse_none(value, what=what, connection=connection)
    text = str(value)
    _refuse_unsafe_text(text, what=what, connection=connection, refused=_ODBC_UNBRACED_REFUSED)
    if not text or text != text.strip():
        raise ValueError(
            f"{hop_name_prefix(connection)}DATABASE {what} must not be empty, blank, "
            "or start or end with a space"
        )
    return text


# MySQL Connector/ODBC's registered names, in lower case. The escape list below holds them, and
# they alone keep MySQL's own ``SSLMODE`` spellings (:func:`_refuse_unread_sslmode`).
_MYSQL_ODBC_DRIVER_NAME = r"mysql odbc [0-9.]+ (?:unicode|ansi) driver"
_MYSQL_ODBC_DRIVERS = re.compile(_MYSQL_ODBC_DRIVER_NAME)

# The ``odbc_driver`` names, in lower case, of the drivers whose password is always sent braced,
# with the ODBC ``}}`` escape (BACKLOG #2705): psqlODBC's and MySQL Connector/ODBC's registered
# names, measured on 2026-10-30 to read that escape, and Microsoft's ``ODBC Driver <n> for SQL
# Server``, not probed then but relied on for the same escape by the SQL Server preset and the
# store. psqlODBC's names include the bare ``PostgreSQL``, the section name RHEL registers it
# under. The legacy name ``SQL Server`` is left out: on Linux it is commonly a FreeTDS alias, which
# has not been measured. Whole names, spacing included, on purpose: a vendor driver whose name
# merely mentions a database, a library path, or another registered name that only folds to one of
# these is unmeasured and does not match.
_ODBC_BRACE_ESCAPE_DRIVERS = re.compile(
    r"postgresql(?: (?:unicode|ansi)(?:\(x64\))?)?"
    rf"|{_MYSQL_ODBC_DRIVER_NAME}"
    r"|odbc driver [0-9]+ for sql server"
)

# The ``sslmode`` values the generic dialect sends for any driver but MySQL Connector/ODBC: libpq's
# six modes, exactly, in lower case (BACKLOG #2705). psqlODBC's source reads an ``SSLmode`` value by
# its first byte, and only a lower case one names a mode, so ``Require``, ``VERIFY-FULL``,
# ``REQUIRED``, ``on`` or ``1`` would mean disable to it, while :func:`generic_odbc_tls_unenforced`
# counts each as TLS addressed. Only these spellings mean the same thing to both.
_LIBPQ_SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")


def _refuse_unread_sslmode(text: str, *, driver: str, connection: str | None) -> None:
    """A ValueError when an ``sslmode`` value is not one of :data:`_LIBPQ_SSL_MODES`, exactly
    (BACKLOG #2705). The keyword is matched in any case, as the build matches every keyword.

    The rule depends on the driver family, read from the ``odbc_driver`` name: MySQL Connector/ODBC
    sends the same keyword with its own upper case values (``REQUIRED``, ``VERIFY_IDENTITY``), so a
    name :data:`_MYSQL_ODBC_DRIVERS` matches whole is left to MySQL's spellings, as before. Every
    other driver, psqlODBC under any name included, takes the libpq spellings only. The refusal
    lists the accepted values and never the value given."""
    if _MYSQL_ODBC_DRIVERS.fullmatch(driver.lower()) or text in _LIBPQ_SSL_MODES:
        return
    raise ValueError(
        f"{hop_name_prefix(connection)}DATABASE odbc_params value for 'sslmode' must be one of "
        f"{', '.join(_LIBPQ_SSL_MODES)}, in lower case (see Generic ODBC in docs/CONNECTIONS.md)"
    )


def _odbc_password(password: object, *, driver: str, connection: str | None) -> str:
    """``password`` as the generic connection string sends it, or a ValueError (BACKLOG #2705).

    For a driver :data:`_ODBC_BRACE_ESCAPE_DRIVERS` names, it is ALWAYS braced, with the ``}}``
    escape, whatever it holds. psqlODBC URL-decodes an unbraced ``PWD`` (``+`` becomes a space and
    ``%XX`` a byte; ``dlg_specific.c``, ``decode_or_remove_braces``) and takes a braced one
    literally, so only the braced form sends the password as written.

    For any other driver it is sent plain, and only when it holds none of ``;``, ``{``, ``}`` or a
    quote character and has no leading or trailing space: a driver that reads no braces (the Access
    driver) takes it only that way, and one that does not read the escape would end a braced value
    at the first ``}`` and read the rest as further keywords. Any other password is refused for
    such a driver. A driver missing from the list is unmeasured, not known to be unsafe.

    A password must be printable ASCII whatever the driver. A refusal names the setting and never
    describes the value beyond saying the driver cannot carry it."""
    text = str(password)
    _refuse_unsafe_text(text, what="password", connection=connection, refused="")
    if _ODBC_BRACE_ESCAPE_DRIVERS.fullmatch(driver.lower()):
        return odbc_brace(text)
    if not any(ch in ";{}\"'" for ch in text) and text == text.strip():
        return text
    raise ValueError(
        f"{hop_name_prefix(connection)}DATABASE password cannot be carried by this odbc_driver; "
        "change the password (see Generic ODBC in docs/CONNECTIONS.md)"
    )


def _is_remote_spelling(value: object) -> bool:
    """Whether the trimmed ``value`` starts with two separators, or with the device prefix, and so
    can name another host. The spelling only; :func:`names_another_host` adds the Windows check."""
    text = str(value).strip()
    return len(text) >= 2 and text[0] in "\\/" and text[1] in "\\/?"


#: ``GetDriveTypeW`` answers: a mapped network drive, no volume at that letter, and an unknown type.
_DRIVE_REMOTE = 4
_DRIVE_NO_ROOT_DIR = 1
_DRIVE_UNKNOWN = 0

#: The first component of a rooted, driveless link target that names the NT object namespace
#: (``\Device\Mup\host\share``), which ``windows_chain`` would read as a folder on the link's drive.
_NT_OBJECT_ROOTS = frozenset({"device", "global??", "??"})


class _LeavesHost(Exception):
    """Raised through :func:`~messagefoundry.auth.anchor_path.windows_chain` by a reader that met
    another host: a network drive, a link to a share, or a share Windows could not reach. Not an
    ``OSError``, which the walk would catch and report as a cause."""


class _PathEnds(Exception):
    """Raised through the walk where a component, or the drive, does not exist yet: nothing past it
    is a link, so the rest of the path is local text. Not an ``OSError``, for the same reason."""


def _windows_drive_type(root: str) -> int:
    """``GetDriveTypeW``'s answer for a volume root. Raises ``OSError`` off Windows."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the drive type is read only on Windows")
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint
    return int(kernel32.GetDriveTypeW(root))


def _windows_drive_target(drive: str) -> str | None:
    """The folder a ``subst`` drive stands for, or ``None`` for a real volume or no device at all,
    as ``anchor_path.windows_host_readers`` reads it: ``QueryDosDeviceW`` answers ``\\??\\C:\\...``
    for a substituted drive. Any other failure of the query raises ``OSError``, so the walk does
    not clear the path: a subst drive it could not read would hide the links behind it."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type checker on POSIX
        raise OSError("the drive target is read only on Windows")
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryDosDeviceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
    kernel32.QueryDosDeviceW.restype = ctypes.c_uint
    buf = ctypes.create_unicode_buffer(1024)
    if not kernel32.QueryDosDeviceW(drive, buf, len(buf)):
        error = ctypes.get_last_error()
        if error == _ERROR_FILE_NOT_FOUND:  # no such device: the drive type then says no volume
            return None
        raise OSError(f"the drive {drive} could not be read (winerror {error})")
    return buf.value[4:] if buf.value.startswith("\\??\\") else None


#: ``QueryDosDeviceW``'s answer for a drive letter with no device behind it.
_ERROR_FILE_NOT_FOUND = 2


def _windows_path_verdict(
    path: str,
    *,
    probe: WinProbe,
    drive_type: Callable[[str], int],
    drive_target: Callable[[str], str | None],
    cwd: str | Callable[[], str],
) -> bool | None:
    """The best-effort verdict on whether a Windows ``path`` leads off this host, from a walk of it
    with :func:`~messagefoundry.auth.anchor_path.windows_chain`. ``True``: the walk found the path
    leads to another host. ``None``: the walk could not finish, and its cause is logged at DEBUG.
    ``False``: the walk found nothing that leads off the host, which is not proof the path is
    local. ``probe``, ``drive_type``, ``drive_target`` and ``cwd`` are the walk's inputs, passed in
    so a test can stand in for the file system. ``docs/CONNECTIONS.md``, Generic ODBC, states the
    check's limits."""

    def volume_cause(root: str) -> str | None:
        kind = drive_type(root)
        if kind == _DRIVE_REMOTE:
            raise _LeavesHost
        if kind == _DRIVE_NO_ROOT_DIR:
            raise _PathEnds  # no volume at that letter here: left to the driver, as a missing file is
        if kind == _DRIVE_UNKNOWN:
            return "the type of this volume could not be read"
        return None

    def probing(part: str) -> tuple[str, str | None]:
        try:
            kind, target = probe(part)
        except (FileNotFoundError, NotADirectoryError) as exc:
            if getattr(exc, "winerror", None) in _WINDOWS_UNREACHABLE:
                raise _LeavesHost from None
            raise _PathEnds from None
        if target is not None:
            text = target.strip()
            if _is_remote_spelling(text) and not _LOCAL_DEVICE_TARGET.match(text):
                raise _LeavesHost
            if text[:1] in "\\/" and text.lstrip("\\/").split("\\")[0].lower() in _NT_OBJECT_ROOTS:
                raise OSError("the link names an NT object path")  # the walk reports it: unclear
        return kind, target

    try:
        _chain, cause = windows_chain(
            path, cwd, probing, volume_cause=volume_cause, drive_target=drive_target
        )
    except _LeavesHost:
        return True
    except _PathEnds:
        return False
    except OSError as exc:  # a reader the walk does not guard, such as drive_target
        logger.debug("DATABASE file keyword path not cleared: %s", exc)
        return None
    if cause is not None:
        logger.debug("DATABASE file keyword path not cleared: %s", cause)
        return None
    return False


#: A link target :func:`_is_remote_spelling` matches that :func:`_windows_path_verdict` does not
#: count as leading off the host: two separators, ``?`` or ``.``, a separator, then a drive letter
#: or ``Volume{``. Any other link target :func:`_is_remote_spelling` matches is counted as leading
#: off the host.
_LOCAL_DEVICE_TARGET = re.compile(r"[\\/]{2}[?.][\\/](?:[A-Za-z]:|[Vv]olume\{)")


def _path_verdict(text: str) -> bool | None:
    """:func:`_windows_path_verdict` for ``text`` on Windows, and ``None`` for an ``OSError`` or
    ``ValueError`` it raises. ``False`` on POSIX, where nothing past the spelling is checked
    (``docs/CONNECTIONS.md``, Generic ODBC)."""
    if sys.platform != "win32":
        return False
    try:
        return _windows_path_verdict(
            text,
            probe=_win_probe,
            drive_type=_windows_drive_type,
            drive_target=_windows_drive_target,
            cwd=os.getcwd,
        )
    except (OSError, ValueError) as exc:
        logger.debug("DATABASE file keyword path not cleared: %s", type(exc).__name__)
        return None


#: A file keyword's verdicts: each spelling a driver may be given, as sent and trimmed, with its
#: :func:`_path_verdict`. Computed ONCE per judgement (:func:`file_keyword_verdicts`) and passed
#: to every reader of it, so the refusal and the checks that read the file cannot disagree.
FileVerdicts = Mapping[str, bool | None]


def file_keyword_verdicts(value: object) -> FileVerdicts:
    """:data:`FileVerdicts` for ``value``, empty for a falsy one. A spelling the spelling check
    refuses is ``True`` and is not walked."""
    if not value:
        return {}
    raw = str(value)
    return {
        p: True if _is_remote_spelling(p) else _path_verdict(p)
        for p in dict.fromkeys((raw, raw.strip()))
        if p
    }


def names_another_host(value: object, verdicts: FileVerdicts | None = None) -> bool:
    """Whether a file keyword's ``value`` must be refused. ``True`` when any spelling's verdict is
    ``True``, or the trimmed spelling's verdict is ``None``. ``False`` otherwise, including for a
    falsy value and for a padded spelling whose verdict alone is ``None``. ``False`` is not proof
    the path is local. ``verdicts`` are this value's (:func:`file_keyword_verdicts`) when the
    caller already has them; otherwise they are computed here. ``docs/CONNECTIONS.md``, Generic
    ODBC, states the check's limits."""
    if not value:
        return False
    if verdicts is None:
        verdicts = file_keyword_verdicts(value)
    trimmed = str(value).strip()
    return True in verdicts.values() or (bool(trimmed) and verdicts.get(trimmed) is None)


def driver_file_spellings(value: object, verdicts: FileVerdicts | None = None) -> tuple[str, ...]:
    """The spellings of a driver file keyword's value the engine checks: as sent, then trimmed,
    since a driver may trim it. Empty for a falsy value and for a value :func:`names_another_host`
    refuses; otherwise every spelling in ``verdicts``. A returned spelling is not proof the path is
    local (``docs/CONNECTIONS.md``, Generic ODBC). Any value, a ``Path`` too, is read as its
    ``str()``, the text the build sends.

    ``verdicts`` are the value's, from the judgement that decided whether it is refused; pass them
    whenever there is one, so the path is judged once. Without them they are computed here, and a
    caller must treat an empty answer for a set value as its own refusal."""
    if not value:
        return ()
    if verdicts is None:
        verdicts = file_keyword_verdicts(value)
    if names_another_host(value, verdicts):
        return ()
    return tuple(verdicts)  # names_another_host is False for these verdicts


def _refuse_remote_path(
    value: object, verdicts: FileVerdicts, *, name: str, connection: str | None
) -> None:
    """Raise ``ValueError`` when :func:`names_another_host` is ``True`` for ``value`` and its
    ``verdicts`` (BACKLOG #2705); otherwise return. The message names the keyword, not the value.
    ``docs/CONNECTIONS.md``, Generic ODBC, states the check's limits."""
    if names_another_host(value, verdicts):
        raise ValueError(
            f"{hop_name_prefix(connection)}DATABASE odbc_params value for '{name}' must be a plain "
            "local path on this host: not a share, a network drive, a link to one, or a path it "
            "cannot read"
        )


def _refuse_remote_paths(
    named: Mapping[str, Any], *, connection: str | None
) -> dict[str, FileVerdicts]:
    """Compute the verdicts of each file keyword in ``named``, in sorted keyword order, and raise
    ``ValueError`` (:func:`_refuse_remote_path`) at the first that :func:`names_another_host`
    refuses, in every ``sslmode``. Otherwise return the verdicts for the checks that read the
    files: one entry per file keyword ``named`` holds, set or not. ``docs/CONNECTIONS.md``, Generic
    ODBC, states the check's limits."""
    verdicts: dict[str, FileVerdicts] = {}
    for name in sorted(_ODBC_PATH_KEYS & named.keys()):
        value = named[name]
        verdicts[name] = file_keyword_verdicts(value)
        _refuse_remote_path(value, verdicts[name], name=name, connection=connection)
    return verdicts


def _refuse_weak_driver_key(
    named: Mapping[str, Any],
    *,
    connection: str | None = None,
    verdicts: Mapping[str, FileVerdicts] | None = None,
) -> None:
    """Check a driver client key's passphrase wrap before the connection string reaches the driver
    (BACKLOG #1352, #1171).

    libpq's ``sslkey`` names a private key file, and ``sslpassword`` its passphrase; MySQL's ODBC
    driver takes ``SSLKEY`` too. The DRIVER decrypts it, so the engine cannot choose the derivation,
    but it hands the key over, so it reads the wrap first and refuses a weak one exactly as the TLS
    loaders do. An encrypted key with no ``sslpassword`` is refused too: libpq would otherwise fall
    back to OpenSSL's terminal prompt.

    ``named`` maps each keyword, in the form :func:`odbc_keyword_name` gives, to its value. The
    builder has already refused a keyword given twice, so the copy read here is the copy the driver
    reads. This binds only a driver that reads ``sslkey`` itself. psqlODBC takes a client key only
    through ``pqopt``, which the builder refuses, so there libpq finds the key on its own (at least
    ``PGSSLKEY``, a service file, or its default path) and no key is checked (BACKLOG #2423).

    The file is read at each spelling :func:`driver_file_spellings` gives (vault BACKLOG #3090), so
    a padded value is checked as a driver may trim it, and a pipe named here is never read: it is
    refused, as anything that is not a regular file is, on its stat, or on its descriptor if it
    was swapped in after that stat (:func:`~messagefoundry.auth.trust_anchors.read_if_regular`)."""
    _refuse_weak_driver_wrap(
        named, "sslkey", "key file", connection, leave_irregular=False, verdicts=verdicts
    )


def _refuse_weak_driver_cert(
    named: Mapping[str, Any],
    *,
    connection: str | None = None,
    verdicts: Mapping[str, FileVerdicts] | None = None,
) -> None:
    """Check the key wrap of a driver's client certificate file before the driver loads it (vault
    BACKLOG #3090, step 5).

    ``sslcert`` names the client certificate a driver loads with its own TLS library, and with no
    ``sslkey`` a PEM there may carry the private key too. A certificate-chain load is the one that
    can prompt for a passphrase, so the file takes :func:`_refuse_weak_driver_key`'s wrap check. A
    plain certificate, PEM or DER, holds no key and passes. The private-key-label refusal a CA file
    takes (BACKLOG #3745) does not apply: a client certificate file may hold its own key.

    With ``sslkey`` set, the key comes from that file, which its own check reads, so ``sslcert`` is
    not read here. That is the rule
    :func:`~messagefoundry.keywrap.refuse_weak_cert_chain_key` follows. It runs when the
    connection is built, not at each connect. docs/CONNECTIONS.md, under the generic dialect, says
    what it does not cover."""
    if not str(named.get("sslkey") or "").strip():
        _refuse_weak_driver_wrap(
            named, "sslcert", "certificate file", connection, verdicts=verdicts
        )


def _refuse_weak_driver_wrap(
    named: Mapping[str, Any],
    keyword: str,
    what: str,
    connection: str | None,
    *,
    leave_irregular: bool = True,
    verdicts: Mapping[str, FileVerdicts] | None = None,
) -> None:
    """Refuse a weak or unlockable key wrap in the ``keyword`` file, with ``sslpassword`` as its
    passphrase, through :func:`~messagefoundry.keywrap.refuse_weak_key_wrap`. A file the check
    cannot read is refused as :class:`~messagefoundry.keywrap.KeyWrapRefused`, as
    :func:`~messagefoundry.keywrap.refuse_weak_key_file` refuses it. ``leave_irregular`` is
    :func:`_read_driver_file`'s."""
    for setting, data in _driver_file_spellings(
        named,
        keyword,
        connection,
        what,
        "its wrap",
        error=KeyWrapRefused,
        leave_irregular=leave_irregular,
        verdicts=verdicts,
    ):
        refuse_weak_key_wrap(
            data,
            setting=setting,
            unlock_setting="odbc_params sslpassword",
            passphrase_given=bool(named.get("sslpassword")),
        )


#: How much of an ``sslca``, ``sslcert`` or ``sslkey`` file :func:`_read_driver_file` reads: 1 MiB,
#: the cap :mod:`messagefoundry.keywrap` puts on a key file (vault BACKLOG #3090, step 8). A CA
#: bundle is tens or hundreds of KiB, and a client certificate with its key a few KiB. The read
#: runs on the event loop when the connection is built, so the cap bounds that stall too.
_MAX_DRIVER_CA_FILE_BYTES = 1 << 20
#: ``ERROR_INVALID_NAME``: Windows' answer for a path it cannot spell, such as one with a leading
#: space before the drive letter.
_WINDOWS_INVALID_NAME = 123
#: ``ERROR_BAD_NETPATH`` and ``ERROR_BAD_NET_NAME``: a share Windows could not reach, which
#: CPython raises as ``FileNotFoundError`` though a file may be there.
_WINDOWS_UNREACHABLE = frozenset({53, 67})


def _refuse_encrypted_driver_ca(
    named: Mapping[str, Any],
    *,
    connection: str | None = None,
    verdicts: Mapping[str, FileVerdicts] | None = None,
) -> None:
    """Refuse an ``sslca`` CA file with an encryption header before the driver loads it (BACKLOG
    #3090).

    MySQL's ODBC driver takes its CA file as ``SSLCA`` and loads it with its own TLS library, so
    the engine never reads it otherwise. Python's ``ssl`` was measured refusing an encrypted block
    in a CA file at once (``tests/test_encrypted_pem_cafile_pin.py``); a driver's own library was
    not. So the file goes through
    :func:`~messagefoundry.auth.trust_anchors.has_encryption_header_bytes` first. The refusal names
    the setting and never the file's content. A file past :data:`_MAX_DRIVER_CA_FILE_BYTES` is
    refused rather than read in part, since a header past the cut would pass unseen. A file with a
    private-key label is refused too, through
    :func:`~messagefoundry.auth.trust_anchors.has_private_key_label_bytes` (BACKLOG #3745).

    :func:`_driver_file_spellings` says which paths are left to the driver, and which spellings
    are read. A share Windows reports as not found because it could not reach it is refused,
    unless ``sslmode`` turns TLS off (:func:`generic_odbc_tls_off`): then the driver reads no CA,
    so it never meets that file.

    **It runs when the connection is built, not at each connect.** What checks the file after
    that, and what does not, is ``auth.trust_anchors`` module item 12."""
    for setting, data in _driver_file_spellings(
        named,
        "sslca",
        connection,
        "CA file",
        "it for an encryption header or a private key",
        leave_unreachable=generic_odbc_tls_off({"dialect": "generic", "odbc_params": named}),
        verdicts=verdicts,
    ):
        if has_encryption_header_bytes(data):
            raise ValueError(
                f"{setting}: the CA file {ENCRYPTION_HEADER_SCOPE}. The driver loads it with its "
                "own TLS library, which can wait for a password on an encrypted block; refusing "
                "to hand it over (BACKLOG #3090)"
            )
        if has_private_key_label_bytes(data):
            raise ValueError(
                f"{setting}: the CA file {PRIVATE_KEY_SCOPE}. A CA file is public trust material, "
                "so a private key does not belong in it; refusing to hand it over (BACKLOG #3745)"
            )


def _driver_file_spellings(
    named: Mapping[str, Any],
    keyword: str,
    connection: str | None,
    what: str,
    checked_for: str,
    *,
    error: type[ValueError] = ValueError,
    leave_irregular: bool = True,
    leave_unreachable: bool = False,
    verdicts: Mapping[str, FileVerdicts] | None = None,
) -> Iterator[tuple[str, bytes]]:
    """``(setting, bytes)`` for each spelling of the ``keyword`` file
    (:func:`driver_file_spellings`) that :func:`_read_driver_file` reads, for the caller to check.
    Nothing when the keyword is unset, and nothing more once a spelling is left to the driver as
    an unreached share: another spelling of it would wait out the same network timeout.

    Raises ``error`` for a set value :func:`names_another_host` refuses. ``verdicts`` are the
    build's (:func:`_refuse_remote_paths`), and the spellings read come from them; a map that lacks
    a set ``keyword`` raises ``KeyError``, since that is a caller's bug. Without a map the verdicts
    are computed here."""
    setting = f"{hop_name_prefix(connection)}DATABASE odbc_params {keyword}"
    value = named.get(keyword)
    if not value:
        return
    given = file_keyword_verdicts(value) if verdicts is None else verdicts[keyword]
    if names_another_host(value, given):
        raise error(
            f"{setting}: the {what} is not a plain local path on this host, so it was not read "
            f"to check {checked_for}"
        )
    for path in driver_file_spellings(value, given):
        try:
            data = _read_driver_file(
                path,
                setting,
                what,
                checked_for,
                error=error,
                leave_irregular=leave_irregular,
                leave_unreachable=leave_unreachable,
            )
        except _UnreachedShare:
            return
        if data is not None:
            yield setting, data


class _UnreachedShare(Exception):
    """:func:`_read_driver_file` could not reach the share a spelling names, and its caller said
    the driver will not read the file, so no spelling of it is read."""


def _read_driver_file(
    path: str,
    setting: str,
    what: str,
    checked_for: str,
    *,
    error: type[ValueError] = ValueError,
    leave_irregular: bool = True,
    leave_unreachable: bool = False,
) -> bytes | None:
    """The bytes of one spelling of a file a driver loads, for the engine to check first, or
    ``None`` when the file is left to the driver. ``what`` and ``checked_for`` word a refusal, and
    ``error`` is its type.

    Like :func:`~messagefoundry.keywrap.refuse_weak_key_file`, a path that does not exist is left
    to the driver, which reports it. With ``leave_irregular``, so is anything that is not a regular
    file: a directory, which is loaded as before, and a device or pipe, which the engine does not
    read because reading one could itself wait. Without it, as for ``sslkey``, those are refused
    unread, as ``refuse_weak_key_file`` refused a directory. Any other read failure is refused,
    because a file the check cannot read is one it cannot clear, and so is a file past
    :data:`_MAX_DRIVER_CA_FILE_BYTES`. That includes a share Windows could not reach
    (:func:`_names_no_file`), unless ``leave_unreachable`` says the driver will not read the file
    either: then :class:`_UnreachedShare` is raised.

    The file is read by :func:`~messagefoundry.auth.trust_anchors.read_if_regular`, which says
    how a device or pipe is judged without being read, or waited on."""
    try:
        data = read_if_regular(path, _MAX_DRIVER_CA_FILE_BYTES + 1)
    except ValueError:
        # A path os.stat cannot take, such as one holding a NUL: the driver cannot load it either.
        logger.debug("%s: no file at this spelling, so the engine does not check it", setting)
        return None
    except OSError as exc:
        # read_if_regular returns None for a directory it stats. One swapped in after that stat
        # can fail the open instead, as PermissionError on Windows, so the path is looked at
        # again after that failure alone: on a share Windows could not reach, a second look would
        # wait out the same network timeout again, on the event loop. A path through a file names
        # no file either. POSIX reports it as NotADirectoryError, which keywrap refused, so sslkey
        # still does; Windows reports it as a missing name, left to the driver.
        if isinstance(exc, NotADirectoryError) or (
            isinstance(exc, (PermissionError, IsADirectoryError)) and os.path.isdir(path)
        ):
            _irregular(setting, what, checked_for, error, leave_irregular)
            return None
        if _names_no_file(exc):
            logger.debug("%s: no file at this spelling, so the engine does not check it", setting)
            return None
        if leave_unreachable and getattr(exc, "winerror", None) in _WINDOWS_UNREACHABLE:
            logger.debug(
                "%s: the share was not reached, and the driver reads no such file", setting
            )
            raise _UnreachedShare from exc
        raise error(
            f"{setting}: the {what} could not be read to check {checked_for}: "
            f"{exc.strerror or type(exc).__name__}"
        ) from exc
    if data is None:  # a directory, device or pipe: judged by its stat, never read
        _irregular(setting, what, checked_for, error, leave_irregular)
        return None
    if len(data) > _MAX_DRIVER_CA_FILE_BYTES:
        raise error(
            f"{setting}: the {what} is larger than the {_MAX_DRIVER_CA_FILE_BYTES // 2**20} MiB "
            f"the engine reads to check {checked_for}"
        )
    return data


def _names_no_file(exc: OSError) -> bool:
    """Whether a failure to read one spelling of a driver file says no file is there, so the
    driver cannot load it either, rather than that a file is there the engine cannot check.

    A missing name counts, unless Windows reports it for a share it could not reach (53 and 67,
    as :mod:`messagefoundry.config.key_file_access` reads them): the driver may reach that file
    at a later connect. So does Windows' ``ERROR_INVALID_NAME``, a padded path for one, and only
    by that Win32 code: CPython maps every Win32 error it has no errno for to EINVAL, so testing
    errno would leave a real read failure unchecked. On POSIX an EINVAL is refused too, even from
    a filesystem that rejects a padded spelling with it, because errno cannot tell that from a
    failed read; that refuses the build rather than check the trimmed spelling."""
    winerror = getattr(exc, "winerror", None)
    if isinstance(exc, FileNotFoundError):
        return winerror not in _WINDOWS_UNREACHABLE
    return winerror == _WINDOWS_INVALID_NAME


def _irregular(
    setting: str, what: str, checked_for: str, error: type[ValueError], leave: bool
) -> None:
    """:func:`_read_driver_file`'s answer for a path that names no regular file."""
    if not leave:
        raise error(
            f"{setting}: the {what} could not be read to check {checked_for}: not a regular file"
        )
    logger.debug("%s: not a regular file, so the engine does not check it", setting)


def _build_odbc_dsn(s: dict[str, Any], *, connection: str | None = None) -> str:
    """Build a GENERIC ODBC connection string (``dialect='generic'``, #66) — decoupled from the ODBC
    Driver 18 / T-SQL preset so a DB reached through its own ODBC driver (PostgreSQL, MySQL) works. The
    operator installs the target ODBC driver at the OS level and names it here.

    The operator supplies the ODBC ``odbc_driver`` name + an ``odbc_params`` mapping of driver keywords
    (PORT, SSLmode, …). ``server`` (the ``[egress].allowed_db`` allowlist key) is emitted as the
    near-universal ``SERVER`` keyword and ``database`` as ``DATABASE`` when set; credentials come from the
    top-level ``username``/``password`` settings (``env()``-resolved + secret-redacted) under the
    ``odbc_user_key``/``odbc_password_key`` keyword names (default ``UID``/``PWD``).

    **The keyword lists cover keywords only, and rely on at least a driver named on the escape list
    reading the ``}}`` escape in a braced password, and the driver reading ``SERVER`` as its target**
    (vault BACKLOG #2577, BACKLOG #2705; docs/CONNECTIONS.md, *Accepted ``odbc_params`` keywords*). An ``odbc_params`` keyword
    must be on :data:`_ODBC_PARAM_ALLOWLIST`, and a credential keyword that is sent on its own short list, or
    the build is refused with the keyword and the connection named. An ``odbc_params`` keyword given
    twice is refused. A driver may take its target under a keyword other than ``SERVER``, and the
    engine does not detect that. The egress check runs outside this builder, at least in
    ``build_source`` and ``build_destination`` (``transports.base``). This builder sends ``server``
    as written.

    Every value must be printable ASCII (STORE-5 injection guard). ``database``, ``username`` and
    every ``odbc_params`` value are sent WITHOUT braces (:func:`_odbc_literal`, BACKLOG #2705), so
    they refuse at least ``;``, ``{``, ``}``, ``=``, a quote, an empty or blank value and a leading
    or trailing space. ``server`` and every ``odbc_params`` value also refuse ``None``, an
    ``odbc_params`` value refuses a boolean, and ``sslmode`` takes only the spellings
    :func:`_refuse_unread_sslmode` accepts for the driver. ``odbc_driver`` is braced and
    refuses ``;``, ``{`` and ``}``. ``password`` is always braced with the ``}}`` escape for a driver
    on the escape list, and otherwise sent plain when it can be and refused when it cannot
    (:func:`_odbc_password`).

    **TLS is the operator's responsibility on this path.** MessageFoundry cannot introspect an arbitrary
    driver's TLS posture the way it reads SQL Server's ``Encrypt``/``TrustServerCertificate``, so the
    weakened-TLS refusal (:func:`_build_dsn`) does not apply here — configure verifying TLS via the
    driver's own keyword in ``odbc_params`` (e.g. psqlODBC ``SSLmode=verify-full``, MySQL
    ``SSLMODE=VERIFY_IDENTITY``). Because that delegation is otherwise invisible, construction logs it
    (:func:`_warn_generic_tls_unenforced`): a **WARNING** when ``odbc_params`` set no TLS mode or pin
    one to a no-TLS value, DEBUG otherwise.

    Delegating TLS is not the same as declining to gate the hop. A connection whose ``odbc_params`` say
    TLS is **not required**, or set no mode at all, is refused off-loopback on an enforcing instance by
    :func:`generic_cleartext_hop_guard` (BACKLOG #1178), which the connectors call beside this builder.
    What stays delegated is the case this path genuinely cannot judge: a mode keyword IS set, and the
    engine cannot tell whether its value verifies anything. See docs/CONNECTIONS.md."""
    driver = str(s.get("odbc_driver") or "").strip()
    where = hop_name_prefix(connection)
    if not driver:
        raise ValueError(f"{where}DATABASE generic dialect requires an 'odbc_driver' setting")
    # SERVER is emitted UNBRACED (validated, not brace-quoted) so a driver that parses a ",port"/":port"
    # suffix in SERVER can resolve the host — mirrors the SQL Server preset's rationale.
    _refuse_none(s["server"], what="server", connection=connection)
    server = str(s["server"])
    if _odbc_unsafe_text(server, _ODBC_UNBRACED_REFUSED):
        raise ValueError(
            f"{where}DATABASE server must not contain ';', '{{', '}}', '=', a quote, a control "
            "character or a non-ASCII character (ODBC injection risk)"
        )
    # The driver name stays braced: names hold spaces and parentheses, and no probe found a driver
    # manager that reads a braced DRIVER wrongly. The delimiters are still refused, not escaped.
    _refuse_unsafe_text(driver, what="odbc_driver", connection=connection, refused=";{}")
    parts = [f"DRIVER={odbc_brace(driver)}", f"SERVER={server}"]
    if s.get("database"):
        database = _odbc_literal(s["database"], what="database", connection=connection)
        parts.append(f"DATABASE={database}")
    username = s.get("username")
    if username:
        user_key = _odbc_credential_keyword(
            s.get("odbc_user_key", "UID"), "odbc_user_key", _ODBC_USER_KEYS, connection=connection
        )
        parts.append(
            f"{user_key}={_odbc_literal(username, what='username', connection=connection)}"
        )
    password = s.get("password")
    if password:
        pwd_key = _odbc_credential_keyword(
            s.get("odbc_password_key", "PWD"),
            "odbc_password_key",
            _ODBC_PASSWORD_KEYS,
            connection=connection,
        )
        secret = _odbc_password(password, driver=driver, connection=connection)
        parts.append(f"{pwd_key}={secret}")
    params = s.get("odbc_params") or {}
    if not isinstance(params, Mapping):
        raise ValueError(f"{where}DATABASE odbc_params must be a mapping of ODBC keyword -> value")
    named: dict[str, Any] = {}
    for key, value in params.items():
        k = _odbc_keyword(str(key), what="odbc_params key", connection=connection)
        name = odbc_keyword_name(k)
        if name not in _ODBC_PARAM_ALLOWLIST:
            raise ValueError(
                # `;` after the keyword, never `:` or `=`: the log scrub reads `<credential word>: x`
                # as a credential pair, and a refused keyword may end in such a word. Kept short:
                # a stored failure keeps about the first 200 characters.
                f"{where}DATABASE odbc_params must not set '{name}'; it is not an accepted keyword "
                "(see Generic ODBC in docs/CONNECTIONS.md). The host comes from 'server'."
            )
        if name in named:
            raise ValueError(
                f"{where}DATABASE odbc_params names {name} more than once "
                "(keywords are case-insensitive); give it once"
            )
        # Before anything reads the value: the remote-path screen reads its str() too.
        _refuse_none(value, what=f"odbc_params value for '{name}'", connection=connection)
        if isinstance(value, bool):
            # str() would send True or False, which no driver is known to spell its own way
            # (psqlODBC reads SSLmode=True as disable). BACKLOG #2705.
            raise ValueError(
                f"{where}DATABASE odbc_params value for '{name}' must not be a boolean; write the "
                "driver's own spelling as a string"
            )
        named[name] = value
        literal = _odbc_literal(
            value, what=f"odbc_params value for '{name}'", connection=connection
        )
        if name == "sslmode":
            _refuse_unread_sslmode(literal, driver=driver, connection=connection)
        parts.append(f"{k}={literal}")
    # After the loop on purpose: these open the key and CA files, so the keywords are settled first.
    # Each file keyword is judged once, here, and every check below reads that judgement.
    verdicts = _refuse_remote_paths(named, connection=connection)
    _refuse_weak_driver_key(named, connection=connection, verdicts=verdicts)
    _refuse_weak_driver_cert(named, connection=connection, verdicts=verdicts)
    _refuse_encrypted_driver_ca(named, connection=connection, verdicts=verdicts)
    _warn_generic_tls_unenforced(params, connection=connection)
    return ";".join(parts) + ";"


def _warn_generic_tls_unenforced(
    params: Mapping[str, Any], *, connection: str | None = None
) -> None:
    """Fail-safe visibility for the generic ODBC dialect (#66 review): unlike the SQL Server preset, this
    path **cannot introspect the driver's TLS posture**, so the posture-keyed weakened-TLS refusal
    (#200 / ADR 0092) does not apply and :func:`_build_connection` reports the hop as non-weakened. That
    is a deliberate operator-owned-TLS model.

    So at construction we log the delegation: a **WARNING** when :func:`generic_odbc_tls_unenforced`
    says the hop may cross in plaintext — no TLS mode in ``odbc_params``, or one pinned to a no-TLS
    value like ``SSLmode=disable`` — dropped to **DEBUG** when that function returns ``None``.

    **This line is visibility, not the control.** It never gates or changes the connection, and until
    BACKLOG #1178 it was the whole of what stood between a generic PHI connection with no TLS keyword
    and a plaintext crossing. The refusal now lives in :func:`generic_cleartext_hop_guard`, which puts
    the same classifier's verdict through the shared hop authority. This still fires beside that gate,
    and it is the ONLY report on the arm the gate no-ops: an unstamped posture, such as a direct
    embedding or test build. The runner stamps its live serve builds, so they reach the gate.

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
            "%s: TLS is delegated to the driver (a TLS mode is set in odbc_params); "
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


def generic_cleartext_hop_guard(
    settings: Mapping[str, Any],
    *,
    cell: str,
    attested: bool,
    attested_reason: str | None,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
    connection: str | None,
) -> InsecureHopGuard | None:
    """The cleartext-hop guard for a generic-ODBC ``DATABASE`` connection, or ``None`` when there is
    nothing on this arm to gate (BACKLOG #1178).

    ``None`` covers two different situations. A non-``generic`` dialect is not this arm at all — the SQL
    Server preset keeps its own posture-keyed weakened-TLS refusal in :func:`_build_dsn`. A generic
    connection returns ``None`` when :func:`generic_odbc_tls_unenforced` does, because it found no reason to think the hop crosses in plaintext; the
    engine still cannot VERIFY an arbitrary driver's keyword, and that residual is unchanged and
    written down above :data:`_ODBC_NO_TLS_VALUES`.

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
    host, port = generic_hop_endpoint(str(settings.get("server") or ""), params)
    return InsecureHopGuard.capture(
        host=host,
        port=port,
        cell=cell,
        # The classifier's reason rides in the description so the refusal names WHAT is unset, not just
        # that something is: the remedy is a specific driver keyword.
        # Not "ODBC DATABASE": the log redaction scrubs two adjacent ALL-CAPS tokens.
        description=f"cleartext generic-ODBC hop to a database ({reason})",
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
        weakened = bool(s.get("trust_server_certificate", False)) or not bool_setting(
            s, "encrypt", default=True
        )
        return (
            _build_dsn(s, read_only=read_only, attested=attested, connection=connection),
            weakened,
        )
    if dialect == "generic":
        return _build_odbc_dsn(s, connection=connection), False
    raise ValueError(f"DATABASE dialect must be 'sqlserver' or 'generic', got {dialect!r}")


# One bare SQL word token. The T-SQL sigils (`@var`, `@@ROWCOUNT`, `#temp`) are part of the token, so
# `#delete` reads as one identifier rather than as the `DELETE` keyword.
_SQL_WORD_RE = re.compile(r"[@#]{0,2}[A-Za-z_][A-Za-z0-9_$#@]*")

# Write/authority keywords refused anywhere outside a string literal, a quoted identifier or a comment.
# `INTO` is here because `SELECT ... INTO copy` writes a table while still opening with `SELECT`; the
# CTE-terminal forms (`WITH c AS (...) DELETE ...`) fall to the same scan. DDL is included for the
# reason a chained `DROP` is refused: a lookup has no business carrying it.
_SQL_WRITE_KEYWORDS = frozenset(
    {
        "ALTER",
        "CREATE",
        "DELETE",
        "DENY",
        "DROP",
        "EXEC",
        "EXECUTE",
        "GRANT",
        "INSERT",
        "INTO",
        "MERGE",
        "REVOKE",
        "TRUNCATE",
        "UPDATE",
    }
)

# Keywords that are also ordinary scalar FUNCTIONS in at least one supported dialect, so a `(` directly
# after one means a call rather than a statement: MySQL has `INSERT(str,pos,len,new)` and
# `TRUNCATE(n,d)`. `EXEC`/`EXECUTE` are deliberately NOT here — T-SQL `EXEC('...')` is dynamic SQL,
# the exact shape this gate exists to refuse.
_SQL_FUNCTION_FORM_KEYWORDS = frozenset({"INSERT", "TRUNCATE"})


def _read_only_message(subject: str) -> str:
    """The refusal :func:`_require_read_only` raises, naming whose statement it refused."""
    return (
        f"{subject} must be a read-only SELECT/WITH query "
        "(no writes, no EXEC, no multiple statements)"
    )


def _scan_sql_tokens(
    statement: str, *, subject: str = "db_lookup statement"
) -> list[tuple[str, str]]:
    """Tokenize ``statement`` into ``(kind, text)`` pairs, dropping comments and the contents of string
    literals and quoted identifiers.

    ``kind`` is ``"word"`` (text upper-cased) or ``"other"`` (one character, ``;`` included).
    Single-quoted strings and double-quoted / ``[...]``-bracketed / backtick-quoted identifiers are
    consumed whole, doubled-delimiter escapes included, so a keyword *inside* one is data and never a
    token. T-SQL block comments nest, so the scan tracks depth.

    An unterminated literal or comment raises :class:`DbLookupError`: the rest of such a statement
    cannot be read, and guessing at it is how a shape-based gate gets bypassed. ``subject`` names
    whose statement it is in that refusal."""
    refusal = _read_only_message(subject)
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(statement)
    while i < n:
        ch = statement[i]
        if ch.isspace():
            i += 1
            continue
        if statement.startswith("--", i):
            nl = statement.find("\n", i)
            i = n if nl == -1 else nl + 1
            continue
        if statement.startswith("/*", i):
            depth, i = 1, i + 2
            while i < n and depth:
                if statement.startswith("/*", i):
                    depth, i = depth + 1, i + 2
                elif statement.startswith("*/", i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            if depth:
                raise DbLookupError(f"{refusal}; unterminated block comment")
            continue
        if ch in "'\"[`":
            closer = "]" if ch == "[" else ch
            i += 1
            while True:
                if i >= n:
                    raise DbLookupError(f"{refusal}; unterminated quoted text")
                if statement[i] == closer:
                    if i + 1 < n and statement[i + 1] == closer:  # doubled = an escaped delimiter
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            continue
        m = _SQL_WORD_RE.match(statement, i)
        if m:
            tokens.append(("word", m.group(0).upper()))
            i = m.end()
            continue
        tokens.append(("other", ch))
        i += 1
    return tokens


def _require_read_only(statement: str, *, subject: str = "db_lookup statement") -> None:
    """Test a db_lookup statement's shape for the ADR 0010 read-only carve-out. Defence in depth only,
    like ``ApplicationIntent=ReadOnly``. A read-only login is the control (``docs/CONNECTIONS.md``).

    A ``DatabaseRef`` statement goes through the same test (BACKLOG #2617), with ``subject`` naming it
    in the refusal. So a stored-procedure ``DatabaseRef`` is refused, as a stored-procedure lookup is.

    The statement is tokenized (:func:`_scan_sql_tokens`), so comments, string literals and quoted
    identifiers are skipped, and then three rules apply:

    1. it must *begin* (after comments and whitespace) with the word ``SELECT`` or ``WITH``;
    2. no write or authority keyword (at least ``INSERT``/``UPDATE``/``DELETE``/``MERGE``/``INTO``/
       ``EXEC``, plus DDL — :data:`_SQL_WRITE_KEYWORDS`) may appear outside a literal or a comment;
    3. nothing may follow a ``;`` (no chained second statement); a trailing one is fine.

    Rule 2 is what makes this a read-only test rather than a leading-token test. Opening with ``SELECT``
    or ``WITH`` never implied the rest was a read: ``SELECT * INTO copy FROM patients`` writes a table,
    ``WITH c AS (...) DELETE FROM patients`` writes through a CTE, and T-SQL needs no ``;`` between
    statements, so ``SELECT 1 UPDATE patients SET mrn='X'`` is two statements that rule 3 cannot see.
    All three passed the former leading-token gate (BACKLOG #1574, #1658).

    This is still a lightweight gate and not a SQL parser, and a statement test is not read-only
    *authority*: a keyword scan cannot follow a write executed on a linked server through a
    pass-through literal, so the account itself should be read-only (``docs/CONNECTIONS.md``). Raises
    :class:`DbLookupError` on violation. The message stays PHI-free — it never echoes statement text,
    and any keyword it names comes from the fixed vocabulary above, never from operator data."""
    refusal = _read_only_message(subject)
    tokens = _scan_sql_tokens(statement, subject=subject)
    if not tokens or tokens[0] not in (("word", "SELECT"), ("word", "WITH")):
        raise DbLookupError(refusal)
    last = len(tokens) - 1
    for index, (kind, text) in enumerate(tokens):
        if kind != "word":
            # A ';' is tolerated only as the final token (a statement terminator); anything after one
            # is a second statement, whatever that statement starts with.
            if text == ";" and index != last:
                raise DbLookupError(refusal)
            continue
        if text not in _SQL_WRITE_KEYWORDS:
            continue
        if (
            text in _SQL_FUNCTION_FORM_KEYWORDS
            and index != last
            and tokens[index + 1] == ("other", "(")
        ):
            continue  # a scalar function call that shares the keyword's name, not a statement
        raise DbLookupError(f"{refusal}; found a '{text}' keyword")
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
    # No chain: the decode error holds the whole payload (BACKLOG #2085). json's own text is a fixed
    # reason and a position, so the stored detail keeps it. json's RecursionError is a permanent
    # payload refusal here too, not an escape.
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        refused: str | None = str(exc)
    except RecursionError:
        refused = "nested too deeply to parse"
    else:
        refused = None
    if refused is not None:
        raise NegativeAckError(
            f"DATABASE payload is not valid JSON: {refused}", code="payload", permanent=True
        )
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


# The native error code an ODBC driver appends to its own message text, ANCHORED on the trailing
# ``(SQLFunctionName)`` the driver always writes after it — ``... (2627) (SQLExecDirectW)``. Both the
# SQL Server driver and psqlODBC use this shape, which is why :func:`_driver_code` can share one
# pattern with :func:`messagefoundry.store.sqlserver._is_lock_timeout`'s substring convention.
#
# THE ANCHOR AND THE DIGIT BOUND ARE THE WHOLE POINT, not tidiness (BACKLOG #1661). A bare
# ``\((\d+)\)`` lifts ``(900123456)`` straight out of ``The duplicate key value is (900123456).`` —
# it would re-introduce, through the extractor, exactly the leak this function stopped interpolating.
# So: at most six digits, an ODBC function name required immediately after, and the LAST match wins
# (the driver's suffix is always last, so a crafted value earlier in the text cannot outrank it).
# *Residual:* a partner-supplied value ending in a literal ``) (SQLx`` could still present 1-6 of its
# own digits here. It is self-chosen, bounded to six characters, and no real driver text ends that
# way; the alternative — dropping the code — costs the operator the only field that separates a PK
# violation (2627) from a unique-index violation (2601) under one generic SQLSTATE.
_DRIVER_CODE_RE = re.compile(r"\((\d{1,6})\)\s*\(SQL[A-Za-z]+\)")


def _driver_code(message: str) -> str | None:
    """The driver's native error number from ``message``, or ``None`` when it carries none."""
    found = _DRIVER_CODE_RE.findall(message)
    return str(found[-1]) if found else None


def _classify_db_error(sqlstate: str, message: str) -> DeliveryError:
    """Map a DB error's SQLSTATE to a transient :class:`DeliveryError` (retry) or a permanent
    :class:`NegativeAckError` (dead-letter), with **PHI-free** text.

    ``message`` is read for its SQLSTATE and native error number and is **never interpolated**
    (BACKLOG #1661). Driver text embeds the offending value on exactly the failures this connector
    meets most — SQL Server 2627/2601 (``The duplicate key value is (...)``) and PostgreSQL 23505
    (``Key (mrn)=(...) already exists``) — and the returned error is persisted to ``queue.last_error``
    and ``message_events.detail`` and rendered into the ``connection_error`` alert, so interpolating
    it would carry a partner's identifier into all three on a first deployment. The same rule the
    ``db_lookup`` arm already follows: name the SQLSTATE, never the statement, params or rows."""
    code = _driver_code(message)
    detail = f"[{sqlstate}]" + (f" driver error {code}" if code else "")
    if _is_transient(sqlstate):
        return DeliveryError(f"database transient error {detail}")
    return NegativeAckError(
        f"database rejected the statement {detail}",
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


def _log_sqlstate(exc: BaseException) -> str | None:
    """The SQLSTATE a log line may name for ``exc``, or ``None`` when it is not read as a driver
    error: asyncpg's ``sqlstate`` attribute, else :func:`_sqlstate`'s ``args[0]``.

    Never for a ``UnicodeError`` or an exception that holds one. ``UnicodeEncodeError``'s first
    argument is the codec name, and ``ascii`` is five alphanumerics, so it would read as one."""
    if isinstance(exc, UnicodeError) or prints_a_codec_error(exc):
        return None
    state = getattr(exc, "sqlstate", None)
    if isinstance(state, str) and len(state) == 5 and state.isalnum():
        return state
    return _sqlstate(exc)


def _safe_db_error(exc: BaseException) -> str:
    """A PHI-free rendering of a failure for a LOG line, the log-side twin of
    :func:`_classify_db_error` (BACKLOG #1661).

    A driver error renders as its type, SQLSTATE and native error number — the message is read, never
    quoted. ``safe_exc`` is NOT enough on its own here and the difference is measured: fed the SQL
    Server 2627 text, it keeps ``Cannot insert duplicate key ... The duplicate key value is (4242``
    because ``redact`` sees no HL7 delimiters and no name run, and the 200-character bound cuts the
    identifier in the middle rather than removing it. asyncpg's errors, from a PostgreSQL store,
    count too: their ``str()`` appends a ``DETAIL`` that quotes the key. Anything else with no
    SQLSTATE (:func:`_log_sqlstate`) keeps the ``safe_exc`` rendering, which is the more useful text
    for a bug or an unreachable host. That is a bound, not a guarantee: an error from another driver
    that quotes a value and carries no SQLSTATE in either place is printed as ``safe_exc`` prints it.

    A Unicode error, or an exception holding one, always takes ``safe_exc``, so this never prints a
    codec error's text; ``tests/test_unicode_error_log_paths.py`` counts it among the safe renderers
    for that reason.

    It never raises. Its callers are error arms and helpers documented never to raise, and an
    exception whose ``__str__`` raises renders as its type and a fixed note instead."""
    try:
        state = _log_sqlstate(exc)
        if state is None:
            return safe_exc(exc)
        code = _driver_code(str(exc))
    except Exception as failure:  # noqa: BLE001 - see docstring
        return (
            f"{type(exc).__name__} [message withheld: {type(failure).__name__} while rendering it]"
        )
    return f"{type(exc).__name__} [{state}]" + (f" driver error {code}" if code else "")


class RedactedDbError(Exception):
    """Stands in for one exception of a logged chain: the original's frames, and
    :func:`_safe_db_error`'s line as its message (BACKLOG #1661). Never raised. Unprefixed because
    its name prints on every line it stands in for."""


def _safe_db_exc_info(exc: BaseException) -> RedactedDbError:
    """An ``exc_info`` for ``exc`` that keeps every frame and cause but no driver message.

    ``logger.exception`` ends each exception of the chain with its ``str()``, and a driver error's
    ``str()`` is the text that embeds the offending value: a 2627 duplicate key, a 245 conversion.
    So each link is copied as a :class:`RedactedDbError` whose message is :func:`_safe_db_error`'s
    line, with the original's traceback and its cause, context and suppression wired the same way.
    The record then takes the logging chain's own path: ``prepare_log_record`` renders it into
    ``exc_text`` with the stdlib's walker, and the control-character scrub keeps its line breaks.

    What the copy loses: an exception group's members, any ``__notes__``, the stdlib's extra hints
    (``Did you mean``, a ``SyntaxError``'s location), each link's module name, and ``safe_exc``'s
    200-character bound applies to every non-driver line.

    It never raises, because it runs in the poll loop's error arm, which must not kill the poller.
    A copy that fails gives one :class:`RedactedDbError` with no frames, whose message names the
    failure, as ``prepare_log_record`` names its own."""
    try:
        return _redacted_copy(exc, {})
    except Exception as failure:  # noqa: BLE001 - see docstring: the poller outlives a failed render
        return RedactedDbError(
            f"[traceback withheld: {type(failure).__name__} while rendering {type(exc).__name__}]"
        )


def _redacted_copy(exc: BaseException, made: dict[int, RedactedDbError]) -> RedactedDbError:
    """``exc`` and its chain as :class:`RedactedDbError` copies. ``made`` closes a cycle."""
    found = made.get(id(exc))
    if found is not None:
        return found
    copy = RedactedDbError(_safe_db_error(exc)).with_traceback(exc.__traceback__)
    made[id(exc)] = copy
    if exc.__cause__ is not None:
        copy.__cause__ = _redacted_copy(exc.__cause__, made)
    if exc.__context__ is not None:
        copy.__context__ = _redacted_copy(exc.__context__, made)
    copy.__suppress_context__ = exc.__suppress_context__  # set last: a cause assignment sets it
    return copy


class _DriverMissingError(RuntimeError):
    """The ``[sqlserver]`` extra is not installed. A ``RuntimeError`` as before, named so a
    ``db_lookup`` can say so without quoting any error text (BACKLOG #2062)."""


def _import_aioodbc() -> Any:
    """Import the optional ``aioodbc`` driver, raising a clear install hint if the ``[sqlserver]`` extra
    isn't present — so a SQLite-only install never touches it until a DATABASE connector is actually used."""
    try:
        import aioodbc
    except ImportError as exc:
        raise _DriverMissingError(
            "DATABASE connector requires the 'sqlserver' extra: "
            "pip install 'messagefoundry[sqlserver]' (plus the Microsoft ODBC Driver 18)"
        ) from exc
    return aioodbc


def _login_timeout(s: Mapping[str, Any], label: str) -> int:
    """The login timeout, in seconds, for a DATABASE connection's pool: its ``connect_timeout``
    setting, for either dialect (BACKLOG #2089, #2705). Pool sites take it from here.

    **Why it is not in the DSN.** ODBC Driver 18 ignores a login-timeout keyword in the connection
    string; the comment in ``store/sqlserver.py::connection_string`` records the #1626
    measurement. The driver reads pyodbc's ``timeout=`` argument instead, and :func:`_make_pool`
    passes the value there.

    The ``generic`` dialect gets the same value since BACKLOG #2705; the ``connect_timeout`` row in
    docs/CONNECTIONS.md says which drivers were measured to honour it.

    ``connect_timeout`` is checked by :func:`check_db_connect_timeout` whatever the dialect, and
    ``label`` names the declaration in its refusal. The destination, poll source and lookup executor
    call this at construction, so ``serve`` and ``messagefoundry check`` refuse a bad value at start.
    ``DatabaseRef`` checks a literal value when it is declared; an ``env()`` value is checked here,
    at each sync, once resolved."""
    return check_db_connect_timeout(s.get("connect_timeout", DEFAULT_DB_CONNECT_TIMEOUT), label)


class AutocommitNotConfirmed(RuntimeError):
    """A connection from an autocommit pool could not be put in autocommit mode (BACKLOG #2148).

    The borrow is refused, and the connection goes back to its pool unconfirmed, so no statement runs
    on it until a later borrow has set the mode. A setter that raises a driver error raises that
    error instead, and its connection goes back unconfirmed the same way. The text names neither
    the DSN nor the server."""


def _thread_settled[T](fn: Callable[[], T], *, gate: CallGate | None = None) -> asyncio.Future[T]:
    """Run ``fn`` on a worker thread and return a future that the THREAD resolves, once ``fn`` has
    returned or raised.

    ``asyncio.to_thread`` gives back a coroutine whose cancellation says nothing about the thread:
    cancelled, it ends at once while ``fn`` runs on. This future is not a task, so no task cancel
    reaches it, loop teardown's cancel-every-task included. Its completion is therefore proof that
    ``fn`` is no longer running, which is what decides when a connection ``fn`` uses may go back to
    its pool (PR 2593 review). If the loop is closed before ``fn`` ends, nothing is left to tell.

    **With ``gate``, ``fn`` runs inside that connection's call gate** (BACKLOG #2394), so it never
    runs beside another pyodbc call on the connection. When a call is running there, as after a
    cancelled ``execute``, ``fn`` is handed to that call, which runs it on its own thread as it
    returns. So no second thread waits for a statement that may have no timeout. Otherwise ``fn``
    goes to a worker thread through the gate, as before."""
    loop = asyncio.get_running_loop()
    settled: asyncio.Future[T] = loop.create_future()

    def _resolve(value: T | None, error: BaseException | None) -> None:
        if settled.done():
            return
        if error is not None:
            settled.set_exception(error)
        else:
            settled.set_result(value)  # type: ignore[arg-type]

    def _work() -> None:
        value: T | None = None
        error: BaseException | None = None
        try:
            value = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the awaiting side, not swallowed
            error = exc
        try:
            loop.call_soon_threadsafe(_resolve, value, error)
        except RuntimeError:
            # The loop closed before the call ended, so nobody is left to settle its connection.
            # Logged from this thread, without the call's result or error text (CLAUDE.md
            # section 6): the connection is not returned, and that is all an operator needs.
            logger.warning(
                "DATABASE: a worker-thread database call ended after the event loop closed; its "
                "connection was not returned to its pool"
            )

    if gate is None:
        loop.run_in_executor(None, _work)
    elif not gate.run_after_running_call(_work):
        loop.run_in_executor(None, partial(gate.run, _work))
    return settled


def _driver_connection(conn: Any) -> Any:
    """``conn``'s pyodbc connection (aioodbc 0.5.0's ``_conn``), or :class:`AutocommitNotConfirmed`
    when it has none, since a connection whose mode cannot be set is refused rather than trusted."""
    raw = getattr(conn, "_conn", None)
    if raw is None:
        raise AutocommitNotConfirmed(
            "DATABASE: a pooled connection exposes no driver connection, so it cannot be put in "
            "autocommit mode; refusing to run a statement on it"
        )
    return raw


def _set_and_read_autocommit(raw: Any) -> bool:
    """Set autocommit on a pyodbc connection, then read it back (BACKLOG #2148). Runs on a worker
    thread, through :func:`_thread_settled`; ``False`` means the set did not take.

    Follows ``store/sqlserver.py``'s ``_assert_autocommit``, and adds the read-back and the refusal.
    ``autocommit=True`` at pool creation is not enough on its own: pyodbc sends
    ``SQL_ATTR_AUTOCOMMIT`` only to turn autocommit OFF, and otherwise trusts the driver's default.
    Setting it here sends it to the driver every time. A driver that rejects the set raises its own
    error from the setter.

    **What the read-back proves is narrow.** It reads pyodbc's own record of the mode, which pyodbc
    writes only after the driver accepted the set. So with pyodbc it cannot come back False; it
    guards the binding (a ``_conn`` that is not pyodbc's, or a later pyodbc that stops recording the
    mode), not the server session. The control is the set itself.

    Setting ``SQL_AUTOCOMMIT_ON`` is valid on every ODBC driver, including one with no transaction
    support, for which ON is the only valid value (the ODBC ``SQLSetConnectAttr`` reference)."""
    raw.autocommit = True
    return bool(raw.autocommit)


def _unwinding_a_cancel() -> bool:
    """Whether the running task has a cancellation in flight, as when a ``finally`` runs because a
    statement's await was cancelled. That statement may still be running on its worker thread."""
    task = asyncio.current_task()
    return task is not None and task.cancelling() > 0


async def _return_to_pool(pool: Any, conn: Any) -> None:
    """Hand ``conn`` back to ``pool`` where no borrower holds it any more. Call it only once no
    worker thread can still be using ``conn`` (the rule :func:`_return_when_settled` enforces).
    Never raises: the caller, if any, is already raising its own reason.

    A connection whose autocommit was not confirmed is returned, not closed. It is not marked
    confirmed, so its next borrow sets autocommit again before any statement runs on it, and refuses
    again if the driver still rejects the set. Closing it would add nothing to that rule, and
    aioodbc's own release of an open connection is what wakes a borrower waiting for a free slot."""
    try:
        await pool.release(conn)
    except Exception as exc:  # noqa: BLE001 - no borrower is left to tell
        # WARNING, not DEBUG: a failed return leaks a pool slot, and main logged it so (PR 2560).
        logger.warning("DATABASE: returning a pooled connection failed: %s", _safe_db_error(exc))


#: Connections returned after their borrower stopped waiting. The loop holds a task only weakly
#: (ruff RUF006), so this set keeps each one alive until it ends.
_DETACHED_SETTLES: set[asyncio.Task[None]] = set()


def _detach(coro: Coroutine[Any, Any, None]) -> None:
    """Run ``coro`` with no awaiting caller, kept alive in :data:`_DETACHED_SETTLES` until it ends."""
    task = asyncio.ensure_future(coro)
    _DETACHED_SETTLES.add(task)
    task.add_done_callback(_DETACHED_SETTLES.discard)


#: How many connections each pool has held back behind a cancelled borrow (BACKLOG #2394): ones
#: :func:`_return_when_settled` or an abandoned autocommit set keeps out of the pool until a driver
#: call returns. Keyed by the aioodbc pool itself, never the :class:`_AutocommitPool` wrapper, so a
#: borrow and a close of one pool read one count whichever object each holds (:func:`_pool_key`).
#: Weak, so a pool nothing else holds drops out. :func:`_close_pool_bounded` stops waiting at a bound
#: only while this is above zero.
_HELD_BACK: weakref.WeakKeyDictionary[Any, int] = weakref.WeakKeyDictionary()


def _pool_key(pool: Any) -> Any:
    """The aioodbc pool under ``pool``: the object :data:`_HELD_BACK` counts against."""
    return pool._pool if isinstance(pool, _AutocommitPool) else pool


def _adjust_held(pool: Any, delta: int) -> None:
    """Move ``pool``'s held-back count by ``delta``, dropping its entry at zero."""
    key = _pool_key(pool)
    try:
        left = _HELD_BACK.get(key, 0) + delta
        if left > 0:
            _HELD_BACK[key] = left
        else:
            _HELD_BACK.pop(key, None)
    except TypeError:
        # A pool that cannot be weakly keyed is not counted, so its close waits unbounded, as
        # before BACKLOG #2394. Logged once per hold, since that wait can outlast a hung statement.
        if delta > 0:
            logger.warning("DATABASE: a held-back connection could not be counted against its pool")


def _hold_back(pool: Any) -> None:
    """Count one more connection of ``pool`` held back behind a cancelled borrow."""
    _adjust_held(pool, 1)


def _settle_held(pool: Any) -> None:
    """Count one connection of ``pool`` no longer held back: it went back, or its return ended."""
    _adjust_held(pool, -1)


def _holds_back(pool: Any) -> int:
    """How many connections of ``pool`` are held back behind a cancelled borrow now."""
    try:
        return _HELD_BACK.get(_pool_key(pool), 0)
    except TypeError:
        return 0


async def _return_held(pool: Any, conn: Any) -> None:
    """Return a held-back ``conn`` to ``pool``, then take it off the count, even if the return is
    itself cancelled, so a later close of the pool waits as it would have before the cancel."""
    try:
        await _return_to_pool(pool, conn)
    finally:
        _settle_held(pool)


def _return_when_settled(pool: Any, conn: Any, work: asyncio.Future[Any], what: str) -> None:
    """Once ``work`` is done, return ``conn`` to ``pool``, but only if ``work`` ending proves the
    worker thread it waited on has finished with ``conn`` (PR 2593 review).

    Until then ``conn`` counts as held back (:func:`_hold_back`), so a close of ``pool`` stops
    waiting at :data:`_POOL_CLOSE_TIMEOUT_S` instead of waiting as long as the call runs. A
    connection this keeps out for good stays counted, since its pool can then never finish closing.

    **Never return a connection while a worker thread may still be using it.** A thread inside a
    pyodbc call on a connection the pool hands to the next borrower is concurrent use of one ODBC
    handle, the crash shape BACKLOG #2049 recorded. A ``work`` the thread resolved
    (:func:`_thread_settled`) proves it, and is never cancelled, so on that path the connection
    always goes back. Only the fallback for a cursor with no raw pyodbc cursor (a test double, or an
    aioodbc that renamed ``_impl``) passes a task, and a CANCELLED task proves nothing: loop
    teardown cancels every task and leaves the thread running. That connection is kept out of the
    pool, and logged. Not closed either, since that is the same crash. It then holds any
    ``wait_closed`` on its pool, so this fallback is a known cost, logged when it happens."""

    def _done(finished: asyncio.Future[Any]) -> None:
        if finished.cancelled():
            logger.warning(
                "DATABASE: %s was cancelled before its worker thread was known to have ended, so the "
                "connection is kept out of the pool rather than handed to another borrower",
                what,
            )
            return
        _detach(_return_held(pool, conn))

    _hold_back(pool)
    work.add_done_callback(_done)


class _ConfirmedAcquire:
    """What :meth:`_AutocommitPool.acquire` returns: awaitable, like aioodbc's own acquire, and an
    async context manager that releases on exit, so ``async with pool.acquire()`` keeps working."""

    __slots__ = ("_conn", "_pool")

    def __init__(self, pool: _AutocommitPool) -> None:
        self._pool = pool
        self._conn: Any = None

    def __await__(self) -> Generator[Any, None, Any]:
        return self._pool._acquire_confirmed().__await__()

    async def __aenter__(self) -> Any:
        self._conn = await self._pool._acquire_confirmed()
        return self._conn

    async def __aexit__(self, *exc_info: object) -> None:
        conn, self._conn = self._conn, None
        await self._pool.release(conn)


class _AutocommitPool:
    """An aioodbc pool whose every borrowed connection has passed :func:`_set_and_read_autocommit`
    (BACKLOG #2148). :func:`_make_pool` returns one for ``autocommit=True``, which covers the poll
    source's mark pool, the ``db_lookup`` pools and the ``DatabaseRef`` sync pool. The check is in the
    borrow, so a call site cannot skip it. Everything else passes through.

    **Once per physical connection, not once per borrow.** A connection that passed is remembered,
    weakly, and later borrows of it skip the driver call. Nothing the engine runs on these pools
    turns autocommit off, so the mode pyodbc set holds while the connection sits in the pool. An
    operator statement that changes the session's own transaction mode is outside this check. A
    connection object that cannot be held weakly is confirmed on every borrow instead.

    **A borrower that stops waiting leaves the connection alone until the driver call returns.** The
    call runs on a worker thread and may still be inside the driver when ``acquire_timeout`` expires
    or the task is cancelled. Releasing or closing the connection then would let another call reach
    it, or free handles the running call is using, the crash shape BACKLOG #2049 recorded. So the call
    runs on :func:`_thread_settled`, whose future only the thread resolves, and is shielded: the
    borrower leaves at once, so ``acquire_timeout`` still bounds the borrow, and the connection goes
    back to the pool only once the call has returned. No task cancel can decide that early, loop
    teardown's included (PR 2593 review). The call also runs through the connection's call gate,
    installed at the borrow (BACKLOG #2394), so no other pyodbc call on that connection, a close
    included, runs beside it.

    **What that does not bound.** Until a hung call returns, its connection is still in use, so a
    close of this pool waits for it. Every close of this pool goes through
    :func:`_close_pool_bounded`, which stops waiting at a bound only while a connection is held back
    behind a cancelled borrow (BACKLOG #2394), and the source's stop after a cancel always does.
    Otherwise the close waits for the call to return: that wait is the price of never freeing a
    connection under a running driver call."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._confirmed: weakref.WeakSet[Any] = weakref.WeakSet()

    def acquire(self) -> _ConfirmedAcquire:
        return _ConfirmedAcquire(self)

    def _mark_confirmed(self, conn: Any) -> None:
        # Not weakly referenceable: it is confirmed on every borrow instead.
        with contextlib.suppress(TypeError):
            self._confirmed.add(conn)

    async def _acquire_confirmed(self) -> Any:
        conn = await self._pool.acquire()
        # BACKLOG #2394: here, not only in _acquire, because a DatabaseRef sync borrows through
        # acquire_pooled, and because the set below goes through the gate.
        install_call_gate(conn)
        if conn in self._confirmed:  # False, not an error, for an object with no weak reference
            return conn
        try:
            # No driver call has run on it before this succeeds: _thread_settled raises at once
            # if the default executor is already shut down, and neither starts a thread then.
            raw = _driver_connection(conn)
            # Through the gate (BACKLOG #2394): the set uses the raw handle, which aioodbc's gated
            # _execute never sees.
            work = _thread_settled(partial(_set_and_read_autocommit, raw), gate=call_gate(conn))
        except (AutocommitNotConfirmed, RuntimeError):
            await _return_to_pool(self._pool, conn)
            raise
        try:
            kept = await asyncio.shield(work)
        except BaseException as exc:
            if work.done() and isinstance(exc, Exception):
                # The thread resolved ``work`` with a driver error, so no call is running on it.
                # Returned open, not closed: a close here is itself a worker-thread call that a
                # cancellation could abandon, and aioodbc wakes no waiter for a closed connection.
                await _return_to_pool(self._pool, conn)
            else:
                # The borrower left (a cancel, or the coroutine closed) while the thread may still
                # be inside the setter. Settled when the thread resolves ``work``, never sooner,
                # and with no await here, so GeneratorExit is let through too. Counted as held
                # back meanwhile, so a close of this pool does not wait out a hung set.
                _hold_back(self._pool)
                work.add_done_callback(partial(self._settle_detached, conn))
            raise
        if not kept:
            await _return_to_pool(self._pool, conn)
            raise AutocommitNotConfirmed(
                "DATABASE: a pooled connection did not keep autocommit mode after it was set; "
                "refusing to run a statement on it"
            )
        self._mark_confirmed(conn)
        return conn

    def _settle_detached(self, conn: Any, work: asyncio.Future[bool]) -> None:
        """Settle ``conn`` once the thread has resolved a set its borrower abandoned: marked
        confirmed and returned if it passed, otherwise logged (no borrower is left to raise to,
        CLAUDE.md section 6) and returned unconfirmed, so its next borrow sets it again. A done
        callback, so it never raises. ``work`` is a :func:`_thread_settled` future, which only
        its thread completes, so this runs only once the setter has returned (PR 2593 review)."""
        if work.cancelled():  # nothing cancels a _thread_settled future; refuse to guess if one is
            logger.warning(
                "DATABASE: an abandoned autocommit set was cancelled before its worker thread was "
                "known to have ended, so the connection is kept out of the pool"
            )
            return
        failure = work.exception()
        if failure is None and work.result():
            self._mark_confirmed(conn)
            _detach(_return_held(self._pool, conn))
            return
        logger.warning(
            "DATABASE: an abandoned borrow's autocommit set did not pass (%s); the connection goes "
            "back unconfirmed and is set again on its next borrow",
            "not kept" if failure is None else safe_exc(failure),
        )
        _detach(_return_held(self._pool, conn))

    async def release(self, conn: Any) -> None:
        await self._pool.release(conn)

    def close(self) -> None:
        self._pool.close()

    async def wait_closed(self) -> None:
        await self._pool.wait_closed()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._pool, name)


async def _make_pool(dsn: str, pool_max: int, *, autocommit: bool, login_timeout: int) -> Any:
    """Create an aioodbc connection pool for ``dsn`` (lazy driver import). The destination wraps
    execute+commit itself (``autocommit=False``); the source marks each row in its own auto-committed
    statement (``autocommit=True``).

    ``login_timeout`` is required, and callers take it from :func:`_login_timeout`, so no pool site
    can quietly go without one. aioodbc forwards ``timeout=`` to every ``pyodbc.connect`` the pool
    makes, for the SQL Server preset and the generic dialect alike (BACKLOG #2705).

    **An ``autocommit=True`` pool is wrapped in :class:`_AutocommitPool`** (BACKLOG #2148), so every
    connection it hands out has autocommit set and read back first. The suspected cause is mostly
    closed already, and the set is kept anyway. The suspicion was ODBC driver-manager pooling handing
    back a physical connection a manual-commit pool had left in that mode, which pyodbc would not
    correct. :func:`disable_driver_manager_pooling` (BACKLOG #2049) turns that pooling off, so each
    ``pyodbc.connect`` opens a fresh physical connection, and a fresh ODBC connection starts in
    autocommit. It comes back only where the driver manager pools by its own configuration
    (unixODBC's ``Pooling = Yes`` in ``odbcinst.ini``), which the engine cannot switch off. The
    mechanism was never reproduced, and the set holds whichever way that falls. A manual-commit pool
    is returned unwrapped: pyodbc sets autocommit OFF itself, explicitly."""
    aioodbc = _import_aioodbc()
    disable_driver_manager_pooling()  # BACKLOG #2049; why is in messagefoundry/odbc_env.py
    pool = await aioodbc.create_pool(
        dsn=dsn,
        minsize=1,
        maxsize=max(1, pool_max),
        autocommit=autocommit,
        timeout=login_timeout,
    )
    return _AutocommitPool(pool) if autocommit else pool


# WP-L3-07 (ASVS 13.1.2/13.2.6): bound a pooled-connection borrow. One delivery/poll worker per
# connection means pool_max is never legitimately exhausted, so an acquire that can't be satisfied
# within the timeout means the pool is wedged or the DB is unresponsive — fail it transiently rather
# than block the worker forever (which would let the queue back up unbounded). Override per connection
# with the ``acquire_timeout`` setting.
_DEFAULT_DB_ACQUIRE_TIMEOUT = 30.0


async def _acquire(pool: Any, timeout: float) -> Any:
    """Acquire a connection from ``pool`` within ``timeout`` seconds, or raise a transient
    :class:`DeliveryError` with a clear, PHI-free message. Wraps the driver's own ``acquire`` so a
    hung/exhausted pool surfaces as a retryable failure instead of an unbounded await.

    The connection comes back with the call gate installed (BACKLOG #2394), so a cancelled call
    cannot free its handles under a running statement, the native crash BACKLOG #2049 recorded."""
    try:
        conn = await asyncio.wait_for(pool.acquire(), timeout)
    except TimeoutError as exc:
        raise DeliveryError(
            f"DATABASE pool acquire timed out after {timeout:g}s (pool exhausted or DB unresponsive)"
        ) from exc
    install_call_gate(conn)
    return conn


async def _close_cursor(cur: Any) -> None:
    """Close a cursor BEFORE its connection goes back to the pool (BACKLOG #1104).

    aioodbc/pyodbc keep the ODBC statement handle open until the cursor is closed, and a connection
    released with an open handle is handed to the NEXT caller still busy. That caller's first command
    then fails with ``HY000 Connection is busy with results for another command`` — a failure with no
    relationship to the statement it lands on, which is what made this hard to attribute. An ``UPDATE``
    leaves a row count pending, so the DATABASE source's ``mark`` is the usual victim, and a failed
    mark **re-emits the row as a DUPLICATE** (see ``_ingest_row``). So this is delivery semantics, not
    tidiness.

    Never raises. A close failure must not mask the caller's real error, and must not skip the pool
    release that follows it — leaking a connection to save a cursor would be the worse trade.
    """
    if cur is None:
        return
    try:
        await cur.close()
    except Exception as exc:  # noqa: BLE001 - hygiene only; the caller's outcome always wins
        logger.debug("DATABASE: cursor close failed, ignored: %s", _safe_db_error(exc))


async def _close_and_release(pool: Any, conn: Any, cur: Any) -> None:
    """Close ``cur``, then return ``conn`` to ``pool``, and never return it while the close may
    still be running on its worker thread (PR 2593 Lander hold).

    aioodbc closes a cursor on a worker thread, and a cursor close can take a while, since the
    driver may discard unread rows. A cancellation that lands during it ends the await and leaves
    the thread running. Releasing then, as a ``finally`` did, hands the connection to the next
    borrower while another thread is still inside the driver on it. So the close runs on
    :func:`_thread_settled` against aioodbc's raw pyodbc cursor (``_impl``, as ``store/sqlserver.py``
    reads it), and is shielded: the caller's cancellation goes through at once, and the connection
    goes back only when the thread has resolved the close. No task cancel can resolve it, loop
    teardown's included, so the connection always does go back, and a later ``wait_closed`` waits
    only for the close itself.

    **A cancellation during ``execute`` or a fetch does not free the cursor under it (BACKLOG
    #2394).** That call may still be running on its worker thread when this function is reached.
    The close runs inside the connection's call gate (:func:`_thread_settled`), handed to the
    running call, so it runs only once that call has returned, and the connection goes back only
    after the close. On that path the same job then rolls back what the cancelled statement may
    have left open (:func:`_close_after_a_cancel`), since the caller's own ``except Exception``
    rollback never ran. The cancelled task waits for none of it: while a cancellation is in flight,
    the return is handed to :func:`_return_when_settled` at once. Until the running call returns,
    the connection keeps its pool slot, and counts as held back, so a close of the pool stops
    waiting for it at a bound (:func:`_close_pool_bounded`). Nothing in the engine bounds that time,
    because this connector sets no statement timeout (ADR 0159, amendment of 2026-10-30).

    **What this does not cover, at least.** A cancellation during ``conn.cursor()`` reaches this
    function with no cursor, so the connection goes back while that call may still be running. The
    gate holds the next borrower's calls behind it, and the cursor it makes is left for the
    collector. A cancellation that lands after a call was handed to the connection's executor but
    before that call entered the gate finds no call running, so the close is not handed to it: the
    two race for the gate, the close may run first, and the connection can go back while that call
    is still to run. A connection with no gate (a test double) closes its cursor beside a running
    call, as before. A cursor with no ``_impl`` (a test double, or an aioodbc that renamed it) is closed
    through its own ``close()`` as a task, and a teardown cancel of that task keeps the connection
    out of the pool (:func:`_return_when_settled`)."""
    if cur is None:
        await pool.release(conn)
        return
    raw_cur = getattr(cur, "_impl", None)
    cancelled = _unwinding_a_cancel()
    work: asyncio.Future[Any]
    if raw_cur is not None:
        gate = call_gate(conn)
        # Only inside a gate: on an ungated connection a rollback would run beside the statement.
        close = (
            partial(_close_after_a_cancel, conn, raw_cur)
            if cancelled and gate is not None
            else partial(_close_raw_cursor, raw_cur)
        )
        try:
            work = _thread_settled(close, gate=gate)
        except RuntimeError as exc:
            # The default executor is shut down: no close thread started, so none runs on it.
            # Not raised: this runs in callers' finally blocks, and must not mask their outcome.
            logger.debug("DATABASE: cursor close not run, executor shut down: %s", exc)
            await pool.release(conn)
            return
    else:
        work = asyncio.ensure_future(_close_cursor(cur))
        # The loop holds a task only weakly; keep this one alive until its done-callback has run.
        _DETACHED_SETTLES.add(work)
        work.add_done_callback(_DETACHED_SETTLES.discard)
    if cancelled:
        # The close may be waiting for a cancelled statement; the cancellation must not.
        _return_when_settled(pool, conn, work, "a cursor close")
        return
    try:
        await asyncio.shield(work)
    except BaseException:
        _return_when_settled(pool, conn, work, "a cursor close")
        raise
    await pool.release(conn)


def _close_raw_cursor(raw_cur: Any) -> None:
    """On a worker thread: close a pyodbc cursor. Never raises, as :func:`_close_cursor` never
    does: a close failure must not mask the caller's outcome or skip the release."""
    try:
        raw_cur.close()
    except Exception as exc:  # noqa: BLE001 - hygiene only; the caller's outcome always wins
        logger.debug("DATABASE: cursor close failed, ignored: %s", _safe_db_error(exc))


def _close_after_a_cancel(conn: Any, raw_cur: Any) -> None:
    """On a worker thread, inside ``conn``'s call gate: close the cursor a cancelled borrow left,
    then roll back what its statement may have left open (BACKLOG #2394, ADR 0159).

    A cancellation skips every caller's ``except Exception: rollback``. On the destination's
    manual-commit pool the connection would otherwise go back holding the cancelled INSERT
    uncommitted, with its locks, for the next send's commit or rollback to settle. On an autocommit
    connection the rollback has nothing to undo. Never raises.

    **A failed rollback is logged, and the connection still goes back.** Discarding it would drop
    its handle, and aioodbc wakes neither a waiting borrower nor a waiting ``wait_closed`` for a
    closed connection, so that wait could last until something else woke it. A rollback usually
    fails because the session is gone, and its transaction with it. A session still alive keeps
    the transaction until the next borrower's own commit or rollback, as before this function."""
    _close_raw_cursor(raw_cur)
    raw = getattr(conn, "_conn", None)
    if raw is None:
        return
    try:
        raw.rollback()
    except Exception as exc:  # noqa: BLE001 - every driver fault; nobody is left to raise to
        logger.warning(
            "DATABASE: rollback after a cancelled statement failed; the connection goes back to "
            "its pool: %s",
            _safe_db_error(exc),
        )


async def _close_pool_bounded(pool: Any, what: str, *, bound: float | None = None) -> None:
    """Close ``pool``. Wait for its connections in use as an unbounded ``wait_closed`` would, but
    stop waiting once a connection of it is held back behind a cancelled borrow (BACKLOG #2394).

    **The bound applies only while that count is above zero** (:func:`_holds_back`), read at the end
    of each tick of :data:`_POOL_CLOSE_TIMEOUT_S`: a close that starts with one held back waits one
    tick, and one held back mid-wait ends the wait at the end of its tick. Such a connection goes back only once its
    cancelled call returns, which nothing bounds (ADR 0159, amendment of 2026-10-30), so a stop or a
    reload would otherwise wait as long as that call runs. With no connection held back, an
    in-flight call is an ordinary one, and the close waits for it as it did before #2394, however
    long it takes. ``bound`` instead stops the wait at that many seconds whatever the count: the
    source's stop after a cancel (BACKLOG #1620) passes it.

    **Stopping the wait frees nothing.** The close is waited on through :func:`asyncio.wait`, which
    never cancels it, so a close cut halfway never leaves a connection's handle for aioodbc's
    ``__del__`` to free; it goes on by itself, and the held connection is still released only once
    its call has returned, to a pool already closing. A caller that then opens a new pool has two
    open beside each other until that call returns, the trade the source's stop after a cancel
    already makes. A close that fails while waited on raises, as before; one that fails after the
    wait has stopped is logged.

    **A retried close waits on the close already in flight** (:func:`_pool_closing`), never a
    second ``wait_closed`` beside it: aioodbc wakes one waiter per returned connection, so a second
    waiter on the same pool might never be woken."""
    pool.close()
    closing = _pool_closing(pool)
    loop = asyncio.get_running_loop()
    started = loop.time()
    tick = _POOL_CLOSE_TIMEOUT_S if bound is None else bound
    try:
        while True:
            done, _pending = await asyncio.wait({closing}, timeout=tick)
            # Re-read each tick: a cancelled borrow can be held back after the close began.
            held = _holds_back(pool)
            if done or held or bound is not None:
                break
    except BaseException:  # a cancelled caller: the close goes on, and a failure is still logged
        closing.add_done_callback(partial(_log_late_pool_close, what))
        raise
    if done:
        closing.result()
        return
    closing.add_done_callback(partial(_log_late_pool_close, what))
    waited = loop.time() - started
    if held:
        logger.warning(
            "%s pool did not close in %.1fs of waiting; %d connection(s) held behind a cancelled "
            "call go back when that call returns, and the close goes on meanwhile",
            what,
            waited,
            held,
        )
    else:  # only a caller's own bound ends the wait with nothing held back
        logger.warning(
            "%s pool did not close in %.1fs of waiting; the close goes on, and a connection still "
            "in use closes when its borrower returns it",
            what,
            waited,
        )


#: The close in flight for each pool, keyed as :data:`_HELD_BACK` is (:func:`_pool_closing`).
_CLOSING: weakref.WeakKeyDictionary[Any, asyncio.Future[None]] = weakref.WeakKeyDictionary()


def _pool_closing(pool: Any) -> asyncio.Future[None]:
    """``pool``'s ``wait_closed``, run detached: the one already in flight if a close that stopped
    waiting, or was cancelled, left one, otherwise a new one. A finished one, a failed close
    included, is not reused, so a retry after a failure closes again."""
    key = _pool_key(pool)
    try:
        closing = _CLOSING.get(key)
    except TypeError:
        # Logged, not swallowed: a retried close of such a pool waits on a second wait_closed.
        logger.warning("DATABASE: a pool close could not be tracked against its pool")
        closing, key = None, None
    if closing is not None and not closing.done():
        return closing
    fresh: asyncio.Task[None] = asyncio.ensure_future(pool.wait_closed())
    _DETACHED_SETTLES.add(fresh)
    fresh.add_done_callback(_DETACHED_SETTLES.discard)
    if key is not None:
        _CLOSING[key] = fresh
        # Dropped once done: a failed close's traceback holds the pool, which would keep the weak
        # key alive through its own value.
        fresh.add_done_callback(partial(_forget_close, key))
    return fresh


def _forget_close(key: Any, closing: asyncio.Future[None]) -> None:
    if _CLOSING.get(key) is closing:
        del _CLOSING[key]


def _log_late_pool_close(what: str, closing: asyncio.Future[None]) -> None:
    error = None if closing.cancelled() else closing.exception()
    if error is not None:
        logger.warning(
            "%s pool close failed after its caller stopped waiting: %s",
            what,
            _safe_db_error(error),
        )


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
            else DeliveryError(f"DATABASE connect failed: {safe_exc(exc)}")
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
            else DeliveryError(f"DATABASE probe failed: {safe_exc(exc)}")
        ) from exc
    finally:
        await _close_and_release(pool, conn, cur)


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
        # it: not every driver takes a DATABASE keyword.
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
        self._connection_name = config.name
        # The posture this connector was built under, for the send-time tripwire (vault BACKLOG #2354).
        self._hop_posture = current_hop_posture()
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
        self._login_timeout = _login_timeout(s, f"DATABASE connection {config.name!r}")
        self._pool_max = count_setting(
            s.get("pool_max", 5), knob="pool_max", transport="DATABASE destination"
        )
        self._acquire_timeout = float_setting(
            s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT),
            knob="acquire_timeout",
            transport="DATABASE destination",
        )
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
        self._capture_max_rows = count_setting(
            s.get("capture_max_rows", 100),
            knob="capture_max_rows",
            transport="DATABASE destination",
        )
        self._capture_max_bytes = count_setting(
            s.get("capture_max_bytes", 256 * 1024),
            knob="capture_max_bytes",
            transport="DATABASE destination",
        )

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                self._pool = await _make_pool(
                    self._dsn,
                    self._pool_max,
                    autocommit=False,
                    login_timeout=self._login_timeout,
                )
        return self._pool

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # #200 decision 4: zero-I/O byte-crossing re-assertion of the posture-keyed hop decision, so a
        # payload never crosses a weakened-TLS DB hop the shared authority would refuse. Defense-in-depth
        # BEHIND the construction-time _build_dsn gate (which already refused a prod-PHI weakened hop),
        # catching a reload / build that reached send() around it. Fixed DSN target → this only ever
        # fires as a tripwire.
        _assert_send_hop(
            weakened=self._weakened_tls,
            attested=self._hop_attested,
            posture=self._hop_posture,
            connection=self._connection_name,
        )
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
            await _close_and_release(pool, conn, cur)
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
        """Close the pool. It waits for an in-flight send, as before, but not for a connection a
        cancelled send's statement still holds, which has no time limit (BACKLOG #2394,
        :func:`_close_pool_bounded`)."""
        if self._pool is not None:
            await _close_pool_bounded(self._pool, "DATABASE destination")
            self._pool = None


#: How many undecodable rows ONE poll will step past before it stops fetching and defers the rest
#: (BACKLOG #1662). A flat number rather than a multiple of ``poll_max_rows``, so it holds for a
#: ceiling of 1 as well as the shipped 500: one poll pulls at most ``poll_max_rows + 64`` rows out of
#: the driver, and logs at most 64 skip lines, which is already fewer than the 500 the shipped code
#: could log for one misconfigured column.
#:
#: **A stop rule re-creates the starvation it was written against whenever the poison run is longer
#: than the bound**, so the bound alone is not the answer and is not asked to be: the dominant case,
#: a ``body_column`` that names no selected column, is caught once per poll before any row is read,
#: and never reaches this budget at all. What is left here is genuinely per-row (an undecodable BLOB,
#: an unserializable column type), where a run of more than 64 in front of the good rows means a
#: table one poll cannot repair — and the operator gets 64 ``row_undecodable`` events saying so.
_MAX_SKIPPED_ROWS_PER_POLL = 64

#: How long a cancelled DatabaseSource.stop() lets a row's hand-off and mark finish before it cuts
#: them (BACKLOG #1620). It bounds the cancel; a step that outlasts it is hung and is cut, and its
#: row re-emits as the at-least-once duplicate a failed mark already makes.
_ROW_STEP_GRACE_S = 2.0
#: How long a cancelled DatabaseSource.stop() waits for the poll task it cut to finish (BACKLOG
#: #1620). A cut task can still be held by a driver call on an executor thread, such as a cursor
#: close behind a hung statement; stop() then returns with the task still referenced, so the next
#: stop() joins it before closing the pool under it.
_CUT_JOIN_TIMEOUT_S = 2.0
#: How long a pool close waits once it has a reason to stop waiting (:func:`_close_pool_bounded`).
#: A pool waits for every connection in use to come back, so one a hung driver call holds would make
#: it wait forever. A cancelled DatabaseSource.stop() waits this long whatever its pool holds
#: (BACKLOG #1620). Every other close of a DATABASE pool, the source's ordinary stop, the
#: destination's, the db_lookup executor's and a DatabaseRef sync's teardown, waits this long only
#: while a connection is held back behind a cancelled borrow (BACKLOG #2394), and otherwise waits
#: for its in-flight calls without a bound.
_POOL_CLOSE_TIMEOUT_S = 2.0
#: How often the row grace re-reads leadership, so a demotion during it ends it (BACKLOG #1620).
_LEADER_RECHECK_S = 0.05


class _PolledBatch(NamedTuple):
    """What one poll took from ``poll_statement``.

    ``rows`` are ``(record, body)`` pairs that decoded; ``skipped`` carries one PHI-free reason per
    row that could not become a body; ``skip_budget_spent`` says this poll stopped fetching early
    because it hit :data:`_MAX_SKIPPED_ROWS_PER_POLL`. Reasons are carried out rather than reported
    in place so the pool connection is released before anything is logged or emitted."""

    rows: list[tuple[dict[str, Any], str]]
    skipped: list[str]
    skip_budget_spent: bool


def _read_only_poll_refusal(statement: str) -> str | None:
    """Why a DATABASE source ``poll_statement`` is refused, or None when it passes (BACKLOG #2178).

    The poll runs on the autocommit pool, so a write in it commits at execute, before any row reaches
    the handler. A poll that claims rows, such as ``UPDATE ... RETURNING``, would mark every row it
    matches, but :meth:`DatabaseSource._select` hands off at most ``poll_max_rows`` of them, so the
    rows past the ceiling would be marked and never ingested, and so would at least a row whose
    handler failed (:meth:`DatabaseSource._poll_once` goes on to the next row) and the rows a stop
    leaves behind. That is accept-and-drop. Only the per-row ``mark_statement``, run after
    the handler returns, may mark a row.

    The test is :func:`_require_read_only`, the one ``db_lookup`` uses, applied whatever
    ``poll_max_rows`` is; its docstring says what it refuses. A locking ``FOR UPDATE`` read is refused
    with the rest (``UPDATE`` is a keyword), and on this autocommit connection its lock ends with the
    statement, so refusing it loses nothing. **It reads the statement's shape only**, so at least a
    ``SELECT`` that calls a function which writes, and a T-SQL second statement with no ``;`` whose
    verb is not in :data:`_SQL_WRITE_KEYWORDS`, pass it. With a ``mark_statement`` the login must be
    able to write, so it cannot backstop the poll; a feed with no mark can use a read-only login.

    ``DatabasePoll`` tests a literal statement when declared, so ``messagefoundry check`` refuses it
    without a build; ``DatabaseSource`` tests every statement, an ``env()`` value included, at
    construction. The text is the fixed refusal vocabulary, never the statement. It is returned, not
    raised, so each caller raises its own type with no ``DbLookupError`` chain."""
    try:
        _require_read_only(statement, subject="DATABASE source poll_statement")
    except DbLookupError as exc:
        return (
            f"{exc}. A poll must only read: it runs on an autocommit connection, so a write in it, "
            "such as UPDATE ... RETURNING or OUTPUT, would commit before any row is handed off, "
            "and at least the rows it marked past poll_max_rows, a row whose hand-off failed, "
            "and the rows left behind a stop would never be ingested. Poll with a SELECT and mark "
            "each handled row with mark_statement. A stored-procedure poll (EXEC, {CALL ...}) is "
            "refused even when the procedure only reads, because this test cannot see its body. "
            "At least a second statement and a FOR UPDATE locking read (whose lock ends with the "
            "statement here) are refused too"
        )
    return None


class DatabaseSource(SourceConnector):
    """Poll a SQL table on an interval, hand each row to the pipeline handler, then mark it processed.

    The File source's *process-then-mark-done* shape (at-least-once), with a query instead of a
    directory: a cooperatively-cancellable background loop runs the operator-declared ``poll_statement``
    (a read-only ``SELECT`` of the next batch; a writing poll is refused at construction, BACKLOG
    #2178), hands each row to the handler as a body, and — **only after the
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
    atomicity here: it's on the operator's SQL. The claim is ``mark_statement``, run per row after the
    handler returns, so a row both nodes read in the brief transition window is a duplicate, the same
    at-least-once class as a crash mid-poll, never a loss. ``poll_statement`` must not claim; see
    :func:`_read_only_poll_refusal`.
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
        # Before the hop is built: a refused poll must not leave a hop-crossing audit line behind.
        refusal = _read_only_poll_refusal(str(s["poll_statement"]))
        if refusal is not None:
            raise ValueError(refusal)
        # Per-connection insecure-hop attestation (#200): the customer-DB poll link rides the same
        # posture-keyed verify-off refusal as the destination (a read still crosses the wire).
        self._dsn, _ = _build_connection(
            s,
            attested=config.tls_hop_attested,
            connection=None if config.name is None else inbound_record_name(config.name),
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
            connection=None if config.name is None else inbound_record_name(config.name),
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
        self._poll_seconds = poll_interval(s, default=5.0, transport="DATABASE source")
        # Per-tick row ceiling, SHIPPED ON (DEFAULT_MAX_ITEMS_PER_POLL — the number and the reason a
        # poll source may default this on are stated once, in transports/base.py). Caps how many rows
        # ONE poll takes from poll_statement's result set; the rest stay in the table and the next poll
        # takes them. None/0 (in any spelling) disables the cap, matching the file sources' knobs.
        self._poll_max_rows: int | None = resolve_poll_ceiling(
            s.get("poll_max_rows", DEFAULT_MAX_ITEMS_PER_POLL),
            knob="poll_max_rows",
            transport="DATABASE source",
        )
        self._encoding: str = declared_encoding(s.get("encoding"))
        # Refused here, when the source is built, by the probe config load uses (BACKLOG #2431). Each
        # polled row is encoded with this name, so an unusable one would otherwise surface per row.
        # Config load refuses an env() inbound encoding and a literal naming no codec (BACKLOG #2431),
        # so this is a backstop for a graph built past load.
        if not _is_text_codec(self._encoding):
            raise ValueError("DATABASE source 'encoding' names no usable text codec")
        self._login_timeout = _login_timeout(
            s,
            f"DATABASE connection {None if config.name is None else inbound_record_name(config.name)!r}",
        )
        self._pool_max = count_setting(
            s.get("pool_max", 5), knob="pool_max", transport="DATABASE source"
        )
        self._acquire_timeout = float_setting(
            s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT),
            knob="acquire_timeout",
            transport="DATABASE source",
        )
        self._pool: Any = None
        self._pool_lock = asyncio.Lock()
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, the poll table (a shared external resource) is
        # polled/marked only while the gate returns True, so in a cluster exactly one node ingests
        # its rows. None = always poll (single-node / direct callers / tests) — byte-identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        # Whether this run of full polls with no mark_statement has already been warned about.
        self._unmarked_ceiling_warned = False
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # The poll task inside a row's hand-off and mark; a cancelled stop() gives it a grace.
        self._row_step_task: asyncio.Task[Any] | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Stop polling and close the pool.

        **A cancelled stop() lets a row's hand-off and mark finish first, for a bounded time**
        (BACKLOG #1620, ADR 0157 Amendment B). Once the handler has committed a row to the store,
        only the mark keeps it from re-emitting, so cutting the task between the two makes a
        duplicate. So when the cancel lands while the task is inside that step, stop() waits up to
        :data:`_ROW_STEP_GRACE_S` for it: ``_stop`` is set, so the task marks the row and exits at
        its next stop check. A step still running after that is cut, as is one a second cancel
        reaches, including a second cancel coalesced with the first. A cancel anywhere else cuts at
        once. The grace also ends as soon as this node is not the leader, whether it was not when
        the cancel landed or stops being one during the grace, so a demoted node stops waiting on
        writes to the shared poll table (ADR 0157).

        **Every wait after a cancel is bounded.** The cut task is joined for at most
        :data:`_CUT_JOIN_TIMEOUT_S`, and the pool close waits at most :data:`_POOL_CLOSE_TIMEOUT_S`,
        so a driver call hung on a thread cannot hold a cancelled stop(). The pool is closed even
        when the cut task is still running: a connection the task still holds is closed when the
        task releases it, and a close that stops waiting goes on by itself. That task stays
        referenced, and the next stop() joins it. A close failure after a cancel is logged, never
        raised over it.

        **An ordinary stop() waits for the pool as before, unless a borrow was cancelled.** It
        waits for an in-flight call without a bound, but stops at :data:`_POOL_CLOSE_TIMEOUT_S` once
        a connection is held back behind a cancelled borrow (BACKLOG #2394), such as a
        ``test_connection`` probe whose ``SELECT 1`` was cancelled while it hung.
        """
        self._stop.set()
        task = self._task
        try:
            if task is not None:
                await self._join_poll(task)
        except (asyncio.CancelledError, Exception):
            await self._finish_stop(task, interrupted=True)
            raise
        await self._finish_stop(task, interrupted=False)

    async def _finish_stop(self, task: asyncio.Task[None] | None, *, interrupted: bool) -> None:
        """Clear a finished poll task, log its fault, and close the pool, bounded if interrupted."""
        if task is not None and task.done():
            # A faulted poll task must not re-raise here — stop() runs during reload quiesce,
            # outside its rollback (mirrors the File source). It is logged instead, once, by the
            # stop() that clears it; reading it in every stop() keeps it from going unretrieved.
            fault = None if task.cancelled() else task.exception()
            if self._task is task:
                self._task = None
                if fault is not None:
                    logger.warning("DATABASE source poll task failed: %s", _safe_db_error(fault))
        if task is not None and self._task is not None and self._task is not task:
            return  # a later start() made a new poll task, and the pool is now that task's
        try:
            await self.aclose(timeout=_POOL_CLOSE_TIMEOUT_S if interrupted else None)
        except Exception as exc:
            if not interrupted:
                raise
            logger.warning(
                "DATABASE source pool close failed during a cancel: %s", _safe_db_error(exc)
            )

    async def _join_poll(self, task: asyncio.Task[None]) -> None:
        """Wait for the poll task; on a cancel, apply stop()'s row-step grace, then cut and join."""
        current = asyncio.current_task()
        # Read before the wait, so a cancel this task already carried does not count as a second.
        before = current.cancelling() if current is not None else 0
        try:
            # wait, not gather: a cancelled wait leaves the task alone, so the arm below decides.
            await asyncio.wait({task})
        except asyncio.CancelledError:
            try:
                again = current is not None and current.cancelling() - before > 1
                if self._row_step_task is task and not again:
                    await self._row_grace(task)
            finally:
                task.cancel()  # a no-op once the task has finished
                if self._row_step_task is task:
                    # Cut: a later cancelled stop() must not grant this task a grace again while it
                    # only finishes a cursor close.
                    self._row_step_task = None
                # wait, not gather, again: a further cancel is not forwarded into the task, and the
                # timeout bounds a task a driver call holds.
                await asyncio.wait({task}, timeout=_CUT_JOIN_TIMEOUT_S)
                if not task.done():
                    logger.warning(
                        "DATABASE source poll task still running %.1fs after a cancelled stop() "
                        "cut it; it stays registered and the next stop() joins it",
                        _CUT_JOIN_TIMEOUT_S,
                    )
            raise

    async def _row_grace(self, task: asyncio.Task[None]) -> None:
        """Wait up to :data:`_ROW_STEP_GRACE_S` for the row step, while this node leads.

        Leadership is re-read every :data:`_LEADER_RECHECK_S`, so a demotion during the grace ends
        it within that interval."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _ROW_STEP_GRACE_S
        while not task.done() and self._leads_or_cut():
            left = deadline - loop.time()
            if left <= 0:
                return
            await asyncio.wait({task}, timeout=min(left, _LEADER_RECHECK_S))

    def _leads_or_cut(self) -> bool:
        """:meth:`_leads` for the row grace: a gate that raises ends the grace rather than
        replacing the cancel stop() is handling."""
        try:
            return self._leads()
        except Exception as exc:  # noqa: BLE001 - the cancel in flight is the outcome that matters
            logger.warning(
                "DATABASE source leader gate failed; cutting the row step: %s", _safe_db_error(exc)
            )
            return False

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        async with self._pool_lock:
            if self._pool is None:
                # autocommit: each mark is its own committed statement, giving per-row mark durability.
                self._pool = await _make_pool(
                    self._dsn,
                    self._pool_max,
                    autocommit=True,
                    login_timeout=self._login_timeout,
                )
        return self._pool

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                # BACKLOG #290 slice 2: a paused engine skips the whole tick, so poll_statement does
                # not run and no row is selected or marked; the rows wait in the table.
                if intake_open(self.intake_gate) and self._may_poll():
                    await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # A poll error (connection drop, a bad poll_statement, an unserializable column) must
                # NOT kill the poller — that would silently stop the connection from receiving while it
                # still reports running. Log and retry on the next interval (mirrors the File source).
                # Not logger.exception: its traceback ends in the driver's text, which quotes the
                # offending value, such as a 245 conversion error naming the column value it could not
                # convert. The frames are kept and each exception line is _safe_db_error's (#1661).
                logger.error(
                    "DATABASE source poll failed; retrying next interval",
                    exc_info=_safe_db_exc_info(exc),
                )
            try:  # noqa: SIM105
                await asyncio.wait_for(self._stop.wait(), self._poll_seconds)
            except TimeoutError:
                pass  # poll interval elapsed; poll again

    def _leads(self) -> bool:
        """Whether this node may touch the shared poll table: no gate, or the gate says leader."""
        return self._leader_gate is None or self._leader_gate()

    def _may_poll(self) -> bool:
        """Whether this tick may run poll_statement (and mark rows). False on a follower (leader-
        gated, Step 4b): a non-leader must NOT execute poll_statement or mark any rows, since the
        table is shared and two nodes polling it would duplicate intake. The loop still ticks, so a
        node that becomes leader polls on its next tick (reactive-by-polling, no restart). When the
        gate is None or True, behaves exactly as before. Logged once on each transition (never per
        skipped tick — that would spam a follower's log every poll interval)."""
        if self._leads():
            if self._skipping:
                self._skipping = False
                logger.debug("DATABASE source resuming polling (now leader)")
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug("DATABASE source skipping polling (not leader; another node ingests it)")
        return False

    async def _emit_event(self, kind: str, *, reason: str | None = None) -> None:
        """Fire one connection event (ADR 0021) to the runner-injected sink, **fail-soft**: an event
        problem must never wedge the poll loop (pure observer). No-op when the sink is unset — capture
        off, or a direct caller / test — so that path stays byte-identical.

        No ``peer_host``: a poll source dials OUT to an operator-configured server, so there is no
        peer address to report and the column stays ``NULL``, unlike the listen sources."""
        sink = self.on_connection_event
        if sink is None:
            return
        try:
            await sink(kind, None, reason)
        except Exception as exc:  # noqa: BLE001 - observer only; a capture bug can't stop ingest
            logger.warning("DATABASE connection-event emit failed: %s", _safe_db_error(exc))

    async def _poll_once(self) -> None:
        assert self._handler is not None
        batch = await self._select()
        for reason in batch.skipped:
            # A row that cannot become a body is skipped, and the shipped code said so ONLY to the
            # logger — no handler call, no mark, no store row, no event — so an operator watching the
            # console saw a silent connection (BACKLOG #1662). The event is the visibility half.
            #
            # It is still NOT marked, and that stays deliberate: mark_statement is an operator-authored
            # UPDATE, so marking a row that never became a message would record data DONE that was
            # never ingested. There is no store disposition to record either — a row the source could
            # not read was never a received message, the same reading the file sources apply to an
            # oversize or unscannable drop.
            logger.error("DATABASE source: %s; skipping row", reason)
            await self._emit_event("row_undecodable", reason=reason)
        if batch.skip_budget_spent:
            logger.error(
                "DATABASE source skipped %d undecodable rows in one poll and stopped fetching; the "
                "rest of the result set is deferred to the next poll (nothing dropped or marked)",
                len(batch.skipped),
            )
        me = asyncio.current_task()
        for record, body in batch.rows:
            if self._stop.is_set():
                break  # shutting down — leave the rest unmarked for the next start (at-least-once)
            # A cancelled stop() gives the hand-off and mark a grace. Keyed by task, so a cut task
            # unwinding late cannot clear the flag of a task a later start() made.
            self._row_step_task = me
            try:
                await self._ingest_row(record, body)
            finally:
                if self._row_step_task is me:
                    self._row_step_task = None

    async def _ingest_row(self, record: dict[str, Any], body: str) -> None:
        """Hand one row to the pipeline, then mark it. A cancelled stop() lets this step run for up
        to :data:`_ROW_STEP_GRACE_S` before it cuts it, so the step is NOT atomic under shutdown."""
        assert self._handler is not None
        try:
            await self._handler(body.encode(self._encoding))
        except Exception as exc:
            # The handler records every message-level outcome itself (parse/route → ERROR) and
            # returns, so an exception here is an infrastructure failure (the durable store write
            # failed). Leave the row UNMARKED so the next poll re-emits it (at-least-once) — marking
            # it now would drop a received-but-unrecorded message (mirrors the File source's M-15).
            # _safe_db_error: on a server store the handler's write is itself a driver call, and a
            # rejection quotes the value it refused, as SQL Server's 2628 truncation and asyncpg's
            # DETAIL line do (#1661).
            logger.warning(
                "DATABASE source handler failed (row left unmarked, will retry): %s",
                _safe_db_error(exc),
            )
            return
        try:
            await self._mark(record)
        except Exception as exc:
            # The handler already ingested the message; a mark failure means the row re-emits next
            # poll (a duplicate — at-least-once). Log and move on rather than abort the batch tail.
            # _safe_db_error, not safe_exc: a mark is an UPDATE bound from the row's own columns,
            # so the driver's rejection text quotes the bound value straight back, and safe_exc
            # is measured to keep a partial copy of it (BACKLOG #1661).
            logger.warning(
                "DATABASE source mark failed (row will re-emit, a duplicate): %s",
                _safe_db_error(exc),
            )

    async def _select(self) -> _PolledBatch:
        """Run ``poll_statement``, decode each row into a body, and return the decodable ones (at most
        ``poll_max_rows``) plus a PHI-free reason per row that could not be decoded. The connection is
        released before the rows are handed to the (possibly slow) handler, so a batch never holds a
        pool connection hostage to downstream store I/O.

        **Decoding happens HERE, under the open cursor, and that is what lets the ceiling count rows
        that produced something** (BACKLOG #1662). ``_body`` is pure, synchronous and cheap — a dict
        lookup or a ``json.dumps`` — so running it at the fetch costs nothing extra and means a row the
        source cannot read is replaced rather than spending a ceiling slot on nothing. The shipped code
        charged the ceiling at the fetch and skipped the row afterwards, so one undecodable row sorting
        first starved a ``poll_max_rows=1`` feed forever: three polls handled nothing and the good row
        behind it was never reached.

        **The ceiling is still charged at the FETCH, not after it**, and the memory contract it exists
        for is intact: each fetch asks only for what is still missing, so one poll pulls at most
        ``poll_max_rows`` plus :data:`_MAX_SKIPPED_ROWS_PER_POLL` rows out of the driver, never the
        whole result set. This is **not** the file sources' rule and must not be described as parity
        with them: they charge on COMPLETION and can afford to, because a directory listing is already
        in hand, while here the point of the ceiling is that the rest of the result set never leaves
        the driver. What is shared is the reason behind it, which the file source states as *a budget
        can only be charged by something that makes progress*.

        **Undecodable rows are bounded two ways, and the bound is why this is not a log flood.** The
        dominant ``_body`` failure is static — ``body_column`` naming a column ``poll_statement`` does
        not select fails EVERY row — so that one is checked ONCE per poll against the cursor's own
        description and returns immediately with a single reason, where the shipped code logged once
        per row up to the ceiling. Everything else (an undecodable BLOB, an unserializable column type)
        is per-row: it is skipped and replaced, up to :data:`_MAX_SKIPPED_ROWS_PER_POLL`, after which
        this poll stops fetching and leaves the rest for the next one.

        Rows not taken are untouched in the table, so the next poll re-runs ``poll_statement`` and takes
        the next batch; nothing is dropped, errored or marked. Progress depends on the ``mark_statement``
        removing a handled row from ``poll_statement``'s own predicate, which is the shape this connector
        already documents and requires — without a mark the same rows re-emit every poll, ceiling or no
        ceiling, and the rows past a full ceiling are not reached at all, so that case logs a WARNING
        once per run of full polls rather than the deferral line. "Untouched" holds only while
        ``poll_statement`` does not write (:func:`_read_only_poll_refusal` says what is refused).

        A falsy ``poll_max_rows`` disables the ceiling and restores the unbounded ``fetchall``; the skip
        budget still applies there, bounding this poll's log and event volume the same way."""
        pool = await self._get_pool()
        conn = await _acquire(pool, self._acquire_timeout)
        cur: Any = None
        rows: list[tuple[dict[str, Any], str]] = []
        skipped: list[str] = []
        budget_spent = False
        ceiling = self._poll_max_rows
        try:
            cur = await conn.cursor()
            await cur.execute(self._poll_sql)
            columns = [d[0] for d in cur.description]
            if self._body_column is not None and self._body_column not in columns:
                # Static: this fails every row in every poll, so say it once and fetch nothing. The
                # reason names the operator's own configured column, never a row value.
                return _PolledBatch(
                    [],
                    [
                        f"body_column {self._body_column!r} is not in the poll_statement result "
                        f"columns"
                    ],
                    False,
                )
            want = 0
            while True:
                if ceiling is None:
                    batch = list(await cur.fetchall())
                else:
                    # Exactly what is still missing, NOT ceiling+1. The +1 probe is the usual idiom
                    # for "is there more?", and it is wrong here: this connector's rows can carry a
                    # message BODY (`body_column`), so the probe row would marshal a whole payload out
                    # of the driver and discard it on every poll — hundreds of KB every `poll_seconds`
                    # to decide one word in a log line. A full batch is the signal instead: it means
                    # the ceiling bound this poll, and cannot distinguish "exactly N remained" from
                    # "more remain", which is why the message says at least rather than naming a
                    # remainder.
                    want = ceiling - len(rows)
                    batch = list(await cur.fetchmany(want))
                for raw in batch:
                    record = dict(zip(columns, raw))  # noqa: B905
                    try:
                        body = self._body(record)
                    except (ValueError, TypeError) as exc:
                        skipped.append(safe_exc(exc))
                        if len(skipped) >= _MAX_SKIPPED_ROWS_PER_POLL:
                            budget_spent = True
                            break
                        continue
                    rows.append((record, body))
                if ceiling is None or budget_spent or len(batch) < want or len(rows) >= ceiling:
                    # A short batch means the driver is out of rows, so there is nothing to top up
                    # with — the ONLY reason to fetch again is a skip, and then only for the shortfall.
                    break
            if ceiling is None or len(rows) < ceiling:
                self._unmarked_ceiling_warned = False  # the run of full polls, if any, is over
            elif self._mark_sql is not None:
                logger.info(
                    "DATABASE source filled poll_max_rows (%s) this poll; any remaining rows are "
                    "left for the next poll (deferred, not dropped)",
                    ceiling,
                )
            elif not self._unmarked_ceiling_warned:
                # With no mark, nothing takes a handled row out of poll_statement's result, so the
                # next poll selects the same first rows again: "deferred" would be false. Once per
                # run of full polls, so a snapshot feed that always fills does not warn every poll.
                self._unmarked_ceiling_warned = True
                logger.warning(
                    "DATABASE source filled poll_max_rows (%s) and has no mark_statement, so each "
                    "poll can select the same first rows again and any rows past the ceiling may "
                    "never be reached; add a mark_statement that takes each handled row out of "
                    "poll_statement's result. Do not disable poll_max_rows for this: with no mark, "
                    "every poll would then re-read and re-ingest the whole table, with no bound on "
                    "the rows held in memory. Logged once until a poll returns fewer rows than the "
                    "ceiling",
                    ceiling,
                )
        finally:
            await _close_and_release(pool, conn, cur)
        return _PolledBatch(rows, skipped, budget_spent)

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
            await _close_and_release(pool, conn, cur)

    async def test_connection(self) -> None:
        await _probe_db(self._get_pool, timeout=self._acquire_timeout)

    async def aclose(self, *, timeout: float | None = None) -> None:
        """Close the pool, waiting at most ``timeout`` seconds when one is given (BACKLOG #1620).
        With none, it waits without a bound, except that it stops at :data:`_POOL_CLOSE_TIMEOUT_S`
        once a connection is held back behind a cancelled borrow (BACKLOG #2394). Either way the
        wait goes through :func:`_close_pool_bounded`, which never cancels the close.

        With no ``timeout`` the reference is kept until the close succeeds, so a stop() retried
        after a failed close finishes it; it is dropped when the wait stops at the bound, as for a
        bounded close. With one, it is dropped before the wait, so neither a cancel nor the timeout
        leaves this source holding a closing pool. In both cases the next :meth:`_get_pool` then
        opens a fresh pool beside the one still closing."""
        pool = self._pool
        if pool is None:
            return
        if timeout is not None:
            self._pool = None
        await _close_pool_bounded(pool, "DATABASE source", bound=timeout)
        if self._pool is pool:
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


def _lookup_connect_failure(connection: str, exc: Exception) -> str:
    """The PHI-free message for a lookup that could not open or borrow a connection (BACKLOG #2062).

    Names the connection and the failure's type, plus a driver error's SQLSTATE and native number
    (the :func:`_safe_db_error` rendering), and never quotes the failure's text: a connect error can
    carry DSN attributes, and the DSN holds the server and the credentials. That is why an error with
    no SQLSTATE gets its type alone rather than ``_safe_db_error``'s quoted fallback. The one cause
    named in words is a missing driver, because its type would not tell an operator to install the
    ``[sqlserver]`` extra."""
    prefix = f"db_lookup on {connection!r}: could not open a connection"
    if isinstance(exc, _DriverMissingError):
        return f"{prefix}; the 'sqlserver' extra is not installed"
    detail = _safe_db_error(exc) if _log_sqlstate(exc) else type(exc).__name__
    return f"{prefix} ({detail})"


#: Row ceiling for one ``db_lookup`` call when its ``DatabaseLookup`` sets no ``max_rows``
#: (BACKLOG #1730). The same number as the poll sources' ``DEFAULT_MAX_ITEMS_PER_POLL``, but a
#: different kind of bound. A poll ceiling DEFERS the rows it does not take, and they wait in the table.
#: This one REFUSES the lookup, so the Handler's message goes to ERROR. It sits well above a lookup that
#: shapes one message, such as a patient's orders or identifiers, and below a result that belongs in a
#: synced ``Reference`` instead. ``DatabaseLookup(max_rows=...)`` moves it; ``0`` removes it.
DEFAULT_DB_LOOKUP_MAX_ROWS = 500


async def fetch_at_most(cur: Any, limit: int) -> tuple[list[Any], bool]:
    """Fetch up to ``limit`` rows from an executed cursor, and say whether the result holds more.

    The one ceiling-at-the-fetch loop, for ``db_lookup`` (BACKLOG #1730) and the ``DatabaseRef`` sync
    (BACKLOG #2617); each caller raises its own refusal on ``True``. It asks the driver for at most
    ``limit + 1`` rows in all, never ``fetchall``, so a result far past the ceiling is judged having
    buffered one row more than it. The +1 row is the only way to tell "exactly ``limit``" from "more".
    It loops because a driver may return fewer rows than asked while more remain. When the answer is
    ``True`` the list holds ``limit + 1`` rows, and the caller must not use them as a result."""
    rows: list[Any] = []
    while len(rows) <= limit:
        batch = list(await cur.fetchmany(limit + 1 - len(rows)))
        if not batch:
            break
        rows.extend(batch)
    return rows, len(rows) > limit


def _lookup_max_rows(value: Any, connection: str) -> int | None:
    """Read one lookup connection's ``max_rows``: a positive ceiling, or ``None`` for the documented
    ``0`` opt-out. Unset (``None``) takes :data:`DEFAULT_DB_LOOKUP_MAX_ROWS`.

    An explicit zero in any spelling is the opt-out; an empty value, and anything else but a whole,
    positive number, is refused at construction, which ``serve`` reaches at
    start and ``messagefoundry check`` reaches in its build leg. The rule is :func:`max_rows_setting`."""
    return max_rows_setting(
        value, label=f"DatabaseLookup {connection!r}", default=DEFAULT_DB_LOOKUP_MAX_ROWS
    )


def max_rows_setting(value: Any, *, label: str, default: int) -> int | None:
    """Read a ``max_rows`` row ceiling: a positive ceiling, or ``None`` for the documented ``0``
    opt-out. Unset (``None``) takes ``default``. Shared by ``DatabaseLookup`` and ``DatabaseRef``
    (BACKLOG #1730, #2617), so the two cannot read one spelling two ways.

    Every value but ``None`` is a cap, read by ``transports.base.positive_cap``, so ``max_rows``
    reads a number as every other ``int`` cap does (PR 2593 review). An explicit zero in any
    spelling (``0``, ``"0"``, ``"0.0"``, ``"0_0"``) turns the ceiling off. **An empty value is the
    one exception:** the ``""`` or blank text a set-but-empty ``env()`` gives is refused, where
    every other cap reads it as off, because this ceiling fails closed (Manager ruling, PR 2593). A
    bool, a fraction, a NaN or an infinity, text such as ``"1e-400"`` that only
    rounds to zero, and a negative are refused; ``count_setting``'s docstring holds that rule. The
    refusals name ``label`` and the setting and withhold the value (BACKLOG #1183, #1796)."""
    if value is None:
        return default
    if isinstance(value, str) and not value.strip():
        # Manager ruling, PR 2593: a set-but-empty env() value is a provisioning slip, and a row
        # ceiling fails closed on one. Every other cap reads it as off; this one refuses it, so an
        # empty variable cannot remove the ceiling. Only an explicit zero turns it off.
        raise ValueError(
            f"{label} max_rows is empty; set a whole number of rows, or 0 for no ceiling"
        )
    return positive_cap(
        value, int, knob="max_rows", transport=label, off_hint="or 0 for no ceiling"
    )


class DatabaseLookupExecutor:
    """Pooled executor for handler-callable **live** lookups (``db_lookup``, ADR 0010).

    Built by the :class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` from the graph's
    ``DatabaseLookup`` specs (``env()``-resolved + ``[egress].allowed_db``-checked by the runner). Lazily
    opens one autocommit ``aioodbc`` pool per named connection; :meth:`query` runs on the engine loop,
    while ``db_lookup`` bridges to it from the handler's worker thread via ``run_coroutine_threadsafe``.
    Reuses the DATABASE connector's DSN build / named-parameter translation / SQLSTATE extraction.

    **Read-only here is a statement test, not read-only authority, and the difference is load-bearing.**
    Two layers sit in front of a lookup: :func:`_require_read_only` refuses a statement that does not
    open with SELECT/WITH or that carries a write/EXEC keyword or a chained statement, and the pool DSN
    carries ``ApplicationIntent=ReadOnly`` (``_build_dsn(read_only=True)``). Neither is authority.
    :func:`_build_dsn` says which servers act on ApplicationIntent and how; it grants no authority
    anywhere. Pools here are opened **autocommit**, so a write that
    got past the statement test would commit rather than be rolled back. What actually bounds this connection is the
    privilege of the account it dials, which only the operator can set — see ``docs/CONNECTIONS.md``
    (BACKLOG #1574). ADR 0010's *Scope* consequence says this executor never commits; a dated
    correction beneath it (BACKLOG #1791) records why that is false and supersedes it.

    Pools are autocommit because each lookup is a single self-contained read; T-SQL has no
    ``SET TRANSACTION READ ONLY``, so there is no read-only transaction to open in its place.

    Production / supported (SQL Server via the ``[sqlserver]`` extra), like the DATABASE connector.
    ``db_lookup`` is SQL-Server-only: ``__init__`` calls :func:`_build_dsn` directly rather than the
    :func:`_build_connection` dialect dispatcher, so the ``generic`` ODBC dialect the DATABASE connector
    accepts is not reachable from here (ADR 0010, "SQL Server backend only")."""

    def __init__(
        self, connections: Mapping[str, Mapping[str, Any]], *, egress: EgressSettings
    ) -> None:
        # connections: name -> already-env-resolved settings (the runner substitutes env() first).
        # `egress` is required and every server is checked against it here, before any DSN is built,
        # so no caller can construct an executor that dials an unchecked host (vault BACKLOG #2605).
        from messagefoundry.transports.egress import check_lookup_allowed

        for cname, s in connections.items():
            check_lookup_allowed(cname, s, egress)
        self._dsn: dict[str, str] = {}
        self._pool_max: dict[str, int] = {}
        self._login_timeout: dict[str, int] = {}
        self._acquire_timeout: dict[str, float] = {}
        self._max_rows: dict[str, int | None] = {}
        for cname, s in connections.items():
            for req in ("server", "database"):
                if not s.get(req):
                    raise ValueError(f"DatabaseLookup {cname!r} requires a {req!r} setting")
            # Per-connection insecure-hop attestation (#200), honoured here as the DATABASE
            # destination and poll source honour theirs: a live read crosses the same wire a write
            # does, so dropping it refused a hop the operator had attested. The mapping is the only
            # carrier this cell has (no Source/Destination model); DatabaseLookup() writes it there
            # from its own tls_hop_attested parameter — see :func:`hop_attestation_from_settings`.
            attested = hop_attestation_from_settings(s)
            # read_only=True: advertise ApplicationIntent=ReadOnly on the lookup pool (ADR 0010). Fail
            # fast on weakened-TLS / bad-auth config.
            self._dsn[cname] = _build_dsn(dict(s), read_only=True, attested=attested)
            self._pool_max[cname] = count_setting(
                s.get("pool_max", 5), knob="pool_max", transport=f"DatabaseLookup {cname!r}"
            )
            self._login_timeout[cname] = _login_timeout(s, f"DatabaseLookup {cname!r}")
            self._acquire_timeout[cname] = float_setting(
                s.get("acquire_timeout", _DEFAULT_DB_ACQUIRE_TIMEOUT),
                knob="acquire_timeout",
                transport=f"DatabaseLookup {cname!r}",
            )
            self._max_rows[cname] = _lookup_max_rows(s.get("max_rows"), cname)
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
                    self._dsn[connection],
                    self._pool_max[connection],
                    autocommit=True,
                    login_timeout=self._login_timeout[connection],
                )
        return self._pools[connection]

    async def query(
        self, connection: str, statement: str, params: Mapping[str, Any] | None
    ) -> list[dict[str, Any]]:
        """Run ``statement`` against ``connection`` and return rows as ``{column: value}`` dicts.

        Always parameterized (``:name`` → positional ``?``, bound from ``params`` — a value can never
        inject SQL) and statement-gated: the text must pass :func:`_require_read_only` (a SELECT/WITH
        query carrying no write keyword and no second statement) before anything executes. That gate is
        a statement test, not read-only authority — see this class's docstring for what actually bounds
        the connection. Raises :class:`DbLookupError` (PHI-free) on an unknown connection, a
        non-read-only statement, a missing parameter, a result larger than the connection's
        ``max_rows``, a failure to open or borrow a connection, or a DB/driver error — the transform
        worker turns it into that message's ``ERROR`` / dead-letter disposition. Runs on the engine
        loop (the handler thread bridges in via ``run_coroutine_threadsafe``), so a slow query never
        blocks the loop, only its own worker thread.

        The row ceiling is charged at the fetch, not after it (BACKLOG #1730). The driver is asked for at
        most ``max_rows + 1`` rows, so a statement whose predicate matches far more than a Handler can
        use is refused having buffered one row past the ceiling, never the whole result set. The result
        is never truncated: a Handler that got the first ``max_rows`` rows of a larger set would shape
        its message from a partial answer and nothing would say so."""
        if connection not in self._dsn:
            known = ", ".join(sorted(self._dsn)) or "(none declared)"
            raise DbLookupError(
                f"db_lookup: no DatabaseLookup connection named {connection!r} (declared: {known})"
            )
        # ADR 0010: run the statement-layer read-only test before anything executes. A write/EXEC
        # the test recognises then never reaches the autocommit pool. That pool would silently
        # commit it and re-apply it on a crash-replay of the transform. PHI-free — never echoes the
        # statement.
        _require_read_only(statement)
        sql, names = _parse_named_params(statement)
        bound = _bind_lookup_params(params or {}, names, connection)
        try:
            # Opening the pool dials the database at once (minsize=1), and an acquire can dial again.
            # Either one failing is a lookup failure, not a Handler crash (BACKLOG #2062).
            pool = await self._get_pool(connection)
            conn = await _acquire(pool, self._acquire_timeout[connection])
        except DeliveryError as exc:
            # Map the transient pool-timeout onto the lookup's own PHI-free error type so the transform
            # worker dead-letters/errors this message consistently with other lookup failures.
            raise DbLookupError(f"db_lookup on {connection!r}: {exc}") from exc
        except Exception as exc:
            raise DbLookupError(_lookup_connect_failure(connection, exc)) from exc
        cur: Any = None
        try:
            cur = await conn.cursor()
            await cur.execute(sql, bound)
            columns = [d[0] for d in cur.description] if cur.description else []
            limit = self._max_rows[connection]
            rows: list[Any] = []
            if limit is None:
                rows = list(await cur.fetchall())
            else:
                # The source poll avoids the +1 row because its rows can carry a whole message body,
                # but here the extra row is read only on the way to refusing the lookup.
                rows, over = await fetch_at_most(cur, limit)
                if over:
                    # PHI-free: the connection and the ceiling only, never the statement or a row.
                    raise DbLookupError(
                        f"db_lookup on {connection!r} returned more than max_rows={limit} rows; "
                        "narrow the statement, or raise max_rows on this DatabaseLookup"
                    )
        except DbLookupError:
            raise
        except Exception as exc:
            state = _sqlstate(exc)
            # PHI-free: name the connection + SQLSTATE (if any) only — never the statement/params/rows.
            raise DbLookupError(
                f"db_lookup query on {connection!r} failed" + (f" [{state}]" if state else "")
            ) from exc
        finally:
            await _close_and_release(pool, conn, cur)
        return [dict(zip(columns, row)) for row in rows]  # noqa: B905

    async def aclose(self) -> None:
        """Close every opened pool (idempotent; safe if no pool was ever opened). Each close stops
        waiting at a bound only while a cancelled lookup holds a connection back, as the
        destination's does (BACKLOG #2394, :func:`_close_pool_bounded`)."""
        pools = list(self._pools.items())  # a snapshot: a lookup may open a pool meanwhile
        outcomes = await asyncio.gather(
            *(_close_pool_bounded(pool, f"DatabaseLookup {name!r}") for name, pool in pools),
            return_exceptions=True,
        )
        failures: list[BaseException] = []
        for (name, pool), outcome in zip(pools, outcomes, strict=True):
            if isinstance(outcome, BaseException):
                failures.append(outcome)  # kept, as before, so a later aclose() closes it again
            elif self._pools.get(name) is pool:  # not a pool a lookup opened under it meanwhile
                del self._pools[name]
        for failure in failures[1:]:  # the first is raised; nothing else would report these
            logger.warning("DatabaseLookup pool close failed: %s", _safe_db_error(failure))
        if failures:
            raise failures[0]
