# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Materializes reference sets off the message path (ADR 0006 Tier 1).

The :class:`ReferenceSyncRunner` is a supervised background loop (modelled on
:class:`~messagefoundry.pipeline.retention.RetentionRunner`) that, for each declared
:class:`~messagefoundry.config.wiring.ReferenceSpec`, periodically loads the external dataset from its
source and writes it into the store as a new versioned, encrypted snapshot
(:meth:`~messagefoundry.store.base.QueueStore.write_reference_snapshot`, build-new-then-atomic-flip).
A Handler then reads the snapshot **purely** via ``reference("name").get(key)`` — no per-message
external call, so the at-least-once re-run invariant holds by construction (ADR 0006).

Tier 1 ships the **file** source (a local CSV/TOML the engine re-reads on cadence — the path for an
externally-produced export). The **database** source (the engine querying SQL Server directly) is
ADR-0006 increment 2.

**Clustered (Track B Step 6).** Each pass splits in two: materialize-from-source runs **only on the
leader** (gated on the coordinator's ``is_leader()``), and — **only when clustered** — every node then
calls :meth:`~messagefoundry.store.base.QueueStore.converge_reference_cache` to read-through any newer
shared snapshot the leader wrote into its own in-process cache. So the external source is read once
(by the leader) and followers converge by reading the shared store — no N-fold source load, no stale
follower caches. Single-node is byte-identical: :class:`NullCoordinator` is always leader (so it
materializes from source every pass exactly as before) and reports ``is_clustered()`` ``False``, so the
convergence call is skipped entirely (not just a returns-``[]`` no-op) and no extra DB read happens per
pass.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.models import hop_attestation_from_settings
from messagefoundry.config.settings import (
    EgressSettings,
    ReferenceSettings,
)
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture, current_hop_posture
from messagefoundry.config.wiring import (
    DEFAULT_REFERENCE_MAX_ROWS,
    ReferenceSpec,
    WiringError,
    refuse_bool_literals,
    refuse_unresolved_hop_flags,
    resolve_env_settings,
)
from messagefoundry.connection_names import reference_record_name
from messagefoundry.keyed_lock import KeyedLock, hold_keyed_lock
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.store import Store
from messagefoundry.store.base import (
    DEFAULT_STORE_ACQUIRE_TIMEOUT,
    ReferenceKeyCollision,
    acquire_pooled,
)
from messagefoundry.transports.base import NegativeAckError, count_setting, float_setting
from messagefoundry.transports.egress import check_lookup_allowed

__all__ = [
    "ReferenceColumnMismatch",
    "ReferenceKeyRefused",
    "ReferenceRowCeilingExceeded",
    "ReferenceStatementRefused",
    "ReferenceStatementTimedOut",
    "ReferenceStatementTimeoutRefused",
    "ReferenceSyncError",
    "ReferenceSyncRunner",
]

log = logging.getLogger(__name__)


class ReferenceSyncError(RuntimeError):
    """A reference set's source could not be materialized (bad source kind, missing file, parse error)."""


# The classes below are separate because the sync's log and alert carry the error's CLASS name
# only, never its text (a source error can hold a reference key). The class is all an operator gets,
# so it has to say which control refused the set (BACKLOG #2617).


class ReferenceStatementRefused(ReferenceSyncError):
    """A ``DatabaseRef`` statement failed the read-only statement test that ``db_lookup`` uses."""


class ReferenceRowCeilingExceeded(ReferenceSyncError):
    """A ``DatabaseRef`` statement returned more rows than its ``max_rows``."""


class ReferenceStatementTimedOut(ReferenceSyncError):
    """A ``DatabaseRef`` statement ran past its ``statement_timeout`` (``HYT00``)."""


class ReferenceStatementTimeoutRefused(ReferenceSyncError):
    """The database driver refused a ``DatabaseRef``'s ``statement_timeout``."""


class ReferenceColumnMismatch(ReferenceSyncError):
    """A ``DatabaseRef`` result does not fit its ``key_column`` and ``value_column``.

    At least: the result lacks either, holds either twice, or, with no ``value_column``, holds one
    column name twice.

    The message holds the set's name and which check failed, never a column's name, so
    ``_sync_one`` logs it whole, as it does ``ReferenceKeyCollision``."""


class ReferenceKeyRefused(ReferenceSyncError):
    """A ``DatabaseRef`` statement returned a NULL key, or two rows with one key.

    The message holds the set's name and row ordinals, never a key, so ``_sync_one`` logs it
    whole, as it does ``ReferenceKeyCollision``."""


#: The SQLSTATE a statement that ran past its ODBC query timeout fails with.
_STATEMENT_TIMEOUT_STATE = "HYT00"


@dataclass(frozen=True)
class _SyncPass:
    """What one :meth:`ReferenceSyncRunner.run_once` pass did."""

    synced: int  # sets re-materialized from source this pass (leader only)
    failed: int  # sets whose source failed (last-good snapshot kept)
    converged: int = (
        0  # sets a follower read-through'd from a newer shared snapshot (Track B Step 6)
    )

    @property
    def did_work(self) -> bool:
        return self.synced > 0 or self.failed > 0 or self.converged > 0


def _load_file_source(settings: Mapping[str, Any]) -> dict[str, Any]:
    """Load a file-backed reference source into a ``{key: value}`` dict (reuses the code-set loaders).

    ``settings`` is the resolved (env-substituted) ``FileRef`` settings: ``path`` (.csv/.toml, the
    code-set format) + ``encoding`` (currently informational — the loaders read utf-8)."""
    path = settings.get("path")
    if not path:
        raise ReferenceSyncError("file reference source requires a 'path'")
    try:
        return dict(load_code_set(path))  # CSV/TOML parse + dup-key check, shared with code sets
    except CodeSetError as exc:
        raise ReferenceSyncError(f"file reference source {path!r}: {exc}") from exc


def _cell(value: Any) -> Any:
    """Coerce a DB cell to a JSON-storable value (the snapshot value is ``json.dumps``'d at rest)."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    from messagefoundry.transports.database import _json_default  # lazy: avoids aioodbc import

    return _json_default(value)  # date/Decimal/bytes -> iso/str/base64


def reference_connection_name(name: str) -> str:
    """How a reference set names itself in an alert, a hop refusal or an audit line:
    ``reference:<name>``. One spelling, so an alert and the hop record it relates to name the set
    the same way. Reference names are not checked against ``CONNECTION_NAME_PATTERN``, so a name
    holding a credential-shaped ``key=`` can still be scrubbed out of a record."""
    return reference_record_name(name)


#: The settings that name the login a DATABASE source dials, and which the role probe is remembered
#: by (BACKLOG #2617). ``password`` is left out on purpose: the key must hold no credential.
_LOGIN_KEYS = ("server", "port", "database", "auth", "username")


def reference_acquire_timeout(settings: Mapping[str, Any]) -> float:
    """Read a DATABASE reference source's ``acquire_timeout`` by the rule in
    :func:`~messagefoundry.transports.base.float_setting`, or refuse it (BACKLOG #3432).

    One reader for the sync and for ``build_check_registry``, so an ``env()`` value the sync would
    refuse fails ``messagefoundry check`` too. ``DatabaseRef`` reads a literal the same way."""
    return float_setting(
        settings.get("acquire_timeout", DEFAULT_STORE_ACQUIRE_TIMEOUT),
        knob="acquire_timeout",
        transport="DATABASE reference source",
    )


def reference_max_rows(settings: Mapping[str, Any]) -> int | None:
    """Read a DATABASE reference source's ``max_rows``: a ceiling, or ``None`` when ``0`` turned it
    off (BACKLOG #2617). Unset takes :data:`~messagefoundry.config.wiring.DEFAULT_REFERENCE_MAX_ROWS`.

    One reader for the sync and for ``build_check_registry``, as :func:`reference_acquire_timeout` is,
    so an ``env()`` value the sync would refuse fails ``messagefoundry check`` too. ``DatabaseRef``
    reads a literal by the same rule when it is declared."""
    from messagefoundry.transports.database import max_rows_setting

    return max_rows_setting(
        settings.get("max_rows"),
        label="DATABASE reference source",
        default=DEFAULT_REFERENCE_MAX_ROWS,
    )


def reference_statement_timeout(settings: Mapping[str, Any]) -> int:
    """Read a DATABASE reference source's ``statement_timeout``, in whole seconds, ``0`` for no
    limit, or refuse it, by the DATABASE connector's rule (``transports.database._statement_timeout``,
    BACKLOG #5756). Unset is :data:`~messagefoundry.config.models.DEFAULT_DB_STATEMENT_TIMEOUT`,
    since a ``DatabaseRef`` is always the SQL Server preset.

    One reader for the sync and for ``build_check_registry``, as :func:`reference_acquire_timeout` is,
    so an ``env()`` value the sync would refuse fails ``messagefoundry check`` too."""
    from messagefoundry.transports.database import _statement_timeout

    return _statement_timeout(settings, "DATABASE reference source")


def reference_statement(settings: Mapping[str, Any], *, name: str | None = None) -> str:
    """Return a DATABASE reference source's ``statement`` once it passes the read-only statement test,
    or raise :class:`ReferenceStatementRefused` (BACKLOG #2617).

    The test is ``db_lookup``'s own (``transports.database._require_read_only``), so the two gates
    cannot drift: the statement must open with ``SELECT`` or ``WITH``, carry no write, ``EXEC`` or DDL
    keyword outside a literal or comment, and chain no second statement. A stored procedure is
    therefore refused. ``DatabaseRef`` runs the same test when declared, ``build_check_registry`` calls
    this, and so does every sync, as a backstop for a spec built without ``DatabaseRef``. An absent
    statement raises the plain :class:`ReferenceSyncError` for a missing setting instead.

    It is a shape test on text, not read-only authority, and the sync pool is autocommit, so a write
    that passed it would commit. The login's privilege is the control (docs/CONNECTIONS.md).

    The refusal is raised outside the handler, so it carries no ``DbLookupError`` chain. Its text is
    the fixed refusal vocabulary and the set's name, never the statement."""
    from messagefoundry.transports.database import _require_read_only

    where = "" if name is None else f"reference set {name!r}: "
    statement = str(settings.get("statement") or "")
    if not statement:
        # A missing statement is a missing setting, not a statement the gate refused.
        raise ReferenceSyncError(f"{where}DATABASE reference source requires a 'statement'")
    refusal: str | None = None
    try:
        _require_read_only(statement, subject="DatabaseRef statement")
    except DbLookupError as exc:
        refusal = str(exc)
    if refusal is not None:
        raise ReferenceStatementRefused(f"{where}{refusal}")
    return statement


def database_source_dsn(settings: Mapping[str, Any], *, connection: str | None = None) -> str:
    """Build a DATABASE reference source's DSN, refusing weakened TLS unless the set is attested.

    The refusal reads no hop posture: it holds at every posture (vault BACKLOG #3533 item 2).

    The one place both callers build it: the sync, just before it dials, and ``build_check``, so
    weakened TLS that every sync would refuse also fails ``messagefoundry check``, dry-run and
    reload (vault BACKLOG #2354). The source is always the SQL Server preset, since ``DatabaseRef`` takes no
    ``dialect``. The per-connection attestation is read and validated here too (#200).

    The DSN advertises ``ApplicationIntent=ReadOnly``, as the ``db_lookup`` DSN does (BACKLOG #2617).
    Which servers act on it, and how, is stated once in ``transports.database._build_dsn``: at least
    a read-only replica can serve the sync, with lagging data, and a ``READ_WRITE`` primary can
    refuse it (docs/CONNECTIONS.md)."""
    from messagefoundry.transports.database import _build_dsn

    attested = hop_attestation_from_settings(settings)
    return _build_dsn(dict(settings), read_only=True, attested=attested, connection=connection)


async def _fetch_reference_rows(cur: Any, limit: int | None, name: str | None) -> list[Any]:
    """Fetch a reference statement's rows, refusing more than ``limit`` (BACKLOG #2617).

    Under a ceiling the fetch is ``db_lookup``'s own (``transports.database.fetch_at_most``), so the
    driver is asked for at most ``limit + 1`` rows and never the whole result. ``None``
    (``max_rows=0``) is the operator's opt-out, and fetches everything as before."""
    from messagefoundry.transports.database import fetch_at_most

    if limit is None:
        return list(await cur.fetchall())
    rows, over = await fetch_at_most(cur, limit)
    if over:
        # PHI-free: the set and the ceiling only, never the statement or a row.
        where = "" if name is None else f"reference set {name!r}: "
        raise ReferenceRowCeilingExceeded(
            f"{where}the DatabaseRef statement returned more than max_rows={limit} rows; "
            "narrow the statement, or raise max_rows on this DatabaseRef"
        )
    return rows


async def _load_database_source(
    settings: Mapping[str, Any],
    egress: EgressSettings,
    *,
    posture: HopPosture | None = None,
    name: str | None = None,
    probed: set[tuple[str, ...]] | None = None,
) -> dict[str, Any]:
    """Materialize a SQL-backed reference source (ADR 0006 increment 2) into ``{key: value}``.

    Runs the operator's ``statement`` once it passes :func:`reference_statement`; ``key_column`` is the
    key; ``value_column`` (if set) is the value, else the value is a dict of the other columns. The
    dial-out is gated by the fail-closed ``[egress].allowed_db`` allowlist (like a DATABASE poll
    source). Reuses ``transports/database.py`` for the DSN/pool (the SQL-Server ``[sqlserver]`` extra).

    The result is bounded by :func:`reference_max_rows` at the fetch (BACKLOG #2617): the driver is
    asked for at most ``max_rows + 1`` rows, and one past the ceiling raises
    :class:`ReferenceRowCeilingExceeded`. The set is never built from a truncated result. The runner
    then keeps the last-good snapshot, as for any source failure.

    It fails in at least these classes too (BACKLOG #5891), each class's docstring saying when:
    :class:`ReferenceStatementTimedOut`, :class:`ReferenceStatementTimeoutRefused`,
    :class:`ReferenceColumnMismatch` and :class:`ReferenceKeyRefused`.

    ``posture`` is the instance hop posture (vault BACKLOG #2354). A sync runs after start, outside
    every ``active_hop_posture`` scope, so it is handed down and stamped here. Since vault BACKLOG
    #3533 item 2 no cell under that stamp reads it, so it is inert: a DatabaseRef is always the SQL
    Server preset, and the weakened-TLS refusal and attestation audit line in ``_build_dsn`` read
    none. The refusal refuses a DatabaseRef with
    ``encrypt=false`` or ``trust_server_certificate=true`` at every posture, unless the set is
    attested, even with ``MEFOR_ALLOW_INSECURE_TLS`` set at ``[security].enforcement = warn``
    (vault BACKLOG #3533 item 2). ``None``
    keeps the ambient posture, so a caller already inside a scope is unchanged. ``name`` is the reference set, so a
    refusal or an attestation line names it.

    Once the pool is open, the login's fixed-role membership is probed before the statement runs
    (BACKLOG #2617, ``transports.database.probe_login_roles``). It warns on a database-wide write
    role and never refuses or raises. ``probed`` remembers which set and login have been probed, so
    the runner probes each once rather than every pass; a set pointed at another login, server or
    database, as on a reload, is probed again. ``None`` probes on every call. A pool that fails to
    open is not probed, and a probe that did not run is not remembered, so the next pass probes
    either again."""
    from messagefoundry.transports.database import (
        _QUERY_TIMEOUT_REFUSED_STATES,
        LoginRoleVerdict,
        _apply_statement_timeout,
        _bound_statements,
        _close_and_release,
        _close_pool_bounded,
        _cursor_refusal_discards,
        _cursor_refused,
        _log_sqlstate,
        _login_timeout,
        _make_pool,
        _sqlstate,
        probe_login_roles,
    )

    where = "" if name is None else f"reference set {name!r}: "
    refused_text = (
        f"{where}the database driver refused statement_timeout; set statement_timeout = 0"
        " on this DatabaseRef if its driver cannot take one"
    )
    server = str(settings.get("server", ""))
    # `egress` is required (vault BACKLOG #2605): a caller that passed none used to skip this check.
    # The same [egress].allowed_db rule as a db_lookup, so the two cannot drift.
    try:
        check_lookup_allowed(name or server, settings, egress, label="DATABASE reference source")
    except WiringError as exc:
        raise ReferenceSyncError(str(exc)) from exc
    key_col = settings.get("key_column")
    value_col = settings.get("value_column")
    if not key_col or not settings.get("statement"):
        raise ReferenceSyncError("DATABASE reference source requires 'statement' and 'key_column'")
    # BACKLOG #2617: DatabaseRef and build_check refuse the statement already; this backstop holds
    # for a spec that reached the runner without either. Before the DSN and the pool, so nothing is
    # dialled. The statement executed below is the value this returned, the one the gate read.
    statement = reference_statement(settings, name=name)
    # Fail loud on weakened TLS or bad auth, before dialing; why the posture is stamped is in the
    # docstring. Unlike wiring_runner._build_lookup_executor, a None posture keeps the ambient one.
    connection = None if name is None else reference_connection_name(name)
    with active_hop_posture(posture if posture is not None else current_hop_posture()):
        dsn = database_source_dsn(settings, connection=connection)
    # BACKLOG #1052: bound the borrow. This pool is throwaway (closed in the finally below), but the
    # acquire was unbounded, so an unresponsive server could hold the reference-sync runner's pass
    # open indefinitely — and the runner is a single sequential loop over every declared set, so one
    # wedged source would stall the sync of all the others. A StoreAcquireTimeout is an Exception, so
    # the runner's existing per-set source-failure handler catches it, keeps the last-good snapshot
    # and alerts, exactly as it does for any other source error.
    # Read before the pool is made, so a refused value leaves no pool unclosed (BACKLOG #3432).
    acquire_timeout = reference_acquire_timeout(settings)
    limit = reference_max_rows(settings)  # BACKLOG #2617, read early for the same reason
    statement_timeout = reference_statement_timeout(settings)  # read early for the same reason
    pool = await _make_pool(
        dsn,
        count_setting(
            settings.get("pool_max", 5), knob="pool_max", transport="DATABASE reference source"
        ),
        autocommit=True,
        login_timeout=_login_timeout(settings, "DATABASE reference source"),
    )
    # Every borrow from this pool carries the statement timeout, as a DATABASE connector's does
    # (BACKLOG #5756). A non-zero value bounds each statement call (execute, each fetch) as the ODBC
    # query timeout, not the pass as a whole. Nothing bounds it at least at 0, on a pool that could
    # not be tracked, or on a driver connection with no timeout (both logged at WARNING; see
    # _bound_statements and _apply_statement_timeout).
    _bound_statements(pool, statement_timeout)
    try:
        # What names the login, never the password, so the remembered key holds no credential.
        probe_key = (str(name),) + tuple(str(settings.get(k, "")) for k in _LOGIN_KEYS)
        if probed is None or probe_key not in probed:
            reading = await probe_login_roles(
                pool,
                label=connection or "DATABASE reference source",
                acquire_timeout=acquire_timeout,
            )
            # A probe that did not run judged nothing, so the next pass tries again.
            if probed is not None and reading.verdict is not LoginRoleVerdict.NOT_RUN:
                probed.add(probe_key)
        conn = await acquire_pooled(pool, timeout=acquire_timeout, backend="reference:database")
        # Before the cursor is made, since pyodbc sets the query timeout on each cursor as it is
        # made, and before the try below: on a refusal it gives the connection back itself.
        timeout_refused = False
        try:
            await _apply_statement_timeout(pool, conn, timeout=acquire_timeout)
        except NegativeAckError:
            timeout_refused = True  # raised below, outside the handler, so no chain is carried
        if timeout_refused:
            raise ReferenceStatementTimeoutRefused(refused_text)
        timed_out = False
        discard = False
        cur: Any = None
        try:
            try:
                cur = await conn.cursor()
            except Exception as exc:
                # A driver that takes the connection timeout but refuses it on a cursor refuses
                # every cursor (docs/CONNECTIONS.md, the statement_timeout facts). The states are
                # the connector's own, read as _cursor_refused reads them, so the two cannot drift.
                state = _log_sqlstate(exc)
                if not statement_timeout or state not in _QUERY_TIMEOUT_REFUSED_STATES:
                    # Any other driver refusal is the connection's failure, classified as a
                    # DATABASE connector's is, and the handle is not lent again (BACKLOG #5749).
                    refused = _cursor_refused(exc, pool)
                    if refused is None:
                        raise
                    discard = _cursor_refusal_discards(refused)
                    raise refused from exc
                timeout_refused = True  # raised below, outside the handler
            if cur is not None:
                try:
                    await cur.execute(statement)
                    columns = [d[0] for d in cur.description]
                    rows = await _fetch_reference_rows(cur, limit, name)
                except Exception as exc:
                    # Read as this setting firing only where one was set.
                    if not statement_timeout or _sqlstate(exc) != _STATEMENT_TIMEOUT_STATE:
                        raise
                    timed_out = True  # raised below, outside the handler: driver text is withheld
        finally:
            # A cancellation returns the connection only once its statement and cursor close have
            # ended (BACKLOG #2394). The pool close below stops waiting for such a held connection
            # at a bound, so once a stop cancels this sync, a statement with no time limit does not
            # hold that stop. An uncancelled statement's calls are bounded by statement_timeout
            # except in the cases the comment at the _bound_statements call above lists.
            await _close_and_release(pool, conn, cur, discard=discard)
    finally:
        await _close_pool_bounded(pool, "DATABASE reference source")
    if timeout_refused:
        raise ReferenceStatementTimeoutRefused(refused_text)
    if timed_out:
        raise ReferenceStatementTimedOut(
            f"{where}the DatabaseRef statement ran past statement_timeout={statement_timeout}s;"
            " narrow the statement, or raise statement_timeout on this DatabaseRef"
        )
    return _rows_to_snapshot(columns, rows, key_col, value_col, name)


def _rows_to_snapshot(
    columns: list[Any], rows: Iterable[Any], key_col: Any, value_col: Any, name: str | None
) -> dict[str, Any]:
    """Build a DATABASE source's ``{key: value}`` set, or refuse it whole.

    A result that does not fit the declared columns is refused rather than built. The refusals are
    listed on :class:`ReferenceColumnMismatch` and :class:`ReferenceKeyRefused`; a
    ``value_column`` the result lacks, a NULL key, or two rows with one key would otherwise replace
    the last-good snapshot with ``None`` values, a ``"None"`` key, or whichever duplicate came last,
    and a column held twice, as a join can, leaves which one is meant untold. The refusals name the
    set and, where one applies, a setting or row ordinals, never a column's name or a key: a key may
    be PHI, and the sync logs these whole."""
    where = "" if name is None else f"reference set {name!r}: "
    for role, col in (("key_column", key_col), ("value_column", value_col)):
        if col is None:
            continue
        count = columns.count(col)
        if count != 1:
            problem = "is not among" if count == 0 else "names more than one of"
            raise ReferenceColumnMismatch(
                f"{where}the DatabaseRef {role} {problem} the statement's result columns;"
                " refusing the snapshot"
            )
    key_at = columns.index(key_col)
    value_at = None if value_col is None else columns.index(value_col)
    others = [(c, i) for i, c in enumerate(columns) if c != key_col] if value_at is None else []
    if len({c for c, _ in others}) != len(others):
        # The dict shape would keep only the last of two same-named columns.
        raise ReferenceColumnMismatch(
            f"{where}the statement's result holds a column name twice and no value_column is"
            " set; alias the columns apart, or set value_column; refusing the snapshot"
        )
    out: dict[str, Any] = {}
    for ordinal, row in enumerate(rows):
        raw_key = row[key_at]
        if raw_key is None:
            raise ReferenceKeyRefused(
                f"{where}row #{ordinal} has a NULL key_column; refusing the snapshot"
            )
        key = str(raw_key)
        if key in out:
            # Rare, so the first row is found by a rescan rather than a second map of every key.
            first = list(out).index(key)
            raise ReferenceKeyRefused(
                f"{where}rows #{first} and #{ordinal} have the same key_column value; refusing the"
                " snapshot (key value withheld: reference keys may be PHI)"
            )
        if value_at is not None:
            out[key] = _cell(row[value_at])
        else:
            out[key] = {c: _cell(row[i]) for c, i in others}
    return out


class ReferenceSyncRunner:
    """Supervises periodic materialization of declared reference sets into store snapshots (ADR 0006).

    ``specs`` is a *provider* (re-read each pass) so a config reload's new declarations are picked up;
    ``env_values`` resolves any :func:`~messagefoundry.config.wiring.env` refs in a source's settings.
    It is a mapping, copied once, or a provider read at each set's sync, which is how the engine hands
    in its values, so a reload that adds or rotates a value reaches the next sync (vault BACKLOG #5698).
    """

    def __init__(
        self,
        store: Store,
        specs: Callable[[], Iterable[ReferenceSpec]],
        settings: ReferenceSettings,
        *,
        env_values: Mapping[str, Any] | Callable[[], Mapping[str, Any]] | None = None,
        egress: EgressSettings,
        alert_sink: AlertSink | None = None,
        coordinator: ClusterCoordinator | None = None,
        clock: Callable[[], float] = time.time,
        hop_posture: HopPosture | None = None,
    ) -> None:
        self._store = store
        self._specs = specs
        self._settings = settings
        if callable(env_values):
            self._env_values: Callable[[], Mapping[str, Any]] = env_values
        else:
            fixed = dict(env_values or {})
            self._env_values = lambda: fixed
        self._egress = egress
        # Handed to every DATABASE source load; see _load_database_source (vault BACKLOG #2354).
        self._hop_posture = hop_posture
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        # Cluster coordination seam (Track B Step 6). None → the no-op NullCoordinator, whose
        # is_leader() is always True, so single-node materializes from source every pass EXACTLY as
        # before. In a cluster, only the leader materializes from source; every node still converges its
        # local read cache from the shared snapshot (the convergence call is a no-op on single-node).
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Per-set last successful sync time (single-task state) — drives per-spec refresh cadence.
        self._last_sync: dict[str, float] = {}
        # Sets this backend can NEVER materialize (write_reference_snapshot raises NotImplementedError —
        # e.g. a backend with no `reference` tables). A permanent incapability, not a transient source
        # failure: retrying is guaranteed-futile, so a set lands here once and is skipped thereafter.
        self._unsupported: set[str] = set()
        # BACKLOG #2617: each DATABASE set's login is role-probed once per DSN, not every pass.
        self._roles_probed: set[tuple[str, ...]] = set()
        # BACKLOG #5892: a background pass can overlap a reload's or promotion's forced sync, so each
        # load takes a start sequence, and a load does not write over one that started after it.
        # This orders loads in THIS process only; see _sync_one.
        self._load_sequence = 0
        self._written_sequence: dict[str, int] = {}
        self._write_locks: dict[str, KeyedLock] = {}

    @property
    def enabled(self) -> bool:
        """True when at least one reference set is declared (else :meth:`start` spawns no task)."""
        return any(True for _ in self._specs())

    def start(self) -> None:
        """Spawn the supervised materialization loop (no-op when no reference sets are declared)."""
        if self._task is not None:
            return
        if not self.enabled:
            log.debug("no reference sets declared; reference sync not started")
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "reference sync enabled: refresh_interval=%gs", self._settings.refresh_interval_seconds
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:  # noqa: SIM105
                await task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        # One isolated pass per interval; a pass error is logged and the loop continues (a sync hiccup
        # must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("reference sync pass failed; will retry next interval")
            await self._sleep(self._settings.refresh_interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop."""
        if delay <= 0:
            delay = 3600.0
        try:  # noqa: SIM105
            await asyncio.wait_for(self._stop.wait(), delay)
        except TimeoutError:
            pass

    async def sync_all(self, now: float | None = None) -> _SyncPass:
        """Force a sync of **every** declared set regardless of cadence (the startup pass)."""
        return await self.run_once(now=now, force=True)

    async def run_once(self, now: float | None = None, *, force: bool = False) -> _SyncPass:
        """One reference-sync pass: (1) materialize-from-source the due sets ON THE LEADER ONLY, then
        (2) ALWAYS converge this node's read cache from the shared store (Track B Step 6).

        Step (1) materializes each declared set whose refresh is due (or all, if ``force``) by reading
        its external source and writing a new shared snapshot — but only when this node is the leader, so
        in a cluster the source is read once. A follower skips (1). :class:`NullCoordinator` is always
        leader, so single-node materializes from source every pass exactly as before. A set's source
        failure is isolated: logged + alerted and the last-good snapshot kept (the write is simply not
        attempted), so one bad source never blocks the others. A store that cannot materialize snapshots
        AT ALL (``write_reference_snapshot`` raises ``NotImplementedError``) is a different animal — a
        permanent backend incapability, reported ONCE at ERROR and then never retried, rather than
        mis-reported as a transient source failure every interval forever.

        Step (2) calls :meth:`~messagefoundry.store.base.QueueStore.converge_reference_cache` so a
        follower picks up the leader's just-written snapshot into its own in-process read cache (the
        read-through). It runs **only when clustered** (``coordinator.is_clustered()``): on a single
        node this handle is the sole writer, so its cache is always current and the call is skipped
        entirely — keeping single-node behaviour byte-identical (no extra DB round-trip per pass)."""
        now = self._clock() if now is None else now
        synced = failed = 0
        if self._coordinator.is_leader():
            # LEADER (or single-node): re-read the external source for the due sets and write the
            # shared snapshot. A follower skips this entirely so the source is read once per cluster.
            for spec in self._specs():
                if spec.name in self._unsupported:
                    continue  # backend can never materialize it — already reported once, don't re-spam
                last = self._last_sync.get(spec.name)  # None = never synced -> always due
                if not force and last is not None and (now - last) < spec.refresh_seconds:
                    continue
                try:
                    await self._sync_one(spec)
                    self._last_sync[spec.name] = now
                    synced += 1
                except NotImplementedError:
                    # PERMANENT BACKEND INCAPABILITY, not a flaky source — the store has no reference-
                    # snapshot table to write into (ADR 0006 "Backend support"). Retrying can never
                    # succeed, and reporting it as a source failure would be an outright lie twice over:
                    # the source is fine, and there is no "last-good" snapshot to keep (there never was
                    # one and there never can be). So: report ONCE at ERROR, naming the incapability, and
                    # never retry. With the start-time gate (check_reference_backend_supported) this is
                    # unreachable in a served engine — it is defense-in-depth for an embedding that
                    # constructs the runner directly, and it must never again present a permanent defect
                    # as a transient one. Exception text is deliberately not logged (see below).
                    failed += 1
                    self._unsupported.add(spec.name)
                    log.error(
                        "reference set %r cannot be materialized: the store backend does not implement "
                        "reference snapshots (ADR 0006 'Backend support') — NOT retrying; the set will "
                        "never load and reference(%r) will raise in a Handler",
                        spec.name,
                        spec.name,
                    )
                    self._alert(spec.name, "backend does not support reference sets (not retrying)")
                    continue
                except Exception as exc:  # source failure → keep last-good, alert, continue
                    failed += 1
                    # Log/alert the set name + error CLASS only — never str(exc): a source error (e.g. a
                    # CSV duplicate-key) can embed a reference KEY, which may be PHI for a patient-keyed
                    # set (CLAUDE.md §9 / PHI.md §7 — no PHI in the general log). The operator knows which
                    # set failed and inspects the source themselves (the RetentionRunner "counts/category
                    # only" discipline). Full exception detail is intentionally not surfaced here.
                    kind = type(exc).__name__
                    log.warning(
                        "reference set %r sync failed (keeping last-good): %s", spec.name, kind
                    )
                    self._alert(spec.name, f"source sync failed ({kind})")
        # CLUSTERED ONLY: read-through any newer shared snapshot into the local cache so a follower
        # converges on what the leader materialized. Skipped entirely on a single node (is_clustered()
        # False), where this handle is the SOLE writer of its reference snapshots — so its cache is
        # always current and converge could never find a newer version. That short-circuit keeps
        # single-node Postgres byte-identical (no extra periodic JOIN/decrypt round-trip per pass), not
        # just SQLite/SQL Server (whose converge already returns []). The decrypt-failure isolation here
        # mirrors step (1)'s per-set guard: one un-decryptable set (e.g. a cross-node key mismatch) must
        # not abort the whole pass and the leader's materialization with it.
        refreshed: list[str] = []
        if self._coordinator.is_clustered():
            try:
                refreshed = await self._store.converge_reference_cache()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Convergence read/decrypt failed (e.g. a cross-node encryption-key mismatch). Log the
                # error CLASS only (a decrypt failure could carry snapshot bytes / a PHI-bearing key —
                # CLAUDE.md §9) and continue: keep the last-good local cache and retry next interval.
                kind = type(exc).__name__
                log.warning("reference cache convergence failed (keeping current cache): %s", kind)
                self._alert("<converge>", f"cache convergence failed ({kind})")
        if refreshed:
            # Names only (a set name is operator config, not PHI) at INFO so an operator can see a
            # follower converge; never the keys/values (which may be PHI).
            log.info(
                "reference cache converged %d set(s): %s", len(refreshed), ", ".join(refreshed)
            )
        result = _SyncPass(synced=synced, failed=failed, converged=len(refreshed))
        if result.did_work:
            await self._audit(result)
        return result

    async def _sync_one(self, spec: ReferenceSpec) -> None:
        # BACKLOG #5892: taken first, because the env() read below is part of what this load read.
        self._load_sequence += 1
        started = self._load_sequence
        # Resolve env() refs in the source settings against this instance's environment. A hop-policy
        # flag is refused first, while still raw, as build_check does (vault BACKLOG #2232).
        try:
            refuse_unresolved_hop_flags(spec.source.settings, f"reference set {spec.name!r}")
            # Vault BACKLOG #3234: a non-bool literal on a boolean setting, as the load refuses it.
            refuse_bool_literals(spec.source.settings, f"reference set {spec.name!r}")
        except WiringError as exc:
            # Vault BACKLOG #3139: sync_all logs only the error class, since a source error can hold
            # a reference key. These refusals' text is config only: the set's name, the setting, a
            # type name and a remedy chosen by the setting and the value's type, which may say a
            # quoted string is a false spelling but never which. Never a value or the reason. So it
            # is logged whole, or the operator learns nothing beyond "WiringError".
            # The text already leads with "reference set '<name>': ", so it is not repeated.
            log.error("%s (not synced)", exc)
            raise
        settings = resolve_env_settings(spec.source.settings, self._env_values())
        kind = spec.source.kind
        if kind == "file":
            rows = await asyncio.to_thread(
                _load_file_source, settings
            )  # blocking file I/O off-loop
        elif kind == "database":
            try:
                rows = await _load_database_source(  # async aioodbc dial
                    settings,
                    self._egress,
                    posture=self._hop_posture,
                    name=spec.name,
                    probed=self._roles_probed,
                )
            except (ReferenceColumnMismatch, ReferenceKeyRefused) as exc:
                # Logged whole, as ReferenceKeyCollision is below: the text holds the set's name and,
                # by refusal, the column setting, or the row ordinals, never a column name or a key.
                log.error("%s (not synced)", exc)
                raise
        else:
            raise ReferenceSyncError(
                f"reference set {spec.name!r}: unknown source kind {kind!r} (file, database)"
            )
        # BACKLOG #5892: held for the check and the write only. Held across the source read above, a
        # wedged source would block a reload's load of this set. It orders loads in this process, so
        # it cannot order a former leader's in-flight write against a new leader's on another node.
        async with hold_keyed_lock(self._write_locks, spec.name):
            if self._written_sequence.get(spec.name, 0) > started:
                log.debug("reference set %r: a later-started load already wrote it", spec.name)
                return
            # Unique per write regardless of sub-second timing: a uuid suffix on the wall-clock
            # seconds, so two re-materializations of the SAME set inside one second still get
            # DISTINCT versions. A follower's converge compares version strings, so an identical
            # version would make it SKIP a genuine re-materialization and keep stale data (Track B
            # Step 6 correctness). The leading seconds keep versions roughly time-ordered for an
            # operator reading reference_version.
            version = f"v{int(self._clock())}-{uuid4().hex[:8]}"
            try:
                await self._store.write_reference_snapshot(
                    name=spec.name, version=version, rows=rows
                )
            except ReferenceKeyCollision as exc:
                # BACKLOG #4917: sync_all logs only the class. This text holds the set's name and two
                # ordinals, never a key, so it is logged whole: the ordinals find the rows in the
                # source.
                log.error("%s (not synced)", exc)
                raise
            # Only after the write returned: a later load that failed must not skip this one's.
            self._written_sequence[spec.name] = started
        log.info(
            "reference set %r materialized: %d rows (version %s)", spec.name, len(rows), version
        )

    def _alert(self, name: str, detail: str) -> None:
        # The AlertSink has no reference-specific event yet; use connection_stopped as the generic
        # "a named component degraded" signal (never raises — be defensive anyway).
        try:
            self._alert_sink.connection_stopped(reference_connection_name(name), detail=detail)
        except Exception:
            log.warning("reference sync alert sink failed", exc_info=True)

    async def _audit(self, result: _SyncPass) -> None:
        detail = json.dumps(
            {"synced": result.synced, "failed": result.failed, "converged": result.converged},
            sort_keys=True,
        )
        await self._store.record_audit("reference_sync", actor="system", detail=detail)
