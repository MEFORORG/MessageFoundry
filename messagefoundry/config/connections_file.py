# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Read ``connections.toml`` — connections authored as **data** (ADR 0007).

A connection's transport (type + settings), the inbound's ``router`` binding, and delivery knobs may
live in an optional ``connections.toml`` next to the code-first ``*.py`` modules. This module decodes
that file into the **same** :class:`~messagefoundry.config.wiring.InboundConnection` /
:class:`~messagefoundry.config.wiring.OutboundConnection` registry entries the ``inbound()`` /
``outbound()`` factories produce — so the runtime, validation, egress gating, and reload are all
unchanged. *Logic* (Routers/Handlers) stays code-first ``*.py``; only transport *config* is data.

Each ``transport`` is mapped to the existing transport factory and called with the decoded settings,
so a TOML connection yields a **byte-identical** ``ConnectionSpec`` to the code-first form and inherits
every factory default and guard — **the factory is the schema**, there is no second source of truth.
An unknown transport, an unexpected/typo'd key, or a malformed value fails loud as a ``WiringError``
naming the connection, exactly like a bad ``inbound()`` call.

``env()`` references are written as an inline table ``{ env = "key", default = ..., cast = "int" }``
(see :func:`~messagefoundry.config.wiring.parse_env_setting`); secrets stay in ``env()``, never inline.
"""

from __future__ import annotations

import tomllib
from enum import Enum
from pathlib import Path
from typing import Any, Callable, TypeVar

from messagefoundry.config.models import (
    AckAfter,
    AckMode,
    BatchConfig,
    BuildupThreshold,
    ContentType,
    InternalErrorPolicy,
    OrderingMode,
    Priority,
    RetryPolicy,
    Schedule,
    StallThreshold,
)
from messagefoundry.config.wiring import (
    ConnectionSpec,
    Database,
    DatabasePoll,
    File,
    Ftp,
    Http,
    InboundConnection,
    MLLP,
    OutboundConnection,
    Registry,
    Rest,
    Sftp,
    Soap,
    Tcp,
    Timer,
    WiringError,
    build_inbound_connection,
    build_outbound_connection,
    parse_env_setting,
)

#: The file an engine config dir may carry alongside its ``*.py`` modules.
CONNECTIONS_FILE_NAME = "connections.toml"

#: ``transport`` value → the transport factory it desugars to. The factory validates its own settings,
#: so this table is the *only* connection between a TOML transport name and its connector.
_TRANSPORTS: dict[str, Callable[..., ConnectionSpec]] = {
    "mllp": MLLP,
    "tcp": Tcp,
    "http": Http,
    "file": File,
    "timer": Timer,
    "rest": Rest,
    "database": Database,
    "database_poll": DatabasePoll,
    "soap": Soap,
    "sftp": Sftp,
    "ftp": Ftp,
}

# The keys each connection table may carry; anything else is a typo and fails loud.
_INBOUND_KEYS = frozenset(
    {
        "name",
        "transport",
        "settings",
        "router",
        "ack_mode",
        "ack_after",
        "strict",
        "hl7_version",
        "strict_timeout_s",
        "content_type",
        "metadata",
        "bind_address",
        "source_ip_allowlist",
        "capture_ack",
        "capture_connection_errors",
        "messages_days",
        "prune_documents_after",
        "prune_documents_min_bytes",
        "priority",
        "shard",
        "schedule",
    }
)
_OUTBOUND_KEYS = frozenset(
    {
        "name",
        "transport",
        "settings",
        "retry",
        "ordering",
        "internal_error",
        "buildup",
        "stall",
        "batch",
        "simulate",
        "dead_letter_days",
        "priority",
        "metadata",
        "schedule",
    }
)

_E = TypeVar("_E", bound=Enum)
_M = TypeVar("_M")  # a policy model (RetryPolicy/BuildupThreshold/StallThreshold) — not an Enum


def load_connections_file(path: Path, registry: Registry) -> None:
    """Decode ``path`` and add its connections to ``registry`` (in place).

    Raises :class:`WiringError` on any malformed entry — a duplicate name (including a name already
    declared in a ``*.py`` module) surfaces as the registry's ``duplicate ... name`` error, so the two
    authoring surfaces can't silently shadow each other."""
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise WiringError(f"cannot read {path.name}: {exc}") from exc

    extra = set(data) - {"inbound", "outbound"}
    if extra:
        raise WiringError(
            f"{path.name}: unknown top-level key(s) {', '.join(sorted(extra))} "
            "(expected [[inbound]] / [[outbound]] arrays of tables)"
        )

    source = str(path)
    for table in _as_tables(data.get("inbound", []), "inbound", path):
        registry.add_inbound(_inbound_from_table(table, source))
    for table in _as_tables(data.get("outbound", []), "outbound", path):
        registry.add_outbound(_outbound_from_table(table, source))


def _inbound_from_table(table: dict[str, Any], source: str) -> InboundConnection:
    name = _require_str(table, "name", "[[inbound]]")
    where = f"inbound connection {name!r}"
    _reject_unknown(table, _INBOUND_KEYS, where)
    spec = _build_spec(_require_str(table, "transport", where), table, where)
    return build_inbound_connection(
        name,
        spec,
        router=_require_str(table, "router", where),
        ack_mode=_enum(AckMode, table["ack_mode"], "ack_mode", where)
        if "ack_mode" in table
        else AckMode.ORIGINAL,
        ack_after=_enum(AckAfter, table["ack_after"], "ack_after", where)
        if table.get("ack_after") is not None
        else None,
        strict=_require_bool(table, "strict", where),
        hl7_version=_optional_str(table, "hl7_version", where),
        strict_timeout_s=_optional_float(table, "strict_timeout_s", where),
        content_type=_enum(ContentType, table["content_type"], "content_type", where)
        if "content_type" in table
        else ContentType.HL7V2,
        metadata=_optional_table(table, "metadata", where),
        bind_address=_optional_str(table, "bind_address", where),
        source_ip_allowlist=_optional_str_list(table, "source_ip_allowlist", where),
        capture_ack=_optional_bool(table, "capture_ack", where),
        capture_connection_errors=_optional_bool(table, "capture_connection_errors", where),
        messages_days=_optional_int(table, "messages_days", where),
        prune_documents_after=_optional_int(table, "prune_documents_after", where),
        prune_documents_min_bytes=_optional_int(table, "prune_documents_min_bytes", where),
        priority=_enum(Priority, table["priority"], "priority", where)
        if table.get("priority") is not None
        else None,
        shard=_optional_str(table, "shard", where),
        schedule=_policy(Schedule, table.get("schedule"), "schedule", where),
        source_file=source,
        source_line=None,
    )


def _outbound_from_table(table: dict[str, Any], source: str) -> OutboundConnection:
    name = _require_str(table, "name", "[[outbound]]")
    where = f"outbound connection {name!r}"
    _reject_unknown(table, _OUTBOUND_KEYS, where)
    spec = _build_spec(_require_str(table, "transport", where), table, where)
    return build_outbound_connection(
        name,
        spec,
        retry=_policy(RetryPolicy, table.get("retry"), "retry", where),
        ordering=_enum(OrderingMode, table["ordering"], "ordering", where)
        if table.get("ordering") is not None
        else None,
        internal_error=_enum(InternalErrorPolicy, table["internal_error"], "internal_error", where)
        if table.get("internal_error") is not None
        else None,
        buildup=_policy(BuildupThreshold, table.get("buildup"), "buildup", where),
        stall=_policy(StallThreshold, table.get("stall"), "stall", where),
        batch=_policy(BatchConfig, table.get("batch"), "batch", where),
        simulate=_require_bool(table, "simulate", where),
        dead_letter_days=_optional_int(table, "dead_letter_days", where),
        priority=_enum(Priority, table["priority"], "priority", where)
        if table.get("priority") is not None
        else None,
        metadata=_optional_table(table, "metadata", where),
        schedule=_policy(Schedule, table.get("schedule"), "schedule", where),
        source_file=source,
        source_line=None,
    )


# --- decoding helpers --------------------------------------------------------


def _build_spec(transport: str, table: dict[str, Any], where: str) -> ConnectionSpec:
    """Resolve ``transport`` to its factory and call it with the decoded ``[settings]`` table."""
    factory = _TRANSPORTS.get(transport)
    if factory is None:
        raise WiringError(
            f"{where}: unknown transport {transport!r} "
            f"(use one of {', '.join(sorted(_TRANSPORTS))})"
        )
    raw = table.get("settings", {})
    if not isinstance(raw, dict):
        raise WiringError(f"{where}: [settings] must be a table")
    settings = {key: parse_env_setting(value) for key, value in raw.items()}
    try:
        return factory(**settings)
    except WiringError:
        raise
    except (TypeError, ValueError) as exc:
        # A missing required / unexpected / wrong-typed setting — the factory IS the schema.
        raise WiringError(f"{where}: invalid {transport!r} settings — {exc}") from exc


def _as_tables(value: Any, key: str, path: Path) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise WiringError(f"{path.name}: [[{key}]] must be an array of tables")
    return value


def _reject_unknown(table: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    extra = set(table) - allowed
    if extra:
        raise WiringError(
            f"{where}: unknown key(s) {', '.join(sorted(extra))} "
            f"(allowed: {', '.join(sorted(allowed))})"
        )


def _require_str(table: dict[str, Any], key: str, where: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise WiringError(f"{where}: {key!r} must be a non-empty string")
    return value


def _optional_str(table: dict[str, Any], key: str, where: str) -> str | None:
    if key not in table or table[key] is None:
        return None
    value = table[key]
    if not isinstance(value, str):
        raise WiringError(f"{where}: {key!r} must be a string")
    return value


def _optional_table(table: dict[str, Any], key: str, where: str) -> dict[str, Any] | None:
    if key not in table or table[key] is None:
        return None
    value = table[key]
    if not isinstance(value, dict):
        raise WiringError(f"{where}: {key!r} must be a table (key/value mapping)")
    return value


def _optional_str_list(table: dict[str, Any], key: str, where: str) -> list[str] | None:
    if key not in table or table[key] is None:
        return None
    value = table[key]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise WiringError(f"{where}: {key!r} must be an array of strings")
    return value


def _require_bool(table: dict[str, Any], key: str, where: str) -> bool:
    if key not in table:
        return False
    value = table[key]
    if not isinstance(value, bool):
        raise WiringError(f"{where}: {key!r} must be true or false")
    return value


def _optional_bool(table: dict[str, Any], key: str, where: str) -> bool | None:
    """A tri-state bool: absent → ``None`` (inherit the default), else the bool. Used for the
    Corepoint-style event-log per-connection overrides (#46), where ``None`` means "inherit the
    ``[diagnostics]`` master switch" — distinct from an explicit ``false``."""
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, bool):
        raise WiringError(f"{where}: {key!r} must be true or false")
    return value


def _optional_int(table: dict[str, Any], key: str, where: str) -> int | None:
    """A tri-state int: absent/None → ``None`` (inherit the global default), else the int. Used for the
    per-connection retention overrides (#34, ADR 0027) ``messages_days``/``dead_letter_days``, where
    ``None`` means "inherit the ``[retention]`` window", ``0`` = keep forever, ``>0`` = days. A ``bool``
    is rejected (TOML ``true``/``false`` is an int subclass but never a valid window)."""
    if key not in table or table[key] is None:
        return None
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise WiringError(f"{where}: {key!r} must be an integer number of days (0 = keep forever)")
    return value


def _optional_float(table: dict[str, Any], key: str, where: str) -> float | None:
    """A tri-state float: absent/None → ``None`` (inherit the engine default), else the number. Used for
    the per-connection ``strict_timeout_s`` strict-validation backstop (#89), where ``None`` means
    "inherit ``_STRICT_VALIDATE_TIMEOUT_SECONDS``" and ``<= 0`` disables it. A ``bool`` is rejected
    (TOML ``true``/``false`` is an int subclass but never a valid duration); an int is accepted and
    widened to float (TOML ``5`` and ``5.0`` are equivalent seconds)."""
    if key not in table or table[key] is None:
        return None
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WiringError(
            f"{where}: {key!r} must be a number of seconds (<= 0 disables the backstop)"
        )
    return float(value)


def _enum(enum_cls: type[_E], value: Any, key: str, where: str) -> _E:
    try:
        return enum_cls(value)
    except ValueError as exc:
        allowed = ", ".join(repr(member.value) for member in enum_cls)
        raise WiringError(f"{where}: invalid {key} {value!r} (allowed: {allowed})") from exc


def _policy(model_cls: Callable[..., _M], raw: Any, key: str, where: str) -> _M | None:
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise WiringError(f"{where}: [{key}] must be a table")
    try:
        return model_cls(**raw)
    except (ValueError, TypeError) as exc:
        raise WiringError(f"{where}: invalid {key} — {exc}") from exc
