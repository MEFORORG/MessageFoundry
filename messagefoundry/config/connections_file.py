# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
naming the connection, exactly like a bad ``inbound()`` call. A **wrong-typed** value fails there too:
the factory's parameter ANNOTATIONS are part of that same schema, and
:func:`_check_setting_types` holds each ``[settings]`` value to them before the factory is called.

``env()`` references are written as an inline table ``{ env = "key", default = ..., cast = "int" }``
(see :func:`~messagefoundry.config.wiring.parse_env_setting`); secrets stay in ``env()``, never inline.
"""

from __future__ import annotations

import inspect
import tomllib
import types
import typing
from collections.abc import Callable
from enum import Enum
from functools import cache
from pathlib import Path
from typing import Any, TypeVar

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
    MLLP,
    ConnectionSpec,
    Database,
    DatabasePoll,
    EnvRef,
    File,
    Ftp,
    Http,
    InboundConnection,
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
        "stream_threshold_bytes",
        "max_message_bytes",
        "priority",
        "shard",
        "schedule",
        # Lifecycle flags (#115 auto_start, #233/ADR 0111 deployed). Both default TRUE, so an existing
        # table that carries neither is byte-identical. auto_start was code-first-only until #233 —
        # the docs claimed otherwise — so it joins the schema here alongside deployed.
        "auto_start",
        "deployed",
        # Operator "object of interest" flag (#131, ADR 0007 amendment) — default FALSE, so an existing
        # table without it is byte-identical. The FIRST console-settable connections.toml key (its write
        # seam rides connections_edit); display-only, no runtime effect.
        "flagged",
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
        "auto_start",  # see the inbound note above
        "deployed",
        "flagged",  # #131 (ADR 0007 amendment); see the inbound note above
        # Cosmetic "Waiting for Reply" pre-display delay (#136, ADR 0065 amendment) — default 0.0, so an
        # existing table without it is byte-identical. Display-only; no delivery effect.
        "waiting_display_delay",
        # ADR 0153 decision 2: the per-outbound cleartext-hop acceptance. TOP-LEVEL keys (as the ADR's
        # TOML sample shows them), NOT under [settings] — a hop *policy* declaration belongs beside the
        # connection's other governance keys, and [settings] is the transport factory's own schema
        # (see _build_spec: "the factory IS the schema"), which no factory would accept.
        "cleartext_accepted",
        "cleartext_reason",
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
        stream_threshold_bytes=_optional_int(table, "stream_threshold_bytes", where),
        max_message_bytes=_optional_int(table, "max_message_bytes", where),
        priority=_enum(Priority, table["priority"], "priority", where)
        if table.get("priority") is not None
        else None,
        shard=_optional_str(table, "shard", where),
        schedule=_policy(Schedule, table.get("schedule"), "schedule", where),
        # Both lifecycle flags default TRUE (an absent key means "run it", as it always has).
        auto_start=_require_bool(table, "auto_start", where, default=True),
        deployed=_require_bool(table, "deployed", where, default=True),
        # #131: the object-of-interest flag defaults FALSE (an absent key = unflagged).
        flagged=_require_bool(table, "flagged", where, default=False),
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
        retry=_policy(RetryPolicy, _coerce_retry_forever(table.get("retry")), "retry", where),
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
        # Both lifecycle flags default TRUE (an absent key means "run it", as it always has).
        auto_start=_require_bool(table, "auto_start", where, default=True),
        deployed=_require_bool(table, "deployed", where, default=True),
        # #131: the object-of-interest flag defaults FALSE (an absent key = unflagged).
        flagged=_require_bool(table, "flagged", where, default=False),
        # #136: the cosmetic waiting-for-reply pre-display delay; absent = 0.0 (show immediately).
        waiting_display_delay=_optional_float(table, "waiting_display_delay", where) or 0.0,
        # ADR 0153: the cleartext-hop acceptance pair; absent = off, so an existing table is
        # byte-identical. The flag/reason coherence rules live once in build_outbound_connection, so
        # this surface and the code-first outbound() surface cannot drift.
        cleartext_accepted=_require_bool(table, "cleartext_accepted", where, default=False),
        cleartext_reason=_optional_str(table, "cleartext_reason", where),
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
    _check_setting_types(factory, settings, transport, where)
    try:
        return factory(**settings)
    except WiringError:
        raise
    except (TypeError, ValueError) as exc:
        # A missing required / unexpected / wrong-typed setting — the factory IS the schema.
        raise WiringError(f"{where}: invalid {transport!r} settings — {exc}") from exc


# --- [settings] scalar typing (BACKLOG #1650) --------------------------------
# The factories are plain Python functions, so their annotations (`port: int | EnvRef`,
# `max_frame_bytes: int | None`, `persistent: bool`) are documentation at run time and nothing more.
# A code-first author at least has mypy available over their config dir (`messagefoundry check` runs
# it, advisory, when it finds one); a connections.toml author had nothing at all, so a quoted number
# or a string boolean reached the connector intact. The three shapes that cost the most:
#
#   port = "2575"            -> Registry.port_collisions() skips it (it keeps only int ports), so a
#                               DUPLICATE quoted port is invisible at validate time. It is still
#                               caught later, by inbound_binding_conflicts via _resolve_port, which
#                               deliberately parses a numeric string -- so this one fails LOUD in the
#                               end, just later and from a different check than the author expects.
#   max_frame_bytes = "16"   -> no check anywhere: the connector compares a frame length against a
#                               STRING and raises TypeError on the first message.
#   persistent = "yes"       -> the worst of the three, because nothing ever errors. A non-empty
#                               string is truthy, so the outbound silently runs in the posture the
#                               author did not ask for.
#
# REFUSE, never coerce. Coercing would make `validate` green on a config its author got wrong, which
# is the whole defect. The check is scoped to the [settings] table, which is the factory's own schema;
# the TOP-LEVEL keys keep their own decoding helpers above (`max_attempts = "forever"` is a deliberate
# string spelling up there and must keep working).

#: The scalar types a ``[settings]`` value can arrive as from TOML. ``bool`` LEADS because it is an
#: ``int`` subclass: order matters everywhere below, and a plain ``isinstance(value, int)`` would read
#: TOML ``true`` as a valid integer -- the silent acceptance this check exists to stop.
_SCALAR_TYPES: tuple[type, ...] = (bool, int, float, str)

#: How each scalar reads in an operator-facing message.
_SCALAR_WORDS: dict[type, str] = {
    bool: "true or false",
    int: "an integer",
    float: "a number",
    str: "a string",
}


@cache
def _factory_signature(factory: Callable[..., ConnectionSpec]) -> inspect.Signature | None:
    """``factory``'s signature with annotations RESOLVED, or ``None`` when they will not resolve.

    ``eval_str=True`` is required: ``wiring.py`` carries ``from __future__ import annotations``, so
    without it every annotation is the string ``"int | EnvRef"`` and no type check is possible.

    ``None`` means **skip the check**, never "accept the value". A failed resolve is the one way this
    gate could quietly become the false green it was built to remove: a check that reports OK having
    examined nothing is worse than no check, because it is reported as coverage.

    Cached because the resolve costs ~0.4 ms and every connection needs one. The key set is CLOSED --
    the values of :data:`_TRANSPORTS`, eleven module-level functions that are immortal anyway, so the
    cache retains nothing new. Never call this with a closure or a ``partial``: an unbounded cache
    keyed on a per-call callable would retain every one and hit on none."""
    try:
        return inspect.signature(factory, eval_str=True)
    except (NameError, TypeError):
        return None


def _check_setting_types(
    factory: Callable[..., ConnectionSpec],
    settings: dict[str, Any],
    transport: str,
    where: str,
) -> None:
    """Hold each ``[settings]`` value to its factory parameter's annotation, or raise ``WiringError``.

    Silently skips anything it cannot judge: an unresolvable signature, a key the factory does not
    declare (the factory's own ``unexpected keyword argument`` is the better message), and any
    annotation carrying a member this module does not model."""
    signature = _factory_signature(factory)
    if signature is None:
        return
    for key, value in settings.items():
        param = signature.parameters.get(key)
        if param is None or param.kind is not inspect.Parameter.KEYWORD_ONLY:
            continue
        if isinstance(value, EnvRef):
            # An env() reference is legal on ANY setting, whether or not EnvRef is in the annotation:
            # resolve_env_settings resolves every ref in the table regardless, so the annotation is not
            # the authority on where a ref may be written. Its resolved value is checked by the ref's
            # own `cast` (a WiringError naming the setting and key), not here. NOTE the schema side
            # answers this question NARROWLY -- connection_schema._accepts_env reports env False for a
            # plain `str` setting -- so a GUI offers no env() control where this accepts one. Closing
            # that gap means changing the annotations or resolve_env_settings, both in wiring.py.
            continue
        accepted = _accepted_scalars(param.annotation)
        if accepted is None or _value_matches(value, accepted):
            continue
        detail = f"{key!r} must be {_render_expected(accepted, param.annotation)}, got {_word_for(value)}"
        if isinstance(value, str) and str not in accepted:
            detail += " (a quoted TOML value is a string: write it unquoted, or use an env() ref)"
        # The VALUE is deliberately absent. A [settings] value can be a password or a connector key,
        # and this string reaches the operator log, the support bundle and GET /logs/tail -- the same
        # reasoning that keeps the value out of resolve_env_settings' cast diagnostic (BACKLOG #1183).
        # The connection, the setting name and both types are the whole diagnostic an author needs.
        raise WiringError(f"{where}: invalid {transport!r} settings — {detail}")


def _accepted_scalars(annotation: Any) -> frozenset[type] | None:
    """The scalar types ``annotation`` accepts, or ``None`` meaning "do not check this setting".

    ``None`` must never be read as "accepted". It is returned for an annotation carrying a member this
    function does not model -- a container, ``Any``, a nested type -- because refusing a value against
    an annotation we cannot read would reject valid config, and this gate's failure mode must be
    letting something through rather than blocking a correct file."""
    if annotation is inspect.Parameter.empty:
        return None
    accepted: set[type] = set()
    for member in literal_values_typed(union_members(annotation)):
        if member is type(None):
            continue  # TOML has no null literal, so a None member constrains nothing here
        if member is EnvRef:
            continue  # handled by the caller; an env() ref never reaches the scalar test
        if member not in _SCALAR_TYPES:
            return None
        accepted.add(member)
    return frozenset(accepted) or None


def _scalar_of(value: Any) -> type | None:
    """The scalar type ``value`` presents as, or ``None`` for a table/array/datetime.

    ``bool`` LEADS :data:`_SCALAR_TYPES`, so TOML ``true`` never reads as an integer here. That single
    ordering is the whole defence against the mirror of the ``persistent = "yes"`` bug, which is why
    both callers read it from the constant instead of re-listing the types."""
    return next((scalar for scalar in _SCALAR_TYPES if isinstance(value, scalar)), None)


def _value_matches(value: Any, accepted: frozenset[type]) -> bool:
    scalar = _scalar_of(value)
    if scalar is None:
        return False
    # An int widens to a float: TOML `receive_timeout = 60` and `60.0` are the same number of seconds,
    # and refusing the first would break valid files. The one widening this check allows.
    return scalar in accepted or (scalar is int and float in accepted)


def _render_expected(accepted: frozenset[type], annotation: Any) -> str:
    words = [_SCALAR_WORDS[scalar] for scalar in _SCALAR_TYPES if scalar in accepted]
    rendered = " or ".join(words)
    if EnvRef in union_members(annotation):
        rendered += " or an env() reference"
    return rendered


def _word_for(value: Any) -> str:
    scalar = _scalar_of(value)
    if scalar is not None:
        return _SCALAR_WORDS[scalar]
    if isinstance(value, dict):
        return "a table"
    if isinstance(value, list):
        return "an array"
    return f"a {type(value).__name__}"


# --- annotation introspection, shared with connection_schema ------------------
# These live HERE rather than in connection_schema.py because that module already imports this one
# (_TRANSPORTS and the direction key sets), so the edge exists and only runs one way. Two copies of a
# union walk is how the schema a GUI renders from and the check a loader refuses with drift apart.


def union_members(annotation: Any) -> tuple[Any, ...]:
    """``annotation``'s union members, or a one-tuple when it is not a union."""
    origin = typing.get_origin(annotation)
    if origin is typing.Union or origin is types.UnionType:
        return typing.get_args(annotation)
    return (annotation,)


def literal_values_typed(members: tuple[Any, ...]) -> tuple[Any, ...]:
    """``members`` with each ``Literal[...]`` replaced by the TYPES of its allowed values.

    A choice-valued setting is annotated ``Literal["move", "delete", "leave"]`` (optionally ``| None``)
    and so carries **no bare ``str`` member**. A scalar scan over the raw members would report it
    unknown -- and the two consumers would fail opposite ways: the IDE form would lose the dropdown it
    picks from ``type``, and this module's check would skip the setting entirely. A literal's values
    carry the setting's real type, so use theirs. The CHOICE itself stays the factory's to validate."""
    out: list[Any] = []
    for member in members:
        if typing.get_origin(member) is typing.Literal:
            out.extend(type(value) for value in typing.get_args(member))
        else:
            out.append(member)
    return tuple(out)


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


def _require_bool(table: dict[str, Any], key: str, where: str, *, default: bool = False) -> bool:
    """A bool with a compile-time default: absent → ``default``, else the bool (a non-bool fails loud).
    ``default`` exists because the lifecycle flags (``auto_start``/``deployed``, #115/#233) default to
    TRUE while the feature flags (``strict``/``simulate``) default to FALSE — an absent key must mean
    the model's default, not a blanket ``False``."""
    if key not in table:
        return default
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


def _enum(enum_cls: type[_E], value: Any, key: str, where: str) -> _E:  # noqa: UP047
    try:
        return enum_cls(value)
    except ValueError as exc:
        allowed = ", ".join(repr(member.value) for member in enum_cls)
        raise WiringError(f"{where}: invalid {key} {value!r} (allowed: {allowed})") from exc


def _policy(model_cls: Callable[..., _M], raw: Any, key: str, where: str) -> _M | None:  # noqa: UP047
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise WiringError(f"{where}: [{key}] must be a table")
    try:
        return model_cls(**raw)
    except (ValueError, TypeError) as exc:
        raise WiringError(f"{where}: invalid {key} — {exc}") from exc


def _coerce_retry_forever(raw: Any) -> Any:
    """BACKLOG #1217 half 2. TOML has no null literal, so a per-outbound retry-forever posture
    (``[outbound.retry] max_attempts = "forever"``, case-insensitive) needs a string spelling here —
    mirrors the ``[delivery]`` global's field validator on ``DeliverySettings.retry_max_attempts``
    (``config/settings.py``). Anything else (not a table, no ``max_attempts`` key, or a value that
    isn't the literal word) passes through untouched so ``_policy``'s "must be a table" check and
    :class:`~messagefoundry.config.models.RetryPolicy`'s own validation still fire exactly as before.
    """
    if not isinstance(raw, dict):
        return raw
    value = raw.get("max_attempts")
    if isinstance(value, str) and value.strip().lower() == "forever":
        return {**raw, "max_attempts": None}
    return raw
