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
from collections import abc
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
    _ENVREF_KEYS,  # parse_env_setting's own env-marker key set -- mirrored, never re-derived
    _UNSET,  # the "no default=" sentinel an EnvRef carries
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
    try:
        # INSIDE the try, not above it. This module's contract is that a bad [settings] table fails
        # loud as a WiringError NAMING THE CONNECTION, and the check below reads annotations through
        # typing.get_origin/get_args over whatever wiring.py happens to declare, so a TypeError or
        # ValueError out of that walk would otherwise escape as a raw traceback naming nothing.
        #
        # IT ABSORBS TypeError AND ValueError, AND SAYS SO RATHER THAN IMPLYING MORE. A factory guard
        # that raises anything else still escapes, and one does today: `odbc_params = { env = "x" }`
        # reaches _reject_envref_odbc_params as an EnvRef, which calls .items() on it and raises
        # AttributeError past this handler (measured). Widening the catch is a change to the factory
        # boundary this branch does not own; the hole is recorded rather than papered over, because a
        # comment claiming coverage it does not have is worse than no comment (SDS-3.7).
        _check_setting_types(factory, settings, transport, where)
        return factory(**settings)
    except WiringError:
        raise
    except (TypeError, ValueError) as exc:
        # A missing required / unexpected / wrong-typed setting — the factory IS the schema.
        raise WiringError(f"{where}: invalid {transport!r} settings — {exc}") from exc


# --- [settings] value typing (BACKLOG #1650 scalars, #1809 containers) -------
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
#
# CONTAINERS were the boundary the scalar pass opted out of, and #1809 is that boundary rather than a
# bug in #1650. `headers: dict[str, str] | None` reached `_accepted_scalars`, failed
# `member not in _SCALAR_TYPES` and returned None -- a SKIP. So `headers = 5` passed validate, passed
# the scalar check, passed the factory, and reached the connector. A deliberate boundary that leaves a
# hole has to be visible as its own row, or the next reader cannot tell "checked and safe" from
# "checked and excluded". Two rules keep the container half honest:
#
#   OUTER SHAPE, then ONE LEVEL IN. `headers = {"X-Key" = 5}` IS a table, so an outer-type-only check
#   would pass it. The element walk is one level deep BY CONSTRUCTION, not by a counter:
#   `_element_accepted` returns None for a container element annotation, so there is no recursion to
#   bound and no crafted file can make this walk deep.
#
#   AN env() SPELLING IS A DIFFERENT RULE, OWNED ELSEWHERE, and an element written that way is
#   skipped. Stated once, in `_element_fits` -- including which positions have a downstream refusal
#   and which are open holes. Do not restate it here (SDS-3.5); the copy that drifts is the one
#   nobody is looking at.

#: The scalar types a ``[settings]`` value can arrive as from TOML. ``bool`` LEADS because it is an
#: ``int`` subclass: order matters everywhere below, and a plain ``isinstance(value, int)`` would read
#: TOML ``true`` as a valid integer -- the silent acceptance this check exists to stop.
_SCALAR_TYPES: tuple[type, ...] = (bool, int, float, str)

#: How each scalar reads as the type the setting EXPECTS ("must be ...").
_SCALAR_WORDS: dict[type, str] = {
    bool: "true or false",
    int: "an integer",
    float: "a number",
    str: "a string",
}

#: How each scalar reads as what the author ACTUALLY WROTE ("got ..."). Kept apart from
#: :data:`_SCALAR_WORDS` because the two are different sentences and only one of them is about the
#: file: a bool's allowed VALUES are "true or false", but a value of that type IS "a boolean". Reusing
#: the expectation word made a refusal read ``got true or false``, which describes the annotation and
#: tells the author nothing about the line they wrote.
_SCALAR_NOUNS: dict[type, str] = {
    bool: "a boolean",
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
    except (NameError, AttributeError, SyntaxError, TypeError):
        # AT LEAST these -- an undefined name, a renamed/moved type behind a dotted path, a malformed
        # annotation string, an unsupported operand -- because every one means the same thing here and
        # the answer is always SKIP. Not an enumeration of what `eval()` can raise (SDS-3.6): it can
        # raise anything, and an uncaught one still escapes. Catching only NameError and TypeError let
        # a SyntaxError ESCAPE as a raw traceback naming no connection (measured), past this module's
        # "fails loud as a WiringError" contract, for the failure class this path exists to absorb.
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
    annotation carrying a member this module does not model. An ``EnvRef`` is judged through its
    inline ``default`` only -- see the comment in the loop for why that is the half that is knowable
    here. A container value is judged at its outer shape and then one level in: :func:`_element_accepted`
    is the depth cap, :func:`_element_fits` the env()-marker carve-out."""
    signature = _factory_signature(factory)
    if signature is None:
        return
    for key, value in settings.items():
        param = signature.parameters.get(key)
        if param is None or param.kind is not inspect.Parameter.KEYWORD_ONLY:
            continue
        accepted = _accepted_types(param.annotation)
        if accepted is None:
            continue
        checked = value
        is_default = isinstance(value, EnvRef)
        if is_default:
            # An env() reference is legal on ANY setting, whether or not EnvRef is in the annotation:
            # resolve_env_settings resolves every ref in the table regardless, so the annotation is not
            # the authority on where a ref may be WRITTEN. NOTE the schema side answers that question
            # NARROWLY -- connection_schema._accepts_env reports env False for a plain `str` setting --
            # so a GUI offers no env() control where this accepts one. Closing that gap means changing
            # the annotations or resolve_env_settings, both in wiring.py.
            #
            # What CAN be judged here is an inline `default =`, because resolve_env_settings returns a
            # default WITHOUT applying the ref's `cast`. So `{ env = "m", cast = "int", default = "16" }`
            # reaches the factory as the STRING "16" -- the exact shape this check exists to stop,
            # written one level down where the cast looks like it covers it.
            #
            # The value that arrives FROM the environment is NOT judged here and must not be claimed to
            # be: an uncast ref hands the factory whatever the environment holds, as a string. That is
            # a RUNTIME value, so it belongs to the runtime numeric guards (step 2 of BACKLOG #1650),
            # which are not built.
            if value.default is _UNSET:
                continue
            checked = value.default
        problem = _first_type_problem(checked, accepted)
        if problem is None:
            continue
        suffix, judged, offender = problem
        # A DEFAULT may not itself be an env() ref -- parse_env_setting reads the env marker only at
        # the top level of [settings] -- so offering one here would be a remedy that loops straight
        # back to this same message with "got a table". An ELEMENT refusal suppresses it for a second
        # reason: an env() marker written one level down is SKIPPED above, never refused, so naming it
        # as the remedy would offer a spelling this check has no opinion on.
        subject = (f"{key!r} env() default" if is_default else repr(key)) + suffix
        expected = _render_expected(judged, None if is_default or suffix else param.annotation)
        detail = f"{subject} must be {expected}, got {_word_for(offender)}"
        if is_default and not suffix:
            # Without this the refusal reads as simply wrong to an author looking at the `cast = "int"`
            # they wrote on the same line. The reason lives in the comment above, where they cannot see it.
            detail += " (a default is not converted by the ref's cast)"
        elif judged.scalars and isinstance(offender, str) and str not in judged.scalars:
            # Stated as a FACT, not as an instruction. "Write it unquoted" is wrong for every value
            # that is not already a valid unquoted TOML spelling of the wanted type: it sends the
            # author of `persistent = "yes"` to `persistent = yes`, and of `port = "abc"` to
            # `port = abc`, both of which tomllib rejects -- a second, worse failure caused by the
            # first message's own advice.
            #
            # `judged.scalars` GUARDS it, because a CONTAINER refusal makes that advice wrong a second
            # way. The fix for `proxy_no_proxy = "host"` is `["host"]`; unquoting gives
            # `proxy_no_proxy = host`, which tomllib rejects. The hint fires only where a SCALAR was
            # wanted, which is the only position in which "unquote it" can ever be right.
            detail += " (a quoted TOML value is always a string, whatever it contains)"
        # The VALUE is deliberately absent, and an ELEMENT refusal keeps that promise the same way: it
        # names the entry KEY or the array INDEX and never the element's value. A [settings] value can
        # be a password or a connector key, and this string reaches the operator log, the support
        # bundle and GET /logs/tail -- the same reasoning that keeps the value out of
        # resolve_env_settings' cast diagnostic (BACKLOG #1183). The connection, the setting name, the
        # position and both types are the whole diagnostic an author needs.
        raise WiringError(f"{where}: invalid {transport!r} settings — {detail}")


#: Annotation origins a TOML **table** satisfies. A `connections.toml` table decodes to a ``dict``,
#: and the abstract spellings appear on the factories too (SOAP's ``body_secrets`` is a ``Mapping``).
_MAPPING_ORIGINS: frozenset[Any] = frozenset({dict, abc.Mapping, abc.MutableMapping})

#: Annotation origins a TOML **array** satisfies. ``str`` is deliberately absent even though Python
#: calls it a ``Sequence``: the factories spell a string alternative out when they mean it
#: (``recipients: list[str] | str | EnvRef``), so a bare ``Sequence[str]`` means an array, and letting
#: a string in would re-admit `proxy_no_proxy = "host"` iterating as four characters.
#: ``abc.Iterable``/``abc.Collection`` are absent for the opposite reason -- a table satisfies both, so
#: they cannot discriminate the two shapes. An origin not listed here is UNMODELLED, which is a skip.
_SEQUENCE_ORIGINS: frozenset[Any] = frozenset(
    {list, tuple, set, frozenset, abc.Sequence, abc.MutableSequence, abc.Set}
)


class _Accepted(typing.NamedTuple):
    """What one annotation accepts, split by the runtime shape a TOML value arrives as.

    Three fields rather than one set because the three are judged differently: a scalar is compared
    to a type, a table is compared to its VALUE annotations, an array to its ITEM annotations."""

    scalars: frozenset[type]
    mapping_values: tuple[Any, ...]
    sequence_items: tuple[Any, ...]


def _classify(annotation: Any) -> _Accepted | None:
    """Split ``annotation``'s union members by shape, or ``None`` when one is not modelled.

    The raw split, with no policy applied: unlike :func:`_accepted_types` it returns an empty
    ``_Accepted`` rather than folding "accepts nothing judgeable" into a skip, because the caller that
    judges ELEMENTS needs to see that emptiness to make its own decision about it."""
    if annotation is inspect.Parameter.empty:
        return None
    scalars: set[type] = set()
    mapping_values: list[Any] = []
    sequence_items: list[Any] = []
    for member in literal_values_typed(union_members(annotation)):
        if member is type(None):
            continue  # TOML has no null literal, so a None member constrains nothing here
        if member is EnvRef:
            continue  # handled by the callers; an env() ref never reaches a type test
        if member in _SCALAR_TYPES:
            scalars.add(member)
            continue
        origin = typing.get_origin(member)
        args = typing.get_args(member)
        if origin in _MAPPING_ORIGINS and len(args) == 2:
            mapping_values.append(args[1])
            continue
        if origin in _SEQUENCE_ORIGINS:
            item = _sequence_item(origin, args)
            if item is None:
                return None
            sequence_items.append(item)
            continue
        return None
    return _Accepted(frozenset(scalars), tuple(mapping_values), tuple(sequence_items))


def _sequence_item(origin: Any, args: tuple[Any, ...]) -> Any | None:
    """A sequence annotation's element type, or ``None`` when its shape is not modelled.

    ``tuple`` is the awkward one: ``tuple[str, ...]`` is a homogeneous array and ``tuple[str, int]``
    is a fixed shape whose members are positional. Only the first is an array an author can write."""
    if origin is tuple:
        return args[0] if len(args) == 2 and args[1] is Ellipsis else None
    return args[0] if len(args) == 1 else None


def _accepted_types(annotation: Any) -> _Accepted | None:
    """What ``annotation`` accepts, or ``None`` meaning "do not check this setting".

    ``None`` must never be read as "accepted". It is returned for THREE distinct reasons, named in
    PROSE only -- every one still returns a bare ``None`` and no caller can tell them apart, which is
    deliberate today and is the thing to change first if any of them ever needs its own answer:

    1. An annotation carrying a member this module does not model -- ``Any``, a bare ``dict``, a
       fixed-shape ``tuple``, a nested generic. Refusing a value against an annotation we cannot read
       would reject valid config, and this gate's failure mode must be letting something through
       rather than blocking a correct file.
    2. An annotation every member of which was understood, none of which is judgeable: an env()-ONLY
       setting such as ``File.credential_password: EnvRef | None``. Skipped DELIBERATELY -- all three
       such settings today are secrets whose factory raises a strictly better message than a generic
       type refusal ("must be an env() reference -- a share password is a secret and is never
       inline"). A future non-secret of this shape should be reconsidered here.

    A CONTAINER always answers with itself, however unreadable its elements are: the OUTER shape is
    knowable whatever they hold, so it is judged and only the element walk stops (:func:`_element_accepted`).

    **A THIRD REASON WAS TRIED AND REMOVED, which is worth the four lines it costs to say.** It
    skipped an env()-only container -- SOAP's ``body_secrets: Mapping[str, EnvRef] | None`` -- whole,
    outer shape included, on the ground that ``_hoist_body_secrets`` refuses a non-mapping with a
    better message. That premise is only HALF true: the factory's guard sits behind
    ``if not body_secrets: return {}``, so ``body_secrets = 0``, ``false``, ``""`` and ``[]`` were all
    accepted in silence and the connection ran with no body secrets at all (measured). A compensating
    control must not rest on a false premise, so the skip went and the outer shape is judged here;
    the ELEMENT walk still stops, which is what leaves the factory its better message on a table."""
    accepted = _classify(annotation)
    if accepted is None:
        return None  # reason 1
    if accepted.scalars or accepted.mapping_values or accepted.sequence_items:
        return accepted
    return None  # reason 2


def _accepted_scalars(annotation: Any) -> frozenset[type] | None:
    """The scalar types ``annotation`` accepts, or ``None`` meaning "no scalar to judge here".

    **It has no production caller** -- :func:`_check_setting_types` reads :func:`_accepted_types`
    directly. It is kept as the narrow question the schema-side coverage pin in
    ``tests/test_connections_file.py`` asks: does the check still READ this parameter as a scalar? A
    container-only annotation answers ``None`` here exactly as it did before containers were
    modelled, so that pin measures the same population it always did (225 of 238 keyword-only
    parameters, unchanged by #1809)."""
    accepted = _accepted_types(annotation)
    if accepted is None or not accepted.scalars:
        return None
    return accepted.scalars


def _element_accepted(annotations: tuple[Any, ...]) -> _Accepted | None:
    """What one level down accepts, or ``None`` to skip the element check.

    **THIS IS THE DEPTH CAP.** A container element annotation returns ``None`` here instead of
    recursing, so the walk is one level deep by construction: there is no recursion to bound, no
    depth counter to get wrong, and no crafted ``connections.toml`` that can make this descend.

    Stopping the ELEMENT walk is all it stops: the parameter's outer shape was already judged by the
    caller, whatever this answers. ``None`` covers two element shapes for one reason -- a nested
    container and an env()-only element are both unreadable here -- and the second is what leaves
    SOAP's ``body_secrets`` table to ``_hoist_body_secrets``, which judges it far better.

    Several annotations merge into one accepted set, which only ever makes the element check MORE
    permissive (``dict[str, str] | list[int]`` would accept a string item). No factory spells that
    shape today; a false refusal is the failure this gate must not have, and a merge cannot cause one."""
    scalars: set[type] = set()
    for annotation in annotations:
        accepted = _classify(annotation)
        if accepted is None or accepted.mapping_values or accepted.sequence_items:
            return None
        scalars |= accepted.scalars
    return _Accepted(frozenset(scalars), (), ()) if scalars else None


def _first_type_problem(value: Any, accepted: _Accepted) -> tuple[str, _Accepted, Any] | None:
    """The first value that does not fit, as ``(subject suffix, what judged it, the value)``.

    ``None`` when everything fits. The suffix names the POSITION inside a container (`` entry 'X'``,
    `` item 2``) and is empty for the setting itself, so one refusal site renders both depths."""
    if isinstance(value, dict):
        if not accepted.mapping_values:
            return "", accepted, value
        element = _element_accepted(accepted.mapping_values)
        if element is None:
            return None
        # TOML table KEYS are always strings, so a key type is never in question from a file; every
        # mapping annotation on a transport factory is keyed `str` today and a test pins that. If one
        # ever is not, the key half has to be built -- it is absent, not decided against.
        for name, item in value.items():
            if not _element_fits(item, element):
                return f" entry {name!r}", element, item
        return None
    if isinstance(value, list):
        if not accepted.sequence_items:
            return "", accepted, value
        element = _element_accepted(accepted.sequence_items)
        if element is None:
            return None
        for index, item in enumerate(value):
            if not _element_fits(item, element):
                return f" item {index}", element, item
        return None
    return None if _value_matches(value, accepted.scalars) else ("", accepted, value)


def _element_fits(value: Any, element: _Accepted) -> bool:
    """Does one element fit? An env() reference in either spelling is SKIPPED, not accepted.

    Same outcome, different reason, and the reason is the part that must not be lost: whether an
    env() ref may be WRITTEN one level down is a rule this module does not own. ``parse_env_setting``
    desugars the marker only at the top level of ``[settings]``, so a nested one arrives as a plain
    dict and a type check cannot tell a legal one from a mistake. Where a refusal exists it is the
    factory's and it is strictly better than a type message -- ``_hoist_body_secrets`` names the shape
    it wants, ``_reject_envref_odbc_params`` says why a nested ref cannot work -- and refusing here
    would preempt both.

    **WHERE NO REFUSAL EXISTS THE VALUE GOES THROUGH, and that is a HOLE, not a decision this skip
    makes safe.** When #1809 measured it, at least three loaded clean, survived
    ``resolve_env_settings`` unchanged, and reached the connector as a literal ``{'env': ...}`` table.
    Two now have a refusal at the factory seam: ``headers`` in ``_reject_envref_headers`` (BACKLOG
    #1649), and ``odbc_params`` in ``_reject_envref_odbc_params``, which tests the raw-dict spelling
    as well as an ``EnvRef`` (BACKLOG #1806). The third, any ``list[str]`` setting, was answered by
    nothing at all and is not re-measured here. None of them is #1809 -- this check judges TYPES --
    and a refusal written here would preempt the factory's, so a hole needs a row, not a patch."""
    if isinstance(value, EnvRef) or _is_env_marker(value):
        return True
    return _value_matches(value, element.scalars)


def _is_env_marker(value: Any) -> bool:
    """Is ``value`` the raw TOML spelling of an env() reference?

    Mirrors :func:`~messagefoundry.config.wiring.parse_env_setting`'s own guard and imports its key
    set rather than re-listing it, because a second copy of that predicate is how this module and the
    decoder would drift into disagreeing about what an env marker is."""
    return isinstance(value, dict) and "env" in value and set(value) <= _ENVREF_KEYS


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


def _render_expected(accepted: _Accepted, annotation: Any) -> str:
    """The expected-type clause. ``annotation`` may be ``None`` to suppress the env() alternative,
    for a position where an env() reference is not a legal spelling in the first place."""
    # One list, one join: appending to the joined string left a leading " or " whenever `accepted` was
    # empty, which is reachable the moment reason 2 in _accepted_types stops being a skip.
    words = [_SCALAR_WORDS[scalar] for scalar in _SCALAR_TYPES if scalar in accepted.scalars]
    if accepted.mapping_values:
        words.append("a table")
    if accepted.sequence_items:
        words.append("an array")
    if annotation is not None and EnvRef in union_members(annotation):
        words.append("an env() reference")
    return " or ".join(words)


def _word_for(value: Any) -> str:
    scalar = _scalar_of(value)
    if scalar is not None:
        return _SCALAR_NOUNS[scalar]
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
    """``annotation``'s union members, or a one-tuple when it is not a union.

    ``inspect.Parameter.empty`` comes back as a one-tuple, where the copy this replaced returned an
    empty one. Named because it is the ONE input on which the two differ, and every caller absorbs it:
    ``_type_name`` returns early on ``empty``, and the membership/origin tests in ``_code_first_only``,
    ``_choices``, ``_accepts_env`` and :func:`_accepted_scalars` all answer the same either way
    (verified over the 238 keyword-only factory parameter annotations and ``empty``: zero
    caller-visible differences)."""
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
