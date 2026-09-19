# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``[settings]`` type check over CONTAINER-annotated parameters (BACKLOG #1809).

BACKLOG #1650 holds a ``[settings]`` value to its factory parameter's annotation and opts out of
containers **by design**: a ``dict[str, str]`` member is not in ``_SCALAR_TYPES``, so the annotation
walk returned ``None``, which is a SKIP. #1809 is that boundary rather than a bug in #1650. A
deliberate boundary that leaves a hole has to be visible as its own row, or the next reader cannot
tell "checked and safe" from "checked and excluded".

What the hole was: ``headers = 5`` on a REST outbound passed ``validate_config``, passed the scalar
check, passed the factory, and reached the connector unchecked. On first deployment a site that wrote
it would find out from the connector on a live message instead of from a load-time refusal naming the
connection.

A SEPARATE FILE from ``test_connections_file.py`` on purpose: that one carries the scalar pass and is
edited heavily on the branch beneath this one.
"""

from __future__ import annotations

import inspect
import typing
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.connections_file import (
    _MAPPING_ORIGINS,
    _TRANSPORTS,
    _check_setting_types,
    _factory_signature,
    literal_values_typed,
    union_members,
)
from messagefoundry.config.wiring import (
    EnvRef,
    Soap,
    WiringError,
    load_config,
)
from tests.test_connections_file import _config

WHERE = "outbound connection 'OB'"


def _check(transport: str, settings: dict[str, Any]) -> None:
    _check_setting_types(_TRANSPORTS[transport], settings, transport, WHERE)


def _rest(settings_toml: str) -> str:
    """A minimal REST outbound carrying ``settings_toml`` in its ``[settings]`` table."""
    return f"""
        [[outbound]]
        name = "OB"
        transport = "rest"
          [outbound.settings]
          url = "https://partner.example/ingest"
{settings_toml}
        """


# --- the outer shape ---------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "detail"),
    [
        ("          headers = 5", "'headers' must be a table, got an integer"),
        ('          headers = ["a"]', "'headers' must be a table, got an array"),
        (
            '          capture_response_headers = "content-type"',
            "'capture_response_headers' must be an array, got a string",
        ),
        ("          proxy_no_proxy = 5", "'proxy_no_proxy' must be an array, got an integer"),
    ],
    ids=["table-got-int", "table-got-array", "array-got-string", "array-got-int"],
)
def test_a_wrong_outer_shape_is_refused_at_load(tmp_path: Path, line: str, detail: str) -> None:
    """The headline of #1809, end to end through the file rather than through the helper.

    ``headers = 5`` is the case the row was cut for. The array arm is here because the two shapes
    fail in opposite directions and one implementation can easily get only one of them right."""
    with pytest.raises(WiringError) as excinfo:
        load_config(_config(tmp_path, _rest(line)))
    assert detail in str(excinfo.value)
    assert "OB" in str(excinfo.value), "a refusal that does not name the connection is unactionable"


def test_a_string_is_not_an_array_even_though_python_calls_it_a_sequence(tmp_path: Path) -> None:
    """``Sequence[str]`` means an ARRAY here, and that is a decision, not an accident.

    ``str`` satisfies ``Sequence[str]`` in the type system, so accepting one would be defensible on
    paper and wrong in practice: ``proxy_no_proxy = "host"`` iterates as four characters. The
    factories spell the string alternative out when they mean it -- ``Email``'s
    ``recipients: list[str] | str | EnvRef`` -- so a bare sequence annotation means an array."""
    with pytest.raises(WiringError, match="must be an array, got a string"):
        load_config(
            _config(
                tmp_path,
                """
                [[inbound]]
                name = "IB"
                transport = "http"
                router = "r"
                  [inbound.settings]
                  port = 8443
                  intake_client_subjects = "CN:partner.example"
                """,
            )
        )


# --- one level in ------------------------------------------------------------


def test_a_wrong_element_is_refused_even_though_the_outer_shape_is_right(tmp_path: Path) -> None:
    """The trap an outer-type-only check falls into: ``{"X-Key" = 5}`` IS a table."""
    with pytest.raises(WiringError) as excinfo:
        load_config(_config(tmp_path, _rest("          headers = { X-Key = 5 }")))
    assert "'headers' entry 'X-Key' must be a string, got an integer" in str(excinfo.value)


def test_a_wrong_array_item_is_refused_and_named_by_index(tmp_path: Path) -> None:
    """The index is the whole navigational value of the message on a long array."""
    with pytest.raises(WiringError) as excinfo:
        load_config(
            _config(
                tmp_path,
                _rest('          capture_response_headers = ["content-type", 5]'),
            )
        )
    assert "'capture_response_headers' item 1 must be a string, got an integer" in str(
        excinfo.value
    )


def test_a_correct_container_still_loads(tmp_path: Path) -> None:
    """THE POSITIVE CONTROL. Without it every refusal above is equally consistent with a check that
    refuses containers outright, which would be a worse defect than the one #1809 names."""
    reg = load_config(
        _config(
            tmp_path,
            _rest(
                '          headers = { X-Key = "abc", Accept = "application/json" }\n'
                '          capture_response_headers = ["content-type", "x-request-id"]'
            ),
        )
    )
    assert reg.outbound["OB"].spec.settings["headers"] == {
        "X-Key": "abc",
        "Accept": "application/json",
    }
    assert reg.outbound["OB"].spec.settings["capture_response_headers"] == [
        "content-type",
        "x-request-id",
    ]


# --- the depth cap -----------------------------------------------------------


def _nested_factory(*, deep: dict[str, list[str]], flat: dict[str, str]) -> None:
    """A stand-in carrying an annotation one level deeper than this check walks."""


def test_the_element_walk_is_one_level_deep_and_the_control_proves_it_walks(
    tmp_path: Path,
) -> None:
    """The depth cap, with the control that makes it a cap rather than a broken walk.

    ``dict[str, list[str]]`` is skipped at ELEMENT depth because the element annotation is itself a
    container -- the cap is structural, not a counter, so no ``connections.toml`` can make this walk
    descend. The ``flat`` arm is the control: the same walk over ``dict[str, str]`` DOES refuse a bad
    element, so the skip above is the cap doing its job and not the walk failing to run.

    The OUTER shape is still judged on the nested one, which is the point of capping rather than
    skipping the parameter whole."""
    _check_setting_types(_nested_factory, {"deep": {"a": [5]}}, "fake", WHERE)  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="'flat' entry 'a' must be a string, got an integer"):
        _check_setting_types(_nested_factory, {"flat": {"a": 5}}, "fake", WHERE)  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="'deep' must be a table, got an integer"):
        _check_setting_types(_nested_factory, {"deep": 5}, "fake", WHERE)  # type: ignore[arg-type]


def _unmodelled_factory(*, pair: tuple[str, str], anything: Any) -> None:
    """Shapes this module does not model: a fixed-length tuple and an unconstrained ``Any``."""


@pytest.mark.parametrize("key", ["pair", "anything"])
def test_an_unmodelled_annotation_skips_rather_than_refusing(key: str) -> None:
    """A shape the walk cannot read must let the value THROUGH to the factory's own guards.

    This gate's failure mode has to be letting something past, never blocking a correct file: a
    wrongly refused ``connections.toml`` cannot be worked around, while a wrongly accepted value
    still meets the factory."""
    _check_setting_types(_unmodelled_factory, {key: 5}, "fake", WHERE)  # type: ignore[arg-type]


# --- env() references, which are a different rule owned elsewhere ------------


@pytest.mark.parametrize(
    "value",
    [{"env": "PARTNER_KEY"}, {"env": "PARTNER_KEY", "default": "d"}, {"env": "K", "cast": "str"}],
    ids=["bare", "with-default", "with-cast"],
)
def test_a_nested_env_marker_is_skipped_not_refused(value: dict[str, str]) -> None:
    """A raw ``{env = "..."}`` table one level down IS a dict, and must not be read as a bad string.

    ``parse_env_setting`` desugars the marker only at the TOP level of ``[settings]``, so a nested one
    arrives here as a plain dict and this check cannot tell a legal one from a mistake. Whether it is
    legal there is a DIFFERENT rule, answered by the factories (``_hoist_body_secrets``,
    ``_reject_envref_odbc_params``) and by the separate nested-headers refusal that is still open
    work. A type refusal here would preempt every one of those with a worse message."""
    _check("rest", {"headers": {"X-Key": value}})
    _check("database", {"odbc_params": {"TrustServerCertificate": value}})


def test_a_nested_envref_object_is_skipped_too() -> None:
    """The code-first spelling of the same thing. Reached only by a direct call -- the loader path
    never produces a nested ``EnvRef`` -- and pinned so the two spellings cannot drift apart."""
    _check("rest", {"headers": {"X-Key": EnvRef(key="k", default=None, cast=None)}})


def test_a_table_that_only_looks_like_an_env_marker_is_still_judged() -> None:
    """The mirror of the test above, and the reason the predicate is imported rather than guessed.

    ``{ not = "a marker" }`` has no ``env`` key, so it is an ordinary table in a string position and
    the check must still refuse it. Without this, "skip anything dict-shaped" would pass every arm of
    the test above while checking nothing."""
    with pytest.raises(WiringError, match="'headers' entry 'X-Key' must be a string, got a table"):
        _check("rest", {"headers": {"X-Key": {"not": "a marker"}}})


def test_an_env_only_container_stays_the_factorys(tmp_path: Path) -> None:
    """SOAP's ``body_secrets: Mapping[str, EnvRef]`` is skipped WHOLE, outer shape included.

    Its factory refuses both depths already and names the shape it wants, which beats a generic
    "must be a table"; ``connection_schema._code_first_only`` separately reports the setting
    unauthorable in TOML. Asserted through the factory so this pins the behaviour a deploying author
    would actually meet, not merely that this module declined to speak."""
    _check("soap", {"body_secrets": 5})
    _check("soap", {"body_secrets": {"tok": "inline"}})
    with pytest.raises(WiringError, match="body_secrets must be a mapping"):
        Soap(url="https://p.example/svc", soap_action="a", body_secrets=5)  # type: ignore[arg-type]


# --- an env() default that is a container ------------------------------------


def test_an_env_default_is_judged_at_both_depths() -> None:
    """``resolve_env_settings`` returns a ``default`` WITHOUT applying the ref's ``cast``, so a
    default is the half of an env() ref that is knowable at load. A container default gets the same
    two-depth treatment as a scalar one, and the cast note is suppressed at element depth where it
    would name a conversion nobody asked about."""
    with pytest.raises(WiringError) as outer:
        _check("rest", {"headers": EnvRef(key="h", default=5, cast=None)})
    assert "'headers' env() default must be a table, got an integer" in str(outer.value)
    assert "a default is not converted by the ref's cast" in str(outer.value)

    with pytest.raises(WiringError) as inner:
        _check("rest", {"headers": EnvRef(key="h", default={"X-Key": 5}, cast=None)})
    assert "'headers' env() default entry 'X-Key' must be a string, got an integer" in str(
        inner.value
    )
    assert "converted by the ref's cast" not in str(inner.value)


# --- the refusal must not echo the value -------------------------------------


@pytest.mark.parametrize(
    "settings",
    [
        {"headers": {"Authorization": 12345678901234567890}},
        {"headers": 12345678901234567890},
        {"capture_response_headers": [12345678901234567890]},
    ],
    ids=["element", "outer", "item"],
)
def test_the_refusal_never_echoes_the_value(settings: dict[str, Any]) -> None:
    """A ``[settings]`` value can be a bearer token or a connector key, and this string reaches the
    operator log, the support bundle and ``GET /logs/tail``. The connection, the setting name, the
    POSITION and both types are the whole diagnostic; the value is not part of it (BACKLOG #1183).

    The element arm is the one that could regress: naming a position invites naming the thing at it."""
    with pytest.raises(WiringError) as excinfo:
        _check("rest", settings)
    assert "12345678901234567890" not in str(excinfo.value)


# --- the assumption this check rests on --------------------------------------


@pytest.mark.parametrize("transport", sorted(_TRANSPORTS))
def test_every_mapping_setting_is_keyed_str(transport: str) -> None:
    """TOML table keys are always strings, so the element walk judges VALUES and not keys.

    That is sound only while every mapping-annotated setting is keyed ``str``. Pinned rather than
    assumed: a future ``dict[int, str]`` would silently go unchecked on its key half, and the fix is
    to build that half, not to widen this test. Named per transport so a failure says which one."""
    signature = _factory_signature(_TRANSPORTS[transport])
    assert signature is not None
    offenders = [
        f"{name}: {member}"
        for name, param in signature.parameters.items()
        for member in literal_values_typed(union_members(param.annotation))
        if typing.get_origin(member) in _MAPPING_ORIGINS
        and typing.get_args(member)
        and typing.get_args(member)[0] is not str
    ]
    assert not offenders, f"{transport}: mapping settings keyed by something other than str"


@pytest.mark.parametrize("transport", sorted(_TRANSPORTS))
def test_the_container_settings_are_actually_reached(transport: str) -> None:
    """The COVERAGE control. Every test above judges REST, HTTP, DATABASE or SOAP; this one asserts
    the walk reads the container parameters of every transport that has any, so a future transport
    growing one cannot arrive silently unjudged.

    Zero container parameters is a legitimate answer for most transports and is not a failure -- what
    would be a failure is a container parameter the walk declines to read for a reason nobody chose.
    The one deliberate decline is asserted by name above (SOAP's ``body_secrets``)."""
    signature = _factory_signature(_TRANSPORTS[transport])
    assert signature is not None
    for name, param in signature.parameters.items():
        members = literal_values_typed(union_members(param.annotation))
        if not any(typing.get_origin(member) is not None for member in members):
            continue
        if name == "body_secrets":
            continue  # asserted as a deliberate skip by test_an_env_only_container_stays_the_factorys
        with pytest.raises(WiringError, match=f"{name!r} must be"):
            _check_setting_types(
                _TRANSPORTS[transport],
                {name: object()},
                transport,
                WHERE,
            )


# --- the scalar pass beneath this one ----------------------------------------


def test_the_scalar_check_is_unchanged() -> None:
    """A PIN, not evidence for #1809: these pass with or without this change, and they are here
    because #1809 rewrites the annotation walk the scalar check reads through. If a scalar refusal
    ever changes wording, it changes here first rather than in a surprised reader's config."""
    with pytest.raises(WiringError, match="'port' must be an integer or an env\\(\\) reference"):
        _check("mllp", {"port": "2575"})
    with pytest.raises(WiringError, match="'persistent' must be true or false, got a string"):
        _check("mllp", {"persistent": "yes"})
    _check("mllp", {"port": 2575})
    inspect.signature(_TRANSPORTS["mllp"])  # the factory is a real callable, not a stand-in
