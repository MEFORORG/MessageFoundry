# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``reply_from`` inbound's reply settings are read env()-resolved (BACKLOG #5745).

The listener always read the resolved settings, while the runner's resolver and the cross-registry
check read the written ones. So ``reply_from=env("x")`` was checked as an outbound literally named
after the reference, and a content type written through ``env()`` would have been answered as the
reference's own repr.

``Http()`` still refuses ``env()`` on ``reply_timeout`` and ``reply_on_timeout``, so those two are
carried here on a spec with the setting replaced after the factory, the way
``test_env_uncast_bool_setting`` carries a capture flag.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ContentType, OrderingMode, RetryPolicy
from messagefoundry.config.settings import DeliverySettings, EgressSettings
from messagefoundry.config.wiring import (
    Http,
    InboundConnection,
    Registry,
    Rest,
    WiringError,
    apply_sync_reply_capture_implication,
    build_inbound_connection,
    build_outbound_connection,
    env,
)
from messagefoundry.pipeline.sync_reply import SyncReplyResolverImpl
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    build_check_registry,
    check_http_sync_reply,
)
from messagefoundry.store import MessageStore
from tests._harness_engine import free_port

SERVICEABLE = DeliverySettings(ordering=OrderingMode.UNORDERED, retry_max_attempts=3)


def _graph(
    *,
    deployed: bool = True,
    capture_response: bool = True,
    port: int = 0,
    **overrides: Any,
) -> tuple[Registry, InboundConnection]:
    """An inbound replying from ``OB_PARTNER``, its settings then overridden past the factory."""
    spec = Http(port=port, reply_from="OB_PARTNER")
    spec = dataclasses.replace(spec, settings={**spec.settings, **overrides})
    ic = build_inbound_connection(
        "IB_HTTP", spec, router="r", content_type=ContentType.JSON, deployed=deployed
    )
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_outbound(
        build_outbound_connection(
            "OB_PARTNER",
            Rest(url="https://partner.example/ingest", capture_response=capture_response),
            ordering=OrderingMode.UNORDERED,
            retry=RetryPolicy(max_attempts=3),
        )
    )
    reg.add_router("r", lambda m: [])
    return reg, ic


async def _resolver(
    tmp_path: Path, env_values: dict[str, Any], **overrides: Any
) -> SyncReplyResolverImpl:
    """The resolver a real listener start injects."""
    reg, ic = _graph(port=free_port(), **overrides)
    store = await MessageStore.open(tmp_path / "reply_env.db")
    try:
        runner = RegistryRunner(
            reg,
            store,
            poll_interval=0.02,
            egress=EgressSettings(deny_by_default=False),
            env_values=env_values,
        )
        await runner.start()
        try:
            # A lost port race isolates a listener (ADR 0031) rather than raising; name that cause.
            assert ic.name in runner._sources, "the listener failed to start"
            resolver = runner._sources[ic.name].sync_reply
            assert isinstance(resolver, SyncReplyResolverImpl)
            return resolver
        finally:
            await runner.stop()
    finally:
        await store.close()


async def test_reply_from_through_env_keys_the_resolved_destination(tmp_path: Path) -> None:
    resolver = await _resolver(
        tmp_path, {"reply_target": "OB_PARTNER"}, reply_from=env("reply_target")
    )
    assert resolver._destination == "OB_PARTNER"


async def test_each_reply_setting_through_env_takes_effect(tmp_path: Path) -> None:
    resolver = await _resolver(
        tmp_path,
        {"t": "7.5", "ct": "application/fhir+json", "ot": "202"},
        reply_timeout=env("t", cast=float),
        reply_content_type=env("ct"),
        reply_on_timeout=env("ot"),
    )
    assert resolver._timeout == 7.5
    assert resolver._content_type == "application/fhir+json"
    assert resolver._on_timeout == "202"


async def test_a_literal_config_is_read_as_written(tmp_path: Path) -> None:
    resolver = await _resolver(
        tmp_path,
        {},
        reply_timeout=12.0,
        reply_content_type="text/plain",
        reply_on_timeout="202",
    )
    assert resolver._destination == "OB_PARTNER"
    assert resolver._timeout == 12.0
    assert resolver._content_type == "text/plain"
    assert resolver._on_timeout == "202"


@pytest.mark.parametrize(
    "key", ["reply_from", "reply_timeout", "reply_content_type", "reply_on_timeout"]
)
def test_an_unset_env_value_fails_the_build_check_as_missing(key: str) -> None:
    overrides: dict[str, Any] = {key: env("nowhere")}
    reg, _ = _graph(**overrides)
    with pytest.raises(WiringError, match="missing: nowhere"):
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values={},
            egress=EgressSettings(deny_by_default=False),
            delivery=SERVICEABLE,
        )


@pytest.mark.parametrize("value", ["", "   ", None, 7])
def test_a_reply_from_resolving_to_no_name_is_refused(value: Any) -> None:
    # Refused on main as an unknown outbound. It must not become an inbound that silently answers 202.
    _, ic = _graph(reply_from=env("target"))
    reg, _ = _graph()
    with pytest.raises(WiringError, match="reply_from"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE, env_values={"target": value})


def test_the_cross_registry_arms_read_the_resolved_target() -> None:
    reg, ic = _graph(reply_from=env("target"))
    with pytest.raises(WiringError, match="unknown outbound 'OB_ELSEWHERE'"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE, env_values={"target": "OB_ELSEWHERE"})

    reg, ic = _graph(reply_from=env("target"), capture_response=False)
    with pytest.raises(WiringError, match="capture_response=True"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE, env_values={"target": "OB_PARTNER"})


def test_a_content_type_resolving_to_passthrough_needs_the_allow_list() -> None:
    reg, ic = _graph(reply_content_type=env("ct", default="text/plain"))
    target = reg.outbound["OB_PARTNER"]
    settings = {k: v for k, v in target.spec.settings.items() if k != "capture_response_headers"}
    reg.outbound["OB_PARTNER"] = dataclasses.replace(
        target, spec=dataclasses.replace(target.spec, settings=settings)
    )
    check_http_sync_reply(ic, reg, delivery=SERVICEABLE, env_values={})
    with pytest.raises(WiringError, match="reply_content_type='passthrough'"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE, env_values={"ct": "passthrough"})


def test_a_caller_with_no_env_values_still_refuses_an_env_target() -> None:
    # The same refusal as on main: such a caller cannot say which outbound the reference names.
    reg, ic = _graph(reply_from=env("target"))
    with pytest.raises(WiringError, match="unknown outbound"):
        check_http_sync_reply(ic, reg, delivery=SERVICEABLE)


def _captured(reg: Registry) -> list[str]:
    return list(reg.outbound["OB_PARTNER"].spec.settings["capture_response_headers"] or [])


def test_the_capture_implication_follows_an_env_target() -> None:
    # Without it a passthrough reply would lose the partner's content type, with no error.
    reg, _ = _graph(reply_from=env("target"))
    apply_sync_reply_capture_implication(reg, {"target": "OB_PARTNER"})
    assert _captured(reg) == ["content-type"]


def test_the_capture_implication_follows_a_content_type_set_through_env() -> None:
    reg, _ = _graph(reply_content_type=env("ct"))
    apply_sync_reply_capture_implication(reg, {"ct": "passthrough"})
    assert _captured(reg) == ["content-type"]

    reg, _ = _graph(reply_content_type=env("ct"))
    apply_sync_reply_capture_implication(reg, {"ct": "text/plain"})
    assert _captured(reg) == []


def test_the_capture_implication_leaves_a_missing_value_to_the_build_check() -> None:
    reg, _ = _graph(reply_from=env("target"))
    apply_sync_reply_capture_implication(reg, {})
    assert _captured(reg) == []


def test_the_capture_implication_resolves_nothing_on_an_undeployed_inbound() -> None:
    def cast(value: Any) -> Any:
        raise AssertionError("a deployed=False connection's env() value was resolved")

    reg, _ = _graph(deployed=False, reply_from=env("target", cast=cast))
    apply_sync_reply_capture_implication(reg, {"target": "OB_PARTNER"})
    assert _captured(reg) == []


def test_the_build_check_applies_the_implication_for_an_env_target() -> None:
    reg, _ = _graph(reply_from=env("target"))
    build_check_registry(
        reg,
        inbound_bind_host="127.0.0.1",
        env_values={"target": "OB_PARTNER"},
        egress=EgressSettings(deny_by_default=False),
        delivery=SERVICEABLE,
    )
    assert _captured(reg) == ["content-type"]


def test_the_implication_without_env_values_is_as_on_main() -> None:
    reg, _ = _graph()
    apply_sync_reply_capture_implication(reg)
    assert _captured(reg) == ["content-type"]

    reg, _ = _graph(reply_from=env("target"))
    apply_sync_reply_capture_implication(reg)
    assert _captured(reg) == []
