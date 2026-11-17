# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5328: a ``headers`` reference standing for the whole table has its ``default=`` held to
the table rule, since an unset key resolves to that default and the connector receives it
unchanged."""

from __future__ import annotations

from types import MappingProxyType
from typing import Any

import pytest

import messagefoundry
from messagefoundry.config import wiring
from messagefoundry.config.wiring import (
    Registry,
    WiringError,
    parse_env_setting,
    resolve_env_settings,
)
from tests.test_nested_env_ref_headers_refusal import HEADERS_FACTORIES

#: A value this test invents, standing in for whatever text a default holds.
SENTINEL = "MFTEST-HEADERS-DEFAULT-NOT-A-TABLE"


@pytest.fixture(autouse=True)
def _registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """``FhirLookup`` self-registers, so it needs an active registry."""
    monkeypatch.setattr(wiring, "_active", Registry())


@pytest.mark.parametrize(
    "default", [SENTINEL, ["X-A", "b"], 5, MappingProxyType({"X-A": "b"})], ids=str
)
@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_a_non_table_default_is_refused(factory: str, default: Any) -> None:
    with pytest.raises(WiringError, match="default= is not a table") as excinfo:
        HEADERS_FACTORIES[factory](messagefoundry.env("all_headers", default=default))
    assert factory in str(excinfo.value)
    assert SENTINEL not in str(excinfo.value)


def test_the_connections_toml_spelling_is_refused_too() -> None:
    ref = parse_env_setting({"env": "all_headers", "default": SENTINEL})
    with pytest.raises(WiringError, match="default= is not a table"):
        HEADERS_FACTORIES["Rest"](ref)


@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_a_table_default_builds_and_is_what_an_unset_key_resolves_to(factory: str) -> None:
    ref = messagefoundry.env("all_headers", default={"X-Trace": "probe-1"})
    spec = HEADERS_FACTORIES[factory](ref)
    assert resolve_env_settings(spec.settings, {})["headers"] == {"X-Trace": "probe-1"}


@pytest.mark.parametrize("with_none", [True, False], ids=["default-none", "no-default"])
@pytest.mark.parametrize("factory", sorted(HEADERS_FACTORIES))
def test_a_none_default_or_no_default_still_builds(factory: str, with_none: bool) -> None:
    ref = (
        messagefoundry.env("all_headers", default=None)
        if with_none
        else messagefoundry.env("all_headers")
    )
    assert HEADERS_FACTORIES[factory](ref).settings["headers"] == ref


def test_a_reference_deeper_than_envrefs_own_scan_is_refused_in_the_default() -> None:
    """The default is checked as a literal table is. EnvRef's own scan of a default stops one
    level sooner, so a reference six lists under a header value is seen only here."""
    deep: Any = messagefoundry.env("x")
    for _ in range(6):
        deep = [deep]
    ref = messagefoundry.env("all_headers", default={"X-A": deep})  # the control: EnvRef passes it
    with pytest.raises(WiringError, match=r"default= of its headers\) headers may not use env"):
        HEADERS_FACTORIES["Rest"](ref)


@pytest.mark.parametrize(
    "value", [SENTINEL, ["X-A", "b"], MappingProxyType({"X-A": "b"})], ids=["str", "list", "proxy"]
)
def test_an_environment_value_that_is_not_a_table_is_refused_once_resolved(value: Any) -> None:
    """BACKLOG #5328: the environment value is held to the rule the default= is held to."""
    spec = HEADERS_FACTORIES["Rest"](messagefoundry.env("all_headers"))
    with pytest.raises(WiringError, match="not a table") as excinfo:
        resolve_env_settings(spec.settings, {"all_headers": value})
    assert SENTINEL not in str(excinfo.value)


def test_an_environment_table_holding_a_reference_is_refused_once_resolved() -> None:
    spec = HEADERS_FACTORIES["Rest"](messagefoundry.env("all_headers"))
    table = {"X-Partner-Key": {"env": "partner_key", "default": SENTINEL}}
    with pytest.raises(WiringError, match="may not use env") as excinfo:
        resolve_env_settings(spec.settings, {"all_headers": table})
    assert SENTINEL not in str(excinfo.value)


def test_an_environment_table_still_resolves() -> None:
    spec = HEADERS_FACTORIES["Rest"](messagefoundry.env("all_headers"))
    resolved = resolve_env_settings(spec.settings, {"all_headers": {"X-Trace": "probe-1"}})
    assert resolved["headers"] == {"X-Trace": "probe-1"}
