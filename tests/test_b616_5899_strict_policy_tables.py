# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5899: the ``[outbound.retry]``, ``[outbound.buildup]``, ``[outbound.stall]`` and
``[outbound.batch]`` tables in ``connections.toml`` refuse an unknown key and a value of the wrong
TOML type.

Before the fix a typo'd retry, buildup or stall key was dropped and the default kept, and a quoted
number or a boolean was coerced, so ``max_oldest_seconds = "300"`` loaded as 300 and
``[outbound.stall] max_oldest_second`` loaded with the stall alert left off. Both now fail the load,
and the unknown-key refusal names the key without quoting its value. Synthetic config only."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.connections_file import load_connections_data
from messagefoundry.config.models import BatchConfig, BuildupThreshold, RetryPolicy, StallThreshold
from messagefoundry.config.wiring import Registry, WiringError


def _load(sub_table: str) -> Registry:
    text = textwrap.dedent(
        """
        [[outbound]]
        name = "OB"
        transport = "mllp"
          [outbound.settings]
          host = "partner.example"
          port = 2700
        """
    ) + textwrap.dedent(sub_table)
    registry = Registry()
    load_connections_data(text.encode("utf-8"), Path("connections.toml"), registry)
    return registry


@pytest.mark.parametrize(
    ("table", "key"),
    [
        ("retry", "max_attempt"),
        ("buildup", "max_dpeth"),
        ("stall", "max_oldest_second"),
        ("batch", "max_cuont"),
        ("schedule", "invrt"),
    ],
)
def test_unknown_key_is_refused_without_echoing_its_value(table: str, key: str) -> None:
    marker = "SYNTHETIC-VALUE-5899"
    with pytest.raises(WiringError, match=rf"\[{table}\]: unknown key\(s\) {key}") as caught:
        _load(f'[outbound.{table}]\n{key} = "{marker}"\n')
    assert marker not in str(caught.value)


@pytest.mark.parametrize(
    ("table", "body"),
    [
        ("retry", 'max_attempts = "5"'),
        ("retry", "max_attempts = true"),
        ("retry", "max_attempts = 5.0"),
        ("retry", 'backoff_seconds = "5"'),
        ("buildup", 'max_depth = "10"'),
        ("buildup", "max_oldest_seconds = true"),
        ("stall", 'max_oldest_seconds = "300"'),
        ("batch", 'max_count = "10"\nmax_wait_ms = 500'),
        ("batch", "max_count = 10\nmax_wait_ms = true"),
        ("batch", "max_count = 10.0\nmax_wait_ms = 500"),
    ],
)
def test_wrong_type_is_refused_not_coerced(table: str, body: str) -> None:
    with pytest.raises(WiringError, match=f"invalid {table}"):
        _load(f"[outbound.{table}]\n{body}\n")


def test_well_typed_tables_still_load() -> None:
    """Positive control: integers where a float is declared, and the ``"forever"`` spelling, load."""
    registry = _load(
        """
        [outbound.retry]
        max_attempts = "Forever"
        backoff_seconds = 2
        max_backoff_seconds = 60.5
        [outbound.buildup]
        max_depth = 50
        max_oldest_seconds = 120
        [outbound.stall]
        max_oldest_seconds = 600
        [outbound.batch]
        max_count = 10
        max_wait_ms = 500
        """
    )
    ob = registry.outbound["OB"]
    assert ob.retry == RetryPolicy(max_attempts=None, backoff_seconds=2.0, max_backoff_seconds=60.5)
    assert ob.buildup == BuildupThreshold(max_depth=50, max_oldest_seconds=120.0)
    assert ob.stall == StallThreshold(max_oldest_seconds=600.0)
    assert ob.batch == BatchConfig(max_count=10, max_wait_ms=500)
