# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BatchConfig wiring — BACKLOG #134 / ADR 0082 (config layer).

The opt-in per-outbound ``batch`` knob: MLLP-only, rejected on a capturing/reingressing outbound, with
numeric guards — validated at the ``build_outbound_connection`` choke point so ``check``/dry-run catches
a bad config before any store opens. Desugars from ``connections.toml`` through the same factory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry import BatchConfig, File, MLLP
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.wiring import Registry, WiringError, build_outbound_connection


def test_valid_mllp_batch_builds() -> None:
    oc = build_outbound_connection(
        "OB_ADT", MLLP(host="h", port=1), batch=BatchConfig(max_count=5, max_wait_ms=200)
    )
    assert oc.batch is not None and oc.batch.max_count == 5 and oc.batch.max_wait_ms == 200


def test_batch_rejected_on_non_mllp_outbound() -> None:
    with pytest.raises(WiringError, match="MLLP .*only"):
        build_outbound_connection(
            "OB_FILE", File(directory="out"), batch=BatchConfig(max_count=5, max_wait_ms=200)
        )


def test_batch_rejected_with_capture_response() -> None:
    with pytest.raises(WiringError, match="capture_response"):
        build_outbound_connection(
            "OB_CAP",
            MLLP(host="h", port=1, capture_response=True),
            batch=BatchConfig(max_count=5, max_wait_ms=200),
        )


def test_batch_rejected_with_reingress_to() -> None:
    # reingress_to implies capture (ADR 0013); the reject names reingress_to specifically.
    with pytest.raises(WiringError, match="reingress_to"):
        build_outbound_connection(
            "OB_LOOP",
            MLLP(host="h", port=1, reingress_to="LOOP"),
            batch=BatchConfig(max_count=5, max_wait_ms=200),
        )


def test_numeric_guards() -> None:
    with pytest.raises(Exception):  # pydantic: max_count >= 2
        BatchConfig(max_count=1, max_wait_ms=200)
    with pytest.raises(Exception):  # pydantic: max_wait_ms >= 1
        BatchConfig(max_count=5, max_wait_ms=0)


def test_connections_toml_desugar(tmp_path: Path) -> None:
    toml = tmp_path / "connections.toml"
    toml.write_text(
        """
[[outbound]]
name = "OB_ADT"
transport = "mllp"
[outbound.settings]
host = "10.0.0.9"
port = 6000
[outbound.batch]
max_count = 8
max_wait_ms = 500
""",
        encoding="utf-8",
    )
    reg = Registry()
    load_connections_file(toml, reg)
    oc = reg.outbound["OB_ADT"]
    assert oc.batch is not None and oc.batch.max_count == 8 and oc.batch.max_wait_ms == 500


def test_connections_toml_desugar_rejects_non_mllp(tmp_path: Path) -> None:
    toml = tmp_path / "connections.toml"
    toml.write_text(
        """
[[outbound]]
name = "OB_FILE"
transport = "file"
[outbound.settings]
directory = "out"
[outbound.batch]
max_count = 8
max_wait_ms = 500
""",
        encoding="utf-8",
    )
    with pytest.raises(WiringError, match="MLLP .*only"):
        load_connections_file(toml, Registry())
