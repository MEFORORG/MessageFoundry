# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale config generation (B11) — the N-inbound code-first graph + the reload-latency
connections.toml generator. Both desugar through the SAME inbound()/outbound() factories into a flat
endpoint list (no "channel" element)."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.wiring import load_config


def test_n_inbound_graph_scales_with_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # The ONE graph file serves any N by env alone (MEFOR_CONNSCALE_COUNT), with no per-N file.
    monkeypatch.setenv("MEFOR_CONNSCALE_COUNT", "7")
    monkeypatch.setenv("MEFOR_CONNSCALE_BASE_PORT", "2600")
    monkeypatch.setenv("MEFOR_CONNSCALE_SINK_PORT", "2700")
    reg = load_config("harness/config/connscale")
    assert len(reg.inbound) == 7
    assert len(reg.outbound) == 7
    assert len(reg.routers) == 7
    assert len(reg.handlers) == 7
    # Each inbound binds base_port + i and its own router; a flat graph wired by name (no bundling).
    ports = sorted(c.spec.settings.get("port") for c in reg.inbound.values())
    assert ports == list(range(2600, 2607))


def test_shape_fails_loud_on_port_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    # The inbound port block must not collide with the sink port range — fail loud in _shape.
    monkeypatch.setenv("MEFOR_CONNSCALE_COUNT", "200")
    monkeypatch.setenv("MEFOR_CONNSCALE_BASE_PORT", "2650")
    monkeypatch.setenv("MEFOR_CONNSCALE_SINK_PORT", "2700")  # 2700 is inside [2650, 2849]
    from harness.config.connscale._shape import load_connscale_shape

    with pytest.raises(ValueError, match="overlaps the sink port range"):
        load_connscale_shape()


def test_shape_fails_loud_past_port_space(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_CONNSCALE_COUNT", "200")
    monkeypatch.setenv("MEFOR_CONNSCALE_BASE_PORT", "65500")
    from harness.config.connscale._shape import load_connscale_shape

    with pytest.raises(ValueError, match="past port 65535"):
        load_connscale_shape()


def test_edit_transform_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_CONNSCALE_COUNT", "2")
    monkeypatch.setenv("MEFOR_CONNSCALE_TRANSFORM", "edit")
    reg = load_config("harness/config/connscale")
    assert len(reg.handlers) == 2  # loads with the edit transform branch active


def test_gen_toml_reload_graph_loads_and_grows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A temp dir is world-writable; the Windows config-source trust guard would refuse it, so allow
    # the dev escape for the test (POSIX runners are unaffected).
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_CONFIG_SOURCE", "1")
    from harness.config.connscale.gen_toml import write_config_dir

    cfg = tmp_path / "reload"
    write_config_dir(cfg, count=8, base_port=2900, sink_host="127.0.0.1", sink_port=2800)
    reg = load_config(cfg)
    assert len(reg.inbound) == 8  # N data-authored inbounds (ADR 0007 desugar)
    assert len(reg.outbound) == 1  # one shared code-first sink outbound
    assert "cs_reload_router" in reg.routers  # routing logic stays code-first

    # Grow-reload: rewrite just the TOML to a larger N (shared_logic.py is stable).
    write_config_dir(cfg, count=12, base_port=2900, sink_host="127.0.0.1", sink_port=2800)
    reg2 = load_config(cfg)
    assert len(reg2.inbound) == 12


def test_gen_toml_fails_loud_past_port_space(tmp_path: Path) -> None:
    from harness.config.connscale.gen_toml import write_config_dir

    with pytest.raises(ValueError, match="past port 65535"):
        write_config_dir(
            tmp_path, count=100, base_port=65500, sink_host="127.0.0.1", sink_port=2800
        )
