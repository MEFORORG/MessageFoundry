"""Inbound bind interface is a service setting, not a per-connection host (Part A).

Inbound MLLP takes only a port; the listen interface comes from ``[inbound].bind_host`` and is
injected when the inbound connector is built. Outbound MLLP still requires a host (the peer)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import WiringError, load_config
from messagefoundry.pipeline.wiring_runner import _source_config
from messagefoundry.transports.mllp import MLLPSource


def _write(directory: Path, body: str) -> Path:
    (directory / "cfg.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return directory


def test_inbound_mllp_rejects_host(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import inbound, router, MLLP
        inbound("IB", MLLP(host="0.0.0.0", port=2575), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    with pytest.raises(WiringError, match="takes no host"):
        load_config(d)


def test_inbound_mllp_port_only_ok(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import inbound, router, MLLP
        inbound("IB", MLLP(port=2575), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    reg = load_config(d)
    # No host is carried on the spec; it's resolved at build time from the service setting.
    assert reg.inbound["IB"].spec.settings.get("host") is None
    assert reg.inbound["IB"].spec.settings["port"] == 2575


def test_outbound_mllp_requires_host(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP
        outbound("OB", MLLP(port=2601))
        """,
    )
    with pytest.raises(WiringError, match="requires a host"):
        load_config(d)


def test_outbound_mllp_with_host_ok(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import outbound, MLLP
        outbound("OB", MLLP(host="epic-host", port=2601))
        """,
    )
    reg = load_config(d)
    assert reg.outbound["OB"].spec.settings["host"] == "epic-host"


def test_source_config_injects_bind_host_for_mllp(tmp_path: Path) -> None:
    d = _write(
        tmp_path,
        """
        from messagefoundry import inbound, router, MLLP, File
        inbound("IB_MLLP", MLLP(port=2575), router="r")
        inbound("IB_FILE", File(directory="./in"), router="r")

        @router("r")
        def route(msg):
            return []
        """,
    )
    reg = load_config(d)
    mllp_src = _source_config(reg.inbound["IB_MLLP"], "0.0.0.0", {})
    assert mllp_src.settings["host"] == "0.0.0.0"
    # File inbound has no host concept and is left untouched.
    file_src = _source_config(reg.inbound["IB_FILE"], "0.0.0.0", {})
    assert "host" not in file_src.settings


def test_mllp_source_never_binds_all_interfaces_by_accident() -> None:
    # A missing/None host must fall back to loopback, never bind 0.0.0.0 implicitly (unauth MLLP).
    src = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 2575, "host": None}))
    assert src.host == "127.0.0.1"
    src_missing = MLLPSource(Source(type=ConnectorType.MLLP, settings={"port": 2575}))
    assert src_missing.host == "127.0.0.1"
