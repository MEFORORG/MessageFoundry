# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Fail-closed outbound/egress allowlist (WP-11c, ASVS 13.2.4/13.2.5/14.2.3): a destination not on the
[egress] allowlist is refused at config build_check; an empty list = unrestricted."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    WiringError,
)
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    check_egress_allowed,
    check_lookup_allowed,
    check_source_allowed,
)
from messagefoundry.store.store import MessageStore


def _mllp(host: str, port: int) -> Destination:
    return Destination(name="OB", type=ConnectorType.MLLP, settings={"host": host, "port": port})


def _file(directory: str) -> Destination:
    return Destination(name="OB", type=ConnectorType.FILE, settings={"directory": directory})


def test_empty_allowlist_is_unrestricted() -> None:
    e = EgressSettings()  # nothing configured → today's behavior (any destination)
    check_egress_allowed(_mllp("anywhere.example", 1234), e)
    check_egress_allowed(_file("/tmp/whatever"), e)


def test_mllp_allowlist_host_and_port() -> None:
    e = EgressSettings(allowed_mllp=["hl7.partner.org:2575", "10.0.0.5"])
    check_egress_allowed(_mllp("hl7.partner.org", 2575), e)  # exact host:port
    check_egress_allowed(_mllp("HL7.Partner.org", 2575), e)  # case-insensitive host
    check_egress_allowed(_mllp("10.0.0.5", 9999), e)  # host-only entry → any port
    with pytest.raises(WiringError, match="allowed_mllp"):
        check_egress_allowed(_mllp("evil.example", 2575), e)  # wrong host
    with pytest.raises(WiringError, match="allowed_mllp"):
        check_egress_allowed(_mllp("hl7.partner.org", 6661), e)  # wrong port


def test_file_allowlist_directory_prefix(tmp_path: Path) -> None:
    base = tmp_path / "out"
    (base / "sub").mkdir(parents=True)
    e = EgressSettings(allowed_file_dirs=[str(base)])
    check_egress_allowed(_file(str(base)), e)  # exact
    check_egress_allowed(_file(str(base / "sub")), e)  # nested under an allowed dir
    with pytest.raises(WiringError, match="allowed_file_dirs"):
        check_egress_allowed(_file(str(tmp_path / "elsewhere")), e)  # outside


def _registry(tmp_path: Path, host: str) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}), router="r"
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.MLLP, {"host": host, "port": 2575}))
    )
    return reg


async def test_build_check_refuses_disallowed_outbound(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        egress = EgressSettings(allowed_mllp=["good.partner.org:2575"])
        # A non-allowed destination is refused at config validation (→ WiringError → 422 / refused reload).
        bad = RegistryRunner(_registry(tmp_path, "evil.example"), store, egress=egress)
        with pytest.raises(WiringError, match="allowed_mllp"):
            bad.build_check(bad.registry)
        # An allowed destination build-checks cleanly.
        good = RegistryRunner(_registry(tmp_path, "good.partner.org"), store, egress=egress)
        good.build_check(good.registry)  # no raise
    finally:
        await store.close()


# --- deny_by_default (Q5b): an empty allowlist refuses instead of allowing --------------------------


def _db_dest(server: str) -> Destination:
    return Destination(
        name="OB", type=ConnectorType.DATABASE, settings={"server": server, "port": 1433}
    )


def test_deny_by_default_refuses_empty_allowlist() -> None:
    e = EgressSettings(deny_by_default=True)  # nothing listed → every destination refused
    for dest in (_mllp("hl7.partner.org", 2575), _file("/tmp/out"), _db_dest("sql.internal")):
        with pytest.raises(WiringError, match="deny_by_default"):
            check_egress_allowed(dest, e)


def test_deny_by_default_honours_a_set_allowlist() -> None:
    # With the relevant list set, behavior matches today: the list is enforced (no extra refusal).
    e = EgressSettings(deny_by_default=True, allowed_mllp=["hl7.partner.org:2575"])
    check_egress_allowed(_mllp("hl7.partner.org", 2575), e)  # listed → allowed
    with pytest.raises(WiringError, match="allowed_mllp"):
        check_egress_allowed(_mllp("evil.example", 2575), e)  # not listed → refused
    # The flag is global, so a different transport with no list of its own is still refused.
    with pytest.raises(WiringError, match="deny_by_default"):
        check_egress_allowed(_file("/tmp/out"), e)


def test_deny_by_default_off_is_unrestricted() -> None:
    e = EgressSettings()  # default false + empty lists → today's behavior (any destination)
    check_egress_allowed(_mllp("anywhere.example", 1234), e)
    check_egress_allowed(_db_dest("any.sql"), e)


def test_deny_by_default_gates_dial_out_sources_and_lookups() -> None:
    e = EgressSettings(deny_by_default=True)
    db_source = Source(
        type=ConnectorType.DATABASE, settings={"server": "sql.internal", "port": 1433}
    )
    with pytest.raises(WiringError, match="deny_by_default"):
        check_source_allowed(db_source, "IB_DB", e)
    with pytest.raises(WiringError, match="deny_by_default"):
        check_lookup_allowed("LK", {"server": "sql.internal", "port": 1433}, e)
    # A listener source (MLLP binds + waits; never dials out) is unaffected even under deny_by_default.
    mllp_source = Source(type=ConnectorType.MLLP, settings={"host": "0.0.0.0", "port": 2575})
    check_source_allowed(mllp_source, "IB_MLLP", e)  # no raise


async def test_build_check_deny_by_default_refuses_unlisted(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        # deny_by_default with nothing listed → the MLLP outbound is refused at build_check.
        refused = RegistryRunner(
            _registry(tmp_path, "good.partner.org"),
            store,
            egress=EgressSettings(deny_by_default=True),
        )
        with pytest.raises(WiringError, match="deny_by_default"):
            refused.build_check(refused.registry)
        # Listing the destination permits it even under deny_by_default.
        allowed = RegistryRunner(
            _registry(tmp_path, "good.partner.org"),
            store,
            egress=EgressSettings(deny_by_default=True, allowed_mllp=["good.partner.org:2575"]),
        )
        allowed.build_check(allowed.registry)  # no raise
    finally:
        await store.close()
