# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The egress policy is deny by default, and every connector build seam requires one (vault BACKLOG
#2605).

Before this change ``EgressSettings().deny_by_default`` was false and every list was empty, which
means unrestricted. ``serve`` flipped the field in place, so any other entry point ran with open
egress: an embedder that omitted the policy, the ``check`` command, and the ``connection`` CLI.
These tests pin three things. The model default denies. Every seam that builds a connector, or
the runner that owns one, names its policy with no default. And ``serve`` still refuses to start
with no destination list set, with a message that says every outbound would be refused.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.api.app import create_managed_app
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings, load_settings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    WiringError,
)
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.reference_sync import (
    ReferenceSyncError,
    ReferenceSyncRunner,
    _load_database_source,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import build_destination, build_source
from messagefoundry.transports.database import DatabaseLookupExecutor
from messagefoundry.transports.fhir import FhirLookupExecutor

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

#: Each seam and the keyword that carries its policy. Every one must have NO default.
_SEAMS: list[tuple[str, Callable[..., Any], str]] = [
    ("build_destination", build_destination, "egress"),
    ("build_source", build_source, "egress"),
    ("DatabaseLookupExecutor", DatabaseLookupExecutor.__init__, "egress"),
    ("FhirLookupExecutor", FhirLookupExecutor.__init__, "egress"),
    ("RegistryRunner", RegistryRunner.__init__, "egress"),
    ("ReferenceSyncRunner", ReferenceSyncRunner.__init__, "egress"),
    ("Engine", Engine.__init__, "egress_settings"),
    ("Engine.create", Engine.create, "egress_settings"),
    ("create_managed_app", create_managed_app, "egress_settings"),
]


def _mllp(host: str) -> Destination:
    return Destination(name="OB", type=ConnectorType.MLLP, settings={"host": host, "port": 2575})


def test_the_settings_model_denies_an_unlisted_destination() -> None:
    assert EgressSettings().deny_by_default is True
    with pytest.raises(WiringError, match="block_unlisted_outbound"):
        build_destination(_mllp("unlisted.example"), egress=EgressSettings())
    # Control: the audited opt-out still restores the per-list posture, so the refusal above is the
    # default speaking and not a host the seam refuses for some other reason.
    build_destination(_mllp("unlisted.example"), egress=EgressSettings(deny_by_default=False))


def test_settings_loaded_with_no_security_section_deny(tmp_path: Path) -> None:
    # The path every non-serve entry point takes: `check`, the `connection` CLI, an embedder.
    path = tmp_path / "messagefoundry.toml"
    path.write_text("", encoding="utf-8")
    assert load_settings(config_path=path, environ={}).egress.deny_by_default is True
    path.write_text("[security]\nblock_unlisted_outbound = false\n", encoding="utf-8")
    assert load_settings(config_path=path, environ={}).egress.deny_by_default is False


@pytest.mark.parametrize(("name", "fn", "keyword"), _SEAMS, ids=[s[0] for s in _SEAMS])
def test_every_seam_requires_an_explicit_policy(
    name: str, fn: Callable[..., Any], keyword: str
) -> None:
    param = inspect.signature(fn).parameters[keyword]
    assert param.default is inspect.Parameter.empty, f"{name}.{keyword} has a default"
    assert param.kind is inspect.Parameter.KEYWORD_ONLY, f"{name}.{keyword} is positional"


def test_the_build_seam_refuses_with_a_listed_control() -> None:
    policy = EgressSettings(allowed_mllp=["partner.example:2575"])
    build_destination(_mllp("partner.example"), egress=policy)  # listed: builds
    with pytest.raises(WiringError, match="allowed_mllp"):
        build_destination(_mllp("other.example"), egress=policy)
    db_source = Source(
        name="IB_DB", type=ConnectorType.DATABASE, settings={"server": "sql.example", "port": 1433}
    )
    with pytest.raises(WiringError, match="allowed_db"):
        build_source(db_source, egress=EgressSettings())


def test_the_lookup_executors_check_before_they_build() -> None:
    with pytest.raises(WiringError, match="allowed_db"):
        DatabaseLookupExecutor(
            {"LK": {"server": "sql.example", "database": "d"}}, egress=EgressSettings()
        )
    with pytest.raises(WiringError, match="allowed_http"):
        FhirLookupExecutor({"FL": {"url": "https://fhir.example/r4"}}, egress=EgressSettings())


def _registry(tmp_path: Path) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}), router="r"
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection(
            "OB", ConnectionSpec(ConnectorType.MLLP, {"host": "partner.example", "port": 2575})
        )
    )
    return reg


async def test_a_stock_runner_policy_denies(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        runner = RegistryRunner(_registry(tmp_path), store, egress=EgressSettings())
        with pytest.raises(WiringError, match="block_unlisted_outbound"):
            runner.build_check(runner.registry)
        with pytest.raises(WiringError, match="block_unlisted_outbound"):
            runner.build_test_connector("OB")
        # Control: the same graph builds once the destination is listed.
        listed = RegistryRunner(
            _registry(tmp_path),
            store,
            egress=EgressSettings(allowed_mllp=["partner.example"]),
        )
        listed.build_check(listed.registry)
    finally:
        await store.close()


async def test_a_reference_source_sync_denies_under_a_stock_policy() -> None:
    # No statement, so a source that passes the gate stops at the next check and never dials.
    settings = {"server": "sql.example"}
    with pytest.raises(ReferenceSyncError, match="block_unlisted_outbound"):
        await _load_database_source(settings, EgressSettings())
    # Control: a listed server passes the gate and reaches that next check.
    with pytest.raises(ReferenceSyncError, match="requires 'statement'"):
        await _load_database_source(settings, EgressSettings(allowed_db=["sql.example"]))


def test_serve_still_refuses_with_no_destination_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # The model default alone would satisfy the open-egress gate, so the gate tests whether the
    # operator wrote the switch. A stock instance must still refuse here with one clear message,
    # rather than start and fail every outbound as a degraded lane.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    assert main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"]) == 2
    err = capsys.readouterr().err
    assert "no outbound destination is declared on a production PHI instance" in err
    assert "every outbound would be refused" in err


def test_serve_passes_the_egress_gate_when_the_switch_is_written_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Control for the refusal above: the same start with the switch written true clears the
    # open-egress gate. A later gate may still refuse this config; only this one is under test.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    (tmp_path / "messagefoundry.toml").write_text(
        "security.block_unlisted_outbound = true\n", encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod"])
    err = capsys.readouterr().err
    assert "no outbound destination is declared" not in err
    assert "egress is UNRESTRICTED" not in err
    # Positive evidence that control got PAST the egress gate: the off-box log gate, which `_serve`
    # runs after it, is what speaks. A refusal at an earlier gate would not print this.
    assert "must forward its logs off-box" in err
