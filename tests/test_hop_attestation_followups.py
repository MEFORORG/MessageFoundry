# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Follow-ups to the strict hop-policy reader of engine PR 2075 (vault BACKLOG #3139).

Each test names the item it pins. Every one is a gap in how a refused or malformed declaration is
reported, not in whether it is refused: the build check already refused each config here.

1. The advisory ``tls-hop-attested`` line printed a reason holding a newline verbatim.
2. ``serve`` ran no build check, so a reference set's raw ``env()`` flag was refused only at its
   first sync, which logged only ``WiringError``.
3. That line called every listed hop ALLOWed, a refused one included.
4. The two readers of a settings carrier's attestation pair held the reason to different rules.
5. A plain string flag was told "an env() reference is not accepted".
6. The FhirLookup executor and the anonymous FTP guard raised without the connection's name, and
   no test covered a ``FileRef`` reference refusal.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.checks import _check_hop_attested
from messagefoundry.config.models import hop_attestation_from_settings
from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import (
    REFUSED_ATTESTATION_MARK,
    DatabaseLookupSpec,
    FhirLookupSpec,
    Registry,
    WiringError,
    attested_secure_hops,
    env,
    load_config,
    refuse_unresolved_hop_flags,
    settings_hop_attestation,
)
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.pipeline.wiring_runner import build_check_registry, refuse_reference_hop_flags
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import rest, smart
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.remotefile import _anon_ftp_guard

REASON = "TLS terminates at the site's stunnel sidecar"
FORGED = "ok\nWARNING forged line"

# --- item 1 and item 3: the advisory line ----------------------------------------------------

_FORGED_MODULE = f"""
from messagefoundry import DatabaseRef, File, Reference, outbound
outbound("OB_OUT", File(directory="."))
src =DatabaseRef(server="db.example.org", database="d", statement="SELECT code FROM t",
                  key_column="code")
src.settings["tls_hop_attested"] = True
src.settings["tls_hop_attested_reason"] = {FORGED!r}
Reference("codes", source=src)
good = DatabaseRef(server="db2.example.org", database="d", statement="SELECT code FROM t",
                   key_column="code", tls_hop_attested=True, tls_hop_attested_reason={REASON!r})
Reference("good", source=good)
"""


def _forged_config(tmp_path: Path) -> Path:
    (tmp_path / "refs.py").write_text(_FORGED_MODULE, encoding="utf-8")
    return tmp_path


def test_the_advisory_line_escapes_a_reason_holding_a_newline(tmp_path: Path) -> None:
    detail = _check_hop_attested(_forged_config(tmp_path)).detail
    assert "\n" not in detail
    assert "ok\\nWARNING forged line" in detail


def test_the_advisory_line_marks_a_refused_carrier_and_not_a_good_one(tmp_path: Path) -> None:
    reg = load_config(_forged_config(tmp_path), allow_empty=True)
    reasons = dict(attested_secure_hops(reg))
    assert reasons["reference:codes"].endswith(REFUSED_ATTESTATION_MARK)
    assert reasons["reference:good"] == REASON
    detail = _check_hop_attested(tmp_path).detail
    assert "ALLOWed where" not in detail
    assert "hop(s) declare they are secure by means the engine cannot see. An enforcing gate " in (
        detail
    )
    assert "unless the entry is marked REFUSED" in detail


def test_the_build_check_refuses_the_config_the_advisory_line_marks(tmp_path: Path) -> None:
    # Control: the mark claims a refusal, so the refusal must be real.
    reg = load_config(_forged_config(tmp_path), allow_empty=True)
    with pytest.raises(WiringError, match="reference set 'codes': .*control characters"):
        build_check_registry(
            reg,
            inbound_bind_host="127.0.0.1",
            env_values={},
            egress=EgressSettings(deny_by_default=False),
        )


def test_an_env_flag_is_marked_refused_in_the_report() -> None:
    reg = Registry()
    spec = FhirLookupSpec("LK", {})
    spec.settings["tls_hop_attested"] = env("att", cast=bool)
    spec.settings["tls_hop_attested_reason"] = REASON
    reg.add_fhir_lookup(spec)
    assert attested_secure_hops(reg) == [("fhir_lookup:LK", f"{REASON} {REFUSED_ATTESTATION_MARK}")]


def test_an_attestation_beside_a_typed_cleartext_acceptance_is_marked_refused() -> None:
    # The lookup settings builder refuses the two opposite claims, so the report marks the entry.
    reg = Registry()
    spec = FhirLookupSpec("LK", {}, cleartext_accepted=True, cleartext_reason="legacy peer")
    spec.settings["tls_hop_attested"] = True
    spec.settings["tls_hop_attested_reason"] = REASON
    reg.add_fhir_lookup(spec)
    assert attested_secure_hops(reg) == [("fhir_lookup:LK", f"{REASON} {REFUSED_ATTESTATION_MARK}")]


def test_a_name_holding_a_newline_is_escaped_in_the_report() -> None:
    # A lookup name is not held to the connection-name pattern.
    reg = Registry()
    reg.add_lookup(
        DatabaseLookupSpec(
            "a\nWARNING forged", {"tls_hop_attested": True, "tls_hop_attested_reason": REASON}
        )
    )
    assert attested_secure_hops(reg) == [("db_lookup:a\\nWARNING forged", REASON)]


def test_an_env_reason_is_shown_by_its_key_never_its_default() -> None:
    reg = Registry()
    reg.add_lookup(
        DatabaseLookupSpec(
            "LK",
            {
                "tls_hop_attested": True,
                "tls_hop_attested_reason": env("r", default="s3cr3t-default"),
            },
        )
    )
    [(_, reason)] = attested_secure_hops(reg)
    assert "s3cr3t-default" not in reason
    assert reason.startswith("env('r')")


# --- item 4: one reason rule for both readers --------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "refusal"),
    [(FORGED, "must not contain control characters"), (5, "must be a string, not int")],
    ids=["control-character", "not-a-string"],
)
def test_both_readers_hold_the_reason_to_one_rule(reason: object, refusal: str) -> None:
    settings = {"tls_hop_attested": True, "tls_hop_attested_reason": reason}
    with pytest.raises(ValueError, match=refusal):
        hop_attestation_from_settings(settings)
    with pytest.raises(WiringError, match=refusal):
        settings_hop_attestation(settings, "w")


def test_both_readers_accept_a_plain_reason() -> None:
    settings = {"tls_hop_attested": True, "tls_hop_attested_reason": REASON}
    assert hop_attestation_from_settings(settings) is True
    assert settings_hop_attestation(settings, "w") is True


# --- item 5: the env() hint only for an env() value --------------------------------------------


def test_a_plain_string_flag_is_not_told_about_env() -> None:
    with pytest.raises(WiringError) as raw:
        refuse_unresolved_hop_flags({"cleartext_accepted": "false"}, "w")
    assert "not str" in str(raw.value) and "env()" not in str(raw.value)
    with pytest.raises(WiringError) as spec:
        FhirLookupSpec("LK", {"tls_hop_attested": "false", "tls_hop_attested_reason": REASON})
    assert "not str" in str(spec.value) and "env()" not in str(spec.value)


def test_an_env_flag_is_told_about_env() -> None:
    with pytest.raises(WiringError, match=r"not EnvRef \(an env\(\) reference is not accepted"):
        refuse_unresolved_hop_flags({"cleartext_accepted": env("att", cast=bool)}, "w")


# --- item 2 and item 6: a FileRef reference set's raw flag -------------------------------------


def _file_ref_graph(tmp_path: Path) -> Registry:
    (tmp_path / "codes.csv").write_text("key,value\nA,1\n", encoding="utf-8")
    (tmp_path / "refs.py").write_text(
        "from messagefoundry import FileRef, Reference\n"
        f"Reference('codes', source=FileRef(path={str(tmp_path / 'codes.csv')!r}))\n",
        encoding="utf-8",
    )
    reg = load_config(tmp_path, allow_empty=True)
    settings = reg.references["codes"].source.settings
    settings["tls_hop_attested"] = env("att", cast=bool)
    settings["tls_hop_attested_reason"] = REASON
    return reg


_FILEREF_REFUSAL = r"reference set 'codes': tls_hop_attested must be true or false, not EnvRef"


def test_the_build_check_refuses_a_file_ref_env_flag(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match=_FILEREF_REFUSAL):
        build_check_registry(
            _file_ref_graph(tmp_path),
            inbound_bind_host="127.0.0.1",
            env_values={"att": "false"},
            egress=EgressSettings(deny_by_default=False),
        )


def test_the_start_gate_refuses_a_file_ref_env_flag(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match=_FILEREF_REFUSAL):
        refuse_reference_hop_flags(_file_ref_graph(tmp_path))


async def test_engine_start_refuses_a_reference_env_flag_before_any_sync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.pipeline.engine import Engine

    reached: list[str] = []

    async def spy_sync_all(self: ReferenceSyncRunner, now: float | None = None) -> Any:
        reached.append("sync_all")
        raise AssertionError("sync_all must not be reached on a refused graph")

    monkeypatch.setattr(ReferenceSyncRunner, "sync_all", spy_sync_all)
    reg = _file_ref_graph(tmp_path)
    store = await MessageStore.open(tmp_path / "start.db")
    engine = Engine(store, egress_settings=EgressSettings(deny_by_default=False))
    engine.add_registry(reg)
    try:
        with pytest.raises(WiringError, match=_FILEREF_REFUSAL):
            await engine.start()
        assert reached == []
    finally:
        await engine.stop()
        await store.close()


def test_the_sync_logs_the_refusal_not_only_its_class(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    spec = _file_ref_graph(tmp_path).references["codes"]
    store: Any = object()  # never reached: the refusal comes before the read and the snapshot
    runner = ReferenceSyncRunner(
        store,
        lambda: [spec],
        ReferenceSettings(),
        env_values={"att": "false"},
        egress=EgressSettings(deny_by_default=False),
    )
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.reference_sync"),
        pytest.raises(WiringError, match=_FILEREF_REFUSAL),
    ):
        asyncio.run(runner._sync_one(spec))
    assert any(
        "tls_hop_attested must be true or false, not EnvRef" in r.getMessage()
        for r in caplog.records
    )


# --- item 6: the two seams name the connection --------------------------------------------------


@pytest.mark.parametrize(
    "key", ["tls_hop_attested", "cleartext_accepted", "tls_revocation_attested"]
)
def test_the_fhir_lookup_executor_names_the_lookup(key: str) -> None:
    settings = {"url": "https://fhir.example.org/fhir", key: "false"}
    with pytest.raises(ValueError, match=rf"^FhirLookup 'epic': {key} must be true or false"):
        FhirLookupExecutor({"epic": settings}, egress=EgressSettings(deny_by_default=False))


def test_the_anonymous_ftp_guard_names_the_connection() -> None:
    settings = {
        "host": "ftp.example.com",
        "remote_dir": "/in",
        "protocol": "ftp",
        "tls_hop_attested": "false",
    }
    with pytest.raises(ValueError, match=r"^connection 'OB_FTP'; tls_hop_attested must be true"):
        _anon_ftp_guard(settings, connection="OB_FTP")


def test_the_moved_revocation_reader_is_still_importable_from_smart() -> None:
    assert smart.revocation_attestation_from_settings is rest.revocation_attestation_from_settings
