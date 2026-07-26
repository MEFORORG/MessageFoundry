# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#234 — connections.toml writer parity: every key the READ schema (`connections_file.py`
`_INBOUND_KEYS`/`_OUTBOUND_KEYS`) accepts must survive the GUI/CLI writer (`connections_edit.py`).

Before #234 the writer emitted a hard-coded 14-scalar + 3-sub-table whitelist, silently deleting the
other **19 per-direction slots (16 distinct keys, including inbound ``metadata``)** on every GUI/CLI
save — `schedule`, `shard`, `priority`, retention/pruning/streaming knobs, and (a security regression)
``source_ip_allowlist``. These tests pin the fix per key (parametrized), on maximal both-direction
tables, and pin the fail-loud rejection of unknown/cross-direction input keys plus ADR 0007's
full-replace upsert semantics (absent key = deleted key)."""

from __future__ import annotations

import textwrap
from datetime import time as dt_time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.connections_edit import list_connections, upsert_connection
from messagefoundry.config.connections_file import _INBOUND_KEYS, _OUTBOUND_KEYS
from messagefoundry.config.wiring import WiringError, load_config

# A minimal code-first module supplying the router/handler the TOML inbounds bind by name.
LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB", msg)
    """
)


def _config(tmp_path: Path, toml: str | None = None) -> Path:
    (tmp_path / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    if toml is not None:
        (tmp_path / "connections.toml").write_text(textwrap.dedent(toml), encoding="utf-8")
    return tmp_path


def _noop_validate(_config_dir: Path) -> None:
    """These tests exercise the WRITER; read-schema legality is asserted via load_config directly."""


_IB_BASE: dict[str, Any] = {
    "direction": "inbound",
    "name": "IB",
    "transport": "mllp",
    "router": "r",
    "settings": {"port": 2600},
}
_OB_BASE: dict[str, Any] = {
    "direction": "outbound",
    "name": "OB",
    "transport": "mllp",
    "settings": {"host": "epic.example", "port": 2700},
}

# Times as ISO strings — the canonical JSON-safe form list_connections emits (the read schema's
# pydantic models re-parse them, so the string form is legal on write-back).
_SCHEDULE: dict[str, Any] = {
    "windows": [
        {"days": [0, 1, 2, 3, 4], "start": "07:00:00", "end": "17:00:00", "timezone": "UTC"}
    ],
    "invert": False,
}

# One representative value per read-schema key (beyond the base's name/transport). The completeness
# pin below forces a new case whenever a key joins the read schema — so a new key cannot ship without
# a round-trip proof. NOTE: content_type stays "hl7v2" so the union of these cases is also the legal
# MAXIMAL fixture (strict + stream_threshold_bytes are HL7-specific).
_INBOUND_CASES: dict[str, Any] = {
    "router": "r",
    "settings": {"port": 2600},
    "ack_mode": "enhanced",
    "ack_after": "ingest",
    "strict": True,
    "hl7_version": "2.5.1",
    "strict_timeout_s": 5.0,
    "content_type": "hl7v2",
    "metadata": {"site": "main-campus"},
    "bind_address": "127.0.0.1",
    "source_ip_allowlist": ["10.0.0.8", "10.0.1.0/24"],
    "capture_ack": True,
    "capture_connection_errors": False,
    "messages_days": 90,
    "prune_documents_after": 30,
    "prune_documents_min_bytes": 4096,
    "stream_threshold_bytes": 8192,
    "max_message_bytes": 134217728,
    "priority": "critical",
    "shard": "site-a",
    "schedule": _SCHEDULE,
    "auto_start": False,
    "deployed": False,
    "flagged": True,  # #131 (ADR 0007 amendment): the object-of-interest flag round-trips too.
}
_OUTBOUND_CASES: dict[str, Any] = {
    "settings": {"host": "epic.example", "port": 2700},
    "retry": {"max_attempts": 5, "backoff_seconds": 2.0},
    "ordering": "fifo",
    "internal_error": "stop",
    "buildup": {"max_depth": 500, "max_oldest_seconds": 120.0},
    "stall": {"max_oldest_seconds": 600.0},
    "batch": {"max_count": 10, "max_wait_ms": 250},
    "simulate": True,
    "dead_letter_days": 7,
    "priority": "low",
    "metadata": {"owner": "integration-team"},
    "schedule": _SCHEDULE,
    "auto_start": False,
    "deployed": False,
    "flagged": True,  # #131 (ADR 0007 amendment): the object-of-interest flag round-trips too.
    "waiting_display_delay": 2.5,  # #136 (ADR 0065 amendment): the cosmetic waiting-for-reply delay.
}

_IB_MAX: dict[str, Any] = {**_IB_BASE, **_INBOUND_CASES}
_OB_MAX: dict[str, Any] = {**_OB_BASE, **_OUTBOUND_CASES}

# Keys whose READ schema enforces a companion key (the per-key round-trip must still be load-legal):
# a pruning size threshold does nothing without its window, so the loader rejects it alone.
_COMPANIONS: dict[str, dict[str, Any]] = {
    "prune_documents_min_bytes": {"prune_documents_after": 30},
}


def test_case_tables_cover_the_read_schema_exactly() -> None:
    """Completeness pin: the parametrized cases (plus the base's name/transport) must cover the read
    schema exactly — 33 distinct keys (25 inbound + 16 outbound, 8 shared; 41 per-direction slots).
    A key added to _INBOUND_KEYS/_OUTBOUND_KEYS without a round-trip case fails HERE."""
    assert set(_INBOUND_CASES) | {"name", "transport"} == _INBOUND_KEYS
    assert set(_OUTBOUND_CASES) | {"name", "transport"} == _OUTBOUND_KEYS


@pytest.mark.parametrize("key", sorted(_INBOUND_CASES))
def test_inbound_key_roundtrips(tmp_path: Path, key: str) -> None:
    """Upsert → list must preserve the key and value; the rewritten file must still satisfy the READ
    schema (load_config)."""
    cfg = _config(tmp_path)
    obj = {**_IB_BASE, **_COMPANIONS.get(key, {}), key: _INBOUND_CASES[key]}
    upsert_connection(cfg, obj, validate=_noop_validate)
    [entry] = list_connections(cfg)
    assert entry[key] == _INBOUND_CASES[key]
    load_config(cfg)  # the written form is read-schema-legal


@pytest.mark.parametrize("key", sorted(_OUTBOUND_CASES))
def test_outbound_key_roundtrips(tmp_path: Path, key: str) -> None:
    cfg = _config(tmp_path)
    obj = {**_OB_BASE, key: _OUTBOUND_CASES[key]}
    upsert_connection(cfg, obj, validate=_noop_validate)
    [entry] = list_connections(cfg)
    assert entry[key] == _OUTBOUND_CASES[key]
    load_config(cfg)


def test_maximal_inbound_roundtrips_intact(tmp_path: Path) -> None:
    """Every inbound read-schema key on ONE table (content_type stays hl7v2 — strict +
    stream_threshold_bytes are HL7-specific): nothing stripped, and the loader rebuilds the semantic
    connection (windows re-parsed from ISO strings, allowlist frozen)."""
    cfg = _config(tmp_path)
    upsert_connection(cfg, _IB_MAX, validate=_noop_validate)
    [entry] = list_connections(cfg)
    assert entry == _IB_MAX
    ib = load_config(cfg).inbound["IB"]
    assert ib.schedule is not None
    assert ib.schedule.windows[0].start == dt_time(7, 0)
    assert ib.schedule.windows[0].end == dt_time(17, 0)
    assert ib.source_ip_allowlist == ("10.0.0.8", "10.0.1.0/24")
    assert ib.shard == "site-a"
    assert ib.metadata == {"site": "main-campus"}
    # `direction` is the [[inbound]]/[[outbound]] header, never a table key — the loader's
    # _reject_unknown would hard-fail the whole file if the writer ever emitted it.
    assert "direction" not in (cfg / "connections.toml").read_text(encoding="utf-8")


def test_maximal_outbound_roundtrips_intact(tmp_path: Path) -> None:
    cfg = _config(tmp_path)
    upsert_connection(cfg, _OB_MAX, validate=_noop_validate)
    [entry] = list_connections(cfg)
    assert entry == _OB_MAX
    ob = load_config(cfg).outbound["OB"]
    assert ob.batch is not None and ob.batch.max_count == 10
    assert ob.stall is not None and ob.stall.max_oldest_seconds == 600.0
    assert ob.retry is not None and ob.retry.max_attempts == 5
    assert ob.metadata == {"owner": "integration-team"}
    assert ob.schedule is not None and ob.schedule.windows[0].start == dt_time(7, 0)
    assert "direction" not in (cfg / "connections.toml").read_text(encoding="utf-8")


def test_upsert_omitting_a_previously_present_key_deletes_it(tmp_path: Path) -> None:
    """ADR 0007 upsert semantics are FULL REPLACE — deliberately retained under #234 (the
    merge-on-absent flip was evaluated and rejected). ``test_upsert_replaces_in_place`` does NOT pin
    this (a merge-on-absent writer passes it too), so this is the explicit pin: a save that OMITS a
    previously-present key REMOVES it from the file."""
    cfg = _config(tmp_path)
    upsert_connection(cfg, {**_IB_BASE, "shard": "site-a"}, validate=_noop_validate)
    [entry] = list_connections(cfg)
    assert entry["shard"] == "site-a"
    upsert_connection(cfg, _IB_BASE, validate=_noop_validate)  # same connection, shard omitted
    [entry] = list_connections(cfg)
    assert "shard" not in entry
    assert "shard" not in (cfg / "connections.toml").read_text(encoding="utf-8")


def test_unknown_input_key_fails_loud_naming_it(tmp_path: Path) -> None:
    """The old writer SILENTLY DROPPED anything it did not recognize — the root #234 failure mode.
    Unknown input keys now fail loud (WiringError naming them, mirroring the loader's
    _reject_unknown shape), and nothing is written."""
    cfg = _config(tmp_path)
    with pytest.raises(WiringError, match="unknown key.*deployd"):
        upsert_connection(cfg, {**_OB_BASE, "deployd": False}, validate=_noop_validate)
    assert not (cfg / "connections.toml").exists()


@pytest.mark.parametrize(
    ("base", "key", "value"),
    [
        pytest.param(_IB_BASE, "retry", {"max_attempts": 3}, id="retry-on-inbound"),
        pytest.param(_IB_BASE, "ordering", "fifo", id="ordering-on-inbound"),
        pytest.param(_OB_BASE, "router", "r", id="router-on-outbound"),
        pytest.param(_OB_BASE, "bind_address", "127.0.0.1", id="bind_address-on-outbound"),
    ],
)
def test_cross_direction_key_fails_loud(
    tmp_path: Path, base: dict[str, Any], key: str, value: Any
) -> None:
    """Unknown-key rejection is validated against the DIRECTION-APPROPRIATE read schema: a key the
    OTHER direction accepts (``retry`` on an inbound) must fail here — a union check would silently
    pass it through to a confusing whole-file load error after the write."""
    cfg = _config(tmp_path)
    with pytest.raises(WiringError, match=f"unknown key.*{key}"):
        upsert_connection(cfg, {**base, key: value}, validate=_noop_validate)
    assert not (cfg / "connections.toml").exists()


def test_sub_table_input_must_be_an_object(tmp_path: Path) -> None:
    """A sub-table key with a non-object value fails loud as a WiringError (the CLI's error contract),
    mirroring the loader's "[key] must be a table" — not an AttributeError traceback mid-write."""
    cfg = _config(tmp_path)
    with pytest.raises(WiringError, match=r"\[retry\] must be a table"):
        upsert_connection(cfg, {**_OB_BASE, "retry": 5}, validate=_noop_validate)
    assert not (cfg / "connections.toml").exists()


def test_explicit_empty_sub_table_survives(tmp_path: Path) -> None:
    """Sub-tables are emitted on ``is not None``, not truthiness — an explicit empty ``metadata``
    table survives a GUI round-trip instead of silently vanishing."""
    cfg = _config(tmp_path)
    upsert_connection(cfg, {**_IB_BASE, "metadata": {}}, validate=_noop_validate)
    [entry] = list_connections(cfg)
    assert entry["metadata"] == {}
    load_config(cfg)


def test_toml_native_schedule_times_roundtrip_semantically(tmp_path: Path) -> None:
    """#234 Phase 2: a hand-authored schedule using TOML-NATIVE times (``start = 07:00:00``,
    unquoted) → list (canonicalized to ISO strings at the list boundary) → upsert → reload must
    yield a semantically equal ``Schedule``. The touched table's native times narrowing to quoted
    strings is EXPLICITLY ACCEPTED — full-replace rewrites the touched table's style (ADR 0007's
    byte contract covers untouched tables), and pydantic re-parses the ISO string to the same
    ``time``; ``date``/``datetime`` values narrow to strings the same way by design."""
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "r"
          [inbound.settings]
          port = 2600
          [inbound.schedule]
          invert = false
          windows = [ { days = [0, 1, 2, 3, 4], start = 07:00:00, end = 17:00:00 } ]
        """,
    )
    before = load_config(cfg).inbound["IB"].schedule
    assert before is not None
    [entry] = list_connections(cfg)
    assert entry["schedule"]["windows"][0]["start"] == "07:00:00"  # canonical at the list boundary
    assert entry["schedule"]["windows"][0]["end"] == "17:00:00"
    upsert_connection(cfg, entry, validate=_noop_validate)
    after = load_config(cfg).inbound["IB"].schedule
    assert after == before  # pydantic models compare by value: time(7, 0) either way
    # ...and the written-back string form is what landed in the file (read-schema-legal).
    assert '"07:00:00"' in (cfg / "connections.toml").read_text(encoding="utf-8")
