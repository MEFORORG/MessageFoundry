# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""connections.toml read path (ADR 0007) — data-authored connections merge into the registry the
code-first inbound()/outbound() populate, sharing every factory + guard."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.connections_edit import (
    _SCALAR_FIELDS,
    _SUB_TABLES,
    list_connections,
    upsert_connection,
)
from messagefoundry.config.connections_file import _INBOUND_KEYS, _OUTBOUND_KEYS
from messagefoundry.config.models import AckMode, ConnectorType, ContentType, OrderingMode
from messagefoundry.config.wiring import (
    EnvRef,
    InboundConnection,
    OutboundConnection,
    WiringError,
    load_config,
    parse_env_setting,
    validate_config,
)

# A minimal code-first module supplying a router/handler the TOML inbounds can bind by name.
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


def _config(tmp_path: Path, toml: str, *, py: str = LOGIC_PY) -> Path:
    (tmp_path / "logic.py").write_text(py, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(textwrap.dedent(toml), encoding="utf-8")
    return tmp_path


def test_inbound_and_outbound_round_trip(tmp_path: Path) -> None:
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2600

            [[outbound]]
            name = "OB"
            transport = "mllp"
            ordering = "fifo"
              [outbound.settings]
              host = "epic.example"
              port = 2700
              [outbound.retry]
              max_attempts = 5
            """,
        )
    )
    ib = reg.inbound["IB"]
    assert ib.router == "r"
    assert ib.spec.type is ConnectorType.MLLP
    assert ib.spec.settings["port"] == 2600
    assert ib.ack_mode is AckMode.ORIGINAL
    assert ib.source_file is not None and ib.source_file.endswith("connections.toml")
    ob = reg.outbound["OB"]
    assert ob.spec.settings["host"] == "epic.example"
    assert ob.ordering is OrderingMode.FIFO
    assert ob.retry is not None and ob.retry.max_attempts == 5


def test_retention_override_roundtrips_toml(tmp_path: Path) -> None:
    """AC-7 (#34, ADR 0027): the per-connection retention overrides — inbound ``messages_days`` and
    outbound ``dead_letter_days`` — desugar through the same build_* factories as code-first, so a TOML
    entry resolves to the identical InboundConnection/OutboundConnection field (None = inherit, 0 = keep
    forever, >0 = days). Authored data-first, edited by hand or the ADR 0007 GUI."""
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
            messages_days = 90
              [inbound.settings]
              port = 2600

            [[inbound]]
            name = "IB_KEEP"
            transport = "mllp"
            router = "r"
            messages_days = 0
              [inbound.settings]
              port = 2601

            [[inbound]]
            name = "IB_INHERIT"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2602

            [[outbound]]
            name = "OB"
            transport = "mllp"
            dead_letter_days = 7
              [outbound.settings]
              host = "epic.example"
              port = 2700
            """,
        )
    )
    assert reg.inbound["IB"].messages_days == 90  # explicit window
    assert reg.inbound["IB_KEEP"].messages_days == 0  # 0 = keep forever (distinct from None)
    assert reg.inbound["IB_INHERIT"].messages_days is None  # absent = inherit the global window
    assert reg.outbound["OB"].dead_letter_days == 7


def test_document_pruning_override_roundtrips_toml(tmp_path: Path) -> None:
    """AC-7 (#47, ADR 0042): the per-connection embedded-document-pruning override —
    ``prune_documents_after`` (+ optional ``prune_documents_min_bytes``) — desugars through the same
    build_inbound_connection factory as code-first (None = never strip, >0 = days)."""
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB_DOC"
            transport = "mllp"
            router = "r"
            prune_documents_after = 30
            prune_documents_min_bytes = 4096
              [inbound.settings]
              port = 2600

            [[inbound]]
            name = "IB_NONE"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2601
            """,
        )
    )
    assert reg.inbound["IB_DOC"].prune_documents_after == 30
    assert reg.inbound["IB_DOC"].prune_documents_min_bytes == 4096
    assert reg.inbound["IB_NONE"].prune_documents_after is None  # absent = never strip
    assert reg.inbound["IB_NONE"].prune_documents_min_bytes is None


def test_document_pruning_rejects_non_positive_window(tmp_path: Path) -> None:
    """``prune_documents_after`` must be > 0 days — "never" is None, not 0 (fail loud at load)."""
    with pytest.raises(WiringError, match="prune_documents_after must be > 0 days"):
        load_config(
            _config(
                tmp_path,
                """
                [[inbound]]
                name = "IB"
                transport = "mllp"
                router = "r"
                prune_documents_after = 0
                  [inbound.settings]
                  port = 2600
                """,
            )
        )


def test_retention_override_rejects_negative_and_non_int(tmp_path: Path) -> None:
    """A negative window is meaningless (fail loud at load, like RetentionSettings(messages_days=-1));
    a non-integer / bool value is rejected by the connections.toml decoder."""
    with pytest.raises(WiringError, match="messages_days must be >= 0"):
        load_config(
            _config(
                tmp_path,
                """
                [[inbound]]
                name = "IB"
                transport = "mllp"
                router = "r"
                messages_days = -1
                  [inbound.settings]
                  port = 2600
                """,
            )
        )
    with pytest.raises(WiringError, match="must be an integer number of days"):
        load_config(
            _config(
                tmp_path,
                """
                [[outbound]]
                name = "OB"
                transport = "mllp"
                dead_letter_days = true
                  [outbound.settings]
                  host = "epic.example"
                  port = 2700
                """,
            )
        )


def test_timer_inbound_from_toml(tmp_path: Path) -> None:
    # A timer source (ADR 0011) is connection transport config, so it is declarable as data too —
    # transport = "timer" desugars through the same Timer() factory as code-first inbound(..., Timer()).
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB_TIMER"
            transport = "timer"
            router = "r"
            content_type = "text"
              [inbound.settings]
              body = "ping"
              interval_seconds = 30.0

            [[outbound]]
            name = "OB"
            transport = "mllp"
              [outbound.settings]
              host = "epic.example"
              port = 2700
            """,
        )
    )
    ib = reg.inbound["IB_TIMER"]
    assert ib.spec.type is ConnectorType.TIMER
    assert ib.spec.settings["body"] == "ping"
    assert ib.spec.settings["interval_seconds"] == 30.0
    assert ib.content_type is ContentType.TEXT


def test_env_ref_decode_with_named_cast(tmp_path: Path) -> None:
    reg = load_config(
        _config(
            tmp_path,
            """
            [[outbound]]
            name = "OB"
            transport = "mllp"
              [outbound.settings]
              host = { env = "Epic_Host" }
              port = { env = "epic_port", cast = "int" }
            """,
        )
    )
    host = reg.outbound["OB"].spec.settings["host"]
    port = reg.outbound["OB"].spec.settings["port"]
    assert isinstance(host, EnvRef) and host.key == "epic_host" and host.cast is None
    assert isinstance(port, EnvRef) and port.key == "epic_port" and port.cast is int


def test_parse_env_setting_discriminates_plain_dicts() -> None:
    assert parse_env_setting(2600) == 2600
    # a REST headers map is a plain dict, NOT an env-ref — returned verbatim
    assert parse_env_setting({"X-Trace": "1"}) == {"X-Trace": "1"}
    ref = parse_env_setting({"env": "Some_Key", "default": "d"})
    assert isinstance(ref, EnvRef) and ref.key == "some_key" and ref.default == "d"


def test_duplicate_name_across_file_and_code_fails(tmp_path: Path) -> None:
    py = LOGIC_PY + textwrap.dedent(
        """
        from messagefoundry import MLLP, inbound
        inbound("IB", MLLP(port=2600), router="r")
        """
    )
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "r"
          [inbound.settings]
          port = 2601
        """,
        py=py,
    )
    with pytest.raises(WiringError, match="duplicate"):
        load_config(cfg)


def test_unknown_transport_fails(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[outbound]]
        name = "OB"
        transport = "smtp"
        """,
    )
    with pytest.raises(WiringError, match="unknown transport"):
        load_config(cfg)


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        routerr = "r"
          [inbound.settings]
          port = 2600
        """,
    )
    with pytest.raises(WiringError, match="unknown key"):
        load_config(cfg)


def test_unknown_router_reference_fails(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "nope"
          [inbound.settings]
          port = 2600
        """,
    )
    with pytest.raises(WiringError, match="unknown router"):
        load_config(cfg)


def test_inbound_host_guard_is_reused(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "r"
          [inbound.settings]
          host = "0.0.0.0"
          port = 2600
        """,
    )
    with pytest.raises(WiringError, match="takes no host"):
        load_config(cfg)


def test_ack_after_delivered_rejected(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "r"
        ack_after = "delivered"
          [inbound.settings]
          port = 2600
        """,
    )
    with pytest.raises(WiringError, match="not yet implemented"):
        load_config(cfg)


def test_strict_with_non_hl7_content_type_rejected(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "mllp"
        router = "r"
        content_type = "json"
        strict = true
          [inbound.settings]
          port = 2600
        """,
    )
    with pytest.raises(WiringError, match="HL7-specific"):
        load_config(cfg)


def test_bad_named_cast_rejected(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[outbound]]
        name = "OB"
        transport = "mllp"
          [outbound.settings]
          host = "epic.example"
          port = { env = "p", cast = "frobnicate" }
        """,
    )
    with pytest.raises(WiringError, match="unknown cast"):
        load_config(cfg)


def test_missing_required_setting_reports_clearly(tmp_path: Path) -> None:
    # MLLP requires a port; omitting it must fail loud naming the connection (the factory IS the schema)
    cfg = _config(
        tmp_path,
        """
        [[outbound]]
        name = "OB"
        transport = "mllp"
          [outbound.settings]
          host = "epic.example"
        """,
    )
    with pytest.raises(WiringError, match="OB"):
        load_config(cfg)


def test_validate_config_reports_toml_problems(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        """
        [[inbound]]
        name = "IB"
        transport = "bogus"
        router = "r"
        """,
    )
    diags = validate_config(cfg)
    assert any("unknown transport" in d.message for d in diags)


def test_shipped_sample_connections_toml_loads() -> None:
    cfg = Path(__file__).resolve().parents[1] / "samples" / "config"
    reg = load_config(cfg)
    ib = reg.inbound["IB_ACME_ADT_TCP"]
    assert ib.router == "acme_adt_router"  # binds the code-first router from IB_ACME_ADT.py
    assert ib.spec.settings["port"] == 2700


def test_streaming_knobs_roundtrip_toml(tmp_path: Path) -> None:
    """#149 (ADR 0105 Phase 1a): the per-inbound very-large-document streaming knobs desugar through the
    same build_inbound_connection factory as code-first, so a TOML entry resolves to the identical
    InboundConnection fields."""
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
            stream_threshold_bytes = 8192
            max_message_bytes = 134217728
              [inbound.settings]
              port = 2600
              max_frame_bytes = 134217728

            [[outbound]]
            name = "OB"
            transport = "mllp"
              [outbound.settings]
              host = "epic.example"
              port = 2700
            """,
        )
    )
    ib = reg.inbound["IB"]
    assert ib.stream_threshold_bytes == 8192
    assert ib.max_message_bytes == 134217728


# --- lifecycle flags: deployed (#233, ADR 0111) + auto_start (#115) -----------
#
# Both are TOML keys as of #233 (auto_start was code-first-only before it, though the docs claimed
# otherwise), both default TRUE, and both must survive the GUI/CLI write path (_SCALAR_FIELDS).
# This commit adds the FLAG ONLY — enforcement (the engine declining to build/run/queue to a
# not-deployed connection) is a later layer, so these tests assert the config surface, nothing else.

_LIFECYCLE_TOML = """
[[inbound]]
name = "IB_OFF"
transport = "mllp"
router = "r"
deployed = false
auto_start = false
  [inbound.settings]
  port = 2600

[[outbound]]
name = "OB"
transport = "mllp"
deployed = false
auto_start = false
  [outbound.settings]
  host = "partner.example"
  port = 2700
"""


def test_lifecycle_flags_round_trip_toml(tmp_path: Path) -> None:
    """AC-10 (read half): ``deployed``/``auto_start`` in a connections.toml table desugar through the
    same build_* factories as code-first, on BOTH directions. Without the key in _INBOUND_KEYS /
    _OUTBOUND_KEYS this file is a hard WiringError (unknown key), so this pins the schema too."""
    reg = load_config(_config(tmp_path, _LIFECYCLE_TOML))
    ib = reg.inbound["IB_OFF"]
    ob = reg.outbound["OB"]
    assert ib.deployed is False
    assert ib.auto_start is False
    assert ob.deployed is False
    assert ob.auto_start is False


def test_lifecycle_flags_default_true_and_leave_the_model_unchanged(tmp_path: Path) -> None:
    """AC-9 / the byte-identical guarantee: a table carrying NEITHER flag builds exactly the connection
    it built before #233. Asserted by full frozen-dataclass equality against an all-defaults model —
    not just the two new fields — so a stray default change anywhere in the factory fails here."""
    reg = load_config(
        _config(
            tmp_path,
            """
            [[inbound]]
            name = "IB"
            transport = "mllp"
            router = "r"
              [inbound.settings]
              port = 2600

            [[outbound]]
            name = "OB"
            transport = "mllp"
              [outbound.settings]
              host = "partner.example"
              port = 2700
            """,
        )
    )
    ib = reg.inbound["IB"]
    ob = reg.outbound["OB"]
    assert (ib.deployed, ib.auto_start) == (True, True)
    assert (ob.deployed, ob.auto_start) == (True, True)
    assert ib == InboundConnection(
        name="IB", spec=ib.spec, router="r", source_file=ib.source_file, source_line=None
    )
    assert ob == OutboundConnection(
        name="OB", spec=ob.spec, source_file=ob.source_file, source_line=None
    )


@pytest.mark.parametrize("flag", ["deployed", "auto_start"])
def test_lifecycle_flag_must_be_a_bool(tmp_path: Path, flag: str) -> None:
    """A string "false" is the classic TOML footgun (it is truthy) — reject it at load, don't deploy a
    connection the author believed was switched off."""
    with pytest.raises(WiringError, match="must be true or false"):
        load_config(
            _config(
                tmp_path,
                f"""
                [[outbound]]
                name = "OB"
                transport = "mllp"
                {flag} = "false"
                  [outbound.settings]
                  host = "partner.example"
                  port = 2700
                """,
            )
        )


def test_misspelled_lifecycle_flag_is_still_rejected(tmp_path: Path) -> None:
    """The unknown-key gate must still fire on a near-miss: a typo'd ``deployd`` that was silently
    ignored would deploy a connection the author believed was switched off — the worst failure mode
    this feature has."""
    with pytest.raises(WiringError, match="unknown key"):
        load_config(
            _config(
                tmp_path,
                """
                [[outbound]]
                name = "OB"
                transport = "mllp"
                deployd = false
                  [outbound.settings]
                  host = "partner.example"
                  port = 2700
                """,
            )
        )


def test_gui_upsert_preserves_lifecycle_flags(tmp_path: Path) -> None:
    """AC-10 (write half): the connections.toml editor (the VS Code GUI / ``connection upsert`` CLI)
    round-trips both flags — they are in _SCALAR_FIELDS. A flag missing from that whitelist is silently
    dropped on the next save, i.e. an operator editing an unrelated field would REDEPLOY a connection
    that was deliberately not deployed. The re-saved file is then re-loaded to prove the write schema's
    output is still accepted by the read schema."""
    cfg = _config(tmp_path, _LIFECYCLE_TOML)
    for name in ("IB_OFF", "OB"):
        [obj] = [c for c in list_connections(cfg) if c["name"] == name]
        assert obj["deployed"] is False
        assert obj["auto_start"] is False
        upsert_connection(cfg, obj, validate=lambda _p: None)  # a no-op GUI re-save

    reg = load_config(cfg)  # the rewritten file still loads
    assert reg.inbound["IB_OFF"].deployed is False
    assert reg.inbound["IB_OFF"].auto_start is False
    assert reg.outbound["OB"].deployed is False
    assert reg.outbound["OB"].auto_start is False


# --- #234: the write schema is derived-and-verified against the read schema ---


def test_write_schema_matches_read_schema_per_direction() -> None:
    """#234's drift guard OF RECORD: the writer's emittable set (scalar tuple ∪ sub-tables) must equal
    the read schema exactly, per direction. A key added to _INBOUND_KEYS/_OUTBOUND_KEYS and not to the
    write tuples fails HERE (naming the key) instead of being silently deleted by the next GUI/CLI
    save — the root cause #234 closes. The module-level ``assert`` in connections_edit.py is
    belt-and-braces only: ``python -O`` strips it, so THIS pytest test is the CI gate."""
    write_union = set(_SCALAR_FIELDS) | set(_SUB_TABLES)
    missing_in = sorted(_INBOUND_KEYS - write_union)
    missing_out = sorted(_OUTBOUND_KEYS - write_union)
    assert not missing_in, f"inbound read-schema keys the writer would DELETE on save: {missing_in}"
    assert not missing_out, (
        f"outbound read-schema keys the writer would DELETE on save: {missing_out}"
    )
    dead = sorted(write_union - (_INBOUND_KEYS | _OUTBOUND_KEYS))
    assert not dead, f"write-schema keys no direction can read back: {dead}"
    # `direction` is the [[inbound]]/[[outbound]] array-of-tables header, never a table key — the
    # loader's _reject_unknown hard-fails a table carrying it, so it must never become writable.
    assert "direction" not in write_union
    # No duplicates within, and no overlap between, the scalar and sub-table emission passes.
    assert len(_SCALAR_FIELDS) + len(_SUB_TABLES) == len(write_union)


def test_streaming_threshold_hl7_only_toml(tmp_path: Path) -> None:
    with pytest.raises(WiringError, match="stream_threshold_bytes is HL7-specific"):
        load_config(
            _config(
                tmp_path,
                """
                [[inbound]]
                name = "IB"
                transport = "mllp"
                router = "r"
                content_type = "json"
                stream_threshold_bytes = 8192
                  [inbound.settings]
                  port = 2600

                [[outbound]]
                name = "OB"
                transport = "mllp"
                  [outbound.settings]
                  host = "epic.example"
                  port = 2700
                """,
            )
        )
