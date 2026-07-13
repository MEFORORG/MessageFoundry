# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""connections.toml read path (ADR 0007) — data-authored connections merge into the registry the
code-first inbound()/outbound() populate, sharing every factory + guard."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType, OrderingMode
from messagefoundry.config.wiring import (
    EnvRef,
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
