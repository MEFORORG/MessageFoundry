# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The dry-run applies the ingress guards the live listener applies (BACKLOG #1689, #1690).

``messagefoundry check`` and the Test Bench are pre-deploy gates: a fixture that previews ``RECEIVED``
and would ``NAK`` on the first live message is a gate that lies, and so is one that previews ``ERROR``
for a body the engine takes. Each test below drives ONE guard and fails on the pre-#1689 code, so the
file doubles as the negative control — deleting a guard turns its own test red and nothing else.

The tests at the bottom hold the one-copy property of part B: both live listeners and the dry-run
refuse each guard's body with the same reason, each caller reaches the shared functions, and no
listener carries its own copy of the sequence.
"""

from __future__ import annotations

import contextlib
import inspect
import io
import textwrap
import tokenize
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    EnvRef,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import RawMessage
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.dryrun import disposition_for, dry_run, route_message, split_messages
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports.base import ReceiptRefusedRetryable

#: A conformant 2.5.1 ADT^A01 whose PID-5 family name carries a byte that is latin-1 but NOT UTF-8
#: (U+00DC, "Ü"). Which of the two charsets an inbound declares is exactly what decides whether the
#: engine accepts this message, so it is the discriminating fixture for the decode guard.
ADT_UMLAUT_TEXT = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||MÜLLER^JANE\r"
)
ADT_LATIN1 = ADT_UMLAUT_TEXT.encode("latin-1")
ADT_UTF8 = ADT_UMLAUT_TEXT.encode("utf-8")


def _inbound(
    name: str = "in",
    *,
    content_type: ContentType = ContentType.HL7V2,
    encoding: str | None = None,
    max_message_bytes: int | None = None,
) -> InboundConnection:
    settings: dict[str, object] = {"host": "0.0.0.0", "port": 2575}
    if encoding is not None:
        settings["encoding"] = encoding
    return InboundConnection(
        name,
        ConnectionSpec(ConnectorType.MLLP, settings),
        router="r",
        content_type=content_type,
        validation=Validation(strict=False, hl7_version="2.5.1"),
        max_message_bytes=max_message_bytes,
    )


def _registry(
    ic: InboundConnection,
    *,
    route: Any = None,
    handle: Any = None,
    deployed: bool = True,
) -> Registry:
    """A one-inbound graph whose handler delivers by default, so any non-RECEIVED result is a guard."""
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_outbound(
        OutboundConnection(
            "out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}), deployed=deployed
        )
    )
    reg.add_router("r", route or (lambda m: ["h"]))
    reg.add_handler("h", handle or (lambda m: Send("out", m)))
    return reg


# --- guard 1: decode with the connection's declared charset, errors="strict" -------------------


def test_latin1_body_on_a_latin1_inbound_is_accepted() -> None:
    """The divergence runs BOTH ways: the engine takes this, so the gate must not refuse it.

    Pre-#1689 ``dry_run`` decoded UTF-8/``replace``, which neither refused nor accepted it honestly —
    it substituted U+FFFD for the byte and previewed a routed, transformed message carrying a
    corrupted patient name."""
    reg = _registry(_inbound(encoding="latin-1"))
    result = dry_run(reg, ADT_LATIN1)
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert "MÜLLER" in result.raw  # decoded with the DECLARED charset, not mojibake
    assert "�" not in result.raw


def test_latin1_body_on_a_utf8_inbound_is_error() -> None:
    """...and the same bytes on a utf-8 inbound are an ERROR, because the engine NAKs them (AR)."""
    reg = _registry(_inbound(encoding="utf-8"))
    result = dry_run(reg, ADT_LATIN1)
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and result.error.startswith("decode error (utf-8)")


def test_utf8_body_on_a_utf8_inbound_is_still_accepted() -> None:
    """The control: tightening the decode must not refuse the ordinary case."""
    result = dry_run(_registry(_inbound(encoding="utf-8")), ADT_UTF8)
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert "MÜLLER" in result.raw


def test_a_str_body_skips_the_charset_guard() -> None:
    """A ``str`` has nothing left to decode, so the Test Bench and ``verify smoke`` keep working."""
    result = dry_run(_registry(_inbound(encoding="utf-8")), ADT_UMLAUT_TEXT)
    assert result.disposition is MessageStatus.RECEIVED, result.error


def test_unknown_codec_name_is_error_not_a_raise() -> None:
    """An unknown ``encoding`` must report ERROR rather than escape out of the gate as LookupError."""
    result = dry_run(_registry(_inbound(encoding="no-such-codec")), ADT_UTF8)
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and "no-such-codec" in result.error


# --- guard 2: reject an embedded NUL ------------------------------------------------------------


def test_nul_in_the_body_is_error_not_received() -> None:
    """INGEST-4: a NUL in PID-5 previewed RECEIVED with one delivery before #1689.

    The live listener dead-letters it BEFORE ``Peek.parse`` and NAKs AR, because a NUL is invalid in
    every text payload accepted here and store-hostile besides."""
    nul_body = ADT_UMLAUT_TEXT.replace("JANE", "JA\x00NE").encode("utf-8")
    result = dry_run(_registry(_inbound(encoding="utf-8")), nul_body)
    assert result.disposition is MessageStatus.ERROR
    assert result.error == ingress_guards.NUL_REJECTED_REASON
    assert result.deliveries == []
    # The rejected body still has to be reportable: a NUL-bearing view escalates to mfb64 carriage
    # rather than being handed to a TEXT store that would truncate or refuse it (ADR 0028).
    assert "\x00" not in result.raw


def test_nul_on_a_non_hl7_inbound_is_error_too() -> None:
    reg = _registry(_inbound(content_type=ContentType.TEXT, encoding="utf-8"))
    result = dry_run(reg, b'{"a": "b\x00c"}')
    assert result.disposition is MessageStatus.ERROR
    assert result.error == ingress_guards.NUL_REJECTED_REASON


# --- guard 3: the size ceiling is the CONNECTION's, not a bare 16 MiB ---------------------------


def test_streaming_inbound_admits_a_body_over_the_engine_default() -> None:
    """#149: a streaming inbound raises the peek ceiling to its ``max_message_bytes``.

    ``dry_run`` called ``Peek.parse(text)`` bare, so it refused at the 16 MiB default a body the
    engine would admit — the gate failing a fixture that works in production."""
    over = ingress_guards.INGRESS_MAX_BYTES + 4096
    padding = "X" * (over - len(ADT_UMLAUT_TEXT))
    body = (ADT_UMLAUT_TEXT + f"OBX|1|ST|NOTE||{padding}\r").encode("utf-8")
    assert len(body) > ingress_guards.INGRESS_MAX_BYTES

    tight = dry_run(_registry(_inbound(encoding="utf-8")), body)
    assert tight.disposition is MessageStatus.ERROR  # the engine default still applies by default
    assert tight.error is not None and "parse error" in tight.error

    streaming = _registry(_inbound(encoding="utf-8", max_message_bytes=256 * 1024 * 1024))
    assert dry_run(streaming, body).disposition is MessageStatus.RECEIVED


def test_below_default_cap_refuses_what_the_default_would_admit() -> None:
    """The same read cuts the other way: a connection capped BELOW the default must refuse sooner."""
    reg = _registry(_inbound(encoding="utf-8", max_message_bytes=len(ADT_UTF8) // 2))
    result = dry_run(reg, ADT_UTF8)
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and "parse error" in result.error


def test_non_hl7_body_over_the_ceiling_is_error() -> None:
    """The non-HL7 path had NO size guard at all — the HL7 one rode in on ``Peek.parse``."""
    reg = _registry(_inbound(content_type=ContentType.TEXT, encoding="utf-8"))
    result = dry_run(reg, b"x" * (ingress_guards.INGRESS_MAX_BYTES + 1))
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and "ingress exceeds max size" in result.error


# --- guard 4: a binary content type is CARRIED, never text-decoded ------------------------------


def test_binary_inbound_carries_bytes_instead_of_decoding_them() -> None:
    """ADR 0028: the listener never decodes a binary body; it hands on ``RawMessage.from_bytes``.

    Pre-#1689 ``_dry_run_raw`` decoded strict UTF-8 outside any ``try``, so a PDF fixture raised
    ``UnicodeDecodeError`` straight out of ``dry_run`` and a decodable one reached the Handler as text
    its codec could not read back as bytes."""
    pdf = b"%PDF-1.7\n\x00\x80\xff binary body \x00"
    seen: list[RawMessage] = []

    def route(msg: RawMessage) -> list[str]:
        seen.append(msg)
        return ["h"]

    reg = _registry(_inbound(content_type=ContentType.BINARY), route=route)
    result = dry_run(reg, pdf)

    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert len(seen) == 1
    assert seen[0].is_binary and seen[0].raw_bytes == pdf  # the exact bytes survive to the codec
    assert result.raw.startswith("mfb64:v1:")


def test_binary_inbound_does_not_double_wrap_a_carriage_string() -> None:
    """Re-running a stored raw through the preview must not wrap ``mfb64:`` inside ``mfb64:``."""
    carried = RawMessage.from_bytes(b"\x00\x01\x02", ContentType.DICOM.value).raw
    reg = _registry(_inbound(content_type=ContentType.DICOM))
    result = dry_run(reg, carried)
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert result.raw == carried


def test_decode_ingress_refuses_a_binary_inbound() -> None:
    """The split is structural, not a caller's option — asking for a text decode here is a bug."""
    with pytest.raises(ValueError, match="carry_binary_ingress"):
        ingress_guards.decode_ingress(b"abc", _inbound(content_type=ContentType.BINARY))


# --- guard 5: the fixture reader hands on BYTES, so the inbound owns the decode -----------------


def test_split_messages_returns_bytes_verbatim_for_a_single_message() -> None:
    """A non-batch payload comes back byte-identical, exactly as the File source hands one off."""
    assert split_messages(ADT_LATIN1) == [ADT_LATIN1]


def test_split_messages_splits_a_latin1_batch_without_mojibake() -> None:
    """The boundary search is a latin-1 byte view, so it is charset-agnostic and byte-faithful.

    Pre-#1689 this returned ``str`` decoded UTF-8/``replace``, so the second message's name reached
    the Router with U+FFFD in it before any inbound had declared a charset."""
    batch = ADT_LATIN1 + ADT_LATIN1.replace(b"MSG1", b"MSG2")
    parts = split_messages(batch)
    assert len(parts) == 2
    assert all(isinstance(p, bytes) for p in parts)
    assert parts[0].decode("latin-1").startswith("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1")
    assert "MÜLLER" in parts[1].decode("latin-1")


def test_split_messages_separator_agnostic_on_bytes() -> None:
    """A batch whose MSH-1 is not ``|`` still splits per-message (low-4), now on the byte view."""
    batch = (
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01^M1^P^2.5.1\r"
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02^M2^P^2.5.1\r"
    )
    parts = split_messages(batch)
    assert len(parts) == 2
    assert parts[0].startswith(b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01")
    assert parts[1].startswith(b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02")


# --- BACKLOG #1690: a decline is not a filter ---------------------------------------------------


def _declining_registry() -> Registry:
    return _registry(_inbound(), deployed=False)


def test_every_send_declined_previews_not_deployed_not_filtered() -> None:
    """#233 ruled a decline must be distinguishable from an intentional filter; the gate collapsed it.

    An author reading FILTERED goes looking for the filter in their Handler. There isn't one — the
    destination is simply not deployed, which is the one thing the old preview could not say."""
    result = dry_run(_declining_registry(), ADT_UTF8)
    assert result.disposition is MessageStatus.NOT_DEPLOYED
    assert result.handlers == ["h"]
    assert result.deliveries == []
    assert result.declined == ["out"]  # named, so the author knows WHICH destination


def test_a_real_filter_still_previews_filtered() -> None:
    """The control for the branch above: nothing declined means the filter reading is the true one."""
    reg = _registry(_inbound(), handle=lambda m: None)
    result = dry_run(reg, ADT_UTF8)
    assert result.disposition is MessageStatus.FILTERED
    assert result.declined == []


def test_disposition_for_prefers_the_decline_over_the_filter() -> None:
    """A handler that both filters one Send and has another declined still has a decline to report."""
    reg = _declining_registry()
    outcome = route_message(reg, reg.inbound["in"], ADT_UMLAUT_TEXT)
    assert outcome.routed and not outcome.deliveries and outcome.declined == ["out"]
    assert disposition_for(outcome) is MessageStatus.NOT_DEPLOYED


# --- one copy: both listeners and the dry-run go through the shared guards (#1689 part B) --------
#
# Part A pinned the listener's inline copy to the shared module with two constant comparisons. Part B
# deleted the copy, so those comparisons had nothing left to compare. What replaces them: the live
# listeners and the dry-run are driven over the same bodies and must refuse with the same reason; each
# caller is shown to reach the shared functions; and the listener source must not grow a copy back.

_LISTENERS = ("_handle_inbound", "_handle_inbound_http")


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "parity.db")
    yield s
    await s.close()


async def _live_rows(
    store: MessageStore, ic: InboundConnection, body: bytes, listener: str
) -> list[dict[str, Any]]:
    """Hand ``body`` to one live listener and return every ``messages`` row (a fresh store per test)."""
    reg = _registry(ic)
    handler = getattr(
        wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False)),
        listener,
    )
    # The HTTP receipt handler raises, after recording the row, for a codec name that sets up no
    # decode; the row is what this compares, so the raise is the listener's answer and not a fault.
    with contextlib.suppress(ReceiptRefusedRetryable):
        await handler(reg.inbound[ic.name], body)
    cur = await store._db.execute("SELECT status, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


#: One body per guard, each with the inbound that makes that guard fire.
_GUARD_CASES = [
    pytest.param(_inbound(encoding="utf-8"), ADT_LATIN1, id="decode"),
    pytest.param(
        _inbound(encoding="utf-8"),
        ADT_UMLAUT_TEXT.replace("JANE", "JA\x00NE").encode("utf-8"),
        id="nul_hl7",
    ),
    # ADR 0205 rule 4: an MLLP start byte inside an HL7 v2 body, past its leading whitespace.
    pytest.param(
        _inbound(encoding="utf-8"),
        ADT_UMLAUT_TEXT.replace("JANE", "JA\x0bNE").encode("utf-8"),
        id="frame_byte_hl7",
    ),
    pytest.param(_inbound(content_type=ContentType.JSON), b'{"a": "b\x00c"}', id="nul_text"),
    pytest.param(
        _inbound(content_type=ContentType.JSON), b'{"a": "' + b"y" * 64 + b'"}', id="size_text"
    ),
    pytest.param(_inbound(content_type=ContentType.BINARY), b"\x00\x01" * 40, id="size_binary"),
    # The declared-type sniff: the listener refuses these, and the dry-run does not run it yet. Strict
    # xfail, so the day the dry-run gains the sniff these turn red and ask to be promoted. Why it is
    # not simply added: the ingress_guards module docstring, "still differ".
    pytest.param(
        _inbound(content_type=ContentType.JSON),
        b"not json at all",
        id="type_text",
        marks=pytest.mark.xfail(strict=True, reason="the dry-run does not run the type sniff"),
    ),
    pytest.param(
        _inbound(content_type=ContentType.DICOM),
        b"\x00\x01\x02",
        id="type_binary",
        marks=pytest.mark.xfail(strict=True, reason="the dry-run does not run the type sniff"),
    ),
]


@pytest.mark.parametrize("listener", _LISTENERS)
@pytest.mark.parametrize(("ic", "body"), _GUARD_CASES)
async def test_the_listener_and_the_dry_run_refuse_with_the_same_reason(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    ic: InboundConnection,
    body: bytes,
    listener: str,
) -> None:
    """The gate's question and the engine's answer, asked of one body: they must agree word for word.

    The ceiling is lowered so the size cases stay small. Both callers read it from the one module
    attribute, so lowering it there is a test of that too: a listener with its own ceiling would take
    the oversize bodies and this would go red."""
    monkeypatch.setattr(ingress_guards, "INGRESS_MAX_BYTES", 64)

    preview = dry_run(_registry(ic), body)
    rows = await _live_rows(store, ic, body, listener)

    assert preview.disposition is MessageStatus.ERROR, preview.error
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert rows[0]["error"] == preview.error


def _spy(monkeypatch: pytest.MonkeyPatch, module: Any, names: tuple[str, ...]) -> list[str]:
    """Wrap each named function in ``module`` so a call records its name, then runs the real one."""
    calls: list[str] = []
    for name in names:
        real = getattr(module, name)

        def spy(*args: Any, _real: Any = real, _name: str = name, **kwargs: Any) -> Any:
            calls.append(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(module, name, spy)
    return calls


@pytest.mark.parametrize("listener", _LISTENERS)
@pytest.mark.parametrize(
    ("content_type", "body", "expected"),
    [
        pytest.param(ContentType.HL7V2, ADT_UTF8, ["decode_body", "check_decoded"], id="hl7v2"),
        pytest.param(ContentType.JSON, b'{"a": 1}', ["decode_body", "check_decoded"], id="json"),
        pytest.param(
            ContentType.BINARY,
            b"\x00\x01",
            ["check_binary_size", "carry_binary_ingress"],
            id="binary",
        ),
    ],
)
async def test_each_listener_calls_the_shared_guards(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    listener: str,
    content_type: ContentType,
    body: bytes,
    expected: list[str],
) -> None:
    """A listener that answered the parity test above from a private copy would never reach these."""
    names = ("decode_body", "check_decoded", "check_binary_size", "carry_binary_ingress")
    calls = _spy(monkeypatch, wiring_runner, names)

    rows = await _live_rows(store, _inbound(content_type=content_type), body, listener)

    assert rows == [{"status": MessageStatus.RECEIVED.value, "error": None}]
    assert calls == expected


def test_the_dry_run_calls_the_same_two_guards(monkeypatch: pytest.MonkeyPatch) -> None:
    """The other half of one copy: ``decode_ingress`` is those two calls, not a sibling of them."""
    calls = _spy(monkeypatch, ingress_guards, ("decode_body", "check_decoded"))

    result = dry_run(_registry(_inbound(encoding="utf-8")), ADT_UTF8)

    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert calls == ["decode_body", "check_decoded"]


#: Code that only an inline copy of the guard sequence would put in a listener's body.
_INLINE_GUARD_MARKERS = (
    "normalize(",
    ".decode(",
    'errors="strict"',
    '"\\x00" in',
    "'\\x00' in",
    "chr(0)",
    "INGRESS_MAX_BYTES",
    "no matching magic bytes",
    "_content_matches_declared",
    "ingress exceeds max size",
    "invalid in a text/HL7 payload",
    "RawMessage.from_bytes",
    "max_message_bytes or",
)


def _code_without_comments(func: Any) -> str:
    """``func``'s source with every ``#`` comment dropped, so a comment can name what code may not."""
    source = textwrap.dedent(inspect.getsource(func))
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return tokenize.untokenize(t for t in tokens if t.type != tokenize.COMMENT)


@pytest.mark.parametrize(
    ("method", "shared_call"),
    [
        ("_handle_inbound", "decode_body("),
        ("_handle_inbound_http", "decode_body("),
        ("_declared_content_mismatch", "check_declared_type("),
    ],
)
def test_no_listener_carries_its_own_copy_of_the_guards(method: str, shared_call: str) -> None:
    """Fails the day someone pastes a decode, a NUL test, a ceiling or a sniff back into a listener.

    The spy test above cannot see that: a listener could call the shared guards AND keep a stale copy
    beside them, and the copy is what drifts. So this reads the code, less its comments. It is a
    tripwire over the spellings a paste would carry, not a proof that no copy exists."""
    code = _code_without_comments(getattr(wiring_runner.RegistryRunner, method))
    assert shared_call in code  # the instrument reads the method it names
    assert [m for m in _INLINE_GUARD_MARKERS if m in code] == []


def test_the_nul_reason_is_the_listeners_stored_wording() -> None:
    # One copy now, in ingress_guards, so this pins the operator-facing wording of the stored reason
    # rather than two copies to each other. The live rows above already assert both callers use it.
    assert (
        ingress_guards.NUL_REJECTED_REASON
        == "ingress body contains a NUL (U+0000), invalid in a text/HL7 payload"
    )


def _inbound_declaring(encoding: object) -> InboundConnection:
    """An inbound whose ``encoding`` setting holds ``encoding`` as-is, past the load-time name check."""
    return InboundConnection(
        "in",
        ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575, "encoding": encoding}),
        router="r",
        content_type=ContentType.HL7V2,
    )


@pytest.mark.parametrize("listener", _LISTENERS)
async def test_a_null_encoding_decodes_as_utf8_on_the_listener_as_in_the_dry_run(
    store: MessageStore, listener: str
) -> None:
    """BACKLOG #2431: an explicit ``None`` is "not declared" on both callers. Before the fix the
    listener handed ``None`` to ``bytes.decode`` and a ``TypeError`` escaped with no row at all."""
    ic = _inbound_declaring(None)
    assert dry_run(_registry(ic), ADT_UTF8).disposition is MessageStatus.RECEIVED

    rows = await _live_rows(store, ic, ADT_UTF8, listener)

    assert rows == [{"status": MessageStatus.RECEIVED.value, "error": None}]


@pytest.mark.parametrize("listener", _LISTENERS)
@pytest.mark.parametrize(
    "declared",
    [
        pytest.param("not-a-real-codec", id="unknown_name"),
        pytest.param("base64", id="not_a_text_codec"),
        pytest.param("undefined", id="refusing_codec"),
        # An env() reference, which the decode never resolves. Config load refuses it on an inbound
        # (test_wiring.py); the backstop refuses one that got past load all the same.
        pytest.param(EnvRef("charset"), id="unresolved_env_ref"),
    ],
)
async def test_a_codec_name_naming_no_text_codec_is_the_same_error_row_on_both_callers(
    store: MessageStore, listener: str, declared: object
) -> None:
    """BACKLOG #2431: a name that sets up no decode is a ``decode`` ERROR row on the listener, worded
    as the dry-run words it. Before the fix a ``LookupError`` or ``TypeError`` escaped the listener
    into its transport with no row."""
    ic = _inbound_declaring(declared)
    preview = dry_run(_registry(ic), ADT_UTF8)

    rows = await _live_rows(store, ic, ADT_UTF8, listener)

    assert preview.disposition is MessageStatus.ERROR
    assert preview.error is not None and preview.error.startswith("decode error (")
    assert rows == [{"status": MessageStatus.ERROR.value, "error": preview.error}]


@pytest.mark.parametrize("listener", _LISTENERS)
async def test_an_env_encoding_is_not_resolved_by_the_decode_even_with_a_value(
    store: MessageStore, listener: str
) -> None:
    """BACKLOG #2431: config load refuses an env() inbound encoding instead of resolving it, so the
    decode never reads an environment value. Pinned with a value present, so a return of per-message
    resolution on either caller fails here rather than passing on an empty value set."""
    ic = _inbound_declaring(EnvRef("charset"))
    reg = _registry(ic)
    preview = dry_run(reg, ADT_UTF8)
    runner = wiring_runner.RegistryRunner(
        reg, store, egress=EgressSettings(deny_by_default=False), env_values={"charset": "utf-8"}
    )
    with contextlib.suppress(
        ReceiptRefusedRetryable
    ):  # the HTTP receipt's answer, as in _live_rows
        await getattr(runner, listener)(reg.inbound["in"], ADT_UTF8)

    cur = await store._db.execute("SELECT status, error FROM messages")
    rows = [dict(r) for r in await cur.fetchall()]
    assert preview.disposition is MessageStatus.ERROR
    assert preview.error is not None and preview.error.startswith("decode error (")
    assert rows == [{"status": MessageStatus.ERROR.value, "error": preview.error}]


async def test_the_mllp_listener_naks_a_codec_name_naming_no_codec(store: MessageStore) -> None:
    """The NAK half: the MLLP listener answers AE, since the configuration and not the message is at
    fault and a resend can succeed once it is fixed; bytes invalid in a usable charset stay AR."""
    ic = _inbound_declaring("not-a-real-codec")
    reg = _registry(ic)
    runner = wiring_runner.RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))

    ack = await runner._handle_inbound(reg.inbound["in"], ADT_UTF8)

    assert ack is not None and "MSA|AE|" in ack
    ic_utf8 = _inbound(encoding="utf-8")
    reg_utf8 = _registry(ic_utf8)
    runner_utf8 = wiring_runner.RegistryRunner(
        reg_utf8, store, egress=EgressSettings(deny_by_default=False)
    )
    invalid = await runner_utf8._handle_inbound(reg_utf8.inbound["in"], ADT_LATIN1)
    assert invalid is not None and "MSA|AR|" in invalid


def test_peek_max_bytes_resolves_the_per_connection_cap() -> None:
    assert ingress_guards.peek_max_bytes(_inbound()) == ingress_guards.INGRESS_MAX_BYTES
    assert ingress_guards.peek_max_bytes(_inbound(max_message_bytes=99)) == 99


def test_ingress_encoding_falls_back_for_an_absent_or_null_declaration() -> None:
    assert ingress_guards.ingress_encoding(_inbound()) == "utf-8"
    assert ingress_guards.ingress_encoding(_inbound(encoding="latin-1")) == "latin-1"


def test_only_a_codec_name_that_decodes_nothing_is_the_configurations_fault() -> None:
    """BACKLOG #2431: the AE/AR split rests on the codec NAME, probed, not on the error's type, so a
    usable codec refusing one body stays that body's fault (AR on MLLP)."""
    with pytest.raises(ingress_guards.IngressGuardError) as body_fault:
        ingress_guards.decode_body(ADT_LATIN1, _inbound(encoding="ascii"))
    assert type(body_fault.value) is ingress_guards.IngressGuardError
    for unusable in ("not-a-real-codec", "undefined", "base64"):
        with pytest.raises(ingress_guards.IngressCodecUnusable):
            ingress_guards.decode_body(ADT_UTF8, _inbound_declaring(unusable))


# --- the strict-validation timeout (BACKLOG #1689 remainder) -----------------------------------


def _strict_inbound(timeout: float | None, **kwargs: Any) -> InboundConnection:
    return InboundConnection(
        "in",
        ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
        router="r",
        content_type=ContentType.HL7V2,
        validation=Validation(strict=True, hl7_version="2.5.1", strict_timeout_s=timeout),
        **kwargs,
    )


def _slow_validate(monkeypatch: pytest.MonkeyPatch, seconds: float) -> list[int]:
    """Make hl7apy's validate take ``seconds`` longer, in BOTH callers' namespaces; the returned list
    counts the calls. On the unfixed dry-run, which validated un-timed, the call then goes on to
    hl7apy, and the test fails on the ERROR hl7apy previews ("Missing required child
    ADT_A01.PV1", since the fixture has no PV1) rather than on the timeout's text."""
    import time

    from messagefoundry.parsing import validate as real
    from messagefoundry.pipeline import dryrun

    calls: list[int] = []

    def slow(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        time.sleep(seconds)
        return real(*args, **kwargs)

    monkeypatch.setattr(dryrun, "validate", slow)
    monkeypatch.setattr(wiring_runner, "validate", slow)
    return calls


@pytest.mark.parametrize("listener", _LISTENERS)
async def test_a_strict_validate_past_the_timeout_is_the_same_error_on_both_sides(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, listener: str
) -> None:
    """The listener refuses a validate that outruns ``validation.strict_timeout_s`` (#89); a dry-run
    that validated un-timed waited it out and previewed hl7apy's own refusal of the body instead
    ("Missing required child ADT_A01.PV1"). Both must now say the same words."""
    _slow_validate(monkeypatch, 0.3)
    ic = _strict_inbound(0.05)

    preview = dry_run(_registry(ic), ADT_UTF8)
    rows = await _live_rows(store, ic, ADT_UTF8, listener)

    assert preview.disposition is MessageStatus.ERROR, preview.error
    assert preview.error == "strict-validation timed out after 0.05s"
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert rows[0]["error"] == preview.error


def _clock(monkeypatch: pytest.MonkeyPatch, step: float) -> None:
    """Advance the dry-run's monotonic clock by ``step`` on every read, so a validate measures as
    ``step`` seconds long without the test sleeping."""
    import time
    from types import SimpleNamespace

    from messagefoundry.pipeline import dryrun

    ticks = iter(range(1_000_000))
    # The module's own `time` name only, so the patched clock reaches nothing outside dryrun.
    fake = SimpleNamespace(time=time.time, monotonic=lambda: next(ticks) * step)
    monkeypatch.setattr(dryrun, "time", fake)


def test_a_validate_measured_past_the_timeout_gives_the_listener_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inline, the preview cannot abandon a validate; it measures it, and a finished validate that
    took longer than the timeout is refused with the listener's text, not with what it returned."""
    _clock(monkeypatch, 31.0)

    result = dry_run(_registry(_strict_inbound(30.0)), ADT_UTF8)

    assert result.disposition is MessageStatus.ERROR
    assert result.error == "strict-validation timed out after 30.0s"


def test_a_fault_raised_after_the_timeout_gives_the_timeout_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The listener has given up by the time a late validate raises, so its row says timed out; the
    preview checks the elapsed time before re-raising, and says the same."""
    from messagefoundry.pipeline import dryrun

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("validator fault")

    monkeypatch.setattr(dryrun, "validate", boom)
    _clock(monkeypatch, 31.0)

    result = dry_run(_registry(_strict_inbound(30.0)), ADT_UTF8)

    assert result.error == "strict-validation timed out after 30.0s"


def test_a_disabled_timeout_validates_un_timed_as_the_listener_does(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``strict_timeout_s <= 0`` turns the backstop off on the listener, so the preview never times
    the validate out, however long it measures."""
    _clock(monkeypatch, 1e6)

    result = dry_run(_registry(_strict_inbound(0)), ADT_UTF8)

    # The fixture has no PV1, so hl7apy refuses it; what matters is that it was not a timeout.
    assert result.error == "Missing required child ADT_A01.PV1"


def test_an_invalid_result_with_empty_error_text_is_still_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``validate`` reports a fault as ``ok=False`` with the exception's text, which can be empty; the
    listener refuses on ``ok`` alone, so the preview must not read the empty text as valid."""
    from messagefoundry.parsing import ValidationResult
    from messagefoundry.pipeline import dryrun

    monkeypatch.setattr(
        dryrun, "validate", lambda *a, **k: ValidationResult(ok=False, version=None, errors=[""])
    )

    result = dry_run(_registry(_strict_inbound(30.0)), ADT_UTF8)

    assert result.disposition is MessageStatus.ERROR


def test_a_fast_validate_inside_the_timeout_still_reports_its_errors() -> None:
    """The bound changes nothing for a validate that finishes in time: hl7apy's own errors come back."""
    result = dry_run(_registry(_strict_inbound(30.0)), ADT_UTF8)

    assert result.disposition is MessageStatus.ERROR
    assert result.error == "Missing required child ADT_A01.PV1"


def test_a_validate_that_raises_inside_the_timeout_still_raises_out_of_the_dry_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fault inside the timeout is the validator's, not a timeout, and leaves ``dry_run`` as before."""
    from messagefoundry.pipeline import dryrun

    def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("validator fault")

    monkeypatch.setattr(dryrun, "validate", boom)

    with pytest.raises(RuntimeError, match="validator fault"):
        dry_run(_registry(_strict_inbound(30.0)), ADT_UTF8)


def test_a_streaming_body_over_its_threshold_is_not_whole_body_validated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The listener validates only the header of such a body, so a whole-body validate the preview
    timed out on would refuse a message the engine takes."""
    calls = _slow_validate(monkeypatch, 0.0)
    _clock(monkeypatch, 1e6)
    ic = _strict_inbound(0.05, stream_threshold_bytes=16)

    result = dry_run(_registry(ic), ADT_UTF8)

    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert calls == []
