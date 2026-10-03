# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``samples/send_mllp.py`` refuses a file holding an MLLP frame byte, before it dials (ASVS 1.1.2).

The operator docs tell a deployer to run this sender against a file they name. It framed with the
leaf's bare ``frame``, so a file holding ``0x1C``, CR, ``0x0B`` and a second MSH would have gone
out as two frames. It now frames with ``frame_checked``, the rule the engine's own MLLP delivery refuses by
(ADR 0205 rule 1), and frames BEFORE opening the connection.

"Nothing is sent" is read off a real loopback listener, not off a patched API, so a dial by any
route is seen; the clean case is the instrument's positive control, the same listener seeing the
one connection and exactly one frame. Each hostile case also shows that the bare ``frame`` of the
same payload is not one frame whose body is free of frame bytes, which is all the guard claims: the
input is the shape the rule refuses, not a clean message refused by mistake. Synthetic data only.

The ACK the script prints is the peer's text, so the last tests show a control character in it,
ESC among them, printed as a visible ``\\xNN`` escape rather than passed to the terminal.
"""

from __future__ import annotations

import ast
import importlib.util
import socket
import threading
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.mllpcodec import CR, EB, SB, MLLPDecoder, build_ack, frame
from messagefoundry.parsing import normalize

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "samples" / "send_mllp.py"

_MSH = "MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A01^ADT_A01|{cid}|P|2.5.1\r"
_CLEAN = _MSH.format(cid="CTRL1") + "EVN|A01|20260101000000\r"

#: The start byte, the end byte alone, the end byte before the trailer CR, and the executed shape:
#: end byte, CR, start byte, then a second MSH segment.
_HOSTILE = {
    "start_byte": _MSH.format(cid="A\x0bB"),
    "end_byte": _MSH.format(cid="A\x1cB"),
    "end_then_cr": _MSH.format(cid="A\x1c\rB"),
    "second_frame": _CLEAN + "\x1c\r\x0b" + _MSH.format(cid="CTRL2"),
    # A file saved with its own framing. The engine's ingress would tolerate the edge bytes, but its
    # delivery refuses any frame byte, and this sender applies the delivery rule (see its docstring).
    "already_framed": "\x0b" + _CLEAN + "\x1c\r",
}


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("_send_mllp_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _is_one_clean_mllp_frame(wire: bytes) -> bool:
    if len(wire) < 3 or wire[0] != SB or wire[-2:] != bytes([EB, CR]):
        return False
    body = wire[1:-2]
    if SB in body or EB in body:
        return False
    return list(MLLPDecoder().feed(wire)) == [body]


@pytest.fixture
def listener() -> Iterator[socket.socket]:
    server = socket.create_server(("127.0.0.1", 0))
    server.settimeout(5)
    try:
        yield server
    finally:
        server.close()


def _port(server: socket.socket) -> str:
    return str(server.getsockname()[1])


@pytest.mark.parametrize("case", sorted(_HOSTILE))
def test_a_file_holding_a_frame_byte_is_refused_before_any_dial(
    case: str, listener: socket.socket, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    raw = _HOSTILE[case].encode("utf-8")
    assert not _is_one_clean_mllp_frame(frame(normalize(raw)))  # the shape the rule refuses
    path = tmp_path / "hostile.hl7"
    path.write_bytes(raw)

    status = _load().main([str(path), "--port", _port(listener), "--timeout", "1"])

    assert status == 3
    listener.setblocking(False)
    with pytest.raises(BlockingIOError):  # no connection is waiting: the script never dialled
        listener.accept()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "frame" in captured.err and "not sent" in captured.err
    assert "SEND" not in captured.err  # the byte and its position, never the content


def test_a_clean_file_still_goes_as_exactly_one_frame(
    listener: socket.socket, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "clean.hl7"
    path.write_bytes(_CLEAN.encode("utf-8"))
    received = bytearray()
    accepted: list[int] = []
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn, _ = listener.accept()
            accepted.append(1)
            with conn:
                conn.settimeout(5)
                while not received.endswith(bytes([EB, CR])):
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    received.extend(chunk)
                conn.sendall(frame(build_ack(_CLEAN, timestamp="1")))
        except OSError as exc:  # surfaced below, not lost to the threading excepthook
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    status = _load().main([str(path), "--port", _port(listener), "--timeout", "5"])
    thread.join(5)

    assert not thread.is_alive() and errors == []
    assert status == 0
    assert accepted == [1]
    assert _is_one_clean_mllp_frame(bytes(received))
    assert list(MLLPDecoder().feed(bytes(received))) == [_CLEAN.encode("utf-8")]
    captured = capsys.readouterr()
    assert "--- ACK ---" in captured.out and "MSA|AA|CTRL1" in captured.out
    assert captured.err == ""


def test_the_script_frames_only_through_the_checked_framer() -> None:
    # A static pin beside the behavioural tests, since the harness guard walks harness/ only. It
    # refuses any `.frame` attribute (`MLLP_CODEC.frame`, `mllpcodec.frame`) and any name `frame`
    # however imported, and requires that `frame_checked` is called. Hand-built frame bytes are out
    # of its sight; the behavioural tests above cover the effect.
    tree = ast.parse(_SCRIPT.read_text(encoding="utf-8"))
    frame_attrs = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "frame"
    ]
    frame_names = [
        node.lineno
        for node in ast.walk(tree)
        if (isinstance(node, ast.Name) and node.id == "frame")
        or (isinstance(node, ast.alias) and node.name == "frame")
    ]
    checked_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "frame_checked"
    ]
    assert len(checked_calls) == 1, checked_calls
    assert frame_attrs == [] and frame_names == [], (frame_attrs, frame_names)


def test_the_check_runs_on_the_message_as_sent_after_crlf_is_collapsed(
    listener: socket.socket, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # In the file the end byte sits at offset 4; after CRLF -> CR it is at 3, which is what is named.
    path = tmp_path / "crlf.hl7"
    path.write_bytes(b"AB\r\n\x1c" + _CLEAN.encode("utf-8"))
    assert path.read_bytes().index(b"\x1c") == 4  # the file offset differs from the named one

    status = _load().main([str(path), "--port", _port(listener), "--timeout", "1"])

    assert status == 3
    assert "0x1C at byte 3;" in capsys.readouterr().err


def test_the_printed_ack_shows_control_characters_as_escapes(
    listener: socket.socket, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A peer's ACK holding ESC sequences (a cursor move, a window retitle), DEL and a C1 CSI: each
    # is printed as a visible escape, while CR still becomes a newline and tab stays a tab.
    path = tmp_path / "clean.hl7"
    path.write_bytes(_CLEAN.encode("utf-8"))
    ack = (
        "MSH|^~\\&|RECV|FAC|SEND|FAC|1||ACK|1|P|2.5.1\r"
        "MSA|AA|CTRL1|\x1b[2J\x1b]0;owned\x07\x7f\u009b1m\tend\r"
    )

    def serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.settimeout(5)
            received = b""
            while not received.endswith(bytes([EB, CR])):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                received += chunk
            conn.sendall(frame(ack))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    status = _load().main([str(path), "--port", _port(listener), "--timeout", "5"])
    thread.join(5)

    assert status == 0
    out = capsys.readouterr().out
    assert out.startswith("--- ACK ---\nMSH|")
    assert "MSA|AA|CTRL1|\\x1b[2J\\x1b]0;owned\\x07\\x7f\\x9b1m\tend\n" in out
    assert not any(ch < " " and ch not in "\n\t" or "\x7f" <= ch < "\xa0" for ch in out)


def test_printable_leaves_ordinary_text_alone() -> None:
    # Control: a clean ACK prints exactly as before, CR as newline, non-ASCII text kept.
    printable = _load()._printable
    assert printable(b"MSH|^~\\&|A\rMSA|AA|X\t\xc3\xa9\r") == "MSH|^~\\&|A\nMSA|AA|X\té\n"
