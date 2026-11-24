# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sandbox worker's serve loop, driven in-process (BACKLOG #6813).

* A call that runs out of memory is answered with a ``memory`` reply. That reply is built when
  memory is scarce, so at least these are released first: the Handler's frames, through the
  traceback or the exception chain, the decoded request and the raw request frame.
* A reply write that fails with ``OSError`` may have put part of a frame on the pipe. Another
  frame after it would desynchronize the MFW2 stream, so the worker exits instead.
"""

from __future__ import annotations

import io
import types
import weakref
from typing import Any

import pytest

from messagefoundry.config import wiring
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline import sandbox as sandbox_mod
from tests._root_logging import root_logging_restored


@pytest.fixture
def worker() -> types.ModuleType:
    """The worker module, imported with the root logger put back afterwards: its import calls
    ``configure_stderr_logging()``, which is right in the worker's child process and wrong here, and
    a module-level import would leave that from collection onward."""
    with root_logging_restored():
        from messagefoundry.pipeline import _sandbox_worker

    return _sandbox_worker


class _Frame(bytearray):
    """A raw request frame that a weakref can watch (``bytes`` cannot be weakly referenced)."""


class _Req:
    def __init__(self) -> None:
        self.request_id, self.phase, self.name = "r1", "transform", "h_oom"


class _Held:
    """Stands in for the memory a Handler's locals hold when it runs out."""


def _drive(
    worker: Any,
    monkeypatch: pytest.MonkeyPatch,
    respond: Any,
    write_frame: Any,
    encode_fail: Any,
) -> tuple[int, dict[str, Any]]:
    """Run :func:`worker.main` over one boot frame and one request frame, with the codec, the
    config load and the frame I/O replaced, and return its exit code and the watched objects."""
    watched: dict[str, Any] = {}
    frames: list[Any] = [b"boot", _Frame(b"request"), None]

    def read_frame(_stream: Any) -> Any:
        frame = frames.pop(0)
        if isinstance(frame, _Frame):
            watched["frame"] = weakref.ref(frame)
        return frame

    def decode_request(_frame: Any) -> _Req:
        req = _Req()
        watched["req"] = weakref.ref(req)
        return req

    boot = types.SimpleNamespace(
        snapshot=None, code_sets=None, mem_mb=None, forbidden=(), broker=False
    )
    monkeypatch.setattr("sys.stdin", types.SimpleNamespace(buffer=io.BytesIO()))
    monkeypatch.setattr("sys.stdout", types.SimpleNamespace(buffer=io.BytesIO()))
    monkeypatch.setattr(worker, "_redirect_stdout_to_stderr", lambda: None)
    monkeypatch.setattr(worker, "_apply_resource_caps", lambda _mb: "the cap")
    monkeypatch.setattr(worker, "_install_import_guard", lambda _forbidden: None)
    monkeypatch.setattr(worker, "_respond", lambda *a: respond(watched, *a))
    monkeypatch.setattr(wiring, "load_snapshot", lambda *_a, **_k: object())
    monkeypatch.setattr(sandbox_mod, "_read_frame_bytes", read_frame)
    monkeypatch.setattr(sandbox_mod, "_write_frame", write_frame)
    monkeypatch.setattr(sandbox_mod, "graph_shape", lambda _registry: None)
    monkeypatch.setattr(codec, "decode_boot", lambda _frame: boot)
    monkeypatch.setattr(codec, "encode_ready", lambda _shape: b"ready")
    monkeypatch.setattr(codec, "decode_request", decode_request)
    monkeypatch.setattr(codec, "encode_fail", lambda **kw: encode_fail(watched, **kw))
    return worker.main(), watched


def _alive(watched: dict[str, Any]) -> list[str]:
    # No collection here: the worker must release these itself before it builds the reply.
    return sorted(name for name, ref in watched.items() if ref() is not None)


class _Sneaky(MemoryError):
    """A Handler's own MemoryError whose methods would fail if the worker called them."""

    def with_traceback(self, tb: Any) -> Any:
        raise RuntimeError("user code ran")

    def __setattr__(self, name: str, value: Any) -> None:
        raise RuntimeError("user code ran")


def _raise_plain(held: _Held) -> None:
    raise MemoryError


def _raise_chained(held: _Held) -> None:
    try:
        raise ValueError("earlier")  # its traceback holds this frame, and so `held`
    except ValueError:
        raise MemoryError  # noqa: B904 - the implicit __context__ is the point


def _raise_in_a_cycle(held: _Held) -> None:
    try:
        raise ValueError("kept")
    except ValueError as exc:
        kept = exc  # frame -> kept -> traceback -> frame: freed only by a collection
    assert kept
    raise MemoryError


def _raise_sneaky(held: _Held) -> None:
    raise _Sneaky


@pytest.mark.parametrize(
    ("raiser", "text"),
    [
        (_raise_plain, "MemoryError: "),
        (_raise_chained, "MemoryError: "),
        (_raise_in_a_cycle, "MemoryError: "),
        (_raise_sneaky, "_Sneaky: "),
    ],
)
def test_the_memory_reply_is_built_after_the_call_is_released(
    worker: Any, monkeypatch: pytest.MonkeyPatch, raiser: Any, text: str
) -> None:
    alive_at: dict[str, list[str]] = {}
    real_error_text = worker._error_text
    watched_by_call: list[dict[str, Any]] = []

    def respond(watched: dict[str, Any], *_args: Any) -> bytes:
        watched_by_call.append(watched)
        held = _Held()
        watched["handler locals"] = weakref.ref(held)
        raiser(held)
        raise AssertionError("unreachable")

    def error_text(exc: BaseException) -> str:
        alive_at["detail"] = _alive(watched_by_call[0])
        return real_error_text(exc)

    def encode_fail(watched: dict[str, Any], **kw: Any) -> bytes:
        alive_at["reply"] = _alive(watched)
        assert kw["kind"] == codec.FAIL_MEMORY
        assert (kw["request_id"], kw["phase"], kw["name"]) == ("r1", "transform", "h_oom")
        assert kw["error"] == f"{text}; the cap"
        return b"fail"

    writes: list[bytes] = []
    monkeypatch.setattr(worker, "_error_text", error_text)
    code, _ = _drive(
        worker, monkeypatch, respond, lambda _s, body: writes.append(body), encode_fail
    )
    assert code == 1
    assert writes == [b"ready", b"fail"]
    assert alive_at == {"detail": [], "reply": []}


def test_a_reply_write_that_fails_with_oserror_writes_no_second_frame(
    worker: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out = io.BytesIO()

    def write_frame(_stream: Any, body: bytes) -> None:
        if body == b"ready":
            return
        out.write(b"\x00\x00\x00\x08")  # the length prefix went out, the body did not
        raise OSError("broken pipe")

    code, _ = _drive(
        worker,
        monkeypatch,
        lambda _watched, *_a: b"answer",
        write_frame,
        lambda _watched, **_kw: b"fail",
    )
    assert code == 1
    assert out.getvalue() == b"\x00\x00\x00\x08", "a second frame followed the torn one"


def test_an_over_cap_reply_is_still_answered_with_an_error(
    worker: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The case the retry exists for: an over-cap frame is refused before any byte is written."""
    writes: list[bytes] = []

    def write_frame(_stream: Any, body: bytes) -> None:
        if body == b"answer":
            raise codec.SandboxError("sandbox frame too large: 99 bytes")
        writes.append(body)

    code, _ = _drive(
        worker,
        monkeypatch,
        lambda _watched, *_a: b"answer",
        write_frame,
        lambda _watched, **kw: b"fail:" + kw["error"].encode(),
    )
    assert code == 0  # served the request, then read EOF
    assert writes == [b"ready", b"fail:unmarshallable result: sandbox frame too large: 99 bytes"]
