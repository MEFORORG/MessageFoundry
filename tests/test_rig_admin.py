# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CI and load rigs sign in (vault BACKLOG #2719, stage A): ``harness/load/rigadmin.py``.

A rig starts a real ``messagefoundry serve``. It used to start it with sign-in switched off. It now
provisions one Administrator, signs in, and reads the API with that session.

Three layers, cheapest first:

* the helper's own rules, with the engine and the network faked;
* the provisioning child against a real store, which is the shipped ``provision-admin`` with its
  terminal read replaced;
* one real ``serve`` behind :class:`~harness.load.failover.EngineNode`, to show the node refuses a
  request with no session and answers the rig's.

The workflow half is ``tests/test_ci_rig_legs_sign_in.py``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import http.server
import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from harness.load import enginepoll, rigadmin
from harness.load.enginepoll import EnginePoller
from harness.load.failover import EngineNode
from harness.load.rigadmin import RIG_SESSION, RigAdmin
from harness.load.tlsmat import harness_ssl_context
from messagefoundry.apiclient import ApiError
from messagefoundry.auth import totp
from messagefoundry.auth.policy import CONTEXT_WORDS, PasswordPolicy

_ROOT = Path(__file__).resolve().parents[1]


def _env_for_a_sqlite_store(**extra: str) -> dict[str, str]:
    """This process's environment for a child that must use its OWN SQLite store: no store setting
    a server-database leg exports."""
    kept = {
        name: value for name, value in os.environ.items() if not name.startswith("MEFOR_STORE_")
    }
    return {**kept, **extra}


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give every test its own credential, session and spent-step holders, and no rig variable from
    the calling shell, and put the process's back after."""
    monkeypatch.setattr(rigadmin, "_credential", rigadmin._HeldAdmin())
    monkeypatch.setattr(rigadmin, "_held", rigadmin._HeldSession())
    monkeypatch.setattr(rigadmin, "_spent", rigadmin._SpentSteps())
    # Set, then deleted: `rig_admin` publishes a drawn password into the environment itself, and
    # monkeypatch can only undo a variable it has seen.
    for name in (rigadmin.ADMIN_PASS_ENV, rigadmin.ADMIN_NAME_ENV, rigadmin.ADMIN_FACTOR_ENV):
        monkeypatch.setenv(name, "")
        monkeypatch.delenv(name)


# --- the password ------------------------------------------------------------


def test_a_drawn_password_cannot_spell_a_deny_listed_word_or_the_username() -> None:
    """The draw is hexadecimal BECAUSE the shipped policy refuses a password that holds a context
    word or the account's own name, and an unscreened draw would hold one now and then. Checked
    against the engine's own list, so a word added there that hex can spell fails here."""
    hexdigits = set("0123456789abcdef")
    for word in (*CONTEXT_WORDS, rigadmin._DEFAULT_USERNAME):
        assert set(word.lower()) - hexdigits, f"{word!r} can be spelled in hexadecimal"
    policy = PasswordPolicy()
    for _ in range(25):
        drawn = rigadmin._new_password()
        assert set(drawn) <= hexdigits and len(drawn) == 48
        assert policy.violations(drawn, username=rigadmin._DEFAULT_USERNAME) == []
    # CONTROL: the same call refuses a draw that does hold a context word.
    assert policy.violations("0123456789abcdef-hl7-0123456789abcdef", username="rig-operator")


def test_the_credential_comes_from_the_environment_when_it_is_there(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(rigadmin.ADMIN_NAME_ENV, "bench-operator")
    monkeypatch.setenv(rigadmin.ADMIN_PASS_ENV, "f" * 48)
    assert rigadmin.rig_admin() == RigAdmin("bench-operator", "f" * 48)


def test_a_drawn_credential_is_published_for_a_child_process_and_drawn_once() -> None:
    first = rigadmin.rig_admin()
    assert first.username == rigadmin._DEFAULT_USERNAME
    # A child harness process (connscale-remote under batchbox) must sign in as the same account.
    assert os.environ[rigadmin.ADMIN_PASS_ENV] == first.password
    assert rigadmin.rig_admin() is first


def test_the_password_is_not_in_the_repr() -> None:
    admin = RigAdmin("rig-operator", "a1" * 24)
    assert "a1a1" not in repr(admin) and "rig-operator" in repr(admin)


# --- the second factor (vault BACKLOG #2796) ---------------------------------


def test_the_authenticator_key_comes_only_from_the_environment_and_stays_out_of_the_repr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A leg opts in to MFA by supplying the key. The rig never draws one."""
    assert rigadmin.rig_admin().totp_secret is None
    assert rigadmin.ADMIN_FACTOR_ENV not in os.environ, "a key was drawn and published"
    monkeypatch.setattr(rigadmin, "_credential", rigadmin._HeldAdmin())
    key = totp.generate_secret()
    monkeypatch.setenv(rigadmin.ADMIN_FACTOR_ENV, key)
    admin = rigadmin.rig_admin()
    assert admin.totp_secret == key
    assert key not in repr(admin)


def test_the_rig_computes_the_engines_totp_codes() -> None:
    key = totp.generate_secret()
    for at in (0.0, 29.999, 30.0, 1_700_000_000.5, time.time()):
        code = rigadmin._totp_code(key, at)
        assert totp.verify_totp_step(key, code, now=at, window=0) == int(at // 30), at
    # Read as the engine reads a key: case, spaces and stripped padding do not matter.
    key = totp.generate_secret()
    spaced = " ".join(key[i : i + 4] for i in range(0, len(key), 4)).lower()
    assert rigadmin._totp_code(spaced, 1e9) == totp.totp(key, now=1e9)


@pytest.mark.parametrize("key", ["", "not base32!", "1" * 32, "A" * 25, "AA"])
def test_a_key_that_is_not_base32_or_too_short_is_refused_by_name_and_never_by_value(
    key: str,
) -> None:
    """A short key would become an enabled Administrator's factor, and the store does not check
    its length, so the rig refuses one under 128 bits."""
    with pytest.raises(rigadmin.RigAdminError, match=rigadmin.ADMIN_FACTOR_ENV) as refused:
        rigadmin._totp_code(key, 0.0)
    assert not key or key not in str(refused.value)
    # CONTROL: the shortest key the rig takes, and the engine's own draw, both give a code.
    assert rigadmin._totp_code("A" * rigadmin._MIN_KEY_CHARS, 0.0).isdigit()
    assert rigadmin._totp_code(totp.generate_secret(), 0.0).isdigit()


def test_sign_in_refuses_an_unusable_key_before_any_wait(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refused as a sign-in refusal, which callers already handle, and before the step wait."""
    monkeypatch.setattr(
        rigadmin, "_code_in_a_fresh_step", lambda key: pytest.fail("it waited for a step")
    )
    calls = _answers(monkeypatch)
    with pytest.raises(rigadmin.RigSignInRefused, match=rigadmin.ADMIN_FACTOR_ENV):
        rigadmin.sign_in("https://127.0.0.1:1", RigAdmin("rig-operator", "ab" * 24, "AA"))
    assert calls == [], "the credential was sent"


class _FakeClock:
    """``rigadmin._now`` and ``rigadmin._pause``: the clock moves only when the rig waits."""

    def __init__(self, start: float) -> None:
        self.at = start
        self.pauses: list[float] = []

    def now(self) -> float:
        return self.at

    def pause(self, seconds: float) -> None:
        self.pauses.append(seconds)
        self.at += seconds


def _clocked(monkeypatch: pytest.MonkeyPatch, start: float) -> _FakeClock:
    clock = _FakeClock(start)
    monkeypatch.setattr(rigadmin, "_now", clock.now)
    monkeypatch.setattr(rigadmin, "_pause", clock.pause)
    monkeypatch.setattr(rigadmin, "_spent", rigadmin._SpentSteps())
    return clock


@pytest.mark.parametrize("start", [3_000.0, 3_000.001, 3_014.5, 3_029.999])
def test_a_sign_in_code_comes_from_the_next_step_a_margin_into_it(
    monkeypatch: pytest.MonkeyPatch, start: float
) -> None:
    """THE REPLAY TRAP. A step that began before the call may already be spent elsewhere, by a
    provisioning child or a sign-in in an earlier process, and the engine counts a reused code as a
    wrong second factor, which feeds the account's lock. So a sign-in takes the NEXT step, even when
    the call lands on a step's first instant, and sends its code a margin into it."""
    clock = _clocked(monkeypatch, start)
    key = totp.generate_secret()
    code, step = rigadmin._code_in_a_fresh_step(key)
    assert step == int(start // 30) + 1, "the code is not from the next step"
    assert step * 30 + rigadmin._STEP_MARGIN_S <= clock.at <= step * 30 + 1.1
    assert code == totp.totp(key, now=clock.at)
    assert rigadmin._spent.claimed == step
    assert rigadmin._spent.last == -1, "a step was recorded as spent before any request"


def test_a_code_is_never_sent_with_less_than_the_margin_left_in_its_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE DEFECT THIS RULE REPLACED. With step 99 spent and the call at 3029.995, the earlier rule
    took step 100 at once, since it was past step 99 and past the opening margin, and sent a code
    with 5 ms left. The engine judges at ``totp_skew_steps = 0`` on its own clock, so that code
    lands in the next step and counts as a wrong second factor."""
    clock = _clocked(monkeypatch, 3_029.995)
    rigadmin._note_spent_step(99)
    code, step = rigadmin._code_in_a_fresh_step(totp.generate_secret())
    assert step == 101
    assert (step + 1) * 30 - clock.at >= rigadmin._STEP_MARGIN_S, "sent too near the step's end"
    assert clock.at >= step * 30 + rigadmin._STEP_MARGIN_S


def test_a_wait_that_overruns_into_the_closing_margin_takes_the_next_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A suspended process can wake late. The code still goes with the margin left on both sides."""
    clock = _clocked(monkeypatch, 3_010.0)
    late = [30.0]  # the first wait ends 30 s late, at 3061, past step 101's closing margin

    def pause(seconds: float) -> None:
        clock.pause(seconds + (late.pop() if late else 0.0))

    monkeypatch.setattr(rigadmin, "_pause", pause)
    _code, step = rigadmin._code_in_a_fresh_step(totp.generate_secret())
    assert step == 103 and clock.at == 103 * 30 + rigadmin._STEP_MARGIN_S
    assert rigadmin._spent.claimed == 103


def test_sign_ins_in_one_process_take_distinct_steps_in_call_order_and_wait_holding_no_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Each call claims a later step than the one before, before it waits. The wait holds no lock,
    so a step recorded while one sign-in waits is never blocked behind it."""
    clock = _clocked(monkeypatch, 3_010.0)
    assert [rigadmin._claim_next_step(), rigadmin._claim_next_step()] == [101, 102]

    clock = _clocked(monkeypatch, 3_010.0)
    free: list[bool] = []

    def pause(seconds: float) -> None:
        taken = rigadmin._spent.lock.acquire(blocking=False)
        if taken:
            rigadmin._spent.lock.release()
        free.append(taken)
        clock.pause(seconds)

    monkeypatch.setattr(rigadmin, "_pause", pause)
    key = totp.generate_secret()
    _code, first = rigadmin._code_in_a_fresh_step(key)
    _code, second = rigadmin._code_in_a_fresh_step(key)
    assert (first, second) == (101, 102), "two sign-ins shared a step"
    assert free and all(free), "a wait held the lock"


def test_the_last_spent_step_bounds_the_claim_when_the_clock_reads_earlier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wall clock stepped back must not hand out a step this process already spent."""
    _clocked(monkeypatch, 3_010.0)
    rigadmin._note_spent_step(105)
    assert rigadmin._claim_next_step() == 106


def test_provision_with_a_key_records_the_step_its_child_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _clocked(monkeypatch, 200 * 30 + 3.0)
    _fake_child(monkeypatch, 0)
    rigadmin.provision(env={}, admin=RigAdmin("rig-operator", "0f" * 24))
    assert rigadmin._spent.last == -1, "an account with no key spent a step"
    rigadmin.provision(env={}, admin=RigAdmin("rig-operator", "0f" * 24, totp.generate_secret()))
    assert rigadmin._spent.last == int(clock.at // 30)


def test_sign_in_with_a_key_sends_both_factors_in_one_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The combined sign-in of ADR 0197: one POST carrying the password and a fresh code."""
    calls = _answers(monkeypatch, (200, {"token": "session-1"}))
    asked: list[str] = []

    def fresh(key: str) -> tuple[str, int]:
        asked.append(key)
        return "123456", 77

    monkeypatch.setattr(rigadmin, "_code_in_a_fresh_step", fresh)
    key = totp.generate_secret()
    admin = RigAdmin("rig-operator", "ab" * 24, key)
    assert rigadmin.sign_in("https://127.0.0.1:1", admin) == "session-1"
    assert asked == [key]
    assert calls[0]["body"] == {
        "username": "rig-operator",
        "password": "ab" * 24,
        "totp_code": "123456",
    }
    assert rigadmin._spent.last == 77


def test_a_sign_in_spends_its_step_only_when_the_engine_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request that never reached the engine spent nothing there. A refusal is an answer."""
    monkeypatch.setattr(rigadmin, "_code_in_a_fresh_step", lambda key: ("123456", 77))
    admin = RigAdmin("rig-operator", "ab" * 24, totp.generate_secret())

    def unreachable(*_a: object, **_k: object) -> tuple[int, bytes]:
        raise rigadmin.RigUnreachable("the engine did not answer (ConnectionRefusedError)")

    monkeypatch.setattr(rigadmin, "_call", unreachable)
    with pytest.raises(rigadmin.RigUnreachable):
        rigadmin.sign_in("https://127.0.0.1:1", admin)
    assert rigadmin._spent.last == -1, "a step was spent by a request that got no answer"

    _answers(monkeypatch, (401, {"detail": "invalid credentials"}))
    with pytest.raises(rigadmin.RigSignInRefused):
        rigadmin.sign_in("https://127.0.0.1:1", admin)
    assert rigadmin._spent.last == 77


# --- the hop -----------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://engine.example.org:8765", "https://127.0.0.1:8765/", "http://127.0.0.1:8765"],
)
def test_a_credential_may_cross_https_or_loopback(url: str) -> None:
    assert rigadmin._checked_base(url) == url.rstrip("/")


@pytest.mark.parametrize("url", ["http://engine.example.org:8765", "http://10.0.0.5:8765", "x"])
def test_a_credential_is_refused_cleartext_to_another_host(url: str) -> None:
    with pytest.raises(rigadmin.RigAdminError, match="cleartext"):
        rigadmin._checked_base(url)


def _answers(monkeypatch: pytest.MonkeyPatch, *replies: tuple[int, object]) -> list[dict[str, Any]]:
    """Script ``rigadmin._call``: each call takes the next reply, and is recorded."""
    calls: list[dict[str, Any]] = []
    queue = list(replies)

    def fake(method: str, url: str, **kw: Any) -> tuple[int, bytes]:
        calls.append({"method": method, "url": url, **kw})
        status, body = queue.pop(0)
        return status, json.dumps(body).encode("utf-8")

    monkeypatch.setattr(rigadmin, "_call", fake)
    return calls


def test_sign_in_posts_the_credential_and_returns_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _answers(monkeypatch, (200, {"token": "session-1"}))
    admin = RigAdmin("rig-operator", "ab" * 24)
    assert rigadmin.sign_in("https://127.0.0.1:1/", admin, cacert="pin.pem") == "session-1"
    assert calls == [
        {
            "method": "POST",
            "url": "https://127.0.0.1:1/auth/login",
            "cacert": "pin.pem",
            "body": {"username": "rig-operator", "password": "ab" * 24},
        }
    ]


@pytest.mark.parametrize(
    ("status", "body"),
    [
        (401, {"detail": "invalid credentials"}),
        (503, {"detail": "authentication is not configured"}),
        (200, {"token": "t", "mfa_required": True}),
        (200, {"token": "t", "must_change_password": True}),
        (200, {"token": ""}),
        (200, ["not", "an", "object"]),
    ],
)
def test_an_answer_that_is_not_a_usable_session_is_a_refusal_and_never_carries_the_password(
    monkeypatch: pytest.MonkeyPatch, status: int, body: object
) -> None:
    _answers(monkeypatch, (status, body))
    admin = RigAdmin("rig-operator", "cd" * 24)
    with pytest.raises(rigadmin.RigSignInRefused) as refused:
        rigadmin.sign_in("https://127.0.0.1:1", admin)
    assert admin.password not in str(refused.value)


def test_an_engine_that_does_not_answer_is_unreachable_and_not_a_refusal() -> None:
    """A real socket with nothing behind it: the hop itself, with no fake. A caller that treats
    "unreachable" as "still starting" must not be handed a refusal, and the reverse."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(rigadmin.RigUnreachable) as unreachable:
        rigadmin.sign_in(f"http://127.0.0.1:{port}", RigAdmin("rig-operator", "ef" * 24))
    assert not isinstance(unreachable.value, rigadmin.RigSignInRefused)
    assert str(port) not in str(unreachable.value), "the address must stay out of the message"


@contextlib.contextmanager
def _engine_answering(status: int, size: int, *, states_length: bool = True) -> Iterator[str]:
    """A loopback HTTP server that answers every request with ``status`` and ``size`` bytes.

    With ``states_length`` false the answer has no ``Content-Length`` and ends when the server
    closes, so the client can only count what arrives."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self) -> None:
            # Read the request body first (BACKLOG #3394). A socket closed with received bytes
            # still unread sends a reset instead of a normal close, and Windows then throws away
            # the answer the client has not read: the sign-in POST read as ConnectionAbortedError.
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(status)
            if states_length:
                self.send_header("Content-Length", str(size))
            self.end_headers()
            self.wfile.write(b"x" * size)

        do_GET = do_POST = _answer

        def log_message(self, *args: object) -> None:  # keep the test output quiet
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("states_length", [True, False], ids=["stated", "unstated"])
@pytest.mark.parametrize("status", [200, 401])
def test_an_answer_past_the_reply_cap_is_refused_and_one_at_it_is_read_whole(
    monkeypatch: pytest.MonkeyPatch, status: int, states_length: bool
) -> None:
    """ASVS 5.1.1 (BACKLOG #1127): the rig reads each engine answer under ``MAX_API_REPLY_BYTES``,
    on the success path and the HTTP-error path alike, and never cuts one short, whether or not
    the answer states its length."""
    monkeypatch.setattr(rigadmin, "MAX_API_REPLY_BYTES", 100_000)
    with _engine_answering(status, 100_000, states_length=states_length) as base:
        assert rigadmin._call("GET", f"{base}/stats", cacert=None) == (status, b"x" * 100_000)
    with (
        _engine_answering(status, 100_001, states_length=states_length) as base,
        pytest.raises(rigadmin.RigReplyRefused),
    ):
        rigadmin._call("GET", f"{base}/stats", cacert=None)


@pytest.mark.parametrize("status", [200, 401])
def test_a_stated_length_past_the_cap_is_refused_before_any_of_the_answer_is_read(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    """An engine that states an over-cap length and then sends nothing is refused for size at once,
    on the success path and the HTTP-error path. Counting alone would wait out the read timeout
    and report an engine that did not answer, not the limit."""
    monkeypatch.setattr(rigadmin, "MAX_API_REPLY_BYTES", 1_000)
    monkeypatch.setattr(rigadmin, "_HTTP_TIMEOUT_S", 2.0)
    with socket.create_server(("127.0.0.1", 0)) as server:
        server.settimeout(10.0)
        done = threading.Event()

        def headers_only() -> None:
            conn, _ = server.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(f"HTTP/1.1 {status} X\r\nContent-Length: 5000\r\n\r\n".encode())
                done.wait(10.0)

        peer = threading.Thread(target=headers_only, daemon=True)
        peer.start()
        base = f"http://127.0.0.1:{server.getsockname()[1]}"
        try:
            with pytest.raises(rigadmin.RigReplyRefused, match="states a length"):
                rigadmin._call("GET", f"{base}/stats", cacert=None)
        finally:
            done.set()
            peer.join(10.0)


@pytest.mark.parametrize("states_length", [True, False], ids=["stated", "unstated"])
def test_a_sign_in_answer_past_the_reply_cap_reads_as_no_answer(
    monkeypatch: pytest.MonkeyPatch, states_length: bool
) -> None:
    """A node polled for its status treats an over-cap answer as no answer and asks again; its
    sign-in must read the same way, not as a refused credential that ends the run."""
    monkeypatch.setattr(rigadmin, "MAX_API_REPLY_BYTES", 1_000)
    with (
        _engine_answering(200, 5_000, states_length=states_length) as base,
        pytest.raises(rigadmin.RigUnreachable, match="limit") as caught,
    ):
        rigadmin.sign_in(base, RigAdmin("rig-operator", "ab" * 24))
    assert isinstance(caught.value, rigadmin.RigReplyRefused)


@pytest.mark.parametrize("status", [200, 401])
def test_an_answer_that_ends_before_its_stated_length_is_no_answer(status: int) -> None:
    """A sized read returns what it got where a whole read raised ``IncompleteRead``, so a cut-off
    answer must still be refused rather than parsed as whole."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        server.settimeout(10.0)

        def short_answer() -> None:
            conn, _ = server.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(
                    f"HTTP/1.1 {status} X\r\nContent-Length: 5000\r\n\r\n".encode() + b"x" * 1200
                )

        peer = threading.Thread(target=short_answer, daemon=True)
        peer.start()
        base = f"http://127.0.0.1:{server.getsockname()[1]}"
        with pytest.raises(rigadmin.RigUnreachable, match="stated length"):
            rigadmin._call("GET", f"{base}/stats", cacert=None)
        peer.join(10.0)


#: ``struct linger``: two ``u_short`` in Winsock, two ``int`` elsewhere.
_LINGER = "HH" if sys.platform == "win32" else "ii"


@contextlib.contextmanager
def _peer_that_breaks_off(status: int, *, reset: bool) -> Iterator[str]:
    """A loopback peer that sends ``status``, a ``Content-Length`` of 5000 and 100 bytes of it.

    It then stalls until the test ends, or with ``reset`` it ends the connection with a reset. Either
    way the client is mid-body, where a read raises rather than returns."""
    with socket.create_server(("127.0.0.1", 0)) as server:
        server.settimeout(10.0)
        done = threading.Event()

        def break_off() -> None:
            conn, _ = server.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(
                    f"HTTP/1.1 {status} X\r\nContent-Length: 5000\r\n\r\n".encode() + b"x" * 100
                )
                if reset:
                    time.sleep(0.2)  # the client is now blocked reading the rest of the body
                    # Linger on, with a zero timeout: close() sends a reset, not a normal close.
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack(_LINGER, 1, 0))
                else:
                    done.wait(10.0)

        peer = threading.Thread(target=break_off, daemon=True)
        peer.start()
        try:
            yield f"http://127.0.0.1:{server.getsockname()[1]}"
        finally:
            done.set()
            peer.join(10.0)


@pytest.mark.parametrize("reset", [False, True], ids=["stalls", "resets"])
@pytest.mark.parametrize("status", [401, 503, 200])
def test_an_answer_that_stalls_or_resets_mid_body_is_no_answer_on_a_refusal_too(
    monkeypatch: pytest.MonkeyPatch, status: int, reset: bool
) -> None:
    """BACKLOG #1127: a refusal's body used to be read outside the guard, so a 401 that stalled
    mid-body raised a raw ``TimeoutError``, and a caller that asks again on ``RigUnreachable``
    crashed. A refusal that breaks off now reads as no answer, in the words a success uses."""
    monkeypatch.setattr(rigadmin, "_HTTP_TIMEOUT_S", 1.0)
    with (
        _peer_that_breaks_off(status, reset=reset) as base,
        pytest.raises(rigadmin.RigUnreachable) as caught,
    ):
        rigadmin._call("GET", f"{base}/stats", cacert=None)
    assert not isinstance(caught.value, rigadmin.RigReplyRefused)
    # The exact reason, so a reset that arrived as a normal close (and read as a short answer)
    # cannot pass for the refusal path this test is about.
    reason = "ConnectionResetError" if reset else "TimeoutError"
    assert str(caught.value) == f"the engine did not answer ({reason})"


class _CountingServer:
    """A loopback HTTP server that records each request's path and ``Authorization`` header."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.seen: list[tuple[str, str | None]] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self) -> None:
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.seen.append((self.path, self.headers.get("Authorization")))
                self.send_response(status)
                for name, value in {**headers, "Content-Length": str(len(body))}.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _answer

            def log_message(self, *args: object) -> None:  # keep the test output quiet
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> _CountingServer:
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_a_redirect_is_never_followed_and_the_bearer_never_leaves(code: int) -> None:
    """BACKLOG #1127: urllib follows a 3xx by default, reading its body with no limit and carrying
    the ``Authorization`` header to the new host. That gets around the reply cap and the loopback
    rule. The rig follows none, and names the status but never where it pointed."""
    with (
        _CountingServer(200, {}, b'{"ok": true}') as elsewhere,
        _CountingServer(code, {"Location": f"{elsewhere.base}/stolen"}, b"x" * 64) as engine,
    ):
        with pytest.raises(rigadmin.RigUnreachable, match=f"redirect \\(HTTP {code}\\)") as caught:
            rigadmin._call("GET", f"{engine.base}/stats", cacert=None, bearer="held-session")
        assert engine.seen == [("/stats", "Bearer held-session")]
        assert elsewhere.seen == [], "the redirect was followed"
        assert elsewhere.base.rsplit(":", 1)[1] not in str(caught.value)
        assert "stolen" not in str(caught.value)

        # CONTROL: the hit count is a working instrument. A normal 200 at the other server is read
        # and counted, and urllib's stock redirect handler, given the same redirect, follows it
        # with the bearer. No proxy, so a machine's own proxy setting cannot move the request.
        assert rigadmin._call("GET", f"{elsewhere.base}/ok", cacert=None) == (200, b'{"ok": true}')
        assert elsewhere.seen == [("/ok", None)]
        stock = urllib.request.Request(
            f"{engine.base}/stats", headers={"Authorization": "Bearer held-session"}
        )
        no_proxy = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with no_proxy.open(stock, timeout=10.0) as followed:
            followed.read()
        assert elsewhere.seen[-1] == ("/stolen", "Bearer held-session")


def test_a_loopback_engine_is_dialled_direct_when_a_proxy_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1127: with ``HTTP_PROXY`` set and no ``NO_PROXY``, urllib sends a request for
    ``http://127.0.0.1`` to the proxy, which would read the sign-in password and the bearer in
    clear. The rig dials a loopback engine direct, as the engine's own openers do."""
    for name in ("no_proxy", "NO_PROXY", "http_proxy", "HTTP_PROXY"):
        monkeypatch.delenv(name, raising=False)
    with (
        _CountingServer(200, {}, b"proxied") as proxy,
        _CountingServer(200, {}, b"direct") as engine,
    ):
        monkeypatch.setenv("http_proxy", proxy.base)
        status, raw = rigadmin._call("GET", f"{engine.base}/stats", cacert=None, bearer="held")
        assert (status, raw) == (200, b"direct")
        assert engine.seen == [("/stats", "Bearer held")]
        assert proxy.seen == [], "the loopback request went through the proxy"

        # CONTROL: stock urllib, under the same environment, hands the request to the proxy.
        stock = urllib.request.Request(
            f"{engine.base}/stats", headers={"Authorization": "Bearer held"}
        )
        with urllib.request.build_opener().open(stock, timeout=10.0) as proxied:
            assert proxied.read() == b"proxied"
        assert proxy.seen == [(f"{engine.base}/stats", "Bearer held")]


# --- the one session per process ---------------------------------------------


def test_one_sign_in_serves_every_node_until_one_refuses_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed_in_at: list[str] = []

    def fake_sign_in(base_url: str, admin: object = None, *, cacert: str | None = None) -> str:
        signed_in_at.append(base_url)
        return f"session-{len(signed_in_at)}"

    monkeypatch.setattr(rigadmin, "sign_in", fake_sign_in)
    # Two nodes of one store: ONE sign-in, so the engine's per-user session cap sees one session.
    assert rigadmin.session_token("https://a") == "session-1"
    assert rigadmin.session_token("https://b") == "session-1"
    assert signed_in_at == ["https://a"]
    # Node b is on another store and refused it: sign in there.
    assert rigadmin.renew_session("https://b", "session-1") == "session-2"
    # A second thread that was refused the SAME stale session gets the replacement, no third sign-in.
    assert rigadmin.renew_session("https://b", "session-1") == "session-2"
    assert signed_in_at == ["https://a", "https://b"]
    # None forces one: a route that wants a credential proved just now.
    assert rigadmin.renew_session("https://b", None) == "session-3"
    assert rigadmin.session_token("https://a") == "session-3"


# --- provisioning: the caller's side -----------------------------------------


def _fake_child(monkeypatch: pytest.MonkeyPatch, returncode: int, text: str = "") -> dict[str, Any]:
    seen: dict[str, Any] = {}

    def fake_run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        seen.update(argv=argv, **kw)
        return subprocess.CompletedProcess(argv, returncode, stdout=text, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return seen


def test_provision_hands_the_password_to_the_child_in_its_environment_and_never_on_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen = _fake_child(monkeypatch, 0)
    admin = RigAdmin("rig-operator", "0f" * 24)
    env = {"MEFOR_STORE_PATH": "rig.db", "PATH": "/x"}
    assert rigadmin.provision(env=env, cwd=tmp_path, db="other.db", admin=admin) is True
    assert admin.password not in " ".join(seen["argv"])
    assert seen["env"] == {
        **env,
        rigadmin.ADMIN_NAME_ENV: "rig-operator",
        rigadmin.ADMIN_PASS_ENV: admin.password,
        "PYTHONIOENCODING": "utf-8",
    }
    # The child's output is pinned to UTF-8 on both ends, so a non-ASCII refusal cannot fail to decode.
    assert (seen["encoding"], seen["errors"]) == ("utf-8", "replace")
    assert seen["cwd"] == str(tmp_path)
    # -P keeps harness/load, which holds a module named `profile`, off the child's sys.path.
    assert seen["argv"][:2] == [sys.executable, "-P"]
    assert Path(seen["argv"][2]) == Path(rigadmin.__file__).resolve()
    assert seen["argv"][3:] == ["provision", "--db", "other.db"]
    assert env == {"MEFOR_STORE_PATH": "rig.db", "PATH": "/x"}, "the caller's env was changed"


def test_provision_hands_the_key_to_the_child_only_from_the_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The key goes in the child's environment, never on argv, and only when the account holds one:
    a stray key in the caller's environment must not enrol an account that has none."""
    key = totp.generate_secret()
    stray = {"PATH": "/x", rigadmin.ADMIN_FACTOR_ENV: totp.generate_secret()}
    seen = _fake_child(monkeypatch, 0)
    rigadmin.provision(env=stray, admin=RigAdmin("rig-operator", "0f" * 24, key))
    assert seen["env"][rigadmin.ADMIN_FACTOR_ENV] == key
    assert key not in " ".join(seen["argv"])
    seen = _fake_child(monkeypatch, 0)
    rigadmin.provision(env=stray, admin=RigAdmin("rig-operator", "0f" * 24))
    assert rigadmin.ADMIN_FACTOR_ENV not in seen["env"]


def test_run_hands_its_child_neither_the_password_nor_the_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(rigadmin, "_require_sign_in", lambda *_a, **_k: None)
    monkeypatch.setattr(rigadmin, "sign_in", lambda *_a, **_k: "a-session")
    monkeypatch.setenv(rigadmin.ADMIN_PASS_ENV, "ab" * 24)
    monkeypatch.setenv(rigadmin.ADMIN_FACTOR_ENV, totp.generate_secret())
    child = (
        "import os, sys; "
        f"sys.exit(9 if {rigadmin.ADMIN_PASS_ENV!r} in os.environ else "
        f"8 if {rigadmin.ADMIN_FACTOR_ENV!r} in os.environ else 0)"
    )
    code = rigadmin.main(
        ["run", "--engine", "https://127.0.0.1:1", "--", sys.executable, "-c", child]
    )
    assert code == 0, code


def test_a_store_that_already_had_an_administrator_is_not_a_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_child(monkeypatch, rigadmin.EXIT_EXISTS)
    assert rigadmin.provision(env={}, admin=RigAdmin("rig-operator", "1e" * 24)) is False


def test_any_other_refusal_raises_with_the_commands_own_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_child(monkeypatch, 2, "no store key is set in this shell; refusing to provision")
    with pytest.raises(rigadmin.RigAdminError, match=r"exit 2.*no store key is set"):
        rigadmin.provision(env={}, admin=RigAdmin("rig-operator", "2d" * 24))


def test_the_json_error_reader_takes_the_last_error_object() -> None:
    assert rigadmin._json_error('noise\n{"error": "first"}\n{"error": "last"}\n') == "last"
    assert rigadmin._json_error('{"username": "rig-operator"}\n') == ""
    assert rigadmin._json_error("not json") == ""


# --- provisioning: the real command, in a child -------------------------------


def _store_key() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


@pytest.mark.timeout(240)
def test_the_child_provisions_through_the_shipped_command_and_then_finds_it_done(
    tmp_path: Path,
) -> None:
    """The real ``provision-admin``, at the shipped ``enforce`` posture, against a SQLite store in
    ``tmp_path``. Only its terminal read is replaced. Two runs: the first creates the account, the
    second finds it. Neither prints the password."""
    admin = RigAdmin("rig-operator", rigadmin._new_password())
    env = _env_for_a_sqlite_store(
        MEFOR_STORE_ENCRYPTION_KEY=_store_key(),
        **{rigadmin.ADMIN_NAME_ENV: admin.username, rigadmin.ADMIN_PASS_ENV: admin.password},
    )
    db = tmp_path / "rig.db"
    argv = [sys.executable, "-P", str(Path(rigadmin.__file__).resolve()), "provision"]
    argv += ["--db", str(db)]
    first = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)
    assert first.returncode == 0, first.stdout + first.stderr
    assert db.exists(), "the store was not created"
    second = subprocess.run(argv, env=env, cwd=tmp_path, capture_output=True, text=True)
    assert second.returncode == rigadmin.EXIT_EXISTS, second.stdout + second.stderr
    for done in (first, second):
        assert admin.password not in done.stdout + done.stderr

    # CONTROL: with no password in its environment the child refuses, and creates no store.
    bare = {k: v for k, v in env.items() if k != rigadmin.ADMIN_PASS_ENV}
    other = tmp_path / "never.db"
    refused = subprocess.run(
        [*argv[:-1], str(other)], env=bare, cwd=tmp_path, capture_output=True, text=True
    )
    assert refused.returncode == 2 and rigadmin.ADMIN_PASS_ENV in refused.stderr
    assert not other.exists()


# --- the poller's client -----------------------------------------------------


class _FakeClient:
    """The slice of ``EngineClient`` that ``adopt_rig_session`` uses."""

    def __init__(self, accepts: set[str]) -> None:
        self.accepts = accepts
        self.token: str | None = None
        self.step_up: Any = None
        self.reauths: list[str] = []
        self.refuse_reauth = False

    def set_token(self, token: str) -> None:
        if token not in self.accepts:
            raise ApiError("session refused", status=401)
        self.token = token

    def set_step_up_handler(self, handler: Any) -> None:
        self.step_up = handler

    def reauth(self, password: str, *, purpose: str | None = None) -> None:
        """Re-prove: refused when told to, else the engine re-keys the session, as it does."""
        self.reauths.append(password)
        if self.refuse_reauth:
            raise ApiError("re-verification failed", status=403)
        self.token = f"{self.token}-rekeyed"


def test_a_client_refused_the_held_session_signs_in_again_at_its_own_node(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    renewed: list[tuple[str, str | None]] = []
    monkeypatch.setattr(rigadmin, "session_token", lambda url, cacert=None: "held")

    def renew(url: str, stale: str | None, cacert: str | None = None) -> str:
        renewed.append((url, stale))
        return "fresh"

    monkeypatch.setattr(rigadmin, "renew_session", renew)
    client = _FakeClient(accepts={"fresh"})
    enginepoll.adopt_rig_session(client, "https://b", None)  # type: ignore[arg-type]
    assert client.token == "fresh" and renewed == [("https://b", "held")]


def test_the_step_up_handler_re_proves_on_a_session_of_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault BACKLOG #2625: the reload takes a proof bound to its action, which no sign-in mints.
    So the handler signs in to a PRIVATE session (never the held one, which every other client
    holds) and re-proves there; the client's reauth carries the stashed action. A refused re-proof
    reports failure, so the client surfaces the original refusal.

    The credential is stubbed rather than drawn: `rig_admin` publishes a drawn password into the
    process environment, and this test must leave none behind."""
    monkeypatch.setattr(rigadmin, "session_token", lambda url, cacert=None: "fresh")
    signed_in: list[str] = []

    def sign_in(url: str, admin: object = None, *, cacert: str | None = None) -> str:
        signed_in.append(url)
        return "private"

    monkeypatch.setattr(rigadmin, "sign_in", sign_in)
    monkeypatch.setattr(rigadmin, "rig_admin", lambda: rigadmin.RigAdmin("rigadmin", "held-pw"))
    monkeypatch.setattr(
        rigadmin, "renew_session", lambda *a, **k: pytest.fail("the held session was replaced")
    )
    monkeypatch.setattr(enginepoll, "_STEP_UP_RETRY_GAP_SECONDS", 0.0)
    client = _FakeClient(accepts={"fresh", "private"})
    enginepoll.adopt_rig_session(client, "https://b", None)  # type: ignore[arg-type]
    assert client.step_up() is True
    assert signed_in == ["https://b"] and client.reauths == ["held-pw"]
    assert client.token == "private-rekeyed"
    client.refuse_reauth = True
    assert client.step_up() is False


def test_a_token_poller_gets_no_reload_client() -> None:
    """A ``--token`` poller drives an engine the rig did not start, so it holds no password to
    re-prove with (vault BACKLOG #3241 declines that limb). It is told so, with no request made."""
    poller = EnginePoller("https://127.0.0.1:1", "a-token", origin=0.0)
    poller._clients = [object()]  # type: ignore[list-item]
    assert not poller.holds_rig_session
    assert asyncio.run(poller.reload_client()) is None
    # CONTROL: a rig poller does hold the session that lets it re-prove.
    assert EnginePoller("https://127.0.0.1:1", RIG_SESSION, origin=0.0).holds_rig_session


def test_an_unreachable_engine_reads_as_an_api_error_and_a_refusal_does_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreachable(url: str, cacert: str | None = None) -> str:
        raise rigadmin.RigUnreachable("the engine did not answer (ConnectionRefusedError)")

    monkeypatch.setattr(rigadmin, "session_token", unreachable)
    with pytest.raises(ApiError):
        enginepoll.adopt_rig_session(_FakeClient(set()), "https://a", None)  # type: ignore[arg-type]

    def refused(url: str, cacert: str | None = None) -> str:
        raise rigadmin.RigSignInRefused("the engine refused the rig Administrator's sign-in")

    monkeypatch.setattr(rigadmin, "session_token", refused)
    with pytest.raises(rigadmin.RigSignInRefused):
        enginepoll.adopt_rig_session(_FakeClient(set()), "https://a", None)  # type: ignore[arg-type]


def test_a_drive_of_another_processs_engines_refuses_to_draw_its_own_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A split drive signs in to engines another process provisioned. A password drawn in the drive
    could only be wrong, and each wrong try counts against the account. So it refuses first."""
    poller = EnginePoller("https://127.0.0.1:1", rigadmin.REMOTE_RIG_SESSION, origin=0.0)
    with pytest.raises(rigadmin.RigAdminError, match="another process started"):
        poller._open_sync()
    assert rigadmin.ADMIN_PASS_ENV not in os.environ, "it drew a credential anyway"
    # CONTROL: with the credential supplied the same check passes.
    monkeypatch.setenv(rigadmin.ADMIN_PASS_ENV, "ab" * 24)
    rigadmin.require_supplied_credential()
    assert rigadmin.RIG_SESSION.supplied is False and rigadmin.REMOTE_RIG_SESSION.supplied is True


# --- the command line's own failures -----------------------------------------


def test_a_rig_that_cannot_sign_in_exits_with_its_own_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``run`` returns its child's code, and the harness command line uses 0 to 3. So "the rig never
    signed in" has a code of its own, and a workflow can fail on that and nothing else."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    engine = f"http://127.0.0.1:{port}"
    assert rigadmin.EXIT_RIG_FAILED == 4
    assert rigadmin.main(["get", "--engine", engine, "/stats"]) == rigadmin.EXIT_RIG_FAILED
    code = rigadmin.main(["run", "--engine", engine, "--", sys.executable, "-c", "pass"])
    assert code == rigadmin.EXIT_RIG_FAILED
    assert "did not answer" in capsys.readouterr().err


@pytest.mark.parametrize("session", ["-abc123", "--abc123", "plain-session"])
def test_run_hands_a_session_that_starts_with_a_dash_to_the_childs_argparse_intact(
    monkeypatch: pytest.MonkeyPatch, session: str
) -> None:
    """A session is ``token_urlsafe``, whose alphabet holds ``-``, so about one in 64 starts with it.
    Passed as ``--token`` then the value, argparse in the child reads such a value as an option and
    exits 2 with "expected one argument": the merge-queue flake on engine PR 1981. The child here is a
    real interpreter whose argparse declares ``--token`` the way ``harness/__main__.py`` does."""
    monkeypatch.setattr(rigadmin, "_require_sign_in", lambda *_a, **_k: None)
    monkeypatch.setattr(rigadmin, "sign_in", lambda *_a, **_k: session)
    child = (
        "import argparse, sys; p = argparse.ArgumentParser(); p.add_argument('--token'); "
        f"sys.exit(0 if p.parse_args().token == {session!r} else 7)"
    )
    code = rigadmin.main(
        ["run", "--engine", "https://127.0.0.1:1", "--", sys.executable, "-c", child]
    )
    assert code == 0, f"the child's argparse did not receive {session!r} as --token (exit {code})"


# --- the workflow legs carry this module's settings ---------------------------


def _serving_step(workflow: str, job: str, needle: str) -> dict[str, Any]:
    from tests._workflow_contexts import jobs_of

    steps = [s for s in jobs_of(workflow)[job]["steps"] if needle in str(s.get("run") or "")]
    assert len(steps) == 1, f"{workflow} {job}: {len(steps)} step(s) hold {needle!r}"
    step: dict[str, Any] = steps[0]
    return step


def test_each_workflow_leg_carries_the_settings_this_module_names() -> None:
    """``SERVE_ENV`` and ``NOTIFY_ENV`` are written out by hand in seven workflow steps, in three
    syntaxes. This holds each copy to the module, so the port or the address cannot drift in one.

    An enforcing leg carries both. A leg at ``warn`` carries ``SERVE_ENV``: the notification gate
    only warns there."""
    pytest.importorskip("yaml")
    enforcing = {**rigadmin.SERVE_ENV, **rigadmin.NOTIFY_ENV}
    assert len(enforcing) == 5, "CONTROL FAILED: the module's settings changed shape"
    # Vault BACKLOG #2796: the sqlite load smoke is the one leg that keeps MFA required.
    with_mfa = {**rigadmin.NOTIFY_ENV, "MEFOR_SECURITY_REQUIRE_MFA": "true"}
    legs: list[tuple[str, str, dict[str, str]]] = [
        ("ci.yml", "load-test", with_mfa),
        ("benchmark.yml", "baseline-sqlite", enforcing),
        ("ci.yml", "load-test-sqlserver", dict(rigadmin.SERVE_ENV)),
        ("benchmark.yml", "baseline-postgres", dict(rigadmin.SERVE_ENV)),
        ("benchmark.yml", "baseline-sqlserver", dict(rigadmin.SERVE_ENV)),
    ]
    for workflow, job, wanted in legs:
        env = _serving_step(workflow, job, "messagefoundry serve")["env"]
        got = {name: str(env.get(name)) for name in wanted}
        assert got == wanted, f"{workflow} {job}: {got}"
    # The container smoke passes them to `docker run`, the Windows smoke to NSSM.
    docker = str(_serving_step("ci.yml", "docker-smoke", "serve --config")["run"])
    service = str(_serving_step("ci.yml", "windows-service-smoke", "AppEnvironmentExtra")["run"])
    for name, value in enforcing.items():
        assert f"-e {name}={value} " in docker, f"docker-smoke: {name}"
        assert f'"{name}={value}" `' in service, f"windows-service-smoke: {name}"


def test_the_mfa_leg_hands_its_key_to_provisioning_and_to_the_sign_in_and_masks_it() -> None:
    """Vault BACKLOG #2796. Read from the step's script with comment lines dropped, so prose about
    the key cannot pass for the commands that carry it."""
    pytest.importorskip("yaml")
    run = str(_serving_step("ci.yml", "load-test", "messagefoundry serve")["run"])
    script = "\n".join(line for line in run.splitlines() if not line.lstrip().startswith("#"))
    handed = f'{rigadmin.ADMIN_FACTOR_ENV}="$rig_totp"'
    assert 'echo "::add-mask::$rig_totp"' in script
    assert f"export {rigadmin.ADMIN_FACTOR_ENV}" not in script, "the key reaches the engine's env"
    for command in ("harness.load.rigadmin provision", "harness.load.rigadmin run"):
        at = script.find(command)
        assert at != -1, command
        # The variable prefixes the command: on its line or on the one continued into it.
        assert handed in script[max(0, at - 200) : at], f"{command} is not handed the key"
    # The census line that would name an account with no authenticator app fails the step. CONTROL:
    # the step's needle is the engine's own warning text, with its source literals joined, so a
    # reworded warning fails here rather than leaving the grep matching nothing.
    needle = "hold a chosen password and no authenticator app"
    assert f'grep -q "{needle}" engine.log' in script
    source = (_ROOT / "messagefoundry" / "auth" / "service.py").read_text(encoding="utf-8")
    assert needle in re.sub(r'"\s+"', "", source), "the census warning no longer says this"


# --- one real engine ---------------------------------------------------------

_CONFIG = """\
from messagefoundry import MLLP, inbound, router

inbound("IB_RIG_PROOF", MLLP(port={port}), router="rig_proof_router")


@router("rig_proof_router")
def route(msg):
    return []
"""


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _cli(*argv: str) -> tuple[int, str]:
    """Run the helper's command line in this process; returns ``(exit code, stdout)``."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = rigadmin.main(list(argv))
    return code, out.getvalue()


@pytest.mark.timeout(300)
async def test_a_rig_node_serves_with_sign_in_on_and_the_rig_reads_it_signed_in(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config"
    config.mkdir()
    (config / "IB_RIG_PROOF.py").write_text(_CONFIG.format(port=_free_port()), encoding="utf-8")
    base_env = _env_for_a_sqlite_store(MEFOR_STORE_PATH=str(tmp_path / "rig.db"))
    node = EngineNode("rig-proof", _free_port(), env=base_env, config_dir=str(config), cwd=tmp_path)
    assert rigadmin.ADMIN_PASS_ENV not in node._env
    assert node._env["MEFOR_SECURITY_REQUIRE_MFA"] == "false"

    await node.start()
    try:
        async with httpx.AsyncClient(timeout=4.0, verify=harness_ssl_context()) as client:
            deadline = time.monotonic() + 120.0
            while not await node.healthy(client):
                assert node.alive, f"the node exited during startup:\n{node.log_tail()}"
                assert time.monotonic() < deadline, f"never healthy:\n{node.log_tail()}"
                await asyncio.sleep(0.25)

            # THE POINT: no session, no answer. A node still serving with sign-in off answers 200.
            bare = await client.get(f"{node.url}/stats")
            assert bare.status_code == 401, bare.status_code
            # ...and the rig's own reads are answered.
            assert await node.stats(client) is not None
            assert await node.role(client) is not None

            # A node that refuses the held session is signed in to again, not read as down.
            good = rigadmin.session_token(node.url, cacert=node.cacert)
            rigadmin._held.token = "not-a-session"
            assert await node.stats(client) is not None
            assert rigadmin._held.token not in (good, "not-a-session")

        poller = EnginePoller(node.url, RIG_SESSION, origin=time.perf_counter())
        await poller.open()
        try:
            assert await poller.sample_once() is not None
            # A caller about to TIME a reload proves for it first (vault BACKLOG #2625), on a
            # client of its own holding a proof bound to config_reload (vault BACKLOG #3241).
            # Neither the held session nor the sampler's client is re-keyed.
            before = rigadmin._held.token
            primary = poller.client
            assert primary is not None
            sampler_token = primary.token
            proved = await poller.reload_client()
            assert proved is not None and proved is not primary
            assert rigadmin._held.token == before and primary.token == sampler_token
            assert proved.token not in (None, before)
            assert await poller.sample_once() is not None
            # The proof opens the reload with no step-up retry, and only once.
            result = await asyncio.to_thread(proved.reload_config)
            assert getattr(result, "inbound", None) is not None, result
            await asyncio.sleep(0.3)  # past the engine's admin-write gap
            with pytest.raises(ApiError) as refused:
                await asyncio.to_thread(proved.reload_config)
            assert refused.value.status == 403
            # Ending it signs its session out, so a run of reloads holds one session at a time.
            ended = proved.token
            await poller.end_reload_client(proved)
            async with httpx.AsyncClient(timeout=4.0, verify=harness_ssl_context()) as check:
                me = await check.get(
                    f"{node.url}/auth/me", headers={"Authorization": f"Bearer {ended}"}
                )
            assert me.status_code == 401, me.status_code
        finally:
            await poller.close()
        # CONTROL: the same poller with no session reads nothing.
        unsigned = EnginePoller(node.url, None, origin=time.perf_counter())
        await unsigned.open()
        try:
            assert await unsigned.sample_once() is None
        finally:
            await unsigned.close()

        # The store has its Administrator now, so provisioning again finds it and changes nothing.
        await node.provision()

        # The command line a workflow step uses, against the same node.
        url, pin = node.url, node.cacert
        code, out = await asyncio.to_thread(_cli, "get", "--engine", url, "--cacert", pin, "/stats")
        assert code == 0 and "in_pipeline" in json.loads(out), out
        code, out = await asyncio.to_thread(
            _cli, "get", "--engine", url, "--cacert", pin, "--field", "in_pipeline", "/stats"
        )
        assert (code, out.strip()) == (0, "0")
        # `run` hands the session to its child as --token, and not the password it came from.
        child = (
            "import os, sys; "
            f"sys.exit(9 if {rigadmin.ADMIN_PASS_ENV!r} in os.environ else "
            "0 if sys.argv[-1].startswith('--token=') and len(sys.argv[-1]) > 28 else 7)"
        )
        code, _ = await asyncio.to_thread(
            _cli, "run", "--engine", url, "--cacert", pin, "--", sys.executable, "-c", child
        )
        assert code == 0, code

        # A credential the store does not hold is refused, in words that carry no password.
        wrong = RigAdmin(rigadmin.rig_admin().username, "0" * 48)
        with pytest.raises(rigadmin.RigSignInRefused, match="HTTP 401"):
            await asyncio.to_thread(rigadmin.sign_in, url, wrong, cacert=pin)
    finally:
        await node.stop()


@pytest.mark.timeout(300)
async def test_a_rig_with_a_key_serves_with_mfa_required_and_signs_in_with_both_factors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Vault BACKLOG #2796: the shipped ``require_mfa = true``, an Administrator enrolled through the
    shipped ``provision-admin`` with only its terminal reads replaced, and a combined sign-in."""
    key = totp.generate_secret()
    password = rigadmin._new_password()
    monkeypatch.setenv(rigadmin.ADMIN_PASS_ENV, password)
    monkeypatch.setenv(rigadmin.ADMIN_FACTOR_ENV, key)
    admin = rigadmin.rig_admin()
    assert admin.totp_secret == key

    config = tmp_path / "config"
    config.mkdir()
    (config / "IB_RIG_PROOF.py").write_text(_CONFIG.format(port=_free_port()), encoding="utf-8")
    base_env = _env_for_a_sqlite_store(
        MEFOR_STORE_PATH=str(tmp_path / "rig.db"), MEFOR_SECURITY_REQUIRE_MFA="true"
    )
    node = EngineNode("rig-mfa", _free_port(), env=base_env, config_dir=str(config), cwd=tmp_path)
    assert node._env["MEFOR_SECURITY_REQUIRE_MFA"] == "true"
    for name in (rigadmin.ADMIN_PASS_ENV, rigadmin.ADMIN_FACTOR_ENV):
        assert name not in node._env, f"{name} reached the engine's environment"

    await node.start()
    try:
        async with httpx.AsyncClient(timeout=4.0, verify=harness_ssl_context()) as client:
            deadline = time.monotonic() + 120.0
            while not await node.healthy(client):
                assert node.alive, f"the node exited during startup:\n{node.log_tail()}"
                assert time.monotonic() < deadline, f"never healthy:\n{node.log_tail()}"
                await asyncio.sleep(0.25)
            url, pin = node.url, node.cacert

            # CONTROL: MFA is really required. The password alone is answered with a demand for
            # the second factor, which the rig reads as a refusal.
            with pytest.raises(rigadmin.RigSignInRefused, match="second factor"):
                await asyncio.to_thread(
                    rigadmin.sign_in, url, RigAdmin(admin.username, password), cacert=pin
                )

            # THE POINT: both factors in one request give a session the API answers.
            held = await asyncio.to_thread(rigadmin.sign_in, url, admin, cacert=pin)
            stats = await client.get(f"{url}/stats", headers={"Authorization": f"Bearer {held}"})
            assert stats.status_code == 200, stats.status_code

            # CONTROL for the wait: the code of the step that sign-in spent, sent again, is refused.
            # Computed from the recorded step and not the clock, which may have reached a new one.
            assert rigadmin._spent.last >= 0, "the sign-in recorded no spent step"
            spent = totp.totp(key, now=rigadmin._spent.last * 30 + 1)
            replay = await client.post(
                f"{url}/auth/login",
                json={"username": admin.username, "password": password, "totp_code": spent},
            )
            assert replay.status_code == 401, replay.status_code

        # The start-up census names no covered account without an authenticator app, and neither
        # factor reached the engine's log.
        log = node.log_tail(limit=8 * 1024 * 1024)
        assert log, "CONTROL FAILED: the engine log is empty"
        assert "hold a chosen password and no authenticator app" not in log, log[-4000:]
        assert key not in log and password not in log
    finally:
        await node.stop()
