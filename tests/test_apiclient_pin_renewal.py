# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine client follows a renewed pinned certificate without being rebuilt (BACKLOG #1276).

The engine renews its self-signed API certificate early, at startup, and writes the new one to the
same file an operator pins with ``cacert=``. A TLS context reads that file once, when it is built,
so a long-lived :class:`EngineClient` (the harness monitor, a CLI session, a poll clone) used to
fail every request against the restarted engine until the operator reconnected.

These tests run a real loopback https server that can swap its pair, so every verification here is
a real handshake against a real certificate rather than a mocked transport.
"""

from __future__ import annotations

import http.server
import json
import logging
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from messagefoundry import pki
from messagefoundry.apiclient import ApiError, EngineClient
from messagefoundry.apiclient import client as client_module


class _RenewableEngine:
    """A loopback https server presenting a minted self-signed pair, which it can swap for a new one.

    It speaks HTTP/1.0, so every request is a fresh handshake: a renewed engine has restarted and
    dropped its connections, and a pooled connection surviving the swap would let a client pinned
    to the OLD certificate pass without ever meeting the new one. It records the requests it
    answers, so a test can see that a retried request reached the engine exactly once.
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._minted = 0
        self.answered: list[str] = []
        #: The Authorization header of each answered request, in step with ``answered``.
        self.bearers: list[str | None] = []
        #: Response headers for ONE 403 challenge (MFA or step-up) the next request receives.
        self.challenges: list[str] = []
        self.pin = directory / "api-generated-cert.pem"
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.serve(self.renew_pin())
        body = json.dumps({"status": "ok", "version": None, "observed_client": None}).encode()
        answered = self.answered
        bearers = self.bearers
        challenges = self.challenges

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self) -> None:
                answered.append(f"{self.command} {self.path}")
                bearers.append(self.headers.get("Authorization"))
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if challenges:
                    refusal = b'{"detail": "challenge"}'
                    self.send_response(403)
                    self.send_header(challenges.pop(0), "true")
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(refusal)))
                    self.end_headers()
                    self.wfile.write(refusal)
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                self._answer()

            def do_POST(self) -> None:
                self._answer()

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.socket = self._ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"https://127.0.0.1:{self._server.server_address[1]}"

    def mint(self) -> tuple[bytes, Path]:
        """A new key and a new self-signed certificate: the cert PEM, and where the pair is kept."""
        self._minted += 1
        cert, key = pki.make_self_signed("127.0.0.1", ["127.0.0.1"], 1)
        stem = self._dir / f"pair-{self._minted}"
        stem.with_suffix(".crt").write_bytes(cert)
        stem.with_suffix(".key").write_bytes(key)
        return cert, stem

    def renew_pin(self) -> Path:
        """Mint a pair and write its certificate to the pinned path, as the engine's renewal does."""
        cert, stem = self.mint()
        self.pin.write_bytes(cert)
        return stem

    def serve(self, stem: Path) -> None:
        """Present the pair kept at ``stem`` on every handshake from now on."""
        self._ctx.load_cert_chain(str(stem.with_suffix(".crt")), str(stem.with_suffix(".key")))

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[_RenewableEngine]:
    served = _RenewableEngine(tmp_path)
    try:
        yield served
    finally:
        served.close()


@pytest.fixture
def builds(monkeypatch: pytest.MonkeyPatch) -> list[str | None]:
    """Every verify context the client builds, by the ``cacert`` it was built from."""
    real = client_module._build_verify_context
    seen: list[str | None] = []

    def counting(
        cacert: str | None, client_cert: str | None, client_key: str | None
    ) -> ssl.SSLContext:
        seen.append(cacert)
        return real(cacert, client_cert, client_key)

    monkeypatch.setattr(client_module, "_build_verify_context", counting)
    return seen


#: Every transport a client opens in this module, mapped to the ``verify`` it was opened with.
_OPENED: dict[int, ssl.SSLContext | bool] = {}


@pytest.fixture(autouse=True)
def _record_transports(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Record what each transport verifies with, through the client's own seam rather than httpx's
    private attributes."""
    real = EngineClient._open_transport

    def recording(self: EngineClient, verify: ssl.SSLContext | bool) -> httpx.Client:
        transport = real(self, verify)
        _OPENED[id(transport)] = verify
        return transport

    monkeypatch.setattr(EngineClient, "_open_transport", recording)
    yield
    _OPENED.clear()


def _pinned(engine: _RenewableEngine) -> EngineClient:
    return EngineClient(engine.url, cacert=str(engine.pin))


def _assert_pinned(client: EngineClient) -> None:
    """The CURRENT transport verifies, and its store holds exactly one certificate: the pin.

    Counting the store catches a widened trust (the pin plus the OS roots, measured at 91
    certificates on the dev box) as well as a dropped one, which a type or verify-mode check alone
    would not. The stdlib lists only CA certificates by content, and the engine's minted
    certificate is a leaf, so WHICH certificate is pinned is shown by the requests that succeed or
    fail around each call."""
    ctx = _OPENED[id(client._http)]
    assert isinstance(ctx, ssl.SSLContext), "the transport does not verify with a pinned context"
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.cert_store_stats() == {"x509": 1, "crl": 0, "x509_ca": 0}


def test_a_renewed_certificate_is_followed_without_a_new_client(engine: _RenewableEngine) -> None:
    """The defect. A new key and a new certificate, written to the pinned path while the engine
    restarts onto them, are trusted by the SAME client on its next request.

    Red before the fix: the second ``health()`` raises ``ApiError`` with CERTIFICATE_VERIFY_FAILED,
    because the client's context still holds the certificate it read at construction."""
    with _pinned(engine) as client:
        assert client.health().status == "ok"
        engine.serve(engine.renew_pin())
        assert client.health().status == "ok"
        _assert_pinned(client)


def test_a_poll_clone_follows_a_renewal_too(engine: _RenewableEngine) -> None:
    """A clone made before the renewal carries its own transport, so it must follow on its own."""
    with _pinned(engine) as client, client.for_polling() as poll:
        assert poll.health().status == "ok"
        engine.serve(engine.renew_pin())
        assert poll.health().status == "ok"
        assert client.health().status == "ok"


def test_a_retried_post_is_delivered_exactly_once(engine: _RenewableEngine) -> None:
    """The retry delivers a POST once: not zero times (the retry works for a body-carrying method)
    and not twice. Verification fails in the handshake, before any byte of the request is written,
    which is why the retry is limited to a connect failure."""
    with _pinned(engine) as client:
        engine.serve(engine.renew_pin())
        engine.answered.clear()
        client._request("POST", "/probe", json={"n": 1})
        assert engine.answered == ["POST /probe"]


def test_the_revoke_of_a_replaced_session_follows_a_renewal_with_the_replaced_token(
    engine: _RenewableEngine, caplog: pytest.LogCaptureFixture
) -> None:
    """The login revoke (BACKLOG #1901) keeps the renewal follow (BACKLOG #1276), and its retry
    still presents the REPLACED token.

    Red when: the certificate retry drops ``_bearer`` and falls back to the held token. That retry
    would end the NEW session, which the client has just adopted, and leave the old one live.
    Red too when the revoke is sent with the follow disarmed: it then fails verification against
    the renewed engine and the replaced session survives, logged as a WARNING."""
    with _pinned(engine) as client:
        client._token = "tok-new"
        engine.serve(engine.renew_pin())
        engine.answered.clear()
        engine.bearers.clear()
        with caplog.at_level(logging.INFO, logger="messagefoundry.apiclient.client"):
            client._end_replaced_session("tok-old")
        assert engine.answered == ["POST /auth/logout"]
        assert engine.bearers == ["Bearer tok-old"]
        assert client.token == "tok-new"
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        _assert_pinned(client)


@pytest.mark.parametrize("challenge", ["X-MFA-Required", "X-Step-Up-Required"])
def test_a_request_retried_after_a_prompt_may_follow_a_renewal(
    engine: _RenewableEngine, challenge: str
) -> None:
    """The MFA and step-up retries are new attempts, so they re-arm the follow.

    The first attempt fails verification and follows renewal one, so its retry runs with the follow
    spent. That retry meets the challenge, and the engine restarts onto renewal two while the
    operator answers the prompt. Only a retry that re-arms the follow reaches the engine; one that
    inherits the spent flag fails verification."""
    with _pinned(engine) as client:

        def answer_the_prompt() -> bool:
            engine.serve(engine.renew_pin())
            return True

        if challenge == "X-MFA-Required":
            client.set_mfa_handler(answer_the_prompt)
        else:
            client.set_step_up_handler(answer_the_prompt)
        engine.serve(engine.renew_pin())
        engine.challenges.append(challenge)
        assert client.health().status == "ok"
        assert engine.challenges == [], "the retry never met the challenge"


def test_an_unchanged_pin_never_rebuilds(
    engine: _RenewableEngine, builds: list[str | None]
) -> None:
    """Control: no churn. Requests that verify, and a rewrite of the SAME bytes, rebuild nothing."""
    with _pinned(engine) as client:
        transport = client._http
        for _ in range(3):
            client.health()
        engine.pin.write_bytes(engine.pin.read_bytes())
        client.health()
        assert client._http is transport
        assert builds == [str(engine.pin)], "only the constructor may build a context here"


def test_an_unchanged_pin_against_a_foreign_certificate_still_fails(
    engine: _RenewableEngine, builds: list[str | None]
) -> None:
    """Pin enforced, and no churn on failure. The engine presents a certificate that is NOT in the
    pinned file, and the file has not changed: the request fails, and nothing is rebuilt."""
    with _pinned(engine) as client:
        transport = client._http
        _, foreign = engine.mint()  # minted but never written to the pin
        engine.serve(foreign)
        for _ in range(2):
            with pytest.raises(ApiError, match="CERTIFICATE_VERIFY_FAILED"):
                client.health()
        assert client._http is transport
        assert builds == [str(engine.pin)]


def test_a_renewed_pin_that_is_not_the_served_certificate_still_fails(
    engine: _RenewableEngine,
) -> None:
    """Pin enforced after a rebuild. The pin file changes to certificate B while the engine serves
    certificate C: the client follows the file to B and still refuses C. Following a renewal never
    means trusting whatever the engine presents."""
    with _pinned(engine) as client:
        first = client._http
        engine.renew_pin()  # B, written to the pin and not served
        _, other = engine.mint()  # C, served and not pinned
        engine.serve(other)
        with pytest.raises(ApiError, match="CERTIFICATE_VERIFY_FAILED"):
            client.health()
        assert client._http is not first, "the changed, loadable pin should have been followed"
        _assert_pinned(client)
        with pytest.raises(ApiError, match="CERTIFICATE_VERIFY_FAILED"):
            client.health()


@pytest.mark.parametrize("mid_renewal", ["missing", "empty", "half-written", "not a certificate"])
def test_a_pin_caught_mid_renewal_keeps_the_current_context(
    engine: _RenewableEngine, mid_renewal: str
) -> None:
    """Control. The engine has restarted onto a new pair but the pin file is not yet a loadable
    certificate. The request fails as the ordinary ``ApiError`` (no crash, no fallback to the OS
    store, no unverified retry), the current context is kept, and once the file is whole the next
    request follows it: retry later, not give up."""
    with _pinned(engine) as client:
        transport = client._http
        cert, stem = engine.mint()
        engine.serve(stem)
        if mid_renewal == "missing":
            engine.pin.unlink()
        elif mid_renewal == "empty":
            engine.pin.write_bytes(b"")
        elif mid_renewal == "half-written":
            engine.pin.write_bytes(cert[: len(cert) // 2])
        else:
            engine.pin.write_bytes(b"-----BEGIN CERTIFICATE-----\nnope\n")
        with pytest.raises(ApiError, match="CERTIFICATE_VERIFY_FAILED"):
            client.health()
        assert client._http is transport
        _assert_pinned(client)
        engine.pin.write_bytes(cert)
        assert client.health().status == "ok"
        _assert_pinned(client)


def test_a_refused_pin_is_logged_once_per_distinct_bytes(
    engine: _RenewableEngine, caplog: pytest.LogCaptureFixture
) -> None:
    """A file that stays broken says so once, not once per request of a background poll."""
    with _pinned(engine) as client:
        _, stem = engine.mint()
        engine.serve(stem)
        engine.pin.write_bytes(b"-----BEGIN CERTIFICATE-----\nnope\n")
        with caplog.at_level("INFO", logger=client_module.__name__):
            for _ in range(3):
                with pytest.raises(ApiError):
                    client.health()
        refused = [r for r in caplog.records if "does not load" in r.getMessage()]
        assert len(refused) == 1


def test_a_transport_already_replaced_is_retried_without_a_reload(
    engine: _RenewableEngine, builds: list[str | None]
) -> None:
    """A caller that failed on a transport another caller has already replaced retries on the
    replacement instead of reloading or giving up. Sequential, so the identity check is what is
    tested; the concurrent case is the next test."""
    with _pinned(engine) as client:
        stale = client._http
        engine.serve(engine.renew_pin())
        assert client._follow_renewed_pin(stale) is True
        assert len(builds) == 2
        assert client._follow_renewed_pin(stale) is True  # the second caller's view
        assert len(builds) == 2, "a transport already replaced must not be rebuilt again"
        assert client.health().status == "ok"


class _ContendedLock:
    """A lock that records when a SECOND thread has asked for it while the first holds it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._asked = 0
        self._count = threading.Lock()
        self.contended = threading.Event()

    def __enter__(self) -> _ContendedLock:
        with self._count:
            self._asked += 1
            if self._asked >= 2:
                self.contended.set()
        self._lock.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._lock.release()


def test_two_threads_failing_together_rebuild_once(
    engine: _RenewableEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two threads share one poll client and both fail on the old transport at once. Exactly one
    rebuild happens and both requests succeed. The rebuild waits until the second thread has asked
    for the rebuild lock, so the second thread is provably inside the window; without the lock
    both would rebuild."""
    real = client_module._build_verify_context
    built: list[str | None] = []
    both_failed = threading.Barrier(2)
    lock = _ContendedLock()

    def waits_for_the_other_thread(
        cacert: str | None, client_cert: str | None, client_key: str | None
    ) -> ssl.SSLContext:
        built.append(cacert)
        if len(built) > 1:
            lock.contended.wait(timeout=5)
        return real(cacert, client_cert, client_key)

    monkeypatch.setattr(client_module, "_build_verify_context", waits_for_the_other_thread)
    real_follow = EngineClient._follow_renewed_pin

    def meet_then_follow(self: EngineClient, failed: httpx.Client) -> bool:
        both_failed.wait(timeout=10)
        return real_follow(self, failed)

    monkeypatch.setattr(EngineClient, "_follow_renewed_pin", meet_then_follow)
    with _pinned(engine) as client:
        client._rebuild_lock = lock  # type: ignore[assignment]
        engine.serve(engine.renew_pin())
        results: list[str] = []
        errors: list[BaseException] = []

        def poll() -> None:
            try:
                results.append(client.health().status)
            except BaseException as exc:  # surfaced below, on the test thread
                errors.append(exc)

        threads = [threading.Thread(target=poll) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert not errors
        assert results == ["ok", "ok"]
        assert lock.contended.is_set(), "the second thread never reached the rebuild lock"
        assert len(built) == 2, "the constructor plus exactly one rebuild"


def test_close_releases_every_transport_the_client_opened(engine: _RenewableEngine) -> None:
    """A retired transport is kept until close, because another thread may still be mid-request on
    it, and closing it under that thread would raise a bare RuntimeError out of a worker."""
    client = _pinned(engine)
    first = client._http
    engine.serve(engine.renew_pin())
    client.health()
    assert client._http is not first
    assert not first.is_closed
    client.close()
    assert first.is_closed
    assert client._http.is_closed


def test_a_closed_client_never_rebuilds(engine: _RenewableEngine, builds: list[str | None]) -> None:
    """A rebuild after close would open a transport nothing ever closes."""
    client = _pinned(engine)
    stale = client._http
    engine.serve(engine.renew_pin())
    client.close()
    assert client._follow_renewed_pin(stale) is False
    assert client._http is stale
    assert builds == [str(engine.pin)]


def test_a_relative_pin_is_followed_at_the_path_it_was_given(
    engine: _RenewableEngine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A relative ``cacert`` names a file relative to the working directory at construction. A
    later change of directory must not make the follow read, and pin, some other file."""
    monkeypatch.chdir(engine.pin.parent)
    client = EngineClient(engine.url, cacert=engine.pin.name)
    try:
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        decoy, _ = engine.mint()
        (elsewhere / engine.pin.name).write_bytes(decoy)
        monkeypatch.chdir(elsewhere)
        engine.serve(engine.renew_pin())
        assert client.health().status == "ok"
        _assert_pinned(client)
        # A poll clone made AFTER the change of directory pins the same file, not the decoy.
        with client.for_polling() as poll:
            assert poll.health().status == "ok"
            engine.serve(engine.renew_pin())
            assert poll.health().status == "ok"
    finally:
        client.close()


def test_the_constructor_records_the_pin_only_when_both_reads_agree(
    engine: _RenewableEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bytes recorded at construction must be the bytes the context loaded. A file rewritten
    during the build leaves them unknown, so the next verification failure follows the file."""
    with _pinned(engine) as steady:
        assert steady._pin_pem == engine.pin.read_bytes()
    reads = iter([b"before", b"after"])
    monkeypatch.setattr(client_module, "_read_pin", lambda _p: next(reads))
    with _pinned(engine) as racing:
        assert racing._pin_pem is None


def test_a_client_without_a_pin_never_follows(
    engine: _RenewableEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A client trusting a store rather than a pin has nothing to follow: a verification failure
    is simply the error, and the transport is kept."""
    monkeypatch.setattr(
        client_module, "_build_verify_context", lambda *_a: ssl.create_default_context()
    )
    with EngineClient(engine.url) as client:
        transport = client._http
        with pytest.raises(ApiError, match="CERTIFICATE_VERIFY_FAILED"):
            client.health()
        assert client._http is transport


def test_a_transport_error_that_is_not_verification_does_not_reload(
    engine: _RenewableEngine, builds: list[str | None]
) -> None:
    """Only a certificate-verification failure triggers the re-read. A refused connection with a
    changed pin file is an unreachable engine, and it does not rebuild the transport. The port is
    held bound and not listening for the whole test, so no other server can take it."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("127.0.0.1", 0))
        port = held.getsockname()[1]
        with EngineClient(f"https://127.0.0.1:{port}", cacert=str(engine.pin)) as client:
            transport = client._http
            engine.renew_pin()
            with pytest.raises(ApiError, match="could not reach engine"):
                client.health()
            assert client._http is transport
            assert builds == [str(engine.pin)]


def test_the_verification_failure_is_found_through_the_httpx_wrapping() -> None:
    """httpx wraps the handshake failure twice (its own ConnectError over httpcore's). The detector
    walks the chain. An unrelated connect error, a cyclic chain, and a NON-connect error carrying a
    verification failure (the request may already be on the wire) all read as False."""
    inner = ssl.SSLCertVerificationError(1, "certificate verify failed")
    middle = RuntimeError("httpcore")
    middle.__context__ = inner
    wrapped = httpx.ConnectError("x")
    wrapped.__cause__ = middle
    assert client_module._is_cert_verification_failure(wrapped)
    assert not client_module._is_cert_verification_failure(httpx.ConnectError("refused"))
    after_send = httpx.ReadError("mid-reply")
    after_send.__cause__ = inner
    assert not client_module._is_cert_verification_failure(after_send)
    cyclic = httpx.ConnectError("a")
    other = httpx.ConnectError("b")
    cyclic.__context__ = other
    other.__context__ = cyclic
    assert not client_module._is_cert_verification_failure(cyclic)
