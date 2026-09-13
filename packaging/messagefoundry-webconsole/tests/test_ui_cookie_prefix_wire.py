# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1117 / ASVS 3.3.1: what the browser-hardening opt-out costs, measured ON THE WIRE.

**OWNER RULING 2026-09-05: the opt-out drops ``__Host-`` ONLY.** It was never written down whether
the org opt-out means "no ``__Host-``" or "no cookie-name prefix at all", and the cookie went bare
either way. It means the first, so ``__Secure-`` is the required fallback wherever ``Secure`` is
genuinely set -- and the bare name survives only where it is not, because a browser drops a
``__Secure-`` cookie without ``Secure`` exactly as it drops a ``__Host-`` one.

**Why a real server rather than an ASGI transport.** The sibling postures in
``test_ui_hardening.py`` drive ``httpx.ASGITransport``, which takes the scheme from the client's
``base_url`` -- so a test asserting a Secure cookie over ``https://t`` has been handed the very fact
it is grading. These arms run the shipped TLS wiring (``ensure_api_tls_material`` ->
``build_api_ssl_context`` -> uvicorn's ``ssl_context_factory``, the same three calls
``messagefoundry serve`` makes) against a real uvicorn on an ephemeral loopback port, log in over
it, and read the response's own ``Set-Cookie``. The scheme is then a fact about the socket.

The arms are the two startable topologies crossed with the opt-out, which is the enumeration
``ensure_api_tls_material``'s return paths bound: it mints (the shipped default), or it returns
``None`` for a declared upstream terminator. A third arm holds no declaration and no TLS -- not a
startable ``serve`` posture, and kept as the negative control that proves ``__Secure-`` is emitted
only where ``Secure`` is.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
import uvicorn

from messagefoundry.api import create_app
from messagefoundry.api.tls import build_api_ssl_context, ensure_api_tls_material
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ApiSettings, AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry_webconsole._auth import BROWSER_HARDENING_OPT_OUT_ENV

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port: int = s.getsockname()[1]
    return port


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    user_id = await service.create_local_user(
        username="op",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )
    return service


@asynccontextmanager
async def _serving(
    engine: Engine,
    service: AuthService,
    *,
    api: ApiSettings,
    state_dir: Path,
    declare_to_app: bool = True,
) -> AsyncIterator[tuple[str, ssl.SSLContext | None]]:
    """Serve ``/ui`` under a real uvicorn, wired exactly as ``messagefoundry serve`` wires it.

    Yields the base URL and the server's ``SSLContext`` (``None`` on the declared-terminator
    topology), so a caller can assert the WIRE scheme rather than assume it. The server runs as a
    task on the suite's own event loop, not in a thread: the engine's aiosqlite store is bound to
    that loop, and a second loop would deliver its results where nobody is awaiting them.

    ``declare_to_app=False`` wires the SOCKET from ``api`` but hands the app no proxy declaration --
    the undeclared-proxy shape #1117 was filed on, where the wire scheme is the only signal left.
    """
    material = ensure_api_tls_material(api, state_dir=state_dir)
    context: ssl.SSLContext | None = None
    if material is not None:
        cert, key = material
        serving_api = api.model_copy(update={"tls_cert_file": cert, "tls_key_file": key})
        context = build_api_ssl_context(serving_api)
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        exposure_protected=api.exposure_protected if declare_to_app else False,
        tls_terminated_upstream=api.tls_terminated_upstream if declare_to_app else False,
        trusted_proxies=api.trusted_proxies if declare_to_app else (),
    )
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            # `None` is uvicorn's own default, so the cleartext arms take the stock path rather than
            # a test-only one -- the serve path's rule verbatim: material -> a factory -> https.
            ssl_context_factory=(
                None if context is None else (lambda config, default_factory: context)
            ),
        )
    )
    task = asyncio.create_task(server.serve())
    deadline = asyncio.get_running_loop().time() + 20
    while not server.started:
        if asyncio.get_running_loop().time() > deadline:  # pragma: no cover - startup wedge
            task.cancel()
            raise RuntimeError("uvicorn did not start")
        await asyncio.sleep(0.02)
    scheme = "https" if context is not None else "http"
    try:
        yield f"{scheme}://127.0.0.1:{port}", context
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=20)


def _client_ssl() -> ssl.SSLContext:
    """Trust the minted self-signed placeholder. The chain is what ADR 0172 ships by design, and
    verifying it is a different test's question -- this one grades the cookie."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _login_set_cookie(base_url: str) -> str:
    async with httpx.AsyncClient(base_url=base_url, verify=_client_ssl(), timeout=20) as c:
        r = await c.post("/ui/login", data={"username": "op", "password": PW})
        assert r.status_code == 303, r.text
        set_cookie: str = r.headers["set-cookie"]
    return set_cookie


def _name_and_attrs(set_cookie: str) -> tuple[str, str]:
    head, _, rest = set_cookie.partition(";")
    return head.split("=", 1)[0], rest.lower()


# --- the two startable topologies, under the org opt-out -----------------------------------------


async def test_opt_out_on_the_shipped_default_falls_back_to_secure_prefix(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shipped default (ADR 0172 mints a pair) + the org opt-out: ``__Secure-mf_session``.

    The opt-out drops ``__Host-`` and nothing else (owner ruling 2026-09-05), so the name keeps the
    weaker prefix rather than going bare. ``__Secure-`` constrains strictly less than ``__Host-`` --
    it requires only ``Secure``, where ``__Host-`` additionally requires ``Path=/`` and no
    ``Domain`` -- so it survives the one realistic proxy failure the hatch exists for, a proxy that
    rewrites ``Path`` or adds a ``Domain``.
    """
    monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    service = await _service(engine)
    api = ApiSettings()  # no operator chain, no declared proxy: the engine mints and serves TLS
    async with _serving(engine, service, api=api, state_dir=tmp_path) as (base_url, context):
        assert context is not None and base_url.startswith("https://")  # the wire really is TLS
        name, attrs = _name_and_attrs(await _login_set_cookie(base_url))
    # THE PREFIX IS ONLY CORRECT BECAUSE SECURE IS THERE: a browser drops a `__Secure-` cookie
    # without `Secure` exactly as it drops a `__Host-` one, so this is asserted, never assumed.
    assert "secure" in attrs, attrs
    assert name == "__Secure-mf_session"


async def test_opt_out_behind_a_declared_terminator_falls_back_to_secure_prefix(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one topology ADR 0172 excludes, under the opt-out: still ``__Secure-mf_session``.

    ``[api].tls_terminated_upstream`` says a proxy terminates TLS in front and speaks plaintext to
    the engine, so nothing is minted and the WIRE is http -- which every scheme-keyed intuition
    reads as "bare name". The browser's origin is https, and ``effective_https`` reaches that fact
    through its ``exposure_protected`` disjunct, so ``Secure`` is set and the prefix is earned.
    Settings validation refuses this topology without ``trusted_proxies``, so there is no startable
    posture that pairs a cleartext wire with ``exposure_protected`` false.
    """
    monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    service = await _service(engine)
    api = ApiSettings(tls_terminated_upstream=True, trusted_proxies=["127.0.0.1"])
    # Its OWN directory, not the shared tmp_path the engine fixture already put a store in, so the
    # minted-nothing assertion below grades this call rather than whatever else wrote there.
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    async with _serving(engine, service, api=api, state_dir=state_dir) as (base_url, context):
        assert context is None and base_url.startswith("http://")  # the excluded, cleartext hop
        assert not any(state_dir.iterdir())  # and it minted nothing, rather than minting quietly
        name, attrs = _name_and_attrs(await _login_set_cookie(base_url))
    assert "secure" in attrs, attrs
    assert name == "__Secure-mf_session"


# --- controls: the ruling moves ONE branch, and only where Secure is real ------------------------


async def test_the_shipped_default_without_the_opt_out_still_carries_host_prefix(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control. The secure-by-default posture is untouched by the ruling: with the hatch
    unset the shipped default still writes ``__Host-mf_session``, so an all-passing file above
    cannot be a resolver that returns ``__Secure-`` unconditionally."""
    monkeypatch.delenv(BROWSER_HARDENING_OPT_OUT_ENV, raising=False)
    service = await _service(engine)
    async with _serving(engine, service, api=ApiSettings(), state_dir=tmp_path) as (base_url, _):
        name, attrs = _name_and_attrs(await _login_set_cookie(base_url))
    assert "secure" in attrs, attrs
    assert name == "__Host-mf_session"


async def test_a_cleartext_bind_with_no_declaration_keeps_the_bare_name(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NEGATIVE CONTROL, and the reason the fallback is conditional. Here the wire is cleartext and
    nothing declares a terminator, so the set site writes no ``Secure`` -- and a ``__Secure-`` name
    without it is dropped by the browser, which breaks login while a grep reads as hardened. The
    bare name is the correct answer on this branch, opt-out or not.

    ``messagefoundry serve`` cannot reach this posture since ADR 0172 (it always serves TLS unless a
    proxy is declared, and a declaration forces ``exposure_protected``). The app is buildable in it,
    which is what makes the branch worth pinning: the resolver must stay keyed on the transport.
    """
    monkeypatch.setenv(BROWSER_HARDENING_OPT_OUT_ENV, "1")
    service = await _service(engine)
    # The socket comes from the declared-terminator settings, so nothing is minted and the wire is
    # cleartext; `declare_to_app=False` withholds the declaration from the app itself.
    api = ApiSettings(tls_terminated_upstream=True, trusted_proxies=["127.0.0.1"])
    async with _serving(engine, service, api=api, state_dir=tmp_path, declare_to_app=False) as (
        base_url,
        context,
    ):
        assert context is None and base_url.startswith("http://")
        name, attrs = _name_and_attrs(await _login_set_cookie(base_url))
    assert "secure" not in attrs, attrs
    assert name == "mf_session"
