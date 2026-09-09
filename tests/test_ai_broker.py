# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Engine-brokered AI assistance (ADR 0135, BACKLOG #95).

Covers the crown-jewel security invariants of the NEW LLM-egress surface: the SERVER re-resolves the
policy (an IDE-claimed scope is never trusted; an over-claim is denied), the SSRF endpoint-allowlist is
fail-closed, the MVP boundary is code_only, the per-use audit reuses the existing hash-chained audit_log
with PHI-safe metadata only (no prompt / reply / key), and the broker runs off the event loop through the
no-redirect opener without importing api/.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.ai_policy import AiDataScope, AiMode, resolve_effective_policy
from messagefoundry.config.settings import AiSettings, AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.transports import ai_broker as ai_broker_mod
from messagefoundry.transports.ai_broker import (
    AiBroker,
    AiBrokerError,
    ai_broker_from_settings,
    endpoint_host_allowed,
)
from messagefoundry.transports.rest import _NO_REDIRECT_OPENER

PW = "Sup3rSecret!!"

# A fully-configured engine-broker [ai] section: managed_endpoint + an allow-listed https endpoint.
_ENDPOINT = "https://ai.internal/v1/messages"


def _managed_ai(**over: object) -> AiSettings:
    kw: dict[str, object] = {
        "mode": AiMode.MANAGED_ENDPOINT,
        "environment": "prod",
        "endpoint": _ENDPOINT,
        "api_key": "sk-secret-key-value",
        "allowed_endpoints": ["ai.internal"],
    }
    kw.update(over)
    return AiSettings(**kw)  # type: ignore[arg-type]


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "ai_broker.db", poll_interval=0.02)
    yield eng
    await eng.stop()


def _client(app: object) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://t")


@pytest.fixture
def stub_broker(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Patch ``AiBroker.chat`` (the blocking POST) to a canned reply — NO network. Records the prompt(s)
    the route handed the broker so a test can assert the server sent exactly the code_only context."""
    seen: list[str] = []

    def fake_chat(self: AiBroker, prompt: str) -> str:
        seen.append(prompt)
        return "def handle(msg): return Send('OB', msg)"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    yield seen


# --- SSRF endpoint-allowlist (fail-closed) -----------------------------------


def test_broker_refuses_endpoint_not_in_allowlist() -> None:
    # The configured endpoint host is NOT on the allowlist -> refuse at construction (SSRF fail-closed).
    with pytest.raises(AiBrokerError, match="allowed_endpoints"):
        AiBroker(
            endpoint="https://evil.example/v1/messages",
            api_key="k",
            allowed_endpoints=["ai.internal"],
        )
    # An EMPTY allowlist permits NOTHING (not permissive-when-empty like [egress].allowed_http).
    with pytest.raises(AiBrokerError, match="allowed_endpoints"):
        AiBroker(endpoint=_ENDPOINT, api_key="k", allowed_endpoints=[])


def test_endpoint_host_allowlist_matching() -> None:
    assert endpoint_host_allowed("https://ai.internal/x", ["ai.internal"]) is True
    assert endpoint_host_allowed("https://ai.internal:8443/x", ["ai.internal:8443"]) is True
    assert endpoint_host_allowed("https://ai.internal:8443/x", ["ai.internal:9000"]) is False
    assert endpoint_host_allowed("https://other.host/x", ["ai.internal"]) is False
    assert endpoint_host_allowed("https://ai.internal/x", []) is False  # empty => nothing


def test_broker_refuses_cleartext_http_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    # http would put the api_key on the wire in clear -> refused unless the dev escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(AiBrokerError, match="cleartext http"):
        AiBroker(
            endpoint="http://ai.internal/v1/messages",
            api_key="k",
            allowed_endpoints=["ai.internal"],
        )


def test_broker_requires_endpoint_and_key() -> None:
    with pytest.raises(AiBrokerError, match="endpoint"):
        AiBroker(endpoint="", api_key="k", allowed_endpoints=["ai.internal"])
    with pytest.raises(AiBrokerError, match="api_key"):
        AiBroker(endpoint=_ENDPOINT, api_key="", allowed_endpoints=["ai.internal"])


# --- broker plumbing: no-redirect opener, off-loop, no api import ------------


def test_broker_uses_no_redirect_opener_and_no_api_import() -> None:
    broker = ai_broker_from_settings(_managed_ai())
    # Reuses rest.py's shared hardened, TLS-verifying, no-redirect opener (never a bespoke one).
    assert broker._opener is _NO_REDIRECT_OPENER
    # One-way deps (CLAUDE.md §4): the broker MUST NOT import api/. Check actual import STATEMENTS (a
    # docstring may legitimately name the api route it serves), not any textual mention.
    src = Path(ai_broker_mod.__file__).read_text(encoding="utf-8")
    for line in src.splitlines():
        stripped = line.strip()
        assert not stripped.startswith("from messagefoundry.api")
        assert not stripped.startswith("import messagefoundry.api")


async def test_broker_chat_async_runs_off_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # chat_async must run the blocking chat() OFF the event loop via asyncio.to_thread.
    import threading

    broker = ai_broker_from_settings(_managed_ai())
    main_thread = threading.get_ident()
    seen_thread: dict[str, int] = {}

    def fake_chat(self: AiBroker, prompt: str) -> str:
        seen_thread["tid"] = threading.get_ident()
        return "ok"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    reply = await broker.chat_async("prompt")
    assert reply == "ok"
    assert seen_thread["tid"] != main_thread  # ran in a worker thread, not the loop thread


# --- response parsing (Anthropic Messages shape), PHI-/secret-safe -----------


def test_extract_text_concatenates_text_blocks() -> None:
    broker = ai_broker_from_settings(_managed_ai())
    body = json.dumps(
        {"content": [{"type": "text", "text": "hello "}, {"type": "text", "text": "world"}]}
    )
    assert broker._extract_text(body) == "hello world"


def test_extract_text_refusal_raises() -> None:
    broker = ai_broker_from_settings(_managed_ai())
    body = json.dumps({"stop_reason": "refusal", "content": []})
    with pytest.raises(AiBrokerError, match="declined"):
        broker._extract_text(body)


def test_extract_text_unparseable_raises_without_echo() -> None:
    broker = ai_broker_from_settings(_managed_ai())
    with pytest.raises(AiBrokerError) as ei:
        broker._extract_text("<<not json>>")
    # The offending body is never echoed in the error message.
    assert "<<not json>>" not in str(ei.value)


# --- resolve_effective_policy: managed_endpoint never grants phi -------------


def test_managed_endpoint_never_grants_phi() -> None:
    # Even claiming phi on a production instance, managed_endpoint floors at code_only (it is NOT the
    # BAA-managed mode, the only mode the phi-granting branch admits).
    eff = resolve_effective_policy(
        mode=AiMode.MANAGED_ENDPOINT, data_scope=AiDataScope.PHI, production=True
    )
    assert eff.mode is AiMode.MANAGED_ENDPOINT  # mode is never clamped
    assert eff.data_scope is AiDataScope.CODE_ONLY  # never reaches phi
    assert eff.reason is not None


# --- POST /ai/chat: the route ------------------------------------------------


async def test_ai_chat_managed_endpoint_returns_reply(
    engine: Engine, stub_broker: list[str]
) -> None:
    app = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True)
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "write a handler that forwards to OB"})
    assert r.status_code == 200
    body = r.json()
    assert body["reply"].startswith("def handle")
    assert body["model"] == "claude-opus-4-8"
    assert body["data_scope"] == "code_only"  # server-enforced scope, echoed back
    # The server handed the broker exactly the IDE prompt (no server-side widening / PHI injection).
    assert stub_broker == ["write a handler that forwards to OB"]


async def test_ai_chat_ignores_ide_claimed_scope_and_denies_overclaim(
    engine: Engine, stub_broker: list[str]
) -> None:
    app = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True)
    async with _client(app) as c:
        # An IDE CLAIMING phi scope is denied — the server re-resolves and never honours the claim.
        denied = await c.post("/ai/chat", json={"prompt": "hi", "data_scope": "phi"})
        # A synthetic over-claim is likewise denied (engine broker MVP is strictly code_only).
        denied2 = await c.post("/ai/chat", json={"prompt": "hi", "data_scope": "synthetic"})
    assert denied.status_code == 403
    assert denied2.status_code == 403
    # The broker was NEVER called for a denied over-claim (nothing egressed).
    assert stub_broker == []


async def test_ai_chat_is_code_only(engine: Engine, stub_broker: list[str]) -> None:
    # Regardless of mode, the enforced + returned scope is code_only (MVP boundary UNCHANGED).
    app = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True)
    async with _client(app) as c:
        r = await c.post(
            "/ai/chat", json={"prompt": "explain this router", "data_scope": "code_only"}
        )
    assert r.status_code == 200
    assert r.json()["data_scope"] == "code_only"


async def test_ai_chat_audit_records_only_phi_safe_metadata(
    engine: Engine, stub_broker: list[str]
) -> None:
    app = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True)
    secret_prompt = "SECRET-PROMPT-BODY-should-never-be-audited"
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": secret_prompt})
    assert r.status_code == 200
    rows = await engine.store.list_audit(action="ai.assist", limit=10)
    assert len(rows) == 1
    row = rows[0]
    assert row["action"] == "ai.assist"
    detail = json.loads(row["detail"])
    # PHI-safe metadata ONLY.
    assert detail["mode"] == "managed_endpoint"
    assert detail["data_scope"] == "code_only"
    assert detail["provider"] == "claude"
    assert detail["model"] == "claude-opus-4-8"
    assert detail["endpoint_host"] == "ai.internal"
    assert detail["prompt_chars"] == len(secret_prompt)
    assert detail["reply_chars"] > 0
    # The prompt, the reply, and the api_key NEVER appear in the audit row.
    raw = json.dumps(row, default=str)
    assert secret_prompt not in raw
    assert "sk-secret-key-value" not in raw
    assert "def handle" not in raw  # the reply body is not audited


async def test_ai_chat_disabled_when_not_managed_endpoint(
    engine: Engine, stub_broker: list[str]
) -> None:
    # Under byo (the default), the engine-broker route is not the configured path -> 409, no egress.
    app = create_app(
        engine, ai_settings=AiSettings(mode=AiMode.BYO, environment="dev"), allow_no_auth=True
    )
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 409
    assert stub_broker == []


async def test_ai_chat_misconfigured_broker_returns_503(engine: Engine) -> None:
    # managed_endpoint but the endpoint host is NOT allow-listed -> broker refuses -> 503 (not a 500).
    ai = _managed_ai(allowed_endpoints=["other.host"])
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "hi"})
    assert r.status_code == 503


async def test_ai_chat_requires_ai_assist_permission(
    engine: Engine, stub_broker: list[str]
) -> None:
    # Deny-by-default RBAC: a viewer role (no ai:assist) is 403; a coding role is permitted.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    for username, role in (("coder", Role.CODING), ("vw", Role.VIEWER)):
        user_id = await service.create_local_user(
            username=username,
            password=PW,
            display_name=None,
            email=None,
            roles=[role.value],
            actor="test",
        )
        # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
        # fixture still stands for an operator who has been provisioned; the channel axis itself
        # is exercised in tests/test_channel_rbac.py.
        await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
        user = await service.store.get_user(user_id)
        assert user is not None and user.password_hash is not None
        # Admin-created accounts force first-login rotation (WP-L3-12); clear it for a usable login so
        # the require() gate tests the PERMISSION, not the password-change redirect.
        await service.store.set_password(
            user_id, password_hash=user.password_hash, must_change_password=False
        )
    app = create_app(engine, auth=service, ai_settings=_managed_ai())
    async with _client(app) as c:
        vw_tok = (await c.post("/auth/login", json={"username": "vw", "password": PW})).json()[
            "token"
        ]
        coder_tok = (
            await c.post("/auth/login", json={"username": "coder", "password": PW})
        ).json()["token"]
        denied = await c.post(
            "/ai/chat", json={"prompt": "hi"}, headers={"Authorization": f"Bearer {vw_tok}"}
        )
        ok = await c.post(
            "/ai/chat", json={"prompt": "hi"}, headers={"Authorization": f"Bearer {coder_tok}"}
        )
    assert denied.status_code == 403  # viewer lacks ai:assist
    assert ok.status_code == 200  # coding role holds ai:assist


# --- ASVS 4.2.5: outbound length bound --------------------------------------


def test_broker_refuses_an_over_length_api_key() -> None:
    """The key ships as `x-api-key` on every provider call and is operator-supplied via env(), so an
    env value that resolved to an unexpected blob would otherwise surface as an opaque provider-side
    failure on the first chat rather than as a config error.

    Mutation: delete the `find_outbound_length_violation` block in `AiBroker.__init__`. Red: DID NOT
    RAISE. The assertion below also pins that the KEY is never echoed."""
    with pytest.raises(AiBrokerError, match="over the 8192-char limit") as exc:
        AiBroker(endpoint=_ENDPOINT, api_key="k" * 9000, allowed_endpoints=["ai.internal"])
    assert "kkkkkkkkkkkkkkkkkkkk" not in str(exc.value)


def test_broker_refuses_an_over_length_endpoint() -> None:
    with pytest.raises(AiBrokerError, match="over the 8192-char limit"):
        AiBroker(
            endpoint=_ENDPOINT + "?q=" + "a" * 9000,
            api_key="k",
            allowed_endpoints=["ai.internal"],
        )


def test_broker_ordinary_construction_still_works() -> None:
    """Byte-identity control. Mutation: drop MAX_OUTBOUND_URL_LEN to 8 -> this reds."""
    broker = AiBroker(endpoint=_ENDPOINT, api_key="k", allowed_endpoints=["ai.internal"])
    assert broker.endpoint_host == "ai.internal"
