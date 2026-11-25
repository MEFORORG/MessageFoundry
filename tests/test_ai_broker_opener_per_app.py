# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The AI broker's anchored opener is held per app, not in one slot for the process (BACKLOG #5527
items 3 to 5), its refusal remedies are written as they are logged (item 13), and each caller of
the opener chooser is a revocation-census site (item 22).

Before this, ``transports/ai_broker.py`` held one module-global slot keyed on the resolved
anchor: two apps with different ``[tls]`` policies evicted each other's opener on alternate
requests, an app whose anchor stopped narrowing left the old opener held, and the opener outlived
the app that built it. The route tests drive ``POST /ai/chat`` and read which opener each request
dialled, or whether a context the route held is still alive; the others build a broker directly
or read the source and the census. Each failed on its assertion against the code before the fix,
run with this file's helper modules at their versions before it too. All certificates, CRLs,
endpoints and keys are synthetic.
"""

from __future__ import annotations

import gc
import inspect
import ssl
import urllib.request
import weakref

import pytest

from messagefoundry.api import create_app
from messagefoundry.config import loaded_crls
from messagefoundry.config.settings import TlsSettings
from messagefoundry.config.tls_policy import TrustAnchorPolicy
from messagefoundry.pipeline import Engine
from messagefoundry.transports import ai_broker as ai_broker_mod
from messagefoundry.transports.ai_broker import AiBroker
from tests.test_ai_broker_revocation_guard import (  # noqa: F401  # fixtures, used by name
    _ENFORCING,
    _broker,
    _client,
    _context,
    _fresh_crossings,
    _managed_ai,
    _Pki,
    engine,
    pki,
)
from tests.test_revocation_guard_census import _scan


def _record_openers(monkeypatch: pytest.MonkeyPatch) -> list[urllib.request.OpenerDirector]:
    """Stand in for the provider POST, recording the opener each request's broker dials with."""
    dialled: list[urllib.request.OpenerDirector] = []

    def fake_chat(self: AiBroker, prompt: str) -> str:
        dialled.append(self._opener)
        return "synthetic reply"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    return dialled


def _record_contexts(monkeypatch: pytest.MonkeyPatch) -> list[weakref.ref[ssl.SSLContext]]:
    """Stand in for the provider POST, recording a WEAK reference to each dialled context, so the
    record itself keeps nothing alive."""
    seen: list[weakref.ref[ssl.SSLContext]] = []

    def fake_chat(self: AiBroker, prompt: str) -> str:
        seen.append(weakref.ref(_context(self)))
        return "synthetic reply"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    return seen


def _still_held(ref: weakref.ref[ssl.SSLContext]) -> bool:
    """Whether the context is alive and recorded as a live CRL copy, after a full collection.
    ``OpenerDirector`` and its handlers form a reference cycle, so only the cyclic collector frees
    a dropped opener."""
    gc.collect()
    ctx = ref()
    return ctx is not None and any(held is ctx for held, _ in loaded_crls.held_contexts())


async def _chat(app: object) -> int:
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "synthetic prompt"})
    return r.status_code


async def test_two_apps_each_hold_their_own_anchored_opener(
    engine: Engine,  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
    pki: _Pki,  # noqa: F811 - the imported fixture
) -> None:
    """Items 4, 20, 30 and 37: two apps in one process with different narrowing ``[tls]``
    policies, called alternately, each keep dialling the one opener built for them. Red before the
    fix: the process held one slot, so each request evicted the other app's opener and rebuilt its
    own, re-reading the CA and CRL files."""
    dialled = _record_openers(monkeypatch)
    crl_only = TlsSettings(crl_file=pki.crl_file)
    pinned = TlsSettings(
        internal_ca_file=pki.ca_file, trust_anchor_mode="pinned", crl_file=pki.crl_file
    )
    first = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True, tls_settings=crl_only)
    second = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True, tls_settings=pinned)
    for app in (first, second, first, second):
        assert await _chat(app) == 200
    assert len(dialled) == 4
    assert dialled[0] is dialled[2]
    assert dialled[1] is dialled[3]
    assert dialled[0] is not dialled[1]


async def test_an_app_whose_anchor_stops_narrowing_lets_its_held_context_go(
    engine: Engine,  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
    pki: _Pki,  # noqa: F811 - the imported fixture
) -> None:
    """Items 3 and 29: once an app's ``[tls]`` policy narrows nothing, the route dials the shared
    opener and the app no longer holds the anchored one, so its context and its ``loaded_crls``
    record go, and the expiry monitor and ``crl_reload`` stop judging a copy no handshake uses.
    Red before the fix: the slot was left as it was, so the context stayed held."""
    seen = _record_contexts(monkeypatch)
    ai = _managed_ai(
        endpoint_revocation_attested=True,
        endpoint_revocation_attested_reason="synthetic: covered elsewhere",
    )
    app = create_app(
        engine, ai_settings=ai, allow_no_auth=True, tls_settings=TlsSettings(crl_file=pki.crl_file)
    )
    assert await _chat(app) == 200
    assert _still_held(seen[0])  # the control: held while the app's anchor narrows
    app.state.tls_settings = TlsSettings()
    assert await _chat(app) == 200
    assert not _still_held(seen[0])


async def test_nothing_outside_the_app_holds_its_anchored_opener(
    engine: Engine,  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
    pki: _Pki,  # noqa: F811 - the imported fixture
) -> None:
    """Items 5 and 31: no process-wide holder keeps the opener the route built; once its request
    is done, the app's own state holds it alone. Dropping what the app holds there, as dropping the
    app does, lets the context and its CRL record go. (The app itself is not dropped here: its
    routes' closures keep it in cycles this test does not control.) Red before the fix: a
    module-global slot kept the opener for the rest of the process, whatever the app held."""
    seen = _record_contexts(monkeypatch)
    app = create_app(
        engine,
        ai_settings=_managed_ai(),
        allow_no_auth=True,
        tls_settings=TlsSettings(crl_file=pki.crl_file),
    )
    assert await _chat(app) == 200
    assert _still_held(seen[0])  # the control: held while the app holds it
    app.state.ai_opener_slot = None
    assert not _still_held(seen[0])


def test_a_broker_built_with_no_app_slot_holds_no_opener(
    pki: _Pki,  # noqa: F811 - the imported fixture
) -> None:
    """A broker built directly, with no app's slot, builds an opener for itself and holds it
    nowhere, so a later broker in the same process does not inherit it. Red before the fix: the
    module-global slot handed the second broker the first one's opener."""
    crl = TrustAnchorPolicy(crl_file=pki.crl_file)
    first = _broker(posture=_ENFORCING, policy=crl)
    second = _broker(posture=_ENFORCING, policy=crl)
    assert first._opener is not second._opener
    assert _context(second).verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    # Held nowhere: once both brokers are dropped, neither context is alive or recorded.
    refs = [weakref.ref(_context(first)), weakref.ref(_context(second))]
    assert all(_still_held(ref) for ref in refs)  # the control: recorded while the brokers live
    del first, second
    assert not any(_still_held(ref) for ref in refs)


def test_each_attestation_remedy_is_written_as_it_is_logged() -> None:
    """Item 13 (and 26, 43): each remedy is written out in the source, so a grep for the logged
    opening words of either finds it, and no text is made by upper-casing another. Red before the
    fix: the text began "set [ai]..." and the code upper-cased it."""
    opening = "Set [ai].endpoint_revocation_attested = true with an "
    assert ai_broker_mod._AI_ATTESTATION_LEVER.startswith(opening)
    # The CRL remedy ends with the same attestation remedy, so the two cannot drift apart.
    tail = ai_broker_mod._AI_ATTESTATION_LEVER[1:]
    assert ai_broker_mod._AI_CRL_LEVER.endswith(", or s" + tail)
    assert ".upper()" not in inspect.getsource(ai_broker_mod._revocation_lever)
    with pytest.raises(ai_broker_mod.AiBrokerError) as info:
        _broker(posture=_ENFORCING)
    assert "Set [ai].endpoint_revocation_attested = true with an " in str(info.value)


def test_the_on_box_remedy_names_the_hosts_the_code_reads_as_loopback() -> None:
    """The refusal's last remedy names endpoint hosts the refusal reads as on-box, and the
    spellings it reads as remote, so following it crosses the refusal. Red before the fix: it said
    "use an endpoint on this machine", and a resolver may take ``localhost.`` or ``127.0.0.1.`` as
    this box, yet each is read as remote and refused with that same remedy."""
    named = ("localhost", "127.0.0.1", "[::1]")
    # Not an exhaustive list: other spellings the predicate reads as loopback cross too.
    also_loopback = ("LOCALHOST", "127.0.0.2", "[0:0:0:0:0:0:0:1]")
    near_misses = ("localhost.", "127.0.0.1.", "127.1")
    for lever in (ai_broker_mod._AI_ATTESTATION_LEVER, ai_broker_mod._AI_CRL_LEVER):
        assert "this machine" not in lever
        assert (
            "at least a spelling with a trailing dot, or a shortened IPv4 address such as 127.1"
            in lever
        )
        assert "whose host reads as loopback here, such as localhost, 127.0.0.1 or [::1]" in lever
        assert "with its host listed in [ai].allowed_endpoints" in lever
    # Each host the remedy names builds under an enforcing posture, with no CRL or attestation.
    for host in named + also_loopback:
        _broker(
            endpoint=f"https://{host}/v1/messages",
            allowed=(host,),
            posture=_ENFORCING,
        )
    # Each spelling the remedy says reads as remote is refused, with either remedy text.
    for host in near_misses:
        for policy, lever in (
            (None, ai_broker_mod._AI_ATTESTATION_LEVER),
            (TrustAnchorPolicy(), ai_broker_mod._AI_CRL_LEVER),
        ):
            with pytest.raises(ai_broker_mod.AiBrokerError) as info:
                _broker(
                    endpoint=f"https://{host}/v1/messages",
                    allowed=(host,),
                    posture=_ENFORCING,
                    policy=policy,
                )
            assert str(info.value).endswith(lever), str(info.value)


def test_each_caller_of_the_ai_opener_chooser_is_a_census_site() -> None:
    """Items 22 and 32: the revocation census treats ``_ai_endpoint_opener`` as a builder, so the
    function that calls it is the site, tied to its own guard call, and a new caller fails the
    census until it is listed. Red before the fix: ``_endpoint_opener`` was the site, guarded by
    one named caller, so a second caller dialled with no guard and the census stayed green."""
    sites = _scan().sites
    assert "messagefoundry/transports/ai_broker.py::AiBroker.__init__" in sites
    assert "messagefoundry/transports/ai_broker.py::_ai_endpoint_opener" not in sites


async def test_an_opener_slot_of_another_type_answers_503(
    engine: Engine,  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An embedder that overwrites ``app.state.ai_opener_slot`` with something else, ``None``
    included, is refused as a misconfiguration, as a ``tls_settings`` stash of another type is,
    rather than built around with a fresh opener on every request. Nothing is sent. The endpoint
    is attested, so the slot is the only reason for the 503: the same app answers 200 first."""
    dialled = _record_openers(monkeypatch)
    ai = _managed_ai(
        endpoint_revocation_attested=True,
        endpoint_revocation_attested_reason="synthetic: covered elsewhere",
    )
    app = create_app(engine, ai_settings=ai, allow_no_auth=True)
    assert await _chat(app) == 200  # the control: the slot create_app set
    for other in (object(), None):
        app.state.ai_opener_slot = other
        assert await _chat(app) == 503
    assert len(dialled) == 1
