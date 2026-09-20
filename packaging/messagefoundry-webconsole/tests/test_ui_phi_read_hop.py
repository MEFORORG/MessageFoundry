# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1738 -- the ADR 0092 serve-hop refusal was missing on the console's PHI routes.

``enforce_phi_read_hop`` is folded into ``api.security.require_phi_read``, so every JSON PHI-read
route takes it through its ``Depends``. The console reaches ``get_message`` / ``list_messages`` /
``list_dead_letters`` / ``download_attachment`` IN-PROCESS, by reference, which skips that
``Depends`` entirely -- and ``require_ui(..., phi=True)`` re-applied the permission and the per-actor
budget but not the hop refusal. On first deployment a production-PHI instance whose serve hop is not
proven secure would therefore have refused a JSON PHI read and served the same body through ``/ui``.

**This suite is written so a silent no-op cannot pass it.** Each REFUSE assertion is paired with an
ALLOW arm built the same way, differing ONLY in ``phi_read_hop_secure``. A fix that never reaches
``request.app.state.phi_read_hop_disposition`` -- a hardcoded raise, or a gate keyed on something
else -- fails one arm or the other. The disposition is DERIVED by ``create_app`` from the posture
here, never stamped onto ``app.state`` by hand, so the test exercises the shipped seam.

``test_ui_plane_states_the_phi_read_hop_gap`` in the engine's ``tests/test_security_doc_drift.py``
holds the doc side, both ways.

All data here is synthetic.
"""

from __future__ import annotations

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AiSettings, AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms -- satisfies the ASVS policy (WP-3)
ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"

#: The PHI needle. Asserting on this rather than only on a status code is what makes a REFUSE arm
#: mean "the body did not leave" instead of "some 403 happened".
NEEDLE = "DOE^JANE"


async def _service(engine: Engine) -> AuthService:
    # require_mfa=False for the same reason the sibling /ui suites pin it: these tests exercise the
    # hop refusal, not MFA enrollment, and an unenrolled session would otherwise divert to /ui/account.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService, *, secure_hop: bool) -> httpx.AsyncClient:
    """A real mounted console on a PRODUCTION-PHI instance, whose serve hop is or is not proven
    secure. ``secure_hop`` is the ONLY variable between the two arms of every test below."""
    app = create_app(
        engine,
        auth=service,
        serve_ui=True,
        ai_settings=AiSettings(environment="prod"),
        phi_read_hop_secure=secure_hop,
    )
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login(c: httpx.AsyncClient, username: str = "op") -> None:
    r = await c.post("/ui/login", data={"username": username, "password": PW})
    assert r.status_code in (200, 303), r.status_code


async def _seed(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


#: The seventh ``phi=True`` route, and the only non-GET one, so it is exercised on its own below
#: rather than in the GET loop. It rides ``require_ui_step_up`` like ``/edit`` does.
EDIT_RESEND = "/ui/messages/{}/edit-resend"


def _phi_routes(message_id: str) -> list[str]:
    """The six GET-reachable console routes whose gate passes ``phi=True``, derived by reading
    ``messagefoundry_webconsole/routes/core.py``. With :data:`EDIT_RESEND` that is SEVEN in all.

    Seven, not the four handlers BACKLOG #1738 names: ``parse-tree`` reaches ``get_message`` too, and
    the edit pair rides ``require_ui_step_up``, which builds its base as ``require_ui(*perms,
    phi=phi, ...)`` -- so a call placed in ``require_ui``'s ``phi`` arm covers the pair with no call
    site of its own. That forwarding is why the pair is asserted here rather than assumed."""
    return [
        "/ui/messages",
        f"/ui/messages/{message_id}",
        f"/ui/messages/{message_id}/parse-tree",
        f"/ui/messages/{message_id}/attachments/deadbeef",
        "/ui/dead-letters",
        f"/ui/messages/{message_id}/edit",
    ]


async def test_an_unproven_serve_hop_refuses_every_ui_phi_route(engine: Engine) -> None:
    """The REFUSE arm. A production-PHI instance over an unproven hop 403s the whole set, and the
    PHI body never reaches the response."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c)
        for path in _phi_routes(mid):
            r = await c.get(path)
            assert r.status_code == 403, f"{path} was not refused: {r.status_code}"
            assert "PHI read refused" in r.text, f"{path} refused for some other reason: {r.text}"
            assert NEEDLE not in r.text, f"{path} leaked the body on its refusal"


async def test_the_edit_resend_post_is_refused_before_it_reads_the_stored_body(
    engine: Engine,
) -> None:
    """The seventh route, and the one a GET-only loop would miss.

    ``POST /ui/messages/{id}/edit-resend`` re-reads the PRISTINE stored copy on its reject path, so it
    emits PHI exactly as the GET editor does. It gets the refusal from the same ``phi`` arm, and it
    gets it in the DEPENDENCY -- before the route body parses the form or re-reads the message."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    headers = {"Sec-Fetch-Site": "same-origin"}
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c)
        r = await c.post(EDIT_RESEND.format(mid), data={"raw": ADT}, headers=headers)
        assert r.status_code == 403, r.status_code
        assert "PHI read refused" in r.text, r.text
        assert NEEDLE not in r.text
    # Control: the same POST over a proven hop is not refused on posture. It may still be turned away
    # for a stale step-up window, which is a different gate and not this test's subject.
    async with _client(engine, service, secure_hop=True) as c:
        await _login(c)
        ok = await c.post(EDIT_RESEND.format(mid), data={"raw": ADT}, headers=headers)
        assert "PHI read refused" not in ok.text, ok.text


async def test_a_proven_serve_hop_still_serves_the_same_routes(engine: Engine) -> None:
    """The ALLOW control arm, and the half that makes the test above mean something.

    Without it a fix that refuses UNCONDITIONALLY -- or one that never reads
    ``request.app.state.phi_read_hop_disposition`` at all and raises on every ``phi=True`` request --
    passes the REFUSE arm perfectly while breaking the console outright. The two apps differ in
    exactly one constructor argument."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=True) as c:
        await _login(c)
        for path in _phi_routes(mid):
            r = await c.get(path)
            assert r.status_code != 403, f"{path} was refused over a PROVEN hop: {r.status_code}"
        # The browse pair actually renders, so the ALLOW arm is a served page and not merely a
        # non-403: a redirect everywhere would satisfy the loop above.
        listing = await c.get("/ui/messages")
        assert listing.status_code == 200, listing.status_code
        detail = await c.get(f"/ui/messages/{mid}")
        assert detail.status_code == 200, detail.status_code
        assert NEEDLE in detail.text, "the raw view served no body over a proven hop"


async def test_the_refusal_lands_after_identity_so_a_visitor_still_gets_the_login_page(
    engine: Engine,
) -> None:
    """THE PLACEMENT, which is a decision the row did not make and the code now does.

    The JSON plane refuses BEFORE any identity work. The console must not: a browser with no session
    has to reach ``/ui/login``, and refusing first would answer an unauthenticated ``GET
    /ui/messages`` with a 403 whose message names the instance's serve-hop posture -- handing an
    anonymous visitor a configuration read the JSON plane never gives them (it answers 401 either
    way). So the call sits inside the ``phi`` block, below the session check and the permission loop.

    Pinned because the two orders are indistinguishable on an AUTHENTICATED request, which is every
    other test in this file."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=False) as c:
        for path in _phi_routes(mid):  # no login: this client holds no session cookie
            r = await c.get(path, follow_redirects=False)
            assert r.status_code == 303, (
                f"{path} did not redirect an anonymous visitor: {r.status_code}"
            )
            assert r.headers["location"].startswith("/ui/login"), r.headers["location"]
            assert "PHI read refused" not in r.text, f"{path} disclosed the posture to a visitor"


async def test_a_forbidden_actor_is_still_refused_on_permission_not_on_posture(
    engine: Engine,
) -> None:
    """The same ordering, one rung further in: the permission loop runs BEFORE the hop guard, so an
    actor who lacks ``messages:view_raw`` learns nothing about the serve hop either.

    A VIEWER holds ``messages:read`` and not ``messages:view_raw``, so the raw view is a plain
    authorization refusal on both hop postures."""
    service = await _service(engine)
    await _add(service, "vw", Role.VIEWER)
    mid = await _seed(engine)
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c, "vw")
        r = await c.get(f"/ui/messages/{mid}")
        assert r.status_code == 403, r.status_code
        assert "PHI read refused" not in r.text, "posture disclosed to an unauthorized actor"
        assert NEEDLE not in r.text


#: Two routes an OPERATOR can actually reach, so a 403 here can only come from the hop guard. Not
#: ``/ui/audit``: it needs ``audit:read``, which the operator role does not hold, so it answers 403
#: from the permission loop on BOTH hop postures and would report a creeping guard that is not there.
@pytest.mark.parametrize("path", ["/ui", "/ui/connections"])
async def test_a_non_phi_console_route_is_untouched_by_the_refusal(
    engine: Engine, path: str
) -> None:
    """The guard is bound to the ``phi=True`` arm, so it must not creep onto the rest of the console.

    An operator on a refusing instance still monitors it -- the refusal withholds message BODIES, not
    the whole operator surface. A fix placed above the ``phi`` block would 403 these and nothing else
    in this file would notice."""
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service, secure_hop=False) as c:
        await _login(c)
        r = await c.get(path)
        assert r.status_code == 200, (
            f"{path} was refused on a PHI-refusing instance: {r.status_code}"
        )
