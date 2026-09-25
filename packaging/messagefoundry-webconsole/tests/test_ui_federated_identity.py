# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1143 / #295 (ADR 0184 slice B): the console screen that links, relinks and unlinks a
federated identity.

The JSON routes (``PUT`` and ``DELETE /users/{user_id}/federated-identity``) are the engine's only
binding path, pinned in ``tests/test_auth_federated_identity_routes.py``. The console calls the SAME
handlers by reference, which skips their ``require_step_up_action`` dependency, so the console route
has to re-assert it. That re-assertion is what these tests carry the weight on:

- **A POST with no grant bound to ``admin_federated_identity`` is refused and writes nothing.** Each
  refusal test is paired with the same POST succeeding after ``/ui/reauth`` mints that grant, so a
  gate broken to deny everything fails here as surely as one broken to allow everything.
- **The login window alone does not open it.** Every POST below is made from a session whose login
  step-up window is fresh, which is exactly what a window-only gate would accept. The one exception
  is the opt-out test, which pins that ``[auth].require_action_step_up = false`` falls back to that
  window here as it does on the JSON twin.

Also here: the page renders the stored pair, refuses the caller's own account, refuses a page that
went stale, shows each service refusal in words, and escapes what it renders.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import uuid4

import httpx
import pytest
from _ui_clients import PW, SAME_ORIGIN, cookie_login, provision, ui_client

from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

ISSUER = "https://idp.example"

#: The route's refusal for a page that no longer shows the stored pair.
CHANGED = "The link changed after this page was opened"

#: What that refusal says about a retry: the POST already spent its single-use grant.
RETRY = "A retry may ask you to re-authenticate first."


async def _service(engine: Engine, **over: object) -> AuthService:
    """MFA off, as the other console suites run, and the issuer the bind requires set."""
    settings: dict[str, object] = {"require_mfa": False, "oidc_issuer": ISSUER}
    settings.update(over)
    service = AuthService(engine.store, AuthSettings(**settings))  # type: ignore[arg-type]
    await service.initialize()
    return service


async def _ad_account(engine: Engine, username: str = "jdoe", *, object_id: bool = True) -> str:
    """A directory mirror row, as a Kerberos sign-in through a directory returning objectGUID
    leaves it: unbound, and carrying its immutable id (BACKLOG #1143 slice C). ``object_id=False``
    is the row a directory with no readable objectGUID leaves, which cannot take a binding."""
    user_id = uuid4().hex
    await engine.store.create_user(
        user_id=user_id,
        username=username,
        auth_provider="ad",
        directory_object_id=f"guid-{username}" if object_id else None,
    )
    return user_id


async def _pair(engine: Engine, user_id: str) -> tuple[str | None, str | None]:
    user = await engine.store.get_user(user_id)
    assert user is not None
    return user.oidc_issuer, user.oidc_subject


async def _shown(engine: Engine, user_id: str, **fields: str) -> dict[str, str]:
    """A form body carrying the pair a freshly opened page would show, plus ``fields``."""
    issuer, subject = await _pair(engine, user_id)
    return {"shown_issuer": issuer or "", "shown_subject": subject or "", **fields}


async def _mint(c: httpx.AsyncClient, next_path: str) -> None:
    """Re-authenticate through /ui/reauth for ``next_path``, which mints the grant its tag names.

    Asserts the re-auth LANDED back on that page. A continuation /ui/reauth does not recognise
    bounces to /ui instead, and a test that minted nothing would then read as a refusal."""
    r = await c.post("/ui/reauth", data={"next": next_path, "password": PW}, headers=SAME_ORIGIN)
    assert r.status_code == 303 and r.headers["location"] == next_path, (r.status_code, r.headers)


def _screen(user_id: str) -> str:
    return f"/ui/users/{user_id}/federated-identity"


@pytest.fixture
async def boss(engine: Engine) -> AsyncIterator[tuple[httpx.AsyncClient, AuthService]]:
    """A browser signed in as an administrator, over a service with the issuer configured."""
    service = await _service(engine)
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    async with ui_client(engine, service) as c:
        await cookie_login(c, "root")
        yield c, service


# --- the screen renders the binding ----------------------------------------------------------------


async def test_the_screen_says_not_linked_then_shows_the_stored_pair(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await _ad_account(engine)

    before = await c.get(_screen(target))
    assert before.status_code == 200
    assert "Not linked" in before.text
    assert f'action="{_screen(target)}/link"' in before.text
    assert ">Link</button>" in before.text
    assert f"The issuer is {ISSUER}." in before.text
    assert "Relinking signs the account out" not in before.text
    assert "unlink-confirm" not in before.text, "an unlinked account was offered an unlink"

    await service.bind_federated_subject(target, "S-1-pair", actor="test")
    after = await c.get(_screen(target))
    assert after.status_code == 200
    assert "Not linked" not in after.text
    assert ISSUER in after.text and "S-1-pair" in after.text
    assert ">Relink</button>" in after.text
    assert "Relinking signs the account out of every session." in after.text
    assert f'href="{_screen(target)}/unlink-confirm"' in after.text
    assert 'name="shown_subject" value="S-1-pair"' in after.text

    # The user's own page states the same pair and links here.
    detail = await c.get(f"/ui/users/{target}")
    assert detail.status_code == 200
    assert "S-1-pair" in detail.text and f'href="{_screen(target)}"' in detail.text


async def test_a_local_account_is_offered_no_link_form(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    local = await provision(service, "loc", [Role.VIEWER.value])
    page = await c.get(_screen(local))
    assert page.status_code == 200
    assert "Only a directory (AD) account can be linked. This is a local account." in page.text
    assert f'action="{_screen(local)}/link"' not in page.text


async def test_no_issuer_means_no_link_form_and_the_post_is_refused_in_words(
    engine: Engine,
) -> None:
    service = await _service(engine, oidc_issuer="")
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    target = await _ad_account(engine)
    async with ui_client(engine, service) as c:
        await cookie_login(c, "root")
        page = await c.get(_screen(target))
        assert "Linking needs [auth].oidc_issuer" in page.text
        assert f'action="{_screen(target)}/link"' not in page.text
        # The page decides only what is offered. The POST still reaches the service's refusal.
        await _mint(c, _screen(target))
        r = await c.post(
            f"{_screen(target)}/link",
            data=await _shown(engine, target, subject="S-1"),
            headers=SAME_ORIGIN,
        )
    assert r.status_code == 400 and "no OIDC issuer is configured" in r.text
    assert await _pair(engine, target) == (None, None)


async def test_get_users_does_not_carry_the_pair(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    """``GET /users`` needs only users:read, so the pair must not ride on it. The control is the
    console screen above, which states the same pair under users:manage."""
    c, service = boss
    target = await _ad_account(engine)
    await service.bind_federated_subject(target, "S-1-hidden", actor="test")
    token = (await c.post("/auth/login", json={"username": "root", "password": PW})).json()["token"]
    resp = await c.get("/users", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "S-1-hidden" not in resp.text
    assert any(r["id"] == target for r in resp.json()), "the control row is missing"


async def test_an_unknown_user_is_404(boss: tuple[httpx.AsyncClient, AuthService]) -> None:
    c, _service = boss
    assert (await c.get(_screen("no-such-user"))).status_code == 404
    assert (await c.get(f"{_screen('no-such-user')}/unlink-confirm")).status_code == 404


# --- link and unlink need the action-bound step-up --------------------------------------------------


async def test_link_is_refused_without_the_grant_and_succeeds_with_it(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, _service = boss
    target = await _ad_account(engine)
    link = f"{_screen(target)}/link"
    body = await _shown(engine, target, subject="S-1-a")

    # No grant, on a session whose login window is fresh: refused, back to the screen, not written.
    bare = await c.post(link, data=body, headers=SAME_ORIGIN)
    assert bare.status_code == 303
    assert bare.headers["location"] == f"/ui/reauth?next={_screen(target)}"
    assert await _pair(engine, target) == (None, None), "a refused POST wrote a binding"

    # A grant for ANOTHER action does not open it either.
    await _mint(c, f"/ui/users/{target}")  # the user page's tag: admin_user_update
    wrong = await c.post(link, data=body, headers=SAME_ORIGIN)
    assert wrong.status_code == 303 and "/ui/reauth" in wrong.headers["location"]
    assert await _pair(engine, target) == (None, None), "another action's grant opened the link"

    # CONTROL: the grant for THIS action lets the same request through.
    await _mint(c, _screen(target))
    ok = await c.post(link, data=body, headers=SAME_ORIGIN)
    assert ok.status_code == 303
    assert ok.headers["location"] == f"{_screen(target)}?m=linked"
    assert await _pair(engine, target) == (ISSUER, "S-1-a")
    rows = await engine.store.list_audit(action="auth.federated_subject_bound", limit=100)
    assert [r["actor"] for r in rows] == ["root"]

    # SINGLE USE: the grant is spent, so a second POST bounces again and writes nothing.
    again = await c.post(
        link, data=await _shown(engine, target, subject="S-1-b"), headers=SAME_ORIGIN
    )
    assert again.status_code == 303 and "/ui/reauth" in again.headers["location"]
    assert await _pair(engine, target) == (ISSUER, "S-1-a")

    landed = await c.get(ok.headers["location"])
    assert "Linked. A federated sign-in with this subject now reaches this account." in landed.text


async def test_relink_moves_the_pair_and_says_so(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await _ad_account(engine)
    await service.bind_federated_subject(target, "S-1-old", actor="test")
    await _mint(c, _screen(target))
    r = await c.post(
        f"{_screen(target)}/link",
        data=await _shown(engine, target, subject="S-1-new"),
        headers=SAME_ORIGIN,
    )
    assert r.status_code == 303 and r.headers["location"] == f"{_screen(target)}?m=relinked"
    assert await _pair(engine, target) == (ISSUER, "S-1-new")
    landed = (await c.get(r.headers["location"])).text
    assert "Relinked." in landed and "sessions were signed out" in landed


async def test_unlink_is_refused_without_the_grant_and_succeeds_after_confirm(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await _ad_account(engine)
    await service.bind_federated_subject(target, "S-1-gone", actor="test")
    unlink = f"{_screen(target)}/unlink"
    confirm = f"{_screen(target)}/unlink-confirm"
    body = await _shown(engine, target)

    # No grant: refused, and sent to the CONFIRM page, never auto-re-POSTed.
    bare = await c.post(unlink, data=body, headers=SAME_ORIGIN)
    assert bare.status_code == 303 and bare.headers["location"] == f"/ui/reauth?next={confirm}"
    assert await _pair(engine, target) == (ISSUER, "S-1-gone"), "a refused POST unlinked"

    # The confirm step states the consequence and carries the one form that acts.
    page = await c.get(confirm)
    assert page.status_code == 200
    assert "signs jdoe out of every session" in page.text
    assert f'action="{unlink}"' in page.text
    assert 'name="shown_subject" value="S-1-gone"' in page.text

    # CONTROL: the grant for this action, minted on the confirm page, lets the same POST through.
    await _mint(c, confirm)
    ok = await c.post(unlink, data=body, headers=SAME_ORIGIN)
    assert ok.status_code == 303 and ok.headers["location"] == f"{_screen(target)}?m=unlinked"
    assert await _pair(engine, target) == (None, None)
    rows = await engine.store.list_audit(action="auth.federated_subject_unbound", limit=100)
    assert [r["actor"] for r in rows] == ["root"]
    assert "Unlinked." in (await c.get(ok.headers["location"])).text


async def test_the_opt_out_falls_back_to_the_login_window_as_the_json_twin_does(
    engine: Engine,
) -> None:
    """``[auth].require_action_step_up = false`` is a documented, audited posture choice. Under it
    the console lane takes the session window, exactly as ``require_step_up_action`` does on the
    JSON route, so this pins the fallback rather than hiding it. Its control is the default-on
    refusal in the tests above."""
    service = await _service(engine, require_action_step_up=False)
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    target = await _ad_account(engine)
    async with ui_client(engine, service) as c:
        await cookie_login(c, "root")
        r = await c.post(
            f"{_screen(target)}/link",
            data=await _shown(engine, target, subject="S-1-w"),
            headers=SAME_ORIGIN,
        )
    assert r.status_code == 303 and r.headers["location"] == f"{_screen(target)}?m=linked"
    assert await _pair(engine, target) == (ISSUER, "S-1-w")


# --- a page that went stale -------------------------------------------------------------------------


async def test_a_link_from_a_stale_page_is_refused_and_keeps_the_other_binding(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    """The operator's page said "Not linked"; another administrator linked the account since. A
    Link from that page must not replace a binding its operator never saw."""
    c, service = boss
    target = await _ad_account(engine)
    stale = await _shown(engine, target, subject="S-1-mine")
    await service.bind_federated_subject(target, "S-1-theirs", actor="other-admin")

    await _mint(c, _screen(target))
    r = await c.post(f"{_screen(target)}/link", data=stale, headers=SAME_ORIGIN)
    assert r.status_code == 409 and CHANGED in r.text
    assert RETRY in r.text, "the refusal must say a retry may re-authenticate first"
    assert "submit again" not in r.text, "the spent grant means a retry is not one submit"
    assert "S-1-theirs" in r.text, "the refusal page must show the current link"
    assert await _pair(engine, target) == (ISSUER, "S-1-theirs")

    # The premise RETRY rests on: the 409 already spent the grant, so a retry bounces.
    fresh = await _shown(engine, target, subject="S-1-mine")
    again = await c.post(f"{_screen(target)}/link", data=fresh, headers=SAME_ORIGIN)
    assert again.status_code == 303 and "/ui/reauth" in again.headers["location"]
    assert await _pair(engine, target) == (ISSUER, "S-1-theirs")

    # A POST carrying no shown pair at all is refused the same way.
    await _mint(c, _screen(target))
    bare = await c.post(f"{_screen(target)}/link", data={"subject": "S-1-x"}, headers=SAME_ORIGIN)
    assert bare.status_code == 409 and CHANGED in bare.text and RETRY in bare.text
    assert await _pair(engine, target) == (ISSUER, "S-1-theirs")


async def test_an_unlink_from_a_stale_confirm_page_is_refused(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await _ad_account(engine)
    await service.bind_federated_subject(target, "S-1-p1", actor="test")
    stale = await _shown(engine, target)
    await service.bind_federated_subject(target, "S-1-p2", actor="other-admin")

    await _mint(c, f"{_screen(target)}/unlink-confirm")
    r = await c.post(f"{_screen(target)}/unlink", data=stale, headers=SAME_ORIGIN)
    assert r.status_code == 409 and CHANGED in r.text and RETRY in r.text
    assert await _pair(engine, target) == (ISSUER, "S-1-p2"), "a stale page removed a binding"


# --- own account -------------------------------------------------------------------------------------


async def test_an_admin_cannot_change_their_own_link(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    """Refused by the API handler's own self-check, reached through the console. The message is the
    handler's, which tells it apart from the service's local-account refusal this account would
    otherwise meet (``root`` is a local account)."""
    c, _service = boss
    me = (await engine.store.get_user_by_username("root")).id  # type: ignore[union-attr]

    screen = await c.get(_screen(me))
    assert screen.status_code == 200
    assert "Another administrator must change your own link" in screen.text
    assert f'action="{_screen(me)}/link"' not in screen.text, "own account was offered a link"
    assert "unlink-confirm" not in screen.text, "own account was offered an unlink"
    confirm = await c.get(f"{_screen(me)}/unlink-confirm")
    assert "Another administrator must change your own link" in confirm.text
    assert f'action="{_screen(me)}/unlink"' not in confirm.text

    await _mint(c, _screen(me))
    link = await c.post(
        f"{_screen(me)}/link", data=await _shown(engine, me, subject="S-1-me"), headers=SAME_ORIGIN
    )
    assert link.status_code == 400
    assert "another administrator must change your own binding" in link.text

    await _mint(c, f"{_screen(me)}/unlink-confirm")
    unlink = await c.post(
        f"{_screen(me)}/unlink", data=await _shown(engine, me), headers=SAME_ORIGIN
    )
    assert unlink.status_code == 400
    assert "another administrator must change your own binding" in unlink.text
    assert await _pair(engine, me) == (None, None)


# --- the service's refusals, in words ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "subject", "status", "words"),
    [
        ("held", "S-1-held", 409, "already bound to another account"),
        ("spaces", " S-1-a ", 400, "printable ASCII, no surrounding spaces"),
        ("control", "S-1\x07a", 400, "printable ASCII, no surrounding spaces"),
        ("empty", "", 400, "1 to 255 characters"),
        ("too long", "S" * 256, 400, "1 to 255 characters"),
        ("same pair", "S-1-mine", 400, "already holds that identity"),
        ("local", "S-1-a", 400, "only a directory (AD) account"),
        # BACKLOG #1143 slice C: the engine's refusal reaches the page through the same mapping.
        (
            "no object id",
            "S-1-a",
            400,
            "directory_object_id_missing: this account has no immutable",
        ),
    ],
)
async def test_each_link_refusal_is_shown_in_words_and_writes_nothing(
    engine: Engine,
    boss: tuple[httpx.AsyncClient, AuthService],
    case: str,
    subject: str,
    status: int,
    words: str,
) -> None:
    c, service = boss
    if case == "local":
        target = await provision(service, "loc", [Role.VIEWER.value])
    elif case == "no object id":
        target = await _ad_account(engine, object_id=False)
    else:
        target = await _ad_account(engine)
    if case == "held":
        other = await _ad_account(engine, "holder")
        await service.bind_federated_subject(other, "S-1-held", actor="test")
    if case == "same pair":
        await service.bind_federated_subject(target, "S-1-mine", actor="test")
    before = await _pair(engine, target)

    await _mint(c, _screen(target))
    r = await c.post(
        f"{_screen(target)}/link",
        data=await _shown(engine, target, subject=subject),
        headers=SAME_ORIGIN,
    )
    assert r.status_code == status, (case, r.status_code, r.text[:300])
    assert words in r.text, case
    assert await _pair(engine, target) == before, f"{case}: a refused link moved the pair"


async def test_unlink_of_an_unlinked_account_is_refused_in_words(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, _service = boss
    target = await _ad_account(engine)
    confirm = await c.get(f"{_screen(target)}/unlink-confirm")
    assert "This account has no federated link to remove." in confirm.text
    assert f'action="{_screen(target)}/unlink"' not in confirm.text
    # A hand-made POST still reaches the service, which refuses it.
    await _mint(c, f"{_screen(target)}/unlink-confirm")
    r = await c.post(
        f"{_screen(target)}/unlink", data=await _shown(engine, target), headers=SAME_ORIGIN
    )
    assert r.status_code == 400 and "no federated binding to remove" in r.text


# --- escaping ----------------------------------------------------------------------------------------

EVIL_NAME = "<script>alert('n')</script>"
EVIL_SUB = '"><img src=x onerror=alert(1)>'


async def test_every_rendered_value_is_escaped(
    engine: Engine, boss: tuple[httpx.AsyncClient, AuthService]
) -> None:
    c, service = boss
    target = await _ad_account(engine, EVIL_NAME)
    await service.bind_federated_subject(target, EVIL_SUB, actor="test")

    for path in (_screen(target), f"{_screen(target)}/unlink-confirm", f"/ui/users/{target}"):
        text = (await c.get(path)).text
        assert EVIL_NAME not in text and EVIL_SUB not in text, path
        assert "&lt;script&gt;" in text, path  # the name IS rendered, escaped
        assert "&lt;img src=x" in text, path  # and so is the subject

    # A refused subject is echoed into the form field, escaped. The leading space makes it refused.
    await _mint(c, _screen(target))
    echoed = ' "><script>alert(2)</script>'
    r = await c.post(
        f"{_screen(target)}/link",
        data=await _shown(engine, target, subject=echoed),
        headers=SAME_ORIGIN,
    )
    assert r.status_code == 400
    assert "<script>alert(2)" not in r.text
    assert "&lt;script&gt;alert(2)" in r.text

    # The notice is chosen from a closed set: a query string cannot supply words.
    probe = await c.get(f"{_screen(target)}?m=%3Cb%3Ex")
    assert "<b>x" not in probe.text and "&lt;b&gt;x" not in probe.text
