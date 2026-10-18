# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""/ui users and RBAC admin (/ui/users, /ui/roles, /ui/ad-groups), BACKLOG #75 phase 4, and its
review-driven regressions."""

from __future__ import annotations

import html
import json
import re

import httpx
import pytest
from _webui_support import (
    PW,
    _add,
    _add_with_role_ids,
    _boss_client,
    _client,
    _cookie_login,
    _mint_action,
    _post_pairs,
    _service,
    _uid,
)

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

# --- L4a: users/RBAC admin (/ui/users, /ui/roles, /ui/ad-groups), #75 phase 4 ----------------------
#
# All admin writes are require_step_up(USERS_MANAGE) in the JSON API. Body-less path actions register
# as auto_retry; every body-carrying FORM PAGE registers as an `unlock` target (the L0c primitive), and
# its POST maps a stale-step-up redirect to that form via reauth_next — a password crosses the wire
# exactly once (the create-user POST) and never rides /ui/reauth.


async def test_users_pages_require_users_read(engine: Engine) -> None:
    # OPERATOR holds neither users:read nor users:manage — the whole admin area is refused.
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _client(engine, service) as c:
        await _cookie_login(c, "op")
        assert (await c.get("/ui/users")).status_code == 403
        assert (await c.get("/ui/roles")).status_code == 403
        assert (await c.get("/ui/users/new")).status_code == 403
        assert (await c.get("/ui/ad-groups")).status_code == 403


async def test_users_page_lists_accounts(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "listed-viewer", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/users")
        assert r.status_code == 200
        # Every account this test created is listed, each as a link to its own detail page. The
        # assertion is on the row's link and name, not a bare substring: a bare "admin" check
        # passes on boss's own Roles cell, which reads "administrator", whatever else is listed.
        for username in ("listed-viewer", "boss"):
            assert f'<a href="/ui/users/{await _uid(service, username)}">{username}</a>' in r.text
        assert "/ui/users/new" in r.text  # the create form link
        # The admin nav entry is registered (visible from any page).
        assert 'href="/ui/users"' in (await c.get("/ui")).text


def test_users_page_scope_column_shows_what_the_account_reaches() -> None:
    """BACKLOG #1152: the Channel scope column resolves BOTH inputs, not just the stored one.

    A stored ``None`` denies now, so it must not read "all". But an ADMINISTRATOR is all-channels by
    role whatever is stored, and printing "(none)" beside an account that holds the whole estate
    hides real access from the person whose job is to review it — the worse of the two errors."""
    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry_webconsole.pages.admin import _scope_cell

    def _u(roles: list[str], scope: list[str] | None) -> UserSummary:
        return UserSummary(
            id="u",
            username="u",
            auth_provider="local",
            disabled=False,
            roles=roles,
            channel_scope=scope,
            channel_scope_withheld=False,
        )

    assert _scope_cell(_u(["operator"], None)) == "(none)"  # never granted -> denies
    assert _scope_cell(_u(["operator"], [])) == "(none)"  # explicitly denied
    assert _scope_cell(_u(["operator"], [ALL_CHANNELS])) == "all"  # the typed grant
    assert _scope_cell(_u(["operator"], ["IB_A", "IB_B"])) == "IB_A, IB_B"
    # By role, and the stored scope is irrelevant in BOTH directions.
    assert _scope_cell(_u(["administrator"], None)) == "all (administrator)"
    assert _scope_cell(_u(["administrator"], ["IB_A"])) == "all (administrator)"


def test_users_page_hides_the_scope_columns_from_a_reader_who_is_not_shown_scopes() -> None:
    """BACKLOG #3189: the engine shows channel scopes only to a users:manage holder, and sends
    anyone else null with ``channel_scope_withheld``. This page renders a null scope as "(none)",
    "reaches nothing", so for such a reader it must drop both scope columns rather than print that
    beside every account. It reads the engine's flag, and does not re-derive the rule."""
    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry_webconsole.pages.admin import _scope_cell, _scope_source_text, users_page

    def _u(withheld: bool) -> UserSummary:
        return UserSummary(
            id="u",
            username="u",
            auth_provider="local",
            disabled=False,
            roles=["operator"],
            channel_scope_withheld=withheld,
        )

    hidden = str(users_page([_u(True)]))
    assert "Channel scope" not in hidden and "Scope source" not in hidden
    assert "(none)" not in hidden
    assert _scope_cell(_u(True)) == "not shown"
    assert _scope_source_text(_u(True)) == "not shown"
    # A mixed list keeps the columns, as the Lock column does, and a withheld cell still never
    # reads "(none)".
    mixed = str(users_page([_u(True), _u(False)]))
    assert "<th>Channel scope</th>" in mixed and mixed.count("not shown") == 2
    # The control: the same null scope, not withheld, is a scope that denies, and both columns show.
    shown = str(users_page([_u(False)]))
    assert "<th>Channel scope</th>" in shown and "<th>Scope source</th>" in shown
    assert "(none)" in shown


async def test_users_page_shows_scopes_only_to_a_users_manage_holder(engine: Engine) -> None:
    """The route half of the rule above: a users:read-only reader, here a custom role, sees no
    account's channels on /ui/users, while an administrator sees them (BACKLOG #3189)."""
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="User reader", description=None, permissions=["users:read"], actor="test"
    )
    await _add_with_role_ids(service, "reader", [role.id])
    await _add(service, "scoped-op", Role.OPERATOR)
    await service.set_channel_scope(await _uid(service, "scoped-op"), ["IB_SECRET"], actor="test")
    async with _client(engine, service) as c:
        await _cookie_login(c, "reader")
        r = await c.get("/ui/users")
        assert r.status_code == 200, r.text
        assert "scoped-op" in r.text
        assert "IB_SECRET" not in r.text and "Channel scope" not in r.text
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/users")
        assert r.status_code == 200
        assert "IB_SECRET" in r.text and "<th>Channel scope</th>" in r.text


async def test_l4a_actions_registered_in_correct_allowlists(engine: Engine) -> None:
    # Form pages are unlock targets; body-less path actions are auto-retry; body-carrying POST paths
    # are in NEITHER list (they can only be reached by a fresh same-origin form submit).
    from messagefoundry_webconsole import is_safe_ui_action, is_unlock_action

    service = await _service(engine)
    create_app(engine, auth=service, serve_ui=True)
    for form in (
        "/ui/users/new",
        "/ui/users/U1",
        "/ui/roles/new",
        "/ui/roles/custom:x/edit",
        "/ui/ad-groups",
    ):
        assert is_unlock_action(form), form
        assert not is_safe_ui_action(form), form
    for action in (
        "/ui/users/U1/delete",
        "/ui/users/U1/reset-password",
        "/ui/users/U1/reset-mfa",
        "/ui/users/U1/revoke-sessions",
        "/ui/roles/custom/custom:x/delete",
    ):
        assert is_safe_ui_action(action), action
        assert not is_unlock_action(action), action
    for body_post in (
        "/ui/users",
        "/ui/users/U1/roles",
        "/ui/users/U1/update",
        "/ui/users/U1/channel-scope",
        "/ui/roles/custom",
        "/ui/ad-groups/map",
        "/ui/ad-groups/scope-map",
    ):
        assert not is_safe_ui_action(body_post), body_post
        assert not is_unlock_action(body_post), body_post


async def test_create_user_end_to_end(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await _post_pairs(
            c,
            "/ui/users",
            [
                ("username", "newop"),
                ("display_name", "New Operator"),
                ("email", "newop@example.test"),
                ("roles", "operator"),
                ("roles", "viewer"),
            ],
        )
        # ADR 0197 Amendment A, AC-A2: the page shows the engine-generated credential ONCE.
        assert r.status_code == 200 and "Account created" in r.text
        user = await service.store.get_user_by_username("newop")
        assert user is not None
        assert sorted(await service.store.get_user_role_ids(user.id)) == ["operator", "viewer"]
        assert user.must_change_password and user.password_generated
        shown = re.search(r"<code>([^<]+)</code>", r.text)
        assert (
            shown is not None and (await service.login("newop", html.unescape(shown.group(1)))).ok
        )


async def test_create_user_duplicate_rerenders_without_password(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "op", Role.OPERATOR)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={"username": "op", "password": PW, "display_name": "Dup"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400
        assert "already exists" in r.text
        assert 'value="op"' in r.text  # non-secret fields are preserved...
        assert PW not in r.text  # ...the password is NEVER echoed back


async def test_a_refused_create_on_the_console_answers_503(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2359: when no credential can be generated, the create form re-renders with the
    refusal and a 503, as the JSON API answers, and no account is written."""
    from types import SimpleNamespace

    from messagefoundry.auth import service as service_module

    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_write_min_interval_seconds=0,
            password_extra_context_words=["globex"],
        ),
    )
    await service.initialize()
    async with _boss_client(engine, service) as c:
        monkeypatch.setattr(
            service_module,
            "secrets",
            SimpleNamespace(token_urlsafe=lambda n=None: "zq-globex-" + "v" * 40),
        )
        r = await _post_pairs(
            c,
            "/ui/users",
            [("username", "newop"), ("email", "newop@example.test"), ("roles", "viewer")],
        )
        assert r.status_code == 503 and "password_extra_context_words" in r.text
        assert await service.store.get_user_by_username("newop") is None
        refused = await service.store.list_audit(action="auth.credential_issue_refused", limit=10)
        assert [json.loads(row["detail"])["op"] for row in refused] == ["create"]


async def test_create_user_a_posted_password_is_never_the_credential(engine: Engine) -> None:
    """ADR 0197 Amendment A, AC-A2: the create form has no password field, and a ``password`` a
    caller posts anyway is ignored. The account gets a generated credential; the posted one does not
    sign in. (Replaces the weak-password refusal test: there is no administrator-typed password left
    to refuse.)"""
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        form = await c.get("/ui/users/new")
        assert 'name="password"' not in form.text
        r = await c.post(
            "/ui/users",
            data={"username": "chooser", "password": PW, "email": "chooser@example.test"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200 and PW not in r.text
        user = await service.store.get_user_by_username("chooser")
        assert user is not None and user.password_generated
        assert not (await service.login("chooser", PW)).ok


async def test_create_user_cross_site_rejected(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={"username": "csrf", "password": PW},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r.status_code == 403
        assert await service.store.get_user_by_username("csrf") is None


async def test_stale_stepup_redirects_body_post_to_unlock_form(engine: Engine) -> None:
    # THE reauth_next mapping: with an expired step-up window, the body-carrying POST /ui/users is
    # redirected to /ui/reauth pointing at its FORM PAGE (/ui/users/new) — never at the POST path —
    # and the form GET itself bounces the same way (its own path IS the unlock target).
    # require_mfa=False takes the MFA leg out of require_ui_step_up, so the stale window below is
    # what redirects; without it _boss_client's unenrolled session is refused first with the SAME
    # 303 and the window measured nothing (BACKLOG #1851). Reasoning, and the third new-IP leg that
    # stays unpinned: the docstring of test_purge_stale_stepup_redirects_to_reauth (BACKLOG #1700).
    service = AuthService(engine.store, AuthSettings(require_mfa=False, step_up_max_age_seconds=-1))
    await service.initialize()
    async with _boss_client(engine, service) as c:
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True  # the MFA leg is NOT what refuses here
        assert await service.has_recent_step_up(tok) is False  # the stale window is
        r = await c.post(
            "/ui/users",
            data={"username": "x", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/users/new"
        r = await c.get("/ui/users/new")
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/users/new"
        # The user was NOT created — the body never outlives the bounced request.
        assert await service.store.get_user_by_username("x") is None


async def test_reauth_unlocks_real_user_form(engine: Engine) -> None:
    # The registered /ui/users/new unlock target round-trips the reauth POST into a GET redirect.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/reauth",
            data={"next": "/ui/users/new", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/users/new"
        assert (await c.get("/ui/users/new")).status_code == 200


async def test_update_user_profile_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        # BACKLOG #1737: the update lane is action-bound, and the grant is SINGLE-USE, so each of the
        # two submits below needs its own. The continuation is the detail PAGE, not the POST path (a
        # body-carrying action is in neither continuation allow-list) — that is where the grant mints.
        await _mint_action(c, f"/ui/users/{uid}")
        r = await c.post(
            f"/ui/users/{uid}/update",
            data={"display_name": "User One", "email": "u1@example.test", "disabled": "on"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None
        assert user.display_name == "User One" and user.disabled
        # Re-enable (checkbox absent) + clear the email ("" clears to None — full-form semantics).
        await _mint_action(c, f"/ui/users/{uid}")
        r = await c.post(
            f"/ui/users/{uid}/update",
            data={"display_name": "User One", "email": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None
        assert not user.disabled and user.email is None


async def _save_profile(c: httpx.AsyncClient, uid: str, form: dict[str, str]) -> httpx.Response:
    await _mint_action(c, f"/ui/users/{uid}")  # BACKLOG #1737: action-bound, single-use
    return await c.post(
        f"/ui/users/{uid}/update", data=form, headers={"Sec-Fetch-Site": "same-origin"}
    )


async def test_an_unrelated_console_save_leaves_the_notification_address(engine: Engine) -> None:
    """BACKLOG #1139, ADR 0182 Amendment A. The form is pre-filled with the stored profile email and
    posts it back on every save. A display-name edit must not copy it into the notification
    address, whether that address is set (X stays X) or missing (it stays missing)."""
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        set_uid, blank_uid = await _uid(service, "u1"), await _uid(service, "u2")
        await service.store.set_user_notify_email(set_uid, email="owner@example.test")
        # The directory-sync write: profile email only.
        for uid in (set_uid, blank_uid):
            await service.store.update_user_profile(
                uid, display_name=None, email="dir@example.test"
            )

        # The page shows both addresses, each in its own field, plus the shown copy.
        page = (await c.get(f"/ui/users/{set_uid}")).text
        assert 'name="notify_email"' in page and 'value="owner@example.test"' in page
        assert 'name="notify_email_shown"' in page
        assert 'value="dir@example.test"' in page

        # Posted back exactly as the page pre-fills it, with only the display name changed.
        r = await _save_profile(
            c,
            set_uid,
            {
                "display_name": "Renamed",
                "email": "dir@example.test",
                "notify_email": "owner@example.test",
                "notify_email_shown": "owner@example.test",
            },
        )
        assert r.status_code == 303
        r = await _save_profile(
            c,
            blank_uid,
            {
                "display_name": "Renamed",
                "email": "dir@example.test",
                "notify_email": "",
                "notify_email_shown": "",
            },
        )
        assert r.status_code == 303

        kept = await service.store.get_user(set_uid)
        blank = await service.store.get_user(blank_uid)
        assert kept is not None and kept.display_name == "Renamed"
        assert kept.notify_email == "owner@example.test"
        assert blank is not None and blank.display_name == "Renamed"
        assert blank.notify_email is None


async def test_a_stale_console_page_cannot_undo_another_admins_move(engine: Engine) -> None:
    """Round-one QA finding. Admin A's page showed X. Admin B then moved the address to Z. A's
    display-name save posts X back, and comparing it with the STORED value read that as a move back
    to X. The route compares it with the value A's page SHOWED, so nothing moves."""
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        await service.store.set_user_notify_email(uid, email="moved@example.test")  # B's move

        r = await _save_profile(
            c,
            uid,
            {
                "display_name": "Renamed",
                "email": "",
                "notify_email": "owner@example.test",
                "notify_email_shown": "owner@example.test",
            },
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and user.display_name == "Renamed"
        assert user.notify_email == "moved@example.test"


async def test_the_console_moves_the_notification_address_only_when_told(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        await service.store.set_user_notify_email(uid, email="owner@example.test")
        shown = {"notify_email_shown": "owner@example.test"}

        # A value that is not one mailbox is refused whole, and the page says why.
        r = await _save_profile(
            c,
            uid,
            {"display_name": "Renamed", "email": "", "notify_email": "not-an-address", **shown},
        )
        assert r.status_code == 400
        assert "enter one email address" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.display_name is None
        assert user.notify_email == "owner@example.test"

        # Emptying the field is refused, as the JSON twin refuses an explicit null.
        r = await _save_profile(
            c, uid, {"display_name": "Renamed", "email": "", "notify_email": "", **shown}
        )
        assert r.status_code == 400
        assert "can be changed but not cleared" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.display_name is None
        assert user.notify_email == "owner@example.test"

        r = await _save_profile(
            c, uid, {"display_name": "", "email": "", "notify_email": "new@example.test", **shown}
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and user.notify_email == "new@example.test"
        rows = [
            a
            for a in await service.store.list_audit()
            if a["action"] == "user.notify_email_changed"
        ]
        assert len(rows) == 1 and rows[0]["actor"] == "boss"


async def test_update_user_requires_a_grant_bound_to_this_action(engine: Engine) -> None:
    """BACKLOG #1737 (ASVS 7.5.1): the console update lane must require the same action-bound,
    single-use step-up its JSON twin (``PATCH /users/{id}``) requires — not the shared window.

    THE CONTROL IS THE BOUNCE, AND IT IS ASSERTED BEFORE ANY GRANT EXISTS. Minting and then
    succeeding shows the flow works, not that the gate stands: this session is freshly signed in, so
    it already satisfies ``has_recent_step_up``, and a route back on ``require_ui_step_up`` would
    serve step 1 with a 303 to the user page and the write applied. The wrong-action leg is the
    second half of the same control — it fails a route that reads any fresh grant rather than this
    action's, which a bare "does a grant work" test cannot tell apart.
    """
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        form = {"display_name": "Renamed", "email": "u1@example.test", "disabled": "on"}

        async def _update() -> httpx.Response:
            return await c.post(
                f"/ui/users/{uid}/update", data=form, headers={"Sec-Fetch-Site": "same-origin"}
            )

        async def _unchanged() -> None:
            user = await service.store.get_user(uid)
            assert user is not None
            assert user.display_name != "Renamed" and not user.disabled

        # 1. The login-seeded window alone does not reach it.
        bounced = await _update()
        assert bounced.status_code == 303
        assert "/ui/reauth" in bounced.headers["location"]
        await _unchanged()

        # 2. Nor does a fresh grant minted for a DIFFERENT action on the same session.
        await _mint_action(c, f"/ui/users/{uid}/reset-password")  # mints admin_reset_password
        bounced = await _update()
        assert bounced.status_code == 303
        assert "/ui/reauth" in bounced.headers["location"]
        await _unchanged()

        # 3. The grant bound to THIS action does, so the gate did not just break the lane.
        await _mint_action(c, f"/ui/users/{uid}")
        r = await _update()
        assert r.status_code == 303 and r.headers["location"] == f"/ui/users/{uid}"
        user = await service.store.get_user(uid)
        assert user is not None and user.display_name == "Renamed" and user.disabled

        # 4. And it is spent: the next submit bounces again rather than riding the refreshed window.
        bounced = await _update()
        assert bounced.status_code == 303
        assert "/ui/reauth" in bounced.headers["location"]


async def test_cannot_disable_self_rerenders_error(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "boss")
        await _mint_action(c, f"/ui/users/{uid}")  # BACKLOG #1737: action-bound lane
        r = await c.post(
            f"/ui/users/{uid}/update",
            data={"display_name": "", "email": "", "disabled": "on"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400
        assert "cannot disable your own account" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and not user.disabled


async def test_set_roles_roundtrip_and_last_admin_guard(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await _post_pairs(c, f"/ui/users/{uid}/roles", [("roles", "operator")])
        assert r.status_code == 303
        assert await service.store.get_user_role_ids(uid) == ["operator"]
        # boss IS the last enabled administrator: initialize() creates no account of its own (ADR
        # 0183 Amendment A), so nothing else in this store holds the role. The handler refuses a
        # self-target first (BACKLOG #1149), so the last-administrator refusal is mapped from a
        # viewer the guard is made to refuse, as tests/test_last_admin_guard.py does on the JSON
        # plane.
        boss_id = await _uid(service, "boss")
        r = await _post_pairs(c, f"/ui/users/{boss_id}/roles", [("roles", "viewer")])
        assert r.status_code == 400
        assert "another administrator must change your own roles" in r.text

        async def refuse(*_a: object, **_k: object) -> bool:
            return False

        monkeypatch.setattr(service.store, "remove_unless_last_admin", refuse)
        r = await _post_pairs(c, f"/ui/users/{uid}/roles", [("roles", "viewer")])
        assert r.status_code == 400
        assert "cannot remove the last administrator" in r.text


async def test_channel_scope_roundtrip(engine: Engine) -> None:
    # Tri-state scope_mode: a list, all-channels (None), and deny-all ([]) each round-trip; a "list"
    # save with an empty textarea is refused instead of guessing (review PR2-M3).
    import json as json_

    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "list", "channels": "IB_ACME_ADT\r\nIB_LAB_ORU\r\n\r\n"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and user.channel_scope is not None
        assert json_.loads(user.channel_scope) == ["IB_ACME_ADT", "IB_LAB_ORU"]
        # Deny-all is explicit — and the detail page re-renders it as the selected mode.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "none", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and json_.loads(user.channel_scope or "null") == []
        # Re-saving the deny-all page unchanged must NOT widen the scope (the PR2-M3 bug):
        # the form now posts scope_mode=none, so [] survives a no-op save.
        detail = (await c.get(f"/ui/users/{uid}")).text
        assert 'value="none" selected' in detail
        # All-channels is explicit too.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "all", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        # BACKLOG #1152: all-channels is the stored ["*"] grant, not a null scope — null now denies,
        # so posting it for the "all" mode would have silently inverted this form.
        assert user is not None and json_.loads(user.channel_scope or "null") == [ALL_CHANNELS]
        assert 'value="all" selected' in (await c.get(f"/ui/users/{uid}")).text
        # "Only these" with an empty list is ambiguous — refused, scope unchanged.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "list", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 400 and "list at least one connection" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and json_.loads(user.channel_scope or "null") == [ALL_CHANNELS]


async def test_the_all_channels_token_cannot_ride_in_through_the_textarea(engine: Engine) -> None:
    """The "only these connections" mode must mean that. Any stored list the token appears in
    resolves to every channel, so accepting one here would grant the whole estate while the form
    said otherwise and the saved list still read as a narrow one -- the read-one-thing-do-another
    shape the tri-state mode exists to prevent. The request model cannot be where this is refused:
    the JSON route shares that model, and there a list holding the token IS the grant."""
    import json as json_

    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "list", "channels": "IB_ACME_ADT"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303  # control: an ordinary list still saves
        for typed in (ALL_CHANNELS, f"{ALL_CHANNELS}\r\nIB_LAB_ORU"):
            r = await c.post(
                f"/ui/users/{uid}/channel-scope",
                data={"scope_mode": "list", "channels": typed},
                headers={"Sec-Fetch-Site": "same-origin"},
            )
            assert r.status_code == 400, typed
            assert "all-channels grant" in r.text, typed
            # Refused means unchanged, not partly applied.
            user = await service.store.get_user(uid)
            assert user is not None
            assert json_.loads(user.channel_scope or "null") == ["IB_ACME_ADT"], typed
        # ...and the mode that DOES mean it still works, so the guard did not just break the grant.
        r = await c.post(
            f"/ui/users/{uid}/channel-scope",
            data={"scope_mode": "all", "channels": ""},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 303
        user = await service.store.get_user(uid)
        assert user is not None and json_.loads(user.channel_scope or "null") == [ALL_CHANNELS]


def test_scope_source_renders_in_words() -> None:
    """BACKLOG #1958: every stored source has words, and one this console has not learned shows
    as itself rather than vanishing from the page."""
    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry_webconsole.pages.admin import _scope_source_text, users_page

    def _u(source: str | None) -> UserSummary:
        return UserSummary(
            id="u",
            username="u",
            auth_provider="ad",
            disabled=False,
            roles=["operator"],
            channel_scope=["IB_A"],
            channel_scope_source=source,
            channel_scope_withheld=False,
        )

    assert _scope_source_text(_u("ad")) == "directory (AD group map)"
    assert _scope_source_text(_u("manual")) == "set by an administrator"
    assert _scope_source_text(_u(None)) == "not recorded"
    assert _scope_source_text(_u("future")) == "future"
    listing = str(users_page([_u("ad")]))
    assert "<th>Scope source</th>" in listing
    assert "directory (AD group map)" in listing


def test_which_scopes_need_the_manual_confirmation() -> None:
    """BACKLOG #1958: the tick is asked for exactly where a save stops the AD login sync withdrawing
    the scope. That is a directory scope, and an AD account's scope with no recorded writer, which
    the sync withdraws the same way. A local account is never synced, so it is never asked."""
    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry_webconsole.pages.admin import needs_manual_scope_confirm

    def _u(provider: str, scope: list[str] | None, source: str | None) -> UserSummary:
        return UserSummary(
            id="u",
            username="u",
            auth_provider=provider,
            disabled=False,
            roles=["operator"],
            channel_scope=scope,
            channel_scope_source=source,
            channel_scope_withheld=False,
        )

    assert needs_manual_scope_confirm(_u("ad", ["IB_A"], "ad"))
    assert needs_manual_scope_confirm(_u("ad", ["IB_A"], None))  # unvouched: the sync withdraws it
    assert not needs_manual_scope_confirm(_u("ad", ["IB_A"], "manual"))
    assert not needs_manual_scope_confirm(_u("ad", None, None))  # nothing stored to withdraw
    assert not needs_manual_scope_confirm(_u("local", ["IB_A"], None))  # never synced


async def test_resaving_a_directory_scope_needs_a_confirmation(engine: Engine) -> None:
    """BACKLOG #1958: a save turns a directory scope manual, even an unchanged one, and the login
    sync never withdraws a manual scope. So the page warns and asks for a tick, and the route
    refuses a save without it. The manual-scope arm is the control: it saves with no tick."""
    import uuid

    from messagefoundry.store.store import SCOPE_SOURCE_AD, SCOPE_SOURCE_MANUAL

    service = await _service(engine)
    ada = uuid.uuid4().hex  # the shape a real account id has
    await service.store.create_user(
        user_id=ada, username="ada", auth_provider="ad", password_generated=False
    )
    await service.store.set_user_channel_scope(ada, json.dumps(["IB_A"]), source=SCOPE_SOURCE_AD)
    resave = {"scope_mode": "list", "channels": "IB_A"}
    same_origin = {"Sec-Fetch-Site": "same-origin"}
    async with _boss_client(engine, service) as c:
        detail = (await c.get(f"/ui/users/{ada}")).text
        assert "Source: directory (AD group map)" in detail
        assert "The directory owns this scope" in detail
        assert 'name="confirm_manual_scope" value="yes" required' in detail

        # The unchanged re-save, without the tick: refused, and the scope stays the directory's.
        r = await c.post(f"/ui/users/{ada}/channel-scope", data=resave, headers=same_origin)
        assert r.status_code == 400
        assert "tick the box to confirm" in r.text
        user = await service.store.get_user(ada)
        assert user is not None and user.channel_scope_source == SCOPE_SOURCE_AD

        # A tick with any other value is not a confirmation.
        r = await c.post(
            f"/ui/users/{ada}/channel-scope",
            data={**resave, "confirm_manual_scope": "on"},
            headers=same_origin,
        )
        assert r.status_code == 400

        # With the tick it saves, and the scope is now the administrator's.
        r = await c.post(
            f"/ui/users/{ada}/channel-scope",
            data={**resave, "confirm_manual_scope": "yes"},
            headers=same_origin,
        )
        assert r.status_code == 303
        user = await service.store.get_user(ada)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_A"]', SCOPE_SOURCE_MANUAL)
        detail = (await c.get(f"/ui/users/{ada}")).text
        assert "Source: set by an administrator" in detail
        assert "confirm_manual_scope" not in detail  # no warning once it is manual

        # The control: a manual scope saves with no tick.
        r = await c.post(f"/ui/users/{ada}/channel-scope", data=resave, headers=same_origin)
        assert r.status_code == 303


async def test_a_refused_scope_save_shows_the_submitted_edits(engine: Engine) -> None:
    """BACKLOG #2099: the missing-tick refusal re-renders the administrator's submitted scope, not
    the stored one, with the warning and an unticked box. The edits are shown, escaped, and never
    saved. The control is the page before the post, which shows the stored scope."""
    import uuid

    from messagefoundry.store.store import SCOPE_SOURCE_AD

    service = await _service(engine)
    ada = uuid.uuid4().hex
    await service.store.create_user(
        user_id=ada, username="ada", auth_provider="ad", password_generated=False
    )
    await service.store.set_user_channel_scope(ada, json.dumps(["IB_A"]), source=SCOPE_SOURCE_AD)
    same_origin = {"Sec-Fetch-Site": "same-origin"}
    stored_textarea = '<textarea name="channels" rows="4">IB_A</textarea>'
    async with _boss_client(engine, service) as c:
        before = (await c.get(f"/ui/users/{ada}")).text
        assert stored_textarea in before  # the control: the form starts from the stored scope

        edit = {"scope_mode": "list", "channels": "IB_B\n  IB_<b>C</b>  \n\n"}
        r = await c.post(f"/ui/users/{ada}/channel-scope", data=edit, headers=same_origin)
        assert r.status_code == 400
        assert "tick the box to confirm" in r.text and "not saved yet" in r.text
        assert "The directory owns this scope" in r.text
        # The submitted names, trimmed and escaped, replace the stored one in the textarea.
        assert (
            '<textarea name="channels" rows="4">IB_B\nIB_&lt;b&gt;C&lt;/b&gt;</textarea>' in r.text
        )
        assert stored_textarea not in r.text and "IB_<b>" not in r.text
        assert '<option value="list" selected>' in r.text
        # The box is asked for again and is never pre-ticked.
        assert 'name="confirm_manual_scope" value="yes" required>' in r.text
        # Nothing was saved: the scope and its source are still the directory's.
        user = await service.store.get_user(ada)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_A"]', SCOPE_SOURCE_AD)

        # A mode change survives too: the select shows the submitted deny-all, not the stored list.
        r = await c.post(
            f"/ui/users/{ada}/channel-scope",
            data={"scope_mode": "none", "channels": ""},
            headers=same_origin,
        )
        assert r.status_code == 400
        assert '<option value="none" selected>' in r.text
        assert '<option value="list" selected>' not in r.text

        # A submitted all-channels shows as all-channels.
        r = await c.post(
            f"/ui/users/{ada}/channel-scope",
            data={"scope_mode": "all", "channels": ""},
            headers=same_origin,
        )
        assert r.status_code == 400
        assert '<option value="all" selected>' in r.text

        # The case that matters for review: a stored all-channels scope and a narrowing edit. The
        # refusal shows the narrow list the administrator asked for, not the wider stored grant.
        await service.store.set_user_channel_scope(
            ada, json.dumps([ALL_CHANNELS]), source=SCOPE_SOURCE_AD
        )
        assert '<option value="all" selected>' in (await c.get(f"/ui/users/{ada}")).text
        r = await c.post(
            f"/ui/users/{ada}/channel-scope",
            data={"scope_mode": "list", "channels": "IB_B"},
            headers=same_origin,
        )
        assert r.status_code == 400
        assert '<option value="list" selected>' in r.text
        assert '<option value="all" selected>' not in r.text
        user = await service.store.get_user(ada)
        assert user is not None and user.channel_scope == json.dumps([ALL_CHANNELS])


async def test_the_other_scope_refusals_keep_the_edits_where_they_can(engine: Engine) -> None:
    """BACKLOG #2099: the tick refusal is not the only one. A ticked resubmit can still fail on a
    bad connection name, and `*` in list mode is refused too; both keep the edits. An empty list
    and an unknown mode have no draft the form can show as chosen, so they show the stored scope."""
    import uuid

    from messagefoundry.store.store import SCOPE_SOURCE_AD

    service = await _service(engine)
    ada = uuid.uuid4().hex
    await service.store.create_user(
        user_id=ada, username="ada", auth_provider="ad", password_generated=False
    )
    await service.store.set_user_channel_scope(ada, json.dumps(["IB_A"]), source=SCOPE_SOURCE_AD)
    same_origin = {"Sec-Fetch-Site": "same-origin"}
    stored_textarea = '<textarea name="channels" rows="4">IB_A</textarea>'
    ticked = {"confirm_manual_scope": "yes"}

    async def _post(c: httpx.AsyncClient, data: dict[str, str]) -> str:
        r = await c.post(f"/ui/users/{ada}/channel-scope", data=data, headers=same_origin)
        assert r.status_code == 400
        # Never saved, and the box is never pre-ticked on the way back.
        user = await service.store.get_user(ada)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_A"]', SCOPE_SOURCE_AD)
        assert 'name="confirm_manual_scope" value="yes" required>' in r.text
        return r.text

    async with _boss_client(engine, service) as c:
        # A ticked resubmit whose name the request model refuses keeps the edits.
        # The rejected name is echoed escaped: this is the one path that shows back a name the
        # validator refused.
        page = await _post(c, {"scope_mode": "list", "channels": "IB_B\nIB <b>A</b>", **ticked})
        assert "invalid input" in page
        assert '<textarea name="channels" rows="4">IB_B\nIB &lt;b&gt;A&lt;/b&gt;</textarea>' in page
        assert "<b>A</b>" not in page
        assert '<option value="list" selected>' in page

        # `*` in list mode keeps the other names and drops the token, and the select stays on
        # the list: showing all-channels would be the widening that refusal exists to stop.
        page = await _post(c, {"scope_mode": "list", "channels": "IB_B\n*\nIB_C", **ticked})
        assert "is the all-channels grant" in page
        assert '<textarea name="channels" rows="4">IB_B\nIB_C</textarea>' in page
        assert '<option value="list" selected>' in page
        assert '<option value="all" selected>' not in page

        # A list of nothing but the token has no draft left, so the stored scope is shown.
        page = await _post(c, {"scope_mode": "list", "channels": "*", **ticked})
        assert stored_textarea in page and '<option value="all" selected>' not in page

        # An empty list shows the stored scope rather than an empty draft, which would read as
        # deny-all, a mode the post did not choose.
        page = await _post(c, {"scope_mode": "list", "channels": "  \n", **ticked})
        assert "list at least one connection" in page
        assert stored_textarea in page and '<option value="none" selected>' not in page

        # An unknown mode has no option to select, so the stored scope is shown.
        page = await _post(c, {"scope_mode": "everything", "channels": "IB_B", **ticked})
        assert "unknown scope mode" in page
        assert stored_textarea in page


def test_only_a_directory_scope_sends_expected_source_on_a_ticked_save() -> None:
    """BACKLOG #2098: the tick becomes ``expected_source="ad"`` only where the directory owns the
    scope. Any other source sends nothing, so a ticked save there behaves as it did before.
    BACKLOG #2252: an AD account's scope with no recorded writer is the directory's too."""
    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry_webconsole.pages.admin import ticked_scope_expected_source

    def _u(source: str | None, provider: str = "ad", stored: bool = True) -> UserSummary:
        return UserSummary(
            id="u",
            username="u",
            auth_provider=provider,
            disabled=False,
            roles=["operator"],
            channel_scope=["IB_A"] if stored else None,
            channel_scope_source=source,
            channel_scope_withheld=False,
        )

    assert ticked_scope_expected_source(_u("ad")) == "ad"
    assert ticked_scope_expected_source(_u("manual")) is None
    assert ticked_scope_expected_source(_u(None)) == "ad"  # legacy AD row: the sync withdraws it
    assert ticked_scope_expected_source(_u(None, provider="local")) is None  # never synced
    assert ticked_scope_expected_source(_u(None, stored=False)) is None  # nothing to withdraw


async def test_the_console_and_the_engine_agree_on_who_owns_a_scope(engine: Engine) -> None:
    """BACKLOG #2252: the console asks for the tick, and sends ``"ad"``, exactly where the engine
    refuses a save without it. The console cannot import the engine's rule, so the two statements
    are compared here, over every provider, source and stored-scope shape the rule reads."""
    import dataclasses
    import itertools
    import uuid

    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry.auth.service import _effective_scope_source
    from messagefoundry.store.store import ChannelScopeSource
    from messagefoundry_webconsole.pages.admin import (
        needs_manual_scope_confirm,
        ticked_scope_expected_source,
    )

    service = await _service(engine)
    uid = uuid.uuid4().hex
    await service.store.create_user(
        user_id=uid, username="ada", auth_provider="ad", password_generated=False
    )
    base = await service.store.get_user(uid)
    assert base is not None
    sources: tuple[ChannelScopeSource | None, ...] = (None, "ad", "manual")
    seen: set[bool] = set()
    for provider, source, scope in itertools.product(
        ("ad", "local"), sources, (None, [], ["IB_A"], [ALL_CHANNELS])
    ):
        record = dataclasses.replace(
            base,
            auth_provider=provider,
            channel_scope_source=source,
            channel_scope=None if scope is None else json.dumps(scope),
        )
        summary = UserSummary(
            id=uid,
            username="ada",
            auth_provider=provider,
            disabled=False,
            roles=["operator"],
            channel_scope=scope,
            channel_scope_source=source,
            channel_scope_withheld=False,
        )
        engine_says = _effective_scope_source(record) == "ad"
        assert needs_manual_scope_confirm(summary) is engine_says, (provider, source, scope)
        assert ticked_scope_expected_source(summary) == ("ad" if engine_says else None)
        seen.add(engine_says)
    assert seen == {True, False}  # both answers occur, so the loop compared something


async def test_a_ticked_save_on_a_legacy_directory_scope_saves(engine: Engine) -> None:
    """BACKLOG #2252: an AD account's scope stored before the source column has a NULL source. The
    console asks for the tick there, and the ticked save must send ``"ad"``, because the engine now
    refuses that save without it. Fails before #2252's console change: the ticked save sent nothing
    and the engine answered with a conflict."""
    import uuid

    from messagefoundry.store.store import SCOPE_SOURCE_MANUAL

    service = await _service(engine)
    ada = uuid.uuid4().hex
    await service.store.create_user(
        user_id=ada, username="ada", auth_provider="ad", password_generated=False
    )
    await service.store.set_user_channel_scope(
        ada,
        json.dumps(["IB_A"]),
        source=None,  # type: ignore[arg-type]  # the legacy row's NULL, which no writer now makes
    )
    edit = {"scope_mode": "list", "channels": "IB_B"}
    same_origin = {"Sec-Fetch-Site": "same-origin"}
    async with _boss_client(engine, service) as c:
        detail = (await c.get(f"/ui/users/{ada}")).text
        assert "Source: not recorded" in detail
        assert 'name="confirm_manual_scope" value="yes" required' in detail

        r = await c.post(f"/ui/users/{ada}/channel-scope", data=edit, headers=same_origin)
        assert r.status_code == 400
        assert "tick the box to confirm" in r.text
        user = await service.store.get_user(ada)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_A"]', None)

        r = await c.post(
            f"/ui/users/{ada}/channel-scope",
            data={**edit, "confirm_manual_scope": "yes"},
            headers=same_origin,
        )
        assert r.status_code == 303
        user = await service.store.get_user(ada)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_B"]', SCOPE_SOURCE_MANUAL)


async def test_a_sign_in_landing_during_a_console_scope_save_is_refused(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #2098: the console reads the scope, then the save handler writes it. A directory
    sign-in that takes the scope over between the two used to be overwritten. The write is now a
    compare-and-set, so the sign-in's grant stays and the form comes back with the edits and a
    plain-words refusal. The control is the same post with no sign-in in the way, which saves."""
    import uuid

    from messagefoundry.store.store import SCOPE_SOURCE_AD, SCOPE_SOURCE_MANUAL

    service = await _service(engine)
    len_ = uuid.uuid4().hex
    await service.store.create_user(
        user_id=len_, username="len", auth_provider="ad", password_generated=False
    )
    await service.store.set_user_channel_scope(
        len_, json.dumps(["IB_M"]), source=SCOPE_SOURCE_MANUAL
    )
    same_origin = {"Sec-Fetch-Site": "same-origin"}
    edit = {"scope_mode": "list", "channels": "IB_B"}
    store = service.store
    real = store.set_user_channel_scope_if_source

    async def sign_in_lands_first(*args: object, **kwargs: object) -> bool:
        await store.set_user_channel_scope(len_, json.dumps(["IB_A"]), source=SCOPE_SOURCE_AD)
        return await real(*args, **kwargs)  # type: ignore[arg-type]

    async with _boss_client(engine, service) as c:
        monkeypatch.setattr(store, "set_user_channel_scope_if_source", sign_in_lands_first)
        r = await c.post(f"/ui/users/{len_}/channel-scope", data=edit, headers=same_origin)
        assert r.status_code == 400
        assert "who owns this scope changed" in r.text and "not saved yet" in r.text
        assert "expected_source" not in r.text  # the JSON wording is not shown
        assert '<textarea name="channels" rows="4">IB_B</textarea>' in r.text
        user = await store.get_user(len_)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_A"]', SCOPE_SOURCE_AD)

        # The control: with no sign-in in the way, the same edit saves once it is ticked.
        monkeypatch.setattr(store, "set_user_channel_scope_if_source", real)
        r = await c.post(
            f"/ui/users/{len_}/channel-scope",
            data={**edit, "confirm_manual_scope": "yes"},
            headers=same_origin,
        )
        assert r.status_code == 303
        user = await store.get_user(len_)
        assert user is not None
        assert (user.channel_scope, user.channel_scope_source) == ('["IB_B"]', SCOPE_SOURCE_MANUAL)


async def test_reset_password_shows_temp_once(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        # BACKLOG #1148 (ASVS 7.5.1): the login window no longer unlocks an admin reset. The bounce
        # is asserted first, so this still shows the gate EXISTS rather than only that a grant works.
        path = f"/ui/users/{uid}/reset-password"
        bounced = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        assert bounced.status_code == 303 and "/ui/reauth" in bounced.headers["location"]
        await _mint_action(c, path)
        r = await c.post(path, headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200
        assert "Temporary password issued" in r.text and "<code>" in r.text
        user = await service.store.get_user(uid)
        assert user is not None and user.must_change_password
        # BACKLOG #1141 (ASVS 6.4.5): the page an administrator actually reads states the deadline.
        # Asserting the RENDERED instant, not merely that some date appears: the sentence is the
        # renewal instruction, and one naming a moment the gate does not honour is worse than none.
        from datetime import UTC, datetime

        assert user.password_changed_at is not None
        deadline = service.initial_credential_deadline(user.password_changed_at)
        assert deadline is not None
        assert (
            datetime.fromtimestamp(deadline, UTC).strftime("%Y-%m-%d %H:%M:%SZ") in r.text
            and "It stops working at" in r.text
        )


async def test_temp_password_page_states_no_deadline_when_expiry_is_off() -> None:
    # The control for the assertion above. `initial_password_expiry_hours = 0` is a documented,
    # supported value, and the honest page then says nothing about a deadline rather than softening
    # the sentence -- so the assertion above is measuring the deadline arm, not boilerplate that is
    # always present.
    from messagefoundry_webconsole.pages import admin as pages

    with_deadline = pages.temp_password_page("u2", "temp-secret", 1_800_000_000.0)
    assert "It stops working at" in str(with_deadline)
    without = pages.temp_password_page("u2", "temp-secret", None)
    assert "It stops working at" not in str(without)
    assert "Temporary password issued" in str(without)  # the rest of the page is unchanged


async def test_reset_mfa_and_revoke_sessions_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        for action in ("reset-mfa", "revoke-sessions"):
            # BACKLOG #1148: reset-mfa is action-bound and needs a fresh grant; revoke-sessions is
            # deliberately NOT -- it sits outside 7.5.1, which names attributes affecting
            # AUTHENTICATION. Minting only for the tagged one keeps that boundary under test.
            if action == "reset-mfa":
                # ASSERT THE BOUNCE, not just the success. Minting and then succeeding proves the
                # flow works and NOT that the gate exists -- measured: reverting the route to the
                # window-scoped gate left this test GREEN until this assertion was added, so the
                # sharper of the two lanes had no console coverage of its own binding.
                bounced = await c.post(
                    f"/ui/users/{uid}/{action}", headers={"Sec-Fetch-Site": "same-origin"}
                )
                assert bounced.status_code == 303, action
                assert "/ui/reauth" in bounced.headers["location"], action
                await _mint_action(c, f"/ui/users/{uid}/{action}")
            r = await c.post(f"/ui/users/{uid}/{action}", headers={"Sec-Fetch-Site": "same-origin"})
            if action == "reset-mfa":
                # ADR 0197 Amendment A, AC-A4: a local account's factor reset also issued a
                # generated credential, shown once on the result page.
                assert r.status_code == 200 and "Authenticator reset" in r.text, action
                user = await service.store.get_user(uid)
                assert user is not None and user.password_generated
                continue
            assert r.status_code == 303, action
            assert r.headers["location"] == f"/ui/users/{uid}", action


@pytest.mark.parametrize("action", ["reset-mfa", "reset-password"])
async def test_a_refused_issue_on_the_console_keeps_the_account_and_the_grant(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """ADR 0197 Amendment A, Manager decision 2026-09-29: when no credential can be issued, the
    console's reset renders the refusal, changes nothing, and gives back the grant its gate spent,
    so the same grant opens the action once the generator can issue again."""
    from types import SimpleNamespace

    from messagefoundry.auth import service as service_module

    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            admin_write_min_interval_seconds=0,  # the retry is machine-speed (PR 1781, #2301)
            password_extra_context_words=["globex"],
        ),
    )
    await service.initialize()
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        before = await service.store.get_user(uid)
        await _mint_action(c, f"/ui/users/{uid}/{action}")
        monkeypatch.setattr(
            service_module,
            "secrets",
            SimpleNamespace(token_urlsafe=lambda n=None: "zq-globex-" + "v" * 40),
        )
        r = await c.post(f"/ui/users/{uid}/{action}", headers={"Sec-Fetch-Site": "same-origin"})
        # BACKLOG #2359: a server-side refusal stays a 503 on the console, as on the JSON API, and
        # the service's one audit row is the console's too.
        assert r.status_code == 503 and "password_extra_context_words" in r.text
        refused = await service.store.list_audit(action="auth.credential_issue_refused", limit=10)
        assert len(refused) == 1, "one refusal, one audit row"
        expected_op = {"reset-mfa": "mfa_reset", "reset-password": "password_reset"}[action]
        assert json.loads(refused[0]["detail"])["op"] == expected_op
        after = await service.store.get_user(uid)
        assert after == before, "a refused issue changed the account"
        monkeypatch.undo()
        r = await c.post(f"/ui/users/{uid}/{action}", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 200, "the refunded grant did not open the action"
        # ...and that success spent it: single-use still holds on the console plane after a refund.
        r = await c.post(f"/ui/users/{uid}/{action}", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code != 200, "the refunded grant opened the action twice"


async def test_delete_user_roundtrip_and_self_guard(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "u2", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u2")
        r = await c.post(f"/ui/users/{uid}/delete", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/users"
        assert await service.store.get_user(uid) is None
        boss_id = await _uid(service, "boss")
        r = await c.post(f"/ui/users/{boss_id}/delete", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 400 and "cannot delete your own account" in r.text
        assert await service.store.get_user(boss_id) is not None


async def test_custom_role_lifecycle_via_ui(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        # Create.
        r = await _post_pairs(
            c,
            "/ui/roles/custom",
            [
                ("display_name", "Ops Lite"),
                ("description", "read-only ops"),
                ("permissions", "monitoring:read"),
                ("permissions", "messages:read"),
            ],
        )
        assert r.status_code == 303
        customs = await service.list_custom_roles()
        assert len(customs) == 1 and customs[0].display_name == "Ops Lite"
        role_id = customs[0].id
        # Listed + editable.
        assert "Ops Lite" in (await c.get("/ui/roles")).text
        assert (await c.get(f"/ui/roles/{role_id}/edit")).status_code == 200
        # Update narrows the permission set.
        r = await _post_pairs(
            c,
            f"/ui/roles/custom/{role_id}/update",
            [("display_name", "Ops Lite"), ("permissions", "monitoring:read")],
        )
        assert r.status_code == 303
        customs = await service.list_custom_roles()
        assert [p.value for p in customs[0].permissions] == ["monitoring:read"]
        # Delete.
        r = await c.post(
            f"/ui/roles/custom/{role_id}/delete", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 303
        assert await service.list_custom_roles() == []


async def test_custom_role_forbidden_permission_rejected(engine: Engine) -> None:
    # The escalation carve-outs (ADR 0045 D1) are not offered on the form AND are refused if posted.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        form = await c.get("/ui/roles/new")
        assert form.status_code == 200
        assert 'value="users:manage"' not in form.text  # not offered
        r = await _post_pairs(
            c,
            "/ui/roles/custom",
            [("display_name", "Sneaky"), ("permissions", "users:manage")],
        )
        assert r.status_code == 400  # refused by the service's validator
        assert await service.list_custom_roles() == []


async def test_builtin_role_edit_is_404(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        assert (await c.get("/ui/roles/administrator/edit")).status_code == 404


async def test_ad_group_inputs_show_an_example_dn(engine: Engine) -> None:
    """BACKLOG #3222: both maps take a full DN only, so every group input says what one looks
    like. Three blank rows per map, and no stored rows yet."""
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.get("/ui/ad-groups")
        assert r.status_code == 200
        hint = 'placeholder="CN=MF-Admins,OU=Groups,DC=example,DC=com"'
        assert r.text.count(hint) == r.text.count('name="ad_group"') == 6


async def test_ad_group_maps_roundtrip(engine: Engine) -> None:
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        assert (await c.get("/ui/ad-groups")).status_code == 200
        # Role map: one real row + one blank filler row (dropped).
        r = await _post_pairs(
            c,
            "/ui/ad-groups/map",
            [
                ("ad_group", "CN=MEFOR-Admins,OU=Groups,DC=example,DC=invalid"),
                ("role", "administrator"),
                ("ad_group", ""),
                ("role", ""),
            ],
        )
        assert r.status_code == 303
        rows = await service.store.list_ad_group_role_map()
        assert [(x["ad_group"], x["role_id"]) for x in rows] == [
            ("cn=mefor-admins,ou=groups,dc=example,dc=invalid", "administrator")
        ]  # groups are case-normalized
        # Unknown role id: 400, map unchanged.
        g2 = "CN=G2,OU=Groups,DC=example,DC=invalid"
        r = await _post_pairs(c, "/ui/ad-groups/map", [("ad_group", g2), ("role", "not-a-role")])
        assert r.status_code == 400 and "unknown role" in r.text
        assert len(await service.store.list_ad_group_role_map()) == 1
        # A short name is refused on both forms, and the page says why (BACKLOG #2610).
        for path, partner in (
            ("/ui/ad-groups/map", "role"),
            ("/ui/ad-groups/scope-map", "channel"),
        ):
            value = "administrator" if partner == "role" else "*"
            r = await _post_pairs(c, path, [("ad_group", "MEFOR-Ops"), (partner, value)])
            assert r.status_code == 400 and "full distinguished name" in r.text
            # A no-break space at the end is refused too, not trimmed (BACKLOG #3222).
            nbsp = "CN=MEFOR-Ops,OU=Groups,DC=example,DC=invalid\u00a0"
            r = await _post_pairs(c, path, [("ad_group", nbsp), (partner, value)])
            assert r.status_code == 400 and "does not print" in r.text
        assert len(await service.store.list_ad_group_role_map()) == 1
        assert await service.store.list_ad_group_scope_map() == []
        # Scope map round-trip.
        r = await _post_pairs(
            c,
            "/ui/ad-groups/scope-map",
            [("ad_group", "CN=MEFOR-Ops,OU=Groups,DC=example,DC=invalid"), ("channel", "*")],
        )
        assert r.status_code == 303
        rows = await service.store.list_ad_group_scope_map()
        assert [(x["ad_group"], x["channel"]) for x in rows] == [
            ("cn=mefor-ops,ou=groups,dc=example,dc=invalid", "*")
        ]


async def test_admin_pages_escape_hostile_display_name(engine: Engine) -> None:
    # An admin-entered display name is DATA: it must render escaped on the list + detail pages.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await c.post(
            "/ui/users",
            data={
                "username": "hostile",
                "display_name": "<script>alert(9)</script>",
                "email": "hostile@x.org",
            },
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200
        for url in ("/ui/users", f"/ui/users/{await _uid(service, 'hostile')}"):
            body = (await c.get(url)).text
            assert "<script>alert(9)</script>" not in body
            assert "&lt;script&gt;alert(9)&lt;/script&gt;" in body


async def test_the_create_form_requires_a_notification_address(engine: Engine) -> None:
    """BACKLOG #2018 (ASVS 6.3.7): the console refuses a create with no address, as the API does,
    and re-renders the form with the service's reason. The control is the same form with one."""
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        form = await c.get("/ui/users/new")
        [email_input] = re.findall(r'<input[^>]*name="email"[^>]*>', form.text)
        assert "required" in email_input
        for email in ("", "a@b.org, c@d.org"):
            r = await c.post(
                "/ui/users",
                data={"username": "nomail", "email": email},
                headers={"Sec-Fetch-Site": "same-origin"},
            )
            assert r.status_code == 400, email
            assert "notification address" in r.text or "one email address" in r.text
            assert await service.store.get_user_by_username("nomail") is None
        r = await c.post(
            "/ui/users",
            data={"username": "nomail", "email": "nomail@x.org"},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 200
        user = await service.store.get_user_by_username("nomail")
        assert user is not None and user.notify_email == "nomail@x.org"


# --- L4a review-driven regressions (adversarial review PR2: 1 high, 1 medium, test gaps) -----------


async def test_ad_group_map_asymmetric_rows_never_cross_bind(engine: Engine) -> None:
    # PR2-H1 regression: blank fields MUST keep their positional slot (keep_blank_values=True) so a
    # role selected on one row can never bind to a group typed on another. Both rows here are
    # incomplete row-wise (one lost its group, the other never chose a role) — both are dropped.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        r = await _post_pairs(
            c,
            "/ui/ad-groups/map",
            [
                ("ad_group", ""),  # row 1: group cleared...
                ("role", "administrator"),  # ...but its select still says administrator
                ("ad_group", "G2"),  # row 2: new group typed...
                ("role", ""),  # ...role never selected
            ],
        )
        assert r.status_code == 303
        # No cross-bound G2->administrator entry — the map is empty (both rows dropped row-wise).
        assert await service.store.list_ad_group_role_map() == []
        # Same invariant on the scope map (the '*' all-channels grant must never cross-bind).
        r = await _post_pairs(
            c,
            "/ui/ad-groups/scope-map",
            [("ad_group", ""), ("channel", "*"), ("ad_group", "G3"), ("channel", "")],
        )
        assert r.status_code == 303
        assert await service.store.list_ad_group_scope_map() == []


async def test_stale_stepup_bounces_body_less_action_via_reauth(engine: Engine) -> None:
    # A body-less auto-retry action under a stale window 303s to /ui/reauth carrying ITS OWN path
    # (no reauth_next mapping) — and nothing is deleted until the retry actually runs.
    # require_mfa=False takes the MFA leg out of the gate, so the stale window below is what
    # redirects; without it _boss_client's unenrolled session is refused first with the SAME 303 and
    # the window measures nothing (BACKLOG #1850). Reasoning, and the third new-IP leg that stays
    # unpinned: the docstring of test_purge_stale_stepup_redirects_to_reauth (BACKLOG #1700).
    service = AuthService(engine.store, AuthSettings(require_mfa=False, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "u9", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True  # the MFA leg is NOT what refuses here
        assert await service.has_recent_step_up(tok) is False  # the stale window is
        uid = await _uid(service, "u9")
        r = await c.post(f"/ui/users/{uid}/delete", headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code == 303
        assert r.headers["location"] == f"/ui/reauth?next=/ui/users/{uid}/delete"
        assert await service.store.get_user(uid) is not None  # nothing happened yet


async def test_stale_stepup_bounces_all_unlock_form_pages(engine: Engine) -> None:
    # Every unlock FORM page is step-up-gated: a stale window 303s each to /ui/reauth with its own
    # path as next (a regression to plain require_ui would silently drop the step-up gate).
    # require_mfa=False takes the MFA leg out of the gate, so the stale window below is what
    # redirects; without it _boss_client's unenrolled session is refused first with the SAME 303 and
    # the window measures nothing (BACKLOG #1850). Reasoning, and the third new-IP leg that stays
    # unpinned: the docstring of test_purge_stale_stepup_redirects_to_reauth (BACKLOG #1700).
    service = AuthService(engine.store, AuthSettings(require_mfa=False, step_up_max_age_seconds=-1))
    await service.initialize()
    await _add(service, "u9", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        tok = c.cookies.get("mf_session")
        assert tok is not None
        assert await service.mfa_satisfied(tok) is True  # the MFA leg is NOT what refuses here
        assert await service.has_recent_step_up(tok) is False  # the stale window is
        uid = await _uid(service, "u9")
        for path in (f"/ui/users/{uid}", "/ui/roles/new", "/ui/ad-groups"):
            r = await c.get(path)
            assert r.status_code == 303, path
            assert r.headers["location"] == f"/ui/reauth?next={path}", path
        # The custom-role edit form too. Pin the percent-encoding the comment used to only claim:
        # _reauth_redirect quotes with safe="/", so the role id's colon rides as %3A.
        r = await c.get("/ui/roles/custom:x/edit")
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/reauth?next=/ui/roles/custom%3Ax/edit"


async def test_users_read_only_role_cannot_reach_admin_writes(engine: Engine) -> None:
    # users:read is grantable via a custom role (users:manage is a forbidden carve-out): such a user
    # sees the read pages but every form page and write is refused — the read/manage split is real.
    service = await _service(engine)
    role = await service.create_custom_role(
        display_name="User Auditor",
        description=None,
        permissions=["users:read", "monitoring:read"],
        actor="test",
    )
    await _add_with_role_ids(service, "reader", [role.id])
    async with _client(engine, service) as c:
        await _cookie_login(c, "reader")
        assert (await c.get("/ui/users")).status_code == 200
        assert (await c.get("/ui/roles")).status_code == 200
        for get_path in ("/ui/users/new", "/ui/ad-groups"):
            assert (await c.get(get_path)).status_code == 403, get_path
        r = await c.post(
            "/ui/users",
            data={"username": "nope", "password": PW},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert r.status_code == 403
        assert await service.store.get_user_by_username("nope") is None


async def test_all_admin_posts_reject_cross_site(engine: Engine) -> None:
    # assert_same_origin is a per-route inline call — sweep EVERY state-changing admin POST so a
    # forgotten call in any one route fails loudly.
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        boss_id = await _uid(service, "boss")
        # 7.5.1: the two action-bound webauthn POSTs (enroll, delete) need a fresh grant to reach their
        # in-body assert_same_origin — mint them so the cross-site sweep still exercises the 403 (a
        # missing assert_same_origin on those routes must fail loudly, not hide behind a no-grant 303).
        await _mint_action(c, "/ui/account/webauthn/enroll")
        await _mint_action(c, "/ui/account/webauthn/abc123/delete")
        # BACKLOG #1148 puts the two admin reset lanes into that same shape, #1737 the update lane
        # (whose grant mints against the detail PAGE — the POST path is not a continuation).
        await _mint_action(c, f"/ui/users/{boss_id}/reset-password")
        await _mint_action(c, f"/ui/users/{boss_id}/reset-mfa")
        await _mint_action(c, f"/ui/users/{boss_id}")
        posts = [
            "/ui/users",
            f"/ui/users/{boss_id}/update",
            f"/ui/users/{boss_id}/roles",
            f"/ui/users/{boss_id}/channel-scope",
            f"/ui/users/{boss_id}/reset-password",
            f"/ui/users/{boss_id}/reset-mfa",
            f"/ui/users/{boss_id}/revoke-sessions",
            f"/ui/users/{boss_id}/delete",
            "/ui/roles/custom",
            "/ui/roles/custom/custom:x/update",
            "/ui/roles/custom/custom:x/delete",
            "/ui/ad-groups/map",
            "/ui/ad-groups/scope-map",
            # L5a (ADR 0068): the passkey POSTs join the sweep (AC-9).
            "/ui/account/webauthn/enroll",
            "/ui/account/webauthn/verify",
            "/ui/account/webauthn/abc123/delete",
            "/ui/reauth/webauthn",
        ]
        for path in posts:
            r = await c.post(path, headers={"Sec-Fetch-Site": "cross-site"})
            assert r.status_code == 403, path


async def test_admin_cookie_not_accepted_on_json_routes(engine: Engine) -> None:
    # The /ui cookie must never authorize the JSON admin analogues (bearer-header only).
    service = await _service(engine)
    async with _boss_client(engine, service) as c:
        boss_id = await _uid(service, "boss")
        assert (await c.get("/users")).status_code == 401
        assert (await c.get("/roles")).status_code == 401
        assert (await c.get("/ad-group-map")).status_code == 401
        assert (
            await c.put(f"/users/{boss_id}/roles", json={"roles": ["viewer"]})
        ).status_code == 401
        assert (await c.delete(f"/users/{boss_id}")).status_code == 401


async def test_a_hostile_role_id_is_refused_before_anything_can_echo_it(engine: Engine) -> None:
    # This used to post a hostile role id, rely on _validate_roles echoing it into the 400 detail,
    # and assert the banner escaped it. Since BACKLOG #1108 the role-id rule refuses that value at
    # RolesUpdateRequest, so it never reaches _validate_roles and the route renders its own fixed
    # "invalid input" instead. That is the stronger property and it is what this now pins.
    #
    # The escaping half did NOT move with it. Losing an XSS regression guard because an upstream
    # rule made one route stop delivering hostile text is exactly how a guard goes quiet, so it is
    # re-armed directly against the renderer in the test below, where no upstream rule can disarm it.
    service = await _service(engine)
    await _add(service, "u1", Role.VIEWER)
    async with _boss_client(engine, service) as c:
        uid = await _uid(service, "u1")
        hostile = "<img src=x onerror=alert(1)>"
        r = await _post_pairs(c, f"/ui/users/{uid}/roles", [("roles", hostile)])
        assert r.status_code == 400
        # Neither the raw value nor an escaped copy of it: the page never saw it.
        assert hostile not in r.text
        assert "&lt;img src=x onerror=alert(1)&gt;" not in r.text
        assert "invalid input" in r.text
        # The control: a well-formed role id that no role carries still reaches the handler, so the
        # route's OTHER arm is alive and the refusal above is the rule and not a dead route.
        ok = await _post_pairs(c, f"/ui/users/{uid}/roles", [("roles", "nosuchrole")])
        assert ok.status_code == 400 and "invalid input" not in ok.text


def test_the_error_banner_escapes_hostile_text() -> None:
    """The reflected-XSS guard for every rerender-with-error path, armed at the renderer itself.

    Driven directly rather than through a route: a route can stop being able to deliver hostile text
    (see above), and when that happens a route-driven guard passes while measuring nothing.
    """
    from messagefoundry.api.auth_models import UserSummary
    from messagefoundry_webconsole import pages

    user = UserSummary(
        id="0" * 32,
        username="u1",
        auth_provider="local",
        disabled=False,
        roles=["viewer"],
        channel_scope_withheld=False,
    )
    hostile = "<img src=x onerror=alert(1)>"
    page = str(pages.user_detail_page(user, [], error=hostile))
    assert hostile not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    # The control: an ordinary message still renders, so the assertion above is escaping and not
    # the banner having been dropped.
    assert "something went wrong" in str(
        pages.user_detail_page(user, [], error="something went wrong")
    )


async def test_ad_user_carveouts_on_ui_surface(engine: Engine) -> None:
    # An AD account: roles come from the AD-group map and the password from the directory — the
    # detail page hides those forms, and a forged direct POST is refused by the handler guards.
    # Reset MFA is NOT among them since BACKLOG #1144: a directory account can hold an engine factor,
    # so the button is its only recovery from a lost authenticator and hiding it would make
    # enrollment a one-way door. That is the half of the carve-out set this test now pins OPEN.
    service = await _service(engine)
    await service.store.create_user(
        user_id="ad-user-1",
        username="aduser",
        auth_provider="ad",
        display_name="AD User",
        password_generated=False,
    )
    async with _boss_client(engine, service) as c:
        detail = await c.get("/ui/users/ad-user-1")
        assert detail.status_code == 200
        assert "AD users get roles from the AD-group map" in detail.text
        assert 'action="/ui/users/ad-user-1/roles"' not in detail.text
        assert 'action="/ui/users/ad-user-1/reset-password"' not in detail.text
        assert 'action="/ui/users/ad-user-1/reset-mfa"' in detail.text
        r = await _post_pairs(c, "/ui/users/ad-user-1/roles", [("roles", "viewer")])
        assert r.status_code == 400 and "AD-group map" in r.text
        assert await service.store.get_user_role_ids("ad-user-1") == []
        # BACKLOG #1148: mint the grant FIRST, or the 400 below is never reached -- the action gate
        # runs before the body and would 303 to reauth, so this would silently stop measuring the
        # AD carve-out it is named for and start measuring the step-up.
        await _mint_action(c, "/ui/users/ad-user-1/reset-password")
        r = await c.post(
            "/ui/users/ad-user-1/reset-password", headers={"Sec-Fetch-Site": "same-origin"}
        )
        assert r.status_code == 400  # only local users have an engine password
