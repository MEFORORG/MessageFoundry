# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5559: the console's user pages read an account only through the engine's checked read.

The detail page, the federated identity screen and its unlink confirmation, and the channel scope
save each read the account through ``AdminHandlers.checked_user``, which is the JSON plane's own
``_checked_user``. So a row altered outside the store, on a keyed store, is answered 423 with none
of what was planted shown, and the failure is handed to the seal-failure report, which writes the
``integrity.authority_seal_failed`` row and raises the alert. Before #5559 these read the store row
directly: the page showed the planted values with a 200 and nothing was recorded.

The users list keeps such an account by id alone (BACKLOG #5520) and, to a users:manage holder,
links to its delete confirmation, the one action the console takes on it, since its detail page
answers 423.

Every test has a control: the same read of an intact account, or of the same account before the
tampering.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from _ui_clients import SAME_ORIGIN, cookie_login, mint_bound_proof, provision
from _webui_support import _client

from messagefoundry.auth import Role
from messagefoundry.auth.service import (
    AUTHORITY_SEAL_FAILED_ACTION,
    USER_SEAL_REFUSED,
    AuthService,
    LastAdministratorRefused,
    UserSealRefused,
)
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

#: What the tampering writes. None of it may appear in an answer.
_PLANTED = "planted-outside-the-store"


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[Engine, Path]]:
    """An engine on a keyed store, so each account record carries an integrity seal."""
    path = tmp_path / "console_user_seal.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    engine = Engine(
        store, poll_interval=0.02, egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        yield engine, path
    finally:
        await engine.stop()


def _tamper(path: Path, user_id: str) -> None:
    """Alter the account's sealed fields on a connection that holds no store key."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "UPDATE users SET display_name=?, channel_scope=?, oidc_issuer=?, oidc_subject=? "
            "WHERE id=?",
            (_PLANTED, f'["{_PLANTED}"]', _PLANTED, _PLANTED, user_id),
        )
        conn.commit()
    finally:
        conn.close()


async def _setup(engine: Engine) -> tuple[AuthService, list[str], str, str]:
    """An administrator ``root``, an intact viewer and a viewer whose row a test then alters."""
    alerts: list[str] = []
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            mfa_verify_min_elapsed_seconds=0,
            require_mfa=False,
        ),
        integrity_alert=alerts.append,
    )
    await service.initialize()
    await provision(service, "root", [Role.ADMINISTRATOR.value])
    intact = await provision(service, "intact", [Role.VIEWER.value])
    victim = await provision(service, "victim", [Role.VIEWER.value])
    return service, alerts, intact, victim


async def _seal_failures(engine: Engine, user_id: str) -> int:
    rows = await engine.store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION, limit=10_000)
    return sum(1 for row in rows if user_id in str(row["detail"]))


async def test_the_detail_page_answers_423_for_a_record_that_fails_its_seal(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, alerts, intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        before = await c.get(f"/ui/users/{victim}")
        assert before.status_code == 200 and "victim" in before.text  # control: before tampering
        _tamper(path, victim)
        r = await c.get(f"/ui/users/{victim}")
        ok = await c.get(f"/ui/users/{intact}")
    assert r.status_code == 423
    assert _PLANTED not in r.text and "victim" not in r.text
    assert USER_SEAL_REFUSED in r.text
    assert await _seal_failures(engine, victim) == 1 and alerts
    assert ok.status_code == 200 and "intact" in ok.text  # control: an intact account


async def test_the_federated_screens_answer_423_for_a_record_that_fails_its_seal(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        screen = await c.get(f"/ui/users/{victim}/federated-identity")
        confirm = await c.get(f"/ui/users/{victim}/federated-identity/unlink-confirm")
        ok = await c.get(f"/ui/users/{intact}/federated-identity")
    for r in (screen, confirm):
        assert r.status_code == 423, r.text
        assert _PLANTED not in r.text
    assert await _seal_failures(engine, victim) == 1  # one report per interval
    assert ok.status_code == 200 and "intact" in ok.text  # control


async def test_a_refused_scope_save_does_not_render_a_record_that_fails_its_seal(
    keyed: tuple[Engine, Path],
) -> None:
    """The channel scope save read the row raw, decided the manual-scope check from it, and
    re-rendered its refusals on the detail page. A post that would be refused for its form (an
    unknown scope mode) is answered 423 first, so nothing is decided from the planted row."""
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    form = {"scope_mode": "bogus"}
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        r = await c.post(f"/ui/users/{victim}/channel-scope", data=form, headers=SAME_ORIGIN)
        ok = await c.post(f"/ui/users/{intact}/channel-scope", data=form, headers=SAME_ORIGIN)
    assert r.status_code == 423
    assert _PLANTED not in r.text
    assert await _seal_failures(engine, victim) == 1
    assert ok.status_code == 400 and "unknown scope mode" in ok.text  # control


async def test_a_failing_account_is_listed_with_its_delete_and_the_delete_removes_it(
    keyed: tuple[Engine, Path],
) -> None:
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        listed = await c.get("/ui/users")
        assert listed.status_code == 200
        # The list leads to a confirmation and holds no form that deletes.
        assert f'href="/ui/users/{victim}/delete-confirm"' in listed.text
        assert f'action="/ui/users/{victim}/delete"' not in listed.text
        assert _PLANTED not in listed.text
        # Control: an intact account is linked and offers no delete on the list.
        assert f'href="/ui/users/{intact}"' in listed.text
        assert f"/ui/users/{intact}/delete" not in listed.text
        confirm = await c.get(f"/ui/users/{victim}/delete-confirm")
        assert confirm.status_code == 200
        assert f'action="/ui/users/{victim}/delete"' in confirm.text and victim in confirm.text
        assert _PLANTED not in confirm.text and "victim" not in confirm.text
        # Control: an intact account's confirmation claims no failed check; it goes to the
        # account's own page. A missing one answers 404.
        intact_confirm = await c.get(f"/ui/users/{intact}/delete-confirm")
        assert intact_confirm.status_code == 303
        assert intact_confirm.headers["location"] == f"/ui/users/{intact}"
        assert (await c.get("/ui/users/no-such-account/delete-confirm")).status_code == 404
        r = await c.post(f"/ui/users/{victim}/delete", headers=SAME_ORIGIN)
    assert r.status_code == 303 and r.headers["location"] == "/ui/users"
    assert await engine.store.get_user(victim) is None
    assert await engine.store.get_user(intact) is not None


async def test_a_refused_delete_of_a_failing_account_answers_its_own_refusal(
    keyed: tuple[Engine, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused delete re-renders the detail page, which answers 423 for a record that fails its
    seal. For the delete the confirmation offers on such a row, the delete's own refusal is the answer.
    The refusal is stood in for at the service's delete; the control is the same refusal on an
    intact account, shown on its detail page."""
    engine, path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    _tamper(path, victim)
    refusal = "stand-in: this would leave no enabled administrator"

    async def refused(user_id: str, *, actor: str) -> None:
        raise LastAdministratorRefused(refusal)

    monkeypatch.setattr(service, "delete_user", refused)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        r = await c.post(f"/ui/users/{victim}/delete", headers=SAME_ORIGIN)
        ok = await c.post(f"/ui/users/{intact}/delete", headers=SAME_ORIGIN)
    assert r.status_code == 400 and refusal in r.text
    assert _PLANTED not in r.text
    assert ok.status_code == 400 and refusal in ok.text and "User: intact" in ok.text  # control
    assert await engine.store.get_user(victim) is not None


async def test_a_refused_delete_keeps_its_own_refusal_when_the_page_read_is_unavailable(
    keyed: tuple[Engine, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused delete re-renders the detail page. When that page's checked read answers 503 (a
    Vault transit Outage), the delete's own refusal is still the answer rather than the 503. The
    control is the 423 case in the test above."""
    from messagefoundry.store.row_seal import TransitSealUnavailableError

    engine, _path = keyed
    service, _alerts, intact, _victim = await _setup(engine)
    refusal = "stand-in: this would leave no enabled administrator"

    async def refused(user_id: str, *, actor: str) -> None:
        raise LastAdministratorRefused(refusal)

    async def outage(user_id: str) -> None:
        raise TransitSealUnavailableError()

    monkeypatch.setattr(service, "delete_user", refused)
    monkeypatch.setattr(service, "checked_user", outage)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        r = await c.post(f"/ui/users/{intact}/delete", headers=SAME_ORIGIN)
    assert r.status_code == 400 and refusal in r.text
    assert await engine.store.get_user(intact) is not None


async def test_a_refused_delete_of_an_account_gone_since_answers_404(
    keyed: tuple[Engine, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A refused delete whose page read finds no account answers 404, not the stale refusal. The
    control is the 503 case above."""
    engine, _path = keyed
    service, _alerts, intact, _victim = await _setup(engine)
    refusal = "stand-in: this would leave no enabled administrator"

    async def refused(user_id: str, *, actor: str) -> None:
        raise LastAdministratorRefused(refusal)

    async def gone(user_id: str) -> None:
        return None

    monkeypatch.setattr(service, "delete_user", refused)
    monkeypatch.setattr(service, "checked_user", gone)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        r = await c.post(f"/ui/users/{intact}/delete", headers=SAME_ORIGIN)
    assert r.status_code == 404 and refusal not in r.text


@pytest.mark.parametrize(
    "failure",
    [UserSealRefused(USER_SEAL_REFUSED), RuntimeError("stand-in: a store read failed")],
    ids=["refused", "read-failed"],
)
async def test_a_page_after_a_landed_action_names_the_account_only_from_a_checked_read(
    keyed: tuple[Engine, Path],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure: Exception,
) -> None:
    """The password reset lands through the engine's own checks, then the page that hands over the
    one-time credential names the account. That name is read through the checked read; when it
    refuses or fails in any other way, the page names the id and the credential is still shown,
    since it was issued. The failure is stood in for at the service's checked reader, after the
    reset's own read."""
    engine, _path = keyed
    service, _alerts, intact, victim = await _setup(engine)
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        path = f"/ui/users/{intact}/reset-password"
        await mint_bound_proof(c, path)
        ok = await c.post(path, headers=SAME_ORIGIN)
        assert ok.status_code == 200 and "Convey this to intact " in ok.text  # control

        async def failing(user_id: str) -> None:
            raise failure

        monkeypatch.setattr(service, "checked_user", failing)
        path = f"/ui/users/{victim}/reset-password"
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
    assert r.status_code == 200
    assert "Temporary password issued" in r.text and "<code>" in r.text
    assert f"Convey this to {victim} " in r.text and "Convey this to victim " not in r.text
    # The fallback is logged with the account's id, and a refusal's text, which can carry the
    # record's values, is not.
    fallback = [
        rec
        for rec in caplog.records
        if rec.levelname == "WARNING"
        and victim in rec.getMessage()
        and "names the account by id" in rec.getMessage()
    ]
    assert fallback
    assert all(not rec.exc_info and "stand-in" not in rec.getMessage() for rec in fallback)


@pytest.mark.parametrize(
    "defect",
    [TypeError("stand-in: a defect"), NotImplementedError("stand-in: a listed defect")],
    ids=["outside-the-refusals", "listed-defect"],
)
async def test_a_defect_in_the_post_action_name_read_still_shows_the_credential(
    keyed: tuple[Engine, Path],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    defect: Exception,
) -> None:
    """The reset has landed by the time its page reads the name, and its one-time credential is
    shown nowhere else. So an error outside the refusal set, and a listed defect inside it
    (``AUDIT_WRITE_DEFECTS``; NotImplementedError is a RuntimeError), still render the page with
    the id, and log an ERROR with the traceback. On the code before this test they raised, and the
    credential was lost. The control for a refusal is the test above."""
    engine, _path = keyed
    service, _alerts, _intact, victim = await _setup(engine)

    async def failing(user_id: str) -> None:
        raise defect

    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        monkeypatch.setattr(service, "checked_user", failing)
        path = f"/ui/users/{victim}/reset-password"
        await mint_bound_proof(c, path)
        r = await c.post(path, headers=SAME_ORIGIN)
    assert r.status_code == 200
    assert "Temporary password issued" in r.text and "<code>" in r.text
    assert f"Convey this to {victim} " in r.text
    assert any(
        rec.levelname == "ERROR"
        and victim in rec.getMessage()
        and rec.exc_info is not None
        and rec.exc_info[1] is defect
        for rec in caplog.records
    )


async def test_the_summary_takes_its_roles_from_a_checked_record_only(
    keyed: tuple[Engine, Path],
) -> None:
    """``user_summary_scoped`` with ``role_ids`` None takes the role rows a checked record's seal
    covered, so the detail page reads none itself. Given a store row nobody checked, it raises
    rather than read roles the seal did not cover."""
    from messagefoundry.api.auth_routes import _console_user_summary

    engine, _path = keyed
    service, _alerts, intact, _victim = await _setup(engine)
    checked = await service.checked_user(intact)
    assert checked is not None
    summary = _console_user_summary(checked, None, show_scope=True)
    assert summary.roles == [Role.VIEWER.value]
    raw = await engine.store.get_user(intact)
    assert raw is not None
    with pytest.raises(TypeError, match="checked record"):
        _console_user_summary(raw, None, show_scope=True)
    # Control: a raw row with its roles passed explicitly still projects, as before.
    assert _console_user_summary(raw, [Role.VIEWER.value], show_scope=True).roles == [
        Role.VIEWER.value
    ]


def test_the_delete_confirmation_offers_no_form_for_the_callers_own_account() -> None:
    """The delete refuses the caller's own account, so its confirmation says so and offers no
    form. The control is the same page for another account."""
    from messagefoundry_webconsole.pages.admin import user_delete_confirm_page

    own = str(user_delete_confirm_page("u1", is_self=True))
    other = str(user_delete_confirm_page("u1", is_self=False))
    assert "/ui/users/u1/delete" not in own and "cannot delete your own account" in own
    assert 'action="/ui/users/u1/delete"' in other  # control


async def test_a_users_read_only_reader_is_offered_no_delete_of_a_failing_account(
    keyed: tuple[Engine, Path],
) -> None:
    """The delete route needs ``users:manage``, so the list offers a reader holding ``users:read``
    alone no delete of a failing row, and the confirmation refuses that reader too. The control is
    the administrator's list of the same account."""
    engine, path = keyed
    service, _alerts, _intact, victim = await _setup(engine)
    role = await service.create_custom_role(
        display_name="User reader", description=None, permissions=["users:read"], actor="test"
    )
    await provision(service, "reader", [role.id])
    _tamper(path, victim)
    async with _client(engine, service) as c:
        await cookie_login(c, "reader")
        listed = await c.get("/ui/users")
        confirm = await c.get(f"/ui/users/{victim}/delete-confirm")
    assert listed.status_code == 200 and victim in listed.text
    assert "integrity check failed" in listed.text
    assert f"/ui/users/{victim}/delete" not in listed.text
    assert confirm.status_code == 403
    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        boss = await c.get("/ui/users")
    assert f'href="/ui/users/{victim}/delete-confirm"' in boss.text  # control


@pytest.mark.parametrize(
    "form",
    [
        {"scope_mode": "bogus"},
        {"scope_mode": "list", "channels": ""},
        {"scope_mode": "list", "channels": "*"},
    ],
    ids=["unknown-mode", "empty-list", "all-channels-token"],
)
async def test_a_refused_scope_save_reads_the_account_once(
    keyed: tuple[Engine, Path], monkeypatch: pytest.MonkeyPatch, form: dict[str, str]
) -> None:
    """A channel-scope post refused for its form re-renders the detail page from the record the
    save already read through the checked read, rather than reading the account a second time.
    The control is the refusal's own page, which names the account."""
    engine, _path = keyed
    service, _alerts, intact, _victim = await _setup(engine)
    reads: list[str] = []
    real = service.checked_user

    async def counting(user_id: str) -> object:
        reads.append(user_id)
        return await real(user_id)

    async with _client(engine, service) as c:
        await cookie_login(c, "root")
        monkeypatch.setattr(service, "checked_user", counting)
        r = await c.post(f"/ui/users/{intact}/channel-scope", data=form, headers=SAME_ORIGIN)
    assert r.status_code == 400 and "User: intact" in r.text
    assert reads.count(intact) == 1, reads
