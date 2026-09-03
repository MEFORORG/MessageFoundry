# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""/ui uploaded-logs page smoke tests (BACKLOG #125/#126, ADR 0134).

The console reaches the engine through the seam-v7 CoreHandlers; these drive the cookie flow end to
end (upload → list → browse → delete) and the RBAC/off-by-default gates."""

from __future__ import annotations

import logging
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import AuthSettings, StoreSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import Engine

PW = "Correct-Horse-Battery-Staple-9"
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||MRN123^^^H^MR||DOE^JANE\r"
ADT2 = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A04|MSG2|P|2.5.1\rPID|1||MRN999\r"
BATCH = ADT + ADT2


async def _add_user(
    service: AuthService, name: str, role: Role, *, channels: list[str] | None = None
) -> str:
    """Create a sign-in-ready local user. ``channels`` sets the per-channel RBAC scope; it is applied
    BEFORE the first login because set_channel_scope revokes the user's sessions.

    ``None`` means "this test is not about the channel axis" and grants the whole estate. Before
    BACKLOG #1152 that was what saying nothing already did; an unset scope now denies, and leaving
    these fixtures unscoped would answer 403 on the resend target inbound for a reason this file --
    which is about the uploads OWNER axis (ASVS 8.2.2) -- never asserts."""
    uid = await service.create_local_user(
        username=name, password=PW, display_name=None, email=None, roles=[role.value], actor="t"
    )
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False
    )
    # `is None`, not falsiness: an explicitly EMPTY list means deny-all and must survive as one.
    await service.set_channel_scope(
        uid, [ALL_CHANNELS] if channels is None else channels, actor="t"
    )
    return uid


async def _service(
    engine: Engine, *users: tuple[str, Role], per_actor: int = 120, step_up_max_age: int = 300
) -> AuthService:
    # per_actor mirrors AuthSettings' default (120); pass a smaller value to exercise the per-actor
    # PHI-read budget in a single test (see test_webui.py:616 test_edit_editor_charges_the_phi_read_budget).
    # step_up_max_age mirrors AuthSettings' default (300); pass -1 to make every step-up window stale
    # on arrival, the idiom the rest of the console suite uses to exercise the /ui/reauth bounce.
    service = AuthService(
        engine.store,
        AuthSettings(
            require_mfa=False,
            phi_read_rate_limit_per_actor=per_actor,
            step_up_max_age_seconds=step_up_max_age,
        ),
    )
    await service.initialize()
    for name, role in users:
        await _add_user(service, name, role)
    return service


def _app(engine: Engine, service: AuthService, tmp_path: Path, *, uploads: bool = True) -> object:
    store_settings = (
        StoreSettings(uploads_dir=str(tmp_path / "uploads"), max_upload_bytes=1_000_000)
        if uploads
        else None
    )
    return create_app(engine, auth=service, serve_ui=True, store_settings=store_settings)


async def _login(c: httpx.AsyncClient, name: str) -> None:
    r = await c.post("/ui/login", data={"username": name, "password": PW})
    assert r.status_code in (200, 303), r.text


async def _upload(c: httpx.AsyncClient, name: str = "acme.hl7") -> str:
    """Upload BATCH and return its file_id, read back off the listing's browse link."""
    up = await c.post(
        "/ui/uploaded-logs/upload", files={"file": (name, BATCH, "application/octet-stream")}
    )
    assert up.status_code in (200, 303), up.text
    listing = await c.get("/ui/uploaded-logs")
    fid = listing.text.split("/ui/uploaded-logs/file/", 1)[1].split('"', 1)[0].split("/")[0]
    assert len(fid) == 32
    return fid


async def test_uploaded_logs_ui_flow(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        # empty list renders
        r = await c.get("/ui/uploaded-logs")
        assert r.status_code == 200 and "Uploaded logs" in r.text

        # upload form + upload
        assert (await c.get("/ui/uploaded-logs/upload")).status_code == 200
        up = await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        assert up.status_code in (200, 303), up.text

        # the file now shows in the list
        r = await c.get("/ui/uploaded-logs")
        assert "acme.hl7" in r.text
        # find the file_id from the browse link
        marker = "/ui/uploaded-logs/file/"
        fid = r.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        assert len(fid) == 32

        # browse renders metadata only (no decrypted body)
        b = await c.get(f"/ui/uploaded-logs/file/{fid}")
        assert b.status_code == 200, b.text
        assert "ADT^A01" in b.text and "ADT^A04" in b.text
        assert "PID|" not in b.text and "MRN123" not in b.text

        # delete confirm → delete
        cf = await c.get(f"/ui/uploaded-logs/file/{fid}/delete-confirm")
        assert cf.status_code == 200 and "Delete uploaded file" in cf.text
        d = await c.post(f"/ui/uploaded-logs/file/{fid}/delete")
        assert d.status_code in (200, 303)
        assert "acme.hl7" not in (await c.get("/ui/uploaded-logs")).text


async def test_uploaded_logs_list_is_paged(engine: Engine, tmp_path: Path) -> None:
    """BACKLOG #1152: the console listing pages, and its counter says window-of-total.

    A bare count could not distinguish "you have three files" from "you are looking at three of
    forty", which is the reading that makes a pager invisible."""
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        for n in range(3):
            up = await c.post(
                "/ui/uploaded-logs/upload",
                files={"file": (f"page{n}.hl7", BATCH, "application/octet-stream")},
            )
            assert up.status_code in (200, 303), up.text

        first = await c.get("/ui/uploaded-logs", params={"limit": 2, "offset": 0})
        assert first.status_code == 200
        assert "1-2 of 3 file(s)" in first.text
        assert "Next" in first.text and "Previous" not in first.text
        assert "/ui/uploaded-logs?limit=2&amp;offset=2" in first.text

        last = await c.get("/ui/uploaded-logs", params={"limit": 2, "offset": 2})
        assert "3-3 of 3 file(s)" in last.text
        assert "Previous" in last.text and "Next" not in last.text
        # The two pages together are the whole set, and neither shows the other's file.
        shown = [n for n in range(3) if f"page{n}.hl7" in first.text + last.text]
        assert shown == [0, 1, 2]
        assert sum(f"page{n}.hl7" in first.text for n in range(3)) == 2

        # The /ui door is no looser than the JSON one: out-of-range bounds are refused, not clamped.
        assert (await c.get("/ui/uploaded-logs", params={"limit": 501})).status_code == 422
        assert (await c.get("/ui/uploaded-logs", params={"offset": -1})).status_code == 422


def test_upload_form_states_consent_affordance() -> None:
    # ASVS 14.2.8: the upload form states, above the submit button, what non-body metadata is retained and
    # who sees it — submitting the form IS the consent (no separate stored flag). Pure page-render check.
    from messagefoundry_webconsole import pages

    html = str(pages.uploaded_logs_upload())
    assert "original filename" in html and "your username" in html
    assert "authorized operators" in html and "audit log" in html
    assert "Submitting this form is your consent" in html
    # The consent notice sits inside the form, ABOVE the submit button.
    assert html.index("your consent") < html.index("Upload</button>")


async def test_uploaded_logs_ui_is_owner_scoped(engine: Engine, tmp_path: Path) -> None:
    # ASVS 8.2.2 (BACKLOG #1152): the object-level check lives in the ENGINE HANDLER bodies, so the
    # console inherits it over the seam — a /ui gate could not, because these /ui routes call the
    # handlers directly and never run their Depends. A second operator sees an empty list, and a deep
    # link to the browse page 303s back to the list (the console's own 404 arm), never the file.
    service = await _service(engine, ("op", Role.OPERATOR), ("op2", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        up = await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        assert up.status_code in (200, 303), up.text
        listing = await c.get("/ui/uploaded-logs")
        marker = "/ui/uploaded-logs/file/"
        fid = listing.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        assert len(fid) == 32

    # A SECOND client, because the console authenticates by session cookie (no per-request header).
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c2:
        await _login(c2, "op2")
        mine = await c2.get("/ui/uploaded-logs")
        assert mine.status_code == 200 and "acme.hl7" not in mine.text
        browse = await c2.get(f"/ui/uploaded-logs/file/{fid}", follow_redirects=False)
        assert browse.status_code == 303 and browse.headers["location"] == "/ui/uploaded-logs"
        confirm = await c2.get(
            f"/ui/uploaded-logs/file/{fid}/delete-confirm", follow_redirects=False
        )
        assert confirm.status_code == 303
        gone = await c2.post(f"/ui/uploaded-logs/file/{fid}/delete", follow_redirects=False)
        assert gone.status_code == 303

    # The file is still there for its owner — the denied delete unlinked nothing.
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c3:
        await _login(c3, "op")
        assert "acme.hl7" in (await c3.get("/ui/uploaded-logs")).text


async def test_browse_with_bad_criteria_never_answers_json_in_the_html_plane(
    engine: Engine, tmp_path: Path
) -> None:
    # The engine parses the content criteria BEFORE it authorizes the file, so a malformed filter 400s
    # first. The route's 400 arm re-invokes the browse with the criteria dropped, which now runs far
    # enough to 404 — and that 404 is raised INSIDE the except block, so without its own arm it escapes
    # the /ui route and renders as application/json in the HTML console. Two ways in, one fix: a
    # non-owner's file, and (pre-existing, not introduced by the owner check) an absent id.
    service = await _service(engine, ("op", Role.OPERATOR), ("op2", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        listing = await c.get("/ui/uploaded-logs")
        marker = "/ui/uploaded-logs/file/"
        fid = listing.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        # Positive control: the OWNER still gets the rendered 400 page, so the arm is not simply dead.
        # A malformed field_path is the URL-safe way to make the engine refuse the criteria now that
        # the needle is POST-only (BACKLOG #1184); make_spec rejects it before it authorizes the file,
        # which is the same arm the old ``?content=...&field_path=...`` pair reached.
        bad = await c.get(f"/ui/uploaded-logs/file/{fid}?field_path=not+a+path")
        assert bad.status_code == 400
        assert bad.headers["content-type"].startswith("text/html")

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c2:
        await _login(c2, "op2")
        for target in (fid, "0" * 32):  # not yours, and does not exist
            r = await c2.get(
                f"/ui/uploaded-logs/file/{target}?field_path=not+a+path",
                follow_redirects=False,
            )
            assert r.status_code == 303, r.text
            assert r.headers["location"] == "/ui/uploaded-logs"
            assert "application/json" not in r.headers.get("content-type", "")


async def test_uploaded_logs_ui_resend_is_owner_scoped(engine: Engine, tmp_path: Path) -> None:
    # The resend POST was the one uploaded-logs route with no 404 arm, so an ASVS 8.2.2 denial came
    # back as application/json inside the HTML console. It needs a REGISTERED, RUNNING inbound: the
    # engine handler rejects an unknown target (404) or a stopped one (409) BEFORE the owner check, so
    # without a started pipeline this would assert against "no such inbound connection" and prove
    # nothing about ownership.
    for d in ("in", "o1"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o1")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    engine.add_registry(reg)
    await engine.start()

    service = await _service(engine, ("op", Role.OPERATOR), ("op2", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        listing = await c.get("/ui/uploaded-logs")
        marker = "/ui/uploaded-logs/file/"
        fid = listing.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        # Positive control: the owner's resend of the same message into the same inbound succeeds,
        # and the SUCCESS response is a bare 303 carrying no outcome flag.
        mine = await c.post(
            f"/ui/uploaded-logs/file/{fid}/resend",
            params={"index": "0", "to": "in1"},
            follow_redirects=False,
        )
        assert mine.status_code == 303, mine.text
        assert mine.headers["location"] == f"/ui/uploaded-logs/file/{fid}"

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c2:
        await _login(c2, "op2")
        denied = await c2.post(
            f"/ui/uploaded-logs/file/{fid}/resend",
            params={"index": "0", "to": "in1"},
            follow_redirects=False,
        )
        # In the HTML plane — never a JSON error body.
        assert denied.status_code == 303, denied.text
        assert "application/json" not in denied.headers.get("content-type", "")
        # A REFUSED resend must not be the byte-identical answer to a successful one, or the operator
        # is told a message was injected when none was. It goes where success never goes, flagged.
        assert denied.headers["location"] == "/ui/uploaded-logs?e=resend_failed"
        assert denied.headers["location"] != mine.headers["location"]
        # ...and it lands on op2's own listing — which the ownership check keeps empty — carrying the
        # fixed notice. Nothing about the file is disclosed by the refusal itself.
        landed = await c2.get(denied.headers["location"], follow_redirects=False)
        assert landed.status_code == 200, landed.text
        assert "That resend did not run" in landed.text
        assert "acme.hl7" not in landed.text


async def test_listing_states_the_scope_it_is_actually_showing(
    engine: Engine, tmp_path: Path
) -> None:
    # The page used to tell EVERY operator "this list shows the files you uploaded". That is false for
    # a files:access_any holder, whose listing does carry other operators' files — and it is false
    # exactly for the reader most likely to act on it. The sentence now follows the engine-computed
    # scope (UploadedFileList.scope), which is the same value the upload.list audit row records.
    service = await _service(engine, ("op", Role.OPERATOR), ("root", Role.ADMINISTRATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        mine = await c.get("/ui/uploaded-logs")
        assert mine.status_code == 200
        assert "This list shows the files you uploaded" in mine.text
        assert "You hold files:access_any" not in mine.text

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as admin:
        await _login(admin, "root")
        theirs = await admin.get("/ui/uploaded-logs")
        assert theirs.status_code == 200
        # The premise: the administrator's listing really does carry the other operator's file, so the
        # owner-scoped sentence would be a false statement to this reader.
        assert "acme.hl7" in theirs.text
        assert "You hold files:access_any" in theirs.text
        assert "This list shows the files you uploaded" not in theirs.text


async def test_failed_resend_is_not_shaped_like_a_successful_one(
    engine: Engine, tmp_path: Path
) -> None:
    # The 404 arm used to answer with the SUCCESS response itself — the same bare 303 to the same URL —
    # so an operator whose resend injected NOTHING was redirected exactly as if it had worked: no
    # banner, no log line, nothing to tell the two apart. The refusal now carries a fixed flag to a
    # target success never reaches, and the list page renders it as fixed text.
    #
    # The second half pins the constraint ON that flag. The resend body is caller-supplied and the
    # engine's 404 quotes the target inbound name straight back in its detail, so putting that text in
    # the query string or the page would be an XSS sink fed by the form. The flag is a boolean.
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    # A target that does not exist, carrying a payload. The name reaches the engine's 404 detail; the
    # test's question is whether any of it comes back out.
    bogus = "IB_NOPEZQX<script>alert(1)</script>"
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)

        # Control: the same operator, same file, a resend that WORKS is not available here (no inbound
        # is registered in this fixture), so the success shape is pinned in the owner-scoped test
        # above. What this asserts is that the failure is NOT that shape.
        failed = await c.post(
            f"/ui/uploaded-logs/file/{fid}/resend",
            params={"index": "0", "to": bogus},
            follow_redirects=False,
        )
        assert failed.status_code == 303, failed.text
        assert failed.headers["location"] == "/ui/uploaded-logs?e=resend_failed"
        assert failed.headers["location"] != f"/ui/uploaded-logs/file/{fid}"

        landed = await c.get(failed.headers["location"], follow_redirects=False)
        assert landed.status_code == 200, landed.text
        assert "That resend did not run" in landed.text

        # ...and NOTHING caller-supplied rode along, into the URL or the HTML.
        assert "IB_NOPEZQX" not in failed.headers["location"]
        assert "IB_NOPEZQX" not in landed.text and "alert(1)" not in landed.text

        # An unrecognized code renders no banner at all (allow-list, not reflection).
        clean = await c.get("/ui/uploaded-logs?e=nope", follow_redirects=False)
        assert clean.status_code == 200 and "That resend did not run" not in clean.text
        assert "nope" not in clean.text
        # The bare list — where a SUCCESSFUL delete lands — carries no banner either.
        bare = await c.get("/ui/uploaded-logs", follow_redirects=False)
        assert bare.status_code == 200 and "did not run" not in bare.text


async def test_refused_resend_signal_is_legible_on_arrival(engine: Engine, tmp_path: Path) -> None:
    # The flag used to be aimed at the browse DETAIL page, which is step-up-gated AND registered as an
    # unlock action. Once the step-up window goes stale that page 303s to /ui/reauth, which deliberately
    # does not carry the query string back (the browse filter is a GET query that can hold PHI-shaped
    # search terms) — so the flag was dropped and the operator landed on a plain detail page, the exact
    # shape a SUCCESSFUL resend produces. The refusal reports on the ungated list page instead.
    #
    # THE WINDOW IS FRESH HERE, and that is the honest premise since BACKLOG #1227: the resend POST is
    # now step-up-gated itself, so a STALE window can no longer reach the refusal path at all — it is
    # refused ahead of the handler. The property this test owns is unchanged and is about the TARGET,
    # not the window: wherever a refusal sends the operator, it must be legible when they land.
    # The stale-window half moved to test_a_stale_window_strips_a_flag_aimed_at_the_detail_page.
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        # upload + list are plain require_ui, so neither needs a fresh step-up window.
        fid = await _upload(c)

        # THE PROPERTY, asserted end to end: follow the WHOLE chain a browser would follow. Wherever
        # the route chooses to send the operator, the refusal must still be legible on arrival. This
        # is the assertion the old target fails — it lands on /ui/reauth with the flag stripped.
        # Nothing was injected, so a second identical POST is safe.
        chased = await c.post(
            f"/ui/uploaded-logs/file/{fid}/resend",
            params={"index": "0", "to": "IB_NOPEZQX"},
            follow_redirects=True,
        )
        assert chased.status_code == 200, chased.text
        assert "That resend did not run" in chased.text

        # ...and THE CHOICE that makes it hold: an ungated target, so no re-auth bounce intervenes.
        refused = await c.post(
            f"/ui/uploaded-logs/file/{fid}/resend",
            params={"index": "0", "to": "IB_NOPEZQX"},
            follow_redirects=False,
        )
        assert refused.status_code == 303, refused.text
        assert refused.headers["location"] == "/ui/uploaded-logs?e=resend_failed"
        landed = await c.get(refused.headers["location"], follow_redirects=False)
        assert landed.status_code == 200, landed.headers.get("location", landed.text)


async def test_a_stale_window_strips_a_flag_aimed_at_the_detail_page(
    engine: Engine, tmp_path: Path
) -> None:
    # The standing justification for _FAILED_TARGET pointing at the LIST page rather than the detail
    # page, split out of the test above when BACKLOG #1227 gated the resend POST. It asserts a
    # property of the DETAIL page, which is unaffected by that change, so it keeps the stale window.
    #
    # step_up_max_age_seconds=-1 is the console suite's idiom for a window that is stale on arrival
    # (test_webui.py test_stale_stepup_bounces_body_less_action_via_reauth and friends).
    service = await _service(engine, ("op", Role.OPERATOR), step_up_max_age=-1)
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)

        # The window really IS stale, and the OLD target really does lose the flag. The detail page
        # bounces to /ui/reauth and the query string does not survive — which is why a refusal aimed
        # there would be indistinguishable from a success.
        stale = await c.get(f"/ui/uploaded-logs/file/{fid}?e=resend_failed", follow_redirects=False)
        assert stale.status_code == 303, stale.text
        assert stale.headers["location"] == f"/ui/reauth?next=/ui/uploaded-logs/file/{fid}"
        assert "resend_failed" not in stale.headers["location"]


async def test_resend_refusal_names_a_distinct_cause_per_status(
    engine: Engine, tmp_path: Path
) -> None:
    # Only the 404 arm used to be handled; 403 (target channel denied) and 409 (inbound registered but
    # not running) escaped the /ui route and rendered as application/json inside the HTML console —
    # with the caller-supplied inbound name quoted back in exc.detail. All three are now allow-listed
    # codes on the ungated list page, and they are DISTINCT so each notice is actionable and true.
    #
    # The engine is deliberately NOT started: add_registry sets the registry_runner, so "in1" is a
    # registered inbound that inbound_running() reports as stopped — which is the 409 precondition.
    for d in ("in", "o1"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o1")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    engine.add_registry(reg)

    service = await _service(engine, ("op", Role.OPERATOR))
    # Scoped to a DIFFERENT connection, so can_access_channel("in1") is False and the target check
    # 403s before anything about the file is consulted. Set before the first login (it revokes).
    await _add_user(service, "scoped", Role.OPERATOR, channels=["IB_SOMETHING_ELSE"])
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        stopped = await c.post(
            f"/ui/uploaded-logs/file/{fid}/resend",
            params={"index": "0", "to": "in1"},
            follow_redirects=False,
        )
        assert stopped.status_code == 303, stopped.text
        assert "application/json" not in stopped.headers.get("content-type", "")
        assert stopped.headers["location"] == "/ui/uploaded-logs?e=resend_stopped"
        landed = await c.get(stopped.headers["location"], follow_redirects=False)
        assert landed.status_code == 200 and "registered but not running" in landed.text
        assert "in1" not in landed.text  # the target name is caller-supplied and never travels

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as sc:
        await _login(sc, "scoped")
        own = await _upload(sc, "scoped.hl7")  # its own file, so ONLY the target is wrong
        denied = await sc.post(
            f"/ui/uploaded-logs/file/{own}/resend",
            params={"index": "0", "to": "in1"},
            follow_redirects=False,
        )
        assert denied.status_code == 303, denied.text
        assert "application/json" not in denied.headers.get("content-type", "")
        assert denied.headers["location"] == "/ui/uploaded-logs?e=resend_denied"
        landed = await sc.get(denied.headers["location"], follow_redirects=False)
        assert landed.status_code == 200 and "not authorized to inject" in landed.text
        assert "in1" not in landed.text
        # The two causes are told apart — and neither is the 404 code, nor the success shape.
        assert denied.headers["location"] != stopped.headers["location"]
        assert "resend_failed" not in denied.headers["location"]


async def test_refused_delete_is_not_shaped_like_a_completed_one(
    engine: Engine, tmp_path: Path
) -> None:
    # The delete POST's 404 arm answered with its OWN success response — the byte-identical bare 303 to
    # the list — so a delete that was REFUSED (including an ASVS 8.2.2 owner denial) told the operator
    # the file was deleted. The refusal now carries a flag; the success stays bare.
    service = await _service(engine, ("op", Role.OPERATOR), ("op2", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c2:
        await _login(c2, "op2")
        refused = await c2.post(f"/ui/uploaded-logs/file/{fid}/delete", follow_redirects=False)
        assert refused.status_code == 303, refused.text
        assert refused.headers["location"] == "/ui/uploaded-logs?e=delete_failed"
        landed = await c2.get(refused.headers["location"], follow_redirects=False)
        assert landed.status_code == 200, landed.text
        assert "That delete did not run" in landed.text
        assert "acme.hl7" not in landed.text  # still not disclosed to a non-owner

    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c3:
        await _login(c3, "op")
        # The premise: the refusal unlinked nothing, so the owner's delete is the one that works.
        assert "acme.hl7" in (await c3.get("/ui/uploaded-logs")).text
        done = await c3.post(f"/ui/uploaded-logs/file/{fid}/delete", follow_redirects=False)
        assert done.status_code == 303, done.text
        assert done.headers["location"] == "/ui/uploaded-logs"
        assert done.headers["location"] != refused.headers["location"]
        after = await c3.get(done.headers["location"], follow_redirects=False)
        assert after.status_code == 200
        assert "acme.hl7" not in after.text and "That delete did not run" not in after.text


_ROUTE_LOGGER = "messagefoundry_webconsole.routes.uploaded_logs"


async def test_refusals_are_recorded_server_side(
    engine: Engine, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # The second, independent half of the fix: a refusal is recorded server-side, so it survives even
    # if every browser-visible signal is lost (the operator closes the tab, a proxy eats the redirect,
    # the flag is stripped). file_id + status ONLY — the target inbound name, the message index and
    # exc.detail are all caller-supplied text, and writing those to a log is log injection.
    service = await _service(engine, ("op", Role.OPERATOR), ("op2", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    bogus = "IB_NOPEZQX<script>alert(1)</script>"
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c2:
        await _login(c2, "op2")
        with caplog.at_level(logging.WARNING, logger=_ROUTE_LOGGER):
            async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
                await _login(c, "op")
                r = await c.post(
                    f"/ui/uploaded-logs/file/{fid}/resend",
                    params={"index": "0", "to": bogus},
                    follow_redirects=False,
                )
                assert r.status_code == 303
                # A file_id the CALLER invented, carrying an encoded newline: the target is unknown, so
                # the engine 404s before it ever validates the id, and the console still has to log
                # something. The minted-shape guard makes it a fixed placeholder rather than a forged
                # second log line.
                forged = await c.post(
                    f"/ui/uploaded-logs/file/{'0' * 32}%0AWARNING-forged-line/resend",
                    params={"index": "0", "to": bogus},
                    follow_redirects=False,
                )
                assert forged.status_code == 303
            d = await c2.post(f"/ui/uploaded-logs/file/{fid}/delete", follow_redirects=False)
            assert d.status_code == 303

    lines = [r.getMessage() for r in caplog.records if r.name == _ROUTE_LOGGER]
    assert f"uploaded-log resend refused: file_id={fid} status=404" in lines
    assert f"uploaded-log delete refused: file_id={fid} status=404" in lines
    assert "uploaded-log resend refused: file_id=malformed status=404" in lines
    # Nothing caller-supplied reached the log: not the inbound name, not the payload, not a newline.
    assert not any("IB_NOPEZQX" in line or "alert(1)" in line for line in lines)
    assert not any("forged" in line or "\n" in line for line in lines)


async def test_uploaded_logs_ui_denied_for_viewer(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine, ("vw", Role.VIEWER))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "vw")
        assert (await c.get("/ui/uploaded-logs")).status_code == 403


async def test_uploaded_logs_ui_503_when_unconfigured(engine: Engine, tmp_path: Path) -> None:
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path, uploads=False))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        assert (await c.get("/ui/uploaded-logs")).status_code == 503


async def test_uploaded_log_browse_charges_the_phi_read_budget(
    engine: Engine, tmp_path: Path
) -> None:
    # BACKLOG #1025 scope guard: GET /ui/uploaded-logs/file/{file_id} is ALREADY under the per-actor
    # read budget and needs no console-side phi= — unlike the two search routes, its console handler has
    # no short-circuit render path: it always calls core.browse_uploaded_file, whose body itself calls
    # enforce_phi_read_pacing (app.py). So the metadata browse charges token 1 (render = 200) and a
    # second browse over the budget 429s, with NO phi= on require_ui_step_up. Adding phi= here would
    # charge the same bucket twice (dependency + handler body), 429ing even the first browse. Upload +
    # list are plain require_ui (no phi), so neither spends a token. Synthetic HL7 only (reuses BATCH).
    service = await _service(engine, ("op", Role.OPERATOR), per_actor=1)
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        up = await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        assert up.status_code in (200, 303), up.text
        r = await c.get("/ui/uploaded-logs")  # require_ui, no phi: spends no token
        marker = "/ui/uploaded-logs/file/"
        fid = r.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        assert len(fid) == 32
        first = await c.get(f"/ui/uploaded-logs/file/{fid}")
        assert first.status_code == 200, first.text  # metadata browse charges token 1
        second = await c.get(f"/ui/uploaded-logs/file/{fid}")
        assert second.status_code == 429
        assert second.headers["Retry-After"]


# --- BACKLOG #1184 (ASVS 14.2.1): the browse filter posts the needle ------------------------------


async def test_browse_filter_posts_the_needle_instead_of_putting_it_on_the_url(
    engine: Engine, tmp_path: Path
) -> None:
    """The uploaded-log filter form must submit as a POST, and a needle left on the browse GET must
    no longer filter.

    The control is the un-filtered browse in the same run: it returns BOTH messages, so a POST that
    returns one is genuinely filtering rather than erroring into an empty page."""
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)

        page = await c.get(f"/ui/uploaded-logs/file/{fid}")
        assert page.status_code == 200, page.text
        assert 'name="field_value"' in page.text  # control: it is still the filter form
        # Pin the FILTER form's own opening tag. The detail page also carries the resend and
        # delete POSTs, so "a post appears somewhere on this page" witnesses nothing. Without
        # this pair the test's own opening sentence is unmeasured: flipping method back to
        # "get" in pages/uploaded_logs.py puts the operator's needle on the query string --
        # the exact ASVS 14.2.1 exposure #1184 removes -- and every other assertion below
        # still passes. The sibling search-form test pins it this way already.
        _filter_action = f'action="/ui/uploaded-logs/file/{fid}/filter"'
        assert f'method="get" {_filter_action}' not in page.text, (
            "the uploaded-log filter form still submits on the URL"
        )
        assert f'method="post" {_filter_action}' in page.text
        assert "ADT^A01" in page.text and "ADT^A04" in page.text  # control: both messages listed

        stale = await c.get(f"/ui/uploaded-logs/file/{fid}", params={"content": "MRN123"})
        assert stale.status_code == 200, stale.text
        assert "ADT^A04" in stale.text, "a query-string needle still filtered the browse"

        r = await c.post(f"/ui/uploaded-logs/file/{fid}/filter", data={"content": "MRN123"})
        assert r.status_code == 200, r.text
        assert "ADT^A01" in r.text and "ADT^A04" not in r.text  # the POST really filtered
        assert "MRN123" not in str(r.request.url), f"the needle rode the URL: {r.request.url}"


async def test_browse_filter_refuses_an_over_long_criterion_instead_of_listing_everything(
    engine: Engine, tmp_path: Path
) -> None:
    """An unparseable filter must REFUSE, not answer 200 with the whole file.

    The arm this covers used to drop all five criteria, re-render the file unfiltered at HTTP 200
    with the inputs blanked and no banner. To an operator that reads as "your filter matched
    everything" -- the opposite of what happened -- and it discarded their VALID criteria silently
    too. The sibling POST /ui/messages/search/run answers 400 with a banner, and the GET this route
    replaced answered 422; this was the only arm that swallowed it (BACKLOG #1184).
    """
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)

        # Over the 512 bound on `content`, and a VALID message_type alongside it: the valid one must
        # survive into the re-render rather than being discarded with the invalid one.
        r = await c.post(
            f"/ui/uploaded-logs/file/{fid}/filter",
            data={"content": "M" * 600, "message_type": "ADT^A01"},
        )
        assert r.status_code == 400, f"an unparseable filter must refuse, got {r.status_code}"
        assert "longer than that field allows" in r.text, "the refusal must say why"
        # The operator's valid criterion is still in the form -- not silently blanked.
        assert 'value="ADT^A01"' in r.text, "a valid criterion was discarded with the invalid one"
        # And the needle never reached the URL even on the refusal path.
        assert "M" * 600 not in str(r.request.url)


async def test_a_stale_step_up_window_injects_nothing(engine: Engine, tmp_path: Path) -> None:
    """BACKLOG #1227 -- the console resend POST must be refused when the step-up window is stale.

    The console invokes the engine handler BY REFERENCE across the CoreHandlers seam, so the engine's
    own ``require_step_up`` Depends never runs; the gate has to be re-asserted on the /ui route. The
    proof obligation is the item's own: a test that only checks a FRESH operator can resend passes on
    the defective code, so the assertion that matters is that nothing was injected -- read from the
    STORE, not from the redirect. A 303 to /ui/reauth proves where the browser was sent; only the
    store proves the message never landed."""
    # A REGISTERED, RUNNING, owned inbound, exactly as test_uploaded_logs_ui_resend_is_owner_scoped
    # builds one. Load-bearing rather than scenery: the engine handler 404s an unknown target and
    # 409s a stopped one BEFORE any gate, so against an unregistered target the store would read zero
    # for a reason that has nothing to do with the step-up and the test would prove nothing.
    for d in ("in", "o1"):
        (tmp_path / d).mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in1",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OB1", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path / "o1")})
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB1", m))
    engine.add_registry(reg)
    await engine.start()

    service = await _service(engine, ("op", Role.OPERATOR), step_up_max_age=-1)
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        await c.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("acme.hl7", BATCH, "application/octet-stream")},
        )
        listing = await c.get("/ui/uploaded-logs")
        marker = "/ui/uploaded-logs/file/"
        fid = listing.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]

        # PREMISE, asserted rather than assumed: the window really IS stale in THIS session. The
        # browse GET is a route already known to be step-up-gated, so if it does not bounce, the
        # zeros below would be measuring a dead fixture instead of the gate.
        browse = await c.get(f"/ui/uploaded-logs/file/{fid}", follow_redirects=False)
        assert browse.status_code == 303, browse.text
        assert browse.headers["location"] == f"/ui/reauth?next=/ui/uploaded-logs/file/{fid}"

        blocked = await c.post(
            f"/ui/uploaded-logs/file/{fid}/resend?index=0&to=in1", follow_redirects=False
        )
        assert blocked.status_code == 303, blocked.text
        location = blocked.headers["location"]
        assert location.startswith("/ui/reauth?next="), location
        # The continuation must point at the CONFIRM page carrying both parameters, not at the POST
        # path -- a body-less POST is re-issuable, but only if the re-auth knows where to send it.
        assert "resend-confirm" in location, location
        # ...and it must not be the SUCCESS shape, which is a bare 303 to the detail page. Answering
        # a refusal with the success response tells the operator a message was injected.
        assert location != f"/ui/uploaded-logs/file/{fid}"

        # THE ASSERTION THE ITEM ACTUALLY ASKS FOR. These are the two direct products of the handler
        # this route reaches -- the ingress enqueue and the audit row -- so a zero on both is the
        # only evidence that the refusal happened BEFORE the injection rather than after it.
        assert await engine.store.count_messages(channel_id="in1") == 0
        assert list(await engine.store.list_audit(action="upload.resend", limit=200)) == []

    # POSITIVE CONTROL, same store, same inbound, same POST -- a FRESH window. Without this the two
    # zeros above are indistinguishable from instruments that cannot see an injection at all.
    fresh = await _service(engine, ("fresh", Role.OPERATOR))
    transport2 = httpx.ASGITransport(app=_app(engine, fresh, tmp_path))
    async with httpx.AsyncClient(transport=transport2, base_url="http://t") as c2:
        await _login(c2, "fresh")
        await c2.post(
            "/ui/uploaded-logs/upload",
            files={"file": ("fresh.hl7", BATCH, "application/octet-stream")},
        )
        listing2 = await c2.get("/ui/uploaded-logs")
        own = listing2.text.split(marker, 1)[1].split('"', 1)[0].split("/")[0]
        allowed = await c2.post(
            f"/ui/uploaded-logs/file/{own}/resend?index=0&to=in1", follow_redirects=False
        )
        assert allowed.status_code == 303, allowed.text
        assert allowed.headers["location"] == f"/ui/uploaded-logs/file/{own}"
        assert await engine.store.count_messages(channel_id="in1") == 1
        assert len(await engine.store.list_audit(action="upload.resend", limit=200)) == 1


async def test_resend_confirm_does_not_reflect_hostile_markup(
    engine: Engine, tmp_path: Path
) -> None:
    """The confirm page is the FIRST place ``to`` is rendered back to the operator (BACKLOG #1227).

    ``to`` is an operator-authored connection name and ``Registry._add`` checks only for a duplicate,
    so it is unconstrained free text arriving from the query. The route module already names this
    reflection as the thing to avoid for the refusal path; the confirm page is the same sink."""
    service = await _service(engine, ("op", Role.OPERATOR))
    transport = httpx.ASGITransport(app=_app(engine, service, tmp_path))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        await _login(c, "op")
        fid = await _upload(c)
        hostile = "<script>alert(1)</script>"
        r = await c.get(
            f"/ui/uploaded-logs/file/{fid}/resend-confirm",
            params={"index": "0", "to": hostile},
            follow_redirects=False,
        )
        assert r.status_code == 200, r.text
        # The raw tag never appears; the escaped form does, which proves the value REACHED the page
        # rather than being dropped somewhere upstream — a page that rendered nothing would also
        # satisfy a bare "not in" assertion.
        assert hostile not in r.text
        assert "&lt;script&gt;" in r.text
