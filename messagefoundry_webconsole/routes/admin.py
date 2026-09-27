# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""L4a admin surface (ADR 0065; #75 phase 4): user, role, and AD-group-mapping /ui pages + actions. Clients of the injected JSON handlers (called directly, re-asserting each gate via require_ui*)."""

from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import ValidationError

from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.auth_models import (
    AdGroupMap,
    AdGroupMapEntry,
    AdGroupScopeEntry,
    AdGroupScopeMap,
    ChannelScope,
    CustomRoleInfo,
    CustomRoleRequest,
    FederatedIdentityRequest,
    FederatedIdentityView,
    PasswordResetResponse,
    RolesUpdateRequest,
    UserCreateRequest,
    UserUpdateRequest,
)
from messagefoundry.api.security import (
    initial_credential_window_hours,
    pending_credential_deadline,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.identity import ALL_CHANNELS
from messagefoundry.auth.permissions import CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
from messagefoundry.auth.service import (
    STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY,
    STEP_UP_ACTION_ADMIN_RESET_MFA,
    STEP_UP_ACTION_ADMIN_RESET_PASSWORD,
    STEP_UP_ACTION_ADMIN_USER_UPDATE,
    AuthService,
)

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
    require_ui_step_up_action,
)
from .._service import _service
from ._common import _form_pairs

register_ui_action(r"^/ui/users/new$", Permission.USERS_MANAGE, auto_retry=False, unlock=True)
# BACKLOG #1737: the user-detail page is the unlock continuation for the body-carrying
# POST /ui/users/{id}/update, whose JSON twin (PATCH /users/{id}) is bound to admin_user_update. The
# POST path itself can never be the continuation -- a body-carrying action is deliberately in neither
# allow-list -- so the grant has to be minted HERE, against the page the operator is 303'd back to.
#
# That page also hosts the /roles and /channel-scope forms, which stay window-gated, so a re-auth
# aimed at either of those mints an admin_user_update grant nothing consumes. Accepted: the grant is
# single-use, bound to that one action id, keyed on that one session's token hash, and expires on the
# same clock as the step-up window it replaces -- so the whole of its effect is that an operator who
# just re-proved their password may submit ONE profile update inside the window they re-proved for.
# The alternative, a narrower continuation, means a new confirm page for a form that already has one.
register_ui_action(
    r"^/ui/users/[^/?#]+$",
    Permission.USERS_MANAGE,
    auto_retry=False,
    unlock=True,
    action=STEP_UP_ACTION_ADMIN_USER_UPDATE,
)
# BACKLOG #1148 (ASVS 7.5.1): the two RESET lanes are split out and TAGGED. Combined and untagged,
# /ui/reauth minted nothing for them, so the browser path -- the only operator surface that ships --
# kept riding the login-seeded window even after the JSON routes were bound. revoke-sessions and
# delete stay combined and untagged: they are out of 7.5.1's scope, which names attributes that
# affect AUTHENTICATION, and tagging them would be motion without a requirement behind it.
register_ui_action(
    r"^/ui/users/[^/?#]+/reset-password$",
    Permission.USERS_MANAGE,
    action=STEP_UP_ACTION_ADMIN_RESET_PASSWORD,
)
register_ui_action(
    r"^/ui/users/[^/?#]+/reset-mfa$",
    Permission.USERS_MANAGE,
    action=STEP_UP_ACTION_ADMIN_RESET_MFA,
)
register_ui_action(
    r"^/ui/users/[^/?#]+/(revoke-sessions|delete)$",
    Permission.USERS_MANAGE,
)
# BACKLOG #1143 / #295 (ADR 0184 slice B): the federated-identity screen. Its two POSTs are
# action-bound to admin_federated_identity, like their JSON twins, and NEITHER is registered: the link
# POST carries a body, and an unlink is never auto-re-POSTed across a re-auth. Each stale POST maps
# back to a GET page instead, the stepdown-confirm shape. Those two GET pages are the continuations,
# and each is TAGGED, so /ui/reauth mints the one grant the POST that follows consumes. A fresh
# login window opens the pages without minting one; the POST then bounces once through /ui/reauth
# and the operator submits again. That is the admin_user_update lane's cost, accepted there first.
register_ui_action(
    r"^/ui/users/[^/?#]+/federated-identity$",
    Permission.USERS_MANAGE,
    auto_retry=False,
    unlock=True,
    action=STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY,
)
register_ui_action(
    r"^/ui/users/[^/?#]+/federated-identity/unlink-confirm$",
    Permission.USERS_MANAGE,
    auto_retry=False,
    unlock=True,
    action=STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY,
)

register_ui_action(r"^/ui/roles/new$", Permission.USERS_MANAGE, auto_retry=False, unlock=True)
register_ui_action(
    r"^/ui/roles/[^/?#]+/edit$", Permission.USERS_MANAGE, auto_retry=False, unlock=True
)
register_ui_action(r"^/ui/roles/custom/[^/?#]+/delete$", Permission.USERS_MANAGE)
register_ui_action(r"^/ui/ad-groups$", Permission.USERS_MANAGE, auto_retry=False, unlock=True)


def register(app: FastAPI, deps: UiDeps) -> None:
    """L4a admin surface (ADR 0065; #75 phase 4): user, role, and AD-group-mapping /ui pages + actions. Clients of the injected JSON handlers (called directly, re-asserting each gate via require_ui*)."""
    admin = deps.admin

    # Custom roles may grant any catalog permission EXCEPT the carved-out escalation primitives
    # (ADR 0045 D1) — don't offer what the service will refuse.
    _role_catalog = sorted(
        p.value for p in Permission if p not in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
    )

    async def _user_detail(
        user_id: str,
        service: AuthService,
        identity: Identity,
        *,
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        user = await service.store.get_user(user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        role_ids = await service.store.get_user_role_ids(user.id)
        all_roles = await admin.list_roles(service=service, _=identity)
        return HTMLResponse(
            pages.user_detail_page(
                # BACKLOG #1141: a must-change account's page states when its credential dies.
                admin.user_summary(
                    user,
                    role_ids,
                    credential_expires_at=pending_credential_deadline(service, user),
                ),
                all_roles,
                error=error,
                # BACKLOG #1143 (ADR 0184 slice B): the page states the federated link.
                federated=admin.federated_identity_view(user, service),
            ),
            status_code=status_code,
        )

    # --- users: pages ---------------------------------------------------

    @app.get("/ui/users", response_class=HTMLResponse)
    async def ui_users(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui(Permission.USERS_READ)),
    ) -> HTMLResponse:
        users = await admin.list_users(service=service, _=identity)
        return HTMLResponse(pages.users_page(users))

    # Declared BEFORE /ui/users/{user_id} so the literal segment wins the route match.
    @app.get("/ui/users/new", response_class=HTMLResponse)
    async def ui_user_new(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> HTMLResponse:
        roles = await admin.list_roles(service=service, _=identity)
        return HTMLResponse(
            pages.user_new_page(
                roles, credential_window_hours=initial_credential_window_hours(service)
            )
        )

    @app.get("/ui/users/{user_id}", response_class=HTMLResponse)
    async def ui_user_detail(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> HTMLResponse:
        return await _user_detail(user_id, service, identity)

    # --- users: actions ---------------------------------------------------

    @app.post("/ui/users")
    async def ui_user_create(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/users/new")
        ),
    ) -> Response:
        assert_same_origin(request)
        pairs = await _form_pairs(request)
        form = dict(pairs)
        roles = [v for k, v in pairs if k == "roles"]
        try:
            body = UserCreateRequest(
                username=form.get("username", "").strip(),
                password=form.get("password", ""),
                display_name=form.get("display_name", "").strip() or None,
                # BACKLOG #2018: required, so a blank is passed through for the service to refuse
                # with a message the form can show, rather than as None.
                email=form.get("email", "").strip(),
                roles=roles,
            )
            created = await admin.create_user(
                body=body, request=request, service=service, identity=identity
            )
        except (ValidationError, HTTPException) as exc:
            detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
            all_roles = await admin.list_roles(service=service, _=identity)
            # Re-render preserving the NON-SECRET fields only — the password is never echoed.
            return HTMLResponse(
                pages.user_new_page(
                    all_roles,
                    error=detail,
                    username=form.get("username", "").strip(),
                    display_name=form.get("display_name", "").strip(),
                    email=form.get("email", "").strip(),
                    checked=roles,
                    credential_window_hours=initial_credential_window_hours(service),
                ),
                status_code=400,
            )
        return RedirectResponse(f"/ui/users/{created.id}", status_code=303)

    @app.post("/ui/users/{user_id}/update")
    async def ui_user_update(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        # BACKLOG #1737 (ASVS 7.5.1): action-bound, matching the JSON twin PATCH /users/{id}. This
        # lane sets display name, email and the DISABLED flag -- the attributes a security notice is
        # delivered to, and the switch that locks an account out -- so a login-seeded window must not
        # reach it through the console while the JSON plane refuses the same request. Enforced HERE:
        # the JSON dependency does not run on this path (the handler FUNCTION is called via the seam).
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_ADMIN_USER_UPDATE,
                Permission.USERS_MANAGE,
                reauth_next=lambda r: r.url.path.removesuffix("/update"),
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        # BACKLOG #1139, ADR 0182 Amendment A. The notification address is sent only when the
        # administrator changed it from the value the page showed (`notify_email_shown`). Comparing
        # against the stored value instead would let a stale page revert another administrator's
        # move. A form with no shown value predates the field and sends a typed value as is.
        typed_notify = form.get("notify_email", "").strip()
        shown_notify = form.get("notify_email_shown")
        notify_changed = (
            typed_notify != shown_notify.strip() if shown_notify is not None else bool(typed_notify)
        )
        if notify_changed and not typed_notify:
            # The JSON twin refuses an explicit null for the same reason: it cannot be cleared.
            return await _user_detail(
                user_id,
                service,
                identity,
                error="the notification address can be changed but not cleared",
                status_code=400,
            )
        try:
            # An HTML form always posts the full profile picture, so every field is set explicitly
            # ("" clears to None; an absent checkbox means enabled) — the PATCH partial semantics of
            # the JSON handler don't apply to a form submit. The notification address is the
            # exception above.
            fields: dict[str, object] = {
                "display_name": form.get("display_name", "").strip() or None,
                "email": form.get("email", "").strip() or None,
                "disabled": "disabled" in form,
            }
            if notify_changed:
                fields["notify_email"] = typed_notify
            body = UserUpdateRequest.model_validate(fields)
            await admin.update_user(user_id, body=body, service=service, identity=identity)
        except (ValidationError, HTTPException) as exc:
            if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
            return await _user_detail(user_id, service, identity, error=detail, status_code=400)
        return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

    @app.post("/ui/users/{user_id}/roles")
    async def ui_user_roles(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.USERS_MANAGE,
                reauth_next=lambda r: r.url.path.removesuffix("/roles"),
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        pairs = await _form_pairs(request)
        roles = [v for k, v in pairs if k == "roles"]
        try:
            body = RolesUpdateRequest(roles=roles)
            await admin.set_user_roles(user_id, body=body, service=service, identity=identity)
        except (ValidationError, HTTPException) as exc:
            if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
            return await _user_detail(user_id, service, identity, error=detail, status_code=400)
        return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

    @app.post("/ui/users/{user_id}/channel-scope")
    async def ui_user_channel_scope(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.USERS_MANAGE,
                reauth_next=lambda r: r.url.path.removesuffix("/channel-scope"),
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        names = [ln.strip() for ln in form.get("channels", "").splitlines() if ln.strip()]
        # The tri-state scope_mode keeps deny-all distinguishable from all-channels — an empty
        # textarea alone must never widen a stored deny-all scope (review PR2-M3). Absent (a
        # pre-tri-state cached form) defaults to "list"; any OTHER value is a hand-crafted post —
        # refused rather than guessed (deny-by-default).
        mode = form.get("scope_mode", "list")
        if mode not in ("all", "list", "none"):
            return await _user_detail(
                user_id, service, identity, error="unknown scope mode", status_code=400
            )
        if mode == "list" and not names:
            return await _user_detail(
                user_id,
                service,
                identity,
                error=(
                    "list at least one connection, or choose the all-channels / "
                    "no-channels scope instead"
                ),
                status_code=400,
            )
        # The token never rides in through the textarea. `set_channel_scope` stores the list as
        # typed, but `auth.service._allowed_channels` returns None -- every channel -- for any
        # stored list the token appears in, so "only these connections" with `*` in the box would
        # grant the whole estate while the form said otherwise, and the saved list would still read
        # as a narrow one. Measured: ["*", "IB_A"] resolves to None. That is the
        # read-one-thing-do-another shape the tri-state mode exists to prevent (review PR2-M3), and
        # the all-channels mode is right there for an operator who means it. Refused HERE and not in
        # the request model, because the model serves the JSON route too, and there a list holding
        # the token is the only spelling of that grant and means exactly what it says.
        if mode == "list" and ALL_CHANNELS in names:
            return await _user_detail(
                user_id,
                service,
                identity,
                error=(
                    f"{ALL_CHANNELS!r} is the all-channels grant, not a connection name -- "
                    "choose the all-channels scope instead of listing it"
                ),
                status_code=400,
            )
        # BACKLOG #1152: all-channels is now the explicit ALL_CHANNELS grant, not a null scope. Null
        # and [] both deny, so posting null for "all" would have silently inverted this form.
        channels = [ALL_CHANNELS] if mode == "all" else ([] if mode == "none" else names)
        try:
            body = ChannelScope(channels=channels)
            await admin.set_channel_scope(user_id, body=body, service=service, identity=identity)
        except (ValidationError, HTTPException) as exc:
            if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
            return await _user_detail(user_id, service, identity, error=detail, status_code=400)
        return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

    @app.post("/ui/users/{user_id}/reset-password")
    async def ui_user_reset_password(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        # BACKLOG #1148: action-bound, and it must be enforced HERE. The JSON dependency does not
        # run on this path -- the handler FUNCTION is called through the seam below, not the route.
        identity: Identity = Depends(
            require_ui_step_up_action(STEP_UP_ACTION_ADMIN_RESET_PASSWORD, Permission.USERS_MANAGE)
        ),
    ) -> Response:
        assert_same_origin(request)
        try:
            # Annotated, and PasswordResetResponse imported for it, so the seam discovery SEEDS this
            # DTO: handler RETURN types are not otherwise reached (only import statements are), and
            # this route reads a field off one. Without the annotation a console built against a
            # newer engine would read `expires_at` off an older one and raise AttributeError at
            # reset time — the exact skew SUPPORTED_ENGINE_SEAMS exists to refuse loudly at startup.
            result: PasswordResetResponse = await admin.reset_user_password(
                user_id, service=service, identity=identity
            )
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            return await _user_detail(
                user_id, service, identity, error=str(exc.detail), status_code=400
            )
        user = await service.store.get_user(user_id)
        username = user.username if user is not None else user_id
        # The one-time credential is rendered ONCE for out-of-band delivery — never logged/stored.
        # BACKLOG #1141 (ASVS 6.4.5): its deadline rides along on the same page, read off the same
        # response, so the administrator who conveys the credential can convey when it dies.
        return HTMLResponse(
            pages.temp_password_page(username, result.temp_password, result.expires_at)
        )

    @app.post("/ui/users/{user_id}/reset-mfa")
    async def ui_user_reset_mfa(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        # BACKLOG #1148: the browser twin of the lane that clears TOTP, every recovery code and
        # every passkey. require_ui_step_up_ACTION keeps the MFA gate, like its JSON counterpart.
        identity: Identity = Depends(
            require_ui_step_up_action(STEP_UP_ACTION_ADMIN_RESET_MFA, Permission.USERS_MANAGE)
        ),
    ) -> Response:
        assert_same_origin(request)
        try:
            await admin.reset_user_mfa(user_id, service=service, identity=identity)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            return await _user_detail(
                user_id, service, identity, error=str(exc.detail), status_code=400
            )
        return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

    # --- users: federated identity (BACKLOG #1143 / #295, ADR 0184 slice B) -----------------------
    #
    # The console's half of the only path that creates a federated binding. Both POSTs call the JSON
    # handlers BY REFERENCE, so the service checks, the self-exclusion and the refusal mapping are
    # the API's own. What a direct call SKIPS is the handler's require_step_up_action Depends, so
    # each POST re-asserts it here with the same action. That dependency is the gate; the pages in
    # front of it only decide what an operator is offered.
    #
    # The single-use grant is spent by the dependency, before the body is read. So a refused POST
    # costs its grant, and trying again goes through /ui/reauth first. The JSON twin behaves the
    # same, and the page says so beside the form.

    async def _federated_view(user_id: str, service: AuthService) -> FederatedIdentityView:
        user = await service.store.get_user(user_id)
        if user is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
        view: FederatedIdentityView = admin.federated_identity_view(user, service)
        return view

    async def _federated_screen(
        user_id: str,
        service: AuthService,
        identity: Identity,
        *,
        notice: str = "",
        error: str | None = None,
        subject: str = "",
        status_code: int = 200,
    ) -> HTMLResponse:
        view = await _federated_view(user_id, service)
        return HTMLResponse(
            pages.federated_identity_page(
                view,
                is_self=view.user_id == identity.user_id,
                notice=notice,
                error=error,
                subject=subject,
            ),
            status_code=status_code,
        )

    def _still_shown(view: FederatedIdentityView, form: dict[str, str]) -> bool:
        """Whether the pair the operator's page showed is still the stored pair.

        The notify_email_shown guard on the user page, applied here: a link or unlink acts on the
        stored binding, and a page opened before another administrator changed it would otherwise
        replace or remove a binding its operator never saw. Both fields are required; a POST
        without them is refused the same way. This narrows the window to the handler call. It does
        not close it, and the service's own checks still run after it."""
        shown = (form.get("shown_issuer"), form.get("shown_subject"))
        return shown == (view.issuer or "", view.subject or "")

    # The dependency already spent this POST's single-use grant, so a retry bounces through
    # /ui/reauth first. "May", not "will": under [auth].require_action_step_up = false a fresh
    # session window stands in for the grant and no re-auth is asked.
    changed = (
        "The link changed after this page was opened, so nothing was changed. The page now shows "
        "the current link. Check it before you try again. A retry may ask you to re-authenticate "
        "first."
    )

    @app.get("/ui/users/{user_id}/federated-identity", response_class=HTMLResponse)
    async def ui_user_federated_identity(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
        m: str = Query("", max_length=16),
    ) -> HTMLResponse:
        return await _federated_screen(user_id, service, identity, notice=m)

    @app.post("/ui/users/{user_id}/federated-identity/link")
    async def ui_user_federated_link(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        # Action-bound, as PUT /users/{id}/federated-identity is. Enforced HERE: the JSON dependency
        # does not run on this path, because the handler FUNCTION is called through the seam.
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY,
                Permission.USERS_MANAGE,
                reauth_next=lambda r: r.url.path.removesuffix("/link"),
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        # Passed as typed. The service refuses surrounding spaces rather than trimming them, because
        # the stored value must match the token byte for byte, and its refusal says so.
        subject = form.get("subject", "")
        # Echo a bounded value only: an oversized post must not size the refusal page.
        echo = subject[:255]
        view = await _federated_view(user_id, service)
        if not _still_shown(view, form):
            return await _federated_screen(
                user_id, service, identity, error=changed, subject=echo, status_code=409
            )
        try:
            body = FederatedIdentityRequest(subject=subject)
        except ValidationError:
            return await _federated_screen(
                user_id,
                service,
                identity,
                error="Enter the identity provider's subject (sub), 1 to 255 characters.",
                subject=echo,
                status_code=400,
            )
        try:
            await admin.bind_user_federated_identity(
                user_id, body=body, service=service, identity=identity
            )
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            return await _federated_screen(
                user_id,
                service,
                identity,
                error=str(exc.detail),
                subject=echo,
                status_code=exc.status_code,
            )
        # Relink versus link, from the pair this request checked above rather than from the
        # handler's message text, which no seam pins.
        outcome = "relinked" if view.linked else "linked"
        return RedirectResponse(
            f"/ui/users/{user_id}/federated-identity?m={outcome}", status_code=303
        )

    @app.get("/ui/users/{user_id}/federated-identity/unlink-confirm", response_class=HTMLResponse)
    async def ui_user_federated_unlink_confirm(
        user_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> HTMLResponse:
        view = await _federated_view(user_id, service)
        return HTMLResponse(
            pages.federated_unlink_confirm_page(view, is_self=view.user_id == identity.user_id)
        )

    @app.post("/ui/users/{user_id}/federated-identity/unlink")
    async def ui_user_federated_unlink(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        # Action-bound, as DELETE /users/{id}/federated-identity is. A stale POST goes back to the
        # confirm page rather than being re-POSTed, so the operator reads the consequence again.
        identity: Identity = Depends(
            require_ui_step_up_action(
                STEP_UP_ACTION_ADMIN_FEDERATED_IDENTITY,
                Permission.USERS_MANAGE,
                reauth_next=lambda r: r.url.path.removesuffix("/unlink") + "/unlink-confirm",
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        view = await _federated_view(user_id, service)
        if not _still_shown(view, form):
            return await _federated_screen(
                user_id, service, identity, error=changed, status_code=409
            )
        try:
            await admin.unbind_user_federated_identity(user_id, service=service, identity=identity)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            return await _federated_screen(
                user_id, service, identity, error=str(exc.detail), status_code=exc.status_code
            )
        return RedirectResponse(
            f"/ui/users/{user_id}/federated-identity?m=unlinked", status_code=303
        )

    @app.post("/ui/users/{user_id}/revoke-sessions")
    async def ui_user_revoke_sessions(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> Response:
        assert_same_origin(request)
        await admin.admin_revoke_user_sessions(user_id, service=service, identity=identity)
        return RedirectResponse(f"/ui/users/{user_id}", status_code=303)

    @app.post("/ui/users/{user_id}/delete")
    async def ui_user_delete(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> Response:
        assert_same_origin(request)
        try:
            await admin.delete_user(user_id, service=service, identity=identity)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            return await _user_detail(
                user_id, service, identity, error=str(exc.detail), status_code=400
            )
        return RedirectResponse("/ui/users", status_code=303)

    # --- roles ------------------------------------------------------------

    @app.get("/ui/roles", response_class=HTMLResponse)
    async def ui_roles(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui(Permission.USERS_READ)),
    ) -> HTMLResponse:
        roles = await admin.list_roles(service=service, _=identity)
        return HTMLResponse(pages.roles_page(roles))

    @app.get("/ui/roles/new", response_class=HTMLResponse)
    async def ui_role_new(
        _identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> HTMLResponse:
        return HTMLResponse(pages.role_form_page(_role_catalog))

    @app.get("/ui/roles/{role_id}/edit", response_class=HTMLResponse)
    async def ui_role_edit(
        role_id: str,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> HTMLResponse:
        # Only CUSTOM roles are editable; a built-in (or unknown) id is a 404, mirroring the JSON API.
        for info in await admin.list_custom_roles(service=service, _=identity):
            if info.id == role_id:
                return HTMLResponse(pages.role_form_page(_role_catalog, role=info))
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such custom role")

    @app.post("/ui/roles/custom")
    async def ui_role_create(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/roles/new")
        ),
    ) -> Response:
        assert_same_origin(request)
        pairs = await _form_pairs(request)
        form = dict(pairs)
        perms = [v for k, v in pairs if k == "permissions"]
        try:
            body = CustomRoleRequest(
                display_name=form.get("display_name", "").strip(),
                description=form.get("description", "").strip() or None,
                permissions=perms,
            )
            await admin.create_custom_role(body=body, service=service, identity=identity)
        except (ValidationError, HTTPException) as exc:
            detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
            return HTMLResponse(
                pages.role_form_page(
                    _role_catalog,
                    error=detail,
                    display_name=form.get("display_name", "").strip(),
                    description=form.get("description", "").strip(),
                    checked=perms,
                ),
                status_code=400,
            )
        return RedirectResponse("/ui/roles", status_code=303)

    @app.post("/ui/roles/custom/{role_id}/update")
    async def ui_role_update(
        role_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.USERS_MANAGE,
                reauth_next=lambda r: f"/ui/roles/{r.path_params['role_id']}/edit",
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        pairs = await _form_pairs(request)
        form = dict(pairs)
        perms = [v for k, v in pairs if k == "permissions"]
        try:
            body = CustomRoleRequest(
                display_name=form.get("display_name", "").strip(),
                description=form.get("description", "").strip() or None,
                permissions=perms,
            )
            await admin.update_custom_role(role_id, body=body, service=service, identity=identity)
        except (ValidationError, HTTPException) as exc:
            if isinstance(exc, HTTPException) and exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            detail = "invalid input" if isinstance(exc, ValidationError) else str(exc.detail)
            current = CustomRoleInfo(
                id=role_id,
                display_name=form.get("display_name", "").strip(),
                description=form.get("description", "").strip() or None,
                permissions=perms,
            )
            return HTMLResponse(
                pages.role_form_page(_role_catalog, role=current, error=detail),
                status_code=400,
            )
        return RedirectResponse("/ui/roles", status_code=303)

    @app.post("/ui/roles/custom/{role_id}/delete")
    async def ui_role_delete(
        role_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> Response:
        assert_same_origin(request)
        await admin.delete_custom_role(role_id, service=service, identity=identity)
        return RedirectResponse("/ui/roles", status_code=303)

    # --- AD group mappings --------------------------------------------------

    async def _ad_groups_response(
        service: AuthService,
        identity: Identity,
        *,
        error: str | None = None,
        status_code: int = 200,
    ) -> HTMLResponse:
        gmap = await admin.get_ad_group_map(service=service, _=identity)
        smap = await admin.get_ad_group_scope_map(service=service, _=identity)
        roles = await admin.list_roles(service=service, _=identity)
        return HTMLResponse(
            pages.ad_groups_page(gmap.entries, smap.entries, roles, error=error),
            status_code=status_code,
        )

    @app.get("/ui/ad-groups", response_class=HTMLResponse)
    async def ui_ad_groups(
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> HTMLResponse:
        return await _ad_groups_response(service, identity)

    @app.post("/ui/ad-groups/map")
    async def ui_ad_group_map(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/ad-groups")
        ),
    ) -> Response:
        assert_same_origin(request)
        pairs = await _form_pairs(request)
        # Paired row inputs, zipped positionally (browsers submit fields in DOM order); a row with
        # an empty group or unselected role is a blank filler row — dropped. The PUT-equivalent JSON
        # handler replaces the whole map, so the surviving rows ARE the new map.
        groups = [v.strip() for k, v in pairs if k == "ad_group"]
        role_ids = [v.strip() for k, v in pairs if k == "role"]
        try:
            body = AdGroupMap(
                entries=[
                    AdGroupMapEntry(ad_group=g, role=r)
                    for g, r in zip(groups, role_ids, strict=True)
                    if g and r
                ]
            )
            await admin.set_ad_group_map(body=body, service=service, identity=identity)
        except (ValidationError, ValueError, HTTPException) as exc:
            detail = str(exc.detail) if isinstance(exc, HTTPException) else "invalid input"
            return await _ad_groups_response(service, identity, error=detail, status_code=400)
        return RedirectResponse("/ui/ad-groups", status_code=303)

    @app.post("/ui/ad-groups/scope-map")
    async def ui_ad_group_scope_map(
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(Permission.USERS_MANAGE, reauth_next=lambda _r: "/ui/ad-groups")
        ),
    ) -> Response:
        assert_same_origin(request)
        pairs = await _form_pairs(request)
        groups = [v.strip() for k, v in pairs if k == "ad_group"]
        channels = [v.strip() for k, v in pairs if k == "channel"]
        try:
            body = AdGroupScopeMap(
                entries=[
                    AdGroupScopeEntry(ad_group=g, channel=c)
                    for g, c in zip(groups, channels, strict=True)
                    if g and c
                ]
            )
            await admin.set_ad_group_scope_map(body=body, service=service, identity=identity)
        except (ValidationError, ValueError, HTTPException) as exc:
            detail = str(exc.detail) if isinstance(exc, HTTPException) else "invalid input"
            return await _ad_groups_response(service, identity, error=detail, status_code=400)
        return RedirectResponse("/ui/ad-groups", status_code=303)
