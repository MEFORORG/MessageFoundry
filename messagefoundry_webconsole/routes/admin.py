# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""L4a admin surface (ADR 0065; #75 phase 4): user, role, and AD-group-mapping /ui pages + actions. Clients of the injected JSON handlers (called directly, re-asserting each gate via require_ui*)."""

from __future__ import annotations


from fastapi import Depends, FastAPI, HTTPException, Request, status
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
    RolesUpdateRequest,
    UserCreateRequest,
    UserUpdateRequest,
)
from messagefoundry.auth import Identity, Permission
from messagefoundry.auth.permissions import CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
from messagefoundry.auth.service import AuthService

from .. import pages
from .._auth import (
    assert_same_origin,
    register_ui_action,
    require_ui,
    require_ui_step_up,
)
from .._service import _service
from ._common import _form_pairs

register_ui_action(r"^/ui/users/new$", Permission.USERS_MANAGE, auto_retry=False, unlock=True)
register_ui_action(r"^/ui/users/[^/?#]+$", Permission.USERS_MANAGE, auto_retry=False, unlock=True)
register_ui_action(
    r"^/ui/users/[^/?#]+/(reset-password|reset-mfa|revoke-sessions|delete)$",
    Permission.USERS_MANAGE,
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
            pages.user_detail_page(admin.user_summary(user, role_ids), all_roles, error=error),
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
        return HTMLResponse(pages.user_new_page(roles))

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
                email=form.get("email", "").strip() or None,
                roles=roles,
            )
            created = await admin.create_user(body=body, service=service, identity=identity)
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
                ),
                status_code=400,
            )
        return RedirectResponse(f"/ui/users/{created.id}", status_code=303)

    @app.post("/ui/users/{user_id}/update")
    async def ui_user_update(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(
            require_ui_step_up(
                Permission.USERS_MANAGE,
                reauth_next=lambda r: r.url.path.removesuffix("/update"),
            )
        ),
    ) -> Response:
        assert_same_origin(request)
        form = dict(await _form_pairs(request))
        try:
            # An HTML form always posts the full profile picture, so every field is set explicitly
            # ("" clears to None; an absent checkbox means enabled) — the PATCH partial semantics of
            # the JSON handler don't apply to a form submit.
            body = UserUpdateRequest(
                display_name=form.get("display_name", "").strip() or None,
                email=form.get("email", "").strip() or None,
                disabled="disabled" in form,
            )
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
        # The tri-state scope_mode keeps deny-all ([]) distinguishable from all-channels (None) —
        # an empty textarea alone must never widen a stored deny-all scope (review PR2-M3).
        # Absent (a pre-tri-state cached form) defaults to "list"; any OTHER value is a
        # hand-crafted post — refused rather than guessed (deny-by-default).
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
        channels = None if mode == "all" else ([] if mode == "none" else names)
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
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
    ) -> Response:
        assert_same_origin(request)
        try:
            result = await admin.reset_user_password(user_id, service=service, identity=identity)
        except HTTPException as exc:
            if exc.status_code == status.HTTP_404_NOT_FOUND:
                raise
            return await _user_detail(
                user_id, service, identity, error=str(exc.detail), status_code=400
            )
        user = await service.store.get_user(user_id)
        username = user.username if user is not None else user_id
        # The one-time credential is rendered ONCE for out-of-band delivery — never logged/stored.
        return HTMLResponse(pages.temp_password_page(username, result.temp_password))

    @app.post("/ui/users/{user_id}/reset-mfa")
    async def ui_user_reset_mfa(
        user_id: str,
        request: Request,
        service: AuthService = Depends(_service),
        identity: Identity = Depends(require_ui_step_up(Permission.USERS_MANAGE)),
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
