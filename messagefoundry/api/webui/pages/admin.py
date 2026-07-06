# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""User/RBAC administration pages for the /ui ops dashboard (ADR 0065, L4a).

Every builder returns escaped markup via :mod:`.._html` — an admin-entered display name or AD group
name can never inject markup. The body-carrying forms here (create user, set roles, custom roles, AD
maps) are the reason the step-up-to-unlock primitive exists: each **form page** is registered as an
``unlock`` action, so it always opens inside a fresh step-up window and its POST is submitted once,
same-origin, never crossing ``/ui/reauth``. A password appears in exactly one place — the create-user
password ``<input>`` — and is never echoed back into a re-rendered form.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from messagefoundry.api.auth_models import (
    AdGroupMapEntry,
    AdGroupScopeEntry,
    CustomRoleInfo,
    RoleInfo,
    UserSummary,
)

from .._html import Markup, el, page, register_nav, rows_table

__all__ = [
    "ad_groups_page",
    "role_form_page",
    "roles_page",
    "temp_password_page",
    "user_detail_page",
    "user_new_page",
    "users_page",
]


def _banner(error: str | None) -> Markup:
    return el("p", error, class_="banner") if error else Markup("")


def _admin_links(active_page: str) -> Markup:
    """The admin area's cross-links (one nav entry, three pages)."""
    links: list[object] = []
    for href, label, key in (
        ("/ui/users", "Users", "users"),
        ("/ui/roles", "Roles", "roles"),
        ("/ui/ad-groups", "AD group mappings", "ad-groups"),
    ):
        links.append(el("a", label, href=href, class_="active" if key == active_page else None))
        links.append(Markup(" "))
    return el("p", *links, class_="muted")


# --- users --------------------------------------------------------------------


def users_page(users: Sequence[UserSummary]) -> Markup:
    """The user list: every account with provider, roles, scope, and status; links to the admin forms."""
    rows: list[list[object]] = []
    for u in users:
        rows.append(
            [
                el("a", u.username, href=f"/ui/users/{u.id}"),
                u.auth_provider,
                u.display_name or "",
                u.email or "",
                ", ".join(u.roles),
                "all" if u.channel_scope is None else ", ".join(u.channel_scope) or "(none)",
                "disabled" if u.disabled else "active",
            ]
        )
    return page(
        "Users",
        el("h1", "Users"),
        _admin_links("users"),
        el("p", el("a", "+ New user", href="/ui/users/new")),
        rows_table(
            ["Username", "Provider", "Display name", "Email", "Roles", "Channel scope", "Status"],
            rows,
        ),
        active="users",
    )


def _role_checkboxes(roles: Iterable[RoleInfo], checked: Iterable[str]) -> list[object]:
    """One labelled checkbox per assignable role (name=roles, value=<role id>)."""
    chosen = set(checked)
    boxes: list[object] = []
    for role in roles:
        boxes.append(
            el(
                "label",
                el(
                    "input",
                    type="checkbox",
                    name="roles",
                    value=role.id,
                    checked=role.id in chosen,
                ),
                f" {role.display_name} ({role.id})",
                class_="check",
            )
        )
    return boxes


def user_new_page(
    roles: Sequence[RoleInfo],
    *,
    error: str | None = None,
    username: str = "",
    display_name: str = "",
    email: str = "",
    checked: Iterable[str] = (),
) -> Markup:
    """The create-user form (an ``unlock`` page: it always opens inside a fresh step-up window).

    On a rejected submit the form is re-rendered with the non-secret fields preserved — the password
    field is always empty (a password is never echoed back into markup).
    """
    form = el(
        "form",
        el("label", "Username", el("input", name="username", value=username, autofocus=True)),
        el(
            "label",
            "Initial password",
            el("input", name="password", type="password", autocomplete="new-password"),
        ),
        el(
            "p",
            "Convey the initial password out-of-band; the user must change it at first sign-in.",
            class_="muted",
        ),
        el("label", "Display name", el("input", name="display_name", value=display_name)),
        el("label", "Email", el("input", name="email", value=email)),
        el("fieldset", el("legend", "Roles"), *_role_checkboxes(roles, checked)),
        el("button", "Create user", type="submit"),
        method="post",
        action="/ui/users",
        class_="login",
    )
    body = el("div", el("h1", "New user"), _banner(error), form, class_="card")
    return page(
        "New user",
        body,
        el("p", el("a", "← Users", href="/ui/users")),
        active="users",
    )


def user_detail_page(
    user: UserSummary,
    roles: Sequence[RoleInfo],
    *,
    error: str | None = None,
) -> Markup:
    """One user's admin page (an ``unlock`` page): profile, roles, channel scope, and account actions.

    AD accounts get their roles from the AD-group map and their password from the directory, so those
    forms are replaced by notes (the JSON handlers refuse them anyway — this just mirrors the contract).
    """
    is_ad = user.auth_provider == "ad"
    profile = el(
        "form",
        el(
            "label",
            "Display name",
            el("input", name="display_name", value=user.display_name or ""),
        ),
        el("label", "Email", el("input", name="email", value=user.email or "")),
        el(
            "label",
            el("input", type="checkbox", name="disabled", checked=user.disabled),
            " Disabled (sign-in refused)",
            class_="check",
        ),
        el("button", "Save profile", type="submit"),
        method="post",
        action=f"/ui/users/{user.id}/update",
        class_="ctl",
    )
    if is_ad:
        roles_section: Markup = el("p", "AD users get roles from the AD-group map.", class_="muted")
    else:
        roles_section = el(
            "form",
            *_role_checkboxes(roles, user.roles),
            el("button", "Save roles", type="submit"),
            method="post",
            action=f"/ui/users/{user.id}/roles",
            class_="ctl",
        )
    # Three explicit scope states so a deny-all ([]) scope ROUND-TRIPS: an empty textarea alone is
    # ambiguous between "all channels" (None) and "no channels" ([]), and silently widening a stored
    # deny-all to all-channels on a re-save would be a privilege-widening bug (review PR2-M3).
    scope_mode = (
        "all" if user.channel_scope is None else ("none" if user.channel_scope == [] else "list")
    )
    mode_options = [
        el("option", label, value=value, selected=value == scope_mode or None)
        for value, label in (
            ("all", "All channels"),
            ("list", "Only the connections listed below"),
            ("none", "No channels (deny all)"),
        )
    ]
    scope = el(
        "form",
        el("label", "Scope", el("select", *mode_options, name="scope_mode")),
        el(
            "label",
            "Allowed connections (one per line)",
            el("textarea", "\n".join(user.channel_scope or []), name="channels", rows=4),
        ),
        el("button", "Save channel scope", type="submit"),
        method="post",
        action=f"/ui/users/{user.id}/channel-scope",
        class_="ctl",
    )
    danger: list[object] = []
    if not is_ad:
        danger.append(
            el(
                "form",
                el("button", "Reset password", type="submit"),
                method="post",
                action=f"/ui/users/{user.id}/reset-password",
                class_="ctl",
            )
        )
        danger.append(
            el(
                "form",
                el("button", "Reset MFA", type="submit"),
                method="post",
                action=f"/ui/users/{user.id}/reset-mfa",
                class_="ctl",
            )
        )
    danger.append(
        el(
            "form",
            el("button", "Sign out all sessions", type="submit"),
            method="post",
            action=f"/ui/users/{user.id}/revoke-sessions",
            class_="ctl",
        )
    )
    danger.append(
        el(
            "form",
            el("button", "Delete user", type="submit"),
            method="post",
            action=f"/ui/users/{user.id}/delete",
            class_="ctl",
        )
    )
    return page(
        f"User {user.username}",
        el("h1", f"User: {user.username}"),
        el(
            "p",
            f"Provider: {user.auth_provider} — {'disabled' if user.disabled else 'active'}",
            class_="muted",
        ),
        _banner(error),
        el("div", el("h2", "Profile"), profile, class_="card"),
        el("div", el("h2", "Roles"), roles_section, class_="card"),
        el("div", el("h2", "Channel scope"), scope, class_="card"),
        el("div", el("h2", "Account actions"), *danger, class_="card"),
        el("p", el("a", "← Users", href="/ui/users")),
        active="users",
    )


def temp_password_page(username: str, temp_password: str) -> Markup:
    """The one-time result of an admin password reset — shown once, never stored or logged."""
    body = el(
        "div",
        el("h1", "Temporary password issued"),
        el(
            "p",
            f"Convey this to {username} out-of-band. It is shown once and must be changed at "
            "first sign-in.",
            class_="muted",
        ),
        el("p", el("code", temp_password)),
        el("p", el("a", "← Users", href="/ui/users")),
        class_="card",
    )
    return page("Temporary password", body, active="users")


# --- roles ---------------------------------------------------------------------


def roles_page(roles: Sequence[RoleInfo]) -> Markup:
    """All assignable roles: the six fixed built-ins plus admin-defined custom roles (ADR 0045)."""
    rows: list[list[object]] = []
    for role in roles:
        name: object = (
            role.display_name
            if role.builtin
            else el("a", role.display_name, href=f"/ui/roles/{role.id}/edit")
        )
        rows.append(
            [
                name,
                role.id,
                "built-in" if role.builtin else "custom",
                ", ".join(role.permissions),
            ]
        )
    return page(
        "Roles",
        el("h1", "Roles"),
        _admin_links("roles"),
        el("p", el("a", "+ New custom role", href="/ui/roles/new")),
        el(
            "p",
            "Built-in roles are fixed; a custom role grants a named subset of the permission "
            "catalog (never user administration, approvals, or DR).",
            class_="muted",
        ),
        rows_table(["Role", "Id", "Type", "Permissions"], rows),
        active="users",
    )


def _permission_checkboxes(catalog: Sequence[str], checked: Iterable[str]) -> list[object]:
    chosen = set(checked)
    return [
        el(
            "label",
            el("input", type="checkbox", name="permissions", value=perm, checked=perm in chosen),
            f" {perm}",
            class_="check",
        )
        for perm in catalog
    ]


def role_form_page(
    catalog: Sequence[str],
    *,
    role: CustomRoleInfo | None = None,
    error: str | None = None,
    display_name: str | None = None,
    description: str | None = None,
    checked: Iterable[str] | None = None,
) -> Markup:
    """Create (``role is None``) or edit a custom role (an ``unlock`` page).

    ``display_name``/``description``/``checked`` override the role's stored values when re-rendering a
    rejected submit, so typed input isn't lost.
    """
    name_value = display_name if display_name is not None else (role.display_name if role else "")
    desc_value = (
        description if description is not None else (role.description or "" if role else "")
    )
    perm_checked = checked if checked is not None else (role.permissions if role else ())
    action = f"/ui/roles/custom/{role.id}/update" if role else "/ui/roles/custom"
    form = el(
        "form",
        el("label", "Name", el("input", name="display_name", value=name_value, autofocus=True)),
        el("label", "Description", el("input", name="description", value=desc_value)),
        el("fieldset", el("legend", "Permissions"), *_permission_checkboxes(catalog, perm_checked)),
        el("button", "Save role" if role else "Create role", type="submit"),
        method="post",
        action=action,
        class_="login",
    )
    extras: list[object] = []
    if role:
        extras.append(
            el(
                "form",
                el("button", "Delete role", type="submit"),
                method="post",
                action=f"/ui/roles/custom/{role.id}/delete",
                class_="ctl",
            )
        )
    title = "Edit custom role" if role else "New custom role"
    body = el("div", el("h1", title), _banner(error), form, *extras, class_="card")
    return page(title, body, el("p", el("a", "← Roles", href="/ui/roles")), active="users")


# --- AD group mappings -----------------------------------------------------------


def _map_rows(
    first_name: str,
    pairs: Sequence[tuple[str, Markup]],
    blank: Markup,
    blanks: int = 3,
) -> list[object]:
    """Rows of paired inputs (existing entries + a few blank rows; empty rows are ignored on save)."""
    rows: list[object] = []
    for value, partner in pairs:
        rows.append(el("div", el("input", name=first_name, value=value), partner, class_="maprow"))
    for _ in range(blanks):
        rows.append(el("div", el("input", name=first_name, value=""), blank, class_="maprow"))
    return rows


def _role_select(roles: Sequence[RoleInfo], selected: str = "") -> Markup:
    options: list[object] = [el("option", "", value="")]
    for role in roles:
        options.append(el("option", role.id, value=role.id, selected=role.id == selected or None))
    return el("select", *options, name="role")


def ad_groups_page(
    map_entries: Sequence[AdGroupMapEntry],
    scope_entries: Sequence[AdGroupScopeEntry],
    roles: Sequence[RoleInfo],
    *,
    error: str | None = None,
) -> Markup:
    """Both AD-group mappings (group→role and group→channel scope), each saved as a full replacement.

    Rows with an empty group or an unselected role/channel are dropped on save — the blank tail rows
    exist to add entries without any client-side scripting (CSP: no inline JS).
    """
    role_rows = _map_rows(
        "ad_group",
        [(e.ad_group, _role_select(roles, e.role)) for e in map_entries],
        _role_select(roles),
    )
    role_form = el(
        "form",
        *role_rows,
        el("button", "Save role map", type="submit"),
        method="post",
        action="/ui/ad-groups/map",
        class_="ctl",
    )
    scope_rows = _map_rows(
        "ad_group",
        [
            (e.ad_group, el("input", name="channel", value=e.channel, placeholder="channel or *"))
            for e in scope_entries
        ],
        el("input", name="channel", value="", placeholder="channel or *"),
    )
    scope_form = el(
        "form",
        *scope_rows,
        el("button", "Save scope map", type="submit"),
        method="post",
        action="/ui/ad-groups/scope-map",
        class_="ctl",
    )
    return page(
        "AD group mappings",
        el("h1", "AD group mappings"),
        _admin_links("ad-groups"),
        _banner(error),
        el(
            "div",
            el("h2", "Group → role"),
            el("p", "AD users receive the mapped roles at sign-in.", class_="muted"),
            role_form,
            class_="card",
        ),
        el(
            "div",
            el("h2", "Group → channel scope"),
            el("p", "Channel ", el("code", "*"), " grants all channels.", class_="muted"),
            scope_form,
            class_="card",
        ),
        active="users",
    )


# Nav registration (append-at-tail): ONE entry for the admin area; Roles + AD mappings cross-link.
register_nav("users", "/ui/users", "Users")
