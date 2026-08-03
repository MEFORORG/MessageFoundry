# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Auth/session/account page builders for the /ui ops dashboard (ADR 0065): sign-in, step-up
re-auth, and the L4b self-service account pages (change password, TOTP MFA lifecycle).

The account pages carry the normal chrome. The UNAUTHENTICATED entry pages (sign-in, the Windows-SSO
challenge) are bare — ``nav=Markup("")``. Every page that is reached WITH a live session but drops the
full nav for focus/confinement (step-up re-auth, reauth-continue, the forced must-change-password
page, passkey enrolment, the federated landing hop) renders ``nav=minimal_nav()`` instead: the
wordmark plus the same one-click POST Sign-out form, so an authenticated page never leaves the
operator without a way out (ASVS 7.4.4). Every dynamic value is placed through the escaping element
builders in :mod:`.._html`. Secrets are handled once: a password is only ever an
``<input type=password>`` (never echoed back), and the TOTP secret / recovery codes render exactly
once on their dedicated pages.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime

from messagefoundry.api.auth_models import CurrentUser, MfaStatusResponse

from .._html import Markup, el, minimal_nav, page, register_nav, wordmark

__all__ = [
    "account_page",
    "leaving_site",
    "login",
    "oidc_landing",
    "mfa_confirm_page",
    "mfa_enroll_page",
    "mfa_gate",
    "mfa_recovery_page",
    "password_page",
    "reauth",
    "reauth_continue",
    "sessions_page",
    "sso_challenge",
    "webauthn_enroll_page",
]


def _when(ts: object) -> str:
    if not isinstance(ts, (int, float)):
        return "—"
    return datetime.fromtimestamp(float(ts), UTC).strftime("%Y-%m-%d %H:%MZ")


def login(
    error: str | None = None,
    *,
    ad_enabled: bool = False,
    sso_enabled: bool = False,
    oidc_enabled: bool = False,
) -> Markup:
    """The sign-in form. Same-origin POST to /ui/login (form-action 'self').

    ``ad_enabled`` (L5b, ADR 0068 §8) renders the provider selector — zero visual change for
    local-only installs. AD passwords verify via the existing live directory bind; AD sessions
    arrive MFA-delegated exactly as on the JSON surface."""
    notes = {
        "must_change": "Password change required — sign in to rotate it.",
        "bad": "Invalid credentials.",
        "loggedout": "Signed out.",
        # ASVS 14.3.1 — the client session watchdog's landing code: it blanks the page and navigates
        # here when the server has ended the session (or can no longer confirm it), so the operator
        # gets a reason instead of an unexplained login form.
        "expired": "Your session ended — sign in again.",
        "pwchanged": "Password changed — sign in with the new password.",
        # L5c (ADR 0068 §9) — allow-listed SSO outcome codes, never reflected text.
        "sso_failed": "Windows SSO sign-in failed — sign in with a password instead.",
        "sso_unavailable": "Windows SSO is not available on this server.",
        "rate_limited": "Too many attempts — wait a moment and try again.",
        # ADR 0142 — allow-listed FEDERATED outcome codes. The IdP's own `error` /
        # `error_description` are never reflected: they are attacker/IdP-controlled text, and echoing
        # them would put it in the URL, the referrer chain, and every proxy log.
        "oidc_failed": "Federated sign-in failed — sign in with a password instead.",
        "oidc_unavailable": "Federated sign-in is not available on this server.",
        "flow_binding_missing": (
            "Your sign-in session expired or did not return to this browser — start again."
        ),
        "sso_mfa_required": (
            "Your identity provider did not confirm multi-factor authentication for this sign-in."
        ),
    }
    banner = el("p", notes.get(error or "", ""), class_="banner") if error else Markup("")
    provider: Markup = Markup("")
    if ad_enabled:
        provider = el(
            "label",
            "Sign in with",
            el(
                "select",
                el("option", "Local account", value="local"),
                el("option", "Active Directory", value="ad"),
                name="provider",
            ),
        )
    form = el(
        "form",
        provider,
        el(
            "label",
            "Username",
            el("input", name="username", autofocus=True, autocomplete="username"),
        ),
        el(
            "label",
            "Password",
            el("input", name="password", type="password", autocomplete="current-password"),
        ),
        el("button", "Sign in", type="submit"),
        method="post",
        action="/ui/login",
        class_="login",
    )
    sso = (
        el("p", el("a", "Sign in with Windows (SSO)", href="/ui/sso"), class_="muted")
        if sso_enabled
        else Markup("")
    )
    federated = (
        el("p", el("a", "Sign in with your organization", href="/ui/oidc/start"), class_="muted")
        if oidc_enabled
        else Markup("")
    )
    body = el("div", el("h1", wordmark(tm=True)), banner, form, sso, federated, class_="card")
    # A bare page (no nav) for the unauthenticated login screen.
    return page("Sign in", body, nav=Markup(""))


def oidc_landing() -> Markup:
    """The same-site landing hop after a successful federated sign-in (ADR 0142).

    Returned as **200 HTML with a meta refresh**, deliberately NOT a 303. The session cookie is
    ``SameSite=Strict``; a 303 issued in response to the IdP's cross-site redirect would leave the
    browser's follow-up request to ``/ui`` still cross-site-initiated, so the Strict cookie would be
    withheld and the operator would land back on the login page despite a successful login. Bouncing
    through a document served from OUR origin makes the next navigation same-site, so the cookie is
    unambiguously sent.

    No JavaScript, so this works under the strict ``/ui`` CSP with no nonce and no ``script-src``
    relaxation. The visible link is the fallback for a browser with meta refresh disabled.
    """
    body = el(
        "div",
        el("h1", wordmark(tm=True)),
        el("p", "Signed in — continuing to the console…"),
        el("p", el("a", "Continue", href="/ui"), class_="muted"),
        class_="card",
    )
    return page(
        "Signing in",
        body,
        nav=minimal_nav(),
        head_extra=el("meta", **{"http-equiv": "refresh", "content": "0;url=/ui"}),
    )


def leaving_site(
    *,
    destination_host: str,
    continue_action: str,
    idn_disguised: bool = False,
    cancel_href: str = "/ui/login",
    purpose: str = "",
) -> Markup:
    """The ASVS 3.7.3 interstitial: you are leaving, here is where to, and you may cancel.

    **The destination URL is deliberately NOT a parameter of this page.** Only the host is passed, for
    display. The actual URL lives in server-side flow state and is looked up by the POST handler — if
    the page carried the target, the interstitial would itself be an open redirect, which is strictly
    worse than having no interstitial at all.

    **``destination_host`` must already be punycode/ASCII** (see ``_external.display_host``). Showing
    the decoded Unicode would show the operator a host that is not the one the browser resolves, which
    makes this page actively misleading rather than merely useless. ``idn_disguised`` surfaces the
    case where the two differ, because a homograph is invisible by construction and cannot be left to
    the reader to spot.

    Continue is a **form POST**, not a link. Two reasons: the POST target carries no URL so it cannot
    be pointed anywhere else, and it puts the navigation behind the console's existing same-origin /
    ``Sec-Fetch-Site`` check — which also closes the pre-existing hole where any external page could
    start a federated sign-in just by linking to the start leg.

    No JavaScript: the ``/ui`` CSP is strict, with no nonce and no ``script-src`` relaxation.
    """
    warn = (
        el(
            "p",
            el("strong", "This address uses non-ASCII characters."),
            " It is shown above in its encoded form, which is what your browser will actually look "
            "up. A name that looks familiar may not be the site you expect.",
            class_="warn",
        )
        if idn_disguised
        else Markup("")
    )
    reason = el("p", purpose, class_="muted") if purpose else Markup("")
    body = el(
        "div",
        el("h1", wordmark(tm=True)),
        el("p", el("strong", "You are leaving this site.")),
        reason,
        el("p", "You will be taken to:"),
        el("p", el("code", destination_host)),
        warn,
        el(
            "form",
            el("button", "Continue", type="submit"),
            method="post",
            action=continue_action,
            class_="login",
        ),
        el("p", el("a", "Cancel", href=cancel_href), class_="muted"),
        class_="card",
    )
    return page("Leaving this site", body, nav=Markup(""))


def sso_challenge() -> Markup:
    """The HTML body of the RFC 4559 401 challenge (L5c, ADR 0068 §9): a browser configured for
    Windows SSO retries the request with its Negotiate token and never renders this; one that
    isn't gets a legible path back to the password form instead of a bare 401."""
    body = el(
        "div",
        el("h1", "Windows SSO"),
        el(
            "p",
            "Your browser did not present a Windows SSO token. SSO needs a domain-joined "
            "machine and this site allow-listed for integrated authentication.",
            class_="muted",
        ),
        el("p", el("a", "Sign in with a password instead", href="/ui/login"), class_="muted"),
        class_="card",
    )
    return page("Windows SSO", body, nav=Markup(""))


def reauth(
    next_path: str,
    *,
    mfa_needed: bool,
    error: str | None = None,
    webauthn_options: str | None = None,
    webauthn_notice: str | None = None,
) -> Markup:
    """The step-up re-authentication form for a sensitive action (replay). POSTs to /ui/reauth.

    Shows a password field always, plus a TOTP field when the session's second factor isn't
    satisfied — and, additively (ADR 0068 decision 1(b)), a passkey button when the user has
    WebAuthn credentials: ``webauthn_options`` carries the staged assertion-options JSON in a
    ``data-*`` hook for app.js (``navigator.credentials.get`` → POST /ui/reauth/webauthn — the
    assertion satisfies the MFA leg; the password below still completes the step-up).
    ``webauthn_notice`` is the legible fail-closed copy (extra absent / public_origin unset) — a
    dead-end message, never a redirect loop. ``next_path`` (a validated /ui action) rides in a
    hidden field so a successful re-auth can auto-retry it.
    """
    banner = el("p", error, class_="banner") if error else Markup("")
    passkey: Markup
    if webauthn_options is not None:
        passkey = el(
            "div",
            el(
                "button",
                "Use passkey",
                type="button",
                data_mf_webauthn_get=webauthn_options,
            ),
            el("p", "", class_="muted", data_mf_webauthn_status=True),
            class_="ctl",
        )
    elif webauthn_notice:
        passkey = el("p", webauthn_notice, class_="muted")
    else:
        passkey = Markup("")
    fields: list[object] = [
        el(
            "label",
            "Password",
            el("input", name="password", type="password", autocomplete="current-password"),
        )
    ]
    if mfa_needed:
        fields.append(
            el(
                "label",
                "Authenticator code",
                el("input", name="code", inputmode="numeric", autocomplete="one-time-code"),
            )
        )
    form = el(
        "form",
        el("input", type="hidden", name="next", value=next_path),
        *fields,
        el("button", "Verify", type="submit"),
        method="post",
        action="/ui/reauth",
        class_="login",
    )
    body = el(
        "div",
        el("h1", "Confirm it's you"),
        el("p", "This action needs a fresh sign-in confirmation.", class_="muted"),
        banner,
        passkey,
        form,
        class_="card",
    )
    return page("Confirm", body, nav=minimal_nav())


def mfa_gate(
    *,
    totp_enrolled: bool,
    error: str | None = None,
    webauthn_options: str | None = None,
    webauthn_notice: str | None = None,
) -> Markup:
    """The ASVS 6.3.3 second-factor page a MFA-pending browser session is confined to. POSTs /ui/mfa.

    Distinct from :func:`reauth`, which confirms a *sensitive action* and therefore always asks for
    the password. This page completes SIGN-IN: the password was proven seconds ago, so asking for it
    again would be noise. Only the second factor is collected.

    Rendered on ``minimal_nav`` for the same reason the reauth page is — the app nav's status poll is
    gated, so a full nav here would fire a request the pending session is not allowed to make.

    Splits by factor exactly like :func:`reauth` (ADR 0068 decision 1(b)): the code field renders iff
    TOTP is enrolled, the passkey button iff WebAuthn is. A user with only a passkey never sees an
    unanswerable code box, and a user with only TOTP never sees a button they cannot use.
    """
    banner = el("p", error, class_="banner") if error else Markup("")
    passkey: Markup
    if webauthn_options is not None:
        passkey = el(
            "div",
            el(
                "button",
                "Use passkey",
                type="button",
                data_mf_webauthn_get=webauthn_options,
                # Tells app.js this assertion COMPLETES sign-in and should navigate, rather than
                # unlocking a password field as it does on the reauth page (where the password is
                # still owed). Without it a passkey-only user verifies and then sits on a dead page.
                data_mf_webauthn_done="/ui",
            ),
            el("p", "", class_="muted", data_mf_webauthn_status=True),
            class_="ctl",
        )
    elif webauthn_notice:
        passkey = el("p", webauthn_notice, class_="muted")
    else:
        passkey = Markup("")
    fields: list[object] = []
    if totp_enrolled:
        fields.append(
            el(
                "label",
                "Authenticator code",
                # No `value=`: never echo a submitted code back into the form. A TOTP or recovery
                # code is a bearer credential, and a re-render is exactly where one leaks.
                el("input", name="code", inputmode="numeric", autocomplete="one-time-code"),
            )
        )
        fields.append(el("button", "Verify", type="submit"))
    form = (
        el("form", *fields, method="post", action="/ui/mfa", class_="login")
        if fields
        else Markup("")
    )
    body = el(
        "div",
        el("h1", "Second factor required"),
        el(
            "p",
            "Your account requires a second factor. Confirm it to continue.",
            class_="muted",
        ),
        banner,
        passkey,
        form,
        class_="card",
    )
    return page("Second factor", body, nav=minimal_nav())


def reauth_continue(next_path: str) -> Markup:
    """After a successful step-up, auto-POST the pending action (``next_path``) via app.js.

    ``next_path`` has already been validated as a same-origin /ui replay action. If JavaScript is off,
    the user clicks Continue (graceful degradation); the POST is same-origin so the CSRF check passes.
    """
    form = el(
        "form",
        el("button", "Continue", type="submit"),
        method="post",
        action=next_path,
        data_autosubmit=True,
        class_="login",
    )
    body = el(
        "div",
        el("h1", "Verified"),
        el("p", "Continuing…", class_="muted"),
        form,
        class_="card",
    )
    return page("Verified", body, nav=minimal_nav())


# --- L4b: self-service account pages (change password + TOTP MFA lifecycle) ------------------------


def account_page(
    me: CurrentUser,
    mfa: MfaStatusResponse,
    *,
    notice: str | None = None,
    error: str | None = None,
    passkeys: Sequence[Mapping[str, object]] | None = None,
    webauthn_notice: str | None = None,
) -> Markup:
    """The signed-in user's account overview: identity, password rotation, and MFA posture/actions.

    ``passkeys`` (ADR 0068): plain row mappings built by the route (label / created_at /
    last_used_at / backed_up / usable / credential_id_hash) — this module never touches the store.
    ``webauthn_notice`` renders the fail-closed copy in place of the Add-a-passkey form (extra
    absent / public_origin unset)."""
    banner = el("p", error, class_="banner") if error else Markup("")
    note = el("p", notice, class_="muted") if notice else Markup("")
    is_ad = me.auth_provider == "ad"
    ident = el(
        "div",
        el("h2", "Identity"),
        el("p", f"Signed in as {me.username} ({me.auth_provider})", class_="muted"),
        el("p", "Roles: " + (", ".join(me.roles) or "(none)"), class_="muted"),
        class_="card",
    )
    if is_ad:
        pw_section = el("p", "AD passwords are managed in Active Directory.", class_="muted")
        mfa_section: Markup = el(
            "p", "AD accounts use directory MFA, not an engine TOTP.", class_="muted"
        )
    else:
        pw_section = el("p", el("a", "Change password", href="/ui/account/password"))
        if mfa.enabled:
            status_line = el(
                "p",
                f"Enabled — {mfa.recovery_codes_remaining} recovery code(s) remaining.",
                class_="muted",
            )
            action = el(
                "form",
                el("button", "Disable MFA", type="submit"),
                method="post",
                action="/ui/account/mfa/disable",
                class_="ctl",
            )
        else:
            status_line = el(
                "p",
                "Not enrolled."
                + (" This account REQUIRES MFA — enroll now." if mfa.required else ""),
                class_="muted",
            )
            action = el(
                "form",
                el("button", "Enroll an authenticator", type="submit"),
                method="post",
                action="/ui/account/mfa/enroll",
                class_="ctl",
            )
        mfa_section = Markup(status_line + action)
    passkey_card = Markup("") if is_ad else _passkey_card(mfa, passkeys or (), webauthn_notice)
    # Active-session management is self-service for EVERY account (local + AD), unlike password/MFA.
    sessions_card = el(
        "div",
        el("h2", "Active sessions"),
        el("p", el("a", "Manage active sessions", href="/ui/account/sessions")),
        class_="card",
    )
    return page(
        "My account",
        el("h1", "My account"),
        note,
        banner,
        ident,
        el("div", el("h2", "Password"), pw_section, class_="card"),
        el("div", el("h2", "Multi-factor authentication"), mfa_section, class_="card"),
        passkey_card,
        sessions_card,
        active="account",
    )


def sessions_page(sessions: Sequence[Mapping[str, object]], *, notice: str | None = None) -> Markup:
    """The self-service active-session inventory (L6b — the desktop `console/sessions.py` twin):
    every live session for the caller with its own **Revoke**, plus **Sign out everywhere else**.

    ``sessions`` are plain row mappings built by the route (id / created_at / last_used_at /
    expires_at / client / current) — this module never touches the store. Revoking one's OWN
    sessions is cookie-authenticated self-service (no step-up); the current session shows no Revoke
    button (use the header Sign out to end it) so the list can't leave the user mid-request."""
    note = el("p", notice, class_="muted") if notice else Markup("")
    rows: list[Markup] = []
    others = 0
    for s in sessions:
        is_current = bool(s.get("current"))
        if not is_current:
            others += 1
        action: Markup = (
            el("span", "(this session)", class_="muted")
            if is_current
            else el(
                "form",
                el("button", "Revoke", type="submit"),
                method="post",
                action=f"/ui/account/sessions/{s.get('id', '')}/revoke",
                class_="ctl",
            )
        )
        rows.append(
            el(
                "tr",
                el("td", _when(s.get("created_at"))),
                el("td", _when(s.get("last_used_at"))),
                el("td", str(s.get("client") or "—")),
                el("td", action),
            )
        )
    table = el(
        "table",
        el("tr", el("th", "Signed in"), el("th", "Last used"), el("th", "Client"), el("th", "")),
        *rows,
    )
    sign_out_others = (
        el(
            "form",
            el("button", f"Sign out everywhere else ({others})", type="submit"),
            method="post",
            action="/ui/account/sessions/revoke-others",
            class_="ctl",
        )
        if others
        else Markup("")
    )
    body = el(
        "div",
        el("h1", "Active sessions"),
        note,
        el("p", el("a", "← Back to my account", href="/ui/account"), class_="muted"),
        el("div", table, sign_out_others, class_="card"),
    )
    # active= belongs on page() (highlights the "My account" nav) — not on the wrapper div.
    return page("Active sessions", body, active="account")


def _passkey_card(
    mfa: MfaStatusResponse,
    passkeys: Sequence[Mapping[str, object]],
    webauthn_notice: str | None,
) -> Markup:
    """The L5a passkeys card: enrolled-credential table (per-row delete), the Add form, and the
    posture caveats (ADR 0068 §6)."""
    rows: list[Markup] = []
    for cred in passkeys:
        flags: list[str] = []
        if cred.get("backed_up"):
            flags.append("synced")
        if not cred.get("usable", True):
            flags.append("unusable (origin changed)")
        remove = el(
            "form",
            el("button", "Remove", type="submit"),
            method="post",
            action=f"/ui/account/webauthn/{cred.get('credential_id_hash', '')}/delete",
            class_="ctl",
        )
        rows.append(
            el(
                "tr",
                el("td", str(cred.get("label", ""))),
                el("td", _when(cred.get("created_at"))),
                el("td", _when(cred.get("last_used_at"))),
                el("td", ", ".join(flags) or "—"),
                el("td", remove),
            )
        )
    table = (
        el(
            "table",
            el(
                "tr",
                el("th", "Label"),
                el("th", "Created"),
                el("th", "Last used"),
                el("th", "Notes"),
                el("th", ""),
            ),
            *rows,
        )
        if rows
        else el("p", "No passkeys enrolled.", class_="muted")
    )
    caveats: list[Markup] = []
    if webauthn_notice:
        add: Markup = el("p", webauthn_notice, class_="muted")
    else:
        add = el(
            "form",
            el("button", "Add a passkey", type="submit"),
            method="post",
            action="/ui/account/webauthn/enroll",
            class_="ctl",
        )
        caveats.append(
            el(
                "p",
                "Keep TOTP enrolled if you use the desktop console — passkeys work in the "
                "browser only. Changing [api].public_origin invalidates enrolled passkeys.",
                class_="muted",
            )
        )
        if len(passkeys) == 1 and not mfa.enabled:
            # Recovery nudge (no recovery codes for passkeys by design — ADR 0068 decision 5).
            caveats.append(
                el(
                    "p",
                    "This is your only second factor: enroll a second passkey or TOTP so a "
                    "lost authenticator doesn't lock you out (recovery is admin-reset only).",
                    class_="muted",
                )
            )
    return el("div", el("h2", "Passkeys"), table, add, *caveats, class_="card")


def password_page(*, forced: bool = False, error: str | None = None) -> Markup:
    """The change-password form (current + new twice; nothing is ever echoed back).

    ``forced`` renders the bare must-change variant: the account is confined here until it rotates
    (every other /ui route 303s back), so the page explains why and drops the (useless) nav.
    """
    banner = el("p", error, class_="banner") if error else Markup("")
    intro = (
        el(
            "p",
            "Your password must be changed before you can continue.",
            class_="muted",
        )
        if forced
        else el("p", "Re-enter your current password, then choose a new one.", class_="muted")
    )
    form = el(
        "form",
        el(
            "label",
            "Current password",
            el(
                "input",
                name="current_password",
                type="password",
                autocomplete="current-password",
                autofocus=True,
            ),
        ),
        el(
            "label",
            "New password",
            el("input", name="new_password", type="password", autocomplete="new-password"),
        ),
        el(
            "label",
            "New password (again)",
            el("input", name="new_password2", type="password", autocomplete="new-password"),
        ),
        el("button", "Change password", type="submit"),
        method="post",
        action="/ui/account/password",
        class_="login",
    )
    body = el("div", el("h1", "Change password"), intro, banner, form, class_="card")
    if forced:
        return page("Change password", body, nav=minimal_nav())
    return page(
        "Change password",
        body,
        el("p", el("a", "← My account", href="/ui/account")),
        active="account",
    )


def mfa_enroll_page(secret: str, otpauth_uri: str) -> Markup:
    """The staged-enrollment page: the TOTP secret + otpauth URI (shown once for authenticator entry)
    and the confirm-code form. No QR image — the /ui surface is zero-dependency (ADR 0065), so the
    secret is entered manually or the URI pasted; the desktop console renders the QR."""
    confirm = el(
        "form",
        el(
            "label",
            "Code from your authenticator",
            el(
                "input",
                name="code",
                inputmode="numeric",
                autocomplete="one-time-code",
                autofocus=True,
            ),
        ),
        el("button", "Activate MFA", type="submit"),
        method="post",
        action="/ui/account/mfa/verify",
        class_="ctl",
    )
    body = el(
        "div",
        el("h1", "Enroll an authenticator"),
        el(
            "p",
            "Add this secret to your authenticator app (manual entry), then prove a live code. "
            "The secret is shown once and is not active until confirmed.",
            class_="muted",
        ),
        el("p", "Secret: ", el("code", secret)),
        el("p", "URI: ", el("code", otpauth_uri)),
        confirm,
        el("p", el("a", "← My account", href="/ui/account")),
        class_="card",
    )
    return page("Enroll MFA", body, active="account")


def webauthn_enroll_page(options_json: str) -> Markup:
    """The passkey creation ceremony page (ADR 0068 §6): the staged creation-options JSON rides a
    ``data-*`` hook (never an inline script — CSP is 'self'-only); app.js runs
    ``navigator.credentials.create`` and POSTs the attestation + label to
    /ui/account/webauthn/verify. The no-JS fallback is a plain explanation (progressive
    enhancement — the TOTP path remains fully script-free)."""
    body = el(
        "div",
        el("h1", "Add a passkey"),
        el(
            "p",
            "Name this passkey, then follow your browser's prompt.",
            class_="muted",
        ),
        el(
            "div",
            el("label", "Label", el("input", name="label", maxlength="100", value="")),
            el(
                "button",
                "Create passkey",
                type="button",
                data_mf_webauthn_create=options_json,
            ),
            el("p", "", class_="muted", data_mf_webauthn_status=True),
            class_="ctl",
        ),
        el(
            "noscript",
            el(
                "p",
                "Passkey enrollment needs JavaScript (the browser credential prompt). "
                "TOTP enrollment on the account page works without it.",
                class_="banner",
            ),
        ),
        el("p", el("a", "Back to my account", href="/ui/account"), class_="muted"),
        class_="card",
    )
    return page("Add a passkey", body, nav=minimal_nav())


def mfa_confirm_page(*, error: str | None = None) -> Markup:
    """The standalone confirm-code form (the unlock re-entry point after a step-up re-auth): the
    secret is already staged server-side and in the user's authenticator, so it is NOT re-shown."""
    banner = el("p", error, class_="banner") if error else Markup("")
    form = el(
        "form",
        el(
            "label",
            "Code from your authenticator",
            el(
                "input",
                name="code",
                inputmode="numeric",
                autocomplete="one-time-code",
                autofocus=True,
            ),
        ),
        el("button", "Activate MFA", type="submit"),
        method="post",
        action="/ui/account/mfa/verify",
        class_="ctl",
    )
    body = el(
        "div",
        el("h1", "Confirm enrollment"),
        el(
            "p",
            "Enter a live code from the authenticator you just added to activate MFA.",
            class_="muted",
        ),
        banner,
        form,
        el("p", el("a", "← My account", href="/ui/account")),
        class_="card",
    )
    return page("Confirm MFA", body, active="account")


def mfa_recovery_page(codes: Sequence[str]) -> Markup:
    """The single-use recovery codes — shown ONCE, immediately after activation. Never re-fetchable."""
    items = [el("li", el("code", c)) for c in codes]
    body = el(
        "div",
        el("h1", "MFA is active"),
        el(
            "p",
            "Save these single-use recovery codes somewhere safe NOW — they are shown once and "
            "each unlocks your account exactly once if the authenticator is lost.",
            class_="muted",
        ),
        el("ul", *items),
        el("p", el("a", "← My account", href="/ui/account")),
        class_="card",
    )
    return page("Recovery codes", body, active="account")


# Nav registration (append-at-tail). Co-located with the builders (ADR 0065 §multi-session-build).
register_nav("account", "/ui/account", "My account")
