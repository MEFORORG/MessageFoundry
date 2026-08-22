# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-vs-code drift guard for ``docs/SECURITY.md``'s authorization documentation.

ASVS 8.1.1 / 8.1.2 / 8.1.3 / 8.1.4 score the **shipped documentation** as the control, so an
incomplete table is the defect itself — and every one of those cells was Partial because a table had
silently fallen behind the code (seven permissions, five Operator grants, 75 routes and one PHI field
were all missing at once). Prose lists are what let that happen; these assertions make the tables
mechanically comparable to the code, in **both** directions, so a new permission / role grant / route /
gate wrapper / PHI property / ingest allow-list that is not documented reds CI instead of drifting.

Most assertions here are derived from the code at test time — the enum, ``BUILTIN_ROLE_PERMISSIONS``,
``PHI_FIELDS``, a live ``create_app()`` route walk (including its ``Mount``s), ``ServiceSettings()``
defaults and a source scan of ``transports/``. The pinned literals are the ones a reviewer must
consciously re-approve: route counts, the un-gated route allow-list, per-model non-PHI field lists,
threshold defaults, the two decision tables' row counts, **and ``_CONTEXTUAL_TOKENS``** — a reviewed
name list, not a derivation. A contextual knob whose name nobody anticipated is caught not by that set
but by ``test_contextual_prefixed_settings_force_a_documented_decision``, which requires every field
matching a curated contextual prefix/suffix to be either documented or explicitly reviewed as a
non-input.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from pydantic import BaseModel

from messagefoundry.api.app import create_app
from messagefoundry.api.field_authz import PHI_FIELDS
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    CUSTOM_ROLE_FORBIDDEN_PERMISSIONS,
    CUSTOM_ROLE_ID_PREFIX,
    Permission,
    Role,
)
from messagefoundry.config.settings import AuthSettings, ServiceSettings
from scripts.security.route_gates import gate_of, route_rows

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "SECURITY.md"

# --- headings the guard slices on (change the doc heading -> change these together) ------------------
_H_DESIGN = "### Authorization design (ASVS 8.1.1)"
_H_CATALOGUE = "### Permission catalogue"
_H_ROLES = "### Built-in roles"
_H_CUSTOM = "### Custom roles (ADR 0045)"
_H_ROUTE_MAP = "### Route → permission map (engine API)"
_H_UI_ROUTE_MAP = "#### The `/ui` console plane (`serve_ui=True`)"
_H_NO_AUTHZ = "#### Functions requiring no authorization"
_H_ENFORCEMENT = "## Enforcement model"
_H_FIELDS = "### Field-level (property) authorization (WP-9)"
_H_CONTEXT = "### Contextual and environmental security inputs (ASVS 8.1.3 / 8.1.4)"

# --- pinned counting basis (see the doc's "Counting basis" paragraph) --------------------------------
# BACKLOG #1184 (ASVS 14.2.1) added three JSON routes -- POST /messages/search, POST /messages/export
# and POST /uploads/{file_id}/messages/search -- and two /ui routes, POST /ui/messages/search/run and
# POST /ui/uploaded-logs/file/{file_id}/filter, so the needle can travel in a body instead of a URL.
_ROUTES_DEFAULT = 108
_ROUTES_WITH_DOCS = 112
_ROUTES_WITH_UI = 208

#: The ``/ui`` routes that legitimately carry no gate: the sign-in, re-auth and second-factor entry
#: points. The three ``/ui/reauth*`` routes authenticate the session cookie MANUALLY — a gate
#: demanding a fresh step-up to perform a step-up would deadlock. ``/ui/mfa`` (ASVS 6.3.3) is the
#: same shape: require_ui 303s every MFA-pending session THERE, so gating it would redirect it to
#: itself. It re-implements the gate's checks by hand, in the gate's order.
_UI_NO_GATE_ROUTES = frozenset(
    {
        ("GET", "/ui/login"),
        ("POST", "/ui/login"),
        ("POST", "/ui/logout"),
        ("GET", "/ui/sso"),
        ("POST", "/ui/csp-report"),
        ("GET", "/ui/reauth"),
        ("POST", "/ui/reauth"),
        ("POST", "/ui/reauth/webauthn"),
        ("GET", "/ui/mfa"),
        ("POST", "/ui/mfa"),
    }
)

#: Every route requiring MORE THAN ONE permission, across both planes. Each fails closed on either.
_MULTI_PERMISSION_ROUTES = frozenset(
    {
        ("GET", "/messages/export"),
        # BACKLOG #1184: the needle-bearing sibling of the export GET. Same two permissions, same
        # fail-closed-on-either behaviour; only the criteria's carrier differs.
        ("POST", "/messages/export"),
        ("GET", "/ui/alerts"),
        # BACKLOG #324: the console editor DISPLAYS the body it edits (textarea + `data-original`),
        # and the POST's reject arm re-ships the pristine stored copy — so both verbs require
        # `messages:view_raw` alongside `messages:edit`.
        ("GET", "/ui/messages/{message_id}/edit"),
        ("POST", "/ui/messages/{message_id}/edit-resend"),
    }
)

#: ``/ui`` routes on plain ``require_ui`` while a JSON route with the same method and the same
#: permission set carries a stronger wrapper. Reviewed and disclosed, one reason each, in the doc's
#: "Behavioural differences from the JSON plane" block.
_UI_WEAKER_THAN_JSON_EQUIVALENT = frozenset(
    {
        ("GET", "/ui/dead-letters"),
        ("GET", "/ui/messages"),
        ("GET", "/ui/messages/{message_id}"),
        ("GET", "/ui/messages/{message_id}/attachments/{attachment_id}"),
        ("GET", "/ui/messages/{message_id}/parse-tree"),
        ("GET", "/ui/uploaded-logs"),
        ("POST", "/ui/connections/{name}/flag"),
        ("POST", "/ui/messages/search/presets/{preset_id}/delete"),
        ("POST", "/ui/uploaded-logs/file/{file_id}/resend"),
        ("POST", "/ui/uploaded-logs/upload"),
    }
)

#: Routes that legitimately require NO permission. 3 unauthenticated + 2 optional_identity (no gate
#: dependency at all) and 13 authenticated self-service routes (a gate with an EMPTY permission tuple).
#: A route losing its permission gate lands here and reds the test.
_NO_GATE_ROUTES = frozenset(
    {
        ("GET", "/auth/providers"),
        ("POST", "/auth/login"),
        ("POST", "/auth/negotiate"),
        ("GET", "/health"),
        ("GET", "/ai/policy"),
    }
)
_PERMISSIONLESS_ROUTES = frozenset(
    {
        ("POST", "/auth/logout"),
        ("GET", "/auth/me"),
        ("POST", "/me/password"),
        ("POST", "/me/reauth"),
        ("POST", "/auth/mfa-verify"),
        ("GET", "/me/mfa"),
        ("POST", "/me/mfa/enroll"),
        ("POST", "/me/mfa/confirm"),
        ("DELETE", "/me/mfa"),
        ("GET", "/me/sessions"),
        ("GET", "/me/security-events"),
        ("DELETE", "/me/sessions/{session_id}"),
        ("DELETE", "/me/sessions"),
    }
)

#: Fields of a PHI_FIELDS-mapped model that are reviewed as carrying no PHI. Adding a field to a mapped
#: model without gating it (or allow-listing it here, deliberately) reds the test — the half the older
#: PHI_FIELDS->model pinning tests structurally cannot do.
_MAPPED_MODEL_NON_PHI_FIELDS: dict[str, frozenset[str]] = {
    "MessageSummary": frozenset(
        {
            "channel_id",
            "control_id",
            "event",
            "id",
            "message_type",
            "received_at",
            "source_type",
            "status",
        }
    ),
    "DeadLetterRow": frozenset(
        {
            "attempts",
            "channel_id",
            "control_id",
            "destination_name",
            "failed_at",
            "message_id",
            "message_type",
            "outbox_id",
            "received_at",
        }
    ),
    "MessageDetail": frozenset(
        {
            "attachments",
            "channel_id",
            "control_id",
            "event",
            "events",
            "id",
            "message_type",
            "outbox",
            # PHI, deliberately NOT per-property: the whole body rides the route's messages:view_raw
            # gate (documented in the doc's whole-body table).
            "raw",
            "received_at",
            "source_type",
            "status",
        }
    ),
    "OutboxInfo": frozenset({"attempts", "destination_name", "id", "next_attempt_at", "status"}),
    "EventInfo": frozenset({"destination", "event", "ts"}),
    "CapturedResponseInfo": frozenset(
        {
            # PHI, gated INLINE at GET /messages/{id}/responses on messages:view_raw, not via the map.
            "body",
            "captured_at",
            "destination_name",
            "outcome",
            "response_seq",
        }
    ),
}

#: Response models reachable on a message-family route that carry no PHI property, each reviewed once.
#: A NEW model on those routes must be either mapped in PHI_FIELDS or added here with a justification —
#: which is the review the fail-open default (an unmapped model is returned in full) makes mandatory.
_NO_PHI_RESPONSE_MODELS: dict[str, str] = {
    "AlertInstanceInfo": (
        "reason is free text PHI.md §2 classifies as POSSIBLY PHI-bearing; deliberately outside the "
        "per-property map — route-gated on monitoring:diagnose (not a PHI permission), scrubbed by "
        "safe_exc() at the emit site and safe_text(reason)[:200] at the store, cipher-encrypted at "
        "rest. A NEW free-text field here must be scrubbed the same way or moved into PHI_FIELDS"
    ),
    "AlertInstanceList": "envelope: alerts + total",
    "AlertRuleInfo": "operator-authored rule name/type/threshold — configuration, not message data",
    "AlertTestEmailResult": (
        "POST /alerts/test-email outcome only: configured/success flags, duration_ms, "
        "recipient_count, and a safe_exc-scrubbed failure detail. The event it sends is SYNTHETIC, so "
        "no message data can reach it, and it deliberately echoes back no email address (not even the "
        "request's recipient_override) — a count, never a recipient"
    ),
    "AlertsConfig": "sink configuration; credentials never returned",
    "AttachmentInfo": "content_type/id/total_bytes — attachment metadata, never bytes",
    "ConnectionEventInfo": (
        "reason is free text PHI.md §2 classifies as POSSIBLY PHI-bearing; same posture as "
        "AlertInstanceInfo.reason — route-gated on monitoring:read, scrubbed at both ends, "
        "cipher-encrypted at rest"
    ),
    "DeadLetterList": "envelope: limit/offset/total + DeadLetterRow rows (mapped)",
    "DeadLetterReplayResult": "requeued count only",
    "EditResendResult": "ids + routing decision, no body",
    "MessageList": "envelope: limit/offset/total + MessageSummary rows (mapped)",
    "MessageResponses": "envelope: message_id + CapturedResponseInfo rows (mapped)",
    "MessageSearchResults": "envelope: counters + MessageSummary rows (mapped)",
    "OutboundPayloadInfo": "payload IS PHI but rides the route's messages:view_raw whole-body gate",
    "OutboundPayloads": "envelope: message_id + OutboundPayloadInfo rows",
    "PendingApprovalResponse": "approval_id/operation/status + a scrubbed operation detail",
    "ReplayResult": "message_id + requeued count",
    "ResendResult": "ids + routing target, no body",
    "SearchPresetCreateResult": "id/name/status",
    "SearchPresetDeleteResult": "id/deleted",
    "SearchPresetInfo": "operator-authored preset name + timestamps",
    "SearchPresetList": "envelope: presets + total",
    "UploadDeleteResult": "file_id/filename/deleted",
    "UploadResendResult": "file_id/index/message_id/status/to",
    "UploadedFileInfo": "file metadata: name/size/sha256/uploader/count — never content",
    "UploadedFileList": (
        "envelope: files + total + scope, the fixed own/any_owner enum saying whose files the count "
        "was taken over (never operator text)"
    ),
    "UploadedMessageSummary": "index/message_type/control_id/size only — no body, no summary",
    "UploadedMessagesResult": "envelope: counters + UploadedMessageSummary rows",
}

#: Contextual/environmental knobs, headers and audit events the 8.1.3/8.1.4 inventory must name.
#:
#: HONEST SCOPE: this is a **reviewed list**, not a derivation. It cannot see a contextual knob whose
#: name nobody anticipated. What DOES back-stop it is
#: ``test_contextual_prefixed_settings_force_a_documented_decision`` below: every settings field whose
#: name matches a curated contextual prefix/suffix must be either in this set or in the explicitly
#: commented ``_CONTEXTUAL_REVIEWED_NON_INPUTS``, so a new knob forces a conscious
#: documented/not-documented decision instead of passing unseen.
_CONTEXTUAL_TOKENS = frozenset(
    {
        # operator-surface network + exposure posture
        "allowed_client_networks",
        "trusted_proxies",
        "public_origin",
        "tls_terminated_upstream",
        "exposure_protected",
        "tls_client_cert_identities",
        "ws_allowed_origins",
        # credential + session attributes
        "login_rate_limit_enabled",
        "login_rate_limit_per_ip",
        "login_rate_limit_global",
        "login_rate_limit_window_seconds",
        "lockout_threshold",
        "lockout_minutes",
        "admin_new_ip_step_up",
        "step_up_max_age_seconds",
        "require_action_step_up",
        "require_mfa",
        "session_idle_timeout_minutes",
        "session_absolute_hours",
        "max_session_hours",
        "oidc_session_max_hours",
        "max_sessions_per_user",
        "phi_read_rate_limit_enabled",
        "phi_read_rate_limit_per_actor",
        "phi_read_rate_limit_window_seconds",
        "phi_read_rate_limit_global",
        "admin_write_rate_limit_per_actor",
        "admin_write_rate_limit_window_seconds",
        "admin_write_rate_limit_enabled",
        "ad_session_recheck_seconds",
        "ad_session_recheck_strikes",
        "ad_session_recheck_max_users",
        "ad_session_revoke_max",
        "ad_session_revoke_max_fraction",
        # federated login-time gates: hard DENY decisions on identity-assertion attributes
        "oidc_require_mfa_claim",
        "oidc_mfa_amr_values",
        "oidc_required_acr_values",
        "oidc_allowed_username_domains",
        "oidc_username_strip_domain",
        # a time attribute x admin-population state that DENIES (disable + revoke + audit)
        "bootstrap_expiry_hours",
        # DATA PLANE — the binding correction: these are pre-auth, IP-keyed ALLOW/DENY decisions too
        "source_ip_allowlist",
        "calling_ae_allowlist",
        "require_called_ae_title",
        "capture_connection_errors",
        "require_calling_aet",
        "require_called_aet",
        # inbound mTLS: a pre-auth, consumer-keyed DENY at the TLS handshake
        "tls_ca_file",
        # the dials that decide whether a "DENY at startup" / hop refusal EXISTS at all
        "enforcement",
        "allow_single_factor_admin_when_exposed",
        "data_class",
        # the federated pending-flow per-IP cap: an IP-keyed refusal of a sign-in leg
        "oidc_flow_cache_max",
        "oidc_flow_ttl_seconds",
        "DEFAULT_PER_IP_CAP",
        # fetch metadata on the federated sign-in legs (distinct header + surface from Sec-Fetch-Site)
        "Sec-Fetch-Mode",
        "non_navigation_fetch",
        # environment posture x claimed AI scope, re-resolved server-side on every /ai/chat
        "derived_posture",
        "data_scope",
        # workflow dual control: operation x requester-vs-approver identity x hold age
        "approvals",
        "expiry_hours",
        # observable outcomes
        "X-MessageFoundry-Denied",
        "client-network",
        "X-Step-Up-Required",
        "X-MFA-Required",
        "X-Step-Up-Action",
        "auth.admin_action_new_ip",
        "auth.ad_session_revoked",
        # the role-drift revocation arm: a PRESENT probe whose mapped roles differ, revoked on a
        # SINGLE pass with no strike accrual (auth/reconcile.py, reason="roles_changed")
        "roles_changed",
        "auth.ad_reconcile_aborted",
        "client_address_monoculture",
        "observed_client",
        "phi_read_hop_disposition",
    }
)

#: (settings section, field, value the doc was written against). The doc row that NAMES the field must
#: contain the value's rendering, and the live default must still equal it — so a default change reds
#: the doc test instead of silently invalidating the decision table.
_PINNED_THRESHOLDS: tuple[tuple[str, str, object, str], ...] = (
    ("auth", "login_rate_limit_per_ip", 10, "10"),
    ("auth", "login_rate_limit_global", 60, "60"),
    ("auth", "login_rate_limit_window_seconds", 60.0, "60 s"),
    ("auth", "lockout_threshold", 5, "5"),
    ("auth", "lockout_minutes", 15, "15 minutes"),
    ("auth", "admin_new_ip_step_up", False, "**off**"),
    ("auth", "step_up_max_age_seconds", 300, "300 s"),
    ("auth", "require_mfa", True, "on"),
    ("auth", "require_action_step_up", True, "on"),
    ("auth", "session_idle_timeout_minutes", 30, "30 min"),
    ("auth", "session_absolute_hours", 12, "12 h"),
    ("auth", "max_sessions_per_user", 5, "5 sessions"),
    ("auth", "phi_read_rate_limit_per_actor", 120, "120 reads"),
    ("auth", "admin_write_rate_limit_per_actor", 12, "12 writes"),
    ("auth", "admin_write_rate_limit_window_seconds", 1.0, "1.0 s"),
    ("auth", "ad_session_recheck_strikes", 2, "**2 consecutive**"),
    ("auth", "ad_session_recheck_max_users", 200, "200 users"),
    ("auth", "ad_session_revoke_max", 5, "**5**"),
    ("auth", "ad_session_revoke_max_fraction", 0.34, "**0.34**"),
    ("auth", "bootstrap_expiry_hours", 72, "72 h"),
    ("auth", "oidc_require_mfa_claim", True, "on"),
    # These three were documented but unpinned — precisely the defaults the trailing lanes plan to
    # move (#297's 8.3.2 route proposes an ADR-0080-style derived ad_session_recheck_seconds), so a
    # change would have made the row false with zero CI signal.
    ("auth", "ad_session_recheck_seconds", 300, "**300 s**"),
    ("auth", "phi_read_rate_limit_global", 0, "`0` = **off**"),
    ("auth", "phi_read_rate_limit_window_seconds", 60.0, "60 s"),
    ("auth", "oidc_flow_cache_max", 512, "**512**"),
    ("auth", "oidc_flow_ttl_seconds", 300, "300 s"),
)

#: Settings-name fragments that make a field a candidate contextual/environmental input. Every field
#: matching one must be in ``_CONTEXTUAL_TOKENS`` or in the reviewed-non-input set below, so a knob
#: with an unanticipated name still forces an explicit decision (8.1.4's completeness axis).
_CONTEXTUAL_NAME_MARKERS = (
    "login_",
    "phi_read_",
    "admin_write_",
    "ad_session_",
    "oidc_",
    "step_up",
    "session_",
    "lockout_",
    "bootstrap_",
    "_allowlist",
    "_networks",
    "_origins",
)

#: Fields matching a contextual marker that are REVIEWED as not being consumer/environment inputs to
#: an access decision. Each is here because it configures HOW a pathway works, not WHETHER a given
#: request is allowed, so it belongs in the settings reference rather than the 8.1.3/8.1.4 tables.
_CONTEXTUAL_REVIEWED_NON_INPUTS = frozenset(
    {
        # OIDC wiring: endpoints, client identity, secrets, discovery and claim-mapping shape.
        "oidc_enabled",
        "oidc_issuer",
        "oidc_client_id",
        "oidc_client_secret",
        "oidc_client_secret_ref",
        "oidc_authorization_endpoint",
        "oidc_token_endpoint",
        "oidc_jwks_uri",
        "oidc_redirect_path",
        "oidc_scopes",
        "oidc_username_claim",
        "oidc_allowed_endpoints",
        "oidc_jwks_ttl_seconds",
        "oidc_jwks_min_refetch_seconds",
        "oidc_clock_skew_seconds",
        # Parameters the engine SENDS on the authorization request. They shape what the IdP does, not
        # what the engine decides about a request it receives.
        "oidc_acr_values",
        "oidc_prompt",
        # Part of the signature-verification ladder / IdP trust plumbing, not a consumer attribute:
        # a token failing these never becomes an identity at all (covered by the amr/acr row).
        "oidc_signing_algorithms",
        "oidc_tls_ca_cert_file",
        # WP #285 (ASVS 6.7.1): the optional SHA-256 integrity pin over the OIDC CA anchor above —
        # an integrity control on trust material, not a consumer/environment access-decision input.
        "oidc_tls_ca_cert_pin",
        # ASVS 6.4.5 arm 2: how long BEFORE the bootstrap deadline to start reminding an operator that
        # the unclaimed first-run credential is about to be retired. Purely the timing of an advisory
        # ALERT — no login, session or authorization outcome turns on it (contrast its sibling
        # `bootstrap_expiry_hours`, which DISABLES the account and is therefore an inventoried input).
        "bootstrap_warn_hours",
        # ASVS 3.7.3: destinations exempted from the "you are leaving this site" interstitial. It
        # decides whether the operator is SHOWN A NOTIFICATION before an outbound navigation — not
        # whether any request is authorized. No login, session, permission or authorization outcome
        # turns on it, and it is never read on an inbound request path at all.
        #
        # ⚠️ It IS a security-relevant setting and it LOWERS security when non-empty, which is why the
        # serve gate warns and names every entry. That makes it a settings-reference concern, not an
        # 8.1.3/8.1.4 contextual-input one — the two are different questions and this list is the
        # place the difference gets recorded rather than assumed.
        "external_link_allowlist",
    }
)

#: Tokens the 8.1.3/8.1.4 section carries in PROSE rather than in a table row, each because it
#: qualifies a whole table rather than describing one attribute. Everything else must be in a ROW —
#: a doc-wide substring search made deleting the `allowed_client_networks`, mTLS, WS-Origin,
#: monoculture, Sec-Fetch, bind-posture and DICOM construction-gate rows completely undetectable,
#: because every one of those tokens also occurs elsewhere in the file.
_CONTEXTUAL_PROSE_ONLY = frozenset(
    {
        # qualifies the whole data-plane table's telemetry footnote
        "capture_connection_errors",
    }
)

#: Body-row counts of the two decision tables. Row-scoping alone cannot catch the deletion of a row
#: whose tokens are shared with a sibling row (Sec-Fetch, bind/exposure, the DICOM construction
#: gate), so the counts are pinned too: removing ANY row reds CI.
_CONTEXT_TABLE_A_ROWS = 35
_CONTEXT_TABLE_B_ROWS = 9

#: The closed action vocabulary the section declares. Every Action cell in BOTH tables must OPEN with
#: exactly one of these — the assertion that turns "no composite risk score" from a phrase the doc
#: asserts about itself into a property of the tables. Five of the old rows failed it: two named no
#: vocabulary word at all, two forked between two words, and one used ``confine``, which was not in
#: the declared set.
_ACTION_VOCABULARY = ("ALLOW", "DENY", "CONFINE", "CHALLENGE", "THROTTLE", "LOG")

#: Transport modules that BUILD an mTLS-capable inbound context (``ssl.CERT_REQUIRED``). The HTTP
#: listener shares ``mllp._mllp_ssl_context`` rather than constructing its own, so it does not appear
#: here; the doc row names all three listeners it covers.
_MTLS_LISTENER_MODULES = frozenset({"dicom", "mllp"})

#: Transport modules that enforce [inbound].source_ip_allowlist, and the label the doc's data-plane
#: table uses for each. Derived from the source at test time; a sixth listener reds the test.
_DATA_PLANE_LABELS = {
    "mllp": "**MLLP**",
    "tcp": "**TCP**",
    "x12": "**X12**",
    "http_listener": "**HTTP**",
    "dicom": "**DICOM C-STORE SCP**",
}

_PERM_RE = re.compile(r"`([a-z_]+:[a-z_]+)`")
_CONST_RE = re.compile(r"`([A-Z][A-Z_]+)`")
_BACKTICK_RE = re.compile(r"`([^`]+)`")


# --- doc parsing -------------------------------------------------------------------------------------


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section(text: str, heading_prefix: str) -> str:
    """The block under the first heading line starting with ``heading_prefix``, up to the next heading
    of the same or a shallower level (so ``####`` sub-blocks stay inside a ``###`` section)."""
    lines = text.splitlines()
    level = len(heading_prefix) - len(heading_prefix.lstrip("#"))
    start = next(
        (i for i, line in enumerate(lines) if line.startswith(heading_prefix)),
        None,
    )
    assert start is not None, (
        f"docs/SECURITY.md no longer has a heading starting {heading_prefix!r}. The authorization "
        "drift guard slices on that heading — update the doc and this guard together."
    )
    out: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("#"):
            depth = len(line) - len(line.lstrip("#"))
            if depth <= level:
                break
        out.append(line)
    return "\n".join(out)


def _tables(block: str) -> list[list[list[str]]]:
    """Every markdown table in ``block`` as a list of rows, each a list of stripped cells. The header
    row is included; the ``|---|`` separator is dropped."""
    tables: list[list[list[str]]] = []
    current: list[list[str]] | None = None
    for raw in block.splitlines():
        line = raw.strip()
        if line.startswith("|") and line.endswith("|") and len(line) > 1:
            cells = [c.strip() for c in line[1:-1].split("|")]
            if cells and all(c and set(c) <= set("-: ") for c in cells):
                continue  # the |---|:--:| separator
            if current is None:
                current = []
            current.append(cells)
        elif current is not None:
            tables.append(current)
            current = None
    if current is not None:
        tables.append(current)
    return tables


def _table_with_header(block: str, first_cell: str) -> list[list[str]]:
    for table in _tables(block):
        if table and table[0] and table[0][0] == first_cell:
            return table
    raise AssertionError(
        f"no markdown table with a leading {first_cell!r} header cell in this section — the drift "
        "guard parses that table; update the doc and the guard together."
    )


# --- route walk (derived from the live app, never hardcoded) -----------------------------------------


# The walk itself lives in scripts/security/route_gates.py — ONE implementation, shared with the DAST
# authorization sweep (ADR 0155). It used to be a private copy here, and two copies of a derivation are
# free to disagree in a way nobody can see: messagefoundry/api/security.py already records a refactor
# that renamed the gate closure's qualname and made EVERY route read as UNGATED. A guard built on this
# walk therefore has a failure mode where it keeps passing while measuring nothing, and with the walk
# duplicated that failure would have had to be found TWICE.
#
# ``_gate_of`` keeps its private name because ``_ui_route_rows`` below reads the ``require_ui*``
# closures with it unchanged.
_gate_of = gate_of


def _route_rows() -> list[tuple[str, str, tuple[str, ...], str | None]]:
    """``(method, path, permissions, gate name)`` for every route object of a default ``create_app()``.
    ``gate name`` is ``None`` when no ``require*()`` dependency was found.

    A thin adapter over the shared :func:`scripts.security.route_gates.route_rows`, which returns
    ``RouteRow`` dataclasses; the tuple shape is what this module's call sites unpack.
    """
    return [(row.method, row.path, row.permissions, row.gate) for row in route_rows()]


# =====================================================================================================
# ASVS 8.1.1 — function-level authorization
# =====================================================================================================


def test_permission_catalogue_matches_the_enum_exactly() -> None:
    """Every ``Permission`` has a catalogue row and every catalogue row is a real ``Permission``.

    RULE: adding a permission means adding its catalogue row in the same change (ASVS 8.1.1) — seven
    permissions were missing when this cell was scored Partial.
    """
    block = _section(_doc_text(), _H_CATALOGUE)
    table = _table_with_header(block, "Constant")
    documented_values = {m for row in table[1:] for m in _PERM_RE.findall(row[1])}
    documented_consts = {m for row in table[1:] for m in _CONST_RE.findall(row[0])}
    assert documented_values == {p.value for p in Permission}, (
        "docs/SECURITY.md's permission catalogue does not match Permission. Missing from the doc: "
        f"{sorted({p.value for p in Permission} - documented_values)}; documented but not a real "
        f"permission: {sorted(documented_values - {p.value for p in Permission})}"
    )
    assert documented_consts == {p.name for p in Permission}, (
        "the catalogue's Constant column does not match the Permission member names: "
        f"{sorted(documented_consts ^ {p.name for p in Permission})}"
    )
    assert len(table) - 1 == len(Permission)


def test_permission_catalogue_heading_states_the_real_size() -> None:
    heading = next(line for line in _doc_text().splitlines() if line.startswith(_H_CATALOGUE))
    assert str(len(Permission)) in heading, (
        f"the catalogue heading {heading!r} no longer states the real catalogue size "
        f"({len(Permission)})."
    )


def test_catalogue_route_counts_match_the_live_route_walk() -> None:
    """The per-permission route count in the catalogue equals what the app actually gates.

    RULE: re-gating a route onto a different permission must be reflected in the doc. A count-only
    total would not catch that; this does.
    """
    block = _section(_doc_text(), _H_CATALOGUE)
    table = _table_with_header(block, "Constant")
    documented: dict[str, int] = {}
    for row in table[1:]:
        value = _PERM_RE.findall(row[1])[0]
        documented[value] = int(row[3])

    derived: dict[str, int] = {p.value: 0 for p in Permission}
    for _method, _path, perms, _gate in _route_rows():
        for perm in perms:
            derived[perm] += 1

    assert documented == derived, (
        "the catalogue's route counts drifted from the live app. Differences (permission: doc -> "
        f"code): { {k: (documented[k], derived[k]) for k in derived if documented.get(k) != derived[k]} }"
    )


def test_role_matrix_matches_builtin_role_permissions() -> None:
    """Each documented role row equals ``BUILTIN_ROLE_PERMISSIONS`` exactly.

    RULE: Administrator is asserted as the WHOLE enum (not a copied list), so a new permission flows
    into it automatically; the other five are asserted set-equal, which is how the Operator row's five
    missing PHI capabilities and the Auditor row's ``audit:export`` were found.
    """
    block = _section(_doc_text(), _H_ROLES)
    table = _table_with_header(block, "Role")
    rows = {row[0].strip("* ").lower(): row for row in table[1:]}
    assert set(rows) == {r.value for r in Role}, (
        f"documented roles {sorted(rows)} != Role members {sorted(r.value for r in Role)}"
    )
    for role in Role:
        row = rows[role.value]
        expected = BUILTIN_ROLE_PERMISSIONS[role]
        assert int(row[1]) == len(expected), (
            f"the {role.value} row claims {row[1]} permissions; the code grants {len(expected)}"
        )
        if role is Role.ADMINISTRATOR:
            assert expected == frozenset(Permission), (
                "Administrator is no longer the whole catalogue — the doc row says it is."
            )
            assert "every permission" in row[2].lower()
            continue
        documented = set(_PERM_RE.findall(row[2]))
        assert documented == {p.value for p in expected}, (
            f"the {role.value} role row drifted. Granted but undocumented: "
            f"{sorted({p.value for p in expected} - documented)}; documented but not granted: "
            f"{sorted(documented - {p.value for p in expected})}"
        )


def test_custom_role_rules_are_documented() -> None:
    block = _section(_doc_text(), _H_CUSTOM)
    assert CUSTOM_ROLE_ID_PREFIX in block, (
        f"the custom-role section must state the {CUSTOM_ROLE_ID_PREFIX!r} id prefix."
    )
    documented = set(_PERM_RE.findall(block))
    forbidden = {p.value for p in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS}
    assert forbidden <= documented, (
        "the custom-role section must name every permission a custom role may never hold; missing: "
        f"{sorted(forbidden - documented)}"
    )
    # And the retired falsehood must not come back.
    assert "no custom-role builder yet" not in _doc_text(), (
        "docs/SECURITY.md claims there is no custom-role builder; ADR 0045 shipped one."
    )


def test_route_count_parity() -> None:
    """The doc's counting basis is pinned to the real app.

    RULE: update the route map and this number together. Built with no arguments so ``expose_docs`` /
    ``serve_ui`` cannot perturb it.
    """
    assert len(create_app().routes) == _ROUTES_DEFAULT, (
        f"create_app() now has {len(create_app().routes)} route objects, not {_ROUTES_DEFAULT}. Add "
        "the new route(s) to docs/SECURITY.md's route -> permission map and update the counting-basis "
        "paragraph and this constant in the same change (ASVS 8.1.1)."
    )
    assert len(create_app(expose_docs=True).routes) == _ROUTES_WITH_DOCS


def test_route_count_parity_with_the_console_mounted() -> None:
    pytest.importorskip("messagefoundry_webconsole")
    assert len(create_app(serve_ui=True).routes) == _ROUTES_WITH_UI, (
        "the /ui plane's route count changed; update docs/SECURITY.md's counting basis and the "
        "'94 routes + one /ui/static mount' statement in the same change."
    )


#: Gate names that appear in the doc but are not the wrapper the introspection reports, because the
#: route documents its enforcement in prose instead (the WS route authorizes inside its body).
_DocRow = tuple[frozenset[str], str | None]


def _json_route_map_block() -> str:
    """The JSON plane's half of the route-map section.

    ``#### The /ui console plane`` is nested inside the ``###`` route-map heading, so its table must
    be cut off here or its rows would compare as "routes the app does not serve".
    """
    block = _section(_doc_text(), _H_ROUTE_MAP)
    cut = block.find(_H_UI_ROUTE_MAP)
    return block if cut < 0 else block[:cut]


def _documented_route_map(block: str) -> dict[tuple[str, str], _DocRow]:
    """``{(method, path): (permissions, gate)}`` parsed from the route-map tables.

    The Permission and Gate cells are located by HEADER NAME, because the sub-tables differ
    (``Method|Path|Permission|Gate[|Extra constraints]``, ``Method|Path|Gate|Extra constraints``,
    ``Method|Path|Why|Compensating control``). A table with no ``Permission`` column contributes an
    empty permission set — which is the truth for the no-authorization sub-table.
    """
    documented: dict[tuple[str, str], _DocRow] = {}
    for table in _tables(block):
        if not table or table[0][0] != "Method":
            continue
        header = table[0]
        perm_col = header.index("Permission") if "Permission" in header else None
        gate_col = header.index("Gate") if "Gate" in header else None
        for row in table[1:]:
            perms = (
                frozenset(_PERM_RE.findall(row[perm_col])) if perm_col is not None else frozenset()
            )
            gate: str | None = None
            if gate_col is not None and gate_col < len(row):
                names = [n for n in _BACKTICK_RE.findall(row[gate_col]) if n.startswith("require")]
                if names:
                    gate = names[0]
                elif "authorize_ws" in row[gate_col]:
                    gate = "authorize_ws"
            for method in _BACKTICK_RE.findall(row[0]):
                for path in _BACKTICK_RE.findall(row[1]):
                    documented[(method, path)] = (perms, gate)
    return documented


def test_every_engine_route_appears_in_the_route_map_with_its_permission_and_gate() -> None:
    """The full row, not just ``(method, path)``.

    RULE: a route that ships without a doc row is the 8.1.1 defect — but so is a row that states the
    WRONG permission or the wrong gate, and the earlier version of this test discarded exactly those
    two cells. Three planted mutations (``PATCH /logging/level`` shown as ``monitoring:read``;
    ``POST /uploads`` shown as ``require``; ``audit:read``/``audit:export`` swapped) all passed. The
    comparison is now over the whole tuple, in both directions.
    """
    documented = _documented_route_map(_json_route_map_block())
    derived = {
        (method, path): (frozenset(perms), gate) for method, path, perms, gate in _route_rows()
    }
    missing = sorted(set(derived) - set(documented))
    assert not missing, (
        "routes missing from docs/SECURITY.md's route -> permission map (ASVS 8.1.1 requires the "
        f"authorization required for EVERY function to be documented): {missing}"
    )
    extra = sorted(set(documented) - set(derived))
    assert not extra, (
        f"docs/SECURITY.md's route map documents routes the app does not serve: {extra}"
    )
    mismatches = _row_mismatches(derived, documented)
    assert not mismatches, (
        "docs/SECURITY.md states the wrong authorization for these routes (permission and/or gate "
        f"disagree with the live app): {mismatches}"
    )


def _row_mismatches(
    derived: dict[tuple[str, str], _DocRow], documented: dict[tuple[str, str], _DocRow]
) -> list[str]:
    """Every route whose documented permission set or gate wrapper disagrees with the live app."""
    out: list[str] = []
    for key, (perms, gate) in sorted(derived.items()):
        if key not in documented:
            continue
        doc_perms, doc_gate = documented[key]
        if doc_perms != perms:
            out.append(
                f"{key[0]} {key[1]}: doc says {sorted(doc_perms)}, code says {sorted(perms)}"
            )
        elif doc_gate != gate:
            out.append(f"{key[0]} {key[1]}: doc gate {doc_gate!r}, code gate {gate!r}")
    return out


def test_route_map_parser_detects_a_planted_permission_mutation() -> None:
    """Proves the comparison above can fail, so a reformat cannot make it silently fail open.

    Mutates one Permission cell and one Gate cell in an IN-MEMORY copy of the section and requires
    the checker to name both routes. Without this the header-keyed parser could stop finding the
    columns and every row would compare as "no permission documented" against… nothing.
    """
    block = _json_route_map_block()
    derived = {
        (method, path): (frozenset(perms), gate) for method, path, perms, gate in _route_rows()
    }
    assert not _row_mismatches(derived, _documented_route_map(block)), "baseline is not clean"
    mutated = block.replace(
        "| `PATCH` | `/logging/level` | `monitoring:diagnose` |",
        "| `PATCH` | `/logging/level` | `monitoring:read` |",
    ).replace(
        "| `POST` | `/uploads` | `files:upload` | `require_step_up` |",
        "| `POST` | `/uploads` | `files:upload` | `require` |",
    )
    assert mutated != block, "the planted mutations did not apply; the fixture rows moved"
    reported = _row_mismatches(derived, _documented_route_map(mutated))
    assert any("/logging/level" in r for r in reported), (
        f"a wrong Permission cell was not detected: {reported}"
    )
    assert any("/uploads:" in r and "gate" in r for r in reported), (
        f"a wrong Gate cell was not detected: {reported}"
    )


def _ui_route_rows() -> list[tuple[str, str, tuple[str, ...], str | None]]:
    """``(method, path, permissions, gate)`` for every ``/ui`` route of ``create_app(serve_ui=True)``.

    ``require_ui*`` factories capture ``permissions`` in the same closure shape as their JSON
    siblings, so ``_gate_of`` reads them unchanged.
    """
    rows: list[tuple[str, str, tuple[str, ...], str | None]] = []
    for route in create_app(serve_ui=True).routes:
        if not isinstance(route, APIRoute) or not route.path.startswith("/ui"):
            continue
        gate: tuple[str, tuple[str, ...], str | None] | None = None
        for dep in route.dependant.dependencies:
            found = _gate_of(dep.call)
            if found is not None:
                gate = found
                break
        for method in sorted(m for m in (route.methods or set()) if m not in ("HEAD", "OPTIONS")):
            rows.append((method, route.path, gate[1] if gate else (), gate[0] if gate else None))
    return rows


def test_every_ui_route_appears_in_the_ui_route_map() -> None:
    """The console plane is 95 of the 200 served functions and the SOLE operator UI in the deployed
    posture, so 8.1.1's "every function" includes it.

    RULE: a ``/ui`` route needs a row stating its permission and its wrapper, in both directions.
    ~20 of them have no JSON counterpart from which the authorization could be inferred.
    """
    pytest.importorskip("messagefoundry_webconsole")
    documented = _documented_route_map(_section(_doc_text(), _H_UI_ROUTE_MAP))
    derived = {
        (method, path): (frozenset(perms), gate)
        for method, path, perms, gate in _ui_route_rows()
        if gate is not None
    }
    missing = sorted(set(derived) - set(documented))
    assert not missing, f"/ui routes with no row in the /ui route -> permission map: {missing}"
    extra = sorted(set(documented) - set(derived))
    assert not extra, f"the /ui route map documents routes the console does not serve: {extra}"
    mismatches = _row_mismatches(derived, documented)
    assert not mismatches, f"the /ui route map states the wrong authorization: {mismatches}"


def test_ungated_ui_routes_are_exactly_the_reviewed_allowlist() -> None:
    """Mirrors the JSON plane's allow-list: a ``/ui`` route losing its gate must red CI."""
    pytest.importorskip("messagefoundry_webconsole")
    ungated = {(m, p) for m, p, _perms, gate in _ui_route_rows() if gate is None}
    assert ungated == _UI_NO_GATE_ROUTES, (
        f"the un-gated /ui route set changed: {sorted(ungated ^ _UI_NO_GATE_ROUTES)}. These are the "
        "sign-in and re-auth entry points; anything else here is a console route that lost its gate."
    )
    block = _section(_doc_text(), _H_UI_ROUTE_MAP)
    assert f"**Unauthenticated `/ui` routes ({len(ungated)}).**" in block, (
        f"the /ui section must state the un-gated count ({len(ungated)})"
    )


def test_multi_permission_routes_are_exactly_the_documented_set() -> None:
    """A third two-permission route cannot appear silently.

    The doc named ``GET /messages/export`` "the only two-permission route" while ``GET /ui/alerts``
    required both ``monitoring:read`` and ``monitoring:diagnose``.
    """
    pytest.importorskip("messagefoundry_webconsole")
    multi = {
        (method, path)
        for method, path, perms, _gate in [*_route_rows(), *_ui_route_rows()]
        if len(perms) > 1
    }
    assert multi == _MULTI_PERMISSION_ROUTES, (
        f"the multi-permission route set changed: {sorted(multi ^ _MULTI_PERMISSION_ROUTES)}. Each "
        "one needs a row naming BOTH permissions and a note that it fails closed on either."
    )
    text = _doc_text()
    # BACKLOG #1184 gave export a needle-bearing POST sibling, so "the ONLY two-permission route"
    # became false the moment that route landed. The set above is the real guard; this pins that the
    # prose claim stays SCOPED to the JSON plane rather than reading as a whole-app enumeration.
    assert "the two-permission routes **on the JSON plane**" in text, (
        "the export rows' exhaustiveness claim must be scoped to the JSON plane"
    )


def test_ui_gate_divergences_are_exactly_the_reviewed_set() -> None:
    """The console routes that are WEAKER than a permission-equivalent JSON route.

    RULE: a new divergence must red CI, and must be disclosed. Derived structurally — a ``/ui`` route
    on plain ``require_ui`` is flagged when ANY JSON route with the same method and the same
    permission set carries ``require_step_up`` / ``require_step_up_action`` / ``require_phi_read`` —
    rather than by path arithmetic, because ``/ui/uploaded-logs`` does not sit under ``/uploads``, so
    a prefix rule would have missed the two upload/resend routes that lose their step-up.
    """
    pytest.importorskip("messagefoundry_webconsole")
    stronger = {"require_step_up", "require_step_up_action", "require_phi_read"}
    json_rows = [(m, frozenset(perms), g) for m, _p, perms, g in _route_rows()]
    diverged: set[tuple[str, str]] = set()
    for method, path, perms, gate in _ui_route_rows():
        if gate != "require_ui" or not perms:
            continue
        if any(
            jm == method and jperms == frozenset(perms) and jg in stronger
            for jm, jperms, jg in json_rows
        ):
            diverged.add((method, path))
    assert diverged == _UI_WEAKER_THAN_JSON_EQUIVALENT, (
        f"the /ui-vs-JSON gate divergence set changed: "
        f"{sorted(diverged ^ _UI_WEAKER_THAN_JSON_EQUIVALENT)}. Every divergence must be listed in "
        "the /ui plane's 'Behavioural differences' block with the reason it is accepted."
    )
    block = _section(_doc_text(), _H_UI_ROUTE_MAP)
    differences = block[block.index("**Behavioural differences from the JSON plane**") :]
    # Tokens may be written bare (`/ui/messages`) or method-qualified (`GET /ui/messages`), so match
    # on the token's tail rather than on one spelling — and on WHOLE tokens, so `/ui/messages` is not
    # satisfied by `/ui/messages/{message_id}`.
    named = {t.split(" ")[-1] for t in _BACKTICK_RE.findall(differences)}
    for _method, path in sorted(diverged):
        assert path in named, (
            f"{path} is weaker than a permission-equivalent JSON route and is not disclosed in the "
            "behavioural-differences block"
        )


def test_ui_plane_states_the_phi_read_hop_gap() -> None:
    """``enforce_phi_read_hop`` has no console call site, so the ADR 0092 refusal does not apply to
    the ``/ui`` browse routes. Asserted both ways, so the disclosure is removed when parity lands."""
    pytest.importorskip("messagefoundry_webconsole")
    console = _ROOT / "messagefoundry_webconsole"
    charges = any(
        "enforce_phi_read_hop" in module.read_text(encoding="utf-8")
        for module in console.rglob("*.py")
    )
    block = _section(_doc_text(), _H_UI_ROUTE_MAP)
    stated = "does not apply on the `/ui` browse routes" in block
    if charges:
        assert not stated, (
            "the console now applies enforce_phi_read_hop; remove the disclosure in the same change."
        )
    else:
        assert stated, (
            "enforce_phi_read_hop appears nowhere in messagefoundry_webconsole, so the /ui PHI browse "
            "routes get the per-actor budget but not the posture-keyed refusal. Say so."
        )


def test_control_plane_mtls_handshake_gate_has_its_own_table_a_row() -> None:
    """The operator listener's own mTLS requirement, derived from the code that creates it.

    A row-count pin alone cannot protect this row, and neither can a token check: the section already
    names ``tls_client_ca_file`` in the subject-mapping row's Knob cell, so a doc-wide substring search
    passes with the handshake row deleted. The gate is therefore derived from ``api/tls.py`` and the
    row is located by the pair of tokens only it carries.

    Why it belongs in Table A at all: it is a pre-auth, consumer-keyed DENY on the CONTROL plane —
    the request never reaches the ASGI stack — and the section claims to inventory every such input on
    both planes, while Table B already gives the identical data-plane gate its own row.
    """
    tls_src = (_ROOT / "messagefoundry" / "api" / "tls.py").read_text(encoding="utf-8")
    assert "CERT_REQUIRED" in tls_src and "tls_client_ca_file" in tls_src, (
        "api/tls.py no longer requires a client certificate when [api].tls_client_ca_file is set. "
        "If the control-plane mTLS gate is gone, remove its Table A row in the same change."
    )
    rows_a, _rows_b = _contextual_table_rows()
    hits = [
        r for r in rows_a if "tls_client_ca_file" in " ".join(r) and "CERT_REQUIRED" in " ".join(r)
    ]
    assert len(hits) == 1, (
        "docs/SECURITY.md's Table A must carry exactly one row for the operator-listener peer "
        "client-certificate handshake gate, naming both [api].tls_client_ca_file and CERT_REQUIRED. "
        f"Found {len(hits)}. api/tls.py sets ssl.CERT_REQUIRED there, so a DENY happens before any "
        "middleware, route or identity resolution — an un-inventoried pre-auth decision otherwise."
    )


def test_ad_role_drift_revocation_has_its_own_table_a_row() -> None:
    """The AD reconciliation produces THREE outcomes, so the section's own rule makes it three rows.

    ``reconcile.py`` revokes on a second, distinct predicate: a PRESENT (resolvable) probe whose
    AD-group-mapped role set differs from the account's current roles is revoked on a **single** pass
    with **no** strike accrual. Documenting only the absence/strike arm tells a reader an AD demotion
    takes two passes when it takes one.
    """
    src = (_ROOT / "messagefoundry" / "auth" / "reconcile.py").read_text(encoding="utf-8")
    assert 'reason="roles_changed"' in src, (
        "auth/reconcile.py no longer revokes on role drift. If that arm is gone, remove its Table A "
        "row and restore the two-row wording in the same change."
    )
    rows_a, _rows_b = _contextual_table_rows()
    hits = [r for r in rows_a if "roles_changed" in " ".join(r)]
    assert len(hits) == 1, (
        f"docs/SECURITY.md's Table A must carry exactly one role-drift row (reason=roles_changed); "
        f"found {len(hits)}."
    )
    row = " ".join(hits[0])
    assert "single" in row.lower() and "no" in row.lower(), (
        "the role-drift row must say it fires on a SINGLE pass with NO strike accrual — that is the "
        "whole difference from the probe-strike row above it."
    )
    text = _doc_text()
    assert "the AD reconciliation three" in text, (
        "the vocabulary preamble still says the AD reconciliation occupies two rows."
    )


def test_ungated_routes_are_exactly_the_reviewed_allowlist() -> None:
    """The 18 routes that require no permission are the reviewed set, and nothing else.

    RULE: a route losing its permission gate must red CI, not silently join the 'no authorization
    required' list the requirement equally demands be documented.
    """
    rows = _route_rows()
    no_gate = {(m, p) for m, p, _perms, gate in rows if gate is None}
    permissionless = {(m, p) for m, p, perms, gate in rows if gate is not None and not perms}
    assert no_gate == _NO_GATE_ROUTES, (
        f"routes with no require*() dependency changed: {sorted(no_gate ^ _NO_GATE_ROUTES)}"
    )
    assert permissionless == _PERMISSIONLESS_ROUTES, (
        "authenticated-but-permissionless routes changed: "
        f"{sorted(permissionless ^ _PERMISSIONLESS_ROUTES)}"
    )
    gated = [r for r in rows if r[2]]
    assert len(gated) == len(rows) - len(no_gate) - len(permissionless)
    # 87 -> 90: BACKLOG #1184's three needle-bearing POSTs, each gated exactly as its GET sibling.
    assert len(gated) == 90, (
        f"{len(gated)} permission-gated routes, not 90 — update the doc's totals."
    )


def _login_limiter_charged_routes() -> set[tuple[str, str]]:
    """``{(METHOD, path)}`` for engine routes whose handler charges ``allow_login_attempt``.

    Read from the source of ``api/auth_routes.py``, so the Enforcement-model summary's
    "bounded by the login limiter instead" claim is checked against the code rather than against
    itself.
    """
    tree = ast.parse((_ROOT / "messagefoundry" / "api" / "auth_routes.py").read_text("utf-8"))
    charged: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        decorators = [
            deco
            for deco in node.decorator_list
            if isinstance(deco, ast.Call)
            and isinstance(deco.func, ast.Attribute)
            and deco.func.attr in {"get", "post", "put", "patch", "delete"}
            and deco.args
            and isinstance(deco.args[0], ast.Constant)
        ]
        if not decorators:
            continue
        calls = {
            sub.func.attr
            for sub in ast.walk(node)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
        }
        if "allow_login_attempt" in calls:
            deco = decorators[0]
            assert isinstance(deco.func, ast.Attribute)
            assert isinstance(deco.args[0], ast.Constant)
            charged.add((deco.func.attr.upper(), str(deco.args[0].value)))
    return charged


def test_enforcement_summary_agrees_with_the_no_authorization_table() -> None:
    """The summary of the unauthenticated routes must not contradict the table that enumerates them.

    RULE (8.1.1): a compensating-control claim about a function requiring no authorization is exactly
    the axis the no-authorization table exists to document. The summary said all three deliberately
    unauthenticated routes were "bounded by the login limiter instead" — while its own table said, of
    ``GET /auth/providers``, "login sliding window is **not** charged here". Both sides are now
    derived from the call sites.
    """
    charged = _login_limiter_charged_routes()
    assert charged, "no auth route charges allow_login_attempt any more"
    text = _doc_text()
    table = _table_with_header(_section(text, _H_NO_AUTHZ), "Method")
    unauthenticated = {
        (row[0].strip("`"), row[1].strip("`")): row[3]
        for row in table[1:]
        if len(row) >= 4 and row[1].strip("`").startswith("/auth")
    }
    assert unauthenticated, "the 'Functions requiring no authorization' table lost its /auth rows"
    for route, compensating in sorted(unauthenticated.items()):
        claims_limiter = "sliding window" in compensating and "not** charged" not in compensating
        assert claims_limiter == (route in charged), (
            f"{route[0]} {route[1]} charges allow_login_attempt = {route in charged}, but its "
            f"compensating-control cell reads {compensating!r}. The Enforcement-model summary and "
            "this table must state the same thing."
        )
    summary = _section(text, _H_ENFORCEMENT)
    unlimited = sorted(route for route in unauthenticated if route not in charged)
    assert unlimited, (
        "every deliberately unauthenticated /auth route now charges the login limiter; the "
        "Enforcement-model paragraph's carve-out is stale — simplify it in the same change."
    )
    for _method, path in unlimited:
        assert f"`GET {path}`" in summary, f"{path} is not named in the Enforcement-model summary"
        assert "charges **no** limiter" in summary, (
            f"{path} is unauthenticated AND charges no limiter; the Enforcement-model paragraph "
            "must not fold it into 'bounded by the login limiter instead'."
        )


def test_static_mount_is_the_only_mount_and_its_posture_is_documented() -> None:
    """A served path with no gate at all is still a function 8.1.1 requires an authorization rule for.

    ``/ui/static`` is a ``StaticFiles`` mount, not an ``APIRoute``, so every route-walking assertion
    in this module is blind to it. It answers 200 with no session in the same app where ``GET /ui``
    answers 503. Deriving the mount set means a SECOND mount — one that might carry PHI — cannot ship
    without its own documented rule.
    """
    from starlette.routing import Mount

    mounts = {route.path for route in create_app(serve_ui=True).routes if isinstance(route, Mount)}
    assert mounts == {"/ui/static"}, (
        f"the app's mount set changed: {sorted(mounts)}. A mount is a served path with no "
        "require*() dependency — state its authorization rule in docs/SECURITY.md's /ui plane "
        "section and update this guard in the same change (ASVS 8.1.1)."
    )
    ui_block = _section(_doc_text(), _H_UI_ROUTE_MAP)
    assert "/ui/static" in ui_block, (
        "the /ui plane section must classify the /ui/static mount — it is the one served path whose "
        "authorization posture the inventory never stated."
    )
    lowered = " ".join(ui_block.replace("*", " ").lower().split())
    assert "no gate whatsoever" in lowered or "no gate at all" in lowered, (
        "the /ui/static mount must be stated as requiring no authentication and no authorization, "
        "not merely counted."
    )


def test_gate_wrapper_preamble_matches_the_table_it_introduces() -> None:
    """The prose above the gate table said "seven wrappers build on that ladder (six table rows)"
    over a table with SEVEN data rows — and ``require_service_cert`` does not build on the ladder at
    all, it deliberately bypasses it."""
    block = _section(_doc_text(), _H_DESIGN)
    table = _table_with_header(block, "Gate wrapper")
    rows = len(table) - 1
    assert rows == 7, f"the gate-wrapper table now has {rows} rows; restate the preamble"
    assert (
        f"The table below has **{['', 'one', 'two', 'three', 'four', 'five', 'six', 'seven'][rows]}** rows"
        in block
    ), f"the gate-wrapper preamble must state the real row count ({rows})"
    assert "deliberately\n**bypasses**" in block or "deliberately **bypasses**" in block, (
        "require_service_cert does not build on require()'s ladder — its own docstring says none of "
        "require's session concerns apply. The preamble must not count it among the wrappers that do."
    )


def test_operator_phi_capability_count_is_derived_from_the_catalogue() -> None:
    """The "five PHI-bearing capabilities" sentence must be assembled from the catalogue's own PHI
    column, not by hand: it previously counted ``files:delete`` (PHI column EMPTY — it destroys PHI,
    it does not emit it) and omitted ``messages:edit`` (PHI-marked, and it renders the raw body)."""
    catalogue = _table_with_header(_section(_doc_text(), _H_CATALOGUE), "Constant")
    header = catalogue[0]
    phi_col = header.index("PHI")
    perm_col = header.index("Permission")
    phi_marked = {
        row[perm_col].strip("`") for row in catalogue[1:] if "PHI" in row[phi_col].upper()
    }
    assert phi_marked, "the permission catalogue lost its PHI column markings"
    operator = {p.value for p in BUILTIN_ROLE_PERMISSIONS[Role.OPERATOR]}
    baseline = {"messages:view_summary", "messages:view_raw"}
    beyond = sorted((phi_marked & operator) - baseline)
    words = {3: "three", 4: "four", 5: "five", 6: "six", 7: "seven"}
    word = words.get(len(beyond))
    assert word is not None, f"add {len(beyond)} to the count words"
    text = _doc_text()
    assert f"**{word} PHI-marked capabilities beyond viewing one message**" in text, (
        f"the Operator's PHI-marked grants beyond viewing one message are {beyond} ({len(beyond)}); "
        "the sentence under the built-in roles table must state that count."
    )
    for permission in beyond:
        assert f"`{permission}`" in text, (
            f"{permission} is a PHI-marked Operator grant but the sentence does not name it"
        )
    assert "`files:delete` is **not** in that count" in text, (
        "files:delete has an EMPTY PHI column; the sentence must say why it is excluded, so the "
        "count cannot be re-assembled by hand next time."
    )


def test_gate_wrapper_table_counts_match_the_route_walk() -> None:
    """The doc's "what each gate ADDS" table lists every wrapper in use, with its real route count."""
    block = _section(_doc_text(), _H_DESIGN)
    table = _table_with_header(block, "Gate wrapper")
    documented: dict[str, int] = {}
    for row in table[1:]:
        names = _BACKTICK_RE.findall(row[0])
        counts = [int(part) for part in re.findall(r"\d+", row[1])]
        assert len(names) == len(counts), f"cannot pair gate names {names} with counts {counts}"
        documented.update(dict(zip(names, counts, strict=True)))

    derived: dict[str, int] = {}
    for _m, _p, _perms, gate in _route_rows():
        if gate is not None:
            derived[gate] = derived.get(gate, 0) + 1
    derived.pop("authorize_ws", None)  # described in prose beneath the table, not as a row

    assert documented == derived, (
        "the gate-wrapper table drifted from the live app (gate: doc -> code): "
        f"{ {k: (documented.get(k), derived.get(k)) for k in set(documented) | set(derived) if documented.get(k) != derived.get(k)} }"
    )


# =====================================================================================================
# ASVS 8.1.2 — data-/field-level authorization
# =====================================================================================================


def _doc_field_triples(text: str) -> set[tuple[str, str, str]]:
    """``(response object, property, permission)`` triples parsed from the field-level read table."""
    block = _section(text, _H_FIELDS)
    table = _table_with_header(block, "Response object")
    triples: set[tuple[str, str, str]] = set()
    for row in table[1:]:
        model = _BACKTICK_RE.findall(row[0])[0]
        prop = _BACKTICK_RE.findall(row[1])[0]
        perm = _PERM_RE.findall(row[3])[0]
        triples.add((model, prop, perm))
    return triples


def test_field_level_table_equals_phi_fields_in_both_directions() -> None:
    """The read table is set-EQUAL to ``PHI_FIELDS``, permission literal included.

    RULE: equality, never subset — a subset check is exactly how the ``metadata`` rows went missing.
    """
    derived = {
        (cls.__name__, prop, perm.value)
        for cls, props in PHI_FIELDS.items()
        for prop, perm in props.items()
    }
    documented = _doc_field_triples(_doc_text())
    assert documented == derived, (
        "docs/SECURITY.md's field-level table does not match api/field_authz.PHI_FIELDS. Gated in "
        f"code but undocumented: {sorted(derived - documented)}; documented but not gated: "
        f"{sorted(documented - derived)}"
    )
    assert len(documented) == 11, f"{len(documented)} (object, property) rows, expected 11"


def test_field_level_table_parser_detects_a_planted_omission() -> None:
    """Self-test: if the table markup is reformatted so rows stop parsing, this guard must not silently
    pass. Deleting one row from an in-memory copy of the doc must be reported."""
    text = _doc_text()
    dropped = "| `MessageSummary` | `metadata` |"
    assert dropped in text, "the planted-omission self-test anchors on the metadata row"
    mutilated = "\n".join(line for line in text.splitlines() if not line.startswith(dropped))
    remaining = _doc_field_triples(mutilated)
    assert ("MessageSummary", "metadata", Permission.MESSAGES_VIEW_SUMMARY.value) not in remaining
    assert len(remaining) == 10, (
        "the parser did not notice a deleted row — it is not actually parsing"
    )


def test_mapped_models_have_no_ungated_field_outside_the_reviewed_list() -> None:
    """Adding a field to an ALREADY-mapped model forces a review.

    RULE: the older PHI_FIELDS -> model pinning tests iterate the MAP, so a new PHI field on a mapped
    model passes them. This iterates the MODEL.
    """
    for cls, props in PHI_FIELDS.items():
        ungated = set(cls.model_fields) - set(props)
        assert cls.__name__ in _MAPPED_MODEL_NON_PHI_FIELDS, (
            f"{cls.__name__} is mapped but has no reviewed non-PHI field list"
        )
        reviewed = _MAPPED_MODEL_NON_PHI_FIELDS[cls.__name__]
        assert ungated == set(reviewed), (
            f"{cls.__name__} gained/lost an ungated field: {sorted(ungated ^ set(reviewed))}. Either "
            "gate it in PHI_FIELDS (and document the row) or add it to the reviewed list here."
        )


def test_message_family_response_models_are_mapped_or_reviewed_as_phi_free() -> None:
    """A NEW response model on a message-family route must be mapped or explicitly reviewed.

    RULE: an unmapped model FAILS OPEN — ``redact_unauthorized`` returns it untouched and
    ``count_exposed`` scores it 0 — so it is both un-redacted and invisible to the exposure census.
    """
    import typing

    # /events and /alerts are in scope because ConnectionEventInfo.reason and AlertInstanceInfo.reason
    # are free-text diagnostic fragments PHI.md §2 classifies as *possibly* PHI-bearing. They stay
    # outside PHI_FIELDS (route-gated on monitoring:* + scrubbed at both ends), but a NEW un-scrubbed
    # field on either model must red CI rather than be invisible.
    families = ("/messages", "/dead-letters", "/search", "/uploads", "/events", "/alerts")
    seen: set[type[BaseModel]] = set()

    def walk(annotation: object) -> None:
        origin = typing.get_origin(annotation)
        if origin is not None:
            for arg in typing.get_args(annotation):
                walk(arg)
            return
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen:
                return
            seen.add(annotation)
            for field in annotation.model_fields.values():
                walk(field.annotation)

    for route in create_app().routes:
        if isinstance(route, APIRoute) and any(route.path.startswith(f) for f in families):
            walk(route.response_model)

    unreviewed = {
        cls.__name__
        for cls in seen
        if cls not in PHI_FIELDS and cls.__name__ not in _NO_PHI_RESPONSE_MODELS
    }
    assert not unreviewed, (
        f"response model(s) {sorted(unreviewed)} are reachable on a message-family route but are "
        "neither declared in PHI_FIELDS nor listed in this test's reviewed no-PHI allow-list. An "
        "unmapped model is returned in FULL and is invisible to the PHI-exposure census — declare it "
        "or justify it here."
    )
    stale = set(_NO_PHI_RESPONSE_MODELS) - {cls.__name__ for cls in seen}
    assert not stale, f"the reviewed no-PHI allow-list has stale entries: {sorted(stale)}"


# =====================================================================================================
# ASVS 8.1.3 / 8.1.4 — contextual and risk-based authorization
# =====================================================================================================


def _contextual_table_rows() -> tuple[list[list[str]], list[list[str]]]:
    """``(Table A body rows, Table B body rows)`` of the 8.1.3/8.1.4 section."""
    tables = _tables(_section(_doc_text(), _H_CONTEXT))
    table_a = next(t for t in tables if t[0][0] == "Attribute")
    table_b = next(t for t in tables if t[0][0] == "Listener")
    return table_a[1:], table_b[1:]


def test_contextual_inventory_names_every_tracked_input_in_a_table_row() -> None:
    """Every contextual knob / header / audit event appears in a ROW of the 8.1.3/8.1.4 tables.

    RULE: a new contextual input must land in the inventory **as a row**, with its attribute,
    threshold and action — that is what the requirement asks for.

    This used to search the whole document, which made it theatre: ``allowed_client_networks`` (×7),
    ``client_address_monoculture``, ``tls_client_cert_identities``, ``ws_allowed_origins`` and
    ``public_origin`` all occur elsewhere in SECURITY.md, so deleting their rows — including the
    ``[security].allowed_client_networks`` row the assessment residual names — left every guard
    green.
    """
    rows_a, rows_b = _contextual_table_rows()
    rows = "\n".join(" ".join(row) for row in [*rows_a, *rows_b])
    missing = sorted(
        token for token in _CONTEXTUAL_TOKENS - _CONTEXTUAL_PROSE_ONLY if token not in rows
    )
    assert not missing, (
        f"these contextual inputs have no ROW in the 8.1.3/8.1.4 decision tables: {missing}. A "
        "mention elsewhere in docs/SECURITY.md does not document the attribute, threshold and action."
    )
    block = _section(_doc_text(), _H_CONTEXT)
    prose_missing = sorted(token for token in _CONTEXTUAL_PROSE_ONLY if token not in block)
    assert not prose_missing, (
        f"prose-only contextual tokens absent from the 8.1.3/8.1.4 section: {prose_missing}"
    )


def test_contextual_decision_tables_keep_every_row() -> None:
    """Row-count pins, because row-scoping alone cannot see the loss of a row whose tokens are
    shared with a sibling (Sec-Fetch, bind/exposure, the DICOM construction gate).

    RULE: removing ANY row from either decision table reds CI.
    """
    rows_a, rows_b = _contextual_table_rows()
    assert len(rows_a) == _CONTEXT_TABLE_A_ROWS, (
        f"Table A (control plane) now has {len(rows_a)} rows, not {_CONTEXT_TABLE_A_ROWS}. A removed "
        "row is an un-inventoried contextual input; a new one needs its attribute/threshold/action "
        "and this constant updated together."
    )
    assert len(rows_b) == _CONTEXT_TABLE_B_ROWS, (
        f"Table B (data plane) now has {len(rows_b)} rows, not {_CONTEXT_TABLE_B_ROWS}."
    )


def test_contextual_row_guard_detects_a_planted_deletion() -> None:
    """Proves the two guards above can fail — the earlier doc-wide search could not.

    Deletes the ``Client source network`` row (the exact attribute the assessment residual names)
    from an
    in-memory copy and requires the row-scoped token check to notice.
    """
    rows_a, rows_b = _contextual_table_rows()
    victim = [r for r in rows_a if r[0].startswith("Client source network")]
    assert len(victim) == 1, "fixture drifted: the client-source-network row moved"
    mutated = [r for r in rows_a if r is not victim[0]]
    assert len(mutated) == len(rows_a) - 1
    text = "\n".join(" ".join(row) for row in [*mutated, *rows_b])
    still_missing = sorted(
        token for token in _CONTEXTUAL_TOKENS - _CONTEXTUAL_PROSE_ONLY if token not in text
    )
    assert "allowed_client_networks" in still_missing, (
        "deleting the client-source-network row must be detected; the row-scoped checker reported "
        f"{still_missing}"
    )


def test_data_plane_mtls_listeners_are_derived_from_the_transports() -> None:
    """The inbound mTLS peer-certificate gate is a Table B row, and its listener set is derived.

    RULE: a transport gaining ``ssl.CERT_REQUIRED`` on its listener is a new pre-auth,
    consumer-keyed DENY on the data plane and needs the row updated.
    """
    transports = _ROOT / "messagefoundry" / "transports"
    capable = {
        path.stem
        for path in sorted(transports.glob("*.py"))
        if "CERT_REQUIRED" in path.read_text(encoding="utf-8")
    }
    assert capable == _MTLS_LISTENER_MODULES, (
        f"the transports building an mTLS-capable context changed: "
        f"{sorted(capable ^ _MTLS_LISTENER_MODULES)}. Update Table B's peer-client-certificate row."
    )
    _rows_a, rows_b = _contextual_table_rows()
    row = [r for r in rows_b if "peer client certificate" in " ".join(r).lower()]
    assert row, "Table B has no inbound mTLS peer-certificate row"
    joined = " ".join(row[0])
    assert "CERT_REQUIRED" in joined and "tls_ca_file" in joined, (
        "the mTLS data-plane row must name the verify mode and the setting that turns it on"
    )
    assert "never reaches the accept path" in joined, (
        "the row must state that the refusal happens at the TLS handshake, before the accept path — "
        "which is why there is no connection event for it"
    )


def test_connection_event_capture_defaults_to_on() -> None:
    """The "Telemetry honesty" note said `capture_connection_errors` defaults to **false** and that
    every allow-list refusal is log-only. It is ``bool | None = None`` and inherits
    ``[diagnostics].connection_events``, which is ``True`` — so MLLP/TCP/HTTP refusals DO write a
    durable row on a default deployment. Pinned so the default can never silently invert again."""
    from messagefoundry.config.wiring import InboundConnection

    field = InboundConnection.__dataclass_fields__["capture_connection_errors"]
    assert field.default is None, (
        "capture_connection_errors is no longer inherit-by-default; the telemetry note is stale."
    )
    assert ServiceSettings().diagnostics.connection_events is True, (
        "[diagnostics].connection_events no longer defaults on; the telemetry note is stale."
    )
    block = _section(_doc_text(), _H_CONTEXT)
    assert "which it is by default" in block and "connection_events" in block, (
        "the telemetry note must state that an unset capture_connection_errors INHERITS the "
        "[diagnostics].connection_events master switch, which is on by default."
    )
    assert "**default false**" not in block, "the retired 'default false' claim is back"


def test_every_rate_limit_setting_is_documented() -> None:
    """Derived from ``AuthSettings`` — a fourth limiter added later without a doc row reds CI."""
    text = _doc_text()
    fields = [name for name in AuthSettings.model_fields if "_rate_limit_" in name]
    assert len(fields) >= 11, "expected at least the three limiters' 4+4+3 settings"
    missing = sorted(name for name in fields if name not in text)
    assert not missing, f"rate-limit settings absent from docs/SECURITY.md: {missing}"


def test_contextual_thresholds_match_the_shipped_defaults() -> None:
    """Each documented threshold literal sits in the row that names its setting, and the live default
    still equals the value the doc was written against."""
    settings = ServiceSettings()
    block = _section(_doc_text(), _H_CONTEXT)
    rows = [row for table in _tables(block) for row in table]
    for section, field, pinned, rendered in _PINNED_THRESHOLDS:
        live = getattr(getattr(settings, section), field)
        assert live == pinned, (
            f"[{section}].{field} now defaults to {live!r}, not {pinned!r}. Update the 8.1.3/8.1.4 "
            "decision table and this pin in the same change."
        )
        naming = [row for row in rows if any(field in cell for cell in row)]
        assert naming, f"no row in the contextual section names [{section}].{field}"
        assert any(rendered in " ".join(row) for row in naming), (
            f"the contextual row naming [{section}].{field} does not state its default {rendered!r}"
        )


def test_data_plane_allowlist_listeners_match_the_transports() -> None:
    """The listeners that enforce ``[inbound].source_ip_allowlist`` are derived from the transport
    sources, and each has a data-plane row.

    RULE (binding correction): 8.1.3/8.1.4's inventory must cover the DATA plane. A sixth listener
    gaining the allow-list without a doc row reds CI.
    """
    transports = _ROOT / "messagefoundry" / "transports"
    enforcing = {
        path.stem
        for path in sorted(transports.glob("*.py"))
        if "peer_ip_allowed(" in path.read_text(encoding="utf-8")
    }
    assert enforcing == set(_DATA_PLANE_LABELS), (
        "the set of transports enforcing [inbound].source_ip_allowlist changed: "
        f"{sorted(enforcing ^ set(_DATA_PLANE_LABELS))}. Add/remove its row in docs/SECURITY.md's "
        "data-plane decision table and update this guard in the same change."
    )
    block = _section(_doc_text(), _H_CONTEXT)
    for module, label in _DATA_PLANE_LABELS.items():
        assert label in block, (
            f"the data-plane table has no row for {module} ({label}) — the 8.1.3 binding correction "
            "requires every ingest listener enforcing the allow-list to be tabulated."
        )


def test_contextual_section_does_not_repeat_the_retired_falsehood() -> None:
    """``allowed_client_networks`` is NOT the only pre-auth source-address ALLOW/DENY input — five
    ingest listeners take the same kind of decision. A doc repeating that claim re-opens 8.1.3."""
    text = _doc_text()
    assert "only pre-auth source-address" not in text
    block = _section(text, _H_CONTEXT)
    assert "inert" in block.lower(), (
        "the operator-surface network gate's undeclared-proxy (R3) inertness must be stated; it must "
        "never be documented as if it closes that case."
    )


def test_risk_grading_model_is_stated_explicitly() -> None:
    """ASVS 8.1.4 asks how factors are graded. The honest answer — binary predicates, one fixed action,
    no composite score — must be written down, not implied."""
    block = _section(_doc_text(), _H_CONTEXT)
    lowered = " ".join(
        block.replace("*", " ").lower().split()
    )  # ignore wrapping + emphasis markers
    for phrase in ("binary predicate", "no composite risk score"):
        assert phrase in lowered, f"the 8.1.4 grading model must state {phrase!r}"
    for action in _ACTION_VOCABULARY:
        assert action in block, f"the closed action vocabulary must name {action}"


def _action_cells() -> list[tuple[str, str]]:
    """``[(row label, Action cell)]`` across BOTH decision tables."""
    block = _section(_doc_text(), _H_CONTEXT)
    out: list[tuple[str, str]] = []
    for table in _tables(block):
        header = table[0]
        if "Action" not in header:
            continue
        action = header.index("Action")
        for row in table[1:]:
            out.append((row[0], row[action]))
    return out


def _vocabulary_words(cell: str) -> list[str]:
    """The declared vocabulary word a cell OPENS with, as a list (empty = none, >1 = ambiguous)."""
    opener = cell.lstrip("* ").split(" ")[0].strip("*—-:,.")
    return [word for word in _ACTION_VOCABULARY if opener == word]


def test_every_action_cell_opens_with_exactly_one_vocabulary_word() -> None:
    """The 8.1.4 answer, asserted as a PROPERTY of the tables rather than a phrase about them.

    The retired model claimed "every row resolves to exactly one of ALLOW/DENY/CHALLENGE/THROTTLE/LOG"
    over a table where five rows falsified it: ``Account / session state`` read "DENY / confine"
    (``confine`` was not in the declared set and the row bundled three attributes with three
    outcomes), ``Live directory resolvability`` forked DENY-or-LOG on a second predicate, the startup
    posture forked refuse-vs-warn, and two rows named no vocabulary word at all. Phrase-presence could
    never see any of that — the very paragraph making the false claim satisfied it.
    """
    cells = _action_cells()
    assert cells, "the contextual section's decision tables lost their Action column"
    bad: list[tuple[str, str]] = []
    for label, cell in cells:
        if len(_vocabulary_words(cell)) != 1:
            bad.append((label, cell[:90]))
    assert not bad, (
        "these Action cells do not OPEN with exactly one word of the declared closed vocabulary "
        f"{list(_ACTION_VOCABULARY)}: {bad}. Split the row so one attribute maps to one action, or "
        "add the word to the declared vocabulary and say so in the grading-model block."
    )


def test_action_vocabulary_guard_detects_a_planted_ambiguity() -> None:
    """Proves the check above can fail: the retired "DENY / confine" shape must be rejected."""
    assert _vocabulary_words("**DENY** / confine") == ["DENY"], (
        "sanity: a leading DENY is still recognised"
    )
    assert _vocabulary_words("the session is born **without** step-up freshness") == [], (
        "a cell naming no vocabulary word must be reported, not silently accepted"
    )
    assert _vocabulary_words("**REVOKE** everything") == [], (
        "a cell opening with an UNDECLARED word must be reported"
    )


def test_contextual_prefixed_settings_force_a_documented_decision() -> None:
    """The backstop ``_CONTEXTUAL_TOKENS`` is not, and its own comment used to claim it was.

    RULE (8.1.4 completeness): a settings field whose NAME marks it as a candidate contextual input
    must be either named in the inventory (``_CONTEXTUAL_TOKENS``) or listed in the reviewed
    non-input set with a written reason. A new knob therefore forces a conscious decision instead of
    landing unseen — the mechanical backstop the same-PR rule was missing.
    """
    from messagefoundry.config.settings import ApiSettings, SecuritySettings

    candidates: set[str] = set()
    for model in (AuthSettings, ApiSettings, SecuritySettings):
        for name in model.model_fields:
            if any(marker in name for marker in _CONTEXTUAL_NAME_MARKERS):
                candidates.add(name)
    assert candidates, "the contextual name markers match nothing — the backstop is inert"
    undecided = sorted(candidates - _CONTEXTUAL_TOKENS - _CONTEXTUAL_REVIEWED_NON_INPUTS)
    assert not undecided, (
        f"these settings match a contextual name marker but are neither documented in the 8.1.3/8.1.4 "
        f"inventory nor reviewed as non-inputs: {undecided}. Add a table row (and its token), or add "
        "the field to _CONTEXTUAL_REVIEWED_NON_INPUTS with a comment saying why it shapes no access "
        "decision."
    )
    stale = sorted(_CONTEXTUAL_REVIEWED_NON_INPUTS - candidates)
    assert not stale, (
        f"_CONTEXTUAL_REVIEWED_NON_INPUTS names fields that no longer exist or no longer match a "
        f"contextual marker: {stale}"
    )


def test_admin_exposed_is_not_derived_from_the_mutated_console_flag() -> None:
    """The exposure predicate must not read a field an earlier arm has already rewritten.

    ``settings.api.serve_ui`` is flipped to ``False`` IN PLACE by both ADR 0143 degrade arms before
    the exposure gates run, so by the time ``admin_exposed`` is derived it answers "is /ui mounted?",
    not "is the admin interface on the network?". Deriving the MFA-at-exposure and #189 dual-control
    gates from it (BACKLOG #326) made both unreachable on the runbook's RECOMMENDED loopback-behind-
    declared-proxy topology, while the ADR 0152 arm in the same function called that boot exposed.

    The behavioural pins live in ``tests/test_cli.py`` and ``tests/test_checks_gate_parity.py``. This
    is the SHAPE guard: it exists so the defect cannot quietly return through a refactor that keeps
    every current test green (re-introducing the console term only changes behaviour for configs no
    case happens to cover). Kept here beside the dual-control slice because it uses the same idiom on
    the same file, including its liveness receipt.
    """
    source = (_ROOT / "messagefoundry" / "__main__.py").read_text(encoding="utf-8")
    marker = "\n    admin_exposed = "
    # Liveness receipt FIRST: a rename or a reflow that makes the slice empty must red this test, not
    # make it unfailable. `in` is checked explicitly so the failure names the cause rather than
    # surfacing a bare ValueError from `index`.
    assert marker in source, (
        "no top-level `admin_exposed = ` assignment found in messagefoundry/__main__.py. If it was "
        "renamed, update this guard AND docs/SECURITY.md Table A AND the literal marker in "
        "test_startup_dual_control_arm_is_documented_as_warn_only, which all name it."
    )
    start = source.index(marker) + 1
    assignment = source[start : source.index("\n", start)]
    assert assignment.strip().startswith("admin_exposed = ") and len(assignment.strip()) > len(
        "admin_exposed = "
    ), (
        f"the assignment slice looks wrong — the assertions below would pass vacuously: {assignment!r}"
    )
    for banned in ("ui_exposed", "serve_ui"):
        assert banned not in assignment, (
            f"`admin_exposed` is derived from `{banned}`, which the ADR 0143 degrade arms rewrite in "
            f"place further up this same function (BACKLOG #326). Derive it from `instance_exposed` "
            f"— the console being mounted is a presentation fact, not an exposure fact. Slice was: "
            f"{assignment!r}"
        )


def test_startup_dual_control_arm_is_documented_as_warn_only() -> None:
    """The bind/exposure inventory claimed a refusal the code does not implement.

    ``admin_exposed + PHI + approvals off`` prints a warning and falls through on EVERY instance;
    ``__main__.py`` records the refuse arm as an unresolved owner fork. Derived by slicing the
    approvals block out of the source and asserting it contains no ``return 2``, so promoting it to a
    refusal later reds the doc.

    The slice is taken by **indentation**, not by "up to the next comment banner". The banner boundary
    was not reference-invariant: it measured whatever happened to sit between the arm and the next
    banner, so inserting an unrelated refusal after the arm (the ASVS 12.1.1 TLS-floor probe did
    exactly this) turned the guard red and blamed the approvals arm for a ``return 2`` that was not in
    it. A gate whose answer depends on unrelated neighbouring code is not measuring its subject.
    """
    source = (_ROOT / "messagefoundry" / "__main__.py").read_text(encoding="utf-8")
    marker = "if admin_exposed and not settings.approvals.enabled"
    # Slice from the START OF THE LINE, not from the marker itself: the `if`'s own indentation is what
    # defines its body, and `source.index` lands past the leading whitespace.
    start = source.rindex("\n", 0, source.index(marker)) + 1
    lines = source[start:].splitlines(keepends=True)
    # The arm is the `if` statement and its own body, which is anything indented deeper than the `if`.
    body_indent = " " * (len(lines[0]) - len(lines[0].lstrip()) + 1)
    arm_lines = [lines[0]]
    for line in lines[1:]:
        if line.strip() and not line.startswith(body_indent):
            break
        arm_lines.append(line)
    arm = "".join(arm_lines)
    # Liveness receipt: a boundary bug that produced a 1-line slice would make the assertion below
    # unfailable, so prove the slice actually captured the arm's body before trusting it.
    assert "warning:" in arm and len(arm_lines) > 5, (
        f"the arm slice looks wrong ({len(arm_lines)} lines) — the assertion below would pass "
        f"vacuously. Slice was:\n{arm}"
    )
    assert "return 2" not in arm, (
        "the approvals-at-exposure arm now REFUSES to start. Move its row out of the WARN action in "
        "docs/SECURITY.md's Table A (and re-check `_CONTEXT_TABLE_A_ROWS`) in the same change."
    )
    rows_a, _rows_b = _contextual_table_rows()
    row = [r for r in rows_a if r[0].startswith("Bind / exposure posture — dual-control arm")]
    assert row, "Table A has no dual-control-arm row"
    joined = " ".join(row[0])
    assert joined.split("|")[0] or True
    assert "**LOG**" in joined, (
        "the dual-control arm's action is a startup WARNING only; it must not be filed under DENY."
    )
    assert "owner fork" in joined, (
        "the row must say the refuse arm is an unresolved owner fork, not a shipped control"
    )
    # And the refusing arms must not claim a production keying the ladder does not have.
    refusing = [r for r in rows_a if r[0].startswith("Bind / exposure posture — refusing arms")]
    assert refusing, "Table A has no refusing-arms row"
    refusing_text = " ".join(refusing[0])
    assert "a non-production instance warns" not in refusing_text, (
        "no arm of the startup ladder keys on `production`; the refuse/warn dial is "
        "[security].enforcement."
    )
    assert "[security].enforcement" in refusing_text, (
        "the refusing-arms row must name the real dial, [security].enforcement"
    )
    from messagefoundry.config.settings import _KNOWN_ENV_POSTURE, SecurityEnforcement

    assert ServiceSettings().security.enforcement is SecurityEnforcement.ENFORCE, (
        "[security].enforcement no longer defaults to ENFORCE; the refuse/warn wording is stale."
    )
    assert _KNOWN_ENV_POSTURE["staging"][1] is False and _KNOWN_ENV_POSTURE["dev"][1] is False, (
        "dev/staging are no longer non-production; the 'includes dev and staging' clause is stale."
    )
    assert all(_KNOWN_ENV_POSTURE[env][0].value == "phi" for env in ("dev", "staging")), (
        "dev/staging no longer derive PHI; the refusing-arms row's clause is stale."
    )
