# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Doc-drift guard for the comparative authentication-strength table (ASVS 6.1.3).

6.1.3 asks that the *relative strength* of every authentication pathway be documented. The table was
scored Partial because it had three rows while five pathways shipped — OIDC federation and the mTLS
service-identity plane were both live and both absent. A table that silently falls one pathway behind
is the defect itself, so the row set is keyed on **code artefacts existing**, not on a hardcoded list:
the interactive pathways are enumerated from the ``AuthService`` entry points that mint a
``LoginOutcome``, and each row is additionally anchored to the setting that turns it on: a settings
field, or for the ingest-plane pathway a connector-factory parameter.

Also pins the numbers the table quotes (lockout, MFA-claim gate, the sign-in window's two dimensions,
the reconciler default) to the live defaults, and asserts the two corrected falsehoods cannot return.
"""

from __future__ import annotations

import ast
import asyncio
import dataclasses
import functools
import inspect
import itertools
import logging
import re
import subprocess
import textwrap
import typing
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from _mfa_grant import keyword_values, mfa_grant_values
from pydantic import BaseModel

from messagefoundry.api import security as api_security
from messagefoundry.api.security import _PHI_VIEW_PERMISSIONS, require_service_cert
from messagefoundry.auth import service as service_module
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.permissions import (
    BUILTIN_ROLE_PERMISSIONS,
    CUSTOM_ROLE_FORBIDDEN_PERMISSIONS,
    CustomRoleError,
    Permission,
    Role,
    validate_custom_role_permissions,
)
from messagefoundry.auth.policy import PasswordPolicy
from messagefoundry.auth.service import AuthService, _directory_login_refusal
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import ApiSettings, AuthSettings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.config.wiring import Http, WiringError
from messagefoundry.pipeline.wiring_runner import check_inbound_revocation
from messagefoundry.store.store import LockoutCounter, UserRecord, lockout_escalates
from tests._sign_in_claim import SIGN_IN_ANY_TENSE, SIGN_IN_CLAIM

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "SECURITY.md"
_HEADING = "### Authentication pathways — comparative strength"

#: The interactive entry points that mint a session. Derived by introspection so a NEW interactive
#: pathway landing without a comparative-strength row reds CI.
_LOGIN_ENTRY_POINTS = frozenset(
    {"login", "authenticate_kerberos", "complete_oidc_login", "authenticate_oidc"}
)

#: Row token -> the setting whose existence proves the pathway still ships: a settings-model field, or
#: a parameter of a connector factory. ``None`` = always available (Local needs no switch). ``mTLS`` is
#: the fifth pathway and the first non-interactive one; HTTP intake authentication is the sixth, on the
#: ingest plane (owner ruling 2026-09-23: ``intake_auth`` IS an authentication pathway).
_PATHWAY_ANCHORS: dict[str, tuple[Callable[..., Any], str] | None] = {
    "**Local**": None,
    "**AD**": (AuthSettings, "ad_enabled"),
    "**Kerberos / SPNEGO**": (AuthSettings, "kerberos_enabled"),
    "**OIDC federation**": (AuthSettings, "oidc_enabled"),
    "**mTLS service identity**": (ApiSettings, "tls_client_cert_identities"),
    "**HTTP intake authentication**": (Http, "intake_auth"),
}

#: Pathways that live on the INGEST plane rather than the engine API. Neither the ``AuthService``
#: derivation nor the ``api.security`` factory derivation can see them, so the set is checked against
#: the ``config.wiring`` factories that take an ``intake_auth`` parameter instead (see
#: ``test_ingest_plane_pathways_are_derived_from_the_connector_factories``).
_INGEST_PLANE_PATHWAYS = frozenset({"**HTTP intake authentication**"})
_INGEST_PLANE_FACTORIES = frozenset({"Http"})

#: Companion-table row labels, in the primary table's order. The two tables label rows differently,
#: so the order check needs the mapping rather than a string compare.
_COMPANION_LABELS = (
    "**Local**",
    "**AD**",
    "**Kerberos**",
    "**OIDC**",
    "**mTLS**",
    "**HTTP intake**",
)

#: Tokens the numbered-6.1.3 paragraph must enumerate — it is the artefact that cites the requirement.
_PARAGRAPH_TOKENS = ("Local", "AD", "Kerberos", "OIDC", "mTLS", "intake_auth")

#: Every public dependency factory in ``messagefoundry.api.security``. The interactive derivation
#: above covers ``AuthService``; this covers the NON-interactive plane, which is where a new
#: authentication mechanism (an HMAC-signed service call, an API key, a second cert plane) would land
#: and, without this, would ship with no comparative-strength row and no test failure.
_REQUIRE_FACTORIES = frozenset(
    {
        "require",
        "require_paced",
        "require_phi_read",
        "require_reauth_only",
        "require_reauth_only_action",
        "require_service_cert",
        "require_step_up",
        "require_step_up_action",
    }
)

#: The subset that authenticates by something OTHER than a bearer session token. Each one is a
#: distinct authentication pathway and needs its own comparative-strength row.
_NON_BEARER_FACTORIES = frozenset({"require_service_cert"})


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section() -> str:
    lines = _doc_text().splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(_HEADING)), None)
    assert start is not None, (
        f"docs/SECURITY.md no longer has the heading {_HEADING!r}. ASVS 6.1.3's evidence cite points "
        "at that section — rename it and this guard together."
    )
    out: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("###") or line.startswith("## "):
            break
        out.append(line)
    return "\n".join(out)


def _tables(block: str) -> list[list[list[str]]]:
    tables: list[list[list[str]]] = []
    current: list[list[str]] | None = None
    for raw in block.splitlines():
        line = raw.strip()
        if line.startswith("|") and line.endswith("|") and len(line) > 1:
            cells = [c.strip() for c in line[1:-1].split("|")]
            if cells and all(c and set(c) <= set("-: ") for c in cells):
                continue
            if current is None:
                current = []
            current.append(cells)
        elif current is not None:
            tables.append(current)
            current = None
    if current is not None:
        tables.append(current)
    return tables


def _primary_table() -> list[list[str]]:
    for table in _tables(_section()):
        if table[0] == ["Pathway", "Factor", "Brute-force defense", "Notes"]:
            return table
    raise AssertionError(
        "the comparative-strength table's 4-column shape "
        "(| Pathway | Factor | Brute-force defense | Notes |) is gone — 6.1.3's evidence cite points "
        "at that artefact, so grow it, do not restructure it."
    )


def test_primary_table_keeps_its_shape_and_has_one_row_per_pathway() -> None:
    table = _primary_table()
    body = table[1:]
    assert len(body) == len(_PATHWAY_ANCHORS), (
        f"the comparative-strength table has {len(body)} body rows; {len(_PATHWAY_ANCHORS)} "
        "authentication pathways ship. RULE: every shipped authentication pathway needs a row "
        "(ASVS 6.1.3)."
    )


def test_row_count_tracks_the_login_entry_points_in_code() -> None:
    """The interactive pathway set is derived from the code, so a new one reds CI.

    RULE: a new ``AuthService`` coroutine returning a ``LoginOutcome`` is a new authentication pathway
    and needs a comparative-strength row.
    """
    derived = {
        name
        for name, member in inspect.getmembers(AuthService, inspect.iscoroutinefunction)
        if not name.startswith("_")
        and "LoginOutcome" in str(inspect.signature(member).return_annotation)
    }
    assert derived == _LOGIN_ENTRY_POINTS, (
        f"the AuthService login entry points changed: {sorted(derived ^ _LOGIN_ENTRY_POINTS)}. A new "
        "one is a new authentication pathway — add its row to docs/SECURITY.md's comparative-strength "
        "table and update this guard in the same change (ASVS 6.1.3)."
    )
    # complete_oidc_login + authenticate_oidc are two legs of ONE pathway, so 4 entry points collapse
    # to 3 interactive pathways beyond Local; +Local +mTLS = 5 API-plane rows, +HTTP intake on the
    # ingest plane = 6 (owner ruling 2026-09-23).
    assert len(_PATHWAY_ANCHORS) == 6
    # BLIND SPOT CLOSED. The public-coroutine derivation above cannot see a new pathway added
    # through the EXISTING public entry point: ``login()`` dispatches on ``AuthProvider`` into a
    # PRIVATE ``_login_<provider>`` coroutine, so a new enum member + ``_login_saml`` would change
    # none of the three code-anchored assertions and would ship with no row and green CI.
    assert {member.name for member in AuthProvider} == {"LOCAL", "AD"}, (
        f"AuthProvider gained or lost a member ({sorted(m.name for m in AuthProvider)}). A provider "
        "is an authentication pathway: add its comparative-strength row to docs/SECURITY.md and "
        "update this guard in the same change (ASVS 6.1.3)."
    )
    private = {
        name
        for name, member in inspect.getmembers(AuthService, inspect.iscoroutinefunction)
        if name.startswith("_login")
        and "LoginOutcome" in str(inspect.signature(member).return_annotation)
    }
    # `_login_ad` was DELETED, not renamed: the AD password sign-in is retired (BACKLOG #1137), so
    # `login()` dispatches into exactly one private leg. Shrinking this set is the deliberate update
    # the retirement owed the guard -- the guard itself is unweakened, because it still fails on any
    # `_login_*` appearing, which is the direction that ships an undocumented pathway.
    assert private == {"_login_local"}, (
        f"the private login coroutines changed: {sorted(private ^ {'_login_local'})}. A new `_login_*` "
        "returning a LoginOutcome is a new authentication pathway and needs a comparative-strength row "
        "in docs/SECURITY.md (ASVS 6.1.3)."
    )


def test_every_pathway_row_is_anchored_to_a_live_code_artefact() -> None:
    # Row LABELS, in order, not a substring of the section: the lead paragraph bolds some of these
    # names too, so a section-wide search passes with the row deleted.
    labels = [r[0] for r in _primary_table()[1:]]
    assert [
        next((t for t in _PATHWAY_ANCHORS if lab.startswith(t)), lab) for lab in labels
    ] == list(_PATHWAY_ANCHORS), (
        f"the comparative-strength rows are {labels}; expected {list(_PATHWAY_ANCHORS)} in order"
    )
    for token, anchor in _PATHWAY_ANCHORS.items():
        if anchor is None:
            continue
        owner, field = anchor
        if isinstance(owner, type) and issubclass(owner, BaseModel):
            present = field in owner.model_fields
        else:
            present = field in inspect.signature(owner).parameters
        assert present, (
            f"{owner.__name__}.{field} no longer exists, but docs/SECURITY.md still tabulates the "
            f"{token} pathway. Remove the row or fix the anchor."
        )


def test_companion_table_covers_the_remaining_strength_dimensions() -> None:
    """The four primary columns cannot carry phishing/replay/storage/MFA/revocation, so a companion
    table does — with the same rows, in the same order."""
    tables = _tables(_section())
    companion = [
        t for t in tables if t[0][:2] == ["Pathway", "Phishing resistance"] and "Revocation" in t[0]
    ]
    assert companion, (
        "the companion comparative table (| Pathway | Phishing resistance | Replay resistance | "
        "Credential stored by the engine | MFA support | Revocation |) is missing."
    )
    body = companion[0][1:]
    assert len(body) == len(_PATHWAY_ANCHORS) == len(_COMPANION_LABELS)
    assert [r[0] for r in body] == list(_COMPANION_LABELS), (
        f"the companion rows are {[r[0] for r in body]}; expected {list(_COMPANION_LABELS)}, the "
        "primary table's pathways in the primary table's order"
    )


def test_ingest_plane_pathways_are_derived_from_the_connector_factories() -> None:
    """RULE: a connector factory that takes ``intake_auth`` authenticates a submitting peer, which
    the owner ruled (2026-09-23) is an authentication pathway. A second one needs its own row."""
    import messagefoundry.config.wiring as wiring

    factories = {
        name
        for name, member in inspect.getmembers(wiring, inspect.isfunction)
        if member.__module__ == wiring.__name__
        and "intake_auth" in inspect.signature(member).parameters
    }
    assert factories == _INGEST_PLANE_FACTORIES, (
        f"the connector factories taking intake_auth changed: {sorted(factories)}. Each is an "
        "ingest-plane authentication pathway -- give it a comparative-strength row in "
        "docs/SECURITY.md and update _INGEST_PLANE_PATHWAYS in the same change (ASVS 6.1.3)."
    )
    assert len(_INGEST_PLANE_PATHWAYS) == len(_INGEST_PLANE_FACTORIES)
    assert set(_PATHWAY_ANCHORS) >= _INGEST_PLANE_PATHWAYS, (
        "_INGEST_PLANE_PATHWAYS names a row label that _PATHWAY_ANCHORS does not carry"
    )


@pytest.mark.parametrize(
    ("model", "field", "pinned", "rendered"),
    [
        # Every rendered token is SETTING-SPECIFIC. Two cases sharing one generic phrase (both were
        # "defaults **on**") make each other vacuous: delete one doc mention and the other still
        # satisfies both parametrized cases.
        (
            AuthSettings,
            "oidc_require_mfa_claim",
            True,
            "`[auth].oidc_require_mfa_claim` defaults **on**",
        ),
        # The MODEL field stays `AuthSettings.require_mfa` (the internal desugared field), but the
        # OPERATOR-FACING key is `[security].require_mfa`: `("auth", "require_mfa")` is in
        # `_RELOCATED_TO_SECURITY`, so the `[auth]` spelling raises at load and `serve` exits 2. The
        # rendered token has to quote the key an operator can actually set, or this guard pins the
        # documentation to a config that cannot start.
        (AuthSettings, "require_mfa", True, "`[security].require_mfa` defaults **on**"),
        (
            AuthSettings,
            "ad_session_recheck_seconds",
            300,
            "`[auth].ad_session_recheck_seconds` (default **300 s**)",
        ),
        (
            AuthSettings,
            "oidc_username_strip_domain",
            True,
            "`[auth].oidc_username_strip_domain` is on (default)",
        ),
        # NB: login_rate_limit_per_ip / _global are deliberately NOT pinned here — this section never
        # quotes 10 or 60, so a token like "per client IP" would match unrelated prose. They are
        # pinned where the table actually quotes them: tests/test_security_doc_rate_limits.py's
        # 6.1.1 protection-set and 2.1.3 limits guards.
    ],
)
def test_quoted_defaults_still_match_the_code(
    model: type[BaseModel], field: str, pinned: object, rendered: str
) -> None:
    assert model.model_fields[field].default == pinned, (
        f"{model.__name__}.{field} now defaults to {model.model_fields[field].default!r}, not "
        f"{pinned!r}. The comparative-strength table quotes it — update both together."
    )
    assert rendered in _section(), (
        f"the comparative-strength section no longer states {rendered!r} for {field}"
    )


def test_lockout_numbers_quoted_in_the_local_row_match_the_policy() -> None:
    policy = PasswordPolicy()
    assert (policy.lockout_threshold, policy.lockout_minutes) == (5, 15)
    row = next(r for r in _primary_table()[1:] if r[0].startswith("**Local**"))
    assert "5/15 min" in row[2], (
        "the Local row must quote the real lockout (5 failures / 15 min); it currently reads "
        f"{row[2]!r}"
    )


def test_mtls_row_states_the_phi_fence_that_the_code_enforces() -> None:
    """The mTLS row's PHI-fence claim is tied to the behaviour, not just to prose."""
    assert _PHI_VIEW_PERMISSIONS, "the PHI-view fence set is empty"
    with pytest.raises(ValueError):
        require_service_cert(Permission.MESSAGES_VIEW_RAW)
    row = next(r for r in _primary_table()[1:] if r[0].startswith("**mTLS"))
    notes = row[3].lower()
    for claim in ("no session", "no mfa", "no step-up", "phi-fenced"):
        assert claim in notes, f"the mTLS row must state {claim!r}"


def test_the_numbered_paragraph_enumerates_every_pathway() -> None:
    """The paragraph citing ASVS 6.1.3 by number is the scored artefact, so it must be complete."""
    block = _section()
    marker = "ASVS 6.1.3"
    assert marker in block, "the section must still cite ASVS 6.1.3 by number"
    paragraph = block[block.index(marker) :]
    missing = [t for t in _PARAGRAPH_TOKENS if t not in paragraph]
    assert not missing, (
        f"the ASVS 6.1.3 paragraph does not enumerate {missing}; it must state which controls do and "
        f"do not cover every one of the {len(_PATHWAY_ANCHORS)} pathways."
    )


def test_the_pathway_count_sentence_matches_the_row_set() -> None:
    """The sentence that makes the count is what a reader quotes, so it must equal the rows.

    It said **Five** while HTTP intake authentication shipped outside it; the owner ruled on
    2026-09-23 that ``intake_auth`` is a sixth pathway, so a count that drifts from the row set again
    reds here rather than going unnoticed.
    """
    words = {4: "Four", 5: "Five", 6: "Six", 7: "Seven", 8: "Eight", 9: "Nine", 10: "Ten"}
    count = len(_PATHWAY_ANCHORS)
    expected = f"**{words.get(count, str(count))}** authentication pathways ship"
    assert expected in _section(), (
        f"the section must open with {expected!r}: the row set has {len(_PATHWAY_ANCHORS)} pathways."
    )


def test_the_intake_row_states_the_modes_and_the_unauthenticated_default() -> None:
    """The HTTP intake row is derived from ``Http()``'s signature, not typed from memory.

    RULE: the modes it names are exactly the ``intake_auth`` Literal, and it states the shipped
    default plainly, because that default admits an unauthenticated peer.
    """
    param = inspect.signature(Http).parameters["intake_auth"]
    # ``wiring.py`` uses postponed annotations, so the raw annotation is a string; resolve it.
    modes = typing.get_args(typing.get_type_hints(Http)["intake_auth"])
    assert param.default == "none" and "none" in modes, (
        f"Http(intake_auth=...) now defaults to {param.default!r}; restate the intake rows and the "
        "count sentence in docs/SECURITY.md."
    )
    row = next(r for r in _primary_table()[1:] if r[0].startswith("**HTTP intake"))
    joined = " ".join(row)
    missing = [m for m in modes if f"`{m}`" not in joined]
    assert not missing, f"the HTTP intake row does not name the intake_auth mode(s) {missing}"
    assert "The default is `none`" in row[1], (
        "the HTTP intake Factor cell must state the unauthenticated default in so many words"
    )
    for claim in ("no session", "no mfa", "no step-up"):
        assert claim in row[3].lower(), f"the HTTP intake row must state {claim!r}"
    lead = _section().split("| Pathway |", 1)[0]
    assert 'intake_auth = "none"' in lead, (
        "the count sentence above the table must state the intake default, not leave it to a cell"
    )


def _passes_header(source: str, name: str, value: str) -> bool:
    """Whether a call in ``source`` passes ``headers={name: value, ...}`` as string literals.

    An AST read, not a substring scan (BACKLOG #1818): a comment or docstring in the function that
    quotes the header kept the old scan green after the real header was changed.
    """
    return any(
        isinstance(node, ast.keyword)
        and node.arg == "headers"
        and isinstance(node.value, ast.Dict)
        and any(
            isinstance(k, ast.Constant)
            and k.value == name
            and isinstance(v, ast.Constant)
            and v.value == value
            for k, v in zip(node.value.keys, node.value.values, strict=True)
        )
        for node in ast.walk(ast.parse(textwrap.dedent(source)))
    )


def test_passes_header_ignores_mentions() -> None:
    """The helper reads code only: a quoted header is ABSENT, the real keyword PRESENT."""
    mention = (
        "def refusal(self):\n"
        '    """Answers 429 with headers={"Retry-After": "60"}."""\n'
        '    # headers={"Retry-After": "60"}\n'
        '    return Error(429, headers={"Retry-After": "30"})\n'
    )
    assert not _passes_header(mention, "Retry-After", "60")
    real = 'def refusal(self):\n    return Error(429, headers={"Retry-After": "60"})\n'
    assert _passes_header(real, "Retry-After", "60")


def test_the_intake_numbers_the_doc_quotes_match_the_code() -> None:
    """The intake rows quote defaults and floors; pin each one to the code that sets it.

    The budget numbers are stated once, in this section's row; Table B names the settings and links
    to CONNECTIONS.md for the values rather than restating them (SDS-3.5).
    """
    from messagefoundry.pipeline.wiring_runner import (
        _INTAKE_ALLOWLIST_MIN_PREFIX_V4,
        _INTAKE_ALLOWLIST_MIN_PREFIX_V6,
    )
    from messagefoundry.transports import http_listener

    params = inspect.signature(Http).parameters
    assert params["intake_auth_rate_limit"].default == 10
    assert params["intake_auth_rate_limit_global"].default == 60
    assert params["intake_api_key_header"].default == "x-api-key"
    assert params["intake_auth_health"].default == "require"
    assert (_INTAKE_ALLOWLIST_MIN_PREFIX_V4, _INTAKE_ALLOWLIST_MIN_PREFIX_V6) == (8, 32)
    assert _passes_header(
        inspect.getsource(http_listener.HttpSource._rate_limit_refusal), "Retry-After", "60"
    ), "the intake 429 no longer passes headers={'Retry-After': '60'}"
    row = " ".join(next(r for r in _primary_table()[1:] if r[0].startswith("**HTTP intake")))
    for quoted in ("`intake_auth_rate_limit` 10/min", "`intake_auth_rate_limit_global` 60/min"):
        assert quoted in row, f"the HTTP intake row no longer quotes {quoted!r}"
    table_b = " ".join(
        line for line in _doc_text().splitlines() if line.startswith("| **HTTP** — ")
    )
    for quoted in (
        "(default `x-api-key`)",
        "`Retry-After: 60`",
        "wider than a /8 (IPv4) or a /32 (IPv6)",
        'unless `intake_auth_health = "allow"`',
    ):
        assert quoted in table_b, f"the Table B HTTP rows no longer quote {quoted!r}"


def test_the_one_switch_that_flattens_three_pathways_is_named_in_each_row() -> None:
    """6.1.3 asks whether the strongest pathway is undermined by the weakest.

    ``[auth].login_rate_limit_enabled = false`` builds no ``_login_limiter``, so ``allow_login_attempt``
    returns True unconditionally, and ``_reauth_limiter`` goes with it. The Kerberos ticket leg and the
    OIDC federated leg lose their ONLY engine-side control; the AD step-up bind loses its per-actor
    budget and keeps the lockout feed and per-session cap (BACKLOG #1138); Local keeps a lockout the
    6.1.1 table records as having no dedicated off switch. Stating the limiter unconditionally
    overstates the directory pathways' floor.
    """
    assert AuthSettings.model_fields["login_rate_limit_enabled"].default is True, (
        "login_rate_limit_enabled no longer defaults on; restate the comparative-strength rows."
    )
    token = "login_rate_limit_enabled"
    for prefix in ("**AD**", "**Kerberos / SPNEGO**", "**OIDC federation**"):
        row = next(r for r in _primary_table()[1:] if r[0].startswith(prefix))
        assert token in row[2], (
            f"the {prefix} row's Brute-force-defense cell states the sign-in window without naming "
            f"`[auth].{token}` — the one flag that removes it and the per-actor budget together."
        )
    block = _section()
    paragraph = block[block.index("ASVS 6.1.3") :]
    assert token in paragraph, (
        "the ASVS 6.1.3 paragraph must name the switch that strips three of the six pathways of "
        "their engine-side throttles — that is the comparative-strength answer the requirement wants."
    )


def _reads_auth_provider(func: Callable[..., Any]) -> bool:
    """True when ``func``'s body reads ``.auth_provider``. Docstrings are constants, so they never match."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    return any(isinstance(n, ast.Attribute) and n.attr == "auth_provider" for n in ast.walk(tree))


def test_the_rows_do_not_draw_the_directory_pathways_weaker_than_the_code() -> None:
    """ASVS 6.1.3 fell to partial (BACKLOG #1133) on three self-contradictions in this section.

    Two drew the directory pathways weaker than the code: the Local row claimed it was the only
    pathway the engine can lock out and the only one with a phishing-resistant factor. The code has
    no provider filter on the TOTP leg or on passkey enrolment, and a locked row refuses a directory
    sign-in (BACKLOG #1144, #1638). The third said the AD step-up bind keeps its per-actor budget
    with the rate-limit flag off; that flag builds neither limiter, which
    ``tests/test_security_doc_rate_limits.py::test_one_flag_disables_both_limiters`` derives from the
    constructor, so it is not re-derived here. The other premises are, so a code change that makes
    an old sentence true again reds this test instead of passing it. A provider check added at the
    ROUTE layer would slip past this AST read; the service methods are what it covers.

    ``verify_mfa`` is off the no-provider list since BACKLOG #2023, and only for one branch: a
    directory account is asked of the directory before its code is checked. That branch adds a
    refusal and exempts nothing, and the Lockout asymmetry paragraph says so. The behaviour the rows
    rest on (a directory account's wrong code feeds the lockout, and its lock is checked before the
    lookup) is pinned in ``tests/test_mfa_directory_recheck.py``, not by this AST read.
    """
    verify_attrs = [
        n.attr
        for n in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(AuthService.verify_mfa))))
        if isinstance(n, ast.Attribute)
    ]
    assert (
        verify_attrs.count("auth_provider") == 1 and "_directory_step_up_refusal" in verify_attrs
    ), (
        "verify_mfa grew a provider branch beyond the BACKLOG #2023 directory check; re-derive the "
        "pathway rows, which say a directory account's TOTP leg feeds and meets the lockout."
    )
    assert "BACKLOG #2023" in _section(), (
        "the pathway section no longer names verify_mfa's one provider branch (BACKLOG #2023)."
    )
    for func in (
        AuthService.begin_mfa_enrollment,
        AuthService.confirm_mfa_enrollment,
        AuthService.begin_webauthn_registration,
        AuthService.finish_webauthn_registration,
    ):
        assert not _reads_auth_provider(func), (
            f"{func.__qualname__} now reads auth_provider. The pathway rows say a directory account "
            "can enrol TOTP or a passkey and that its TOTP leg feeds the lockout; re-derive both."
        )
    verify_tree = ast.parse(textwrap.dedent(inspect.getsource(AuthService.verify_mfa)))
    assert any(
        isinstance(n, ast.Attribute) and n.attr == "_register_failure"
        for n in ast.walk(verify_tree)
    ), "verify_mfa no longer feeds the lockout; the rows say a wrong TOTP code does."
    locked = SimpleNamespace(disabled=False, locked_until=float("inf"))
    assert _directory_login_refusal(locked, 0.0, federated=False) == "locked", (  # type: ignore[arg-type]
        "a directory sign-in no longer refuses a locked row; the Kerberos and OIDC rows say it does."
    )
    for sign_in_path in (AuthService._complete_ad_login, AuthService._upsert_ad_user):
        tree = ast.parse(textwrap.dedent(inspect.getsource(sign_in_path)))
        assert any(
            isinstance(n, ast.Name) and n.id == "_directory_login_refusal" for n in ast.walk(tree)
        ), f"{sign_in_path.__qualname__} no longer checks a locked row; re-derive the rows."
    # ...and both directory sign-ins still reach that check.
    for entry in (AuthService._authenticate_kerberos, AuthService._authenticate_oidc):
        tree = ast.parse(textwrap.dedent(inspect.getsource(entry)))
        assert any(
            isinstance(n, ast.Attribute) and n.attr == "_complete_ad_login" for n in ast.walk(tree)
        ), f"{entry.__qualname__} no longer routes through _complete_ad_login; re-derive the rows."

    text = _doc_text()
    # The first and fifth phrases are main's pre-BACKLOG #1138 wording; the rest were on this
    # branch's base. All five are false against the code above.
    for retired in (
        "the only pathway the engine itself can lock out",
        "the only pathway whose sign-in feeds the engine lockout",
        "the only one with a phishing-resistant factor",
        "no longer strips this pathway bare",
        "the AD step-up bind keeps its per-actor budget",
    ):
        assert retired not in text, (
            f"docs/SECURITY.md says {retired!r} again; the code contradicts it (BACKLOG #1133)."
        )
    rows = _primary_table()[1:]
    local_notes = next(r for r in rows if r[0].startswith("**Local**"))[3]
    assert "directory accounts included" in local_notes and "passkey" in local_notes, (
        "the Local Notes cell must say the TOTP leg feeds the lockout on directory accounts too, and "
        "that a directory account can hold a passkey."
    )
    ad_defense = next(r for r in rows if r[0].startswith("**AD**"))[2]
    assert "removes the per-actor budget" in ad_defense, (
        "the AD row must say login_rate_limit_enabled=false removes its per-actor budget."
    )
    companion = next(
        t for t in _tables(_section()) if t[0][:2] == ["Pathway", "Phishing resistance"]
    )
    kerb_phish = next(r for r in companion[1:] if r[0].startswith("**Kerberos"))[1]
    assert "passkey" in kerb_phish, (
        "the companion Kerberos phishing cell must name the engine passkey the session can meet."
    )
    block = _section()
    asymmetry = " ".join(block[block.index("**Lockout asymmetry") :].split())[:400]
    assert "directory accounts included, **feed**" in asymmetry, (
        "the lockout-asymmetry paragraph must open by saying the TOTP leg feeds the lock on "
        "directory accounts too."
    )


def test_the_console_dependency_of_the_browser_legs_is_stated() -> None:
    """OIDC is browser-only, so a JSON-only deployment has no OIDC route at all — while
    ``GET /auth/providers`` still advertises it, because ``oidc_available`` never consults the
    console mount. The enforcement paragraph must say both halves."""
    # A property: mypy reads the attribute as its getter's type, which has no fget.
    source = inspect.getsource(AuthService.oidc_available.fget)  # type: ignore[attr-defined]
    assert "serve_ui" not in source and "serve_web_console" not in source, (
        "oidc_available now consults the console mount; the doc's providers caveat is stale."
    )
    block = _section()
    assert "serve_web_console" in block, (
        "the enforcement paragraph must name `[security].serve_web_console` — the second gate that "
        "removes the three browser sign-in legs (and therefore OIDC entirely)."
    )
    assert "configured" in block, (
        "GET /auth/providers reports what is CONFIGURED, not what is reachable; the paragraph must "
        "not claim it reports which pathways are live."
    )


def test_corrected_falsehoods_cannot_return() -> None:
    text = _doc_text()
    assert "global rate-limit only" not in text, (
        "the AD row understated the engine-side throttle: the sign-in limiter is per-IP AND global."
    )
    assert "often MFA-backed" not in text, (
        "the Kerberos row asserted MFA the engine cannot observe — directory sessions are issued "
        "MFA-satisfied unconditionally and no amr-equivalent is received."
    )
    local = next(r for r in _primary_table()[1:] if r[0].startswith("**Local**"))
    assert "password **plus** an engine second factor" not in local[1], (
        "the Local Factor cell claims the pathway's factor is password PLUS a second factor. At HEAD "
        "a non-Administrator local account with nothing enrolled is issued an MFA-satisfied session "
        "on a password alone — the second factor binds at the step-up boundary, not at sign-in."
    )


def test_the_retired_directory_password_sign_in_is_not_described_as_live() -> None:
    """ASVS 6.1.3 was held at partial a second time (BACKLOG #1133) on two older passages.

    The L5b paragraph said ``/ui/login`` offers a provider selector and that an AD password signs
    in, and the signal table said the engine MFA gate never fires for a directory identity. Both
    were false against the code: the engine refuses ``provider=ad`` (BACKLOG #1137), the login page
    renders no selector, ``GET /auth/providers`` reports ``ad`` as a constant false, and
    ``mfa_satisfied`` refuses an un-verified directory session under ``require_mfa``. The code
    premises are pinned first, so a change that revives the sign-in reds here instead of silently
    making the old sentences true again.
    """
    from messagefoundry.api import auth_routes
    from messagefoundry_webconsole import pages

    dispatch = ast.parse(textwrap.dedent(inspect.getsource(AuthService._dispatch_login)))
    assert any(
        isinstance(n, ast.Constant) and n.value == "pathway_retired" for n in ast.walk(dispatch)
    ), "_dispatch_login no longer refuses provider=ad; the retired-sign-in prose is stale."
    routes = ast.parse(inspect.getsource(auth_routes))
    assert any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name)
        and n.func.id == "ProvidersInfo"
        and any(
            k.arg == "ad" and isinstance(k.value, ast.Constant) and k.value.value is False
            for k in n.keywords
        )
        for n in ast.walk(routes)
    ), (
        "GET /auth/providers no longer reports ad as a constant false; re-derive the providers prose."
    )
    # Every keyword-only switch is turned ON, so a revived selector gated on a new flag (the old one
    # was ``ad_enabled: bool = False``) still renders here and reds the check.
    switches = {
        name: True
        for name, p in inspect.signature(pages.login).parameters.items()
        if p.kind is inspect.Parameter.KEYWORD_ONLY
    }
    form = str(pages.login(None, **switches))
    assert 'name="provider"' not in form and "<select" not in form, (
        "/ui/login renders a provider selector again; the L5b paragraph says it does not."
    )
    # The directory floor: one BoolOp naming both the AD provider and require_mfa. Behaviour is
    # pinned in tests/test_mfa_access_gate.py; this only ties the signal-table AD row to it. The body
    # is ``_unverified_session_owes_factor`` since BACKLOG #2076: ``mfa_satisfied`` hashes the token
    # and delegates to ``_mfa_satisfied_hash`` (BACKLOG #296), which asks that helper about an
    # unstamped session, and the session cap asks the same helper, so all three share one rule.
    satisfied = ast.parse(
        textwrap.dedent(inspect.getsource(AuthService._unverified_session_owes_factor))
    )
    assert any(
        isinstance(n, ast.BoolOp)
        and {"AD", "require_mfa"} <= {a.attr for a in ast.walk(n) if isinstance(a, ast.Attribute)}
        for n in ast.walk(satisfied)
    ), "mfa_satisfied lost its directory floor; the signal-table AD row says when the gate fires."

    # Whitespace-normalised: a phrase that wraps across a source line must still be caught.
    text = " ".join(_doc_text().split())
    for retired in (
        "`/ui/login` offers a provider selector",
        "the engine MFA gate never fires for it",
        "and `ad` (`[auth].ad_enabled`) are pure config",
        "(LDAP bind + optional Windows SSO)",
        "local, LDAPS or Kerberos sign-in",
        # Unscoped, this says every sign-in seeds a step-up window; browser SSO and OIDC do not.
        "`reauth_at` is stamped at login and refreshed by",
    ):
        assert retired not in text, (
            f"docs/SECURITY.md says {retired!r} again; the code contradicts it (BACKLOG #1133)."
        )
    raw = _doc_text()
    l5b = raw[raw.index("**Browser AD login (L5b).**") :].split("\n\n", 1)[0]
    assert "retired" in l5b and "`provider=ad`" in l5b, (
        "the L5b paragraph must say the browser AD password sign-in is retired and refused."
    )


def test_local_row_scopes_the_second_factor_to_step_up_and_administrator() -> None:
    """The Factor column IS the comparative claim, so it must carry the scope qualifier.

    Pinned against ``_mfa_required_for``. Since ASVS 6.3.3 the DEFAULT scope is
    ``every_local_account``, so a plain local account IS required to carry a second factor; the
    Administrator-only rule survives as the ``administrators`` opt-out. Both arms are asserted, so
    neither the default flip nor the opt-out can regress without reddening this guard.
    """
    service = AuthService.__new__(AuthService)
    service._settings = AuthSettings(require_mfa=True)
    # A placeholder user: _mfa_required_for reads no field off it, provider included (BACKLOG #1144).
    user: UserRecord = SimpleNamespace(auth_provider=AuthProvider.LOCAL.value)  # type: ignore[assignment]
    assert (
        service._mfa_required_for(user, frozenset({Role.OPERATOR}), second_factor_enrolled=False)
        is True
    ), (
        "_mfa_required_for no longer demands a second factor for a plain local account under the "
        "default scope; the Local row's every_local_account claim is stale — update the doc in the "
        "same change."
    )
    narrowed = AuthService.__new__(AuthService)
    narrowed._settings = AuthSettings(require_mfa=True, require_mfa_scope="administrators")
    assert (
        narrowed._mfa_required_for(user, frozenset({Role.OPERATOR}), second_factor_enrolled=False)
        is False
    ), "require_mfa_scope='administrators' must restore the pre-6.3.3 non-admin exemption"
    assert (
        service._mfa_required_for(
            user, frozenset({Role.ADMINISTRATOR}), second_factor_enrolled=False
        )
        is True
    )
    assert (
        service._mfa_required_for(user, frozenset({Role.OPERATOR}), second_factor_enrolled=True)
        is True
    )
    factor = next(r for r in _primary_table()[1:] if r[0].startswith("**Local**"))[1]
    for qualifier in (
        # Timing: 6.3.3 moved the factor from the step-up boundary to sign-in, so the cell must now
        # say ACCESS gate. The old "not at sign-in" wording would understate the pathway.
        "access gate",
        "every_local_account",
        # The opt-out and its consequence both stay named: without them the cell overstates the
        # shipped posture for an estate that has narrowed the scope.
        "administrators",
        "password-only end to end",
        # ASVS 6.3.3 L3 hardware-factor relaxation: a passkey is asserted at UV=preferred, so
        # possession alone can satisfy the gate. Disclosed here or the cell overstates strength.
        "user_verification=preferred",
    ):
        assert qualifier in factor, (
            f"the Local Factor cell must state {qualifier!r} — without the timing, the scope and the "
            "passkey UV caveat it misstates the pathway's strength."
        )


def test_the_directory_rows_disclose_what_each_leg_actually_grants() -> None:
    """The directory pathways are the dominant ones in the scored posture, so their MFA truth belongs
    in the TABLE.

    Since ASVS 6.3.4 the grant is a per-mechanism ARGUMENT rather than a literal inside
    ``_complete_ad_login``, so this is pinned at the call sites: Kerberos passes a hard ``False`` (it
    receives no assertion the engine can read, so it grants nothing — BACKLOG #1144), while the
    federated leg must pass no constant at all, because its grant is derived from
    ``oidc_require_mfa_claim``. Asserting both halves keeps the two legs from silently converging in
    either direction.

    RETIREMENT NOTE (BACKLOG #1137): the grant used to be read off ``_login_ad``; that leg is gone,
    so the assertion follows the fact to the caller that still makes it -- Kerberos.

    POLARITY (BACKLOG #1144): the grant this test pinned was a hard ``True`` under the owner-signed
    delegated-directory relaxation. That relaxation is retired, so the polarity here is inverted
    rather than the test dropped -- the table must disclose the current grant, whichever way it
    points.

    ANCHOR (BACKLOG #1140): the Kerberos anchor now reads ``_authenticate_kerberos`` rather than the
    public ``authenticate_kerberos``. The public method became a thin wrapper that holds a FAILED
    challenge to a fixed deadline (ASVS 6.3.8) and delegates, so the grant sits one frame down. The
    anchor is a source-level name, so a future split reds this test rather than passing on a method
    that no longer carries the grant, which is the safe direction. The OIDC anchor moved to
    ``_authenticate_oidc`` for the same reason when that seam gained the same wrapper (BACKLOG #1947).
    """

    kerberos_grant = mfa_grant_values(AuthService._authenticate_kerberos)
    assert kerberos_grant and all(
        isinstance(v, ast.Constant) and v.value is False for v in kerberos_grant
    ), (
        "the Kerberos leg mints sessions mfa_verified=True again; the Kerberos rows say it grants "
        "nothing on an unreadable assertion — re-derive the disclosure."
    )
    oidc_grant = mfa_grant_values(AuthService._authenticate_oidc)
    assert oidc_grant and not any(isinstance(v, ast.Constant) for v in oidc_grant), (
        "the OIDC leg passes a CONSTANT mfa_verified; 6.3.4 requires it to be derived from "
        "[auth].oidc_require_mfa_claim, and the OIDC row claims the engine verifies it."
    )
    factor = next(r for r in _primary_table()[1:] if r[0].startswith("**Kerberos"))[1]
    for token in ("MFA-pending", "engine second factor"):
        assert token in factor, (
            f"the Kerberos Factor cell must state {token!r}: what the engine does with a ticket that "
            "asserts nothing is a comparative-strength fact, not a footnote."
        )
    companion = next(
        t for t in _tables(_section()) if t[0][:2] == ["Pathway", "Phishing resistance"]
    )
    mfa_col = companion[0].index("MFA support")
    kerb_mfa = next(r for r in companion[1:] if r[0].startswith("**Kerberos"))[mfa_col]
    assert "engine" in kerb_mfa, (
        "the companion Kerberos row reads as a delegation claim; it must say the factor is an ENGINE "
        "factor, because nothing the ticket asserts reaches the engine."
    )
    block = _section()
    marker = "ASVS 6.1.3"
    paragraph = " ".join(block[block.index(marker) :].split())
    assert (
        "No pathway grants MFA satisfaction on an assertion the engine cannot read" in paragraph
    ), (
        "the paragraph after the 6.1.3 block must state the current consequence. It used to assert "
        "the opposite — that a domain ticket reaches the same PHI surface as a passkey-backed local "
        "Administrator — and that sentence is now a recorded retraction, not the live disclosure, so "
        "matching on it would answer the adjacent question (SDS-3.8)."
    )


def test_non_interactive_authentication_planes_are_enumerated_too() -> None:
    """Closes the loop the interactive derivation already closes for ``AuthService``.

    RULE: a public ``require_*`` dependency factory in ``messagefoundry.api.security`` that
    authenticates by something OTHER than a bearer session token is a NEW authentication pathway and
    needs a comparative-strength row. Today ``require_service_cert`` (mTLS) is the only one; every
    other factory layers additional checks on the same bearer session.
    """
    factories = {
        name
        for name, member in inspect.getmembers(api_security, callable)
        if name.startswith("require") and getattr(member, "__module__", "") == api_security.__name__
    }
    assert factories == _REQUIRE_FACTORIES, (
        f"the api.security dependency factories changed: {sorted(factories ^ _REQUIRE_FACTORIES)}. If "
        "the new one authenticates by anything other than a bearer session token it is a new "
        "authentication pathway — give it a comparative-strength row in docs/SECURITY.md and add it "
        "to _NON_BEARER_FACTORIES."
    )
    assert factories >= _NON_BEARER_FACTORIES
    assert len(_NON_BEARER_FACTORIES) + 4 + len(_INGEST_PLANE_PATHWAYS) == len(_PATHWAY_ANCHORS), (
        "the four interactive pathways plus every non-bearer plane plus the ingest-plane pathways "
        "must equal the documented row set"
    )


_CONSOLE_ROUTES = _ROOT / "messagefoundry_webconsole" / "routes"


def _console_route_funcs() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """``{"<METHOD> <path>": function}`` for every decorated console route function."""
    out: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for module in sorted(_CONSOLE_ROUTES.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for deco in node.decorator_list:
                if (
                    isinstance(deco, ast.Call)
                    and isinstance(deco.func, ast.Attribute)
                    and deco.func.attr in {"get", "post", "put", "patch", "delete"}
                    and deco.args
                    and isinstance(deco.args[0], ast.Constant)
                    and isinstance(deco.args[0].value, str)
                ):
                    out[f"{deco.func.attr.upper()} {deco.args[0].value}"] = node
    return out


def _called(node: ast.AST, name: str) -> bool:
    return any(
        isinstance(n, ast.Call)
        and (
            (isinstance(n.func, ast.Name) and n.func.id == name)
            or (isinstance(n.func, ast.Attribute) and n.func.attr == name)
        )
        for n in ast.walk(node)
    )


def test_the_fourth_sweep_leaves_no_older_pathway_contradiction() -> None:
    """ASVS 6.1.3 was held at partial a third time (BACKLOG #1133) on passages older than both fixes.

    Each earlier pass fixed the sentences it was pointed at and left older ones that said the
    opposite. This pass swept the whole file, so it pins three code facts and every retired phrasing:

    1. ``GET /ui/oidc/start`` is not simply "rate-limited" or simply "free". It renders the ASVS 3.7.3
       interstitial and charges nothing, unless ``_interstitial_needed()`` is false, when it runs the
       POST leg itself: limiter, flow and all.
    2. A browser SSO or OIDC session's first sensitive action does not always force a step-up.
       ``verify_mfa`` stamps ``reauth_at``, and neither code route asks whether the session already
       met its factor, so a TOTP or recovery code opens a fresh window at any time. A passkey does not.
    3. Console routes charge the per-actor ceremony budget, ``POST /ui/mfa`` among them. There were
       four when this pass ran; BACKLOG #296 added ``POST /ui/reauth/oidc`` for five, and the doc's
       count is now derived from the route list below rather than written into this test.

    The code premises come first, so a change that makes a retired sentence true again reds here.
    """
    routes = _console_route_funcs()

    interstitial = routes["GET /ui/oidc/start"]
    delegates = [
        n
        for n in ast.walk(interstitial)
        # Polarity pinned too: `if not _interstitial_needed(): return await ui_oidc_start(...)`.
        if isinstance(n, ast.If)
        and isinstance(n.test, ast.UnaryOp)
        and isinstance(n.test.op, ast.Not)
        and _called(n.test.operand, "_interstitial_needed")
        and any(_called(stmt, "ui_oidc_start") for stmt in n.body)
    ]
    assert delegates, (
        "GET /ui/oidc/start no longer runs the POST leg when the interstitial is skipped; restate "
        "the Route -> limiter map's OIDC row and every passage that links to it."
    )
    assert not _called(interstitial, "allow_login_attempt"), (
        "GET /ui/oidc/start now charges the sign-in window itself; the doc says it charges only by "
        "delegating to the POST leg."
    )

    service_tree = ast.parse(inspect.getsource(AuthService))
    verify = next(
        n
        for n in ast.walk(service_tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "verify_mfa"
    )
    assertion = next(
        n
        for n in ast.walk(service_tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "finish_webauthn_assertion"
    )
    assert _called(verify, "mark_session_reauthed"), (
        "verify_mfa no longer stamps reauth_at; the step-up paragraph says a TOTP opens a window."
    )
    assert not _called(assertion, "mark_session_reauthed"), (
        "a passkey assertion now stamps reauth_at; the doc says it marks the factor only."
    )
    assert not _called(verify, "mfa_satisfied") and not any(
        isinstance(n, ast.Attribute) and n.attr == "mfa_verified_at" for n in ast.walk(verify)
    ), "verify_mfa now asks whether the factor was met; the doc says a code renews at any time."
    from messagefoundry.api import auth_routes

    json_verify = next(
        n
        for n in ast.walk(ast.parse(inspect.getsource(auth_routes)))
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "mfa_verify"
    )
    for label, handler in (("POST /ui/mfa", routes["POST /ui/mfa"]), ("JSON", json_verify)):
        assert _called(handler, "verify_mfa") and not _called(handler, "mfa_satisfied"), (
            f"the {label} MFA route now checks whether the session already met its factor; the "
            "doc says a TOTP refreshes the step-up window at any time."
        )

    ceremony = sorted(r for r, fn in routes.items() if _called(fn, "allow_reauth_attempt"))
    assert ceremony == [
        "POST /ui/account/mfa/verify",
        "POST /ui/mfa",
        "POST /ui/reauth",
        # BACKLOG #296: the federated step-up's start leg, registered only with federation on.
        "POST /ui/reauth/oidc",
        "POST /ui/reauth/webauthn",
    ], f"the console routes charging the per-actor ceremony budget changed: {ceremony}"

    text = " ".join(_doc_text().split())
    for retired in (
        # Item 1 of the vault re-read: the console sign-in section named an AD form.
        "shows a sign-in form (Local / Active Directory)",
        # Item 2: GET /ui/oidc/start stated as always rate-limited, or as never charging.
        "on `GET /ui/sso`, `GET /ui/oidc/start` and `GET /ui/oidc/callback`",
        "**in-process** — `GET /ui/oidc/start` — reject-when-full",
        "the GET renders the 3.7.3 interstitial and stages nothing, so it is not a lever",
        '`GET /ui/oidc/start` now renders the "you are leaving this site" page and mints **no** flow',
        "the two `GET /ui/oidc/*` routes",
        # Item 3: the unqualified first-sensitive-action claims.
        "so their first sensitive action forces a step-up",
        "so its first sensitive action forces an explicit credential step-up",
        "proof is ambient, so the first sensitive action forces the directory-password step-up",
        "mints with no step-up window, so the first sensitive action forces a step-up",
        "born without step-up freshness, so its first sensitive action forces one",
        "these routes carry both a recent password re-verify",
        "so a disabled AD account cannot refresh its window.",
        "presents a TOTP/recovery code, not a re-prompt of the same password",
        # Item 4: the configuration section's single-section claim.
        "All knobs live in the `[auth]` section",
        # Item 5: the ceremony-route count and its Retry-After split.
        "3 JSON + 3 console ceremony routes",
        "`Retry-After: 30` on the two `/ui/reauth*` routes, none on the other four",
        "the two `/ui/reauth*` **ceremony** routes send it too",
        # Found by the sweep: POST /ui/mfa counted among the routes that charge nothing.
        "the remaining three charge nothing",
        "limiter 3 on the assertion **finish** leg only",
    ):
        assert retired not in text, (
            f"docs/SECURITY.md says {retired!r} again; the code contradicts it (BACKLOG #1133)."
        )

    raw = _doc_text()
    oidc_row = next(
        line for line in raw.splitlines() if line.startswith("| `POST /ui/oidc/start`, `GET /ui")
    )
    for token in ("_interstitial_needed()", "external_link_interstitial", "organization_domains"):
        assert token in oidc_row, (
            f"the limiter map's OIDC row must state the GET's condition and name {token!r}."
        )
    # The count is derived from the route list pinned above, so a sixth route reds here until the
    # row counts it. It used to be a literal "4" that contradicted the five-route list (BACKLOG #1133).
    assert f"3 JSON + {len(ceremony)} console ceremony routes" in text, (
        f"the 2.1.3 Credential ceremonies row must count the {len(ceremony)} console routes above."
    )
    ceremony_row = next(
        line for line in raw.splitlines() if line.startswith("| Credential ceremonies")
    )
    # The scope list only. The row names POST /ui/reauth/oidc a second time, in its no-Retry-After
    # clause, so a check over the whole row passed with the route dropped from the list.
    scope_list = ceremony_row.split("ceremony routes (", 1)[1].split(")", 1)[0]
    for route in ceremony:
        assert f"`{route}`" in scope_list, (
            f"the 2.1.3 Credential ceremonies row must list {route}, which charges the budget."
        )
    assert "`verify_mfa` calls `mark_session_reauthed`" in text, (
        "the step-up paragraph must say why a TOTP proved at the MFA gate opens a window."
    )


def _heading_block(heading: str) -> str:
    """The text under one ``#``-heading, up to the next heading of any level."""
    lines = _doc_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(heading))
    out: list[str] = []
    for line in lines[start + 1 :]:
        # A real heading, not a wrapped "#1184)" citation that happens to start a line.
        if line.startswith("#") and line.lstrip("#").startswith(" "):
            break
        out.append(line)
    return "\n".join(out)


def _service_func(name: str) -> ast.AsyncFunctionDef | ast.FunctionDef:
    tree = ast.parse(inspect.getsource(AuthService))
    return next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef) and n.name == name
    )


def test_the_fifth_sweep_carries_the_idp_step_up_leg_into_every_pathway_claim() -> None:
    """ASVS 6.1.3 was held at partial a fourth time (BACKLOG #1133) by the OIDC step-up leg.

    BACKLOG #296 (engine PR #1663) gave an ``oidc`` session its own re-authentication leg, at the
    IdP, and the pathway section never picked it up. So the document described one pathway's
    step-up two ways: as a password re-bind in the AD row, Table A and the step-up section, and as
    an IdP round trip in the OIDC section. The code has only the second. This pins what the code
    does, then refuses every phrasing that said otherwise:

    1. ``reauth`` refuses an ``oidc`` session before any verify, so no password or bind is checked.
    2. ``session_steps_up_at_idp`` keys on the SESSION's mechanism, not the account's provider; past
       it, the account's provider picks the password or the re-bind leg.
    3. ``complete_oidc_step_up`` stamps the window and mints the action-bound grant. No function on
       the IdP leg calls a lockout counter or the per-session re-proof cap, or reads the account
       lock, directly (the check does not follow the helpers they call).
    4. The grant is minted by exactly those two step-ups.
    5. A local sign-in that owes no factor is seeded unless its address is first-seen (``NEW``), and
       a combined sign-in always is (BACKLOG #288, ADR 0197), so "the initial login counts" is
       conditional.
    6. ``verify_mfa`` asks the directory about a directory account before it checks the code
       (BACKLOG #2023), so a code does not renew a disabled directory account's window, and a
       step-up is not the only live directory check.
    """
    assert _called(_service_func("verify_mfa"), "_directory_step_up_refusal"), (
        "verify_mfa no longer asks the directory before a code renews the window; the identity-"
        "provider row and the reconciliation section say it does (BACKLOG #2023)."
    )
    # A re-proof failure skips the sign-in counter only while the SIGN-IN lock is live, which is
    # what the step-up section says. _live_lock reads locked_until and nothing else.
    # (A second_step_locked call further down gates only the success path's counter clear.)
    reproof = _service_func("_reproof_serialized")
    locked_at = [
        ast.unparse(n.value)
        for n in ast.walk(reproof)
        if isinstance(n, ast.Assign)
        and any(isinstance(tg, ast.Name) and tg.id == "locked" for tg in n.targets)
    ]
    assert locked_at == ["current is not None and _live_lock(current, now)"], (
        f"_reproof_serialized now decides the live lock as {locked_at}; the step-up section says "
        "a re-proof skips the sign-in counter only 'while the sign-in lock is live'."
    )
    # And the guard around the sign-in charge tests that value and nothing more. Only an If whose
    # own statements make the charge, so the outer `if not verdict:` is not collected.
    expected_guard = ast.dump(ast.parse("current is not None and not locked", mode="eval").body)
    charge_guards = [
        n.test
        for n in ast.walk(reproof)
        if isinstance(n, ast.If)
        and any(not isinstance(s, ast.If) and _called(s, "_register_failure") for s in n.body)
    ]
    assert [ast.dump(g) for g in charge_guards] == [expected_guard], (
        f"_reproof_serialized now guards the sign-in charge with "
        f"{[ast.unparse(g) for g in charge_guards]}; the step-up section says it is skipped only "
        "while the sign-in lock is live."
    )
    # The IdP leg refuses the grant only for these actions, which is what both OIDC passages say.
    blocked_hash = _service_func("_factor_binding_is_blocked_hash")
    assert any(
        isinstance(n, ast.Compare)
        and ast.unparse(n) == "purpose not in self._PENDING_REFUSED_ACTIONS"
        for n in ast.walk(blocked_hash)
    ), (
        "_factor_binding_is_blocked_hash no longer consults _PENDING_REFUSED_ACTIONS; both OIDC "
        "passages say the IdP leg refuses the grant only for those actions."
    )
    assert {
        service_module.STEP_UP_ACTION_MFA_ENROLL,
        service_module.STEP_UP_ACTION_MFA_CONFIRM,
        service_module.STEP_UP_ACTION_WEBAUTHN_ENROLL,
        service_module.STEP_UP_ACTION_SESSION_TERMINATE,
    } == AuthService._PENDING_REFUSED_ACTIONS and _called(
        _service_func("complete_oidc_step_up"), "_factor_binding_is_blocked_hash"
    ), (
        "the IdP leg's grant refusal changed; the OIDC row and the Federated section say it covers "
        "a factor-binding or session-terminate action."
    )
    reauth = _service_func("reauth")
    body = [
        s
        for s in reauth.body
        if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
    ]
    first = body[0]
    assert (
        isinstance(first, ast.If)
        and _called(first.test, "session_steps_up_at_idp")
        and any(isinstance(s, ast.Return) for s in first.body)
        and not _called(first, "_reproof")
    ), (
        "reauth() no longer refuses an oidc session before any verify; the AD row, Table A and the "
        "step-up section say the bind never reaches such a session."
    )
    steps_up = _service_func("session_steps_up_at_idp")
    returned = [
        ast.unparse(n.value) for n in ast.walk(steps_up) if isinstance(n, ast.Return) and n.value
    ]
    # Exact, so an inverted polarity (`!=`, or a key on the account) reds too.
    assert "session is not None and session.auth_mechanism == SessionMechanism.OIDC.value" in (
        returned
    ), (
        "session_steps_up_at_idp no longer keys on the session's mechanism; the step-up section says "
        "the session decides whether the step-up goes to the IdP, not the account."
    )
    # The other half of that sentence: past the IdP branch the ACCOUNT's provider picks the password
    # or the re-bind leg, which is why a NULL-mechanism row on an AD account takes the re-bind.
    directory_kw = [
        kw.value
        for n in ast.walk(reauth)
        if isinstance(n, ast.Call) and _called(n, "_reproof")
        for kw in n.keywords
        if kw.arg == "directory"
    ]
    assert directory_kw and all(
        ast.unparse(v) == "identity.auth_provider is AuthProvider.AD" for v in directory_kw
    ), (
        "reauth() no longer picks the password or re-bind leg from the account's provider; the "
        "step-up section and Table A's identity-provider row say it does."
    )
    complete = _service_func("complete_oidc_step_up")
    assert _called(complete, "mark_session_reauthed") and _called(
        complete, "_grant_action_step_up"
    ), "the IdP step-up no longer stamps the window or mints the grant; restate both tables."
    # Every function on the IdP leg, not only the success path: refusals return through
    # _step_up_refused, and a cancel at the IdP through abandon_oidc_step_up.
    for leg in (
        "begin_oidc_step_up",
        "complete_oidc_step_up",
        "abandon_oidc_step_up",
        "_step_up_refused",
    ):
        body_of_leg = _service_func(leg)
        for charge in (
            "reauth",
            "_reproof",
            "_register_failure",
            "_charge_reproof_failure",
            "_record_reproof_lockout",
            "_record_lock",
            "_revoke_for_budget",
            "increment_login_failure",
        ):
            assert not _called(body_of_leg, charge), (
                f"{leg} now calls {charge}; the OIDC row and the step-up section say a refused IdP "
                "step-up feeds no lockout counter and no per-session cap."
            )
        for lock_check in (
            "sign_in_locked",
            "second_step_locked",
            "_live_lock",
            # The sign-in leg's own lock-refusing helper, the likeliest thing to be copied in.
            "_directory_login_refusal",
            # verify_mfa's lock helper, which reads the second-step lock inside it.
            "_mfa_lock_refused",
        ):
            assert not _called(body_of_leg, lock_check), (
                f"{leg} now reads the account lock ({lock_check}); the doc says the lock does not "
                "refuse the IdP step-up."
            )
        lock_columns = {
            a.attr
            for a in ast.walk(body_of_leg)
            if isinstance(a, ast.Attribute)
            and a.attr in {"locked_until", "second_step_locked_until"}
        }
        assert not lock_columns, (
            f"{leg} now reads {sorted(lock_columns)}; the doc says the lock does not refuse the IdP "
            "step-up."
        )
    service_tree = ast.parse(inspect.getsource(AuthService))
    minters = sorted(
        n.name
        for n in ast.walk(service_tree)
        if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef)
        and n.name != "_grant_action_step_up"
        and _called(n, "_grant_action_step_up")
    )
    assert minters == ["complete_oidc_step_up", "reauth"], (
        f"the action-bound grant is minted by {minters}; Table A's grant row names exactly two."
    )
    login_local = _service_func("_login_local")
    seeds = [
        kw.value
        for n in ast.walk(login_local)
        if isinstance(n, ast.Call) and _called(n, "_issue_session")
        for kw in n.keywords
        if kw.arg == "seed_reauth"
    ]
    # Exact, so a changed combination (an `and` for the `or`, `is` for `is not`) reds too.
    assert seeds and all(
        ast.unparse(v) == "combined or (not mfa_required and address is not _LoginAddress.NEW)"
        for v in seeds
    ), (
        "_login_local's seed no longer depends on the first-seen address and the combined sign-in; "
        "the step-up section's seeding sentence says it does."
    )

    raw = _doc_text()
    text = " ".join(raw.split())
    for retired in (
        # The AD row said the bind re-proves sessions OIDC minted.
        "the session's MFA state was decided at sign-in by Kerberos or OIDC",
        "where it re-proves a session **another** pathway minted",
        "where it re-proves a session another pathway minted",
        # Table A keyed the re-proof on the account's provider.
        "the step-up re-proof for that identity becomes a **live directory re-bind**",
        # Table A said only the password leg mints the grant.
        "a single-use grant minted only by `reauth(purpose=…)`, on the",
        # The step-up section keyed POST /me/reauth on the provider and missed the IdP leg.
        "performs a **live Active Directory re-bind** for AD accounts, so AD operators can still step up",
        "`reauth_at` is refreshed by **`POST /me/reauth`** and the console's `POST /ui/reauth`, so a",
        "This re-proves the password (secondary verification)",
        # The step-up section's unconditional local seed (BACKLOG #288 made it conditional).
        "the **initial login counts as the first verification**",
        # A TOTP renews the window unless the SECOND-STEP lock is live (ADR 0197), not any lock.
        "at any time the account is not locked",
        # The same drift, in the passages the vault re-read listed.
        "because their grant needs the re-bind",
        "The live re-bind happens only in `POST /me/reauth`",
        "The two self-service terminates are **password-only** step-ups",
        "the enroll/confirm routes sit behind an action-bound **password** step-up",
        "sits behind the **password-only re-proof**",
        "the mandatory password leg of `POST /ui/reauth` still stamps step-up freshness",
        # The ceremony count that contradicted this module's own route list.
        "3 JSON + 4 console ceremony routes",
        # BACKLOG #2023: verify_mfa asks the directory first, so a code no longer renews a
        # disabled directory account's window, and a step-up is not the only directory check.
        "It still can with an engine TOTP or recovery code",
        "The live directory check happens only in a step-up",
        # Review round 1: a live SECOND-STEP lock does not stop a re-proof charging the sign-in
        # counter; a Kerberos session re-proves the directory password, not its ticket; only two
        # console legs mint the grant; the grant refusal covers four actions; the reconciler and
        # the sign-ins also ask the directory.
        "counter, except during a live lock, when it is charged",
        "This re-proves the session's sign-in credential",
        "the console's step-up legs, the IdP one included, mint it",
        "a pending session on an account with a factor, as on the password leg)",
        "a pending session on an account with a factor). Console only",
        "The live directory check happens only when a session renews",
        # Review round 2: the same sign-in-lock rule, worded as "a live lock" in the lockout section.
        "During a live lock a failure is charged to the session only",
    ):
        assert retired not in text, (
            f"docs/SECURITY.md says {retired!r} again; the code contradicts it (BACKLOG #1133)."
        )

    rows = _primary_table()[1:]
    ad = next(r for r in rows if r[0].startswith("**AD**"))
    assert "**Kerberos** minted" in ad[1] and "NULL" in ad[1], (
        "the AD row must scope the bind to Kerberos sessions and the NULL-mechanism rows."
    )
    oidc_row = next(r for r in rows if r[0].startswith("**OIDC federation**"))
    for cell, label in ((oidc_row[2], "Brute-force defense"), (oidc_row[3], "Notes")):
        assert "`POST /ui/reauth/oidc`" in cell, (
            f"the OIDC row's {label} cell must name the federated step-up leg."
        )
    assert "`max_age=0`" in oidc_row[3], (
        "the OIDC Notes cell must say the IdP must re-authenticate."
    )
    block = _section()
    where = block[block.index("**Where each pathway is enforced") :].split("\n\n", 1)[0]
    assert "`POST /ui/reauth/oidc`" in where, (
        "the enforcement map must name the federated step-up leg among the OIDC routes."
    )
    grant_row = next(
        line for line in raw.splitlines() if line.startswith("| Action-bound step-up grant")
    )
    assert "complete_oidc_step_up" in grant_row, (
        "Table A's grant row must name the IdP leg among what mints the grant."
    )
    step_up = " ".join(_heading_block("### Step-up re-verification").split())
    for token in ("complete_oidc_step_up", "| OIDC (`oidc`) |", "First-seen sign-in address"):
        assert token in step_up, f"the step-up section must state {token!r}."


#: Every name that reads the SIGN-IN lock: the row's predicate, its column, the service's helper,
#: and the directory sign-in's refusal helper, which reads it one call down.
_SIGN_IN_LOCK_READS = frozenset(
    {"sign_in_locked", "locked_until", "_live_lock", "_directory_login_refusal"}
)


def _names_read(node: ast.AST) -> set[str]:
    """Every attribute and bare name ``node`` mentions, calls included."""
    out: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, ast.Name):
            out.add(n.id)
    return out


def _flow_cache_full_statuses(func: ast.AST) -> list[int]:
    """The ``status_code=`` literal every ``except FlowCacheFullError`` handler in ``func`` returns."""
    out: list[int] = []
    for n in ast.walk(func):
        if not isinstance(n, ast.ExceptHandler) or n.type is None:
            continue
        if ast.unparse(n.type) != "FlowCacheFullError":
            continue
        for ret in (r for r in ast.walk(n) if isinstance(r, ast.Return) and r.value is not None):
            for call in (c for c in ast.walk(ret) if isinstance(c, ast.Call)):
                for kw in call.keywords:
                    if kw.arg == "status_code" and isinstance(kw.value, ast.Constant):
                        assert isinstance(kw.value.value, int)
                        out.append(kw.value.value)
    return out


def test_the_sixth_sweep_states_both_adr_0197_locks_in_the_lock_prose() -> None:
    """ASVS 6.1.3 was held at partial a fifth time (BACKLOG #1133), and BACKLOG #2293 filed four more.

    ADR 0197 (engine PR 1700) split the account lock in two: a SIGN-IN lock (``locked_until``) and a
    SECOND-STEP lock (``second_step_locked_until``). The 6.1.3 and 6.1.1 prose still spoke of one
    lock, "enforced wherever a pathway signs in or proves a second factor", and cited
    ``finish_webauthn_assertion`` as checking ``locked_until``. Neither is true. This pins what the
    code does, then refuses every phrasing that said otherwise:

    1. The two second-factor legs read the second-step lock only. ``verify_mfa`` refuses through
       ``_mfa_lock_refused``; ``finish_webauthn_assertion`` reads ``second_step_locked`` itself.
    2. The local sign-in refuses on the second-step lock, or on the sign-in lock unless combined.
       A directory sign-in refuses on either lock.
    3. A good code or passkey writes ``record_login_success``, which clears both locks, so the
       successful-login write runs under a live sign-in lock. The IdP step-up does not write it.
    4. ``GET /ui/oidc/callback`` charges the sign-in window before it picks the step-up branch, so a
       flood on the sign-in surface can deny an ``oidc`` session its IdP step-up.
    5. ``POST /ui/reauth/oidc`` stages into the same flow cache, and answers a full one with 429,
       where the sign-in start answers 303.
    """
    # 1. The second-factor legs.
    assertion = _service_func("finish_webauthn_assertion")
    assert "second_step_locked" in _names_read(assertion), (
        "finish_webauthn_assertion no longer reads the second-step lock; the lockout paragraph's "
        "table says that lock refuses the assertion leg."
    )
    assert not _names_read(assertion) & _SIGN_IN_LOCK_READS, (
        f"finish_webauthn_assertion now reads {sorted(_names_read(assertion) & _SIGN_IN_LOCK_READS)}; "
        "the doc says the sign-in lock refuses no second-factor leg."
    )
    lock_refused = _service_func("_mfa_lock_refused")
    assert "second_step_locked" in _names_read(lock_refused), (
        "_mfa_lock_refused no longer tests the second-step lock; the doc says that lock refuses the "
        "TOTP/recovery leg."
    )
    verify = _service_func("verify_mfa")
    for fn, label in ((lock_refused, "_mfa_lock_refused"), (verify, "verify_mfa")):
        assert not _names_read(fn) & _SIGN_IN_LOCK_READS, (
            f"{label} now reads {sorted(_names_read(fn) & _SIGN_IN_LOCK_READS)}; the doc says the "
            "sign-in lock does not refuse the TOTP/recovery leg."
        )
    assert _called(verify, "_mfa_lock_refused"), "verify_mfa no longer refuses a locked account."

    # 2. The sign-in legs. Exact, so a flipped `and not combined` reds too.
    #
    # The refusal's audit write is now a nested ``async def`` queued to run inside the failure pad
    # (BACKLOG #1131), and it names the action through ``LOGIN_LOCKED_ACTION``, so the If is found
    # by any ``_audit`` call in its body, however deep, that names the locked action either way.
    login_local = _service_func("_login_local")
    refusal_tests = [
        n.test
        for n in ast.walk(login_local)
        if isinstance(n, ast.If)
        and any(
            _called(s, "_audit")
            and ("auth.login_locked" in ast.unparse(s) or "LOGIN_LOCKED_ACTION" in ast.unparse(s))
            for s in n.body
        )
    ]
    expected_refusal = ast.parse(
        "user.second_step_locked(now) or (user.sign_in_locked(now) and not combined)", mode="eval"
    ).body
    assert [ast.dump(t) for t in refusal_tests] == [ast.dump(expected_refusal)], (
        f"_login_local now refuses a locked account on {[ast.unparse(t) for t in refusal_tests]}; "
        "restate the lock table."
    )
    directory = ast.parse(inspect.getsource(_directory_login_refusal))
    assert {"locked_until", "second_step_locked_until"} <= _names_read(directory), (
        "_directory_login_refusal no longer reads both locks; the doc says either refuses a "
        "Kerberos or OIDC sign-in."
    )

    # 3. What writes the successful-login clear, which the Recovery paragraph enumerates.
    service_tree = ast.parse(inspect.getsource(AuthService))
    writers = sorted(
        n.name
        for n in ast.walk(service_tree)
        if isinstance(n, ast.AsyncFunctionDef | ast.FunctionDef)
        and _called(n, "record_login_success")
    )
    assert writers == [
        "_complete_ad_login",
        "_login_local",
        "_reproof_serialized",
        "finish_webauthn_assertion",
        "verify_mfa",
    ], f"record_login_success is now written by {writers}; restate the Recovery paragraph."
    for fn_name in ("identity_for_token", "_build_identity"):
        read = _names_read(_service_func(fn_name)) & (
            _SIGN_IN_LOCK_READS | {"second_step_locked", "second_step_locked_until"}
        )
        assert not read, (
            f"{fn_name} now reads {sorted(read)}; the Recovery paragraph says session validation "
            "consults neither lock."
        )

    # 4. The callback charges the sign-in window before it picks the step-up branch.
    routes = _console_route_funcs()
    callback = routes["GET /ui/oidc/callback"]
    charge_at = [i for i, s in enumerate(callback.body) if _called(s, "allow_login_attempt")]
    branch_at = [i for i, s in enumerate(callback.body) if _called(s, "oidc_flow_is_step_up")]
    assert charge_at and branch_at and charge_at[0] < branch_at[0], (
        "GET /ui/oidc/callback no longer charges allow_login_attempt before its step-up branch; the "
        "limiter-split residual in the 6.1.1 section says it does."
    )
    reauth_oidc = routes["POST /ui/reauth/oidc"]
    assert _called(reauth_oidc, "allow_reauth_attempt") and not _called(
        reauth_oidc, "allow_login_attempt"
    ), "POST /ui/reauth/oidc changed limiter; control 7's 'what remains' cell names limiter 3."

    # 5. The flow cache's two start legs.
    assert _called(reauth_oidc, "begin_oidc_step_up")
    assert _flow_cache_full_statuses(reauth_oidc) == [429], (
        "POST /ui/reauth/oidc no longer answers a full flow cache with 429; control 7 says it does."
    )
    assert _flow_cache_full_statuses(routes["POST /ui/oidc/start"]) == [303], (
        "POST /ui/oidc/start no longer answers a full flow cache with 303; control 7 says it does."
    )
    for leg in ("begin_oidc_step_up", "begin_oidc_login"):
        caches = [
            ast.unparse(n.args[0])
            for n in ast.walk(_service_func(leg))
            if isinstance(n, ast.Call)
            and ast.unparse(n.func).split(".")[-1] == "start_flow"
            and n.args
        ]
        assert caches == ["self._oidc_flows"], (
            f"{leg} now stages into {caches}; control 7 says both start legs share one flow cache."
        )
    # The step-up start's 429 carries no Retry-After, which three passages say. The page it renders
    # comes from reauth_idp_response, so neither function may set a header.
    oidc_module = ast.parse((_CONSOLE_ROUTES / "oidc.py").read_text(encoding="utf-8"))
    idp_page = next(
        n
        for n in ast.walk(oidc_module)
        if isinstance(n, ast.FunctionDef) and n.name == "reauth_idp_response"
    )
    for fn, label in ((reauth_oidc, "POST /ui/reauth/oidc"), (idp_page, "reauth_idp_response")):
        # A READ of request.headers (a Sec-Fetch-Mode check) is fine; a write to a response's is not.
        sets_header = any(
            (isinstance(n, ast.keyword) and n.arg == "headers")
            or (isinstance(n, ast.Constant) and n.value == "Retry-After")
            or (
                isinstance(n, ast.Subscript)
                and isinstance(n.ctx, ast.Store)
                and isinstance(n.value, ast.Attribute)
                and n.value.attr == "headers"
            )
            or (
                isinstance(n, ast.Attribute)
                and n.attr == "headers"
                and isinstance(n.ctx, ast.Store)
            )
            for n in ast.walk(fn)
        )
        assert not sets_header, (
            f"{label} now sets a header; the doc says the step-up start's 429 has no Retry-After."
        )

    # The Recovery paragraph's "a good password re-proof clears neither lock" and "nothing reaches it
    # under a live second-step lock" rest on this guard, the only one on the re-proof's clear.
    reproof = _service_func("_reproof_serialized")
    cleared = [
        n.value
        for n in ast.walk(reproof)
        if isinstance(n, ast.Assign)
        and any(isinstance(tg, ast.Name) and tg.id == "cleared" for tg in n.targets)
    ]
    assert len(cleared) == 1, "_reproof_serialized no longer assigns `cleared` exactly once."
    guard = cleared[0]
    assert isinstance(guard, ast.BoolOp) and isinstance(guard.op, ast.And), (
        "_reproof_serialized no longer decides its lockout clear in one `cleared = ... and ...`."
    )
    terms = [ast.unparse(v) for v in guard.values]
    assert "not locked" in terms and "not current.second_step_locked(now)" in terms, (
        f"_reproof_serialized now clears the lockout on {terms}; the Recovery paragraph says a good "
        "password re-proof clears neither lock while either is live."
    )

    raw = _doc_text()
    text = " ".join(raw.split())
    for retired in (
        # Item 1 of the fifth re-read: one lock, enforced on every leg, read as `locked_until`.
        "wherever a pathway signs in or proves a second factor against an engine account row",
        "`finish_webauthn_assertion` checks `locked_until` first",
        "so the lock is *enforced* across every factor leg",
        "adds a refusal for a directory account and exempts none from the lock.",
        # Item 2: Table A named one exception for the sign-in lock.
        "except that the sign-in lock does **not** refuse a combined sign-in",
        "The **sign-in** lock refuses a password-only sign-in but **not** a combined one",
        "lock refuses every sign-in and the second step.",
        # Item 3: the limiter split claimed every signed-in operator was covered.
        "could otherwise exhaust it and deny re-authentication",
        # Item 4: the #1138 note's subject is the sign-in lock, which does not refuse verify_mfa.
        "and the lock still refuses the code leg",
        # Item 5: the Recovery paragraph missed the code and passkey legs' clear.
        "Two of the four can run while a lock is live",
        # Review round 1: the failed-attempt write runs under a live lock too.
        "Three of the four can run while a lock is live",
        # Review round 2: a directory account with TOTP cannot pass its sign-in lock either.
        "or the sign-in lock on an account with no TOTP.",
        "so that write is not reached under a live lock except by a combined",
        "A good step-up re-auth during a lock does not clear it either",
        "consults `locked_until`, the lock does not refuse this re-proof",
        # Found by the sweep: one lock named where two exist.
        "as long as an attacker sustains the lock — only the host-gated",
        "they read the lock only once the ticket",
        "The re-proofs are not refused by the lock;",
        "**not** refused by the lock; the IdP step-up",
        "the re-proofs are not refused by it,",
        "and the account lock does not refuse it.",
        "The account lock does not refuse this password re-proof",
        # BACKLOG #2293 items b and c: one start leg, one answer.
        "which the start leg turns into a **303 redirect",
        "flooding the OIDC start leg (`POST /ui/oidc/start`",
        "limiter 2 (the same routes charge `allow_login_attempt` first)",
    ):
        assert retired not in text, (
            f"docs/SECURITY.md says {retired!r} again; against the two-lock code it is false or "
            "incomplete (BACKLOG #1133, #2293)."
        )

    # The lock table, row by row. Keyed on its header, so a restructure reds rather than passes.
    lock_tables = [
        t
        for t in _tables(_section())
        if t[0]
        == [
            "Leg",
            "Sign-in lock (`locked_until`)",
            "Second-step lock (`second_step_locked_until`)",
        ]
    ]
    assert len(lock_tables) == 1, "the lockout paragraph's two-lock table is gone."
    rows = {r[0]: (r[1], r[2]) for r in lock_tables[0][1:]}
    no, yes = "does **not** refuse", "refuses"
    expected = {
        "Local password-only sign-in": (yes, yes),
        "Combined sign-in (password and TOTP code), local account with TOTP enrolled": (no, yes),
        "Kerberos and OIDC sign-in (`_directory_login_refusal`)": (yes, yes),
        "TOTP/recovery leg (`verify_mfa`, through `_mfa_lock_refused`)": (no, yes),
        "Passkey assertion leg (`finish_webauthn_assertion`)": (no, yes),
        "The two password re-proofs, and an `oidc` session's IdP step-up": (no, no),
    }
    assert rows == expected, f"the two-lock table now reads {rows}."

    table_a = next(
        line
        for line in raw.splitlines()
        if line.startswith("| Consecutive credential failures on one account")
    )
    for token in ("The sign-in lock has **two** exceptions", "it refuses **no** second-factor leg"):
        assert token in table_a, f"Table A's failures row must state {token!r}."
    for token in (
        "**An `oidc` session's step-up is not covered, and that is a residual of the shipped code.**",
        "`allow_login_attempt` runs ahead of `oidc_flow_is_step_up`",
        "Only the second-step lock refuses the code leg.",
        "Three of the four can end a lock that is still live",
        "The successful-login write can end a live **sign-in** lock only",
        "it clears only its own counter's lock, and only once that lock has lapsed",
        "a sign-in reaches the successful-login write under a live sign-in lock only as a combined",
        "the sign-in lock on any account except a local one with TOTP enrolled",
        "Only the second-step lock refuses those last two legs",
        "turns it into a **429** that re-renders the step-up page",
    ):
        assert token in text, f"docs/SECURITY.md must state {token!r} (BACKLOG #1133, #2293)."

    # BACKLOG #2293 item a: POST /ui/reauth/oidc among the routes that send no Retry-After.
    none_clause = text.split("`POST /ui/mfa` (control 3);", 1)[1].split("carry none.", 1)[0]
    assert "`POST /ui/reauth/oidc`" in none_clause, (
        "the 6.1.1 paragraph's no-Retry-After list must name POST /ui/reauth/oidc."
    )
    # Items b and c: control 7 names the step-up start, and what remains under it.
    control7 = next(line for line in raw.splitlines() if line.startswith("| 7 | **Federated"))
    for token in ("`POST /ui/reauth/oidc`", "`begin_oidc_step_up`", "`allow_reauth_attempt`"):
        assert token in control7, f"control 7 must name {token!r}."
    # Item d: the console sign-in section states the combined sign-in.
    console = " ".join(_heading_block("## Web console sign-in").split())
    for token in ("**combined sign-in**", "**authenticator code**", "never a recovery code"):
        assert token in console, f"the web console sign-in section must state {token!r}."


# NOTE: test_the_mtls_runbook_and_the_table_cannot_diverge moved to tests/test_off_loopback_runbook.py (2026-07-26). They asserted against
# the deny-listed off-loopback runbook, so on the public mirror they failed at runtime and took
# this whole module's required test leg red — while the rest of this file guards shipped
# behaviour that must keep running publicly. The new home already carries the doc-absent guard.


#: Every ``AuthService`` method the 6.8.4 table's Where column cites. An exact set, so a dropped or
#: added citation forces a re-read of the rows rather than passing on a count.
_FALLBACK_CITES = frozenset(
    {
        "_login_local",
        "verify_mfa",
        "finish_webauthn_assertion",
        "_authenticate_kerberos",
        "_complete_ad_login",
        "_unverified_session_owes_factor",
        "reauth",
        "_authenticate_oidc",
        "begin_oidc_step_up",
        "complete_oidc_step_up",
    }
)

_H_FALLBACK = (
    "### With no strength or recency from the identity provider, the engine assumes the minimum"
)


def _calls_method(func: Any, name: str) -> bool:
    """Whether ``func``'s own body calls ``name`` (a call, not a mention): :func:`_called` on its
    source."""
    return _called(ast.parse(textwrap.dedent(inspect.getsource(func))), name)


def test_the_6_8_4_fallback_statement_names_live_code_and_states_its_minimum() -> None:
    """ASVS 6.8.4's documented fallback (BACKLOG #2031) cites code by name, so pin the names and the
    facts its rows rest on. A renamed symbol or a flipped constant reds here instead of leaving the
    vault's 6.8.4 cell reading a statement that is no longer true.

    NOT PINNED, stated so nobody reads the test as wider than it is: a directory leg that stamps the
    step-up window through some other call AFTER ``_complete_ad_login`` mints; the local leg's
    ``seed_reauth`` expression; and ``pyspnego`` surfacing no strength (the engine reads only the
    principal, which is a property of the library and not of this repository).
    """
    from messagefoundry.auth import webauthn as webauthn_module
    from messagefoundry.auth.oidc import claims as claims_module

    block = _heading_block(_H_FALLBACK)
    cited = set(re.findall(r"`AuthService\.(\w+)`", block))
    assert cited == _FALLBACK_CITES, (
        f"the 6.8.4 table's AuthService citations changed: {sorted(cited ^ _FALLBACK_CITES)}. "
        "Re-read the rows against the code, then update _FALLBACK_CITES."
    )
    for name in sorted(cited):
        assert hasattr(AuthService, name), f"the 6.8.4 fallback cites AuthService.{name}, gone"
    for name in ("_check_auth_time", "_check_mfa_gate"):
        assert f"`{name}`" in block and hasattr(claims_module, name), name
    # The BACKLOG #2032 paragraph cites the load refusal and the check advisory by name.
    from messagefoundry import checks as checks_module

    assert "`AuthSettings._require_oidc_fields`" in block
    assert hasattr(AuthSettings, "_require_oidc_fields")
    assert "`_check_oidc_auth_params`" in block and hasattr(
        checks_module, "_check_oidc_auth_params"
    )
    for slug in ("auth_time_missing", "auth_time_stale", "mfa_claim_missing"):
        assert f"`{slug}`" in block and slug in claims_module.REASONS, slug
    assert f"`{service_module.STEP_UP_NOT_FRESH}`" in block

    # Kerberos minting at the minimum is pinned by
    # test_the_directory_rows_disclose_what_each_leg_actually_grants. This pins the OIDC half more
    # tightly than "not a constant": the grant is a name bound to the claim-gate setting itself.
    oidc_grant = mfa_grant_values(AuthService._authenticate_oidc)
    assert oidc_grant and all(isinstance(v, ast.Name) for v in oidc_grant)
    oidc_tree = ast.parse(textwrap.dedent(inspect.getsource(AuthService._authenticate_oidc)))
    bound = [
        n.value
        for n in ast.walk(oidc_tree)
        if isinstance(n, ast.Assign)
        and any(isinstance(g, ast.Name) and g.id == "mfa_verified" for g in n.targets)
    ]
    assert bound and all(
        isinstance(v, ast.Attribute) and v.attr == "oidc_require_mfa_claim" for v in bound
    ), "the OIDC grant is no longer [auth].oidc_require_mfa_claim; re-word the strength row"
    # "No directory sign-in opens the step-up window": the seed is a constant False in the one seam.
    seeds = keyword_values(AuthService._complete_ad_login, "seed_reauth")
    assert seeds and all(isinstance(v, ast.Constant) and v.value is False for v in seeds), (
        "_complete_ad_login no longer mints every directory session with seed_reauth=False; the "
        "6.8.4 fallback says no directory sign-in opens the step-up window."
    )
    # The AD re-bind and the IdP step-up stamp the window and never mark the second factor; the
    # passkey marks the factor and never stamps the window. Controls: the TOTP leg does both.
    for func in (AuthService.reauth, AuthService.complete_oidc_step_up):
        assert _calls_method(func, "mark_session_reauthed"), func.__name__
        assert not _calls_method(func, "mark_session_mfa_verified"), func.__name__
    assert _calls_method(AuthService.finish_webauthn_assertion, "mark_session_mfa_verified")
    assert not _calls_method(AuthService.finish_webauthn_assertion, "mark_session_reauthed")
    assert _calls_method(AuthService.verify_mfa, "mark_session_mfa_verified")
    assert _calls_method(AuthService.verify_mfa, "mark_session_reauthed")
    # The passkey is not relied on for user verification: asked for at PREFERRED, never required.
    assert "`verify_assertion`" in block
    uv_required = keyword_values(webauthn_module.verify_assertion, "require_user_verification")
    assert all(isinstance(v, ast.Constant) and v.value is False for v in uv_required), (
        "passkey assertions now require user verification; re-word the row"
    )
    uv_asked = keyword_values(webauthn_module.assertion_options, "user_verification")
    assert uv_asked and all(
        isinstance(v, ast.Attribute) and v.attr == "PREFERRED" for v in uv_asked
    ), "passkey assertions no longer ask for user_verification=preferred; re-word the row"
    # The defaults the rows quote.
    auth = AuthSettings()
    assert auth.oidc_require_mfa_claim is True
    assert auth.oidc_required_acr_values == []
    assert auth.oidc_mfa_amr_values == ["mfa"]


#: Every package that could declare an engine-API or console route.
_ROUTE_PACKAGES = (_ROOT / "messagefoundry", _ROOT / "messagefoundry_webconsole")


def _service_cert_call_sites() -> list[tuple[str, str, list[str]]]:
    """Each ``require_service_cert(...)`` call: its file, the nearest enclosing function, and that
    function's decorators. Found by AST over every source file, so a second gated route reds."""
    out: list[tuple[str, str, list[str]]] = []
    for pkg in _ROUTE_PACKAGES:
        for path in sorted(pkg.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parent = {
                child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
            }
            for n in ast.walk(tree):
                if not (
                    isinstance(n, ast.Call)
                    and ast.unparse(n.func).split(".")[-1] == "require_service_cert"
                ):
                    continue
                up: ast.AST | None = parent.get(n)
                while up is not None and not isinstance(up, ast.AsyncFunctionDef | ast.FunctionDef):
                    up = parent.get(up)
                name, decorators = ("<module>", []) if up is None else (up.name, up.decorator_list)
                rel = path.relative_to(_ROOT).as_posix()
                out.append((rel, name, [ast.unparse(d) for d in decorators]))
    return out


def _name_reference_sites(name: str) -> list[tuple[str, str]]:
    """Each Name or Attribute reference to ``name`` in code (not in a string or a comment): its file
    and the MODULE-LEVEL function or class holding it, so a closure reports its factory."""
    out: list[tuple[str, str]] = []
    for pkg in _ROUTE_PACKAGES:
        for path in sorted(pkg.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for top in tree.body:
                holder = getattr(top, "name", "<module>")
                for n in ast.walk(top):
                    if (
                        (isinstance(n, ast.Name) and n.id == name)
                        or (isinstance(n, ast.Attribute) and n.attr == name)
                        or (isinstance(n, ast.alias) and name in (n.name, n.asname))
                    ):
                        out.append((path.relative_to(_ROOT).as_posix(), holder))
    return out


def test_the_seventh_sweep_offers_no_mtls_remedy_and_states_which_locks_double() -> None:
    """ASVS 6.1.3 was held at partial a sixth time (BACKLOG #1133, vault PR 2036) on two sentences.

    1. The L5b paragraph told an MFA-pending bearer-token service account it could move to the mTLS
       service-identity plane. It cannot: ``require_service_cert`` gates one route,
       ``GET /service/identity``. The paragraph also called the ``require_mfa_scope`` row the
       authority on "why mTLS is not a third" remedy, having just offered it as one of two.
    2. The Local pathway row said "each lock doubles ... where the owner has that way past it".
       ``lockout_escalates`` doubles the second-step lock on every local account and the sign-in lock
       only on a local account with TOTP enrolled.

    The reviewer also found the ``administrators`` scope is no remedy for an Administrator-role
    account, and that ``require_mfa = false`` is one. Each is pinned against the code below.
    """
    # 1a. require_service_cert guards exactly one route, and it is GET /service/identity.
    sites = _service_cert_call_sites()
    assert sites == [
        ("messagefoundry/api/app.py", "service_identity", ["app.get('/service/identity')"])
    ], (
        f"require_service_cert is now called from {sites}; restate the L5b paragraph and the mTLS row."
    )
    # The primitive that admits a certificate identity is referenced only inside that dependency, so
    # an aliased import or a direct call on a second route cannot widen the plane unseen.
    refs = _name_reference_sites("resolve_client_cert_identity")
    assert refs == [("messagefoundry/api/security.py", "require_service_cert")], (
        f"resolve_client_cert_identity is now referenced from {refs}; a certificate identity may "
        "reach a route other than GET /service/identity."
    )

    # 1b. _mfa_required_for: the Administrator role stays in scope under both values, and
    # require_mfa = false frees any un-enrolled account. Called on a stand-in self, so this pins the
    # rule the doc states rather than a whole AuthService.
    admin, other = frozenset({Role.ADMINISTRATOR}), frozenset({Role.OPERATOR})
    # A placeholder user: _mfa_required_for reads no field off it, provider included (BACKLOG #1144).
    user: UserRecord = SimpleNamespace(auth_provider=AuthProvider.LOCAL.value)  # type: ignore[assignment]

    def required(scope: str, roles: frozenset[Role], *, on: bool, enrolled: bool) -> bool:
        fake = SimpleNamespace(_settings=SimpleNamespace(require_mfa=on, require_mfa_scope=scope))
        return bool(
            AuthService._mfa_required_for(
                fake,  # type: ignore[arg-type]
                user,
                roles,
                second_factor_enrolled=enrolled,
            )
        )

    for scope in ("administrators", "every_local_account"):
        assert required(scope, admin, on=True, enrolled=False), (
            f"an un-enrolled Administrator is no longer MFA-required under {scope!r}; the L5b "
            "paragraph and the require_mfa_scope row say the scope frees no Administrator."
        )
        assert not required(scope, admin, on=False, enrolled=False), (
            "require_mfa = false no longer frees an un-enrolled Administrator; the doc names it as "
            "the remedy for that account."
        )
        for roles in (admin, other):
            assert required(scope, roles, on=False, enrolled=True), (
                "an enrolled account no longer owes its factor with require_mfa off; the doc says "
                "it must satisfy it under either setting."
            )
    assert required("every_local_account", other, on=True, enrolled=False)
    assert not required("administrators", other, on=True, enrolled=False), (
        "the administrators scope no longer frees a local non-Administrator; the doc names it as "
        "that account's remedy."
    )
    assert not required("administrators", other, on=False, enrolled=False)
    assert not required("every_local_account", other, on=False, enrolled=False)

    # What an UNSTAMPED session owes, which is what the MFA gate asks. It adds the directory floor,
    # so the directory half of both remedies is pinned here: under `administrators` an un-enrolled
    # directory session stays pending, and require_mfa = false frees it.
    def owes(
        provider: str, scope: str, roles: frozenset[Role], *, on: bool, enrolled: bool
    ) -> bool:
        async def role_ids(_user_id: object) -> list[str]:
            return [r.value for r in roles]

        async def second_factor(_user: object) -> bool:
            return enrolled

        fake = SimpleNamespace(
            _settings=SimpleNamespace(require_mfa=on, require_mfa_scope=scope),
            _store=SimpleNamespace(get_user_role_ids=role_ids),
            _second_factor_enrolled=second_factor,
        )
        fake._mfa_required_for = functools.partial(
            AuthService._mfa_required_for,
            fake,  # type: ignore[arg-type]
        )
        account = SimpleNamespace(id="u1", auth_provider=provider)
        return bool(
            asyncio.run(
                AuthService._unverified_session_owes_factor(
                    fake,  # type: ignore[arg-type]
                    account,  # type: ignore[arg-type]
                )
            )
        )

    ad, local = AuthProvider.AD.value, AuthProvider.LOCAL.value
    assert owes(ad, "administrators", other, on=True, enrolled=False), (
        "an unstamped directory session is no longer MFA-pending under administrators; the L5b "
        "paragraph and the require_mfa_scope row say it stays pending under both values."
    )
    assert not owes(local, "administrators", other, on=True, enrolled=False)
    for provider, scope, roles in itertools.product(
        (ad, local), ("administrators", "every_local_account"), (admin, other)
    ):
        assert not owes(provider, scope, roles, on=False, enrolled=False), (
            f"require_mfa = false no longer frees an un-enrolled {provider} session; the doc "
            "says it frees any account that has not enrolled a factor, whatever its role."
        )
        assert owes(provider, scope, roles, on=False, enrolled=True), (
            f"an enrolled {provider} account no longer owes its factor with require_mfa off."
        )

    # 2. lockout_escalates: the whole truth table, so a third condition or a dropped one reds.
    counters = typing.get_args(LockoutCounter)
    assert set(counters) == {"sign_in", "second_step"}
    for counter in counters:
        for provider in ("local", "ad"):
            for totp in (False, True):
                want = provider == "local" and (counter == "second_step" or totp)
                got = lockout_escalates(counter, auth_provider=provider, totp_enabled=totp)
                assert got is want, (
                    f"lockout_escalates({counter!r}, {provider!r}, totp={totp}) is now {got}; the "
                    "Local row, control 1 and Table A say only the second-step lock on a local "
                    "account and the sign-in lock on a local account with TOTP double."
                )

    security = " ".join(_doc_text().split())
    configuration = " ".join(
        (_ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8").split()
    )
    settings_src = " ".join(
        (_ROOT / "messagefoundry" / "config" / "settings.py").read_text(encoding="utf-8").split()
    )
    for label, text in (
        ("SECURITY.md", security),
        ("CONFIGURATION.md", configuration),
        ("settings.py", settings_src),
    ):
        for retired in (
            "account moves to the mTLS service-identity plane",
            "why mTLS is not a third",
            "move it to mTLS",
            "where the owner has that way past it",
            "The one remaining fix is **set this to `administrators`**",
            "(or keeps the bind on loopback)",
            "**There is one remedy.** Set `require_mfa_scope",
            "when the API is bound **off-loopback** with `require_mfa`",
        ):
            assert retired not in text, (
                f"{label} says {retired!r} again; against the code it is false (BACKLOG #1133)."
            )
        assert not re.search(r"\bmoves? (?:it |the account )?to (?:the )?mTLS", text), (
            f"{label} offers mTLS as a place to move an account again; it serves one route."
        )

    for token in (
        "two settings answer it, each with a limit. Setting the scope to `administrators` frees "
        "only a **local** account that does not hold the Administrator role.",
        "The Administrator role stays in scope under either value (`AuthService._mfa_required_for`)",
        "Setting `[security].require_mfa = false` frees any account that has not enrolled a factor",
        "Nor is the mTLS service-identity plane: a certificate identity is admitted on one route "
        "only, `GET /service/identity`",
        "why neither AD nor mTLS is a third",
        # An enrolled factor binds only while it is kept: with the requirement off, or outside the
        # scope, the removal guards (_mfa_required_for with second_factor_enrolled=False) let the
        # holder remove the last one.
        "An account that has enrolled a factor owes it while it keeps one, under either setting, "
        "and an OIDC sign-in meets it while `[auth].oidc_require_mfa_claim` is on, the default.",
        "the holder may remove its last factor.",
    ):
        assert token in security, f"docs/SECURITY.md must state {token!r} (BACKLOG #1133)."
    local_row = next(r for r in _primary_table()[1:] if r[0].startswith("**Local**"))
    doubling = (
        "The second-step lock doubles per cycle up to `lockout_max_minutes` on every local "
        "account, and the sign-in lock does so only on a local account with TOTP enrolled; every "
        "other lock keeps `lockout_minutes`"
    )
    assert doubling in " ".join(local_row[2].split()), (
        "the Local row's brute-force cell must state which locks double, as lockout_escalates does."
    )
    for token in (
        "**Set this to `administrators`**, which frees only a **local** account that does not "
        "hold the Administrator role",
        "Or **set `require_mfa = false`**, which frees any account that has not enrolled a factor",
        "**With `require_mfa` kept on, there is one remedy.** Set `require_mfa_scope",
    ):
        assert token in configuration, (
            f"docs/CONFIGURATION.md must state {token!r} (BACKLOG #1133)."
        )


def test_the_eighth_sweep_names_both_ways_past_the_intake_revocation_refusal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """ASVS 6.1.3 was held at partial a seventh time (BACKLOG #1133, vault PR 2064) on one cell.

    The HTTP intake row's Revocation cell said an ``mtls_subject`` listener under enforcement "must
    also set ``tls_crl_file``, or it is refused at start". ``check_inbound_revocation`` has a second
    way past that refusal: a per-connection ``tls_revocation_attested`` with its mandatory reason,
    which starts the listener and logs a WARNING carrying the reason instead. The code is probed
    first, so a change to the gate reds here before the cell can drift from it.
    """
    settings = {"tls": True, "tls_cert_file": "c.pem", "tls_ca_file": "ca.pem"}
    enforcing = HopPosture(enforcing=True)

    def gate(**fields: Any) -> None:
        check_inbound_revocation(
            Source(type=ConnectorType.HTTP, name="intake-in", **fields),
            "intake-in",
            posture=enforcing,
        )

    with pytest.raises(WiringError):
        gate(settings=settings)
    gate(settings={**settings, "tls_crl_file": "crl.pem"})
    reason = "the partner PKI checks revocation at its gateway"
    # The fragment log_attested_crossing writes; the cell quotes it so an operator can grep for it.
    marker = "on operator attestation"
    with caplog.at_level(logging.WARNING):
        gate(
            settings=settings,
            tls_revocation_attested=True,
            tls_revocation_attested_reason=reason,
        )
    crossings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and marker in r.getMessage() and reason in r.getMessage()
    ]
    assert len(crossings) == 1, (
        f"an attested mTLS listener no longer starts with exactly one WARNING reading {marker!r}; "
        "check_inbound_revocation or log_attested_crossing changed, so restate the HTTP intake "
        "Revocation cell in docs/SECURITY.md to match."
    )

    companion = next(
        t
        for t in _tables(_section())
        if t[0][:2] == ["Pathway", "Phishing resistance"] and "Revocation" in t[0]
    )
    intake = next(r for r in companion[1:] if r[0] == "**HTTP intake**")
    cell = " ".join(intake[-1].split())
    assert "must also set `tls_crl_file`, or it is refused at start" not in cell, (
        "the HTTP intake Revocation cell claims a CRL is the only way past the enforcing refusal "
        "again; check_inbound_revocation also honours tls_revocation_attested (BACKLOG #1133)."
    )
    for token in (
        "`tls_crl_file`",
        "`tls_revocation_attested = true`",
        "`tls_revocation_attested_reason`",
        f"each start logs a WARNING that reads `{marker}` and carries the reason",
    ):
        assert token in cell, (
            f"the HTTP intake Revocation cell must state {token!r}: the enforcing refusal clears on "
            "a CRL file or on the revocation attestation, and the attestation is logged "
            "(BACKLOG #1133)."
        )


_CONFIG_DOC = _ROOT / "docs" / "CONFIGURATION.md"
_H_TABLE_A = "#### Table A — control plane (operator API + web console)"


def _flat(text: str) -> str:
    return " ".join(text.split())


def _table_a_row(attribute: str) -> str:
    """One Table A row, whitespace-flattened, found by its Attribute cell."""
    table = next(t for t in _tables(_heading_block(_H_TABLE_A)) if t[0][0] == "Attribute")
    row = next(r for r in table[1:] if r[0] == attribute)
    return _flat(" | ".join(row))


def _config_row(key: str, kind: str) -> str:
    """The CONFIGURATION.md table row for ``key`` whose Type cell is ``kind``, whitespace-flattened.
    The type tells a live row from a retired alias row, which leaves its Type cell empty."""
    text = _CONFIG_DOC.read_text(encoding="utf-8")
    prefix = f"| `{key}` | {kind} |"
    return _flat(next(line for line in text.splitlines() if line.startswith(prefix)))


def test_the_ninth_sweep_probes_the_amendment_a_order_in_the_code() -> None:
    """The code half of the ninth 6.1.3 re-read (BACKLOG #1133). Each probe is a fact the doc
    sentences below state, so a change here reds before the prose can drift from it."""
    from messagefoundry.auth.service import TOTP_REMOVAL_REFUSED, FactorEnrolmentRequired
    from messagefoundry.store.store import MessageStore, WebAuthnCredential, lockout_arms

    assert (
        frozenset(
            {
                ("POST", "/me/reauth"),
                ("GET", "/me/mfa"),
                ("POST", "/me/mfa/enroll"),
                ("POST", "/me/mfa/confirm"),
            }
        )
        == api_security._ENROL_FIRST_ROUTES
    ), "the enrol-first admitted set moved; restate Table A's must-change row to match"
    assert (
        frozenset({"/auth/logout", "/auth/me", "/auth/mfa-verify", "/me/password"})
        == api_security._MUST_CHANGE_EXEMPT_PATHS
    ), "the must-change exempt set moved; restate Table A's must-change row to match"
    assert not lockout_arms("sign_in", password_generated=True)
    assert lockout_arms("sign_in", password_generated=False)
    assert lockout_arms("second_step", password_generated=True)
    # Item 8: a combined sign-in owes nothing more. ``mfa_required = not combined and ...`` is read
    # from the parsed code, so a comment or docstring cannot keep it green.
    owes = [
        node.value
        for node in ast.walk(_service_func("_login_local"))
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "mfa_required" for t in node.targets)
    ]
    assert len(owes) == 1 and isinstance(owes[0], ast.BoolOp), owes
    first = owes[0].values[0]
    assert (
        isinstance(owes[0].op, ast.And)
        and isinstance(first, ast.UnaryOp)
        and isinstance(first.op, ast.Not)
        and isinstance(first.operand, ast.Name)
        and first.operand.id == "combined"
    ), "a combined sign-in no longer owes nothing more; restate item 8 in Table A"

    async def probe() -> None:
        store = await MessageStore.open(":memory:")
        try:
            service = AuthService(store, AuthSettings())  # require_mfa on, the shipped default
            await service.initialize()
            created = await service.create_local_user(
                username="holder",
                display_name=None,
                email="holder@example.org",
                roles=["viewer"],
                actor="test-admin",
            )
            out = await service.login("holder", created.credential.password)
            assert out.ok and out.identity is not None and out.token is not None
            identity = out.identity
            # Items 1-3: a covered account with no TOTP enrols before it rotates.
            with pytest.raises(FactorEnrolmentRequired):
                await service.change_password(identity, "a-brand-new-chosen-passphrase")
            # Items 2 and 5: its first factor may not be a passkey.
            with pytest.raises(FactorEnrolmentRequired):
                await service.begin_webauthn_registration(
                    identity, token=out.token, rp_id="localhost", rp_name="t"
                )
            off = AuthService(store, AuthSettings(require_mfa=False))
            assert not await off.must_enrol_before_rotating(identity), (
                "with require_mfa off the account should rotate first"
            )
            # Item 6: once TOTP is on, a covered account cannot remove it, passkey or not ...
            await store.enable_totp(identity.user_id, recovery_code_hashes=[])
            await store.add_webauthn_credential(
                WebAuthnCredential(
                    credential_id_hash="ninth-sweep-hash",
                    credential_id="ninth-sweep-id",
                    user_id=identity.user_id,
                    rp_id="localhost",
                    public_key="cose-public-key-b64url",
                    sign_count=0,
                    transports=None,
                    device_type="multi_device",
                    backed_up=True,
                    label="key",
                    aaguid=None,
                    created_at=1000.0,
                )
            )
            with pytest.raises(ValueError) as refused:
                await service.disable_mfa(identity)
            assert str(refused.value) == TOTP_REMOVAL_REFUSED
            # ... while the passkey, which is not its last factor, can go.
            assert await service.delete_webauthn_credential(identity, "ninth-sweep-hash")
            # A local account the requirement does not cover removes TOTP freely.
            await off.disable_mfa(identity)
            row = await store.get_user(identity.user_id)
            assert row is not None and not row.totp_enabled
        finally:
            await store.close()

    asyncio.run(probe())


def test_the_ninth_sweep_states_the_local_pathway_after_amendment_a() -> None:
    """ASVS 6.1.3 was held at partial a ninth time (BACKLOG #1133) on eight sentences left stale by
    ADR 0197 Amendment A wave 1. Under the shipped ``require_mfa`` a covered local account with no
    TOTP enrols TOTP before it may rotate, and a passkey cannot be its first factor. Each assertion
    reds if one of the eight old sentences returns; the probes above pin the code they describe."""
    doc = _flat(_doc_text())
    config = _flat(_CONFIG_DOC.read_text(encoding="utf-8"))

    # 1. The must-change CONFINE row names the enrol-first set and the new order.
    confine = _table_a_row("Account state — credential rotation pending")
    conditional = "With the requirement off, an account with no factor rotates first"
    assert confine.count("no factor rotates first") == confine.count(conditional), (
        "item 1: the must-change row says an account with no factor rotates first, unconditionally"
    )
    for route in ("`POST /me/reauth`", "`GET /me/mfa`", "`POST /me/mfa/enroll`"):
        assert route in confine, f"item 1: the must-change row must name {route}"
    assert "`_ENROL_FIRST_ROUTES`" in confine and "enrols TOTP" in confine

    # 2. The factor-binding row no longer lets a no-factor account rotate from a pending session.
    binding = _table_a_row("Binding a NEW second factor, ending sessions, or changing the password")
    assert "ends its own sessions and changes its password from a password-only session" not in (
        binding
    ), "item 2: the factor-binding row says a no-factor account changes its password pending"
    assert "first factor must be TOTP" in binding

    # 3. A pending no-factor session cannot rotate, in any configuration.
    assert "An account with no factor still changes its password from a pending session" not in doc
    assert "it cannot rotate from a pending session either" in doc

    # 4. A reset passkey-only account also enrols TOTP before it rotates.
    assert "A passkey-only account has to do this on the console" not in doc
    assert "must also enrol TOTP before it rotates" in doc and "`_has_way_past` counts TOTP" in doc

    # 5. CONFIGURATION.md's require_mfa row: TOTP first for a covered local account.
    assert "to enrol TOTP or a passkey." not in config, (
        "item 5: the require_mfa row offers a passkey as a covered local account's first factor"
    )
    assert "enrols **TOTP first**" in _config_row("require_mfa", "bool")

    # 6. TOTP removal refuses on its own condition, and the MFA section says so.
    assert "the same refusal, on the same condition, as the passkey removal path" not in doc
    assert "`DELETE /me/mfa` disables it; an administrator clears" not in doc
    assert "no longer refuse on the same condition" in doc

    # 7. The generated-credential exception, in all three lockout statements.
    lockout = _table_a_row("Consecutive credential failures on one account")
    assert "engine-generated" in lockout and "arm no sign-in lock" in lockout, (
        "item 7: Table A's lockout row omits the generated-credential exception"
    )
    limit_row = _flat(
        next(line for line in _doc_text().splitlines() if line.startswith("| Account lockout |"))
    )
    assert "engine-generated" in limit_row, "item 7: the limits table's lockout row omits it"
    assert "engine-generated" in _config_row("lockout_threshold", "int"), (
        "item 7: CONFIGURATION.md's lockout_threshold row omits it"
    )

    # 8. A combined sign-in is not the owes-a-factor path.
    assert "this is the path every local sign-in takes" not in doc
    assert "every password-only local sign-in takes" in doc


def test_the_tenth_sweep_probes_the_directory_floor_under_both_scopes() -> None:
    """The code half of the tenth 6.1.3 re-read (BACKLOG #1133). The MFA section's scope sentence
    and its directory sentence state these facts, so a change here reds before the prose drifts."""
    from messagefoundry.auth.oidc.claims import ClaimsError, OidcClaimPolicy, _check_mfa_gate

    admin, other = frozenset({Role.ADMINISTRATOR}), frozenset({Role.OPERATOR})
    ad, local = AuthProvider.AD.value, AuthProvider.LOCAL.value

    def satisfied(
        provider: str,
        scope: str,
        roles: frozenset[Role],
        *,
        stamped: bool,
        enrolled: bool = False,
        on: bool = True,
    ) -> bool:
        """``_mfa_satisfied_hash`` for one session, on a stand-in self that supplies every read."""
        account = SimpleNamespace(id="u1", auth_provider=provider)
        session = SimpleNamespace(
            user_id="u1",
            revoked_at=None,
            mfa_verified_at="2026-09-30T00:00:00Z" if stamped else None,
        )

        async def get_session(_hash: str) -> object:
            return session

        async def get_user(_user_id: str) -> object:
            return account

        async def role_ids(_user_id: object) -> list[str]:
            return [r.value for r in roles]

        async def second_factor(_user: object) -> bool:
            return enrolled

        fake = SimpleNamespace(
            _settings=SimpleNamespace(require_mfa=on, require_mfa_scope=scope),
            _store=SimpleNamespace(
                get_session=get_session, get_user=get_user, get_user_role_ids=role_ids
            ),
            _second_factor_enrolled=second_factor,
        )
        fake._mfa_required_for = functools.partial(
            AuthService._mfa_required_for,
            fake,  # type: ignore[arg-type]
        )
        fake._unverified_session_owes_factor = functools.partial(
            AuthService._unverified_session_owes_factor,
            fake,  # type: ignore[arg-type]
        )
        return bool(asyncio.run(AuthService._mfa_satisfied_hash(fake, "h")))  # type: ignore[arg-type]

    scopes = ("administrators", "every_local_account")
    # 1. A directory session that proved no factor (every Kerberos session, and an OIDC one minted
    #    while the claim gate is off) stays pending under BOTH scope values, a non-admin included.
    for scope in scopes:
        for roles in (admin, other):
            assert not satisfied(ad, scope, roles, stamped=False), (
                f"an unstamped directory session is satisfied under {scope!r}; the MFA section says "
                "a directory session that proved no factor owes one under either scope value."
            )
    # 2. `administrators` takes only a local non-Administrator out of scope.
    assert satisfied(local, "administrators", other, stamped=False)
    assert not satisfied(local, "administrators", admin, stamped=False)
    assert not satisfied(local, "every_local_account", other, stamped=False)
    # 3. An enrolled account owes its factor under either value, the freed local non-admin included.
    #    With require_mfa on, the directory floor answers an `ad` row before enrolment is read, so
    #    the off arm is the one that tests the enrolled-factor rule for a directory account.
    for provider in (ad, local):
        for scope in scopes:
            for on in (True, False):
                assert not satisfied(provider, scope, other, stamped=False, enrolled=True, on=on), (
                    f"an enrolled {provider} session is satisfied under {scope!r} (require_mfa "
                    f"{on}) with no stamp; the MFA section says an account that has enrolled a "
                    "factor owes it under either value."
                )
    # 4. The directory floor holds only while require_mfa is on: off, an un-enrolled directory
    #    session is satisfied, which is why the directory sentence opens "While require_mfa is on".
    for scope in scopes:
        for roles in (admin, other):
            assert satisfied(ad, scope, roles, stamped=False, on=False), (
                "require_mfa = false no longer frees an un-enrolled directory session; restate the "
                "MFA section's directory sentence and its opt-out."
            )
    # 5. A session minted with its factor met (the OIDC leg with the claim gate on) is satisfied,
    #    whatever the scope says.
    for scope in scopes:
        assert satisfied(ad, scope, other, stamped=True)

    # 6. The OIDC leg's grant IS the claim-gate setting, so the stamp in 5 is what a federated
    #    session with the claim required gets, and 1 is what it gets with the gate off. The gate
    #    is on by default, as the directory sentence says.
    tree = ast.parse(textwrap.dedent(inspect.getsource(AuthService._authenticate_oidc)))
    grant_sources = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "mfa_verified" for t in node.targets)
    ]
    assert [ast.unparse(v) for v in grant_sources] == ["self._settings.oidc_require_mfa_claim"], (
        "the OIDC leg's mfa_verified is no longer the oidc_require_mfa_claim setting; restate the "
        "MFA section's directory sentence."
    )
    assert [ast.unparse(v) for v in mfa_grant_values(AuthService._authenticate_oidc)] == [
        "mfa_verified"
    ]

    assert AuthSettings.model_fields["oidc_require_mfa_claim"].default is True

    # 7. With the claim required, a token with no configured amr/acr is refused, and one with it passes.
    policy = OidcClaimPolicy(
        issuer="https://idp.example",
        client_id="c",
        signing_algorithms=(),
        nonce="n",
        max_age_seconds=300,
        require_mfa_claim=True,
    )
    with pytest.raises(ClaimsError):
        _check_mfa_gate({"amr": ["pwd"]}, policy)
    assert _check_mfa_gate({"amr": ["mfa"]}, policy) == (("mfa",), None)


def test_the_tenth_sweep_states_the_mfa_scope_reach_for_both_account_kinds() -> None:
    """ASVS 6.1.3 was held at partial a tenth time (BACKLOG #1133) on one contradiction in the MFA
    section. One sentence said `administrators` narrows the requirement to the Administrator role,
    and the next said a directory account is in scope like any other. Under that scope a directory
    session that proved no factor still owes one, so it is in scope more than a local account is.
    The probe above pins the code; these assertions red if either old sentence returns."""
    doc = _flat(_doc_text())
    for retired in (
        "and `administrators` narrows it to the **Administrator** role",
        "**A directory account is in scope like any other**",
        "is refused outright while the knob is on",
    ):
        assert retired not in doc, (
            f"docs/SECURITY.md says {retired!r} again; `_unverified_session_owes_factor` keeps a "
            "directory session with no proven factor pending under either scope (BACKLOG #1133)."
        )
    for token in (
        "Setting the scope to `administrators` frees only a **local** account without the "
        "Administrator role from the access gate.",
        "a directory session that proved no factor stays MFA-pending under both "
        "(`AuthService._unverified_session_owes_factor`).",
        "A directory account without the Administrator role does leave scope for the `required` "
        "flag of `GET /me/mfa` and for the last-factor removal guard",
        "An account that has enrolled a factor owes it under either value while the factor stays "
        "enrolled; an OIDC sign-in meets it at mint while `[auth].oidc_require_mfa_claim` is on, "
        "the default.",
        "**While `require_mfa` is on, a directory session that proved no factor owes one under "
        "either scope value** (BACKLOG #1144). That is every Kerberos session, and an OIDC session "
        "minted while `[auth].oidc_require_mfa_claim` is off.",
        "With the claim required, the default, the engine refuses a token that carries no "
        "configured `amr`/`acr`, and one that carries it mints the session with its factor met.",
    ):
        assert token in doc, f"docs/SECURITY.md must state {token!r} (BACKLOG #1133)."
    guide = _flat((_ROOT / "docs" / "EARLY-ADOPTER-GUIDE.md").read_text(encoding="utf-8"))
    assert "a directory account is in scope like any other" not in guide.lower(), (
        "docs/EARLY-ADOPTER-GUIDE.md says a directory account is in scope like any other again; "
        "under `administrators` a directory session with no proven factor owes more (BACKLOG #1133)."
    )


def test_the_eleventh_sweep_says_no_doc_delegates_directory_mfa() -> None:
    """ASVS 6.1.3 was held at partial an eleventh time (BACKLOG #1133) on one SECURITY.md sentence:
    the engine's own second factor "binds a directory account like any other". Under
    `administrators` a directory session that proved no factor owes more than a local account does,
    and an OIDC sign-in meets its factor on the IdP's claim, so it is not the local rule. At least
    seven sentences in five other operator docs said directory MFA is delegated, which
    `_unverified_session_owes_factor` contradicts while `require_mfa` is on. A second review round
    found the claim in more files, with two neighbours: a lockout said to cover local accounts only,
    which `verify_mfa` and the step-up re-bind contradict, and container comments keying the
    MFA-at-exposure gate on local admins and the PHI tier, neither of which the `admin_exposed`
    block in `__main__.py` reads. The probes earlier in this file pin the MFA code. They do not pin
    the lockout or the gate: `tests/test_cli.py` tests the gate. These assertions red if an old
    phrasing returns. ADRs are dated records and are not read here."""
    retired_by_doc = {
        "docs/SECURITY.md": ("binds a directory account like any other",),
        "docs/DEPLOYMENT.md": (
            "AD/Entra MFA stays delegated",
            "so MEFOR does not re-implement",
            "workstation logon was already MFA'd",
        ),
        "docs/PHI.md": ("AD MFA delegated", "native TOTP MFA built for local accounts"),
        "docs/CLOUD-PHI-HIPAA.md": ("AD/Entra MFA stays delegated",),
        "docs/EARLY-ADOPTER-GUIDE.md": (
            "AD/Entra MFA is enforced by your directory;",
            "lockout covers local accounts only",
        ),
        "docker/README.md": ("AD-only shops delegate MFA",),
        # Round two of the same sweep: the delegation claim, and the account-kind gate wording it
        # carried, survived in at least these files too.
        "docs/FEATURE-MAP.md": (
            "directory-delegated",
            "TOTP MFA (local users)",
            "passkeys (local users, browser)",
        ),
        "docs/MENTAL-MODEL.md": (
            "the \\[webauthn\\] extra) for local accounts,",
            "the [webauthn] extra) for local accounts,",
            "as a second factor for local accounts.",
        ),
        "docs/CONTAINER-EXPOSURE-EVALUATION.md": (
            "Production-PHI + local accounts",
            "production-PHI MFA refusal",
            "required on a production PHI instance with local admins",
            "quiet on synthetic",
        ),
        "docs/REMOTE-CONSOLE.md": ("TOTP MFA) or AD/LDAP", "A non-PHI instance is silent."),
        "docker/compose.yaml": (
            "required for local Administrator accounts on an exposed PHI bind",
            "MFA-for-local-admins",
        ),
        "docker/k8s/ha-postgres.yaml": ("local-admin MFA on an exposed PHI bind",),
        "docker/k8s/statefulset.yaml": ("local-admin MFA on an exposed PHI bind",),
    }
    for name, retired in retired_by_doc.items():
        text = _flat((_ROOT / name).read_text(encoding="utf-8"))
        for phrase in retired:
            assert phrase not in text, (
                f"{name} says {phrase!r} again (BACKLOG #1133). Each retired phrase said one of: "
                "directory MFA is delegated, the lockout covers local accounts only, or the "
                "MFA-at-exposure gate keys on local admins or the PHI tier. The code says none."
            )
    doc = _flat(_doc_text())
    assert (
        "First, while `[security].require_mfa` is on, a directory session that proved no factor "
        "at sign-in owes an engine factor under either `require_mfa_scope` value. That includes "
        "at least every Kerberos session and an OIDC session minted while "
        "`[auth].oidc_require_mfa_claim` is off." in doc
    ), (
        "docs/SECURITY.md's Browser AD login paragraph must state the directory rule (BACKLOG #1133)."
    )


#: A sentence saying a capability is absent or still to come. Matched on text with the Markdown
#: emphasis stripped, so "*not* there yet" and "**MFA**" read as plain words.
_ABSENT = re.compile(
    r"\broadmap\b|\bnot there yet\b|n't built\b|\bnot (?:yet )?built\b|\bremaining\b[^.]*\bgaps?\b"
    r"|\bplanned\b|\bdeferred\b",
    re.IGNORECASE,
)

#: The engine's second factor under any name a doc gives it.
_SECOND_FACTOR = re.compile(
    r"\bMFA\b|\bTOTP\b|\bpasskeys?\b|second factor|two-factor|multi-factor", re.IGNORECASE
)

#: Off-box logs and the de-identification framework, under the names the docs give them.
_BUILT_ELSEWHERE = re.compile(
    r"off-box log|log shipping|log forwarding|de-identification framework|\bde-identification\)",
    re.IGNORECASE,
)


def _clauses(text: str) -> list[str]:
    """``text`` flattened and cut at sentence ends, semicolons and table-cell bars, with emphasis and
    blockquote markers removed.

    The unit a claim lives in. A cut at ``;`` keeps "X is built; Y is on the roadmap" from reading
    as a claim that X is on the roadmap. A blockquote's ``>`` would otherwise split a phrase that
    wraps across its lines."""
    plain = _flat(re.sub(r"(?m)^[ \t]*>[ \t]?", "", text)).replace("*", "")
    return [c for c in re.split(r"(?<=[.!?;])\s+|\s*\|\s*", plain) if c]


def _doc(name: str) -> str:
    return (_ROOT / name).read_text(encoding="utf-8")


def test_the_twelfth_sweep_probes_mfa_and_the_first_factor_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The code half of the twelfth 6.1.3 re-read (BACKLOG #1133). Four docs outside the three the
    earlier sweeps read still said MFA was not built, that the sign-in form offers an AD provider,
    and that a first factor may be a passkey. The test below refuses those claims; this pins the
    code they contradict, so a change that makes an old claim true again reds here first."""
    # 1. MFA is built and on: the default, both factor kinds, and the access gate on `require`.
    assert AuthSettings.model_fields["require_mfa"].default is True
    for enrol in ("begin_mfa_enrollment", "begin_webauthn_registration"):
        assert inspect.iscoroutinefunction(getattr(AuthService, enrol, None)), (
            f"AuthService.{enrol} is gone; the README and the early-adopter guide say TOTP and "
            "passkeys are built."
        )
    assert _called(
        ast.parse(textwrap.dedent(inspect.getsource(api_security.require))), "mfa_satisfied"
    ), (
        "api.security.require no longer asks mfa_satisfied; the docs say the factor is an access gate."
    )

    # 2. The first factor of an account the requirement covers is TOTP. The ninth sweep pins the
    #    covered local refusal end to end; this adds the arms the docs now also state: a directory
    #    account and a local account outside the requirement may register a passkey first. A real
    #    service and store, with the account row swapped and the first store read past the gate
    #    raising a sentinel, so "passed the gate" is told from "refused at it" with no WebAuthn extra.
    from messagefoundry.store.store import MessageStore

    class _PastTheGate(Exception):
        pass

    async def past_the_gate(_user_id: str) -> list[object]:
        raise _PastTheGate

    async def probe() -> dict[str, str]:
        store = await MessageStore.open(":memory:")
        try:
            on = AuthService(store, AuthSettings())  # require_mfa on, the shipped default
            await on.initialize()
            off = AuthService(store, AuthSettings(require_mfa=False))
            created = await on.create_local_user(
                username="holder12",
                display_name=None,
                email="holder12@example.org",
                roles=["viewer"],
                actor="test-admin",
            )
            out = await on.login("holder12", created.credential.password)
            assert out.ok and out.identity is not None and out.token is not None
            identity, token = out.identity, out.token
            row = await store.get_user(identity.user_id)
            assert row is not None and not row.totp_enabled
            monkeypatch.setattr(store, "list_webauthn_credentials", past_the_gate)
            arms = {
                "covered local, no TOTP": (on, row),
                "covered local, TOTP": (on, dataclasses.replace(row, totp_enabled=True)),
                "local, requirement off": (off, row),
                "directory, no TOTP": (on, dataclasses.replace(row, auth_provider="ad")),
            }
            seen: dict[str, str] = {}
            for arm, (service, record) in arms.items():

                async def get_user(_user_id: str, _record: UserRecord = record) -> UserRecord:
                    return _record

                monkeypatch.setattr(store, "get_user", get_user)
                try:
                    await service.begin_webauthn_registration(
                        identity, token=token, rp_id="localhost", rp_name="t"
                    )
                    seen[arm] = "returned"
                except service_module.FactorEnrolmentRequired:
                    seen[arm] = "refused"
                except _PastTheGate:
                    seen[arm] = "passed"
            return seen
        finally:
            await store.close()

    assert asyncio.run(probe()) == {
        "covered local, no TOTP": "refused",
        "covered local, TOTP": "passed",
        "local, requirement off": "passed",
        "directory, no TOTP": "passed",
    }, (
        "the first-passkey order changed. docs/REMOTE-CONSOLE.md and docs/BROWSER-SUPPORT.md say a "
        "covered local account enrols TOTP first and a directory account or a local account outside "
        "the requirement may register a passkey first."
    )
    # ...and a covered account cannot then drop the TOTP that came first.
    disable = ast.parse(textwrap.dedent(inspect.getsource(AuthService.disable_mfa)))
    assert _called(disable, "_covered_by_requirement"), (
        "disable_mfa no longer refuses a covered account's TOTP removal; docs/BROWSER-SUPPORT.md "
        "says a covered local account keeps its TOTP."
    )
    # A session owing a factor it already holds cannot enrol another (so a passkey-only account in a
    # browser with no WebAuthn cannot add TOTP to get past the gate).
    assert service_module.STEP_UP_ACTION_MFA_ENROLL in AuthService._PENDING_REFUSED_ACTIONS

    # 3. A TOTP or recovery code at the MFA gate opens a step-up window, so a Windows SSO session's
    #    first sensitive action does not always force the directory-password step-up.
    assert _called(_service_func("verify_mfa"), "mark_session_reauthed")

    # 4. No serve-time refusal reads oidc_require_mfa_claim. The modules that read it are derived, so
    #    a new reader anywhere in the engine (a serve gate in __main__ or api/app.py, say) reds here
    #    until someone decides whether it refuses the off value. In every reader, no ``if`` that
    #    tests the claim for OFF holds a ``raise`` anywhere in its body. The settings check that
    #    does raise refuses the ON value with nothing to match. A refusal written another way (an
    #    exit code, a ``not (a or b)``) still slips past; this is a tripwire, not a proof.
    from messagefoundry.config import settings as settings_module

    claim = "oidc_require_mfa_claim"

    def _is_the_claim(node: ast.AST) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == claim

    def _tests_for_off(test: ast.AST) -> bool:
        return any(
            (isinstance(u, ast.UnaryOp) and isinstance(u.op, ast.Not) and _is_the_claim(u.operand))
            or (
                isinstance(u, ast.Compare)
                and _is_the_claim(u.left)
                and any(isinstance(c, ast.Constant) and c.value is False for c in u.comparators)
            )
            for u in ast.walk(test)
        )

    trees = {
        rel: ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
        for rel in {site for site, _holder in _name_reference_sites(claim)}
    }
    assert sorted(trees) == [
        "messagefoundry/auth/service.py",
        "messagefoundry/config/settings.py",
        "messagefoundry/verify/federation.py",
    ], (
        f"the modules reading {claim} changed: {sorted(trees)}. If a new one refuses the off value "
        "at serve, docs/SECURITY-LOOSENING.md's scope note (no serve-time refusal of its own) is stale."
    )
    refusing: list[tuple[str, ast.If]] = [
        (name, n)
        for name, tree in trees.items()
        for n in ast.walk(tree)
        if isinstance(n, ast.If)
        and any(_is_the_claim(a) for a in ast.walk(n.test))
        and any(isinstance(r, ast.Raise) for s in n.body for r in ast.walk(s))
    ]
    # The off-value scan below walks these, so it must have something to walk.
    assert len(refusing) >= 1, (
        f"no `if` in {sorted(trees)} tests {claim} and raises, so the scan for a refusal of the "
        "off value reads nothing; re-derive it."
    )
    assert any(name.endswith("config/settings.py") for name, _ in refusing), (
        f"the settings check that refuses {claim} = true with nothing to match is gone"
    )
    off_refusals = [f"{name}:{n.lineno}" for name, n in refusing if _tests_for_off(n.test)]
    assert not off_refusals, (
        f"{off_refusals} now raise when {claim} is off; restate docs/SECURITY-LOOSENING.md's "
        "scope note."
    )
    # 5. The posture registry DOES report require_mfa off, so the scope note must not list it among
    #    the switches it leaves out.
    loosenings = ast.parse(textwrap.dedent(inspect.getsource(settings_module.security_loosenings)))
    assert any(
        isinstance(n, ast.Tuple)
        and n.elts
        and isinstance(n.elts[0], ast.Constant)
        and n.elts[0].value == "require_mfa"
        for n in ast.walk(loosenings)
    ), "security_loosenings no longer reports require_mfa; restate docs/SECURITY-LOOSENING.md."


# The twelfth 6.1.3 re-read (BACKLOG #1133) held the cell at partial on four shipped docs outside
# SECURITY.md, CONFIGURATION.md and CONNECTIONS.md (owner ruling 2026-10-02: those count), and raised
# four lower-confidence lines, each confirmed wrong against the code before it was changed. The probe
# above pins the code. Each test below refuses one CLAIM rather than one sentence wherever the claim
# can be told apart from its correction, so a reworded return of it still reds.


@pytest.mark.parametrize(
    ("name", "subject"),
    [
        (doc, subject)
        for doc in ("README.md", "docs/EARLY-ADOPTER-GUIDE.md")
        for subject in ("second factor", "off-box logs or de-identification")
    ],
)
def test_the_twelfth_sweep_no_doc_says_a_built_control_is_missing(name: str, subject: str) -> None:
    """README.md said MFA and off-box log shipping "remain on the roadmap". The early-adopter guide
    said MFA, off-box logs and the de-identification framework are not there yet, not built, a
    remaining gap, or deferred. All three are built (the probes above).

    Two units are read. A clause may not pair the control, under any of its names, with absence.
    A table row may not name the control in its label cell and absence in a later cell, which a
    clause cut at the cell bars cannot see. The subject must occur, or the scan examined nothing."""
    pattern = {
        "second factor": _SECOND_FACTOR,
        "off-box logs or de-identification": _BUILT_ELSEWHERE,
    }[subject]
    text = _doc(name)
    clauses = [c for c in _clauses(text) if pattern.search(c)]
    assert clauses, f"{name} no longer names the {subject} at all, so this check reads nothing"
    stale = [c for c in clauses if _ABSENT.search(c)]
    for line in text.splitlines():
        cells = [c.strip().replace("*", "") for c in line.strip().strip("|").split("|")]
        if line.lstrip().startswith("|") and len(cells) > 1 and pattern.search(cells[0]):
            stale += [line.strip() for c in cells[1:] if _ABSENT.search(c)][:1]
    assert not stale, (
        f"{name} says the {subject} is missing or still to come: {stale}. It is built "
        "(BACKLOG #1133)."
    )


def test_the_twelfth_sweep_user_guide_offers_no_provider_choice() -> None:
    """docs/USER-GUIDE.md told the operator to pick a Provider, with Active Directory shown when the
    engine advertises it. The form has no selector, and the steps must name the links it does
    render, read from the form itself."""
    guide = _doc("docs/USER-GUIDE.md")
    start = guide.index("### Opening and signing in to the console")
    signing_in = guide[start : guide.index("\n### ", start + 1)]
    # The section must still hold steps to read, or the scan below clears a heading and no more.
    steps = _clauses(signing_in)
    assert len(steps) >= 8, (
        f"docs/USER-GUIDE.md's sign-in section cut into {len(steps)} clause(s), floor 8: the "
        "provider-choice scan reads too little to clear it."
    )
    # A choice on the form, worded with or without the word "provider": a choosing word, or the
    # old "appears", beside a provider or one of the two provider names.
    chooser = [
        c
        for c in steps
        if re.search(r"(?i:\bproviders?\b)|\bActive Directory\b|\bAD\b|\bLocal\b", c)
        and re.search(r"\b(pick|choose|select|selector|dropdown|appears)\b", c, re.IGNORECASE)
    ]
    assert not chooser, (
        f"docs/USER-GUIDE.md's sign-in steps offer a provider choice again: {chooser}. The form has "
        "no selector and the engine refuses provider=ad (BACKLOG #1137)."
    )
    from messagefoundry_webconsole import pages

    form = str(pages.login(None, sso_enabled=True, oidc_enabled=True))
    links = re.findall(r"<a [^>]*>([^<]+)</a>", form)
    assert links, "the sign-in form renders no directory link; re-derive the USER-GUIDE step"
    for link in links:
        assert link in _flat(signing_in), (
            f"docs/USER-GUIDE.md's sign-in steps must name the form's {link!r} link."
        )


def test_the_twelfth_sweep_remote_console_sends_a_covered_account_to_totp_first() -> None:
    """docs/REMOTE-CONSOLE.md's X-MFA-Required row said "Enrol TOTP or a passkey". A covered local
    account's first passkey is refused until it holds TOTP."""
    row = _flat(
        next(
            line
            for line in _doc("docs/REMOTE-CONSOLE.md").splitlines()
            if line.startswith("| Signed in, but every route returns `403` with `X-MFA-Required")
        )
    )
    assert not re.search(r"TOTP or a passkey", row), (
        "docs/REMOTE-CONSOLE.md offers TOTP or a passkey as the first factor again; "
        "begin_webauthn_registration refuses a covered local account's first passkey."
    )
    # The refusal is quoted as the text the operator sees, read from the code that sends it.
    assert "TOTP first" in row and f"`{service_module.ENROL_AUTHENTICATOR_FIRST}`" in row, (
        "docs/REMOTE-CONSOLE.md's X-MFA-Required row must say TOTP comes first and quote the "
        "refusal the engine sends."
    )


def test_the_twelfth_sweep_phi_does_not_delegate_mfa() -> None:
    """docs/PHI.md listed MFA among controls "delegated to the org's environment (IdP/AD, ...)"."""
    clauses = _clauses(_doc("docs/PHI.md"))
    assert len(clauses) >= 1000, (
        f"docs/PHI.md cut into {len(clauses)} clause(s), floor 1000: the MFA scan reads too little "
        "to clear it."
    )
    delegated = [c for c in clauses if re.search(r"\bMFA\b", c) and re.search(r"\bdelegated\b", c)]
    assert not delegated, (
        f"docs/PHI.md delegates MFA to the org's environment again: {delegated}. The engine's own "
        "factor gates local and directory accounts while require_mfa is on (BACKLOG #1133)."
    )


def test_the_twelfth_sweep_feature_map_sso_row_names_the_mfa_window() -> None:
    """docs/FEATURE-MAP.md said a Windows SSO session's first sensitive action forces the
    directory-password step-up. A code proved at /ui/mfa stamps a window first (`verify_mfa`)."""
    sso_row = _flat(
        next(
            line
            for line in _doc("docs/FEATURE-MAP.md").splitlines()
            if line.startswith("| Passwordless Windows SSO (Kerberos / SPNEGO)")
        )
    )
    assert "first sensitive action forces" not in sso_row and "`/ui/mfa`" in sso_row, (
        "docs/FEATURE-MAP.md's Windows SSO row must say a code proved at /ui/mfa opens the step-up "
        "window, not that the first sensitive action always forces one."
    )
    # The window does not reach an action-bound route: its grant comes only from a step-up (the
    # fifth sweep pins the two minters), so the row must keep that caveat beside the /ui/mfa clause.
    assert "require_action_step_up" in sso_row, (
        "docs/FEATURE-MAP.md's Windows SSO row must say an action-bound route still asks for the "
        "step-up after a code at /ui/mfa."
    )


def test_the_twelfth_sweep_loosening_note_gives_the_claim_gate_no_refusal() -> None:
    """docs/SECURITY-LOOSENING.md said `oidc_require_mfa_claim` is gated by its own serve-time
    refusal, and listed `require_mfa` among the switches the registry does not report. No serve gate
    reads the first, and the registry reports the second (the probe above)."""
    clauses = _clauses(_doc("docs/SECURITY-LOOSENING.md"))
    assert len(clauses) >= 500, (
        f"docs/SECURITY-LOOSENING.md cut into {len(clauses)} clause(s), floor 500: the require_mfa "
        "scan reads too little to clear it."
    )
    unreported = [c for c in clauses if "not reported" in c and "`require_mfa`" in c]
    assert not unreported, (
        f"docs/SECURITY-LOOSENING.md says require_mfa is not reported again: {unreported}. "
        "security_loosenings() reports it."
    )
    loosening = [c for c in clauses if "oidc_require_mfa_claim" in c and "serve-time refusal" in c]
    assert loosening and all("no serve-time refusal of its own" in c for c in loosening), (
        f"docs/SECURITY-LOOSENING.md gives oidc_require_mfa_claim a serve-time refusal of its own "
        f"again: {loosening}. No serve gate reads it."
    )


def test_the_twelfth_sweep_browser_support_does_not_say_a_passkey_is_never_alone() -> None:
    """docs/BROWSER-SUPPORT.md said "A passkey is never the only factor". A directory account and a
    local account outside the requirement can register one with no TOTP (the probe above)."""
    assert not re.search(
        r"passkey (?:is|can) never (?:be )?the only factor",
        _flat(_doc("docs/BROWSER-SUPPORT.md")),
        re.IGNORECASE,
    ), (
        "docs/BROWSER-SUPPORT.md says a passkey is never the only factor again; a directory account "
        "and a local account outside the requirement can hold one alone."
    )


# The twelfth sweep's second round. The first round removed MFA from sentences that also called
# off-box log forwarding and the de-identification framework missing, called at-rest encryption
# opt-in, called mTLS and off-box logs delegated, and named a removed key. Each was checked against
# the code before it was changed; the probe below pins what was checked.


def test_the_twelfth_sweep_second_round_probes_what_is_built() -> None:
    """The code facts the second round's sentences now state."""
    from messagefoundry import anon
    from messagefoundry.config import ai_policy
    from messagefoundry.config import settings as settings_module
    from messagefoundry.config.wiring import X12, Tcp
    from messagefoundry.logging_setup import SyslogForward

    # 1. Off-box log forwarding is built and wired: serve builds a SyslogForward handler.
    main_tree = ast.parse((_ROOT / "messagefoundry" / "__main__.py").read_text(encoding="utf-8"))
    assert inspect.isclass(SyslogForward) and _called(main_tree, "SyslogForward"), (
        "serve no longer builds the SyslogForward handler; README and the early-adopter guide say "
        "off-box log forwarding is built."
    )
    # 2. The de-identification framework is built; only the AI-assist path lacks it, and the guide's
    #    row says that path's scope falls back to code_only.
    assert callable(getattr(anon, "anonymize_checked", None)), "messagefoundry.anon lost its entry"
    deid = ai_policy.resolve_effective_policy(
        mode=ai_policy.AiMode.MANAGED_CLAUDE_BAA,
        data_scope=ai_policy.AiDataScope.DEIDENTIFIED,
        production=True,
    )
    assert deid.data_scope is ai_policy.AiDataScope.CODE_ONLY, (
        "the AI deidentified scope is live now; restate the early-adopter guide's de-identification row."
    )
    # 3. At-rest encryption is required by default: with no key and no opt-out the gate refuses.
    assert (
        settings_module.keyless_opt_out_refusal(
            settings_module.StoreSettings(), settings_module.SecuritySettings()
        )
        == settings_module.KEYLESS_REFUSED_BY_NO_OPT_OUT
    ), "a keyless store opens by default now; the guide says encryption is required by default."
    # 4. Raw TCP and X12 take no TLS setting, so they are the remaining transport gap. Both
    #    signatures are read into one list, floored above what either holds alone today, so a
    #    factory cut down to ``**settings`` cannot pass by showing no names to scan.
    parameters = [
        (factory.__name__, name)
        for factory in (Tcp, X12)
        for name in inspect.signature(factory).parameters
    ]
    assert len(parameters) >= 30, (
        f"Tcp() and X12() show {len(parameters)} parameter(s) between them, floor 30: the TLS scan "
        "reads too little to clear them."
    )
    tls = [f"{factory}({name})" for factory, name in parameters if "tls" in name.lower()]
    assert not tls, (
        f"{tls} are TLS settings now; the guide names raw TCP and X12 as the remaining transport gap."
    )
    # 5. `[auth].enabled`, and the `[security].require_sign_in` it had moved to, are removed keys,
    #    refused at load: no config turns sign-in off.
    for key in (("auth", "enabled"), ("security", "require_sign_in")):
        assert key in settings_module._REMOVED_KEYS, (
            f"{key} is no longer refused as removed; restate docs/SECURITY-LOOSENING.md and the "
            "guide's API checklist item."
        )


def test_the_twelfth_sweep_guide_names_the_real_transport_gap_and_encryption_default() -> None:
    """The guide named off-box log shipping as the remaining transport gap (raw TCP and X12 are at
    least two), called at-rest encryption opt-in twice and told the reader to set
    `require_encryption` to get the keyless refusal (a keyless store is refused by default), and
    said auth can be disabled (`serve` always requires sign-in)."""
    clauses = _clauses(_doc("docs/EARLY-ADOPTER-GUIDE.md"))
    assert len(clauses) >= 300, (
        f"docs/EARLY-ADOPTER-GUIDE.md cut into {len(clauses)} clause(s), floor 300: the opt-in and "
        "auth-disabled scans read too little to clear it."
    )
    gap = [c for c in clauses if re.search(r"\bremaining transport gaps?\b", c, re.IGNORECASE)]
    assert gap and all("raw TCP and X12" in c for c in gap), (
        f"the guide's remaining-transport-gap sentence must name raw TCP and X12: {gap}"
    )
    opt_in = [
        c
        for c in clauses
        if re.search(r"at-rest (?:body )?encryption", c, re.IGNORECASE)
        and re.search(r"\bopt-in\b", c, re.IGNORECASE)
    ]
    assert not opt_in, f"the guide calls at-rest encryption opt-in again: {opt_in}"
    # The require_encryption step must not be the thing that creates the keyless refusal.
    require = [c for c in clauses if "require_encryption" in c]
    assert require and not any(
        "so the engine refuses to start unencrypted" in c for c in require
    ), f"the guide says require_encryption creates the keyless refusal again: {require}"
    disabled = [
        c for c in clauses if re.search(r"\bauth(?:entication)? (?:is )?disabled\b", c, re.I)
    ]
    assert not disabled, f"the guide says auth can be disabled again: {disabled}"


def test_the_twelfth_sweep_phi_does_not_delegate_built_controls() -> None:
    """docs/PHI.md said mTLS, certificate revocation and off-box logs are "delegated to the org's
    environment", and its threat table said to delegate off-box log shipping to the SIEM. The engine
    builds each; the org supplies the PKI and the SIEM."""
    clauses = _clauses(_doc("docs/PHI.md"))
    assert len(clauses) >= 1000, (
        f"docs/PHI.md cut into {len(clauses)} clause(s), floor 1000: the built-controls scan reads "
        "too little to clear it."
    )
    delegated = [
        c
        for c in clauses
        if re.search(r"\bdelegat", c, re.IGNORECASE) and re.search(r"mTLS|off-box log", c)
    ]
    assert not delegated, f"docs/PHI.md delegates built controls again: {delegated}"


def test_the_twelfth_sweep_loosening_note_does_not_gate_a_removed_key() -> None:
    """docs/SECURITY-LOOSENING.md listed `[auth].enabled` among switches gated by their own
    serve-time refusals. The key is gone: it is refused at load (the probe above)."""
    clauses = _clauses(_doc("docs/SECURITY-LOOSENING.md"))
    assert len(clauses) >= 500, (
        f"docs/SECURITY-LOOSENING.md cut into {len(clauses)} clause(s), floor 500: the removed-key "
        "scan reads too little to clear it."
    )
    gated = [c for c in clauses if "`[auth].enabled`" in c and "serve-time refusal" in c]
    assert not gated, f"docs/SECURITY-LOOSENING.md gates the removed [auth].enabled again: {gated}"


# The thirteenth 6.1.3 re-read (BACKLOG #1133, vault PR 2242) held the cell at partial on four more
# sentences in shipped docs outside the three the early sweeps read, and asked whether "nobody can
# sign in before `provision-admin`" holds for a directory sign-in. Each was checked against the code
# before it was changed; the probe below pins what was checked, and each test after it refuses the
# CLAIM rather than one sentence.


def test_the_thirteenth_sweep_probes_the_code_the_docs_now_state(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The code facts the thirteenth sweep's sentences now state."""
    from messagefoundry.auth.ldap import AdPrincipal
    from messagefoundry.pipeline import wiring_runner
    from messagefoundry.store.store import MessageStore
    from messagefoundry_webconsole import _auth as console_auth

    # 1. A pending browser session is redirected to /ui/mfa, not held there. The page forwards an
    #    account with no factor to the account page, and the account page and the enrolment
    #    factory both admit a pending session.
    routes = _console_route_funcs()
    assert any(
        isinstance(n, ast.Constant) and n.value == "/ui/account?m=enroll_first"
        for n in ast.walk(routes["GET /ui/mfa"])
    ), "GET /ui/mfa no longer forwards an account with no factor to /ui/account"
    for where, values in (
        (
            "GET /ui/account",
            [
                kw.value
                for n in ast.walk(routes["GET /ui/account"])
                if isinstance(n, ast.Call)
                for kw in n.keywords
                if kw.arg == "allow_mfa_pending"
            ],
        ),
        (
            "require_ui_reauth_only_action",
            keyword_values(console_auth.require_ui_reauth_only_action, "allow_mfa_pending"),
        ),
    ):
        flags = [v for v in values if isinstance(v, ast.Constant) and v.value is True]
        assert flags, f"{where} no longer admits an MFA-pending session"
    assert _called(routes["POST /ui/account/mfa/enroll"], "require_ui_reauth_only_action")

    # 2. HTTP intake: three partner-authentication modes, no Basic, and a peer-control gate that
    #    refuses under enforce, warns otherwise, runs at build and at check, and ignores the
    #    cleartext escape.
    with pytest.raises(WiringError, match="intake_auth must be one of"):
        Http(port=8080, intake_auth="basic")  # type: ignore[arg-type]
    exposed = {"host": "0.0.0.0", "tls": True, "tls_cert_file": "c.pem", "tls_key_file": "k.pem"}

    def gate(enforcing: bool, **settings: Any) -> None:
        wiring_runner.check_http_intake_auth(
            Source(type=ConnectorType.HTTP, name="intake-in", settings={**exposed, **settings}),
            "intake-in",
            posture=HopPosture(enforcing=enforcing),
        )

    # The allow-list floors docs/DEPLOYMENT.md quotes, probed on both sides of each.
    assert (
        wiring_runner._INTAKE_ALLOWLIST_MIN_PREFIX_V4,
        wiring_runner._INTAKE_ALLOWLIST_MIN_PREFIX_V6,
    ) == (
        8,
        32,
    ), "the intake allow-list floors moved; restate docs/DEPLOYMENT.md's caveat"
    for refused in (
        {},
        {"tls_ca_file": "ca.pem"},
        {"source_ip_allowlist": ["0.0.0.0/0"]},
        {"source_ip_allowlist": ["10.0.0.0/7"]},
        {"source_ip_allowlist": ["2001:db8::/31"]},
    ):
        with pytest.raises(WiringError):
            gate(True, **refused)
    with caplog.at_level(logging.WARNING):
        gate(False)  # warned, not refused
    assert any(
        r.levelno == logging.WARNING and "no effective peer control" in r.getMessage()
        for r in caplog.records
    ), "check_http_intake_auth no longer warns under warn; restate docs/DEPLOYMENT.md"
    gate(True, intake_auth="api_key", intake_api_key="k")
    gate(True, intake_auth="bearer", intake_api_key="k")
    gate(True, intake_auth="mtls_subject", tls_ca_file="ca.pem", intake_client_subjects=["CN:p"])
    gate(True, source_ip_allowlist=["10.0.0.0/8", "2001:db8::/32"])
    # Once intake_auth names a mode, only that mode is judged: a narrow allow-list does not rescue
    # a key mode with no key (docs/DEPLOYMENT.md says the allow-list is then not consulted).
    for incomplete in (
        {"intake_auth": "bearer", "intake_api_key": ""},
        {"intake_auth": "mtls_subject", "tls_ca_file": "ca.pem", "intake_client_subjects": []},
    ):
        with pytest.raises(WiringError):
            gate(True, source_ip_allowlist=["10.0.0.0/24"], **incomplete)
    assert (
        "allow_insecure_bind"
        not in inspect.signature(wiring_runner.check_http_intake_auth).parameters
    )
    for caller in (
        wiring_runner.RegistryRunner._start_inbound_unsafe,
        wiring_runner._build_check_connectors,
    ):
        tree = ast.parse(textwrap.dedent(inspect.getsource(caller)))
        assert _called(tree, "check_http_intake_auth"), f"{caller.__name__} lost the intake gate"

    # 3. The only directory bind a user's password reaches is the step-up re-bind. Two layers. In
    #    the LDAP client, a connection is opened only by the service-account helper and by
    #    `authenticate` (with its timing-equaliser, which only `authenticate` calls). In the engine,
    #    only `_reauth_ad` reaches `authenticate`; simple-bind sign-in is retired.
    ldap_tree = ast.parse(
        (_ROOT / "messagefoundry" / "auth" / "ldap.py").read_text(encoding="utf-8")
    )
    ldap_funcs = [
        f for f in ast.walk(ldap_tree) if isinstance(f, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    openers = sorted({f.name for f in ldap_funcs if _called(f, "Connection")})
    assert openers == ["_equalizing_bind", "_service_conn", "authenticate"], (
        f"the LDAP functions that open a connection changed: {openers}. Re-derive which binds carry "
        "a user's password before trusting docs/SECURITY-LOOSENING.md's cleartext-LDAP loss."
    )
    assert sorted(f.name for f in ldap_funcs if _called(f, "_equalizing_bind")) == ["authenticate"]
    # Every reference to the name, whatever its receiver, in the engine and the console. The two
    # api/security.py holders are a parameter of that name, unrelated to the directory.
    sites = sorted(set(_name_reference_sites("authenticate")))
    assert sites == [
        ("messagefoundry/api/security.py", "_gate"),
        ("messagefoundry/api/security.py", "require_phi_read"),
        ("messagefoundry/auth/service.py", "AuthService"),
    ], (
        f"the code referring to `authenticate` changed: {sites}. Re-derive which paths bind a "
        "directory user before trusting docs/SECURITY-LOOSENING.md's cleartext-LDAP loss."
    )
    service_tree = ast.parse(textwrap.dedent(inspect.getsource(AuthService)))
    binders = sorted(
        {
            f.name
            for f in ast.walk(service_tree)
            if isinstance(f, ast.FunctionDef | ast.AsyncFunctionDef)
            and any(isinstance(n, ast.Attribute) and n.attr == "authenticate" for n in ast.walk(f))
        }
    )
    assert binders == ["_reauth_ad"], (
        f"the AuthService methods binding a directory user changed: {binders}. Restate the "
        "cleartext-LDAP loss in docs/SECURITY-LOOSENING.md."
    )

    # 4. With the claim gate on, the default, an OIDC session is minted as having met the factor.
    #    The tenth sweep's probe pins the grant to the setting; this pins the default it reads.
    assert AuthSettings.model_fields["oidc_require_mfa_claim"].default is True

    # 5. On a store with no Administrator a Windows sign-in is not refused: it mints a session on a
    #    new directory row holding no role, still owing its factor. The role map and the federated
    #    binding are both administrator-only, so nothing grants that row a role, and an OIDC
    #    sign-in finds no account to sign in to.
    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="jdoe@example.org",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
        directory_object_id="0f0e0d0c-0b0a-0908-0706-050403020100",
    )

    class _OneUserDirectory:
        def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
            return principal if username == "jdoe" else None

    monkeypatch.setattr(service_module, "kerberos_principal", lambda _t, _s: "jdoe")

    async def probe() -> tuple[bool, frozenset[Permission], bool, list[str], bool]:
        store = await MessageStore.open(":memory:")
        try:
            settings = AuthSettings(
                ad_enabled=True,
                kerberos_enabled=True,
                ad_server="ldaps://x",
                ad_user_search_base="DC=x",
                ad_bind_dn="CN=svc,DC=x",
                ad_bind_password="x",
            )
            service = AuthService(store, settings, ldap=_OneUserDirectory())  # type: ignore[arg-type]
            await service.initialize()
            assert not await service.has_enabled_administrator()
            assert list(await store.list_ad_group_role_map()) == []
            out = await service.authenticate_kerberos(b"spnego-token")
            assert out.identity is not None
            row = await store.get_user_by_username("jdoe")
            assert row is not None and row.auth_provider == AuthProvider.AD.value
            return (
                out.ok,
                out.identity.permissions,
                out.mfa_required,
                list(await store.get_user_role_ids(row.id)),
                await service.has_enabled_administrator(),
            )
        finally:
            await store.close()

    assert asyncio.run(probe()) == (True, frozenset(), True, [], False), (
        "a Windows sign-in on a store with no Administrator changed shape; restate the "
        "provisioning passages in docs/DEPLOYMENT.md, docs/INSTALL-GUIDE.md and docs/SERVICE.md."
    )
    routes_tree = ast.parse(
        (_ROOT / "messagefoundry" / "api" / "auth_routes.py").read_text(encoding="utf-8")
    )
    for route in ("set_ad_group_map", "bind_user_federated_identity"):
        func = next(
            n
            for n in ast.walk(routes_tree)
            if isinstance(n, ast.AsyncFunctionDef) and n.name == route
        )
        assert "Permission.USERS_MANAGE" in ast.unparse(func.args), f"{route} is not admin-only now"
    assert [
        r.value for r, p in BUILTIN_ROLE_PERMISSIONS.items() if Permission.USERS_MANAGE in p
    ] == [Role.ADMINISTRATOR.value]
    # ...and no custom role can hold it either: the write-time validator refuses it.
    assert Permission.USERS_MANAGE in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
    with pytest.raises(CustomRoleError, match="not assignable"):
        validate_custom_role_permissions([Permission.USERS_MANAGE.value])
    assert "FEDERATED_SUBJECT_NOT_BOUND" in {
        n.id for n in ast.walk(_service_func("_authenticate_oidc")) if isinstance(n, ast.Name)
    }, "_authenticate_oidc no longer refuses a federated identity bound to no account"


def test_the_thirteenth_sweep_remote_console_redirects_rather_than_confines() -> None:
    """docs/REMOTE-CONSOLE.md said a pending browser session "is confined to `/ui/mfa`". The gate
    redirects it there, the page forwards an account with no factor to `/ui/account`, and the
    account and enrolment pages admit it (the probe above)."""
    row = _flat(
        next(
            line
            for line in _doc("docs/REMOTE-CONSOLE.md").splitlines()
            if line.startswith("| Signed in, but every route returns `403` with `X-MFA-Required")
        )
    )
    held = re.findall(
        r"\b(?:confined|restricted|limited|locked|kept|held)\b[^.;|]*`/ui/mfa`|\bonly `/ui/mfa`",
        row,
        re.IGNORECASE,
    )
    assert not held, f"docs/REMOTE-CONSOLE.md holds a pending session at /ui/mfa again: {held}"
    assert any("`/ui/mfa`" in c and "redirect" in c for c in _clauses(row)), (
        "docs/REMOTE-CONSOLE.md's X-MFA-Required row must say the session is redirected to /ui/mfa."
    )


def _deployment_intake_scopes() -> dict[str, str]:
    """The three places docs/DEPLOYMENT.md describes the HTTP intake listener's partner auth."""
    doc = _doc("docs/DEPLOYMENT.md")
    lines = doc.splitlines()
    start = doc.index("### Caveat — accepting inbound web-service calls")
    end = doc.index("\n## ", start)
    return {
        "plane row": next(x for x in lines if x.startswith("| **Inbound web service**")),
        "caveat": doc[start:end],
        "matrix row": next(x for x in lines if x.startswith("| **HTTP source**")),
    }


#: An intake claim the code contradicts: no bearer mode, no partner authentication built, or a
#: peer control that is optional or never enforced. The last three phrasings are true under
#: `warn`, so a clause that names `warn` may use them.
_INTAKE_STALE = re.compile(
    r"\bno bearer\b|bearer/basic|partner authentication[^.]*\bnot built\b"
    r"|\bunenforced\b|\bnot enforced\b|\bneither\b[^.]*\b(?:required|enforced)\b"
    r"|\baccepts (?:any peer|POSTs from anyone)\b|\bstarts cleanly\b",
    re.IGNORECASE,
)


@pytest.mark.parametrize("scope", ["plane row", "caveat", "matrix row"])
def test_the_thirteenth_sweep_deployment_states_the_built_intake_auth(scope: str) -> None:
    """docs/DEPLOYMENT.md said the HTTP intake listener has no bearer or basic partner auth and
    that neither peer control is enforced. `intake_auth` offers `api_key`, `bearer` and
    `mtls_subject`, and `check_http_intake_auth` refuses an off-loopback listener with no
    effective peer control under enforce (the probe above)."""
    text = _deployment_intake_scopes()[scope]
    clauses = _clauses(text)
    assert len(clauses) >= 5, (
        f"docs/DEPLOYMENT.md's intake {scope} cut into {len(clauses)} clause(s), floor 5: the scan "
        "reads too little to clear it."
    )
    stale = [
        c
        for c in clauses
        if (m := _INTAKE_STALE.search(c))
        and (re.search(r"bearer|partner authentication", m.group(0), re.I) or "`warn`" not in c)
    ]
    assert not stale, f"docs/DEPLOYMENT.md's intake {scope} contradicts the code again: {stale}"
    flat = _flat(text)
    for token in ("`intake_auth`", "`api_key`", "`bearer`", "`mtls_subject`"):
        assert token in flat, f"docs/DEPLOYMENT.md's intake {scope} must name {token}"
    if scope != "plane row":
        assert "`check_http_intake_auth`" in flat, (
            f"docs/DEPLOYMENT.md's intake {scope} must name the peer-control gate"
        )
    if scope == "caveat":
        # The controls are not "any of three": once intake_auth names a mode the allow-list is not
        # consulted (the probe above refuses a keyless bearer behind a narrow allow-list).
        assert not re.search(r"\bthree things count\b", flat, re.I), (
            "the caveat counts the controls as any one of three again"
        )
        assert any(
            re.search(r"allow-?list", c, re.I) and re.search(r"not consulted", c) for c in clauses
        ), "the caveat must say the allow-list is not consulted once intake_auth names a mode"


def test_the_thirteenth_sweep_loosening_note_binds_no_user_at_sign_in() -> None:
    """docs/SECURITY-LOOSENING.md said the password of every user who signs in crosses a plain
    `ldap://` hop. Simple-bind sign-in is retired; the step-up re-bind is the only user bind left
    (the probe above)."""
    doc = _doc("docs/SECURITY-LOOSENING.md")
    start = doc.index("### `[auth].ad_allow_insecure_ldap = true`")
    section = doc[start : doc.index("\n### ", start + 1)]
    clauses = [c for c in _clauses(section) if "password" in c]
    assert clauses, "the cleartext-LDAP section names no password, so this check reads nothing"
    # The shared pattern in every tense, so "sign-in", "login", "signed in" and "logged on" are read.
    at_sign_in = [c for c in clauses if SIGN_IN_ANY_TENSE.search(c)]
    assert not at_sign_in, (
        f"docs/SECURITY-LOOSENING.md says a user's sign-in binds a password again: {at_sign_in}"
    )
    assert any(re.search(r"\bstep(?:s|-)? ?up\b", c) for c in clauses), (
        "the cleartext-LDAP section must say the step-up re-bind carries the user's password"
    )


def test_the_thirteenth_sweep_phi_qualifies_the_second_factor_for_oidc() -> None:
    """docs/PHI.md said the engine enforces its own second factor "on any bind". With
    `oidc_require_mfa_claim` on, the default, an OIDC session meets it on the identity provider's
    claim (the probe above). A paragraph that says the factor applies everywhere must say so."""
    paragraphs = [p for p in re.split(r"\n\s*\n", _doc("docs/PHI.md")) if "require_mfa`" in p]
    assert paragraphs, "docs/PHI.md names require_mfa nowhere, so this check reads nothing"
    universal = [
        p
        for p in paragraphs
        if re.search(r"\bany bind\b|\bevery (?:sign-in|session|bind)\b", _flat(p), re.I)
    ]
    assert universal, "docs/PHI.md no longer says where require_mfa applies; re-derive this check"
    bare = [_flat(p)[:120] for p in universal if "oidc_require_mfa_claim" not in p]
    assert not bare, (
        f"docs/PHI.md says the engine's factor applies on any bind without the OIDC claim: {bare}"
    )


#: Shipped docs that carried the claim, at least, with a clause floor below each one's count today.
#: Not every carrier: the IDE extension's own strings and dated records (CHANGELOG, ADRs) are outside.
_PROVISIONING_DOCS = {
    "README.md": 100,
    "docs/SECURITY.md": 2000,
    "docs/EARLY-ADOPTER-GUIDE.md": 300,
    "docs/DEPLOYMENT.md": 250,
    "docs/INSTALL-GUIDE.md": 250,
    "docs/SERVICE.md": 250,
}


@pytest.mark.parametrize("name", sorted(_PROVISIONING_DOCS))
def test_the_thirteenth_sweep_no_doc_says_nobody_can_sign_in_before_provisioning(
    name: str,
) -> None:
    """Six docs said nobody can sign in before `provision-admin` runs. A Windows sign-in is not
    refused for want of an Administrator: it creates a directory row holding no role (the probe
    above). Nobody can MANAGE the engine; somebody can sign in."""
    clauses = _clauses(_doc(name))
    floor = _PROVISIONING_DOCS[name]
    assert len(clauses) >= floor, (
        f"{name} cut into {len(clauses)} clause(s), floor {floor}: the scan reads too little to "
        "clear it."
    )
    stale = [c for c in clauses if SIGN_IN_CLAIM.search(c)]
    assert not stale, f"{name} says nobody can sign in before provisioning again: {stale}"
    # Read in the provisioning paragraph itself: every paragraph that says the engine creates no
    # account AND who cannot manage it must carry the Kerberos note, so a passage elsewhere cannot
    # stand in for it. The README's quick-start line says only the first, and provisions nothing.
    passages = [
        flat
        for p in re.split(r"\n\s*\n", _doc(name))
        if "creates no account on its own" in (flat := _flat(p)) and "nobody can manage" in flat
    ]
    assert passages, f"{name} no longer says who cannot manage a new store; re-derive this check"
    assert all(re.search(r"Kerberos[^.]*\.?[^.]*\bno role\b", p) for p in passages), (
        f"{name} must say, where it provisions the first Administrator, that a Windows sign-in "
        "before then holds no role"
    )
    # The Kerberos note must not read as the default path. At the shipped posture a start with no
    # Administrator is refused, so a sign-in ahead of provisioning happens only if a start goes
    # ahead. A clause placing it ahead of provisioning must carry that condition itself.
    unconditional = [
        c
        for c in clauses
        if "Kerberos" in c
        and re.search(r"\b(?:before|until) (?:then|provisioning)\b", c)
        and not re.search(r"\bgoes ahead\b|\bwarn\b|\bwaive", c)
    ]
    assert not unconditional, (
        f"{name} says a Windows sign-in can come before provisioning with no condition: "
        f"{unconditional}"
    )


#: Dated records keep what they said on the day: the released changelog and its fragments, each
#: numbered ADR (the ADR index, docs/adr/README.md, is a maintained page and IS scanned), and the
#: dated benchmark and status records. Everything else tracked as Markdown is a shipped page.
_DATED_RECORDS = ("CHANGELOG.md", "changelog.d/", "docs/adr/0", "docs/benchmarks/")


def test_the_thirteenth_sweep_no_shipped_page_says_nobody_can_sign_in() -> None:
    """The six docs above carry the provisioning passage; this reads every other tracked page too,
    so a new page cannot bring the claim back unchecked. The IDE extension's TypeScript strings are
    outside it: they are not Markdown, and they are a filed follow-up of their own."""
    out = subprocess.run(
        ["git", "-C", str(_ROOT), "ls-files", "-z", "--", "*.md"], check=True, capture_output=True
    ).stdout.decode("utf-8")
    pages = [rel for rel in out.split("\0") if rel and not rel.startswith(_DATED_RECORDS)]
    assert len(pages) >= 150, (
        f"only {len(pages)} tracked pages found, floor 150; re-derive the list"
    )
    assert set(_PROVISIONING_DOCS) <= set(pages), "control: the six named docs are in the listing"
    assert "docs/adr/README.md" in pages, "control: the ADR index is a page, not a dated record"
    hits = [
        f"{rel}: {c[:120]}"
        # The six named docs are read by the parametrized test above with the same pattern.
        for rel in pages
        if rel not in _PROVISIONING_DOCS
        # Through _doc, the reader every prose check in this file uses: this is a claim about
        # pages, not about source, so it is not a source probe.
        for c in _clauses(_doc(rel))
        if SIGN_IN_CLAIM.search(c)
    ]
    assert not hits, f"a shipped page says nobody can sign in again: {hits}"


def test_the_thirteenth_sweep_second_round_probes_reply_logging_and_opt_in() -> None:
    """The code facts the thirteenth sweep's second round states: the synchronous reply is built,
    the forwarded log copy passes the same filters as stdout, and API mTLS and log forwarding act
    only once configured, with forwarding required at serve under enforce."""
    from messagefoundry import logging_setup
    from messagefoundry.config import settings as settings_module
    from messagefoundry.pipeline import wiring_runner

    # 1. The synchronous captured reply (ADR 0154 increment B).
    assert {"reply_from", "reply_timeout"} <= set(inspect.signature(Http).parameters)
    assert callable(wiring_runner.check_http_sync_reply)

    # 1b. What the blocked turn answers (ADR 0154 D5). A reply captured as anything but accepted or
    #     no-reply resolves `rejected`, and `rejected` is answered 502 WITH the partner's body. Only
    #     a dead or cancelled delivery row resolves `failed`, which is answered 502 with fixed JSON.
    from messagefoundry.pipeline import sync_reply
    from messagefoundry.store.store import OutboxStatus
    from messagefoundry.transports import rest, soap
    from messagefoundry.transports.base import InboundReply, ReplyOutcome
    from messagefoundry.transports.http_listener import HttpSource

    partner = "<soap:Fault>the partner's own words</soap:Fault>"
    listener: Any = SimpleNamespace(reply_on_empty="204", reply_on_timeout="504")
    rejected = InboundReply(outcome=ReplyOutcome.REJECTED, body=partner)
    assert HttpSource._reply_to_wire(listener, rejected, "m1") == (502, partner, None), (
        "a captured rejection is no longer answered 502 with the partner's body: re-derive the "
        "intake caveat in docs/DEPLOYMENT.md"
    )
    status, fixed, _ = HttpSource._reply_to_wire(
        listener, InboundReply(outcome=ReplyOutcome.FAILED), "m1"
    )
    assert (status, "delivery_failed" in fixed, "partner" in fixed) == (502, True, False)
    assert {OutboxStatus.DEAD.value} <= sync_reply._TERMINAL_ROW_STATES

    async def committed(outcome: str) -> InboundReply:
        async def correlate_response(message_id: str) -> list[SimpleNamespace]:
            return [
                SimpleNamespace(
                    kind="response",
                    destination_name="OB",
                    response_seq=1,
                    body=partner,
                    outcome=outcome,
                    headers={},
                )
            ]

        store: Any = SimpleNamespace(correlate_response=correlate_response)
        resolver = sync_reply.SyncReplyResolverImpl(
            store, typing.cast(Any, None), destination="OB", timeout=1.0, content_type="text/xml"
        )
        return await resolver._read_committed_reply("m1", 1, 0)

    for outcome in ("rejected", "unparseable"):
        reply = asyncio.run(committed(outcome))
        assert (reply.outcome, reply.body) == (ReplyOutcome.REJECTED, partner), outcome
    assert asyncio.run(committed("accepted")).outcome is ReplyOutcome.REPLY
    # The caveat's example and its "most": a capturing SOAP send returns a 2xx <Fault> as a
    # rejected reply, and REST retries exactly two 4xx statuses and dead-letters the rest.
    # Read from the code, not the text: some DeliveryResponse(...) call in send passes the literal
    # outcome="rejected", so a comment or docstring naming it cannot keep this green.
    send_tree = ast.parse(textwrap.dedent(inspect.getsource(soap.SoapDestination.send)))
    assert any(
        isinstance(n, ast.Call)
        and ast.unparse(n.func).split(".")[-1] == "DeliveryResponse"
        and any(
            kw.arg == "outcome"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value == "rejected"
            for kw in n.keywords
        )
        for n in ast.walk(send_tree)
    ), "SoapDestination.send no longer returns a captured <Fault> as a rejected reply"
    retried_4xx = rest._RETRYABLE_4XX
    assert retried_4xx == frozenset({408, 429})

    # 2. Each sink handler the engine builds gets the one filter chain, read per handler: every name
    #    bound to a handler constructor is passed to `_install_phi_filters` in the same function.
    sinks = {"_ForwardQueueHandler", "GuardedStreamHandler", "GuardedFileHandler", "StreamHandler"}
    tree = ast.parse(textwrap.dedent(inspect.getsource(logging_setup)))
    built: list[tuple[str, str]] = []
    filtered: set[tuple[str, str]] = set()
    for f in ast.walk(tree):
        if not isinstance(f, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for n in ast.walk(f):
            if (
                isinstance(n, ast.Assign)
                and isinstance(n.value, ast.Call)
                and ast.unparse(n.value.func).split(".")[-1] in sinks
            ):
                built += [(f.name, t.id) for t in n.targets if isinstance(t, ast.Name)]
            if isinstance(n, ast.Call) and ast.unparse(n.func) == "_install_phi_filters":
                filtered |= {(f.name, a.id) for a in n.args if isinstance(a, ast.Name)}
    assert len(built) >= 3, f"the forwarder, stdout and file handler builders moved: {built}"
    unfiltered = [b for b in built if b not in filtered]
    assert not unfiltered, f"{unfiltered} build a log sink without the PHI filter chain"

    # 3. Built is not on: no client CA and no collector by default, and serve's forwarding gate
    #    refuses the default configuration.
    assert settings_module.ApiSettings.model_fields["tls_client_ca_file"].default is None
    assert settings_module.LoggingSettings.model_fields["forward_host"].default is None
    assert settings_module.forwarding_gate_refusal(settings_module.LoggingSettings()) is not None


def test_the_thirteenth_sweep_deployment_does_not_call_the_sync_reply_unbuilt() -> None:
    """docs/DEPLOYMENT.md's intake caveat said the synchronous downstream reply was an ADR 0013
    follow-on, not built, respond-with-receipt only. `reply_from` builds it (the probe above), and
    CONNECTIONS.md says it shipped with ADR 0154 increment B."""
    caveat = _deployment_intake_scopes()["caveat"]
    clauses = _clauses(caveat)
    assert len(clauses) >= 5, f"the intake caveat cut into {len(clauses)} clause(s), floor 5"
    unbuilt = [
        c
        for c in clauses
        if re.search(r"synchronous|SOAP|reply", c, re.I)
        and re.search(r"not built|follow-on|receipt only", c, re.I)
    ]
    assert not unbuilt, f"docs/DEPLOYMENT.md calls the synchronous reply unbuilt again: {unbuilt}"
    flat = _flat(caveat)
    assert "`reply_from`" in flat, (
        "the intake caveat must name reply_from, the setting that builds the synchronous reply"
    )
    # ...and must not promise a partner's own body on every answer: a dead-lettered delivery is
    # answered with fixed JSON.
    assert "502" in flat, "the intake caveat must say a partner error reaches the caller as a 502"
    # Nor may it say the reverse, that every 502 is fixed JSON. The caveat said "That holds only
    # when the partner succeeds: a partner error dead-letters and the caller gets a fixed-JSON
    # `502`, not the partner's own body". A reply captured as a rejection is delivered, not
    # dead-lettered, and its 502 carries the partner's body (the probe above).
    blanket = [
        c
        for c in clauses
        if re.search(r"only when the partner succeeds|\ba partner error\b", c, re.I)
        or ("fixed-JSON" in c and not re.search(r"dead-letter", c, re.I))
    ]
    assert not blanket, (
        f"docs/DEPLOYMENT.md says every partner error is answered with fixed JSON again: {blanket}"
    )
    with_body = [
        c
        for c in clauses
        if "`502`" in c and re.search(r"\breject", c, re.I) and "carries the partner's body" in c
    ]
    assert with_body, (
        "the intake caveat must say a reply captured as a rejection comes back as a 502 that "
        "carries the partner's body"
    )


#: The retracted claim, in each phrasing a doc gave it: the forwarded log copy, or the audit rows in
#: it, called PHI-redacted or PHI-free outright. "PHI-redacted audit rows", "(PHI-redacted) audit"
#: and "PHI-redacted metadata" are the phrasings the first pattern missed. "PHI-redaction filters"
#: does not match: naming the filters is true, and calling their output PHI-redacted is the claim.
_FORWARDED_PHI_FREE = re.compile(
    r"PHI-(?:redacted|free)\)? (?:stream|copy|audit|metadata|rows?|logs?|evidence)"
    r"|redacted (?:stream|copy)"
    r"|(?:copy|stream|rows?|audit) (?:is|are) PHI-(?:redacted|free)",
    re.IGNORECASE,
)

#: A clause about the off-box copy, under the names the docs give it.
_OFF_BOX_COPY = re.compile(r"forward|collector|off-box|\bSIEM\b|syslog", re.IGNORECASE)


@pytest.mark.parametrize(
    ("name", "floor", "subject_floor"),
    [
        ("docs/EARLY-ADOPTER-GUIDE.md", 300, 5),
        ("docs/PHI.md", 1000, 30),
        ("docs/DEPLOYMENT.md", 300, 8),
        ("docs/CONFIGURATION.md", 2000, 30),
        ("docs/SECURITY.md", 2000, 25),
        ("docs/CONTAINER-EXPOSURE-EVALUATION.md", 150, 6),
    ],
)
def test_the_thirteenth_sweep_no_doc_calls_the_forwarded_copy_phi_free(
    name: str, floor: int, subject_floor: int
) -> None:
    """docs/EARLY-ADOPTER-GUIDE.md told the reader not to copy the potential-PHI log files off-box
    because forwarding sends "a PHI-redacted stream" instead, and docs/PHI.md's forwarder row said
    "the forwarded copy is PHI-redacted". The forwarded copy passes the same best-effort filters as
    stdout (the probe above), and docs/PHI.md grades the log files and the spool both "Possibly".

    That correction left the same claim standing as "PHI-redacted audit rows", "(PHI-redacted)
    audit" and "PHI-redacted metadata", here and in four more documents. The audit tee scrubs only
    HL7-shaped spans out of a row's ``detail`` (the probe above), so a forwarded audit row is no
    more PHI-free than a forwarded log line."""
    clauses = _clauses(_doc(name))
    assert len(clauses) >= floor, f"{name} cut into {len(clauses)} clause(s), floor {floor}"
    forwarded = [c for c in clauses if _OFF_BOX_COPY.search(c)]
    assert len(forwarded) >= subject_floor, (
        f"{name} has {len(forwarded)} clause(s) about the off-box copy, floor {subject_floor}: "
        "this check reads too little to clear it"
    )
    # No exemption for a clause that also says "best-effort" somewhere: "the copy is PHI-free once
    # the best-effort filters have run" is the retracted claim with one word added.
    phi_free = [c for c in forwarded if _FORWARDED_PHI_FREE.search(c)]
    assert not phi_free, f"{name} presents the forwarded log copy as PHI-free again: {phi_free}"
    if name == "docs/EARLY-ADOPTER-GUIDE.md":
        assert any("collector" in c and "potential PHI" in c for c in forwarded), (
            "the guide must say the collector's copy is potential PHI too"
        )


def test_the_thirteenth_sweep_phi_says_built_is_not_on() -> None:
    """docs/PHI.md said mTLS, revocation and off-box logs are "built into the engine" with nothing
    on what turns them on, and sent the reader to section 11 for `forward_*`, which section 7
    documents."""
    doc = _doc("docs/PHI.md")
    paragraphs = [
        _flat(p)
        for p in re.split(r"\n\s*\n", doc)
        if "built into the engine" in _flat(p) and "mTLS" in p and "off-box" in p
    ]
    assert paragraphs, "docs/PHI.md no longer says the off-loopback controls are built"
    for p in paragraphs:
        for token in (
            "`[api].tls_client_ca_file`",
            "`[logging].forward_host`",
            "`[logging].forward_tls_crl_file`",
        ):
            assert token in p, f"docs/PHI.md's built-controls paragraph must name {token}"
    clauses = _clauses(doc)
    assert len(clauses) >= 1000, f"docs/PHI.md cut into {len(clauses)} clause(s), floor 1000"
    # _clauses strips emphasis asterisks, so `forward_*` reads as `forward_` here.
    forward_rows = [c for c in clauses if "`[logging].forward_`" in c]
    assert forward_rows, "docs/PHI.md names [logging].forward_* nowhere, so this reads nothing"
    misdirected = [c for c in forward_rows if re.search(r"§11|#11-hardening", c)]
    assert not misdirected, f"docs/PHI.md sends forward_* to section 11 again: {misdirected}"


def test_the_passkey_leg_asks_the_directory_and_the_doc_says_so() -> None:
    """BACKLOG #2239. The step-up section said "the passkey leg does not ask the directory", which
    was true until ``finish_webauthn_assertion`` gained the same directory check ``verify_mfa`` has
    (#2023). This pins the call, then refuses the old sentence and asks for the new citation. The
    behaviour (refused before the challenge is taken, nothing charged) is pinned in
    ``tests/test_passkey_directory_recheck.py``, not by this AST read."""
    assertion = _service_func("finish_webauthn_assertion")
    assert _called(assertion, "_directory_step_up_refusal"), (
        "finish_webauthn_assertion no longer asks the directory; the step-up section and the "
        "passkey row say it does (BACKLOG #2239)."
    )
    provider_reads = sum(
        1 for n in ast.walk(assertion) if isinstance(n, ast.Attribute) and n.attr == "auth_provider"
    )
    assert provider_reads == 1, (
        f"finish_webauthn_assertion reads auth_provider {provider_reads} times; the lockout "
        "paragraph says each second-factor leg has ONE provider branch, the directory check."
    )
    text = " ".join(_doc_text().split())
    assert "the passkey leg does not ask the directory" not in text, (
        "docs/SECURITY.md says the passkey leg does not ask the directory again; it does (#2239)."
    )
    assert "BACKLOG #2239" in _section(), (
        "the pathway section no longer names the passkey leg's provider branch (BACKLOG #2239)."
    )
    paragraph = next(
        (
            " ".join(p.split())
            for p in re.split(r"\n\s*\n", _doc_text())
            if p.startswith("**The passkey leg asks the same question")
        ),
        None,
    )
    assert paragraph is not None, "the step-up section lost the passkey leg's directory paragraph"
    for token in (
        "`auth.webauthn_failed`",
        "`reason=directory_unconfirmed`",
        "challenge in flight",
    ):
        assert token in paragraph, f"the passkey leg's directory paragraph must name {token}"
