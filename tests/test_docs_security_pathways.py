# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-drift guard for the comparative authentication-strength table (ASVS 6.1.3).

6.1.3 asks that the *relative strength* of every authentication pathway be documented. The table was
scored Partial because it had three rows while five pathways shipped — OIDC federation and the mTLS
service-identity plane were both live and both absent. A table that silently falls one pathway behind
is the defect itself, so the row set is keyed on **code artefacts existing**, not on a hardcoded list:
the interactive pathways are enumerated from the ``AuthService`` entry points that mint a
``LoginOutcome``, and each row is additionally anchored to the settings field that turns it on.

Also pins the numbers the table quotes (lockout, MFA-claim gate, the sign-in window's two dimensions,
the reconciler default) to the live defaults, and asserts the two corrected falsehoods cannot return.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from messagefoundry.api import security as api_security
from messagefoundry.api.security import _PHI_VIEW_PERMISSIONS, require_service_cert
from messagefoundry.auth.permissions import Permission, Role
from messagefoundry.auth.policy import PasswordPolicy
from messagefoundry.auth.service import AuthProvider, AuthService
from messagefoundry.config.settings import ApiSettings, AuthSettings

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "SECURITY.md"
_HEADING = "### Authentication pathways — comparative strength"

#: The interactive entry points that mint a session. Derived by introspection so a SIXTH pathway
#: landing without a comparative-strength row reds CI.
_LOGIN_ENTRY_POINTS = frozenset(
    {"login", "authenticate_kerberos", "complete_oidc_login", "authenticate_oidc"}
)

#: Row token -> the settings field whose existence proves the pathway still ships. ``None`` = always
#: available (Local needs no switch). ``mTLS`` is the fifth, non-interactive pathway.
_PATHWAY_ANCHORS: dict[str, tuple[type[BaseModel], str] | None] = {
    "**Local**": None,
    "**AD**": (AuthSettings, "ad_enabled"),
    "**Kerberos / SPNEGO**": (AuthSettings, "kerberos_enabled"),
    "**OIDC federation**": (AuthSettings, "oidc_enabled"),
    "**mTLS service identity**": (ApiSettings, "tls_client_cert_identities"),
}

#: Tokens the numbered-6.1.3 paragraph must enumerate — it is the artefact that cites the requirement.
_PARAGRAPH_TOKENS = ("Local", "AD", "Kerberos", "OIDC", "mTLS")

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
    """The interactive pathway set is derived from the code, so a sixth one reds CI.

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
    # to 3 interactive pathways beyond Local; +Local +mTLS = 5 rows.
    assert len(_PATHWAY_ANCHORS) == 5
    # BLIND SPOT CLOSED. The public-coroutine derivation above cannot see a sixth pathway added
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
    assert private == {"_login_local", "_login_ad"}, (
        f"the private login coroutines changed: {sorted(private ^ {'_login_local', '_login_ad'})}. A "
        "new `_login_*` returning a LoginOutcome is a new authentication pathway and needs a "
        "comparative-strength row in docs/SECURITY.md (ASVS 6.1.3)."
    )


def test_every_pathway_row_is_anchored_to_a_live_code_artefact() -> None:
    block = _section()
    for token, anchor in _PATHWAY_ANCHORS.items():
        assert token in block, f"the comparative-strength table has no {token} row"
        if anchor is None:
            continue
        model, field = anchor
        assert field in model.model_fields, (
            f"{model.__name__}.{field} no longer exists, but docs/SECURITY.md still tabulates the "
            f"{token} pathway. Remove the row or fix the anchor."
        )


def test_companion_table_covers_the_remaining_strength_dimensions() -> None:
    """The four primary columns cannot carry phishing/replay/storage/MFA/revocation, so a companion
    table does — with the same five rows, in the same order."""
    tables = _tables(_section())
    companion = [
        t for t in tables if t[0][:2] == ["Pathway", "Phishing resistance"] and "Revocation" in t[0]
    ]
    assert companion, (
        "the companion comparative table (| Pathway | Phishing resistance | Replay resistance | "
        "Credential stored by the engine | MFA support | Revocation |) is missing."
    )
    body = companion[0][1:]
    assert len(body) == len(_PATHWAY_ANCHORS)


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
        (AuthSettings, "require_mfa", True, "`[auth].require_mfa` defaults **on**"),
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


def test_the_numbered_paragraph_enumerates_all_five_pathways() -> None:
    """The paragraph citing ASVS 6.1.3 by number is the scored artefact, so it must be complete."""
    block = _section()
    marker = "ASVS 6.1.3"
    assert marker in block, "the section must still cite ASVS 6.1.3 by number"
    paragraph = block[block.index(marker) :]
    missing = [t for t in _PARAGRAPH_TOKENS if t not in paragraph]
    assert not missing, (
        f"the ASVS 6.1.3 paragraph does not enumerate {missing}; it must state which controls do and "
        "do not cover every one of the five pathways."
    )


def test_the_one_switch_that_flattens_three_pathways_is_named_in_each_row() -> None:
    """6.1.3 asks whether the strongest pathway is undermined by the weakest.

    ``[auth].login_rate_limit_enabled = false`` builds no ``_login_limiter``, so ``allow_login_attempt``
    returns True unconditionally: the AD, Kerberos and OIDC rows lose their ONLY engine-side control,
    while Local keeps a lockout the 6.1.1 table records as having no dedicated off switch. Stating the
    limiter unconditionally overstates the directory pathways' floor.
    """
    assert AuthSettings.model_fields["login_rate_limit_enabled"].default is True, (
        "login_rate_limit_enabled no longer defaults on; restate the comparative-strength rows."
    )
    token = "login_rate_limit_enabled"
    for prefix in ("**AD**", "**Kerberos / SPNEGO**", "**OIDC federation**"):
        row = next(r for r in _primary_table()[1:] if r[0].startswith(prefix))
        assert token in row[2], (
            f"the {prefix} row's Brute-force-defense cell states the sign-in window without naming "
            f"`[auth].{token}` — the one flag that removes it entirely, leaving that pathway with no "
            "engine-side control at all."
        )
    block = _section()
    paragraph = block[block.index("ASVS 6.1.3") :]
    assert token in paragraph, (
        "the ASVS 6.1.3 paragraph must name the switch that flattens three of the five pathways to "
        "directory-only defense — that is the comparative-strength answer the requirement wants."
    )


def test_the_console_dependency_of_the_browser_legs_is_stated() -> None:
    """OIDC is browser-only, so a JSON-only deployment has no OIDC route at all — while
    ``GET /auth/providers`` still advertises it, because ``oidc_available`` never consults the
    console mount. The enforcement paragraph must say both halves."""
    source = inspect.getsource(AuthService.oidc_available.fget)  # type: ignore[union-attr]
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


def test_local_row_scopes_the_second_factor_to_step_up_and_administrator() -> None:
    """The Factor column IS the comparative claim, so it must carry the scope qualifier.

    Pinned against ``_mfa_required_for``. Since ASVS 6.3.3 the DEFAULT scope is
    ``every_local_account``, so a plain local account IS required to carry a second factor; the
    Administrator-only rule survives as the ``administrators`` opt-out. Both arms are asserted, so
    neither the default flip nor the opt-out can regress without reddening this guard.
    """
    service = AuthService.__new__(AuthService)
    service._settings = AuthSettings(require_mfa=True)  # type: ignore[attr-defined]
    user = SimpleNamespace(auth_provider=AuthProvider.LOCAL.value)
    assert (
        service._mfa_required_for(  # type: ignore[arg-type]
            user, frozenset({Role.OPERATOR}), second_factor_enrolled=False
        )
        is True
    ), (
        "_mfa_required_for no longer demands a second factor for a plain local account under the "
        "default scope; the Local row's every_local_account claim is stale — update the doc in the "
        "same change."
    )
    narrowed = AuthService.__new__(AuthService)
    narrowed._settings = AuthSettings(  # type: ignore[attr-defined]
        require_mfa=True, require_mfa_scope="administrators"
    )
    assert (
        narrowed._mfa_required_for(  # type: ignore[arg-type]
            user, frozenset({Role.OPERATOR}), second_factor_enrolled=False
        )
        is False
    ), "require_mfa_scope='administrators' must restore the pre-6.3.3 non-admin exemption"
    assert (
        service._mfa_required_for(  # type: ignore[arg-type]
            user, frozenset({Role.ADMINISTRATOR}), second_factor_enrolled=False
        )
        is True
    )
    assert (
        service._mfa_required_for(  # type: ignore[arg-type]
            user, frozenset({Role.OPERATOR}), second_factor_enrolled=True
        )
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


def test_ad_rows_disclose_the_unconditional_mfa_satisfied_grant() -> None:
    """AD is the dominant pathway in the scored posture, so its MFA truth belongs in the TABLE.

    Since ASVS 6.3.4 the grant is a per-mechanism ARGUMENT rather than a literal inside
    ``_complete_ad_login``, so this is pinned at the call sites: the AD simple-bind leg still passes a
    hard ``True`` (the owner-signed delegated relaxation — an AD password clears every engine MFA gate
    with zero engine-verified evidence, which is what the AD rows must disclose), while the federated
    leg must NOT, because its grant is derived from ``oidc_require_mfa_claim``. Asserting both halves
    keeps the two legs from silently converging in either direction.
    """

    def _mfa_grant(func: object) -> list[ast.expr]:
        tree = ast.parse(textwrap.dedent(inspect.getsource(func)))  # type: ignore[arg-type]
        return [
            kw.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            for kw in node.keywords
            if kw.arg == "mfa_verified"
        ]

    bind_grant = _mfa_grant(AuthService._login_ad)
    assert bind_grant and all(
        isinstance(v, ast.Constant) and v.value is True for v in bind_grant
    ), (
        "the AD simple-bind leg no longer mints sessions mfa_verified=True under the signed "
        "relaxation; the AD rows' disclosure is stale — re-derive it."
    )
    oidc_grant = _mfa_grant(AuthService.authenticate_oidc)
    assert oidc_grant and not any(isinstance(v, ast.Constant) for v in oidc_grant), (
        "the OIDC leg passes a CONSTANT mfa_verified; 6.3.4 requires it to be derived from "
        "[auth].oidc_require_mfa_claim, and the OIDC row claims the engine verifies it."
    )
    factor = next(r for r in _primary_table()[1:] if r[0].startswith("**AD**"))[1]
    for token in ("MFA-satisfied", "unverifiable"):
        assert token in factor, (
            f"the AD Factor cell must state {token!r}: the engine grants MFA satisfaction with no "
            "evidence, which is a comparative-strength fact, not a footnote."
        )
    companion = next(
        t for t in _tables(_section()) if t[0][:2] == ["Pathway", "Phishing resistance"]
    )
    mfa_col = companion[0].index("MFA support")
    ad_mfa = next(r for r in companion[1:] if r[0].startswith("**AD**"))[mfa_col]
    assert "unverifiable" in ad_mfa, (
        "the companion AD row reads as an enforcement claim ('delegated to the directory'); it must "
        "say the grant is unconditional and unverifiable at the engine."
    )
    block = _section()
    marker = "ASVS 6.1.3"
    paragraph = " ".join(block[block.index(marker) :].split())
    assert "same PHI surface" in paragraph, (
        "the 6.1.3 paragraph must state the consequence: every directory pathway satisfies the "
        "engine's MFA gates without an engine-verified factor."
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
    assert len(_NON_BEARER_FACTORIES) + 4 == len(_PATHWAY_ANCHORS), (
        "the four interactive pathways plus every non-bearer plane must equal the documented row set"
    )


# NOTE: test_the_mtls_runbook_and_the_table_cannot_diverge moved to tests/test_off_loopback_runbook.py (2026-07-26). They asserted against
# the deny-listed off-loopback runbook, so on the public mirror they failed at runtime and took
# this whole module's required test leg red — while the rest of this file guards shipped
# behaviour that must keep running publicly. The new home already carries the doc-absent guard.
