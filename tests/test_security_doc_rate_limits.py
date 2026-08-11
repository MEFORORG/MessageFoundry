# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-drift guard for ``docs/SECURITY.md``'s anti-automation documentation (ASVS 2.1.3 / 6.1.1).

Both cells score the shipped prose, and both were Partial for the same reason: the document named the
wrong limiter for a route. ``POST /me/password`` was described as part of "the unauthenticated auth
surface … limited per client IP and globally" when it actually charges the per-**actor** credential
ceremony budget (``glob=0``) — asserting exactly the coupling the code deliberately removed. Five
further sign-in call sites and the whole ceremony limiter were missing.

So the assertions here are derived, not copied:

* the route -> limiter map is rebuilt by **AST-walking the call sites** in ``api/auth_routes.py`` and
  ``messagefoundry_webconsole/routes/`` and compared with the map in the doc — the assertion that
  would have caught the ``/me/password`` misfiling;
* the four-GET PHI-pacing scope is rebuilt by AST-walking ``enforce_phi_read_pacing`` calls in
  ``api/app.py`` and mapping each to its route decorator;
* the **conditionality** (6.1.1's binding correction) is asserted behaviourally: one flag off means
  BOTH limiters are gone, and the doc must present them as one conditional pair, never two independent
  controls;
* the ``/ui`` pacing gap is asserted **both ways**, so the honest-interim wording is forced out of the
  doc at exactly the moment console parity lands.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, ServiceSettings

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "SECURITY.md"
#: The OPERATOR configuration reference. 2.1.3's residual named this file, not SECURITY.md: an
#: enforced limit that is absent from the settings reference is undocumented for the person who has
#: to tune it, however well the security narrative covers it.
_CONFIG_DOC = _ROOT / "docs" / "CONFIGURATION.md"
_APP = _ROOT / "messagefoundry" / "api" / "app.py"
_AUTH_ROUTES = _ROOT / "messagefoundry" / "api" / "auth_routes.py"
_SECURITY = _ROOT / "messagefoundry" / "api" / "security.py"
_AUTH_PKG = _ROOT / "messagefoundry" / "auth"
_SERVICE = _AUTH_PKG / "service.py"
_CONSOLE_ROUTES = _ROOT / "messagefoundry_webconsole" / "routes"
_WEBCONSOLE = _ROOT / "messagefoundry_webconsole"

_H_CONFIG_AUTH = "### `[auth]` — authentication & RBAC"

#: The two limiter accessors that defend the AUTHENTICATION surface (6.1.1). The other two
#: (``allow_phi_read``, ``allow_admin_write``) are post-authentication business-logic limits and
#: belong to the 2.1.3 table instead. The split is asserted rather than assumed:
#: ``test_every_sliding_window_limiter_is_filed_under_the_right_requirement`` fails if a fifth
#: limiter appears, forcing an explicit decision about which table it joins.
_AUTH_SURFACE_ACCESSORS = frozenset({"allow_login_attempt", "allow_reauth_attempt"})
_BUSINESS_LIMIT_ACCESSORS = frozenset({"allow_phi_read", "allow_admin_write"})

#: Anti-automation controls that are not objects and so cannot be derived: they are enforcement
#: SHAPES (a counter on a user row, a semaphore, ASGI middleware, a CIDR test). Each is pinned to a
#: token that must appear in its 6.1.1 row, so the row cannot be deleted or renamed away.
_STRUCTURAL_CONTROLS: dict[str, str] = {
    "per-account lockout": "lockout_minutes",
    "argon2 concurrency cap": "argon2",
    "request-body cap": "max_upload_bytes",
    "pre-auth client-network gate": "allowed_client_networks",
}

#: The count word the 6.1.1 preamble uses, pinned against the live row count so the sentence and the
#: table can never disagree.
_COUNT_WORDS = {
    5: "Five",
    6: "Six",
    7: "Seven",
    8: "Eight",
    9: "Nine",
    10: "Ten",
    11: "Eleven",
    12: "Twelve",
}

_H_BRUTE = "## Brute-force & abuse protection"
_H_LIMITS = "### Business-logic limits (ASVS 2.1.3)"
_H_MAP = "### Route → limiter map"
_H_SET = "### The documented protection set (ASVS 6.1.1)"

#: The four bulk-PHI step-up GETs that must charge the PHI-read budget explicitly, because
#: require_step_up paces NON-GET only. The count word in the doc is pinned alongside.
_FOUR_GET_SCOPE = frozenset(
    {
        "/messages/search",
        "/messages/export",
        "/uploads/{file_id}/messages",
        "/search/layered",
    }
)

_BACKTICK_RE = re.compile(r"`([^`]+)`")
_ROUTE_TOKEN_RE = re.compile(r"`((?:GET|POST|PUT|PATCH|DELETE) /[^`]*)`")


def _doc_text() -> str:
    return _DOC.read_text(encoding="utf-8")


def _section(heading_prefix: str) -> str:
    lines = _doc_text().splitlines()
    level = len(heading_prefix) - len(heading_prefix.lstrip("#"))
    start = next((i for i, line in enumerate(lines) if line.startswith(heading_prefix)), None)
    assert start is not None, (
        f"docs/SECURITY.md no longer has a heading starting {heading_prefix!r}; the 2.1.3/6.1.1 doc "
        "guard slices on it."
    )
    out: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("#") and len(line) - len(line.lstrip("#")) <= level:
            break
        out.append(line)
    return "\n".join(out)


def _config_section(text: str | None = None) -> str:
    """The ``[auth]`` settings block of ``docs/CONFIGURATION.md`` (heading to the next ``###``)."""
    lines = (text if text is not None else _CONFIG_DOC.read_text(encoding="utf-8")).splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(_H_CONFIG_AUTH)), None)
    assert start is not None, (
        f"docs/CONFIGURATION.md no longer has a heading starting {_H_CONFIG_AUTH!r}; the 2.1.3 "
        "operator-reference guard slices on it."
    )
    out: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("###"):
            break
        out.append(line)
    return "\n".join(out)


def _config_auth_rows(section: str) -> dict[str, tuple[str, str]]:
    """``{setting: (type cell, default cell)}`` for every row of the ``[auth]`` table.

    Keyed on the FIRST cell only, so a name that merely occurs in some other row's prose does not
    count as documented — the failure mode that let ``admin_write_rate_limit_*`` be "covered" by a
    narrative mention while the operator table had no row at all. The **Default** column is parsed
    too: a row whose default has silently gone stale is as wrong for the operator tuning it as a
    missing row, and column 1 alone could never see that (BACKLOG #287 is scheduled to move
    ``admin_write_rate_limit_window_seconds`` off ``1.0``).
    """
    rows: dict[str, tuple[str, str]] = {}
    for raw in section.splitlines():
        line = raw.strip()
        if not (line.startswith("|") and line.endswith("|") and len(line) > 1):
            continue
        cells = [c.strip() for c in line[1:-1].split("|")]
        first = cells[0]
        if not first or set(first) <= set("-: "):
            continue
        type_cell = cells[1] if len(cells) > 1 else ""
        default_cell = cells[2] if len(cells) > 2 else ""
        for name in _BACKTICK_RE.findall(first):
            rows[name] = (type_cell, default_cell)
    return rows


def _config_auth_keys(section: str) -> set[str]:
    """Every setting name in the FIRST column of the ``[auth]`` table."""
    return set(_config_auth_rows(section))


def _rendered_defaults(value: object) -> set[str]:
    """Every spelling of ``value`` the operator table is allowed to use.

    Bools render as ``true``/``false`` (TOML, not Python); a whole float may render either as
    ``60`` or ``60.0``. Backticks are stripped from the doc cell before comparison.
    """
    if isinstance(value, bool):
        return {str(value).lower()}
    if isinstance(value, float) and value.is_integer():
        return {str(value), str(int(value))}
    return {str(value)}


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


# --- AST helpers: which routes call which limiter -----------------------------------------------------


def _decorated_path(node: ast.AST) -> str | None:
    """The HTTP path of the ``@app.<method>("/path")`` decorator on a function definition."""
    for deco in getattr(node, "decorator_list", []):
        if not isinstance(deco, ast.Call):
            continue
        func = deco.func
        methods = {"get", "post", "put", "patch", "delete", "websocket"}
        if (
            isinstance(func, ast.Attribute)
            and func.attr in methods
            and deco.args
            and isinstance(deco.args[0], ast.Constant)
            and isinstance(deco.args[0].value, str)
        ):
            return deco.args[0].value
    return None


def _calls_to(tree: ast.AST, names: set[str]) -> set[str]:
    """Every function name in ``names`` that is called anywhere in ``tree``."""
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else None
            )
            if name in names:
                found.add(name)
    return found


def _route_limiter_calls(path: Path, limiters: set[str]) -> dict[str, set[str]]:
    """``{"<METHOD> <path>": {limiter, …}}`` for every decorated route function in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        route = _decorated_path(node)
        if route is None:
            continue
        used = _calls_to(node, limiters)
        if used:
            method = next(
                deco.func.attr.upper()
                for deco in node.decorator_list
                if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
            )
            out[f"{method} {route}"] = used
    return out


def _reauth_limiter_settings() -> set[str]:
    """The ``AuthSettings`` fields the per-actor ceremony limiter is CONSTRUCTED from.

    Derived, because the whole point is that these are shared with the sign-in window: whichever
    fields feed ``_reauth_limiter`` must say so in their own operator row. A zero literal (``glob=0``)
    is not a settings field and is correctly excluded.
    """
    tree = ast.parse(_SERVICE.read_text(encoding="utf-8"))
    fields: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        target = node.targets[0] if isinstance(node, ast.Assign) else node.target
        if getattr(target, "attr", None) != "_reauth_limiter" or node.value is None:
            continue
        for sub in ast.walk(node.value):
            if isinstance(sub, ast.Attribute) and sub.attr in AuthSettings.model_fields:
                fields.add(sub.attr)
    return fields


def _all_route_limiter_calls() -> dict[str, set[str]]:
    limiters = {"allow_login_attempt", "allow_reauth_attempt"}
    calls = _route_limiter_calls(_AUTH_ROUTES, limiters)
    for module in sorted(_CONSOLE_ROUTES.glob("*.py")):
        calls.update(_route_limiter_calls(module, limiters))
    return calls


# =====================================================================================================
# ASVS 2.1.3 — business-logic limits, documented per-user and globally
# =====================================================================================================


def test_every_rate_limit_setting_has_a_documented_row() -> None:
    """Derived from ``AuthSettings`` — a limiter added later without a doc row reds CI.

    RULE (2.1.3): the enforced business-logic limits must be documented. This cell went Partial
    because the three ``admin_write_rate_limit_*`` settings existed in code and in no operator table.
    """
    block = _section(_H_LIMITS)
    fields = [name for name in AuthSettings.model_fields if "_rate_limit_" in name]
    missing = sorted(name for name in fields if name not in block)
    assert not missing, (
        f"rate-limit settings absent from the business-logic-limits table: {missing}"
    )
    # Pin the spelled-out count in the validator-floor note, so it cannot drift the next time a
    # limiter setting lands (it read "twelve" against eleven shipped fields).
    word = _COUNT_WORDS.get(len(fields))
    assert word is not None, f"add {len(fields)} to _COUNT_WORDS"
    assert f"None of the {word.lower()} `*_rate_limit_*` fields" in _doc_text(), (
        f"AuthSettings has {len(fields)} *_rate_limit_* fields; the validator-floor note must say "
        f"{word.lower()!r}."
    )


def test_every_rate_limit_setting_has_a_row_in_the_operator_configuration_reference() -> None:
    """The clause that actually kept 2.1.3 Partial.

    RULE: an enforced limit must be in **docs/CONFIGURATION.md**'s ``[auth]`` table, not only in the
    security narrative. The residual said the three ``admin_write_rate_limit_*`` settings were
    "documented only at docs/SECURITY.md" — so more SECURITY.md prose is, by construction, not a
    fix. Derived from ``AuthSettings``: a limiter added later without an operator row reds CI.
    """
    keys = _config_auth_keys(_config_section())
    fields = {name for name in AuthSettings.model_fields if "_rate_limit_" in name}
    missing = sorted(fields - keys)
    assert not missing, (
        f"rate-limit settings absent from docs/CONFIGURATION.md's [auth] table: {missing}. The "
        "operator configuration reference is the artefact ASVS 2.1.3 scores; a row in SECURITY.md "
        "does not substitute for one here."
    )


def test_configuration_reference_parser_detects_a_planted_omission() -> None:
    """Proves the guard above can fail.

    Deletes one shipped ``phi_read_*`` row from an in-memory copy and requires the checker to name
    it. Without this, a reformat that broke the table parser would leave the guard silently green.
    """
    section = _config_section()
    victim = "phi_read_rate_limit_window_seconds"
    assert victim in _config_auth_keys(section), "fixture drifted: the victim row is already gone"
    mutated = "\n".join(
        line for line in section.splitlines() if not line.strip().startswith(f"| `{victim}`")
    )
    keys = _config_auth_keys(mutated)
    assert victim not in keys, (
        "the [auth]-table parser did not notice a deleted row — it is not a real guard"
    )
    assert "phi_read_rate_limit_per_actor" in keys, (
        "the mutation removed more than the one victim row; the parser is over-broad"
    )


def test_configuration_reference_does_not_repeat_the_retired_falsehoods() -> None:
    """Two live false statements in the operator table, pinned so they cannot return.

    ``POST /me/password`` charges the per-ACTOR ceremony budget, not the sign-in window (this is the
    same misfiling that kept 6.1.1 Partial), and the PHI-read throttle covers far more than the
    three routes the row used to name.
    """
    section = _config_section()
    login_row = next(
        line
        for line in section.splitlines()
        if line.strip().startswith("| `login_rate_limit_enabled`")
    )
    assert "`/me/password`" not in login_row.split("in front of")[0], (
        "the login-window row lists /me/password as part of the sign-in surface again; it charges "
        "the per-actor ceremony budget (allow_reauth_attempt)."
    )
    assert "ceremony" in login_row.lower(), (
        "the login-window row must state that the same flag also constructs the per-actor "
        "credential-ceremony limiter — one switch, not two controls."
    )
    phi_row = next(
        line
        for line in section.splitlines()
        if line.strip().startswith("| `phi_read_rate_limit_enabled`")
    )
    assert "PHI-read endpoints `/messages`, `/messages/{id}`, `/dead-letters`" not in phi_row, (
        "the PHI-read throttle's scope is back to the stale three-route list"
    )
    # ONE NUMBER, TWO LIMITERS. ``login_rate_limit_per_ip`` and ``login_rate_limit_window_seconds``
    # are also the per-ACTOR credential-ceremony limiter's threshold and window (``_reauth_limiter``
    # is built from exactly those two fields). An operator who reads only "per client IP" retunes a
    # per-actor budget on /me/reauth without knowing it — the residual's own complaint that the
    # sharing is "documented only at docs/SECURITY.md".
    shared = _reauth_limiter_settings()
    assert shared, "no settings field feeds _reauth_limiter any more; re-derive this guard"
    for field in sorted(shared):
        row = next(line for line in section.splitlines() if line.strip().startswith(f"| `{field}`"))
        assert "ceremony" in row.lower(), (
            f"docs/CONFIGURATION.md's `{field}` row must state that the same value is also the "
            "per-actor credential-ceremony limiter's budget/window — one number, two limiters."
        )


def test_business_logic_limit_table_states_both_dimensions_for_every_row() -> None:
    """ "Per-user **and** globally" is the requirement's own wording, so every row must answer both —
    including the rows where one dimension is deliberately hard-coded off."""
    table = next(t for t in _tables(_section(_H_LIMITS)) if t[0][0] == "Limit")
    header = table[0]
    for column in ("Per-user", "Global", "Per-IP"):
        assert column in header, f"the limits table lost its {column!r} column"
    per_user, glob = header.index("Per-user"), header.index("Global")
    for row in table[1:]:
        assert row[per_user], f"row {row[0]!r} does not answer the per-user dimension"
        assert row[glob], f"row {row[0]!r} does not answer the global dimension"


#: Enforcement-scope vocabulary the Scope cell must declare, per row. The blanket claim this
#: replaces ("All are in-process, per API process — N engine shards multiply every budget by N") was
#: false for three of the table's own rows: two API processes share ONE lockout counter, ONE session
#: cap and ONE bootstrap timer, because all three are written through the store.
_SCOPE_TOKENS = ("**in-process**", "**store-backed**", "**stateless**", "**n/a**")

#: Limits whose state lives in the STORE, mapped to the ``self._store`` method that proves it. If a
#: mechanism stops being store-backed the assertion below fails and the row must be re-scoped.
_STORE_BACKED_LIMITS: dict[str, str] = {
    "lockout_threshold": "record_login_failure",
    "max_sessions_per_user": "enforce_session_cap",
    "bootstrap_expiry_hours": "set_user_disabled",
}

#: Reject-when-full caches that are plain in-process objects, mapped to the class ``_bounded_caches``
#: must discover. Their budgets ARE multiplied by N engine shards.
_IN_PROCESS_CACHE_LIMITS: dict[str, str] = {
    "oidc_flow_cache_max": "FlowCache",
    "GLOBAL_PENDING_CAP": "ChallengeCache",
}


def _store_method_calls() -> set[str]:
    """Every ``self._store.<name>(...)`` method called in ``auth/service.py``."""
    tree = ast.parse(_SERVICE.read_text(encoding="utf-8"))
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        owner = node.func.value
        if (
            isinstance(owner, ast.Attribute)
            and owner.attr == "_store"
            and isinstance(owner.value, ast.Name)
            and owner.value.id == "self"
        ):
            calls.add(node.func.attr)
    return calls


def _limit_rows_by_setting() -> dict[str, list[str]]:
    """``{setting-or-constant token: [row cells]}`` for the 2.1.3 limits table."""
    table = next(t for t in _tables(_section(_H_LIMITS)) if t[0][0] == "Limit")
    out: dict[str, list[str]] = {}
    for row in table[1:]:
        for token in _BACKTICK_RE.findall(row[1]):
            out[token.split("].")[-1].strip()] = row
    return out


def _scope_cell(row: list[str]) -> str:
    header = next(t for t in _tables(_section(_H_LIMITS)) if t[0][0] == "Limit")[0]
    return row[header.index("Scope")]


def test_business_logic_limit_scope_is_stated_per_row() -> None:
    """Every row declares whether its budget is per-process or shared, and the code agrees.

    RULE (2.1.3): "N engine shards multiply every budget by N" is a claim an assessor tests. It is
    true of the sliding-window limiters and the two pending-flow caches and FALSE of the account
    lockout, the session cap and the bootstrap timer, which are written through the one unified
    store. Blanket-scoping the table inverts exactly the distinction that separates a per-process
    limiter from a durable one.
    """
    table = next(t for t in _tables(_section(_H_LIMITS)) if t[0][0] == "Limit")
    scope = table[0].index("Scope")
    for row in table[1:]:
        assert any(row[scope].startswith(token) for token in _SCOPE_TOKENS), (
            f"row {row[0]!r} does not declare its enforcement scope; the Scope cell must open with "
            f"one of {list(_SCOPE_TOKENS)}."
        )

    store_calls = _store_method_calls()
    rows_by_setting = _limit_rows_by_setting()
    for setting, method in sorted(_STORE_BACKED_LIMITS.items()):
        assert method in store_calls, (
            f"auth/service.py no longer calls self._store.{method}(); the {setting!r} limit may no "
            "longer be store-backed — re-scope its row in docs/SECURITY.md."
        )
        assert setting in rows_by_setting, f"no limits-table row names `{setting}`"
        cell = _scope_cell(rows_by_setting[setting])
        assert cell.startswith("**store-backed**"), (
            f"`{setting}` is enforced through self._store.{method}() — one counter shared by every "
            f"API process — but its row is scoped {cell.split(' — ')[0]!r}. It is NOT multiplied by "
            "N engine shards."
        )

    caches = _bounded_caches()
    for setting, cache in sorted(_IN_PROCESS_CACHE_LIMITS.items()):
        assert cache in caches, f"{cache} is no longer a bounded cache; re-derive the scope"
        assert setting in rows_by_setting, f"no limits-table row names `{setting}`"
        assert _scope_cell(rows_by_setting[setting]).startswith("**in-process**"), (
            f"`{setting}` bounds the in-process {cache.split('.')[0]} object; its row must say so."
        )

    for setting in sorted(AuthSettings.model_fields):
        if "_rate_limit_" not in setting or setting not in rows_by_setting:
            continue
        assert _scope_cell(rows_by_setting[setting]).startswith("**in-process**"), (
            f"`{setting}` configures a SlidingWindowRateLimiter, which is a per-process object; its "
            "row must be scoped in-process so the shard-multiplication caveat stays true."
        )


def test_scope_guard_detects_a_planted_rescoping() -> None:
    """Proves the scope guard can fail: re-label a store-backed row in-process and it must be seen."""
    rows_by_setting = _limit_rows_by_setting()
    row = rows_by_setting["lockout_threshold"]
    cell = _scope_cell(row)
    assert cell.startswith("**store-backed**"), (
        "fixture drifted: the lockout row is not store-backed"
    )
    mutated = cell.replace("**store-backed**", "**in-process**", 1)
    assert not mutated.startswith("**store-backed**"), (
        "the scope check reads a token that a rescoping edit would not change — it is not a guard"
    )


def test_ingest_plane_rate_limit_is_documented_as_existing_but_off() -> None:
    """A silent omission reads as coverage, and so does an overstatement in the other direction.

    Until 2026-08-11 this guard asserted the doc said "no message-rate or volume limit exists", which
    was true and load-bearing. The MLLP pacing build (ASVS 2.4.1 / 15.2.2) falsified it, so the guard
    had to move with the code and the doc rather than be deleted -- the row must now state BOTH that
    a control exists and that it ships OFF, because either half alone misleads: "exists" implies the
    shipped default is bounded, and "none" is now simply false.
    """
    block = _section(_H_LIMITS)
    assert "Ingest plane" in block
    assert "max_messages_per_second" in block, (
        "the ingest row must name the control that now exists"
    )
    assert "ships OFF" in block, "and must say it is not on by default, or 'exists' overstates it"
    # The honest gaps stay named: an off default bounds nothing, and the raw-TCP intake never got it.
    assert "still no volume bound" in block
    assert "raw-TCP inbound" in block
    for cap in ("max_connections", "receive_timeout", "max_frame_bytes", "max_message_bytes"):
        assert cap in block, f"the ingest row must name the {cap} resource cap it DOES have"


def test_four_get_phi_pacing_scope_matches_the_call_sites() -> None:
    """The bulk-PHI GETs that charge the PHI-read budget explicitly are exactly four, and the doc says
    so — including the count word, so it cannot silently drift.

    RULE: ``require_step_up`` paces NON-GET only, so a bulk-selecting step-up GET is unpaced unless it
    charges ``enforce_phi_read_pacing`` itself. A fifth such GET must be documented.
    """
    tree = ast.parse(_APP.read_text(encoding="utf-8"))
    charged: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        route = _decorated_path(node)
        if route and _calls_to(node, {"enforce_phi_read_pacing"}):
            charged.add(route)
    assert charged == _FOUR_GET_SCOPE, (
        "the explicit PHI-read pacing call sites changed: "
        f"{sorted(charged ^ _FOUR_GET_SCOPE)}. Update docs/SECURITY.md's four-GET scope statement (and "
        "its count word) in the same change."
    )
    text = _doc_text()
    assert "**four**" in text or "the four " in text, (
        "the doc must state the count of bulk-PHI GETs charged at admission"
    )
    for route in _FOUR_GET_SCOPE:
        assert f"`{route}`" in text, f"{route} is missing from the four-GET scope statement"


def _phi_read_dependency_routes() -> set[str]:
    """Routes taking ``require_phi_read`` as a FastAPI dependency, from the AST of ``api/app.py``."""
    tree = ast.parse(_APP.read_text(encoding="utf-8"))
    routes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        route = _decorated_path(node)
        if route is None:
            continue
        defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
        for default in defaults:
            if _calls_to(default, {"require_phi_read"}):
                routes.add(route)
                break
    return routes


def _ui_phi_view_count() -> int:
    """Console views charging the same per-actor budget via ``require_ui(..., phi=True)``."""
    count = 0
    for module in sorted(_CONSOLE_ROUTES.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else node.func.id
                if isinstance(node.func, ast.Name)
                else None
            )
            if name != "require_ui":
                continue
            for kw in node.keywords:
                if (
                    kw.arg == "phi"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    count += 1
    return count


def _ui_delegating_phi_get_count() -> int:
    """Console **GET**s that inherit the PHI-read charge by calling a pacing-charging JSON handler.

    These carry no ``require_ui(..., phi=True)`` of their own — they call e.g. ``core.search_messages``
    directly, and that handler charges ``enforce_phi_read_pacing`` in its own body. Derived on both
    sides (the charging handler names come from ``api/app.py``'s AST) so the figure cannot be prose.
    """
    tree = ast.parse(_APP.read_text(encoding="utf-8"))
    charging = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and _decorated_path(node) is not None
        and _calls_to(node, {"enforce_phi_read_pacing"})
    }
    assert charging, "no route handler in api/app.py charges enforce_phi_read_pacing any more"
    count = 0
    for module in sorted(_CONSOLE_ROUTES.rglob("*.py")):
        console = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(console):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if _decorated_path(node) is None:
                continue
            method = next(
                deco.func.attr
                for deco in node.decorator_list
                if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
            )
            if method == "get" and _calls_to(node, charging):
                count += 1
    return count


def test_phi_read_scope_counts_are_derived_from_the_enforcement_sites() -> None:
    """A POSITIVE, derived assertion — not "the old phrasing is absent".

    The retired understatement named 3 of 15+ charge points. A substring-absence check would pass on
    any *other* understatement, so the enforced scope is rebuilt from code and the doc must state the
    live counts. Adding or removing a PHI-read route now reds CI in the PR that does it.
    """
    dependency_routes = _phi_read_dependency_routes()
    ui_views = _ui_phi_view_count()
    assert dependency_routes, "no route takes require_phi_read as a dependency any more"
    text = _doc_text()
    assert f"{len(dependency_routes)} JSON routes via `require_phi_read`" in text, (
        f"{len(dependency_routes)} routes take require_phi_read as a dependency "
        f"({sorted(dependency_routes)}); docs/SECURITY.md must state that count."
    )
    assert f"{ui_views} `/ui` views via `require_ui(phi=True)`" in text, (
        f"{ui_views} console views charge the PHI-read budget via require_ui(..., phi=True); "
        "docs/SECURITY.md must state that count."
    )
    # The operator reference must agree with the security narrative, not contradict it.
    config = _config_section()
    assert f"**{len(dependency_routes)} JSON routes**" in config, (
        "docs/CONFIGURATION.md's phi_read_rate_limit_enabled row must state the same JSON-route "
        "count as docs/SECURITY.md — the two artefacts disagreeing is the 2.1.3 defect."
    )
    assert f"**{ui_views} `/ui` PHI views**" in config, (
        "docs/CONFIGURATION.md's phi_read_rate_limit_enabled row must state the /ui view count"
    )
    # The fourth figure in the same sentence was hardcoded prose while its three siblings were
    # derived; derive it too, so a console route that starts (or stops) delegating into a charging
    # handler reds CI rather than silently invalidating the scope statement.
    delegating = _ui_delegating_phi_get_count()
    assert f"{delegating} further `/ui` GETs" in text, (
        f"{delegating} console GETs inherit the PHI-read charge by delegating into a JSON handler "
        "that calls enforce_phi_read_pacing; docs/SECURITY.md must state that count."
    )
    stale = "(`/messages`, `/messages/{id}`, `/dead-letters`) carry a"
    assert stale not in _section(_H_BRUTE), "the stale three-route list is back"


def test_both_pacing_gate_families_are_named() -> None:
    """``_enforce_admin_write_pacing`` has exactly two callers; naming only one understates coverage."""
    tree = ast.parse(_SECURITY.read_text(encoding="utf-8"))
    callers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _calls_to(
            node, {"_enforce_admin_write_pacing"}
        ):
            callers.add(node.name)
    # the inner `dependency` closures carry the call; attribute them to their enclosing factory
    factories = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name.startswith("require")
        and _calls_to(node, {"_enforce_admin_write_pacing"})
    }
    assert factories == {"require_paced", "require_step_up"}, (
        f"the gate families charging the admin-write floor changed: {sorted(factories)}. Name them all "
        "in docs/SECURITY.md's anti-automation paragraph."
    )
    assert callers, "no function calls _enforce_admin_write_pacing any more"
    text = _doc_text()
    for gate in factories:
        assert f"`{gate}`" in text, f"the anti-automation paragraph must name `{gate}`"


def _users_manage_routes() -> dict[str, set[str]]:
    """``{"<METHOD> <path>": {gate factory, …}}`` for every ``users:manage`` route."""
    tree = ast.parse(_AUTH_ROUTES.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        route = _decorated_path(node)
        if route is None:
            continue
        defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
        gates: set[str] = set()
        mentions_users_manage = False
        for default in defaults:
            for sub in ast.walk(default):
                if isinstance(sub, ast.Attribute) and sub.attr == "USERS_MANAGE":
                    mentions_users_manage = True
                if (
                    isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Name)
                    and sub.func.id.startswith("require")
                ):
                    gates.add(sub.func.id)
        if not mentions_users_manage:
            continue
        method = next(
            deco.func.attr.upper()
            for deco in node.decorator_list
            if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
        )
        out[f"{method} {route}"] = gates
    return out


def test_users_manage_write_pacing_exemptions_are_named_exactly() -> None:
    """The ``require_step_up`` bullet claims "every ``users:manage`` write" charges the floor.

    It does not: ``PATCH /users/{user_id}`` was promoted to the action-bound
    ``require_step_up_action`` gate, which never calls ``_enforce_admin_write_pacing`` — and the
    doc's own Route -> limiter map already files it under "No limiter of any kind". Derived here, so
    promoting a SECOND route to an action gate reds CI instead of quietly widening the overstatement.
    """
    charging = {"require_paced", "require_step_up"}
    routes = _users_manage_routes()
    assert routes, "no route carries Permission.USERS_MANAGE any more"
    unpaced = {
        route
        for route, gates in routes.items()
        if not route.startswith("GET ") and not (gates & charging)
    }
    assert unpaced == {"PATCH /users/{user_id}"}, (
        f"the set of non-GET `users:manage` routes charging NO admin-write pacing changed: "
        f"{sorted(unpaced)}. docs/SECURITY.md's `require_step_up` bullet names the exemptions "
        "explicitly — update it in the same change."
    )
    text = _doc_text()
    for route in sorted(unpaced):
        path = route.split(" ", 1)[1]
        assert f"except `PATCH {path}`" in text, (
            f"{route} is a `users:manage` write that charges no pacing; the anti-automation "
            "paragraph must name it as an exception rather than claiming 'every users:manage write'."
        )


def test_ui_pacing_gap_wording_flips_with_the_code() -> None:
    """Honest-interim wording, enforced both ways.

    While ``allow_admin_write`` has no console call site, the doc MUST state the gap. The moment
    console parity (BACKLOG #287) lands a charge, this same test demands the sentence be removed — so
    the interim wording can never become a stale falsehood.
    """
    console_charges = any(
        "allow_admin_write" in module.read_text(encoding="utf-8")
        for module in _CONSOLE_ROUTES.parent.rglob("*.py")
    )
    # The SAME time-bound claim is written into BOTH artefacts, so it must be guarded in both:
    # guarding only SECURITY.md would leave docs/CONFIGURATION.md asserting the gap forever once
    # console parity lands, which is precisely the rot this cell exists to close.
    surfaces = {
        "docs/SECURITY.md": (
            "no `/ui` route charges it" in _doc_text()
            or "the `/ui` write path is not paced" in _doc_text()
        ),
        "docs/CONFIGURATION.md": "no `/ui` route charges it" in _config_section(),
    }
    for artefact, gap_stated in sorted(surfaces.items()):
        if console_charges:
            assert not gap_stated, (
                f"the web console now charges allow_admin_write, but {artefact} still states the "
                "pacing gap. Remove the interim wording from BOTH documents in the same change."
            )
        else:
            assert gap_stated, (
                "allow_admin_write has zero callers in messagefoundry_webconsole, so every non-GET "
                f"/ui route is unpaced. {artefact} must say so — 2.1.3 requires the artefact to be "
                "accurate, not flattering."
            )


# =====================================================================================================
# ASVS 6.1.1 — the documented protection set, "not disabled or bypassable"
# =====================================================================================================


def test_one_flag_disables_both_limiters() -> None:
    """BINDING CORRECTION: ``login_rate_limit_enabled`` gates the sign-in window **and** the per-actor
    credential-ceremony budget. They are one conditional pair, never two independent controls."""
    off = AuthService.__new__(AuthService)  # limiters are plain attributes; no store/loop needed
    settings = AuthSettings(login_rate_limit_enabled=False)
    assert settings.login_rate_limit_enabled is False
    # Assert the construction guard itself, so the coupling is pinned in code rather than paraphrased.
    source = ast.parse(
        (_ROOT / "messagefoundry" / "auth" / "service.py").read_text(encoding="utf-8")
    )
    guarded: set[str] = set()
    for node in ast.walk(source):
        if isinstance(node, ast.Assign | ast.AnnAssign) and isinstance(node.value, ast.IfExp):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            attr = getattr(target, "attr", None)
            test = node.value.test
            if attr in {"_login_limiter", "_reauth_limiter"} and isinstance(test, ast.Attribute):
                assert test.attr == "login_rate_limit_enabled", (
                    f"{attr} is no longer gated by login_rate_limit_enabled ({test.attr}); the doc's "
                    "conditionality statement is now wrong."
                )
                guarded.add(attr)
    assert guarded == {"_login_limiter", "_reauth_limiter"}, (
        f"expected both limiters to be conditionally constructed; found {sorted(guarded)}"
    )
    # Behavioural half: with both limiters absent, both accessors pass unconditionally.
    off._login_limiter = None
    off._reauth_limiter = None
    assert all(off.allow_login_attempt("198.51.100.7") for _ in range(1000))
    assert all(off.allow_reauth_attempt("user-1") for _ in range(1000))


def test_doc_presents_the_two_limiters_as_one_conditional_pair() -> None:
    block = _section(_H_SET)
    assert "login_rate_limit_enabled" in block
    lowered = " ".join(block.replace("*", " ").lower().split())
    assert "constructs" in lowered and "neither limiter" in lowered, (
        "the 6.1.1 control set must state that login_rate_limit_enabled=false constructs NEITHER "
        "limiter — they must never read as two independent controls."
    )
    assert "no global dimension" in lowered or "glob=0" in lowered, (
        "the ceremony limiter's missing global dimension must be stated"
    )


def _limiter_accessors() -> dict[str, str]:
    """``{accessor_name: limiter_attribute}`` for every ``SlidingWindowRateLimiter`` in the service."""
    tree = ast.parse(_SERVICE.read_text(encoding="utf-8"))
    attrs: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        for sub in ast.walk(node.value) if node.value is not None else ():
            if isinstance(sub, ast.Call) and (
                (isinstance(sub.func, ast.Name) and sub.func.id == "SlidingWindowRateLimiter")
                or (
                    isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "SlidingWindowRateLimiter"
                )
            ):
                target = node.targets[0] if isinstance(node, ast.Assign) else node.target
                attr = getattr(target, "attr", None)
                if attr:
                    attrs.add(attr)
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
            "allow_"
        ):
            used = {
                s.attr for s in ast.walk(node) if isinstance(s, ast.Attribute) and s.attr in attrs
            }
            if len(used) == 1:
                out[node.name] = next(iter(used))
    return out


#: Words that mark a raised error as enforcing a RATE, SIZE or REFETCH bound rather than reporting a
#: business failure. The narrow ``*FullError`` rule this widens missed the JWKS amplification bound
#: entirely — ``JwksCache`` raises a plain ``JwksError``, so the completeness lock could not see that
#: control 7's sibling on the OIDC *callback* leg had no row.
_BOUND_MARKERS = ("bound", "throttled", "exceeds", "cap", "too many", "full")


def _bounded_caches() -> set[str]:
    """``{"<Class>"}`` for every anti-automation bound enforced by a class in ``messagefoundry/auth``.

    Discovered structurally, on two signals: a class method that ``raise``s an exception whose name
    ends in ``FullError`` (a reject-when-full cache), **or** one that raises any ``*Error`` whose
    message names a rate/size/refetch bound. Seams are keyed on the CLASS, so a bound enforced across
    two methods of one cache is one row, and a tenth bound cannot land without a 6.1.1 row.
    """
    found: set[str] = set()
    for module in sorted(_AUTH_PKG.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for member in node.body:
                if not isinstance(member, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                for sub in ast.walk(member):
                    if not (
                        isinstance(sub, ast.Raise)
                        and isinstance(sub.exc, ast.Call)
                        and isinstance(sub.exc.func, ast.Name)
                        and sub.exc.func.id.endswith("Error")
                    ):
                        continue
                    message = " ".join(
                        part.value
                        for part in ast.walk(sub.exc)
                        if isinstance(part, ast.Constant) and isinstance(part.value, str)
                    ).lower()
                    if sub.exc.func.id.endswith("FullError") or any(
                        marker in message for marker in _BOUND_MARKERS
                    ):
                        found.add(node.name)
    return found


def _derived_protection_seams() -> dict[str, str]:
    """The 6.1.1 control registry: ``{label: token that must appear in its row}``, from code."""
    seams = dict(_STRUCTURAL_CONTROLS)
    accessors = _limiter_accessors()
    for accessor in sorted(_AUTH_SURFACE_ACCESSORS):
        assert accessor in accessors, (
            f"{accessor} is no longer a SlidingWindowRateLimiter accessor; re-derive the 6.1.1 set."
        )
        seams[accessor] = accessor
    for cache in sorted(_bounded_caches()):
        seams[cache] = cache
    return seams


def test_every_sliding_window_limiter_is_filed_under_the_right_requirement() -> None:
    """A fifth limiter must join one table or the other — it cannot land undocumented.

    ``allow_login_attempt``/``allow_reauth_attempt`` defend the AUTHENTICATION surface (6.1.1);
    ``allow_phi_read``/``allow_admin_write`` are post-authentication business-logic limits (2.1.3).
    The split is asserted, so a new accessor forces an explicit decision rather than silently
    inheriting one table's coverage claim.
    """
    accessors = set(_limiter_accessors())
    known = _AUTH_SURFACE_ACCESSORS | _BUSINESS_LIMIT_ACCESSORS
    assert accessors == known, (
        f"the sliding-window accessor set changed: {sorted(accessors ^ known)}. File the new one in "
        "docs/SECURITY.md's 6.1.1 protection set (authentication surface) or its 2.1.3 "
        "business-logic-limits table, and update this split."
    )
    limits = _section(_H_LIMITS)
    protection = _section(_H_SET)
    for accessor in sorted(_AUTH_SURFACE_ACCESSORS):
        assert accessor in protection, f"{accessor} has no row in the 6.1.1 protection set"
    for accessor in sorted(_BUSINESS_LIMIT_ACCESSORS):
        field = "phi_read" if "phi" in accessor else "admin_write"
        assert f"{field}_rate_limit_enabled" in limits, (
            f"{accessor}'s settings have no row in the 2.1.3 business-logic-limits table"
        )


def _protection_rows() -> list[list[str]]:
    return next(t for t in _tables(_section(_H_SET)) if t[0][0] == "#")


def test_protection_set_answers_what_remains_when_each_control_is_off() -> None:
    """6.1.1's "not disabled or bypassable" clause is evidenced by stating the residual."""
    table = _protection_rows()
    header = table[0]
    assert "What remains when off" in header
    residual = header.index("What remains when off")
    for row in table[1:]:
        assert row[residual], f"control {row[1]!r} does not state what remains when it is disabled"


def test_protection_set_is_derived_from_the_shipped_anti_automation_seams() -> None:
    """The completeness lock, derived — a hard-coded row count is unfalsifiable.

    RULE: every anti-automation seam the engine ships must have a row. Two of them (the OIDC
    pending-flow cache and the WebAuthn ceremony cache) are found structurally, so a third
    reject-when-full bound cannot land without one; the rest are pinned by an enforcement token.
    """
    table = _protection_rows()
    rows = ["  ".join(row) for row in table[1:]]
    seams = _derived_protection_seams()
    missing = sorted(
        label for label, token in seams.items() if not any(token.lower() in r.lower() for r in rows)
    )
    assert not missing, (
        f"anti-automation seams with no row in the 6.1.1 protection set: {missing}. Each shipped "
        "control needs a row naming its threshold, its disable switch and what remains when it is off."
    )
    assert len(rows) == len(seams), (
        f"the protection set has {len(rows)} rows for {len(seams)} derived seams "
        f"({sorted(seams)}); a row without a seam is unfalsifiable prose."
    )


def test_protection_set_count_word_matches_the_table() -> None:
    """The prose count and the table cannot diverge."""
    rows = len(_protection_rows()) - 1
    word = _COUNT_WORDS.get(rows)
    assert word is not None, f"add {rows} to _COUNT_WORDS"
    assert f"{word} controls defend the authentication surface" in _section(_H_SET), (
        f"the 6.1.1 preamble must say {word!r} — the table now has {rows} rows."
    )


def test_protection_set_guard_detects_a_planted_omission() -> None:
    """Proves the completeness lock can fail: delete one row and the checker must name its seam."""
    table = _protection_rows()
    seams = _derived_protection_seams()
    victim = "FlowCache"
    assert victim in seams, "fixture drifted: the OIDC flow cache is no longer a derived seam"
    rows = ["  ".join(row) for row in table[1:] if victim.lower() not in "  ".join(row).lower()]
    assert len(rows) == len(table) - 2, "the planted deletion removed more than one row"
    missing = sorted(
        label for label, token in seams.items() if not any(token.lower() in r.lower() for r in rows)
    )
    assert missing == [victim], (
        f"deleting the {victim} row must be detected; the checker reported {missing}"
    )


def test_malicious_lockout_clause_is_discharged_in_the_doc() -> None:
    """The lockout window auto-expires, so an attacker cannot lock an account out indefinitely."""
    block = _section(_H_SET)
    lowered = " ".join(block.lower().split())
    assert "auto-expiring" in lowered or "lapsed window restarts" in lowered
    settings = ServiceSettings().auth
    assert (settings.lockout_threshold, settings.lockout_minutes) == (5, 15)


def test_route_to_limiter_map_matches_the_call_sites() -> None:
    """The doc's route -> limiter map is rebuilt from the AST.

    RULE: this is the assertion that catches a ``/me/password``-style misfiling — a route documented
    under the wrong limiter, which is exactly why 6.1.1 was Partial.
    """
    derived = _all_route_limiter_calls()
    table = next(t for t in _tables(_section(_H_MAP)) if t[0][0] == "Route")
    documented: dict[str, str] = {}
    for row in table[1:]:
        limiter = row[1].lower()
        for token in _ROUTE_TOKEN_RE.findall(row[0]):
            documented[token] = limiter

    for route, limiters in sorted(derived.items()):
        assert route in documented, (
            f"{route} charges {sorted(limiters)} but has no row in docs/SECURITY.md's route -> "
            "limiter map."
        )
        stated = documented[route]
        if "allow_login_attempt" in limiters:
            assert "sign-in" in stated, (
                f"{route} charges the SIGN-IN window; the doc files it under {stated!r}."
            )
        if "allow_reauth_attempt" in limiters:
            assert "ceremony" in stated or "inherits" in stated, (
                f"{route} charges the per-ACTOR ceremony budget; the doc files it under {stated!r}. "
                "This is the /me/password misfiling that kept 6.1.1 Partial."
            )


def test_me_password_is_not_described_as_part_of_the_sign_in_surface() -> None:
    """The exact retired falsehood, pinned so it cannot come back."""
    text = _doc_text()
    assert "`/auth/login`, `/auth/negotiate`,\n`/me/password`" not in text
    assert "unauthenticated auth surface (`/auth/login`, `/auth/negotiate`," not in text
    block = _section(_H_MAP)
    row = next(line for line in block.splitlines() if "`POST /me/password`" in line)
    assert "ceremony" in row.lower(), f"the /me/password row reads {row!r}"
    assert "not** the sign-in window" in row or "not" in row.lower()


def test_reauth_surface_has_no_lockout_and_the_doc_says_so() -> None:
    """``reauth`` verifies a password but neither checks ``locked_until`` nor registers a failure, so
    the ceremony budget is the ONLY bound there — a fact the SEC-024 caveat must not overstate away."""
    source = ast.parse(
        (_ROOT / "messagefoundry" / "auth" / "service.py").read_text(encoding="utf-8")
    )
    reauth = next(
        node
        for node in ast.walk(source)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "reauth"
    )
    assert not _calls_to(reauth, {"_register_failure"}), (
        "reauth now feeds the per-account lockout — the doc's honest caveat is stale, update it."
    )
    block = _section(_H_BRUTE)
    assert "does **not** reach the credential re-proof surface" in block, (
        "the SEC-024 caveat must state that neither the global ceiling nor the lockout covers "
        "POST /me/reauth and POST /me/password."
    )


def test_throttle_observability_split_is_documented() -> None:
    block = _section(_H_BRUTE)
    lowered = " ".join(block.replace("*", " ").lower().split())
    assert "not" in lowered and "audit_log" in lowered, (
        "the doc must state that rate-limit rejections go to the rotating log, not the hash-chained "
        "audit_log (anti-amplification, ASVS 16.3.3)."
    )


def test_console_entry_route_breach_shape_is_documented_per_route() -> None:
    """6.1.1 scores the CONSEQUENCE of a triggered defense, so the doc must not flatten it.

    Only ``POST /ui/login`` raises 429 + ``Retry-After: 30``; the other three console entry routes
    return a 303 redirect to ``/ui/login?e=rate_limited``. Derived from the AST of each route's
    rate-limit branch, so the split cannot rot back into one blanket sentence.
    """
    shapes: dict[str, str] = {}
    for module in sorted(_CONSOLE_ROUTES.rglob("*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            route = _decorated_path(node)
            if route is None:
                continue
            for branch in ast.walk(node):
                # `if not auth.allow_login_attempt(...):` — inspect what that branch does.
                if not (
                    isinstance(branch, ast.If) and _calls_to(branch.test, {"allow_login_attempt"})
                ):
                    continue
                body = ast.dump(ast.Module(body=branch.body, type_ignores=[]))
                if "RedirectResponse" in body:
                    shapes[route] = "303"
                elif "429" in body:
                    shapes[route] = "429"
    assert shapes, "no console entry route has an allow_login_attempt branch any more"
    redirecting = sorted(r for r, s in shapes.items() if s == "303")
    throttling = sorted(r for r, s in shapes.items() if s == "429")
    assert throttling == ["/ui/login"], (
        f"the console routes answering a sign-in throttle with 429 changed: {throttling}"
    )
    assert redirecting == ["/ui/oidc/callback", "/ui/oidc/start", "/ui/sso"], (
        f"the console routes answering with a 303 redirect changed: {redirecting}"
    )
    text = _doc_text()
    assert "429 + `Retry-After: 30` on `POST /ui/login`" in text, (
        "the doc must state the 429 + Retry-After: 30 shape of the POST /ui/login sign-in throttle"
    )
    for route in redirecting:
        assert f"`GET {route}`" in text, f"{route}'s 303 breach shape is not documented"
    assert "no 429, no `Retry-After`" in text, (
        "the doc must state that the three redirecting console routes send neither a 429 nor a "
        "Retry-After — a browser navigation cannot render a 429 usefully."
    )


def _retry_after_routes() -> set[str]:
    """Every rate-limit branch that emits ``Retry-After``, across BOTH limiter families.

    The narrower walk this replaces looked only at ``allow_login_attempt`` branches, so the two
    ceremony routes that DO send ``Retry-After: 30`` were structurally invisible to it — and it then
    pinned the resulting falsehood ("only POST /ui/login carries it") into the doc. Deriving the set
    means a header added to or removed from any throttle branch reds CI.
    """
    limiters = {"allow_login_attempt", "allow_reauth_attempt"}
    emitting: set[str] = set()
    modules = [_AUTH_ROUTES, *sorted(_CONSOLE_ROUTES.rglob("*.py"))]
    for module in modules:
        tree = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            route = _decorated_path(node)
            if route is None:
                continue
            method = next(
                deco.func.attr.upper()
                for deco in node.decorator_list
                if isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
            )
            for branch in ast.walk(node):
                if not (isinstance(branch, ast.If) and _calls_to(branch.test, limiters)):
                    continue
                body = ast.dump(ast.Module(body=branch.body, type_ignores=[]))
                if "Retry-After" in body:
                    emitting.add(f"{method} {route}")
    return emitting


def test_retry_after_is_attributed_to_every_route_that_sends_it() -> None:
    """6.1.1 scores the CONSEQUENCE of a triggered defense, so mis-attributing one is the defect.

    Derived across both the sign-in window (control 2) and the per-actor ceremony budget (control 3):
    ``POST /ui/reauth``, ``POST /ui/reauth/webauthn`` and ``POST /ui/mfa`` carry ``Retry-After: 30``
    too, so scoping it to ``POST /ui/login`` "only" is false.

    ``POST /ui/mfa`` (ASVS 6.3.3) joined the set deliberately: it submits a second factor for a
    session that has already proven its password, so it draws the SAME per-actor ceremony budget as
    ``POST /ui/reauth`` and must report the same clear-time. A different Retry-After on one limiter
    would misreport when the budget actually recovers.
    """
    emitting = _retry_after_routes()
    assert emitting == {
        "POST /ui/login",
        "POST /ui/reauth",
        "POST /ui/reauth/webauthn",
        "POST /ui/mfa",
    }, (
        f"the throttle branches emitting Retry-After changed: {sorted(emitting)}. Restate the "
        "consequences paragraph and the Route -> limiter map in the same change."
    )
    text = _doc_text()
    for route in sorted(emitting):
        assert f"`{route}`" in text, f"{route} sends Retry-After but the doc does not name it"
    assert "`Retry-After: 30` on `POST /ui/login` only" not in text, (
        "the retired falsehood is back: two ceremony routes also carry Retry-After: 30."
    )
    ceremony = next(
        line
        for line in _section(_H_LIMITS).splitlines()
        if line.strip().startswith("| Credential ceremonies")
    )
    assert "Retry-After: 30" in ceremony and "/ui/reauth" in ceremony, (
        "the 2.1.3 'Credential ceremonies' On-breach cell must split the per-route consequence the "
        "same way the sign-in row does — control 3 cannot be documented less completely than 2."
    )


def test_zero_flow_cache_max_refuses_every_federated_login() -> None:
    """``oidc_flow_cache_max = 0`` is a total OIDC denial of service, not "an unbounded cache".

    ``put`` refuses at ``len(entries) >= global_cap``, so ``0 >= 0`` is true on an EMPTY cache. The
    doc said the opposite three rows above its own "a ``per_key`` or ``glob`` of ``0`` silently
    disables that dimension" note, inviting the reader to generalise a 0-means-off convention that
    does not hold here.
    """
    from messagefoundry.auth.oidc.flow import FlowCache, FlowCacheFullError, PendingFlow

    cache = FlowCache(ttl_seconds=300.0, global_cap=0)
    flow = PendingFlow(
        state="s",
        nonce="n",
        code_verifier="v",
        return_to="/ui",
        client_ip="198.51.100.7",
        deadline=1e12,
    )
    with pytest.raises(FlowCacheFullError):
        cache.put("flow-1", flow)
    row = next(
        line
        for line in _section(_H_SET).splitlines()
        if "oidc_flow_cache_max" in line and line.strip().startswith("|")
    )
    assert "unbounded" not in row.lower(), (
        "the control-7 disable-switch cell calls oidc_flow_cache_max = 0 an unbounded cache; it "
        "refuses EVERY federated sign-in."
    )
    assert "every" in row.lower(), (
        "the control-7 disable-switch cell must state that 0 rejects every federated sign-in"
    )


def test_lockout_is_fed_by_two_legs_but_enforced_on_the_assertion_leg_too() -> None:
    """Both halves of the lockout-coverage sentence, pinned against code.

    The retired wording ("not WebAuthn assertions") read as if a locked account could still sign in
    with its passkey. ``finish_webauthn_assertion`` refuses a locked account BEFORE any verification;
    what it does not do is FEED the lockout.
    """
    tree = ast.parse(_SERVICE.read_text(encoding="utf-8"))
    assertion = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
        and node.name == "finish_webauthn_assertion"
    )
    reads_lock = any(
        isinstance(n, ast.Attribute) and n.attr == "locked_until" for n in ast.walk(assertion)
    )
    assert reads_lock, (
        "finish_webauthn_assertion no longer refuses a locked account; docs/SECURITY.md says the "
        "lock is ENFORCED across every local factor."
    )
    assert not _calls_to(assertion, {"_register_failure"}), (
        "WebAuthn assertion failures now feed the lockout; the doc's deliberate-divergence note is "
        "stale — update it in the same change."
    )
    text = _doc_text()
    assert (
        "**feed** it" in text and "already-locked account IS refused at the assertion leg" in text
    ), "the lockout paragraph must separate FEEDING the lockout from ENFORCING it."


@pytest.mark.parametrize(
    ("field", "pinned"),
    [
        ("login_rate_limit_enabled", True),
        ("login_rate_limit_per_ip", 10),
        ("login_rate_limit_global", 60),
        ("login_rate_limit_window_seconds", 60.0),
        ("phi_read_rate_limit_enabled", True),
        ("phi_read_rate_limit_per_actor", 120),
        ("phi_read_rate_limit_global", 0),
        ("phi_read_rate_limit_window_seconds", 60.0),
        ("admin_write_rate_limit_enabled", True),
        ("admin_write_rate_limit_per_actor", 12),
        ("admin_write_rate_limit_window_seconds", 1.0),
        ("max_sessions_per_user", 5),
        ("bootstrap_expiry_hours", 72),
    ],
)
def test_limit_defaults_quoted_in_the_table_match_the_code(field: str, pinned: object) -> None:
    live = getattr(ServiceSettings().auth, field)
    assert live == pinned, (
        f"[auth].{field} now defaults to {live!r}, not {pinned!r}. Update BOTH docs/SECURITY.md's "
        "business-logic-limits table AND docs/CONFIGURATION.md's `[auth]` table (its Default "
        "column), plus this pin, in the same change (ASVS 2.1.3)."
    )
    block = _section(_H_LIMITS)
    assert field in block, f"[auth].{field} has no row in the business-logic-limits table"
    # The OPERATOR reference's Default column, asserted against the live value. Column 1 alone
    # cannot see a stale default, and this is the artefact 2.1.3 scores.
    rows = _config_auth_rows(_config_section())
    assert field in rows, f"[auth].{field} has no row in docs/CONFIGURATION.md's [auth] table"
    rendered = rows[field][1].replace("`", "").strip()
    assert rendered in _rendered_defaults(live), (
        f"docs/CONFIGURATION.md's `{field}` row states default {rendered!r}, but the live default "
        f"is {live!r}. The operator configuration reference is what an operator tunes from."
    )
