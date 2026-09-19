# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Golden surface locks for the mounted /ui web console (Option B, ADR 0065).

Two drift guards over the console's externally-observable surface, both built by mounting the real
console onto a real engine app (``create_app(serve_ui=True)`` -> ``mount_ui``):

* the exact set of mounted ``(method, path)`` /ui routes matches a checked-in golden list, and
* the ``register_ui_action`` write-action registry (``_auth._UI_WRITE_ACTIONS``) matches a golden set
  of ``pattern<TAB>action<TAB>flags`` rows — the pattern, the single-use step-up action tag bound to
  it, and the three continuation flags (``step_up`` / ``auto_retry`` / ``unlock``) that decide which
  paths the step-up re-auth may re-POST or 303-redirect to.

A new page/route, a renamed write-action pattern, a changed action tag, or a flipped continuation
flag is an intentional change that must update the golden — so an *accidental* drift (a dropped
route after a move, a stale/misspelled step-up pattern, a silently deleted action tag, a lane
quietly added to or dropped from the re-auth continuation allow-list) fails loudly here. A third check
pins the security-relevant registration ORDER for the literal-vs-path-param pairs (a literal route
registered AFTER its ``{param}`` sibling would be shadowed — an authz regression, e.g.
``/ui/messages/search`` swallowed by ``/ui/messages/{message_id}``).
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import httpx
from fastapi.routing import APIRoute
from pydantic import TypeAdapter
from starlette.routing import Mount

import messagefoundry_webconsole._auth as ui_auth
import messagefoundry_webconsole.routes._common as ui_common
from messagefoundry.api import create_app
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

_GOLDEN = Path(__file__).resolve().parent / "golden"

# The action column's stand-in for ``UiWriteAction.action is None``. A literal marker, never an empty
# field: a blank second column is indistinguishable from a row that lost its tab, so the one drift
# this column exists to catch would read as a formatting nit.
_UNTAGGED = "-"


def _read_golden(name: str) -> list[str]:
    return _GOLDEN.joinpath(name).read_text(encoding="utf-8").splitlines()


def _continuation_flags(action: ui_auth.UiWriteAction) -> str:
    """The three continuation flags as ``name=0/1``, NAMED rather than positional.

    A bare ``1\t1\t0`` triple would put the reader of a diff in the position of counting columns to
    learn which flag moved — the same presence-without-scope failure the repo's glyph rule is about.
    ``step_up=1,auto_retry=1,unlock=0`` says what changed in the diff itself.
    """
    return (
        f"step_up={int(action.step_up)},"
        f"auto_retry={int(action.auto_retry)},"
        f"unlock={int(action.unlock)}"
    )


async def _serve_ui_app(engine: Engine) -> httpx.ASGITransport:
    """Build the JSON engine app with the console mounted (the create_app -> mount_ui path)."""
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))


def _mounted_ui_routes(app: object) -> list[str]:
    """Every mounted /ui route as ``"METHOD /path"`` (a StaticFiles Mount as ``"MOUNT /ui/static"``),
    deduplicated + sorted the same way the golden file is generated."""
    lines: set[str] = set()
    for route in app.router.routes:  # type: ignore[attr-defined]
        path = getattr(route, "path", None)
        if not (isinstance(path, str) and path.startswith("/ui")):
            continue
        methods = getattr(route, "methods", None)
        if methods:
            lines.update(f"{method} {path}" for method in methods)
        else:
            lines.add(f"MOUNT {path}")
    return sorted(lines)


async def test_ui_route_table_matches_golden(engine: Engine) -> None:
    """The exact mounted /ui (method, path) surface is pinned. A dropped/renamed/added route (e.g. a
    route lost in a package move, or a path-param typo) diverges from the golden and fails here."""
    transport = await _serve_ui_app(engine)
    actual = _mounted_ui_routes(transport.app)
    golden = _read_golden("ui_routes.txt")
    assert actual == golden, (
        "the mounted /ui route table drifted from tests/golden/ui_routes.txt — if intentional, "
        "regenerate the golden; if not, a route was dropped/renamed by a change.\n"
        f"missing (in golden, not mounted): {sorted(set(golden) - set(actual))}\n"
        f"unexpected (mounted, not golden): {sorted(set(actual) - set(golden))}"
    )


async def test_ui_write_action_registry_matches_golden(engine: Engine) -> None:
    """The write-action registry is pinned as ``pattern<TAB>action``. This is the step-up re-auth
    allow-list; a stale/misspelled/renamed pattern after a route move — the exact failure a
    single-module registry can still make silently — diverges from the golden and fails here.

    THE ACTION COLUMN IS THE SECURITY-LOAD-BEARING HALF (BACKLOG #1148). ``action`` is the
    single-use step-up grant ``/ui/reauth`` mints for a continuation (``routes/core.py`` passes it
    as ``purpose``); ``None`` mints nothing, so the lane falls back to the shared login-seeded
    window. Deleting one ``action=`` kwarg therefore downgrades a factor-binding browser lane from a
    fresh per-action proof to a window a five-minute-old login satisfies, in a one-line deletion
    that reads like tidying.

    WHAT WAS ACTUALLY MEASURED, because the honest result is narrower than "it was unguarded".
    A mutation sweep deleted each of the 9 ``action=`` kwargs in turn:

    * this golden caught NONE of them. It compared ``path_re.pattern`` only, so the field that
      changed was invisible to it while its own docstring called it the step-up allow-list guard.
    * behavioural console tests caught all 9, but incidentally: they were written for the MFA,
      WebAuthn and session lifecycles, and they report "the lifecycle broke", not "this pattern lost
      its action tag".
    * for the 2 WebAuthn lanes that coverage exists ONLY with the optional ``[webauthn]`` extra
      installed. Without it those tests ``importorskip`` and both deletions ran completely GREEN —
      so a contributor without the extra gets a clean local run on a real downgrade.

    So this column does not close an unguarded hole. It replaces incidental, extra-gated coverage
    with a direct one that names the field. Pin the pair, not the pattern.

    THE CONTINUATION-FLAG COLUMN IS DIFFERENT: IT CLOSES A GENUINELY UNGUARDED ONE (BACKLOG #1148,
    named in that item as this golden's remaining blind spot). ``step_up`` / ``auto_retry`` /
    ``unlock`` sat outside the comparison, and ``_auth._UI_WRITE_ACTIONS`` is by its own comment the
    ONLY source of truth for which paths the step-up re-auth may hand control back to — "the gate
    that stops the re-auth becoming an open POST/redirect gadget". ``auto_retry`` is what puts a path
    in the re-POST allow-list (``is_safe_ui_action``), ``unlock`` in the 303-GET-redirect one
    (``is_unlock_action``), and ``step_up`` drives the enroll-first branch that keeps a
    required-but-unenrolled session out of a re-auth loop (``routes/core.py``).

    MEASURED on the pristine tree before this column existed, one probe, positive controls in the
    same runs. ``step_up=False`` was added to the ``/ui/users/{id}/reset-mfa`` registration — a
    factor-binding admin lane, and a flip that is behaviourally silent because the branch it
    disables only fires for a required-but-unenrolled operator:

    * the full console suite: **422 passed, 3 skipped — GREEN.**
    * the engine's security-doc drift, rate-limit, security-static, seam-discovery, lint-parity and
      full API-auth suites plus this golden: **242 passed — GREEN.**

    Nothing anywhere observed it. Scope control, so the claim is not wider than the run: the SAME
    engine set DOES catch a gate swap — replacing this lane's ``require_ui_step_up_action`` with the
    MFA-gate-OFF ``require_ui_reauth_only_action`` reds
    ``test_security_doc_drift::test_every_ui_route_appears_in_the_ui_route_map``, which compares the
    dependency name against a row in the public, tracked ``docs/SECURITY.md``. So the ROUTE's gate is
    guarded and environment-independent; it was the REGISTRATION's flags that were not.
    """
    await _serve_ui_app(engine)  # mount so every module-level register_ui_action has fired
    actual = sorted(
        f"{action.path_re.pattern}\t{action.action or _UNTAGGED}\t{_continuation_flags(action)}"
        for action in ui_auth._UI_WRITE_ACTIONS
    )
    golden = _read_golden("ui_write_actions.txt")
    assert actual == golden, (
        "the /ui write-action registry drifted from tests/golden/ui_write_actions.txt — if "
        "intentional, regenerate the golden; if not, a register_ui_action pattern, its step-up "
        "action tag, or one of its continuation flags changed. A row whose action column went to "
        f"{_UNTAGGED!r} LOST its single-use grant and now rides the shared step-up window; a row "
        "whose auto_retry/unlock flipped changed which paths /ui/reauth may re-POST or "
        "303-redirect to; a row that went step_up=0 lost the enroll-first anti-loop routing.\n"
        f"missing (in golden, not registered): {sorted(set(golden) - set(actual))}\n"
        f"unexpected (registered, not golden): {sorted(set(actual) - set(golden))}"
    )


# The literal path that MUST be registered before its {param} sibling (else the path-param route
# shadows it and steals the request — a route-order authz/behaviour regression the golden set-compare
# cannot catch on its own). Verified against the pre-extraction order.
_LITERAL_BEFORE_PARAM = (
    ("/ui/messages/search", "/ui/messages/{message_id}"),
    ("/ui/connections/purge-confirm", "/ui/connections/{name}/purge/{scope}"),
    ("/ui/users/new", "/ui/users/{user_id}"),
    ("/ui/roles/new", "/ui/roles/{role_id}/edit"),
    ("/ui/dead-letters/replay-all", "/ui/dead-letters/{channel_id}/replay"),
)


async def test_literal_routes_precede_path_param_siblings(engine: Engine) -> None:
    """FastAPI/Starlette matches routes in registration order, so a literal segment must be mounted
    BEFORE the ``{param}`` route that would otherwise capture it — the route-order guard mount_ui's
    fixed registrar tuple exists to preserve."""
    transport = await _serve_ui_app(engine)
    order = [
        getattr(r, "path", None)
        for r in transport.app.router.routes  # type: ignore[attr-defined]
        if not isinstance(r, Mount)
    ]
    for literal, param in _LITERAL_BEFORE_PARAM:
        assert literal in order, f"expected literal route {literal!r} to be mounted"
        assert param in order, f"expected path-param route {param!r} to be mounted"
        assert order.index(literal) < order.index(param), (
            f"{literal!r} must register before {param!r} or the path-param route shadows it "
            "(route-order authz regression)"
        )


# --- the third golden: which input rule each /ui parameter carries (BACKLOG #1740) ----------------
#
# A different thing from the two above. ``ui_routes.txt`` pins WHICH routes are mounted and
# ``ui_write_actions.txt`` pins the step-up continuation registry; this pins, for every string path
# and query parameter on those routes, the ``api/validation.py`` rule it enforces and how a refusal
# is shaped. It lives HERE rather than beside its behavioural tests so all three tables come from
# ONE mount (``_serve_ui_app``) and one route walk: a separate module would have believed in a route
# population nothing ever compared against this one's.


def _string_schema(schema: dict[str, Any]) -> dict[str, Any] | None:
    """The string branch of a parameter's JSON schema, or ``None`` if it has none.

    A /ui parameter is rarely a bare string: ``X | None`` renders as ``anyOf`` and a repeated query
    value as ``array``. Digging to the string branch lets one comparison cover all three, and
    returning ``None`` for an int or a bool is how ``limit``/``offset``/``defer`` stay out of the
    table -- they are not data items these rules govern, and excluding them also keeps this golden
    from churning on unrelated pager work.
    """
    if schema.get("type") == "string":
        return schema
    if schema.get("type") == "array":
        items = schema.get("items")
        return _string_schema(items) if isinstance(items, dict) else None
    for branch in schema.get("anyOf", []):
        if isinstance(branch, dict) and (found := _string_schema(branch)) is not None:
            return found
    return None


def _constraint(schema: dict[str, Any]) -> tuple[str | None, int | None]:
    """A string schema reduced to the pair that identifies a rule: its pattern and its ceiling."""
    max_length = schema.get("maxLength")
    return (schema.get("pattern"), max_length if isinstance(max_length, int) else None)


def _rule_names_by_constraint() -> dict[tuple[str | None, int | None], str]:
    """Every rule ``routes/_common`` defines, indexed by the constraint it actually enforces.

    Names are JOINED where two rules share a constraint rather than one winning: ``status`` and
    ``event kind`` are distinct rules over one annotated type today, so an annotated parameter
    carrying that constraint honestly reads ``event kind|status``. Picking a winner would put an
    arbitrary tie-break inside a table whose whole job is to be checkable.

    The join covers only rules ``routes/_common`` OWNS. ``api/validation.py`` ships others that share
    a constraint with these -- ``ActorFilter`` and ``IdempotencyKey`` are both printable-256, like
    ``control id`` -- so a /ui parameter annotated with one of THOSE would be reported here under the
    console's name for that constraint. No such parameter exists today. Widen this index before
    annotating a /ui parameter with a rule the console does not name.
    """
    index: dict[tuple[str | None, int | None], list[str]] = {}
    for rule in ui_common.FILTER_RULES:
        schema = _string_schema(rule.adapter.json_schema())
        assert schema is not None, f"{rule.name} does not resolve to a string schema"
        index.setdefault(_constraint(schema), []).append(rule.name)
    return {key: "|".join(sorted(names)) for key, names in index.items()}


def _string_annotation(field: Any) -> dict[str, Any] | None:
    """The string schema of one FastAPI parameter, or ``None`` if it is not a string parameter.

    Rebuilds the parameter's effective type first: FastAPI splits an ``Annotated`` alias into an
    annotation plus metadata, and a ``Query(max_length=...)`` contributes metadata with no
    annotation of its own. Only the pair carries the real constraint.
    """
    info = field.field_info
    annotation = Annotated[(info.annotation, *info.metadata)] if info.metadata else info.annotation
    return _string_schema(TypeAdapter(annotation).json_schema())


def _input_rule_rows(app: object) -> list[str]:
    """The live table: ``METHOD path<TAB>param<TAB>where<TAB>rule<TAB>refusal``.

    ``rule`` is ``-`` where the parameter carries no rule ``routes/_common`` defines, which is the
    honest reading and not a hidden gap: several /ui path ids are BACKLOG #1740's second limb and
    several query values are not control-plane data items at all. Those rows are IN the golden on
    purpose, so closing one is a visible diff rather than an invisible improvement.

    One row per METHOD, matching ``_mounted_ui_routes`` above, so the two tables believe in the same
    route population. A list, not a set: a duplicate registration must fail rather than merge away.
    """
    by_constraint = _rule_names_by_constraint()
    rows: list[str] = []
    for route in app.router.routes:  # type: ignore[attr-defined]
        if not isinstance(route, APIRoute) or not route.path.startswith("/ui"):
            continue
        body_rules = ui_common.UI_BODY_FILTER_RULES.get(route.path, {})
        for where, fields in (
            ("path", route.dependant.path_params),
            ("query", route.dependant.query_params),
        ):
            for field in fields:
                schema = _string_annotation(field)
                if schema is None:
                    continue
                # The ALIAS, not the python name: ``status_filter`` rides the wire as ``status``,
                # which is the key both the filter form and UI_BODY_FILTER_RULES use.
                name = field.alias or field.name
                if declared := by_constraint.get(_constraint(schema)):
                    rule, refusal = declared, "422"
                elif (body_rule := body_rules.get(name)) is not None:
                    rule, refusal = body_rule.name, "400-rerender"
                else:
                    rule, refusal = "-", "-"
                rows += [
                    f"{method} {route.path}\t{name}\t{where}\t{rule}\t{refusal}"
                    for method in route.methods
                ]
    return sorted(rows)


async def test_ui_input_rule_table_matches_golden(engine: Engine) -> None:
    """The pinned table. A /ui parameter that loses its rule, gains a different one, or arrives with
    none at all diverges here -- including a NEW route, which lands as an unexpected ``-`` row.

    WHAT IT DOES NOT SEE, so nobody reads it as more than it is. The ``400-rerender`` column is read
    from ``UI_BODY_FILTER_RULES``, not from the route body, so deleting a route's ``check_filters``
    call leaves both that dict row and this golden intact and green. The behavioural tests in
    ``test_ui_input_rules.py`` are what catch that, and neither guard is sufficient alone. The table
    is also built from FastAPI's parameter list, so a route that reads its values out of the request
    BODY contributes no rows at all -- ``ui_bulk_control`` and ``ui_purge_bulk`` are absent from it.
    """
    transport = await _serve_ui_app(engine)
    actual = _input_rule_rows(transport.app)
    golden = _read_golden("ui_input_rules.txt")
    assert actual == golden, (
        "the /ui input-rule table drifted from tests/golden/ui_input_rules.txt -- if intentional, "
        "regenerate the golden; if not, a parameter lost or changed the rule it carries.\n"
        f"missing (in golden, not live): {sorted(set(golden) - set(actual))}\n"
        f"unexpected (live, not golden): {sorted(set(actual) - set(golden))}"
    )


async def test_the_input_rule_drift_check_can_return_the_other_answer(engine: Engine) -> None:
    """The control. A comparison that still passes against a doctored table is measuring nothing.

    Doctors the LIVE rows rather than the golden, and runs the SAME equality the real test runs.
    Doctoring the golden instead would pass for the wrong reason the day the table has genuinely
    drifted -- the two would differ either way, and the control could not tell which.

    Two assertions, because one is not enough. The first pins that the replacement actually changed
    something: if every ``connection|422`` row ever disappears, the substitution becomes a no-op and
    a single inequality assertion degenerates into re-testing the assertion above.
    """
    transport = await _serve_ui_app(engine)
    actual = _input_rule_rows(transport.app)
    doctored = [row.replace("\tconnection\t422", "\t-\t-") for row in actual]
    assert doctored != actual, "the doctored table must differ, or this control measures nothing"
    assert doctored != _read_golden("ui_input_rules.txt"), (
        "a row whose rule column was blanked must fail the comparison the real test makes"
    )


async def test_every_declared_body_rule_names_a_live_route_and_parameter(engine: Engine) -> None:
    """A body-checked declaration must name a mounted path AND a parameter that route really has.

    The typo guard the golden cannot give, in both halves. A misspelled PATH means the route checks
    nothing at all. A misspelled FIELD is quieter still: ``check_filters`` reads the echo dict with
    ``.get(field, "")``, so a key that is not there looks blank, blank means "no filter", and that
    rule is simply off. In both cases the table would report the parameter as carrying no rule --
    true, and not the drift anyone was looking for, so a regenerated golden would absorb it.
    """
    transport = await _serve_ui_app(engine)
    aliases: dict[str, set[str]] = {}
    for route in transport.app.router.routes:  # type: ignore[attr-defined]
        if isinstance(route, APIRoute):
            aliases.setdefault(route.path, set()).update(
                (f.alias or f.name)
                for f in (*route.dependant.path_params, *route.dependant.query_params)
            )
    for path, rules in ui_common.UI_BODY_FILTER_RULES.items():
        assert path in aliases, f"{path} declares filter rules and is not a mounted route"
        unknown = sorted(set(rules) - aliases[path])
        assert not unknown, f"{path} declares rules for parameters it does not have: {unknown}"
