#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Authenticated authorization sweep against a live loopback listener in front of a real engine.

THE DEFECT THIS EXISTS FOR. Point any scanner at a deny-by-default API without a credential and it
gets 401 from every route, finds nothing, exits 0, and the run reads as "all endpoints protected". It
tested NOTHING: a wall of 401s is equally consistent with perfect authorization and with a target that
never dispatched a single request. That shape — green because nothing was measured — is the failure
this repo has catalogued repeatedly, and it is the one an authorization scan is most prone to.

So the load-bearing number here is not the finding count. It is AUTHORIZED REACH: how many gated
operations a PRIVILEGED token actually got PAST authentication and authorization on. If an MFA wall, a
step-up wall, a rate limiter or a broken login silently re-arms, reach collapses, unexplained-unreached
goes positive, and the run fails — instead of reporting a clean sweep of refusals. Every count is
computed by this runner from its own request log and the LIVE route table; nothing is parsed out of
another tool's human-readable summary.

THREE PASSES, over the gated HTTP rows derived by ``scripts/security/route_gates.py``:
  NEGATIVE  every gated operation, twice: no credential, and an invalid bearer. Not-401 is a finding.
  REACH     every gated GET, with the administrator bearer. GET-ONLY IS A SAFETY RULE, NOT LAZINESS —
            a reach probe carries a VALID privileged token and would really execute a mutating
            endpoint. Reached = the status is outside {401, 403, 429}.
  BFLA      every gated GET whose permission set the low-privilege role does NOT hold, with the viewer
            bearer. Refused = {401, 403, 429}; anything else is a finding, INCLUDING 404 — the path
            template matched, so a 404 means the caller got past authorization into resource lookup.

EXIT CONTRACT: 0 = clean AND a liveness receipt naming how many units were EXAMINED; 1 = findings;
2 = FAIL CLOSED, could not measure (a coverage floor unmet, no gated operation derived, an unreadable
policy, a target whose administrator session cannot reach a deep route, or ANY escape that stopped the
sweep finishing — a transport failure mid-scan is the canonical one). A floor that is not met is 2,
never 0, and a run that never measured must never borrow the FINDINGS code: CI reads exit 1 from a
canary as proof the injected defect was detected, so a crash returning 1 would certify a detection
that never happened.

THE RECEIPT RECORDS NO BODIES. Method, path TEMPLATE, status code, counts and the scanned posture only
— never a request or response body, never a header value, never a token. It is an uploaded CI artifact.

USAGE
    python scripts/security/dast_auth_sweep.py --receipt dast-auth-receipt.json
    python scripts/security/dast_auth_sweep.py --canary open-auth --receipt canary-open-auth.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

# Sibling imports work whether this file is run as a script or imported as ``scripts.security.*``
# (the in-repo idiom from scripts/ci/check_required_workflow_state.py).
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from messagefoundry.auth.permissions import BUILTIN_ROLE_PERMISSIONS  # noqa: E402
from scripts.security import route_gates  # noqa: E402
from scripts.security.dast_target import DastTargetUnusable, dast_target  # noqa: E402

#: The honesty boundary, held as ONE long line so it can be embedded verbatim in a markdown paragraph.
#: It exists in exactly TWO places — here and docs/adr/0155 — and tests/test_dast_claims.py pins the
#: two byte-identical. The second copy is justified because the receipt travels outside the repo as a
#: CI artifact, and without it the numbers would circulate stripped of their boundary. Do not
#: paraphrase it anywhere.
INDEPENDENCE_NOTICE: str = (
    "Self-run automated DAST of the authenticated HTTP API plane only. It fills PART of the "
    'Secure_Development_Standards §6.1 "Dynamic" tier row — DAST / authenticated testing of the '
    "running app — and nothing else; at least the unauthenticated MLLP/TCP/X12/DICOM ingress plane, "
    "the /ui console plane and TLS are outside what it scans, and controls including MFA, the rate "
    'limiters, lockout and step-up freshness are relaxed in the scanned posture (ADR 0155, "What '
    'this does NOT give us"). It does NOT satisfy Secure_Build_Standards signal 10, "Independent '
    'external verification" (third-party source review + penetration test + DAST), which requires '
    "INDEPENDENCE, not automation: an internally-run pass "
    "is the substitute that rubric explicitly exists to grade past. The independent engagement has "
    "not been performed and its dated risk acceptance remains in force; "
    "Secure_Development_Standards §A.6 is the single source of record for that status."
)

DEFAULT_POLICY = Path(__file__).resolve().parent / "dast-policy.json"

#: An invalid bearer. It must be syntactically well-formed so the 401 proves TOKEN REJECTION rather
#: than a header parse failure.
INVALID_BEARER = "dast-not-a-real-token"

#: Statuses that mean "the caller was refused before the endpoint did any work".
REFUSED = frozenset({401, 403, 429})

_PREFIX = "dast_auth_sweep"


class PolicyError(RuntimeError):
    """The policy file is missing, unreadable or structurally wrong — a fail-closed condition, because
    a sweep with no floors is a sweep that cannot report having measured too little."""


def load_policy(path: Path) -> dict[str, Any]:
    """Read and structurally validate the policy. Every failure here is fatal by design."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read the policy at {path}: {exc}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"the policy at {path} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PolicyError(f"the policy at {path} must be a JSON object")
    for key in ("floors", "canary_floors", "unreachable_allowlist", "anonymous_allowlist"):
        if key not in parsed:
            raise PolicyError(f"the policy at {path} is missing the required {key!r} section")
    return parsed


def _key(entry: object) -> tuple[str, str]:
    """``(METHOD, path)`` for a policy allow-list entry."""
    if not isinstance(entry, dict):
        raise PolicyError(f"allow-list entries must be objects, got {type(entry).__name__}")
    method = entry.get("method")
    path = entry.get("path")
    if not isinstance(method, str) or not isinstance(path, str):
        raise PolicyError("every allow-list entry needs string 'method' and 'path' fields")
    return (method.upper(), path)


def low_privilege_permissions(policy: dict[str, Any]) -> frozenset[str]:
    """The wire-string permissions the policy's low-privilege role holds."""
    role_value = policy.get("low_privilege_role", "viewer")
    for role, granted in BUILTIN_ROLE_PERMISSIONS.items():
        if role.value == role_value:
            return frozenset(p.value for p in granted)
    raise PolicyError(f"low_privilege_role {role_value!r} is not a built-in role")


def is_refused(status: int) -> bool:
    """Whether ``status`` means the caller was turned away BEFORE the endpoint did any work.

    This is the sweep's oracle, exposed as a pure function so a test can drive it on a bare status
    code rather than re-implementing the rule beside it — a local copy of a rule is the drift this
    repo keeps writing parity tests to catch.

    404 is deliberately NOT refusal. The probe requests a path built from the route's own TEMPLATE, so
    the route matched; a 404 therefore means the caller got PAST authorization and into resource
    lookup, which for the BFLA pass is exactly the defect being hunted.
    """
    return status in REFUSED


def is_reached(status: int) -> bool:
    """Whether a privileged probe got past authentication and authorization. The inverse of
    :func:`is_refused`, named separately because it is the sweep's anti-fake-green measurement."""
    return not is_refused(status)


def _finding(
    method: str, path: str, pass_name: str, observed: int, expected: str
) -> dict[str, Any]:
    """A finding carries the path TEMPLATE and a status code — never a body, header or token."""
    return {
        "method": method,
        "path": path,
        "pass_name": pass_name,
        "observed_status": observed,
        "expected": expected,
    }


async def _probe(client: httpx.AsyncClient, method: str, url: str, token: str | None) -> int:
    """One request; the STATUS CODE is the only thing that leaves this function."""
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    response = await client.request(method, url, headers=headers)
    return response.status_code


async def run_sweep(policy: dict[str, Any], *, canary: str | None = None) -> dict[str, Any]:
    """Bring up the target, run the three passes, and return the receipt."""
    placeholder = str(policy.get("path_param_placeholder", route_gates.PATH_PARAM_PLACEHOLDER))
    viewer_permissions = low_privilege_permissions(policy)
    allowlisted = {_key(e) for e in policy["unreachable_allowlist"]}

    async with dast_target(canary=canary) as target:
        rows = route_gates.route_rows(target.app)
        gated = route_gates.gated_http_rows(target.app)
        ungated = route_gates.ungated_http_rows(target.app)
        websocket_rows = [r for r in rows if r.method == route_gates.WS_METHOD]

        findings: list[dict[str, Any]] = []
        negative_probes = 0
        negative_non_401 = 0
        get_rows = [r for r in gated if r.method == "GET"]
        reached = 0
        unreached_allowlisted = 0
        unreached_unexplained = 0
        bfla_probes = 0
        bfla_violations = 0

        # Every gated row is a BFLA CANDIDATE when the low-privilege role does not hold its whole
        # permission set. Only the GET subset is probed in increment 1 (see the module docstring), so
        # the receipt reports the ratio instead of implying full BFLA coverage.
        bfla_candidates = [r for r in gated if not set(r.permissions) <= viewer_permissions]

        async with httpx.AsyncClient(base_url=target.base_url, timeout=30.0) as client:
            for row in gated:
                url = route_gates.concrete_path(row.path, placeholder)
                for token in (None, INVALID_BEARER):
                    status = await _probe(client, row.method, url, token)
                    negative_probes += 1
                    if status != 401:
                        negative_non_401 += 1
                        findings.append(
                            _finding(
                                row.method,
                                row.path,
                                "negative-no-credential"
                                if token is None
                                else "negative-invalid-credential",
                                status,
                                "401",
                            )
                        )

            for row in get_rows:
                url = route_gates.concrete_path(row.path, placeholder)
                status = await _probe(client, "GET", url, target.admin_token)
                if is_reached(status):
                    reached += 1
                elif (row.method, row.path) in allowlisted:
                    unreached_allowlisted += 1
                else:
                    unreached_unexplained += 1
                    findings.append(
                        _finding(
                            row.method,
                            row.path,
                            "authorized-reach",
                            status,
                            "a status outside {401,403,429} for the administrator identity, or an "
                            "entry in the policy's unreachable_allowlist with a reason",
                        )
                    )

            for row in (r for r in bfla_candidates if r.method == "GET"):
                url = route_gates.concrete_path(row.path, placeholder)
                status = await _probe(client, "GET", url, target.viewer_token)
                bfla_probes += 1
                if not is_refused(status):
                    # 404 counts. With the path template matched, it means the caller got PAST
                    # authorization and into resource lookup.
                    bfla_violations += 1
                    findings.append(
                        _finding(row.method, row.path, "bfla", status, "401, 403 or 429")
                    )

        return {
            "independence_notice": INDEPENDENCE_NOTICE,
            "target_base_url": target.base_url,
            "posture": dict(target.posture),
            "identities": {name: len(perms) for name, perms in target.identities.items()},
            "route_rows_examined": len(rows),
            "gated_http_rows": len(gated),
            "ungated_http_rows": len(ungated),
            "ungated_routes": [{"method": r.method, "path": r.path} for r in ungated],
            "websocket_rows": [{"method": r.method, "path": r.path} for r in websocket_rows],
            "negative_probes": negative_probes,
            "negative_non_401": negative_non_401,
            "get_rows": len(get_rows),
            "reached": reached,
            "unreached_allowlisted": unreached_allowlisted,
            "unreached_unexplained": unreached_unexplained,
            "bfla_probes": bfla_probes,
            "bfla_violations": bfla_violations,
            "bfla_candidate_rows_total": len(bfla_candidates),
            "findings": findings,
            "canary": canary,
        }


def evaluate(receipt: dict[str, Any], policy: dict[str, Any]) -> tuple[int, list[str]]:
    """``(exit code, error lines)`` for a receipt. Pure — the tests drive it with no target running.

    Ordering is deliberate: a COULD-NOT-MEASURE condition outranks a finding, because a run that did
    not measure enough cannot be trusted to have found everything it should have.
    """
    fatal: list[str] = []
    errors: list[str] = []
    floors = policy.get("floors", {})

    observed = {
        "min_route_rows_examined": int(receipt.get("route_rows_examined", 0)),
        "min_gated_http_rows": int(receipt.get("gated_http_rows", 0)),
        "min_negative_probes": int(receipt.get("negative_probes", 0)),
        "min_get_rows_reached": int(receipt.get("reached", 0)),
        "min_bfla_probes": int(receipt.get("bfla_probes", 0)),
    }

    if observed["min_gated_http_rows"] == 0:
        fatal.append(
            "examined ZERO gated operations. The route walk yielded nothing to probe, which means "
            "the gate derivation broke (api/security.py records a refactor that made EVERY route "
            "read as ungated) — this is a blind gate, not a clean sweep."
        )

    for name, value in observed.items():
        floor = floors.get(name)
        if floor is None:
            fatal.append(f"the policy declares no floor for {name} — refusing to report a pass")
        elif value < int(floor):
            fatal.append(
                f"{name}: examined {value}, below the floor of {floor} — refusing (fail closed). "
                "Too little was measured for a clean result to mean anything."
            )

    # A newly ungated route must red the run rather than quietly joining the background.
    try:
        expected_anonymous = {_key(e) for e in policy.get("anonymous_allowlist", [])}
    except PolicyError as exc:
        return 2, [str(exc)]
    actual_anonymous = {
        (str(r["method"]).upper(), str(r["path"])) for r in receipt.get("ungated_routes", [])
    }
    if actual_anonymous != expected_anonymous:
        added = sorted(actual_anonymous - expected_anonymous)
        removed = sorted(expected_anonymous - actual_anonymous)
        errors.append(
            "the ungated (anonymous) route set no longer matches the documented allow-list. "
            f"Newly anonymous: {added or 'none'}; documented but absent: {removed or 'none'}. "
            "A route with no require*() gate is reachable by anyone."
        )

    max_unexplained = int(policy.get("max_unexplained_unreached", 0))
    unexplained = int(receipt.get("unreached_unexplained", 0))
    if unexplained > max_unexplained:
        errors.append(
            f"{unexplained} gated GET operation(s) refused the ADMINISTRATOR identity and are not in "
            "the policy's unreachable_allowlist. Either authorization is wrong, or a wall (MFA, "
            "step-up, a limiter) re-armed and this run measured far less than it appears to."
        )

    for finding in receipt.get("findings", []):
        errors.append(
            f"{finding['pass_name']}: {finding['method']} {finding['path']} answered "
            f"{finding['observed_status']}; expected {finding['expected']}"
        )

    # A canary run must produce AT LEAST its floor of findings. Fewer means the injected defect was not
    # detected in the volume expected, so the sweep's ability to see has NOT been demonstrated — which
    # is a measurement failure, not a pass and not an ordinary finding.
    canary = receipt.get("canary")
    if canary is not None:
        canary_floors = policy.get("canary_floors", {})
        if canary == "open-auth":
            got, floor_name = (
                int(receipt.get("negative_non_401", 0)),
                ("open-auth_min_negative_findings"),
            )
        else:
            got, floor_name = int(receipt.get("bfla_violations", 0)), "bfla_min_violations"
        floor = canary_floors.get(floor_name)
        if floor is None:
            fatal.append(f"the policy declares no canary floor {floor_name!r}")
        elif got < int(floor):
            fatal.append(
                f"canary {canary!r} produced {got} finding(s), below the floor of {floor}. The "
                "injected defect was not detected as expected — the sweep's detection is NOT "
                "demonstrated, so nothing this run reports can be credited."
            )

    if fatal:
        return 2, fatal + errors
    if errors:
        return 1, errors
    return 0, []


def annotation_level(*, canary: str | None, code: int) -> str:
    """The GitHub annotation level for this run's reported lines — ``"notice"`` or ``"error"``.

    A DETECTING canary produces hundreds of findings BY DESIGN; they are that step's expected outcome,
    not a defect in the app. Emitting them as ``::error::`` puts ~230 red annotations on a perfectly
    healthy nightly run, drowning (and, past GitHub's per-step annotation cap, truncating) the REAL
    scan's findings — which are the entire signal this job exists to deliver. An expected canary finding
    is therefore a ``::notice::``; the canary's evidence is its EXIT CODE and its receipt, both of which
    CI checks independently.

    Everything else stays an error, and the two cases that matter most are why this is a named function
    rather than an inline conditional: a REAL scan's findings (``canary is None``) must never be
    downgraded, and a canary that COULD NOT MEASURE (code 2) is never expected, so it must not be
    quietened either.
    """
    return "notice" if (canary is not None and code == 1) else "error"


def receipt_lines(receipt: dict[str, Any], policy: dict[str, Any], verdict: str) -> list[str]:
    """The human- and test-readable measurement receipt. Says what was EXAMINED, not just what was
    found: "0 findings" and "the probe stopped running" are otherwise the same output."""
    floors = policy.get("floors", {})
    posture = receipt.get("posture", {})
    posture_text = " ".join(f"{k}={v}" for k, v in posture.items())
    identities = receipt.get("identities", {})
    identity_text = ", ".join(
        f"{name}: {count} permission(s) (token minted via POST /auth/login)"
        for name, count in identities.items()
    )
    ws = receipt.get("websocket_rows", [])
    floor_text = " ".join(
        f"{name}>={floors.get(name, '?')}"
        f" {'ok' if int(value) >= int(floors.get(name, 0)) else 'FAIL'}({value})"
        for name, value in (
            ("min_route_rows_examined", receipt.get("route_rows_examined", 0)),
            ("min_gated_http_rows", receipt.get("gated_http_rows", 0)),
            ("min_negative_probes", receipt.get("negative_probes", 0)),
            ("min_get_rows_reached", receipt.get("reached", 0)),
            ("min_bfla_probes", receipt.get("bfla_probes", 0)),
        )
    )
    anonymous_ok = len(receipt.get("ungated_routes", [])) and {
        (str(r["method"]).upper(), str(r["path"])) for r in receipt["ungated_routes"]
    } == {_key(e) for e in policy.get("anonymous_allowlist", [])}
    return [
        INDEPENDENCE_NOTICE,
        f"target {receipt.get('target_base_url')} (uvicorn, loopback, one process, one event loop)",
        f"posture scanned -- {posture_text}",
        f"identities -- {identity_text}",
        f"route table -- {receipt.get('route_rows_examined')} rows examined; "
        f"{receipt.get('gated_http_rows')} gated HTTP rows; {receipt.get('ungated_http_rows')} "
        f"ungated; {len(ws)} WebSocket row(s) (authorize inside the endpoint body; excluded from "
        "HTTP probing and reported, not hidden)",
        f"ungated set {'matches' if anonymous_ok else 'DOES NOT MATCH'} the documented anonymous "
        f"allowlist ({receipt.get('ungated_http_rows')}/"
        f"{len(policy.get('anonymous_allowlist', []))})",
        f"negative probes -- {receipt.get('negative_probes')} requests "
        f"({receipt.get('gated_http_rows')} operations x "
        "{no-credential, invalid-credential}); "
        f"{int(receipt.get('negative_probes', 0)) - int(receipt.get('negative_non_401', 0))}/"
        f"{receipt.get('negative_probes')} answered 401",
        f"authorized reach -- {receipt.get('reached')}/{receipt.get('get_rows')} gated GET "
        "operations answered outside {401,403,429} with the administrator token",
        f"unreached -- {receipt.get('unreached_allowlisted')} allowlisted; unexplained "
        f"{receipt.get('unreached_unexplained')}",
        f"BFLA -- {receipt.get('bfla_probes')} of {receipt.get('bfla_candidate_rows_total')} "
        f"candidate rows probed (GET only, increment 1); "
        f"{int(receipt.get('bfla_probes', 0)) - int(receipt.get('bfla_violations', 0))}/"
        f"{receipt.get('bfla_probes')} refused",
        f"floors -- {floor_text} unexplained<="
        f"{policy.get('max_unexplained_unreached', 0)} "
        f"{'ok' if int(receipt.get('unreached_unexplained', 0)) <= int(policy.get('max_unexplained_unreached', 0)) else 'FAIL'}"
        f"({receipt.get('unreached_unexplained')})",
        verdict,
    ]


def _emit(lines: list[str], summary: Path | None) -> None:
    for line in lines:
        print(f"{_PREFIX}: {line}")
    if summary is None:
        return
    try:
        with summary.open("a", encoding="utf-8") as handle:
            handle.write(f"### {_PREFIX}\n\n")
            for line in lines:
                handle.write(f"- {line}\n")
            handle.write("\n")
    except OSError as exc:
        # A summary we cannot write is a reporting problem, not a measurement one: say so loudly and
        # let the exit code continue to reflect the SCAN.
        print(f"::warning::could not append the step summary at {summary}: {exc}", file=sys.stderr)


def _run(coro: Coroutine[Any, Any, dict[str, Any]]) -> dict[str, Any]:
    """Drive the sweep to completion from either a sync or an async caller.

    ``asyncio.run()`` cannot nest, and the pytest suite shares ONE session-scoped event loop — so a
    test case that awaits anything and then calls :func:`main` would hit ``RuntimeError: asyncio.run()
    cannot be called from a running event loop`` and read as a broken sweep rather than a broken call.
    Handing the work to a private thread with its own loop also keeps the uvicorn server off the
    caller's loop entirely, so it cannot outlive this function and poison a later test.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Authenticated authorization sweep against a live loopback engine listener.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--receipt", type=Path, default=None)
    parser.add_argument("--summary", type=Path, default=None)
    parser.add_argument("--canary", choices=["open-auth", "bfla"], default=None)
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        print(f"::error::{_PREFIX}: {exc} (fail closed)", file=sys.stderr)
        return 2

    try:
        receipt = _run(run_sweep(policy, canary=args.canary))
    except DastTargetUnusable as exc:
        print(
            f"::error::{_PREFIX}: the scan target is unusable -- {exc} Refusing to report a result "
            "(fail closed).",
            file=sys.stderr,
        )
        return 2
    except PolicyError as exc:
        print(f"::error::{_PREFIX}: {exc} (fail closed)", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all; see below
        # EVERY could-not-measure path must be 2, including the ones nobody enumerated. Without this
        # arm an httpx transport error (the listener going away mid-scan), a uvicorn task dying during
        # bring-up, or any other escape would propagate, CPython would exit 1 — the FINDINGS code — and
        # a run that never talked to the app would be indistinguishable from one that measured and
        # found defects. Worse, the CI canary loop reads exit 1 as "the canary detected the injected
        # defect", so a crashed canary would certify a detection that never happened.
        print(
            f"::error::{_PREFIX}: the sweep failed to run to completion "
            f"({type(exc).__name__}: {exc}). Refusing to report a result (fail closed).",
            file=sys.stderr,
        )
        return 2

    code, errors = evaluate(receipt, policy)
    verdict = {0: "PASS", 1: "FINDINGS", 2: "COULD NOT MEASURE (fail closed)"}[code]
    receipt["verdict"] = verdict
    receipt["floors"] = {
        name: {"floor": policy.get("floors", {}).get(name), "observed": value}
        for name, value in (
            ("min_route_rows_examined", receipt["route_rows_examined"]),
            ("min_gated_http_rows", receipt["gated_http_rows"]),
            ("min_negative_probes", receipt["negative_probes"]),
            ("min_get_rows_reached", receipt["reached"]),
            ("min_bfla_probes", receipt["bfla_probes"]),
        )
    }
    receipt["floors"]["max_unexplained_unreached"] = {
        "floor": policy.get("max_unexplained_unreached", 0),
        "observed": receipt["unreached_unexplained"],
    }

    _emit(receipt_lines(receipt, policy, verdict), args.summary)

    level = annotation_level(canary=args.canary, code=code)
    for error in errors:
        print(f"::{level}::{_PREFIX}: {error}", file=sys.stderr)

    if args.receipt is not None:
        try:
            args.receipt.write_text(
                json.dumps(receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError as exc:
            print(f"::error::{_PREFIX}: could not write {args.receipt}: {exc}", file=sys.stderr)
            return 2

    return code


if __name__ == "__main__":
    raise SystemExit(main())
