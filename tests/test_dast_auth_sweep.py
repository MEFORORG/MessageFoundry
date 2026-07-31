# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the DAST authenticated authorization sweep (ADR 0155, BACKLOG #318).

Every case here drives the SHIPPED functions from ``scripts/security/dast_auth_sweep.py`` and
``scripts/security/dast_target.py`` — ``main()``, ``evaluate()``, ``is_refused()``, ``dast_target()``.
None of them re-implements the rule beside it: a guard whose test asserts its own private copy of the
logic is a guard nobody has ever run, and this repo already carries parity tests written to catch
exactly that drift.

THIS MODULE IS THE MERGE-BLOCKING HALF OF THE DAST TIER. ``.github/workflows/dast.yml`` runs the sweep
nightly and is deliberately NOT a required context; it has no ``pull_request`` arm and cannot report on
a PR at all. These tests run inside the EXISTING required ``test`` legs and prove the sweep can still
SEE an injected defect. So the probe's ability to fail gates the merge while the probe run is advisory:
a change that blinds the detector reds a pull request.

Cost: the sweep brings up a real loopback uvicorn listener in front of a real ``Engine`` and a real
``AuthService``, which measures ~2.5 s per full run — comfortably inside the suite's 60 s per-test
watchdog. Nothing here sleeps for a fixed period, nothing touches the network beyond ``127.0.0.1``, and
no message is ever seeded, so no payload — synthetic or otherwise — exists to leak.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from scripts.security import dast_target as dast_target_module
from scripts.security.dast_auth_sweep import (
    INDEPENDENCE_NOTICE,
    annotation_level,
    evaluate,
    is_refused,
    load_policy,
    main,
)
from scripts.security.dast_target import (
    ADMIN_USERNAME,
    DastTargetUnusable,
    _login,
    dast_target,
)

_REPO = Path(__file__).resolve().parents[1]
_POLICY = _REPO / "scripts" / "security" / "dast-policy.json"

#: A route no identity in the scan can reach over a bearer token, used to force the bring-up preflight
#: to fail. It is mTLS-client-certificate only by design (ADR 0083), which is why it is also the sole
#: entry in the policy's ``unreachable_allowlist``.
_UNREACHABLE_ROUTE = "/service/identity"


def _policy() -> dict[str, Any]:
    return load_policy(_POLICY)


@pytest.fixture(scope="module")
def clean_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[int, dict[str, Any]]:
    """One real sweep against the shipped app, shared by the cases that read its receipt.

    Module-scoped because the bring-up dominates the cost and every consumer wants the SAME run: a
    per-test sweep would multiply the wall time without measuring anything new.
    """
    receipt_path = tmp_path_factory.mktemp("dast-clean") / "receipt.json"
    code = main(["--policy", str(_POLICY), "--receipt", str(receipt_path)])
    receipt: dict[str, Any] = json.loads(receipt_path.read_text(encoding="utf-8"))
    return code, receipt


# =====================================================================================================
# The sweep against the shipped app
# =====================================================================================================


def test_sweep_is_clean_against_the_real_app(clean_run: tuple[int, dict[str, Any]]) -> None:
    """AC-1. Against an unchanged app the sweep must exit 0 with no finding of any class."""
    code, receipt = clean_run
    assert receipt["negative_non_401"] == 0, (
        "a gated operation answered something other than 401 to a no-credential or invalid-credential "
        f"request: {receipt['findings']}"
    )
    assert receipt["bfla_violations"] == 0, (
        f"the low-privilege identity was admitted somewhere it holds no permission: {receipt['findings']}"
    )
    assert receipt["unreached_unexplained"] == 0, (
        "a gated GET refused the ADMINISTRATOR identity without an entry in the policy's "
        f"unreachable_allowlist: {receipt['findings']}"
    )
    assert code == 0, f"the sweep did not report a clean run: {receipt['verdict']}"
    assert receipt["verdict"] == "PASS"


def test_receipt_names_what_it_examined(clean_run: tuple[int, dict[str, Any]]) -> None:
    """THE ANTI-FAKE-GREEN CASE. A clean run and a run that probed nothing produce the same finding
    count, so a pass is only evidence when the receipt also states how many units were EXAMINED.

    ``reached`` is the load-bearing number: it counts operations a PRIVILEGED token actually got PAST
    authentication and authorization on. A wall of 401s — the shape a lazy scanner of a deny-by-default
    API produces — cannot satisfy it.
    """
    _code, receipt = clean_run

    assert receipt["route_rows_examined"] >= 95, receipt["route_rows_examined"]
    assert receipt["gated_http_rows"] >= 90, receipt["gated_http_rows"]
    assert receipt["negative_probes"] >= 180, receipt["negative_probes"]
    assert receipt["reached"] >= 40, (
        f"only {receipt['reached']} gated GET operation(s) admitted the administrator identity. A "
        "sweep that cannot get past authorization is measuring a wall, not authorization."
    )
    assert receipt["bfla_probes"] >= 15, receipt["bfla_probes"]

    # Partiality is stated, never implied away: the receipt prints the probed/candidate ratio.
    assert receipt["bfla_probes"] <= receipt["bfla_candidate_rows_total"]
    assert receipt["bfla_candidate_rows_total"] > receipt["bfla_probes"], (
        "increment 1 probes only the GET subset of the BFLA candidates; if that is no longer true the "
        "receipt's ratio claim needs revisiting rather than silently becoming a completeness claim."
    )

    # The scan RELAXES five controls to stay deterministic. The receipt must print every relaxation, so
    # no reader can mistake the scanned posture for the shipped default.
    posture = receipt["posture"]
    assert posture["auth"] == "ENABLED"
    for knob in (
        "require_mfa",
        "login_rate_limit",
        "phi_read_rate_limit",
        "admin_write_rate_limit",
    ):
        assert posture[knob] == "OFF", f"the receipt does not record {knob} as scanned"
    assert posture["step_up_max_age"], (
        "the receipt does not record the step-up freshness it scanned"
    )
    assert posture["lockout_threshold"], (
        "the receipt does not record the lockout posture it scanned"
    )
    assert posture["transport"] == "uvicorn/loopback/http"

    assert receipt["independence_notice"].strip(), "the receipt carries no independence notice"
    assert receipt["independence_notice"] == INDEPENDENCE_NOTICE

    # The floors are echoed with their observed values, so the artifact records what was compared.
    floors = receipt["floors"]
    assert floors["min_gated_http_rows"]["observed"] == receipt["gated_http_rows"]
    assert floors["min_get_rows_reached"]["observed"] == receipt["reached"]


def test_the_receipt_records_no_bodies_headers_or_tokens(
    clean_run: tuple[int, dict[str, Any]],
) -> None:
    """The receipt is an uploaded CI artifact, so it must carry only method, path template, status and
    counts. A finding shape that grew a body or a header field would leak on the next red run, which is
    the worst moment to discover it."""
    _code, receipt = clean_run
    for finding in receipt["findings"]:
        assert set(finding) == {"method", "path", "pass_name", "observed_status", "expected"}, (
            finding
        )
    blob = json.dumps(receipt)
    assert "Authorization" not in blob
    assert "Bearer " not in blob


def test_ungated_routes_are_exactly_the_documented_anonymous_set(
    clean_run: tuple[int, dict[str, Any]],
) -> None:
    """AC-6. A newly ungated route must red the run rather than quietly joining the background.

    This is the "detector guarding a shape that cannot occur" defence: an anonymous-route count alone
    would tolerate a swap, so the SET is asserted equal to the reviewed allow-list.
    """
    _code, receipt = clean_run
    policy = _policy()
    documented = {(e["method"].upper(), e["path"]) for e in policy["anonymous_allowlist"]}
    observed = {(r["method"].upper(), r["path"]) for r in receipt["ungated_routes"]}
    assert observed == documented, (
        f"newly anonymous: {sorted(observed - documented)}; documented but absent: "
        f"{sorted(documented - observed)}. A route with no require*() gate is reachable by anyone."
    )
    assert len(observed) == receipt["ungated_http_rows"]

    # The WebSocket route authorizes inside its own body, so the closure walk cannot see its gate. It
    # is REPORTED as excluded rather than absorbed into the background — a blind spot stated is a blind
    # spot; a blind spot hidden is a lie.
    assert receipt["websocket_rows"], (
        "the receipt no longer reports the WebSocket row it excluded from HTTP probing"
    )


# =====================================================================================================
# The auth bootstrap — is the scan identity really authenticated?
# =====================================================================================================


async def test_the_scan_identity_is_really_authenticated() -> None:
    """A sweep that silently fell back to anonymous would report a perfect wall of 401s and exit 0.

    So prove the 200 came from the TOKEN: the same deep route answers 401 with no header and 401 with a
    well-formed but invalid bearer, and only the minted administrator bearer gets through.
    """
    async with dast_target() as target:
        assert target.admin_token and target.viewer_token
        assert target.admin_token != target.viewer_token, (
            "both identities minted the same token — the sweep would be probing one identity twice"
        )
        assert len(target.identities[ADMIN_USERNAME]) > len(
            target.identities[dast_target_module.VIEWER_USERNAME]
        ), "the low-privilege identity is not lower-privilege, so the BFLA pass would prove nothing"

        async with httpx.AsyncClient(base_url=target.base_url, timeout=30.0) as client:
            anonymous = await client.get(dast_target_module.PREFLIGHT_PATH)
            assert anonymous.status_code == 401, (
                "the deep preflight route answered a TOKENLESS caller. Every later 200 would then be "
                "consistent with an anonymous fallback rather than a real session."
            )
            invalid = await client.get(
                dast_target_module.PREFLIGHT_PATH,
                headers={"Authorization": "Bearer dast-not-a-real-token"},
            )
            assert invalid.status_code == 401
            authenticated = await client.get(
                dast_target_module.PREFLIGHT_PATH,
                headers={"Authorization": f"Bearer {target.admin_token}"},
            )
            assert authenticated.status_code == 200, (
                f"the administrator session could not reach {dast_target_module.PREFLIGHT_PATH} "
                f"({authenticated.status_code})"
            )


async def test_a_wrong_credential_fails_closed_at_login() -> None:
    """A credential the target rejects must raise, never degrade to an anonymous scan.

    DOCUMENTED GAP — the assignment asks for "a missing credential env var fails CLOSED". There is no
    such variable to miss: ``dast_target`` PROVISIONS both throwaway identities into a store it creates
    empty in a temp directory, and generates a fresh random password per run when the optional
    ``MEFOR_DAST_SCAN_PASSWORD`` escape hatch is unset (a checked-in constant would be strictly weaker).
    So the honest equivalent is exercised instead: the real ``_login`` against the real listener with a
    wrong password must raise ``DastTargetUnusable``, and ``main()`` must turn that into exit 2 — proved
    by ``test_unusable_session_exits_2``.
    """
    async with (
        dast_target() as target,
        httpx.AsyncClient(base_url=target.base_url, timeout=30.0) as client,
    ):
        with pytest.raises(DastTargetUnusable) as caught:
            await _login(client, ADMIN_USERNAME, "not-the-generated-scan-password")
    message = str(caught.value)
    assert "could not mint a session" in message
    assert "meaningless" in message, (
        "the failure must say WHY a scan without an identity is worthless"
    )


# =====================================================================================================
# Fail on purpose — the canaries
# =====================================================================================================


def test_canary_open_auth_is_detected(tmp_path: Path) -> None:
    """AC-3. FAIL ON PURPOSE: authentication disabled at the target must exit 1 with real findings.

    THE TRAP THIS CANARY IS SPECIFIED AROUND: ``allow_no_auth=True`` is honoured ONLY when
    ``auth is None or not auth.enabled`` (``messagefoundry/api/security.py``). Passing it alongside an
    ENABLED ``AuthService`` is SILENTLY IGNORED, and the canary then reports ZERO findings and "passes
    clean" — indistinguishable from a blind scanner. ``dast_target`` therefore builds the canary app
    against a second, DISABLED service. If this case ever starts passing with exit 0, the sweep has gone
    blind; do NOT rerun it, and do not relax the floor.
    """
    receipt_path = tmp_path / "canary-open-auth.json"
    code = main(["--policy", str(_POLICY), "--canary", "open-auth", "--receipt", str(receipt_path)])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert code == 1, (
        f"the open-auth canary exited {code}. A canary that does not red means the sweep cannot see an "
        "authentication bypass, so nothing it reports on a real run can be credited."
    )
    assert receipt["negative_non_401"] >= 50, receipt["negative_non_401"]
    assert receipt["posture"]["auth"].startswith("DISABLED"), receipt["posture"]["auth"]
    assert any(f["pass_name"].startswith("negative-") for f in receipt["findings"])


def test_canary_bfla_is_detected(tmp_path: Path) -> None:
    """AC-4. FAIL ON PURPOSE: over-granting the low-privilege identity must exit 1.

    Authentication is untouched here, which is precisely why the open-auth canary cannot catch it —
    they are separate canaries because they inject separate defect classes.
    """
    receipt_path = tmp_path / "canary-bfla.json"
    code = main(["--policy", str(_POLICY), "--canary", "bfla", "--receipt", str(receipt_path)])
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert code == 1, (
        f"the bfla canary exited {code}. A canary that does not red means the sweep cannot see broken "
        "function-level authorization."
    )
    assert receipt["bfla_violations"] >= 5, receipt["bfla_violations"]
    assert receipt["negative_non_401"] == 0, (
        "the bfla canary must inject ONLY an authorization defect; a negative finding here means it "
        "also broke authentication, and the two canaries would no longer be independent"
    )
    assert all(f["pass_name"] == "bfla" for f in receipt["findings"])


# =====================================================================================================
# Fail closed — the floors must BITE, not decorate
# =====================================================================================================


def test_floor_breach_exits_2(tmp_path: Path, clean_run: tuple[int, dict[str, Any]]) -> None:
    """A coverage floor that is not met is 2 (could not measure), never 0 and never 1.

    Driven end to end against a temp policy whose floor sits one ABOVE the real count, so it exercises
    the same path a shrinking route table would take.
    """
    _code, receipt = clean_run
    policy = _policy()
    policy["floors"]["min_gated_http_rows"] = int(receipt["gated_http_rows"]) + 1
    policy_path = tmp_path / "floor-breach-policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    receipt_path = tmp_path / "receipt.json"
    code = main(["--policy", str(policy_path), "--receipt", str(receipt_path)])
    assert code == 2, (
        f"an unmet coverage floor exited {code}. Exit 0 would report a pass on a run that measured too "
        "little to mean anything; exit 1 would misfile it as a finding."
    )
    written = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert written["verdict"] == "COULD NOT MEASURE (fail closed)"


def test_zero_gated_operations_exits_2() -> None:
    """AC-5. If the gate derivation breaks, EVERY route reads as ungated and the sweep has nothing to
    probe. That has happened here before — a refactor renamed the gate closure's qualname and every
    route silently read as ungated — so "no gated operation" must fail closed and say so."""
    code, errors = evaluate({"gated_http_rows": 0}, _policy())
    assert code == 2, f"a receipt with no gated operation exited {code}"
    assert any("ZERO" in line for line in errors), errors
    assert any("blind gate" in line for line in errors), errors


def test_unusable_session_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A session that cannot reach a deep route makes every later 403 meaningless.

    Injected honestly: the bring-up preflight is pointed at a route the bearer identity genuinely
    cannot reach (mTLS-client-certificate only, ADR 0083), so the REAL preflight code sees a real
    non-200 over the wire. The sweep must refuse to report at all rather than emit a clean wall of
    refusals.
    """
    monkeypatch.setattr(dast_target_module, "PREFLIGHT_PATH", _UNREACHABLE_ROUTE)
    receipt_path = tmp_path / "receipt.json"
    code = main(["--policy", str(_POLICY), "--receipt", str(receipt_path)])
    assert code == 2, f"an unusable administrator session exited {code}"
    assert not receipt_path.exists(), (
        "a receipt was written for a run that never measured anything; the artifact would read as "
        "evidence of a scan that did not happen"
    )


def test_a_target_that_dies_mid_scan_exits_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transport failure is the canonical COULD-NOT-MEASURE, and it must not exit 1.

    Without a catch-all in ``main()`` an ``httpx`` error escapes, CPython exits 1 — the FINDINGS code —
    and no receipt is written. An operator triaging the nightly by exit code would read "the sweep found
    authorization defects" where the truth is "the sweep never finished talking to the app". Worse, the
    CI canary loop treats exit 1 as proof the canary detected its injected defect, so a canary that
    crashed before issuing a single probe would certify a detection that never happened.
    """
    import scripts.security.dast_auth_sweep as sweep

    async def _dead(*_args: object, **_kwargs: object) -> int:
        raise httpx.ReadTimeout("the target went away mid-scan")

    monkeypatch.setattr(sweep, "_probe", _dead)
    receipt_path = tmp_path / "receipt.json"
    code = main(["--policy", str(_POLICY), "--receipt", str(receipt_path)])
    assert code == 2, (
        f"a target that died mid-scan exited {code}. Exit 1 would file a run that measured nothing as "
        "a set of findings; only 2 says 'could not measure'."
    )
    assert not receipt_path.exists(), "a receipt was written for a scan that never completed"


def test_a_crashing_canary_exits_2_not_1(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The same escape, on the path where it does the most damage.

    CI reads exit 1 from a canary as "the injected defect was detected". A canary that crashed must
    therefore never produce that code, or the loop would certify a detection that never happened and
    then run the real scan under the impression the sweep had been proved sighted.
    """
    import scripts.security.dast_auth_sweep as sweep

    async def _dead(*_args: object, **_kwargs: object) -> int:
        raise httpx.ConnectError("the canary target never answered")

    monkeypatch.setattr(sweep, "_probe", _dead)
    code = main(["--policy", str(_POLICY), "--canary", "open-auth"])
    assert code == 2, (
        f"a crashed canary exited {code}; CI would have read 1 as a successful detection"
    )


def test_a_missing_policy_fails_closed(tmp_path: Path) -> None:
    """No policy means no floors, and a sweep with no floors cannot report having measured too little."""
    assert main(["--policy", str(tmp_path / "absent.json")]) == 2


def test_a_policy_without_floors_fails_closed(tmp_path: Path) -> None:
    """A floor the policy simply forgot must not silently pass — an absent floor is not a met floor."""
    policy = _policy()
    del policy["floors"]["min_get_rows_reached"]
    code, errors = evaluate(
        {
            "gated_http_rows": 99,
            "route_rows_examined": 105,
            "negative_probes": 198,
            "reached": 46,
            "bfla_probes": 19,
            "ungated_routes": policy["anonymous_allowlist"],
        },
        policy,
    )
    assert code == 2
    assert any("declares no floor" in line for line in errors), errors


# =====================================================================================================
# The route walk — nothing may fall off the end of it
# =====================================================================================================


def test_no_route_falls_off_the_end_of_the_walk() -> None:
    """Every route object on the app must produce at least one row.

    The ungated-set invariant is the sweep's defence against a route landing with no ``require*()``
    gate. It is worth exactly as much as the walk's coverage: an earlier revision classified only
    ``APIRoute`` and ``APIWebSocketRoute`` and dropped everything else silently, so the four anonymous
    docs endpoints (``/openapi.json``, ``/docs``, ``/docs/oauth2-redirect``, ``/redoc``) and the ``/ui``
    static mount were invisible to it — a detector blind to a whole route class while reporting
    "ungated set matches the documented anonymous allowlist".

    Driven with ``expose_docs=True`` and ``serve_ui=True`` on purpose: those are the flags that
    MATERIALISE the route classes the walk used to drop.
    """
    from messagefoundry.api.app import create_app
    from scripts.security import route_gates

    app = create_app(expose_docs=True)
    rows = route_gates.route_rows(app)
    covered = {row.path for row in rows}
    missing = sorted(
        getattr(route, "path", "?")
        for route in app.routes
        if getattr(route, "path", None) not in covered
    )
    assert not missing, (
        f"route(s) the walk emitted no row for: {missing}. A route class the walk does not understand "
        "must land in ungated_http_rows and be reviewed into an allow-list, never vanish."
    )
    docs = {"/openapi.json", "/docs", "/redoc"}
    assert docs <= covered, f"the docs routes are still dropped: {sorted(docs - covered)}"
    # They land UNGATED, which is the truth — they carry no require*() dependency.
    ungated = {r.path for r in route_gates.ungated_http_rows(app)}
    assert docs <= ungated, sorted(docs - ungated)


def test_the_scan_target_publishes_no_docs_surface_of_its_own() -> None:
    """The scan must not create the surface it then reports on.

    ``expose_docs`` is OFF by the shipped default; an earlier revision turned it ON at the target,
    which published four anonymous 200 endpoints that exist only because the scan asked for them. The
    receipt's posture must record what was actually scanned.
    """
    posture = dast_target_module._posture(canary=None)
    assert posture["expose_docs"] == "OFF", posture
    assert posture["serve_ui"] == "OFF", posture


# =====================================================================================================
# The oracle
# =====================================================================================================


def test_only_an_expected_canary_finding_is_downgraded_to_a_notice() -> None:
    """Real findings must stay `::error::`, or the job's only signal is buried under canary noise.

    A detecting canary emits ~215 findings by design, so annotating them as errors would put a wall of
    red on a perfectly healthy nightly and — past GitHub's per-step annotation cap — truncate the REAL
    scan's findings behind them. The downgrade is therefore narrow, and its two dangerous edges are
    pinned here: a real scan's findings (no canary) are never quietened, and a canary that COULD NOT
    MEASURE (exit 2) is never quietened either, because that outcome is never expected.
    """
    assert annotation_level(canary="open-auth", code=1) == "notice"
    assert annotation_level(canary="bfla", code=1) == "notice"
    assert annotation_level(canary=None, code=1) == "error", (
        "a REAL scan's findings were downgraded to a notice — the job's whole signal would go quiet"
    )
    assert annotation_level(canary="open-auth", code=2) == "error", (
        "a canary that could not measure was downgraded to a notice; that outcome is never expected "
        "and is exactly the one an operator must see"
    )
    assert annotation_level(canary=None, code=2) == "error"


def test_bfla_oracle_treats_404_as_a_violation() -> None:
    """404 is NOT a refusal. The probe requests a path built from the route's own TEMPLATE, so the route
    matched; a 404 therefore means the caller got PAST authorization and into resource lookup — which is
    the defect the BFLA pass exists to find. A scanner that scored 404 as "denied" would report a
    broken-authorization API as clean.
    """
    assert is_refused(404) is False
    assert all(is_refused(s) for s in (401, 403, 429))
    assert is_refused(200) is False

    policy = _policy()
    receipt = {
        "gated_http_rows": 99,
        "route_rows_examined": 105,
        "negative_probes": 198,
        "reached": 46,
        "bfla_probes": 19,
        "bfla_violations": 1,
        "unreached_unexplained": 0,
        "ungated_routes": policy["anonymous_allowlist"],
        "findings": [
            {
                "method": "GET",
                "path": "/messages/{message_id}",
                "pass_name": "bfla",
                "observed_status": 404,
                "expected": "401, 403 or 429",
            }
        ],
    }
    code, errors = evaluate(receipt, policy)
    assert code == 1, f"a 404 answered to the low-privilege identity exited {code}, not 1"
    assert any("404" in line and "bfla" in line for line in errors), errors


def test_an_unexplained_unreached_operation_is_a_finding() -> None:
    """The fake-green detector itself. If a wall (MFA, step-up, a limiter) silently re-arms, reach
    collapses and unreached-unexplained goes positive — that must red the run, not be absorbed. An
    operation may only become unreachable by being written into the allow-list WITH a reason."""
    policy = _policy()
    receipt = {
        "gated_http_rows": 99,
        "route_rows_examined": 105,
        "negative_probes": 198,
        "reached": 46,
        "bfla_probes": 19,
        "unreached_unexplained": 3,
        "ungated_routes": policy["anonymous_allowlist"],
        "findings": [],
    }
    code, errors = evaluate(receipt, policy)
    assert code == 1
    assert any("unreachable_allowlist" in line for line in errors), errors
    assert all(entry.get("reason") for entry in policy["unreachable_allowlist"]), (
        "every unreachable_allowlist entry must carry a reason; an unexplained exemption is how a "
        "shrinking scan becomes invisible"
    )


def test_a_newly_ungated_route_reds_the_run() -> None:
    """Drive the shipped ``evaluate()`` with an ungated set that gained a route it should not have."""
    policy = _policy()
    receipt = {
        "gated_http_rows": 99,
        "route_rows_examined": 105,
        "negative_probes": 198,
        "reached": 46,
        "bfla_probes": 19,
        "unreached_unexplained": 0,
        "ungated_routes": [*policy["anonymous_allowlist"], {"method": "GET", "path": "/messages"}],
        "findings": [],
    }
    code, errors = evaluate(receipt, policy)
    assert code == 1
    assert any("/messages" in line for line in errors), errors


# =====================================================================================================
# Advisory BY PLACEMENT, not by continue-on-error — the workflow's structural invariants
# =====================================================================================================


def _dast_workflow() -> dict[Any, Any]:
    from tests._workflow_contexts import load_workflow

    # Keyed by ``Any``, not ``str``: PyYAML parses a bare ``on:`` key as the BOOLEAN True (YAML 1.1),
    # so this mapping genuinely has a non-string key.
    return dict(load_workflow("dast.yml"))


def test_the_dast_workflow_has_no_pull_request_trigger() -> None:
    """This is what makes the job structurally incapable of wedging a PR — and therefore what makes it
    safe to leave out of branch protection. A ``pull_request`` arm would create exactly the
    required-but-absent trap docs/CI.md warns about."""
    doc = _dast_workflow()
    # PyYAML parses a bare ``on:`` key as the BOOLEAN True (YAML 1.1), so read both spellings.
    triggers = doc.get(True, doc.get("on"))
    assert isinstance(triggers, dict), triggers
    assert "pull_request" not in triggers, triggers
    assert "pull_request_target" not in triggers, triggers
    assert set(triggers) >= {"schedule", "workflow_dispatch", "push"}, triggers


def test_the_dast_job_can_actually_go_red() -> None:
    """ADVISORY MEANS NOT IN BRANCH PROTECTION. It does not mean ``continue-on-error``: GitHub reports a
    continue-on-error job as SUCCESS, which is a job that CANNOT fail — the measurement-gate lie this
    whole change is organised against."""
    doc = _dast_workflow()
    jobs = doc["jobs"]
    assert set(jobs) == {"dast-auth"}, jobs
    job = jobs["dast-auth"]
    assert "continue-on-error" not in job, job
    for step in job["steps"]:
        assert "continue-on-error" not in step, step
        run = step.get("run", "")
        assert "|| true" not in run, step
        assert "--exit-zero" not in run, step
        assert "|| exit 0" not in run, step


def test_the_dast_job_name_collides_with_no_other_workflow_job() -> None:
    """JOB-NAME COLLISION IS THE SILENT KILLER HERE. ``tests/_workflow_contexts.py`` keys reportable
    jobs by DECLARED NAME across ALL workflow files and expands an Actions expression to a ``.+``
    wildcard, so a colliding or templated name would silently re-map an existing REQUIRED context onto
    this advisory job."""
    from tests._workflow_contexts import WORKFLOWS, context_of, jobs_of

    name = _dast_workflow()["jobs"]["dast-auth"]["name"]
    assert "${{" not in name, f"a templated job name resolves as a wildcard context: {name!r}"

    elsewhere = [
        (path.name, key)
        for path in sorted(WORKFLOWS.glob("*.yml"))
        if path.name != "dast.yml"
        for key, job in jobs_of(path.name).items()
        if context_of(key, job) == name
    ]
    assert not elsewhere, f"the DAST job name {name!r} is already declared by {elsewhere}"


def test_the_dast_job_adds_no_required_context() -> None:
    """A new workflow file adds ZERO contexts to the canonical required set. If this ever fails, either
    the job was promoted without the branch-protection change, or the canonical list drifted."""
    from tests._workflow_contexts import required_contexts

    contexts = required_contexts()
    name = _dast_workflow()["jobs"]["dast-auth"]["name"]
    assert name not in contexts, (
        f"{name!r} is in .github/required-contexts.txt but its workflow has no pull_request trigger, "
        "so it can never report on a PR — that is the required-but-absent trap."
    )
    assert "dast" not in " ".join(contexts).lower()


def test_the_dast_job_installs_no_scanner() -> None:
    """The whole design rests on adding no dependency: the sweep runs on uvicorn + httpx, which are BASE
    runtime deps. An inline scanner install here would also trip
    ``tests/test_ci_venv_pinning.py::test_no_moved_tool_is_reinstalled_inline``."""
    runs = " ".join(
        step.get("run", "") for step in _dast_workflow()["jobs"]["dast-auth"]["steps"]
    ).lower()
    for tool in (
        "bandit",
        "pip-audit",
        "zizmor",
        "mutmut",
        "diff-cover",
        "pytest-cov",
        "schemathesis",
    ):
        assert f"install {tool}" not in runs, tool
        assert f"add {tool}" not in runs, tool


def test_the_canary_step_runs_before_the_real_scan() -> None:
    """A green DAST run whose canary was not proven THAT SAME RUN is not evidence of anything, so the
    canary must gate the scan rather than follow it."""
    steps = _dast_workflow()["jobs"]["dast-auth"]["steps"]
    # Located by what each step RUNS, not by its name: the canary step's own name mentions the sweep,
    # so a name match would have identified the wrong step (and did, the first time this was written).
    runs = [str(step.get("run", "")) for step in steps]
    canary = next(i for i, run in enumerate(runs) if "--canary" in run)
    scan = next(
        i for i, run in enumerate(runs) if "dast_auth_sweep.py" in run and "--canary" not in run
    )
    assert canary < scan, [str(step.get("name", "")) for step in steps]
    canary_run = runs[canary]
    assert "--canary" in canary_run
    for name in ("open-auth", "bfla"):
        assert name in canary_run, f"the canary step no longer runs the {name} canary"
    assert "::error::" in canary_run, (
        "a canary outcome that does not demonstrate detection must be a hard, annotated failure — "
        "that outcome means the sweep is blind or could not measure, which is worse than a finding"
    )


def test_the_canary_step_demands_exit_code_1_specifically() -> None:
    """THE CANARY GATE MUST TEST THE EXACT CODE, and this asserts the shipped shell does.

    A canary run can never exit 0 — ``evaluate()`` turns a below-floor canary into 2 (could not
    measure) and an above-floor one into 1 (findings), and every counted finding is appended to the
    findings list, so there is no path to a clean canary. An earlier revision of the step therefore
    read ``if <the sweep succeeded>; then <fail>; fi``, which is DEAD CODE guarding a shape that cannot
    occur — while silently accepting exit 2, the shape a NEUTERED canary actually produces, as proof of
    detection. That is the "detector guarding a shape that cannot occur" failure this whole change is
    organised against, so the fix is pinned here rather than left to review.
    """
    runs = [str(step.get("run", "")) for step in _dast_workflow()["jobs"]["dast-auth"]["steps"]]
    canary_run = next(run for run in runs if "--canary" in run)

    assert "-ne 1" in canary_run, (
        "the canary step no longer compares the exit code against 1 specifically. Any 'non-zero means "
        "detected' form accepts exit 2 (could not measure) and a crash as proof of detection, and its "
        "exit-0 branch is unreachable dead code."
    )
    assert "rc=" in canary_run, (
        "the canary step must CAPTURE the exit code to compare it; an `if <command>` condition can "
        "only distinguish zero from non-zero"
    )
    # The receipt is the canary's other half of the evidence. On the fail-closed paths main() returns
    # before writing one, and `if-no-files-found: error` on the upload fires only when EVERY glob is
    # empty — so a missing canary receipt would otherwise ride along invisibly beside the real one.
    assert 'canary-$c.json" ]' in canary_run or 'canary-$c.json" ];' in canary_run, (
        "the canary step does not verify that the canary wrote its receipt"
    )
