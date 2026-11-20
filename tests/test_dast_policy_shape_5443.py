# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5443: a malformed DAST policy is could-not-measure (exit 2), never a crash to exit 1.

Exit 1 is the sweep's FINDINGS code, and the CI canary loop reads it as "the canary detected its
injected defect". ``load_policy`` checked only that the sections exist, and ``main`` ran ``evaluate``
and ``receipt_lines`` outside any handler, so a null floor, a non-numeric cap or a malformed
allow-list entry crashed the run to exit 1 after the sweep: a canary that certified a detection that
never happened. ``load_policy`` now checks each value's type, and ``main`` refuses with 2 if the
post-sweep steps raise anyway.

No live sweep runs here: ``_run`` is stubbed to hand back a hand-built passing receipt, so the only
thing that can change the exit code is the policy under test.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import pytest

from scripts.security import dast_auth_sweep as sweep
from tests.test_dast_auth_sweep import _declared_public, _passing_ws_rows, _policy


def _receipt(policy: dict[str, Any]) -> dict[str, Any]:
    """A receipt that clears every floor of the shipped policy, as a clean sweep would report it."""
    return {
        "route_rows_examined": 105,
        "gated_http_rows": 99,
        "ungated_http_rows": 5,
        "negative_probes": 198,
        "negative_non_401": 0,
        "reached": 46,
        "get_rows": 49,
        "bfla_probes": 19,
        "bfla_violations": 0,
        "write_reached": 61,
        "write_rows": 61,
        "write_bfla_probes": 43,
        "write_bfla_violations": 0,
        "websocket_rows": _passing_ws_rows(),
        "unreached_unexplained": 0,
        "ungated_routes": _declared_public(policy),
        "findings": [],
    }


def _stub_sweep(monkeypatch: pytest.MonkeyPatch, receipt: dict[str, Any]) -> None:
    def run(coro: Coroutine[Any, Any, dict[str, Any]]) -> dict[str, Any]:
        coro.close()  # never started: nothing is measured, the receipt stands in for the sweep
        return dict(receipt)

    monkeypatch.setattr(sweep, "_run", run)


def _main(tmp_path: Path, policy: dict[str, Any], *extra: str) -> int:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    return sweep.main(["--policy", str(path), *extra])


def _null_floor(p: dict[str, Any]) -> None:
    p["floors"]["min_get_rows_reached"] = None


def _text_floor(p: dict[str, Any]) -> None:
    p["floors"]["min_bfla_probes"] = "lots"


def _bool_floor(p: dict[str, Any]) -> None:
    p["floors"]["min_bfla_probes"] = True


def _null_floors(p: dict[str, Any]) -> None:
    p["floors"] = None


def _null_cap(p: dict[str, Any]) -> None:
    p["max_unexplained_unreached"] = None


def _text_rebuild_cap(p: dict[str, Any]) -> None:
    p["max_write_session_rebuilds"] = "five"


def _string_allowlist_entry(p: dict[str, Any]) -> None:
    p["anonymous_allowlist"] = [*p["anonymous_allowlist"], "GET /planted"]


def _pathless_allowlist_entry(p: dict[str, Any]) -> None:
    p["unreachable_allowlist"] = [{"method": "GET"}]


def _null_canary_floor(p: dict[str, Any]) -> None:
    p["canary_floors"]["bfla_min_violations"] = None


def _null_canary_floors(p: dict[str, Any]) -> None:
    p["canary_floors"] = None


_MALFORMED: list[Any] = [
    pytest.param(_null_floor, id="null-floor"),
    pytest.param(_text_floor, id="text-floor"),
    pytest.param(_bool_floor, id="bool-floor"),
    pytest.param(_null_floors, id="null-floors-section"),
    pytest.param(_null_cap, id="null-unexplained-cap"),
    pytest.param(_text_rebuild_cap, id="text-rebuild-cap"),
    pytest.param(_string_allowlist_entry, id="string-allowlist-entry"),
    pytest.param(_pathless_allowlist_entry, id="pathless-allowlist-entry"),
    pytest.param(_null_canary_floor, id="null-canary-floor"),
    pytest.param(_null_canary_floors, id="null-canary-floors-section"),
]


def test_control_the_shipped_policy_passes_the_stubbed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control: with the shipped policy the same receipt exits 0, so a 2 below is the policy's."""
    policy = _policy()
    _stub_sweep(monkeypatch, _receipt(policy))
    assert _main(tmp_path, policy) == 0


@pytest.mark.parametrize("break_it", _MALFORMED)
@pytest.mark.parametrize("canary", [None, "bfla"])
def test_a_malformed_policy_cannot_measure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    break_it: Callable[[dict[str, Any]], None],
    canary: str | None,
) -> None:
    """Each malformed shape exits 2, with or without a canary, and never raises out of main."""
    policy = _policy()
    receipt = _receipt(policy)
    if canary is not None:
        receipt.update(canary=canary, bfla_violations=19, write_bfla_violations=52)
    _stub_sweep(monkeypatch, receipt)
    break_it(policy)
    extra = ("--canary", canary) if canary is not None else ()
    assert _main(tmp_path, policy, *extra) == 2
    assert "fail closed" in capsys.readouterr().err


@pytest.mark.parametrize("break_it", _MALFORMED)
def test_load_policy_itself_refuses_each_malformed_shape(
    tmp_path: Path, break_it: Callable[[dict[str, Any]], None]
) -> None:
    """The refusal is load_policy's, not only main's backstop: each shape raises PolicyError."""
    policy = _policy()
    break_it(policy)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    with pytest.raises(sweep.PolicyError):
        sweep.load_policy(path)


def test_a_reporting_crash_after_the_sweep_is_could_not_measure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The backstop: whatever raises after the sweep, main answers 2, not CPython's 1."""
    policy = _policy()
    _stub_sweep(monkeypatch, _receipt(policy))

    def broken(*_: object) -> list[str]:
        raise KeyError("synthetic")

    monkeypatch.setattr(sweep, "receipt_lines", broken)
    assert _main(tmp_path, policy) == 2
    assert "fail closed" in capsys.readouterr().err


@pytest.mark.parametrize("placeholder", ["", "a/b", 7, ".", ".."])
def test_a_path_placeholder_that_is_not_one_segment_cannot_measure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, placeholder: object
) -> None:
    """Substituted into every path parameter, a bad placeholder probes other routes: findings, 1."""
    policy = _policy()
    _stub_sweep(monkeypatch, _receipt(policy))
    policy["path_param_placeholder"] = placeholder
    assert _main(tmp_path, policy) == 2


def test_control_a_detecting_canary_still_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Control for the canary arm above: with the shipped policy, a canary receipt carrying a
    finding exits 1, so the 2s there are the malformed policy's and not the canary's."""
    policy = _policy()
    receipt = _receipt(policy)
    receipt.update(canary="bfla", bfla_violations=19, write_bfla_violations=52)
    receipt["findings"] = [
        {
            "pass_name": "bfla",
            "method": "GET",
            "path": "/synthetic",
            "observed_status": 200,
            "expected": "403",
        }
    ]
    _stub_sweep(monkeypatch, receipt)
    assert _main(tmp_path, policy, "--canary", "bfla") == 1


def test_a_reporting_crash_still_writes_the_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The measured counts are evidence, so the receipt is written, marked could-not-measure, and
    a multi-line exception stays one annotation."""
    policy = _policy()
    _stub_sweep(monkeypatch, _receipt(policy))

    def broken(*_: object) -> list[str]:
        raise RuntimeError("synthetic\nsecond line")

    monkeypatch.setattr(sweep, "receipt_lines", broken)
    out = tmp_path / "receipt.json"
    assert _main(tmp_path, policy, "--receipt", str(out)) == 2
    err = capsys.readouterr().err
    assert "synthetic%0Asecond line" in err
    assert not any(line.startswith("second line") for line in err.splitlines())
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["verdict"] == "COULD NOT MEASURE (fail closed)"
    assert written["gated_http_rows"] == 99


def test_a_policy_that_is_not_utf8_cannot_measure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A policy file that does not decode is unread, exit 2, not a UnicodeDecodeError to 1."""
    path = tmp_path / "policy.json"
    path.write_bytes(b"\xff\xfe{}")
    assert sweep.main(["--policy", str(path)]) == 2
    assert "fail closed" in capsys.readouterr().err


def test_load_policy_does_not_claim_its_readers_run_outside_a_handler() -> None:
    """load_policy's comments said its readers ran outside a handler and would crash to exit 1.
    main's catch-alls now cover every later reader, as the reporting-crash tests above exercise,
    so neither stale reason may stand. Only the withdrawn claims are pinned, not new wording."""
    # One line of prose, so a claim wrapped across two comment lines still matches.
    lines = inspect.getsource(sweep.load_policy).splitlines()
    source = " ".join(line.strip().lstrip("#").strip() for line in lines)
    for stale in ("outside any handler", "outside evaluate()'s", "crash it later as exit 1"):
        assert stale not in source, stale
