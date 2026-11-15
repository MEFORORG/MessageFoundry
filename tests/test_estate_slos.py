# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The estate SLO verdict fails a run that never drained or measured nothing (BACKLOG #5437).

``_evaluate_slos`` used to check the drain only when ``max_drain_seconds`` was set, and that threshold
defaults to unset, so a timed-out drain passed on default settings. ``zero_loss`` used ``all()`` over
the records, which is true for an empty list.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from typing import cast

from harness.load.estate import runner
from harness.load.estate.profile import EstateProfile, EstateSlo, get_estate_profile
from harness.load.estate.report import EstateRecord


def _profile(slo: EstateSlo) -> EstateProfile:
    return dataclasses.replace(get_estate_profile("estate-smoke"), slo=slo)


def _rec(*, drain_seconds: float | None, no_loss_ok: bool = True) -> EstateRecord:
    return cast(
        EstateRecord,
        SimpleNamespace(drain_seconds=drain_seconds, no_loss=SimpleNamespace(ok=no_loss_ok)),
    )


def _passes(profile: EstateProfile, records: list[EstateRecord]) -> bool:
    return all(c.ok for c in runner._evaluate_slos(profile, records))


def test_a_drained_lossless_run_passes_on_the_default_slo() -> None:
    profile = _profile(EstateSlo())
    assert profile.slo.max_drain_seconds is None  # the default this row is about
    assert _passes(profile, [_rec(drain_seconds=1.5)])


def test_a_timed_out_drain_fails_on_the_default_slo_bug_5437() -> None:
    checks = runner._evaluate_slos(_profile(EstateSlo()), [_rec(drain_seconds=None)])
    assert not all(c.ok for c in checks)
    drain = next(c for c in checks if c.name == "drain_completed")
    assert not drain.ok
    assert drain.observed == "0/1"


def test_an_empty_record_list_fails_bug_5437() -> None:
    assert not _passes(_profile(EstateSlo()), [])
    assert not _passes(_profile(EstateSlo(zero_loss=True, max_drain_seconds=10.0)), [])


def test_a_timed_out_drain_poisons_the_max_drain_worst_case_bug_5437() -> None:
    # One record drained in 1 s and one timed out: the worst case is "never drained", not 1 s.
    checks = runner._evaluate_slos(
        _profile(EstateSlo(max_drain_seconds=10.0)),
        [_rec(drain_seconds=1.0), _rec(drain_seconds=None)],
    )
    max_drain = next(c for c in checks if c.name == "max_drain_seconds")
    assert not max_drain.ok
    assert max_drain.observed == -1.0
