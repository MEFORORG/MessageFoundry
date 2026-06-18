# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the load-profile schema + TOML loader.

Pin the loud-validation contract (a typo'd/missing/wrong-typed key is rejected before any traffic),
the open/closed-loop rate interpolation the governor relies on, and that the shipped built-in presets
parse and self-validate.
"""

from __future__ import annotations

import pytest

from harness.load.profile import (
    PROFILES_DIR,
    LoadProfileError,
    Phase,
    TypeMix,
    get_profile,
    list_profiles,
    load_profile_text,
)

_MINIMAL = """
[load]
name = "t"
[[load.target]]
name = "hub"
port = 2600
types = ["ADT"]
[load.mix]
ADT = 1.0
[[load.phase]]
name = "s"
kind = "sustained"
loop = "open"
rate_start = 10.0
duration_s = 5.0
"""


def test_minimal_profile_parses_with_defaults() -> None:
    p = load_profile_text(_MINIMAL)
    assert p.name == "t"
    assert p.pool_size == 8  # default
    assert len(p.targets) == 1 and p.targets[0].port == 2600
    assert p.targets[0].types == ("ADT",)
    assert len(p.phases) == 1 and p.phases[0].measured


def test_unknown_key_fails_loud() -> None:
    bad = _MINIMAL + "\n[load.slo]\nmax_e2e_p99_ms = 5000\nwidgets = 3\n"
    with pytest.raises(LoadProfileError, match="unknown key"):
        load_profile_text(bad)


def test_unknown_top_level_key_fails_loud() -> None:
    with pytest.raises(LoadProfileError, match="unknown top-level"):
        load_profile_text(_MINIMAL + "\n[other]\nx = 1\n")


def test_missing_mix_fails_loud() -> None:
    no_mix = """
[load]
name = "t"
[[load.target]]
name = "hub"
[[load.phase]]
name = "s"
kind = "sustained"
loop = "open"
rate_start = 10.0
duration_s = 5.0
"""
    with pytest.raises(LoadProfileError, match="load.mix"):
        load_profile_text(no_mix)


def test_closed_loop_requires_concurrency() -> None:
    bad = """
[load]
name = "t"
[[load.target]]
name = "hub"
types = ["ADT"]
[load.mix]
ADT = 1.0
[[load.phase]]
name = "c"
kind = "sustained"
loop = "closed"
duration_s = 5.0
"""
    with pytest.raises(LoadProfileError, match="concurrency"):
        load_profile_text(bad)


def test_open_loop_requires_positive_rate() -> None:
    bad = _MINIMAL.replace("rate_start = 10.0", "rate_start = 0.0")
    with pytest.raises(LoadProfileError, match="positive rate"):
        load_profile_text(bad)


def test_bad_kind_and_loop_rejected() -> None:
    with pytest.raises(LoadProfileError, match="kind"):
        load_profile_text(_MINIMAL.replace('kind = "sustained"', 'kind = "blast"'))
    with pytest.raises(LoadProfileError, match="loop"):
        load_profile_text(_MINIMAL.replace('loop = "open"', 'loop = "sideways"'))


def test_mix_emits_type_no_target_accepts() -> None:
    bad = _MINIMAL.replace("ADT = 1.0", "ADT = 1.0\nORU = 1.0")
    with pytest.raises(LoadProfileError, match="no target accepts"):
        load_profile_text(bad)


def test_target_with_no_types_accepts_all() -> None:
    # A target without an explicit types filter accepts every code, so the cross-ref check passes.
    text = _MINIMAL.replace('types = ["ADT"]', "").replace("ADT = 1.0", "ADT = 1.0\nORU = 2.0")
    p = load_profile_text(text)
    assert p.codes() == {"ADT", "ORU"}


def test_type_mix_normalizes() -> None:
    mix = TypeMix({"ADT": 3.0, "ORU": 1.0})
    norm = mix.normalized()
    assert abs(norm["ADT"] - 0.75) < 1e-9 and abs(norm["ORU"] - 0.25) < 1e-9


def test_type_mix_zero_weights_rejected() -> None:
    with pytest.raises(LoadProfileError, match="positive"):
        TypeMix({"ADT": 0.0}).normalized()


def test_phase_rate_interpolation() -> None:
    ramp = Phase("r", "ramp", "open", duration_s=10.0, rate_start=100.0, rate_end=200.0)
    assert ramp.rate_at(0.0) == 100.0
    assert ramp.rate_at(5.0) == 150.0
    assert ramp.rate_at(10.0) == 200.0
    assert ramp.rate_at(20.0) == 200.0  # clamps past the end
    flat = Phase("f", "sustained", "open", duration_s=10.0, rate_start=300.0)
    assert flat.rate_at(3.0) == 300.0


def test_per_phase_mix_and_slo_override_defaults() -> None:
    text = (
        _MINIMAL
        + """
[[load.phase]]
name = "s2"
kind = "sustained"
loop = "open"
rate_start = 5.0
duration_s = 5.0
mix = { ADT = 1.0, ORL = 1.0 }
slo = { max_e2e_p99_ms = 999.0 }
"""
    )
    # ORL in the phase mix needs a target that accepts it; the only target is ADT-only → rejected.
    with pytest.raises(LoadProfileError, match="no target accepts"):
        load_profile_text(text)


@pytest.mark.parametrize("name", ["smoke", "fanout-baseline", "soak", "closed-loop"])
def test_builtin_presets_parse(name: str) -> None:
    p = get_profile(name)
    assert p.name == name
    assert p.phases and p.targets
    p.default_mix.normalized()  # weights valid


def test_closed_loop_profile_sweeps_concurrency_with_conformance_slo() -> None:
    p = get_profile("closed-loop")
    # Every phase is closed-loop with a concurrency (the governor's _run_closed needs it).
    assert p.phases
    for ph in p.phases:
        assert ph.loop == "closed"
        assert ph.concurrency is not None and ph.concurrency >= 1
    # The measured (sustained) phases step concurrency upward to find the throughput ceiling.
    measured = [ph.concurrency for ph in p.phases if ph.measured]
    assert len(measured) >= 2 and measured == sorted(measured)
    # The sender pool must exceed the highest concurrency, or the pool (not the engine) is the cap.
    assert p.pool_size > max(c for c in measured if c is not None)
    # Conformance-tier SLO only: zero loss enforced, no throughput floor (throughput is measured here).
    assert p.default_slo.zero_loss is True
    assert p.default_slo.min_sustained_msg_s is None


def test_list_profiles_includes_builtins() -> None:
    names = set(list_profiles())
    assert {"smoke", "fanout-baseline", "soak", "closed-loop"} <= names


def test_get_profile_unknown_lists_choices() -> None:
    with pytest.raises(LoadProfileError, match="unknown profile"):
        get_profile("does-not-exist")


def test_get_profile_by_path(tmp_path: object) -> None:
    # A filesystem path resolves directly (this is how real-numbers profiles in migration-local run).
    path = PROFILES_DIR / "smoke.toml"
    assert get_profile(str(path)).name == "smoke"
