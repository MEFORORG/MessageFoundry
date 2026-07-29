# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the new-dependency (anti-slopsquat) gate.

Every test drives the SHIPPED functions from ``scripts/security/new_dependency_check.py`` through an
injected ``fetch``, never a local reimplementation of the rule. A guard whose test asserts its own copy
of the logic is a guard nobody has ever run.

The fetch seam is also what makes these offline and deterministic: the real gate talks to PyPI, and a
unit test that did the same would be a network flake in the required leg.
"""

from __future__ import annotations

import json
import urllib.error
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from scripts.security.new_dependency_check import (
    Finding,
    declared_distributions,
    main,
    normalize,
    requirement_name,
    vet,
)

_ROOT = Path(__file__).resolve().parents[1]
_NOW = datetime(2026, 7, 29, tzinfo=UTC)


def _payload(name: str, *, first_release: datetime | None, canonical: str | None = None) -> dict:
    releases: dict[str, list[dict]] = {}
    if first_release is not None:
        releases["1.0.0"] = [{"upload_time_iso_8601": first_release.isoformat()}]
    return {"info": {"name": canonical or name}, "releases": releases}


def _fetch_all_good(name: str) -> dict:
    return _payload(name, first_release=_NOW - timedelta(days=2000))


# --- the parsing layer -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("pynetdicom>=3.0.4,<4", "pynetdicom"),
        ("fhir.resources>=7.1.0", "fhir.resources"),
        ("webauthn>=3.0.0,<4", "webauthn"),
        ("annotated-types<0.8", "annotated-types"),
        ("uvicorn[standard]>=0.30", "uvicorn"),
        ("tomli; python_version < '3.11'", "tomli"),
        ("  hvac>=2.3.0  ", "hvac"),
        ("", None),
    ],
)
def test_requirement_name_extracts_the_distribution(spec: str, expected: str | None) -> None:
    assert requirement_name(spec) == expected


def test_normalize_matches_pep503() -> None:
    """The identity PyPI compares under — and the one that bit this repo already.

    pyproject records that "py_webauthn"/"py-webauthn" normalize to an UNRELATED project while the
    intended distribution is exactly "webauthn". Normalization is why those are the same name to PyPI.
    """
    assert normalize("py_webauthn") == normalize("py-webauthn") == "py-webauthn"
    assert normalize("webauthn") == "webauthn"
    assert normalize("fhir.resources") == "fhir-resources"
    assert normalize("Annotated_Types") == "annotated-types"


def test_declared_distributions_covers_extras_not_just_core() -> None:
    """An extra is exactly where a niche, plausible-sounding, hallucination-prone name lands."""
    found = declared_distributions(
        """
        [project]
        dependencies = ["fastapi>=0.100", "hl7>=0.4"]

        [project.optional-dependencies]
        dicom = ["pynetdicom>=3.0.4,<4", "pydicom>=3.0.2,<4"]
        vault = ["hvac>=2.3.0"]
        """
    )
    assert set(found) == {"fastapi", "hl7", "pynetdicom", "pydicom", "hvac"}


# --- the vetting rules: each failure mode proven, not assumed ----------------------------------


def test_a_clean_tree_produces_no_findings_and_a_nonzero_count() -> None:
    findings, examined = vet({"fastapi": "fastapi>=0.100"}, _fetch_all_good, now=_NOW)
    assert findings == []
    assert examined == 1, "a clean sweep must still report what it examined"


def test_a_nonexistent_name_is_caught() -> None:
    """The hallucinated-dependency case: PyPI serves no project under the name."""
    findings, examined = vet(
        {"hl7-fhir-toolkit": "hl7-fhir-toolkit>=1.0"}, lambda _: None, now=_NOW
    )
    assert examined == 1
    assert [f.problem for f in findings] == ["does not exist on PyPI"]


def test_a_registered_but_empty_project_is_caught() -> None:
    """A parked name with no files — the shape a squatter leaves on a predicted name."""
    findings, _ = vet(
        {"messagefoundry-helpers": "messagefoundry-helpers>=1.0"},
        lambda name: _payload(name, first_release=None),
        now=_NOW,
    )
    assert [f.problem for f in findings] == ["no release history"]


def test_a_freshly_registered_distribution_is_caught() -> None:
    """The actual slopsquat: a real, published package registered days ago."""
    findings, _ = vet(
        {"hl7-parse-utils": "hl7-parse-utils>=0.1"},
        lambda name: _payload(name, first_release=_NOW - timedelta(days=9)),
        now=_NOW,
    )
    assert [f.problem for f in findings] == ["freshly registered"]
    assert "9d ago" in findings[0].detail


def test_age_is_measured_from_the_earliest_release_not_the_newest() -> None:
    """A squatter who registers a name then publishes later must not look established.

    Taking the CURRENT version's upload date would call a name registered yesterday "established" the
    moment it cut a second release, and would call a decade-old project "fresh" the day it ships.
    """
    old_name_new_release = {
        "info": {"name": "settled"},
        "releases": {
            "0.1.0": [{"upload_time_iso_8601": (_NOW - timedelta(days=3000)).isoformat()}],
            "9.9.9": [{"upload_time_iso_8601": (_NOW - timedelta(days=1)).isoformat()}],
        },
    }
    findings, _ = vet({"settled": "settled>=1"}, lambda _: old_name_new_release, now=_NOW)
    assert findings == [], "a long-established project that just released must not be flagged"


def test_a_name_served_under_a_different_canonical_name_is_caught() -> None:
    """An alias/redirect landing on another project.

    This is the aliased-name case, NOT the wrong-package case — see the blind-spot test below.
    """
    findings, _ = vet(
        {"some-alias": "some-alias>=3.0.0"},
        lambda name: _payload(
            name, first_release=_NOW - timedelta(days=2000), canonical="other-project"
        ),
        now=_NOW,
    )
    assert [f.problem for f in findings] == ["resolves to a different project"]


def test_documented_blind_spot_a_real_but_wrong_package_passes_every_check() -> None:
    """THE LIMIT OF THIS GATE, pinned so it is known rather than discovered.

    ``pyproject.toml`` warns that "py_webauthn"/"py-webauthn" resolve to AS207960's project while the
    intended distribution is exactly "webauthn". Verified against live PyPI on 2026-07-29:
    ``py-webauthn`` exists, publishes files, is years old, and is served under precisely that canonical
    name. So every check here passes it — it is simply a different maintainer's WebAuthn library.

    A registry cannot answer "is this the package you meant"; that needs intent. The compensating
    controls are human verify-before-add (CLAUDE.md section 5) and the dated vet note beside each
    dependency. This test exists so nobody reads the gate as covering that class, following
    tests/test_gate_liveness.py, which likewise documents its own blindness instead of hiding it.
    """
    findings, examined = vet(
        {"py-webauthn": "py-webauthn>=3.0.0"},
        # Exactly what PyPI really returns for this name: canonical, established, publishing.
        lambda name: _payload(
            name, first_release=_NOW - timedelta(days=2000), canonical="py-webauthn"
        ),
        now=_NOW,
    )
    assert examined == 1
    assert findings == [], (
        "this gate does NOT detect a real-but-wrong package. If a future change makes it do so, that is "
        "a genuine improvement — update this test and the module docstring's limitations section "
        "together, rather than deleting the assertion."
    )


def test_a_malformed_name_never_reaches_the_network() -> None:
    """Validated before it is interpolated into a URL, so no scheme or host can be injected."""

    def exploding_fetch(_: str) -> dict:
        raise AssertionError("fetch must not be called for a malformed name")

    findings, _ = vet({"evil name/../x": "evil name/../x"}, exploding_fetch, now=_NOW)
    assert [f.problem for f in findings] == ["malformed name"]


def test_the_allowlist_skips_a_name_and_does_not_count_it() -> None:
    findings, examined = vet(
        {"brand-new-thing": "brand-new-thing>=0.1"},
        lambda name: _payload(name, first_release=_NOW - timedelta(days=1)),
        now=_NOW,
        allowlist={"brand_new_thing": "reviewed 2026-07-29 — deliberately new, vendor-published"},
    )
    assert findings == []
    assert examined == 0, "an allowlisted name is skipped, and must not inflate the examined count"


def test_findings_are_reported_for_every_bad_name_not_just_the_first() -> None:
    """A gate that stops at the first problem hides the rest of the diff's problems."""
    bad = {"ghost-one": "ghost-one>=1", "ghost-two": "ghost-two>=1", "fastapi": "fastapi>=0.1"}

    def fetch(name: str) -> dict | None:
        return None if name.startswith("ghost") else _fetch_all_good(name)

    findings, examined = vet(bad, fetch, now=_NOW)
    assert examined == 3
    assert sorted(f.distribution for f in findings) == ["ghost-one", "ghost-two"]


# --- fail-closed behaviour ---------------------------------------------------------------------


def test_a_transport_error_propagates_rather_than_reading_as_absent() -> None:
    """A 500 or a timeout must NOT be reported as "the package does not exist".

    Mapping a transport error onto None would turn a PyPI outage into a wall of false
    "hallucinated dependency" failures; swallowing it would turn the gate green while blind. The
    contract is that only a 404 is None and everything else raises.
    """

    def flaky_fetch(_: str) -> dict:
        raise urllib.error.URLError("connection reset")

    with pytest.raises(urllib.error.URLError):
        vet({"fastapi": "fastapi>=0.1"}, flaky_fetch, now=_NOW)


def test_main_exits_2_when_pypi_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail CLOSED at the CLI boundary: unreachable is a failure, never a pass."""
    import scripts.security.new_dependency_check as mod

    def unreachable(_name: str, **_kw: object) -> dict:
        raise urllib.error.URLError("no route to host")

    monkeypatch.setattr(mod, "_http_fetch", unreachable)
    assert main([]) == 2


def test_main_exits_2_when_the_sweep_examines_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ "Zero findings" must never be reachable by "zero dependencies parsed"."""
    import scripts.security.new_dependency_check as mod

    monkeypatch.setattr(mod, "_http_fetch", lambda name, **_kw: _fetch_all_good(name))
    empty = tmp_path / "pyproject.toml"
    empty.write_text('[project]\nname = "x"\n', encoding="utf-8")
    assert main(["--pyproject", str(empty)]) == 2


def test_main_exits_1_on_a_hallucinated_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import scripts.security.new_dependency_check as mod

    monkeypatch.setattr(mod, "_http_fetch", lambda _name, **_kw: None)
    project = tmp_path / "pyproject.toml"
    project.write_text(
        '[project]\nname = "x"\ndependencies = ["totally-invented-pkg>=1"]\n', encoding="utf-8"
    )
    assert main(["--pyproject", str(project)]) == 1


def test_main_exits_0_on_the_real_pyproject_with_a_stubbed_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real file must parse and sweep cleanly — a schema change here is a broken gate."""
    import scripts.security.new_dependency_check as mod

    monkeypatch.setattr(mod, "_http_fetch", lambda name, **_kw: _fetch_all_good(name))
    assert main([]) == 0


# --- the real tree, offline --------------------------------------------------------------------


def test_the_real_pyproject_declares_a_plausible_number_of_distributions() -> None:
    """Liveness against the actual file: if this collapses, the gate is sweeping almost nothing.

    A floor, not an exact count — adding a dependency must not require editing this test, but the
    parser silently losing the optional-dependencies table must.
    """
    declared = declared_distributions((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert len(declared) >= 25, (
        f"only {len(declared)} distributions parsed out of pyproject.toml: {sorted(declared)}. The "
        "[project.optional-dependencies] table carries most of them, so a low count means the parser "
        "stopped seeing the extras."
    )
    # Spot-check one core dep and one extra, so a table being dropped entirely is caught by name.
    assert "fastapi" in declared
    assert "pynetdicom" in declared, "the [dicom] extra is not being read"


def test_every_finding_message_names_the_remedy() -> None:
    """A failure a reader cannot act on gets suppressed rather than fixed."""
    findings, _ = vet(
        {"ghost": "ghost>=1", "fresh": "fresh>=1"},
        lambda name: None if name == "ghost" else _payload(name, first_release=_NOW),
        now=_NOW,
    )
    assert len(findings) == 2
    for finding in findings:
        assert len(finding.detail) > 40, f"{finding.problem} has no actionable detail"


def test_finding_is_hashable_so_callers_can_dedupe() -> None:
    a = Finding("x", "p", "d")
    assert {a, Finding("x", "p", "d")} == {a}


def test_the_payload_helper_shape_matches_what_pypi_returns() -> None:
    """Guards the FIXTURE, not the code.

    If this helper drifts from PyPI's real schema, every test above passes against a shape the gate
    will never see in production — the quietest way for a green suite to mean nothing. `upload_time`
    and `upload_time_iso_8601` are both real PyPI fields; the code reads either.
    """
    payload = json.loads(json.dumps(_payload("fastapi", first_release=_NOW)))
    assert set(payload) == {"info", "releases"}
    assert "name" in payload["info"]
    entry = next(iter(payload["releases"].values()))[0]
    assert "upload_time_iso_8601" in entry
