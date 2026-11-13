# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the new-dependency (anti-slopsquat) gate.

Every test drives the SHIPPED functions from ``scripts/security/new_dependency_check.py`` through an
injected ``fetch``, never a local reimplementation of the rule. A guard whose test asserts its own copy
of the logic is a guard nobody has ever run.

The fetch seam is also what makes these offline and deterministic: the real gate talks to PyPI, and a
unit test that did the same would be a network flake in the required leg.
"""

from __future__ import annotations

import errno
import functools
import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from email.message import Message
from pathlib import Path

import pytest

from scripts.security import new_dependency_check as _gate
from scripts.security.new_dependency_check import (
    Finding,
    RetryBudget,
    _http_fetch,
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


def test_declared_distributions_covers_pep735_dependency_groups() -> None:
    """The CI toolchain (ADR 0034 §3) is declared in `[dependency-groups]`, not in an extra.

    Those names are resolved into `uv.lock` and installed into the runner that executes the BLOCKING
    security gates, so a squatted scanner name lands with the job's token in hand. A gate that cannot
    see the table cannot vet it, and would report a clean sweep while ignoring it entirely.
    """
    found = declared_distributions(
        """
        [project]
        dependencies = ["fastapi>=0.100"]

        [dependency-groups]
        ci-scanners = ["bandit==1.9.4", "zizmor==1.5.2"]
        ci-quality = ["mutmut==3.6.0", "pytest-cov>=7.0"]
        """
    )
    assert set(found) == {"fastapi", "bandit", "zizmor", "mutmut", "pytest-cov"}


def test_an_include_group_table_is_skipped_not_crashed_on() -> None:
    """PEP 735 lets a group entry be `{include-group = "other"}` instead of a requirement string.

    That table names another GROUP, not a distribution, so there is nothing to vet — and handing the
    dict to `requirement_name()` would raise, taking the whole gate down with it. The included group's
    own members are still swept, because every group is iterated regardless of who includes it.
    """
    found = declared_distributions(
        """
        [project]
        dependencies = []

        [dependency-groups]
        base = ["bandit==1.9.4"]
        everything = [{ include-group = "base" }, "zizmor==1.5.2"]
        """
    )
    assert set(found) == {"bandit", "zizmor"}


def test_a_bogus_name_declared_in_a_dependency_group_is_rejected() -> None:
    """End-to-end: a hallucinated name in a GROUP must fail vetting exactly like one in an extra.

    Drives the real `declared_distributions` -> `vet` path rather than asserting the parser alone, so
    "the table is parsed" and "the table is enforced" are two different claims and both are proven.
    """
    declared = declared_distributions(
        """
        [project]
        dependencies = ["fastapi>=0.100"]

        [dependency-groups]
        ci-scanners = ["bandit==1.9.4", "hl7-sast-scanner==2.0"]
        """
    )
    assert "hl7-sast-scanner" in declared, "the group name never reached the vetting stage"
    findings, examined = vet(
        declared,
        lambda name: None if name == "hl7-sast-scanner" else _fetch_all_good(name),
        now=_NOW,
    )
    assert examined == 3
    assert [(f.distribution, f.problem) for f in findings] == [
        ("hl7-sast-scanner", "does not exist on PyPI")
    ]


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


# --- transient retry (BACKLOG #3089): the link is retried, the answer never is ------------------
#
# These drive the SHIPPED _http_fetch -> _fetch_once path with only urllib.request.urlopen replaced, so
# the 404 mapping and the transient classification under test are the real ones. Sleeps are recorded,
# never slept.


class _ReadFails:
    """An outcome that connects, then raises ``exc`` from ``response.read()``."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc


class _FakeResponse:
    def __init__(self, body: bytes | _ReadFails) -> None:
        self._body = body

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        if isinstance(self._body, _ReadFails):
            raise self._body.exc
        return self._body


def _script_urlopen(
    monkeypatch: pytest.MonkeyPatch, outcomes: list[BaseException | bytes | _ReadFails]
) -> list[str]:
    """Replace urlopen with one that plays ``outcomes`` in order (the last repeats). Returns the URLs
    it was called with, so a test counts attempts by what reached the wire."""
    calls: list[str] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> _FakeResponse:
        calls.append(request.full_url)
        outcome = outcomes[min(len(calls), len(outcomes)) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return _FakeResponse(outcome)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return calls


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://pypi.org/pypi/x/json", code, "x", Message(), None)


_GOOD_BODY = json.dumps(_fetch_all_good("fastapi")).encode()


def _handshake_timeout() -> urllib.error.URLError:
    """The exact shape the 2026-10-20 merge-group evictions logged. A fresh instance per use: one
    shared exception re-raised across tests would accumulate every raise's frames on its traceback."""
    return urllib.error.URLError(TimeoutError("_ssl.c:1064: The handshake operation timed out"))


def _budget(remaining: int = 6) -> RetryBudget:
    return RetryBudget(remaining=remaining)


@pytest.mark.parametrize(
    "transient",
    [
        _handshake_timeout(),
        TimeoutError("timed out"),
        ConnectionResetError(104, "Connection reset by peer"),
        urllib.error.URLError(ConnectionRefusedError(111, "Connection refused")),
        urllib.error.URLError(OSError(errno.ENETUNREACH, "Network is unreachable")),
        urllib.error.URLError(socket.gaierror(socket.EAI_AGAIN, "Temporary failure")),
        urllib.error.URLError(OSError(errno.ENOTCONN, "Transport endpoint is not connected")),
        _ReadFails(http.client.IncompleteRead(b"{", 100)),
        _ReadFails(TimeoutError("The read operation timed out")),
        _http_error(429),
        _http_error(503),
    ],
    ids=[
        "tls-handshake-timeout",
        "read-timeout",
        "reset",
        "refused",
        "net-unreachable",
        "dns-eai-again",
        "not-connected",
        "incomplete-read-on-body",
        "timeout-on-body",
        "http-429",
        "http-503",
    ],
)
def test_a_transient_failure_is_retried_then_succeeds(
    monkeypatch: pytest.MonkeyPatch, transient: BaseException | _ReadFails
) -> None:
    calls = _script_urlopen(monkeypatch, [transient, _GOOD_BODY])
    sleeps: list[float] = []
    budget = _budget()

    payload = _http_fetch("fastapi", budget=budget, sleep=sleeps.append)

    assert payload is not None and payload["info"]["name"] == "fastapi"
    assert len(calls) == 2, "a transient failure must be tried again, exactly once here"
    assert len(sleeps) == 1 and 1.0 <= sleeps[0] < 1.5, f"backoff out of range: {sleeps}"
    assert budget.remaining == 5


def test_a_persistent_timeout_fails_after_the_attempts_are_spent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FAIL CLOSED: retries delay the failure, they never replace it with a payload."""
    calls = _script_urlopen(monkeypatch, [_handshake_timeout()])
    sleeps: list[float] = []

    with pytest.raises(urllib.error.URLError):
        _http_fetch("fastapi", budget=_budget(), sleep=sleeps.append)

    assert len(calls) == 3
    assert len(sleeps) == 2 and sleeps[0] < sleeps[1], f"backoff must grow: {sleeps}"


def test_a_404_is_not_retried_and_still_means_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _script_urlopen(monkeypatch, [_http_error(404)])
    sleeps: list[float] = []

    assert _http_fetch("ghost-pkg", budget=_budget(), sleep=sleeps.append) is None
    assert len(calls) == 1 and sleeps == [], "a 404 is a definitive answer and must not be retried"


@pytest.mark.parametrize(
    "definitive",
    [
        _http_error(403),
        _http_error(400),
        b"<html>not json</html>",
        b"[]",
        b"\xff\xfe not utf-8",
        urllib.error.URLError(ssl.SSLCertVerificationError("certificate verify failed")),
        urllib.error.URLError(ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")),
        urllib.error.URLError(ssl.SSLEOFError(8, "EOF occurred in violation of protocol")),
        urllib.error.URLError(OSError("Tunnel connection failed: 403 Forbidden")),
        urllib.error.URLError(socket.gaierror(socket.EAI_NONAME, "Name or service not known")),
        urllib.error.URLError("unknown url type: ftp"),
    ],
    ids=[
        "http-403",
        "http-400",
        "malformed-json",
        "json-not-an-object",
        "not-utf-8",
        "cert-verify-failed",
        "tls-wrong-version",
        "tls-eof",
        "proxy-tunnel-403",
        "dns-no-such-name",
        "urlerror-with-text-reason",
    ],
)
def test_a_definitive_failure_is_raised_at_once(
    monkeypatch: pytest.MonkeyPatch, definitive: BaseException | bytes
) -> None:
    calls = _script_urlopen(monkeypatch, [definitive, _GOOD_BODY])
    sleeps: list[float] = []

    with pytest.raises((urllib.error.URLError, ValueError)):
        _http_fetch("fastapi", budget=_budget(), sleep=sleeps.append)

    assert len(calls) == 1 and sleeps == [], "a definitive answer must never be retried into a pass"


def test_the_run_budget_caps_retries_across_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    """A PyPI that is flaky on EVERY name must fail closed in minutes, not after 56 x 3 attempts."""
    calls = _script_urlopen(monkeypatch, [_handshake_timeout()])
    budget = _budget(remaining=1)

    with pytest.raises(urllib.error.URLError):
        _http_fetch("first", budget=budget, sleep=lambda _s: None)
    assert len(calls) == 2 and budget.remaining == 0

    with pytest.raises(urllib.error.URLError):
        _http_fetch("second", budget=budget, sleep=lambda _s: None)
    assert len(calls) == 3, "an exhausted budget must not retry"


def test_no_retry_starts_once_the_run_window_has_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """The time bound, not just the count: a closed window fails the first transient error at once."""
    calls = _script_urlopen(monkeypatch, [_handshake_timeout(), _GOOD_BODY])
    budget = RetryBudget(remaining=6, window_ends=time.monotonic() - 1.0)

    with pytest.raises(urllib.error.URLError):
        _http_fetch("fastapi", budget=budget, sleep=lambda _s: None)
    assert len(calls) == 1 and budget.remaining == 6


def test_the_budget_defaults_are_read_when_it_is_made(monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.security.new_dependency_check as mod

    monkeypatch.setattr(mod, "_RUN_RETRY_BUDGET", 2)
    monkeypatch.setattr(mod, "_RETRY_WINDOW_S", 50.0)
    before = time.monotonic()
    budget = RetryBudget()
    assert budget.remaining == 2
    assert before + 50.0 <= budget.window_ends <= time.monotonic() + 50.0


def _zero_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    import scripts.security.new_dependency_check as mod

    monkeypatch.setattr(mod, "_BACKOFF_BASE_S", 0.0)
    monkeypatch.setattr(mod, "_BACKOFF_JITTER_S", 0.0)


def test_main_exits_2_after_retrying_a_persistent_handshake_timeout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI end of the contract: exit 2 (unreachable), each retry logged with attempt and host."""
    _zero_backoff(monkeypatch)
    calls = _script_urlopen(monkeypatch, [_handshake_timeout()])

    assert main([]) == 2
    assert len(calls) == 3, "the sweep must stop at the first request whose retries are spent"
    err = capsys.readouterr().err
    assert "attempt 1 of 3 (URLError(TimeoutError))" in err
    hosts = re.findall(
        r"^::warning::PyPI request for '[^']+' to (\S+) failed transiently ", err, re.M
    )
    assert hosts == ["pypi.org", "pypi.org"], f"one warning per retry, naming the host: {hosts}"
    assert "attempt 2 of 3" in err
    assert {urllib.parse.urlsplit(url).hostname for url in calls} == {"pypi.org"}
    assert "could not reach PyPI" in err


@pytest.mark.parametrize(
    "outcome",
    [_ReadFails(http.client.IncompleteRead(b"{", 100)), b"\xff\xfe not utf-8", b"[]"],
    ids=["incomplete-read", "not-utf-8", "json-not-an-object"],
)
def test_main_exits_2_not_1_when_the_body_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: bytes | _ReadFails,
) -> None:
    """Exit 1 means "a dependency failed vetting"; an unreadable reply is "could not see" -- exit 2.

    And the reply itself stays out of the CI log: a UnicodeDecodeError's repr carries the whole body.
    """
    _zero_backoff(monkeypatch)
    _script_urlopen(monkeypatch, [outcome])

    assert main([]) == 2
    assert "not utf-8" not in capsys.readouterr().err, "the response body leaked into the log"


def _fail_once_then_good(name: str, *, timeout: float, seen: set[str]) -> dict:
    if name not in seen:
        seen.add(name)
        raise _handshake_timeout()
    return _fetch_all_good(name)


def test_main_passes_when_a_transient_timeout_clears(monkeypatch: pytest.MonkeyPatch) -> None:
    """One handshake timeout mid-sweep -- the 2026-10-20 eviction -- now clears instead of exiting 2.

    Patches _fetch_once rather than urlopen because each name needs its own canonical payload. Every
    name but fastapi is pre-marked as seen, so exactly one request fails once."""
    import scripts.security.new_dependency_check as mod

    _zero_backoff(monkeypatch)
    seen = set(declared_distributions((_ROOT / "pyproject.toml").read_text(encoding="utf-8")))
    seen.discard("fastapi")
    monkeypatch.setattr(mod, "_fetch_once", functools.partial(_fail_once_then_good, seen=seen))

    assert main([]) == 0
    assert "fastapi" in seen, "the one transient failure never happened"


def test_main_shares_one_budget_across_every_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three names each failing once need three retries; a run budget of two must fail closed.

    A budget made per request (a partial or lambda that builds a RetryBudget per call) would pass
    this run.
    """
    import scripts.security.new_dependency_check as mod

    _zero_backoff(monkeypatch)
    monkeypatch.setattr(mod, "_RUN_RETRY_BUDGET", 2)
    monkeypatch.setattr(mod, "_fetch_once", functools.partial(_fail_once_then_good, seen=set()))
    project = tmp_path / "pyproject.toml"
    project.write_text(
        '[project]\nname = "x"\ndependencies = ["alpha>=1", "bravo>=1", "charlie>=1"]\n',
        encoding="utf-8",
    )

    assert main(["--pyproject", str(project)]) == 2


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
    assert "bandit" in declared, "the [dependency-groups] CI toolchain is not being read"
    assert "hatchling" in declared, "the [build-system].requires backend is not being read"


def test_the_ci_toolchain_groups_actually_raise_the_examined_count() -> None:
    """The count must MOVE, not merely be plausible — a parser that silently reads nothing new passes
    every floor above.

    Measured on this branch: 42 distributions before `[dependency-groups]` was swept, 51 after. Six of
    the nine added names are the CI toolchain (`bandit`, `pip-audit`, `zizmor`, `diff-cover`,
    `mutmut`, `pytest-cov`). The other three — `sigstore`, `build` and `cyclonedx-bom` — are the
    RELEASE toolchain that BACKLOG #332 routes through `uv.lock`: a different group doing a different
    job, listed here because this test asserts what the SWEEP finds, not what any one group holds.
    `pytest-timeout` is declared in BOTH the `dev` extra and `ci-quality` and so adds nothing, which is
    itself deliberate — the identical spec in both places is what stops uv resolving two versions.

    **The 41/47 this docstring carried was ALREADY STALE before #332 touched it** — `main` measures
    42/48 today, so the prose had drifted from the assertion beside it while the test still passed.
    Re-pointing the SET is what the failure message asks for; the counts are prose, and prose that
    disagrees with the assertion next to it is how a reader learns to trust neither. Both are now
    measured rather than remembered.

    Asserted as a SET DELTA rather than a magic total, so adding an ordinary dependency tomorrow does
    not red this, but the group table falling out of the parser does.
    """
    from scripts.security.new_dependency_check import declared_distributions as parse

    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    with_groups = set(parse(text))

    # The same file with [dependency-groups] renamed to an inert table = the pre-change behaviour.
    without = set(parse(text.replace("\n[dependency-groups]\n", "\n[inert-not-a-real-table]\n", 1)))

    added = with_groups - without
    print(f"examined: {len(without)} -> {len(with_groups)} (+{len(added)}): {sorted(added)}")
    assert added == {
        "bandit",
        "pip-audit",
        "zizmor",
        "diff-cover",
        "mutmut",
        "pytest-cov",
        "sigstore",
        "build",
        "cyclonedx-bom",
    }, (
        f"the [dependency-groups] sweep added {sorted(added)}; expected the six CI toolchain names "
        "plus the three release-toolchain ones (sigstore, build, cyclonedx-bom). If a tool was "
        "deliberately added or removed, re-point this set in the same commit."
    )
    assert "pytest-timeout" in without, (
        "pytest-timeout must remain declared in the [dev] extra too — the ci-quality group deliberately "
        "repeats its exact spec so uv cannot resolve two different versions"
    )


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


# --- BACKLOG #5641: every declaration surface is read, and nothing is skipped in silence ----------
#
# These reach the names #5641 added through the module object (`_gate`) rather than the import block,
# so against the pre-#5641 code each one fails on its own instead of the whole file failing to collect.


def _stub_registry(
    monkeypatch: pytest.MonkeyPatch, *, absent: frozenset[str] = frozenset()
) -> list[str]:
    """Replace the network with a registry that knows every name but ``absent``. Returns the asks."""
    asked: list[str] = []

    def fetch(name: str, **_kw: object) -> dict | None:
        asked.append(name)
        return None if name in absent else _fetch_all_good(name)

    monkeypatch.setattr(_gate, "_http_fetch", fetch)
    return asked


def test_case_and_separator_variants_are_one_distribution() -> None:
    """S28-84: keyed by the PEP 503 name, so 'PyYAML' and 'pyyaml' are one fetch and one count."""
    declared = declared_distributions(
        """
        [project]
        dependencies = ["PyYAML>=6", "foo_bar>=1"]

        [project.optional-dependencies]
        dev = ["pyyaml>=6.0.3", "Foo.Bar>=1"]
        """
    )
    assert set(declared) == {"pyyaml", "foo-bar"}
    assert declared["pyyaml"] == "PyYAML>=6", "the first spelling's spec is the one kept"
    asked: list[str] = []

    def fetch(name: str) -> dict:
        asked.append(name)
        return _fetch_all_good(name)

    _, examined = vet(declared, fetch, now=_NOW)
    assert examined == 2
    assert sorted(asked) == ["foo-bar", "pyyaml"]


@pytest.mark.parametrize(
    "spec",
    [
        "",
        "   ",
        "# a comment, not a requirement",
        "./vendor/thing-1.0-py3-none-any.whl",
        "https://example.invalid/thing-1.0.tar.gz",
        "thing:1.0",
    ],
    ids=["empty", "blank", "comment", "local-path", "bare-url", "colon"],
)
def test_an_unnameable_string_is_a_finding_not_a_silent_skip(spec: str) -> None:
    """S28-08: a declared entry the gate cannot name used to vanish, so it entered unvetted."""
    text = f'[project]\ndependencies = ["fastapi>=0.100", {json.dumps(spec)}]\n'
    assert set(declared_distributions(text)) == {"fastapi"}
    findings = _gate.unnameable_entries(text)
    assert [f.problem for f in findings] == ["unnameable entry"]
    assert "[project].dependencies" in findings[0].distribution


def test_a_bare_url_is_not_vetted_as_the_name_https() -> None:
    """The name grammar must end at a PEP 508 boundary, or 'https://...' is vetted as 'https'."""
    assert requirement_name("https://example.invalid/x.whl") is None
    assert requirement_name("thing @ https://example.invalid/x.whl") == "thing"
    assert requirement_name("thing(>=1)") == "thing"


@pytest.mark.parametrize(
    "toml_text",
    [
        "[project]\ndependencies = [42]\n",
        "[project]\ndependencies = [{ name = 'fastapi' }]\n",
        "[dependency-groups]\nci = [{ include-group = 'base', extra = 1 }]\nbase = []\n",
        "[dependency-groups]\nci = [{ not-include-group = 'base' }]\n",
        "[build-system]\nrequires = [true]\n",
    ],
    ids=[
        "integer",
        "table-in-dependencies",
        "include-group-with-extra-key",
        "other-table-in-group",
        "boolean-in-build-requires",
    ],
)
def test_a_non_string_entry_is_a_finding(toml_text: str) -> None:
    findings = _gate.unnameable_entries(toml_text)
    assert [f.problem for f in findings] == ["unnameable entry"], findings


@pytest.mark.parametrize(
    "toml_text",
    [
        "[project]\ndependencies = 'fastapi'\n",
        "[project]\noptional-dependencies = ['fastapi']\n",
        "[project.optional-dependencies]\ndev = 'pytest'\n",
        "[dependency-groups]\nci = 'bandit'\n",
        "[build-system]\nrequires = 'hatchling'\n",
        "[tool.uv]\nconstraint-dependencies = 'x'\n",
    ],
    ids=["dependencies", "optional-dependencies", "an-extra", "a-group", "build-requires", "uv"],
)
def test_a_table_of_the_wrong_toml_type_is_a_finding_not_iterated(toml_text: str) -> None:
    """``dependencies = 'fastapi'`` used to be iterated character by character, vetting 'f', 'a'."""
    assert declared_distributions(toml_text) == {}
    findings = _gate.unnameable_entries(toml_text)
    assert len(findings) == 1, findings
    assert findings[0].problem in {"not a list", "not a table"}, findings


def test_the_include_group_table_is_still_skipped_without_a_finding() -> None:
    text = '[dependency-groups]\nbase = ["bandit==1.9.4"]\nall = [{ include-group = "base" }]\n'
    assert _gate.unnameable_entries(text) == []


def test_build_system_requires_is_swept() -> None:
    """S28-09: a build backend runs in release.yml's build jobs, which hold `id-token: write`."""
    declared = declared_distributions(
        '[build-system]\nrequires = ["hatchling==1.33.0", "hatch-vcs-hallucinated>=1"]\n'
    )
    assert set(declared) == {"hatchling", "hatch-vcs-hallucinated"}


def test_the_uv_dependency_tables_are_swept() -> None:
    """S28-09: uv resolves and installs these. None is used in this tree today, so it is synthetic."""
    declared = declared_distributions(
        """
        [tool.uv]
        dev-dependencies = ["devdep>=1"]
        constraint-dependencies = ["constrained<2"]
        override-dependencies = ["overridden==1.0"]
        build-constraint-dependencies = ["buildconstrained<3"]

        [tool.uv.extra-build-dependencies]
        some-sdist = ["extrabuild>=1", { requirement = "matched", match-runtime = true }]
        """
    )
    assert set(declared) == {
        "devdep",
        "constrained",
        "overridden",
        "buildconstrained",
        "extrabuild",
        "matched",
    }


def test_main_sweeps_the_packaging_pyprojects_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S28-09: a name declared only in packaging/*/pyproject.toml must be fetched and refused."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["fastapi>=0.100"]\n', encoding="utf-8"
    )
    sub = tmp_path / "packaging" / "messagefoundry-thing"
    sub.mkdir(parents=True)
    (sub / "pyproject.toml").write_text(
        '[project]\nname = "messagefoundry-thing"\ndependencies = ["invented-helper>=1"]\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(_gate, "_ROOT", tmp_path)
    asked = _stub_registry(monkeypatch, absent=frozenset({"invented-helper"}))

    assert main([]) == 1
    assert sorted(asked) == ["fastapi", "invented-helper"]


def test_main_refuses_when_the_packaging_tree_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default sweep reading no packaging file is the tree moving under the gate, not clean."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["fastapi>=0.100"]\n', encoding="utf-8"
    )
    monkeypatch.setattr(_gate, "_ROOT", tmp_path)
    _stub_registry(monkeypatch)
    assert main([]) == 2


def test_main_exits_1_on_an_unnameable_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text(
        '[project]\nname = "x"\ndependencies = ["fastapi>=0.100", "./vendor/x.whl"]\n',
        encoding="utf-8",
    )
    _stub_registry(monkeypatch)
    assert main(["--pyproject", str(project)]) == 1
    assert "unnameable entry" in capsys.readouterr().err


def test_first_party_names_are_excluded_with_a_reason_and_not_counted() -> None:
    """This repository's own distributions are ours: existence and age say nothing about them."""
    first_party = _gate.FIRST_PARTY
    assert {normalize(n) for n in first_party} >= {
        "messagefoundry",
        "messagefoundry-toolkit",
        "messagefoundry-webconsole",
        "messagefoundry-harness",
    }
    assert all(len(reason) > 40 for reason in first_party.values())

    def exploding(name: str) -> dict:
        raise AssertionError(f"first-party {name!r} must not reach the registry")

    findings, examined = vet(
        declared_distributions('[project]\ndependencies = ["messagefoundry_toolkit==0.5.2"]\n'),
        exploding,
        now=_NOW,
    )
    assert (findings, examined) == ([], 0)


def test_a_near_miss_of_a_first_party_name_is_still_vetted() -> None:
    """The exclusion is by exact PEP 503 name, so a typo of our own name is fetched like any other."""
    findings, examined = vet(
        declared_distributions('[project]\ndependencies = ["messagefoundry-tolkit==0.5.2"]\n'),
        lambda _: None,
        now=_NOW,
    )
    assert examined == 1
    assert [f.problem for f in findings] == ["does not exist on PyPI"]


def test_the_real_tree_default_sweep_reads_every_packaging_pyproject() -> None:
    """Liveness against the real tree: the default file list names every packaging pyproject."""
    files = _gate.default_pyprojects(_ROOT)
    assert files[0] == _ROOT / "pyproject.toml"
    assert set(files[1:]) == set((_ROOT / "packaging").glob("*/pyproject.toml"))
    assert len(files) >= 4, f"expected the root plus three packaging pyprojects, got {files}"


def test_the_real_pyprojects_declare_nothing_unnameable() -> None:
    for path in _gate.default_pyprojects(_ROOT):
        text = path.read_text(encoding="utf-8")
        assert _gate.unnameable_entries(text, source=str(path)) == []


def test_documented_blind_spot_npm_manifests_are_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A STATED BOUNDARY, pinned. This gate vets PyPI names only. A package.json -- ide/package.json
    and ci/npm-tools/package.json in this tree -- is never opened, so an invented npm name passes
    here. `npm audit` answers known advisories, the npm counterpart of pip-audit, and so shares its
    blindness to a freshly registered name. If a future change reads npm manifests, update this test
    and the module docstring together rather than deleting the assertion.
    """
    project = tmp_path / "pyproject.toml"
    project.write_text(
        '[project]\nname = "x"\ndependencies = ["fastapi>=0.100"]\n', encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"invented-npm-helper": "^1.0.0"}}), encoding="utf-8"
    )
    asked = _stub_registry(monkeypatch, absent=frozenset({"invented-npm-helper"}))
    assert main(["--pyproject", str(project)]) == 0
    assert asked == ["fastapi"]
