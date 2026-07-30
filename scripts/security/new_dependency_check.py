#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Verify every dependency this project declares is a REAL, established distribution.

THE GAP THIS CLOSES. ``pip-audit`` answers "does this pinned version have a known CVE". It cannot
answer "is this package the one I meant, or a name a model invented". A freshly registered
hallucinated name has no advisory, so it audits clean, resolves through ``uv lock``, hashes into
``requirements.lock`` and installs under ``--require-hashes`` — every DEP-1 control passes it. The only
thing standing in the way today is that ``uv lock`` cannot resolve a name PyPI does not serve, which is
a resolver side effect rather than a control, and is exactly the case slopsquatting is built to defeat.

WHY IT MATTERS HERE SPECIFICALLY. This project's dependencies are chosen by an AI. Spracklen et al.
(USENIX Security 2025) measured 19.7% hallucinated package references across 2.23M suggestions, with
58% of invented names recurring across runs — i.e. predictable, therefore registrable. A 2026
frontier-model replication found the rate compressed to ~4.6-6.1% but identified 127 names that five
independent models invent IDENTICALLY. ``docs/Secure_AI_Development_Standards.md`` already names this
the "highest-priority deferred gate" and records that verify-before-add "is today enforced only by the
human remembering". CLAUDE.md section 5 states the rule in prose, and prose is what a session
rationalizes past at 2am.

WHAT IT SWEEPS: ``[project].dependencies``, every ``[project.optional-dependencies]`` extra, and every
PEP 735 ``[dependency-groups]`` group. The last was added 2026-07-29 with the hash-pinned CI toolchain
(ADR 0034 section 3): those names are not shipped in the wheel, but they are resolved into ``uv.lock``
and installed into the runner that executes the BLOCKING security gates, which makes a squatted scanner
name a sharper target than a runtime dependency rather than a softer one.

WHAT IT CHECKS, per declared distribution:
  * EXISTS         -- PyPI serves a project page for the name at all.
  * HAS RELEASES   -- at least one release with files. A registered-but-empty placeholder is the shape
                      a squatter parks on a predicted name.
  * ESTABLISHED    -- its FIRST release is older than ``--min-age-days``. Every real dependency here is
                      years old, so this is quiet in practice and fires precisely on a name registered
                      to catch a hallucination.
  * CANONICAL      -- the name PyPI considers canonical normalizes to the declared name, so a spec
                      that is being served under some OTHER project's canonical name (an alias or a
                      redirect) is flagged rather than silently accepted.

WHAT THIS CANNOT CATCH -- stated plainly, because a supply-chain control that overstates its reach is
worse than a modest one. This gate answers "is this name a real, established, self-consistent
distribution". It cannot answer "is it the one you MEANT". The live counter-example is in this very
tree: ``pyproject.toml`` warns that "py_webauthn"/"py-webauthn" resolve to AS207960's project while the
intended distribution is exactly "webauthn". Verified 2026-07-29 -- ``py-webauthn`` exists, publishes,
is years old, and PyPI serves it under precisely that canonical name, so EVERY check above passes it.
It is simply a different maintainer's WebAuthn library.

So the taxonomy is: this gate covers the invented name, the parked name, the freshly registered name
and the aliased name. The plausible-but-wrong name -- a real package that is not your intended one --
is covered only by human verify-before-add (CLAUDE.md section 5) plus the dated vet note beside each
dependency in ``pyproject.toml``. ``tests/test_new_dependency_check.py`` pins that blind spot with a
named test rather than leaving it to be discovered, following the precedent in
``tests/test_gate_liveness.py``, which documents its own reconciliation sum's blindness instead of
hiding it.

FAIL-CLOSED. A network error, a rate limit or an unparsable response is a FAILURE, never a pass. A
supply-chain gate that degrades to green when it cannot see is the failure mode this repo has already
catalogued three times (docs/CI.md, "Gate liveness"): a check that reports success while measuring
nothing. For the same reason the summary prints the number of distributions actually EXAMINED, and
exits non-zero if that number is zero.

USAGE
    python scripts/security/new_dependency_check.py                 # sweep pyproject.toml
    python scripts/security/new_dependency_check.py --min-age-days 180
    python scripts/security/new_dependency_check.py --pyproject path/to/pyproject.toml
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]

# A distribution registered less recently than this is treated as established. 90 days is chosen
# against the attack, not arbitrarily: slopsquatting requires the attacker to register a PREDICTED
# name and wait for a victim, so the window between registration and first use is what this closes. It
# is also comfortably below the age of every dependency in this tree, so it costs nothing today.
DEFAULT_MIN_AGE_DAYS = 90

_PYPI_JSON = "https://pypi.org/pypi/{name}/json"

# PEP 508 name grammar. Anything outside this never reaches a URL.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$")

# Reviewed exceptions: distribution -> reason. Deliberately a code constant rather than a file, so
# adding one shows up in a diff with its justification attached.
ALLOWLIST: dict[str, str] = {}


def normalize(name: str) -> str:
    """PEP 503 normalization -- the identity PyPI actually compares names under."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(spec: str) -> str | None:
    """The distribution name from a PEP 508 requirement string, or None if there isn't one.

    ``"pynetdicom>=3.0.4,<4"`` -> ``pynetdicom``; ``"fhir.resources>=7.1.0"`` -> ``fhir.resources``.
    Extras and environment markers are stripped: only the name is being vetted.
    """
    text = spec.strip()
    if not text or text.startswith("#"):
        return None
    text = text.split(";", 1)[0]  # environment marker
    text = text.split("[", 1)[0]  # extras
    match = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", text)
    return match.group(0) if match else None


def declared_distributions(pyproject_text: str) -> dict[str, str]:
    """Every distribution this project declares -> the spec it was declared with.

    Covers THREE tables, because a name this gate does not read is a name that enters the tree unvetted:

    * ``[project].dependencies`` -- the runtime closure.
    * every ``[project.optional-dependencies]`` extra -- exactly where a niche, plausible-sounding,
      hallucination-prone name lands.
    * every PEP 735 ``[dependency-groups]`` group -- the CI toolchain (ADR 0034 section 3). These are
      not published wheel metadata, but they ARE resolved into ``uv.lock``, hash-exported to
      ``ci/locks/*.lock``, and installed into the runner that executes the blocking security gates. A
      slopsquatted scanner name is if anything a SHARPER target than a runtime dependency: it runs with
      the job's token before any of these controls report.
    """
    data = tomllib.loads(pyproject_text)
    project = data.get("project") or {}
    specs: list[str] = list(project.get("dependencies") or [])
    for extra_specs in (project.get("optional-dependencies") or {}).values():
        specs.extend(extra_specs or [])
    for group_specs in (data.get("dependency-groups") or {}).values():
        # A PEP 735 entry is EITHER a requirement string OR a `{include-group = "other"}` table. The
        # table names another group in this same file, not a distribution, so it has nothing to vet --
        # and passing the dict to requirement_name() would raise. Include-groups are covered anyway:
        # every group is iterated here regardless of who includes it.
        specs.extend(spec for spec in (group_specs or []) if isinstance(spec, str))

    found: dict[str, str] = {}
    for spec in specs:
        name = requirement_name(spec)
        if name is not None:
            found.setdefault(name, spec)
    return found


@dataclass(frozen=True)
class Finding:
    distribution: str
    problem: str
    detail: str


PyPIFetch = Callable[[str], dict | None]
"""Fetch the PyPI JSON payload for a name. Returns None for "no such project" (404).

Anything else -- a timeout, a 5xx, a rate limit, malformed JSON -- must RAISE. Returning None on a
transport error would turn every dependency into a "does not exist" failure, and swallowing it would
turn the gate green while blind; neither is acceptable, so the contract is explicit.
"""


def _first_release_date(payload: dict) -> datetime | None:
    """The earliest upload time across all releases, or None if no release has files.

    Earliest across ALL releases, not the current version's: a squatter who registers a name and later
    publishes a version would otherwise look established, and a legitimate project's newest release
    says nothing about how long the NAME has existed.
    """
    earliest: datetime | None = None
    for files in (payload.get("releases") or {}).values():
        for file_info in files or []:
            raw = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
            if not raw:
                continue
            try:
                # fromisoformat parses a trailing "Z" natively on 3.11+, so no pre-substitution is
                # needed; the project floor is 3.14. PyPI serves both `upload_time_iso_8601`
                # (Z-suffixed, UTC) and the naive `upload_time`, which is why tzinfo is normalized
                # below rather than assumed.
                stamp = datetime.fromisoformat(raw)
            except ValueError:
                continue
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=UTC)
            if earliest is None or stamp < earliest:
                earliest = stamp
    return earliest


def vet(
    declared: dict[str, str],
    fetch: PyPIFetch,
    *,
    now: datetime,
    min_age_days: int = DEFAULT_MIN_AGE_DAYS,
    allowlist: dict[str, str] | None = None,
) -> tuple[list[Finding], int]:
    """Vet every declared distribution. Returns (findings, number examined).

    The count is returned rather than inferred so the caller can prove the sweep was not empty --
    "zero findings" and "nothing was checked" are indistinguishable from the exit code alone.
    """
    allowed = allowlist if allowlist is not None else ALLOWLIST
    findings: list[Finding] = []
    examined = 0

    for name in sorted(declared, key=normalize):
        if normalize(name) in {normalize(k) for k in allowed}:
            continue
        examined += 1

        if not _SAFE_NAME.match(name):
            findings.append(
                Finding(
                    name, "malformed name", f"{name!r} is not a valid PEP 508 distribution name"
                )
            )
            continue

        payload = fetch(name)
        if payload is None:
            findings.append(
                Finding(
                    name,
                    "does not exist on PyPI",
                    "no project is published under this name. This is the signature of a hallucinated "
                    "or mistyped dependency -- verify the INTENDED name before changing anything.",
                )
            )
            continue

        info = payload.get("info") or {}
        canonical = str(info.get("name") or "")
        if canonical and normalize(canonical) != normalize(name):
            findings.append(
                Finding(
                    name,
                    "resolves to a different project",
                    f"PyPI serves this name under the canonical name {canonical!r}. An alias or "
                    "redirect landing on another project is worth a deliberate look -- confirm which "
                    "distribution you actually meant. (Note this does NOT catch a real package that "
                    "is simply the wrong one: see the module docstring's limitations.)",
                )
            )
            continue

        first = _first_release_date(payload)
        if first is None:
            findings.append(
                Finding(
                    name,
                    "no release history",
                    "the name is registered but publishes no files. A registered-but-empty project is "
                    "what a squatter parks on a predicted name.",
                )
            )
            continue

        age_days = (now - first).days
        if age_days < min_age_days:
            findings.append(
                Finding(
                    name,
                    "freshly registered",
                    f"first release {first.date().isoformat()} ({age_days}d ago) is younger than the "
                    f"{min_age_days}d floor. A brand-new distribution appearing as a dependency is the "
                    "slopsquat shape; if it is genuinely new and genuinely intended, add it to "
                    "ALLOWLIST with a reason.",
                )
            )

    return findings, examined


def _http_fetch(name: str, *, timeout: float = 20.0) -> dict | None:
    """Fetch PyPI's JSON for ``name``. None means 404; every other error raises (fail-closed)."""
    url = _PYPI_JSON.format(name=urllib.parse.quote(name, safe=""))
    # bandit owns this one. Older urllib call sites here carry a ruff `S310` suppression alongside the
    # nosec, but flake8-bandit's `S` family is not in pyproject's ruff extend-select, so that half is
    # inert -- and ruff's own RUF100 strips it on sight. Only the nosec is load-bearing.
    #
    # Why it is safe: the scheme is the module-level https://pypi.org literal and the only interpolated
    # part is a percent-encoded path segment whose value already passed _SAFE_NAME above. B310's
    # non-http(s)-scheme concern therefore cannot arise -- no scheme, host, or path traversal is
    # reachable from a dependency name.
    request = urllib.request.Request(  # nosec B310 — fixed https://pypi.org literal
        url,
        headers={"Accept": "application/json", "User-Agent": "messagefoundry-dep-vet"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pyproject", type=Path, default=_ROOT / "pyproject.toml")
    parser.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS)
    args = parser.parse_args(argv)

    declared = declared_distributions(args.pyproject.read_text(encoding="utf-8"))
    try:
        findings, examined = vet(
            declared, _http_fetch, now=datetime.now(UTC), min_age_days=args.min_age_days
        )
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        # FAIL CLOSED. Passing here would mean "PyPI was unreachable, so every dependency is fine".
        print(
            f"::error::dependency vetting could not reach PyPI ({exc!r}). Treating this as a FAILURE: "
            "a supply-chain gate that goes green while blind is worse than no gate.",
            file=sys.stderr,
        )
        return 2

    # Liveness receipt: report the number EXAMINED, not the number of problems. "0 findings" and "the
    # parser stopped seeing dependencies" produce the same exit code otherwise.
    print(f"new_dependency_check: examined {examined} distributions from {args.pyproject}")
    if examined == 0:
        print(
            "::error::examined ZERO distributions. pyproject.toml parsed but yielded no dependency "
            "names -- the schema moved under the parser. This is a broken gate, not a clean sweep.",
            file=sys.stderr,
        )
        return 2

    if findings:
        for finding in findings:
            print(
                f"::error::{finding.distribution}: {finding.problem} -- {finding.detail}",
                file=sys.stderr,
            )
        print(
            f"\n{len(findings)} dependency name(s) failed vetting. Verify the INTENDED distribution "
            "(real, reputable, exact name) before touching pyproject.toml, then re-lock "
            "(CLAUDE.md section 5).",
            file=sys.stderr,
        )
        return 1

    print(
        f"new_dependency_check: all {examined} distributions exist, publish, and are established."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
