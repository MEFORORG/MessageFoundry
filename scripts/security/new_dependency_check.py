#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

WHAT IT SWEEPS: by default the root ``pyproject.toml`` and every ``packaging/*/pyproject.toml``, and in
each of them ``[build-system].requires``, ``[project].dependencies``, every
``[project.optional-dependencies]`` extra, every PEP 735 ``[dependency-groups]`` group, and the
``[tool.uv]`` requirement lists (``declared_distributions`` names them all). The groups were added
2026-07-29 with the hash-pinned CI toolchain (ADR 0034 section 3): those names are not shipped in the
wheel, but they are resolved into ``uv.lock`` and installed into the runner that executes the BLOCKING
security gates, which makes a squatted scanner name a sharper target than a runtime dependency rather
than a softer one. The build requirements, the uv tables, hatch build-target and build-hook
``dependencies`` and the packaging files were added by BACKLOG #5641.

REFUSED RATHER THAN VETTED (each a finding, never a silent skip; ``unnameable_entries``): a declared
entry the gate cannot name (a bare URL, a path, a non-string, a table or list of the wrong TOML
type); a direct reference (``name @ url``), whose bytes come from the URL rather than from the PyPI
project the name would be vetted against; ``[project].dynamic`` naming the dependency lists, which a
build plugin fills from a file this gate never opens; and a non-empty ``[tool.uv]`` source or index
key, which sends a vetted name somewhere other than pypi.org. This repository's own distributions
(``FIRST_PARTY``) are excluded by exact name, each with its reason and what the exclusion gives up.

NOT SWEPT, at least: npm manifests (``ide/package.json``, ``ci/npm-tools/package.json``), and tools
a workflow or script installs by command line (a ``pipx install`` or ``uv tool install``), hatch
environment tables, and any requirements file. An invented name there passes this gate. ``npm audit``
answers known advisories, the npm counterpart of pip-audit, and so has pip-audit's blindness to a
freshly registered name. The npm boundary is pinned by a named test in
``tests/test_new_dependency_check.py``; none of these is a check this gate performs.

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

FAIL-CLOSED. A network error, a rate limit or an unparsable response that is still failing once the
transient retries below are spent is a FAILURE (exit 2), never a pass. A supply-chain gate that
degrades to green when it cannot see is the failure mode this repo has already catalogued three times
(docs/CI.md, "Gate liveness"): a check that reports success while measuring nothing. For the same
reason the summary prints the number of distributions actually EXAMINED, and exits non-zero if that
number is zero.

TRANSIENT RETRY (BACKLOG #3089). The sweep makes one PyPI request per declared distribution, in
sequence, inside a REQUIRED job, so a single TLS handshake timeout used to evict a clean pull request
from the merge queue. A request that fails TRANSIENTLY gets up to ``_ATTEMPTS`` attempts in total
(two retries), with exponential backoff of about 1s then 2s plus up to 0.5s of jitter. Transient is
an allowlist, and ``_is_transient`` is the one place it is written down: at least a connect, TLS
handshake or read timeout, a reset or refused connection, an unreachable network or host, a temporary
DNS failure, a body cut short with IncompleteRead, and an HTTP 429 or 5xx. Everything else fails at
once, and in particular a DEFINITIVE answer is never retried: a 404 still means "no such project" on
the first reply, and a 4xx other than 429, any TLS error other than a timeout (a certificate failure
above all), a proxy refusal, and a body that is not UTF-8 JSON naming an object keep their meaning.
When the retries are spent the last error propagates and the run exits 2 exactly as before; a retry
never turns an unreachable PyPI into a pass.

Worst case added time. The whole run gets at most ``_RUN_RETRY_BUDGET`` (6) retries, and none starts
once the sweep has been running ``_RETRY_WINDOW_S`` (120s). So retries add at most those 120s plus
the duration of the last retried attempt and its backoff (at most 2.5s). One attempt has no hard
ceiling of its own -- urlopen's 20s timeout applies per socket operation and per resolved address --
which was equally true of every request before this change.

USAGE
    python scripts/security/new_dependency_check.py                 # root + packaging/*/pyproject.toml
    python scripts/security/new_dependency_check.py --min-age-days 180
    python scripts/security/new_dependency_check.py --pyproject path/to/pyproject.toml  # repeatable
"""

from __future__ import annotations

import argparse
import errno
import functools
import http.client
import json
import random
import re
import socket
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
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

# This repository's OWN distributions -> why each is excluded. A packaging/*/pyproject.toml declares
# its siblings by name (the harness wheel requires messagefoundry and messagefoundry-toolkit). Each is
# built from this tree, so "did a model invent this name" is not a question to ask of it, and a sibling
# not yet uploaded, or first uploaded in a recent release, would read as absent or "freshly
# registered" and red the gate on every pull request. Matched by exact PEP 503 name only, so a
# near-miss of one of these names is fetched and vetted like any other.
#
# WHAT THIS EXCLUSION GIVES UP, stated so nobody reads it as covered: release.yml does not upload every
# one of these on every release (the harness and the web console are each behind their own switch), so
# a name here may be unclaimed on PyPI, and this gate does not check who holds it there. An install of
# one of these from PyPI before this project has uploaded it would take whoever registered the name.
_FIRST_PARTY_REASON = (
    "built from this repository, so the question this gate asks of an outside name does not apply; "
    "whether the PyPI name is held by this project is not checked here"
)
FIRST_PARTY: dict[str, str] = {
    "messagefoundry": f"the engine, from the root pyproject.toml; {_FIRST_PARTY_REASON}",
    "messagefoundry-toolkit": f"packaging/messagefoundry-toolkit; {_FIRST_PARTY_REASON}",
    "messagefoundry-webconsole": f"packaging/messagefoundry-webconsole; {_FIRST_PARTY_REASON}",
    "messagefoundry-harness": f"packaging/messagefoundry-harness; {_FIRST_PARTY_REASON}",
}


def normalize(name: str) -> str:
    """PEP 503 normalization -- the identity PyPI actually compares names under."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(spec: str) -> str | None:
    """The distribution name from a PEP 508 requirement string, or None if there isn't one.

    ``"pynetdicom>=3.0.4,<4"`` -> ``pynetdicom``; ``"fhir.resources>=7.1.0"`` -> ``fhir.resources``.
    Extras and environment markers are stripped: only the name is being vetted. The name must end at
    a PEP 508 boundary (the end, whitespace, ``(``, a version operator or ``@``), so a bare URL or a
    path is None rather than vetted as its first word: ``"https://..."`` is not the name ``https``.
    """
    text = spec.strip()
    if not text or text.startswith("#"):
        return None
    text = text.split(";", 1)[0]  # environment marker
    text = text.split("[", 1)[0]  # extras
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?=$|[\s(<>=!~@])", text)
    return match.group(1) if match else None


@dataclass(frozen=True)
class Finding:
    distribution: str
    problem: str
    detail: str


# The [tool.uv] keys holding PEP 508 requirement lists that uv resolves or installs. A constraint or
# override names a distribution uv will fetch as surely as a dependency does.
_UV_REQUIREMENT_LISTS = (
    "dev-dependencies",
    "constraint-dependencies",
    "override-dependencies",
    "build-constraint-dependencies",
)
# The [tool.uv] keys that change where a distribution is fetched from. Any non-empty one is refused.
_UV_SOURCE_KEYS = ("sources", "index", "index-url", "extra-index-url", "find-links")


def scan(
    pyproject_text: str, *, source: str = "pyproject.toml"
) -> tuple[dict[str, str], list[Finding]]:
    """One pass over a pyproject: (``declared_distributions``, ``unnameable_entries``) for it.

    The findings are what used to be dropped in silence (BACKLOG #5641): a string that names no
    distribution, a non-string entry, and a table or list of the wrong TOML type, which a plain
    iteration would walk character by character. The one non-string entry skipped without a finding
    is PEP 735's ``{include-group = "<group>"}``: it names another group in this same file, whose
    members are swept in their own right. Each finding names ``source`` and the entry's place in it.
    """
    declared: dict[str, str] = {}
    bad: list[Finding] = []

    def refuse(where: str, problem: str, detail: str) -> None:
        bad.append(Finding(f"{source} {where}", problem, detail))

    def add(where: str, spec: str) -> None:
        name = requirement_name(spec)
        if name is None:
            refuse(
                where,
                "unnameable entry",
                f"{spec!r} is not a PEP 508 requirement this gate can name, so the distribution it "
                "brings in would enter unvetted. Declare it by its PyPI name.",
            )
        elif "@" in spec.split(";", 1)[0]:
            # `name @ url`: the name is vettable, the bytes are not -- uv installs whatever the URL
            # serves. Vetting the PyPI project of that name would pass an attacker's wheel.
            refuse(
                where,
                "direct reference",
                f"{spec!r} installs from a URL or path, not from the PyPI project of that name, so "
                "vetting the name says nothing about what is installed. Declare it by its PyPI name.",
            )
        else:
            declared.setdefault(normalize(name), spec)

    def table(container: dict[str, object], key: str, where: str) -> dict[str, object]:
        value = container.get(key, {})
        if isinstance(value, dict):
            return value
        refuse(
            where,
            "not a table",
            f"expected a TOML table here, found a {type(value).__name__}. Whatever it declares "
            "cannot be vetted; write it in the shape the tool that reads it expects.",
        )
        return {}

    def requirements(
        value: object, where: str, *, include_groups: bool = False, requirement_tables: bool = False
    ) -> None:
        if not isinstance(value, list):
            refuse(
                where,
                "not a list",
                f"expected a list of requirement strings, found a {type(value).__name__}. It is "
                "not read entry by entry, so nothing it names is vetted; make it a list.",
            )
            return
        for index, entry in enumerate(value):
            if isinstance(entry, str):
                add(f"{where}[{index}]", entry)
            elif (
                include_groups
                and isinstance(entry, dict)
                and set(entry) == {"include-group"}
                and isinstance(entry["include-group"], str)
            ):
                continue
            elif (
                # uv's `{ requirement = "...", match-runtime = true }` form names its distribution.
                requirement_tables
                and isinstance(entry, dict)
                and isinstance(entry.get("requirement"), str)
            ):
                add(f"{where}[{index}].requirement", entry["requirement"])
            else:
                refuse(
                    f"{where}[{index}]",
                    "unnameable entry",
                    f"a {type(entry).__name__} where a requirement string belongs names no "
                    "distribution this gate can vet; declare it as a PEP 508 string.",
                )

    data = tomllib.loads(pyproject_text)
    build_system = table(data, "build-system", "[build-system]")
    requirements(build_system.get("requires", []), "[build-system].requires")
    project = table(data, "project", "[project]")
    requirements(project.get("dependencies", []), "[project].dependencies")
    dynamic = project.get("dynamic", [])
    for key in ("dependencies", "optional-dependencies"):
        if isinstance(dynamic, list) and key in dynamic:
            refuse(
                "[project].dynamic",
                "dynamic dependencies",
                f"{key!r} is dynamic, so a build plugin supplies the list from a file this gate "
                "never opens. Declare the requirements statically in [project].",
            )
    extras = table(project, "optional-dependencies", "[project.optional-dependencies]")
    for extra, value in extras.items():
        requirements(value, f"[project.optional-dependencies].{extra}")
    for group, value in table(data, "dependency-groups", "[dependency-groups]").items():
        requirements(value, f"[dependency-groups].{group}", include_groups=True)
    tool = table(data, "tool", "[tool]")
    uv = table(tool, "uv", "[tool.uv]")
    for key in _UV_REQUIREMENT_LISTS:
        requirements(uv.get(key, []), f"[tool.uv].{key}")
    extra_build = table(uv, "extra-build-dependencies", "[tool.uv.extra-build-dependencies]")
    for package, value in extra_build.items():
        requirements(
            value, f"[tool.uv.extra-build-dependencies].{package}", requirement_tables=True
        )
    metadata = uv.get("dependency-metadata", [])
    for index, entry in enumerate(metadata if isinstance(metadata, list) else [metadata]):
        where = f"[tool.uv].dependency-metadata[{index}]"
        if isinstance(entry, dict):
            requirements(entry.get("requires-dist", []), f"{where}.requires-dist")
        else:
            refuse(where, "not a table", "a dependency-metadata entry must be a table.")
    # Where uv fetches FROM. The gate vets a name against pypi.org, so a source or an index that
    # sends the name anywhere else makes that verdict about a different artifact.
    for key in _UV_SOURCE_KEYS:
        if uv.get(key):
            refuse(
                f"[tool.uv].{key}",
                "non-PyPI source",
                "this redirects where uv fetches a distribution from, and this gate vets names "
                "against pypi.org only, so what it passes is not what would be installed.",
            )
    hatch_build = table(table(tool, "hatch", "[tool.hatch]"), "build", "[tool.hatch.build]")
    hooks = [("[tool.hatch.build.hooks]", table(hatch_build, "hooks", "[tool.hatch.build.hooks]"))]
    for target, config in table(hatch_build, "targets", "[tool.hatch.build.targets]").items():
        where = f"[tool.hatch.build.targets.{target}]"
        if not isinstance(config, dict):
            refuse(where, "not a table", "a hatch build target must be a table.")
            continue
        requirements(config.get("dependencies", []), f"{where}.dependencies")
        hooks.append((f"{where}.hooks", table(config, "hooks", f"{where}.hooks")))
    for prefix, hook_table in hooks:
        for hook, config in hook_table.items():
            if isinstance(config, dict):
                requirements(config.get("dependencies", []), f"{prefix}.{hook}.dependencies")
            else:
                refuse(f"{prefix}.{hook}", "not a table", "a hatch build hook must be a table.")
    return declared, bad


def declared_distributions(pyproject_text: str) -> dict[str, str]:
    """Every distribution this project declares, by PEP 503 name -> the first spec declaring it.

    Keyed by ``normalize(name)``, so ``PyYAML`` in one table and ``pyyaml`` in another are ONE
    distribution: one fetch, one count. Covers every table below, because a name this gate does not
    read is a name that enters the tree unvetted:

    * ``[build-system].requires`` -- the build backend, run by PEP 517 build isolation inside the
      release build jobs, which hold ``id-token: write``.
    * ``[project].dependencies`` -- the runtime closure.
    * every ``[project.optional-dependencies]`` extra -- exactly where a niche, plausible-sounding,
      hallucination-prone name lands.
    * every PEP 735 ``[dependency-groups]`` group -- the CI toolchain (ADR 0034 section 3). These are
      not published wheel metadata, but they ARE resolved into ``uv.lock``, hash-exported to
      ``ci/locks/*.lock``, and installed into the runner that executes the blocking security gates. A
      slopsquatted scanner name is if anything a SHARPER target than a runtime dependency: it runs with
      the job's token before any of these controls report.
    * the ``[tool.uv]`` requirement lists (``dev-dependencies``, ``constraint-dependencies``,
      ``override-dependencies``, ``build-constraint-dependencies``) and every
      ``[tool.uv.extra-build-dependencies]`` list, and each ``[tool.uv].dependency-metadata``
      entry's ``requires-dist``: uv fetches what they name.
    * hatch build-target and build-hook ``dependencies``: the backend asks PEP 517 isolation to
      install them in the same release build jobs.

    An entry it cannot name is not here; ``unnameable_entries`` reports it, and ``main`` reads both
    from one ``scan``.
    """
    return scan(pyproject_text)[0]


def unnameable_entries(pyproject_text: str, *, source: str = "pyproject.toml") -> list[Finding]:
    """Every declared entry ``declared_distributions`` cannot name, as a Finding naming where it sits.

    Before BACKLOG #5641 such an entry was skipped in silence, so a bare URL, a local path or a
    mistyped table declared a dependency nothing vetted.
    """
    return scan(pyproject_text, source=source)[1]


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
    "zero findings" and "nothing was checked" are indistinguishable from the exit code alone. An
    allowlisted or FIRST_PARTY name is skipped and not counted.
    """
    allowed = allowlist if allowlist is not None else ALLOWLIST
    skipped = {normalize(k) for k in allowed} | {normalize(k) for k in FIRST_PARTY}
    findings: list[Finding] = []
    examined = 0

    for name in sorted(declared, key=normalize):
        if normalize(name) in skipped:
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


# Retry policy for TRANSIENT network failures only (BACKLOG #3089); the module docstring states the
# worst case. Attempts are per request; the budget and the window are per run, so a PyPI that is flaky
# on every name fails closed within about two minutes rather than retrying every request.
_ATTEMPTS = 3
_BACKOFF_BASE_S = 1.0
_BACKOFF_JITTER_S = 0.5
_RUN_RETRY_BUDGET = 6
_RETRY_WINDOW_S = 120.0
_PYPI_HOST = urllib.parse.urlsplit(_PYPI_JSON).hostname


@dataclass
class RetryBudget:
    """Retries left for the whole run, and the moment after which none may start.

    Required by ``_http_fetch`` rather than defaulted, so a caller cannot silently get a fresh budget
    per request and lose the per-run cap. The defaults are read when the budget is made, not when the
    module loads.
    """

    remaining: int = field(default_factory=lambda: _RUN_RETRY_BUDGET)
    window_ends: float = field(default_factory=lambda: time.monotonic() + _RETRY_WINDOW_S)

    def spend(self) -> bool:
        """Take one retry if any is left and the window is open; False means fail now."""
        if self.remaining <= 0 or time.monotonic() >= self.window_ends:
            return False
        self.remaining -= 1
        return True


class UnreadableReply(ValueError):
    """PyPI answered, but not with UTF-8 JSON naming an object. Definitive: never retried.

    Its message names the failure class only, never the body, which can be large and arbitrary.
    """


# Plain-OSError errnos that mean the link, not the answer. Matched only on an exception whose type is
# exactly OSError (how socket reports these), so an ssl error's own small error numbers cannot collide.
_TRANSIENT_ERRNOS = frozenset(
    {
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ENOTCONN,  # "Transport endpoint is not connected", the BACKLOG #3089 pip-audit log
        errno.EADDRNOTAVAIL,  # an unusable IPv6 address tried last on an IPv4-only runner
        errno.ETIMEDOUT,
        errno.ECONNABORTED,
    }
)


def _is_transient(exc: BaseException) -> bool:
    """The transient ALLOWLIST: True only for a failure that is the link, not the answer.

    The module docstring summarizes this; the code is the record. HTTPError is checked first because it
    subclasses URLError, and a 404 never reaches here. Anything not matched below -- a certificate or
    other TLS error that is not a timeout, a proxy refusal (a bare OSError with no errno), an
    UnreadableReply -- is definitive and fails at once.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or 500 <= exc.code <= 599
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    # TimeoutError: the 2026-10-20 evictions logged URLError(TimeoutError) from a TLS handshake.
    # ConnectionError: reset, refused, aborted, and http.client.RemoteDisconnected.
    if isinstance(reason, TimeoutError | ConnectionError | http.client.IncompleteRead):
        return True
    if isinstance(reason, socket.gaierror):
        return reason.errno == socket.EAI_AGAIN
    return type(reason) is OSError and reason.errno in _TRANSIENT_ERRNOS


def _describe(exc: BaseException) -> str:
    """The exception class (and the wrapped reason's class or HTTP status), never a payload."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTPError {exc.code}"
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, BaseException):
        return f"URLError({type(exc.reason).__name__})"
    return type(exc).__name__


def _http_fetch(
    name: str,
    *,
    budget: RetryBudget,
    timeout: float = 20.0,
    sleep: Callable[[float], None] | None = None,
) -> dict | None:
    """Fetch PyPI's JSON for ``name``, retrying TRANSIENT failures only.

    None means 404. A definitive error raises at once; a transient one raises once ``_ATTEMPTS`` or the
    run's ``budget`` is spent. Either way the caller fails closed -- nothing here returns a payload it
    did not receive.
    """
    attempt = 1
    while True:
        try:
            return _fetch_once(name, timeout=timeout)
        except (OSError, http.client.HTTPException) as exc:
            if attempt >= _ATTEMPTS or not _is_transient(exc):
                raise
            # Checked separately and last, because spend() consumes a retry: a definitive error or a
            # final attempt must not draw down the run's budget.
            if not budget.spend():
                raise
            if isinstance(exc, urllib.error.HTTPError):
                exc.close()  # release the 429/5xx response's socket now, not at garbage collection
            # Jitter only de-synchronises retries; it guards nothing, so a non-crypto PRNG is right.
            jitter = random.uniform(0, _BACKOFF_JITTER_S)  # nosec B311
            delay = _BACKOFF_BASE_S * 2 ** (attempt - 1) + jitter
            print(
                f"::warning::PyPI request for {name!r} to {_PYPI_HOST} failed transiently on attempt "
                f"{attempt} of {_ATTEMPTS} ({_describe(exc)}); retrying in {delay:.1f}s "
                f"({budget.remaining} retries left this run).",
                file=sys.stderr,
            )
            (sleep or time.sleep)(delay)
            attempt += 1


def _fetch_once(name: str, *, timeout: float) -> dict | None:
    """One request for PyPI's JSON for ``name``. None means 404; every other error raises."""
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
            raw = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            exc.close()
            return None
        raise
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError as exc:  # UnicodeDecodeError or JSONDecodeError; both carry the whole body
        raise UnreadableReply(
            f"PyPI's reply for {name!r} is not UTF-8 JSON ({type(exc).__name__})"
        ) from None
    if not isinstance(payload, dict):
        raise UnreadableReply(f"PyPI's reply for {name!r} is a JSON {type(payload).__name__}")
    return payload


def _annotation(line: str) -> str:
    """``line`` safe as ONE GitHub workflow command: a raw newline in a TOML key would start another.

    The escapes are the ones the runner itself decodes in a command's message.
    """
    return line.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _print_finding(finding: Finding) -> None:
    print(
        _annotation(f"::error::{finding.distribution}: {finding.problem} -- {finding.detail}"),
        file=sys.stderr,
    )


def default_pyprojects(root: Path) -> list[Path]:
    """The files the gate sweeps when none is named: the root pyproject, then every packaging one."""
    return [root / "pyproject.toml", *sorted((root / "packaging").glob("*/pyproject.toml"))]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--pyproject",
        type=Path,
        action="append",
        help="a pyproject.toml to sweep; repeatable. Default: the root one and packaging/*/.",
    )
    parser.add_argument("--min-age-days", type=int, default=DEFAULT_MIN_AGE_DAYS)
    args = parser.parse_args(argv)

    files: list[Path] = args.pyproject or default_pyprojects(_ROOT)
    if not args.pyproject and len(files) == 1:
        print(
            f"::error::found no packaging/*/pyproject.toml under {_ROOT}. The default sweep reads "
            "every one, so finding none means the tree moved under the gate. This is a broken gate, "
            "not a clean sweep.",
            file=sys.stderr,
        )
        return 2
    declared: dict[str, str] = {}
    declared_in: dict[str, Path] = {}
    unnameable: list[Finding] = []
    for path in files:
        # A file that cannot be read or parsed is "could not see" (2), never "failed vetting" (1),
        # which is what a traceback would exit with.
        try:
            names, problems = scan(path.read_text(encoding="utf-8"), source=str(path))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
            print(
                _annotation(
                    f"::error::could not read {path} ({type(exc).__name__}: {exc}). This is a "
                    "broken gate, not a clean sweep."
                ),
                file=sys.stderr,
            )
            return 2
        for name, spec in names.items():
            declared.setdefault(name, spec)
            declared_in.setdefault(name, path)
        unnameable.extend(problems)
    # Named before PyPI is asked anything, so an unreachable PyPI cannot hide them.
    for finding in unnameable:
        _print_finding(finding)
    # FAIL CLOSED on both branches below. Passing here would mean "PyPI was unreachable (or answered
    # nonsense), so every dependency is fine". Either one escaping as a traceback would exit 1, the
    # code that means "a dependency failed vetting", rather than 2, "could not see".
    try:
        findings, examined = vet(
            declared,
            functools.partial(_http_fetch, budget=RetryBudget()),
            now=datetime.now(UTC),
            min_age_days=args.min_age_days,
        )
    except UnreadableReply as exc:
        print(
            f"::error::dependency vetting got an unreadable reply from PyPI ({exc}). Treating this as "
            "a FAILURE: a supply-chain gate that goes green while blind is worse than no gate.",
            file=sys.stderr,
        )
        return 2
    # OSError covers URLError, HTTPError and every timeout; HTTPException covers IncompleteRead, which
    # is not an OSError.
    except (OSError, http.client.HTTPException) as exc:
        print(
            f"::error::dependency vetting could not reach PyPI ({exc!r}). Treating this as a FAILURE: "
            "a supply-chain gate that goes green while blind is worse than no gate.",
            file=sys.stderr,
        )
        return 2

    # Liveness receipt: report the number EXAMINED, not the number of problems. "0 findings" and "the
    # parser stopped seeing dependencies" produce the same exit code otherwise.
    sources = ", ".join(str(path) for path in files)
    print(f"new_dependency_check: examined {examined} distributions from {sources}")
    for finding in findings:
        name = finding.distribution
        if name in declared:
            name = f"{name} (declared as {declared[name]!r} in {declared_in[name]})"
        _print_finding(Finding(name, finding.problem, finding.detail))
    findings = unnameable + findings
    if examined == 0:
        print(
            "::error::examined ZERO distributions. pyproject.toml parsed but yielded no dependency "
            "names -- the schema moved under the parser. This is a broken gate, not a clean sweep.",
            file=sys.stderr,
        )
        return 2

    if findings:
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
