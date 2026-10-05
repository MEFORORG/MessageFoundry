#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read public PyPI and OSV data for every runtime component, dated (BACKLOG #1189, ASVS 15.1.4).

ASVS 5.0.0 chapter V15.1 defines a "risky component" as a third-party library "with missing or
poorly implemented security controls around its development processes or functionality", and gives
as examples components that are "poorly maintained, unsupported, at the end-of-life stage, or have
a history of significant vulnerabilities". ``docs/RISKY-COMPONENTS.md`` designates components by
exposure. This script supplies the other reading: each component measured on those examples, from
public metadata only.

THE POPULATION is every distribution the page assesses: each name in the core runtime closure,
``security/runtime-closure-core.txt``, plus each name an assessed extra's closure adds to it. ``EXTRAS``
names those extras and their closure files (BACKLOG #2414 brought ``harness`` in). It is not only
the designated set, because a component can be risky by maintenance or history even where the
exposure criterion did not designate it. Each reading records which extras add its name, and
``tests/test_risky_component_designation.py`` holds the population to the closure files, so a
closure the page assesses and this script does not read turns that test red.

OSV MATCHES AN ADVISORY BY PYPI NAME. A flaw in code a wheel carries inside it, such as a compiled
library, is counted only where an advisory names the PyPI package. So no reading here can show
that a wheel's contents are free of known flaws. The rendered section says so, and the page's
``harness`` section says what it means for the Qt inside that extra's wheels.

THE SOURCES, and nothing else:

* the PyPI JSON API (``https://pypi.org/pypi/<name>/json``): the newest upload, the release cadence,
  the ``Development Status`` classifier, the latest ``requires-python``, and whether the pinned
  version's files are yanked;
* the PyPI Simple API in JSON form, for the PEP 792 project status (``active``, ``archived``,
  ``deprecated`` or ``quarantined``);
* the OSV API (``https://api.osv.dev/v1/query``): every advisory recorded for the package, and the
  ones recorded as affecting the pinned version.

It writes two things. ``security/risky-component-readings.json`` is the dated snapshot: the readings,
the criteria and their windows, and a re-read date. The page section between the
``component-readings`` markers in ``docs/RISKY-COMPONENTS.md`` is rendered from that snapshot and
from the page's own tiers. ``tests/test_risky_component_designation.py`` re-derives every verdict
and re-renders the section, WITHOUT the network, and fails if either differs from what is tracked.

WHAT A WHEEL CARRIES is answered by a third file, ``security/bundled-code-survey.json`` (BACKLOG
#2935): a survey, made by hand, of whether each pinned wheel carries a package, a library tree or
a data set of another project, as compiled code, source code or data. A single module adapted
from another project is recorded where the survey's search found one, and changes no answer. This
script never writes the survey. It renders it into the same page section, and ``survey_problems``
holds it to the snapshot: one answer per reading at the reading's pin, an answer for every form,
and a route for each not-designated wheel that counts as carrying another project's code. A run
that leaves the survey behind says so and exits 1, after writing the snapshot and the page.

A full run needs the network and runs by hand, never in CI. Standard library only, like
``runtime_closure.py`` beside it, so it runs under any Python 3.11 or later with nothing installed:

    python scripts/security/component_readings.py

The snapshot date is always today, UTC: the APIs answer only with today's classifiers, statuses and
yanks, so no earlier date can be read honestly. The readings are dated to that day and to the pins
the closure files held on it; a later lock bump does not change them until the next run.
``--render-only`` re-renders the page section from the tracked snapshot with no network, for when
the tiers change and the readings do not.
"""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import json
import re
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any, TypedDict

# Sibling imports work whether this file is run as a script or imported as ``scripts.security.*``
# (the in-repo idiom from scripts/ci/check_required_workflow_state.py). The closure reader is the
# one the designation gate already uses, so both read the population the same way.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.security import runtime_closure  # noqa: E402

ROOT = runtime_closure.ROOT
CORE = runtime_closure.CLOSURE
#: Each extra the page assesses and its closure file, in the page's order. The population is the
#: core closure plus what each of these adds to it (``population``).
EXTRAS: dict[str, Path] = {
    "sqlserver": runtime_closure.SQLSERVER_CLOSURE,
    "harness": runtime_closure.HARNESS_CLOSURE,
}
SNAPSHOT = ROOT / "security" / "risky-component-readings.json"
#: The hand-made survey of what each pinned wheel carries inside it (BACKLOG #2935). A run of this
#: script never writes it. ``survey_problems`` holds it to the snapshot and to the page's tiers.
SURVEY = ROOT / "security" / "bundled-code-survey.json"
PAGE = ROOT / "docs" / "RISKY-COMPONENTS.md"

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_SIMPLE = "https://pypi.org/simple/{name}/"
OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"

#: The windows and thresholds. The snapshot records them and the guard re-derives every verdict
#: from the recorded copy. The guard also holds that copy, and the re-read date, to these constants,
#: so changing one here turns the guard red until a new run records it.
MAINTENANCE_WINDOW_DAYS = 730
ADVISORY_WINDOW_DAYS = 1825
REREAD_INTERVAL_DAYS = 90
SIGNIFICANT_SEVERITIES = ("HIGH", "CRITICAL")
#: PEP 792 statuses that say the project is no longer supported. ``active`` and an absent status
#: are not.
UNSUPPORTED_STATUSES = ("archived", "deprecated", "quarantined")
INACTIVE_CLASSIFIER = "Development Status :: 7 - Inactive"

#: The GitHub advisory database rates severity in these words; its MODERATE is the medium band.
_SEVERITY_RANK = {"LOW": 1, "MODERATE": 2, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

#: CVSS 3.x base-metric weights, from the FIRST specification. ``PR`` weighs more when scope changes.
_CVSS3_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_CVSS3_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_USER_AGENT = "messagefoundry-component-readings/1 (BACKLOG 1189)"
_TIMEOUT_SECONDS = 30

AXES = ("maintenance", "support", "advisory_history")
_AXIS_WORDS = {
    "maintenance": "maintenance",
    "support": "support",
    "advisory_history": "vulnerability history",
}

#: The page section this script owns. Everything between the two lines is rendered; the heading and
#: the definition above the first line are written by hand.
BEGIN = (
    "<!-- BEGIN component-readings: rendered by scripts/security/component_readings.py "
    "from security/risky-component-readings.json. Do not edit by hand. -->"
)
END = "<!-- END component-readings -->"
#: The width the page's hand-written prose wraps at, so rendered prose matches it.
_PAGE_WIDTH = 100
#: What CommonMark reads as the start of a list item, heading, quote or table at a line's start.
_BLOCK_START = re.compile(r"^(\d+[.)]|[-*+>#|])(\s|$)")
#: The heading that ends the page's tier tables. The designation labels are read above it.
READINGS_HEADING = "## Risky by ASVS's own examples, read from public data"
#: The rendered subsection that lists what was read for the names the assessed extras add. An
#: extra's own section on the page points a reader at it by this name.
EXTRAS_HEADING = "### The names the assessed extras add"
#: The rendered subsection that says what each wheel carries inside it, from ``SURVEY``.
SURVEY_HEADING = "### What each wheel carries inside it"

#: A survey answer to "does the pinned wheel carry a bundled copy of another project in this form".
#: The last one counts as carrying code wherever a route is decided: a guessed "no" is what the
#: survey exists to stop.
CARRIES = ("yes", "no", "not established")
#: The forms the survey answers for. A wheel's top-level ``carries`` and ``projects`` answer for
#: compiled code; its ``source`` and ``data`` entries answer for the other two.
FORMS = ("compiled", "source", "data")
#: The forms that are another project's CODE. Carrying one is what owes a not-designated wheel a
#: route. Data alone owes none: the page lists it and says why.
CODE_FORMS = ("compiled", "source")
#: What an answer may rest on. A ``none-any`` wheel whose files were listed can only support "no".
#: A source-tree answer names the source distribution it read. A file-list answer names wheels
#: only: no source distribution was read, so it cannot show what is linked into a compiled file,
#: and the guard cannot check its "no" beyond the files named. Project metadata lists no file, so
#: it can never support "no".
TAG_AND_LIST = "wheel tag and file list"
SOURCE_TREE = "wheel file list and source tree"
FILE_LIST = "wheel file list"
METADATA_ONLY = "project metadata"
EVIDENCE_KINDS = (TAG_AND_LIST, SOURCE_TREE, FILE_LIST, METADATA_ONLY)
#: What the page does about a not-designated wheel that carries: highlight it as risky on what it
#: carries, or read the carried project's own advisories. A ``read`` route records these fields.
ROUTES = ("highlight", "read")
READ_FIELDS = ("source", "date", "version", "result")
#: What a file the word search hit was recorded as. Only the first is listed on the page: a single
#: module adapted from another project. It is not the survey's unit, and is owed no route.
ADAPTED, COPIED_LINES, PROSE = "adapted module", "copied lines", "prose"
HIT_KINDS = (ADAPTED, COPIED_LINES, PROSE)
#: The rules of the source and data search that the control must be shown to fire. Each needs a
#: path in the control wheel that it fired on.
CONTROL_RULES = ("directory", "licence file", "data", "words")
#: What the record's ``search`` entry must state: the lists as lists, the rules as text.
SEARCH_LISTS = ("directories", "words", "suffixes", "cannot_see")
SEARCH_RULES = ("directory_rule", "top_level_rule", "licence_rule", "size_rule", "word_rule")


class Advisory(TypedDict):
    """One advisory, after the OSV records that alias each other are merged into one.

    ``rated_by`` says where ``severity`` came from: ``github`` (the GitHub advisory database's
    word), ``cvss3`` (the CVSS 3 base score of a vector in the record) or ``none``.
    """

    id: str
    severity: str
    rated_by: str
    published: str


class Twin(TypedDict):
    """A record from another database and the GitHub advisory it names, as ``screen`` judged it."""

    id: str
    twin: str


class Reading(TypedDict):
    """Everything recorded for one component.

    ``newest_upload``, ``development_status``, ``project_status``, ``pinned_yanked`` and
    ``advisories`` decide the verdicts in ``risky``. The rest is context for a reader.
    ``added_by`` names the assessed extras whose closure adds this name to the core one, in
    ``EXTRAS`` order; it is empty for a name in the core closure.
    """

    name: str
    pinned: str
    added_by: list[str]
    latest_version: str
    newest_upload: str | None
    releases_in_maintenance_window: int
    development_status: list[str]
    project_status: str
    pinned_yanked: bool
    requires_python_latest: str
    advisories: list[Advisory]
    advisories_dropped: list[Twin]
    advisories_unresolved: list[Twin]
    advisories_affecting_pin: list[str]
    risky: dict[str, bool]


Fetch = Callable[[str, bytes | None], Any]


def fetch_json(url: str, body: bytes | None = None) -> Any:
    """GET (or POST ``body`` as JSON) and decode the reply. Any HTTP error propagates."""
    headers = {"User-Agent": _USER_AGENT}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if "/simple/" in url:
        headers["Accept"] = "application/vnd.pypi.simple.v1+json"
    # nosec B310: every URL is built from the fixed https PyPI and OSV constants above.
    request = urllib.request.Request(url, data=body, headers=headers)  # nosec B310
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as reply:  # nosec B310
        return json.loads(reply.read())


def _day(timestamp: str) -> dt.date:
    """The UTC calendar day of an ISO 8601 timestamp such as ``2022-10-25T02:36:20.889702Z``."""
    return dt.date.fromisoformat(timestamp[:10])


def _merge_aliases(vulns: Iterable[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group OSV records that name each other, so one flaw published twice counts once.

    Union-find over each record's id and aliases (a CVE id links a GHSA to its PYSEC twin). It is
    transitive, so a record naming two CVEs joins both flaws into one advisory; that undercounts,
    and never overcounts. Screen withdrawn records out first (``screen``).
    """
    parent: dict[str, str] = {}

    def find(key: str) -> str:
        while parent.setdefault(key, key) != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    records = list(vulns)
    for record in records:
        for alias in record.get("aliases") or []:
            parent[find(alias)] = find(record["id"])
    groups: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        groups.setdefault(find(record["id"]), []).append(record)
    return list(groups.values())


def _representative(group: list[dict[str, Any]]) -> str:
    """The id a reader can look up: the GitHub advisory if one exists, else the first id sorted."""
    ids = sorted(str(r["id"]) for r in group)
    return next((i for i in ids if i.startswith("GHSA-")), ids[0])


def cvss3_score(vector: str) -> float | None:
    """The CVSS 3.x base score of ``vector``, or None when it is not a complete 3.x vector.

    The FIRST specification's formula, including its Roundup to one decimal place.
    """
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        changed = {"U": False, "C": True}[metrics["S"]]
        pr = (_CVSS3_PR_CHANGED if changed else _CVSS3_WEIGHTS["PR"])[metrics["PR"]]
        exploitability = (
            8.22
            * _CVSS3_WEIGHTS["AV"][metrics["AV"]]
            * _CVSS3_WEIGHTS["AC"][metrics["AC"]]
            * pr
            * _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        )
        c, i, a = (_CVSS3_WEIGHTS["CIA"][metrics[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    raw = min((1.08 if changed else 1.0) * (impact + exploitability), 10.0)
    scaled = round(raw * 100_000)
    return scaled / 100_000 if scaled % 10_000 == 0 else (scaled // 10_000 + 1) / 10.0


def _cvss3_word(score: float) -> str:
    """The CVSS 3 qualitative rating of a base score."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def _group_severity(group: list[dict[str, Any]]) -> tuple[str, str]:
    """The group's severity word and where it came from.

    The GitHub advisory database's word wins where any member has one. Otherwise the highest CVSS 3
    base score among the members' vectors is rated by the CVSS scale. A group with neither, such
    as one carrying only a CVSS 4 vector, is ``UNRATED``.
    """
    rated = [str((r.get("database_specific") or {}).get("severity", "")).upper() for r in group]
    ranked = [s for s in rated if s in _SEVERITY_RANK]
    if ranked:
        return max(ranked, key=_SEVERITY_RANK.__getitem__), "github"
    scores = [
        score
        for r in group
        for s in r.get("severity") or []
        if (score := cvss3_score(str(s.get("score", "")))) is not None
    ]
    return (_cvss3_word(max(scores)), "cvss3") if scores else ("UNRATED", "none")


def screen(
    name: str, vulns: list[dict[str, Any]], fetch: Fetch
) -> tuple[list[dict[str, Any]], list[Twin], list[Twin]]:
    """The records to count, and two lists naming what was judged: dropped, and unresolved.

    Each record is judged on its own, never as a group. A withdrawn record is left out. A record
    from another database is left out when every GitHub advisory it names FOR THIS PACKAGE is
    withdrawn: its only reviewed view here is gone. A GitHub advisory about another package says
    nothing either way. OSV's package query omits withdrawn records, so a GitHub alias the query did
    not return is fetched by id. The fastapi record PYSEC-2024-38 is the case this exists for: its
    fastapi GitHub twin was withdrawn, and the live one it also names is about python-multipart.

    A GitHub alias that OSV does not have at all (404) cannot be judged, so it is treated as about
    this package. When no alias is live, its record still counts and is listed as unresolved.
    """
    # GHSA id to (withdrawn, about this package). None for withdrawn means OSV does not have it.
    status: dict[str, tuple[bool | None, bool]] = {
        str(v["id"]): (bool(v.get("withdrawn")), True)
        for v in vulns
        if str(v["id"]).startswith("GHSA-")
    }
    kept: list[dict[str, Any]] = []
    dropped: list[Twin] = []
    unresolved: list[Twin] = []
    for record in vulns:
        if record.get("withdrawn"):
            continue
        twins = [str(a) for a in record.get("aliases") or [] if str(a).startswith("GHSA-")]
        if not str(record["id"]).startswith("GHSA-"):
            for alias in twins:
                if alias not in status:
                    status[alias] = _ghsa_status(alias, name, fetch)
            twins = [a for a in twins if status[a][1]]
        if str(record["id"]).startswith("GHSA-") or not twins:
            kept.append(record)
            continue
        if all(status[a][0] is True for a in twins):
            dropped.append({"id": str(record["id"]), "twin": twins[0]})
            continue
        kept.append(record)
        if not any(status[a][0] is False for a in twins):
            missing = next(a for a in twins if status[a][0] is None)
            unresolved.append({"id": str(record["id"]), "twin": missing})
    return kept, dropped, unresolved


def _ghsa_status(ghsa: str, name: str, fetch: Fetch) -> tuple[bool | None, bool]:
    """Whether OSV records the GitHub advisory as withdrawn, and whether it is about ``name``.

    ``(None, True)`` when OSV does not have it: unknown, and not shown to be about another package.
    """
    try:
        record = fetch(OSV_VULN.format(id=urllib.parse.quote(ghsa, safe="")), None)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None, True
        raise
    packages = {
        runtime_closure.canonical_name(str((a.get("package") or {}).get("name", "")))
        for a in record.get("affected") or []
    }
    return bool(record.get("withdrawn")), not packages or name in packages


def _date(record: Mapping[str, Any]) -> str:
    """A record's first-published day, or its last-modified day when OSV gives no publish date."""
    return str(record.get("published") or record.get("modified") or "")[:10]


def advisories(vulns: Iterable[dict[str, Any]]) -> list[Advisory]:
    """Screened OSV records as merged advisories, sorted by id: one per flaw, dated by its first.

    A group with no date at all is kept, dated ``unknown``, so it still reaches the page.
    """
    out: list[Advisory] = []
    for group in _merge_aliases(vulns):
        dates = [d for d in (_date(r) for r in group) if d]
        severity, rated_by = _group_severity(group)
        out.append(
            {
                "id": _representative(group),
                "severity": severity,
                "rated_by": rated_by,
                "published": min(dates) if dates else "unknown",
            }
        )
    return sorted(out, key=lambda a: a["id"])


def _osv_all(name: str, version: str | None, fetch: Fetch) -> list[dict[str, Any]]:
    """Every OSV record for ``name`` on PyPI, or for that one version, following page tokens."""
    query: dict[str, Any] = {"package": {"name": name, "ecosystem": "PyPI"}}
    if version is not None:
        query["version"] = version
    vulns: list[dict[str, Any]] = []
    seen: set[str] = set()
    while True:
        reply = fetch(OSV_QUERY, json.dumps(query).encode("utf-8"))
        vulns += reply.get("vulns") or []
        token = reply.get("next_page_token")
        if not token:
            return vulns
        if token in seen:
            raise ValueError(f"{name}: OSV returned the page token {token!r} twice")
        seen.add(token)
        query["page_token"] = token


def in_window(
    reading: Mapping[str, Any], as_of: dt.date, criteria: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    """The reading's advisories first published inside the advisory window ending ``as_of``."""
    floor = as_of - dt.timedelta(days=int(criteria["advisory_window_days"]))
    # An advisory OSV gives no date for cannot be shown to fall outside, so it counts as inside.
    return [
        a
        for a in reading["advisories"]
        if a["published"] == "unknown" or floor <= dt.date.fromisoformat(a["published"]) <= as_of
    ]


def significant_in_window(
    reading: Mapping[str, Any], as_of: dt.date, criteria: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    """The in-window advisories whose severity the criteria count as significant."""
    significant = set(criteria["significant_severities"])
    return [a for a in in_window(reading, as_of, criteria) if a["severity"] in significant]


def classify(
    reading: Mapping[str, Any], as_of: dt.date, criteria: Mapping[str, Any]
) -> dict[str, bool]:
    """Each ASVS example's verdict for one component, from its recorded readings and the criteria.

    The guard calls this on the snapshot, so a verdict that does not follow from its readings fails
    there without the network.
    """
    maintenance_floor = as_of - dt.timedelta(days=int(criteria["maintenance_window_days"]))
    newest = reading["newest_upload"]
    return {
        # No unyanked release at all is the strongest reading of this example, not an error.
        "maintenance": newest is None or dt.date.fromisoformat(newest) < maintenance_floor,
        "support": (
            reading["project_status"] in criteria["unsupported_statuses"]
            or criteria["inactive_classifier"] in reading["development_status"]
            or reading["pinned_yanked"]
        ),
        "advisory_history": bool(significant_in_window(reading, as_of, criteria)),
    }


def criteria() -> dict[str, Any]:
    """The thresholds this run applies, recorded so the guard can apply the same ones."""
    return {
        "maintenance_window_days": MAINTENANCE_WINDOW_DAYS,
        "advisory_window_days": ADVISORY_WINDOW_DAYS,
        "significant_severities": list(SIGNIFICANT_SEVERITIES),
        "unsupported_statuses": list(UNSUPPORTED_STATUSES),
        "inactive_classifier": INACTIVE_CLASSIFIER,
    }


def read_component(
    name: str, pinned: str, *, added_by: list[str], as_of: dt.date, fetch: Fetch = fetch_json
) -> Reading:
    """One component's readings from PyPI and OSV, as of ``as_of``."""
    quoted = urllib.parse.quote(name, safe="")
    project = fetch(PYPI_JSON.format(name=quoted), None)
    simple = fetch(PYPI_SIMPLE.format(name=quoted), None)
    info = project["info"]
    releases: dict[str, list[dict[str, Any]]] = project["releases"]

    uploads = {
        version: min(_day(f["upload_time_iso_8601"]) for f in files)
        for version, files in releases.items()
        if files and not all(f.get("yanked") for f in files)
    }
    # A project with every release yanked, or a quarantined one PyPI offers no files for, reads as
    # no release at all, and a pinned version PyPI no longer lists reads as yanked. Those are what
    # the maintenance and support examples exist to catch, so neither stops the run.
    past = [d for d in uploads.values() if d <= as_of]
    window_floor = as_of - dt.timedelta(days=MAINTENANCE_WINDOW_DAYS)
    pinned_files = releases.get(pinned, [])
    kept, dropped, unresolved = screen(name, _osv_all(name, None, fetch), fetch)
    gone = {t["id"] for t in dropped}
    at_pin = [
        r for r in _osv_all(name, pinned, fetch) if not r.get("withdrawn") and r["id"] not in gone
    ]

    reading: Reading = {
        "name": name,
        "pinned": pinned,
        "added_by": list(added_by),
        "latest_version": str(info["version"]),
        "newest_upload": max(past).isoformat() if past else None,
        "releases_in_maintenance_window": sum(window_floor <= d for d in past),
        "development_status": sorted(
            c for c in info.get("classifiers") or [] if c.startswith("Development Status ::")
        ),
        "project_status": str((simple.get("project-status") or {}).get("status", "absent")),
        "pinned_yanked": all(f.get("yanked") for f in pinned_files),
        "requires_python_latest": str(info.get("requires_python") or ""),
        "advisories": advisories(kept),
        "advisories_dropped": dropped,
        "advisories_unresolved": unresolved,
        "advisories_affecting_pin": [a["id"] for a in advisories(at_pin)],
        "risky": {},
    }
    reading["risky"] = classify(reading, as_of, criteria())
    return reading


def population() -> dict[str, tuple[str, list[str]]]:
    """Name to its pin and the extras that add it: the core closure plus every extra's additions.

    A core name's list is empty. A name two closures pin at different versions raises: a reading
    records one pin per name, so it could not say which version was read.
    """
    core = runtime_closure.closure_pins(CORE)
    members: dict[str, tuple[str, list[str]]] = {name: (pin, []) for name, pin in core.items()}
    for extra, path in EXTRAS.items():
        for name, pin in runtime_closure.closure_pins(path).items():
            recorded, added_by = members.setdefault(name, (pin, []))
            if recorded != pin:
                raise ValueError(
                    f"{path.name} pins {name} at {pin}; another closure pins it at {recorded}"
                )
            if name not in core:
                added_by.append(extra)
    return members


def snapshot(as_of: dt.date, fetch: Fetch = fetch_json) -> dict[str, Any]:
    """The whole dated snapshot: provenance, criteria, and one reading per population member."""
    return {
        "subject": "Public-metadata readings of each runtime component on ASVS 5.0.0 V15.1's "
        "risky-component examples (BACKLOG #1189, ASVS 15.1.4)",
        "snapshot_date": as_of.isoformat(),
        "reread_by": (as_of + dt.timedelta(days=REREAD_INTERVAL_DAYS)).isoformat(),
        "population": {
            "core": CORE.relative_to(ROOT).as_posix(),
            "extras": {extra: path.relative_to(ROOT).as_posix() for extra, path in EXTRAS.items()},
        },
        "sources": {
            "pypi_json": PYPI_JSON,
            "pypi_simple": PYPI_SIMPLE + " (Accept: application/vnd.pypi.simple.v1+json)",
            "osv_query": OSV_QUERY,
        },
        "criteria": criteria(),
        "generator": "python scripts/security/component_readings.py",
        "readings": [
            read_component(name, pin, added_by=added_by, as_of=as_of, fetch=fetch)
            for name, (pin, added_by) in sorted(population().items())
        ],
    }


# --- The survey of what each wheel carries (BACKLOG #2935) ---------------------------------------


def form_answer(wheel: Mapping[str, Any], form: str) -> Mapping[str, Any]:
    """The wheel's answer for one form: its ``carries``, ``projects`` and ``evidence``.

    Compiled code is answered by the wheel's own top-level fields. A missing entry for another
    form is an empty answer, which ``survey_problems`` reports.
    """
    answer = wheel if form == "compiled" else wheel.get(form)
    return answer if isinstance(answer, Mapping) else {}


def carries_code(wheel: Mapping[str, Any]) -> bool:
    """Whether the wheel counts as carrying another project's code, compiled or source.

    It does unless both code forms were shown to be "no" and the data answer was established. An
    answer that is not established, for any form, counts as code: what is in the wheel is not known.
    """
    return any(form_answer(wheel, form).get("carries") != "no" for form in CODE_FORMS) or (
        form_answer(wheel, "data").get("carries") not in ("yes", "no")
    )


def carries_anything(wheel: Mapping[str, Any]) -> bool:
    """Whether any form's answer is other than a shown "no"."""
    return any(form_answer(wheel, form).get("carries") != "no" for form in FORMS)


def _needs_route(wheel: Mapping[str, Any], labels: Mapping[str, str]) -> bool:
    """Whether the page owes this wheel a route: it is not designated, and counts as carrying code."""
    return wheel["name"] not in labels and carries_code(wheel)


def _said(value: object) -> bool:
    """Whether a recorded field says anything: a JSON null, or blank text, does not."""
    return bool(str(value or "").strip())


def _said_list(value: object) -> bool:
    """Whether a recorded field is a list with an entry, where every entry says something."""
    return isinstance(value, list) and bool(value) and all(_said(item) for item in value)


def _entries(value: object) -> list[Mapping[str, Any]]:
    """A recorded list of entries, each as a mapping. An entry of another shape reads as empty.

    So a malformed entry is reported by the check on its fields, and never raises there or in
    the renderer.
    """
    items = value if isinstance(value, list) else []
    return [item if isinstance(item, Mapping) else {} for item in items]


_SHA256 = re.compile(r"[0-9a-f]{64}")


def _file_pin(file: str) -> tuple[str, str]:
    """The distribution name, canonical, and the exact version a wheel or sdist file name states.

    A wheel's name is ``dist-version-tags.whl`` and its dist part holds no hyphen. A source
    distribution's is ``dist-version.tar.gz``. The version is compared whole, never as a prefix.
    """
    if file.endswith(".whl"):
        dist, _, rest = file.partition("-")
        return runtime_closure.canonical_name(dist), rest.partition("-")[0]
    dist, _, version = file.removesuffix(".zip").removesuffix(".tar.gz").rpartition("-")
    return runtime_closure.canonical_name(dist), version


def survey_problems(
    survey: Mapping[str, Any], data: Mapping[str, Any], labels: Mapping[str, str]
) -> list[str]:
    """Where the survey fails to answer for the snapshot's population, or to route what it found.

    One answer per reading, at the reading's pin, so a re-read that moves a pin leaves the survey
    behind visibly. Each answer names the files it was read from, and each file name must carry
    the surveyed pin, so moving the pin alone does not pass. Each file named must carry a sha256,
    a source-tree answer must name a wheel and a source distribution, a file-list answer wheels
    only, and a metadata answer no file. A missing or malformed field of a wheel is reported,
    never raised, except its ``name``.

    Every wheel answers for every form in ``FORMS``. A source or data answer of "yes" or "no"
    needs a wheel that was listed, and those answers may not be dated before the compiled one.

    The route rule reads all the forms. A not-designated wheel is owed a route when it carries
    another project's code, compiled or source, or when any form's answer is not established. A
    designated wheel is owed none. Nor is a wheel shown to carry no code from another project,
    whether it carries nothing or carries data only.

    The record must state its search under ``search``, and name a control wheel outside the
    survey with a path for each rule in ``CONTROL_RULES`` that fired on it. Each file the word
    search hit is recorded with a kind in ``HIT_KINDS``, and the files recorded as adapted modules
    must be the ones ``adapted_modules`` names. A wheel nobody fetched can record neither.
    """
    problems: list[str] = []
    search = survey.get("search")
    search = search if isinstance(search, Mapping) else {}
    if not all(_said_list(search.get(key)) for key in SEARCH_LISTS) or not all(
        _said(search.get(key)) for key in SEARCH_RULES
    ):
        problems.append(f"the survey does not state its search: {SEARCH_LISTS + SEARCH_RULES}")
    listed = search.get("words")
    words = {str(word) for word in listed} if isinstance(listed, list) else set()
    control = survey.get("control")
    control = control if isinstance(control, Mapping) else {}
    fired = control.get("fired_on")
    fired = fired if isinstance(fired, Mapping) else {}
    if not (
        _said(control.get("file"))
        and _SHA256.fullmatch(str(control.get("sha256", "")))
        and all(_said_list(fired.get(rule)) for rule in CONTROL_RULES)
    ):
        problems.append(
            "the survey names no control with a path that each rule of its search fired on: "
            f"{CONTROL_RULES}"
        )
    if str(control.get("word")) not in words:
        problems.append("the control names no listed word that the word search hit")
    surveyed_names = {str(wheel["name"]) for wheel in survey["wheels"]}
    if _file_pin(str(control.get("file", "")))[0] in surveyed_names:
        problems.append("the control is one of the surveyed wheels, so it controls nothing")
    pins = {r["name"]: r["pinned"] for r in data["readings"]}
    answers: dict[str, Mapping[str, Any]] = {}
    for wheel in survey["wheels"]:
        if wheel["name"] in answers:
            problems.append(f"the survey answers for {wheel['name']} twice")
        answers[wheel["name"]] = wheel
    missing = sorted(pins.keys() - answers.keys())
    if missing:
        problems.append(f"no survey answer for {missing}")
    stray = sorted(answers.keys() - pins.keys())
    if stray:
        problems.append(f"the survey answers for {stray}, which the snapshot does not read")
    for name, wheel in sorted(answers.items()):
        pinned = str(wheel.get("pinned"))
        if name in pins and pinned != pins[name]:
            problems.append(f"{name}: surveyed at {pinned}, the snapshot reads {pins[name]}")
        try:
            dt.date.fromisoformat(str(wheel.get("surveyed")))
        except ValueError:
            problems.append(f"{name}: no date is recorded for the answer")
        carries, kind = wheel.get("carries"), wheel.get("evidence_kind")
        projects = wheel.get("projects") or []
        read = _entries(wheel.get("files_read"))
        files = [str(f.get("file", "")) for f in read]
        wheels_named = sum(f.endswith(".whl") for f in files)
        if carries not in CARRIES:
            problems.append(f"{name}: the answer {carries!r} is not one of {CARRIES}")
        if kind not in EVIDENCE_KINDS or not _said(wheel.get("evidence")):
            problems.append(f"{name}: no evidence of a known kind is recorded")
        if (carries == "yes") != bool(projects) or not _projects_named(projects):
            problems.append(f"{name}: the answer {carries!r} does not match the projects named")
        # Project metadata lists no file, so it cannot show that a wheel carries nothing.
        if kind == METADATA_ONLY:
            if carries == "no":
                problems.append(f"{name}: project metadata cannot show a wheel carries nothing")
            if files:
                problems.append(f"{name}: a project-metadata answer names files it did not read")
        elif not files or not all(_file_pin(f) == (name, pinned) for f in files):
            problems.append(f"{name}: the files read are not named, or not at the surveyed pin")
        elif kind == TAG_AND_LIST and (
            carries != "no" or not all(f.endswith("-none-any.whl") for f in files)
        ):
            problems.append(f"{name}: a none-any answer needs a none-any wheel that carries none")
        elif (kind == SOURCE_TREE and not 0 < wheels_named < len(files)) or (
            kind == FILE_LIST and wheels_named != len(files)
        ):
            problems.append(f"{name}: the files read do not match the evidence kind {kind!r}")
        if not all(_SHA256.fullmatch(str(f.get("sha256", ""))) for f in read):
            problems.append(f"{name}: a file read has no sha256 recorded")
        for form in FORMS[1:]:
            answer = form_answer(wheel, form)
            said, named = answer.get("carries"), answer.get("projects") or []
            if said not in CARRIES:
                problems.append(f"{name}: no answer for {form} that is one of {CARRIES}")
                continue
            if (said == "yes") != bool(named) or not _projects_named(named):
                problems.append(f"{name}: the {form} answer {said!r} does not match the projects")
            if not _said(answer.get("evidence")):
                problems.append(f"{name}: no evidence is recorded for {form}")
            # A file list is what shows source or data, so an answer needs a wheel that was read.
            if said != "not established" and not wheels_named:
                problems.append(f"{name}: a {form} answer of {said!r} names no wheel it listed")
        try:
            forms_day = dt.date.fromisoformat(str(wheel.get("forms_surveyed")))
        except ValueError:
            problems.append(f"{name}: no date is recorded for the source and data answers")
        else:
            # An unreadable ``surveyed`` is reported above, and is not reported again here.
            try:
                early = forms_day < dt.date.fromisoformat(str(wheel.get("surveyed")))
            except ValueError:
                early = False
            if early:
                problems.append(f"{name}: the source and data answers are dated before the first")
        problems += [f"{name}: {problem}" for problem in _hit_problems(wheel, words, wheels_named)]
        route = wheel.get("route")
        if not _needs_route(wheel, labels):
            if route is not None:
                problems.append(f"{name}: a route is recorded where the page owes none")
        elif route not in ROUTES or not _said(wheel.get("route_reason")):
            problems.append(f"{name}: not designated and not shown to carry no code, with no route")
        elif route == "read" and not all(
            _said(_entries([wheel.get("read")])[0].get(field)) for field in READ_FIELDS
        ):
            problems.append(f"{name}: a read route must record {READ_FIELDS}")
    return problems


def _projects_named(projects: object) -> bool:
    """Whether ``projects`` is a list whose every entry is a mapping with a name and a version."""
    return isinstance(projects, list) and all(
        isinstance(p, Mapping) and _said(p.get("name")) and _said(p.get("version"))
        for p in projects
    )


def _hit_problems(wheel: Mapping[str, Any], words: set[str], wheels_named: int) -> list[str]:
    """Where a wheel's word-search hits and adapted modules are not recorded as the page needs.

    Both must be lists. Each hit names its files, the listed words that hit and a kind in
    ``HIT_KINDS``, and says what the hit is. Each adapted module names its file, the project the
    file names and the words that say so. The files recorded as adapted modules must be the same
    in both lists, so neither can be edited alone. A wheel that was not fetched records none.
    """
    hits, modules = wheel.get("word_hits"), wheel.get("adapted_modules")
    if not isinstance(hits, list) or not isinstance(modules, list):
        return ["the word-search hits and the adapted modules are not both recorded as lists"]
    if not wheels_named:
        return ["a wheel that was not fetched records a word-search hit"] if hits or modules else []
    problems = []
    for hit in _entries(hits):
        named = hit.get("words")
        if not (
            _said_list(hit.get("files"))
            and _said_list(named)
            and {str(word) for word in named or []} <= words
            and hit.get("kind") in HIT_KINDS
            and _said(hit.get("says"))
        ):
            problems.append(f"a word-search hit is not fully recorded: {hit.get('files')!r}")
    if not all(
        _said(m.get(key)) for m in _entries(modules) for key in ("file", "project", "words")
    ):
        problems.append("an adapted module lacks its file, its project or its words")
    as_hits = {
        str(file)
        for hit in _entries(hits)
        if hit.get("kind") == ADAPTED and isinstance(hit.get("files"), list)
        for file in hit["files"]
    }
    as_modules = {str(m.get("file")) for m in _entries(modules)}
    if as_hits != as_modules:
        problems.append(
            f"the adapted modules and the hits of that kind differ on {sorted(as_hits ^ as_modules)}"
        )
    return problems


_FORM_WORDS = {"compiled": "compiled code", "source": "source code", "data": "data"}

#: The page's unit, stated once: what counts as a bundled copy. The guard holds this exact text.
SURVEY_UNIT = (
    "**This page's unit.** A bundled copy counts when it is a package, a library tree or a data "
    "set of another project, in any form. The forms are compiled code, source code and data. A "
    "single module adapted from another project is not that unit. It is recorded where the "
    "search found one, and is owed no route. Lines copied into a wheel's own module are not "
    "counted."
)

#: The page's rule for which wheel is owed a route, stated once. The guard holds this exact text.
SURVEY_CRITERION = (
    "**This page's criterion.** A wheel that is not designated is owed a route when it carries "
    "another project's code, compiled or source. A wheel that carries only another project's "
    "data is listed below with what it carries. It is owed no route, because data holds another "
    "project's tables and none of its logic. That holds where the tables are kept as generated "
    "Python modules too. That line is this page's choice, and a reader can draw it elsewhere: "
    "data still decides things, as a list of root certificates decides what is trusted. A wheel "
    "whose answer is not established, for any form, is treated as carrying code."
)


def _carried(wheel: Mapping[str, Any], forms: Iterable[str] = ("compiled",)) -> str:
    """What the wheel carries in ``forms``, for a table cell: each project, and its version."""
    words = {"not established": ", version not established", "as locked": ""}
    return (
        "; ".join(
            # ``display`` is the whole phrase, for a project whose name and version do not join.
            str(p["display"])
            if _said(p.get("display"))
            else str(p.get("name")) + words.get(str(p.get("version")), f" {p.get('version')}")
            for form in forms
            for p in _entries(form_answer(wheel, form).get("projects"))
        )
        or "not established"
    )


def _days(days: Iterable[object]) -> str:
    """One day, or the span of days where some answers were made again later."""
    span = sorted({str(day) for day in days})
    return f"on {span[0]}" if len(span) == 1 else f"between {span[0]} and {span[-1]}"


def _form_evidence(wheel: Mapping[str, Any], form: str) -> str:
    """The kind of evidence behind one form's answer, for a table cell."""
    if form == "compiled":
        return str(wheel.get("evidence_kind"))
    listed = any(str(f.get("file", "")).endswith(".whl") for f in _entries(wheel.get("files_read")))
    # The source and data search lists the wheel and opens files in it, so it is more than a list.
    return "wheel file list and files opened" if listed else "wheel not fetched"


def survey_counts(wheels: Iterable[Mapping[str, Any]], form: str) -> str:
    """The page's count sentence for one form, with its arithmetic."""
    said = [form_answer(w, form).get("carries") for w in wheels]
    # Anything that is not a plain yes or no counts as not established, a missing answer too, so
    # the arithmetic printed is always true.
    yes, no = said.count("yes"), said.count("no")
    unknown = len(said) - yes - no
    return (
        f"**Another project's {_FORM_WORDS[form]}: found in {yes} of {len(said)}. Not found in "
        f"{no}. Not established: {unknown}. {yes} plus {no} plus {unknown} is {len(said)}.**"
    )


def _listed_count(search: Mapping[str, Any], key: str) -> str:
    """How many entries the record's search lists under ``key``, or that it lists none."""
    listed = search.get(key)
    return str(len(listed)) if isinstance(listed, list) and listed else "no recorded"


def _first(paths: object) -> str:
    """The first path a control rule fired on, or that none is recorded."""
    return str(paths[0]) if isinstance(paths, list) and paths else "not recorded"


def hit_counts(wheels: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """How many files the word search hit, by the kind each was recorded as."""
    counts = dict.fromkeys(HIT_KINDS, 0)
    for wheel in wheels:
        for hit in _entries(wheel.get("word_hits")):
            files, kind = hit.get("files"), hit.get("kind")
            # A kind that is not text cannot be a key, and is reported by ``_hit_problems``.
            if isinstance(kind, str) and kind in counts and isinstance(files, list):
                counts[kind] += len(files)
    return counts


def _render_adapted(wheels: list[Mapping[str, Any]], labels: Mapping[str, str]) -> list[str]:
    """What the word search hit: its counts, the adapted modules, and a wheel's own second line."""
    counts = hit_counts(wheels)
    searched = sum(
        any(str(f.get("file", "")).endswith(".whl") for f in _entries(w.get("files_read")))
        for w in wheels
    )
    out = [
        "",
        f"The word search ran over the {searched} wheels that were fetched. It hit "
        + _count(sum(counts.values()), "file", "files")
        + f". Counted in files: {counts[ADAPTED]} hold a single module adapted from another "
        f"project, {counts[COPIED_LINES]} hold lines copied into a wheel's own module, and "
        f"{counts[PROSE]} hold prose that marks no copy, such as a project's own licence "
        "header. The record lists each hit under its wheel.",
    ]
    rows = [
        f"| `{w['name']}` | `{m.get('file')}` | {m.get('project')} | "
        f"{'yes, ' + labels[w['name']] if w['name'] in labels else 'no'} |"
        for w in wheels
        for m in _entries(w.get("adapted_modules"))
    ]
    if rows:
        out += [
            "",
            "**Single modules adapted from another project, as found:**",
            "",
            "| Component | File | The project the file names | Designated above |",
            "|---|---|---|---|",
            *rows,
            "",
            "Each row is what the file says of itself. No file was compared with the project it "
            "names, and no advisory for that project was read. Under the unit above, none of "
            "these moves a count or owes a route. The list is what the word search found, and "
            "it is not a full list: a module adapted from another project that does not say so "
            "in one of the listed words is not in it.",
        ]
    for wheel in wheels:
        for line in _entries(wheel.get("own_release_lines")):
            out += [
                "",
                f"`{wheel['name']}` also holds a second release line of its own project: "
                f"`{line.get('path')}`, {line.get('files')} files, version {line.get('version')}. "
                "That is the same project, so it is not counted as another project's source. An "
                f"advisory against that line would name `{wheel['name']}`, at that line's own "
                "version numbers. The reading above asks about the pinned version only, so no "
                "advisory was read at that line's version.",
            ]
    return out


def _render_survey(survey: Mapping[str, Any], labels: Mapping[str, str]) -> list[str]:
    """The survey subsection: what was found in each form, on what evidence, and each route."""
    wheels = sorted(survey["wheels"], key=lambda w: str(w["name"]))
    size = len(wheels)
    routed = [w for w in wheels if _needs_route(w, labels)]
    control = survey.get("control")
    control = control if isinstance(control, Mapping) else {}
    fired = control.get("fired_on")
    fired = fired if isinstance(fired, Mapping) else {}
    search = survey.get("search")
    search = search if isinstance(search, Mapping) else {}

    def route(wheel: Mapping[str, Any]) -> str:
        if wheel["name"] in labels:
            return f"designated, {labels[wheel['name']]}"
        if not carries_code(wheel):
            return "none owed: data only"
        words = {"highlight": "highlighted below", "read": "read below"}
        return words.get(str(wheel.get("route")), "none")

    out = [
        SURVEY_HEADING,
        "",
        "The vulnerability-history test reads advisories by PyPI name. This survey asks what "
        f"that test cannot: whether each of the {size} pinned wheels carries a bundled copy of "
        "another separately distributed project, and in what form. The "
        f"compiled-code answers were made by hand {_days(w.get('surveyed') for w in wheels)}, "
        f"and the source and data answers {_days(w.get('forms_surveyed') for w in wheels)}, "
        "against the pins the snapshot reads. The evidence, the files read and their hashes are "
        "recorded in "
        "[`security/bundled-code-survey.json`](../security/bundled-code-survey.json). A run of "
        "the script does not repeat it.",
        "",
        SURVEY_UNIT,
        "",
        SURVEY_CRITERION,
    ]
    for form in FORMS:
        out += ["", survey_counts(wheels, form)]
    out += [
        "",
        "Each count is what the search described below found, and not a statement of what a "
        "wheel holds. The search reads names, sizes and marked text. It can miss a copy that has "
        "no marker, so a wheel counted as not found can still carry one.",
        "",
        "The table has one row for each wheel and form where the answer is not a plain no.",
        "",
        "| Component | Pinned | Form | Carries | Evidence | Route |",
        "|---|---|---|---|---|---|",
    ]
    out += [
        f"| `{w['name']}` | {w.get('pinned')} | {_FORM_WORDS[form]} | {_carried(w, (form,))} "
        f"| {_form_evidence(w, form)} | {route(w)} |"
        for w in wheels
        for form in FORMS
        if form_answer(w, form).get("carries") != "no"
    ]
    for kind in EVIDENCE_KINDS:
        names = [
            f"`{w['name']}`"
            for w in wheels
            if w.get("carries") == "no" and w.get("evidence_kind") == kind
        ]
        if names:
            out += [
                "",
                _count(len(names), "wheel was", "wheels were")
                + f" found to carry no compiled code, on the evidence of the {kind}: "
                + ", ".join(names)
                + ".",
            ]
    clear = sum(not carries_anything(w) for w in wheels)
    out += [
        "",
        _count(clear, "wheel has", "wheels have")
        + " no row in the table: the search found no package, library tree or data set of "
        "another project in them, in any form.",
    ]
    out += _render_adapted(wheels, labels)
    data_only = [
        w for w in wheels if not carries_code(w) and form_answer(w, "data").get("carries") == "yes"
    ]
    if data_only:
        loose = [f"`{w['name']}`" for w in data_only if w["name"] not in labels]
        out += [
            "",
            _count(len(data_only), "wheel carries", "wheels carry")
            + " another project's data and none of its code: "
            + ", ".join(f"`{w['name']}`" for w in data_only)
            + ". "
            + (
                f"Not designated among them: {', '.join(loose)}. Under the criterion above, "
                "that owes no route."
                if loose
                else "Each of them is designated."
            )
            + " No notice about any of that data was read.",
        ]
    out += [
        "",
        "Each answer rests on the evidence the record names. A wheel tagged `none-any` had its "
        "file list read as well as its tag. For any other wheel that was fetched, one Linux "
        "x86_64 wheel and the Windows amd64 wheel were read, where the lock carries them. A "
        "file list shows a bundled library and cannot show code linked into an extension, so "
        "the pinned source distribution was read too. A wheel the record does not name was not "
        "read, and can carry something else. That holds for another platform, and for a second "
        "Linux x86_64 wheel where the lock carries more than one.",
        "",
        "The source and data answers rest on the same wheels, fetched again. The search looked "
        f"for a directory with one of {_listed_count(search, 'directories')} vendoring names, a "
        "top-level name beyond the project's own, a licence file named for another project, a "
        "large file that is not a Python module, and any of "
        f"{_listed_count(search, 'words')} marker words in the text files. The record gives "
        "the names, the size and the words under `search`. A Python module was opened as a "
        "possible table only where its name or size suggested one, which is a judgement and "
        "not an exact rule. No file was compared with the project it names.",
        "",
        "As a control, the same search was run over "
        f"`{control.get('file', 'not recorded')}`, a wheel known to vendor source and not one "
        "of the wheels surveyed. "
        + " ".join(
            f"The {words} fired on `{_first(fired.get(rule))}`."
            for rule, words in (
                ("directory", "directory search"),
                ("licence file", "licence-file search"),
                ("data", "size search"),
                ("words", "word search"),
            )
        )
        + " The top-level-name search has no control: that wheel has one top-level name, its "
        "own.",
    ]
    # The two kinds of evidence that fall short of the paragraphs above, each naming its wheels.
    for kind, lead, rests_on in (
        (
            FILE_LIST,
            "No source distribution was read for {}.",
            "wheel file lists alone, which cannot show what is linked into a compiled file.",
        ),
        (
            METADATA_ONLY,
            "No wheel was fetched for {}.",
            "PyPI project metadata, which lists no file. What the table names for such a wheel "
            "is the least it carries: nothing else was looked for. For the same reason, no "
            "source or data answer is established for such a wheel.",
        ),
    ):
        names = [f"`{w['name']}`" for w in wheels if w.get("evidence_kind") == kind]
        if names:
            whose = (
                "Its compiled answer rests" if len(names) == 1 else "Their compiled answers rest"
            )
            out += ["", f"{lead.format(_series(names, 'or'))} {whose} on {rests_on}"]
    out += [
        "",
        "A designated wheel is already highlighted, by its tier. No carried project's advisories "
        "were read for a designated wheel. "
        + _count(len(routed), "wheel is", "wheels are")
        + " not designated and counted as carrying another project's code. Each takes one of "
        "two routes: this page highlights it as risky on what it carries, or reads the carried "
        "project's own advisories.",
    ]
    highlighted = [w for w in routed if w.get("route") == "highlight"]
    if highlighted:
        out += [
            "",
            "**Highlighted as risky on what it carries:**",
            "",
            "| Component | Carries | Why |",
            "|---|---|---|",
        ]
        out += [
            f"| `{w['name']}` | {_carried(w, CODE_FORMS)} | {w.get('route_reason')} |"
            for w in highlighted
        ]
        out += [
            "",
            "No advisory for a carried project was read for these. A reader who needs that has "
            "to check the carried project's own security notices against the version the pinned "
            "wheel carries. Where the table gives no version, the survey did not establish one. "
            "Highlighting here does not move a wheel into a tier.",
        ]
    read = [w for w in routed if w.get("route") == "read"]
    if read:
        out += [
            "",
            "**Read from the carried project's own advisories:**",
            "",
            "| Component | Carries | Source | Date read | Version read | Result |",
            "|---|---|---|---|---|---|",
        ]
        out += [
            f"| `{w['name']}` | {_carried(w, CODE_FORMS)} | "
            + " | ".join(str(_entries([w.get("read")])[0].get(field)) for field in READ_FIELDS)
            + " |"
            for w in read
        ]
    return out


# --- The page ------------------------------------------------------------------------------------

_TIER_HEADING = re.compile(r"^## Tier (\d+)\b")
_EXTRA_HEADING = re.compile(r"^## The `([^`]+)` extra$")
_FIRST_CELL_NAMES = re.compile(r"^\|\s*((?:`[a-z0-9][a-z0-9._-]*`,?\s*)+)\|")


def designation_labels(page: str) -> dict[str, str]:
    """Name to where the page's tiers designate it: ``tier N``, or ``the `X` extra``.

    Reads only the designated tables above the readings heading: a tier's table, or the
    ``### Designated`` table under an extra's own ``## The `X` extra`` heading. Any other heading
    ends the current label, so a not-designated table is never read as a designation.
    """
    labels: dict[str, str] = {}
    label: str | None = None
    extra: str | None = None
    for line in page.splitlines():
        if line == READINGS_HEADING:
            break
        if line.startswith("## "):
            tier, named = _TIER_HEADING.match(line), _EXTRA_HEADING.match(line)
            label = f"tier {tier[1]}" if tier else None
            extra = named[1] if named else None
            continue
        if line.startswith("#"):
            label = f"the `{extra}` extra" if extra and line == "### Designated" else None
            continue
        row = _FIRST_CELL_NAMES.match(line)
        if label and row:
            for cell in row[1].split(","):
                labels[runtime_closure.canonical_name(cell.strip(" `"))] = label
    return labels


def _count(n: int, one: str, many: str) -> str:
    """``n`` with the noun phrase that agrees with it: "1 advisory carries", "2 advisories carry"."""
    return f"{n} {one if n == 1 else many}"


def _series(items: list[str], joiner: str) -> str:
    """Items as "a, b <joiner> c"."""
    return f" {joiner} ".join([", ".join(items[:-1]), items[-1]] if len(items) > 1 else items)


def _either(words: Iterable[str]) -> str:
    """Backticked words as "`a`, `b` or `c`"."""
    return _series([f"`{w}`" for w in words], "or")


def render_section(
    data: Mapping[str, Any], labels: Mapping[str, str], survey: Mapping[str, Any]
) -> str:
    """The page section between the markers: the snapshot, the page's tier labels and the survey."""
    rules = data["criteria"]
    as_of = dt.date.fromisoformat(data["snapshot_date"])
    readings = data["readings"]
    size = len(readings)
    added = [r for r in readings if r["added_by"]]
    additions = {
        extra: [f"`{r['name']}`" for r in readings if extra in r["added_by"]]
        for extra in data["population"]["extras"]
    }
    flagged = {axis: [r for r in readings if r["risky"][axis]] for axis in AXES}
    clean = [r for r in readings if not any(r["risky"].values())]

    def designated(name: str) -> str:
        return f"yes, {labels[name]}" if name in labels else "no"

    out = [
        f"> **Snapshot date: {data['snapshot_date']}. Re-read by: {data['reread_by']}.** Every "
        "reading below comes from public data on the snapshot date: PyPI, the Python Package "
        "Index, and OSV, the Open Source Vulnerabilities database. It covers the versions the "
        "closure files pinned that day. Support status and advisory history go stale. After the "
        "re-read date, treat this section as out of date until "
        "[`scripts/security/component_readings.py`](../scripts/security/component_readings.py) "
        "runs again.",
        "",
        "The readings, their sources and their windows are recorded in "
        "[`security/risky-component-readings.json`](../security/risky-component-readings.json).",
        "",
        "### What is read, and the test for each example",
        "",
        f"All {size} distributions this page assesses are read: the {size - len(added)} in the "
        f"core closure and the {len(added)} that the assessed extras add to it. "
        + " ".join(
            f"The `{extra}` extra adds {len(names)}"
            + (f": {_series(names, 'and')}." if names else ".")
            for extra, names in additions.items()
        )
        + " That is not only the designated part. A library can be risky on these examples even "
        "where the tiers did not designate it.",
        "",
        "| Example | A component is risky on it when | Source |",
        "|---|---|---|",
        "| Poorly maintained | it has uploaded no release to PyPI in the "
        f"{rules['maintenance_window_days']} days before the snapshot. A pre-release counts; a "
        "release whose every file is yanked does not | PyPI JSON API |",
        "| Unsupported or end of life | its PyPI project status, the marker Python standard "
        "PEP 792 defines, is "
        + _either(rules["unsupported_statuses"])
        + f", or its latest release is classified `{rules['inactive_classifier']}`, or the "
        "pinned version is yanked or no longer listed | PyPI JSON and Simple APIs |",
        "| A history of significant vulnerabilities | at least one advisory rated "
        + _either(rules["significant_severities"])
        + f" was first published in the {rules['advisory_window_days']} days (about "
        f"{round(int(rules['advisory_window_days']) / 365)} years) before the snapshot | OSV API |",
        "",
        "OSV often records one flaw twice, once from the GitHub advisory database and once from the "
        "Python advisory database. Records that name each other count once. A record does not count "
        "when every GitHub advisory it names about that package has been withdrawn.",
        "",
        "The severity is the GitHub advisory database's rating. Where it gives none, the script "
        "scores the record's CVSS 3 vector and rates it on that system's scale. CVSS is the Common "
        "Vulnerability Scoring System. An advisory with neither does not count. The ones in the "
        "window are named below so a reader can judge them.",
        "",
        "OSV matches an advisory to a component by its PyPI name. A flaw in something a wheel "
        "carries inside it from another project shows up here only when an advisory names the "
        "PyPI package. That holds for a compiled library, for a copy of another project's "
        "source, and for its data. So nothing below shows that what a wheel carries is free of "
        f"known flaws. *{SURVEY_HEADING.removeprefix('### ')}*, further down, says which wheels "
        "carry another project in any of those forms, and what this page does about each.",
        "",
        "These tests are mechanical. A small library that is finished can trip the first one "
        "without being neglected. The reading says where to look; it does not say the library is "
        "broken.",
        "",
        f"**Risky on at least one example: {size - len(clean)} of {size}. On maintenance: "
        f"{len(flagged['maintenance'])}. On support: {len(flagged['support'])}. On vulnerability "
        f"history: {len(flagged['advisory_history'])}. Not risky on any: {len(clean)}. "
        f"{size - len(clean)} plus {len(clean)} is {size}.**",
        "",
        "### Poorly maintained",
        "",
    ]
    if flagged["maintenance"]:
        out += ["| Component | Newest release | Designated above |", "|---|---|---|"]
        out += [
            f"| `{r['name']}` | {r['newest_upload'] or 'none'} | {designated(r['name'])} |"
            for r in flagged["maintenance"]
        ]
    else:
        out.append("None on the snapshot date.")
    out += ["", "### Unsupported or end of life", ""]
    if flagged["support"]:
        out += [
            "| Component | Project status | Inactive classifier | Pinned version yanked "
            "| Designated above |",
            "|---|---|---|---|---|",
        ]
        out += [
            f"| `{r['name']}` | {r['project_status']} | "
            f"{'yes' if rules['inactive_classifier'] in r['development_status'] else 'no'} | "
            f"{'yes' if r['pinned_yanked'] else 'no'} | {designated(r['name'])} |"
            for r in flagged["support"]
        ]
    else:
        out.append("None on the snapshot date.")
    out += ["", "### A history of significant vulnerabilities", ""]
    if flagged["advisory_history"]:
        out += [
            "| Component | Significant in the window | Newest of those | Designated above |",
            "|---|---|---|---|",
        ]
        for r in flagged["advisory_history"]:
            hits = significant_in_window(r, as_of, rules)
            # The default only shows on a hand-edited snapshot; the guard names that case.
            newest = max((a["published"] for a in hits), default="none")
            out.append(f"| `{r['name']}` | {len(hits)} | {newest} | {designated(r['name'])} |")
    else:
        out.append("None on the snapshot date.")
    out.append("")
    open_hits = [(a, r["name"]) for r in readings for a in r["advisories_affecting_pin"]]
    if open_hits:
        out.append(
            "On the snapshot date OSV listed "
            + _count(len(open_hits), "advisory", "advisories")
            + " against a pinned version: "
            + "; ".join(f"`{a}` against `{n}`" for a, n in open_hits)
            + ". `.github/SECURITY.md` says how an advisory against a component is handled."
        )
    else:
        out.append(
            f"On the snapshot date OSV listed no advisory against any pinned version, in any of "
            f"the {size}. The table above counts past advisories only."
        )
    unrated = [
        (a["id"], r["name"])
        for r in readings
        for a in in_window(r, as_of, rules)
        if a["severity"] == "UNRATED"
    ]
    out.append("")
    if unrated:
        out.append(
            _count(len(unrated), "advisory in the window carries", "advisories in the window carry")
            + " no rating from either source, so the test above does not count "
            + ("it" if len(unrated) == 1 else "them")
            + ": "
            + "; ".join(f"`{a}` against `{n}`" for a, n in unrated)
            + "."
        )
    else:
        out.append("Every advisory in the window carries a rating from one of the two sources.")
    dropped = [(d["id"], d["twin"], r["name"]) for r in readings for d in r["advisories_dropped"]]
    if dropped:
        out += [
            "",
            _count(len(dropped), "record was", "records were")
            + " left out because every GitHub advisory about the package "
            + ("it names is" if len(dropped) == 1 else "they name is")
            + " withdrawn: "
            + "; ".join(f"`{i}` against `{n}`, twin of `{w}`" for i, w, n in dropped)
            + ".",
        ]
    unresolved = [
        (u["id"], u["twin"], r["name"]) for r in readings for u in r["advisories_unresolved"]
    ]
    if unresolved:
        out += [
            "",
            _count(len(unresolved), "record names", "records name")
            + " a GitHub advisory that OSV does not have, so its status is unknown. "
            + ("It still counts" if len(unresolved) == 1 else "They still count")
            + ": "
            + "; ".join(f"`{i}` against `{n}`, naming `{w}`" for i, w, n in unresolved)
            + ".",
        ]
    out += ["", "### Not risky on any of the three", "", "| Components | Designated above |"]
    out.append("|---|---|")
    for yes in (True, False):
        names = [r["name"] for r in clean if (r["name"] in labels) == yes]
        if names:
            out.append(f"| {', '.join(f'`{n}`' for n in names)} | {'yes' if yes else 'no'} |")
    out += [
        "",
        "Not risky here means that none of the three tests fired. It is not a clean result "
        "beyond them: the vulnerability-history test reads advisories by PyPI name only, as "
        "stated with the tests above.",
    ]
    risky = [r for r in readings if any(r["risky"].values())]
    both = [r for r in risky if r["name"] in labels]
    only = [r for r in risky if r["name"] not in labels]

    def axes(r: Mapping[str, Any]) -> str:
        return " and ".join(_AXIS_WORDS[a] for a in AXES if r["risky"][a])

    out += [
        "",
        "### How this reading and the tiers fit together",
        "",
        "The tiers stay the designation. This reading does not move a component into or out of "
        "them. Where the two agree is where to look first.",
        "",
    ]
    if both:
        out.append(
            _count(len(both), "designated component is", "designated components are")
            + " also risky on an ASVS example:"
        )
        out += ["", "| Component | Designated above | Risky on |", "|---|---|---|"]
        out += [f"| `{r['name']}` | {labels[r['name']]} | {axes(r)} |" for r in both]
    else:
        out.append("No designated component is risky on an ASVS example.")
    out.append("")
    if only:
        out.append(
            _count(len(only), "component is", "components are")
            + " risky here and not designated above: "
            + ", ".join(f"`{r['name']}` ({axes(r)})" for r in only)
            + ". The tiers did not designate "
            + ("it" if len(only) == 1 else "them")
            + " under the exposure criterion. The reading names "
            + ("it" if len(only) == 1 else "them")
            + " so that choice stays visible, and a reviewer can revisit it."
        )
    else:
        out.append("Every component risky on an ASVS example is also designated above.")
    out += ["", *_render_survey(survey, labels)]
    if added:
        out += [
            "",
            EXTRAS_HEADING,
            "",
            "The same readings again, for the names an assessed extra adds to the core closure. "
            "The advisory column is how many advisories this reading counted under that PyPI "
            "name, of any severity and any date, after the merging and the leaving out described "
            "with the tests above. Read it under the limit stated there: a 0 is about the name, "
            "not about the code inside the wheel.",
            "",
            "| Component | Added by | Pinned | Newest release | Advisories counted under the name "
            "| Risky on |",
            "|---|---|---|---|---|---|",
        ]
        out += [
            f"| `{r['name']}` | {_series([f'`{e}`' for e in r['added_by']], 'and')} | "
            f"{r['pinned']} | {r['newest_upload'] or 'none'} | {len(r['advisories'])} | "
            f"{axes(r) or 'none'} |"
            for r in added
        ]
    return "\n".join(_wrap(line) for line in out)


def _wrap(line: str) -> str:
    """A prose line wrapped at the page's width; a table row, heading or blank line as it is."""
    if not line or line.startswith(("|", "#")):
        return line
    prefix = "> " if line.startswith("> ") else ""
    lines = textwrap.wrap(
        line.removeprefix(prefix),
        width=_PAGE_WIDTH - len(prefix),
        break_long_words=False,
        break_on_hyphens=False,
    )
    # A continuation line that opens like a list item or heading ("1. On support", "- x") would
    # render as one and break the paragraph, so pull the previous line's last word down onto it.
    for i in range(1, len(lines)):
        while _BLOCK_START.match(lines[i]) and " " in lines[i - 1]:
            head, _, word = lines[i - 1].rpartition(" ")
            lines[i - 1], lines[i] = head, f"{word} {lines[i]}"
    return "\n".join(prefix + ln for ln in lines)


def _marker_bounds(page: str) -> tuple[int, int]:
    """Where the BEGIN line starts and the END line starts, each counted from its leading newline.

    Offsets into ``page``, not successive partitions: an empty section puts the two lines next to
    each other and they share one newline, which a second partition would never find.
    """
    begin, end = f"\n{BEGIN}\n", f"\n{END}\n"
    for marker in (begin, end):
        if page.count(marker) != 1:
            raise ValueError(f"the page must carry {marker.strip()!r} once, on its own line")
    start = page.index(begin)
    if page.find(end, start + len(begin) - 1) < 0:
        raise ValueError("the page must put the BEGIN marker before the END marker")
    return start, page.index(end, start + len(begin) - 1)


def section_of(page: str) -> str:
    """The text between the markers, without their own lines or the blank lines around it."""
    start, stop = _marker_bounds(page)
    return page[start + len(BEGIN) + 2 : stop].strip("\n")


def render_page(page: str, data: Mapping[str, Any], survey: Mapping[str, Any]) -> str:
    """``page`` with the section between the markers re-rendered from ``data`` and ``survey``."""
    start, stop = _marker_bounds(page)
    body = render_section(data, designation_labels(page), survey)
    return f"{page[:start]}\n{BEGIN}\n\n{body}\n\n{END}\n{page[stop + len(END) + 2 :]}"


def _write_text(path: Path, text: str) -> None:
    """Write ``text`` keeping the file's current line ending, so a Windows run makes no churn."""
    crlf = path.exists() and b"\r\n" in path.read_bytes()
    path.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--render-only",
        action="store_true",
        help="re-render the page section from the tracked snapshot; no network",
    )
    args = parser.parse_args(argv)
    # Read before the network run, so a broken hand-made survey stops it before the long read.
    text = PAGE.read_text(encoding="utf-8")
    survey = json.loads(SURVEY.read_text(encoding="utf-8"))
    if args.render_only:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    else:
        try:
            # Today, never a chosen date: PyPI and OSV answer only with today's classifiers,
            # statuses and yanks, so an earlier date would label today's data with it.
            data = snapshot(dt.datetime.now(dt.UTC).date())
        except (OSError, http.client.HTTPException, ValueError, KeyError) as exc:
            # Nothing is written on a failed read, so a half-fetched snapshot never lands.
            print(f"component readings failed, nothing written: {exc}", file=sys.stderr)
            return 1
    page = render_page(text, data, survey)
    if not args.render_only:
        _write_text(SNAPSHOT, json.dumps(data, indent=2) + "\n")
    _write_text(PAGE, page)
    counts = {axis: sum(r["risky"][axis] for r in data["readings"]) for axis in AXES}
    print(f"{len(data['readings'])} readings as of {data['snapshot_date']}: {counts}")
    # The survey is made by hand, so a re-read that moved a pin or a name leaves it behind. Say so
    # here; tests/test_risky_component_designation.py fails on the same list.
    behind = survey_problems(survey, data, designation_labels(text))
    for problem in behind:
        print(f"{SURVEY.name} needs a new survey: {problem}", file=sys.stderr)
    return 1 if behind else 0


if __name__ == "__main__":
    sys.exit(main())
