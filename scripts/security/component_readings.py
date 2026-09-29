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

THE POPULATION is every name in ``security/runtime-closure-sqlserver.txt``: the core runtime closure
plus the two names the ``sqlserver`` extra adds, which is everything the page assesses. It is the
whole assessed closure, not only the designated set, because a component can be risky by maintenance
or history even where the exposure criterion did not designate it.

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

A full run needs the network and runs by hand, never in CI. Standard library only, like
``runtime_closure.py`` beside it, so it runs under a bare ``python3``:

    python scripts/security/component_readings.py

``--as-of YYYY-MM-DD`` fixes the snapshot date (default: today, UTC). The readings are dated to that
day and to the pins the closure file held on it; a later lock bump does not change them until the
next run. ``--render-only`` re-renders the page section from the tracked snapshot with no network,
for when the tiers change and the readings do not.
"""

from __future__ import annotations

import argparse
import datetime as dt
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
POPULATION = runtime_closure.SQLSERVER_CLOSURE
CORE = runtime_closure.CLOSURE
SNAPSHOT = ROOT / "security" / "risky-component-readings.json"
PAGE = ROOT / "docs" / "RISKY-COMPONENTS.md"

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
PYPI_SIMPLE = "https://pypi.org/simple/{name}/"
OSV_QUERY = "https://api.osv.dev/v1/query"

#: The windows and thresholds. They are recorded in the snapshot, and the guard re-derives every
#: verdict from the recorded copy, so changing one here changes nothing until the next run.
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
#: The heading that ends the page's tier tables. The designation labels are read above it.
READINGS_HEADING = "## Risky by ASVS's own examples, read from public data"


class Advisory(TypedDict):
    """One advisory, after the OSV records that alias each other are merged into one."""

    id: str
    severity: str
    published: str


class Reading(TypedDict):
    """Everything recorded for one component.

    ``newest_upload``, ``development_status``, ``project_status``, ``pinned_yanked`` and
    ``advisories`` decide the verdicts in ``risky``. The rest is context for a reader.
    """

    name: str
    pinned: str
    in_core: bool
    latest_version: str
    newest_upload: str
    releases_in_maintenance_window: int
    development_status: list[str]
    project_status: str
    pinned_yanked: bool
    requires_python_latest: str
    advisories: list[Advisory]
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

    Union-find over each record's id and aliases (a CVE id links a GHSA to its PYSEC twin).
    Withdrawn records are dropped first.
    """
    parent: dict[str, str] = {}

    def find(key: str) -> str:
        while parent.setdefault(key, key) != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    records = [v for v in vulns if not v.get("withdrawn")]
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


def _group_severity(group: list[dict[str, Any]]) -> str:
    """The highest qualitative severity any member records, or ``UNRATED`` when none does.

    Only the GitHub advisory database writes a word here. A group with no GHSA member and only a
    CVSS vector stays ``UNRATED`` rather than being scored by this script.
    """
    rated = [str((r.get("database_specific") or {}).get("severity", "")).upper() for r in group]
    ranked = [s for s in rated if s in _SEVERITY_RANK]
    return max(ranked, key=_SEVERITY_RANK.__getitem__) if ranked else "UNRATED"


def advisories(vulns: Iterable[dict[str, Any]]) -> list[Advisory]:
    """OSV records as merged advisories, sorted by id: one per flaw, dated by its first record."""
    out: list[Advisory] = [
        {
            "id": _representative(group),
            "severity": _group_severity(group),
            "published": min(r["published"][:10] for r in group if r.get("published")),
        }
        for group in _merge_aliases(vulns)
        if any(r.get("published") for r in group)
    ]
    return sorted(out, key=lambda a: a["id"])


def _osv_all(name: str, version: str | None, fetch: Fetch) -> list[dict[str, Any]]:
    """Every OSV record for ``name`` on PyPI, or for that one version, following page tokens."""
    query: dict[str, Any] = {"package": {"name": name, "ecosystem": "PyPI"}}
    if version is not None:
        query["version"] = version
    vulns: list[dict[str, Any]] = []
    while True:
        reply = fetch(OSV_QUERY, json.dumps(query).encode("utf-8"))
        vulns += reply.get("vulns") or []
        token = reply.get("next_page_token")
        if not token:
            return vulns
        query["page_token"] = token


def in_window(
    reading: Mapping[str, Any], as_of: dt.date, criteria: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    """The reading's advisories first published inside the advisory window ending ``as_of``."""
    floor = as_of - dt.timedelta(days=int(criteria["advisory_window_days"]))
    return [a for a in reading["advisories"] if dt.date.fromisoformat(a["published"]) >= floor]


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
    return {
        "maintenance": dt.date.fromisoformat(reading["newest_upload"]) < maintenance_floor,
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
    name: str, pinned: str, *, in_core: bool, as_of: dt.date, fetch: Fetch = fetch_json
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
    past = [d for d in uploads.values() if d <= as_of]
    if not past:
        raise ValueError(f"{name}: PyPI lists no unyanked release on or before {as_of}")
    if pinned not in releases:
        raise ValueError(f"{name}: PyPI has no release {pinned}, the version the closure pins")
    window_floor = as_of - dt.timedelta(days=MAINTENANCE_WINDOW_DAYS)
    pinned_files = releases[pinned]

    reading: Reading = {
        "name": name,
        "pinned": pinned,
        "in_core": in_core,
        "latest_version": str(info["version"]),
        "newest_upload": max(past).isoformat(),
        "releases_in_maintenance_window": sum(window_floor <= d for d in past),
        "development_status": sorted(
            c for c in info.get("classifiers") or [] if c.startswith("Development Status ::")
        ),
        "project_status": str((simple.get("project-status") or {}).get("status", "absent")),
        "pinned_yanked": bool(pinned_files) and all(f.get("yanked") for f in pinned_files),
        "requires_python_latest": str(info.get("requires_python") or ""),
        "advisories": advisories(_osv_all(name, None, fetch)),
        "advisories_affecting_pin": [a["id"] for a in advisories(_osv_all(name, pinned, fetch))],
        "risky": {},
    }
    reading["risky"] = classify(reading, as_of, criteria())
    return reading


def snapshot(as_of: dt.date, fetch: Fetch = fetch_json) -> dict[str, Any]:
    """The whole dated snapshot: provenance, criteria, and one reading per population member."""
    members = runtime_closure.closure_pins(POPULATION)
    core = runtime_closure.closure_pins(CORE)
    return {
        "subject": "Public-metadata readings of each runtime component on ASVS 5.0.0 V15.1's "
        "risky-component examples (BACKLOG #1189, ASVS 15.1.4)",
        "snapshot_date": as_of.isoformat(),
        "reread_by": (as_of + dt.timedelta(days=REREAD_INTERVAL_DAYS)).isoformat(),
        "population": POPULATION.relative_to(ROOT).as_posix(),
        "sources": {
            "pypi_json": PYPI_JSON,
            "pypi_simple": PYPI_SIMPLE + " (Accept: application/vnd.pypi.simple.v1+json)",
            "osv_query": OSV_QUERY,
        },
        "criteria": criteria(),
        "generator": "python scripts/security/component_readings.py",
        "readings": [
            read_component(n, v, in_core=n in core, as_of=as_of, fetch=fetch)
            for n, v in sorted(members.items())
        ],
    }


# --- The page ------------------------------------------------------------------------------------

_TIER_HEADING = re.compile(r"^## Tier (\d+)\b")
_FIRST_CELL_NAMES = re.compile(r"^\|\s*((?:`[a-z0-9][a-z0-9._-]*`,?\s*)+)\|")


def designation_labels(page: str) -> dict[str, str]:
    """Name to where the page's tiers designate it: ``tier N``, or the ``sqlserver`` extra.

    Reads only the designated tables above the readings heading. A not-designated table, or any
    heading other than a tier or the extra's ``### Designated``, ends the current label.
    """
    labels: dict[str, str] = {}
    label: str | None = None
    for line in page.splitlines():
        if line == READINGS_HEADING:
            break
        if line.startswith("#"):
            tier = _TIER_HEADING.match(line)
            label = f"tier {tier[1]}" if tier else None
            if line == "### Designated":
                label = "the `sqlserver` extra"
            continue
        row = _FIRST_CELL_NAMES.match(line)
        if label and row:
            for cell in row[1].split(","):
                labels[runtime_closure.canonical_name(cell.strip(" `"))] = label
    return labels


def _either(words: Iterable[str]) -> str:
    """Backticked words as "`a`, `b` or `c`"."""
    quoted = [f"`{w}`" for w in words]
    return " or ".join([", ".join(quoted[:-1]), quoted[-1]] if len(quoted) > 1 else quoted)


def render_section(data: Mapping[str, Any], labels: Mapping[str, str]) -> str:
    """The page section between the markers, from the snapshot and the page's tier labels."""
    rules = data["criteria"]
    as_of = dt.date.fromisoformat(data["snapshot_date"])
    readings = data["readings"]
    size = len(readings)
    core = sum(r["in_core"] for r in readings)
    flagged = {axis: [r for r in readings if r["risky"][axis]] for axis in AXES}
    clean = [r for r in readings if not any(r["risky"].values())]

    def designated(name: str) -> str:
        return f"yes, {labels[name]}" if name in labels else "no"

    out = [
        f"> **Snapshot date: {data['snapshot_date']}. Re-read by: {data['reread_by']}.** Every "
        "reading below comes from public PyPI and OSV data on the snapshot date, for the versions "
        "the closure files pinned that day. Support status and advisory history go stale. After the "
        "re-read date, treat this section as out of date until "
        "[`scripts/security/component_readings.py`](../scripts/security/component_readings.py) "
        "runs again.",
        "",
        "The readings, their sources and their windows are recorded in "
        "[`security/risky-component-readings.json`](../security/risky-component-readings.json).",
        "",
        "### What is read, and the test for each example",
        "",
        f"All {size} distributions in the `sqlserver` closure are read: the {core} in the core "
        f"closure and the {size - core} the extra adds. That is the whole assessed set, not only "
        "the designated part. A library can be risky on these examples even where the tiers did "
        "not designate it.",
        "",
        "| Example | A component is risky on it when | Source |",
        "|---|---|---|",
        "| Poorly maintained | it has uploaded no release to PyPI, pre-releases included, in the "
        f"{rules['maintenance_window_days']} days before the snapshot | PyPI JSON API |",
        "| Unsupported or end of life | its PyPI project status (PEP 792) is "
        + _either(rules["unsupported_statuses"])
        + f", or its latest release is classified `{rules['inactive_classifier']}`, or the "
        "pinned version is yanked | PyPI JSON and Simple APIs |",
        "| A history of significant vulnerabilities | at least one advisory rated "
        + _either(rules["significant_severities"])
        + f" was first published in the {rules['advisory_window_days']} days (about "
        f"{round(int(rules['advisory_window_days']) / 365)} years) before the snapshot | OSV API |",
        "",
        "OSV often records one flaw twice, once from the GitHub advisory database and once from the "
        "Python advisory database. Records that name each other count once. The severity is the "
        "GitHub advisory database's rating. An advisory with no rating does not count, and the "
        "ones in the window are named below so a reader can judge them.",
        "",
        "These tests are mechanical. A small library that is finished can trip the first one "
        "without being neglected. The reading says where to look; it does not say the library is "
        "broken.",
        "",
        f"**{size - len(clean)} of {size} are risky on at least one example: "
        f"{len(flagged['maintenance'])} on maintenance, {len(flagged['support'])} on support, "
        f"and {len(flagged['advisory_history'])} on vulnerability history. {len(clean)} are not. "
        f"{size - len(clean)} plus {len(clean)} is {size}.**",
        "",
        "### Poorly maintained",
        "",
    ]
    if flagged["maintenance"]:
        out += ["| Component | Newest release | Designated above |", "|---|---|---|"]
        out += [
            f"| `{r['name']}` | {r['newest_upload']} | {designated(r['name'])} |"
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
            newest = max(a["published"] for a in hits)
            out.append(f"| `{r['name']}` | {len(hits)} | {newest} | {designated(r['name'])} |")
    else:
        out.append("None on the snapshot date.")
    out.append("")
    open_hits = [(a, r["name"]) for r in readings for a in r["advisories_affecting_pin"]]
    if open_hits:
        out.append(
            "On the snapshot date OSV listed these advisories against a pinned version: "
            + "; ".join(f"`{a}` against `{n}`" for a, n in open_hits)
            + ". Each is handled through the process in `.github/SECURITY.md`."
        )
    else:
        out.append(
            f"On the snapshot date OSV listed no advisory against any pinned version, in any of "
            f"the {size}. This is history, not an open finding."
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
            f"{len(unrated)} advisories in the window carry no severity rating, so the test above "
            "does not count them: " + "; ".join(f"`{a}` against `{n}`" for a, n in unrated) + "."
        )
    else:
        out.append("Every advisory in the window carries a severity rating.")
    out += ["", "### Not risky on any of the three", "", "| Components | Designated above |"]
    out.append("|---|---|")
    for yes in (True, False):
        names = [r["name"] for r in clean if (r["name"] in labels) == yes]
        if names:
            out.append(f"| {', '.join(f'`{n}`' for n in names)} | {'yes' if yes else 'no'} |")
    both = [r for r in readings if any(r["risky"].values()) and r["name"] in labels]
    only = [r for r in readings if any(r["risky"].values()) and r["name"] not in labels]

    def why(r: Mapping[str, Any]) -> str:
        where = [labels[r["name"]]] if r["name"] in labels else []
        axes = " and ".join(_AXIS_WORDS[a] for a in AXES if r["risky"][a])
        return f"`{r['name']}` ({', '.join([*where, axes])})"

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
            f"{len(both)} designated components are also risky on an ASVS example: "
            + ", ".join(why(r) for r in both)
            + "."
        )
    else:
        out.append("No designated component is risky on an ASVS example.")
    out.append("")
    if only:
        out.append(
            f"{len(only)} are risky here and not designated above: "
            + ", ".join(why(r) for r in only)
            + ". None of them parses hostile input, holds a secret or terminates a protocol, which "
            "is why the tiers left them out. The reading names them so that choice stays visible."
        )
    else:
        out.append("Every component risky on an ASVS example is also designated above.")
    return "\n".join(_wrap(line) for line in out)


def _wrap(line: str) -> str:
    """A prose line wrapped at the page's width; a table row, heading or blank line as it is."""
    if not line or line.startswith(("|", "#")):
        return line
    prefix = "> " if line.startswith("> ") else ""
    return textwrap.fill(
        line.removeprefix(prefix),
        width=_PAGE_WIDTH,
        initial_indent=prefix,
        subsequent_indent=prefix,
        break_long_words=False,
        break_on_hyphens=False,
    )


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


def render_page(page: str, data: Mapping[str, Any]) -> str:
    """``page`` with the section between the markers re-rendered from ``data``."""
    start, stop = _marker_bounds(page)
    body = render_section(data, designation_labels(page))
    return f"{page[:start]}\n{BEGIN}\n\n{body}\n\n{END}\n{page[stop + len(END) + 2 :]}"


def _write_text(path: Path, text: str) -> None:
    """Write ``text`` keeping the file's current line ending, so a Windows run makes no churn."""
    crlf = path.exists() and b"\r\n" in path.read_bytes()
    path.write_bytes((text.replace("\n", "\r\n") if crlf else text).encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--as-of",
        type=dt.date.fromisoformat,
        default=dt.datetime.now(dt.UTC).date(),
        help="the snapshot date, YYYY-MM-DD (default: today, UTC)",
    )
    parser.add_argument(
        "--render-only",
        action="store_true",
        help="re-render the page section from the tracked snapshot; no network",
    )
    args = parser.parse_args(argv)
    if args.render_only:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    else:
        try:
            data = snapshot(args.as_of)
        except (urllib.error.URLError, ValueError, KeyError) as exc:
            # Nothing is written on a failed read, so a half-fetched snapshot never lands.
            print(f"component readings failed, nothing written: {exc}", file=sys.stderr)
            return 1
    page = render_page(PAGE.read_text(encoding="utf-8"), data)
    if not args.render_only:
        _write_text(SNAPSHOT, json.dumps(data, indent=2) + "\n")
    _write_text(PAGE, page)
    counts = {axis: sum(r["risky"][axis] for r in data["readings"]) for axis in AXES}
    print(f"{len(data['readings'])} readings as of {data['snapshot_date']}: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
