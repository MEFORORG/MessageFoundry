#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Dependency-vulnerability program metrics — NIST SSDF **RV.2** evidence.

Computes the dependency fast-response KPIs from REAL repo data + public feeds, so "is the program
actually fast?" is answerable from recorded evidence rather than assertion. Emits a CSV (one dated row
per run) and a Markdown summary; the weekly `.github/workflows/vuln-metrics.yml` runs it, uploads the
CSV as an artifact, and renders the summary to the job page.

The seven metrics (the plan's RV.2 set):
  1. MTTD                 — detect latency: Dependabot security PR opened vs the advisory's publish.
  2. dep-CVE MTTR         — fix latency: security PR opened -> merged (overall + KEV-only).
  3. KEV-exposure-age     — oldest still-open security PR whose CVE is on CISA KEV.
  4. EPSS coverage        — share of seen CVEs with an EPSS score; count at the >=0.7 "imminent" bar.
  5. adopter patch-lag    — days from a release to adopters re-pinning (needs --adopter-repos).
  6. auto-merge health    — share of Dependabot PRs that merged, and the median time-to-merge.
  7. reachability ratio   — share of triaged CVEs judged reachable (needs triage data; --reachability).

Sources, no extra secrets: the GitHub API via `gh` (Dependabot PRs are GITHUB_TOKEN-readable), CISA KEV
(public JSON), FIRST EPSS (public API). Metrics needing an input this script can't derive from the repo
alone (adopter patch-lag, reachability ratio) are emitted as `n/a` with the reason + the hook to fill
them, rather than faked.

A source that could not be READ is not a source that answered nothing (BACKLOG #5447). A failed `gh`
call listing the Dependabot PRs, a failed CISA KEV or FIRST EPSS fetch, or an answer from one in a
shape this cannot read, leaves the metrics it feeds as `n/a` naming the source, never `0`. So does
an unread adopter source once `--adopter-repos` opts in. The run then exits 2 after writing the CSV
and summary, so the weekly job goes red rather than recording a feed outage as zero exposure.
"""

from __future__ import annotations

import argparse
import base64
import csv
import http.client
import json
import os
import re
import statistics
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_USER_AGENT = "messagefoundry-vuln-metrics"
#: Seconds one `gh` call may take; the weekly job's own limit is 10 minutes.
_GH_TIMEOUT = 120.0


def _gh(args: list[str]) -> Any:
    """Run a `gh` command that emits JSON; return the parsed value, or ``None`` when the call failed
    or its output was empty or not JSON. ``None`` and an empty list are different answers (BACKLOG
    #5447): `gh` prints ``[]`` for an empty list, so no output at all is not one."""
    try:
        out = subprocess.run(  # nosec B603 B607 - fixed argv (`gh`), no shell, args are literals
            ["gh", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",  # PR bodies carry non-cp1252 bytes; force utf-8 (Windows default isn't)
            errors="replace",
            check=True,
            # A hung call would hold the step until the job is cancelled, and no row is written.
            timeout=_GH_TIMEOUT,
        ).stdout
    # OSError covers a gh that is missing or cannot be executed.
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"warning: gh {' '.join(args)} failed: {exc}", file=sys.stderr)
        return None
    if not out or not out.strip():
        print(f"warning: gh {' '.join(args)} printed nothing", file=sys.stderr)
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        print(f"warning: gh {' '.join(args)} returned non-JSON: {exc}", file=sys.stderr)
        return None


def _http_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        # nosec B310 - same reason as the noqa: the URL is a fixed https advisory feed, never
        # message-derived or caller-supplied, so no file:/custom scheme is reachable here.
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            return json.loads(resp.read())
    # ValueError covers a non-JSON body and a body that is not UTF-8; HTTPException a truncated
    # or garbled response. Each is a feed that could not be read (BACKLOG #5447).
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        ValueError,
        http.client.HTTPException,
    ) as exc:
        print(f"warning: GET {url} failed: {exc}", file=sys.stderr)
        return None


def _parse_dt(value: str | None) -> datetime | None:
    """``value`` as an aware datetime, or ``None`` when it is empty, not ISO, or carries no offset:
    a naive one cannot be subtracted from an aware one, and its zone would be a guess."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def dependabot_prs(repo: str, limit: int) -> list[dict[str, Any]] | None:
    """The window's Dependabot PRs, or ``None`` when ``gh`` could not list them."""
    data = _gh(
        [
            "pr",
            "list",
            "--repo",
            repo,
            "--author",
            "app/dependabot",
            "--state",
            "all",
            "--limit",
            str(limit),
            "--json",
            "number,title,body,state,createdAt,mergedAt,labels",
        ]
    )
    if not isinstance(data, list) or not all(_pr_shaped(p) for p in data):
        return None
    return data


def _pr_shaped(pr: object) -> bool:
    """Whether ``pr`` has the field types the metrics read. A list holding one that does not
    crashed the run to exit 1 with no row written, so the list is an unread source instead."""
    if not isinstance(pr, dict):
        return False
    labels = pr.get("labels", [])
    return (
        isinstance(pr.get("title", ""), str)
        and isinstance(pr.get("body"), str | None)
        # A state the metrics do not name would drop an open PR from the KEV exposure age, and a
        # list or dict one is unhashable.
        and isinstance(pr.get("state"), str)
        and pr.get("state") in _PR_STATES
        # A timestamp that does not parse, or has no offset, would drop the PR or crash the run.
        and all(_timestamp_or_null(pr.get(f)) for f in ("createdAt", "mergedAt"))
        and isinstance(labels, list)
        and all(isinstance(lbl, dict) and isinstance(lbl.get("name", ""), str) for lbl in labels)
    )


#: The states `gh pr list --json state` reports.
_PR_STATES = frozenset({"OPEN", "CLOSED", "MERGED"})


def _timestamp_or_null(value: object) -> bool:
    return value is None or (isinstance(value, str) and _parse_dt(value) is not None)


def _is_security_pr(pr: dict[str, Any]) -> bool:
    if any("security" in (lbl.get("name", "").lower()) for lbl in pr.get("labels", [])):
        return True
    return bool(_CVE_RE.search(pr.get("title", "") + " " + (pr.get("body") or "")))


def _cves_in(pr: dict[str, Any]) -> set[str]:
    return {m.upper() for m in _CVE_RE.findall(pr.get("title", "") + " " + (pr.get("body") or ""))}


def kev_cves(timeout: float) -> set[str] | None:
    """The CVE ids on CISA KEV, or ``None`` when the catalog could not be read or is not shaped as
    one: an empty catalog would score every open PR as off KEV."""
    data = _http_json(KEV_URL, timeout)
    vulns = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulns, list) or not vulns:
        return None
    # Any entry without a cveID string makes the whole catalog unread, not partial: the CVE that
    # entry should have named would score an open PR as off KEV, a false zero exposure.
    if not all(isinstance(v, dict) and isinstance(v.get("cveID"), str) for v in vulns):
        return None
    return {v["cveID"].upper() for v in vulns}


def epss_scores(cves: set[str], timeout: float) -> dict[str, float] | None:
    """EPSS scores for ``cves``, or ``None`` when any chunk could not be fetched or is not shaped as
    an EPSS answer: a partial or empty answer would understate the coverage.

    EPSS has no score for a CVE it does not know yet, and says so: its answer carries
    ``"status": "OK"`` and a ``total`` that counts only the rows it found. Only an answer carrying
    both, with ``total`` matching its rows, is one; a bare or short ``data`` list is not."""
    if not cves:
        return {}
    out: dict[str, float] = {}
    ordered = sorted(cves)
    for i in range(0, len(ordered), 100):  # EPSS API caps the cve list per call
        chunk = ordered[i : i + 100]
        data = _http_json(f"{EPSS_URL}?cve={','.join(chunk)}", timeout)
        if not isinstance(data, dict):
            return None
        rows, total = data.get("data"), data.get("total")
        if (
            not isinstance(rows, list)
            or data.get("status") != "OK"
            or not isinstance(total, int)
            or isinstance(total, bool)
            or total != len(rows)
        ):
            return None
        for row in rows:
            try:
                out[row["cve"].upper()] = float(row["epss"])
            except (KeyError, ValueError, TypeError, AttributeError):
                # A row that does not parse (a renamed field, an error shape) would understate
                # the coverage, so the answer is not an EPSS answer.
                return None
    return out


def _norm_ver(v: str) -> str:
    return v.strip().lstrip("vV").lower()


def _release_tuple(v: str) -> tuple[int, ...] | None:
    """A plain release (``v1.2.0``, ``1.2``) as a key under which it equals itself padded with
    zeros, as PEP 440 has it; ``None`` for anything else (a pre-release, another tag scheme)."""
    norm = _norm_ver(v)
    if not re.fullmatch(r"\d+(?:\.\d+)*", norm):
        return None
    parts = [int(x) for x in norm.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _reachability_ratio(spec: str | None) -> str:
    """Triaged reachable/total from the runbook records (a judgment, not API-derivable)."""
    if not spec:
        return "n/a: needs triage data (--reachability R/T)"
    try:
        r, t = (int(x) for x in spec.split("/", 1))
        return f"{r / t:.2f}" if t else "n/a: --reachability total is 0"
    except (ValueError, ZeroDivisionError):
        return f"n/a: bad --reachability '{spec}' (want R/T)"


def adopter_lag(
    repo: str,
    adopter_repos: list[str],
    now: datetime,
    timeout: float,
    failures: list[str] | None = None,
) -> str:
    """Max days the newest engine release has been out that an adopter isn't yet pinned to.

    Best-effort: needs read access to the adopter repos (a CI GITHUB_TOKEN is scoped to one repo, so this
    is `n/a` there unless a cross-repo token is supplied; it computes locally / with a PAT that can read
    the config repos). Once ``--adopter-repos`` opts in, a source that could not be read, or answered
    in a shape this cannot read, is appended to ``failures`` so the run exits 2 (BACKLOG #5447).
    """
    if not adopter_repos:
        return "n/a: needs --adopter-repos (config-repo pin history)"

    def _unread(why: str) -> str:
        if failures is not None:
            failures.append(f"adopter patch-lag: {why}")
        return f"n/a: {why}"

    # Not releases/latest: the repo also publishes other distributions (webconsole-v...), and
    # whichever is newest is "latest", so the engine release is picked out by its plain v-tag.
    rels = _gh(
        [
            "api",
            f"repos/{repo}/releases?per_page=100",
            "--jq",
            "[.[] | {tag: .tag_name, at: .published_at, draft: .draft, pre: .prerelease}]",
        ]
    )
    if rels is None:
        return _unread("gh could not read the engine releases")
    if not isinstance(rels, list) or not all(isinstance(r, dict) for r in rels):
        return _unread("the releases answer is not a list of releases")
    engine = [
        (key, r)
        for r in rels
        if not r.get("draft")
        and not r.get("pre")
        and isinstance(r.get("tag"), str)
        and (key := _release_tuple(r["tag"])) is not None
    ]
    if not engine:
        return "n/a: no engine release to compare against"
    latest, rel = max(engine, key=lambda kr: kr[0])
    published = _parse_dt(rel.get("at")) if isinstance(rel.get("at"), str) else None
    lags: list[float] = []
    # The first adopter with no exact pin. Every adopter is still read, so an unread one later in
    # --adopter-repos reds the run whatever the order.
    unpinned: str | None = None
    for ar in adopter_repos:
        # The whole JSON answer, not `--jq .content`: jq prints a string raw, which is not JSON.
        answer = _gh(["api", f"repos/{ar}/contents/requirements.txt"])
        content = answer.get("content") if isinstance(answer, dict) else None
        if not isinstance(content, str) or not content:
            return _unread(f"can't read {ar}/requirements.txt (cross-repo access?)")
        try:
            # utf-8-sig: a BOM would otherwise hide a pin on the first line.
            text = base64.b64decode(content).decode("utf-8-sig", "replace")
        # binascii.Error is a ValueError, and so is a non-ASCII str: either is an unread file.
        except ValueError:
            return _unread(f"{ar}/requirements.txt content is not base64")
        pin = _exact_pin(text)
        # Only an exact pin can be compared. A range, an extras pin this did not parse, or no
        # messagefoundry line at all is not "up to date", so it is n/a, never a lag of 0.
        if pin is None:
            unpinned = (
                unpinned or f"n/a: {ar}/requirements.txt has no single exact messagefoundry== pin"
            )
            continue
        if _release_tuple(pin) != latest:
            if published is None:
                # A published release always has a date; a missing or naive one is malformed.
                return _unread("the latest engine release has no publish date with an offset")
            lags.append((now - published).total_seconds() / 86400)
    if unpinned is not None:
        return unpinned
    return f"{max(lags):.1f}" if lags else "0"


#: A requirement line naming the engine distribution itself (not messagefoundry-toolkit), with
#: optional extras; group 1 is the version specifier and whatever follows it.
_ENGINE_REQ_RE = re.compile(r"messagefoundry(?![\w.-])\s*(?:\[[^\]]*\])?(.*)", re.IGNORECASE)


def _exact_pin(text: str) -> str | None:
    """The version every ``messagefoundry==X`` requirement in ``text`` pins, or ``None`` when there
    is no messagefoundry requirement, one is not an exact ``==`` pin, or two pin different
    versions (marker-split lines that agree, one per platform, are one pin)."""
    pins: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        req = _ENGINE_REQ_RE.match(line)
        if req is None:
            continue
        # Cut an environment marker, a comment, a line continuation, or a trailing option.
        spec = re.split(r"[;#\\]|\s--", req.group(1), maxsplit=1)[0].strip()
        exact = re.fullmatch(r"==\s*([\w.+!-]+)", spec)
        if exact is None:
            return None
        pins.append(exact.group(1))
    if not pins or len({_norm_ver(p) for p in pins}) != 1:
        return None
    return pins[0]


#: The metrics each source feeds, so a source that could not be read blanks exactly these.
_PR_METRICS = (
    "dep_mttr_days",
    "dep_mttr_kev_days",
    "kev_exposure_max_age_days",
    "epss_coverage_pct",
    "epss_ge_0_7_count",
    "automerge_merged_rate_pct",
    "automerge_median_hours",
    "dependabot_prs_window",
    "security_prs_window",
)
_KEV_METRICS = ("dep_mttr_kev_days", "kev_exposure_max_age_days")
_EPSS_METRICS = ("epss_coverage_pct", "epss_ge_0_7_count")


def compute(
    repo: str,
    limit: int,
    timeout: float,
    now: datetime,
    adopter_repos: list[str],
    reachability: str | None,
    failures: list[str] | None = None,
) -> dict[str, str]:
    """The metrics row. Each source that could not be read is appended to ``failures`` and leaves
    the metrics it feeds as ``n/a`` naming it, never a zero computed over nothing (BACKLOG #5447)."""
    failed: list[str] = [] if failures is None else failures
    unread: dict[str, str] = {}

    def _unread(source: str, metrics: tuple[str, ...]) -> None:
        failed.append(f"{source} could not be read")
        for name in metrics:
            unread.setdefault(name, f"n/a: {source} could not be read")

    fetched = dependabot_prs(repo, limit)
    if fetched is None:
        _unread("the Dependabot PR list (gh)", _PR_METRICS)
    prs = fetched or []
    closed = [p for p in prs if p.get("state") in {"MERGED", "CLOSED"}]
    merged = [p for p in prs if p.get("mergedAt")]
    sec = [p for p in prs if _is_security_pr(p)]
    sec_merged = [p for p in sec if p.get("mergedAt")]
    sec_open = [p for p in sec if p.get("state") == "OPEN"]

    seen_cves: set[str] = set()
    for p in sec:
        seen_cves |= _cves_in(p)
    # KEV feeds only the open and merged security PRs' metrics: with no CVE among those, the
    # catalog cannot change a metric, so it is not asked and its outage cannot red the run.
    kev_relevant = {c for p in sec_open + sec_merged for c in _cves_in(p)}
    kev = kev_cves(timeout) if kev_relevant else set()
    if kev is None:
        _unread("the CISA KEV catalog", _KEV_METRICS)
        kev = set()
    epss = epss_scores(seen_cves, timeout)
    if epss is None:
        _unread("the FIRST EPSS API", _EPSS_METRICS)
        epss = {}

    m: dict[str, str] = {"date": now.date().isoformat()}

    # 1. MTTD — advisory publish date isn't on the PR; left as n/a (needs the Dependabot alerts API,
    #    which GITHUB_TOKEN can't read). The PR-open timestamp is the proxy anchor we DO have.
    m["mttd_days"] = "n/a: needs Dependabot alerts API (advisory publish date)"

    # 2. dep-CVE MTTR — security PR opened -> merged (the part we can see without the alerts API).
    def _ttm_days(p: dict[str, Any]) -> float | None:
        c, mg = _parse_dt(p.get("createdAt")), _parse_dt(p.get("mergedAt"))
        return (mg - c).total_seconds() / 86400 if c and mg else None

    sec_ttm = [d for p in sec_merged if (d := _ttm_days(p)) is not None]
    m["dep_mttr_days"] = (
        f"{statistics.median(sec_ttm):.1f}" if sec_ttm else "n/a: no merged security PRs in window"
    )
    kev_ttm = [d for p in sec_merged if _cves_in(p) & kev and (d := _ttm_days(p)) is not None]
    m["dep_mttr_kev_days"] = (
        f"{statistics.median(kev_ttm):.1f}" if kev_ttm else "n/a: no merged KEV PRs in window"
    )

    # 3. KEV-exposure-age — oldest OPEN security PR whose CVE is on KEV (0 if none open).
    kev_ages = [
        (now - c).total_seconds() / 86400
        for p in sec_open
        if _cves_in(p) & kev and (c := _parse_dt(p.get("createdAt")))
    ]
    m["kev_exposure_max_age_days"] = f"{max(kev_ages):.1f}" if kev_ages else "0"

    # 4. EPSS coverage — share of seen CVEs scored + count at the >=0.7 imminent bar.
    if seen_cves:
        # Only the CVEs asked about: a row the API added for another CVE would overstate both.
        asked = {c: v for c, v in epss.items() if c in seen_cves}
        scored = len(asked)
        imminent = sum(1 for v in asked.values() if v >= 0.7)
        m["epss_coverage_pct"] = f"{100 * scored / len(seen_cves):.0f}"
        m["epss_ge_0_7_count"] = str(imminent)
    else:
        m["epss_coverage_pct"] = "n/a: no CVEs referenced in window"
        m["epss_ge_0_7_count"] = "0"

    # 5. adopter patch-lag — days the newest release has been out that an adopter isn't yet pinned to.
    m["adopter_patch_lag_days"] = adopter_lag(repo, adopter_repos, now, timeout, failed)

    # 6. auto-merge health — share of Dependabot PRs that merged + median time-to-merge (hours).
    if closed:
        m["automerge_merged_rate_pct"] = f"{100 * len(merged) / len(closed):.0f}"
    else:
        m["automerge_merged_rate_pct"] = "n/a: no closed Dependabot PRs in window"
    ttm_hours = [d * 24 for p in merged if (d := _ttm_days(p)) is not None]
    m["automerge_median_hours"] = f"{statistics.median(ttm_hours):.1f}" if ttm_hours else "n/a"

    # 7. reachability ratio — a triage judgment fed in from the runbook records.
    m["reachability_ratio"] = _reachability_ratio(reachability)

    m["dependabot_prs_window"] = str(len(prs))
    m["security_prs_window"] = str(len(sec))
    m.update(unread)
    return m


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # Measure the repo the workflow actually runs in. vuln-metrics.yml invokes this with no --repo, so a
    # hardcoded default silently decides what gets measured: it named the private vault, whose Dependabot
    # PRs a public GITHUB_TOKEN cannot read — every KPI would have been computed over an empty window.
    # $GITHUB_REPOSITORY makes it self-correcting; the literal is only for a local run outside Actions.
    p.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY") or "MEFORORG/MessageFoundry",
    )
    p.add_argument("--limit", type=int, default=200, help="Dependabot PRs to scan (the window)")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--csv", default="docs/security/metrics/vuln-metrics.csv")
    p.add_argument(
        "--summary",
        default=None,
        help="write a Markdown summary to this path (e.g. $GITHUB_STEP_SUMMARY)",
    )
    p.add_argument(
        "--now",
        default=None,
        help="ISO timestamp with an offset for the run (default: current UTC)",
    )
    p.add_argument(
        "--adopter-repos",
        default="",
        help="comma-separated owner/repo adopter config repos, for the patch-lag metric",
    )
    p.add_argument("--reachability", default=None, help="triaged reachable/total, e.g. 3/5")
    args = p.parse_args(argv)

    if args.now is None:
        now = datetime.now(UTC)
    elif (parsed := _parse_dt(args.now)) is None:
        # Exits 2. A naive or unparsable --now was a crash to 1, or silently the current time.
        p.error(f"--now {args.now!r} is not an ISO timestamp with an offset")
    else:
        now = parsed
    adopter_repos = [r.strip() for r in args.adopter_repos.split(",") if r.strip()]
    failures: list[str] = []
    row = compute(
        args.repo, args.limit, args.timeout, now, adopter_repos, args.reachability, failures
    )

    csv_path = Path(args.csv)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(row.keys())
    existing = csv_path.exists()
    # If the header drifted (new metric column), rewrite rather than append a ragged row.
    if existing:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            header = next(csv.reader(fh), [])
        if header != fields:
            existing = False
    with open(csv_path, "a" if existing else "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if not existing:
            w.writeheader()
        w.writerow(row)

    md = [
        "# Dependency-vulnerability metrics (RV.2)",
        "",
        f"Run: {row['date']} · repo `{args.repo}`",
        "",
        "| Metric | Value |",
        "|---|---|",
    ]
    md += [f"| `{k}` | {v} |" for k, v in row.items() if k != "date"]
    summary = "\n".join(md) + "\n"
    print(summary)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(summary)
    # 2, not 0: the row above is written with each unread source's metrics as n/a, and the run goes red
    # so a feed outage is never recorded as a clean week (BACKLOG #5447).
    for why in failures:
        print(f"::error::vuln-metrics: {why}; its metrics are n/a, not 0", file=sys.stderr)
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
