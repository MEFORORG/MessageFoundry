#!/usr/bin/env python3
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
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import statistics
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_USER_AGENT = "messagefoundry-vuln-metrics"


def _gh(args: list[str]) -> Any:
    """Run a `gh` command that emits JSON; return the parsed value ([] on failure)."""
    try:
        out = subprocess.run(
            ["gh", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",  # PR bodies carry non-cp1252 bytes; force utf-8 (Windows default isn't)
            errors="replace",
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"warning: gh {' '.join(args)} failed: {exc}", file=sys.stderr)
        return []
    try:
        return json.loads(out) if out and out.strip() else []
    except json.JSONDecodeError as exc:
        print(f"warning: gh {' '.join(args)} returned non-JSON: {exc}", file=sys.stderr)
        return []


def _http_json(url: str, timeout: float) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https feeds
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        print(f"warning: GET {url} failed: {exc}", file=sys.stderr)
        return None


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def dependabot_prs(repo: str, limit: int) -> list[dict[str, Any]]:
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
    return data if isinstance(data, list) else []


def _is_security_pr(pr: dict[str, Any]) -> bool:
    if any("security" in (lbl.get("name", "").lower()) for lbl in pr.get("labels", [])):
        return True
    return bool(_CVE_RE.search(pr.get("title", "") + " " + (pr.get("body") or "")))


def _cves_in(pr: dict[str, Any]) -> set[str]:
    return {m.upper() for m in _CVE_RE.findall(pr.get("title", "") + " " + (pr.get("body") or ""))}


def kev_cves(timeout: float) -> set[str]:
    data = _http_json(KEV_URL, timeout)
    if not isinstance(data, dict):
        return set()
    return {v["cveID"].upper() for v in data.get("vulnerabilities", []) if v.get("cveID")}


def epss_scores(cves: set[str], timeout: float) -> dict[str, float]:
    if not cves:
        return {}
    out: dict[str, float] = {}
    ordered = sorted(cves)
    for i in range(0, len(ordered), 100):  # EPSS API caps the cve list per call
        chunk = ordered[i : i + 100]
        data = _http_json(f"{EPSS_URL}?cve={','.join(chunk)}", timeout)
        if isinstance(data, dict):
            for row in data.get("data", []):
                try:
                    out[row["cve"].upper()] = float(row["epss"])
                except (KeyError, ValueError, TypeError):
                    continue
    return out


def _norm_ver(v: str) -> str:
    return v.strip().lstrip("vV").lower()


def _reachability_ratio(spec: str | None) -> str:
    """Triaged reachable/total from the runbook records (a judgment, not API-derivable)."""
    if not spec:
        return "n/a: needs triage data (--reachability R/T)"
    try:
        r, t = (int(x) for x in spec.split("/", 1))
        return f"{r / t:.2f}" if t else "n/a: --reachability total is 0"
    except (ValueError, ZeroDivisionError):
        return f"n/a: bad --reachability '{spec}' (want R/T)"


def adopter_lag(repo: str, adopter_repos: list[str], now: datetime, timeout: float) -> str:
    """Max days the newest engine release has been out that an adopter isn't yet pinned to.

    Best-effort: needs read access to the adopter repos (a CI GITHUB_TOKEN is scoped to one repo, so this
    is `n/a` there unless a cross-repo token is supplied; it computes locally / with a PAT that can read
    the config repos).
    """
    if not adopter_repos:
        return "n/a: needs --adopter-repos (config-repo pin history)"
    rel = _gh(
        ["api", f"repos/{repo}/releases/latest", "--jq", "{tag: .tag_name, at: .published_at}"]
    )
    if not isinstance(rel, dict) or not rel.get("tag"):
        return "n/a: no engine release to compare against"
    latest = _norm_ver(rel["tag"])
    published = _parse_dt(rel.get("at"))
    lags: list[float] = []
    for ar in adopter_repos:
        content = _gh(["api", f"repos/{ar}/contents/requirements.txt", "--jq", ".content"])
        if not isinstance(content, str) or not content:
            return f"n/a: can't read {ar}/requirements.txt (cross-repo access?)"
        text = base64.b64decode(content).decode("utf-8", "replace")
        match = re.search(r"messagefoundry==([\w.\-]+)", text)
        if match and _norm_ver(match.group(1)) != latest and published:
            lags.append((now - published).total_seconds() / 86400)
    return f"{max(lags):.1f}" if lags else "0"


def compute(
    repo: str,
    limit: int,
    timeout: float,
    now: datetime,
    adopter_repos: list[str],
    reachability: str | None,
) -> dict[str, str]:
    prs = dependabot_prs(repo, limit)
    closed = [p for p in prs if p.get("state") in {"MERGED", "CLOSED"}]
    merged = [p for p in prs if p.get("mergedAt")]
    sec = [p for p in prs if _is_security_pr(p)]
    sec_merged = [p for p in sec if p.get("mergedAt")]
    sec_open = [p for p in sec if p.get("state") == "OPEN"]

    seen_cves: set[str] = set()
    for p in sec:
        seen_cves |= _cves_in(p)
    kev = kev_cves(timeout)
    epss = epss_scores(seen_cves, timeout)

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
        scored = len(epss)
        imminent = sum(1 for v in epss.values() if v >= 0.7)
        m["epss_coverage_pct"] = f"{100 * scored / len(seen_cves):.0f}"
        m["epss_ge_0_7_count"] = str(imminent)
    else:
        m["epss_coverage_pct"] = "n/a: no CVEs referenced in window"
        m["epss_ge_0_7_count"] = "0"

    # 5. adopter patch-lag — days the newest release has been out that an adopter isn't yet pinned to.
    m["adopter_patch_lag_days"] = adopter_lag(repo, adopter_repos, now, timeout)

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
    return m


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--repo", default="wshallwshall/MessageFoundry")
    p.add_argument("--limit", type=int, default=200, help="Dependabot PRs to scan (the window)")
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--csv", default="docs/security/metrics/vuln-metrics.csv")
    p.add_argument(
        "--summary",
        default=None,
        help="write a Markdown summary to this path (e.g. $GITHUB_STEP_SUMMARY)",
    )
    p.add_argument("--now", default=None, help="ISO timestamp for the run (default: current UTC)")
    p.add_argument(
        "--adopter-repos",
        default="",
        help="comma-separated owner/repo adopter config repos, for the patch-lag metric",
    )
    p.add_argument("--reachability", default=None, help="triaged reachable/total, e.g. 3/5")
    args = p.parse_args(argv)

    now = _parse_dt(args.now) or datetime.now(timezone.utc)
    adopter_repos = [r.strip() for r in args.adopter_repos.split(",") if r.strip()]
    row = compute(args.repo, args.limit, args.timeout, now, adopter_repos, args.reachability)

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
