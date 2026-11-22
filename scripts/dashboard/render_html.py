#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Render a ``collect_metrics.py`` snapshot as ONE self-contained static ``index.html``.

THE PAGE IS SELF-CONTAINED: inline CSS and inline SVG charts, no script, font, image or CDN
fetched from anywhere, so it opens from ``file://`` with no network. Light and dark follow the
viewer's ``prefers-color-scheme``.

EVERY SNAPSHOT VALUE IS DATA. Each one is HTML-escaped before it reaches the page, and a metric
that could not be read renders as "no data", never as zero.

WHERE IT WRITES, first match wins: ``--out-dir``; the ``MEFOR_DASHBOARD_DIR`` environment variable;
``%USERPROFILE%/OneDrive/Desktop/MEFOR/dashboard`` when ``OneDrive/Desktop/MEFOR`` already exists;
otherwise ``%USERPROFILE%/MEFOR/dashboard``. It writes ``index.html`` and a copy of the snapshot as
``snapshot.json``, each through a temporary file and an atomic replace, so a failed run leaves the
previous page whole. The directory is refused inside a git work tree, with the collector's guard:
the page quotes the same private vault counts as the snapshot.

The rows are built by ``to_rows.py``, so the page and the row files never disagree.

EXIT STATUS. 0 when the page was written, and its ``file:///`` URL is printed; 1 when it was not.

Usage::

    python scripts/dashboard/render_html.py C:/outside/any/repo/metrics.json [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import html
import importlib.util
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

_HERE = Path(__file__).resolve().parent

ENV_DIR = "MEFOR_DASHBOARD_DIR"
STATUSES = ("good", "warn", "bad", "unknown")


def _to_rows() -> ModuleType:
    """The sibling converter, loaded by path: this directory is no package."""
    name = "dashboard_to_rows"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _HERE / "to_rows.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {_HERE / 'to_rows.py'}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def resolve_out_dir(arg: Path | None, env: Mapping[str, str], home: Path) -> Path:
    """The output directory, in the order the module docstring gives."""
    if arg is not None:
        return arg
    if env.get(ENV_DIR):
        return Path(env[ENV_DIR])
    onedrive = home / "OneDrive" / "Desktop" / "MEFOR"
    if onedrive.is_dir():
        return onedrive / "dashboard"
    return home / "MEFOR" / "dashboard"


def _home(env: Mapping[str, str]) -> Path:
    profile = env.get("USERPROFILE")
    return Path(profile) if profile else Path.home()


# --------------------------------------------------------------------------------------------------
# Values.
# --------------------------------------------------------------------------------------------------


def fmt(value: Any, unit: str = "") -> str:
    """A display string, escaped. ``None`` is "no data"; a percent carries its sign."""
    if value is None or value == "":
        return '<span class="nodata">no data</span>'
    if isinstance(value, bool):
        text = "yes" if value else "no"
    elif isinstance(value, float):
        text = f"{value:,.1f}".rstrip("0").rstrip(".") if value != int(value) else f"{value:,.0f}"
    elif isinstance(value, int):
        text = f"{value:,}"
    else:
        text = str(value)
    suffix = "%" if unit == "percent" else ""
    return esc(text) + suffix


def _status(value: Any) -> str:
    return value if value in STATUSES else "unknown"


# --------------------------------------------------------------------------------------------------
# Charts: inline SVG, coloured by CSS classes so both themes apply.
# --------------------------------------------------------------------------------------------------

W, H, PAD_L, PAD_R, PAD_T, PAD_B = 560, 220, 40, 12, 12, 36


def _scale(top: float) -> float:
    """A round axis top at or above ``top``."""
    if top <= 0:
        return 1.0
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000):
        if top <= step * 4:
            return float(step * 4)
    return float(top)


def _frame(weeks: Sequence[str], top: float, unit: str) -> list[str]:
    inner_w, inner_h = W - PAD_L - PAD_R, H - PAD_T - PAD_B
    parts = []
    for i in range(5):
        y = PAD_T + inner_h * i / 4
        label = top * (4 - i) / 4
        parts.append(
            f'<line class="grid" x1="{PAD_L}" x2="{W - PAD_R}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="axis" x="{PAD_L - 6}" y="{y + 4:.1f}" text-anchor="end">'
            f"{esc(f'{label:g}')}{esc(unit)}</text>"
        )
    for i, week in enumerate(weeks):
        x = PAD_L + inner_w * (i + 0.5) / max(len(weeks), 1)
        parts.append(
            f'<text class="axis" x="{x:.1f}" y="{H - 12}" text-anchor="middle">'
            f"{esc(week.split('-')[-1])}</text>"
        )
    return parts


def _x(i: int, n: int) -> float:
    return PAD_L + (W - PAD_L - PAD_R) * (i + 0.5) / max(n, 1)


def _y(value: float, top: float) -> float:
    return PAD_T + (H - PAD_T - PAD_B) * (1 - value / top)


def _svg(title: str, body: list[str]) -> str:
    return (
        f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}" '
        f'preserveAspectRatio="xMidYMid meet">{"".join(body)}</svg>'
    )


def line_chart(
    title: str,
    weeks: Sequence[str],
    lines: Sequence[tuple[str, str, Mapping[str, Any]]],
    partial: set[str],
    *,
    top: float | None = None,
    reference: float | None = None,
    unit: str = "",
) -> str:
    """``lines`` is ``(name, css class, week -> value)``. A null week breaks the line; a week still
    in progress is drawn hollow."""
    values = [v for _, _, pts in lines for v in pts.values() if isinstance(v, (int, float))]
    axis_top = top if top is not None else _scale(max(values, default=0.0))
    body = _frame(weeks, axis_top, unit)
    if reference is not None:
        y = _y(reference, axis_top)
        body.append(f'<line class="ref" x1="{PAD_L}" x2="{W - PAD_R}" y1="{y:.1f}" y2="{y:.1f}"/>')
        body.append(
            f'<text class="axis" x="{W - PAD_R}" y="{y - 4:.1f}" text-anchor="end">'
            f"{esc(f'{reference:g}')}{esc(unit)} target</text>"
        )
    for name, css, pts in lines:
        run: list[str] = []
        segments: list[list[str]] = []
        for i, week in enumerate(weeks):
            v = pts.get(week)
            if isinstance(v, (int, float)):
                run.append(f"{_x(i, len(weeks)):.1f},{_y(float(v), axis_top):.1f}")
            elif run:
                segments.append(run)
                run = []
        if run:
            segments.append(run)
        for seg in segments:
            body.append(f'<polyline class="line {css}" points="{" ".join(seg)}"/>')
        for i, week in enumerate(weeks):
            v = pts.get(week)
            if isinstance(v, (int, float)):
                hollow = " hollow" if week in partial else ""
                body.append(
                    f'<circle class="dot {css}{hollow}" cx="{_x(i, len(weeks)):.1f}" '
                    f'cy="{_y(float(v), axis_top):.1f}" r="3.5"><title>{esc(name)} {esc(week)}: '
                    f"{esc(f'{v:g}')}</title></circle>"
                )
    return _svg(title, body)


def stacked_chart(
    title: str,
    weeks: Sequence[str],
    stacks: Sequence[tuple[str, str, Mapping[str, Any]]],
    partial: set[str],
) -> str:
    totals = [
        sum(float(pts.get(w) or 0) for _, _, pts in stacks if isinstance(pts.get(w), (int, float)))
        for w in weeks
    ]
    axis_top = _scale(max(totals, default=0.0))
    body = _frame(weeks, axis_top, "")
    slot = (W - PAD_L - PAD_R) / max(len(weeks), 1)
    bar_w = slot * 0.6
    for i, week in enumerate(weeks):
        base = 0.0
        x = PAD_L + slot * i + (slot - bar_w) / 2
        for name, css, pts in stacks:
            v = pts.get(week)
            if not isinstance(v, (int, float)) or v <= 0:
                continue
            y_top, y_base = _y(base + float(v), axis_top), _y(base, axis_top)
            hollow = " hollow" if week in partial else ""
            body.append(
                f'<rect class="bar {css}{hollow}" x="{x:.1f}" y="{y_top:.1f}" width="{bar_w:.1f}" '
                f'height="{y_base - y_top:.1f}"><title>{esc(name)} {esc(week)}: {esc(v)}'
                "</title></rect>"
            )
            base += float(v)
    return _svg(title, body)


def legend(items: Sequence[tuple[str, str]]) -> str:
    return (
        '<ul class="legend">'
        + "".join(f'<li><span class="key {css}"></span>{esc(name)}</li>' for name, css in items)
        + "</ul>"
    )


# --------------------------------------------------------------------------------------------------
# The page.
# --------------------------------------------------------------------------------------------------

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#5f5f5a;--line:#e2e2dc;
--good:#1f7a4d;--warn:#9a6300;--bad:#b3261e;--unknown:#6b6b66;
--s1:#2f5fb3;--s2:#c2571a;--s3:#6b4fa8;--ref:#8a8a84}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--ink:#ecebe6;
--muted:#a5a49d;--line:#33332f;--good:#5cc08c;--warn:#e0a640;--bad:#f07a6e;--unknown:#9a9993;
--s1:#7aa2ec;--s2:#f08c4e;--s3:#b399e8;--ref:#77766f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 6px}h2{font-size:16px;margin:0 0 8px}
.lede{color:var(--muted);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.tile,.chart{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile h3{font-size:14px;margin:0}.q{color:var(--muted);font-size:13px;margin:2px 0 8px}
.big{font-size:30px;font-weight:650;font-variant-numeric:tabular-nums}
.unit{color:var(--muted);font-size:13px;margin-left:4px}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:99px;
border:1px solid currentColor;margin-left:8px;vertical-align:middle}
.pill.good{color:var(--good)}.pill.warn{color:var(--warn)}.pill.bad{color:var(--bad)}
.pill.unknown{color:var(--unknown)}
dl{display:grid;grid-template-columns:1fr auto;gap:2px 12px;margin:10px 0;font-size:13px}
dt{color:var(--muted)}dd{margin:0;text-align:right;font-variant-numeric:tabular-nums}
.note{color:var(--muted);font-size:12px;margin:8px 0 0}
.err{color:var(--bad);font-size:12px;margin:6px 0 0;overflow-wrap:anywhere}
.nodata{color:var(--muted);font-style:italic;font-weight:400}
.charts{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;margin-top:20px}
svg{width:100%;height:auto;display:block}
.grid{stroke:var(--line);stroke-width:1}.ref{stroke:var(--ref);stroke-dasharray:4 4}
.axis{fill:var(--muted);font-size:11px}
.line{fill:none;stroke-width:2}.dot{stroke-width:2;fill:var(--card)}
.line.s1,.dot.s1{stroke:var(--s1)}.line.s2,.dot.s2{stroke:var(--s2)}.line.s3,.dot.s3{stroke:var(--s3)}
.dot.s1:not(.hollow){fill:var(--s1)}.dot.s2:not(.hollow){fill:var(--s2)}
.dot.s3:not(.hollow){fill:var(--s3)}
.bar.s1{fill:var(--s1)}.bar.s2{fill:var(--s2)}.bar.s3{fill:var(--s3)}.bar.hollow{opacity:.45}
.legend{list-style:none;padding:0;margin:6px 0 0;display:flex;gap:14px;font-size:12px;
color:var(--muted);flex-wrap:wrap}
.key{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
.key.s1{background:var(--s1)}.key.s2{background:var(--s2)}.key.s3{background:var(--s3)}
footer{color:var(--muted);font-size:12px;margin-top:24px}
"""


def lede(headline: Sequence[Mapping[str, Any]]) -> str:
    counts = dict.fromkeys(STATUSES, 0)
    for row in headline:
        counts[_status(row.get("status"))] += 1
    parts = [f"{counts[s]} {s}" for s in ("good", "warn", "bad") if counts[s]]
    if counts["unknown"]:
        parts.append(f"{counts['unknown']} with no data")
    text = f"{len(headline)} headline metrics: " + (", ".join(parts) or "none read") + "."
    bad = [str(r.get("label") or r.get("id")) for r in headline if r.get("status") == "bad"]
    if bad:
        text += " Bad: " + ", ".join(bad) + "."
    return esc(text)


def tile(row: Mapping[str, Any], facts: Sequence[Mapping[str, Any]]) -> str:
    status = _status(row.get("status"))
    unit = str(row.get("unit") or "")
    shown_unit = "" if unit == "percent" else unit
    dl = "".join(f"<dt>{esc(f.get('label', ''))}</dt><dd>{fmt(f.get('value'))}</dd>" for f in facts)
    error = row.get("error")
    return (
        '<section class="tile">'
        f"<h3>{esc(row.get('label', ''))}"
        f'<span class="pill {status}">{esc(status if status != "unknown" else "no data")}</span>'
        "</h3>"
        f'<p class="q">{esc(row.get("question", ""))}</p>'
        f'<div><span class="big">{fmt(row.get("value"), unit)}</span>'
        + (f'<span class="unit">{esc(shown_unit)}</span>' if shown_unit else "")
        + "</div>"
        + (f"<dl>{dl}</dl>" if dl else "")
        + (f'<p class="note">{esc(row["note"])}</p>' if row.get("note") else "")
        + (f'<p class="err">{esc(error)}</p>' if error else "")
        + "</section>"
    )


def _points(series: Sequence[Mapping[str, Any]], name: str) -> dict[str, Any]:
    return {str(r["week"]): r.get("value") for r in series if r.get("series") == name}


def render(data: dict[str, Any], *, source_name: str = "snapshot.json") -> str:
    """The whole page for one snapshot. Never raises on a missing metric or field."""
    tr = _to_rows()
    snap = tr.Snapshot(data)
    rows = tr.metric_rows(snap)
    series = tr.series_rows(snap)
    headline = [r for r in rows if "." not in str(r["id"])]
    by_metric: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        mid, dot, _ = str(r["id"]).partition(".")
        if dot:
            by_metric.setdefault(mid, []).append(r)
    weeks = snap.weeks
    partial = {str(r["week"]) for r in series if r.get("partial")}

    burn = line_chart(
        "Ledger rows filed and closed per week",
        weeks,
        [("Filed", "s2", _points(series, "Filed")), ("Closed", "s1", _points(series, "Closed"))],
        partial,
    )
    # Series names and the CI bar come from their owners, so a rename or a new threshold shows here.
    repos = [(name, f"s{i}") for i, (_, name) in enumerate(tr.repo_series(), start=1)]
    merged = stacked_chart(
        "Pull requests merged per week",
        weeks,
        [(n, c, _points(series, n)) for n, c in repos],
        partial,
    )
    ci_bar = float(tr._collector().THRESHOLDS["ci_main"]["good_pct"])
    ci = line_chart(
        "CI pass percent on main per week",
        weeks,
        [("CI pass %", "s1", _points(series, "CI pass %"))],
        partial,
        top=100.0,
        reference=ci_bar,
        unit="%",
    )
    tiles = "".join(tile(r, by_metric.get(str(r["id"]), [])) for r in headline)
    if not tiles:
        tiles = '<p class="nodata">no data: the snapshot holds no metrics</p>'
    generated = data.get("generated_at") or "unknown"
    window = f"{weeks[0]} to {weeks[-1]}" if weeks else "unknown"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Project Progress</title>
<style>{CSS}</style>
</head>
<body>
<main>
<h1>Project progress</h1>
<p class="lede">{lede(headline)} Window {esc(window)}, through {esc(data.get("through") or "unknown")}.</p>
<div class="tiles">{tiles}</div>
<div class="charts">
<section class="chart"><h2>Ledger rows filed and closed</h2>{burn}
{legend([("Filed", "s2"), ("Closed", "s1")])}</section>
<section class="chart"><h2>Pull requests merged per week</h2>{merged}
{legend(repos)}</section>
<section class="chart"><h2>CI pass percent on main</h2>{ci}
{legend([("CI pass %", "s1")])}</section>
</div>
<footer>
<p>Generated at {esc(generated)} from {esc(source_name)}.</p>
<p>Method: scripts/dashboard/collect_metrics.py read each source at run time; to_rows.py flattened
the snapshot and render_html.py drew this page. A value that could not be read shows as no data,
never as zero, and its reason is printed in its tile. A hollow point or faded bar is a week still in
progress. State metrics (open PRs, alerts, ASVS, ledger rows, release distance) are as of the run,
whatever the window says.</p>
</footer>
</main>
</body>
</html>
"""


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "snapshot", type=Path, nargs="?", help="a snapshot written by collect_metrics.py"
    )
    ap.add_argument("--out-dir", type=Path, default=None, help="where index.html goes")
    ap.add_argument(
        "--print-out-dir",
        action="store_true",
        help="print the directory the page would be written to, and write nothing",
    )
    args = ap.parse_args(argv)
    out = resolve_out_dir(args.out_dir, os.environ, _home(os.environ)).resolve()
    if args.print_out_dir:
        print(out)
        return 0
    if args.snapshot is None:
        ap.error("the snapshot path is required unless --print-out-dir is given")
    tr = _to_rows()
    cm = tr._collector()
    reason = cm.refuse_dir_reason(tr._nearest_existing(out).resolve())
    if reason is not None:
        print(f"ERROR: refusing out dir {out}: {reason}", file=sys.stderr)
        return 1
    try:
        data = json.loads(args.snapshot.read_text(encoding="utf-8"), parse_constant=lambda _: None)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot read {args.snapshot}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if not isinstance(data, dict):
        print(f"ERROR: {args.snapshot} is not a snapshot object", file=sys.stderr)
        return 1
    # The footer names the copy published beside the page, not the input, which may be temporary.
    page = render(data, source_name="snapshot.json")
    try:
        out.mkdir(parents=True, exist_ok=True)
        # The snapshot first: a page is never newer than the data published beside it.
        cm.write_json_atomic(out / "snapshot.json", data)
        cm.write_text_atomic(out / "index.html", page)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot write {out}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print((out / "index.html").as_uri())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
