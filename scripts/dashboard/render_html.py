#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Render a ``collect_metrics.py`` snapshot as ONE self-contained static ``index.html``.

THE PAGE IS SELF-CONTAINED: inline CSS and inline SVG charts, no script, font, image or CDN
fetched from anywhere, so it opens from ``file://`` with no network. Light and dark follow the
viewer's ``prefers-color-scheme``. The ledger charts' range buttons are radio inputs styled with
CSS alone: every range is drawn into the page, and the checked one is shown, so the page still
needs no script and its Content-Security-Policy still allows none.

EVERY SNAPSHOT VALUE IS DATA. Each one is HTML-escaped before it reaches the page, and a metric
that could not be read renders as "no data", never as zero.

WHERE IT WRITES, first match wins: ``--out-dir``; the ``MEFOR_DASHBOARD_DIR`` environment variable;
``%USERPROFILE%/OneDrive/Desktop/MEFOR/dashboard`` when ``OneDrive/Desktop/MEFOR`` already exists;
otherwise ``%USERPROFILE%/MEFOR/dashboard``. It writes ``index.html`` alone, through a temporary
file and an atomic replace, so a failed run leaves the previous page whole; the snapshot is its
input and is never copied beside the page. The page quotes the same private vault counts as the
snapshot, so the directory is refused, before anything is read, whenever the collector's guard
(``refuse_dir_reason``) finds git reporting a work tree there; that guard's docstring says what
it cannot see. Every ASVS number is shown beside the collector's ref pair (``to_rows.py`` says how
it is built), its commits shortened on the tile and given in full. The scorecard tool's own ``#``
header line (the one the collector reads ``engine=`` from) is on the tile's face, labelled when
its scorecard half reads ``NO-GIT`` so the collector's pair is the one to quote; the tool's other
``#`` provenance lines are in the tile's "how it is measured" disclosure. The ASVS headline is shown
beside its needs-review and unverified counts, or not at all unless the snapshot holds both.

TIMES ARE US CENTRAL (``to_rows.central``), with the UTC time beside the page's own stamp.

The rows are built by ``to_rows.py``, so the page and the row files never disagree.

EXIT STATUS. 0 when the page was written, and its ``file:///`` URL is printed; 1 when it was not.

Usage::

    python scripts/dashboard/render_html.py C:/outside/any/repo/metrics.json [--out-dir DIR]
"""

from __future__ import annotations

import argparse
import html
import io
import math
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypeGuard

# The sibling scripts are imported by name from this directory: it is no package, and under
# ``python -I`` the script's own directory is not on the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import collect_metrics as cm  # noqa: E402
import to_rows as tr  # noqa: E402

ENV_DIR = "MEFOR_DASHBOARD_DIR"
#: ``info`` is a progress number with no health bar behind it.
STATUSES = ("good", "warn", "bad", "info", "unknown")


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
        if not math.isfinite(value):
            return '<span class="nodata">no data</span>'
        if value.is_integer():
            text = f"{value:,.0f}"
        elif abs(value) < 0.05:
            # One decimal would show a nonzero value as 0; keep two significant digits instead.
            text = f"{value:.2g}"
        else:
            # A value the collector wrote at two places (a weekly pace) keeps both, so the page
            # prints the figure a date beside it was worked from; anything finer shows one.
            places = 2 if round(value, 2) == value else 1
            text = f"{value:,.{places}f}".rstrip("0").rstrip(".")
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
#: At most this many week labels on an axis; a longer range labels every k-th week.
MAX_X_LABELS = 13


def _scale(top: float) -> float:
    """A round axis top at or above ``top``."""
    if top <= 0:
        return 1.0
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000):
        if top <= step * 4:
            return float(step * 4)
    return float(top)


def _short(n: float) -> str:
    return f"{n / 1000:g}k" if n >= 1000 else f"{n:g}"


class Axis:
    """A value axis: linear from 0 to ``top``, or log, 0 then each power of ten up to ``top``.

    The log axis plots ``log10(1 + v)``, so a zero stays on the chart and a week of 60 sits
    visibly apart from a week of 2,400. The grid starts at 10: a line for 1 would sit on top of 0."""

    def __init__(self, top: float, *, log: bool = False, unit: str = "") -> None:
        self.log, self.unit = log, unit
        self.power = max(1, math.ceil(math.log10(max(top, 1.0)))) if log else 0
        self.top = float(10**self.power) if log else top

    def frac(self, value: float) -> float:
        """0 at the bottom of the plot, 1 at the top."""
        if self.log:
            return math.log10(1 + max(value, 0.0)) / math.log10(1 + self.top)
        return value / self.top

    def ticks(self) -> list[tuple[float, str]]:
        if self.log:
            return [(0.0, "0")] + [
                (self.frac(10.0**p), _short(10.0**p)) for p in range(1, self.power + 1)
            ]
        return [(i / 4, f"{self.top * i / 4:g}") for i in range(5)]


def _x(i: int, n: int) -> float:
    return PAD_L + (W - PAD_L - PAD_R) * (i + 0.5) / max(n, 1)


def _y(value: float, axis: Axis) -> float:
    return PAD_T + (H - PAD_T - PAD_B) * (1 - axis.frac(value))


def _frame(weeks: Sequence[str], axis: Axis) -> list[str]:
    parts = []
    for frac, label in axis.ticks():
        y = PAD_T + (H - PAD_T - PAD_B) * (1 - frac)
        parts.append(
            f'<line class="grid" x1="{PAD_L}" x2="{W - PAD_R}" y1="{y:.1f}" y2="{y:.1f}"/>'
        )
        parts.append(
            f'<text class="axis" x="{PAD_L - 6}" y="{y + 4:.1f}" text-anchor="end">'
            f"{esc(label)}{esc(axis.unit)}</text>"
        )
    # The newest week is always labelled; older ones every `step` weeks back from it.
    step = max(1, math.ceil(len(weeks) / MAX_X_LABELS))
    for i, week in enumerate(weeks):
        if (len(weeks) - 1 - i) % step:
            continue
        parts.append(
            f'<text class="axis" x="{_x(i, len(weeks)):.1f}" y="{H - 12}" text-anchor="middle">'
            f"{esc(week.split('-')[-1])}</text>"
        )
    return parts


def _svg(title: str, body: list[str]) -> str:
    return (
        f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="{esc(title)}" '
        f'preserveAspectRatio="xMidYMid meet">{"".join(body)}</svg>'
    )


def _number(v: Any) -> TypeGuard[int | float]:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def line_chart(
    title: str,
    weeks: Sequence[str],
    lines: Sequence[tuple[str, str, Mapping[str, Any]]],
    partial: set[str],
    *,
    top: float | None = None,
    reference: float | None = None,
    unit: str = "",
    log: bool = False,
) -> str:
    """``lines`` is ``(name, css class, week -> value)``. A null week breaks the line; a week still
    in progress is drawn hollow. ``log`` draws a log axis (:class:`Axis`)."""
    # Only the weeks drawn set the axis, so a narrow range zooms in on its own values.
    values = [float(v) for _, _, pts in lines for w in weeks if _number(v := pts.get(w))]
    peak = max(values, default=0.0)
    axis = Axis(top if top is not None else peak if log else _scale(peak), log=log, unit=unit)
    radius = 3.5 if len(weeks) <= 26 else 2
    body = _frame(weeks, axis)
    if reference is not None:
        y = _y(reference, axis)
        body.append(f'<line class="ref" x1="{PAD_L}" x2="{W - PAD_R}" y1="{y:.1f}" y2="{y:.1f}"/>')
        body.append(
            f'<text class="axis" x="{W - PAD_R}" y="{y - 4:.1f}" text-anchor="end">'
            f"{esc(f'{reference:g}')}{esc(unit)} good bar</text>"
        )
    for name, css, pts in lines:
        run: list[str] = []
        segments: list[list[str]] = []
        for i, week in enumerate(weeks):
            v = pts.get(week)
            if _number(v):
                run.append(f"{_x(i, len(weeks)):.1f},{_y(float(v), axis):.1f}")
            elif run:
                segments.append(run)
                run = []
        if run:
            segments.append(run)
        for seg in segments:
            body.append(f'<polyline class="line {css}" points="{" ".join(seg)}"/>')
        for i, week in enumerate(weeks):
            v = pts.get(week)
            if _number(v):
                hollow = " hollow" if week in partial else ""
                body.append(
                    f'<circle class="dot {css}{hollow}" cx="{_x(i, len(weeks)):.1f}" '
                    f'cy="{_y(float(v), axis):.1f}" r="{radius}"><title>{esc(name)} {esc(week)}: '
                    f"{esc(f'{v:,g}')}</title></circle>"
                )
    return _svg(title, body)


def stacked_chart(
    title: str,
    weeks: Sequence[str],
    stacks: Sequence[tuple[str, str, Mapping[str, Any]]],
    partial: set[str],
) -> str:
    totals = [
        sum(float(pts.get(w) or 0) for _, _, pts in stacks if _number(pts.get(w))) for w in weeks
    ]
    axis = Axis(_scale(max(totals, default=0.0)))
    body = _frame(weeks, axis)
    slot = (W - PAD_L - PAD_R) / max(len(weeks), 1)
    bar_w = slot * 0.6
    for i, week in enumerate(weeks):
        base = 0.0
        x = PAD_L + slot * i + (slot - bar_w) / 2
        for name, css, pts in stacks:
            v = pts.get(week)
            if not _number(v) or v <= 0:
                continue
            y_top, y_base = _y(base + float(v), axis), _y(base, axis)
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
# Ledger ranges: every range drawn, the checked radio's shown, with CSS alone.
# --------------------------------------------------------------------------------------------------

#: The ranges offered, in weeks; one shorter than the history is offered, and "All" always is.
RANGES = (4, 8, 13, 26, 52)
DEFAULT_RANGE = 13


def ranges_for(n_weeks: int) -> list[tuple[str, int]]:
    """``(key, weeks)`` per range button; "all" covers the whole history."""
    out = [(str(n), n) for n in RANGES if n < n_weeks]
    return [*out, ("all", n_weeks)]


def default_range(options: Sequence[tuple[str, int]]) -> str:
    keys = [k for k, _ in options]
    return str(DEFAULT_RANGE) if str(DEFAULT_RANGE) in keys else keys[-1]


def range_css(options: Sequence[tuple[str, int]]) -> str:
    rules = []
    for key, _ in options:
        rules.append(f"#rg-{key}:checked~.charts .rv-{key}{{display:block}}")
        rules.append(
            f"#rg-{key}:checked~.ranges label[for=rg-{key}]"
            "{background:var(--ink);color:var(--card);border-color:var(--ink)}"
        )
        rules.append(
            f"#rg-{key}:focus-visible~.ranges label[for=rg-{key}]"
            "{outline:2px solid var(--s1);outline-offset:2px}"
        )
    return "".join(rules)


def range_controls(options: Sequence[tuple[str, int]], checked: str) -> str:
    inputs = "".join(
        f'<input class="rg" type="radio" name="range" id="rg-{key}"'
        + (" checked" if key == checked else "")
        + ">"
        for key, _ in options
    )
    labels = "".join(
        f'<label for="rg-{key}">'
        + esc("All" if key == "all" else f"{n} weeks")
        + (f" ({n})" if key == "all" else "")
        + "</label>"
        for key, n in options
    )
    return f'{inputs}<div class="ranges"><span>Ledger range</span>{labels}</div>'


def ranged(options: Sequence[tuple[str, int]], draw: Any) -> str:
    """One ``rv-<key>`` view per range; ``draw(n)`` draws the newest ``n`` weeks."""
    return "".join(f'<div class="rv rv-{key}">{draw(n)}</div>' for key, n in options)


# --------------------------------------------------------------------------------------------------
# The page.
# --------------------------------------------------------------------------------------------------

CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--muted:#5f5f5a;--line:#e2e2dc;
--good:#1f7a4d;--warn:#9a6300;--bad:#b3261e;--info:#2f5fb3;--unknown:#6b6b66;
--s1:#2f5fb3;--s2:#c2571a;--s3:#6b4fa8;--ref:#8a8a84}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--ink:#ecebe6;
--muted:#a5a49d;--line:#33332f;--good:#5cc08c;--warn:#e0a640;--bad:#f07a6e;--info:#7aa2ec;
--unknown:#9a9993;--s1:#7aa2ec;--s2:#f08c4e;--s3:#b399e8;--ref:#77766f}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 2px}h2{font-size:16px;margin:0 0 8px}
.stamp{font-size:14px;margin:0 0 8px;font-variant-numeric:tabular-nums}
.stamp span{color:var(--muted)}
.lede{color:var(--muted);margin:0 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}
.tile,.chart{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;
min-width:0}
.tile h3{font-size:14px;margin:0}.q{color:var(--muted);font-size:13px;margin:2px 0 8px}
.big{font-size:30px;font-weight:650;font-variant-numeric:tabular-nums}
.unit{color:var(--muted);font-size:13px;margin-left:4px}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:99px;
border:1px solid currentColor;margin-left:8px;vertical-align:middle}
.pill.good{color:var(--good)}.pill.warn{color:var(--warn)}.pill.bad{color:var(--bad)}
.pill.info{color:var(--info)}.pill.unknown{color:var(--unknown)}
dl{display:grid;grid-template-columns:1fr auto;gap:2px 12px;margin:10px 0;font-size:13px}
dt{color:var(--muted)}dd{margin:0;text-align:right;font-variant-numeric:tabular-nums;min-width:0;overflow-wrap:anywhere}
.note{color:var(--muted);font-size:12px;margin:8px 0 0}
details.how{font-size:12px;color:var(--muted);margin:8px 0 0}
details.how summary{cursor:pointer}
details.how p{margin:6px 0 0}
.mono{font:12px/1.4 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}
.err{color:var(--bad);font-size:12px;margin:6px 0 0;overflow-wrap:anywhere}
.nodata{color:var(--muted);font-style:italic;font-weight:400}
.charts{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;margin-top:12px}
.rg{position:absolute;opacity:0;width:1px;height:1px;margin:0}
.ranges{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:24px;font-size:13px}
.ranges span{color:var(--muted);margin-right:4px}
.ranges label{cursor:pointer;padding:3px 11px;border:1px solid var(--line);border-radius:99px;
background:var(--card);color:var(--ink)}
.rv{display:none}
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
.wide{margin-top:12px}.tablewrap{overflow-x:auto}
table.prio{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
.prio th,.prio td{padding:5px 10px;border-bottom:1px solid var(--line);text-align:right;white-space:nowrap}
.prio thead th{color:var(--muted);font-weight:600}
.prio tbody th,.prio thead th:first-child{text-align:left}
.prio tr.sum th,.prio tr.sum td{font-weight:650;border-bottom:none}
"""


def lede(headline: Sequence[Mapping[str, Any]]) -> str:
    counts = dict.fromkeys(STATUSES, 0)
    for row in headline:
        counts[_status(row.get("status"))] += 1
    parts = [f"{counts[s]} {s}" for s in ("good", "warn", "bad") if counts[s]]
    if counts["info"]:
        parts.append(f"{counts['info']} progress only")
    if counts["unknown"]:
        parts.append(f"{counts['unknown']} with no data")
    text = f"{len(headline)} headline metrics: " + (", ".join(parts) or "none read") + "."
    bad = [str(r.get("label") or r.get("id")) for r in headline if r.get("status") == "bad"]
    if bad:
        text += " Bad: " + ", ".join(bad) + "."
    return esc(text)


_SHA = re.compile(r"\b([0-9a-f]{7})[0-9a-f]{33}\b")


def short_pair(pair: str) -> str:
    """The ref pair with each full commit cut to seven characters, for the tile's face."""
    return _SHA.sub(r"\1", pair)


def tile(
    row: Mapping[str, Any],
    facts: Sequence[Mapping[str, Any]],
    provenance_lines: Sequence[str] = (),
) -> str:
    status = _status(row.get("status"))
    unit = str(row.get("unit") or "")
    shown_unit = "" if unit == "percent" else unit
    # The scorecard tool's provenance lines are part of the measurement (scripts/asvs/CLAUDE.md).
    # Its header, the line the collector reads engine= from, stays on the face; the other tool
    # lines sit in the disclosure.
    header_line = cm.asvs_header_line(provenance_lines)
    tool_lines = [ln for ln in provenance_lines if ln != header_line]
    shown = [f for f in facts if not str(f.get("id", "")).endswith(".provenance")]
    dl = "".join(f"<dt>{esc(f.get('label', ''))}</dt><dd>{fmt(f.get('value'))}</dd>" for f in shown)
    error = row.get("error")
    if row.get("ref") and header_line is None:
        # A missing tool header is said on the tile's face, never only inside the disclosure,
        # and beside any other error rather than hidden by it.
        # Its own words, not the provenance fact's error: that fact inherits the metric's error,
        # which says why the metric failed, not that the header is absent.
        # The collector's own words for a header-less list, so its partial error is not repeated.
        reason = (
            "scorecard provenance printed no engine= ref"
            if provenance_lines
            else "the snapshot holds no scorecard provenance lines"
        )
        if not error:
            error = reason
        elif reason not in str(error):
            error = f"{error}; {reason}"
    note = f'<p class="note">{esc(row["note"])}</p>' if row.get("note") else ""
    how = ""
    header = ""
    if row.get("ref"):
        if header_line:
            # The tool reads an archived scorecard copy, and the scheduled refresh runs it from
            # an archive, so either half can read NO-GIT; labelled, so the face says which pair
            # to quote.
            label = (
                '<p class="note">Scorecard tool header, as printed. A NO-GIT half is a ref the '
                "tool could not stamp because it read an archive; quote the collector's ref pair "
                "under Measured at instead.</p>"
                if "NO-GIT" in header_line
                else ""
            )
            header = f'{label}<p class="mono">{esc(header_line)}</p>'
        # The ASVS ref pair sits beside the value it qualifies, never only in a footnote.
        lines = [
            f'<p>Collector ref pair:</p><p class="mono">{esc(row["ref"])}</p>',
            (
                '<p>Scorecard tool provenance:</p><p class="mono">'
                + "<br>".join(esc(ln) for ln in tool_lines)
                + "</p>"
                if tool_lines
                else ""
            ),
            f"<p>{esc(row['note'])}</p>" if row.get("note") else "",
        ]
        how = (
            '<details class="how"><summary>Measured at '
            f'<span class="mono">{esc(short_pair(str(row["ref"])))}</span></summary>'
            + "".join(lines)
            + "</details>"
        )
        note = ""
    return (
        '<section class="tile">'
        f"<h3>{esc(row.get('label', ''))}"
        f'<span class="pill {status}">{esc(status if status != "unknown" else "no data")}</span>'
        "</h3>"
        f'<p class="q">{esc(row.get("question", ""))}</p>'
        f'<div><span class="big">{fmt(row.get("value"), unit)}</span>'
        + (f'<span class="unit">{esc(shown_unit)}</span>' if shown_unit else "")
        + "</div>"
        + header
        + (f"<dl>{dl}</dl>" if dl else "")
        + how
        + note
        + (f'<p class="err">{esc(error)}</p>' if error else "")
        + "</section>"
    )


def priority_table(rows: Sequence[Mapping[str, Any]]) -> str:
    """Ledger rows by priority (rows) and status (columns), with totals; "no data" when the
    snapshot holds no priority census."""
    if not rows:
        return '<p class="nodata">no data: the snapshot holds no priority census</p>'
    priorities = list(dict.fromkeys(str(r["priority"]) for r in rows))
    statuses = list(dict.fromkeys(str(r["status"]) for r in rows))
    cell = {(str(r["priority"]), str(r["status"])): r.get("value") for r in rows}

    def total(values: Sequence[Any]) -> Any:
        # A total over a cell with no measurement is no measurement either.
        return None if any(not _number(v) for v in values) else sum(values)

    head = "".join(f"<th>{esc(s.capitalize())}</th>" for s in statuses)
    body = []
    for p in priorities:
        values = [cell.get((p, s)) for s in statuses]
        label = tr.PRIORITY_LABELS.get(p, p)
        body.append(
            f"<tr><th>{esc(label)}</th>"
            + "".join(f"<td>{fmt(v)}</td>" for v in values)
            + f"<td>{fmt(total(values))}</td></tr>"
        )
    columns = [total([cell.get((p, s)) for p in priorities]) for s in statuses]
    body.append(
        '<tr class="sum"><th>Total</th>'
        + "".join(f"<td>{fmt(v)}</td>" for v in columns)
        + f"<td>{fmt(total(columns))}</td></tr>"
    )
    return (
        '<div class="tablewrap"><table class="prio"><thead><tr><th>Priority</th>'
        f"{head}<th>Total</th></tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _points(series: Sequence[Mapping[str, Any]], name: str) -> dict[str, Any]:
    return {str(r["week"]): r.get("value") for r in series if r.get("series") == name}


def ledger_charts(snap: tr.Snapshot, series: Sequence[Mapping[str, Any]]) -> tuple[str, str]:
    """The ranged filed-and-closed chart (log axis) and the burndown, with the range controls."""
    hist = [r for r in series if r.get("series") in {name for name, _ in tr.HISTORY_SERIES}]
    weeks = sorted({str(r["week"]) for r in hist})
    if weeks:
        # By ledger_history key, never by position, so reordering HISTORY_SERIES swaps nothing.
        by_key = {key: _points(hist, name) for name, key in tr.HISTORY_SERIES}
        filed, closed, opened = by_key["filed"], by_key["closed"], by_key["open"]
        partial = {str(r["week"]) for r in hist if r.get("partial")}
    else:
        # A snapshot from before the history was collected: its window alone, as before.
        weeks = list(snap.weeks)
        filed, closed, opened = _points(series, "Filed"), _points(series, "Closed"), {}
        partial = {str(r["week"]) for r in series if r.get("partial")}
    options = ranges_for(len(weeks))
    checked = default_range(options)

    def burn(n: int) -> str:
        return line_chart(
            "Ledger rows filed and closed per week, log scale",
            weeks[-n:],
            [("Filed", "s2", filed), ("Closed", "s1", closed)],
            partial,
            log=True,
        )

    def down(n: int) -> str:
        return line_chart(
            "Open ledger rows at the end of each week",
            weeks[-n:],
            [("Open", "s3", opened)],
            partial,
        )

    forecast = tr.forecast_line(snap)
    has_open = any(_number(v) for v in opened.values())
    # A caveat on the worked-back count only beside a count that was drawn.
    undated = tr.burndown_undated_note(snap) if has_open else None
    controls = range_controls(options, checked)
    charts = (
        '<section class="chart"><h2>Ledger rows filed and closed</h2>'
        + ranged(options, burn)
        + legend([("Filed", "s2"), ("Closed", "s1")])
        + '<p class="note">Log scale: each grid line is ten times the one below it.</p></section>'
        '<section class="chart"><h2>Backlog burndown</h2>'
        + ranged(options, down)
        + legend([("Open rows", "s3")])
        + ("" if has_open else '<p class="nodata">no data</p>')
        + '<p class="note">Open rows at the end of each week, worked back from the count at run '
        "time through each week's filed and closed rows."
        + (f" {esc(undated)}" if undated else "")
        + (f" {esc(forecast)}" if forecast else "")
        + "</p></section>"
    )
    # The caller closes the .charts div after appending the window charts to it.
    return range_css(options), controls + f'<div class="charts">{charts}'


def render(data: dict[str, Any]) -> str:
    """The whole page for one snapshot. Never raises on a missing metric or field."""
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

    extra_css, ledger = ledger_charts(snap, series)
    # Series names and the CI bar come from their owners, so a rename or a new threshold shows here.
    repos = [(name, f"s{i}") for i, (_, name) in enumerate(tr.repo_series(), start=1)]
    merged = stacked_chart(
        "Pull requests merged per week",
        weeks,
        [(n, c, _points(series, n)) for n, c in repos],
        partial,
    )
    ci_bar = float(cm.THRESHOLDS["ci_main"]["good_pct"])
    ci = line_chart(
        "CI pass percent on main per week",
        weeks,
        [("CI pass %", "s1", _points(series, "CI pass %"))],
        partial,
        top=100.0,
        reference=ci_bar,
        unit="%",
    )
    raw_lines = snap.detail("asvs").get("provenance")
    lines = [str(ln) for ln in raw_lines if str(ln).strip()] if isinstance(raw_lines, list) else []
    tiles = "".join(
        tile(r, by_metric.get(str(r["id"]), []), lines if r["id"] == "asvs" else ())
        for r in headline
    )
    if not tiles:
        tiles = '<p class="nodata">no data: the snapshot holds no metrics</p>'
    generated = data.get("generated_at")
    stamp = tr.central(generated)
    utc = tr.utc_clock(generated)
    stamp_html = (
        f"Updated {esc(stamp)}" + (f" <span>({esc(utc)})</span>" if utc else "")
        if stamp
        else '<span class="nodata">update time unknown</span>'
    )
    window = f"{weeks[0]} to {weeks[-1]}" if weeks else "unknown"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Project Progress</title>
<style>{CSS}{extra_css}</style>
</head>
<body>
<main>
<h1>Project progress</h1>
<p class="stamp">{stamp_html}</p>
<p class="lede">{lede(headline)} Window {esc(window)}, through {esc(data.get("through") or "unknown")} (UTC).</p>
<div class="tiles">{tiles}</div>
<section class="chart wide"><h2>Ledger rows by priority</h2>{priority_table(tr.priority_rows(snap))}
<p class="note">Every ledger row that carries a status banner, open and closed, by its tier and its status
banner. The tier is the one on the row's first banner score line, else the priority on its own
Cluster line. A row with a score but neither tier is in the "Scored, no tier" row; most of
these are filing estimates. A row with no score and no Cluster priority is unscored. Open,
partial and in progress are open rows; closed, declined and superseded are closed ones. As of the vault at run time.</p></section>
{ledger}
<section class="chart"><h2>Pull requests merged per week</h2>{merged}
{legend(repos)}</section>
<section class="chart"><h2>CI pass percent on main</h2>{ci}
{legend([("CI pass %", "s1")])}</section>
</div>
<footer>
<p>Method: scripts/dashboard/collect_metrics.py read each source at run time; to_rows.py flattened
the snapshot and render_html.py drew this page. A value that could not be read shows as no data,
never as zero, and its reason is printed in its tile. A hollow point or faded bar is a week still in
progress. The ledger range buttons apply to the two ledger charts; the pull request and CI charts
cover the window. State metrics (alerts, ASVS, ledger rows, release distance) are as of
the run, whatever the window says. Times are US Central.</p>
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
    # UTF-8 out, whatever the console: the caller reads the printed path back, and -I ignores
    # PYTHONIOENCODING.
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8", errors="strict")
    out = resolve_out_dir(args.out_dir, os.environ, _home(os.environ)).resolve()
    # Refused before anything else, --print-out-dir included, so a caller asks this FIRST and
    # never collects for a directory the page may not be written to.
    reason = cm.refuse_out_dir(out)
    if reason is not None:
        print(f"ERROR: refusing out dir {out}: {reason}", file=sys.stderr)
        return 1
    if args.print_out_dir:
        print(out)
        return 0
    if args.snapshot is None:
        ap.error("the snapshot path is required unless --print-out-dir is given")
    data = tr.load_snapshot(args.snapshot)
    if isinstance(data, str):
        print(f"ERROR: {data}", file=sys.stderr)
        return 1
    page = render(data)
    try:
        out.mkdir(parents=True, exist_ok=True)
        # The page only: the snapshot is this script's input and is not published beside it.
        cm.write_text_atomic(out / "index.html", page)
    except (OSError, ValueError) as exc:
        print(f"ERROR: cannot write {out}: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print((out / "index.html").as_uri())
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
