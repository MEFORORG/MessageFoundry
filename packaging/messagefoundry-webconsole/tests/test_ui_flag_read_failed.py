# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A failed flag read reads as unknown on the dashboard, never as no flags (BACKLOG #2623).

``ConnectionRow.flagged`` is ``None`` when the store's read failed. Taken for ``False``, that would
hide every row under Flagged only, on an empty page with no reason given, and every row's toggle
would post ``flagged=true`` until the read recovered: a value derived from a read that failed.
``tests/test_connection_audit_writes.py`` pins the ``None``. These tests pin what the console does
with it. The filter tests run the REAL ``static/app.js`` under Node with a fake DOM, because a text
grep of the source cannot tell which rows it hides.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

import messagefoundry_webconsole
from messagefoundry.api.models import ConnectionRow
from messagefoundry_webconsole.pages import connections as connection_pages

_APP_JS = Path(messagefoundry_webconsole.__file__).parent / "static" / "app.js"
_NODE = shutil.which("node")

#: Loads app.js against just enough of a browser for the connections filter and the toolbar, one row
#: per given ``data-flagged`` value, then runs the steps: ``"click"`` clicks select-all, ``"swap"``
#: replaces the table as a poll does, firing the observers in the order the page registered them, and
#: ``{"tick": value}`` clicks that row's box, and ``{"query": text}`` types into the filter. Prints
#: which values stayed visible and which are selected.
_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const [appPath, valuesJson, flaggedOnlyJson, stepsJson] = process.argv.slice(2);
const makeRows = () => JSON.parse(valuesJson).map((value) => {
  const row = { value, style: {}, textContent: `row ${value}` };
  row.cb = {
    value,
    checked: false,
    getAttribute(name) { return name === "data-flagged" ? value : null; },
    hasAttribute(name) { return name === "data-mf-conns-cb"; },
    closest() { return row; },
  };
  row.querySelector = () => row.cb;
  return row;
});
let rows = makeRows();
const all = {
  checked: false,
  indeterminate: false,
  hasAttribute(name) { return name === "data-mf-conns-all"; },
};
const listeners = {};
const poll = {
  querySelectorAll(sel) {
    return sel === "tbody tr" ? rows : rows.map((r) => r.cb);
  },
  querySelector() { return all; },
  addEventListener(type, fn) { listeners[type] = fn; },
  dispatchEvent(event) { listeners[event.type]?.(event); },
};
const input = { value: "", addEventListener(_type, fn) { input.onInput = fn; } };
const flaggedOnly = { checked: JSON.parse(flaggedOnlyJson), addEventListener() {} };
const toolbar = { querySelector() { return null; } };
const hooks = {
  "[data-poll]": poll,
  "[data-mf-conns-filter]": input,
  "[data-mf-conns-flagged]": flaggedOnly,
  "[data-mf-conns-toolbar]": toolbar,
};
const document = {
  querySelector(sel) { return hooks[sel] ?? null; },
  querySelectorAll() { return []; },
  getElementById() { return null; },
  addEventListener() {},
  body: { classList: { contains() { return false; } } },
};
const observers = [];
class FakeObserver {
  constructor(fn) { observers.push(fn); }
  observe() {}
}
const sandbox = {
  document,
  window: { addEventListener() {}, location: {} },
  location: { protocol: "https:", host: "ops.example" },
  MutationObserver: FakeObserver,
  Set,
  Date,
  Math,
  JSON,
  Object,
  Event: class { constructor(type) { this.type = type; } },
  parseInt,
  setInterval() { return 1; },
  clearInterval() {},
  setTimeout() { return 1; },
  clearTimeout() {},
  fetch() { return new Promise(() => {}); },
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(appPath, "utf8"), sandbox);
for (const step of JSON.parse(stepsJson)) {
  if (step === "click") {
    all.checked = !all.checked;
    listeners.change({ target: all });
  } else if (step === "swap") {
    rows = makeRows();
    all.checked = false;
    all.indeterminate = false;
    observers.forEach((fn) => fn());
  } else if ("query" in step) {
    input.value = step.query;
    input.onInput();
  } else {
    const { cb } = rows.find((r) => r.value === step.tick);
    cb.checked = !cb.checked;
    listeners.change({ target: cb });
  }
}
console.log(JSON.stringify({
  visible: rows.filter((r) => r.style.display !== "none").map((r) => r.value),
  selected: rows.filter((r) => r.cb.checked).map((r) => r.value),
  header: all.checked,
  indeterminate: all.indeterminate,
}));
"""


def _run_app_js(
    tmp_path: Path,
    *,
    flagged_only: bool,
    values: tuple[str, ...] = ("1", "0", "unknown"),
    steps: tuple[str | dict[str, str], ...] = ("click",),
    query: str = "",
) -> dict[str, Any]:
    if query:
        steps = ({"query": query}, *steps)
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS, encoding="utf-8")
    assert _NODE is not None
    proc = subprocess.run(
        [
            _NODE,
            str(harness),
            str(_APP_JS),
            json.dumps(values),
            json.dumps(flagged_only),
            json.dumps(steps),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    result: dict[str, Any] = json.loads(proc.stdout.strip().splitlines()[-1])
    return result


def _row(*, flagged: bool | None, status: str = "running") -> ConnectionRow:
    return ConnectionRow.model_construct(
        role="destination",
        channel_id="IB_A",
        channel_name="IB_A",
        destination="OB_A",
        name="OB_A",
        status=status,
        direction="out",
        flagged=flagged,
        paused=False,
        waiting_for_reply=False,
        queue_depth=0,
        errored=0,
        alerts_active=0,
        read=0,
        written=0,
        idle_seconds=None,
    )


@pytest.mark.parametrize("status", ["running", "draining"])
def test_a_failed_read_offers_no_toggle(status: str) -> None:
    """RED when the row reads as unflagged: its form posts ``flagged=true``, from a failed read."""
    cell = str(connection_pages._flag_cell(_row(flagged=None, status=status)))
    assert "<form" not in cell
    assert 'name="flagged"' not in cell


@pytest.mark.parametrize("flagged", [False, True])
def test_a_read_that_answered_still_offers_the_toggle(flagged: bool) -> None:
    """The control: the toggle goes only for a failed read, and it still posts the opposite value."""
    cell = str(connection_pages._flag_cell(_row(flagged=flagged)))
    assert 'action="/ui/connections/OB_A/flag"' in cell
    assert f'name="flagged" value="{str(not flagged).lower()}"' in cell


@pytest.mark.parametrize(("flagged", "attribute"), [(None, "unknown"), (False, "0"), (True, "1")])
def test_the_row_tells_the_filter_which_of_the_three_it_is(
    flagged: bool | None, attribute: str
) -> None:
    fragment = str(connection_pages.connections_fragment([_row(flagged=flagged)]))
    assert f'data-flagged="{attribute}"' in fragment


def test_the_page_says_why_the_flags_are_missing() -> None:
    """An operator with no markers, no toggles and every row under Flagged only is told the cause
    on the page. The banner sits in the polled fragment, so it clears on the first read that
    answers."""
    failed = str(connection_pages.connections_fragment([_row(flagged=None)]))
    assert connection_pages.FLAGS_UNREAD_NOTICE in failed
    answered = str(connection_pages.connections_fragment([_row(flagged=False)]))
    assert connection_pages.FLAGS_UNREAD_NOTICE not in answered
    assert connection_pages.FLAGS_UNREAD_NOTICE not in str(
        connection_pages.connections_fragment([])
    )


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_flagged_only_hides_only_a_row_known_to_be_unflagged(tmp_path: Path) -> None:
    """RED when an unknown row is hidden: a failed read then empties the page under Flagged only.
    The ``"0"`` row is the control, so a pass is not a filter that stopped filtering."""
    assert _run_app_js(tmp_path, flagged_only=True)["visible"] == ["1", "unknown"]


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_select_all_under_flagged_only_takes_no_row_of_unknown_flag(tmp_path: Path) -> None:
    """A failed read keeps an unknown row on screen, so visibility alone would let one transient
    error sweep every connection into a bulk action the operator scoped to flagged rows. RED when
    select-all takes the ``"unknown"`` row."""
    assert _run_app_js(tmp_path, flagged_only=True)["selected"] == ["1"]


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_select_all_with_flagged_only_off_takes_every_row(tmp_path: Path) -> None:
    """The control: the skip belongs to the filter. With it off, the flag has no say."""
    assert _run_app_js(tmp_path, flagged_only=False) == {
        "visible": ["1", "0", "unknown"],
        "selected": ["1", "0", "unknown"],
        "header": True,
        "indeterminate": False,
    }


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_a_select_all_that_took_nothing_leaves_its_box_clear(tmp_path: Path) -> None:
    """RED when the box stays ticked: the next click is then the uncheck, which clears every row,
    including those the operator ticked by hand."""
    run = _run_app_js(tmp_path, flagged_only=True, values=("unknown", "unknown"))
    assert run["selected"] == [] and run["header"] is False


#: Each hides a row: Flagged only hides the ``"0"`` row and select-all skips ``"unknown"``, and the
#: typed query hides everything but ``"1"``.
_FILTERED = pytest.mark.parametrize(
    "filtered",
    [{"flagged_only": True}, {"flagged_only": False, "query": "row 1"}],
    ids=["flagged-only", "typed-query"],
)


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
@_FILTERED
def test_a_filtered_select_all_keeps_its_box_ticked_and_the_next_click_clears(
    tmp_path: Path, filtered: dict[str, Any]
) -> None:
    """RED when the box counts every rendered row: it clears as soon as it is clicked, and the next
    click selects again rather than clearing."""
    once = _run_app_js(tmp_path, steps=("click",), **filtered)
    assert once["selected"] == ["1"] and once["header"] is True and once["indeterminate"] is False
    twice = _run_app_js(tmp_path, steps=("click", "click"), **filtered)
    assert twice["selected"] == [] and twice["header"] is False


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
@_FILTERED
def test_a_swap_leaves_a_filtered_select_all_ticked(
    tmp_path: Path, filtered: dict[str, Any]
) -> None:
    """A poll replaces the table every few seconds, and the toolbar's observer runs before the
    filter hides the fresh rows. RED when the box is judged only there: every row then counts as
    takeable, so the box clears on the first tick and the next click selects again."""
    swapped = _run_app_js(tmp_path, steps=("click", "swap"), **filtered)
    assert swapped["selected"] == ["1"] and swapped["header"] is True
    cleared = _run_app_js(tmp_path, steps=("click", "swap", "click"), **filtered)
    assert cleared["selected"] == [] and cleared["header"] is False


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_a_part_selection_of_the_rows_it_can_take_reads_as_part(tmp_path: Path) -> None:
    """The control: ticking the box is earned by every takeable row, not by any one of them."""
    run = _run_app_js(tmp_path, flagged_only=False, steps=({"tick": "1"},))
    assert run["header"] is False and run["indeterminate"] is True
    run = _run_app_js(tmp_path, flagged_only=True, values=("1", "unknown"), steps=({"tick": "1"},))
    assert run["header"] is True and run["indeterminate"] is False, "the only row it can take"


@pytest.mark.skipif(_NODE is None, reason="node is not installed")
def test_typing_a_filter_judges_the_box_again(tmp_path: Path) -> None:
    """RED when only a click or a swap judges the box: it then reads the rows from before the
    filter moved until the next poll. A selected row the filter hides stays selected, so the box
    reads as part ticked rather than empty."""
    steps: tuple[dict[str, str], ...] = ({"tick": "1"}, {"query": "row 1"})
    run = _run_app_js(tmp_path, flagged_only=False, values=("1", "0"), steps=steps)
    assert run["header"] is True and run["indeterminate"] is False
    steps = ({"tick": "0"}, {"query": "row 1"})
    run = _run_app_js(tmp_path, flagged_only=False, values=("1", "0"), steps=steps)
    assert run["selected"] == ["0"] and run["visible"] == ["1"]
    assert run["header"] is False and run["indeterminate"] is True
