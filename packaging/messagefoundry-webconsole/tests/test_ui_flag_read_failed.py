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

import pytest

import messagefoundry_webconsole
from messagefoundry.api.models import ConnectionRow
from messagefoundry_webconsole.pages import connections as connection_pages

_APP_JS = Path(messagefoundry_webconsole.__file__).parent / "static" / "app.js"
_NODE = shutil.which("node")

#: Loads app.js against just enough of a browser for the connections filter, with Flagged only
#: ticked, and prints which of the given ``data-flagged`` values stayed visible.
_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const [appPath, valuesJson] = process.argv.slice(2);
const rows = JSON.parse(valuesJson).map((value) => ({
  value,
  style: {},
  textContent: "",
  querySelector() {
    return { getAttribute() { return value; } };
  },
}));
const poll = { querySelectorAll() { return rows; } };
const input = { value: "", addEventListener() {} };
const flaggedOnly = { checked: true, addEventListener() {} };
const hooks = {
  "[data-poll]": poll,
  "[data-mf-conns-filter]": input,
  "[data-mf-conns-flagged]": flaggedOnly,
};
const document = {
  querySelector(sel) { return hooks[sel] ?? null; },
  querySelectorAll() { return []; },
  getElementById() { return null; },
  addEventListener() {},
  body: { classList: { contains() { return false; } } },
};
class FakeObserver { observe() {} }
const sandbox = {
  document,
  window: { addEventListener() {}, location: {} },
  location: { protocol: "https:", host: "ops.example" },
  MutationObserver: FakeObserver,
  Date,
  Math,
  JSON,
  Object,
  parseInt,
  setInterval() { return 1; },
  clearInterval() {},
  setTimeout() { return 1; },
  clearTimeout() {},
  fetch() { return new Promise(() => {}); },
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(appPath, "utf8"), sandbox);
console.log(JSON.stringify(rows.filter((r) => r.style.display !== "none").map((r) => r.value)));
"""


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
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS, encoding="utf-8")
    assert _NODE is not None
    proc = subprocess.run(
        [_NODE, str(harness), str(_APP_JS), json.dumps(["1", "0", "unknown"])],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout.strip().splitlines()[-1]) == ["1", "unknown"]
