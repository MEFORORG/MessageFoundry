# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reason cannot forge the REFUSED mark or a second entry on the ``tls-hop-attested`` line.

Vault BACKLOG #3139. The mark used to be plain text appended to the author's reason, and the reason
rule refused only control characters. So a live attestation whose reason held the mark text read as
REFUSED, and a reviewer would skip it. A reason holding ``); name (`` read as two entries. Each test
here loads a config the build check accepts, so every listed hop is one the engine would cross.

The module imports only names that existed before the fix, so it runs unchanged against the old
code and fails there.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from messagefoundry.checks import _check_hop_attested
from messagefoundry.config.wiring import load_config

_LOGIC = (
    "from messagefoundry import Send, handler, router\n\n"
    '@router("r")\n'
    "def route(msg):\n"
    '    return ["h"]\n\n'
    '@handler("h")\n'
    "def handle(msg):\n"
    '    return Send("OB", msg)\n'
)

OLD_MARK = "[REFUSED: the build check rejects this declaration; no gate allows it]"

FORGERIES = {
    "old-mark-text": f"sidecar {OLD_MARK}",
    "entry-separator": "x); db_lookup:ghost (y",
    "quote-closer": 'x") REFUSED; db_lookup:ghost ("y',
    "trailing-mark": "sidecar) REFUSED",
}

_QUOTED = r'"(?:[^"\\]|\\.)*"'
_ENTRY = re.compile(
    rf"(?P<name>[A-Za-z0-9_.:-]+|{_QUOTED}) \((?P<why>{_QUOTED}|none recorded)\)(?P<mark> REFUSED)?"
)


def _entries(detail: str) -> list[tuple[str, str | None, bool]]:
    """Parse the list after the dash into ``(name, reason, refused)``, consuming every character.

    A reason that escaped its quotes would leave text this grammar cannot place, so the parse fails
    rather than reading a forged entry or mark."""
    listed = detail.split(" — ", 1)[1]
    out: list[tuple[str, str | None, bool]] = []
    pos = 0
    while True:
        m = _ENTRY.match(listed, pos)
        assert m is not None, f"unparseable entry at {pos}: {listed[pos:]!r}"
        name = m["name"]
        why = m["why"]
        out.append(
            (
                json.loads(name) if name.startswith('"') else name,
                None if why == "none recorded" else json.loads(why),
                m["mark"] is not None,
            )
        )
        pos = m.end()
        if pos == len(listed):
            return out
        assert listed.startswith("; ", pos), f"no separator at {pos}: {listed[pos:]!r}"
        pos += 2


def _config(tmp_path: Path, reason: str) -> Path:
    (tmp_path / "logic.py").write_text(_LOGIC, encoding="utf-8")
    (tmp_path / "ob.py").write_text(
        "from messagefoundry import Tcp, outbound\n"
        'outbound("OB", Tcp(host="10.0.0.5", port=5000), tls_hop_attested=True,\n'
        f"         tls_hop_attested_reason={reason!r})\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.mark.parametrize("reason", list(FORGERIES.values()), ids=list(FORGERIES))
def test_a_reason_renders_as_one_quoted_live_entry(tmp_path: Path, reason: str) -> None:
    detail = _check_hop_attested(_config(tmp_path, reason)).detail
    assert detail.startswith("1 hop(s) declare")
    # Exactly one entry, the author's text intact inside it, and no mark from the engine.
    assert _entries(detail) == [("OB", reason, False)]


def test_a_reason_holding_the_old_mark_leaves_the_refused_field_false(tmp_path: Path) -> None:
    # Imported here, not at the top, so the line-level tests above still run against old code.
    from messagefoundry.config.wiring import AttestedHop, attested_secure_hop_records

    reason = FORGERIES["old-mark-text"]
    registry = load_config(_config(tmp_path, reason))
    assert attested_secure_hop_records(registry) == [AttestedHop("OB", reason, refused=False)]
