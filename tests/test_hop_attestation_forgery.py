# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reason cannot forge the REFUSED mark or a second entry on the ``tls-hop-attested`` line.

Vault BACKLOG #3139. The mark used to be plain text appended to the author's reason, and the reason
rule refused only control characters. So a live attestation whose reason held the mark text read as
REFUSED, and a reviewer would skip it. A reason holding ``); name (`` read as two entries. Each test
here loads a config the build check accepts, so every listed hop is one the engine would cross.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from messagefoundry.checks import _check_hop_attested
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import AttestedHop, attested_secure_hop_records, load_config
from messagefoundry.pipeline.wiring_runner import build_check_registry

OLD_MARK = "[REFUSED: the build check rejects this declaration; no gate allows it]"

FORGERIES = {
    "old-mark-text": f"sidecar {OLD_MARK}",
    "entry-separator": "x); db_lookup:ghost (y",
    "quote-closer": 'x") REFUSED; db_lookup:ghost ("y',
    "trailing-mark": "sidecar) REFUSED",
    # Lookalike quotes and a right-to-left run: JSON alone leaves them raw, and a reader sees an end
    # quote, the mark and a second entry that a parser does not.
    "modifier-quote": "sidecarʺ) REFUSED; db_lookup:ghost (ʺTLS at sidecar",
    "fullwidth-quote": "sidecar＂） REFUSED； db_lookup:ghost (＂y",
    "curly-quote": "sidecar”) REFUSED; db_lookup:ghost (“y",
    "rtl-run": "אב) REFUSED; db_lookup:ghost (ג",
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
    # The parse above is what a program reads. A person reads the glyphs, so no author character
    # may reach the line outside ASCII, where a lookalike quote or a bidi run could fool the eye.
    listed = detail.split(" — ", 1)[1]
    assert listed.isascii(), listed.encode("ascii", "backslashreplace")


@pytest.mark.parametrize("reason", list(FORGERIES.values()), ids=list(FORGERIES))
def test_a_forged_reason_is_a_live_attestation_with_refused_false(
    tmp_path: Path, reason: str
) -> None:
    registry = load_config(_config(tmp_path, reason))
    # Control: the build check accepts it, so this is a hop the engine would cross.
    build_check_registry(
        registry,
        inbound_bind_host="127.0.0.1",
        env_values={},
        egress=EgressSettings(deny_by_default=False),
    )
    assert attested_secure_hop_records(registry) == [AttestedHop("OB", reason, refused=False)]
