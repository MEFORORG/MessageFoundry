# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""connections.toml writer TRIVIA parity: a GUI/CLI save must not destroy documentation.

`connections_edit.upsert_connection` replaced the edited entry with a freshly built table
(``aot[index] = new_table``). tomlkit discards the trivia around a swapped array-of-tables item, so
a save deleted:

  * the edited connection's own inline comments (``settings = { ... }  # why this endpoint``), and
  * the entire leading comment block of the FOLLOWING entry -- a connection the user never edited.

Reproduced with a no-op save (feeding `connection list` output straight back to `connection upsert`)
which rewrote 572 bytes to 505 and dropped two comments. Writing also translated "\\n" to "\\r\\n" on
Windows, turning any one-key edit of an LF-committed file into a whole-file diff.

These tests pin the contract the fix establishes: a no-op save is byte-identical, a real edit is a
minimal diff, and neighbouring entries' comments are never collateral."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

from messagefoundry.config.connections_edit import list_connections, upsert_connection

COMMENTED_TOML = """\
# File header: shared outbound connections, declared once so several feeds can share an endpoint.
# Second header line.

# Leading block for the first connection.
[[outbound]]
name = "OB_ONE"
transport = "mllp"
settings = { host = "one.example.test", port = 6000 }  # trailing endpoint comment
retry = { max_attempts = 3, backoff_seconds = 5 }
priority = "normal"

# Leading block for the SECOND connection -- this must survive editing the FIRST.
[[outbound]]
name = "OB_TWO"
transport = "mllp"
settings = { host = "two.example.test", port = 6100 }  # second trailing comment
"""


def _noop_validate(_config_dir: Path) -> None:
    """These tests exercise the WRITER only; load-time legality is covered elsewhere."""


def _config(tmp_path: Path, toml: str = COMMENTED_TOML) -> Path:
    # newline="" so the fixture is LF on every platform -- the EOL assertion below is the point.
    (tmp_path / "connections.toml").write_text(toml, encoding="utf-8", newline="")
    return tmp_path


def _entry(config_dir: Path, name: str) -> dict[str, Any]:
    return next(c for c in list_connections(config_dir) if c["name"] == name)


def test_noop_upsert_is_byte_identical(tmp_path: Path) -> None:
    """Feeding `list` output straight back to `upsert` must not touch a single byte."""
    config = _config(tmp_path)
    path = config / "connections.toml"
    before = path.read_bytes()

    upsert_connection(config, _entry(config, "OB_ONE"), validate=_noop_validate)

    assert path.read_bytes() == before


def test_edit_preserves_neighbour_comments(tmp_path: Path) -> None:
    """Editing one connection must not delete another connection's documentation."""
    config = _config(tmp_path)
    path = config / "connections.toml"

    edited = _entry(config, "OB_ONE")
    edited["settings"]["port"] = 6001
    upsert_connection(config, edited, validate=_noop_validate)
    after = path.read_text(encoding="utf-8")

    assert "# Leading block for the SECOND connection" in after
    assert "# second trailing comment" in after
    assert "# File header: shared outbound connections" in after
    assert "# Leading block for the first connection." in after
    assert "# trailing endpoint comment" in after  # the edited entry keeps its own comment too


def test_edit_rewrites_only_the_changed_line(tmp_path: Path) -> None:
    """A one-scalar change is a one-line diff -- no reflow of untouched keys or tables."""
    config = _config(tmp_path)
    path = config / "connections.toml"
    before = path.read_text(encoding="utf-8").splitlines()

    edited = _entry(config, "OB_ONE")
    edited["settings"]["port"] = 6001
    upsert_connection(config, edited, validate=_noop_validate)

    after = path.read_text(encoding="utf-8").splitlines()
    changed = [(a, b) for a, b in zip(before, after, strict=True) if a != b]
    assert len(changed) == 1, f"expected a single changed line, got {changed}"
    assert "6000" in changed[0][0] and "6001" in changed[0][1]
    # the inline table keeps its shape rather than reflowing into [outbound.settings]
    assert changed[0][1].lstrip().startswith("settings = {")


def test_save_does_not_rewrite_line_endings(tmp_path: Path) -> None:
    """An LF-committed file stays LF: no CRLF translation on write (Windows default `open`)."""
    config = _config(tmp_path)
    path = config / "connections.toml"

    edited = _entry(config, "OB_ONE")
    edited["settings"]["port"] = 6002
    upsert_connection(config, edited, validate=_noop_validate)

    assert b"\r\n" not in path.read_bytes()


def test_full_replace_still_removes_absent_keys(tmp_path: Path) -> None:
    """ADR 0007's full-replace semantics survive the in-place update: absent key = deleted key."""
    config = _config(tmp_path)
    path = config / "connections.toml"

    edited = _entry(config, "OB_ONE")
    del edited["priority"]
    upsert_connection(config, edited, validate=_noop_validate)

    assert "priority" not in _entry(config, "OB_ONE")
    assert "priority" not in path.read_text(encoding="utf-8")
    # ...and removing a key still does not harm the neighbour's documentation
    assert "# Leading block for the SECOND connection" in path.read_text(encoding="utf-8")


def test_new_connection_still_appends(tmp_path: Path) -> None:
    """The append path is untouched, and appending preserves existing entries' comments."""
    config = _config(tmp_path)
    path = config / "connections.toml"

    upsert_connection(
        config,
        {
            "direction": "outbound",
            "name": "OB_THREE",
            "transport": "mllp",
            "settings": {"host": "three.example.test", "port": 6200},
        },
        validate=_noop_validate,
    )

    after = path.read_text(encoding="utf-8")
    assert "OB_THREE" in after
    assert "# Leading block for the SECOND connection" in after
    assert "# trailing endpoint comment" in after
    assert {c["name"] for c in list_connections(config)} == {"OB_ONE", "OB_TWO", "OB_THREE"}


def test_sub_table_section_style_is_preserved(tmp_path: Path) -> None:
    """A connection written with [outbound.settings] sections stays sectioned (no inline reflow)."""
    sectioned = textwrap.dedent(
        """\
        [[outbound]]
        name = "OB_SECTION"
        transport = "mllp"

        [outbound.settings]
        host = "section.example.test"  # keep me
        port = 6300
        """
    )
    config = _config(tmp_path, sectioned)
    path = config / "connections.toml"

    edited = _entry(config, "OB_SECTION")
    edited["settings"]["port"] = 6301
    upsert_connection(config, edited, validate=_noop_validate)

    after = path.read_text(encoding="utf-8")
    assert "[outbound.settings]" in after
    assert "# keep me" in after
    assert "6301" in after
