# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Three copies of the exposure rule that stated it before a set ``trusted_proxies`` counted.

``serve`` counts an instance as exposed on an off-loopback bind, a declared TLS-terminating proxy,
or a set ``[api].trusted_proxies`` (vault BACKLOG #2251). Three places still gave the older rule,
"non-loopback" or "off-loopback bind or a declared reverse proxy", and one of them the retired
production split (vault BACKLOG #3474, item 9). Each is pinned to name the third arm.

What this reads is text, so it catches the rule dropping out of these three places, and nothing
about a fourth.
"""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _require_mfa_comment() -> str:
    """The comment block above ``AuthSettings.require_mfa``, read from the source lines."""
    path = _ROOT / "messagefoundry" / "config" / "settings.py"
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ClassDef) and node.name == "AuthSettings":
            for stmt in node.body:
                if (
                    isinstance(stmt, ast.AnnAssign)
                    and isinstance(stmt.target, ast.Name)
                    and stmt.target.id == "require_mfa"
                ):
                    above = []
                    for line in reversed(lines[: stmt.lineno - 1]):
                        if not line.strip().startswith("#"):
                            break
                        above.append(line.strip().lstrip("#").strip())
                    return " ".join(reversed(above))
    raise AssertionError("AuthSettings.require_mfa not found")


def test_the_require_mfa_comment_states_the_current_rule() -> None:
    comment = _require_mfa_comment()
    assert "sec-mfa-on" in comment, comment  # control: the right block was read
    assert "trusted_proxies" in comment
    assert "non-loopback" not in comment
    assert "production instance" not in comment, "no arm of that gate keys on production"


def test_the_single_factor_ack_names_a_trusted_proxy_as_exposure() -> None:
    text = (_ROOT / "docs" / "SECURITY-LOOSENING.md").read_text(encoding="utf-8")
    head = "### `allow_single_factor_admin_when_exposed = true`"
    assert head in text
    section = text.split(head, 1)[1].split("\n### ", 1)[0]
    lose = section.split("- **What you lose:**", 1)[1].split("\n- **", 1)[0]
    assert "admin surface is exposed" in lose  # control
    assert "trusted_proxies" in lose, lose


def test_the_trusted_proxies_row_says_the_instance_counts_as_exposed() -> None:
    text = (_ROOT / "docs" / "CONFIGURATION.md").read_text(encoding="utf-8")
    rows = [line for line in text.splitlines() if line.startswith("| `trusted_proxies` |")]
    assert len(rows) == 1, rows
    assert "counts the instance as exposed" in rows[0]
