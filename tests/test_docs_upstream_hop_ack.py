# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every copy-pasteable upstream-terminator block must acknowledge the plaintext hop (BACKLOG #1179).

With ``[api].tls_terminated_upstream = true`` and no ``[api].tls_cert_file``, the proxy-to-engine hop
is plaintext by design (ADR 0172 decision 3), and ``serve`` refuses to start until
``[api].plaintext_upstream_hop_acknowledged = true`` is set, in every mode.

The TOML-loading doc guards cannot catch a missing acknowledgement: it is a SERVE refusal, not a load
error, so a block without it loads cleanly and then exits 2 the first time an operator starts it.
This guard parses every fenced ``toml`` block in the tracked Markdown and requires the key wherever
the block turns the terminator on without a certificate.

It lives in its own module on purpose. ``tests/test_runbook_proxy_tls_floor.py`` derives a similar
set of blocks, but it skips at module level when the private runbook is absent, which is always the
case in this repository, so a guard placed there would never run here.

TRACKED FILES ONLY (``git ls-files``), not a directory walk: a walk rooted at the primary checkout
descends into every sibling worktree under ``.claude/worktrees`` and reports their docs as this
branch's.
"""

from __future__ import annotations

import functools
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
from _docs_toml import TOML_FENCE_RE, dedent

from messagefoundry.config.settings import ApiSettings

_ROOT = Path(__file__).resolve().parent.parent

#: The key, pinned against the model, so a rename fails this module at import instead of leaving it
#: green over docs that name a key the loader would refuse (ApiSettings ignores unknown keys, so
#: validating a block through the model could not catch that).
_ACK = "plaintext_upstream_hop_acknowledged"
assert _ACK in ApiSettings.model_fields, f"[api].{_ACK} is no longer a setting; update this guard"

#: Any run of Markdown blockquote markers (``>``, ``> >``, indented) at the start of a line.
#: ``TOML_FENCE_RE`` does not match a fence inside a quote, and docs/CONFIGURATION.md prints its
#: terminator recipe in one. Stripping a line prefix keeps line numbers intact.
_QUOTE_RE = re.compile(r"^[ \t]*(?:>[ \t]?)+", re.MULTILINE)

#: Pages that print such a block today. The derivation below is the mechanism; this is the floor
#: under it, because a parametrize list that goes empty reports as a SKIP, not a failure.
_KNOWN_PAGES = frozenset(
    {"CONFIGURATION.md", "REMOTE-CONSOLE.md", "CONTAINER-EXPOSURE-EVALUATION.md"}
)


@functools.cache
def _tracked_markdown() -> tuple[Path, ...]:
    out = subprocess.run(
        ["git", "-C", str(_ROOT), "ls-files", "-z", "--", "*.md"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return tuple(_ROOT / rel for rel in out.split("\0") if rel)


def _api_table(body: str) -> dict[str, Any] | None:
    """The ``[api]`` table a block defines, in any TOML spelling, or None if it is not TOML."""
    try:
        doc = tomllib.loads(body)
    except tomllib.TOMLDecodeError:
        return None  # an illustrative fragment with placeholders, not a copy-pasteable block
    api = doc.get("api")
    return api if isinstance(api, dict) else None


@functools.cache
def _terminator_blocks(path: Path) -> tuple[tuple[int, dict[str, Any]], ...]:
    """``(line, [api] table)`` for every fenced toml block in ``path`` that turns the terminator on."""
    text = _QUOTE_RE.sub("", path.read_text(encoding="utf-8"))
    found: list[tuple[int, dict[str, Any]]] = []
    for fence in TOML_FENCE_RE.finditer(text):
        api = _api_table(dedent(fence.group("body"), fence.group("indent")))
        if api is not None and api.get("tls_terminated_upstream") is True:
            found.append((text.count("\n", 0, fence.start()) + 2, api))
    return tuple(found)


def _pages() -> list[Path]:
    return [p for p in _tracked_markdown() if _terminator_blocks(p)]


def test_the_derivation_still_finds_every_known_page() -> None:
    found = {p.name for p in _pages()}
    missing = _KNOWN_PAGES - found
    assert not missing, (
        f"these pages no longer print a fenced tls_terminated_upstream = true block: {sorted(missing)}. "
        f"If that is deliberate, remove them from _KNOWN_PAGES; otherwise the derivation broke."
    )


@pytest.mark.parametrize("path", _pages(), ids=lambda p: p.name)
def test_every_plaintext_terminator_block_acknowledges_the_hop(path: Path) -> None:
    rel = path.relative_to(_ROOT)
    for lineno, api in _terminator_blocks(path):
        if api.get("tls_cert_file"):
            continue  # the engine serves that hop over TLS, so there is nothing to acknowledge
        assert api.get(_ACK) is True, (
            f"{rel} line {lineno} prints a copy-pasteable [api].tls_terminated_upstream = true block "
            f"with no [api].tls_cert_file and no [api].{_ACK} = true. The proxy-to-engine hop is "
            f"plaintext there, so serve refuses the block (exit 2) in every mode. Add the "
            f"acknowledgement to the block."
        )
