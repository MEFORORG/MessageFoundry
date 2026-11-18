# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5445: an allowlist entry excuses a WHOLE line, never a line that merely contains its shape.

An allowlist entry is a per-line veto applied before every detector of the leak gate. The OIDC core
citation entry was the one entry written without whole-line anchors, and the scanner applied entries
with ``search``, so any line that also carried that citation shape skipped every detector: a routable
IP, a site code or a customer name on the same line went unreported. The scanner now applies every
entry with ``fullmatch``, so an entry excuses only a line it matches in full, whatever its anchors.

Every probe value here is synthetic and assembled at runtime, because this file is itself scanned by
the gate it tests: a literal dotted section number reads as an IP address.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCANNER_PATH = _REPO_ROOT / "scripts" / "security" / "scan_forbidden.py"
_ALLOWLIST_PATH = _REPO_ROOT / "scripts" / "security" / "scan-allowlist.txt"
#: The one tracked line the OIDC core entry exists to excuse.
_CLAIMS = _REPO_ROOT / "messagefoundry" / "auth" / "oidc" / "claims.py"


def _load_scanner():
    spec = importlib.util.spec_from_file_location("scan_forbidden_5445", _SCANNER_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _routable_ip() -> str:
    # A public resolver address, outside the scanner's allow-set, assembled so no literal sits here.
    return ".".join(("8", "8", "4", "4"))


def _citation_line() -> str:
    """The tracked comment line the OIDC core entry was written for, read from the tree."""
    marker = "OIDC core " + ".".join(("3", "1", "3", "7")) + "/2"
    lines = [ln for ln in _CLAIMS.read_text(encoding="utf-8").splitlines() if marker in ln]
    assert len(lines) == 1, "claims.py must carry the citation the allowlist entry excuses"
    return lines[0]


@pytest.fixture
def mod():
    m = _load_scanner()
    # The committed allowlist must load in full, or a vacuous pass below would mean nothing.
    committed = [
        ln.strip()
        for ln in _ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert len(m.ALLOWLIST) == len(committed)
    return m


def test_the_excused_citation_line_itself_stays_clean(mod, tmp_path: Path) -> None:
    """Control: the line the entry exists for still passes, so the tree stays green."""
    p = tmp_path / "claims.py"
    p.write_text(_citation_line() + "\n", encoding="utf-8")
    assert mod.scan_file(p) == []


def test_a_leak_beside_the_citation_shape_still_trips(mod, tmp_path: Path) -> None:
    """The defect: the citation shape on a line excused the whole line, so the IP beside it was
    never seen. Each variant carries the shape the old unanchored entry searched for."""
    section = ".".join(("3", "1", "3", "7"))
    ip = _routable_ip()
    variants = (
        f"# OIDC core {section}/2 host {ip}",
        f"{_citation_line()} {ip}",
        f"connect({ip!r})  # OIDC core {section}/2",
    )
    for i, line in enumerate(variants):
        p = tmp_path / f"leak{i}.py"
        p.write_text(line + "\n", encoding="utf-8")
        hits = mod.scan_file(p)
        assert any("routable IP address" in h for h in hits), (i, hits)


def test_every_allowlist_entry_excuses_only_a_whole_line(mod) -> None:
    """The class, not the instance: a line an entry excuses stops being excused once anything is
    appended to it, for every committed entry. ``re`` cannot generate a matching string, so each
    entry is probed with a line built for it below; a new entry without a probe fails here, which
    is the point -- it must be shown to be whole-line before it ships."""
    six = "".join(("1", "2", "3", "4", "5", "6"))
    probes = {
        r"^\s*[A-Z0-9_]+\s+\d+ ms\s+\d+ tasks\s*$": "WRITELOG  12 ms  " + six + " tasks",
        r"^ABUSE_\d{6}_ABUSE$": f"ABUSE_{six}_ABUSE",
        r"^lky_vipnyc_\d{6}$": f"lky_vipnyc_{six}",
        r"^dungklose_\d{6}$": f"dungklose_{six}",
    }
    for pat in mod.ALLOWLIST:
        if pat.pattern.startswith("^openssl "):
            probe = re.sub(r"\[0\]\{3\}", "000", pat.pattern[1:-1].replace("\\", ""))
        elif "OIDC core" in pat.pattern:
            probe = _citation_line()
        else:
            assert pat.pattern in probes, f"no probe for allowlist entry {pat.pattern!r}"
            probe = probes[pat.pattern]
        assert mod._allowlisted(probe), pat.pattern
        assert not mod._allowlisted(probe + " " + _routable_ip()), pat.pattern
        assert not mod._allowlisted(_routable_ip() + " " + probe), pat.pattern
