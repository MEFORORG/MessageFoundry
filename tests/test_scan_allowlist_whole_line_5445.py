# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5445: an allowlist entry excuses a WHOLE line, never a line that merely contains its shape.

An allowlist entry is a per-line veto applied before every detector of the leak gate. The OIDC core
citation entry was the one entry written without whole-line anchors, and the scanner applied entries
with ``search``, so any line that also carried that citation shape skipped every detector: a routable
IP, a site code or a customer name on the same line went unreported. The scanner now applies every
entry with ``fullmatch``, and its loader refuses an entry with an unbounded wildcard, which would
let a whole-line match still carry a leak inside it.

Every probe value here is synthetic and assembled at runtime, because this file is itself scanned by
the gate it tests: a literal dotted section number reads as an IP address.
"""

from __future__ import annotations

import importlib.util
import re
import shutil
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SECURITY_DIR = _REPO_ROOT / "scripts" / "security"
_SCANNER_PATH = _SECURITY_DIR / "scan_forbidden.py"
_ALLOWLIST_PATH = _SECURITY_DIR / "scan-allowlist.txt"
#: The one tracked line the OIDC core entry exists to excuse.
_CLAIMS = _REPO_ROOT / "messagefoundry" / "auth" / "oidc" / "claims.py"


def _load_scanner(path: Path = _SCANNER_PATH, name: str = "scan_forbidden_5445"):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _routable_ip() -> str:
    # A public resolver address, outside the scanner's allow-set, assembled so no literal sits here.
    return ".".join(("8", "8", "4", "4"))


def _section() -> str:
    return ".".join(("3", "1", "3", "7"))


def _citation_line() -> str:
    """The tracked comment line the OIDC core entry was written for, read from the tree."""
    marker = f"OIDC core {_section()}/4"
    lines = [ln for ln in _CLAIMS.read_text(encoding="utf-8").splitlines() if marker in ln]
    assert len(lines) == 1, "claims.py must carry the citation the allowlist entry excuses"
    return lines[0]


@pytest.fixture
def mod():
    return _load_scanner()


def test_the_excused_citation_line_itself_stays_clean(mod, tmp_path: Path) -> None:
    """Control: the line the entry exists for still passes, so the tree stays green."""
    assert mod.ALLOWLIST, "the committed allowlist must load"
    p = tmp_path / "claims.py"
    p.write_text(_citation_line() + "\n", encoding="utf-8")
    assert mod.scan_file(p) == []


def test_a_leak_beside_the_citation_shape_still_trips(mod, tmp_path: Path) -> None:
    """The defect: the citation shape on a line excused the whole line, so the IP beside it was
    never seen. Each variant carries the shape the old unanchored entry searched for, and the hit
    must name the PLANTED address, not only the section number that now reads as one."""
    ip = _routable_ip()
    variants = (
        f"# OIDC core {_section()}/4 host {ip}",
        f"{_citation_line()} {ip}",
        f"connect({ip!r})  # OIDC core {_section()}/4",
    )
    for i, line in enumerate(variants):
        p = tmp_path / f"leak{i}.py"
        p.write_text(line + "\n", encoding="utf-8")
        hits = mod.scan_file(p, show_context=True)
        assert any(f"routable IP address ({ip})" in h for h in hits), (i, hits)


def _insertions(probe: str, leak: str) -> list[str]:
    """``probe`` with ``leak`` added at its start, at its end, and beside every space inside it."""
    spaces = [i for i, ch in enumerate(probe) if ch == " "]
    inner = [probe[:i] + " " + leak + probe[i:] for i in spaces]
    return [leak + " " + probe, probe + " " + leak, *inner]


def test_every_allowlist_entry_excuses_only_a_whole_line(mod) -> None:
    """The class, not the instance: a line an entry excuses stops being excused once anything is
    added to it, at either end or inside it, for every committed entry. ``re`` cannot generate a
    matching string, so each entry is probed with a line built for it below; a new entry without a
    probe fails here, which is the point -- it must be shown to be whole-line before it ships."""
    six = "".join(("1", "2", "3", "4", "5", "6"))
    probes = {
        r"^\s*[A-Z_]+\s+\d+ ms\s+\d+ tasks\s*$": "WRITELOG  12 ms  " + six + " tasks",
        r"^ABUSE_\d{6}_ABUSE$": f"ABUSE_{six}_ABUSE",
        r"^lky_vipnyc_\d{6}$": f"lky_vipnyc_{six}",
        r"^dungklose_\d{6}$": f"dungklose_{six}",
    }
    assert mod.ALLOWLIST, "the committed allowlist must load"
    # Every committed entry, not just some: the loader's refusals must pass each one.
    committed = [
        ln.strip()
        for ln in _ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert [p.pattern for p in mod.ALLOWLIST] == committed
    for pat in mod.ALLOWLIST:
        if pat.pattern.startswith("^openssl "):
            probe = re.sub(r"\[0\]\{3\}", "000", pat.pattern[1:-1])
        elif "OIDC core" in pat.pattern:
            probe = _citation_line()
        else:
            assert pat.pattern in probes, f"no probe for allowlist entry {pat.pattern!r}"
            probe = probes[pat.pattern]
        assert mod._allowlisted(probe), pat.pattern
        for line in _insertions(probe, _routable_ip()):
            assert not mod._allowlisted(line), (pat.pattern, line)
        # An identifier in the estate shape, butted against either end with no space: an entry
        # whose first or last piece is a word class would otherwise absorb it.
        estate = "PT_" + "99" + "0210" + "_ADT"
        for line in (estate + probe.lstrip(), probe.rstrip() + estate):
            assert not mod._allowlisted(line), (pat.pattern, line)


@pytest.mark.parametrize(
    ("entry", "keep"),
    [
        pytest.param(".*OIDC core [0-9]+.*", False, id="padded-both-ends"),
        pytest.param("^# keep .* here$", False, id="interior-wildcard"),
        pytest.param("^# keep [^!]+ here$", False, id="negated-class"),
        pytest.param(r"^# keep [\s\S]* here$", False, id="space-and-non-space-class"),
        pytest.param(r"^# keep [\w\W]+ here$", False, id="word-and-non-word-class"),
        pytest.param(r"^# keep \w+ here$", False, id="word-escape"),
        pytest.param(r"^# keep \\.* here$", False, id="a-literal-backslash-then-a-wildcard"),
        pytest.param(r"(?x)^\#\ keep\ . *\ here$", False, id="verbose-spaced-wildcard"),
        pytest.param(r"^# keep (?x:. *) here$", False, id="scoped-verbose-spaced-wildcard"),
        # A comment group is no text: the source-text reader took ``.(?#c)*`` for ``.`` then a
        # comment, but it compiles as ``.*``; the parse-tree walk sees what compiles.
        pytest.param("^# keep .(?#c)* here$", False, id="comment-between-wildcard-and-quantifier"),
        pytest.param("^# keep (?#[).* here$", False, id="comment-opening-a-class"),
        pytest.param("^# keep (?:x.)+ here$", False, id="wildcard-inside-a-quantified-group"),
        pytest.param("^# keep (?:.{0,4})+ here$", False, id="bounded-wildcard-in-unbounded-group"),
        pytest.param("^# keep [^a]+ here$", False, id="one-member-negated-class"),
        pytest.param("^# keep [ -~]+ here$", False, id="printable-ascii-range"),
        pytest.param(r"^# keep [\x00-\uffff]+ here$", False, id="whole-plane-range"),
        pytest.param("^# keep [ A-Za-z]+ here$", False, id="space-and-every-letter"),
        pytest.param("^# keep [A-Za-z0-9]+ here$", False, id="every-letter-and-digit"),
        pytest.param(r"^# keep [a-z\d]+ here$", False, id="every-letter-and-digit-category"),
        pytest.param(r"^# keep [A-Mn-z\s]+ here$", False, id="every-letter-either-case-and-space"),
        pytest.param(r"^# keep [\d\D]+ here$", False, id="digit-and-non-digit-class"),
        # The union of one repeat's body, not each class alone: three narrow alternatives that
        # together take a name, an IP and the spaces between them.
        pytest.param(
            "^# keep (?:[A-Za-z]+|[0-9.]+| )+ here$", False, id="narrow-alternatives-union-wide"
        ),
        pytest.param("^# keep (?:[a-z]| )+ here$", False, id="class-and-literal-union-wide"),
        # A bound past _MAX_BOUND absorbs as much as no bound.
        pytest.param(r"^# keep \S{1,4294967294} here$", False, id="huge-finite-bound"),
        pytest.param("^# keep .{0,33} here$", False, id="bound-just-past-the-limit"),
        # Refused only by the verbose check: the walk alone would load it.
        pytest.param(r"(?x)^\#\ keep\ [a-z]+\ here$", False, id="verbose-without-a-wildcard"),
        pytest.param(r"^# keep (?i:[a-z]+) here$", True, id="control-a-scoped-non-verbose-flag"),
        pytest.param("^# keep [A-Z_]+ here$", True, id="control-every-letter-alone"),
        # Nested bounds multiply, and a bounded outer repeat is judged whole.
        pytest.param("^# keep (?:.{0,32}){0,32} here$", False, id="nested-bounds-multiply"),
        pytest.param("^# keep (?:[A-Za-z]+ ){0,32}here$", False, id="bounded-outer-union-wide"),
        # Leaving out a rare letter does not make a class narrow.
        pytest.param("^# keep [ A-Ya-y]+ here$", False, id="all-but-one-letter-and-space"),
        pytest.param("^# keep [ -Y]+ here$", False, id="space-digits-and-most-capitals"),
        pytest.param("^# keep [ a-f]+ here$", True, id="control-space-and-some-letters"),
        pytest.param("^# keep .{1,32} here$", True, id="control-a-short-bounded-wildcard"),
        pytest.param("^# keep (?#.*)x here$", True, id="control-a-wildcard-only-in-a-comment"),
        pytest.param("^# keep [a-z]+ here$", True, id="control-a-letter-class"),
        pytest.param("^# keep [.*] here$", True, id="control-a-literal-class"),
        pytest.param(r"^# keep \.* here$", True, id="control-an-escaped-dot"),
    ],
)
def test_the_loader_refuses_an_entry_with_an_unbounded_wildcard(
    tmp_path: Path, entry: str, keep: bool
) -> None:
    """Under a whole-line match, a wildcard is where a leak would sit: ``^# keep .* here$`` excuses
    ``# keep <a routable IP> here``. The bounded control loads, so the refusal is the wildcard."""
    dst = tmp_path / "security"
    # Never the git-ignored real token list: a copy would sit in pytest's kept temp directories.
    shutil.copytree(_SECURITY_DIR, dst, ignore=shutil.ignore_patterns("scan-tokens.local.txt"))
    (dst / "scan-allowlist.txt").write_text(entry + "\n", encoding="utf-8")
    loaded = _load_scanner(dst / "scan_forbidden.py", f"scan_forbidden_5445_{keep}_{len(entry)}")
    assert bool(loaded.ALLOWLIST) is keep, entry
