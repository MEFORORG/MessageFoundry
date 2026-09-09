# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard for the shipped-artifact line-ending pin (BACKLOG #1442).

THE DEFECT THIS EXISTS FOR. Every blob in this repository stores pure LF, and under
`core.autocrlf=true` every text file checks out CRLF. Without a `.gitattributes` pin, a wheel built
from a Windows tree is byte-different from the released Linux one and the two `*.dist-info/RECORD`
rows disagree -- different sha256, different size -- while the content is identical. That defeats
rebuild-to-verify against the SLSA provenance, which binds an artifact's sha256 to a source commit.

WHY `text=auto` AND NOT A BARE `text`. `text` forces normalization on, overriding git's binary
detection, and a bare `text eol=lf` strips CRLF byte pairs from inside a binary blob -- measured, a
17-byte fixture holding NULs and CRLF pairs stored as 14. `text=auto` defers to the detection and
stores it intact. The 19 `messagefoundry/tray/assets/*.ico` files contain no CRLF pair today, so a
bare `text` would agree with `auto` on the current corpus BY LUCK; `test_no_shipped_path_uses_a_bare_text_attribute`
is what stops that regressing silently.

WHY THE ROOT PATTERNS ARE ANCHORED. A `.gitattributes` pattern with no slash matches at any depth,
so an unanchored `README.md` also matches `docs/README.md`, `ide/README.md` and 22 others. Measured
against the real path list: the unanchored spelling captures 24 files outside the shipped set, the
anchored one zero. `test_the_root_patterns_stay_anchored` is that regression.

WHAT THIS MODULE MUST NOT ASSERT. Other stanzas legitimately pin paths outside the shipped set --
`*.sh`, the lockfiles, the vendored CLA bundle, and the HAPI fixtures' own nested `-text` file. A
blanket "everything outside is unspecified" assertion fails against all four and says nothing about
this pin, so every check below is scoped to a class the shipped-set stanza actually governs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: Files that ship outside the package: LICENSE and NOTICE ride into the wheel via
#: `[project].license-files`; the other three are packed by `[tool.hatch.build.targets.sdist]`
#: `only-include` or read into METADATA. Kept explicit because there is no glob that means
#: "the root files hatchling ships" -- pyproject.toml is the source of record for the list.
SHIPPED_ROOT_FILES = ("LICENSE", "NOTICE", "README.md", "CHANGELOG.md", "pyproject.toml")

#: The vendored HAPI fixtures carry their own `-text` pin in
#: `samples/messages/hapi-hl7v2/.gitattributes`, because they are stored byte-verbatim and EOL
#: normalization would break the MPL-2.0 "unmodified" basis. Four are bare-CR terminated and three
#: are CRLF, which is what HL7 v2 segment termination looks like on disk. This module must never
#: assert they are unpinned, and the shipped-set stanza must never reach them.
VENDORED_FIXTURES = "samples/messages/hapi-hl7v2/"


def _tracked(prefix: str = "") -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", prefix] if prefix else ["git", "ls-files"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [line for line in out.splitlines() if line]


def _check_attr(paths: list[str]) -> dict[str, dict[str, str]]:
    """Map ``path -> {attribute: value}`` for ``text`` and ``eol``.

    stdin is passed as BYTES on purpose. With ``text=True`` Python applies universal-newline
    translation to stdin as well as stdout, so on Windows every ``\\n`` becomes ``\\r\\n``, git reads
    each path with a trailing CR, quotes it, and matches no pattern -- returning ``unspecified`` for
    every path including the controls. A dead instrument here looks exactly like an absent pin.
    """
    result = subprocess.run(
        ["git", "check-attr", "--stdin", "text", "eol"],
        cwd=REPO_ROOT,
        input=("\n".join(paths) + "\n").encode(),
        capture_output=True,
        check=True,
    ).stdout.decode()

    attrs: dict[str, dict[str, str]] = {}
    for line in result.splitlines():
        if not line:
            continue
        path, rest = line.split(": ", 1)
        attr, value = rest.rsplit(": ", 1)
        attrs.setdefault(path, {})[attr] = value
    return attrs


@pytest.fixture(scope="module")
def shipped_paths() -> list[str]:
    paths = _tracked("messagefoundry") + list(SHIPPED_ROOT_FILES)
    assert len(paths) > 100, f"expected the package to have many tracked files, got {len(paths)}"
    return paths


def test_the_instrument_can_distinguish_pinned_from_unpinned() -> None:
    """Control. A path in the stanza and one outside it must NOT read the same.

    Without this, every other assertion in the file could pass against a broken `check-attr` call
    that returns `unspecified` for everything -- which is indistinguishable from a deleted stanza.
    """
    attrs = _check_attr(["messagefoundry/__main__.py", "tests/conftest.py"])
    assert attrs["messagefoundry/__main__.py"]["text"] == "auto"
    assert attrs["tests/conftest.py"]["text"] == "unspecified"


def test_every_shipped_path_is_pinned_to_lf(shipped_paths: list[str]) -> None:
    attrs = _check_attr(shipped_paths)
    unpinned = {
        path: attrs.get(path, {})
        for path in shipped_paths
        if attrs.get(path, {}).get("eol") != "lf"
    }
    assert not unpinned, (
        "these shipped paths are not pinned to LF, so a Windows build would ship different bytes "
        f"than the released Linux one: {unpinned}"
    )


def test_no_shipped_path_uses_a_bare_text_attribute(shipped_paths: list[str]) -> None:
    """`text=auto` everywhere: a bare `text` corrupts any binary holding a CRLF byte pair."""
    attrs = _check_attr(shipped_paths)
    forced = {
        path: attrs[path] for path in shipped_paths if attrs.get(path, {}).get("text") == "set"
    }
    assert not forced, (
        "these paths carry a bare `text` rather than `text=auto`, which overrides git's binary "
        f"detection and would strip CRLF pairs from inside a binary file: {forced}"
    )


def test_the_binary_assets_still_defer_to_binary_detection() -> None:
    icons = [path for path in _tracked("messagefoundry") if path.endswith(".ico")]
    assert icons, "expected tray icon assets to be tracked; the sweep found none"
    attrs = _check_attr(icons)
    forced = {path: attrs[path] for path in icons if attrs[path]["text"] != "auto"}
    assert not forced, f"tray assets must stay `text=auto` so git decides they are binary: {forced}"


def test_the_root_patterns_stay_anchored() -> None:
    """The regression an unanchored root pattern causes, named exactly.

    A `.gitattributes` pattern containing no slash matches at ANY depth, so a bare `README.md`
    also matches `docs/README.md`, `ide/README.md` and 22 others. Measured against the real path
    list: the unanchored spelling captures 24 files outside the shipped set, the anchored one zero.
    Asserting "everything outside is unspecified" would be wrong here -- `*.sh` and the lockfile
    stanzas legitimately pin other paths -- so this checks the precise class that unanchoring
    breaks.
    """
    candidates = [
        path
        for path in _tracked()
        if Path(path).name in SHIPPED_ROOT_FILES
        and path not in SHIPPED_ROOT_FILES  # not the root copy itself
        and not path.startswith("messagefoundry/")  # covered on purpose by the package glob
    ]
    assert len(candidates) > 10, (
        f"expected many same-named files at depth to test against, found {len(candidates)} -- "
        "if this drops to zero the assertion below becomes vacuous"
    )

    attrs = _check_attr(candidates)
    leaked = {
        path: attrs[path] for path in candidates if attrs.get(path, {}).get("text") != "unspecified"
    }
    assert not leaked, (
        "a root pattern in the shipped-set stanza lost its leading slash, so it now matches files "
        f"of the same name at any depth: {leaked}"
    )


def test_the_stanza_does_not_reach_the_vendored_hl7_fixtures() -> None:
    """They are pinned `-text` by their own nested file; the shipped-set stanza must not fight it."""
    fixtures = [
        path
        for path in _tracked("samples/messages")
        if path.startswith(VENDORED_FIXTURES) and not path.endswith((".gitattributes", ".md"))
    ]
    assert fixtures, "expected vendored HAPI fixtures to be tracked; the sweep found none"

    attrs = _check_attr(fixtures)
    wrong = {path: attrs[path] for path in fixtures if attrs[path]["text"] != "unset"}
    assert not wrong, (
        "the vendored HAPI fixtures must stay `-text` (text: unset). Normalizing them rewrites "
        f"bytes stored verbatim from upstream and breaks the MPL-2.0 unmodified basis: {wrong}"
    )
