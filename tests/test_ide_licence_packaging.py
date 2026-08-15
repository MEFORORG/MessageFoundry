# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The VS Code extension's licence metadata must stay coherent with the repo it ships from.

WHY THIS EXISTS, AND WHY IT IS NOT THE FIX THAT WAS ASKED FOR. BACKLOG #1010 step 6 records that
``ide/package.json`` declares ``"license": "SEE LICENSE IN LICENSE"`` while ``no ide/LICENSE
exists``, and proposes adding the file or correcting the field. Re-measured before acting, that
premise does not hold:

  * ``vscode:prepublish`` runs ``copyFileSync('../LICENSE','LICENSE')``, and ``vsce package`` runs
    ``vscode:prepublish``, so the published ``.vsix`` carries the licence by construction;
  * ``ide/.gitignore`` lists ``LICENSE`` explicitly, so the file's absence from the tree is a
    recorded decision rather than an oversight.

Adding a tracked ``ide/LICENSE`` would therefore fight that ignore rule and put a second copy of a
GENERATED file under version control -- two records of one fact with no drift signal between them,
which is the defect this project keeps paying for, not a fix for one.

What is genuinely missing is the CONTROL. The master test plan already carries this as a P1 risk in
the words "marketplace metadata is unverified", and it was right: nothing asserted any of it. Move
or rename the root ``LICENSE``, edit the one-liner, or add ``LICENSE`` to ``.vscodeignore``, and the
extension publishes with no licence -- or fails at publish time, which is the latest and most
expensive moment to find out. These tests are cheap and run in the ordinary pytest job.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_IDE = _ROOT / "ide"
_MANIFEST = _IDE / "package.json"

# Matches the copy in `vscode:prepublish`: copyFileSync('<src>','<dst>'). Parsed rather than compared
# as a whole string so reformatting the script does not fail the test for the wrong reason.
_COPY = re.compile(r"copyFileSync\(\s*['\"](?P<src>[^'\"]+)['\"]\s*,\s*['\"](?P<dst>[^'\"]+)['\"]")


def _manifest() -> dict[str, object]:
    data: dict[str, object] = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return data


def test_prepublish_copies_a_licence_that_actually_exists() -> None:
    """The source path in the prepublish copy must resolve, relative to ``ide/``."""
    scripts = _manifest()["scripts"]
    assert isinstance(scripts, dict)
    prepublish = scripts.get("vscode:prepublish")
    assert isinstance(prepublish, str), "ide/package.json lost its vscode:prepublish script"

    match = _COPY.search(prepublish)
    assert match is not None, (
        "vscode:prepublish no longer copies a licence into the extension. If that is deliberate, the "
        f"manifest's license field must stop pointing at a file. Script: {prepublish!r}"
    )

    source = (_IDE / match.group("src")).resolve()
    assert source.is_file(), (
        f"vscode:prepublish copies {match.group('src')!r}, which does not exist"
    )
    assert source == (_ROOT / "LICENSE").resolve(), (
        "the extension must ship the project's own LICENSE, not some other file"
    )


def test_the_manifest_licence_field_matches_what_prepublish_ships() -> None:
    """``SEE LICENSE IN <name>`` must name the file prepublish actually writes."""
    manifest = _manifest()
    declared = manifest["license"]
    assert isinstance(declared, str)

    scripts = manifest["scripts"]
    assert isinstance(scripts, dict)
    match = _COPY.search(str(scripts["vscode:prepublish"]))
    assert match is not None
    written = match.group("dst")

    if declared.startswith("SEE LICENSE IN "):
        named = declared.removeprefix("SEE LICENSE IN ").strip()
        assert named == written, (
            f"manifest points at {named!r} but prepublish writes {written!r} -- a published "
            "extension would reference a file it does not contain"
        )
    else:
        # An SPDX expression is also valid and needs no file; it must still name this project's licence.
        assert declared == "AGPL-3.0-or-later", (
            f"ide/package.json declares {declared!r}, which is neither a SEE-LICENSE-IN pointer nor "
            "this project's SPDX identifier"
        )


def test_vscodeignore_does_not_exclude_the_licence() -> None:
    """A packaging-time exclusion would silently undo the prepublish copy."""
    ignore = _IDE / ".vscodeignore"
    if not ignore.is_file():
        return
    patterns = [
        line.strip()
        for line in ignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert not any(p in {"LICENSE", "LICENSE*", "/LICENSE", "**/LICENSE"} for p in patterns), (
        "ide/.vscodeignore excludes LICENSE, which would strip the file vscode:prepublish just wrote"
    )


def test_the_untracked_licence_is_deliberate_and_stays_recorded() -> None:
    """Pin the reason ``ide/LICENSE`` is absent, so it is not "fixed" by adding a tracked copy.

    This is the assertion that would have saved the investigation behind this file: the absence looks
    exactly like an oversight, and the tempting repair -- commit an ``ide/LICENSE`` -- would duplicate
    a generated artifact and put two copies of one fact under version control.
    """
    gitignore = _IDE / ".gitignore"
    assert gitignore.is_file(), "ide/.gitignore is what records that ide/LICENSE is generated"
    entries = {
        line.strip()
        for line in gitignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert "LICENSE" in entries, (
        "ide/.gitignore no longer ignores LICENSE. Either the file is now tracked -- in which case it "
        "is a second copy of the root LICENSE and needs a drift check -- or the ignore was dropped by "
        "accident and a publish will leave an untracked LICENSE in the tree."
    )
