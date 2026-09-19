# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The gate on the vendored CLA action's provenance record (BACKLOG #1578).

THE DEFECT. `.github/actions/cla-assistant-lite/` carries 1.18 MB of third-party JavaScript that no
dependency gate in this repository can see, and its only recorded provenance was a checksum in a
ledger entry stored in a separate repository. A bundle edited here -- by a bad merge, a rebase over
a mangled file, or a deliberate change -- would land with nothing in the tree contradicting it.

WHAT THIS MODULE ASSERTS, in the order that matters:

1. the vendored bundle still derives from the pinned upstream commit, offline and without Node
   (:func:`test_the_vendored_bundle_still_derives_from_the_pinned_upstream_commit`);
2. the record is a fixed point of its generator, so the bundle cannot move without the record
   moving with it;
3. the record still names the commit the workflow and the README name;
4. the limitation sentence is present, verbatim.

WHY THE NEGATIVE CONTROLS ARE NOT OPTIONAL. A green check is evidence only once somebody has proved
it can go red. The tests below mutate a COPY of the tree in `tmp_path` -- at least a byte of the
bundle, a character of the record, the vendoring header, the lockfile, and a recorded file removed
outright -- and assert the checker reports each. Without them a checker that silently read the wrong
path would pass forever while measuring nothing, which is the failure this repository has already
paid for more than once.

THE CONTROLS ARE WHAT FOUND THE ONE REAL HOLE IN THIS GATE, and they found it by being EXTENDED
rather than by being present. The first cut mutated only the bundle, and `--write` refused as
designed. The same shape over the LOCKFILE returned exit 0 and regenerated a clean record carrying
the injected package -- the artifact an auditor is told to scan, laundered by the tool whose refusal
message says it will not launder anything. Covering three of four recorded files left the one
exploitable path uncovered, so a control table is read for what it OMITS.

WHAT NONE OF IT PROVES. A clean audit of the vendored lockfile proves the DECLARED dependencies of
the pinned upstream commit are clean. It does not prove the bundle was built from them: that needs
a Node toolchain this repository does not carry. :func:`test_the_record_states_what_it_cannot_prove`
pins that sentence in place so the record cannot quietly grow into a claim it does not support.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import re
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = REPO_ROOT / "scripts" / "security" / "build_cla_action_provenance.py"


def _load_module() -> ModuleType:
    """Load the standalone CI script by path; it is not part of the ``messagefoundry`` package."""
    spec = importlib.util.spec_from_file_location("build_cla_action_provenance", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provenance = _load_module()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A throwaway copy of the vendored action, mutable without touching the repository.

    The record lives inside the action directory, so one copy carries both and every checker path
    resolves against ``tmp_path`` exactly as it would against the real root.
    """
    destination = tmp_path / provenance.ACTION_DIR
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(REPO_ROOT / provenance.ACTION_DIR, destination)
    return tmp_path


def _inject(tree: Path) -> None:
    """Append a byte to the copied bundle -- the mutation the negative controls are built on."""
    bundle = tree / provenance.BUNDLE_PATH
    bundle.write_bytes(bundle.read_bytes() + b"\n// injected\n")


def _inject_lockfile(tree: Path) -> None:
    """Add a package to the copied lockfile -- the tamper that once regenerated clean.

    Shaped like the real attack rather than like a corruption: the file still parses, still looks
    like npm wrote it, and the only visible effect is one more component in the inventory.
    """
    path = tree / provenance.LOCK_PATH
    lock = json.loads(path.read_text(encoding="utf-8"))
    lock["packages"]["node_modules/evil-pkg"] = {
        "version": "9.9.9",
        "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-9.9.9.tgz",
        "license": "MIT",
    }
    path.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")


@functools.cache
def _record() -> dict[str, Any]:
    """The committed record, parsed once. No test mutates it; the copies live under ``tmp_path``."""
    record: dict[str, Any] = json.loads(
        (REPO_ROOT / provenance.RECORD_PATH).read_text(encoding="utf-8")
    )
    return record


def _property(section: str, name: str) -> str:
    """One property value from the record's ``metadata`` or its primary ``component``.

    An unknown *section* raises rather than defaulting to ``component``. With a two-branch
    conditional here, ``_property("metdata", ...)`` searched the component's properties, failed to
    find the key, and reported "the record carries no 'metdata' property" -- naming a section it
    had never looked in and sending the reader to the wrong half of the document.
    """
    holders = {
        "metadata": _record()["metadata"],
        "component": _record()["metadata"]["component"],
    }
    if section not in holders:
        raise AssertionError(f"unknown record section {section!r}; expected metadata or component")
    for entry in holders[section]["properties"]:
        if entry["name"] == name:
            return str(entry["value"])
    raise AssertionError(f"the record carries no {section} property {name!r}")


# --- What is actually proven ----------------------------------------------------------------


def test_the_vendored_bundle_still_derives_from_the_pinned_upstream_commit() -> None:
    """Strip the two-line vendoring header and the rest is the upstream blob, byte for byte.

    This is the whole provenance claim, and it is checkable with no network and no Node: the
    recorded upstream digest is reproduced from the file on disk rather than merely asserted.
    """
    bundle = (REPO_ROOT / provenance.BUNDLE_PATH).read_bytes()
    body = provenance.split_vendoring_header(bundle)

    assert hashlib.sha256(body).hexdigest() == provenance.UPSTREAM_BUNDLE_SHA256
    assert _property("component", "messagefoundry:upstream:bundle-sha256") == (
        provenance.UPSTREAM_BUNDLE_SHA256
    )


def test_the_vendored_lockfile_is_the_upstream_blob() -> None:
    """The recorded lock blob id is RE-DERIVED from the file on disk, not merely asserted.

    The bundle's upstream digest was reproducible from the start and the lockfile's was not, and
    that asymmetry is what let a tampered lockfile regenerate a clean record. `git hash-object`
    agrees with this computation, so an auditor can confirm it with a tool they already trust.
    """
    lock = (REPO_ROOT / provenance.LOCK_PATH).read_bytes().replace(b"\r\n", b"\n")

    assert provenance.git_blob_id(lock) == provenance.UPSTREAM_LOCK_BLOB_ID
    assert _property("component", "messagefoundry:upstream:lock-blob-id") == (
        provenance.UPSTREAM_LOCK_BLOB_ID
    )


def test_the_record_describes_the_vendored_tree() -> None:
    """THE GATE. Every digest and count in the record is recomputed from the files it describes.

    A bundle, action.yml, LICENSE or lockfile edited without regenerating the record fails here.
    """
    assert provenance.check(REPO_ROOT) == []


def test_every_recorded_digest_reproduces_from_the_file_it_names() -> None:
    """The per-file digests are re-derived independently of the generator's own rendering path.

    ``check`` compares a rendered document; this walks the recorded properties instead, so a
    generator that stopped digesting anything would still be caught.
    """
    for relative, mode in provenance.RECORDED_FILES.items():
        recorded = _property("component", f"messagefoundry:recorded-files:sha256:{relative}")
        expected = provenance.digest((REPO_ROOT / relative).read_bytes(), mode)
        assert recorded == expected, relative


def test_the_recorded_lockfile_is_the_one_the_record_names() -> None:
    """The vendored lockfile parses, and its package counts match what the record claims."""
    lock = json.loads((REPO_ROOT / provenance.LOCK_PATH).read_text(encoding="utf-8"))
    components = provenance.lock_components(lock)

    assert _property("component", "messagefoundry:upstream:lock-packages") == str(len(components))
    assert len(components) > 100, "the lockfile parsed to almost nothing; check the parser"
    assert _record()["components"] == components


# --- Cross-file consistency: three places name this commit, and they must agree ---------------


@pytest.mark.parametrize(
    "relative",
    [
        ".github/workflows/cla.yml",
        f"{provenance.ACTION_DIR}/README.md",
        provenance.BUNDLE_PATH,
    ],
)
def test_the_pinned_commit_is_named_consistently(relative: str) -> None:
    """A provenance record naming a different commit than the workflow runs is worse than none.

    The whole file is searched, not its head: `cla.yml` names the commit beside the `uses:` line
    that consumes the action, which sits about 180 lines in.

    SEARCHED AS BYTES. One of these paths is the 1.18 MB minified bundle, and decoding it to `str`
    with `errors="replace"` to find a 40-character ASCII commit id spent a megabyte of mangling per
    run for nothing. The id is ASCII, so the byte search answers the same question.
    """
    blob = (REPO_ROOT / relative).read_bytes()
    assert provenance.UPSTREAM_COMMIT.encode("ascii") in blob, (
        f"{relative} does not name the pinned commit"
    )


#: The prose that restates the record's numbers. Two documents, so a reader who finds one of them
#: is not reading a figure the record has since moved past.
_PROSE_DOCS = (
    REPO_ROOT / provenance.ACTION_DIR / "README.md",
    REPO_ROOT / "docs" / "SUPPLY-CHAIN.md",
)


def _derived_facts() -> dict[str, str]:
    """Every number the prose restates, DERIVED from the record rather than typed out here.

    Hardcoding them in this test would make it a third copy of the same facts, which is the defect
    it exists to catch.
    """
    components = _record()["components"]
    runtime = sum(1 for component in components if component["scope"] == "required")
    return {
        "package count": str(len(components)),
        "runtime package count": str(runtime),
        "excluded package count": str(len(components) - runtime),
        "vendoring header length": str(len(provenance.VENDORING_HEADER)),
        "upstream bundle digest": provenance.UPSTREAM_BUNDLE_SHA256,
    }


@pytest.mark.parametrize("label", sorted(_derived_facts()))
def test_the_prose_states_the_number_the_record_holds(label: str) -> None:
    """The counts and digests repeated in prose still match the generated record.

    CLAUDE.md section 11 (SDS-3.5) says state a load-bearing fact once and link to it. These are
    restated anyway, because a reader of the README should not have to open a 95 KB CycloneDX
    document to learn how many packages are in the closure. The cost of that choice is drift, and
    this test is what pays it: re-pin the lockfile and every figure below moves, so a document left
    behind reds here instead of quietly contradicting the artifact it describes.
    """
    expected = _derived_facts()[label]
    # WORD-BOUNDED, because a bare substring search here false-passes. The pinned commit is
    # `ca4a40a7d1004f18d9960b404b97e5f30a505a08` and it contains the digits `404`, so had the
    # package count ever moved 403 -> 404 a containment check would have found the "new" number
    # inside a hex SHA and reported the prose up to date. Measured while building this test.
    pattern = re.compile(rf"\b{re.escape(expected)}\b")
    stating = [doc.name for doc in _PROSE_DOCS if pattern.search(doc.read_text(encoding="utf-8"))]

    assert stating, (
        f"no prose document states the record's {label} ({expected}). Either the record moved and "
        f"{[doc.name for doc in _PROSE_DOCS]} still carry the old figure, or the sentence naming it "
        "was dropped -- read the record before editing either."
    )


def test_the_record_is_the_purl_of_the_pinned_commit() -> None:
    component = _record()["metadata"]["component"]
    assert component["purl"].endswith(f"@{provenance.UPSTREAM_COMMIT}")
    assert component["licenses"] == [{"license": {"id": "Apache-2.0"}}]


# --- The honesty constraint -------------------------------------------------------------------


def test_the_record_states_what_it_cannot_prove() -> None:
    """The limitation sentence is present, verbatim, in the record itself.

    Not in a README beside it: an auditor reads the artifact their tool ingests, and a caveat that
    lives only in prose nobody opens is a compensating control resting on a false premise.
    """
    limitation = _property("metadata", "messagefoundry:provenance:limitation")

    assert limitation == provenance.LIMITATION
    assert "does NOT prove this bundle was built from them" in limitation
    assert "Node toolchain this repository does not carry" in limitation


def test_the_record_says_where_the_bundle_runs() -> None:
    """Severity claims about this bundle are bounded by where it executes, so the record says."""
    exposure = _property("metadata", "messagefoundry:provenance:exposure")

    assert exposure == provenance.EXPOSURE
    assert "not packaged into the wheel or sdist" in exposure.lower()


# --- Negative controls: prove the gate can see ------------------------------------------------


def test_the_gate_sees_a_changed_bundle(tree: Path) -> None:
    """One appended byte in the bundle reds the check. The control for the whole module."""
    assert provenance.check(tree) == [], "the copied tree should start clean"

    _inject(tree)

    problems = provenance.check(tree)
    assert problems, "a changed bundle went unnoticed"
    assert any("does not reproduce the recorded upstream digest" in p for p in problems)


def test_the_gate_sees_a_stripped_vendoring_header(tree: Path) -> None:
    """Removing the header breaks the derivation, and the message says that rather than a digest."""
    bundle = tree / provenance.BUNDLE_PATH
    bundle.write_bytes(provenance.split_vendoring_header(bundle.read_bytes()))

    problems = provenance.check(tree)
    assert any("does not start with the recorded vendoring header" in p for p in problems)


def test_the_gate_sees_an_edited_record(tree: Path) -> None:
    """Editing the record without touching the bundle reds it too -- the gate binds both ways."""
    record_path = tree / provenance.RECORD_PATH
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["metadata"]["component"]["hashes"][0]["content"] = "0" * 64
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")

    problems = provenance.check(tree)
    assert any("not a fixed point of its generator" in p for p in problems)


def test_the_gate_sees_a_missing_record(tree: Path) -> None:
    (tree / provenance.RECORD_PATH).unlink()

    assert any("does not exist" in p for p in provenance.check(tree))


def test_write_refuses_to_launder_a_changed_bundle(tree: Path) -> None:
    """``--write`` over a bundle whose provenance does not check out must REFUSE.

    Regenerating would turn an unexplained change into a freshly-signed record, which is the one
    way a gate like this makes things worse than having none.
    """
    _inject(tree)
    before = (tree / provenance.RECORD_PATH).read_bytes()

    assert provenance.main(["--write", "--root", str(tree)]) == 2
    assert (tree / provenance.RECORD_PATH).read_bytes() == before


def test_the_gate_sees_a_tampered_lockfile(tree: Path) -> None:
    """An added package reds the check, and the message names the lockfile rather than the bundle."""
    _inject_lockfile(tree)

    problems = provenance.check(tree)
    assert any("not the upstream blob it is recorded as" in p for p in problems), problems


def test_write_refuses_to_launder_a_tampered_lockfile(tree: Path) -> None:
    """THE CONTROL FOR THE HOLE THIS REVIEW FOUND. ``--write`` must refuse the lockfile too.

    Before the lockfile derivation existed this returned 0, printed "wrote ...", and produced a
    record whose `components` listed the injected package and whose `--check` was clean. The
    bundle-only refusal made the tool look like it covered the artifact auditors actually scan.
    """
    _inject_lockfile(tree)
    before = (tree / provenance.RECORD_PATH).read_bytes()

    assert provenance.main(["--write", "--root", str(tree)]) == 2
    assert (tree / provenance.RECORD_PATH).read_bytes() == before, (
        "the record was rewritten over a tampered lockfile -- the laundering path is open again"
    )


@pytest.mark.parametrize("relative", sorted(provenance.RECORDED_FILES))
def test_the_gate_sees_a_removed_recorded_file(tree: Path, relative: str) -> None:
    """Deleting any recorded file is REPORTED, not raised.

    Every recorded path was opened unguarded, so removing one -- the LICENSE that makes the
    Apache-2.0 vendoring lawful, say -- surfaced as a FileNotFoundError traceback instead of as the
    finding it is. A gate that crashes on the change it exists to name has told the reader nothing.
    """
    (tree / relative).unlink()

    problems = provenance.check(tree)
    assert any(relative in p and "is not in the tree" in p for p in problems), problems
