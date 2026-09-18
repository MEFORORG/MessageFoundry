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
it can go red. Three tests below mutate a COPY of the tree in `tmp_path` -- one byte of the bundle,
one character of the record, the vendoring header -- and assert the checker reports each. Without
them a checker that silently read the wrong path would pass forever while measuring nothing, which
is the failure this repository has already paid for more than once.

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
import shutil
from pathlib import Path
from types import ModuleType

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


@functools.cache
def _record() -> dict:
    """The committed record, parsed once. No test mutates it; the copies live under ``tmp_path``."""
    return json.loads((REPO_ROOT / provenance.RECORD_PATH).read_text(encoding="utf-8"))


def _property(section: str, name: str) -> str:
    """One property value from the record's ``metadata`` or its primary ``component``."""
    holder = _record()["metadata"] if section == "metadata" else _record()["metadata"]["component"]
    for entry in holder["properties"]:
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
    """
    text = (REPO_ROOT / relative).read_text(encoding="utf-8", errors="replace")
    assert provenance.UPSTREAM_COMMIT in text, f"{relative} does not name the pinned commit"


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
