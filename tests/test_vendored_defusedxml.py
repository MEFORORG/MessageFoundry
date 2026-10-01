# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the vendored defusedxml copy to upstream's bytes, and the packaging that carries it.

``messagefoundry/_vendor/defusedxml/README.md`` states each vendored file's upstream SHA-256 in a table.
These tests read the table and check it against the tree, so the README cannot claim a provenance the
files no longer have. What each call site's parser REFUSES is held by
``tests/test_xml_refusal_guard.py``, and that nothing imports the upstream package any more is held
by ``tests/test_security_static.py``.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import tomllib
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import messagefoundry._vendor.defusedxml as vendored

REPO = Path(__file__).resolve().parent.parent
#: Located through the import, so the files checked are the ones the engine loads.
VENDOR = Path(vendored.__file__).parent

#: The upstream release the copy was taken from, as the README and the header both state it.
VENDORED_VERSION = "0.7.1"

#: The upstream files the README's table must record, one digest each.
UPSTREAM_FILES = ("common.py", "ElementTree.py", "LICENSE")

#: The two lines each vendored module carries above upstream's bytes, exactly.
HEADER = (
    b"# SPDX-License-Identifier: PSF-2.0\n"
    b"# Vendored from defusedxml " + VENDORED_VERSION.encode() + b". Every line after these two is "
    b"upstream's, unchanged.\n"
)


def _load_sbom_finalize() -> ModuleType:
    """The SBOM helper, loaded by path because it is a script. Its README grammar is the RULE this
    file reads the table with, so the release and these tests cannot parse the table differently."""
    spec = importlib.util.spec_from_file_location(
        "sbom_finalize", REPO / "scripts" / "security" / "sbom_finalize.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sbom_finalize = _load_sbom_finalize()
#: The README's file rows: name to upstream SHA-256.
RECORDED = dict(sbom_finalize._FILE_ROW.findall((VENDOR / "README.md").read_text(encoding="utf-8")))


def _upstream_bytes(name: str) -> bytes:
    """The file as upstream shipped it: a module loses its header, and the licence is whole."""
    data = (VENDOR / name).read_bytes()
    if name.endswith(".py"):
        assert data.startswith(HEADER), f"{name} does not start with the vendoring header"
        return data[len(HEADER) :]
    return data


def test_the_readme_records_every_upstream_file() -> None:
    # The positive control for the digest test: an empty table would make it pass vacuously.
    assert set(RECORDED) == set(UPSTREAM_FILES)


@pytest.mark.parametrize("name", UPSTREAM_FILES)
def test_each_vendored_file_is_upstreams_bytes(name: str) -> None:
    assert hashlib.sha256(_upstream_bytes(name)).hexdigest() == RECORDED[name]


def _installed_upstream() -> Path | None:
    """The upstream package's directory, where an extra installed it (``pyx12`` pulls it in)."""
    spec = importlib.util.find_spec("defusedxml")
    return Path(spec.origin).parent if spec is not None and spec.origin else None


@pytest.mark.parametrize("name", ["common.py", "ElementTree.py"])
def test_each_vendored_module_is_the_installed_upstream_file(name: str) -> None:
    """The README digests are written beside the files, so an edit that updates both passes the
    test above. This one compares with upstream's own bytes wherever upstream is installed, which
    the CI test legs do through the ``x12`` extra, and only while the lock pins the same version."""
    upstream = _installed_upstream()
    if upstream is None:
        pytest.skip("upstream defusedxml is not installed here (it rides only the x12 extra)")
    assert importlib.metadata.version("defusedxml") == VENDORED_VERSION
    assert _upstream_bytes(name) == (upstream / name).read_bytes()


def test_the_lock_pins_the_version_that_was_vendored() -> None:
    """A lock that moves upstream defusedxml off the vendored version means someone must re-vendor.

    Without this, a bump would turn the dependency audit of the lock green while the engine kept
    parsing through the old copy. The ``x12`` extra is the only thing that still locks it."""
    lock = tomllib.loads((REPO / "uv.lock").read_text(encoding="utf-8"))
    locked = {p["version"] for p in lock["package"] if p["name"] == "defusedxml"}
    assert locked == {VENDORED_VERSION}, (
        f"uv.lock pins defusedxml {sorted(locked)}, but messagefoundry/_vendor/defusedxml is "
        f"{VENDORED_VERSION}: re-vendor it, or record why the two may differ"
    )


def test_the_package_ships_only_what_the_readme_accounts_for() -> None:
    """A module dropped in beside the recorded ones would ride along unrecorded."""
    shipped = {p.name for p in VENDOR.iterdir() if p.name != "__pycache__"}
    assert shipped == {"__init__.py", "README.md", *UPSTREAM_FILES}


def test_the_engine_no_longer_declares_the_package() -> None:
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert not [d for d in project["dependencies"] if d.lower().startswith("defusedxml")]
    # The vendored licence travels with every wheel and sdist, as PSF-2.0 requires.
    assert "messagefoundry/_vendor/defusedxml/LICENSE" in project["license-files"]
    assert "PSF-2.0" in project["license"]


# --- the SBOM lists the copy (BACKLOG #2498) -------------------------------------------------------
# These sit here, on the engine legs, and not in tests/test_sbom_finalize.py, which is tooling-tier and
# path-gated to scripts/ and .github/. A pull request that vendors something trips this file's gate.


def _finalized_sbom(tmp_path: Path) -> dict[str, Any]:
    """A minimal BOM finalized with ``--vendored-from`` over the real vendor directory."""
    bom = tmp_path / "bom.cdx.json"
    seed = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {"component": {"bom-ref": "root", "name": "messagefoundry"}},
        "components": [],
    }
    bom.write_text(json.dumps(seed), encoding="utf-8")
    assert sbom_finalize.main([str(bom), "--vendored-from", str(VENDOR.parent)]) == 0
    doc: dict[str, Any] = json.loads(bom.read_text(encoding="utf-8"))
    return doc


def test_every_vendored_package_is_in_the_finalized_sbom(tmp_path: Path) -> None:
    """A copy under messagefoundry/_vendor that the SBOM omits fails here.

    The tree is enumerated by NAME, not by the helper's own package test, so a single vendored module
    the helper cannot see as a package cannot pass both. Only the helper's named extras are skipped.
    """
    extras = sbom_finalize._VENDOR_DIR_EXTRAS
    vendored = sorted(Path(p.name).stem for p in VENDOR.parent.iterdir() if p.name not in extras)
    assert "defusedxml" in vendored, f"the enumeration found {vendored}; it has gone blind"
    # The absence check below walks `vendored`, so it passes on an empty walk; pin both inputs.
    assert len(vendored) >= 1, "the vendor enumeration found nothing"
    components = _finalized_sbom(tmp_path)["components"]
    assert len(components) >= 1, "the finalized SBOM has no components"
    listed = {
        prop["value"]
        for c in components
        for prop in c.get("properties", [])
        if prop["name"] == sbom_finalize.VENDORED_PROPERTY
    }
    missing = [n for n in vendored if f"messagefoundry._vendor.{n}" not in listed]
    assert not missing, f"vendored packages missing from the finalized SBOM: {missing}"


def _locked_sdist_sha256() -> str:
    """The digest uv.lock records for the vendored version's sdist."""
    lock = tomllib.loads((REPO / "uv.lock").read_text(encoding="utf-8"))
    [entry] = [
        p for p in lock["package"] if p["name"] == "defusedxml" and p["version"] == VENDORED_VERSION
    ]
    algorithm, _, digest = entry["sdist"]["hash"].partition(":")
    assert algorithm == "sha256", entry["sdist"]["hash"]
    return str(digest)


def test_the_sbom_component_carries_the_upstream_record(tmp_path: Path) -> None:
    """Name, version, licence and purl are what a scanner matches an advisory on. Upstream's digests
    sit in the pedigree, checked here against the files and the lock rather than against the README
    the helper read them from, and never on the component, whose shipped bytes differ."""
    [c] = [
        c
        for c in _finalized_sbom(tmp_path)["components"]
        if str(c.get("bom-ref")).startswith(sbom_finalize.VENDORED_REF_PREFIX)
    ]
    assert (c["type"], c["name"], c["version"]) == ("library", "defusedxml", VENDORED_VERSION)
    assert c["purl"] == f"pkg:pypi/defusedxml@{VENDORED_VERSION}"
    assert c["licenses"] == [{"license": {"id": "PSF-2.0"}}]
    assert "hashes" not in c and "components" not in c
    [upstream] = c["pedigree"]["ancestors"]
    assert upstream["purl"] == c["purl"]
    [dist] = upstream["externalReferences"]
    assert dist["url"].endswith(f"/defusedxml-{VENDORED_VERSION}.tar.gz")
    assert dist["hashes"] == [{"alg": "SHA-256", "content": _locked_sdist_sha256()}]
    files = {f["name"]: f["hashes"][0]["content"] for f in upstream["components"]}
    assert files == {n: hashlib.sha256(_upstream_bytes(n)).hexdigest() for n in UPSTREAM_FILES}
