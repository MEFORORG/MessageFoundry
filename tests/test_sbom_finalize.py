# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for scripts/security/sbom_finalize.py (ADR 0149).

The helper is a standalone CI script (not part of the `messagefoundry` package), so it is loaded by
path via importlib rather than imported as a module.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "security" / "sbom_finalize.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("sbom_finalize", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


sbom_finalize = _load_module()


def _write_bom(tmp_path: Path, **overrides) -> Path:
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-07-21T00:00:00Z",
            "tools": {"components": [{"name": "cyclonedx-py"}]},
            "component": {"name": "messagefoundry", "type": "application"},
        },
        "components": [{"name": "httpx", "version": "0.27.0"}],
    }
    bom.update(overrides)
    p = tmp_path / "sbom.cdx.json"
    p.write_text(json.dumps(bom), encoding="utf-8")
    return p


def _read(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def test_injects_build_lifecycle(tmp_path: Path):
    """AC-1: a BOM with no metadata.lifecycles gains [{"phase": "build"}]."""
    p = _write_bom(tmp_path)
    rc = sbom_finalize.main([str(p)])
    assert rc == 0
    assert _read(p)["metadata"]["lifecycles"] == [{"phase": "build"}]


def test_phase_override(tmp_path: Path):
    p = _write_bom(tmp_path)
    assert sbom_finalize.main([str(p), "--phase", "operations"]) == 0
    assert _read(p)["metadata"]["lifecycles"] == [{"phase": "operations"}]


def test_backfills_dynamic_version(tmp_path: Path):
    """AC-2: a null primary-component version is filled from --set-version-from."""
    p = _write_bom(tmp_path)  # metadata.component has no "version"
    vfile = tmp_path / "__init__.py"
    vfile.write_text('foo = 1\n__version__ = "0.3.0"\nbar = 2\n', encoding="utf-8")
    assert sbom_finalize.main([str(p), "--set-version-from", str(vfile)]) == 0
    assert _read(p)["metadata"]["component"]["version"] == "0.3.0"


def test_preserves_existing_version(tmp_path: Path):
    """AC-5: an existing primary-component version is never overwritten."""
    p = _write_bom(
        tmp_path,
        metadata={
            "timestamp": "2026-07-21T00:00:00Z",
            "tools": {"components": [{"name": "cyclonedx-npm"}]},
            "component": {"name": "messagefoundry", "version": "0.0.34", "type": "application"},
        },
    )
    vfile = tmp_path / "__init__.py"
    vfile.write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    assert sbom_finalize.main([str(p), "--set-version-from", str(vfile)]) == 0
    assert _read(p)["metadata"]["component"]["version"] == "0.0.34"


def test_rejects_non_cyclonedx(tmp_path: Path):
    """AC-3: a non-CycloneDX document exits non-zero (fails the release)."""
    p = _write_bom(tmp_path, bomFormat="SPDX")
    assert sbom_finalize.main([str(p)]) == 1


def test_rejects_missing_spec_version(tmp_path: Path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    assert sbom_finalize.main([str(p)]) == 1


def test_idempotent(tmp_path: Path):
    """AC-4: a second run over a finalized BOM changes nothing."""
    p = _write_bom(tmp_path)
    vfile = tmp_path / "__init__.py"
    vfile.write_text('__version__ = "0.3.0"\n', encoding="utf-8")
    assert sbom_finalize.main([str(p), "--set-version-from", str(vfile)]) == 0
    first = p.read_text(encoding="utf-8")
    assert sbom_finalize.main([str(p), "--set-version-from", str(vfile)]) == 0
    assert p.read_text(encoding="utf-8") == first


def test_does_not_clobber_existing_lifecycle(tmp_path: Path):
    p = _write_bom(tmp_path)
    doc = _read(p)
    doc["metadata"]["lifecycles"] = [{"phase": "post-build"}]
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert sbom_finalize.main([str(p)]) == 0
    assert _read(p)["metadata"]["lifecycles"] == [{"phase": "post-build"}]


def test_unreadable_file_returns_2(tmp_path: Path):
    assert sbom_finalize.main([str(tmp_path / "nope.json")]) == 2


def test_null_metadata_coerced(tmp_path: Path):
    """A hand-edited BOM with metadata: null must not crash — it is coerced to a dict."""
    p = tmp_path / "s.json"
    p.write_text(
        json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": None}),
        encoding="utf-8",
    )
    assert sbom_finalize.main([str(p)]) == 0
    assert _read(p)["metadata"]["lifecycles"] == [{"phase": "build"}]


def _platform_values(doc: dict) -> list[str]:
    return [
        p["value"]
        for p in doc["metadata"].get("properties", [])
        if p.get("name") == sbom_finalize.PLATFORM_PROPERTY
    ]


def test_sys_platform_is_recorded_from_the_running_interpreter(tmp_path: Path, monkeypatch):
    """The Linux and Windows engine SBOMs share a root component, so the label is what tells them
    apart once the filename is gone. It comes from ``sys.platform``, never from the caller."""
    monkeypatch.setattr(sbom_finalize.sys, "platform", "win32")
    p = _write_bom(tmp_path)
    assert sbom_finalize.main([str(p), "--record-sys-platform"]) == 0
    assert _platform_values(_read(p)) == ["win32"]


def test_sys_platform_replaces_rather_than_appends_and_keeps_other_properties(
    tmp_path: Path, monkeypatch
):
    """A re-run must leave ONE label, or a consumer reads two platforms."""
    p = _write_bom(
        tmp_path,
        metadata={
            "component": {"name": "messagefoundry", "type": "application"},
            "properties": [{"name": "other:prop", "value": "kept"}],
        },
    )
    monkeypatch.setattr(sbom_finalize.sys, "platform", "linux")
    assert sbom_finalize.main([str(p), "--record-sys-platform"]) == 0
    monkeypatch.setattr(sbom_finalize.sys, "platform", "win32")
    assert sbom_finalize.main([str(p), "--record-sys-platform"]) == 0
    doc = _read(p)
    assert _platform_values(doc) == ["win32"]
    assert {"name": "other:prop", "value": "kept"} in doc["metadata"]["properties"]


def test_no_sys_platform_flag_writes_no_label(tmp_path: Path):
    """The npm and container SBOMs call this helper without the flag and must not gain a label."""
    p = _write_bom(tmp_path)
    assert sbom_finalize.main([str(p)]) == 0
    assert "properties" not in _read(p)["metadata"]


# --- vendored packages (BACKLOG #2498) -------------------------------------------------------------

_REPO = _SCRIPT.parents[2]
_VENDOR = _REPO / "messagefoundry" / "_vendor"


def _vendored(doc: dict) -> list[dict]:
    return [
        c
        for c in doc.get("components", [])
        if str(c.get("bom-ref", "")).startswith(sbom_finalize.VENDORED_REF_PREFIX)
    ]


def _write_rooted_bom(tmp_path: Path) -> Path:
    """A BOM shaped like cyclonedx-py's: a root bom-ref and a dependency graph hanging off it."""
    return _write_bom(
        tmp_path,
        metadata={
            "timestamp": "2026-07-21T00:00:00Z",
            "tools": {"components": [{"name": "cyclonedx-py"}]},
            "component": {"bom-ref": "root-component", "name": "messagefoundry"},
        },
        components=[{"bom-ref": "httpx==0.27.0", "name": "httpx", "version": "0.27.0"}],
        dependencies=[
            {"ref": "root-component", "dependsOn": ["httpx==0.27.0"]},
            {"ref": "httpx==0.27.0"},
        ],
    )


def test_every_vendored_package_is_in_the_finalized_sbom(tmp_path: Path):
    """THE GUARD #2498 ASKS FOR: a package under messagefoundry/_vendor the SBOM omits fails here.

    The packages are enumerated from the tree, not from the helper, so a helper that stopped finding
    one cannot agree with itself. ``cyclonedx-py environment`` lists installed distributions only, so
    without this a vendored copy is invisible to every scanner reading the SBOM.
    """
    packages = sorted(p.name for p in _VENDOR.iterdir() if (p / "__init__.py").is_file())
    assert "defusedxml" in packages, f"the enumeration found {packages}; it has gone blind"
    p = _write_rooted_bom(tmp_path)
    assert sbom_finalize.main([str(p), "--vendored-from", str(_VENDOR)]) == 0
    listed = {
        prop["value"]
        for c in _vendored(_read(p))
        for prop in c.get("properties", [])
        if prop["name"] == sbom_finalize.VENDORED_PROPERTY
    }
    missing = [n for n in packages if f"messagefoundry._vendor.{n}" not in listed]
    assert not missing, f"vendored packages missing from the finalized SBOM: {missing}"


def _upstream_sha256(path: Path) -> str:
    """The SHA-256 of ``path`` as upstream shipped it: a vendored module loses its two header lines."""
    data = path.read_bytes()
    if path.suffix == ".py":
        data = b"".join(data.splitlines(keepends=True)[2:])
    return hashlib.sha256(data).hexdigest()


def test_the_defusedxml_component_carries_the_upstream_record(tmp_path: Path):
    """Name, version, licence and purl are what a scanner matches an advisory on. The file digests
    are checked against the files themselves, not against the README the helper read them from."""
    p = _write_rooted_bom(tmp_path)
    assert sbom_finalize.main([str(p), "--vendored-from", str(_VENDOR)]) == 0
    [c] = [c for c in _vendored(_read(p)) if c["name"] == "defusedxml"]
    assert c["type"] == "library"
    assert c["version"] == "0.7.1"
    assert c["purl"] == "pkg:pypi/defusedxml@0.7.1"
    assert c["licenses"] == [{"license": {"id": "PSF-2.0"}}]
    [dist] = [r for r in c["externalReferences"] if r["type"] == "distribution"]
    assert dist["url"].endswith("/defusedxml-0.7.1.tar.gz")
    assert dist["hashes"] == [{"alg": "SHA-256", "content": _DEFUSEDXML_SDIST_SHA256}]
    files = {f["name"]: f["hashes"][0]["content"] for f in c["components"]}
    assert set(files) == {"common.py", "ElementTree.py", "LICENSE"}
    for name, digest in files.items():
        assert digest == _upstream_sha256(_VENDOR / "defusedxml" / name), name


#: The digest uv.lock records for the defusedxml 0.7.1 sdist, which the README restates.
_DEFUSEDXML_SDIST_SHA256 = "1bb3032db185915b62d7c6209c5a8792be6a32ab2fedacc84e01b52c51aa3e69"


def test_vendoring_is_idempotent_and_hangs_off_the_root(tmp_path: Path):
    """A re-run must leave one component and one edge, or a consumer counts the copy twice."""
    p = _write_rooted_bom(tmp_path)
    for _ in range(2):
        assert sbom_finalize.main([str(p), "--vendored-from", str(_VENDOR)]) == 0
    doc = _read(p)
    refs = [c["bom-ref"] for c in _vendored(doc)]
    assert len(refs) == len(set(refs)) == 1
    [root] = [d for d in doc["dependencies"] if d["ref"] == "root-component"]
    assert root["dependsOn"] == ["httpx==0.27.0", *refs]
    assert [d for d in doc["dependencies"] if d["ref"] in refs] == [{"ref": r} for r in refs]
    assert {"bom-ref": "httpx==0.27.0", "name": "httpx", "version": "0.27.0"} in doc["components"]


def test_a_resolver_emitted_copy_of_the_same_package_is_kept(tmp_path: Path):
    """An extra (x12's pyx12) can install upstream defusedxml too. That is a second, real copy, so
    the vendored component sits beside it rather than replacing it."""
    resolved = {"bom-ref": "defusedxml==0.7.1", "name": "defusedxml"}
    p = _write_bom(tmp_path, components=[resolved])
    assert sbom_finalize.main([str(p), "--vendored-from", str(_VENDOR)]) == 0
    refs = [c.get("bom-ref") for c in _read(p)["components"] if c["name"] == "defusedxml"]
    assert refs == ["defusedxml==0.7.1", "messagefoundry-vendored:defusedxml@0.7.1"]


def test_no_vendored_flag_adds_no_component(tmp_path: Path):
    """The npm and container SBOMs call this helper without the flag and must not gain one."""
    p = _write_bom(tmp_path)
    assert sbom_finalize.main([str(p)]) == 0
    assert _vendored(_read(p)) == []


def _fake_vendor(tmp_path: Path, readme: str | None) -> Path:
    vendor = tmp_path / "_vendor"
    pkg = vendor / "fakepkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    if readme is not None:
        (pkg / "README.md").write_text(readme, encoding="utf-8")
    return vendor


_GOOD_README = (_VENDOR / "defusedxml" / "README.md").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("readme", "needle"),
    [
        (None, "no readable README.md"),
        (_GOOD_README.replace("| Upstream version |", "| Version |"), "upstream"),
        (_GOOD_README.replace("SPDX `PSF-2.0`", "PSF-2.0"), "licence"),
        (_GOOD_README.replace("| sdist SHA-256 |", "| sdist hash |"), "sdist_sha256"),
        (
            "\n".join(ln for ln in _GOOD_README.splitlines() if not ln.startswith("| `")),
            "per-file upstream SHA-256 rows",
        ),
    ],
    ids=["no-readme", "no-version", "no-licence", "no-sdist-hash", "no-file-rows"],
)
def test_a_vendored_package_the_readme_cannot_describe_fails_the_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], readme: str | None, needle: str
):
    """Fail closed: a package missing from the SBOM must not be one README edit away from silent.
    The BOM is left untouched, so a release step stops before it ships a partial one."""
    p = _write_bom(tmp_path)
    before = p.read_bytes()
    rc = sbom_finalize.main([str(p), "--vendored-from", str(_fake_vendor(tmp_path, readme))])
    assert rc == 1
    assert needle in capsys.readouterr().err
    assert p.read_bytes() == before


def test_the_unedited_readme_is_accepted(tmp_path: Path):
    """The positive control for the arms above: the same harness, the README unedited."""
    p = _write_bom(tmp_path)
    vendor = _fake_vendor(tmp_path, _GOOD_README)
    assert sbom_finalize.main([str(p), "--vendored-from", str(vendor)]) == 0
    [c] = _vendored(_read(p))
    assert c["properties"] == [{"name": sbom_finalize.VENDORED_PROPERTY, "value": "fakepkg"}]


def test_an_empty_or_missing_vendor_dir_fails(tmp_path: Path):
    """A flag that claims vendored code and finds none is a broken call, not a clean result."""
    p = _write_bom(tmp_path)
    (tmp_path / "empty").mkdir()
    assert sbom_finalize.main([str(p), "--vendored-from", str(tmp_path / "empty")]) == 1
    assert sbom_finalize.main([str(p), "--vendored-from", str(tmp_path / "absent")]) == 1


def test_vendoring_refuses_a_pre_1_5_bom(tmp_path: Path):
    """externalReferences[].hashes, which carries the sdist digest, arrived in CycloneDX 1.5."""
    p = _write_bom(tmp_path, specVersion="1.4")
    assert sbom_finalize.main([str(p), "--vendored-from", str(_VENDOR)]) == 1
