# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for scripts/security/sbom_finalize.py (ADR 0149).

The helper is a standalone CI script (not part of the `messagefoundry` package), so it is loaded by
path via importlib rather than imported as a module.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

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
