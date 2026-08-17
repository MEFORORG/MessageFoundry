#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Finalize a CycloneDX SBOM: declare its lifecycle, backfill a null primary-component version,
and assert the fields a downstream operator relies on are present before we ship/retain it.

WHY THIS EXISTS (ADR 0149). The SBOM generators we run — ``cyclonedx-py environment`` (Python),
``@cyclonedx/cyclonedx-npm`` (the VS Code extension), and ``trivy image`` (the container) — emit a
CycloneDX BOM carrying at least components, licenses, and ``metadata.tools`` (the generating tool, i.e.
the draft-2025 CISA "Tool Name" minimum element). Per-component *hashes* are NOT among them for the
Python SBOM: ``cyclonedx-py environment`` emits none at all, so do not describe the finalized artifact
as hash-bearing (docs/SUPPLY-CHAIN.md says so to operators, and the two must not drift apart again).
Two gaps remain that this closes:

  1. None of them set ``metadata.lifecycles`` — the CycloneDX field that records WHERE in the SDLC
     the BOM was produced. That maps to CISA's "Build" SBOM Type and the draft-2025 CISA "Generation
     Context" minimum element, so a consumer knows the generation approach that shaped the component
     list. We inject ``[{"phase": "build"}]`` (override with --phase).

  2. ``cyclonedx-py environment --pyproject`` names the root component (messagefoundry) but leaves its
     version null, because the version is hatchling-*dynamic* (single-sourced from __init__.py) and is
     not resolvable from pyproject.toml alone. We backfill it from an explicit source file, opt-in via
     --set-version-from, so the same helper can finalize the npm/container SBOMs (whose primary
     component already carries a version) without mis-stamping them.

It then asserts the CycloneDX invariants and the CISA/NTIA-relevant metadata are present: a genuinely
broken SBOM (wrong bomFormat / no specVersion) exits non-zero so a release can't ship it; softer gaps
(no tools / no timestamp / no primary component) warn but do not fail, since sbomqs scores those.

Stdlib-only, idempotent (safe to re-run), and format-only (never invents components or vuln claims).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# metadata.lifecycles is a CycloneDX 1.5+ field; injecting it into an older-spec BOM would be invalid.
_LIFECYCLE_SPECS = {"1.5", "1.6", "1.7"}
# CycloneDX lifecycle phase enum (1.5+). "build" is the phase these SBOMs are produced in.
_PHASES = {"design", "pre-build", "build", "post-build", "operations", "discovery", "decommission"}


def _read_version(path: Path) -> str | None:
    """Extract ``__version__ = "x.y.z"`` from a Python source file (the single-source version)."""
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', path.read_text(encoding="utf-8"), re.M)
    return m.group(1) if m else None


def _tools_present(metadata: dict[str, Any]) -> bool:
    """metadata.tools is either the legacy list [{name,...}] or the 1.5+ object {components,services}."""
    tools = metadata.get("tools")
    if isinstance(tools, list):
        return len(tools) > 0
    if isinstance(tools, dict):
        return bool(tools.get("components") or tools.get("services"))
    return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Finalize a CycloneDX SBOM (lifecycle + asserts).")
    ap.add_argument("sbom", type=Path, help="Path to the CycloneDX JSON SBOM to finalize in place.")
    ap.add_argument(
        "--phase",
        default="build",
        choices=sorted(_PHASES),
        help="CycloneDX lifecycle phase to declare (default: build).",
    )
    ap.add_argument(
        "--set-version-from",
        type=Path,
        default=None,
        metavar="FILE",
        help="If the primary component has no version, read __version__ from this Python "
        "file and set it (used for the Python SBOM's dynamic-version root component).",
    )
    args = ap.parse_args(argv)

    try:
        doc = json.loads(args.sbom.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"::error::sbom_finalize: cannot read {args.sbom}: {exc}", file=sys.stderr)
        return 2

    # --- fatal invariants: a BOM that fails these is not a usable SBOM -------------------------------
    fatal = []
    if doc.get("bomFormat") != "CycloneDX":
        fatal.append(f"bomFormat is {doc.get('bomFormat')!r}, expected 'CycloneDX'")
    spec = str(doc.get("specVersion") or "")
    if not spec:
        fatal.append("specVersion is missing")
    if fatal:
        for f in fatal:
            print(f"::error::sbom_finalize: {f}", file=sys.stderr)
        return 1

    # Coerce a missing OR explicitly-null metadata to a dict — no generator emits `"metadata": null`, but
    # this keeps the release-gating helper crash-proof against a hand-edited BOM.
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        doc["metadata"] = metadata

    # --- (1) declare the lifecycle / generation context (CISA "Build" type) -------------------------
    if spec in _LIFECYCLE_SPECS:
        if not metadata.get("lifecycles"):
            metadata["lifecycles"] = [{"phase": args.phase}]
    else:
        print(
            f"::warning::sbom_finalize: specVersion {spec} predates metadata.lifecycles (1.5+); "
            "skipping lifecycle injection",
            file=sys.stderr,
        )

    # --- (2) backfill a null primary-component version ----------------------------------------------
    component = metadata.get("component")
    if (
        args.set_version_from is not None
        and isinstance(component, dict)
        and not component.get("version")
    ):
        ver = _read_version(args.set_version_from)
        if ver:
            component["version"] = ver
        else:
            print(
                f"::warning::sbom_finalize: no __version__ found in {args.set_version_from}; "
                "primary component version left unset",
                file=sys.stderr,
            )

    # --- soft assertions: warn (sbomqs scores these), never fail the build --------------------------
    if not _tools_present(metadata):
        print(
            "::warning::sbom_finalize: metadata.tools is empty (CISA 'Tool Name')", file=sys.stderr
        )
    if not metadata.get("timestamp"):
        print(
            "::warning::sbom_finalize: metadata.timestamp is missing (CISA 'Timestamp')",
            file=sys.stderr,
        )
    if not isinstance(component, dict):
        print(
            "::warning::sbom_finalize: no metadata.component (primary component)", file=sys.stderr
        )

    args.sbom.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    name = component.get("name") if isinstance(component, dict) else None
    version = component.get("version") if isinstance(component, dict) else None
    print(
        f"sbom_finalize: {args.sbom.name} — CycloneDX {spec}, "
        f"primary={name}@{version}, lifecycle={metadata.get('lifecycles')}, "
        f"components={len(doc.get('components', []))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
