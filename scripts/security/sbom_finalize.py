#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

  3. The engine ships TWO Python SBOMs, one resolved on Linux and one on Windows, because the core
     lock carries ``sys_platform`` markers and the two component sets differ. Both carry the same root
     component, so nothing inside either file said which platform it describes; only the filename did,
     and a filename does not survive ingestion into an inventory tool. --record-sys-platform writes
     THIS interpreter's ``sys.platform`` (the PEP 508 ``sys_platform``: ``linux``, ``win32``) as a
     ``metadata.properties`` entry named ``messagefoundry:resolved-for:sys_platform``. Read from the
     interpreter rather than typed by the caller, so it is true by construction wherever the helper
     runs on the same runner as the environment it finalizes, which is how every workflow calls it.
     It still never inspects the components.

  4. The engine carries third-party code in its own tree under ``messagefoundry/_vendor/`` (defusedxml
     0.7.1 since PR 1852). ``cyclonedx-py environment`` lists installed distributions only, so a
     vendored copy is invisible to it, and so to every scanner that reads the SBOM for advisories.
     --vendored-from DIR adds one ``library`` component per package under DIR: name, version, SPDX
     licence, PyPI purl, the upstream sdist and its SHA-256, and one ``file`` subcomponent per upstream
     file carrying that file's upstream SHA-256. Every value is read from the package's own
     ``README.md``, the record ``tests/test_vendored_defusedxml.py`` checks against the files. A
     package whose README does not yield all of them FAILS the run: a vendored package missing from
     the SBOM is the defect this exists to stop, so it must not be skippable by a README edit.

It then asserts the CycloneDX invariants and the CISA/NTIA-relevant metadata are present: a genuinely
broken SBOM (wrong bomFormat / no specVersion) exits non-zero so a release can't ship it; softer gaps
(no tools / no timestamp / no primary component) warn but do not fail, since sbomqs scores those.

Stdlib-only and idempotent (safe to re-run). It never invents a component or a vuln claim: the only
components it adds are the vendored ones in (4), each read from the tree's own record of it.
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
# The metadata.properties name --record-sys-platform writes. Namespaced to this project: the `cdx:`
# prefix is reserved for CycloneDX's own property taxonomy.
PLATFORM_PROPERTY = "messagefoundry:resolved-for:sys_platform"
# The property each --vendored-from component carries: the dotted module path the copy is imported as.
VENDORED_PROPERTY = "messagefoundry:vendored-at"
# The bom-ref prefix of every component --vendored-from adds, so a re-run finds and replaces its own
# (including one a version bump has renamed) and never touches a resolver-emitted component.
VENDORED_REF_PREFIX = "messagefoundry-vendored:"

# The rows of a vendored package's README.md this reads. The file-row pattern is the one
# tests/test_vendored_defusedxml.py checks the files against, so the two read the same table.
_README_FIELDS = {
    "upstream": re.compile(r"^\| Upstream version \| `([^`]+)` (\S+) \|$", re.M),
    "source": re.compile(r"^\| Source \| (https://\S+) \|$", re.M),
    "sdist_sha256": re.compile(r"^\| sdist SHA-256 \| `([0-9a-f]{64})` \|$", re.M),
    "project": re.compile(r"^\| Project \| (https://\S+) \|$", re.M),
    "licence": re.compile(r"^\| Licence \|.*\bSPDX `([^`]+)`.*\|$", re.M),
}
_FILE_ROW = re.compile(r"^\| `([^`]+)` \| [^|]+ \| `([0-9a-f]{64})` \|$", re.M)


class VendoredRecordError(ValueError):
    """A vendored package whose README does not yield everything its SBOM component needs."""


def _module_path(package: Path) -> str:
    """The dotted import path of ``package``: its name, prefixed by every enclosing package."""
    parts = [package.name]
    parent = package.resolve().parent
    while (parent / "__init__.py").is_file():
        parts.insert(0, parent.name)
        parent = parent.parent
    return ".".join(parts)


def _vendored_component(package: Path) -> dict[str, Any]:
    """The CycloneDX component for one vendored package, read from its README.md."""
    readme = package / "README.md"
    try:
        text = readme.read_text(encoding="utf-8")
    except OSError as exc:
        raise VendoredRecordError(f"{package} has no readable README.md: {exc}") from exc
    found: dict[str, re.Match[str]] = {}
    missing: list[str] = []
    for key, pattern in _README_FIELDS.items():
        match = pattern.search(text)
        if match is None:
            missing.append(key)
        else:
            found[key] = match
    files = _FILE_ROW.findall(text)
    if not files:
        missing.append("per-file upstream SHA-256 rows")
    if missing:
        raise VendoredRecordError(f"{readme} does not record: {', '.join(missing)}")
    name, version = found["upstream"].groups()
    module = _module_path(package)
    ref = f"{VENDORED_REF_PREFIX}{name}@{version}"
    return {
        "type": "library",
        "bom-ref": ref,
        "name": name,
        "version": version,
        # PEP 503 normalisation, which the purl spec's pypi type requires.
        "purl": f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}",
        "description": (
            f"Vendored: a copy of {name} {version} inside the messagefoundry package as {module}, "
            "not installed as a separate distribution."
        ),
        "licenses": [{"license": {"id": found["licence"].group(1)}}],
        "externalReferences": [
            {
                "type": "distribution",
                "url": found["source"].group(1),
                "hashes": [{"alg": "SHA-256", "content": found["sdist_sha256"].group(1)}],
            },
            {"type": "vcs", "url": found["project"].group(1)},
        ],
        "properties": [{"name": VENDORED_PROPERTY, "value": module}],
        "components": [
            {
                "type": "file",
                "bom-ref": f"{ref}#{file_name}",
                "name": file_name,
                "description": (
                    "The SHA-256 is of upstream's file. The vendored copy may differ by the "
                    "changes its README records."
                ),
                "hashes": [{"alg": "SHA-256", "content": digest}],
            }
            for file_name, digest in files
        ],
    }


def vendored_components(vendor_dir: Path) -> list[dict[str, Any]]:
    """One component per package (a directory holding ``__init__.py``) directly under ``vendor_dir``.

    Raises VendoredRecordError when there is no package at all, or when any README falls short.
    """
    if not vendor_dir.is_dir():
        raise VendoredRecordError(f"{vendor_dir} is not a directory")
    packages = sorted(p for p in vendor_dir.iterdir() if (p / "__init__.py").is_file())
    if not packages:
        raise VendoredRecordError(
            f"no vendored package (a directory with __init__.py) in {vendor_dir}"
        )
    return [_vendored_component(p) for p in packages]


def _add_vendored(doc: dict[str, Any], vendored: list[dict[str, Any]], root_ref: object) -> None:
    """Replace any earlier vendored components with ``vendored``, and hang them off the root."""

    def ours(ref: object) -> bool:
        return isinstance(ref, str) and ref.startswith(VENDORED_REF_PREFIX)

    components = doc.get("components")
    kept = [
        c
        for c in (components if isinstance(components, list) else [])
        if not (isinstance(c, dict) and ours(c.get("bom-ref")))
    ]
    doc["components"] = [*kept, *vendored]
    if not isinstance(root_ref, str):
        return
    refs = [c["bom-ref"] for c in vendored]
    deps = doc.get("dependencies")
    deps = [
        d
        for d in (deps if isinstance(deps, list) else [])
        if not (isinstance(d, dict) and ours(d.get("ref")))
    ]
    root = next((d for d in deps if isinstance(d, dict) and d.get("ref") == root_ref), None)
    if root is None:
        root = {"ref": root_ref}
        deps.append(root)
    prior = root.get("dependsOn")
    root["dependsOn"] = [
        *(r for r in (prior if isinstance(prior, list) else []) if not ours(r)),
        *refs,
    ]
    doc["dependencies"] = [*deps, *({"ref": r} for r in refs)]


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
    ap.add_argument(
        "--record-sys-platform",
        action="store_true",
        help="Record this interpreter's sys.platform (e.g. linux, win32) as the metadata property "
        f"{PLATFORM_PROPERTY}, replacing any earlier value. Run it on the runner that resolved the "
        "environment.",
    )
    ap.add_argument(
        "--vendored-from",
        type=Path,
        default=None,
        metavar="DIR",
        help="Add one component per vendored package directly under DIR (e.g. "
        "messagefoundry/_vendor), read from each package's README.md. Fails if a package's "
        "README does not record everything the component needs.",
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
    vendored: list[dict[str, Any]] = []
    if args.vendored_from is not None:
        # externalReferences[].hashes, which carries the sdist digest, is a CycloneDX 1.5 field.
        if spec not in _LIFECYCLE_SPECS:
            fatal.append(f"--vendored-from needs CycloneDX 1.5 or later, and this BOM is {spec!r}")
        else:
            try:
                vendored = vendored_components(args.vendored_from)
            except VendoredRecordError as exc:
                fatal.append(f"cannot record the vendored packages: {exc}")
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

    # --- (3) label the platform the environment was resolved for ------------------------------------
    if args.record_sys_platform:
        props = metadata.get("properties")
        if props is not None and not isinstance(props, list):
            print(
                f"::warning::sbom_finalize: metadata.properties is a {type(props).__name__}, not a "
                "list; replacing it with the platform label alone",
                file=sys.stderr,
            )
        kept = [
            p
            for p in (props if isinstance(props, list) else [])
            if not (isinstance(p, dict) and p.get("name") == PLATFORM_PROPERTY)
        ]
        metadata["properties"] = [*kept, {"name": PLATFORM_PROPERTY, "value": sys.platform}]

    # --- (4) list the third-party code the package carries in its own tree --------------------------
    if args.vendored_from is not None:
        root_ref = component.get("bom-ref") if isinstance(component, dict) else None
        _add_vendored(doc, vendored, root_ref)

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
        + (f", sys_platform={sys.platform}" if args.record_sys_platform else "")
        + (
            ", vendored=" + ",".join(c["purl"] for c in vendored)
            if args.vendored_from is not None
            else ""
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
