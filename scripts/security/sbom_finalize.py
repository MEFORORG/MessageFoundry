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
     --vendored-from DIR adds one ``library`` component per package under DIR, with the name,
     version, SPDX licence and PyPI purl a scanner matches an advisory on. Upstream's sdist, its
     SHA-256 and each upstream file's SHA-256 go in the component's ``pedigree.ancestors``, not on the
     component: the copy adds a header to each module, so those digests describe upstream's bytes and
     not the shipped ones. Every value is read from the package's own ``README.md``, the record
     ``tests/test_vendored_defusedxml.py`` checks against the files. A README that does not yield all
     of them, or anything under DIR that is not a package directory, FAILS the run: a vendored copy
     missing from the SBOM is the defect this exists to stop, so it must not be one edit from silent.

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
# Compared as numbers within major version 1 (see _spec_1x_at_least), so 1.8 qualifies and 2.0 does not.
_LIFECYCLE_MINOR = 5
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

# The rows of a vendored package's README.md this reads. tests/test_vendored_defusedxml.py imports
# _FILE_ROW to check the files against the same table, so the two cannot read it differently.
_README_FIELDS = {
    "upstream": re.compile(r"^\| Upstream version \| `([^`]+)` (\S+) \|$", re.M),
    "source": re.compile(r"^\| Source \| (https://\S+) \|$", re.M),
    "sdist_sha256": re.compile(r"^\| sdist SHA-256 \| `([0-9a-f]{64})` \|$", re.M),
    "project": re.compile(r"^\| Project \| (https://\S+) \|$", re.M),
    "licence": re.compile(r"^\| Licence \|.*\bSPDX `([^`]+)`.*\|$", re.M),
}
_FILE_ROW = re.compile(r"^\| `([^`]+)` \| [^|]+ \| `([0-9a-f]{64})` \|$", re.M)
# What may sit directly under the vendor directory beside the package directories. Anything else, such
# as a single vendored module, fails the run rather than being left out of the SBOM.
_VENDOR_DIR_EXTRAS = frozenset({"__init__.py", "__pycache__", "README.md"})
# A single SPDX licence id. Anything else (`MIT OR Apache-2.0`, `LicenseRef-x`) goes in CycloneDX's
# `expression` field: license.id must be one id from the SPDX list. This does not check the list.
_SPDX_ID = re.compile(r"(?!LicenseRef-|DocumentRef-)[A-Za-z0-9][A-Za-z0-9.+-]*")


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
    hits = {key: [m.groups() for m in p.finditer(text)] for key, p in _README_FIELDS.items()}
    missing = [key for key, rows in hits.items() if not rows]
    files = _FILE_ROW.findall(text)
    if not files:
        missing.append("per-file upstream SHA-256 rows")
    if missing:
        raise VendoredRecordError(f"{readme} does not record: {', '.join(missing)}")
    # A second row is a stale one left beside its replacement, and the first match is not
    # necessarily the true one, so refuse rather than guess.
    names = [file_name for file_name, _ in files]
    repeated = [key for key, rows in hits.items() if len(rows) > 1]
    repeated += sorted({n for n in names if names.count(n) > 1})
    if repeated:
        raise VendoredRecordError(f"{readme} records {', '.join(repeated)} more than once")
    found = {key: rows[0] for key, rows in hits.items()}
    name, version = found["upstream"]
    (licence,) = found["licence"]
    module = _module_path(package)
    # PEP 503 normalisation, which the purl spec's pypi type requires.
    purl = f"pkg:pypi/{re.sub(r'[-_.]+', '-', name).lower()}@{version}"
    upstream = {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "externalReferences": [
            {
                "type": "distribution",
                "url": found["source"][0],
                "hashes": [{"alg": "SHA-256", "content": found["sdist_sha256"][0]}],
            }
        ],
        "components": [
            {"type": "file", "name": n, "hashes": [{"alg": "SHA-256", "content": digest}]}
            for n, digest in files
        ],
    }
    return {
        "type": "library",
        "bom-ref": f"{VENDORED_REF_PREFIX}{name}@{version}",
        "name": name,
        "version": version,
        "purl": purl,
        "description": (
            f"Vendored: a copy of {name} {version} inside the messagefoundry package as {module}, "
            "not installed as a separate distribution."
        ),
        "licenses": [
            {"license": {"id": licence}} if _SPDX_ID.fullmatch(licence) else {"expression": licence}
        ],
        "externalReferences": [{"type": "vcs", "url": found["project"][0]}],
        "properties": [{"name": VENDORED_PROPERTY, "value": module}],
        "pedigree": {
            "ancestors": [upstream],
            "notes": f"Upstream's files with the changes {package.name}/README.md records.",
        },
    }


def vendored_components(vendor_dir: Path) -> list[dict[str, Any]]:
    """One component per package (a directory holding ``__init__.py``) directly under ``vendor_dir``.

    Raises VendoredRecordError when there is no package at all, when anything else sits there, or when
    any README falls short.
    """
    if not vendor_dir.is_dir():
        raise VendoredRecordError(f"{vendor_dir} is not a directory")
    entries = sorted(p for p in vendor_dir.iterdir() if p.name not in _VENDOR_DIR_EXTRAS)
    if stray := [p.name for p in entries if not (p / "__init__.py").is_file()]:
        raise VendoredRecordError(
            f"{vendor_dir} holds {', '.join(stray)}, which is not a package directory with "
            "__init__.py, so it would be left out of the SBOM"
        )
    if not entries:
        raise VendoredRecordError(
            f"no vendored package (a directory with __init__.py) in {vendor_dir}"
        )
    components = [_vendored_component(p) for p in entries]
    refs = [c["bom-ref"] for c in components]
    if repeated := sorted({r for r in refs if refs.count(r) > 1}):
        raise VendoredRecordError(f"two vendored packages record the same release: {repeated}")
    return components


def _add_vendored(doc: dict[str, Any], vendored: list[dict[str, Any]], root_ref: object) -> None:
    """Replace any earlier vendored components and edges with ``vendored``, hung off the root."""

    def ours(ref: object) -> bool:
        return isinstance(ref, str) and ref.startswith(VENDORED_REF_PREFIX)

    def kept(key: str, ref_field: str) -> list[Any]:
        items = doc.get(key)
        return [
            item
            for item in (items if isinstance(items, list) else [])
            if not (isinstance(item, dict) and ours(item.get(ref_field)))
        ]

    refs = [c["bom-ref"] for c in vendored]
    doc["components"] = [*kept("components", "bom-ref"), *vendored]
    deps = kept("dependencies", "ref")
    # Strip a prior run's edges from every node, so a re-run on a BOM whose root lost its bom-ref
    # leaves no edge pointing at a component it just replaced.
    for dep in deps:
        if isinstance(dep, dict) and isinstance(dep.get("dependsOn"), list):
            dep["dependsOn"] = [r for r in dep["dependsOn"] if not ours(r)]
    if isinstance(root_ref, str):
        root = next((d for d in deps if isinstance(d, dict) and d.get("ref") == root_ref), None)
        if root is None:
            root = {"ref": root_ref}
            deps.append(root)
        prior = root.get("dependsOn")
        root["dependsOn"] = [*(prior if isinstance(prior, list) else []), *refs]
        deps += [{"ref": r} for r in refs]
    if deps or "dependencies" in doc:
        doc["dependencies"] = deps


def _spec_1x_at_least(spec: str, minor: int) -> bool:
    """Whether specVersion is ``1.<n>`` with ``n >= minor``, compared as numbers. A 2.x spec does not
    qualify: a new major version may move the fields this writes."""
    m = re.fullmatch(r"1\.(\d+)", spec)
    return m is not None and int(m[1]) >= minor


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
        "README does not record everything the component needs, or if anything else under DIR "
        "is not a package directory.",
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
        # Every field it writes is in the CycloneDX 1.4 schema: properties arrived in 1.3.
        if not _spec_1x_at_least(spec, 4):
            fatal.append(f"--vendored-from needs CycloneDX 1.4 to 1.x, and this BOM is {spec!r}")
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
    if _spec_1x_at_least(spec, _LIFECYCLE_MINOR):
        if not metadata.get("lifecycles"):
            metadata["lifecycles"] = [{"phase": args.phase}]
    else:
        print(
            f"::warning::sbom_finalize: specVersion {spec} is not 1.5 to 1.x, where "
            "metadata.lifecycles is defined; "
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
    if vendored:
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
        + (", vendored=" + ",".join(c["purl"] for c in vendored) if vendored else "")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
