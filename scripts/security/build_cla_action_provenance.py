#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Generate and verify the provenance record for the vendored CLA action (BACKLOG #1578).

WHAT THIS EXISTS FOR. ``.github/actions/cla-assistant-lite/`` carries 1.18 MB of third-party
JavaScript that no dependency gate in this repository can see. ``uv``/``pip-audit`` audit Python,
``npm-audit`` audits ``ide/package-lock.json``, and the SBOM generators inventory the engine, the
extension and the container image. None of them reach a compiled bundle sitting in ``.github/``.
So the bundle's only recorded provenance was a checksum in a ledger entry that lives in a separate
repository, and nothing in this tree could be pointed at a tool.

WHAT IT DOES NOT DO, AND THIS IS THE LOAD-BEARING SENTENCE. A clean audit of
``upstream-package-lock.json`` proves the DECLARED dependencies of the pinned upstream commit are
clean. It does not prove this bundle was BUILT from them: reproducing an ncc/webpack build needs a
Node toolchain this repository does not carry, so nobody can check that here. The record says so in
its own text (:data:`LIMITATION`) and :mod:`tests.test_cla_action_provenance` fails if that sentence
goes missing, because a provenance record that quietly implies more than it proves is worse than
none -- it is a compensating control resting on a false premise.

WHAT IS ACTUALLY PROVEN, and it is more than the ledger checksum was. BOTH vendored upstream
artifacts are derived offline rather than asserted, so an auditor with no network recomputes them
from the files on disk:

    sha256 of (dist/index.js with its first two lines removed) == UPSTREAM_BUNDLE_SHA256
    git blob id of upstream-package-lock.json               == UPSTREAM_LOCK_BLOB_ID

The first is what :func:`split_vendoring_header` checks -- the vendored bundle is the upstream blob
at commit ``ca4a40a7`` with a 176-byte two-line header prepended, verified byte for byte. The second
is :func:`git_blob_id`, and ``git hash-object`` agrees with it. Both turn a recorded number into a
reproducible derivation, and :func:`verify_derivation` runs both.

THE OTHER TWO RECORDED FILES ARE PINNED RATHER THAN DERIVED (:data:`PINNED_DIGESTS`), because no
upstream id for them is recorded here. Weaker as provenance, identical as a refusal.

EVERY RECORDED FILE NEEDS AN ANCHOR, AND FINDING THAT OUT TOOK TWO ROUNDS. ``--write`` refuses only
what :func:`verify_derivation` reports, so a recorded file with no anchor is regenerated from the
tree -- the record is rewritten to describe the change instead of reporting it. Measured twice on a
copy, and the second time is the one to remember: round one closed the LOCKFILE (an injected package
came back exit 0, "wrote ...", a clean ``--check``, and the package in ``components``), and round two
found the identical hole still open on ``action.yml`` -- the file GitHub reads to decide which script
the privileged ``pull_request_target`` job runs. Closing one instance of a class is not closing the
class, and a repair round introduces its own asymmetries.

THE RECORD IS ALSO AN ALLOWLIST, so :func:`unrecorded_files` walks the directory. Four named keys
cannot see a file that was ADDED beside them, and a dropped ``dist/payload.js`` plus a repointed
``action.yml`` is a complete path from "add a file" to "the record signs off on it".

WHY THE LOCKFILE IS NOT NAMED ``package-lock.json``. GitHub's dependency graph ingests a file with
that name anywhere in the repository. The 2021-era tree it describes carries advisories nobody here
can remediate -- moving a pin means rebuilding the bundle, which needs the absent toolchain -- so
ingesting it would produce unactionable alerts, and repository-level Dependabot security updates
would open bump PRs against a lockfile with no build behind it. The record is deliberately
AUDIT-ONLY: readable by a tool an auditor points at it, invisible to one that scans for manifests.
``.github/dependabot.yml`` carries no npm entry for this directory for the same reason.

TWO DIGEST MODES, and mixing them up silently breaks the record on Windows:

* ``dist/index.js`` is digested over RAW bytes. Its blob genuinely holds 1,297 CRLF pairs and
  ``.gitattributes`` pins it ``-text`` so no checkout converts it. Normalizing would compute a
  number that describes no file that exists.
* Every other recorded file is digested over CRLF-normalized bytes, so the value does not depend on
  the platform the checkout was made on. Their blobs hold pure LF and ``.gitattributes`` pins them
  ``eol=lf``; normalizing additionally rescues an older checkout made before that pin landed.

Stdlib only (no install), like ``scripts/security/scan_forbidden.py`` -- runnable as a CI step, by
hand, and from pytest. The ``--check``/``--write`` generated-record shape, and the LF-normalized
digest, both follow ``scripts/security/build_password_corpus.py``; the two-line helpers are copied
rather than imported, because that script pulls in ``messagefoundry.auth`` and importing it would
drag the engine package into a script whose whole point is running without one::

    python scripts/security/build_cla_action_provenance.py --check   verify the record
    python scripts/security/build_cla_action_provenance.py --write   regenerate the record
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Literal

# This file is ``<repo>/scripts/security/build_cla_action_provenance.py``, so the root is two up.
REPO_ROOT = Path(__file__).resolve().parents[2]

#: The vendored action's directory, relative to the repository root.
ACTION_DIR = ".github/actions/cla-assistant-lite"

#: The generated record. CycloneDX because it is the format this project already publishes
#: (ADR 0149) and because `trivy sbom` / `osv-scanner` read it without a converter.
RECORD_PATH = f"{ACTION_DIR}/provenance.cdx.json"

#: The upstream repository the bundle was taken from.
UPSTREAM_REPO = "contributor-assistant/github-action"

#: The exact upstream commit. Every digest below is a fact ABOUT THIS COMMIT and nothing else.
UPSTREAM_COMMIT = "ca4a40a7d1004f18d9960b404b97e5f30a505a08"

#: The release tag that commit carries.
UPSTREAM_TAG = "v2.6.1"

#: SHA-256 of the upstream ``dist/index.js`` blob at :data:`UPSTREAM_COMMIT`, over its raw bytes.
#: Fetched from the GitHub contents API on 2026-09-18 and re-derived offline from the vendored copy
#: by stripping the vendoring header -- the two agreed, which is what makes this number checkable
#: without a network.
UPSTREAM_BUNDLE_SHA256 = "a44111084c0d4782206c04b4276292f7fec6d1f7a33525512fbeef3242079dfb"

#: Git blob id of the upstream ``package-lock.json`` at :data:`UPSTREAM_COMMIT`. Recorded beside the
#: SHA-256 because it is what the GitHub contents API reports, so a re-fetch is comparable without
#: downloading the file.
UPSTREAM_LOCK_BLOB_ID = "5700fc1014797e967a7a5395c1198643634cf204"

#: When the bundle was vendored -- the author date of ``4c884575435bc72a8ae21e0740772aecba999e68``,
#: the commit that added the bundle. NOT "the only commit that has ever touched
#: :data:`ACTION_DIR`", which an earlier draft of this comment said: the commit adding this record
#: touches that directory too, so the claim was false on arrival. A shallow engine checkout cannot
#: enumerate the directory's history anyway (``git rev-parse --is-shallow-repository`` reports
#: true), so nothing here could have checked it.
VENDORED_DATE = "2026-08-29"

#: When this record was built and its upstream digests re-verified against the archived repository.
RECORDED_DATE = "2026-09-18"

#: ``metadata.timestamp`` is pinned to :data:`RECORDED_DATE` rather than taken from the clock. A
#: generated file that embeds "now" is never a fixed point of its own generator, so ``--check``
#: could not be a gate.
RECORD_TIMESTAMP = f"{RECORDED_DATE}T00:00:00Z"

#: Why the bundle is vendored at all. Stated here so the record carries it and no reader has to
#: reconstruct the decision from a ledger they cannot open.
VENDORING_REASON = (
    "GitHub archived the upstream repository and no maintained fork or successor exists, so the "
    "action cannot be consumed as a pinned remote `uses:`. Vendoring freezes a reviewed commit "
    "instead of depending on an archived one that could be deleted or transferred."
)

#: THE HONESTY CONSTRAINT. Asserted verbatim by the test; do not soften it.
LIMITATION = (
    "A clean audit of upstream-package-lock.json proves the DECLARED dependencies of the pinned "
    "upstream commit are clean. It does NOT prove this bundle was built from them. Reproducing an "
    "ncc/webpack build needs a Node toolchain this repository does not carry, so nobody can check "
    "that here, and no number in this record should be read as if somebody had."
)

#: Where the bundle runs, stated because the answer bounds every severity claim about it. It is a
#: CI-only artifact: `.github/` is outside `[tool.hatch.build.targets.sdist].only-include`, so no
#: wheel, sdist or engine deployment carries it.
#:
#: NARROWER THAN THE WORKFLOW'S TRIGGERS, and an earlier draft of this sentence read the `on:` block
#: instead of the step and so named one event too many. `cla.yml` is triggered by merge_group, but
#: the `CLA Assistant` step's own `if:` skips it there -- that file's header records the paired
#: measurement (run 33796353619 on pull_request_target RAN the step; run 33797809984 on merge_group
#: SKIPPED it, both green). A record that overstates where a privileged bundle runs inflates every
#: severity claim read off it, which is the defect this property exists to bound.
EXPOSURE = (
    "CI only, and narrower than the workflow's triggers. The bundle executes in "
    ".github/workflows/cla.yml on pull_request_target, and on issue_comment when the comment body "
    "is exactly 'recheck' or the sign-off sentence -- a privileged context holding a repository "
    "token. The workflow is also triggered by merge_group, where the step's own `if:` skips the "
    "bundle rather than running it. It is not packaged into the wheel or sdist and no engine "
    "deployment carries it."
)

#: The vendored bundle, and the lockfile it is audited against. Named once because both the keys of
#: :data:`RECORDED_FILES` and several direct readers need them, and two spellings of one path drift.
BUNDLE_PATH = f"{ACTION_DIR}/dist/index.js"
LOCK_PATH = f"{ACTION_DIR}/upstream-package-lock.json"

#: How a file's bytes are turned into a digest. ``raw`` means exactly the bytes on disk; ``lf``
#: normalizes CRLF first. Which one a file takes follows its `.gitattributes` pin, not a preference
#: -- see the two-digest note in the module docstring.
DigestMode = Literal["raw", "lf"]

#: Files whose bytes are a supply-chain fact, mapped to their digest mode. README.md is deliberately
#: ABSENT: it is prose about the record, and digesting it would red this gate on an ordinary wording
#: edit, which is how a gate teaches people to regenerate without reading.
#:
#: ``action.yml`` and ``LICENSE`` take ``lf`` because nothing pins them -- `git check-attr text`
#: reports them unspecified, so `core.autocrlf=true` converts them on checkout and a raw digest of
#: either would name no file that exists on Windows.
ACTION_YML_PATH = f"{ACTION_DIR}/action.yml"
LICENSE_PATH = f"{ACTION_DIR}/LICENSE"

RECORDED_FILES: dict[str, DigestMode] = {
    BUNDLE_PATH: "raw",
    ACTION_YML_PATH: "lf",
    LICENSE_PATH: "lf",
    LOCK_PATH: "lf",
}

#: PINNED DIGESTS, and the reason they are constants rather than whatever `--write` finds on disk.
#: `--write` refuses only what :func:`verify_derivation` reports, so a recorded file with no anchor
#: is regenerated from the tree -- the record is rewritten to describe the change instead of
#: reporting it. Measured on a copy: repoint `action.yml`'s `runs.main` at `dist/evil.js`, and
#: `--check` reds while `--write` returns 0 and leaves `--check` clean over the tampered file.
#: ACTION.YML IS THE FILE GITHUB READS TO DECIDE WHICH SCRIPT THE PRIVILEGED `pull_request_target`
#: JOB RUNS, so that was the laundering path through the file that SELECTS the code.
#:
#: The bundle and the lockfile anchor to upstream identities (:data:`UPSTREAM_BUNDLE_SHA256`,
#: :data:`UPSTREAM_LOCK_BLOB_ID`). These two have no upstream id recorded here, so they anchor to
#: the reviewed bytes instead -- weaker as provenance, identical as a refusal. Changing either is
#: then a deliberate edit to this constant, which is the friction the bundle already has.
PINNED_DIGESTS: dict[str, str] = {
    ACTION_YML_PATH: "8acc29dc1f1559b9c5117eee0ffb24710233459ddff6e068fcdd3c04486e2a4f",
    LICENSE_PATH: "7503bb1b07845ec2f549da3c778f788f885f0f3be523dbcb41d7d070419ee88e",
}

#: Files that live in :data:`ACTION_DIR` and are deliberately NOT recorded. README.md is prose about
#: the record; the record cannot contain its own digest. Everything else in that directory is
#: unaccounted for -- see :func:`unrecorded_files`.
UNRECORDED_BY_DESIGN = frozenset({f"{ACTION_DIR}/README.md", RECORD_PATH})

#: The vendoring header prepended to the upstream bundle, byte for byte. The vendored file is this
#: followed by the upstream blob and nothing else, which :func:`split_vendoring_header` verifies.
VENDORING_HEADER = (
    b"// SPDX-License-Identifier: Apache-2.0\n"
    b"// Vendored from contributor-assistant/github-action@"
    b"ca4a40a7d1004f18d9960b404b97e5f30a505a08 (v2.6.1). See README.md in this directory.\n"
)


def unrecorded_files(root: Path) -> list[str]:
    """Files in :data:`ACTION_DIR` that no part of this record accounts for.

    THE RECORD IS AN ALLOWLIST, AND AN ALLOWLIST IS NOT AN INVENTORY. Without this, a file DROPPED
    into the vendored action -- ``dist/payload.js`` beside the audited bundle, say -- was invisible:
    measured on a copy, ``--check`` exited 0 and printed "describes the vendored tree" over a
    directory carrying unrecorded executable content. Chained with a repointed ``action.yml`` that
    is a complete path from "add a file" to "the record signs off on it", which is why this walks
    the directory instead of trusting the four keys it was handed.
    """
    action_dir = root / ACTION_DIR
    if not action_dir.is_dir():
        return [f"{ACTION_DIR} is not a directory in this tree"]
    accounted = set(RECORDED_FILES) | UNRECORDED_BY_DESIGN
    found = {path.relative_to(root).as_posix() for path in action_dir.rglob("*") if path.is_file()}
    return [
        f"{relative} is in {ACTION_DIR} but nothing in this record accounts for it. A file was "
        "added to the vendored action; record it or remove it -- do not regenerate over it."
        for relative in sorted(found - accounted)
    ]


def missing_recorded(root: Path) -> list[str]:
    """Recorded files absent from *root*, as human-readable problems.

    Checked BEFORE anything reads them. :func:`read_recorded` opens every path unguarded, so
    without this a deleted ``LICENSE`` -- the file that makes the Apache-2.0 vendoring lawful --
    came out of ``--check`` as a ``FileNotFoundError`` traceback rather than as the finding it is.
    A gate that crashes on the change it exists to name has told the reader nothing.
    """
    return [
        f"{relative} is recorded but is not in the tree. A file this record describes was removed, "
        "so the record no longer describes the vendored action; restore it or re-vendor."
        for relative in sorted(RECORDED_FILES)
        if not (root / relative).is_file()
    ]


def read_recorded(root: Path) -> dict[str, bytes]:
    """Read every file in :data:`RECORDED_FILES` once, raw, keyed by repository-relative path.

    One read per file per run. ``dist/index.js`` alone is 1.18 MB and three separate callers want
    it -- the digest, the header split and the upstream derivation -- so they share this instead of
    each opening the file. Deliberately NOT cached across calls: the negative-control tests mutate
    a tree between two checks, and a process-lifetime cache would make them pass while measuring a
    file that no longer exists.
    """
    return {relative: (root / relative).read_bytes() for relative in sorted(RECORDED_FILES)}


def digest(data: bytes, mode: DigestMode) -> str:
    """SHA-256 of *data* under *mode*. One definition, so every caller agrees.

    An unknown mode raises rather than falling through to a default: a typo would otherwise be a
    silently wrong digest, and the recorded value would look like any other.
    """
    if mode == "raw":
        return hashlib.sha256(data).hexdigest()
    if mode == "lf":
        return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()
    raise ValueError(f"unknown digest mode {mode!r}")


def git_blob_id(data: bytes) -> str:
    """Git's object id for *data* as a blob: SHA-1 over ``blob <length>\\0`` then the bytes.

    NOT A SECURITY CONTROL, and ``usedforsecurity=False`` says so to the reader and to bandit. It
    is git's content address, reimplemented in four lines so :data:`UPSTREAM_LOCK_BLOB_ID` can be
    REPRODUCED from the vendored lockfile instead of merely asserted -- the same move
    :func:`split_vendoring_header` makes for the bundle. ``git hash-object`` agrees with it, which
    is what lets an auditor confirm the number with a tool they already trust.
    """
    return hashlib.sha1(b"blob %d\0" % len(data) + data, usedforsecurity=False).hexdigest()


def digest_mode_summary() -> str:
    """The digest-mode rule as one sentence, DERIVED from :data:`RECORDED_FILES` rather than
    restated. A hand-written summary is a fifth copy of the rule that no gate compares."""
    raw = sorted(rel for rel, mode in RECORDED_FILES.items() if mode == "raw")
    lf = sorted(rel for rel, mode in RECORDED_FILES.items() if mode == "lf")
    return (
        f"raw bytes for {', '.join(raw) or 'nothing'}; "
        f"CRLF normalized to LF for {', '.join(lf) or 'nothing'}"
    )


def split_vendoring_header(bundle: bytes) -> bytes:
    """Return *bundle* with its vendoring header removed, which is the upstream blob.

    Raises :class:`ValueError` when the file does not start with :data:`VENDORING_HEADER`, because
    then the derivation this record rests on -- body digest equals the upstream blob digest -- is
    not the thing being measured any more.
    """
    if not bundle.startswith(VENDORING_HEADER):
        raise ValueError(
            "the vendored bundle does not start with the recorded vendoring header, so its "
            "upstream body cannot be derived; re-check the vendoring before regenerating"
        )
    return bundle[len(VENDORING_HEADER) :]


def _purl(name: str, version: str) -> str:
    """PackageURL for an npm package. A scoped name's leading ``@`` is percent-encoded, per the
    purl spec's npm type: ``@actions/core`` -> ``pkg:npm/%40actions/core``."""
    encoded = "%40" + name[1:] if name.startswith("@") else name
    return f"pkg:npm/{encoded}@{version}"


def lock_components(lock: dict[str, Any]) -> list[dict[str, Any]]:
    """Every distinct package the upstream lockfile declares, as CycloneDX components.

    Deduplicated by PackageURL: npm records one entry per INSTALL PATH, so the same name+version
    appears several times when it is hoisted differently at different depths, and an inventory
    listing it twice says nothing an auditor can use. ``scope`` carries npm's ``dev`` flag through
    as CycloneDX ``excluded``, which is what a scanner reads to separate the upstream BUILD
    toolchain from the closure that could have reached the bundle.

    NO PER-COMPONENT HASHES, deliberately. npm's ``integrity`` digests the REGISTRY TARBALL, not
    anything in this repository, so carrying it here would invite the exact reading
    docs/SUPPLY-CHAIN.md warns against -- an SBOM read as an integrity check on the artifact rather
    than as an inventory. The values stay available verbatim in the vendored lockfile beside this
    record, where what they cover is unambiguous.
    """
    packages = lock.get("packages", {})
    by_purl: dict[str, dict[str, Any]] = {}
    for path, entry in packages.items():
        if not path or not isinstance(entry, dict):
            continue  # the "" key is the upstream root project, described by metadata.component
        if "node_modules/" not in path:
            # A workspace or local link, not an installed package. Without this the rsplit below
            # returns the whole path and builds a purl like `pkg:npm/packages/cli@1.0.0`, whose
            # namespace resolves to nothing -- a scanner either drops it silently or reports an
            # unknown package. The current lockfile has no such entry, so this is a guard against a
            # future re-pin rather than a fix for today.
            continue
        name = path.rsplit("node_modules/", 1)[-1]
        version = entry.get("version")
        if not name or not isinstance(version, str):
            continue
        purl = _purl(name, version)
        dev = bool(entry.get("dev"))
        existing = by_purl.get(purl)
        if existing is not None:
            # A package hoisted at one depth and dev-only at another is required overall.
            if not dev:
                existing["scope"] = "required"
            continue
        component: dict[str, Any] = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
            "scope": "excluded" if dev else "required",
        }
        by_purl[purl] = component
    return [by_purl[purl] for purl in sorted(by_purl)]


def _properties(pairs: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, value in pairs]


def build_record(contents: dict[str, bytes]) -> dict[str, Any]:
    """Build the whole record from already-read file *contents*. Pure: no I/O, returns a document."""
    digests = {rel: digest(contents[rel], mode) for rel, mode in sorted(RECORDED_FILES.items())}

    lock = json.loads(contents[LOCK_PATH].replace(b"\r\n", b"\n").decode("utf-8"))
    components = lock_components(lock)
    runtime = sum(1 for c in components if c["scope"] == "required")

    # Deterministic and stable: the same upstream commit always yields the same serial number, and
    # a different one always yields a different one. A random UUID would make every regeneration a
    # diff, which would train a reviewer to skip reading it.
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/{UPSTREAM_REPO}/{UPSTREAM_COMMIT}")

    metadata_properties = [
        ("messagefoundry:provenance:limitation", LIMITATION),
        ("messagefoundry:provenance:exposure", EXPOSURE),
        ("messagefoundry:provenance:reason", VENDORING_REASON),
        ("messagefoundry:provenance:vendored-date", VENDORED_DATE),
        ("messagefoundry:provenance:recorded-date", RECORDED_DATE),
        (
            "messagefoundry:provenance:ledger-rows",
            "BACKLOG #1381 (vendoring), BACKLOG #1578 (this record)",
        ),
        ("messagefoundry:provenance:generator", "scripts/security/build_cla_action_provenance.py"),
        (
            "messagefoundry:provenance:audit-command",
            "osv-scanner --lockfile package-lock.json:.github/actions/cla-assistant-lite/"
            "upstream-package-lock.json",
        ),
        (
            "messagefoundry:provenance:dependency-graph",
            "The lockfile is named upstream-package-lock.json, not package-lock.json, so GitHub's "
            "dependency graph does not ingest it as this repository's own manifest. It describes "
            "an upstream tree nobody here can move: the record is audit-only by construction.",
        ),
    ]

    component_properties = [
        ("messagefoundry:vendored:path", BUNDLE_PATH),
        ("messagefoundry:upstream:commit", UPSTREAM_COMMIT),
        ("messagefoundry:upstream:tag", UPSTREAM_TAG),
        ("messagefoundry:upstream:bundle-sha256", UPSTREAM_BUNDLE_SHA256),
        (
            "messagefoundry:upstream:bundle-derivation",
            "The vendored file is the upstream blob with a "
            f"{len(VENDORING_HEADER)}-byte two-line header prepended and nothing else changed. "
            "Strip the first two lines and the SHA-256 of what remains is the upstream digest "
            "above -- reproducible offline, no network and no Node.",
        ),
        ("messagefoundry:upstream:lock-blob-id", UPSTREAM_LOCK_BLOB_ID),
        (
            "messagefoundry:upstream:lock-derivation",
            "The vendored lockfile is the upstream blob byte for byte. `git hash-object "
            "upstream-package-lock.json` reproduces the id above -- reproducible offline, and "
            "checked on every run, so the inventory below cannot be regenerated from a lockfile "
            "that is not the one at the pinned commit.",
        ),
        ("messagefoundry:upstream:lock-packages", str(len(components))),
        ("messagefoundry:upstream:lock-packages-runtime", str(runtime)),
        ("messagefoundry:recorded-files:digest-mode", digest_mode_summary()),
    ] + [
        (f"messagefoundry:recorded-files:sha256:{rel}", sha) for rel, sha in sorted(digests.items())
    ]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": RECORD_TIMESTAMP,
            # `post-build`, NOT `build`. A CycloneDX consumer reads the `build` phase as "this BOM
            # was emitted by the build that produced the component", which would contradict
            # LIMITATION in the same document: nobody here ran or can reproduce that build. This
            # record was assembled from a finished artifact after the fact, which is what
            # `post-build` means.
            "lifecycles": [{"phase": "post-build"}],
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "build_cla_action_provenance.py",
                        "group": "messagefoundry",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": f"pkg:github/{UPSTREAM_REPO}@{UPSTREAM_COMMIT}",
                "name": "cla-assistant-lite",
                "version": UPSTREAM_TAG,
                "description": (
                    "Vendored compiled bundle of the archived "
                    f"{UPSTREAM_REPO} GitHub Action, run by .github/workflows/cla.yml."
                ),
                "purl": f"pkg:github/{UPSTREAM_REPO}@{UPSTREAM_COMMIT}",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "hashes": [{"alg": "SHA-256", "content": digests[BUNDLE_PATH]}],
                "externalReferences": [
                    {
                        "type": "vcs",
                        "url": f"https://github.com/{UPSTREAM_REPO}/tree/{UPSTREAM_COMMIT}",
                    },
                    {
                        "type": "distribution",
                        "url": (
                            f"https://github.com/{UPSTREAM_REPO}/blob/{UPSTREAM_COMMIT}/"
                            "dist/index.js"
                        ),
                    },
                    {
                        "type": "license",
                        "url": f"https://github.com/{UPSTREAM_REPO}/blob/{UPSTREAM_COMMIT}/LICENSE",
                    },
                ],
                "properties": _properties(component_properties),
            },
            "properties": _properties(metadata_properties),
        },
        "components": components,
    }


def render(record: dict[str, Any]) -> str:
    """Serialize *record* deterministically: two-space indent, LF, one trailing newline."""
    return json.dumps(record, indent=2, ensure_ascii=False, sort_keys=False) + "\n"


def verify_derivation(contents: dict[str, bytes]) -> list[str]:
    """The checks that are facts rather than formatting. Returns human-readable problems.

    BOTH VENDORED UPSTREAM ARTIFACTS ARE DERIVED HERE, and covering only the bundle was a hole with
    a working exploit. ``--write`` refuses when this returns anything, so while the lockfile was
    merely digested-as-found rather than derived, a tampered ``upstream-package-lock.json`` reddened
    ``--check`` and then regenerated CLEAN: measured on a copy, an injected ``evil-pkg`` entry came
    back exit 0, "wrote ...", a clean ``--check``, and the package sitting in ``components``. That
    is precisely the laundering the refusal below exists to stop, through the artifact the README
    tells an auditor to scan.

    Every problem is accumulated rather than returned at the first one, so a run that changed both
    artifacts names both. Reporting one and hiding the other is how a second change rides in behind
    the first.
    """
    problems: list[str] = []

    try:
        body = split_vendoring_header(contents[BUNDLE_PATH])
    except ValueError as exc:
        problems.append(str(exc))
    else:
        body_sha = hashlib.sha256(body).hexdigest()
        if body_sha != UPSTREAM_BUNDLE_SHA256:
            problems.append(
                "the vendored bundle's body does not reproduce the recorded upstream digest: "
                f"got {body_sha}, recorded {UPSTREAM_BUNDLE_SHA256}. The bundle was changed, or it "
                "is no longer the upstream blob at " + UPSTREAM_COMMIT
            )

    # Over CRLF-normalized bytes, matching this file's `lf` digest mode: git hashes the BLOB, and a
    # checkout made before `.gitattributes` pinned this path could hold CRLF on disk.
    lock_blob = git_blob_id(contents[LOCK_PATH].replace(b"\r\n", b"\n"))
    if lock_blob != UPSTREAM_LOCK_BLOB_ID:
        problems.append(
            "the vendored lockfile is not the upstream blob it is recorded as: got git blob id "
            f"{lock_blob}, recorded {UPSTREAM_LOCK_BLOB_ID}. The inventory in this record is "
            "derived from that file, so it now describes a dependency closure that is not the one "
            "at " + UPSTREAM_COMMIT
        )

    for relative, pinned in sorted(PINNED_DIGESTS.items()):
        found = digest(contents[relative], RECORDED_FILES[relative])
        if found != pinned:
            problems.append(
                f"{relative} does not match its pinned digest: got {found}, pinned {pinned}. It is "
                "a recorded file of the vendored action, so regenerating would rewrite the record "
                "to describe the change instead of reporting it."
            )
    return problems


def check(root: Path) -> list[str]:
    """Every reason the record on disk fails to describe the tree at *root*. Empty means clean."""
    # Accumulated, not returned at the first one. An early return here would defeat at the outer
    # level exactly what verify_derivation accumulates for: a bad merge that removes LICENSE AND
    # edits the bundle would report the removal, then surface the bundle only after somebody fixed
    # the first thing -- one hidden failure per round trip.
    problems = unrecorded_files(root) + missing_recorded(root)
    if any(not (root / relative).is_file() for relative in RECORDED_FILES):
        # Nothing below can read the tree, so this is as far as the run goes.
        return problems
    contents = read_recorded(root)
    problems += verify_derivation(contents)
    record_path = root / RECORD_PATH
    if not record_path.exists():
        return problems + [f"{RECORD_PATH} does not exist; run --write"]
    if problems:
        # The derivation already failed, so the record either cannot be rendered at all (a missing
        # vendoring header raises) or would be compared against artifacts that are not the ones it
        # describes. Either way the fixed-point answer adds nothing to the problem already found,
        # and printing a second failure beside it would bury the one that names the cause.
        return problems
    # read_text applies universal-newline translation, so a CRLF checkout of the record compares
    # equal to the LF form render() produces without normalizing here.
    if record_path.read_text(encoding="utf-8") != render(build_record(contents)):
        problems.append(
            f"{RECORD_PATH} is not a fixed point of its generator -- it no longer describes the "
            "vendored tree. Read what changed before regenerating: "
            "python scripts/security/build_cla_action_provenance.py --write"
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify the record describes the tree")
    mode.add_argument("--write", action="store_true", help="regenerate the record")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root to read")
    args = parser.parse_args(argv)

    root: Path = args.root
    # NAME THE FILE ACTED ON, not the repository-relative constant. `--root /tmp/copy` printed
    # "wrote .github/actions/..." -- a path in the real checkout, while writing somewhere else. A
    # transcript then cannot say which tree was measured, which is SDS-3.8 inside the tool's own
    # output.
    record_path = root / RECORD_PATH
    if args.write:
        problems = unrecorded_files(root) + missing_recorded(root)
        contents = (
            {}
            if any(not (root / relative).is_file() for relative in RECORDED_FILES)
            else read_recorded(root)
        )
        problems += verify_derivation(contents) if contents else []
        if problems:
            for problem in problems:
                print(f"REFUSED: {problem}", file=sys.stderr)
            print(
                "Refusing to regenerate over a vendored action whose provenance does not check "
                "out. A regenerated record would launder the change into evidence.",
                file=sys.stderr,
            )
            return 2
        record_path.write_text(render(build_record(contents)), encoding="utf-8", newline="\n")
        print(f"wrote {record_path}")
        return 0

    problems = check(root)
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    if problems:
        return 1
    print(f"{record_path} describes the vendored tree")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
