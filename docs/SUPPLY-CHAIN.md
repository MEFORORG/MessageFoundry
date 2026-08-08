# Software Supply-Chain Transparency

MessageFoundry publishes a verifiable software supply chain so a hospital security team can answer
"what's in it, who built it, and is CVE-X actually exploitable?" from signed artifacts — not a
questionnaire. This page is the operator-facing guide to what we publish and how to verify it. The
decision record is [ADR 0149](adr/0149-multi-ecosystem-sbom-vex-and-sbom-quality-gate.md).

> MessageFoundry is **open-source integration middleware, not an FDA-regulated medical device**. This
> program is driven by procurement and customer trust, not a device-SBOM mandate.

## What we publish, per release

| Artifact | What it is | Where |
|---|---|---|
| `messagefoundry-*.whl` / `*.tar.gz` | The Python engine (wheel + sdist) | GitHub release + PyPI |
| `messagefoundry-sbom.cdx.json` | **CycloneDX SBOM** of the engine — license-complete, from the hash-locked core runtime, lifecycle = `build` | GitHub release |
| `messagefoundry-vex.openvex.json` | **OpenVEX** — the document carrying our exploitability assessment for a CVE, once one has been made | GitHub release |
| `*.sigstore*` bundles | Sigstore signatures for the wheel, sdist, **SBOM, and VEX** | GitHub release |
| PEP 740 attestations | PyPI-side provenance (Trusted Publishing) | PyPI |
| SLSA build provenance | in-toto attestation binding each artifact (incl. SBOM + VEX) to the source commit | GitHub attestations / Sigstore bundle |

Additional CycloneDX SBOMs — the **VS Code extension** (npm) and the **container image** (Debian base +
system libs + installed Python) — are produced by the daily/​on-demand `security.yml` workflow and
retained as CI artifacts (`sbom-cyclonedx`, `sbom-container-image`). The container and extension are not
released through the PyPI pipeline, so their SBOMs live with CI rather than as release assets.

## Verifying what you downloaded

### The PyPI package (provenance)

PyPI exposes a public **Integrity API**. Fetch the PEP 740 provenance for a specific file:

```
GET https://pypi.org/integrity/messagefoundry/<version>/<filename>/provenance
```

The response bundles the attestations with the publisher identity that produced them. `pip` verifies
attestations automatically when installing from PyPI.

### GitHub release artifacts (Sigstore + SLSA)

One verifier covers our artifacts. Verify the SLSA build provenance of any released file:

```bash
gh attestation verify messagefoundry-<version>.tar.gz --repo MEFORORG/MessageFoundry
```

Or verify a Sigstore bundle directly (the SBOM and VEX are signed too):

```bash
python -m sigstore verify identity \
  --cert-identity-regexp 'https://github.com/.*/MessageFoundry/.github/workflows/release.yml@.*' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  messagefoundry-sbom.cdx.json
```

A single `cosign` (v2.4.0+) also verifies the bundle format used across npm provenance, GitHub Artifact
Attestations, and our releases, if you standardize on one tool across ecosystems.

## Using the SBOM + VEX

The SBOM (CycloneDX 1.6) is a machine-readable inventory carrying at least a name, version, PackageURL and
**license** for every component. It does **not** carry per-component file hashes — the generator we run does
not emit them (see [How the SBOMs are generated](#how-the-sboms-are-generated-for-auditors)) — so use it as an
inventory, not as an integrity check on the components it lists. "Hash-locked" elsewhere on this page refers
to the lock file the inventory is built from, not to a field inside the SBOM. Feed it to your own tooling:

```bash
# Scan the SBOM for known CVEs. --vex applies whatever assessments our VEX carries; --show-suppressed
# lists what was suppressed, so a run with nothing to apply is visibly a no-op:
trivy sbom messagefoundry-sbom.cdx.json --vex messagefoundry-vex.openvex.json --show-suppressed

# Or score the SBOM's completeness (0-10, NTIA minimum elements):
sbomqs score -b messagefoundry-sbom.cdx.json
```

**Do not demand a zero-CVE "clean scan."** Per CISA's *Minimum Requirements for VEX* and NTIA's
*Software Consumers Playbook*, the correct posture is to accept a valid VEX assessment. Our VEX is the
`messagefoundry-vex.openvex.json` release asset above. Where we have assessed a CVE, its statement records
whether the vulnerable code is reachable in MessageFoundry and carries an OpenVEX `justification`. Where we
have not, the document says nothing about that CVE and your scanner's finding stands unsuppressed — see
[`security/vex/README.md`](../security/vex/README.md) for the assessment process and when a statement is added.

## How the SBOMs are generated (for auditors)

- **Python engine** — `cyclonedx-py environment` over an install of the hash-locked
  `docker/locks/requirements-core.lock` (environment mode populates licenses from installed metadata),
  then `scripts/security/sbom_finalize.py` declares the lifecycle and backfills the dynamic version. The
  broader all-extras dependency set is continuously audited by **pip-audit**.
- **VS Code extension** — `@cyclonedx/cyclonedx-npm --package-lock-only` over the committed
  `ide/package-lock.json` (install-free, full tree). The extension bundles its payload with esbuild and
  has no runtime npm dependencies, so the SBOM inventories the build toolchain. Continuously audited by
  **npm-audit**.
- **Container image** — `trivy image --format cyclonedx` over the built image (OS + Python layers).
  Continuously vuln-scanned by **Trivy** (with our VEX applied).

Every generated SBOM declares `metadata.lifecycles = [{phase: build}]` (CISA "Build" SBOM Type). The
Python engine and npm extension SBOMs are additionally quality-scored by **sbomqs** on each run (the
container-image SBOM is retained unscored; run `sbomqs score -b` against it on demand). Our format choice
is **CycloneDX** (native VEX support); an SPDX rendering can be produced on request.

## Related

- [`SECURITY.md`](SECURITY.md) — authn/RBAC, PHI handling, reporting.
- [`security/vex/README.md`](../security/vex/README.md) — how VEX statements are maintained.
- [ADR 0149](adr/0149-multi-ecosystem-sbom-vex-and-sbom-quality-gate.md) — the decision + acceptance criteria.
