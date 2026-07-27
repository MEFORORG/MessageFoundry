# 0149 — Multi-ecosystem SBOM, VEX, and an SBOM quality gate

- **Status:** Accepted  <!-- build in progress; owner-approved "go" 2026-07-21 -->
- **Date:** 2026-07-21
- **Related:** ADR 0017 (container image) · ADR 0088 (apiclient) · [`docs/SUPPLY-CHAIN.md`](../SUPPLY-CHAIN.md) · `.github/workflows/release.yml` · `.github/workflows/security.yml` · deep-research report 2026-07-21

---

## Context

MessageFoundry already ships a strong software supply-chain baseline: a release-time CycloneDX SBOM,
Sigstore keyless signing, SLSA build provenance, PyPI PEP 740 attestations, and pip-audit / npm-audit /
bandit / gitleaks / semgrep / Trivy / OpenSSF-Scorecard gates in CI. A deep-research pass against the
current CISA/NTIA/OpenSSF guidance (verified claim set, 2026-07-21) surfaced four concrete gaps that a
healthcare integration vendor selling to hospital security teams should close. MessageFoundry is **not**
an FDA-regulated medical device (owner-confirmed), so this is **procurement/trust hardening driven by
customer expectations, not a regulatory mandate** — which is exactly where the project already leads.

The gaps, measured against the shipped baseline:

1. **Licenses absent + no lifecycle declared.** The SBOM was generated with `cyclonedx-py requirements
   requirements.lock`; the `requirements` parser has no package metadata, so component **licenses** were
   empty (a draft-2025 CISA minimum element), and no `metadata.lifecycles` (CISA "Build" SBOM Type /
   "Generation Context") was declared.
2. **Single-ecosystem coverage.** The SBOM covered only the all-extras Python lockfile. The **VS Code
   extension** (npm) and the **container image** (Debian base + system libs + installed Python) — both
   real distribution surfaces — had no SBOM, though pip-audit/npm-audit/Trivy already watch their trees.
   NTIA's *Software Consumers Playbook* expects a container-contents manifest and enumeration of runtime
   dependencies across ecosystems.
3. **No SBOM quality measurement.** Nothing scored the SBOM's completeness against the NTIA minimum
   elements, so a regression in SBOM quality would pass unnoticed.
4. **No VEX.** An SBOM lists what is *present*; it cannot say whether a flagged CVE is *exploitable* in
   context. Without a VEX companion, hospital operators running their own scanners must chase every CVE
   against our dependencies rather than the ones that actually matter.

This must not weaken any existing invariant. In particular it must not touch the **[reliability
invariant](../../CLAUDE.md)** (staged queue / at-least-once) or the **count-and-log invariant** — these
are build/release-pipeline and documentation changes only, with one new **stdlib-only, side-effect-free**
helper script. It must also respect the publishing rule that **security-posture docs stay private**
(the retired publish deny-list covered
`docs/security`); the SBOM/VEX and the operator guide are **transparency artifacts meant to be public**,
so they live outside the deny-listed paths.

## Decision

Close all four gaps with build/release-pipeline changes plus one committed helper and two data/doc
artifacts — **no engine code changes**:

1. **License-complete, lifecycle-declared Python SBOM.** Generate via `cyclonedx-py environment` from an
   install of the **hash-locked core runtime** (`docker/locks/requirements-core.lock`) — environment mode
   reads installed dist metadata, so licenses populate — then run a new
   [`scripts/security/sbom_finalize.py`](../../scripts/security/sbom_finalize.py) to inject
   `metadata.lifecycles=[{"phase":"build"}]` and backfill the hatchling-**dynamic** root-component version
   (which `--pyproject` leaves null). The core lock is the honest closure `pip install messagefoundry`
   pulls; the all-extras `requirements.lock` stays covered by pip-audit. **`--output-reproducible` is
   deliberately NOT used** — it strips the SBOM timestamp, itself a CISA/NTIA minimum element; artifact
   reproducibility is already provided by the SLSA/Sigstore attestation.
2. **Multi-ecosystem SBOMs.** Add a **container-image** CycloneDX SBOM (`trivy image --format cyclonedx`,
   in the existing `trivy` job that already builds the image — captures OS + Python layers) and a **VS
   Code extension** CycloneDX SBOM (`@cyclonedx/cyclonedx-npm@6.0.0 --package-lock-only`, install-free
   like the npm-audit job — the **full** tree, since the extension is esbuild-bundled with no runtime npm
   deps, so its build toolchain is the only npm supply chain worth inventorying). Both are finalized by the
   same helper and retained as CI artifacts.
3. **SBOM quality gate.** Score the Python engine and npm extension SBOMs with `sbomqs` (pinned `v2.0.11`,
   checksum-verified) — advisory (`sbomqs score -b` + NTIA breakdown), printed to the CI/release log, never
   blocking. (The container-image SBOM is generated + retained in the separate `trivy` job but not scored,
   to avoid a second pinned-tool install there; it can be scored on demand from the retained artifact.)
4. **VEX companion.** Maintain an **OpenVEX** source of truth at
   [`security/vex/messagefoundry.openvex.json`](../../security/vex/messagefoundry.openvex.json). Wire it
   into our own Trivy gate (`--vex … --show-suppressed`) so an assessed `not_affected`/`fixed` CVE is
   suppressed (and logged) here too, and **ship it** — the release attaches, Sigstore-signs, and
   SLSA-attests it alongside the SBOM, so operators feed the same file to their own scanners. It starts
   with **zero statements** (an honest, valid empty document — no fabricated assessments); a maintainer
   adds statements when a real CVE needs triage (process: `security/vex/README.md`).

The shipped release additionally **signs and attests the SBOM and VEX** themselves, not just the code
artifacts, so their provenance is verifiable too.

## Acceptance Criteria

- **AC-1** — WHEN `sbom_finalize` runs on a CycloneDX BOM with no `metadata.lifecycles`, THE SYSTEM SHALL
  inject `[{"phase":"build"}]` (overridable via `--phase`).
  → `tests/test_sbom_finalize.py::test_injects_build_lifecycle`
- **AC-2** — WHEN the primary component version is null AND `--set-version-from` is given, THE SYSTEM SHALL
  backfill it from that file's `__version__`.
  → `tests/test_sbom_finalize.py::test_backfills_dynamic_version`
- **AC-3** — IF the document's `bomFormat` is not `CycloneDX`, THEN THE SYSTEM SHALL exit non-zero so a
  release cannot ship a broken SBOM.
  → `tests/test_sbom_finalize.py::test_rejects_non_cyclonedx`
- **AC-4** — THE SYSTEM SHALL be idempotent: a second run over a finalized BOM changes nothing.
  → `tests/test_sbom_finalize.py::test_idempotent`
- **AC-5** — WHERE a shipped SBOM has a non-null primary-component version, THE SYSTEM SHALL NOT overwrite
  it (npm/container SBOMs keep their own version).
  → `tests/test_sbom_finalize.py::test_preserves_existing_version`
- **AC-6** — WHEN a release or the daily security workflow runs, THE SYSTEM SHALL emit license-complete
  CycloneDX SBOMs for the Python engine, the npm extension, and the container image, plus attach the
  OpenVEX companion to the release. → verified by the `release.yml` `workflow_dispatch` dry-run and the
  `security.yml` `sbom`/`trivy` jobs (CI-observed; no pytest).

## Options considered

1. **CycloneDX everywhere, per-ecosystem SBOMs, OpenVEX, sbomqs advisory — CHOSEN.** Reuses the format
   MessageFoundry already emits (native VEX story), the jobs that already build the artifacts, and the
   install-free lock/lockfile sources. Lowest blast radius, no engine code.
2. **Aggregate one SBOM across all ecosystems (e.g. Syft over the whole repo).** Rejected: conflates three
   distinct distribution artifacts with different PURLs/lifecycles; per-artifact SBOMs are what NTIA and
   consumers expect, and it would add a new heavyweight tool where `cyclonedx-py`/`cyclonedx-npm`/`trivy`
   already fit each ecosystem.
3. **Dual-emit SPDX alongside CycloneDX.** Deferred (not rejected): both are feature-equivalent and
   `sbomqs`/Syft can convert, but no consumer has asked for SPDX; revisit if SPDX-centric procurement
   appears. Recorded as an open item, not built here.
4. **Make sbomqs / Trivy-image / VEX BLOCKING.** Rejected for now: these are advisory first (matching the
   existing SBOM/Trivy posture) so a fast-moving external tool or vuln-DB day cannot wedge a PR. Promote to
   blocking deliberately once a baseline is established.

## Consequences

**Positive** — Licenses + lifecycle + primary-component version now populate the shipped SBOM; three
distribution surfaces (PyPI package, npm extension, container image) each get a CycloneDX SBOM; SBOM
quality is machine-scored every run; a signed, attested VEX travels with each release and is wired into
our own scanner, closing the SBOM→VEX→gate loop. Strengthens the answer to hospital procurement security
questionnaires — a differentiator vs. Mirth/Corepoint, which ship no SBOM.

**Negative / risks** — More release/CI surface to maintain (pinned tool versions: `cyclonedx-bom~=7.3`,
`@cyclonedx/cyclonedx-npm@6.0.0`, `sbomqs v2.0.11` — bump deliberately). The core-lock-derived SBOM
represents the default runtime, not every extra (mitigated: pip-audit audits the all-extras set; the doc
states the scope). The VEX is hand-maintained and must not drift into stale/false assessments (mitigated:
`security/vex/README.md` process + honesty requirement).

**Out of scope** — SPDX dual-emit (option 3); publishing/pushing the container image or the `.vsix` to a
registry/marketplace via CI (unchanged: operators build the image, the extension ships separately);
promoting any of these gates to blocking; automated VEX generation.

## To resolve on acceptance

- [x] Confirm MessageFoundry is not FDA-regulated (owner-confirmed 2026-07-21) — no medical-device SBOM
      field mandate applies.
- [ ] After the first daily `security.yml` run, capture the sbomqs baseline score and decide whether to
      promote scoring/Trivy-image to blocking (tracked separately, not in this ADR).
