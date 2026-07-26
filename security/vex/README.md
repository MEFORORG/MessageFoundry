# VEX — Vulnerability Exploitability eXchange

`messagefoundry.openvex.json` is MessageFoundry's maintained [OpenVEX](https://github.com/openvex/spec)
document — the **source of truth** for our per-CVE exploitability assessments. It is the companion to the
CycloneDX SBOMs (see [`docs/SUPPLY-CHAIN.md`](../../docs/SUPPLY-CHAIN.md) and
[ADR 0149](../../docs/adr/0149-multi-ecosystem-sbom-vex-and-sbom-quality-gate.md)).

## Why it exists

An SBOM says which components are **present**. A scanner then flags every CVE known against those
components — but "present" ≠ "exploitable". A CVE in a dependency may be unreachable in the way
MessageFoundry uses it, already fixed in our pinned version, or genuinely relevant. **VEX records that
judgement**, so a hospital security team triaging our releases can suppress the noise and focus on real
risk — instead of demanding a zero-CVE "clean scan" (per CISA's *Minimum Requirements for VEX* and NTIA's
*Software Consumers Playbook*).

This file starts with **no statements**: we add one only when a scanner surfaces a CVE that warrants an
assessment. An empty document is valid and harmless — it suppresses nothing.

## The four statuses (OpenVEX)

| `status` | Meaning |
|---|---|
| `not_affected` | The vulnerability is present in a component but **not exploitable** in MessageFoundry. Requires a `justification` (see below). |
| `affected` | Exploitable. Should carry an `action_statement` (what a user should do). |
| `fixed` | Remediated in the referenced product version. |
| `under_investigation` | We are still assessing. |

A `not_affected` statement **must** carry a machine-readable `justification`, one of:
`component_not_present`, `vulnerable_code_not_present`, `vulnerable_code_not_in_execute_path`,
`vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist`.

## Adding a statement

Edit `messagefoundry.openvex.json`: append to `statements`, **bump the top-level `version`** (integer),
and update the top-level `timestamp` (RFC 3339, UTC). Reference the product by its **PackageURL** so a
consumer's scanner can match it to the SBOM component. Example (illustrative — replace with a real,
assessed CVE):

```json
{
  "vulnerability": { "name": "CVE-YYYY-NNNNN" },
  "products": [
    { "@id": "pkg:pypi/messagefoundry", "identifiers": { "purl": "pkg:pypi/messagefoundry" } }
  ],
  "status": "not_affected",
  "justification": "vulnerable_code_not_in_execute_path",
  "impact_statement": "One sentence: WHY the vulnerable path is unreachable in MessageFoundry.",
  "timestamp": "YYYY-MM-DDThh:mm:ssZ"
}
```

Keep every assessment **honest and specific** — a VEX statement is a security assertion an operator will
trust. Do not assert `not_affected` without a concrete reason you can defend.

## How it is used

- **Our own CI gate** — the `trivy` job in [`.github/workflows/security.yml`](../../.github/workflows/security.yml)
  runs `trivy image --vex security/vex/messagefoundry.openvex.json --show-suppressed …`, so a `not_affected`
  assessment is suppressed in our scan too (and logged, so nothing is silently hidden). Trivy also consumes
  CycloneDX VEX and CSAF, if we ever switch encodings.
- **Shipped to operators** — [`.github/workflows/release.yml`](../../.github/workflows/release.yml) attaches
  this file to each GitHub release as `messagefoundry-vex.openvex.json`, Sigstore-signs it, and includes it
  in the SLSA build-provenance subjects. Operators feed it to their own Trivy/Grype/scanner to apply the
  same suppressions against the MessageFoundry SBOM.

## Validating a change

```bash
python -c "import json,sys; json.load(open('security/vex/messagefoundry.openvex.json')); print('valid JSON')"
```

For deeper validation, `vexctl` (the OpenVEX CLI) can lint and merge VEX documents.
