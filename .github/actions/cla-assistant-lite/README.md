# cla-assistant-lite (vendored)

This directory vendors `contributor-assistant/github-action` at commit `ca4a40a7d1004f18d9960b404b97e5f30a505a08` (tag `v2.6.1`).

GitHub archived the upstream repository, and no maintained fork or successor exists. We vendor it instead, the same approach this project already takes for other unmaintained-but-needed third-party code (see `messagefoundry/anon/`, vendored to `tee/anon/`).

The action is Apache-2.0 licensed. The license text is in `LICENSE` in this directory.

We vendor only the compiled `dist/index.js`, not the TypeScript source. The source review happened once, against the upstream repository directly, and the compiled output is what actually runs.

Upstream source, for reference: https://github.com/contributor-assistant/github-action/tree/ca4a40a7d1004f18d9960b404b97e5f30a505a08

## Provenance (BACKLOG #1578)

`provenance.cdx.json` is the machine-readable record: a CycloneDX 1.6 document naming the upstream repository, the pinned commit, the bundle's SHA-256 as vendored, the date and reason it was vendored, and an inventory of the 403 distinct packages the upstream lockfile declares (161 of them outside the upstream dev toolchain). `upstream-package-lock.json` is that lockfile, copied verbatim from the pinned commit.

`scripts/security/build_cla_action_provenance.py` generates the record and verifies it; `tests/test_cla_action_provenance.py` is the gate, so the bundle cannot change without the record changing with it.

```
python scripts/security/build_cla_action_provenance.py --check    # verify
python scripts/security/build_cla_action_provenance.py --write    # regenerate
```

### What is proven

The vendored bundle is the upstream blob at the pinned commit with a 176-byte two-line header prepended, and nothing else changed. Strip the first two lines of `dist/index.js` and the SHA-256 of what remains is `a44111084c0d4782206c04b4276292f7fec6d1f7a33525512fbeef3242079dfb`, the upstream digest recorded in the CycloneDX document. That check needs no network and no Node.

### What is not proven, and nobody can prove it here

A clean audit of `upstream-package-lock.json` proves the **declared** dependencies of the pinned upstream commit are clean. It does **not** prove this bundle was built from them. Reproducing an ncc/webpack build needs a Node toolchain this repository does not carry, so no number in the record should be read as if somebody had checked that.

### Auditing the declared closure

```
osv-scanner --lockfile package-lock.json:.github/actions/cla-assistant-lite/upstream-package-lock.json
trivy sbom .github/actions/cla-assistant-lite/provenance.cdx.json
```

**The two commands do not cover the same set, so run the first one.** `osv-scanner` reads the lockfile and reports on all 403 packages. `trivy sbom` reads the CycloneDX record, where the 242 packages npm marked `dev` carry CycloneDX `scope: excluded` and are skipped. For a compiled ncc/webpack artifact the dev toolchain is exactly what produced the bundle, so the lockfile scan is the wider lane and the SBOM scan is the convenient one.

The lockfile is named `upstream-package-lock.json` rather than `package-lock.json` on purpose. GitHub's dependency graph ingests a file with the stock name anywhere in the repository, and the 2021-era tree it describes carries advisories nobody here can remediate: moving a pin means rebuilding the bundle, which needs the absent toolchain. So the record is **audit-only** — a tool an auditor points at it reads it, and a tool that scans for manifests does not. `.github/dependabot.yml` carries no npm entry for this directory for the same reason.

### Where the bundle runs

CI only. `.github/workflows/cla.yml` runs it on `pull_request_target`, and on an `issue_comment` whose body is exactly `recheck` or the sign-off sentence — a privileged context holding a repository token. The workflow is also triggered by `merge_group`, but the step's own `if:` skips the bundle there rather than running it, so the trigger list of the workflow is wider than the list of events the bundle actually executes on. `.github/` sits outside `[tool.hatch.build.targets.sdist].only-include`, so the bundle is not packaged into the wheel or sdist and no engine deployment carries it.
