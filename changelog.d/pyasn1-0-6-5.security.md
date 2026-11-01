- **The repository's locks pin pyasn1 0.6.5, past CVE-2026-119194, CVE-2026-119195, CVE-2026-119196
  and CVE-2026-119197.** In 0.6.4 and earlier, crafted BER, CER or DER input could cost quadratic CPU
  in `decode()`, through schema-less containers, constructed strings, indefinite-length `ANY` or binary
  `REAL`. A site using the optional `[webauthn]` extra has pyasn1's BER decoder on its passkey
  registration path, for Android Key attestation, so it would otherwise keep the old decoder there.
- **The `ide/` extension's build toolchain moves to glob 14.0.3 and minimatch 11.0.3, past
  [GHSA-3g3m-2fjr-6pw4](https://github.com/advisories/GHSA-3g3m-2fjr-6pw4) and
  [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249).** Both are development
  dependencies, so the packaged extension's file list is unchanged. The `overrides` entries in
  `ide/package.json` hold mocha and vsce to the fixed versions, because neither has released a version
  that requires them.
