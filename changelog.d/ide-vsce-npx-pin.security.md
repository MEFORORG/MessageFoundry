- **`npm run package` in `ide/` runs vsce through `npx` at a pinned top-level version,
  `@vscode/vsce@4.1.0`.** Its dependencies are not locked, and the `overrides` in `ide/package.json`,
  npm audit, Dependabot and the extension SBOM do not reach them. Read 2026-11-17, that tree carries
  [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) (picomatch) and
  [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249) (minimatch). The
  `@azure/msal-node` override, which only vsce's tree used, is removed.
