- **`npm run package` in `ide/` runs vsce through `npx` at a pinned top-level version,
  `@vscode/vsce@4.1.0`.** vsce's dependencies are not locked. Neither vsce nor its dependencies are
  in the extension SBOM or read by npm audit or Dependabot, and the `overrides` in `ide/package.json`
  do not reach them. Read 2026-11-17 with `npm audit`, a fresh lock-only resolve of
  `@vscode/vsce@4.1.0` carries
  [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) (picomatch) and
  [GHSA-g3hv-75wg-m249](https://github.com/advisories/GHSA-g3hv-75wg-m249) (minimatch); the tree npx
  runs may come from its cache instead. The
  `@azure/msal-node` override, which only vsce's tree used, is removed.
