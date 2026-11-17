- **`npm run package` in `ide/` now runs `@vscode/vsce@4.1.0` through `npx`, not whatever version is
  latest.** Only that top-level version is pinned: vsce's dependencies are not locked, and npm audit,
  Dependabot and the extension SBOM do not cover vsce or its dependencies. The unused
  `@azure/msal-node` override, which only vsce's tree needed, is removed.
