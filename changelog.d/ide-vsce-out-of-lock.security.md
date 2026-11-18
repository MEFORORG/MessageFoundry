- **The `ide/` extension's locked build tree no longer holds `@vscode/vsce`, and with it picomatch,
  which carries [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) with no
  fixed release.** The advisory still applies when the extension is packaged: `npm run package` now
  fetches vsce with `npx`, and that copy still pulls picomatch. It runs outside the lock,
  so the npm audit gate, Dependabot and the `overrides` in `ide/package.json` do not reach it. The
  extension's own code and bundle are unchanged.
