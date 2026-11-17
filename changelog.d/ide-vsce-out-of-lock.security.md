- **The `ide/` extension's build toolchain no longer locks `@vscode/vsce`, so the locked tree no
  longer holds picomatch, which carries
  [GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf) with no fixed release.**
  vsce was the only path to it. It was used only by the manual `npm run package` script, which now
  fetches vsce with `npx` when it runs, so the packaging tool is outside the audited lock. The
  extension's own code and bundle are unchanged.
