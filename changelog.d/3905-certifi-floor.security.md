- **`pyproject.toml` now requires `certifi>=2026.10.19`, past
  [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2).** certifi is
  transitive: httpx and httpcore pull it in on a base install, requests through extras, and none
  of them sets a floor that excludes the affected releases. Before this, upgrading into an
  environment that already held an affected certifi could keep it, because the repository's locks
  bind only installs made from them. The floor binds an install that resolves the dependencies of
  a release built from this change onward. It does not bind an install with `--no-deps`, or any
  release already published. Not covered, at least: the copy pip vendors, the container image's
  own trust store, and hops that verify against the operating system's trust store, which never
  read certifi. Not refreshed here: `security/risky-component-readings.json`,
  `security/bundled-code-survey.json` and `docs/RISKY-COMPONENTS.md` still describe certifi
  2026.7.22 and do not record this advisory. They are dated snapshots made by hand.
  (`BACKLOG #3905`)
