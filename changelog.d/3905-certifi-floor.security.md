- **`pyproject.toml` now requires `certifi>=2026.10.19`, so installing or upgrading MessageFoundry
  cannot leave the certifi release that
  [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2) affects in place.**
  certifi arrives through httpx and httpcore, and neither sets a floor that excludes the affected
  releases. Before this, `pip install -U messagefoundry` into an environment that already held an
  older certifi kept it, because the repository's locks bind only installs made from them. The
  floor applies to a release built from this change onward; the metadata of a release already
  published cannot be amended. (`BACKLOG #3905`)
