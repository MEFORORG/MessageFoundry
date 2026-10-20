- **The repository's locks pin certifi 2026.10.19, past
  [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2).** The version locked
  before, 2026.7.22, trusted a root whose intermediates have compromised keys, and certifi
  2026.10.19 drops that root. A hop that trusts the certifi bundle, such as a Vault hop with no CA
  file set, would otherwise accept a forged certificate from an on-path attacker. `pyproject.toml`
  now also requires `certifi>=2026.10.19`. certifi arrives through at least httpx, httpcore and
  requests, and none of them sets a floor that excludes the affected releases, so before this an
  upgrade into an environment that already held an affected certifi could keep it. The floor
  binds a release built from this change onward and an install that resolves dependencies; an
  install with `--no-deps` skips it, and a release already published cannot be amended. Not
  covered by this change, at least: the copy pip vendors, the container image's own trust store,
  and hops that verify against the operating system's trust store, which never read certifi.
  (`BACKLOG #3905`)
