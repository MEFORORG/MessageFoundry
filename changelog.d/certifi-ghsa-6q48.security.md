- **The repository's locks pin certifi 2026.10.19, past
  [GHSA-6q48-6c7w-9gw2](https://github.com/advisories/GHSA-6q48-6c7w-9gw2).** The version locked
  before, 2026.7.22, trusted a root whose intermediates have compromised keys, and certifi
  2026.10.19 drops that root. A hop that trusts the certifi bundle, such as a Vault hop with no CA
  file set, would otherwise accept a forged certificate from an on-path attacker. Not covered by
  this change: the copy pip vendors, and the container image's own trust store.
