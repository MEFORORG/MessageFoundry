- **certifi moves to 2026.10.19 in every lock, for GHSA-6q48-6c7w-9gw2.** certifi 2026.7.22, the
  version locked before, still trusted the emSign ECC Root CA - G3 root, and eight eMudhra
  intermediates that chain to it have compromised private keys. A client trusting that bundle would
  accept a certificate issued with one of those keys for any hostname. certifi 2026.10.19 drops the
  affected roots. Only certifi and its hashes change.
