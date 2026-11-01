- **`organization_domains` and `external_link_allowlist` refuse all of `0.0.0.0/8`.** They already
  refused `0.0.0.0`, but `ipaddress` reads most of that block as neither unspecified nor reserved,
  so `0.1.2.3` loaded. The web console now also ignores an IPv4 entry that is not one host's address
  if one reaches it another way, and a host that is an IPv4 address takes only an exact match, so a
  URL to such an address shows the interstitial rather than skipping it. A loopback entry still
  loads, and a single label such as `com` still loads and covers every host under it;
  [`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md) now says both. (BACKLOG #3765)
- **The OIDC username check compares a non-ASCII UPN suffix as written.** It lower-cased both sides
  with `str.lower()`, which turns the Kelvin sign into an ASCII `k`, so a claim could pass as a
  suffix the allow-list names and the claim does not. It also removed non-ASCII white space from
  both. An ASCII suffix still matches without regard to case. A suffix with any non-ASCII character
  now matches only as written, on both sides, so this refuses some pairs it accepted before and
  accepts none it refused. (BACKLOG #3765)
