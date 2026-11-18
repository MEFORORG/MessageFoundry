- **An HTTP listener's `trusted_proxies` handling changes in four ways** (BACKLOG #5525). One
  failed request whose ambiguous bare IPv6 hop keys two per-peer budgets now spends one unit of
  the global budget, not two. One trust path widens: a listed inner proxy whose bare hop misreads,
  without its last group, to an address no host can hold is now skipped as its plain hop is,
  rather than taken for the client; a hop whose whole-address reading is that unholdable address
  is still the client. A refused entry is named by the form the parse refused, so a zoned network
  is no longer worded as a zoned address. `messagefoundry check` gains an advisory
  `listener-trusted-proxies` line naming every listener with a non-empty list, as
  `GET /security/posture` does.
