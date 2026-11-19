- **On a SQL Server cluster the renew clamp is checked against both of the lease claim's
  windows.** There the claim's wait for a pooled connection and its statement each get their own
  window, so a clamp inside the detection margin could still let a renew land past it. A
  `lease_renew_timeout_seconds` you set whose two windows reach the margin is now refused at load,
  where it used to load with a start-up warning; a derived one is stepped down to the largest
  whole number of seconds that fits; a fence/TTL pair that no clamp of at least 1 s fits is
  refused, which at the stock `[store].acquire_timeout` is at least every pair whose margin is 2 s
  or less. `[store].acquire_timeout` caps the claim's pool wait, so on a SQL Server cluster it now
  feeds this check. The SQL Server failover profiles get wider TTLs so that they load there
  (`harness/load/profiles/failover-sqlserver.toml`, TTL 8.0; the CI profile, TTL 6.0); the
  Postgres failover profiles keep their TTLs. See the `lease_renew_timeout_seconds` row of
  [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #5979`)
- **`[store].acquire_timeout` refuses `nan` and `inf` at config load.** It must now be a finite
  number above 0; neither value bounds the pool wait. (`BACKLOG #5979`)
