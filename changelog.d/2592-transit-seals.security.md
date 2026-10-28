- **Under `vault_transit`, identity and authorization rows now carry an integrity seal.** Before
  this, that provider wrote and checked no row seal, so a database writer with no key could insert
  an administrator session, a role or a channel scope. Sessions, user records, custom roles, the
  Active Directory maps and dual-control approval requests are now sealed with Transit's own HMAC
  and checked with Transit's verify call, at the key version the stored seal names, so no seal
  key enters the engine's memory. The seal is `mfseal:v1:<key id>:<Transit's vault:v<N>: string>`,
  where the key id is a digest of the Transit key's name. It runs under the audit key
  (`MEFOR_STORE_TRANSIT_AUDIT_KEY`, or the data key when that is unset), so the Vault policy now
  also needs `update` on `transit/verify/<audit key>`. Each Transit call runs off the event loop.
  A successful check is cached for one minute, and the cache is emptied when a refused check's key
  probe names a different latest version, and a check already waiting on Transit then keeps its answer out of the cache. A Transit call that does not complete refuses that request or write: the API answers 503
  with a `Retry-After`, the CLI prints one error line, and the engine logs an error and raises an
  `integrity_drift` alert under `authority-seal-transit`, each at most once per five minutes. It
  writes no `integrity.authority_seal_failed` row and ends no session, since an outage is not a
  forgery. A stored seal that is not a well-formed Transit MAC fails with no Vault call. A
  well-formed one Transit refuses to check while its key answers (a retired version, one the node
  does not hold yet, or a planted one) is treated as a failed seal: denied, its session ended, an
  `integrity.authority_seal_unverifiable` audit row, and an `integrity_drift` alert under
  `authority-seal-transit-unverifiable:<kind>:<id>`, at most once per five minutes for each row.
  No version number is compared, so a genuine seal checked against a Vault node that lags a
  rotation reads as unverifiable, and its user signs in again. An edit of a custom role in that state is refused with
  409, and so is the delete of any custom role while the AD group-to-role map is in that state,
  since the delete could not re-seal the map. A directory sign-in refused for an unverifiable map
  is audited as `auth.login_refused_unverifiable`, which the sign-in burst signal does not count. A
  reconcile pass that holds role or scope diffs on such a map raises one `ad_reconcile_aborted`
  alert (reason `directory_map_unverifiable`) when the hold begins, and each map always pages
  under its own subject, never the capped aggregate. `provision-admin` names the recovery, rather
  than calling the account unrepairable or printing a defect report, when Vault transit would not
  check the account it repairs. Before raising the audit key's `min_decryption_version`, read
  [PHI.md](../docs/PHI.md#raising-the-transit-audit-keys-minimum-version). `serve` seals and verifies
  fixed input at start, before it seeds the auth tables, and refuses to start when the token
  cannot.
  A row written on `vault_transit` before this change carries no seal, and is refused like any
  other unsealed row. Not yet built: the store id pin (vault BACKLOG #3411) and rollback
  detection. (vault BACKLOG #2592)
