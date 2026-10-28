- **Under `vault_transit`, identity and authorization rows now carry an integrity seal.** Before
  this, that provider wrote and checked no row seal, so a database writer with no key could insert
  an administrator session, a role or a channel scope. Sessions, user records, custom roles, the
  Active Directory maps and dual-control approval requests are now sealed with Transit's own HMAC
  and checked with Transit's verify call, at the key version the stored seal names, so no seal
  key enters the engine's memory. The seal is `mfseal:v1:<key id>:<Transit's vault:v<N>: string>`,
  where the key id is a digest of the Transit key's name. It runs under the audit key
  (`MEFOR_STORE_TRANSIT_AUDIT_KEY`, or the data key when that is unset), so the Vault policy now
  also needs `update` on `transit/verify/<audit key>`. Each Transit call runs off the event loop.
  A successful check is cached for one minute, and the cache is emptied when the engine sees a
  newer key version, and a check already waiting on Transit then keeps its answer out of the
  cache. A Transit call that does not complete refuses that request or write: the API answers 503
  with a `Retry-After`, the CLI prints one error line, and the engine logs an error and raises an
  `integrity_drift` alert under `authority-seal-transit`, each at most once per five minutes. It
  writes no `integrity.authority_seal_failed` row and ends no session, since an outage is not a
  forgery. A seal naming a key version newer than the Vault node holds counts as that outage, and
  one naming a version below the key's `min_decryption_version` is refused the same way, with a
  503 and no `Retry-After`. So seal rows again before raising that minimum; no engine command does
  that yet. `serve` seals and verifies fixed input at start, and refuses to start when the token
  cannot.
  A row written on `vault_transit` before this change carries no seal, and is refused like any
  other unsealed row. Not yet built: the store id pin (vault BACKLOG #3411) and rollback
  detection. (vault BACKLOG #2592)
