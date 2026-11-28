- **`GET /search/layered` on a store opened with no key refuses a sealed preset as a cell it cannot
  open, not as malformed criteria.** A preset whose criteria are sealed, read by a store opened
  with no key configured, now answers 423 with an ERROR record that points at the store's key
  configuration. The route's refusal audit row is written only where the audit chain accepts it,
  for example on a store that was always keyless. On a store a key wrote and that is reopened with
  no key, the keyed audit chain refuses that row, so the only records are the ERROR lines for the
  refusal and for the audit write that failed. Each ERROR is rate-limited per preset and cause to
  about one an hour, held in memory by each engine process, so each process logs its own, and past
  the 4096 entries it remembers the limit is best effort. Before, the store handed the ciphertext
  back as the criteria and the route answered 400 "malformed criteria". (`BACKLOG #5523`)
