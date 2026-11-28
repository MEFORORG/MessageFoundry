- **`GET /search/layered` on a store opened with no key refuses a sealed preset as a cell it cannot
  open, not as malformed criteria.** A preset whose criteria a keyed store sealed, read by a store
  opened with no key configured, now answers 423 with the route's audit row, best effort, and an
  ERROR record that points at the store's key configuration. The ERROR is rate-limited per preset
  and cause to about one an hour, held in memory by each engine process, so each process logs its
  own, and past the 4096 entries it remembers the limit is best effort. Before, the store handed
  the ciphertext back as the criteria and the route answered 400 "malformed criteria".
  (`BACKLOG #5523`)
