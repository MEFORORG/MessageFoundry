- **`GET /search/layered` on a store opened with no key refuses a sealed preset as a cell it cannot
  open, not as malformed criteria.** A preset whose criteria a keyed store sealed, read by a store
  opened with no key configured, now answers 423 with the route's audit row and an ERROR record
  that names the store key setting to set. Before, the store handed the ciphertext
  back as the criteria and the route answered 400 "malformed criteria". (`BACKLOG #5523`)
