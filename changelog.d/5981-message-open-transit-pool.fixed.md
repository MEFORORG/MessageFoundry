- **Opening one message under Vault Transit uses the bounded Transit pool.** `get_message` on every
  store backend opened a message's four cells through asyncio's default executor. Under
  `vault_transit` each open is a Vault round trip, so a slow Vault could fill that shared executor.
  The opens now run on the Transit call pool, as the store's other cell opens do. Under an
  in-process key they still run in a worker thread, off the event loop.
