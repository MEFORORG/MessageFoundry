- **A message's cells are sealed under a tag that binds the message's channel, and a saved search's
  criteria under one that binds its owner.** The associated data of `messages.raw`, `error`,
  `summary` and `metadata` now covers the row's `id` and `channel_id`, built by one helper,
  `message_cell_aad`; `search_presets.criteria` covers its `id` and `owner_user_id`, built by
  `preset_criteria_aad`. Both hold on SQLite, Postgres and SQL Server. A message moved to another
  channel, or a preset moved to another owner, outside the store no longer opens. Opening one of
  them raises an `integrity_drift` alert, under the subject `messages-tag` or `search_presets-tag`,
  and writes an `integrity.message_tag_failed` or `integrity.preset_tag_failed` audit row, once per
  cell per hour in each process. A message read or a preset recall refuses; the by-id message
  routes answer 423 inside the caller's channel scope and the usual 404 outside it, and an export
  skips the row; the layered-search preset recall answers 423. A delivery whose `dynamic_headers`
  metadata read fails its tag is dead-lettered without sending, whatever the internal-error policy.
  Under `vault_transit` a failed open keeps the cipher's own error and raises no
  integrity alert, because that cipher cannot tell a moved cell from an unreachable Vault. The message list and the dead-letter list keep the row,
  by its plaintext columns, with its sealed cells withheld. Content search leaves it out, and the
  document strip skips it. A transform handoff that reads such a message's metadata dead-letters the
  routed row, so the message records `ERROR` and the lane moves on; on the SQL Server fused path the
  runner does the same. A captured-response re-ingress whose origin fails its tag is consumed and
  dead-lettered like a corrupt reference. The on-open seal pass, `rotate-key` and the restore-verify
  cell list rebuild the same tags; `rotate-key` steps over a cell that fails its tag under a key it
  holds and names the count in a WARNING. Cells written before this change carry the old tag and
  are refused on read, and so is the criteria of a saved search moved from a 0.3.2 table, whose
  owner the open rewrites. A keyless store, and a store with `[store].aad_bind` off, bind no tag.
  (vault BACKLOG #2593)
