- **A queue row's payload is sealed under a tag that binds the row's routing fields.** The
  associated data of every `queue.payload` cell now covers the row's `id`, `message_id`, `stage`,
  `channel_id`, `destination_name`, `handler_name` and body kind, built by one helper,
  `queue_payload_aad`, on SQLite, Postgres and SQL Server. A NULL field and the text `None` give
  different tags. A store-once fan-out row now seals its `shared_body` key in its own `payload`
  instead of leaving it blank, and a claim opens that cell and refuses the row when the sealed key
  and `body_ref` differ. A row with a blank payload is never delivered on a keyed store. A row whose
  payload does not open under its own tag is dead-lettered, its message records `ERROR`, the lane
  moves on, and the engine writes an `integrity.queue_tag_failed` audit row and raises an
  `integrity_drift` alert under the subject `queue-tag`. A resend from such a row is refused and
  alerted the same way. The outbound body view refuses a live row whose tag fails, and leaves out a
  dead one the claim already reported. The on-open seal pass and `rotate-key` rebuild the same tag;
  `rotate-key` steps over a dead row whose tag fails, and names the count in a WARNING. On SQL
  Server a claim does not read `body_ref`, so a `body_ref` set outside the store delivers only that
  row's own body there. Queue cells written before this change carry the old tag and are
  dead-lettered when claimed, and so is a pending empty body written before the store had a key. A
  keyless store, and a store with `[store].aad_bind` off, bind no tag. (vault BACKLOG #2593)
