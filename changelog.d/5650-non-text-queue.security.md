- **A queue payload, or a cell a list read opens, that is not text is refused as such.** A
  planted BLOB in a queue row's `payload` now raises a queue tag error with cause `non-text`, so
  a claim dead-letters the row and writes its tag-failed audit row, and on a keyed store raises
  the `integrity_drift` alert; a keyless store has no alert hook. Before, a keyed store
  dead-lettered the row as a bare `TypeError` with neither, and a keyless store handed the bytes
  to delivery. A planted BLOB in a cell opened by the store's list-read helper, such as a dead
  letter's `last_error` on the dead-letter list, fails that read with a cipher error, on a keyed
  and a keyless store alike; before, a keyed store raised a bare `TypeError` and a keyless store
  handed the bytes back. Other reads of the same cells that decrypt directly are not changed: at
  least a store-once row's shared body, a message's delivery list and a by-id alert read still
  raise `TypeError` on a keyed store and hand the bytes back on a keyless one. (`BACKLOG #5650`)
