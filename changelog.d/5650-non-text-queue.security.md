- **A queue payload or listed cell that is not text is refused as such.** A planted BLOB in a
  queue row's `payload` now raises a queue tag error with cause `non-text`, so a claim
  dead-letters the row and writes its tag-failed audit row, and on a keyed store raises the
  `integrity_drift` alert; a keyless store has no alert hook. Before, a keyed store dead-lettered
  the row as a bare `TypeError` with neither, and a keyless store handed the bytes to delivery. A
  planted BLOB in a cell a list read opens, such as a dead letter's `last_error`, fails the read
  with a cipher error rather than a `TypeError`, and a keyless store no longer hands the bytes
  back from that read. (`BACKLOG #5650`)
