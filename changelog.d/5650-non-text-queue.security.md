- **A queue payload or listed cell that is not text is refused as such.** A planted BLOB in a
  queue row's `payload` now raises a queue tag error with cause `non-text`, so a claim
  dead-letters the row with its tag-failed audit row and alert, where before it was dead-lettered
  as a bare `TypeError` with neither. A planted BLOB in a cell a list read opens, such as a dead
  letter's `last_error`, fails the read with a cipher error rather than a `TypeError`, and a keyless
  store no longer hands the bytes back. (`BACKLOG #5650`)
