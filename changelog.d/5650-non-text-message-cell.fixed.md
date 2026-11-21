- **A planted non-text value in a message cell is refused as integrity drift, not a 500.** A BLOB
  written into a `messages` cell outside the store reached the cipher: a keyed store raised a
  `TypeError`, so a list read answered 500 and a stage handoff re-pended the row on every pass, and
  a keyless store returned the bytes. The store now refuses it as drift on every key mode: a list
  withholds the row's tagged cells and a handoff dead-letters it, with the tag-failed audit row.
  (`BACKLOG #5650`)
