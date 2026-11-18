- **The embedded-document strip now stops when its batch writes keep failing, and records it.** A
  write fault that hits every batch, such as a full disk or a read-only store, was met once per
  batch for the whole scan, each logged at WARNING. Two failed batch writes in a row now end the
  strip call early; each failure is logged at ERROR, and the retention pass's audit row carries a
  new `documents_strip_write_failed` flag, which also makes a pass whose only event it was write
  that row. An unreachable key service is now judged an outage after the first three rows of a
  batch to reach it, rather than after every row of the batch. A refused cell found before a
  store-wide cipher error in the same batch is still audited, and a failed batch read logs its
  traceback at DEBUG. (`BACKLOG #5651`)
