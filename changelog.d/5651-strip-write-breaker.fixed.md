- **The embedded-document strip now stops when its batch writes keep failing, and records it.** A
  write fault that hits every batch, such as a full disk or a read-only store, was met once per
  batch for the whole scan, each logged at WARNING. Two attempted batch writes failing in a row now
  end the strip call early; each failure is logged at ERROR, and the retention pass's audit row
  carries a new `documents_strip_write_failed` flag when the pass writes one. A failed write alone
  does not make the pass write that row, since the same fault would refuse it. A refused cell found
  before a store-wide cipher error in the same batch is still audited, and a failed batch read logs
  its traceback at DEBUG. (`BACKLOG #5651`)
