- **A failed batch write in the embedded-document strip is now logged at ERROR and recorded.** The
  strip still passes over a batch whose write failed and rolled back, and goes on to the rows after
  it, but each such failure is now logged at ERROR rather than WARNING, and the retention pass's
  audit row carries a new `documents_strip_write_failed` flag; a failed write alone makes the pass
  write that row. A refused cell found before a store-wide cipher error in the same batch is still
  audited, and a failed batch read logs its traceback at DEBUG. (`BACKLOG #5651`)
