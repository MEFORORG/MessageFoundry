- **The embedded-document strip ends a call after three batch writes in a row fail.** A write
  fault that hits every batch, such as a full disk or a read-only store, used to have the strip
  re-seal every candidate in the store on every pass, each seal counting toward the AES-GCM
  invocation ceiling, and log one ERROR per batch. The call now ends early instead, flagged
  `write_failed`, and the retention pass skips the rest of its strip phase. A write that lands in
  between resets the count, so failures on particular rows still do not stop the rows after them.
  The strip also releases each batch's bodies before it reads the next. (`BACKLOG #5651`)
