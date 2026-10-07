- **A row that runs out its retries now writes a WARNING when it dead-letters.** A transient
  refusal or a transport failure that reached a finite `max_attempts` was dead-lettered inside the
  store with no log line. That held on the single-row path and the batch path. The delivery worker
  now writes one WARNING after that dead-letter, the same content-free line a permanent refusal
  writes. It names the connection, the outbox row, the exception class and its code, and the
  attempt count. The single-row line also names the message id, and the batch line names the batch
  size and its head row. No line carries the message or the error's text. The line shares the
  permanent-refusal throttle, under its own key per connection and code, so the two never merge.
  `max_attempts = None` still retries forever and never writes it. The dead-letter itself, its
  event and its counts are unchanged. (`BACKLOG #3108`)
