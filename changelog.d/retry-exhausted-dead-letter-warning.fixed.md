- **A row that runs out its retries now writes a WARNING when it dead-letters.** A transient
  refusal or a transport failure that reached a finite `max_attempts` was dead-lettered inside the
  store with no log line. That held on the single-row path and the batch path. The delivery worker
  now writes one WARNING after that dead-letter, the same content-free line a permanent refusal
  writes. It names the connection, the outbox row, the exception class and its code, and the
  attempt count. The single-row line also names the message id, and the batch line names the batch
  size and its head row. No line carries the message or the error's text. The worker reads the row
  back first, so a final write the HA epoch fence re-pended is not reported as a dead-letter. The
  line has its own throttle key per connection and code, so it never merges with a permanent
  refusal's count; both share the cap of 100 lines a minute. `max_attempts = None` still retries
  forever and never writes it. The dead-letter itself, its event and its counts are unchanged.
  (`BACKLOG #3108`)
