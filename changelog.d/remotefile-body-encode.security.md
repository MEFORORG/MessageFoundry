- **The RemoteFile destination refuses a payload it cannot encode without naming any of it.** Such a
  payload raised a bare `UnicodeEncodeError` on SFTP, FTP and FTPS uploads. Its text named a
  character of the message, and its `.object` held the whole payload. The delivery worker stored
  that text as an internal error, and `internal_error` decided the rest. The payload now goes
  through the shared `encode_wire_body`, as on Direct. The refusal is permanent, names the charset
  and a position, carries no exception chain, and comes before anything is sent.
- **Under `internal_error = stop`, an unencodable RemoteFile payload no longer stops the lane.**
  Before, `stop` kept the row queued, stopped the lane, and raised a `connection_stopped` alert.
  The refusal is now a bad message, not an internal error, so the row dead-letters on the first
  attempt under either policy, and no alert fires. One bad message no longer holds every message
  behind it, and the row stays replayable from the dead-letter queue. (vault `BACKLOG #3044`)
