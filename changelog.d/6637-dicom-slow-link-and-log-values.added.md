- **The DICOM C-STORE SCP takes `min_message_bytes_per_second`, so a link of at least 16 KiB a
  second can deliver a large object.** At the unchanged default of 64 KiB a second, a link slower
  than that would have an object over a size set by the link cut at the same point on every
  attempt. On a link at or above 16 KiB a second, set the rate at or under the link's. The least
  it takes is 16 KiB a second, and no value turns the per-message deadline off, so a slower link
  also needs `timeout_seconds` raised. It is refused on an outbound connection. pynetdicom's and pydicom's logs are now
  default-deny: a line that matches no pinned template is withheld and names only its logger, level
  and exception class, so a C-FIND, C-GET or C-MOVE line or an unrecognised exception's text no
  longer reaches the log. The the C-STORE client also dead-letters an object it can never propose instead of
  retrying it. (`BACKLOG #6637`)
