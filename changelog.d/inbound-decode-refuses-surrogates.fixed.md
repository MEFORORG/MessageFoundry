- **An inbound body that decodes to a UTF-16 surrogate code point is refused at decode.** At least
  `utf-7` decodes `+2D8-` to one with no error, and strict UTF-8 cannot encode it, so on at least
  the SQLite store the ingress write or a document detach failed on it and the body got no row.
  Both listeners and the dry run now refuse it as a `decode` error naming the position, with an
  `AR` where an HL7 reply is owed, and the `ERROR` row stores the bytes as received.
  (`BACKLOG #1619`)
