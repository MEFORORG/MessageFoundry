- **The outbound delimiter override now writes a `BHS` or `FHS` header correctly.** It wrote the
  header's field separator as an extra field and changed only the escape character of its old
  encoding characters, so every batch or file header field moved one place. Field 2 of a
  `BHS` or `FHS` header now advertises the target encoding characters, as `MSH-2` does. (`BACKLOG
  #5802`)
