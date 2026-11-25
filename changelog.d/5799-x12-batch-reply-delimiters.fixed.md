- A listener reply whose characters the inbound charset cannot encode is now refused, not sent
  with `?` written in, when `?` is a delimiter its header declares in more of the shapes a reply
  takes: an X12 `ISA` (read at its fixed delimiter offsets, so a malformed ISA counts too), and in
  an HL7 reply led by `MSH`, `BHS` or `FHS`, every line that starts with one of those, at CR, LF
  or CRLF line ends, so a batch member's own `MSH` counts. Before, only the first line of an
  `MSH`-led reply was read, so a replaced character in such a reply would have read as structure.
  (`BACKLOG #5799`)
