- A listener reply whose characters the inbound charset cannot encode is now refused, not sent
  with `?` written in, when `?` is a delimiter its header declares, or a declared delimiter is a
  character the charset cannot encode, in more of the shapes an HL7 reply takes: a reply led by
  `MSH`, `BHS` or `FHS`, where every segment that starts with one of those is read, so a batch
  member's own `MSH` counts. HL7 segments end at CR when the reply holds one, and at LF only in a
  reply with no CR. Before, only the first line of an `MSH`-led reply was read. Not covered, so a
  `?` can still be written into at least these: an X12 reply led by `ISA`, whose delimiters the
  reply check still does not read (that half of the work is withdrawn and still open), an HL7
  reply whose header lines end at LF but which holds a CR elsewhere, a member header after an
  LF-only blank line in a CR reply, and an HL7 v2.7 truncation character declared as `?`.
  (`BACKLOG #5799`)
