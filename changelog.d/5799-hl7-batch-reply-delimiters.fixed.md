- A listener reply whose characters the inbound charset cannot encode is now refused, not sent
  with `?` written in, when `?` is a delimiter its header declares, or a declared delimiter is a
  character the charset cannot encode, in more of the shapes an HL7 reply takes: a reply led by
  `MSH`, `BHS` or `FHS`, where every segment that starts with one of those is read, so a batch
  member's own `MSH` counts. Until now only the text before the first CR of an `MSH`-led reply
  was read. HL7 segments end at CR when the reply holds one, and at LF only in a reply with no
  CR; in such a reply an `MSH` first line shorter than its MSH-1 and MSH-2 span is read past its
  LF, as the read before the first CR did. Not covered, so a `?` can still be written in: at least the shapes the
  docstring of `_reply_delimiters` in `messagefoundry/transports/framing.py` lists, an X12 reply
  led by `ISA` among them.
  (`BACKLOG #5799`)
