- A listener reply whose characters the inbound charset cannot encode is now refused, not sent
  with `?` written in, when `?` is a delimiter its header declares in more of the shapes a reply
  takes: an X12 reply led by a fixed-width `ISA` (read at its delimiter offsets), and an HL7 reply
  led by `MSH`, `BHS` or `FHS`, where every segment that starts with one of those is read, so a
  batch member's own `MSH` counts. Segments end at CR when the reply holds one, and at LF only in a
  reply with no CR. Before, only the first line of an `MSH`-led reply was read. Not covered, so a
  `?` can still be written into these: an HL7 reply whose header lines end at LF but which holds a
  CR elsewhere, an X12 interchange after the first `ISA`, an `ISA` that is not fixed-width (one
  with unpadded elements declares nothing, as before), and an HL7 v2.7 truncation character
  declared as `?`. (`BACKLOG #5799`)
