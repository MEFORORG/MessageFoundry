- A listener reply whose characters the inbound charset cannot encode is now refused, not sent
  with `?` written in, when `?` is a delimiter its header declares, or a declared delimiter is a
  character the charset cannot encode, in more of the shapes a reply takes: an X12 reply led by a
  fixed-width `ISA` (read at its delimiter offsets, ISA11 from 00501 only), and an HL7 reply led by
  `MSH`, `BHS` or `FHS`, where every segment that starts with one of those is read, so a batch
  member's own `MSH` counts. Segments end at CR when the reply holds one, and at LF only in a reply
  with no CR. Before, only the first line of an `MSH`-led reply was read. Not covered, so a `?` can
  still be written into at least these: an HL7 reply whose header lines end at LF but which holds a
  CR elsewhere, a member header after an LF-only blank line in a CR reply, an X12 interchange after
  the first `ISA`, and an HL7 v2.7 truncation character declared as `?`. An `ISA` that is not
  fixed-width declares nothing, as before, so it is refused neither where `?` is one of its
  delimiters nor where a delimiter is a character the charset cannot encode; at least these are
  not fixed-width: one with unpadded elements, one cut short, and one whose element separator also
  appears before ISA16 away from its separator offsets, such as in an ISA06 of `AC*MER`, in ISA11
  or in the `ISA` tag. (`BACKLOG #5799`)
