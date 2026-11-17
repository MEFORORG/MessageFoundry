- **`trim_field` and `append_to_field` keep a component's escapes.** On a component or
  subcomponent path they read the decoded value and wrote it back, so a `\.br\` inside the value
  raised and a `\H\` was lost. `trim_field` now strips the decoded whitespace at the ends of the
  value, drops an escape sequence only when it lies wholly inside that whitespace, and keeps every
  other escape as sent; on a whole field it now also strips an escape that decodes to whitespace at
  an end, such as a trailing `\.br\`. It raises `ValueError` on field 1 or 2 of `MSH`, `BHS` or
  `FHS`, and so does `append_to_field` on a component of one. `append_to_field` writes the suffix as
  data after the component's last leaf. The edits these actions make to a value's wire text now
  decode it with the encoding characters a `Message.field` read decodes with, which in a batch are
  the `BHS` or `FHS` header's rather than `MSH-2`'s. (`BACKLOG #5928`)
