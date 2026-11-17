- **`trim_field` and `append_to_field` keep a component's escapes.** On a component or
  subcomponent path they read the decoded value and wrote it back, so a `\.br\` inside the value
  raised and a `\H\` was lost. `trim_field` now strips the decoded whitespace at the ends of the
  value, drops an escape sequence only when it lies wholly inside that whitespace, and keeps every
  other escape as sent; on a whole field it now also strips an escape that decodes to whitespace at
  an end, such as a trailing `\.br\`. It raises `ValueError` on field 1 or 2 of `MSH`, `BHS` or
  `FHS`, and so does `append_to_field` on a component of one. `append_to_field` writes the suffix as
  data after the component's last leaf. The actions' edits now split and decode a value as a
  `Message.field` read of it does, also in a batch whose header's encoding characters differ from
  `MSH-2`. (`BACKLOG #5928`)
