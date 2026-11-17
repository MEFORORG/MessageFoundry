- **`trim_field` and `append_to_field` keep a component's escapes.** On a component or
  subcomponent path they read the decoded value and wrote it back, so a `\.br\` inside the value
  raised and a `\H\` was lost. `trim_field` now strips the decoded whitespace at the ends of the
  value and keeps the escapes it does not strip; on a whole field it now also strips an escape that
  decodes to whitespace at an end, such as a trailing `\.br\`, and it raises `ValueError` on field 1 or 2 of
  `MSH`, `BHS` or `FHS`. `append_to_field` writes the suffix as data after the component's last
  leaf. The actions' edits now decode with the separators a read uses, which in a batch are the
  `BHS` or `FHS` header's. (`BACKLOG #5928`)
