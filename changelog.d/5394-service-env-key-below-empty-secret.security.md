- **The Windows service start now refuses a store key written below an empty secret in three more
  shapes.** In the service's registry environment, an empty secret such as
  `MEFOR_STORE_ENCRYPTION_KEY=` followed, on the next line or in the next item, by `x=<key>`, a
  base64url secret with one `=`, or `=<key>` would have read as unset, so the start was not refused.
  Each now reads as that secret's value, and the start is refused. A line whose value is a
  retired-keys list or a quoted key is read the same way. A line with no 32-byte secret in it still
  ends the empty value. (`BACKLOG #5394`)
