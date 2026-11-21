- **The Windows service start now refuses a store key written below an empty secret in more
  shapes.** In the service's registry environment, an empty secret such as
  `MEFOR_STORE_ENCRYPTION_KEY=` followed by `x=<key>`, by `x=` set to a comma list of keys or to a
  quoted key, on the next line or in the next item, would have read as unset, so the start was not
  refused. So would a base64url secret with one `=`, or `=<key>`, in the next item; on the next
  line those two already refused. Each now reads as that secret's value, and the start is refused.
  A line with no 32-byte key text in it still ends the empty value, and so, at least, does a key
  list with an empty entry, such as one with a trailing or doubled comma, which the engine's own
  retired-keys reading accepts. (`BACKLOG #5394`)
