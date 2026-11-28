- **A generated API pair whose certificate names a bind host only without its trailing dot, or
  only with it, is re-minted for that bind.** The hostname check the tray's probe runs, Python's
  `ssl` under `httpx`, keeps the dot, so `https://localhost.:8765` refuses a certificate naming
  only `localhost`, and the reverse. The engine's startup bind check ignored the dot and served
  the old pair after a bind move that added or dropped one, so the tray would have shown a
  running engine as down. It now re-mints the pair, audited as a replacement (`bind_changed`, or
  `renewal` when the pair is also due for renewal). A bind spelled with the dot is not a loopback
  bind, so under the default `[security].enforcement` the exposed-bind gate refuses to serve the
  generated pair there. (`BACKLOG #5973`)
