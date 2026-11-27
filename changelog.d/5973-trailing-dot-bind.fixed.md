- **A generated API pair reused across a bind move that adds or drops a trailing dot is
  re-minted.** The hostname check the tray's probe runs, Python's `ssl` under `httpx`, keeps the
  dot, so `https://localhost.:8765` refuses a
  certificate naming only `localhost`, and the reverse. The engine's startup bind check ignored
  the dot and served the old pair, so the tray would have shown a running engine as down. It now
  re-mints the pair, audited as `bind_changed`. (`BACKLOG #5973`)
