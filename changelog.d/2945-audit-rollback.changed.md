- **A config write whose audit row does not land is undone and refused.** When the engine writes a
  file the config digest covers, today only through the connection flag toggle, its audit row is
  now bounded at 10 seconds. A row that fails or runs past that bound first restores the bytes of
  the files the write declares it touches, so no write stays on disk without its row. The toggle
  then answers 503, since the audit log and not the request is at fault. A file another edit
  changed in the meantime is left as that edit wrote it, the 503's detail says the write could not
  be fully undone, and the next start reports it. (`BACKLOG #2945`)
