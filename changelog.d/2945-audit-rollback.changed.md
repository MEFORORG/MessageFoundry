- **A config write whose audit row does not land is undone and refused.** When the engine writes a
  file the config digest covers, today only through the connection flag toggle, its audit row is
  now bounded at 10 seconds. A row that fails or runs past that bound first restores the bytes of
  the files the write declares it touches, and the toggle then answers 503, since the audit log and
  not the request is at fault. A row or write that is cancelled is undone the same way, and the
  cancellation is passed on. At least these still leave a write on disk with no row: a file another
  edit changed in the meantime, which is left as that edit wrote it; a file the undo could not
  read, write or lock; a file the write changed but did not declare; and a crash before the row.
  The 503's detail says when the write could not be fully undone, and the next start reports each
  of these as a config change. (`BACKLOG #2945`)
