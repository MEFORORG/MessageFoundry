- **A config write whose audit row does not land is put back.** When the engine writes a file the
  config digest covers, today only through the connection flag toggle, its audit row is now bounded
  at 10 seconds. A row that fails or runs past that bound first restores the bytes the write
  changed, so no write stays on disk without its row. A timed-out row is refused with a 409; any
  other failure is raised as before. A file another edit changed in the meantime is left as that
  edit wrote it, and logged, and the next start reports it. (`BACKLOG #2945`)
