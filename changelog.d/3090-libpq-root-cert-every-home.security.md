- **A psqlODBC connection's default libpq root certificate is now checked in both homes libpq
  may read it from** (BACKLOG #3090). Off Windows, whenever `HOME` was set the check read
  `root.crt` under it alone, so it could clear one file while an older libpq loaded another from
  the password-file home. When the two homes differ, both are now checked, and an encryption
  header or a private key in either refuses the build. `docs/CONNECTIONS.md`, Generic ODBC, says
  which libpq reads which home. On Windows the folder is now asked for through the ANSI shell
  call libpq makes, and a `ctypes` import or call failure refuses the build with a `ValueError`
  rather than escaping it.

  A host would now refuse where it would have built before, in at least these cases:
  - off Windows, when the password-file home differs from `HOME` and its `root.crt` cannot be
    opened or read, is over 1 MiB, or meets a stat fault such as `EIO`, as any checked file is
    refused;
  - off Windows, when `pwd` cannot be imported, even with `HOME` set;
  - on Windows, when the roaming folder's name holds a character the ANSI code page maps by best
    fit to one no Windows name can hold, at least a fullwidth `*`, `<`, `|` or `"`: the check
    cannot read that path, so it refuses the build;
  - on Windows, when the ANSI folder's bytes do not decode in the code page.

  On Windows, a roaming folder whose name the ANSI code page holds only by best fit would now be
  checked at its best-fit path, the one libpq is given, not at its real name.

  One case would now build where it refused before: on Windows, when the roaming folder's name
  holds a character the ANSI code page cannot hold and the ANSI call writes a `?` for it, the
  engine reads no file there, since libpq opens no file at that path. Before, the engine read the
  folder's real name, and an encrypted or private-key `root.crt` there refused the build.
