- **A psqlODBC connection's default libpq root certificate is now checked in both homes libpq
  may read it from.** Off Windows, whenever `HOME` was set the check read `root.crt` under it
  alone, so it could clear one file while an older libpq loaded another from the password-file
  home. When the two homes
  differ, both are now checked, and an encryption header or a private key in either refuses the
  build. `docs/CONNECTIONS.md`, Generic ODBC, says which libpq reads which home. On Windows the
  folder is now asked for through the ANSI shell call libpq makes, and a `ctypes` import or call
  failure refuses the build with a `ValueError` rather than escaping it. One host now builds
  where it refused before: on Windows, when the roaming folder's name holds a character the ANSI
  code page cannot hold and the ANSI call writes a `?` for it, the engine reads no file there,
  since libpq opens no file at that path. Before, the engine read the folder's real name, and an
  encrypted or private-key `root.crt` there refused the build.
