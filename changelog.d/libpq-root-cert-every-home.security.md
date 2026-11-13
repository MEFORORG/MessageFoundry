- **A psqlODBC connection's default libpq root certificate is now checked in both homes libpq
  may read it from.** Off Windows the check read `root.crt` under `HOME` only, so it could clear
  one file while an older libpq loaded another from the password-file home. When the two homes
  differ, both are now checked, and an encryption header or a private key in either refuses the
  build. `docs/CONNECTIONS.md`, Generic ODBC, says which libpq reads which home. On Windows the
  folder is now asked for through the ANSI shell call libpq makes, and a `ctypes` import or call
  failure refuses the build with a `ValueError` rather than escaping it.
