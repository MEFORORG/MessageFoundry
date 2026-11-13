- **A psqlODBC connection's libpq root certificate is now checked in every place the installed
  libpq could read it.** Off Windows, libpq 15 and later read `HOME` while libpq 14 and older read
  the password-file home, and the check read only the first, so it could clear one `root.crt`
  while libpq loaded another. When the two homes differ, both are now checked, and an encryption
  header or a private key in either refuses the build. `PGSSLROOTCERT=system`, which libpq older
  than 16 opens as a file named `system` in the working directory, now has that file checked. On
  Windows the folder is asked for through the ANSI shell call libpq makes, and a `ctypes` import
  or call failure refuses the build with a `ValueError` rather than escaping it.
