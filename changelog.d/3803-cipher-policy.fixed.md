- **The `host.ciphers` verify row on Linux now reads the OpenSSL file that `openssl` loads, and
  reads it the way OpenSSL does.** Without `OPENSSL_CONF`, it asks `openssl version -d` for the
  binary's `OPENSSLDIR` and reads `openssl.cnf` there. It still reads `/etc/ssl/openssl.cnf`
  too, and the worse of the two readings stands. A program named `openssl` earlier on the `PATH`
  can print any folder, so it cannot hide that file's FAIL. With no `/etc/ssl/openssl.cnf`, a
  binary's file under a `PATH` folder reads MANUAL. A missing file now reads FAIL, because OpenSSL
  then applies no policy. A name that starts with `.include`, such as `.include_x`, now reads as
  an include. Only a space, a tab or a carriage return counts as space. A backtick now quotes a
  value, as in OpenSSL. A line the row cannot read as OpenSSL does now reads MANUAL, because
  OpenSSL may apply none of such a file. So does a `$name` that no earlier line defines. So do a
  NUL, a lone carriage return and a line-end backslash, and outside a comment line, any backslash
  or non-ASCII character. Before, a missing file read MANUAL and a backtick-quoted floor read
  FAIL; each of the others could read PASS. See
  [DEPLOY-SERVER-DB.md](../docs/DEPLOY-SERVER-DB.md) section 5.4. (`BACKLOG #3803`)
