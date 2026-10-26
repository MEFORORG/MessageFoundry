- **The `host.ciphers` verify row on Linux now reads the OpenSSL file that `openssl` loads, and
  reads it the way OpenSSL does.** Without `OPENSSL_CONF`, it asks `openssl version -d` for the
  binary's `OPENSSLDIR` and reads `openssl.cnf` there, instead of always reading
  `/etc/ssl/openssl.cnf`. A missing file now reads FAIL, because OpenSSL then applies no policy.
  A name that starts with `.include`, such as `.include_x`, now reads as an include. Only a space,
  a tab or a carriage return counts as space, and a lone carriage return no longer ends a line. A
  backtick now quotes a value, as in OpenSSL. A line the row cannot read as OpenSSL does now reads
  MANUAL, because OpenSSL may apply none of such a file. So does a `$name` that no earlier line
  defines, and a backslash, a NUL or a non-ASCII character. Before, a missing file read MANUAL
  and a backtick-quoted floor read FAIL; each of the others could read PASS.
  See [DEPLOY-SERVER-DB.md](../docs/DEPLOY-SERVER-DB.md) section 5.4. (`BACKLOG #3803`)
