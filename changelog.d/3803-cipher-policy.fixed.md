- **The `host.ciphers` verify row on Linux now reads the OpenSSL file that `openssl` loads, and
  reads it the way OpenSSL does.** Without `OPENSSL_CONF`, it asks `openssl version -d` for the
  binary's `OPENSSLDIR` and reads `openssl.cnf` there, instead of always reading
  `/etc/ssl/openssl.cnf`. A name that starts with `.include`, such as `.include_x`, now reads as
  an include, as OpenSSL reads it. Only a space, a tab or a carriage return counts as space, so a
  no-break space after a `MinProtocol` value no longer reads as a healthy floor. A line the row
  cannot read as OpenSSL does now reads MANUAL, because OpenSSL may apply none of such a file.
  Each of these could read PASS before. See [DEPLOY-SERVER-DB.md](../docs/DEPLOY-SERVER-DB.md)
  section 5.4. (`BACKLOG #3803`)
