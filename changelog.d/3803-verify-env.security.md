- **The `host.ciphers` verify row no longer SKIPs on a store it cannot see, and its probes get a
  narrower environment.** `MEFOR_STORE_BACKEND` overrides the service config file, and the shell
  that runs `verify` need not carry the service's own environment. So when that shell does not
  set it, the row no longer reads "no ODBC hop" from a file that says `sqlite`: a FAIL or ERROR
  policy reading is now reported as MANUAL, with the reason in its detail. Set
  `MEFOR_STORE_BACKEND` as the service sets it to get a reading that counts. On Windows, the
  PowerShell the row starts now gets a `PATH` and `PSModulePath` fixed to the system folders, so
  a program or module planted where the operator can write is not found through either. On
  Linux, `openssl` no longer gets the Python interpreter's `PYTHON*` variables, which it never
  reads. See [DEPLOY-SERVER-DB.md](../docs/DEPLOY-SERVER-DB.md) section 5.4 and
  [DANGEROUS-FUNCTIONALITY.md](../docs/DANGEROUS-FUNCTIONALITY.md) section 4. (`BACKLOG #3803`)
