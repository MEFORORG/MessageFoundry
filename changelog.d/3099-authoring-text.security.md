- **Authoring docstrings and connection-editor help that name `MEFOR_ALLOW_INSECURE_TLS` now say it
  works only on an instance at `[security].enforcement = warn`.** Six factory docstrings in
  `config/wiring.py` and twelve parameter comments, which the connection editor shows as help,
  said the escape alone was enough. So did docstrings in the Email, Direct, remote-file and
  DATABASE transports and the Postgres store. Where a connection can instead declare
  `tls_hop_attested` or `cleartext_accepted`, the text now says so. No gate changed. The test
  that checks these texts now reads docstrings in six pinned files and comments in
  `config/wiring.py`, and it closes three gaps in how it read calls. Its docstring says which
  shapes and files it still cannot see. (`vault BACKLOG #3099`)
