- **A bad `anon.toml` overlay is reported more accurately, and earlier.** Four small changes, none
  of which changes what the anonymizer scrubs. A path the system refuses to open, such as one with
  an embedded NUL, is now reported as `the path is not one the system can open`; it used to be
  reported as a value the TOML parser refused. TOML that stops early now reads `invalid TOML at
  the end of the file, line N`, where N is the last line; for a file ending in a newline the old
  text named the line after the last one. `python -m tee anonymize-captures` now checks the salt
  and loads the overlay before it reads the store, so a bad overlay or a weak salt refuses the run
  even when the store holds no captured bodies. `kept_defaults` is now exported from
  `messagefoundry.anon` and `tee.anon`. (`BACKLOG #3003`)
