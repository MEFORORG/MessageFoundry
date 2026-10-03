- **More console lines, and the Markdown verify report, now escape a peer's text (ASVS 1.1.2).**
  The `messagefoundry verify` console summary printed each check's detail raw, a JWKS key id
  included, so on first deployment a crafted `kid` could have driven the operator's terminal or
  started a line reading as a check that passed. The summary now escapes control, bidirectional and
  other format characters and the newline, and keeps printable Unicode, so the engine's own em
  dashes still print as themselves; the `--report-json` file keeps the value as it was. At least
  the harness `shardcert-driver`, `shardcert-drive` and `shardcert-drive-ladder` engine-error
  lines, the `--fuzz` setup and failure lines, and the scenario and load verdict lines now escape
  the newline as well, so engine text cannot start a line of its own there, and the `connscale`,
  `connscale-remote`, `estate`, `multishard` and `failover` setup errors escape the engine log tail
  they quote. `scripts/service/import-db-ca.ps1` shows a certificate's Subject and Issuer with
  control and format characters as `\uXXXX`. `messagefoundry/terminal_text.py` gains the
  `single_line` and `keep_printable_unicode` options these use, and now doubles a run of
  backslashes only before text that reads as an escape, so most Windows and UNC paths print as
  typed. The `--report-md` table now applies the same escape to every cell and writes at least `&`,
  `<`, `>`, `|`, a backtick, `$` and the `(` after a link's `]` as character references, so a
  peer's text cannot start a forged row or render as raw HTML, a remote image or a link whose text
  hides its target; what it still leaves, at least a bare URL's autolink, is listed in
  `messagefoundry/verify/report.py`. At least the load report's engine `/status` strings and `tee
  naks` still carry a peer's text as it came.
  The `shardcert` shard-start errors now escape the engine log tail they quote, the
  `ingress_probe` setup-failure line escapes it to one line (it is printed beside the `RESULT`
  line its workflow reads), and the `connscale` reload probe's warning escapes the engine reply to
  one line. A `--fuzz` failure line escapes a quoted identifier once rather than twice, so a real
  ESC prints as `\x1b` and text spelling it prints doubled. With `keep_printable_unicode`, a
  backslash is now also doubled before any non-ASCII character and before `x`, `u` or `U` followed
  by non-ASCII look-alike hex digits, and a kept character standing directly before such an escape
  body is escaped, so at least fullwidth, Cyrillic, combining-mark and look-alike-backslash
  spellings of an escape no longer pass for an escaped bidirectional override. An ASCII letter
  that resembles a hex digit, such as `l` for `1`, is still not treated as one, in either mode.
  At least the `connscale` pooled-arm miss notes and the batch-box cell notes, and a `shardcert`
  provisioning failure's traceback, still print engine output as it came.
