- **An `anon.toml` overlay that points a default field at a different surrogate kind now warns.**
  The kinds do not rewrite the same parts of a field. `id`, `mrn` and `ssn` rewrite the first
  component only, so `"PID-5" = "id"` left the given name in the dataset, and `"PID-7" = "date"`
  left the birth year. Nothing said so. The leak check counts such a field as scrubbed and does
  not scan what is left; that is unchanged, so a clean `anonymize_checked` return does not clear
  a retargeted field. `load_rules` now logs each such retarget at WARNING, naming the field, the default kind and the
  new kind, and never a value. A retarget to the same kind and a `drop` do not warn. The new
  `retargeted_defaults`, exported from `messagefoundry.anon` and `tee.anon`, lists them, and
  `python -m tee anonymize-captures` prints them on stderr at every `--log-level`. The retarget
  still loads: refusing one is not built. Two smaller changes ride along. The overlay warnings are
  logged once per process for one set of lines; a caller that passed `overlay=` for every message
  used to get them once per message. And a schema refusal now quotes at most 80 characters of any
  overlay key or value, and of the whole list of unknown keys, with a count of what was left out.
  (`BACKLOG #3000`)
