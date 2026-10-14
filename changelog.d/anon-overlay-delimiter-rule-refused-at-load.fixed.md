- **An `anon.toml` rule on `MSH-1` or `MSH-2` is now refused when the overlay loads.** No rule can
  rewrite those two fields, because they hold the message's delimiters. The refusal used to run
  only for each message. So such an overlay loaded, every message then failed, and
  `python -m tee anonymize-captures` printed a count of failed messages with advice to extend the
  rule map. `load_rules` now raises one `RuleError` that names the overlay file and the field, and
  the tee prints that one line and writes no dataset. A `keep` on either field still loads. The
  check for each message stays, so a rule set built in code still meets the refusal there. A rule
  on field 0 was already refused at load. (`BACKLOG #2997`)
