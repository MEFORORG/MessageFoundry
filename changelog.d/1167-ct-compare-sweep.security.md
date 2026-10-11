- **Five more compares run in constant time.** The session-list routes in the API and the web
  console, the session-rotation grant walk, the trust-anchor pin check, and the DR backup's key-id
  match each used `==` or `!=`, which stops at the first differing character. Each now calls
  `messagefoundry.credential.constant_time_equal`. Only the grant walk compares a value the caller
  is not already shown: the session lists return each hash, a CA fingerprint is public, and an
  archive's key id sits in its header. The outcome of each compare is unchanged.
  (`BACKLOG #1167`, ASVS 11.2.4)
