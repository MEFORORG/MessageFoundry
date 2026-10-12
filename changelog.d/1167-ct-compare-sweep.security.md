- **Five more compares run in constant time.** The session-list routes in the API and the web
  console, the session-rotation grant walk, the trust-anchor pin check, and the DR backup's key-id
  match each used `==` or `!=`, which stops at the first differing character. Each now calls
  `messagefoundry.credential.constant_time_equal`. Only the grant walk compares a value the caller
  is not already shown: the session lists return each hash, a CA fingerprint is public, and an
  archive's key id sits in its header. The outcome of each compare is unchanged.
  The store cipher's keyring fallback no longer stops at the first key that opens a value. A row
  whose marker names no configured key, or whose named key fails, is now tried against every
  keyring key, so the read time no longer shows which fallback key sealed it. A row whose named
  key opens it still stops at that key. Fallback reads cost one tag check per keyring key, plus
  one sub-key derivation per key for a v4 row. The decrypted value and the error texts are
  unchanged. (`BACKLOG #1167`, ASVS 11.2.4)
