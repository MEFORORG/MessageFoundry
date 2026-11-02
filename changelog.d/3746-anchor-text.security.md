- **A trust anchor's `cadata=` text now reads lines and blocks closer to the way OpenSSL does.** It
  split lines at a lone CR, which OpenSSL's reader does not, so dropping a non-ASCII comment line
  ended by one could have put a certificate block in the loaded text that `cafile=` never reads,
  and a first deployment would have trusted that CA. It now splits at LF alone. A line holding
  `-----BEGIN ` anywhere now opens a block for the non-ASCII check, so a non-ASCII line in a block
  OpenSSL finds mid-line refuses, where it would have been dropped. That is stricter than `cafile=`
  in at least two shapes, and [CONFIGURATION.md](../docs/CONFIGURATION.md) says what it covers. The
  header and private-key refusals now run ahead of the non-ASCII refusal. The encryption-header
  refusal now quotes `"Proc-Type:"` and `"DEK-Info:"` and says it matches them in any case.
  (`BACKLOG #3746`)
