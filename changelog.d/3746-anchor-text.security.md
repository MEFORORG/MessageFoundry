- **A trust anchor's `cadata=` text now splits lines at LF alone, as OpenSSL's reader does.** It
  also split at a lone CR, so on a first deployment the text could have differed from what `cafile=`
  reads. A line holding `-----BEGIN ` anywhere now opens a block for the non-ASCII check, and the
  `TRUSTED CERTIFICATE` label now refuses anywhere on a line, even outside a block, as in a comment.
  A byte-order mark is stripped at the start of the file and after an `-----END ` line that closes
  a block in this check's own line model. That model is not OpenSSL's reader: it is stricter than
  `cafile=` in at least three shapes, and at least some shapes can still trust more than `cafile=`.
  The header and private-key refusals now run ahead of the non-ASCII refusal, whose text now says
  what to remove. The encryption-header refusal now quotes `"Proc-Type:"` and `"DEK-Info:"` and says
  it matches them in any case. (`BACKLOG #3746`)
