- **A trust anchor's `cadata=` text now splits lines at LF alone, as OpenSSL's reader does.** It
  also split at a lone CR, so on a first deployment the text could have differed from what `cafile=`
  reads. A line holding `-----BEGIN ` anywhere now opens a block for the non-ASCII check, and a
  `TRUSTED CERTIFICATE` block refuses wherever its BEGIN sits on a line. A byte-order mark is now
  stripped only after an `-----END ` line that closes a block in this check's own line model. That
  model is not OpenSSL's reader, so it does not match `cafile=` in every shape, and it is stricter
  than `cafile=` in at least three. The header and private-key refusals now run ahead of the
  non-ASCII refusal, whose text now says what to remove. The encryption-header refusal now quotes
  `"Proc-Type:"` and `"DEK-Info:"` and says it matches them in any case. (`BACKLOG #3746`)
