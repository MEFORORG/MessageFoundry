- **Listeners that share one CRL file no longer each log the scan's held-copy warning.** When
  running hops still hold an older copy of a replaced CRL file, the certificate monitor logs
  `a running TLS hop still holds a copy of ...` and names every setting that holds one. It logged
  that line once for each row naming the file, so N listeners sharing a file gave N lines a pass,
  each listing the same N holders. A pass now logs the same line once, under the first row that
  names the file, and the line ends by naming the other rows: `The same file also serves ...`. A
  file one row names logs the line it always did. At least two cases still log more than one such
  line for a file in a pass: a file replaced part way through the pass, and a pass whose row
  grouping failed. The `crl_expiry` alerts did not change. Each row still raises its own, with its
  own `detail` and `shared_with`, so with no `[alerts]` transport the logged alert lines are still
  one set for each row. (`vault BACKLOG #3099`)
