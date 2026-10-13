- **Listeners that share one CRL file no longer each log the held-copy warning.** When running
  hops still hold an older copy of a replaced CRL file, the certificate monitor logs
  `a running TLS hop still holds a copy of ...` and names every setting that holds one. It logged
  that line once for each row naming the file, so N listeners sharing a file gave N lines a pass,
  each listing the same N holders. A pass now logs it once for each file, and the line ends by
  naming the other rows: `The same file also serves ...`. A file one row names logs the line it
  always did. The `crl_expiry` alerts did not change: each row still raises its own, with its own
  `detail` and `shared_with`. (`vault BACKLOG #3099`)
