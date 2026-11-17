- **A Transit audit MAC 400 reads "refused" only when its errors list names a version refusal.**
  At least unknown Vault wording, an empty list and a body past the re-parse bound that hvac
  parsed now take the "could not be confirmed" text instead. The row is still a break with the
  tamper alert. An exception while reading the 400, or raised by a warning the audit check logs
  beside a break, now leaves the row a break; on main, at least an exception other than
  MemoryError or RecursionError there made the walk unable to run. (vault `BACKLOG #6707`)
