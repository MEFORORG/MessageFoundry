- **A Transit audit MAC 400 reads "refused" only when its errors list names a version refusal.**
  At least unknown Vault wording, an empty list and a body past the re-parse bound that hvac
  parsed now take the "could not be confirmed" text instead. The row is still a break with the
  tamper alert. An exception while reading the 400 now leaves the row a break; on main, one other
  than MemoryError or RecursionError made the walk unable to run. An exception while building or
  logging a warning the audit check logs beside a break also leaves the row a break now; on main,
  any such exception made the walk unable to run. (vault `BACKLOG #6707`)
- **The data-key decrypt's warning about an unread oversized 400 body is reported when it cannot
  be logged.** Its exception class goes to stderr, and the warning is tried again on the next such
  decrypt rather than held back for the interval. (vault `BACKLOG #6707`)
