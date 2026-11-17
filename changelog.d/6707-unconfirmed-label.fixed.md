- **A Transit audit MAC 400 reads "refused" only when its errors list names a version refusal.**
  At least unknown Vault wording, an empty list and a body past the re-parse bound that hvac
  parsed now take the "could not be confirmed" text instead. The row is still a break with the
  tamper alert. An exception while reading the 400 now leaves the row a break; on main, one other
  than MemoryError or RecursionError made the walk unable to run. An exception from the log call
  of a warning the audit check logs beside a break also leaves the row a break now; on main, any
  such exception made the walk unable to run. (vault `BACKLOG #6707`)
