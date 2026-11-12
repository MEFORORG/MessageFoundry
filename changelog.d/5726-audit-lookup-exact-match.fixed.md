- **The audit lookups behind keyed audit evidence and the transit-bound attestation match exactly on
  SQL Server.** Each took `MAX(seq)` over a filter that compares in the database collation, which on
  SQL Server folds case and pads trailing spaces, so a variant row, for example a newer row by an
  account whose name differs only in case, would have shadowed the row the lookup wanted, and the
  exact recheck after it would have refused genuine evidence. Each lookup now checks the row it
  finds exactly and steps past a variant, on every backend. (`BACKLOG #5726`)
