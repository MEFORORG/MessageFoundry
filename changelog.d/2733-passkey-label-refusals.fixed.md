- **A passkey enrolment that the store refuses is called a label clash only when the label is
  taken.** A label differing only by case from one the account holds is now refused before the
  ceremony is used, on every backend, as SQL Server's collation already refused it; two enrolments
  racing such labels can still both land on SQLite and Postgres. A label's 100-character cap counts
  UTF-16 code units, as SQL Server's column does, so a label of characters outside the Basic
  Multilingual Plane no longer passes the check and then fails on that store. Any other refusal now
  says the passkey could not be stored. (`vault BACKLOG #2733`)
