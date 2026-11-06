- **A passkey enrolment that the store refuses is called a label clash only when the label is
  taken.** Two labels differing only by case are now refused on every backend, as SQL Server's
  collation already refused them, and a label's 100-character cap counts UTF-16 code units, as SQL
  Server's column does, so a label of characters outside the Basic Multilingual Plane no longer
  passes the check and then fails on that store. Any other refusal now says the passkey could not
  be stored. (`vault BACKLOG #2733`)
