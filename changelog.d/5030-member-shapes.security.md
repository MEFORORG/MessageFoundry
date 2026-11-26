- **Three more connection-string shapes are masked in a log line: a first member with no `;`
  before it, a key with a qualifier after its credential word, and a member after `; `.** A first
  member, as in `Password=a b;Server=h`, is read where its value runs to a `;` that another
  `<key>=` follows. A key such as `ClientSecretValue`, `PasswordOld` or `Password2` holds a
  credential word followed by one qualifier, at least `value`, `old`, `new`, `primary` or a run of
  digits. A member may follow its `;` after spaces or tabs. Each value is masked as a member after
  `;` is, on the write-time log filters and the support bundle; before, its tail after a space
  printed. A key such as `PasswordPolicy` or `TokenEndpoint` keeps its value. (BACKLOG #5030)
