- **Three more connection-string shapes are masked in a log line: a first member with no `;`
  before it, a key with a qualifier after its credential word, and a member after `; `.** A first
  member, as in `Password=a b;Server=h`, is read where its value runs to a `;` that another
  `<key>=` follows. A key such as `ClientSecretValue`, `PasswordOld` or `Password2` holds a
  credential word followed by one qualifier: `value`, `primary`, `secondary`, `old`, `new`,
  `next`, `current`, `previous`, `prev`, `plaintext`, `plain`, `raw`, `text`, `string` or a run of
  digits, each after an optional `_`. A member may follow its `;` after spaces or tabs. Each value
  is masked as a member after `;` is, on the write-time log filters and the support bundle; before,
  its tail after a space printed. What still prints, at least: a key with any other suffix after
  its word, such as `PasswordHint`, `PasswordHash` or `TokenKey`, whose value prints as before; and
  a first member whose value does not reach such a `;`. The cost: prose after `; password=` is now
  masked to the next `;`, quote or the end of the line, as after a glued `;password=`, so
  `login failed; password=wrong for user bob` loses the words after `password=`. A key such as
  `PasswordPolicy` or `TokenEndpoint` keeps its value. (BACKLOG #5030)
