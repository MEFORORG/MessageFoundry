- **On each line below, the values `tests/test_b532r_redaction_bracket_tail.py` names for it are now
  hidden on every entry point that test checks.**
  - `connect postgres://svc:Kv9x@Zq7;w@db.example.invalid/x failed`
  - `connect postgres://svc:Kv9x@Zq7;w;Mx4@db failed`
  - `connect postgres://svc:Kv9x@;Wq4@db failed`
  - `connect postgres://svc:Kv9x@Zq7;;Wq4@db failed`
  - `connect postgres://svc:Kv9x@Zq7;Wq4;@db failed`
  - `connect postgres://svc:Kv9@Aa1;Bb2@Cc3;Dd4@h2 failed`
  - `connect postgres://svc:Kv9x@Zq7@Wq4;Mx5@db failed`

  What still prints is stated in the comment on `_WIDE_DSN_PASSWORD` in
  `messagefoundry/secretscrub.py`. (`BACKLOG #5386`)
