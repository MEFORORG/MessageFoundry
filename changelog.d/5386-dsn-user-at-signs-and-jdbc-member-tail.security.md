- **On each line below, the values `tests/test_b20010_dsn_5386_remainder.py` names for it are now
  hidden on every entry point that test checks.**
  - `connect postgres://ops@corp.example@srv:Kv9Sec@srv.example.invalid/x failed`
  - `postgres://a@b@srv:Kv9_Az@srv.example.invalid/x`
  - `x postgres://ops@srv:@Kv9x@db.invalid`
  - `jdbc:sqlserver://db.invalid:1433;user=svc;sslpassword=P@ss_Sec9;`

  What still prints includes at least the residuals stated in the comments on `_WIDE_DSN_PASSWORD`
  and `_DSN_MEMBER_TAIL` in `messagefoundry/secretscrub.py`; that list is not complete.
  A `messagefoundry verify` report does not take these readings, so it still prints each value
  above, as it did before this change; the comment above `_WIDE_DSN_PASSWORD` says why.
  (`BACKLOG #5386`)
