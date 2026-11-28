- **On each line below, the values `tests/test_b20010_dsn_5386_remainder.py` names for it are now
  hidden on every entry point that test checks.**
  - `connect postgres://ops@corp.example@srv:Kv9Sec@srv.example.invalid/x failed`
  - `postgres://a@b@srv:Kv9_Az@srv.example.invalid/x`
  - `x postgres://ops@srv:@Kv9x@db.invalid`
  - `jdbc:sqlserver://db.invalid:1433;user=svc;sslpassword=P@ss_Sec9;`

  What still prints includes at least the residuals stated in the comments on `_WIDE_DSN_PASSWORD`
  and `_DSN_MEMBER_TAIL` in `messagefoundry/secretscrub.py`; that list is not complete.
  Text that `messagefoundry.verify_leaf.safe_detail_text` scrubs, including at least the text
  `safe_exc_detail` and `safe_exc_text` pass it, does not take this change: each value above
  still prints there, as it did before. That text includes at least the details of a
  `messagefoundry verify` report and the acceptance harness's probe rows that quote an
  exception (`scrubbed_exc` in `harness/acceptance/probes.py`); the docstring of
  `scrub_credentials_without_tails` in `messagefoundry/secretscrub.py` says why.
  (`BACKLOG #5386`)
