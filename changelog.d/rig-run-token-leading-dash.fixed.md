- **`python -m harness.load.rigadmin run` passes the session as one `--token=VALUE` argument.** A
  session is drawn from `secrets.token_urlsafe`, whose alphabet holds `-`, so about one in 64
  starts with it, and the child's argparse read `--token` followed by such a value as a missing
  value and exited 2 (`expected one argument`). The CI load-test legs failed intermittently on
  that; the benchmark legs, whose gate fails only on `run`'s own exit 4, went green on such a run
  with no report.
