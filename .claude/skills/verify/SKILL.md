---
name: verify
description: Run the engine end to end - start a real `serve` on the sample config, send one synthetic ADT over MLLP, assert the AA ACK and the PROCESSED disposition through the API. Use before committing a change to messagefoundry/pipeline/, transports/, parsing/, store/ or config/, or whenever unit tests pass but you need proof the running engine still moves a message.
---

# verify: end-to-end engine smoke

From the worktree root, with its venv (`scripts\worktree\ensure-venv.ps1` first):

```
.venv/Scripts/python.exe -m harness.e2e_smoke
```

(`.venv/bin/python` on POSIX.)

It starts `python -P -X disable-remote-debug -m messagefoundry serve --config samples/config --env dev`
on a fresh temp store and a free API port, sends `samples/messages/adt_a01.hl7` to `IB_Test_ADT`
on 2575, signs in as a per-run rig Administrator, and reads the message's disposition from
`GET /messages`. Then it stops the engine and deletes the temp directory. About 20 s.

- Exit 0 prints `PASS e2e smoke`. A Ctrl+C exits 130 after `INTERRUPTED e2e smoke`; another
  signal it handles (SIGTERM, SIGHUP, Ctrl+Break) exits 128 plus the signal number with no line of
  its own. In both the engine is stopped and the temp directory deleted first.
  Exit 1 prints `FAIL <step>: <reason>` on stderr, the step one
  of `message`, `ports`, `checkout`, `provision`, `serve`, `sign-in`, `ready`, `mllp`,
  `disposition`, or `teardown`. An unforeseen error prints its type and message after the step it
  escaped. A `serve` or `ready` failure also prints the engine log's tail. An installed harness, with
  no checkout around it, fails `message` at once unless `--config`, `--message` and
  `--project-root` are passed.
- `FAIL checkout` means the venv imports `messagefoundry` from another checkout, so the engine
  would not run your change. Run `scripts\worktree\ensure-venv.ps1` in this worktree.
- `FAIL ports` means something already holds 2575, often another session's engine. Find out
  whose process it is first (PowerShell: `Get-NetTCPConnection -LocalPort 2575 -State Listen`,
  then `Get-Process -Id <OwningProcess>`; POSIX: `lsof -iTCP:2575 -sTCP:LISTEN`). Stop it only if
  your own session started it: never kill another session's engine. `--mllp-port` alone does not
  move the sample inbound, whose port is fixed at 2575 in `samples/config/adt.py`; to run beside the
  holder, point the smoke at a graph whose inbound listens elsewhere:
  `--config <dir> --inbound <name> --mllp-port <port>`. Otherwise report the held port and stop.
- `FAIL teardown` means every step passed but stopping the engine raised an error or left the
  engine, a process it started, or the temp directory behind (a `WARNING` line says which); a
  `WARNING the teardown failed too` line is the error case after a step failed. Either way, check for a
  leftover engine process and temp directory (`mefor-e2e-smoke-*`).
- `--expect unrouted|filtered|not_deployed|error` asserts another final disposition (`error`
  only after the ACK: a NAKed message fails `mllp`); `--message <file>` sends
  another file. Synthetic HL7 only.

Its tests, with the negative controls: `pytest tests/test_harness_e2e_smoke.py`.
