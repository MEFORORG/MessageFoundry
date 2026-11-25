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

- Exit 0 prints `PASS e2e smoke`. Exit 1 prints `FAIL <step>: <reason>` on stderr, the step one
  of `message`, `ports`, `checkout`, `provision`, `serve`, `sign-in`, `ready`, `mllp`,
  `disposition`. A `serve` or `ready` failure also prints the engine log's tail.
- `FAIL checkout` means the venv imports `messagefoundry` from another checkout, so the engine
  would not run your change. Run `scripts\worktree\ensure-venv.ps1` in this worktree.
- `FAIL ports` means something already holds 2575, often another engine. Stop it, or point the
  run at your own graph: `--config <dir> --inbound <name> --mllp-port <port>`.
- `--expect unrouted|filtered|not_deployed|error` asserts another final disposition (`error`
  only after the ACK: a NAKed message fails `mllp`); `--message <file>` sends
  another file. Synthetic HL7 only.

Its tests, with the negative controls: `pytest tests/test_harness_e2e_smoke.py`.
