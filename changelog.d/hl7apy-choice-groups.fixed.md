- **Strict validation no longer rejects an order message for carrying one order detail.**
  hl7apy 1.3.5 checks a `choice` group as if every alternative were required (upstream
  crs4/hl7apy issue 151). A strict inbound would have NAKed every `ORM^O01` and `ORR^O02` with
  an OBR or RXO order detail, with `Missing required child ORM_O01_CHOICE.RQD` or its per-version
  name, and the same for any other structure with a choice group. The engine now carries the
  upstream fix (PR 152, unmerged) at its own validation boundary: a choice group needs exactly
  one alternative, and two in one group are still rejected. Sixteen groups that hl7apy's
  v2.6+ tables label as choices are really sequences (RSP_E22_QUERY_ACK is QAK then QPD, for
  one); the engine keeps validating them as sequences, where PR 152 as written would reject
  every valid message of those structures. The shim stays on while
  hl7apy itself gets any of three synthetic probe messages wrong, and a test goes red on the first hl7apy release
  that fixes the bug, so the shim is removed with it.
