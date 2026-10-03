- **`samples/send_mllp.py` refuses a file holding an MLLP frame byte (ASVS 1.1.2).** The sender the
  operator docs tell a deployer to run framed a named file with the unchecked framer, so a file
  holding `0x1C`, CR, `0x0B` and a second MSH segment would have gone out as two frames. It now
  frames with `frame_checked`, the rule the engine's own MLLP delivery refuses by
  ([ADR 0205](../docs/adr/0205-an-outbound-frame-holds-exactly-one-message.md) rule 1), before it
  connects. A refused file prints the reason to stderr, and the helper exits 3 without opening a
  connection. A file saved with its own MLLP framing around it is refused too; strip that first.
