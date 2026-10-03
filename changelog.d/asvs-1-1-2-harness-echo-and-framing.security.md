- **The harness X12 sink never echoes an ISA13 that is not nine digits into its TA1 (ASVS 1.1.2).**
  The sink wrote the received ISA13 into TA101 with fixed separators, and ISA13 is read by fixed
  offset, so one holding `*` and `~` could turn a TA1 the sink sent as accepted into one the
  engine's codec reads as TA1-04 `R`, which the engine's X12 destination dead-letters. The sink now
  answers such an interchange with nothing, as it already did for one with no readable ISA13, and
  the TA1 builder refuses the value.
- **The harness Compose tab frames through `frame_checked` by default.** A message holding an MLLP
  frame byte is refused before any connection and shows `not sent:` with the byte and its position,
  as the Send tab does. Sending such bytes on purpose, to test the engine's ingress refusal
  ([ADR 0205](../docs/adr/0205-an-outbound-frame-holds-exactly-one-message.md) rule 4), is a
  labelled opt-in checkbox.
- **`samples/send_mllp.py` prints the peer's ACK with control characters escaped.** Every C0
  control except newline and tab, DEL, and every C1 control is printed as a visible `\xNN` escape,
  so an ACK holding a terminal escape sequence cannot act on the operator's terminal.
- **`messagefoundry verify`'s live smoke frames through `frame_checked`**, like every other MLLP
  sender, and refuses before dialling. Its message is synthetic, so this is consistency.
