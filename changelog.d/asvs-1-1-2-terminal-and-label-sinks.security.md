- **More of the tools that print a peer's text now escape it first, and harness labels fed by the
  engine show it as plain text (ASVS 1.1.2).** `rigadmin get` printed any 200 body raw, the
  attachment route included, so on first deployment a sender's ESC or OSC sequence would have
  reached the terminal of whoever ran it. It now prints a non-JSON body by the rule
  `samples/send_mllp.py` already printed an ACK by, which now lives once in
  `messagefoundry/terminal_text.py`: printable ASCII, newline and tab as themselves, every other
  character as a visible `\xNN`, `\uNNNN` or `\UNNNNNNNN` escape. A JSON body keeps its value:
  plain JSON prints byte for byte, and any other character prints as JSON's own `\uNNNN` escape.
  The harness scenario and load command lines escape the engine's error text and a scenario's
  detail the same way, so an em dash in that text now shows as `—`, and the harness reconcile
  text report escapes the message keys and difference lines it lists. The harness monitor status
  and stats labels, the receive status label and the sign-in error label are now plain text, so
  engine or peer text that looks like HTML is shown as written. At least `tee naks` and the JWKS
  key ids in `messagefoundry verify` still print a peer's text as it came.
