- **The "too predictable" anonymizer salt refusal now names the floor that binds.** It used to
  cite the 32-bit total, but every salt that reaches that check is at least 32 characters, so the
  per-character floor of 2.0 bits refuses it as well, which is 64 bits at 32 characters. The
  message now states the salt's per-character estimate and that floor, with its total at the
  salt's length. No threshold or check changed. Both the toolkit keyer and the copy vendored
  into the tee changed (BACKLOG #4652).
