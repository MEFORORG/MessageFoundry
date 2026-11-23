- **The harness message detail panel no longer acts on, or shows, the previous message while a new
  one opens.** Selecting a row now clears the panel and withdraws Replay and Show body until that
  message's open lands. Before, Replay pressed in that window would replay the previously shown
  message. An open that fails with an error other than an API error is now reported and clears the
  panel, where before it left the previous message on screen with nothing said. A row selected
  while Replay's step-up prompt is open is kept: the refresh after the replay no longer reopens the
  replayed message over it.
