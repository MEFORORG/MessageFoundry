- **Alert state writes for one condition now reach the store in the order they were raised.** The
  alert sink ran each open and each auto-resolve as its own background task, so a slow open could
  land after the clear raised behind it and leave a recovered connection showing an open alert, or
  the reverse. Writes for the same alert type and connection now wait for the one before them,
  while writes for different conditions still run side by side. A write cancelled at shutdown no
  longer holds up the one queued behind it. (`vault BACKLOG #2272`)
