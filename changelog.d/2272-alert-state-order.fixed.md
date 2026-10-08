- **Alert state writes for one condition now reach the store in the order they were raised.** The
  alert sink ran each open and each auto-resolve as its own background task, so a slow open could
  land after the clear raised behind it and leave a recovered connection showing an open alert, or
  the reverse. Writes for the same alert type and connection now queue in emit order, while writes
  for different conditions still run side by side. Each write also records the time the condition
  was raised or cleared, rather than the time the store finished the write.
  (`vault BACKLOG #2272`)
