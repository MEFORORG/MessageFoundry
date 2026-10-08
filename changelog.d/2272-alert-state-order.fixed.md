- **Alert state writes for one condition now reach the store in the order they were raised.** The
  alert sink ran each open and each auto-resolve as its own background task. A slow open could
  then land after the clear raised behind it, so a recovered connection kept showing an open
  alert. The reverse could happen too. Writes for the same alert type and connection now queue in
  emit order, while writes for different conditions still run side by side. Each write records
  the time the sink raised or cleared the condition. Before, the store stamped the time the write
  reached it. (`vault BACKLOG #2272`)
