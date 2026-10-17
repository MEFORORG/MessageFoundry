- **A rate limiter with no global budget keeps no global window.** It recorded every admitted
  call in a window nothing read, so a per-key-only limiter held one entry per call of the last
  window. It now records global hits only when the global budget is set. (`BACKLOG #2714`)
