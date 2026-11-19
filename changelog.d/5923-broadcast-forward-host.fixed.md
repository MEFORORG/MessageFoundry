- **`[logging].forward_host` refuses the IPv4 limited broadcast address at load.** The forwarder
  never enables broadcast on its socket, so every send to `255.255.255.255` failed and, with a
  spool, held every later record behind it. With forwarding on, the start now refuses that value,
  its IPv4-mapped IPv6 spelling included, with a message naming the setting. A directed subnet
  broadcast address is not detected. (`BACKLOG #5923`)
