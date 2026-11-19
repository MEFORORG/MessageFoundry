- **`[logging].forward_host` refuses the IPv4 limited broadcast address at load.** The forwarder
  never enables broadcast on its socket, so every send to `255.255.255.255` failed and, with a
  spool, held every later record behind it. With forwarding on, the start now refuses that value,
  its IPv4-mapped IPv6 spelling included, with a message naming the setting. The check reads only
  IP literals and does no DNS, so at least these are not refused: a directed subnet broadcast
  address, a multicast address (IPv4 `224.0.0.0/4`, IPv6 `ff00::/8`), and a host name that
  resolves to the broadcast address. (`BACKLOG #5923`)
