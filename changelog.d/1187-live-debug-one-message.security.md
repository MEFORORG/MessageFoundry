- **The IDE's Live Debug reveal now shows one message.** *Reveal Values for One Run* used to show
  values from every message in a multi-message sample. It now asks which message first, listing them
  by file name and disposition, and the revealed run keeps only that one. A one-message sample needs
  no choice. The pick is by position: if the sample's message count changed since it was listed,
  nothing is revealed, and the next reveal lists the messages again. Hide, or turning Live Debug
  off, while the choice is open starts no reveal. The `--show-phi` run still covers the whole
  sample, and the extension drops every other message before anything renders, as the Test
  Bench's per-case reveal does. Owner ruling R15 reads a reveal
  as per message. (ASVS 14.2.6, vault `BACKLOG #1187`)
