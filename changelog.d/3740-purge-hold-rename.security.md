- **Under dual control, a requester who is renamed while their purge is held now joins that hold
  when they ask for the same purge again.** Before this, the second request filed a second hold.
  The purge hold records the requester's display name, so the rename made the two requests look
  different. The route and the console now look first for the caller's open purge hold, matched on
  their user id. That lookup reads the newest 1000 open requests. Past that, a second hold is still
  filed. The hold keeps the display name it was filed under. That name is shown to the approver,
  and the released purge's audit row records it, even if the name has since passed to someone
  else. A different person who later gets the freed name still files their own hold. The replay
  and reload holds still file a second hold after a rename. See
  [SECURITY.md](../docs/SECURITY.md). (`BACKLOG #3740` item 9)
