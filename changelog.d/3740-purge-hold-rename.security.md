- **Under dual control, a requester who is renamed while their purge is held now joins that hold
  when they ask for the same purge again.** Before this, a second request for the same purge filed
  a second hold. The purge hold records the requester's display name, so the rename made the two
  requests look different. A repeat request is now matched on the requester's immutable user id.
  It needs no new step-up proof, as for any repeat. The hold keeps the name it was filed under, so
  the approver sees that name and the released purge is recorded under it. A different person who
  later gets the freed name still files their own hold. The replay and reload holds still file a
  second hold after a rename. (`BACKLOG #3740` item 9)
