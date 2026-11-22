- **The IDE's step-up re-proof is now tracked like a sign-in.** `/me/reauth` rotates the session
  token, but a cache reader did not wait for it and a sign-in started meanwhile did not either, so
  the sign-in could name the token the re-proof had just ended and the re-proof's late store could
  then overwrite the sign-in's newer token. Both now wait for the re-proof in that VS Code window.
  (`vault BACKLOG #2950`)
