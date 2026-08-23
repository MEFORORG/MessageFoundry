<!--
BACKLOG #1137 precondition. The owner ruled 2026-08-22 to RETIRE the directory simple-bind login
pathway; the dispatcher gated the build on one sentence: nothing retires the step-up re-bind until
the build STATES what a Kerberos identity re-proves with. This note is that statement.

SCOPE. It answers the precondition and nothing else. It does not retire anything, does not change
behaviour, and does not decide the replacement -- the last of those turns on a question this note
opens rather than closes, and opening it is the point.

Measured 2026-08-22 against engine tree c9fb6022. Code is cited by SYMBOL; a line number rots and a
symbol does not.
-->

# What an AD identity re-proves with, once simple bind is gone

**The step-up path for every AD-stamped identity today is a live simple re-bind with the user's
directory password.** Retiring the simple-bind login pathway therefore does not only remove a login
option — it removes the only credential the step-up path knows how to check, for identities that
never had a password to give.

## 1. Why Kerberos users are affected at all

`AuthProvider` has two members, LOCAL and AD. `_complete_ad_login` is the shared tail of **three**
login paths — `_login_ad` (simple bind), `authenticate_kerberos`, and `authenticate_oidc` — so a
Kerberos-authenticated user is stamped **AD**, indistinguishably from a simple-bind one.

`AuthService.reauth` dispatches on exactly that stamp: `AuthProvider.AD` goes to `_reauth_ad`, which
performs a live directory bind with a submitted password. Everything else goes to
`verify_current_password`.

**So a Kerberos user's step-up asks for a password they were never required to have.** That is
already true today; simple-bind retirement makes it unavoidable rather than merely awkward.

## 2. The mechanical answer, and why it is not sufficient

`authenticate_kerberos` takes a **SPNEGO token**, resolves the principal through
`kerberos_principal`, and looks it up in the directory. Nothing in that path needs a password, so a
`_reauth_kerberos` that verifies a freshly presented ticket resolves to the *same* principal as the
session identity is straightforward to build.

**It would satisfy the letter of the re-proof and weaken its purpose.** A Kerberos ticket is served
from a cache the client already holds; a browser can re-present one with no human involvement. A
step-up (ASVS 7.5.3) exists to establish that *the person is still there* before a highly sensitive
operation. A silent re-proof establishes that the *machine* is still there, which is what the session
cookie already established.

So a fresh SPNEGO exchange is a valid **identity** re-proof and a poor **presence** re-proof, and
step-up wants the second.

## 3. The candidate that fits the purpose, and the measurement it needs

The obvious replacement is a second factor — TOTP or a passkey — as the step-up for AD identities.
**One thing blocks stating that as the answer:** all three AD login paths complete with
`mfa_verified=True`, on the recorded reasoning that a Kerberos service ticket carries no
factor-strength assertion the library surfaces, so directory delegation stands.

If AD identities are MFA-verified **by delegation** rather than by enrolment, an AD user may hold no
second factor for the engine to challenge. That is the question the replacement turns on, and this
note does not answer it: **whether an AD-stamped identity can carry an engine-side second factor, and
what share of real deployments would have one.** It is a measurement plus a product call, not a code
reading, and it should be settled before the replacement is chosen rather than discovered during it.

## 4. The unmeasured cost the ruling already carries

Recorded here so it travels with the build rather than living in one message: **a client that cannot
do Kerberos — not domain-joined, cross-forest, or an unconfigured browser — loses AD login with no
fallback once simple bind is gone.** Nobody has measured how common that is. The owner ruled with
that cost stated.

## 5. Sequencing this establishes

1. Retiring the simple-bind **login** pathway and retiring the simple-bind **step-up** are separable,
   and the second is strictly harder. The login side has a replacement in hand (Kerberos, which every
   real AD deployment provides). The step-up side does not yet.
2. So the step-up re-bind must **outlive** the login pathway, or AD identities lose access to every
   step-up-gated operation on the day the login change lands.
3. `_reauth_ad` may therefore not be deleted in the same change that removes `_login_ad`, and any
   plan that treats them as one deletion is wrong for a reason that is invisible until an AD operator
   tries to enroll a factor or disable MFA.

## 6. Not established

- Whether an AD-stamped identity can hold an engine-side TOTP secret or passkey in practice.
- What share of AD deployments have clients that cannot obtain a Kerberos ticket.
- Whether a fresh SPNEGO exchange can be made non-silent (a re-prompt) on any browser the console
  supports. If it can, section 2's objection weakens and the mechanical answer may suffice.
