# Firebase desktop authentication contract

The React renderer must never receive Firebase refresh tokens, Firebase Admin
credentials, or the desktop OAuth code verifier. Those values belong to the
native desktop host and the KotSafe backend.

## Required flow

1. The native host creates a fresh `state` and PKCE verifier/challenge, starts
   a loopback listener on `127.0.0.1` using a random port, and opens the system
   browser at `https://auth.kotsafe.com/desktop`.
2. The hosted Firebase Auth page completes email, Google, GitHub, or MFA login.
   Configure Firebase Hosting to use `auth.kotsafe.com` as the `authDomain`.
3. The page sends its Firebase ID token to a Cloud Function over HTTPS. The
   function verifies it with the Firebase Admin SDK, records a single-use code
   bound to the PKCE challenge and `state`, then redirects only to the supplied
   loopback callback.
4. The native host validates the callback `state`, exchanges the one-time code
   and PKCE verifier with the Cloud Function, and saves the resulting session in
   the operating system's credential vault. It then publishes only the safe
   session summary through `window.kotSafeDesktop`.

## Guest policy

`beginGuestSession` may expose only the local exit-node host capability.
`client_mode`, mesh pairing, cloud synchronization, and security settings must
be rejected by the native host until a verified session exists. The renderer's
`accessPolicy.ts` mirrors this rule for the UI; it is not the enforcement layer.
