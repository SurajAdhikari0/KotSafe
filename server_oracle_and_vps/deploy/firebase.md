# Deploying the Firebase (serverless) path

This path skips signaling-server/coturn entirely — Firestore itself is the "signaling
server" the app talks to directly via the Firestore SDK (see `FirebaseProvider.java` in
the app-side plan). This repo's `firebase-functions/` only adds two things Firestore alone
can't do: **auth-gated pairing token creation** and **TTL cleanup**, since Firestore has no
built-in expiring documents by default.

## 1. Create the Firebase project

1. [console.firebase.google.com](https://console.firebase.google.com) → **Add project**.
2. Enable **Firestore Database** (production mode, pick a region close to you).
3. Enable **Cloud Functions** (requires the Blaze pay-as-you-go plan — the free quota
   comfortably covers personal use; you will not be charged for casual traffic).
4. Project Settings → **General** → add an Android app (or Web app if you only need the
   config fields) → copy `projectId`, `apiKey`, `appId`. These three values are what the
   user pastes into the app's Backend Setup Wizard.

## 2. Deploy Firestore rules and the cleanup function

```bash
cd kotsafe-relay/firebase-functions
npm install -g firebase-tools     # if not already installed
firebase login
firebase use --add                # select your project
firebase deploy --only firestore:rules,functions
```

`firestore.rules` (already in this repo) restricts each `pairings/{token}` document so
that:
- Anyone who *knows the token* can read/write candidates for that pairing (the token
  itself, generated with 16 random bytes, is the credential — same trust model as the
  self-hosted signaling server's shared secret, just scoped per-pairing instead of
  per-server).
- No one can list all pairing documents or enumerate tokens.

The scheduled Cloud Function (`cleanupExpiredPairings`, runs hourly) deletes any
`pairings/{token}` doc whose `expiresAt` has passed, mirroring the self-hosted server's
in-memory TTL sweep.

## 3. In the app

Settings → Backend → Firebase → paste `projectId` / `apiKey` / `appId` → Test connection
(this does a throwaway `pairings/_healthcheck` write+read+delete) → Save.

## 4. Cost note

Firestore's free tier (50K reads / 20K writes / 20K deletes per day) is far more than
personal candidate-publishing traffic needs — a device publishing on every network change
plus a live subscriber is on the order of dozens of operations/day, not thousands.
