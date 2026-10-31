# KotSafe TV phone-link deployment

The TV sign-in experience uses a short-lived QR code much like YouTube's device flow:

1. The TV asks the relay for a ten-minute, single-use link session.
2. The signed-in KotSafe phone scans the QR code and sends its Firebase ID token only to the relay.
3. The relay verifies the token with Firebase Admin, checks the account entitlement, and mints a one-time Firebase custom token for the TV.
4. The TV signs in with that custom token. It never receives the phone password, Firebase ID token, refresh token, or licence key.

## Required Firebase setup

Use the **same Firebase project** as the KotSafe Android app, but add separate Android app registrations for the TV packages:

- `com.kotsafe.tv` for release.
- `com.kotsafe.tv.debug` for the debug build used by `deploy-to-tv.sh`.

Add the matching SHA-1/SHA-256 signing certificate fingerprints. Download the resulting multi-client `google-services.json` and place it at `kotsafe-tv/app/google-services.json`. Do not copy the phone app's JSON unchanged: Android OAuth registration is tied to both its package name and signing certificate.

Enable Google in Firebase Authentication. The mobile app already handles Google sign-in; the TV can use either phone linking or the direct Google-on-TV fallback.

## Relay deployment

`web/server/licenseBackend.js` now exposes:

- `POST /v1/tv-auth/start`
- `POST /v1/tv-auth/approve`
- `POST /v1/tv-auth/exchange`

Deploy that server behind the HTTPS relay configured in `TV_AUTH_BASE_URL` (currently `https://relay.kotsafe.com`). Install dependencies and give only the server a Firebase Admin credential:

```sh
cd web
npm ci
export GOOGLE_APPLICATION_CREDENTIALS=/secure/path/firebase-service-account.json
npm run server
```

On Cloud Run or Firebase Functions, use Application Default Credentials instead. An alternative is to provide `FIREBASE_SERVICE_ACCOUNT_JSON` as an encrypted runtime secret. Never add an Admin credential to either Android app or to source control.

The included pairing map is suitable for one relay process during development. Before running more than one process, store sessions in Redis or Firestore with a ten-minute TTL and an atomic one-time exchange.

## Entitlements

The relay deliberately does **not** trust a licence-shaped string from an app. Your trusted billing or licence activation service must set Firebase custom claims after a server-side verification. For example:

```js
await getAuth().setCustomUserClaims(uid, {
  kotsafePlan: 'PRO', // or ENTERPRISE
  p2p: true,
  licenseExpiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
});
```

The current demo licence registry in `licenseBackend.js` is not a production entitlement store and should not be used to decide account claims. Claims must be refreshed on the phone after a plan change; new TV links then receive the current entitlement.

## Release checklist

1. Deploy the HTTPS relay routes and verify start → approve → exchange with a test account.
2. Put the generated TV Firebase configuration in the TV project and build both debug and release variants.
3. Sign in as a guest: all local security features must remain available and P2P must remain locked.
4. Link a basic account: security-only access is expected.
5. Link a Pro/Enterprise account: P2P client and exit-node controls should unlock.
6. Sign out or let an entitlement expire: verify that the SOCKS listener closes and stored P2P pairings are erased.
