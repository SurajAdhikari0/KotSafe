// Firebase Cloud Functions companion to the direct-Firestore FirebaseProvider path.
// Firestore alone handles publish/subscribe (the app SDK talks to it directly),
// these two functions cover what Firestore can't do on its own:
//   1. Auth-gated pairing token creation (so token generation isn't purely client-trusted)
//   2. Scheduled cleanup of expired pairing documents (Firestore has no native TTL
//      trigger without enabling the separate TTL policy feature — this function is
//      the portable alternative that works on any plan)

const { onCall, HttpsError } = require('firebase-functions/v2/https');
const { onSchedule } = require('firebase-functions/v2/scheduler');
const { initializeApp } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const crypto = require('crypto');

initializeApp();
const db = getFirestore();

const PAIRING_TTL_SECONDS = 86400;

exports.createPairing = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError('unauthenticated', 'Sign in (even anonymously) before pairing.');
  }
  const token = crypto.randomBytes(16).toString('hex');
  const now = Date.now();
  const expiresAt = now + PAIRING_TTL_SECONDS * 1000;

  await db.collection('pairings').doc(token).set({
    candidates: [],
    updatedAt: now,
    expiresAt,
    ownerUid: request.auth.uid,
  });

  return { token, expiresAt };
});

exports.cleanupExpiredPairings = onSchedule('every 60 minutes', async () => {
  const now = Date.now();
  const snap = await db.collection('pairings').where('expiresAt', '<', now).get();
  const batch = db.batch();
  snap.forEach((doc) => batch.delete(doc.ref));
  if (!snap.empty) await batch.commit();
  console.log(`cleanupExpiredPairings: removed ${snap.size} expired pairing(s)`);
});
