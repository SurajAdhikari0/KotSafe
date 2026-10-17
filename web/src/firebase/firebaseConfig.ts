import { initializeApp, getApps, getApp, FirebaseApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, Auth } from 'firebase/auth';
import { getFirestore, Firestore } from 'firebase/firestore';

export const firebaseConfig = {
  apiKey: "AIzaSyCKG2K6Ww2ecC8_uubyb_WeXX_7r_k4vcw",
  authDomain: "kotsafe-9b782.firebaseapp.com",
  projectId: "kotsafe-9b782",
  storageBucket: "kotsafe-9b782.firebasestorage.app",
  messagingSenderId: "445715318354",
  appId: "1:445715318354:web:kotsafe-desktop-app"
};

export const app: FirebaseApp = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);
export const auth: Auth = getAuth(app);
export const db: Firestore = getFirestore(app);
export const googleProvider = new GoogleAuthProvider();
