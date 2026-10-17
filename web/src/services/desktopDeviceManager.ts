/**
 * KotSafe Desktop Device Manager & Multi-Device Cloud Synchronizer
 * Connects with Firestore collection `users/{uid}/devices` to register
 * desktop hardware and provide real-time multi-device tracking.
 */
import {
  collection,
  doc,
  onSnapshot,
  serverTimestamp,
  setDoc,
  updateDoc,
  addDoc,
  Unsubscribe,
  Timestamp,
} from 'firebase/firestore';
import { User } from 'firebase/auth';
import { db } from '../firebase/firebaseConfig';

export interface ConnectedDevice {
  deviceId: string;
  ownerUid: string;
  model: string;
  osVersion: string;
  appVersion: string;
  isOnline: boolean;
  isProtected: boolean;
  statusType: 'ONLINE' | 'OFFLINE' | 'REVOKED' | string;
  meshStatus: string;
  threatScore: number;
  deviceType?: 'android' | 'desktop' | 'ios' | 'server';
  lastHeartbeat: number | Timestamp | { toMillis?: () => number; toDate?: () => Date } | null;
  isCurrentDevice?: boolean;
}

const LOCAL_STORAGE_DEVICE_ID_KEY = 'kotsafe_desktop_device_id_v2';

export function getDesktopDeviceId(): string {
  if (typeof window === 'undefined') return 'desktop_server';
  let deviceId = localStorage.getItem(LOCAL_STORAGE_DEVICE_ID_KEY);
  if (!deviceId) {
    const randomHex = Math.random().toString(36).substring(2, 10);
    const tsHex = Date.now().toString(36);
    deviceId = `desktop_${randomHex}_${tsHex}`;
    localStorage.setItem(LOCAL_STORAGE_DEVICE_ID_KEY, deviceId);
  }
  return deviceId;
}

export function detectDesktopPlatform(): { os: string; model: string } {
  if (typeof navigator === 'undefined') {
    return { os: 'Linux x86_64', model: 'KotSafe Desktop Node' };
  }

  const ua = navigator.userAgent;
  let os = 'Linux x86_64';
  let model = 'KotSafe Linux Workstation';

  if (ua.includes('Win')) {
    os = 'Windows 11 / 10 Pro';
    model = 'KotSafe Windows Workstation';
  } else if (ua.includes('Macintosh') || ua.includes('Mac OS')) {
    os = 'macOS Sonoma / Ventura';
    model = 'KotSafe Mac Sentinel';
  } else if (ua.includes('CrOS')) {
    os = 'ChromeOS';
    model = 'KotSafe Chromebook';
  } else if (ua.includes('Linux')) {
    os = 'Linux (X11 / Wayland)';
    model = 'KotSafe Linux Sentinel Workstation';
  }

  return { os, model };
}

/**
 * Register or update this desktop client in Firestore under `users/{uid}/devices/{deviceId}`
 */
export async function registerDesktopDevice(user: User): Promise<string> {
  const deviceId = getDesktopDeviceId();
  const { os, model } = detectDesktopPlatform();

  const deviceData = {
    deviceId,
    ownerUid: user.uid,
    model,
    osVersion: os,
    appVersion: '2.0.5 Desktop Pro',
    isOnline: true,
    statusType: 'ONLINE',
    isProtected: true,
    meshStatus: 'Zero-Trust Armed (Desktop Sentinel)',
    threatScore: 100,
    deviceType: 'desktop',
    lastHeartbeat: serverTimestamp(),
  };

  // 1. Write to nested user devices subcollection
  const userDeviceRef = doc(db, 'users', user.uid, 'devices', deviceId);
  await setDoc(userDeviceRef, deviceData, { merge: true });

  // 2. Also register in global devices collection (matching Android CloudSyncManager)
  const globalDeviceRef = doc(db, 'devices', deviceId);
  await setDoc(globalDeviceRef, deviceData, { merge: true }).catch(() => {
    // Non-fatal if global devices permissions are stricter
  });

  // 3. Update top-level user doc with active device
  const userDocRef = doc(db, 'users', user.uid);
  await setDoc(
    userDocRef,
    {
      uid: user.uid,
      email: user.email ?? '',
      displayName: user.displayName ?? (user.email ? user.email.split('@')[0] : 'KotSafe Sentinel'),
      isActive: true,
      deviceStatus: 'ONLINE',
      activeDeviceId: deviceId,
      activeDeviceModel: model,
      platform: 'desktop',
      lastActiveTime: serverTimestamp(),
    },
    { merge: true }
  ).catch(err => {
    console.warn('[DesktopDeviceManager] User doc update notice:', err);
  });

  return deviceId;
}

/**
 * Periodic heartbeat to maintain live ONLINE presence
 */
export function startDesktopHeartbeat(uid: string): () => void {
  const deviceId = getDesktopDeviceId();
  const intervalId = window.setInterval(async () => {
    try {
      const userDeviceRef = doc(db, 'users', uid, 'devices', deviceId);
      await updateDoc(userDeviceRef, {
        isOnline: true,
        statusType: 'ONLINE',
        lastHeartbeat: serverTimestamp(),
      });
    } catch (e) {
      // Discard network interruptions gracefully
    }
  }, 30000);

  return () => {
    window.clearInterval(intervalId);
  };
}

/**
 * Mark this desktop device OFFLINE on user logout or window teardown
 */
export async function markDesktopOffline(uid: string): Promise<void> {
  try {
    const deviceId = getDesktopDeviceId();
    const userDeviceRef = doc(db, 'users', uid, 'devices', deviceId);
    await updateDoc(userDeviceRef, {
      isOnline: false,
      statusType: 'OFFLINE',
      lastHeartbeat: serverTimestamp(),
    });
  } catch (err) {
    console.warn('[DesktopDeviceManager] Offline update notice:', err);
  }
}

/**
 * Subscribe in real time to all devices registered under the single user account
 */
export function subscribeToUserDevices(
  uid: string,
  onDevicesUpdate: (devices: ConnectedDevice[]) => void,
  onError?: (error: Error) => void
): Unsubscribe {
  const currentDeviceId = getDesktopDeviceId();
  const devicesCollectionRef = collection(db, 'users', uid, 'devices');

  return onSnapshot(
    devicesCollectionRef,
    snapshot => {
      const devices: ConnectedDevice[] = [];
      let foundCurrent = false;

      snapshot.forEach(docSnap => {
        const data = docSnap.data();
        const dId = data.deviceId || docSnap.id;
        const isCur = dId === currentDeviceId;
        if (isCur) foundCurrent = true;

        // Auto-detect deviceType if missing
        let detectedType: 'android' | 'desktop' | 'ios' | 'server' = 'desktop';
        const modelStr = (data.model || '').toLowerCase();
        const osStr = (data.osVersion || '').toLowerCase();
        if (data.deviceType) {
          detectedType = data.deviceType;
        } else if (modelStr.includes('oppo') || modelStr.includes('samsung') || modelStr.includes('pixel') || osStr.includes('android')) {
          detectedType = 'android';
        } else if (osStr.includes('ios') || modelStr.includes('iphone')) {
          detectedType = 'ios';
        }

        devices.push({
          deviceId: dId,
          ownerUid: data.ownerUid || uid,
          model: data.model || 'KotSafe Device',
          osVersion: data.osVersion || 'Unknown OS',
          appVersion: data.appVersion || '2.0.5',
          isOnline: typeof data.isOnline === 'boolean' ? data.isOnline : true,
          isProtected: typeof data.isProtected === 'boolean' ? data.isProtected : true,
          statusType: data.statusType || (data.isOnline ? 'ONLINE' : 'OFFLINE'),
          meshStatus: data.meshStatus || 'Zero-Trust Armed',
          threatScore: typeof data.threatScore === 'number' ? data.threatScore : 100,
          deviceType: detectedType,
          lastHeartbeat: data.lastHeartbeat || null,
          isCurrentDevice: isCur,
        });
      });

      // If current desktop is not in snapshot yet, add local optimistic placeholder
      if (!foundCurrent) {
        const { os, model } = detectDesktopPlatform();
        devices.unshift({
          deviceId: currentDeviceId,
          ownerUid: uid,
          model,
          osVersion: os,
          appVersion: '2.0.5 Desktop Pro',
          isOnline: true,
          isProtected: true,
          statusType: 'ONLINE',
          meshStatus: 'Zero-Trust Armed (Desktop Sentinel)',
          threatScore: 100,
          deviceType: 'desktop',
          lastHeartbeat: Date.now(),
          isCurrentDevice: true,
        });
      }

      // Sort: current device first, then online devices, then others
      devices.sort((a, b) => {
        if (a.isCurrentDevice) return -1;
        if (b.isCurrentDevice) return 1;
        if (a.isOnline && !b.isOnline) return -1;
        if (!a.isOnline && b.isOnline) return 1;
        return a.model.localeCompare(b.model);
      });

      onDevicesUpdate(devices);
    },
    error => {
      console.error('[DesktopDeviceManager] Snapshot error:', error);
      onError?.(error);
    }
  );
}

/**
 * Remotely revoke / sign out a device and optionally trigger Zero-Trust Kill Switch
 */
export async function revokeDeviceSession(uid: string, targetDeviceId: string): Promise<void> {
  const targetDeviceRef = doc(db, 'users', uid, 'devices', targetDeviceId);

  // 1. Mark device revoked and offline
  await updateDoc(targetDeviceRef, {
    isOnline: false,
    statusType: 'REVOKED',
    isProtected: false,
    revokedAt: serverTimestamp(),
  });

  // 2. Dispatch command to device's commands subcollection (listened by Android CloudSyncManager)
  const commandsRef = collection(db, 'users', uid, 'devices', targetDeviceId, 'commands');
  await addDoc(commandsRef, {
    command: 'REMOTE_KILL_SWITCH',
    status: 'PENDING',
    timestamp: serverTimestamp(),
    issuedBy: getDesktopDeviceId(),
    reason: 'Remote sign-out triggered from KotSafe Desktop',
  }).catch(() => {
    // Non-fatal if command subcollection permissions differ
  });
}
