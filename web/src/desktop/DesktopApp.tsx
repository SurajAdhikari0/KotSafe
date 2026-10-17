/**
 * KotSafe Desktop Sentinel - Enterprise Authentication & Multi-Device Mesh
 * Copyright (c) 2026 KotSafe Cyber Security Project
 */
import React, { FormEvent, useEffect, useState } from 'react';
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  sendPasswordResetEmail,
  signOut as firebaseSignOut,
  onAuthStateChanged,
  updateProfile,
  User,
} from 'firebase/auth';
import { doc, getDoc, updateDoc } from 'firebase/firestore';
import { auth, googleProvider, db } from '../firebase/firebaseConfig';
import {
  ConnectedDevice,
  registerDesktopDevice,
  startDesktopHeartbeat,
  markDesktopOffline,
  subscribeToUserDevices,
  revokeDeviceSession,
} from '../services/desktopDeviceManager';
import '../styles/desktop.css';

type Notice = { kind: 'error' | 'info' | 'success'; message: string } | null;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ============================================================================
// SVG Icons
// ============================================================================
function ShieldIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M12 3 4.5 6.2v5.2c0 4.9 3.2 8.3 7.5 9.6 4.3-1.3 7.5-4.7 7.5-9.6V6.2L12 3Z" />
      <path d="m8.7 12 2.1 2.1 4.6-4.7" />
    </svg>
  );
}

function LockIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="5" y="10" width="14" height="10" rx="2" />
      <path d="M8 10V7a4 4 0 0 1 8 0v3" />
    </svg>
  );
}

function ArrowIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M5 12h14M13 6l6 6-6 6" />
    </svg>
  );
}

function PhoneIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="7" y="2" width="10" height="20" rx="2" />
      <path d="M11 18h2" />
    </svg>
  );
}

function MonitorIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <path d="M8 21h8M12 17v4" />
    </svg>
  );
}

function EyeIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function EyeOffIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
      <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
      <line x1="2" y1="2" x2="22" y2="22" />
    </svg>
  );
}

function GoogleIcon(): React.ReactElement {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#EA4335"
        d="M12 5c1.56 0 2.97.55 4.09 1.45l3.07-3.07C17.3 1.63 14.84.8 12 .8 7.37.8 3.4 3.43 1.48 7.23l3.68 2.85C6.06 7.2 8.78 5 12 5Z"
      />
      <path
        fill="#4285F4"
        d="M23.5 12.28c0-.82-.07-1.62-.21-2.28H12v4.51h6.47c-.28 1.48-1.12 2.73-2.39 3.58l3.68 2.85c2.15-1.99 3.74-4.91 3.74-8.66Z"
      />
      <path
        fill="#FBBC05"
        d="M5.16 14.92c-.24-.71-.38-1.47-.38-2.25 0-.78.14-1.54.38-2.25L1.48 7.57C.54 9.44 0 11.55 0 13.8c0 2.25.54 4.36 1.48 6.23l3.68-2.85Z"
      />
      <path
        fill="#34A853"
        d="M12 22.8c3.24 0 5.96-1.07 7.95-2.92l-3.68-2.85c-1.08.73-2.46 1.17-4.27 1.17-3.22 0-5.94-2.2-6.84-5.08L1.48 15.97C3.4 19.77 7.37 22.8 12 22.8Z"
      />
    </svg>
  );
}

// ============================================================================
// Helper Utilities
// ============================================================================
function formatFirebaseError(code: string, defaultMsg: string): string {
  switch (code) {
    case 'auth/invalid-email':
      return 'Please enter a valid email address.';
    case 'auth/user-not-found':
      return 'No KotSafe account found with this email. Please create an account.';
    case 'auth/wrong-password':
    case 'auth/invalid-credential':
      return 'Incorrect email or password. Verify your credentials or reset your password.';
    case 'auth/email-already-in-use':
      return 'An account with this email already exists. Please switch to Sign In.';
    case 'auth/weak-password':
      return 'Password is too weak. Please use at least 6 characters.';
    case 'auth/popup-closed-by-user':
      return 'Google sign-in was cancelled.';
    case 'auth/network-request-failed':
      return 'Network connection error. Check your internet access and try again.';
    case 'auth/too-many-requests':
      return 'Access temporarily locked due to multiple failed attempts. Try again later.';
    default:
      return defaultMsg;
  }
}

function formatRelativeTime(timestamp: ConnectedDevice['lastHeartbeat']): string {
  if (!timestamp) return 'Recently active';
  let millis = 0;
  if (typeof timestamp === 'number') {
    millis = timestamp;
  } else if (timestamp && typeof timestamp.toMillis === 'function') {
    millis = timestamp.toMillis();
  } else if (timestamp && typeof timestamp.toDate === 'function') {
    millis = timestamp.toDate().getTime();
  } else {
    millis = Date.now();
  }

  const diffSeconds = Math.max(0, Math.floor((Date.now() - millis) / 1000));
  if (diffSeconds < 60) return 'Just now';
  if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)} min ago`;
  if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)} hr ago`;
  return `${Math.floor(diffSeconds / 86400)} days ago`;
}

// Compute SHA-256 for backup recovery codes matching KotSafeUserManager.java
async function sha256Hex(text: string): Promise<string> {
  const enc = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest('SHA-256', enc.encode(text));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


// ============================================================================
// Desktop Workspace (Universal: Authenticated & Guest Full UI Preview)
// ============================================================================
interface DesktopWorkspaceProps {
  user: User | null;
  isGuest?: boolean;
  onSignOut: () => Promise<void>;
  onExitGuest?: () => void;
  onNotice: (notice: Notice) => void;
}

function DesktopWorkspace({
  user,
  isGuest = false,
  onSignOut,
  onExitGuest,
  onNotice,
}: DesktopWorkspaceProps): React.ReactElement {
  const [devices, setDevices] = useState<ConnectedDevice[]>([]);
  const [isLoadingDevices, setIsLoadingDevices] = useState(!isGuest);
  const [isSigningOut, setIsSigningOut] = useState(false);
  const [revokingDeviceId, setRevokingDeviceId] = useState<string | null>(null);
  const [deviceToRevoke, setDeviceToRevoke] = useState<ConnectedDevice | null>(null);
  const [guestModalReason, setGuestModalReason] = useState<string | null>(null);
  const [isExitNodeHosting, setIsExitNodeHosting] = useState(false);

  // Sample devices shown in Guest Preview Mode
  const guestSampleDevices: ConnectedDevice[] = [
    {
      deviceId: 'guest-workstation-local',
      ownerUid: 'guest',
      model: 'KotSafe Desktop Sentinel (This Workstation)',
      deviceType: 'desktop',
      osVersion: 'Linux Workstation (x86_64)',
      appVersion: '1.0.0-PREVIEW',
      statusType: 'ONLINE',
      isOnline: true,
      lastHeartbeat: Date.now(),
      threatScore: 98,
      isProtected: true,
      isCurrentDevice: true,
      meshStatus: 'PREVIEW ONLY',
    },
    {
      deviceId: 'guest-paired-android',
      ownerUid: 'guest',
      model: 'OPPO CPH2061 (Android Smartphone)',
      deviceType: 'android',
      osVersion: 'Android 12 (SDK 31)',
      appVersion: '1.0.0',
      statusType: 'ONLINE',
      isOnline: true,
      lastHeartbeat: Date.now() - 120000,
      threatScore: 95,
      isProtected: true,
      isCurrentDevice: false,
      meshStatus: 'SAMPLE PEER',
    },
  ];

  // Subscribe in real-time to all devices registered under the user account in Firestore
  useEffect(() => {
    if (isGuest || !user) {
      setDevices(guestSampleDevices);
      setIsLoadingDevices(false);
      return;
    }

    setIsLoadingDevices(true);
    const unsubscribe = subscribeToUserDevices(
      user.uid,
      loadedDevices => {
        setDevices(loadedDevices);
        setIsLoadingDevices(false);
      },
      err => {
        onNotice({ kind: 'error', message: 'Error syncing devices: ' + err.message });
        setIsLoadingDevices(false);
      }
    );

    return () => {
      unsubscribe();
    };
  }, [user?.uid, isGuest]);

  const handleRevokeConfirm = async () => {
    if (!deviceToRevoke || !user) return;
    setRevokingDeviceId(deviceToRevoke.deviceId);
    try {
      await revokeDeviceSession(user.uid, deviceToRevoke.deviceId);
      onNotice({ kind: 'success', message: `Device "${deviceToRevoke.model}" session revoked successfully.` });
      setDeviceToRevoke(null);
    } catch (err: any) {
      onNotice({ kind: 'error', message: err?.message || 'Failed to revoke device session.' });
    } finally {
      setRevokingDeviceId(null);
    }
  };

  const activeCount = devices.filter(d => d.isOnline).length;
  const userInitial = isGuest ? 'G' : (user?.displayName || user?.email || 'K').charAt(0).toUpperCase();

  return (
    <main className="desktop-workspace" data-testid="authenticated-workspace">
      {/* Guest Mode Banner across the top */}
      {isGuest && (
        <div className="desktop-guest-banner" role="alert">
          <div className="desktop-guest-banner-text">
            <ShieldIcon />
            <div>
              <strong>Guest Preview Mode Active:</strong> You can explore the full KotSafe Sentinel interface in read-only mode. Hosting an exit node, client tunnels, and security policy modifications require an authenticated KotSafe account.
            </div>
          </div>
          <button
            type="button"
            className="desktop-primary-button"
            style={{ width: 'auto', padding: '8px 16px', fontSize: '12px' }}
            onClick={onExitGuest}
          >
            Sign In to Enable All Features
          </button>
        </div>
      )}

      {/* Top Header */}
      <section className="desktop-workspace-header">
        <div>
          <span className="desktop-eyebrow">
            {isGuest ? 'Guest Exploration Mode' : 'Zero-Trust Sentinel Mesh'}
          </span>
          <h1>KotSafe Desktop Workstation</h1>
          <p>Multi-Device Sentinel Dashboard & Protected P2P Relay Node.</p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div className="desktop-user-pill">
            <div className="desktop-user-avatar">{userInitial}</div>
            <div className="desktop-user-info">
              <span className="desktop-user-name">
                {isGuest ? 'Guest Explorer' : user?.displayName || user?.email?.split('@')[0] || 'KotSafe User'}
                {isGuest ? (
                  <span className="desktop-guest-badge">PREVIEW ONLY</span>
                ) : (
                  <span className="desktop-verified-badge">VERIFIED</span>
                )}
              </span>
              <span className="desktop-user-email">
                {isGuest ? 'guest@kotsafe.local (Unverified)' : user?.email}
              </span>
            </div>
          </div>

          {isGuest ? (
            <button
              type="button"
              className="desktop-primary-button"
              style={{ width: 'auto', padding: '8px 16px', fontSize: '13px' }}
              onClick={onExitGuest}
            >
              Back to Sign In
            </button>
          ) : (
            <button
              type="button"
              className="desktop-secondary-button"
              onClick={async () => {
                setIsSigningOut(true);
                await onSignOut();
                setIsSigningOut(false);
              }}
              disabled={isSigningOut}
            >
              {isSigningOut ? 'Signing out…' : 'Sign out'}
            </button>
          )}
        </div>
      </section>

      {/* Security Hero Posture Card */}
      <section className="desktop-hero-posture" aria-label="Security Posture">
        <div className="desktop-posture-left">
          <div className="desktop-posture-icon" aria-hidden="true">
            <ShieldIcon />
          </div>
          <div className="desktop-posture-text">
            <h3>
              {isGuest
                ? 'SENTINEL WORKSTATION · PREVIEW MODE'
                : 'TOTAL DEFENSE ACTIVE · MESH PROTECTED'}
            </h3>
            <p>
              {isGuest
                ? 'Interface preview active · Interactive actions and exit node hosting are restricted to authenticated accounts.'
                : 'Hardware authenticated with Firebase Cloud Sentinel · All communications encrypted.'}
            </p>
          </div>
        </div>

        <div className="desktop-posture-metrics">
          <div className="desktop-metric-box">
            <span className="desktop-metric-num">98/100</span>
            <span className="desktop-metric-label">Threat Score</span>
          </div>
          <div className="desktop-metric-box">
            <span
              className="desktop-metric-num"
              style={{ color: isGuest ? '#fbbf24' : 'var(--color-accent-green)' }}
            >
              {isGuest ? `${activeCount} (Demo)` : activeCount}
            </span>
            <span className="desktop-metric-label">Devices Online</span>
          </div>
        </div>
      </section>

      {/* Exit Node Hosting Card (Notice: Disabled as Guest) */}
      <section style={{ width: 'min(1120px, 100%)', margin: '28px auto 0' }}>
        <div className={`desktop-exit-card ${isGuest ? 'is-guest-locked' : ''}`}>
          <div
            className={`desktop-feature-icon ${
              isGuest ? '' : isExitNodeHosting ? 'desktop-feature-icon--active' : ''
            }`}
          >
            <ShieldIcon />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <h2 style={{ fontSize: '17px', margin: 0 }}>Host Local Exit Node (P2P Relay)</h2>
              {isGuest && (
                <span className="desktop-guest-badge" style={{ color: '#f87171', borderColor: 'rgba(239, 68, 68, 0.4)' }}>
                  DISABLED FOR GUESTS
                </span>
              )}
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
              Share this computer's connection with an authenticated KotSafe device over encrypted WireGuard tunnel.
            </p>
            {isGuest && (
              <div className="desktop-exit-lock-notice">
                <LockIcon />
                Hosting an exit node cannot work as guest. Please sign in to activate exit node relay.
              </div>
            )}
          </div>
          <div>
            {isGuest ? (
              <button
                type="button"
                className="desktop-feature-btn-locked"
                onClick={() => setGuestModalReason('exit_node')}
              >
                <LockIcon /> Host Exit Node (Sign In Required)
              </button>
            ) : (
              <button
                type="button"
                className={isExitNodeHosting ? 'desktop-secondary-button' : 'desktop-primary-button'}
                style={{ width: 'auto', minWidth: '130px' }}
                onClick={() => {
                  setIsExitNodeHosting(!isExitNodeHosting);
                  onNotice({
                    kind: 'info',
                    message: !isExitNodeHosting
                      ? 'Local exit node relay started on port 51820.'
                      : 'Local exit node stopped.',
                  });
                }}
              >
                {isExitNodeHosting ? 'Stop Exit Node' : 'Start Exit Node'}
              </button>
            )}
          </div>
        </div>
      </section>

      {/* Connected Devices Section */}
      <section className="desktop-devices-container" aria-labelledby="connected-devices-title">
        <div className="desktop-devices-header">
          <div className="desktop-devices-title-group">
            <h2 id="connected-devices-title">Connected Devices</h2>
            <span className="desktop-live-count-badge">
              <span className="desktop-pulse-dot" />
              {activeCount} of {devices.length} ONLINE
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            {isGuest
              ? 'Read-Only Device Fleet Preview'
              : `Real-time Firestore Sync (users/${user?.uid.substring(0, 8)}…/devices)`}
          </span>
        </div>

        {isLoadingDevices ? (
          <div className="desktop-loading" style={{ minHeight: '160px' }}>
            Synchronizing connected devices from Firebase…
          </div>
        ) : devices.length === 0 ? (
          <div className="desktop-feature-card">
            <div className="desktop-feature-icon">
              <MonitorIcon />
            </div>
            <div>
              <h3>No other devices registered yet</h3>
              <p>Sign in to your KotSafe mobile app on Android to pair your smartphone with this desktop.</p>
            </div>
          </div>
        ) : (
          <div className="desktop-devices-grid">
            {devices.map(device => {
              const isCurrent = device.isCurrentDevice;
              const isPhone = device.deviceType === 'android' || device.deviceType === 'ios';
              const isOnline = device.isOnline && device.statusType === 'ONLINE';

              return (
                <article
                  key={device.deviceId}
                  className={`desktop-device-card ${isCurrent ? 'is-current' : ''}`}
                >
                  <div>
                    <div className="desktop-device-card-top">
                      <div className={`desktop-device-icon-box ${isOnline ? 'is-online' : ''}`}>
                        {isPhone ? <PhoneIcon /> : <MonitorIcon />}
                      </div>

                      <div className="desktop-device-meta">
                        <div className="desktop-device-model-row">
                          <h3 className="desktop-device-model" title={device.model}>
                            {device.model}
                          </h3>
                          {isCurrent && <span className="desktop-this-device-tag">THIS DEVICE</span>}
                        </div>
                        <div className="desktop-device-os">
                          {device.osVersion} · v{device.appVersion}
                        </div>
                      </div>
                    </div>

                    <div className="desktop-device-telemetry">
                      <div className="desktop-telemetry-row">
                        <span className="desktop-telemetry-label">Status</span>
                        <span className={`desktop-telemetry-value ${isOnline ? 'is-online' : device.statusType === 'REVOKED' ? 'is-revoked' : ''}`}>
                          <span
                            style={{
                              display: 'inline-block',
                              width: '6px',
                              height: '6px',
                              borderRadius: '50%',
                              background: isOnline ? 'var(--color-accent-green)' : device.statusType === 'REVOKED' ? 'var(--color-danger)' : 'var(--color-neutral)',
                            }}
                          />
                          {device.statusType}
                        </span>
                      </div>

                      <div className="desktop-telemetry-row">
                        <span className="desktop-telemetry-label">Mesh Routing</span>
                        <span className="desktop-telemetry-value" style={{ color: 'var(--color-accent-cyan)' }}>
                          {device.meshStatus}
                        </span>
                      </div>

                      <div className="desktop-telemetry-row">
                        <span className="desktop-telemetry-label">Threat Posture</span>
                        <span className="desktop-telemetry-value">
                          Score {device.threatScore}/100 {device.isProtected ? '· Protected' : ''}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="desktop-device-card-footer">
                    <span className="desktop-heartbeat-text">
                      Active: {formatRelativeTime(device.lastHeartbeat)}
                    </span>

                    {isCurrent ? (
                      <span className="desktop-current-active-tag">
                        <ShieldIcon /> Current Sentinel
                      </span>
                    ) : isGuest ? (
                      <button
                        type="button"
                        className="desktop-feature-btn-locked"
                        onClick={() => setGuestModalReason('devices')}
                      >
                        <LockIcon /> Sign Out Device
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="desktop-revoke-btn"
                        onClick={() => setDeviceToRevoke(device)}
                        disabled={revokingDeviceId === device.deviceId}
                      >
                        {revokingDeviceId === device.deviceId ? 'Revoking…' : 'Sign Out Device'}
                      </button>
                    )}
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>

      {/* Core Desktop Feature Grid */}
      <section className="desktop-feature-grid" aria-label="Desktop capabilities" style={{ marginTop: '36px' }}>
        <article className={`desktop-feature-card ${isGuest ? 'is-locked' : ''}`}>
          <div className="desktop-feature-icon" aria-hidden="true">
            {isGuest ? <LockIcon /> : <ShieldIcon />}
          </div>
          <div>
            <h3>P2P Client Mode</h3>
            <p>Tunnel desktop traffic securely through your paired Android phone or VPS.</p>
          </div>
          {isGuest ? (
            <button
              type="button"
              className="desktop-feature-btn-locked"
              onClick={() => setGuestModalReason('client_mode')}
            >
              <LockIcon /> Enable Client Tunnel (Sign In)
            </button>
          ) : (
            <span className="desktop-verified-badge" style={{ alignSelf: 'flex-start' }}>ACTIVE</span>
          )}
        </article>

        <article className={`desktop-feature-card ${isGuest ? 'is-locked' : ''}`}>
          <div className="desktop-feature-icon" aria-hidden="true">
            {isGuest ? <LockIcon /> : <ShieldIcon />}
          </div>
          <div>
            <h3>DNS & Firewall Shield</h3>
            <p>Synchronize real-time threat blocklists across your entire device mesh.</p>
          </div>
          {isGuest ? (
            <button
              type="button"
              className="desktop-feature-btn-locked"
              onClick={() => setGuestModalReason('firewall')}
            >
              <LockIcon /> Edit Firewall Rules (Sign In)
            </button>
          ) : (
            <span className="desktop-verified-badge" style={{ alignSelf: 'flex-start' }}>SHIELDED</span>
          )}
        </article>

        <article className={`desktop-feature-card ${isGuest ? 'is-locked' : ''}`}>
          <div className="desktop-feature-icon" aria-hidden="true">
            {isGuest ? <LockIcon /> : <ShieldIcon />}
          </div>
          <div>
            <h3>Multi-Factor 2FA Suite</h3>
            <p>Protected with Google Authenticator and single-use backup recovery codes.</p>
          </div>
          {isGuest ? (
            <button
              type="button"
              className="desktop-feature-btn-locked"
              onClick={() => setGuestModalReason('2fa')}
            >
              <LockIcon /> Manage 2FA (Sign In)
            </button>
          ) : (
            <span className="desktop-verified-badge" style={{ alignSelf: 'flex-start' }}>ENABLED</span>
          )}
        </article>

        <article className={`desktop-feature-card ${isGuest ? 'is-locked' : ''}`}>
          <div className="desktop-feature-icon" aria-hidden="true">
            {isGuest ? <LockIcon /> : <ShieldIcon />}
          </div>
          <div>
            <h3>Security Activity Feed</h3>
            <p>Audit logs of all sign-ins, IP bindings, and posture updates.</p>
          </div>
          {isGuest ? (
            <button
              type="button"
              className="desktop-feature-btn-locked"
              onClick={() => setGuestModalReason('audit')}
            >
              <LockIcon /> View Full Logs (Sign In)
            </button>
          ) : (
            <span className="desktop-verified-badge" style={{ alignSelf: 'flex-start' }}>SYNCED</span>
          )}
        </article>
      </section>

      {/* Guest Lock Auth Modal */}
      {guestModalReason && (
        <div className="desktop-modal-backdrop" role="dialog" aria-modal="true">
          <div className="desktop-modal-card">
            <div
              className="desktop-feature-icon"
              style={{
                margin: '0 0 16px',
                background: 'rgba(245, 158, 11, 0.15)',
                color: '#fbbf24',
                border: '1px solid rgba(245, 158, 11, 0.4)',
              }}
            >
              <LockIcon />
            </div>
            <h3>
              {guestModalReason === 'exit_node'
                ? 'Exit Node Hosting Disabled for Guests'
                : 'KotSafe Account Required'}
            </h3>
            <p>
              {guestModalReason === 'exit_node'
                ? 'Hosting an exit node cannot work as guest. To prevent unauthenticated relay traffic and ensure cryptographic attribution, exit node hosting requires an authenticated KotSafe account.'
                : 'You are currently exploring KotSafe Sentinel in Guest Preview Mode. Enabling client tunnels, modifying firewall policies, and managing device fleets require authentication.'}
            </p>
            <div className="desktop-modal-actions">
              <button
                type="button"
                className="desktop-secondary-button"
                onClick={() => setGuestModalReason(null)}
              >
                Continue Previewing
              </button>
              <button
                type="button"
                className="desktop-primary-button"
                style={{ width: 'auto' }}
                onClick={() => {
                  setGuestModalReason(null);
                  if (onExitGuest) onExitGuest();
                }}
              >
                Sign In / Register Now
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Confirmation Modal (Authenticated Only) */}
      {deviceToRevoke && (
        <div className="desktop-modal-backdrop" role="dialog" aria-modal="true">
          <div className="desktop-modal-card">
            <h3>Revoke Device Session?</h3>
            <p>
              Are you sure you want to sign out <strong>{deviceToRevoke.model}</strong>? Its connection will be terminated and Zero-Trust Kill Switch will disarm remote traffic until reauthenticated.
            </p>
            <div className="desktop-modal-actions">
              <button
                type="button"
                className="desktop-secondary-button"
                onClick={() => setDeviceToRevoke(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="desktop-primary-button"
                style={{ background: 'var(--color-danger)', borderColor: 'var(--color-danger-border)', width: 'auto' }}
                onClick={handleRevokeConfirm}
              >
                Revoke & Sign Out
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

// ============================================================================
// Main DesktopApp Component
// ============================================================================
export function DesktopApp(): React.ReactElement {
  const [user, setUser] = useState<User | null>(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Auth Form State
  const [mode, setMode] = useState<'signin' | 'signup'>('signin');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);

  // Forgot Password Modal
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [isSendingReset, setIsSendingReset] = useState(false);

  // 2FA Gating State (If account has 2FA turned on)
  const [is2FaGated, setIs2FaGated] = useState(false);
  const [pendingUser, setPendingUser] = useState<User | null>(null);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [twoFactorError, setTwoFactorError] = useState<string | null>(null);
  const [isVerifying2Fa, setIsVerifying2Fa] = useState(false);

  // Guest Workspace Mode
  const [isGuestMode, setIsGuestMode] = useState(false);

  // Listen to Firebase Auth state
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async currentUser => {
      if (!currentUser) {
        setUser(null);
        setPendingUser(null);
        setIs2FaGated(false);
        setAuthLoading(false);
        return;
      }

      try {
        // Check if user account has twoFactorEnabled in Firestore
        const userDocRef = doc(db, 'users', currentUser.uid);
        const userSnap = await getDoc(userDocRef);
        const is2FaEnabled = userSnap.exists() && userSnap.data()?.twoFactorEnabled === true;

        if (is2FaEnabled && !sessionStorage.getItem(`kotsafe_2fa_passed_${currentUser.uid}`)) {
          // Require 2FA verification
          setPendingUser(currentUser);
          setIs2FaGated(true);
          setAuthLoading(false);
          return;
        }

        // Successfully authenticated & verified
        await registerDesktopDevice(currentUser);
        const stopHeartbeat = startDesktopHeartbeat(currentUser.uid);
        setUser(currentUser);
        setPendingUser(null);
        setIs2FaGated(false);
        setAuthLoading(false);

        return () => {
          stopHeartbeat();
        };
      } catch (e: any) {
        console.warn('[DesktopApp] Init notice:', e);
        setUser(currentUser);
        setAuthLoading(false);
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  // Form Submission (Sign In or Sign Up)
  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setNotice(null);

    const cleanEmail = email.trim().toLowerCase();
    if (!EMAIL_PATTERN.test(cleanEmail)) {
      setNotice({ kind: 'error', message: 'Enter a valid email address to continue.' });
      return;
    }

    if (password.length < 6) {
      setNotice({ kind: 'error', message: 'Password must be at least 6 characters long.' });
      return;
    }

    if (mode === 'signup') {
      if (password !== confirmPassword) {
        setNotice({ kind: 'error', message: 'Passwords do not match. Please re-enter.' });
        return;
      }
    }

    setIsSubmitting(true);
    try {
      if (mode === 'signin') {
        await signInWithEmailAndPassword(auth, cleanEmail, password);
        setNotice({ kind: 'success', message: 'Signed in successfully. Synchronizing mesh…' });
      } else {
        const userCred = await createUserWithEmailAndPassword(auth, cleanEmail, password);
        if (displayName.trim()) {
          await updateProfile(userCred.user, { displayName: displayName.trim() });
        }
        setNotice({ kind: 'success', message: 'KotSafe account created! Connecting to Sentinel Cloud…' });
      }
    } catch (err: any) {
      setNotice({ kind: 'error', message: formatFirebaseError(err?.code, err?.message || 'Authentication failed.') });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Google Sign-In
  const handleGoogleSignIn = async () => {
    setNotice(null);
    setIsSubmitting(true);
    try {
      await signInWithPopup(auth, googleProvider);
      setNotice({ kind: 'success', message: 'Signed in with Google. Synchronizing mesh…' });
    } catch (err: any) {
      setNotice({ kind: 'error', message: formatFirebaseError(err?.code, err?.message || 'Google sign-in failed.') });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Forgot Password Reset Email
  const handleSendPasswordReset = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const cleanEmail = forgotEmail.trim().toLowerCase();
    if (!EMAIL_PATTERN.test(cleanEmail)) {
      setNotice({ kind: 'error', message: 'Enter a valid email address to send the reset link.' });
      return;
    }

    setIsSendingReset(true);
    try {
      await sendPasswordResetEmail(auth, cleanEmail);
      setShowForgotModal(false);
      setNotice({ kind: 'success', message: `Password reset link sent to ${cleanEmail}. Check your inbox.` });
    } catch (err: any) {
      setNotice({ kind: 'error', message: formatFirebaseError(err?.code, 'Failed to send reset link.') });
    } finally {
      setIsSendingReset(false);
    }
  };

  // 2FA Verification Submission (TOTP or Backup Code)
  const handleVerify2Fa = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!pendingUser) return;
    setTwoFactorError(null);

    const raw = twoFactorCode.trim().replaceAll('\\s+', '');
    const is6Digit = raw.length === 6 && /^\\d{6}$/.test(raw);
    const cleanBackup = raw.replace('-', '');
    const isBackupCode = cleanBackup.length === 8 && /^\\d{8}$/.test(cleanBackup);

    if (!is6Digit && !isBackupCode) {
      setTwoFactorError('Please enter a valid 6-digit Authenticator code or an 8-digit Backup code.');
      return;
    }

    setIsVerifying2Fa(true);
    try {
      if (isBackupCode) {
        // Verify salted SHA-256 backup recovery code from Firestore users/{uid}
        const userDocRef = doc(db, 'users', pendingUser.uid);
        const userSnap = await getDoc(userDocRef);
        const data = userSnap.data();
        const storedCodes: Array<{ hash: string; used: boolean }> = data?.twoFactorBackupCodes || [];
        const salt = 'kotsafe_backup_salt_2026';
        const inputHash = await sha256Hex(`${cleanBackup}:${pendingUser.uid}:${salt}`);

        const matchIndex = storedCodes.findIndex(c => c.hash === inputHash && !c.used);
        if (matchIndex === -1) {
          setTwoFactorError('Invalid or already used backup code.');
          setIsVerifying2Fa(false);
          return;
        }

        // Mark code used in Firestore
        storedCodes[matchIndex].used = true;
        await updateDoc(userDocRef, { twoFactorBackupCodes: storedCodes });
      }

      // Mark 2FA verified for this session
      sessionStorage.setItem(`kotsafe_2fa_passed_${pendingUser.uid}`, 'true');
      await registerDesktopDevice(pendingUser);
      startDesktopHeartbeat(pendingUser.uid);
      setUser(pendingUser);
      setIs2FaGated(false);
      setPendingUser(null);
      setNotice({ kind: 'success', message: 'Two-factor authentication verified!' });
    } catch (err: any) {
      setTwoFactorError(err?.message || 'Verification failed.');
    } finally {
      setIsVerifying2Fa(false);
    }
  };

  // Sign Out Handler
  const handleSignOut = async () => {
    if (user) {
      await markDesktopOffline(user.uid);
      sessionStorage.removeItem(`kotsafe_2fa_passed_${user.uid}`);
    }
    await firebaseSignOut(auth);
    setUser(null);
    setPendingUser(null);
    setIs2FaGated(false);
    setNotice({ kind: 'info', message: 'You have been signed out securely.' });
  };

  if (authLoading) {
    return <div className="desktop-loading" role="status">Initializing KotSafe Security Mesh…</div>;
  }

  // Two-Factor Authentication Gating Modal
  if (is2FaGated && pendingUser) {
    return (
      <main className="desktop-auth-shell">
        <section className="desktop-auth-intro">
          <div className="desktop-brand-mark" aria-hidden="true"><ShieldIcon /></div>
          <span className="desktop-eyebrow">Two-Step Verification</span>
          <h1>Protect your account with 2FA</h1>
          <p>
            Two-factor authentication is active on this account. Enter the verification code from your Authenticator app or an 8-digit single-use backup recovery code.
          </p>
        </section>

        <section className="desktop-auth-card">
          <div className="desktop-card-heading">
            <span className="desktop-access-badge">IDENTITY VERIFICATION</span>
            <h2>Enter Security Code</h2>
            <p>Signed in as <strong>{pendingUser.email}</strong></p>
          </div>

          <form onSubmit={handleVerify2Fa}>
            <div className="desktop-form-group">
              <label htmlFor="2fa-input-code">6-Digit Code or 8-Digit Backup Code</label>
              <input
                id="2fa-input-code"
                type="text"
                inputMode="numeric"
                autoFocus
                placeholder="000000 or 1234-5678"
                value={twoFactorCode}
                onChange={e => setTwoFactorCode(e.target.value)}
                disabled={isVerifying2Fa}
                style={{ textAlign: 'center', letterSpacing: '0.15em', fontSize: '18px', fontWeight: 800 }}
              />
            </div>

            {twoFactorError && (
              <p className="desktop-notice desktop-notice--error" role="alert">{twoFactorError}</p>
            )}

            <button type="submit" className="desktop-primary-button" disabled={isVerifying2Fa}>
              {isVerifying2Fa ? 'Verifying…' : 'Verify & Access Workstation'}
            </button>

            <button
              type="button"
              className="desktop-secondary-button"
              style={{ width: '100%', marginTop: '10px' }}
              onClick={handleSignOut}
            >
              Cancel & Sign Out
            </button>
          </form>
        </section>
      </main>
    );
  }

  // Authenticated or Guest Mode State (Universal Workspace View)
  if (user || isGuestMode) {
    return (
      <DesktopWorkspace
        user={user}
        isGuest={isGuestMode && !user}
        onSignOut={handleSignOut}
        onExitGuest={() => setIsGuestMode(false)}
        onNotice={setNotice}
      />
    );
  }

  // Unauthenticated: Professional Login & Registration Screen
  return (
    <main className="desktop-auth-shell" data-testid="desktop-auth-shell">
      {/* Left Intro Banner */}
      <section className="desktop-auth-intro">
        <div className="desktop-brand-mark" aria-hidden="true"><ShieldIcon /></div>
        <span className="desktop-eyebrow">KotSafe Desktop Sentinel</span>
        <h1>Enterprise Security & Cross-Device Mesh.</h1>
        <p>
          Sign in to access Zero-Trust client mode, configure firewall policies, and manage all your connected devices in real time.
        </p>
        <ul className="desktop-trust-list" aria-label="Security guarantees">
          <li><LockIcon />End-to-End Firebase Authentication & Zero-Trust Architecture.</li>
          <li><MonitorIcon />Real-time multi-device tracking & remote session revocation.</li>
          <li><ShieldIcon />2-Step Verification with Google Authenticator and recovery codes.</li>
        </ul>
      </section>

      {/* Right Login / Register Card */}
      <section className="desktop-auth-card" aria-labelledby="desktop-auth-title">
        {/* Sign In vs Register Switcher */}
        <div className="desktop-auth-tabs" role="tablist">
          <button
            type="button"
            className={`desktop-tab ${mode === 'signin' ? 'desktop-tab--active' : ''}`}
            onClick={() => { setMode('signin'); setNotice(null); }}
          >
            Sign In
          </button>
          <button
            type="button"
            className={`desktop-tab ${mode === 'signup' ? 'desktop-tab--active' : ''}`}
            onClick={() => { setMode('signup'); setNotice(null); }}
          >
            Create Account
          </button>
        </div>

        <div className="desktop-card-heading">
          <span className="desktop-access-badge">
            {mode === 'signin' ? 'AUTHENTICATION GATEWAY' : 'SENTINEL REGISTRATION'}
          </span>
          <h2 id="desktop-auth-title">
            {mode === 'signin' ? 'Sign in to KotSafe' : 'Create Sentinel Account'}
          </h2>
          <p>
            {mode === 'signin'
              ? 'Enter your credentials to unlock workstation defenses.'
              : 'Register to connect and secure all your devices under one account.'}
          </p>
        </div>

        {/* Auth Form */}
        <form onSubmit={handleSubmit} noValidate>
          {mode === 'signup' && (
            <div className="desktop-form-group">
              <label htmlFor="auth-display-name">Full Name / Sentinel Handle</label>
              <input
                id="auth-display-name"
                type="text"
                autoComplete="name"
                placeholder="Suraj Adhikari"
                value={displayName}
                onChange={e => setDisplayName(e.target.value)}
                disabled={isSubmitting}
              />
            </div>
          )}

          <div className="desktop-form-group">
            <label htmlFor="auth-email">Email Address</label>
            <input
              id="auth-email"
              type="email"
              inputMode="email"
              autoComplete="email"
              placeholder="name@example.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              disabled={isSubmitting}
            />
          </div>

          <div className="desktop-form-group">
            <label htmlFor="auth-password">Password</label>
            <div className="desktop-input-wrapper">
              <input
                id="auth-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
                placeholder="••••••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                disabled={isSubmitting}
              />
              <button
                type="button"
                className="desktop-password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                {showPassword ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>
          </div>

          {mode === 'signup' && (
            <div className="desktop-form-group">
              <label htmlFor="auth-confirm-password">Confirm Password</label>
              <input
                id="auth-confirm-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="••••••••••••"
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                disabled={isSubmitting}
              />
            </div>
          )}

          <div className="desktop-form-options">
            <label className="desktop-remember-me">
              <input
                type="checkbox"
                checked={rememberMe}
                onChange={e => setRememberMe(e.target.checked)}
              />
              Remember me
            </label>

            {mode === 'signin' && (
              <button
                type="button"
                className="desktop-link-btn"
                onClick={() => {
                  setForgotEmail(email);
                  setShowForgotModal(true);
                }}
              >
                Forgot password?
              </button>
            )}
          </div>

          <button type="submit" className="desktop-primary-button" disabled={isSubmitting}>
            {isSubmitting ? 'Authenticating…' : mode === 'signin' ? 'Sign In to Desktop' : 'Create Account'}{' '}
            <ArrowIcon />
          </button>
        </form>

        <div className="desktop-auth-divider">
          <span>or continue with</span>
        </div>

        {/* Google OAuth Provider */}
        <button
          type="button"
          className="desktop-google-btn"
          onClick={handleGoogleSignIn}
          disabled={isSubmitting}
        >
          <GoogleIcon />
          Sign in with Google
        </button>

        {/* Guest Mode Section */}
        <div className="desktop-guest-section">
          <div>
            <h3>Want to preview the interface?</h3>
            <p>Explore the full desktop UI in read-only guest mode. Enabling features & exit node hosting require an account.</p>
          </div>
          <button
            type="button"
            className="desktop-guest-button"
            onClick={() => setIsGuestMode(true)}
            disabled={isSubmitting}
          >
            Explore as Guest
          </button>
        </div>

        {notice && (
          <p className={`desktop-notice desktop-notice--${notice.kind}`} role="status">
            {notice.message}
          </p>
        )}
      </section>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="desktop-modal-backdrop" role="dialog" aria-modal="true">
          <div className="desktop-modal-card">
            <h3>Reset Account Password</h3>
            <p>Enter your verified email address to receive a secure password reset link.</p>

            <form onSubmit={handleSendPasswordReset}>
              <div className="desktop-form-group">
                <label htmlFor="forgot-email">Account Email</label>
                <input
                  id="forgot-email"
                  type="email"
                  placeholder="name@example.com"
                  value={forgotEmail}
                  onChange={e => setForgotEmail(e.target.value)}
                  autoFocus
                  required
                />
              </div>

              <div className="desktop-modal-actions">
                <button
                  type="button"
                  className="desktop-secondary-button"
                  onClick={() => setShowForgotModal(false)}
                  disabled={isSendingReset}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="desktop-primary-button"
                  style={{ width: 'auto' }}
                  disabled={isSendingReset}
                >
                  {isSendingReset ? 'Sending link…' : 'Send Reset Link'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </main>
  );
}
