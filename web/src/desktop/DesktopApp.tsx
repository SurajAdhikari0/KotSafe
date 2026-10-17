import React, { FormEvent, useEffect, useState } from 'react';
import {
  DesktopAccessMode,
  accessModeLabel,
  canUseDesktopCapability,
} from './accessPolicy.ts';
import {
  DesktopAuthBridge,
  DesktopAuthProvider,
  DesktopSession,
  getDesktopAuthBridge,
} from './desktopAuthBridge.ts';
import '../styles/desktop.css';

type Notice = { kind: 'error' | 'info' | 'success'; message: string } | null;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function useDesktopSession(): {
  accessMode: DesktopAccessMode;
  session: DesktopSession | null;
  bridge: DesktopAuthBridge | null;
} {
  const [accessMode, setAccessMode] = useState<DesktopAccessMode>('loading');
  const [session, setSession] = useState<DesktopSession | null>(null);
  const bridge = getDesktopAuthBridge();

  useEffect(() => {
    let isMounted = true;
    if (!bridge) {
      setAccessMode('signed_out');
      return undefined;
    }

    const applySession = (nextSession: DesktopSession | null) => {
      if (!isMounted) return;
      setSession(nextSession);
      setAccessMode(nextSession ? 'authenticated' : 'signed_out');
    };

    bridge.getSession().then(applySession).catch(() => applySession(null));
    const unsubscribe = bridge.subscribeToSessionChanges(applySession);

    return () => {
      isMounted = false;
      unsubscribe();
    };
  }, [bridge]);

  return { accessMode, session, bridge };
}

interface FeatureCardProps {
  title: string;
  description: string;
  locked?: boolean;
}

function FeatureCard({ title, description, locked = false }: FeatureCardProps): React.ReactElement {
  return (
    <article className={`desktop-feature-card ${locked ? 'is-locked' : ''}`}>
      <div className="desktop-feature-icon" aria-hidden="true">
        {locked ? <LockIcon /> : <ShieldIcon />}
      </div>
      <div>
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
      {locked && <span className="desktop-locked-label">Sign in required</span>}
    </article>
  );
}

interface GuestWorkspaceProps {
  bridge: DesktopAuthBridge;
  onSignIn: () => void;
  onNotice: (notice: Notice) => void;
}

function GuestWorkspace({ bridge, onSignIn, onNotice }: GuestWorkspaceProps): React.ReactElement {
  const [isStartingExitNode, setIsStartingExitNode] = useState(false);
  const canHostExitNode = canUseDesktopCapability('guest', 'guest_exit_node');

  const startExitNode = async () => {
    if (!canHostExitNode || isStartingExitNode) return;
    setIsStartingExitNode(true);
    onNotice(null);
    try {
      await bridge.startGuestExitNode();
      onNotice({ kind: 'success', message: 'Guest exit node started. Client mode remains locked.' });
    } catch (error) {
      onNotice({ kind: 'error', message: getErrorMessage(error, 'Unable to start the guest exit node.') });
    } finally {
      setIsStartingExitNode(false);
    }
  };

  return (
    <main className="desktop-workspace" data-testid="guest-workspace">
      <section className="desktop-workspace-header">
        <div>
          <span className="desktop-eyebrow">Guest session</span>
          <h1>Exit Node host</h1>
          <p>Guest access is isolated to hosting a local exit node. It cannot join another node or change security policy.</p>
        </div>
        <button type="button" className="desktop-secondary-button" onClick={onSignIn}>
          Sign in to unlock
        </button>
      </section>

      <section className="desktop-guest-grid" aria-label="Guest capabilities">
        <article className="desktop-exit-card">
          <div className="desktop-feature-icon desktop-feature-icon--active" aria-hidden="true">
            <ShieldIcon />
          </div>
          <div>
            <span className="desktop-status-dot">Available in guest mode</span>
            <h2>Host exit node</h2>
            <p>Share this computer's connection with an already paired KotSafe device.</p>
          </div>
          <button
            type="button"
            className="desktop-primary-button"
            onClick={startExitNode}
            disabled={isStartingExitNode}
          >
            {isStartingExitNode ? 'Starting…' : 'Start exit node'}
          </button>
        </article>

        <div className="desktop-feature-grid" aria-label="Locked capabilities">
          <FeatureCard title="Client mode" description="Connect this computer through a KotSafe exit node." locked />
          <FeatureCard title="Security settings" description="Manage firewall, DNS, and device policy." locked />
          <FeatureCard title="Mesh pairing" description="Pair devices and manage encrypted routes." locked />
          <FeatureCard title="Cloud sync" description="Back up settings and receive account updates." locked />
        </div>
      </section>
    </main>
  );
}

interface AuthenticatedWorkspaceProps {
  session: DesktopSession;
  bridge: DesktopAuthBridge;
  onNotice: (notice: Notice) => void;
}

function AuthenticatedWorkspace({ session, bridge, onNotice }: AuthenticatedWorkspaceProps): React.ReactElement {
  const [isSigningOut, setIsSigningOut] = useState(false);

  const signOut = async () => {
    setIsSigningOut(true);
    try {
      await bridge.signOut();
    } catch (error) {
      onNotice({ kind: 'error', message: getErrorMessage(error, 'Unable to sign out securely.') });
    } finally {
      setIsSigningOut(false);
    }
  };

  return (
    <main className="desktop-workspace" data-testid="authenticated-workspace">
      <section className="desktop-workspace-header">
        <div>
          <span className="desktop-eyebrow">Protected workspace</span>
          <h1>Welcome{session.displayName ? `, ${session.displayName}` : ''}</h1>
          <p>{session.email ?? 'Verified KotSafe account'} · all desktop controls are available.</p>
        </div>
        <button type="button" className="desktop-secondary-button" onClick={signOut} disabled={isSigningOut}>
          {isSigningOut ? 'Signing out…' : 'Sign out'}
        </button>
      </section>

      <section className="desktop-feature-grid" aria-label="Desktop capabilities">
        <FeatureCard title="Client mode" description="Connect this computer through a trusted KotSafe exit node." />
        <FeatureCard title="Security settings" description="Manage firewall, DNS, and device policy." />
        <FeatureCard title="Mesh pairing" description="Pair devices and manage encrypted routes." />
        <FeatureCard title="Cloud sync" description="Keep trusted settings and devices in sync." />
      </section>
    </main>
  );
}

export function DesktopApp(): React.ReactElement {
  const { accessMode, session, bridge } = useDesktopSession();
  const [email, setEmail] = useState('');
  const [isOpeningBrowser, setIsOpeningBrowser] = useState(false);
  const [isEnteringGuestMode, setIsEnteringGuestMode] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [showGuestWorkspace, setShowGuestWorkspace] = useState(false);

  const beginBrowserLogin = async (provider: DesktopAuthProvider, event?: FormEvent<HTMLFormElement>) => {
    event?.preventDefault();
    const emailHint = email.trim().toLowerCase();
    if (provider === 'email' && !EMAIL_PATTERN.test(emailHint)) {
      setNotice({ kind: 'error', message: 'Enter a valid email address to continue securely.' });
      return;
    }
    if (!bridge) {
      setNotice({ kind: 'error', message: 'The secure desktop host is unavailable. Browser authentication cannot start.' });
      return;
    }

    setIsOpeningBrowser(true);
    setNotice(null);
    try {
      await bridge.beginBrowserLogin({ provider, emailHint: emailHint || undefined });
      setNotice({ kind: 'info', message: 'Your browser has opened. Complete sign-in there, then return to KotSafe.' });
    } catch (error) {
      setNotice({ kind: 'error', message: getErrorMessage(error, 'Unable to open secure browser sign-in.') });
    } finally {
      setIsOpeningBrowser(false);
    }
  };

  const enterGuestMode = async () => {
    if (!bridge) {
      setNotice({ kind: 'error', message: 'The secure desktop host is unavailable. Guest exit-node mode cannot start.' });
      return;
    }

    setIsEnteringGuestMode(true);
    setNotice(null);
    try {
      await bridge.beginGuestSession();
      setShowGuestWorkspace(true);
    } catch (error) {
      setNotice({ kind: 'error', message: getErrorMessage(error, 'Unable to start guest mode.') });
    } finally {
      setIsEnteringGuestMode(false);
    }
  };

  if (accessMode === 'loading') {
    return <div className="desktop-loading" role="status">Checking secure session…</div>;
  }

  if (accessMode === 'authenticated' && session && bridge) {
    return <AuthenticatedWorkspace session={session} bridge={bridge} onNotice={setNotice} />;
  }

  if (showGuestWorkspace && bridge) {
    return <GuestWorkspace bridge={bridge} onSignIn={() => setShowGuestWorkspace(false)} onNotice={setNotice} />;
  }

  return (
    <main className="desktop-auth-shell" data-testid="desktop-auth-shell">
      <section className="desktop-auth-intro">
        <div className="desktop-brand-mark" aria-hidden="true"><ShieldIcon /></div>
        <span className="desktop-eyebrow">KotSafe desktop</span>
        <h1>Security starts with a verified session.</h1>
        <p>
          Sign in to manage client mode, protected routing, mesh pairing, and security settings.
        </p>
        <ul className="desktop-trust-list" aria-label="Security guarantees">
          <li><LockIcon />Credentials are entered only on the secure KotSafe browser page.</li>
          <li><ShieldIcon />Guest mode is limited to hosting an exit node.</li>
          <li><ShieldIcon />Client mode and all settings require sign-in.</li>
        </ul>
      </section>

      <section className="desktop-auth-card" aria-labelledby="desktop-auth-title">
        <div className="desktop-card-heading">
          <span className="desktop-access-badge">{accessModeLabel('signed_out')}</span>
          <h2 id="desktop-auth-title">Sign in to KotSafe</h2>
          <p>Continue securely in your default browser with Firebase Authentication.</p>
        </div>

        <form onSubmit={event => void beginBrowserLogin('email', event)} noValidate>
          <label htmlFor="desktop-auth-email">Email address</label>
          <input
            id="desktop-auth-email"
            type="email"
            inputMode="email"
            autoComplete="email"
            value={email}
            onChange={event => setEmail(event.target.value)}
            placeholder="you@example.com"
            disabled={isOpeningBrowser || isEnteringGuestMode}
          />
          <button type="submit" className="desktop-primary-button" disabled={isOpeningBrowser || isEnteringGuestMode}>
            {isOpeningBrowser ? 'Opening secure browser…' : 'Continue securely'} <ArrowIcon />
          </button>
        </form>

        <div className="desktop-auth-divider"><span>or continue with</span></div>
        <div className="desktop-provider-actions">
          <button type="button" onClick={() => void beginBrowserLogin('google')} disabled={isOpeningBrowser || isEnteringGuestMode}>
            Google
          </button>
          <button type="button" onClick={() => void beginBrowserLogin('github')} disabled={isOpeningBrowser || isEnteringGuestMode}>
            GitHub
          </button>
        </div>

        <div className="desktop-guest-section">
          <div>
            <h3>Need to host an exit node only?</h3>
            <p>Guest mode has no client routing, mesh pairing, cloud sync, or settings access.</p>
          </div>
          <button type="button" className="desktop-guest-button" onClick={() => void enterGuestMode()} disabled={isOpeningBrowser || isEnteringGuestMode}>
            {isEnteringGuestMode ? 'Preparing guest mode…' : 'Continue as guest'}
          </button>
        </div>

        {notice && <p className={`desktop-notice desktop-notice--${notice.kind}`} role="status">{notice.message}</p>}
      </section>
    </main>
  );
}
