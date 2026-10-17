/**
 * The only authentication surface exposed to the desktop renderer.
 *
 * Electron/Tauri/native code owns browser launch, the localhost callback,
 * token exchange, and OS-backed secret storage. No Firebase ID token,
 * refresh token, or Admin credential is ever exposed to React or localStorage.
 */
export type DesktopAuthProvider = 'email' | 'google' | 'github';

export interface DesktopSession {
  uid: string;
  displayName: string | null;
  email: string | null;
  expiresAt: string | null;
}

export interface BrowserLoginRequest {
  provider: DesktopAuthProvider;
  emailHint?: string;
}

export interface DesktopAuthBridge {
  getSession(): Promise<DesktopSession | null>;
  beginBrowserLogin(request: BrowserLoginRequest): Promise<void>;
  beginGuestSession(): Promise<void>;
  startGuestExitNode(): Promise<void>;
  signOut(): Promise<void>;
  subscribeToSessionChanges(listener: (session: DesktopSession | null) => void): () => void;
}

declare global {
  interface Window {
    kotSafeDesktop?: DesktopAuthBridge;
  }
}

export function getDesktopAuthBridge(): DesktopAuthBridge | null {
  return window.kotSafeDesktop ?? null;
}
