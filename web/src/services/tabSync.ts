/**
 * KotSafe Multi-Tab License Synchronizer
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Synchronizes license state across multiple browser tabs and windows in real-time
 * using BroadcastChannel with storage event fallback.
 */

import { CachedLicenseData } from '../types/license.ts';

export type TabSyncMessage =
  | { type: 'LICENSE_ACTIVATED'; payload: CachedLicenseData }
  | { type: 'LICENSE_DEACTIVATED' }
  | { type: 'LICENSE_UPDATED'; payload: CachedLicenseData };

export class TabSyncManager {
  private channel: BroadcastChannel | null = null;
  private listeners: Set<(message: TabSyncMessage) => void> = new Set();
  private channelName = 'kotsafe_license_sync_v2';
  private storageKey = 'kotsafe_tab_sync_ping';

  constructor() {
    this.init();
  }

  private init() {
    if (typeof globalThis.BroadcastChannel !== 'undefined') {
      try {
        this.channel = new BroadcastChannel(this.channelName);
        this.channel.onmessage = (event: MessageEvent<TabSyncMessage>) => {
          if (event.data && event.data.type) {
            this.notify(event.data);
          }
        };
      } catch {
        this.channel = null;
      }
    }

    // Fallback: window storage event
    if (typeof window !== 'undefined') {
      window.addEventListener('storage', (event: StorageEvent) => {
        if (event.key === this.storageKey && event.newValue) {
          try {
            const message: TabSyncMessage = JSON.parse(event.newValue);
            this.notify(message);
          } catch {
            // ignore
          }
        }
      });
    }
  }

  public broadcast(message: TabSyncMessage): void {
    if (this.channel) {
      try {
        this.channel.postMessage(message);
      } catch {
        // Broadcast failed
      }
    }

    // Also dispatch storage ping for fallback
    if (typeof localStorage !== 'undefined') {
      try {
        localStorage.setItem(this.storageKey, JSON.stringify(message));
      } catch {
        // ignore
      }
    }
  }

  public subscribe(callback: (message: TabSyncMessage) => void): () => void {
    this.listeners.add(callback);
    return () => {
      this.listeners.delete(callback);
    };
  }

  private notify(message: TabSyncMessage) {
    this.listeners.forEach(cb => {
      try {
        cb(message);
      } catch (err) {
        console.error('[TabSync] Listener error:', err);
      }
    });
  }

  public destroy() {
    if (this.channel) {
      this.channel.close();
      this.channel = null;
    }
    this.listeners.clear();
  }
}

export const tabSyncManager = new TabSyncManager();
