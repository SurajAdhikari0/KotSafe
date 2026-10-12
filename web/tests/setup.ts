import '@testing-library/jest-dom';
import { vi } from 'vitest';
import { webcrypto } from 'node:crypto';

// Polyfill web crypto for jsdom in tests if needed
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    writable: true,
  });
}

// Polyfill BroadcastChannel if not available
if (typeof globalThis.BroadcastChannel === 'undefined') {
  class MockBroadcastChannel {
    name: string;
    onmessage: ((event: MessageEvent) => void) | null = null;
    private static channels = new Map<string, Set<MockBroadcastChannel>>();

    constructor(name: string) {
      this.name = name;
      if (!MockBroadcastChannel.channels.has(name)) {
        MockBroadcastChannel.channels.set(name, new Set());
      }
      MockBroadcastChannel.channels.get(name)!.add(this);
    }

    postMessage(data: unknown) {
      const peers = MockBroadcastChannel.channels.get(this.name);
      if (peers) {
        peers.forEach(channel => {
          if (channel !== this && channel.onmessage) {
            channel.onmessage(new MessageEvent('message', { data }));
          }
        });
      }
    }

    close() {
      const peers = MockBroadcastChannel.channels.get(this.name);
      if (peers) {
        peers.delete(this);
      }
    }
  }
  // @ts-expect-error polyfill
  globalThis.BroadcastChannel = MockBroadcastChannel;
}

// Mock clipboard
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn().mockImplementation(() => Promise.resolve()),
    readText: vi.fn().mockImplementation(() => Promise.resolve('KOT-PRO-ABCD1234-EF56')),
  },
});
