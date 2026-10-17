import { describe, expect, it, beforeEach } from 'vitest';
import {
  getDesktopDeviceId,
  detectDesktopPlatform,
} from '../src/services/desktopDeviceManager';

describe('Desktop Device Manager', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('generates a stable desktop device ID and persists to localStorage', () => {
    const id1 = getDesktopDeviceId();
    expect(id1).toMatch(/^desktop_[a-z0-9]+_[a-z0-9]+$/);

    const id2 = getDesktopDeviceId();
    expect(id2).toBe(id1);
  });

  it('detects desktop platform and returns model and OS strings', () => {
    const platform = detectDesktopPlatform();
    expect(platform).toBeDefined();
    expect(typeof platform.os).toBe('string');
    expect(typeof platform.model).toBe('string');
    expect(platform.model.length).toBeGreaterThan(0);
  });
});
