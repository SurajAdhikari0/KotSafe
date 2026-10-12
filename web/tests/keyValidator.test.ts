import { describe, it, expect } from 'vitest';
import {
  normalizeLicenseKey,
  validateKeyFormat,
  maskKey,
} from '../src/core/keyValidator.ts';

describe('Key Format Validator & Masker', () => {
  describe('normalizeLicenseKey', () => {
    it('trims whitespace and auto-uppercases', () => {
      const input = '  kot-pro-abcd1234-ef56  ';
      expect(normalizeLicenseKey(input)).toBe('KOT-PRO-ABCD1234-EF56');
    });

    it('replaces spaces and underscores with dashes', () => {
      const input = 'kot pro abcd1234 ef56';
      expect(normalizeLicenseKey(input)).toBe('KOT-PRO-ABCD1234-EF56');
    });

    it('cleans duplicate dashes', () => {
      const input = 'KOT--PRO---ABCD1234--EF56';
      expect(normalizeLicenseKey(input)).toBe('KOT-PRO-ABCD1234-EF56');
    });

    it('strips malicious and invalid injection characters', () => {
      const input = '<script>KOT-PRO-ABCD1234-EF56</script>';
      expect(normalizeLicenseKey(input)).toBe('SCRIPTKOT-PRO-ABCD1234-EF56SCRIPT');
    });
  });

  describe('validateKeyFormat', () => {
    it('fails on empty string', () => {
      const res = validateKeyFormat('');
      expect(res.isValid).toBe(false);
      expect(res.error).toContain('cannot be empty');
    });

    it('fails when prefix is not KOT-', () => {
      const res = validateKeyFormat('XYZ-PRO-ABCD1234-EF56');
      expect(res.isValid).toBe(false);
      expect(res.error).toContain('must begin with "KOT-"');
    });

    it('fails on unknown plan tier', () => {
      const res = validateKeyFormat('KOT-UNKNOWN-ABCD1234-EF56');
      expect(res.isValid).toBe(false);
      expect(res.error).toContain('Unknown plan tier');
    });

    it('fails when parts are missing or incomplete', () => {
      const res = validateKeyFormat('KOT-PRO-123');
      expect(res.isValid).toBe(false);
      expect(res.error).toContain('incomplete');
    });

    it('accepts valid PRO license key format', () => {
      const res = validateKeyFormat('kot-pro-abcd1234-ef56');
      expect(res.isValid).toBe(true);
      expect(res.normalized).toBe('KOT-PRO-ABCD1234-EF56');
    });

    it('accepts valid ENTERPRISE license key format', () => {
      const res = validateKeyFormat('KOT-ENT-99998888-A1B2');
      expect(res.isValid).toBe(true);
      expect(res.normalized).toBe('KOT-ENT-99998888-A1B2');
    });
  });

  describe('maskKey (Security requirement)', () => {
    it('masks full key showing only the last 4 characters', () => {
      const key = 'KOT-PRO-ABCD1234-EF56';
      const masked = maskKey(key);
      expect(masked).toBe('****-****-****-EF56');
      expect(masked).not.toContain('ABCD1234');
    });

    it('returns None when key is null or undefined', () => {
      expect(maskKey(null)).toBe('None');
      expect(maskKey(undefined)).toBe('None');
      expect(maskKey('')).toBe('None');
    });

    it('handles short keys safely without leaking', () => {
      expect(maskKey('12')).toBe('****');
    });
  });
});
