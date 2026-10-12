/**
 * KotSafe License System - Type Definitions
 * Copyright (c) 2026 KotSafe Cyber Security Project
 */

export type LicenseState =
  | 'UNLICENSED'
  | 'VERIFYING'
  | 'ACTIVE'
  | 'INVALID'
  | 'EXPIRED'
  | 'ERROR'
  | 'GRACE_PERIOD'
  | 'DEACTIVATING';

export type LicensePlan = 'freemium' | 'pro' | 'enterprise';

export type LicenseStatus = 'active' | 'expired' | 'invalid' | 'revoked';

export type LicenseErrorCode =
  | 'KEY_NOT_FOUND'
  | 'SEAT_LIMIT'
  | 'EXPIRED'
  | 'RATE_LIMITED'
  | 'REVOKED'
  | 'NETWORK_ERROR'
  | 'INVALID_FORMAT'
  | 'TAMPERED_SIGNATURE'
  | 'SERVER_ERROR';

export interface LicenseSeats {
  used: number;
  max: number;
}

export interface LicenseRecord {
  key: string;              // Masked or full stored key
  status: LicenseStatus;
  plan: LicensePlan;
  expiresAt: string | null; // ISO-8601 string or null for lifetime
  activatedAt: string;      // ISO-8601 string
  lastVerifiedAt: string;   // ISO-8601 string
  seats: LicenseSeats;
  signature: string;        // Server-issued cryptographic signature
  deviceId: string;         // Device / installation identifier
}

export interface CachedLicenseData {
  record: LicenseRecord | null;
  state: LicenseState;
  lastCheckedTime: number; // Epoch ms
  storedAt: number;        // Epoch ms
}

export interface LicenseApiResponse {
  status: LicenseStatus;
  plan: LicensePlan;
  expiresAt: string | null;
  seats: LicenseSeats;
  signature: string;
  errorCode?: LicenseErrorCode;
  serverTime?: number;
}

export interface ActivateRequest {
  key: string;
  deviceId: string;
  appVersion: string;
}

export interface ValidateRequest {
  key: string;
  deviceId: string;
}

export interface DeactivateRequest {
  key: string;
  deviceId: string;
}

export interface StateBadgeConfig {
  label: string;
  variant: 'neutral' | 'success' | 'warning' | 'danger' | 'info';
  icon: string;
  ariaLabel: string;
  hasRenewLink?: boolean;
}

export type FeatureKey =
  | 'p2p_multi_device'
  | 'ai_autonomous_guard'
  | 'yara_memory_scan'
  | 'unlimited_pcapng'
  | 'zero_latency_mesh'
  | 'standard_capture';

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  durationMs?: number;
}
