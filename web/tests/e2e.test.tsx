/**
 * KotSafe License Activation - End-to-End Component Flow Test
 *
 * Scenarios Tested:
 * 1. Initial State: Freemium (input IS present in the DOM)
 * 2. Key Entry & Activation: User enters valid key -> clicks Activate
 * 3. Active State: State becomes ACTIVE, Input is ABSENT from DOM (not just CSS hidden)
 * 4. Security Check: Full key is NEVER visible in DOM, only masked (****-****-****-EF56)
 * 5. Reload Simulation: Page reloads -> synchronous hydration renders ACTIVE immediately on first paint (no flash of input)
 * 6. Deactivation: User clicks "Deactivate this device" -> confirms modal -> State becomes UNLICENSED -> Input RETURNS to the DOM!
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { App } from '../src/App.tsx';
import { clearLicenseFromStorage } from '../src/security/secureStorage.ts';
import { licenseService } from '../src/services/licenseService.ts';
import { buildCanonicalPayload, generateSignature } from '../src/security/signatureVerifier.ts';

describe('License Activation End-to-End User Flow', () => {
  const validKey = 'KOT-PRO-ABCD1234-EF56';

  beforeEach(() => {
    localStorage.clear();
    clearLicenseFromStorage();
    licenseService.destroy();
  });

  it('completes the full lifecycle: Freemium -> Activate -> Active (input gone) -> Reload -> Deactivate -> Input returns', async () => {
    // 1. Initial State: Freemium
    const { unmount } = render(<App />);

    // Verify initial badge is Freemium Plan
    expect(screen.getByTestId('state-badge')).toHaveTextContent(/Freemium Plan/i);

    // Verify Activation Input is PRESENT in the DOM
    const inputElement = screen.getByTestId('license-input');
    expect(inputElement).toBeInTheDocument();

    const activateBtn = screen.getByTestId('activate-submit-button');
    expect(activateBtn).toBeInTheDocument();
    expect(activateBtn).toBeDisabled(); // Disabled when empty

    // 2. Setup mock server activation response
    const expiresAt = new Date(Date.now() + 365 * 86400000).toISOString();
    const serverPayload = {
      status: 'active' as const,
      plan: 'pro' as const,
      expiresAt,
      seats: { used: 1, max: 6 },
    };

    // Intercept fetch
    globalThis.fetch = vi.fn().mockImplementation(async (url: string, options: any) => {
      let body: any = {};
      try {
        if (options && options.body) body = JSON.parse(options.body);
      } catch {
        // ignore
      }
      const deviceId = body.deviceId || 'test-device';

      if (url.includes('/license/activate')) {
        const sig = await generateSignature(
          buildCanonicalPayload(serverPayload, deviceId)
        );
        return {
          status: 200,
          json: async () => ({ ...serverPayload, signature: sig, serverTime: Date.now() }),
        };
      }
      if (url.includes('/license/deactivate')) {
        return {
          status: 200,
          json: async () => ({ status: 'invalid', plan: 'freemium' }),
        };
      }
      return { status: 404 };
    });

    // 3. User types or pastes license key into the input
    fireEvent.change(inputElement, { target: { value: 'kot-pro-abcd1234-ef56' } });
    expect(inputElement).toHaveValue('KOT-PRO-ABCD1234-EF56'); // Auto-uppercased and normalized
    expect(activateBtn).not.toBeDisabled();

    // User submits activation
    fireEvent.click(activateBtn);

    // 4. Wait for Active state
    await waitFor(() => {
      expect(screen.getByTestId('state-badge')).toHaveTextContent(/Active License/i);
    });

    // CRITICAL ACCEPTANCE CRITERION 1:
    // Input must be completely ABSENT from the DOM (queryByTestId returns null)
    expect(screen.queryByTestId('license-input')).toBeNull();
    expect(screen.queryByTestId('activation-form')).toBeNull();

    // CRITICAL ACCEPTANCE CRITERION 2:
    // Full key is NEVER exposed anywhere in the document, only masked
    expect(screen.getByTestId('masked-key')).toHaveTextContent('****-****-****-EF56');
    expect(document.body.textContent).not.toContain(validKey);

    // Licensed actions must now be visible
    expect(screen.getByTestId('licensed-actions')).toBeInTheDocument();
    expect(screen.getByTestId('revalidate-button')).toBeInTheDocument();
    expect(screen.getByTestId('deactivate-button')).toBeInTheDocument();

    // 5. Reload simulation (unmount and re-render App)
    unmount();
    const { unmount: unmountReloaded } = render(<App />);

    // CRITICAL ACCEPTANCE CRITERION 3:
    // Status is correct on first paint after reload: Active, input absent
    expect(screen.getByTestId('state-badge')).toHaveTextContent(/Active License/i);
    expect(screen.queryByTestId('license-input')).toBeNull();
    expect(screen.getByTestId('masked-key')).toHaveTextContent('****-****-****-EF56');

    // 6. Deactivation flow
    const deactivateTriggerBtn = screen.getByTestId('deactivate-button');
    fireEvent.click(deactivateTriggerBtn);

    // Confirmation modal appears
    const modal = screen.getByTestId('deactivate-modal');
    expect(modal).toBeInTheDocument();
    expect(modal).toHaveTextContent(/Deactivate Device License/i);

    // User confirms deactivation in modal
    const confirmBtn = screen.getByTestId('modal-confirm-btn');
    fireEvent.click(confirmBtn);

    // 7. Wait for state to revert to UNLICENSED
    await waitFor(() => {
      expect(screen.getByTestId('state-badge')).toHaveTextContent(/Freemium Plan/i);
    });

    // CRITICAL ACCEPTANCE CRITERION 4:
    // After deactivation, input returns to the DOM
    expect(screen.getByTestId('license-input')).toBeInTheDocument();
    expect(screen.getByTestId('activation-form')).toBeInTheDocument();
    expect(screen.queryByTestId('licensed-actions')).toBeNull();

    unmountReloaded();
  });
});
