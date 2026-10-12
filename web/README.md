# KotSafe License & Activation Architecture

> Enterprise & Pro License State Machine, Zero-Flash Hydration, 7-Day Offline Grace Period, and Multi-Tab Synchronization.

---

## 1. 🏛️ License State Machine

KotSafe models the device license as an **explicit, deterministic finite state machine (Single Source of Truth)**:

```
  UNLICENSED (Freemium) ──► VERIFYING ──► ACTIVE
                                       ──► INVALID (Key not found / Revoked)
                                       ──► EXPIRED
                                       ──► ERROR (Network/Server)
  ACTIVE ───────────────► GRACE_PERIOD (Server unreachable <= 7 days)
  ACTIVE ───────────────► DEACTIVATING ──► UNLICENSED
```

### Visual State Badges (Color + Icon + Text)

Per accessibility specifications (WCAG 2.1 AA), state is **never communicated by color alone**:

| State | Semantic Variant | Visual Icon | Badge Text Label | User Action / Link |
| :--- | :--- | :--- | :--- | :--- |
| `UNLICENSED` | Neutral Slate | Shield SVG | **Freemium Plan** | "Upgrade to Pro" link |
| `ACTIVE` | Success Emerald (`#3DDC84`) | Check-Circle SVG | **Active License** | Re-validate, Deactivate |
| `GRACE_PERIOD` | Warning Amber (`#FFB300`) | Alert-Triangle SVG | **Grace Period** | Warning notice with countdown |
| `EXPIRED` | Warning Amber (`#FFB300`) | Clock SVG | **Expired** | Interactive **Renew &rarr;** link |
| `INVALID` | Danger Crimson (`#FF334B`) | X-Circle SVG | **Invalid / Revoked** | Error banner, re-entry allowed |
| `ERROR` | Danger Crimson (`#FF334B`) | Wifi-Off SVG | **Connection Error** | Retry, re-validation option |
| `VERIFYING` | Cyan Glow (`#00E5FF`) | Animated Spinner SVG | **Verifying...** | Transient state |
| `DEACTIVATING` | Cyan Glow (`#00E5FF`) | Animated Spinner SVG | **Deactivating...** | Transient state |

---

## 2. 🛡️ DOM Presence & Conditional Rendering

* **Strict Rule**: When a valid license exists (`ACTIVE` or `GRACE_PERIOD`), the license key input field is **completely removed from the DOM tree** (not just hidden using `display: none` or CSS).
* **Licensed View**: Replaces the input field with entitlement metrics and management actions:
  - **Re-validate now**: Triggers instantaneous background verification with the server.
  - **Deactivate this device**: Opens an accessible confirmation modal (`role="dialog"`, keyboard focus trapped, returns focus on close) explaining that 1 seat will be freed on the server.
  - **Manage license**: Secure external link opening the customer license management portal.
* **Deactivation**: Frees the seat, clears local secure cache, broadcasts to other tabs, and cleanly re-renders the input field in the DOM.

---

## 3. ⏳ 7-Day Offline Grace Period

Mobile devices and tactical cybersecurity operators frequently operate in air-gapped, offline, or low-connectivity environments:

1. **Background Re-Validation**: Automatic silent re-validation occurs on application startup and every 24 hours.
2. **Server Unreachable**:
   - If the server cannot be reached, the system checks elapsed time since `lastVerifiedAt`.
   - **Elapsed $\le$ 7 Days (604,800,000 ms)**:
     - State transitions to `GRACE_PERIOD`.
     - All Pro cyber defense engines remain **100% active and unlocked**.
     - Status card displays warning banner: *"Offline Grace Period Active: Server unreachable. License valid offline for X more days."*
   - **Elapsed > 7 Days**:
     - State gracefully downgrades to `UNLICENSED (Freemium)`.
     - Premium modules revert to community mode and the activation form returns to the DOM.

---

## 4. ⚡ Zero-Flash First-Paint Hydration

To prevent jarring layout shifts or flashes of the "Freemium" state during page load/refresh:
- The license cache is read **synchronously** from local obfuscated storage on module evaluation before React mounts.
- If a valid cached signature is detected and within the valid expiry/grace window, initial state is synchronously initialized to `ACTIVE` (or `GRACE_PERIOD`).
- Background re-validation runs asynchronously without blocking initial paint or flashing the unlicensed state.

---

## 5. 🔄 Multi-Tab Real-Time Synchronization

State is shared across all open tabs and windows via `BroadcastChannel('kotsafe_license_sync_v2')` (with fallback to `window.addEventListener('storage')`):
- **User activates in Tab A**: Tab B receives `LICENSE_ACTIVATED`, immediately updates its `useLicense()` hook, displays the Active badge, and removes the input field from the DOM without requiring a page reload.
- **User deactivates in Tab A**: Tab B receives `LICENSE_DEACTIVATED`, immediately reverts to Freemium, and restores the activation input field.

---

## 6. 🔒 Security Boundaries & Cryptography

1. **Server Signature Verification**:
   - All server responses return an HMAC-SHA256 signature calculated over:
     `status:plan:expiresAt:seatsUsed:seatsMax:deviceId`
   - Client verifies this signature via Web Crypto API (`crypto.subtle`).
   - Tampered responses (e.g. modified plan or manipulated expiration dates) are rejected as `TAMPERED_SIGNATURE`.
2. **Key Masking**:
   - The full key is **never displayed** in the UI, logs, or error reports.
   - Masking utility exposes only the last 4 characters: `****-****-****-EF56`.
3. **Encrypted Persistence**:
   - The license cache is stored encrypted with device-bound salt, never in plaintext `localStorage`.
4. **Client & Server Rate Limiting**:
   - Max 5 activation attempts per 60 seconds with an active visible cooldown countdown.
   - Prevents brute-force key enumeration.

---

## 7. 📡 API Contract

### Endpoints

* `POST /license/activate`: `{ key: string, deviceId: string, appVersion: string }`
* `POST /license/validate`: `{ key: string, deviceId: string }`
* `POST /license/deactivate`: `{ key: string, deviceId: string }`

### Standard Response Payload

```json
{
  "status": "active",
  "plan": "pro",
  "expiresAt": "2027-10-12T00:00:00.000Z",
  "seats": {
    "used": 1,
    "max": 6
  },
  "signature": "3E2616D195AC7590833F8EE6A374384BBCA0EBDCE42A8C41961A348CD77E5114",
  "serverTime": 1791816522000
}
```

---

## 8. 🧪 Running Tests & Development

```bash
# 1. Install dependencies
npm install

# 2. Run comprehensive unit, integration, and E2E test suites
npm test

# 3. Build optimized production bundle
npm run build

# 4. Start local mock license API server (Port 8080)
npm run server

# 5. Start Vite development server
npm run dev
```

### Test Suite Coverage

* `tests/stateMachine.test.ts`: Complete coverage of all 8 states, transitions, grace periods, and badge configurations.
* `tests/keyValidator.test.ts`: Normalization, regex validation, XSS filtering, and masking.
* `tests/security.test.ts`: HMAC signature generation, tamper detection, encrypted storage, and rate limiting.
* `tests/licenseApi.test.ts`: Exponential backoff retries on network drop, 4xx fast fail, 429 Retry-After parsing.
* `tests/licenseService.test.ts`: Synchronous hydration, multi-tab sync, background re-validation, grace degradation.
* `tests/e2e.test.tsx`: Full lifecycle E2E flow (Freemium &rarr; Activate &rarr; Input gone &rarr; Reload &rarr; Deactivate &rarr; Input returns).
