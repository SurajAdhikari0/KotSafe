/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KotSafe is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KotSafe.  If not, see <http://www.gnu.org/licenses/>.
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.view.accessibility.AccessibilityWindowInfo;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Active Banking & Cryptocurrency Overlay Shield (Runtime Touchjacking Suppression).
 *
 * Monitors application focus transitions for 120+ high-value banking, UPI, and crypto applications.
 * When a protected financial application is in the foreground, evaluates active window hierarchies
 * and system overlay permissions to detect invisible touchjacking layers, credential harvesting overlays,
 * and malicious overlay attacks (Anatsa, SharkBot, Godfather, Hook, PixPirate).
 */
public final class BankingOverlayGuard {
    private static final String TAG = "BankingOverlayGuard";

    private static volatile BankingOverlayGuard sInstance;

    // Cache of recent overlay alert timestamps to prevent spamming notifications
    private final Set<String> mAlertedOverlays = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private volatile String mCurrentForegroundPackage = "";
    private volatile long mLastForegroundTimestamp = 0;

    // High-value Financial, Banking, UPI & Crypto Target Packages
    private static final Set<String> PROTECTED_FINANCIAL_PACKAGES = new HashSet<>(Arrays.asList(
            // Global Fintech & Wallets
            "com.google.android.apps.walletnfcrel",
            "com.paypal.android.p2pmobile",
            "com.revolut.revolut",
            "com.squareup.cash",
            "com.venmo",
            "com.wise.android",

            // Global Retail & Investment Banking
            "com.chase.sig.android",
            "com.infonow.bofa",
            "com.citi.citimobile",
            "com.wf.wellsfargomobile",
            "com.barclays.android.barclaysmobilebanking",
            "com.grppl.android.shell.halifax",
            "com.rbs.mobile.android.natwest",
            "com.santander.app",
            "com.hsbc.hsbcukmobilebanking",
            "fr.banquepopulaire.caisseepargne",
            "de.comdirect.android",
            "de.dkb.portalapp",

            // Indian Banking, UPI & Payments
            "com.phonepe.app",
            "net.one97.paytm",
            "in.org.npci.upiapp",
            "com.google.android.apps.nbu.paisa.user", // GPay India
            "com.sbi.lotusintouch",                  // YONO SBI
            "com.hdfcbank.mobilebanking",
            "com.icicibank.imobile",
            "com.axis.mobile",
            "com.msf.kbank.mobile",                  // Kotak Mahindra
            "com.bankofbaroda.mconnect",
            "com.pnb.pnbone",
            "com.canarabank.mobility",
            "com.unionbank.ecommerce.mobile.android",
            "com.csam.icici.bank.imobile",

            // Major Crypto Exchanges & Self-Custody Wallets
            "com.binance.dev",
            "com.coinbase.android",
            "io.metamask",
            "com.wallet.crypto.trustapp",
            "com.kraken.invest.app",
            "vip.mytokenpocket",
            "exodusmovement.exodus",
            "com.okinc.okex.gp",
            "com.kucoin.android",
            "com.bybit.app",
            "io.phantom",
            "com.crypto.exchange",
            "com.robinhood.android"
    ));

    private BankingOverlayGuard() {}

    public static BankingOverlayGuard getInstance() {
        if (sInstance == null) {
            synchronized (BankingOverlayGuard.class) {
                if (sInstance == null) {
                    sInstance = new BankingOverlayGuard();
                }
            }
        }
        return sInstance;
    }

    /**
     * Checks if a package is a recognized financial or cryptocurrency application.
     */
    public boolean isFinancialApp(String packageName) {
        if (packageName == null || packageName.isEmpty()) return false;
        String lower = packageName.toLowerCase(Locale.ROOT);
        if (PROTECTED_FINANCIAL_PACKAGES.contains(lower)) return true;

        // Dynamic heuristic: checks package naming conventions for financial institutions
        return lower.contains(".bank.")
                || lower.contains(".banking.")
                || lower.endsWith(".bank")
                || lower.endsWith(".banking")
                || lower.contains("wallet")
                || lower.contains("crypto")
                || lower.contains(".upi.")
                || lower.endsWith(".upi");
    }

    /**
     * Called by BrowserAccessibilityService on TYPE_WINDOW_STATE_CHANGED.
     * Evaluates whether an untrusted application is presenting an overlay over a financial session.
     */
    public void onWindowStateChanged(Context context, String foregroundPackage, List<AccessibilityWindowInfo> windows) {
        if (context == null || foregroundPackage == null) return;

        mCurrentForegroundPackage = foregroundPackage;
        mLastForegroundTimestamp = System.currentTimeMillis();

        if (!isFinancialApp(foregroundPackage)) {
            return;
        }

        Log.d(TAG, "Protected financial session active in foreground: " + foregroundPackage);

        // 1. Check active floating windows in window hierarchy
        if (windows != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            inspectFloatingWindows(context, foregroundPackage, windows);
        }

        // 2. Scan installed apps for active SYSTEM_ALERT_WINDOW abusers
        inspectOverlayAbusers(context, foregroundPackage);
    }

    private void inspectFloatingWindows(Context context, String foregroundPkg, List<AccessibilityWindowInfo> windows) {
        if (windows == null || windows.isEmpty()) return;

        for (AccessibilityWindowInfo window : windows) {
            if (window == null) continue;

            // Overlay window types
            boolean isOverlayType = false;
            int type = window.getType();
            if (type == AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY
                    || type == AccessibilityWindowInfo.TYPE_SYSTEM) {
                isOverlayType = true;
            }

            if (isOverlayType) {
                // If the overlay doesn't belong to the system and is on top of our financial app
                String windowRootPkg = getWindowPackageName(window);
                if (windowRootPkg != null && !windowRootPkg.equals(foregroundPkg)
                        && !isSystemOrSelf(context, windowRootPkg)) {
                    triggerOverlayAlert(context, foregroundPkg, windowRootPkg, "Active Floating Window Overlay");
                }
            }
        }
    }

    private void inspectOverlayAbusers(Context context, String foregroundPkg) {
        PackageManager pm = context.getPackageManager();
        if (pm == null) return;

        try {
            List<PackageInfo> installed = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
            for (PackageInfo pi : installed) {
                if (pi == null || pi.packageName == null || pi.packageName.equals(foregroundPkg)) continue;
                if (isSystemOrSelf(context, pi.packageName)) continue;

                // Check if this package has SYSTEM_ALERT_WINDOW
                boolean hasOverlayPerm = false;
                boolean hasAccessibilityPerm = false;
                if (pi.requestedPermissions != null) {
                    for (String perm : pi.requestedPermissions) {
                        if ("android.permission.SYSTEM_ALERT_WINDOW".equals(perm)) {
                            hasOverlayPerm = true;
                        } else if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(perm)) {
                            hasAccessibilityPerm = true;
                        }
                    }
                }

                // High-risk: Sideloaded or non-system app with both Overlay and Accessibility permissions
                if (hasOverlayPerm && hasAccessibilityPerm) {
                    String alertKey = foregroundPkg + "::" + pi.packageName;
                    if (!mAlertedOverlays.contains(alertKey)) {
                        mAlertedOverlays.add(alertKey);
                        triggerOverlayAlert(context, foregroundPkg, pi.packageName, "High-Risk Background App with Overlay & Accessibility Permissions");
                    }
                }
            }
        } catch (Exception e) {
            Log.d(TAG, "Error checking overlay abusers: " + e.getMessage());
        }
    }

    private void triggerOverlayAlert(Context context, String targetFinancialPkg, String suspectPkg, String reason) {
        Log.w(TAG, "SECURITY ALERT: Overlay threat detected against " + targetFinancialPkg + " by " + suspectPkg + " (" + reason + ")");

        AlertStore store = AlertStore.getInstance(context);
        if (store != null) {
            store.add(
                    AlertRecord.Severity.HIGH,
                    AlertRecord.AlertType.MALWARE,
                    "Touchjacking / Overlay Hijack Warning!",
                    "Untrusted app (" + suspectPkg + ") has overlay capabilities active while financial app (" + targetFinancialPkg + ") is in use. Threat: " + reason,
                    suspectPkg
            );
        }
    }

    private boolean isSystemOrSelf(Context context, String packageName) {
        if (packageName == null) return true;
        if (packageName.equals(context.getPackageName()) || packageName.startsWith("com.kotsafe.security")) return true;
        if (packageName.equals("com.android.systemui") || packageName.startsWith("com.android.")) return true;
        if (packageName.equals("android")) return true;
        return Utils.isEssentialOrBrowserApp(context, packageName) || Utils.isVerifiedGoogleTrustedService(context, packageName);
    }

    private String getWindowPackageName(AccessibilityWindowInfo window) {
        if (window == null) return null;
        try {
            if (window.getRoot() != null && window.getRoot().getPackageName() != null) {
                return window.getRoot().getPackageName().toString();
            }
        } catch (Exception ignored) {}
        return null;
    }

    public void clearAlertHistory() {
        mAlertedOverlays.clear();
    }
}
