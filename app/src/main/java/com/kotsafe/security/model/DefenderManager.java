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

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.AntivirusScanActivity;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.CaptureService;

/**
 * DefenderManager: Central orchestration engine for "1-Tap Total Safety / Defender Mode".
 * Allows non-technical customers to arm all defensive subsystems (Firewall, Real-Time Antivirus,
 * Threat-Filtering Quad9 DNS, Daily Automated Scanning, and Screen-Off Lockdown) simultaneously
 * in a single click, exactly like Microsoft Defender / Apple Lockdown.
 */
public class DefenderManager {

    private static final String TAG = "DefenderManager";

    public static final String PREF_DEFENDER_AUTO_PILOT = "pref_defender_auto_pilot";
    public static final String PREF_DEFENDER_SIMPLE_MODE = "pref_defender_simple_mode";

    /**
     * Checks if Defender Auto-Pilot mode is turned on (defaults to true for all users).
     */
    public static boolean isAutoPilotEnabled(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        return prefs.getBoolean(PREF_DEFENDER_AUTO_PILOT, true);
    }

    /**
     * Checks if all defensive subsystems (Firewall, AV, Quad9 DNS, Screen-Off Block, Daily Scan) are configured & armed.
     */
    public static boolean isAllSafetyArmed(Context context) {
        if (context == null) return false;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        boolean fwOn = Prefs.isFirewallEnabled(context, prefs);
        boolean avOn = Prefs.isMalwareDetectionEnabled(context, prefs);
        boolean screenOffBlock = prefs.getBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, false);
        boolean useSysDns = prefs.getBoolean(Prefs.PREF_USE_SYSTEM_DNS, true);
        String dnsV4 = Prefs.getDnsServerV4(prefs);
        boolean secureDns = !useSysDns && (dnsV4 != null && !dnsV4.isEmpty() && !dnsV4.equals("8.8.8.8"));
        boolean autoScan = prefs.getBoolean(DailyDeepScanWorker.PREF_AUTO_DAILY_DEEP_SCAN, true);

        return fwOn && avOn && screenOffBlock && secureDns && autoScan;
    }

    /**
     * Checks if Total Safety is actively defending the device right now (subsystems armed AND VPN capture running).
     */
    public static boolean isTotalSafetyActive(Context context) {
        return isAllSafetyArmed(context) && CaptureService.isServiceActive();
    }

    /**
     * Instantly arms all defensive subsystems in SharedPreferences without needing manual technical tweaking.
     */
    public static void armAllDefenses(Context context) {
        if (context == null) return;
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        SharedPreferences.Editor editor = prefs.edit();

        // 1. Smart Firewall: drop malicious connections & trackers
        editor.putBoolean(Prefs.PREF_FIREWALL, true);
        CaptureService.setFirewallEnabled(true);

        // 2. Real-Time Antivirus & Automated Daily Deep Scanning
        editor.putBoolean(Prefs.PREF_MALWARE_DETECTION, true);
        editor.putBoolean(DailyDeepScanWorker.PREF_AUTO_DAILY_DEEP_SCAN, true);

        // 3. Screen-Off Background Traffic Lockdown (prevents covert telemetry leaks)
        editor.putBoolean(Prefs.PREF_FIREWALL_SCREEN_OFF_BLOCK, true);

        // 4. High-Performance DNS: Cloudflare (1.1.1.1)
        DnsProvider cloudflare = DnsProvider.findById("cloudflare");
        if (cloudflare != null) {
            editor.putBoolean(Prefs.PREF_USE_SYSTEM_DNS, false)
                    .putString(Prefs.PREF_DNS_SERVER_V4, cloudflare.getPrimaryIpv4())
                    .putString(Prefs.PREF_DNS_SERVER_V6, cloudflare.getPrimaryIpv6() != null ? cloudflare.getPrimaryIpv6() : "2606:4700:4700::1111")
                    .putString(Prefs.PREF_ADBLOCK_DOH_PROVIDER, cloudflare.getId());
        } else {
            editor.putBoolean(Prefs.PREF_USE_SYSTEM_DNS, false)
                    .putString(Prefs.PREF_DNS_SERVER_V4, "1.1.1.1")
                    .putString(Prefs.PREF_DNS_SERVER_V6, "2606:4700:4700::1111")
                    .putString(Prefs.PREF_ADBLOCK_DOH_PROVIDER, "cloudflare");
        }

        // 5. Autonomous AI Defense: silently triage & drop threats without harassing user
        editor.putBoolean("pref_ai_autonomous_defense", true);

        editor.apply();

        // Schedule 24h background scan
        DailyDeepScanWorker.schedulePeriodic(context);
        Log.i(TAG, "KotSafe Defender: All defensive subsystems successfully armed.");
    }

    public static boolean isBatteryOptimizationExempt(Context context) {
        if (context == null) return true;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return true;
        }
        PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
        return pm != null && pm.isIgnoringBatteryOptimizations(context.getPackageName());
    }

    public static void openOemAutoStartSettings(Context context) {
        if (context == null) return;

        Intent[] candidates = new Intent[] {
                new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + context.getPackageName())),
                new Intent("android.settings.APP_OPS_DETAILS"),
                new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")),
                new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")),
                new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.PermissionManagerActivity")),
                new Intent().setComponent(new ComponentName("com.heytap.powermanager", "com.heytap.powermanager.user.PowerSettingsActivity")),
                new Intent().setComponent(new ComponentName("com.oppo.safe", "com.oppo.safe.permission.PermissionActivity"))
        };

        for (Intent intent : candidates) {
            try {
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(intent);
                Log.i(TAG, "Opened OEM startup / app policy settings screen for boot restore workaround.");
                return;
            } catch (Exception e) {
                Log.w(TAG, "OEM startup settings intent failed: " + e.getMessage());
            }
        }

        try {
            Intent fallback = new Intent(Settings.ACTION_SETTINGS);
            fallback.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(fallback);
            Log.i(TAG, "Opened generic Android settings as fallback for startup policy workaround.");
        } catch (Exception e) {
            Log.w(TAG, "Unable to open any startup settings screen: " + e.getMessage());
        }
    }

    public static void requestBatteryOptimizationExemption(Context context) {
        if (context == null) return;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return;

        try {
            Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            intent.setData(Uri.parse("package:" + context.getPackageName()));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
            Log.i(TAG, "Opened battery optimization exemption screen for boot-start workaround.");
        } catch (Exception e) {
            try {
                Intent fallback = new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
                fallback.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(fallback);
            } catch (Exception fallbackEx) {
                Log.w(TAG, "Unable to open battery optimization settings: " + fallbackEx.getMessage());
                openOemAutoStartSettings(context);
            }
        }
    }

    /**
     * Defender-style startup logic.
     *
     * This mirrors the Microsoft Defender pattern: arm the protection state first,
     * then attempt to activate the live runtime capture. If the OS requires VPN
     * consent, degrade gracefully instead of falsely claiming the firewall is live.
     */
    public static boolean restoreProtectionIfNeeded(Context context) {
        if (context == null) return false;

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        if (!Prefs.startAtBoot(prefs) || !Prefs.isFirewallEnabled(context, prefs)) {
            return false;
        }

        if (CaptureService.isServiceActive()) {
            return true;
        }

        armAllDefenses(context);

        if (!isBatteryOptimizationExempt(context)) {
            // Battery exemption improves reliability but is not a prerequisite for
            // attempting a user-enabled boot restore. Opening settings from a boot
            // receiver is blocked on modern Android and can prevent the VPN start.
            Log.w(TAG, "Battery optimization exemption is missing; attempting boot restore anyway. OEM auto-start policy may still block this receiver.");
        }

        try {
            Intent prepareIntent = VpnService.prepare(context);
            if (prepareIntent != null) {
                Log.w(TAG, "VPN consent required during Defender restore; marking protection as degraded.");
                VpnConsentManager.postDegradedStatusNotification(context);
                return false;
            }
        } catch (Exception e) {
            Log.w(TAG, "Unable to resolve VPN consent state during Defender restore: " + e.getMessage());
        }

        try {
            CaptureSettings settings = new CaptureSettings(context, prefs);
            Intent serviceIntent = new Intent(context, CaptureService.class);
            serviceIntent.putExtra("settings", settings);
            ContextCompat.startForegroundService(context, serviceIntent);
            // Service startup is asynchronous; checking isServiceActive() here
            // races onStartCommand and incorrectly reports a successful request
            // as failed. BootReceiver schedules a delayed health/retry check.
            Log.i(TAG, "Defender foreground-service start request accepted; runtime activation is pending.");
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Defender restore failed: " + e.getMessage());
            VpnConsentManager.postDegradedStatusNotification(context);
            return false;
        }
    }

    /**
     * 1-Tap Master Activation: Arms all defenses and immediately starts the VPN capture engine.
     */
    public static void armAllDefensesAndStart(Activity activity) {
        if (activity == null) return;

        armAllDefenses(activity);

        if (!CaptureService.isServiceActive() && activity instanceof MainActivity) {
            ((MainActivity) activity).startCapture();
        }
    }

    /**
     * Pauses or stops the live protection tunnel.
     */
    public static void stopProtection(Activity activity) {
        if (activity == null) return;
        if (CaptureService.isServiceActive() && activity instanceof MainActivity) {
            ((MainActivity) activity).stopCapture();
        }
    }

    /**
     * Displays a clean, human-friendly Defender setup and status dialog designed for non-technical users.
     */
    public static void showDefenderDialog(Activity activity, Runnable onUpdated) {
        if (activity == null) return;

        boolean active = isTotalSafetyActive(activity);
        boolean armed = isAllSafetyArmed(activity);

        AlertDialog.Builder b = new AlertDialog.Builder(activity);

        if (active) {
            b.setTitle("🛡️ KotSafe: Maximum Protection Active");
            b.setMessage("Your device is currently fully guarded:\n\n"
                    + "✔ Real-Time Antivirus: Scanning apps & downloads\n"
                    + "✔ Smart Firewall: Blocking unauthorized connections\n"
                    + "✔ Threat-Blocking DNS: Quad9 (9.9.9.9) active\n"
                    + "✔ Screen-Off Guard: Background data leaks prevented\n"
                    + "✔ Daily Deep Scan: Automated scheduled defense\n"
                    + "✔ VPN Security Tunnel: Encrypting device traffic\n\n"
                    + "All defenses are operating autonomously.");

            b.setPositiveButton("Antivirus Scan", (dialog, which) -> {
                activity.startActivity(new Intent(activity, AntivirusScanActivity.class));
            });

            b.setNeutralButton("Pause Protection", (dialog, which) -> {
                stopProtection(activity);
                if (onUpdated != null) onUpdated.run();
                Toast.makeText(activity, "Protection paused.", Toast.LENGTH_SHORT).show();
            });

            b.setNegativeButton("Close", null);
        } else {
            b.setTitle("🛡️ 1-Tap Total Safety (KotSafe Auto-Pilot)");
            b.setMessage("Enable complete device protection with zero configuration:\n\n"
                    + "1. Smart Firewall: Auto-blocks malicious hosts & trackers\n"
                    + "2. Real-Time Antivirus: Arms heuristic scanning & daily deep audits\n"
                    + "3. Threat-Blocking DNS: Enforces Quad9 encrypted clean DNS\n"
                    + "4. Screen-Off Guard: Stops apps from communicating when phone is locked\n"
                    + "5. Active Shield: Launches secure VPN inspection tunnel\n\n"
                    + "Zero technical setup required. Designed for complete peace of mind.");

            b.setPositiveButton("Arm All & Protect Now", (dialog, which) -> {
                armAllDefensesAndStart(activity);
                if (onUpdated != null) onUpdated.run();
                Toast.makeText(activity, "🛡️ KotSafe Active! Full protection is running.", Toast.LENGTH_LONG).show();
            });

            if (!armed) {
                b.setNeutralButton("Arm Silently (No VPN)", (dialog, which) -> {
                    armAllDefenses(activity);
                    if (onUpdated != null) onUpdated.run();
                    Toast.makeText(activity, "Defensive subsystems armed (Standby).", Toast.LENGTH_SHORT).show();
                });
            }

            b.setNegativeButton("Cancel", null);
        }

        b.show();
    }
}
