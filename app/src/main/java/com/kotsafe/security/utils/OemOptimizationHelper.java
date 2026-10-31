/*
 * KotSafe - OEM Battery Killer Defense & Background Persistence Engine
 * Prevents aggressive task termination on ColorOS, MIUI/HyperOS, OneUI, and EMUI.
 */

package com.kotsafe.security.utils;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.PowerManager;
import android.provider.Settings;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;

import java.util.Locale;

public final class OemOptimizationHelper {
    private static final String TAG = "OemOptimizationHelper";

    private OemOptimizationHelper() {}

    public static boolean isIgnoringBatteryOptimizations(Context context) {
        if (context == null) return true;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
            return pm != null && pm.isIgnoringBatteryOptimizations(context.getPackageName());
        }
        return true;
    }

    public static String getManufacturer() {
        return Build.MANUFACTURER != null ? Build.MANUFACTURER.toLowerCase(Locale.ROOT) : "";
    }

    public static boolean isOppoOrRealme() {
        String m = getManufacturer();
        return m.contains("oppo") || m.contains("realme") || m.contains("oneplus");
    }

    public static boolean isXiaomi() {
        String m = getManufacturer();
        return m.contains("xiaomi") || m.contains("redmi") || m.contains("poco");
    }

    public static boolean isSamsung() {
        return getManufacturer().contains("samsung");
    }

    public static boolean isHuawei() {
        String m = getManufacturer();
        return m.contains("huawei") || m.contains("honor");
    }

    public static boolean isVivo() {
        String m = getManufacturer();
        return m.contains("vivo") || m.contains("iqoo");
    }

    /**
     * Attempts to open OEM-specific auto-start / background launch manager.
     * Falls back to standard Android battery optimization settings.
     */
    public static void openOptimizationSettings(Context context) {
        if (context == null) return;

        // Try OEM-specific Auto-Start managers
        Intent[] oemIntents = null;

        if (isOppoOrRealme()) {
            oemIntents = new Intent[]{
                    new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.permission.startup.StartupAppListActivity")),
                    new Intent().setComponent(new ComponentName("com.coloros.safecenter", "com.coloros.safecenter.startupapp.StartupAppListActivity")),
                    new Intent().setComponent(new ComponentName("com.oplus.battery", "com.oplus.battery.BatteryMainActivity")),
                    new Intent().setComponent(new ComponentName("com.coloros.oppoguardelf", "com.coloros.powermanager.fuelgaue.PowerUsageModelActivity"))
            };
        } else if (isXiaomi()) {
            oemIntents = new Intent[]{
                    new Intent().setComponent(new ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")),
                    new Intent().setComponent(new ComponentName("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity"))
            };
        } else if (isHuawei()) {
            oemIntents = new Intent[]{
                    new Intent().setComponent(new ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")),
                    new Intent().setComponent(new ComponentName("com.huawei.systemmanager", "com.huawei.systemmanager.optimize.process.ProtectActivity"))
            };
        } else if (isVivo()) {
            oemIntents = new Intent[]{
                    new Intent().setComponent(new ComponentName("com.iqoo.secure", "com.iqoo.secure.ui.phoneoptimize.BgStartUpManager")),
                    new Intent().setComponent(new ComponentName("com.vivo.permissionmanager", "com.vivo.permissionmanager.activity.BgStartUpManagerActivity"))
            };
        }

        if (oemIntents != null) {
            for (Intent intent : oemIntents) {
                try {
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    context.startActivity(intent);
                    Log.i(TAG, "Launched OEM startup activity: " + intent.getComponent());
                    return;
                } catch (Exception ignored) {}
            }
        }

        // Standard Android battery optimization prompt
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                intent.setData(Uri.parse("package:" + context.getPackageName()));
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(intent);
                return;
            } catch (Exception e) {
                try {
                    Intent intent = new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    context.startActivity(intent);
                    return;
                } catch (Exception ignored) {}
            }
        }

        // Final fallback to App Info settings
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(Uri.parse("package:" + context.getPackageName()));
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
        } catch (Exception e) {
            Toast.makeText(context, "Please set Battery to Unrestricted in Android Settings", Toast.LENGTH_LONG).show();
        }
    }

    private static boolean sPromptedThisSession = false;

    /**
     * Displays a tactical Zero-Trust dialog guiding the user to whitelist KotSafe.
     */
    public static void showBatteryExemptionDialog(Activity activity) {
        if (activity == null || activity.isFinishing()) return;
        if (sPromptedThisSession) return;
        if (isIgnoringBatteryOptimizations(activity)) return;

        sPromptedThisSession = true;
        String brand = isOppoOrRealme() ? "ColorOS / Realme" :
                (isXiaomi() ? "MIUI / HyperOS" :
                        (isSamsung() ? "Samsung OneUI" : "Android"));

        new AlertDialog.Builder(activity)
                .setTitle("🛡️ Unrestricted Background Defense")
                .setMessage("To ensure your KotSafe P2P mesh tunnel, WireGuard exit node, and packet firewall remain continuously active while locked, please allow KotSafe to run unrestricted.\n\n" +
                        "OEM system (" + brand + ") requires explicit authorization to prevent aggressive battery termination.")
                .setPositiveButton("Configure Unrestricted", (dialog, which) -> {
                    dialog.dismiss();
                    openOptimizationSettings(activity);
                })
                .setNegativeButton("Later", (dialog, which) -> dialog.dismiss())
                .setCancelable(true)
                .show();
    }
}
