/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.PowerManager;
import android.provider.Settings;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.services.BrowserAccessibilityService;
import com.google.android.material.button.MaterialButton;

public class AppPermissionsActivity extends BaseActivity {
    private static final String TAG = "AppPermissionsActivity";
    public static final String PREF_PERMISSIONS_SETUP_COMPLETED = "permissions_setup_completed";
    public static final String EXTRA_IS_FIRST_RUN = "is_first_run";

    private static final int REQ_NOTIF_PERMISSION = 101;
    private static final int REQ_STORAGE_PERMISSION = 102;
    private static final int REQ_LOCATION_PERMISSION = 103;

    private TextView mTextReadinessScore;
    private TextView mTextReadinessStatus;
    private ProgressBar mProgressReadiness;

    private TextView mStatusOverlay;
    private TextView mStatusNotifications;
    private TextView mStatusBattery;
    private TextView mStatusStorage;
    private TextView mStatusAccessibility;
    private TextView mStatusUsageStats;
    private TextView mStatusWifiSecurity;

    private MaterialButton mBtnOverlay;
    private MaterialButton mBtnNotifications;
    private MaterialButton mBtnBattery;
    private MaterialButton mBtnStorage;
    private MaterialButton mBtnAccessibility;
    private MaterialButton mBtnUsageStats;
    private MaterialButton mBtnWifiSecurity;
    private MaterialButton mBtnContinue;

    private View mCardOverlay;
    private View mCardNotifications;
    private View mCardBattery;
    private View mCardAccessibility;
    private View mCardStorage;
    private View mCardUsageStats;
    private View mCardWifiSecurity;
    private View mCardNativeNetwork;
    private View mSectionDeepInspection;

    private boolean mIsFirstRun;

    public static boolean shouldPromptPermissions(Context context) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
        return !prefs.getBoolean(PREF_PERMISSIONS_SETUP_COMPLETED, false);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_permissions);

        mIsFirstRun = getIntent().getBooleanExtra(EXTRA_IS_FIRST_RUN, false);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(!mIsFirstRun);
        }
        toolbar.setNavigationOnClickListener(v -> finish());

        bindViews();
        setupWindowInsets();
        setupListeners();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshPermissionStatuses();
    }

    private void bindViews() {
        mTextReadinessScore = findViewById(R.id.text_readiness_score);
        mTextReadinessStatus = findViewById(R.id.text_readiness_status);
        mProgressReadiness = findViewById(R.id.progress_readiness);

        mStatusOverlay = findViewById(R.id.status_overlay);
        mStatusNotifications = findViewById(R.id.status_notifications);
        mStatusBattery = findViewById(R.id.status_battery);
        mStatusStorage = findViewById(R.id.status_storage);
        mStatusAccessibility = findViewById(R.id.status_accessibility);
        mStatusUsageStats = findViewById(R.id.status_usage_stats);
        mStatusWifiSecurity = findViewById(R.id.status_wifi_security);

        mBtnOverlay = findViewById(R.id.btn_grant_overlay);
        mBtnNotifications = findViewById(R.id.btn_grant_notifications);
        mBtnBattery = findViewById(R.id.btn_grant_battery);
        mBtnStorage = findViewById(R.id.btn_grant_storage);
        mBtnAccessibility = findViewById(R.id.btn_grant_accessibility);
        mBtnUsageStats = findViewById(R.id.btn_grant_usage_stats);
        mBtnWifiSecurity = findViewById(R.id.btn_grant_wifi_security);
        mBtnContinue = findViewById(R.id.btn_continue_to_app);

        mCardOverlay = findViewById(R.id.card_overlay);
        mCardNotifications = findViewById(R.id.card_notifications);
        mCardBattery = findViewById(R.id.card_battery);
        mCardAccessibility = findViewById(R.id.card_accessibility);
        mCardStorage = findViewById(R.id.card_storage);
        mCardUsageStats = findViewById(R.id.card_usage_stats);
        mCardWifiSecurity = findViewById(R.id.card_wifi_security);
        mCardNativeNetwork = findViewById(R.id.card_native_network);
        mSectionDeepInspection = findViewById(R.id.section_deep_inspection);

        boolean isFullPower = "fullPower".equalsIgnoreCase(BuildConfig.FLAVOR);
        if (isFullPower) {
            if (mCardNativeNetwork != null) mCardNativeNetwork.setVisibility(View.GONE);
            if (mCardOverlay != null) mCardOverlay.setVisibility(View.VISIBLE);
            if (mCardAccessibility != null) mCardAccessibility.setVisibility(View.VISIBLE);
            if (mCardUsageStats != null) mCardUsageStats.setVisibility(View.VISIBLE);
        } else {
            if (mCardNativeNetwork != null) mCardNativeNetwork.setVisibility(View.VISIBLE);
            if (mCardOverlay != null) mCardOverlay.setVisibility(View.GONE);
            if (mCardAccessibility != null) mCardAccessibility.setVisibility(View.GONE);
            if (mCardUsageStats != null) mCardUsageStats.setVisibility(mIsFirstRun ? View.GONE : View.VISIBLE);
        }
    }

    private void setupWindowInsets() {
        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            // Nullify the BaseActivity toolbar listener so toolbar doesn't get squeezed
            ViewCompat.setOnApplyWindowInsetsListener(toolbar, (view, insets) -> insets);
        }

        View appbar = findViewById(R.id.appbar);
        if (appbar != null) {
            ViewCompat.setOnApplyWindowInsetsListener(appbar, (view, insets) -> {
                Insets statusBarInsets = insets.getInsets(WindowInsetsCompat.Type.statusBars() | WindowInsetsCompat.Type.displayCutout());
                view.setPadding(0, statusBarInsets.top, 0, 0);
                return insets;
            });
        }

        View bottomBar = findViewById(R.id.bottom_action_bar);
        if (bottomBar != null) {
            final int basePadBottom = bottomBar.getPaddingBottom();
            ViewCompat.setOnApplyWindowInsetsListener(bottomBar, (view, insets) -> {
                Insets navInsets = insets.getInsets(WindowInsetsCompat.Type.navigationBars());
                view.setPadding(
                        view.getPaddingLeft(),
                        view.getPaddingTop(),
                        view.getPaddingRight(),
                        basePadBottom + navInsets.bottom
                );
                return insets;
            });
        }
    }

    private void setupListeners() {
        if (mBtnOverlay != null) mBtnOverlay.setOnClickListener(v -> requestOverlayPermission());
        if (mBtnNotifications != null) mBtnNotifications.setOnClickListener(v -> requestNotificationPermission());
        if (mBtnBattery != null) mBtnBattery.setOnClickListener(v -> requestBatteryOptimizationExemption());
        if (mBtnStorage != null) mBtnStorage.setOnClickListener(v -> requestStoragePermission());
        if (mBtnAccessibility != null) mBtnAccessibility.setOnClickListener(v -> requestAccessibilityPermission());
        if (mBtnUsageStats != null) mBtnUsageStats.setOnClickListener(v -> requestUsageStatsPermission());
        if (mBtnWifiSecurity != null) mBtnWifiSecurity.setOnClickListener(v -> requestWifiLocationPermission());

        mBtnContinue.setOnClickListener(v -> {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            prefs.edit().putBoolean(PREF_PERMISSIONS_SETUP_COMPLETED, true).apply();

            if (mIsFirstRun) {
                Intent intent = new Intent(this, MainActivity.class);
                intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                startActivity(intent);
            }
            finish();
        });
    }

    private void refreshPermissionStatuses() {
        int colorOk = ContextCompat.getColor(this, R.color.ok);
        int colorDanger = ContextCompat.getColor(this, R.color.danger);
        int colorWarning = ContextCompat.getColor(this, R.color.warning);
        int colorAccent = ContextCompat.getColor(this, R.color.colorAccent);

        boolean isFullPower = "fullPower".equalsIgnoreCase(BuildConfig.FLAVOR);
        int grantedCount = 0;
        final int totalCount = isFullPower ? 7 : 4;

        if (isFullPower) {
            // 1. Overlay (Optional Floating Alert)
            boolean hasOverlay = Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(this);
            if (hasOverlay) {
                grantedCount++;
                setGrantedState(mStatusOverlay, mBtnOverlay, "✓ Active", "✓ Overlay Shield Armed", colorOk);
            } else {
                setRequiredState(mStatusOverlay, mBtnOverlay, "Optional", "Enable Floating Overlay (Optional)", colorWarning, colorAccent);
            }
        }

        // Native Network & Web Guard (Standard flavor has built-in zero-permission engine)
        if (!isFullPower) {
            grantedCount++; // Always armed via native VpnService engine
        }

        // Notifications (POST_NOTIFICATIONS)
        boolean hasNotif = true;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            hasNotif = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED;
        }
        if (hasNotif) {
            grantedCount++;
            setGrantedState(mStatusNotifications, mBtnNotifications, "✓ Active", "✓ Threat Alerts Active", colorOk);
        } else {
            setRequiredState(mStatusNotifications, mBtnNotifications, "Required", "Enable Threat Alerts", colorDanger, colorAccent);
        }

        // Battery Optimization
        boolean isBatteryExempt = isBatteryOptimizationExempt();
        if (isBatteryExempt) {
            grantedCount++;
            setGrantedState(mStatusBattery, mBtnBattery, "✓ Unrestricted", "✓ 24/7 Resilience Armed", colorOk);
        } else {
            setRequiredState(mStatusBattery, mBtnBattery, "Optimized", "Disable Battery Restrictions", colorWarning, colorAccent);
        }

        if (isFullPower) {
            // Web & Browser Live Protection (Accessibility Service)
            boolean hasAccess = BrowserAccessibilityService.isAccessibilityServiceEnabled(this);
            if (hasAccess) {
                grantedCount++;
                setGrantedState(mStatusAccessibility, mBtnAccessibility, "✓ Active", "✓ Browser Live Guard Armed", colorOk);
            } else {
                setRequiredState(mStatusAccessibility, mBtnAccessibility, "Standby", "Enable Browser Live Guard", colorWarning, colorAccent);
            }
        }

        // Storage & Files (On-Demand in Standard, Required in FullPower)
        boolean hasStorage = hasStoragePermission();
        if (hasStorage) {
            if (isFullPower) grantedCount++;
            setGrantedState(mStatusStorage, mBtnStorage, "✓ Active", "✓ Full Disk Access Granted", colorOk);
        } else {
            if (isFullPower) {
                setRequiredState(mStatusStorage, mBtnStorage, "Not Granted", "Allow Storage Access", colorDanger, colorAccent);
            } else {
                setOnDemandState(mStatusStorage, mBtnStorage, "On-Demand", "Grant Full Disk Access (Optional)", colorAccent);
            }
        }

        // Usage Stats (Optional in both flavors)
        boolean hasUsage = com.kotsafe.security.model.NetworkStatsUsageMonitor.hasUsageStatsPermission(this);
        if (hasUsage) {
            if (isFullPower) grantedCount++;
            setGrantedState(mStatusUsageStats, mBtnUsageStats, "✓ Active", "✓ Anomaly Detection Armed", colorOk);
        } else {
            if (isFullPower) {
                setRequiredState(mStatusUsageStats, mBtnUsageStats, "Optional", "Grant Usage Access", colorWarning, colorAccent);
            } else {
                setOnDemandState(mStatusUsageStats, mBtnUsageStats, "Optional", "Grant Usage Access (Optional)", colorAccent);
            }
        }

        // Wi-Fi Security (Location)
        boolean hasLoc = com.kotsafe.security.model.WifiSecurityMonitor.hasLocationPermission(this);
        if (hasLoc) {
            grantedCount++;
            setGrantedState(mStatusWifiSecurity, mBtnWifiSecurity, "✓ Active", "✓ Wi-Fi Guard Active", colorOk);
        } else {
            setRequiredState(mStatusWifiSecurity, mBtnWifiSecurity, "Optional", "Enable Wi-Fi Guard", colorWarning, colorAccent);
        }

        // Update Defense Readiness Score
        int score = Math.min(grantedCount, totalCount);
        if (mProgressReadiness != null) {
            mProgressReadiness.setMax(totalCount);
            mProgressReadiness.setProgress(score);
        }
        if (mTextReadinessScore != null) {
            mTextReadinessScore.setText(score + "/" + totalCount + " Armed");
        }
        if (mTextReadinessStatus != null) {
            if (score >= totalCount) {
                mTextReadinessStatus.setText("Fortress Mode: 100% Defense Engines Armed 🛡️");
            } else if (score >= 2) {
                mTextReadinessStatus.setText("Shield Active: Core protection engines running");
            } else {
                mTextReadinessStatus.setText("Setup Incomplete: Enable threat alerts & battery resilience");
            }
        }

        // Update Bottom Sticky Action Button
        if (mBtnContinue != null) {
            if (score >= totalCount) {
                mBtnContinue.setText("🛡️ ALL PROTECTIONS ARMED • LAUNCH KOTSAFE");
                mBtnContinue.setBackgroundTintList(ColorStateList.valueOf(colorAccent));
            } else {
                mBtnContinue.setText("CONTINUE TO KOTSAFE (" + score + "/" + totalCount + " ARMED) →");
                mBtnContinue.setBackgroundTintList(ColorStateList.valueOf(colorAccent));
            }
        }
    }

    private void setOnDemandState(TextView statusView, MaterialButton button, String statusText, String buttonText, int statusColor) {
        if (statusView != null) {
            statusView.setText(statusText);
            statusView.setTextColor(statusColor);
            statusView.setBackgroundResource(R.drawable.badge_pill_bg);
        }
        if (button != null) {
            button.setText(buttonText);
            button.setBackgroundTintList(ColorStateList.valueOf(0x186366F1));
            button.setTextColor(statusColor);
            button.setStrokeColor(ColorStateList.valueOf(0x406366F1));
            button.setStrokeWidth((int) (1 * getResources().getDisplayMetrics().density));
            button.setEnabled(true);
            button.setAlpha(1.0f);
        }
    }

    private void setGrantedState(TextView statusView, MaterialButton button, String statusText, String buttonText, int colorOk) {
        if (statusView != null) {
            statusView.setText(statusText);
            statusView.setTextColor(colorOk);
            statusView.setBackgroundResource(R.drawable.badge_pill_active);
        }
        if (button != null) {
            button.setText(buttonText);
            button.setBackgroundTintList(ColorStateList.valueOf(0x1810B981)); // 10% translucent emerald green
            button.setTextColor(colorOk);
            button.setStrokeColor(ColorStateList.valueOf(0x4010B981));
            button.setStrokeWidth((int) (1 * getResources().getDisplayMetrics().density));
            button.setEnabled(true);
            button.setAlpha(1.0f);
        }
    }

    private void setRequiredState(TextView statusView, MaterialButton button, String statusText, String buttonText, int statusColor, int accentColor) {
        if (statusView != null) {
            statusView.setText(statusText);
            statusView.setTextColor(statusColor);
            statusView.setBackgroundResource(R.drawable.badge_pill_bg);
        }
        if (button != null) {
            button.setText(buttonText);
            button.setBackgroundTintList(ColorStateList.valueOf(accentColor));
            button.setTextColor(ContextCompat.getColor(this, android.R.color.white));
            button.setStrokeWidth(0);
            button.setEnabled(true);
            button.setAlpha(1.0f);
        }
    }

    private boolean isBatteryOptimizationExempt() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            return pm != null && pm.isIgnoringBatteryOptimizations(getPackageName());
        }
        return true;
    }

    private boolean hasStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return Environment.isExternalStorageManager();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
        }
        return true;
    }

    private void requestOverlayPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:" + getPackageName()));
                startActivity(intent);
                Toast.makeText(this, "Enable 'Allow display over other apps' for KotSafe", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                try {
                    Intent fallback = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION);
                    startActivity(fallback);
                    Toast.makeText(this, "Find KotSafe and enable Display over other apps", Toast.LENGTH_LONG).show();
                } catch (Exception e2) {
                    openAppDetailsSettings();
                }
            }
        }
    }

    private void requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF_PERMISSION);
        } else {
            try {
                Intent intent = new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS);
                intent.putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName());
                startActivity(intent);
            } catch (Exception e) {
                openAppDetailsSettings();
            }
        }
    }

    @SuppressLint("BatteryLife")
    private void requestBatteryOptimizationExemption() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                Intent intent = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } catch (Exception e) {
                try {
                    Intent fallback = new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
                    startActivity(fallback);
                } catch (Exception e2) {
                    try {
                        Intent appInfo = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:" + getPackageName()));
                        startActivity(appInfo);
                    } catch (Exception e3) {
                        openAppDetailsSettings();
                    }
                }
            }
        }

        try {
            Intent autoStart = new Intent();
            autoStart.setComponent(new android.content.ComponentName(
                    "com.coloros.safecenter",
                    "com.coloros.safecenter.permission.startup.StartupAppListActivity"));
            startActivity(autoStart);
        } catch (Exception ignored) {
            // Some OEMs hide the app-startup screen behind a vendor-specific package.
            // The user still gets the app details screen and can enable background launch manually.
        }
    }

    private void requestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } catch (Exception e) {
                try {
                    Intent fallback = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                    startActivity(fallback);
                } catch (Exception e2) {
                    openAppDetailsSettings();
                }
            }
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE, Manifest.permission.READ_EXTERNAL_STORAGE},
                    REQ_STORAGE_PERMISSION);
        }
    }

    private void requestAccessibilityPermission() {
        if (!com.kotsafe.security.model.Prefs.isBrowserUrlTermsAccepted(this)) {
            com.kotsafe.security.dialogs.BrowserUrlTrackingTermsDialog.show(this, () -> {
                com.kotsafe.security.dialogs.BrowserUrlTrackingTermsDialog.launchAccessibilitySettings(this);
            });
        } else {
            com.kotsafe.security.dialogs.BrowserUrlTrackingTermsDialog.launchAccessibilitySettings(this);
        }
    }

    private void requestUsageStatsPermission() {
        try {
            Intent intent = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                intent.setData(Uri.parse("package:" + getPackageName()));
            }
            startActivity(intent);
            Toast.makeText(this, "Find 'KotSafe' and grant Usage Access", Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            try {
                Intent fallback = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
                startActivity(fallback);
            } catch (Exception e2) {
                openAppDetailsSettings();
            }
        }
    }

    private void requestWifiLocationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            boolean previouslyRequested = getSharedPreferences("app_perms_prefs", MODE_PRIVATE)
                    .getBoolean("loc_requested", false);
            if (previouslyRequested && !ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.ACCESS_FINE_LOCATION)) {
                Toast.makeText(this, "Please enable Location permission in App Settings", Toast.LENGTH_LONG).show();
                openAppDetailsSettings();
                return;
            }
            getSharedPreferences("app_perms_prefs", MODE_PRIVATE).edit().putBoolean("loc_requested", true).apply();
        }
        if (ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.ACCESS_FINE_LOCATION)) {
            Toast.makeText(this, "Location/Wi-Fi permission is required by Android to inspect Wi-Fi security", Toast.LENGTH_LONG).show();
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.NEARBY_WIFI_DEVICES},
                    REQ_LOCATION_PERMISSION);
        } else {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION},
                    REQ_LOCATION_PERMISSION);
        }
    }

    private void openAppDetailsSettings() {
        try {
            Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            intent.setData(Uri.parse("package:" + getPackageName()));
            startActivity(intent);
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        refreshPermissionStatuses();
    }
}
