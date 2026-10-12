/*
 * This file is part of KotSafe.
 *
 * KotSafe is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package com.kotsafe.security;

import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;

import androidx.annotation.NonNull;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.activities.ErrorActivity;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.CtrlPermissions;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.Prefs;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Set;

import cat.ereza.customactivityoncrash.config.CaocConfig;

/* The KotSafe app class.
 * This class is instantiated before anything else, and its reference is stored in mInstance.
 * Global state is stored into this class via singletons.
 */
public class KotSafe extends Application {
    private static final String TAG = "KotSafe";
    private MatchList mVisMask;
    private MatchList mMalwareWhitelist;
    private MatchList mFirewallWhitelist;
    private MatchList mDecryptionList;
    private Blocklist mBlocklist;
    private Blacklists mBlacklists;
    private CtrlPermissions mCtrlPermissions;
    private Context mLocalizedContext;
    private boolean mIsDecryptingPcap = false;
    private boolean mIsUsharkAvailable = false;
    private String mLoadedPcapBasename = null;
    private static WeakReference<KotSafe> mInstance;
    protected static boolean isUnderTest = false;

    @Override
    public void onCreate() {
        super.onCreate();

        if(!isUnderTest())
            Log.init(getCacheDir().getAbsolutePath());

        Utils.BuildType buildtp = Utils.getVerifiedBuild(this);
        Log.i(TAG, "Build type: " + buildtp);

        CaocConfig.Builder builder = CaocConfig.Builder.create();
        if((buildtp == Utils.BuildType.PLAYSTORE) || (buildtp == Utils.BuildType.UNKNOWN)) {
            builder.enabled(false);
        } else {
            builder.errorDrawable(R.drawable.ic_app_crash)
                    .errorActivity(ErrorActivity.class);
        }
        builder.apply();

        mInstance = new WeakReference<>(this);
        Utils.applyAppLocale(this);
        mLocalizedContext = createConfigurationContext(Utils.getLocalizedConfig(this));
        mIsUsharkAvailable = CaptureService.isUsharkAvailable(this);

        // Apply selected theme mode (System / Day / Night)
        Prefs.applyThemeMode(Prefs.getThemeMode(this));

        // Schedule security database maintenance & retention
        com.kotsafe.security.model.RetentionWorker.schedulePeriodic(this);

        // Schedule automatic daily background deep scan
        com.kotsafe.security.model.DailyDeepScanWorker.schedulePeriodic(this);

        // Start Firewall Block HTTP Server daemon on port 8090
        com.kotsafe.security.server.FirewallBlockHttpServer.getInstance(this).start();

        // Initialize Dual-Mode API Passive Traffic & Security Subsystem
        com.kotsafe.security.model.ApiTrafficMonitorManager.getInstance(this).initialize();

        // Start 24/7 Real-Time Downloads & Storage Sentinel (Dual-Sentinel Architecture)
        com.kotsafe.security.model.FileProtectionWatcher.getInstance(this).startWatching();

        // Initialize KotSafe Event-Driven Security Subsystems
        com.kotsafe.security.security.event.SecurityEventBus.getInstance();
        com.kotsafe.security.security.event.EventNormalizer.getInstance(this);
        com.kotsafe.security.security.identity.AppIdentityEngine.getInstance(this);
        com.kotsafe.security.security.correlation.CrossDomainCorrelationEngine.getInstance(this);
        com.kotsafe.security.security.policy.SecurityPolicyEngine.getInstance(this);
        com.kotsafe.security.security.intelligence.ThreatIntelOrchestrator.getInstance(this);
        if (!isUnderTest()) {
            com.kotsafe.security.model.PermissionTimelineMonitor.getInstance(this);
        }

        // Check and auto-sync dynamic detection rules if enabled
        com.kotsafe.security.model.DetectionRulesManager.getInstance(this).checkAndAutoSync();

        // Schedule automated background 24-hour threat intelligence delta sync
        com.kotsafe.security.model.ThreatFeedSyncWorker.schedulePeriodicSync(this);

        // Ensure P2P Exit Node Host service is running if host mode is enabled
        android.content.SharedPreferences defaultPrefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
        if (defaultPrefs.getBoolean(com.kotsafe.security.model.Prefs.PREF_P2P_EXIT_NODE_HOST_ENABLED, false)
                || defaultPrefs.getBoolean(com.kotsafe.security.model.Prefs.PREF_PERSONAL_GATEWAY_EXIT_ENABLED, false)) {
            com.kotsafe.security.model.P2PExitNodeService.start(this);
        }

        // Listen to package events
        IntentFilter filter = new IntentFilter();
        filter.addAction(Intent.ACTION_PACKAGE_ADDED);
        filter.addAction(Intent.ACTION_PACKAGE_REMOVED);
        filter.addDataScheme("package");
        registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
                    boolean newInstall = !intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
                    String packageName = intent.getData().getSchemeSpecificPart();
                    Log.d(TAG, "ACTION_PACKAGE_ADDED [new=" + newInstall + "]: " + packageName);

                    if(newInstall)
                        checkUidMapping(packageName);
                } else if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
                    boolean isUpdate = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
                    String packageName = intent.getData().getSchemeSpecificPart();
                    Log.d(TAG, "ACTION_PACKAGE_REMOVED [update=" + isUpdate + "]: " + packageName);

                    if(!isUpdate) {
                        checkUidMapping(packageName);
                        removeUninstalledAppsFromAppFilter();
                    }
                }
            }
        }, filter);

        removeUninstalledAppsFromAppFilter();
    }

    public static @NonNull KotSafe getInstance() {
        return mInstance.get();
    }

    public static boolean isUnderTest() {
        return isUnderTest;
    }

    public MatchList getVisualizationMask() {
        if(mVisMask == null)
            mVisMask = MatchList.load(mLocalizedContext, Prefs.PREF_VISUALIZATION_MASK);

        return mVisMask;
    }

    public Blacklists getBlacklists() {
        if(mBlacklists == null)
            mBlacklists = new Blacklists(mLocalizedContext);
        return mBlacklists;
    }

    public MatchList getMalwareWhitelist() {
        if(mMalwareWhitelist == null)
            mMalwareWhitelist = MatchList.load(mLocalizedContext, Prefs.PREF_MALWARE_WHITELIST);
        return mMalwareWhitelist;
    }

    public Blocklist getBlocklist() {
        if(mBlocklist == null)
            mBlocklist = Blocklist.load(mLocalizedContext);
        return mBlocklist;
    }

    // use some safe defaults to guarantee basic services
    private void initFirewallWhitelist() {
        mFirewallWhitelist.addApp(0 /* root */);
        mFirewallWhitelist.addApp(1000 /* android */);
        mFirewallWhitelist.addApp(getPackageName() /* KotSafe */);

        mFirewallWhitelist.addApp("com.android.vending" /* Google Play Store & Google Play Protect */);
        mFirewallWhitelist.addApp("com.google.android.gms" /* Google Play Services */);
        mFirewallWhitelist.addApp("com.google.android.gsf" /* Google Services Framework (push notifications) */);
        mFirewallWhitelist.addApp("com.google.android.ims" /* Carrier Services */);
        mFirewallWhitelist.addApp("com.sec.spp.push" /* Samsung Push Service */);
        mFirewallWhitelist.save();
    }

    private void checkUidMapping(String pkg) {
        if(mVisMask != null)
            mVisMask.uidMappingChanged(pkg);

        if((mMalwareWhitelist != null) && mMalwareWhitelist.uidMappingChanged(pkg))
            CaptureService.reloadMalwareWhitelist();

        if((mFirewallWhitelist != null) && mFirewallWhitelist.uidMappingChanged(pkg)) {
            if(CaptureService.isServiceActive())
                CaptureService.requireInstance().reloadFirewallWhitelist();
        }

        if((mDecryptionList != null) && mDecryptionList.uidMappingChanged(pkg))
            CaptureService.reloadDecryptionList();

        if((mBlocklist != null) && mBlocklist.uidMappingChanged(pkg)) {
            if(CaptureService.isServiceActive())
                CaptureService.requireInstance().reloadBlocklist();
        }
    }

    private void removeUninstalledAppsFromAppFilter() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        Set<String> filter = Prefs.getAppFilterRaw(prefs);
        ArrayList<String> to_remove = new ArrayList<>();
        PackageManager pm = getPackageManager();

        for (String package_name: filter) {
            try {
                Utils.getPackageInfo(pm, package_name, 0);
            } catch (PackageManager.NameNotFoundException e) {
                Log.i(TAG, "Package " + package_name + " uninstalled, removing from app filter");
                to_remove.add(package_name);
            }
        }

        if (!to_remove.isEmpty()) {
            filter.removeAll(to_remove);
            prefs.edit()
                    .putStringSet(Prefs.PREF_APP_FILTER, filter)
                    .apply();
        }
    }

    public MatchList getFirewallWhitelist() {
        if(mFirewallWhitelist == null) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            mFirewallWhitelist = MatchList.load(mLocalizedContext, Prefs.PREF_FIREWALL_WHITELIST);

            if(!Prefs.isFirewallWhitelistInitialized(prefs)) {
                initFirewallWhitelist();
                Prefs.setFirewallWhitelistInitialized(prefs);
            } else {
                boolean changed = false;
                changed |= mFirewallWhitelist.addApp("com.android.vending");
                changed |= mFirewallWhitelist.addApp("com.google.android.gms");
                if (changed) {
                    mFirewallWhitelist.save();
                }
            }
        }
        return mFirewallWhitelist;
    }

    public MatchList getDecryptionList() {
        if(mDecryptionList == null)
            mDecryptionList = MatchList.load(mLocalizedContext, Prefs.PREF_DECRYPTION_LIST);

        return mDecryptionList;
    }

    public CtrlPermissions getCtrlPermissions() {
        if(mCtrlPermissions == null)
            mCtrlPermissions = new CtrlPermissions(this);
        return mCtrlPermissions;
    }

    public void setIsDecryptingPcap(boolean val) {
        mIsDecryptingPcap = val;
    }

    public boolean isDecryptingPcap() {
        return mIsDecryptingPcap;
    }

    public boolean isUsharkAvailable() {
        return mIsUsharkAvailable;
    }

    public void setLoadedPcapBasename(String basename) {
        mLoadedPcapBasename = basename;
    }

    public String getLoadedPcapBasename() {
        return mLoadedPcapBasename;
    }
}
