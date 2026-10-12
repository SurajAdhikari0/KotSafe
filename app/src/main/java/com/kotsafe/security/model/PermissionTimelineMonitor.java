/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PermissionInfo;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Records observed changes to other apps' dangerous runtime permissions.
 * Android does not expose a public callback for the instant another app displays a
 * permission prompt. Install/update broadcasts and foreground reconciliations report
 * requested permissions and observed grant-state changes. Timestamps are observation
 * times, not prompt times.
 */
public final class PermissionTimelineMonitor implements Application.ActivityLifecycleCallbacks {
    private static final String TAG = "PermissionTimeline";
    private static final String PREF_PERMISSION_SNAPSHOT_PREFIX = "permission_timeline_snapshot:";

    private static volatile PermissionTimelineMonitor sInstance;

    private final Context mContext;
    private final PackageManager mPackageManager;
    private final SharedPreferences mPreferences;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "KotSafe-PermissionTimeline");
        thread.setPriority(Thread.NORM_PRIORITY - 1);
        return thread;
    });
    private final AtomicBoolean mReconcileQueued = new AtomicBoolean();
    private final Map<String, Boolean> mDangerousPermissionCache = new ConcurrentHashMap<>();
    private int mStartedActivities;

    private PermissionTimelineMonitor(Context context) {
        mContext = context.getApplicationContext();
        mPackageManager = mContext.getPackageManager();
        mPreferences = PreferenceManager.getDefaultSharedPreferences(mContext);
        if (mContext instanceof Application) {
            ((Application) mContext).registerActivityLifecycleCallbacks(this);
        }
        requestForegroundReconciliation();
    }

    @NonNull
    public static PermissionTimelineMonitor getInstance(@NonNull Context context) {
        PermissionTimelineMonitor instance = sInstance;
        if (instance == null) {
            synchronized (PermissionTimelineMonitor.class) {
                instance = sInstance;
                if (instance == null) {
                    instance = new PermissionTimelineMonitor(context);
                    sInstance = instance;
                }
            }
        }
        return instance;
    }

    /** Add an install/update permission inventory to this app's timeline. */
    public void onPackageInstalledOrUpdated(@NonNull String packageName, boolean replacing) {
        mExecutor.execute(() -> {
            PackagePermissions current = readPackagePermissions(packageName);
            if (current == null) return;

            Map<String, Boolean> previous = readSnapshot(packageName);
            recordChanges(packageName, previous, current.grants, replacing ? "update" : "install");
            writeSnapshot(packageName, current.grants);

            String title = replacing ? "Permission inventory after app update" : "App installed — permission inventory";
            String detail = current.grants.isEmpty()
                    ? "No dangerous runtime permissions are declared by this app."
                    : formatInventory(current.grants);
            recordEvent(packageName, title, detail);
        });
    }

    /**
     * Load persisted permission history, recording the current inventory once when this
     * package has no history yet. This gives already-installed apps a useful first timeline
     * entry without pretending it was the time an individual prompt appeared.
     */
    public void loadPermissionHistory(@NonNull String packageName,
                                     @NonNull Consumer<List<UnifiedIncidentTimeline.IncidentEvent>> callback) {
        mExecutor.execute(() -> {
            UnifiedIncidentTimeline timeline = UnifiedIncidentTimeline.getInstance(mContext);
            List<UnifiedIncidentTimeline.IncidentEvent> events =
                    timeline.getPermissionEventsForApp(packageName, 200);
            if (events.isEmpty()) {
                PackagePermissions current = readPackagePermissions(packageName);
                if (current != null) {
                    String detail = current.grants.isEmpty()
                            ? "No dangerous runtime permissions are currently declared by this app."
                            : formatInventory(current.grants);
                    recordEvent(packageName, "Current permission inventory observed", detail);
                    writeSnapshot(packageName, current.grants);
                    events = timeline.getPermissionEventsForApp(packageName, 200);
                }
            }
            callback.accept(events);
        });
    }

    @Override
    public void onActivityStarted(Activity activity) {
        if (++mStartedActivities == 1) {
            // Public Android APIs do not notify ordinary apps whenever another app's
            // permission is granted/revoked. Reconcile on return to KotSafe and label
            // entries as observed changes, not as exact prompt timestamps.
            requestForegroundReconciliation();
        }
    }

    @Override public void onActivityCreated(Activity activity, Bundle state) {}
    @Override public void onActivityResumed(Activity activity) {}
    @Override public void onActivityPaused(Activity activity) {}
    @Override public void onActivitySaveInstanceState(Activity activity, Bundle state) {}
    @Override public void onActivityStopped(Activity activity) { mStartedActivities = Math.max(0, mStartedActivities - 1); }
    @Override public void onActivityDestroyed(Activity activity) {}

    private void seedInstalledPackageSnapshots() {
        try {
            List<PackageInfo> installed = mPackageManager.getInstalledPackages(PackageManager.GET_PERMISSIONS);
            for (PackageInfo packageInfo : installed) {
                if (packageInfo == null || packageInfo.packageName == null) continue;
                PackagePermissions snapshot = readPackagePermissions(packageInfo.packageName);
                if (snapshot == null) continue;
                Map<String, Boolean> previous = readSnapshot(packageInfo.packageName);
                recordChanges(packageInfo.packageName, previous, snapshot.grants, "KotSafe foreground/startup reconciliation");
                writeSnapshot(packageInfo.packageName, snapshot.grants);
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not establish initial permission snapshots: " + e.getMessage());
        }
    }

    private void requestForegroundReconciliation() {
        if (!mReconcileQueued.compareAndSet(false, true)) return;
        mExecutor.execute(() -> {
            try {
                seedInstalledPackageSnapshots();
            } finally {
                mReconcileQueued.set(false);
            }
        });
    }

    @Nullable
    private PackagePermissions readPackagePermissions(@NonNull String packageName) {
        try {
            PackageInfo info = mPackageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS);
            String[] requested = info.requestedPermissions;
            int[] flags = info.requestedPermissionsFlags;
            Map<String, Boolean> grants = new HashMap<>();
            if (requested == null) return new PackagePermissions(grants);

            for (int i = 0; i < requested.length; i++) {
                String permission = requested[i];
                if (permission == null || !isDangerousRuntimePermission(permission)) continue;
                boolean granted = flags != null && i < flags.length
                        && (flags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0;
                grants.put(permission, granted);
            }
            return new PackagePermissions(grants);
        } catch (PackageManager.NameNotFoundException e) {
            return null;
        } catch (Exception e) {
            Log.w(TAG, "Could not read permissions for " + packageName + ": " + e.getMessage());
            return null;
        }
    }

    private boolean isDangerousRuntimePermission(String permission) {
        Boolean cached = mDangerousPermissionCache.get(permission);
        if (cached != null) return cached;

        boolean dangerous = false;
        try {
            PermissionInfo info = mPackageManager.getPermissionInfo(permission, 0);
            int baseProtection = info.protectionLevel & PermissionInfo.PROTECTION_MASK_BASE;
            dangerous = baseProtection == PermissionInfo.PROTECTION_DANGEROUS;
        } catch (Exception ignored) {
            // Unknown or unavailable permission definitions are not treated as runtime grants.
        }
        mDangerousPermissionCache.put(permission, dangerous);
        return dangerous;
    }

    private void recordChanges(String packageName, @Nullable Map<String, Boolean> previous,
                               @NonNull Map<String, Boolean> current, String reason) {
        if (previous == null) return;
        Set<String> all = new HashSet<>(previous.keySet());
        all.addAll(current.keySet());
        List<String> permissions = new ArrayList<>(all);
        Collections.sort(permissions);

        for (String permission : permissions) {
            Boolean before = previous.get(permission);
            Boolean after = current.get(permission);
            if (before == null && after != null) {
                recordEvent(packageName, "Permission declared: " + shortPermissionName(permission),
                    permission + " was added to the app's dangerous runtime permission manifest; current state: "
                        + stateLabel(after) + ". Observed during app " + reason + ".");
            } else if (before != null && after == null) {
                recordEvent(packageName, "Permission no longer requested: " + shortPermissionName(permission),
                        permission + " is no longer declared by the app. Observed during app " + reason + ".");
            } else if (before != null && after != null && !before.equals(after)) {
                String state = after ? "granted" : "revoked/denied";
                recordEvent(packageName, "Permission " + state + ": " + shortPermissionName(permission),
                        permission + " changed from " + stateLabel(before) + " to " + stateLabel(after)
                            + ". KotSafe detected the changed state during " + reason
                            + "; Android does not expose when the app displayed its permission prompt.");
            }
        }
    }

    private void recordEvent(String packageName, String title, String detail) {
        UnifiedIncidentTimeline.getInstance(mContext).record(new UnifiedIncidentTimeline.IncidentEvent.Builder()
                .type(UnifiedIncidentTimeline.EventType.APP_PERMISSION_CHANGE)
                .severity(UnifiedIncidentTimeline.Severity.INFO)
                .title(title)
                .detail(detail)
                .sourceApp(packageName)
                .target("Android runtime permissions")
                .risk(0));
    }

    private String formatInventory(Map<String, Boolean> grants) {
        List<String> permissions = new ArrayList<>(grants.keySet());
        Collections.sort(permissions);
        StringBuilder detail = new StringBuilder("Dangerous runtime permissions declared (state observed at install/update):");
        for (String permission : permissions) {
            detail.append("\n• ").append(permission).append(" — ").append(stateLabel(grants.get(permission)));
        }
        return detail.toString();
    }

    private static String shortPermissionName(String permission) {
        int separator = permission.lastIndexOf('.');
        return separator >= 0 && separator < permission.length() - 1
                ? permission.substring(separator + 1) : permission;
    }

    private static String stateLabel(boolean granted) {
        return granted ? "granted" : "not granted";
    }

    private Map<String, Boolean> readSnapshot(String packageName) {
        String raw = mPreferences.getString(snapshotKey(packageName), null);
        if (raw == null) return null;
        try {
            JSONObject json = new JSONObject(raw);
            Map<String, Boolean> result = new HashMap<>();
            java.util.Iterator<String> keys = json.keys();
            while (keys.hasNext()) {
                String permission = keys.next();
                result.put(permission, json.optBoolean(permission, false));
            }
            return result;
        } catch (JSONException e) {
            Log.w(TAG, "Discarding malformed permission snapshot for " + packageName);
            return null;
        }
    }

    private void writeSnapshot(String packageName, Map<String, Boolean> grants) {
        JSONObject json = new JSONObject();
        try {
            for (Map.Entry<String, Boolean> entry : grants.entrySet()) {
                json.put(entry.getKey(), entry.getValue());
            }
            mPreferences.edit().putString(snapshotKey(packageName), json.toString()).apply();
        } catch (JSONException e) {
            Log.w(TAG, "Could not persist permission snapshot for " + packageName);
        }
    }

    private static String snapshotKey(String packageName) {
        return PREF_PERMISSION_SNAPSHOT_PREFIX + packageName;
    }

    private static final class PackagePermissions {
        final Map<String, Boolean> grants;
        PackagePermissions(Map<String, Boolean> grants) { this.grants = grants; }
    }
}
