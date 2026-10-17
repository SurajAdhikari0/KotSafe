/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import androidx.annotation.NonNull;

import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.firestore.FieldValue;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.SetOptions;
import com.kotsafe.security.BuildConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import android.os.Handler;
import android.os.Looper;
import com.google.firebase.Timestamp;
import com.google.firebase.firestore.DocumentChange;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.ListenerRegistration;
import android.content.Intent;
import com.kotsafe.security.activities.LockOverlayActivity;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.services.AntivirusScanService;
import com.kotsafe.security.model.ScanModeConfig;
import com.kotsafe.security.model.SecurityNotificationHub;

/**
 * Enterprise Cloud Database & Telemetry Synchronizer for KotSafe.
 * Manages Zero-Trust synchronization between client devices, user accounts,
 * P2P exit nodes, active sessions, and SOC security posture.
 */
public class CloudSyncManager {

    private static final String TAG = "KotSafe-CloudSync";

    // Firestore Collections
    public static final String COL_USERS = "users";
    public static final String COL_DEVICES = "devices";
    public static final String COL_P2P_NODES = "p2p_nodes";
    public static final String COL_P2P_SESSIONS = "p2p_sessions";
    public static final String COL_SECURITY_EVENTS = "security_events";
    public static final String COL_COMMANDS = "commands";
    public static final String COL_RULES = "rules";

    private ListenerRegistration mCommandListener;
    private ListenerRegistration mDeviceLoginListener;
    private ListenerRegistration mRulesListener;
    private long mLoginListenerStartTime = 0;

    private static volatile CloudSyncManager sInstance;
    private final Context mContext;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    private CloudSyncManager(Context context) {
        mContext = context.getApplicationContext();
    }

    public static CloudSyncManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (CloudSyncManager.class) {
                if (sInstance == null) {
                    sInstance = new CloudSyncManager(context);
                }
            }
        }
        return sInstance;
    }

    public static CloudSyncManager getInstance() {
        return sInstance;
    }

    private FirebaseFirestore getDb() {
        try {
            if (!FirebaseApp.getApps(mContext).isEmpty()) {
                return FirebaseFirestore.getInstance();
            }
        } catch (Exception e) {
            Log.w(TAG, "Firebase not initialized: " + e.getMessage());
        }
        return null;
    }

    @SuppressLint("HardwareIds")
    public String getDeviceId() {
        try {
            String id = Settings.Secure.getString(mContext.getContentResolver(), Settings.Secure.ANDROID_ID);
            if (id != null && !id.isEmpty()) return id;
        } catch (Exception ignored) {}
        return "device_" + Build.SERIAL;
    }

    /**
     * Synchronize user profile & register current hardware device on auth success
     */
    public void syncUserOnAuth(FirebaseUser user) {
        if (user == null) return;
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            if (db == null) return;

            String uid = user.getUid();
            String deviceId = getDeviceId();

            // 1. Prepare User Document
            Map<String, Object> userData = new HashMap<>();
            userData.put("uid", uid);
            userData.put("email", user.getEmail() != null ? user.getEmail() : "");
            userData.put("displayName", user.getDisplayName() != null ? user.getDisplayName() : "KotSafe Sentinel");
            userData.put("isActive", true);
            userData.put("deviceStatus", "ONLINE");
            userData.put("activeDeviceId", deviceId);
            userData.put("activeDeviceModel", Build.MANUFACTURER + " " + Build.MODEL);
            userData.put("lastActiveTime", FieldValue.serverTimestamp());
            userData.put("platform", "android");

            // Safe defaults for posture if not exists
            Map<String, Object> posture = new HashMap<>();
            posture.put("threatScore", 100);
            posture.put("antivirusArmed", true);
            posture.put("firewallActive", true);
            posture.put("currentStatus", "PROTECTED");
            posture.put("lastScanTime", System.currentTimeMillis());
            posture.put("threatsBlockedCount", 0);
            userData.put("securityPosture", posture);

            db.collection(COL_USERS).document(uid)
                    .set(userData, SetOptions.merge())
                    .addOnSuccessListener(unused -> Log.i(TAG, "User document synchronized: " + uid))
                    .addOnFailureListener(e -> Log.e(TAG, "Failed to sync user: " + e.getMessage()));

            // 2. Register Device Document under users/{uid}/devices/{deviceId}
            Map<String, Object> deviceData = new HashMap<>();
            deviceData.put("deviceId", deviceId);
            deviceData.put("ownerUid", uid);
            deviceData.put("model", Build.MANUFACTURER + " " + Build.MODEL);
            deviceData.put("osVersion", "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")");
            deviceData.put("appVersion", BuildConfig.VERSION_NAME);
            deviceData.put("isOnline", true);
            deviceData.put("statusType", "ONLINE");
            deviceData.put("isProtected", true);
            deviceData.put("meshStatus", "Zero-Trust Armed (P2P Direct)");
            deviceData.put("threatScore", 100);
            deviceData.put("lastHeartbeat", FieldValue.serverTimestamp());

            db.collection(COL_USERS).document(uid)
                    .collection(COL_DEVICES).document(deviceId)
                    .set(deviceData, SetOptions.merge())
                    .addOnSuccessListener(unused -> Log.i(TAG, "Device registered: " + deviceId))
                    .addOnFailureListener(e -> Log.e(TAG, "Failed to register device: " + e.getMessage()));

            // Also mirror in top-level devices collection for quick device search
            db.collection(COL_DEVICES).document(deviceId)
                    .set(deviceData, SetOptions.merge());
        });
    }

    /**
     * Update user telemetry: scan time, antivirus posture, firewall state
     */
    public void updateSecurityPosture(boolean antivirusArmed, boolean firewallActive, long lastScanTime, String status, int threatsFound) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (db == null || user == null) return;

            String uid = user.getUid();
            Map<String, Object> posture = new HashMap<>();
            posture.put("securityPosture.antivirusArmed", antivirusArmed);
            posture.put("securityPosture.firewallActive", firewallActive);
            posture.put("securityPosture.lastScanTime", lastScanTime);
            posture.put("securityPosture.currentStatus", status);
            posture.put("securityPosture.threatsBlockedCount", threatsFound);
            posture.put("lastActiveTime", FieldValue.serverTimestamp());

            db.collection(COL_USERS).document(uid)
                    .update(posture)
                    .addOnFailureListener(e -> Log.w(TAG, "Posture update deferred: " + e.getMessage()));
        });
    }

    /**
     * Heartbeat pulse to keep device status online
     */
    public void sendHeartbeat() {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (db == null || user == null) return;

            String uid = user.getUid();
            String deviceId = getDeviceId();

            Map<String, Object> heartbeat = new HashMap<>();
            heartbeat.put("isOnline", true);
            heartbeat.put("lastHeartbeat", FieldValue.serverTimestamp());

            db.collection(COL_USERS).document(uid)
                    .collection(COL_DEVICES).document(deviceId)
                    .set(heartbeat, SetOptions.merge());
        });
    }

    /**
     * Publish or update P2P Exit Node state in mesh registry
     */
    public void publishP2PNodeState(String nodeId, String nodeName, String nodeType,
                                   String status, String publicIp, int port,
                                   long bandwidthBytes, int activePeers) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (db == null) return;

            String ownerUid = user != null ? user.getUid() : "anonymous_sentinel";

            Map<String, Object> node = new HashMap<>();
            node.put("nodeId", nodeId);
            node.put("ownerUid", ownerUid);
            node.put("nodeName", nodeName);
            node.put("nodeType", nodeType != null ? nodeType : "exit_node");
            node.put("status", status != null ? status : "STANDBY");
            node.put("publicIp", publicIp != null ? publicIp : "");
            node.put("port", port);
            node.put("bandwidthBytes", bandwidthBytes);
            node.put("activePeersCount", activePeers);
            node.put("lastHeartbeat", FieldValue.serverTimestamp());
            node.put("isVerified", true);

            db.collection(COL_P2P_NODES).document(nodeId)
                    .set(node, SetOptions.merge())
                    .addOnSuccessListener(unused -> Log.i(TAG, "P2P Node state updated: " + nodeId))
                    .addOnFailureListener(e -> Log.e(TAG, "P2P Node update failed: " + e.getMessage()));
        });
    }

    /**
     * Audit log for active P2P connection session
     */
    public void recordP2PSession(String sessionId, String hostUid, String nodeId, long bytesTransferred, String status) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (db == null || user == null) return;

            Map<String, Object> session = new HashMap<>();
            session.put("sessionId", sessionId);
            session.put("clientUid", user.getUid());
            session.put("clientDeviceId", getDeviceId());
            session.put("hostUid", hostUid);
            session.put("nodeId", nodeId);
            session.put("bytesTransferred", bytesTransferred);
            session.put("status", status != null ? status : "ACTIVE");
            session.put("updatedAt", FieldValue.serverTimestamp());

            db.collection(COL_P2P_SESSIONS).document(sessionId)
                    .set(session, SetOptions.merge());
        });
    }

    /**
     * Log threat detection incident to SOC cloud telemetry
     */
    public void logSecurityThreat(String threatType, String targetIndicator, String actionTaken, Map<String, Object> details) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (db == null) return;

            String uid = user != null ? user.getUid() : "unauthenticated_device";
            String eventId = "evt_" + System.currentTimeMillis() + "_" + (int)(Math.random() * 10000);

            Map<String, Object> event = new HashMap<>();
            event.put("eventId", eventId);
            event.put("userId", uid);
            event.put("deviceId", getDeviceId());
            event.put("threatType", threatType);
            event.put("targetIndicator", targetIndicator);
            event.put("actionTaken", actionTaken);
            event.put("timestamp", FieldValue.serverTimestamp());
            if (details != null) {
                event.put("details", details);
            }

            db.collection(COL_SECURITY_EVENTS).document(eventId)
                    .set(event)
                    .addOnSuccessListener(unused -> Log.i(TAG, "Security threat event logged: " + threatType))
                    .addOnFailureListener(e -> Log.w(TAG, "Event logging failed: " + e.getMessage()));
        });
    }

    /**
     * Connected Hardware & Active Session Model
     */
    public static class DeviceInfo {
        public String deviceId;
        public String ownerUid;
        public String model;
        public String osVersion;
        public String appVersion;
        public boolean isOnline;
        public long lastHeartbeat;
        public boolean isCurrentDevice;
        public boolean isProtected;
        public String statusType; // "ONLINE", "RELAY", "OFFLINE"
        public String meshStatus;
        public int threatScore;

        public DeviceInfo() {
            this.isProtected = true;
            this.statusType = "ONLINE";
            this.meshStatus = "Zero-Trust Armed (P2P Direct)";
            this.threatScore = 100;
        }

        public DeviceInfo(String deviceId, String ownerUid, String model, String osVersion,
                          String appVersion, boolean isOnline, long lastHeartbeat, boolean isCurrentDevice,
                          boolean isProtected, String statusType, String meshStatus, int threatScore) {
            this.deviceId = deviceId;
            this.ownerUid = ownerUid;
            this.model = model;
            this.osVersion = osVersion;
            this.appVersion = appVersion;
            this.isOnline = isOnline;
            this.lastHeartbeat = lastHeartbeat;
            this.isCurrentDevice = isCurrentDevice;
            this.isProtected = isProtected;
            this.statusType = statusType != null ? statusType : (isOnline ? "ONLINE" : "OFFLINE");
            this.meshStatus = meshStatus != null ? meshStatus : "Zero-Trust Mesh Active";
            this.threatScore = threatScore;
        }

        // Backward compatibility constructor
        public DeviceInfo(String deviceId, String ownerUid, String model, String osVersion,
                          String appVersion, boolean isOnline, long lastHeartbeat, boolean isCurrentDevice) {
            this(deviceId, ownerUid, model, osVersion, appVersion, isOnline, lastHeartbeat, isCurrentDevice,
                 true, isOnline ? "ONLINE" : "OFFLINE", "Zero-Trust Armed", 100);
        }
    }

    public interface DeviceListCallback {
        void onDevicesLoaded(List<DeviceInfo> devices);
        void onError(String error);
    }

    /**
     * Build standard device info for current physical hardware
     */
    public DeviceInfo createCurrentDeviceInfo(String uid) {
        return new DeviceInfo(
                getDeviceId(),
                uid != null ? uid : "",
                Build.MANUFACTURER + " " + Build.MODEL,
                "Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")",
                BuildConfig.VERSION_NAME,
                true,
                System.currentTimeMillis(),
                true,
                true,
                "ONLINE",
                "Direct Node (Protected)",
                100
        );
    }

    /**
     * Query all hardware devices connected with this user account from Firestore
     */
    public void loadUserDevices(String uid, DeviceListCallback callback) {
        if (callback == null) return;
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            if (db == null || uid == null || uid.isEmpty()) {
                List<DeviceInfo> fallback = new ArrayList<>();
                fallback.add(createCurrentDeviceInfo(uid));
                new Handler(Looper.getMainLooper()).post(() -> callback.onDevicesLoaded(fallback));
                return;
            }

            db.collection(COL_USERS).document(uid)
                    .collection(COL_DEVICES)
                    .get()
                    .addOnSuccessListener(queryDocumentSnapshots -> {
                        List<DeviceInfo> list = new ArrayList<>();
                        String currentDevId = getDeviceId();
                        boolean foundCurrent = false;

                        if (queryDocumentSnapshots != null && !queryDocumentSnapshots.isEmpty()) {
                            for (DocumentSnapshot doc : queryDocumentSnapshots.getDocuments()) {
                                String dId = doc.getString("deviceId");
                                if (dId == null || dId.isEmpty()) dId = doc.getId();
                                String model = doc.getString("model");
                                String os = doc.getString("osVersion");
                                String appVer = doc.getString("appVersion");
                                Boolean online = doc.getBoolean("isOnline");
                                Boolean isProt = doc.getBoolean("isProtected");
                                String statusType = doc.getString("statusType");
                                String meshStatus = doc.getString("meshStatus");
                                Long score = doc.getLong("threatScore");
                                Timestamp ts = doc.getTimestamp("lastHeartbeat");
                                long heartbeat = ts != null ? ts.toDate().getTime() : System.currentTimeMillis();

                                boolean isCur = currentDevId.equals(dId);
                                if (isCur) foundCurrent = true;

                                DeviceInfo info = new DeviceInfo(
                                        dId,
                                        uid,
                                        model != null ? model : "KotSafe Sentinel Device",
                                        os != null ? os : ("Android " + Build.VERSION.RELEASE),
                                        appVer != null ? appVer : BuildConfig.VERSION_NAME,
                                        online != null ? online : true,
                                        heartbeat,
                                        isCur,
                                        isProt != null ? isProt : true,
                                        statusType != null ? statusType : ((online != null && online) ? "ONLINE" : "OFFLINE"),
                                        meshStatus != null ? meshStatus : "Zero-Trust Armed",
                                        score != null ? score.intValue() : 100
                                );

                                if (isCur) {
                                    list.add(0, info);
                                } else {
                                    list.add(info);
                                }
                            }
                        }

                        // Ensure current hardware is always present at top
                        if (!foundCurrent) {
                            list.add(0, createCurrentDeviceInfo(uid));
                        }

                        // Strictly only return devices connected with this user account
                        new Handler(Looper.getMainLooper()).post(() -> callback.onDevicesLoaded(list));
                    })
                    .addOnFailureListener(e -> {
                        Log.w(TAG, "Failed to load user devices: " + e.getMessage());
                        List<DeviceInfo> fallback = new ArrayList<>();
                        fallback.add(createCurrentDeviceInfo(uid));
                        new Handler(Looper.getMainLooper()).post(() -> callback.onDevicesLoaded(fallback));
                    });
        });
    }

    /**
     * Revoke session for a specific device. Removes from Firestore users/{uid}/devices/{deviceId}.
     */
    public void revokeDeviceSession(String uid, String deviceId, Runnable onSuccess, java.util.function.Consumer<String> onFailure) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            if (db == null || uid == null || deviceId == null) {
                if (onSuccess != null) {
                    new Handler(Looper.getMainLooper()).post(onSuccess);
                }
                return;
            }

            db.collection(COL_USERS).document(uid)
                    .collection(COL_DEVICES).document(deviceId)
                    .delete()
                    .addOnSuccessListener(unused -> {
                        try {
                            db.collection(COL_DEVICES).document(deviceId).delete();
                        } catch (Exception ignored) {}

                        Log.i(TAG, "Device session revoked successfully: " + deviceId);
                        if (onSuccess != null) {
                            new Handler(Looper.getMainLooper()).post(onSuccess);
                        }
                    })
                    .addOnFailureListener(e -> {
                        Log.e(TAG, "Failed to revoke device session: " + e.getMessage());
                        if (onFailure != null) {
                            new Handler(Looper.getMainLooper()).post(() -> onFailure.accept(e.getMessage()));
                        }
                    });
        });
    }

    /**
     * Send remote defense command to target device (e.g. REMOTE_ARM, REMOTE_DISARM, REMOTE_SCAN, REMOTE_KILL_SWITCH)
     */
    public void sendRemoteDefenseCommand(String uid, String targetDeviceId, String command, Runnable onSuccess, java.util.function.Consumer<String> onFailure) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            if (db == null || uid == null || targetDeviceId == null || command == null) {
                if (onFailure != null) {
                    new Handler(Looper.getMainLooper()).post(() -> onFailure.accept("Firebase not available"));
                }
                return;
            }

            Map<String, Object> cmdData = new HashMap<>();
            cmdData.put("command", command);
            cmdData.put("status", "PENDING");
            cmdData.put("issuedAt", FieldValue.serverTimestamp());
            cmdData.put("issuedBy", Build.MANUFACTURER + " " + Build.MODEL);
            cmdData.put("issuedByDeviceId", getDeviceId());

            db.collection(COL_USERS).document(uid)
                    .collection(COL_DEVICES).document(targetDeviceId)
                    .collection(COL_COMMANDS).add(cmdData)
                    .addOnSuccessListener(docRef -> {
                        Log.i(TAG, "Dispatched remote defense command " + command + " to " + targetDeviceId);
                        // Optimistic state update on target device document
                        if ("REMOTE_KILL_SWITCH".equalsIgnoreCase(command)) {
                            Map<String, Object> update = new HashMap<>();
                            update.put("isProtected", false);
                            update.put("statusType", "REVOKED");
                            db.collection(COL_USERS).document(uid).collection(COL_DEVICES).document(targetDeviceId)
                                    .update(update);
                        } else if ("REMOTE_ARM".equalsIgnoreCase(command)) {
                            db.collection(COL_USERS).document(uid).collection(COL_DEVICES).document(targetDeviceId)
                                    .update("isProtected", true);
                        } else if ("REMOTE_DISARM".equalsIgnoreCase(command)) {
                            db.collection(COL_USERS).document(uid).collection(COL_DEVICES).document(targetDeviceId)
                                    .update("isProtected", false);
                        }

                        if (onSuccess != null) {
                            new Handler(Looper.getMainLooper()).post(onSuccess);
                        }
                    })
                    .addOnFailureListener(e -> {
                        Log.e(TAG, "Failed to send command: " + e.getMessage());
                        if (onFailure != null) {
                            new Handler(Looper.getMainLooper()).post(() -> onFailure.accept(e.getMessage()));
                        }
                    });
        });
    }

    /**
     * Start listening for remote defense commands directed to THIS hardware device
     */
    public synchronized void startCommandListener() {
        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
        FirebaseFirestore db = getDb();
        if (user == null || db == null) return;
        if (mCommandListener != null) return; // Already listening

        String uid = user.getUid();
        String myDeviceId = getDeviceId();

        mCommandListener = db.collection(COL_USERS).document(uid)
                .collection(COL_DEVICES).document(myDeviceId)
                .collection(COL_COMMANDS)
                .whereEqualTo("status", "PENDING")
                .addSnapshotListener((querySnapshots, e) -> {
                    if (e != null) {
                        Log.w(TAG, "Command listener error: " + e.getMessage());
                        return;
                    }
                    if (querySnapshots == null || querySnapshots.isEmpty()) return;

                    for (DocumentSnapshot doc : querySnapshots.getDocuments()) {
                        String cmd = doc.getString("command");
                        String cmdId = doc.getId();
                        if (cmd == null) continue;

                        Log.i(TAG, "Received remote defense command: " + cmd + " (id: " + cmdId + ")");

                        // Mark command EXECUTED immediately to prevent duplicate runs
                        doc.getReference().update("status", "EXECUTED", "executedAt", FieldValue.serverTimestamp());

                        // Dispatch local execution
                        executeLocalDefenseCommand(cmd, uid, myDeviceId);
                    }
                });
    }

    private void executeLocalDefenseCommand(String cmd, String uid, String myDeviceId) {
        new Handler(Looper.getMainLooper()).post(() -> {
            try {
                if ("REMOTE_KILL_SWITCH".equalsIgnoreCase(cmd)) {
                    Log.w(TAG, "🚨 EXECUTING REMOTE ZERO-TRUST KILL SWITCH!");
                    // 1. Immediately terminate active VPN / SOCKS tunnel
                    if (CaptureService.isServiceActive()) {
                        CaptureService.stopService();
                    }
                    // 2. Launch full-screen LockOverlayActivity with PIN/Biometrics
                    Intent lockIntent = new Intent(mContext, LockOverlayActivity.class);
                    lockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
                    lockIntent.putExtra("reason", "Zero-Trust Kill Switch triggered remotely from account mesh");
                    mContext.startActivity(lockIntent);

                    // 3. Update device status in Firestore
                    FirebaseFirestore db = getDb();
                    if (db != null) {
                        Map<String, Object> update = new HashMap<>();
                        update.put("isProtected", false);
                        update.put("statusType", "REVOKED");
                        db.collection(COL_USERS).document(uid).collection(COL_DEVICES).document(myDeviceId)
                                .update(update);
                    }
                } else if ("REMOTE_SCAN".equalsIgnoreCase(cmd)) {
                    Log.i(TAG, "🔍 Triggering Antivirus scan via remote defense command");
                    AntivirusScanService.startScan(mContext, ScanModeConfig.ScanMode.QUICK);
                } else if ("REMOTE_DISARM".equalsIgnoreCase(cmd)) {
                    Log.i(TAG, "Stopping VPN via remote command");
                    if (CaptureService.isServiceActive()) {
                        CaptureService.stopService();
                    }
                } else if ("REMOTE_ARM".equalsIgnoreCase(cmd)) {
                    Log.i(TAG, "Arming protection via remote command");
                    FirebaseFirestore db = getDb();
                    if (db != null) {
                        db.collection(COL_USERS).document(uid).collection(COL_DEVICES).document(myDeviceId)
                                .update("isProtected", true);
                    }
                }
            } catch (Exception ex) {
                Log.e(TAG, "Failed executing defense command " + cmd + ": " + ex.getMessage());
            }
        });
    }

    /**
     * Listen for new devices registered to the same account and trigger security notification
     */
    public synchronized void startNewDeviceLoginListener() {
        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
        FirebaseFirestore db = getDb();
        if (user == null || db == null) return;
        if (mDeviceLoginListener != null) return; // Already listening

        String uid = user.getUid();
        String myDeviceId = getDeviceId();
        mLoginListenerStartTime = System.currentTimeMillis();

        mDeviceLoginListener = db.collection(COL_USERS).document(uid)
                .collection(COL_DEVICES)
                .addSnapshotListener((querySnapshots, e) -> {
                    if (e != null) {
                        Log.w(TAG, "Device login listener error: " + e.getMessage());
                        return;
                    }
                    if (querySnapshots == null) return;

                    for (DocumentChange dc : querySnapshots.getDocumentChanges()) {
                        if (dc.getType() == DocumentChange.Type.ADDED) {
                            DocumentSnapshot doc = dc.getDocument();
                            String devId = doc.getString("deviceId");
                            if (devId == null || devId.isEmpty()) devId = doc.getId();

                            // Skip our own device
                            if (myDeviceId.equals(devId)) continue;

                            // Check heartbeat/creation time to only alert on new registrations
                            Timestamp ts = doc.getTimestamp("lastHeartbeat");
                            long docTime = ts != null ? ts.toDate().getTime() : 0;
                            if (docTime > 0 && (docTime >= mLoginListenerStartTime - 30_000L)) {
                                String model = doc.getString("model");
                                String os = doc.getString("osVersion");
                                String ip = doc.getString("publicIp");
                                SecurityNotificationHub.getInstance(mContext)
                                        .postDeviceLoginAlert(model, os, ip);
                            }
                        }
                    }
                });
    }

    /**
     * Cross-Device Firewall Rule Synchronizer
     */
    public void syncFirewallRule(String target, String ruleType, String action, String category) {
        mExecutor.execute(() -> {
            FirebaseFirestore db = getDb();
            FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
            if (db == null || user == null || target == null) return;

            String uid = user.getUid();
            String ruleId = target.replace('/', '_').replace('.', '_');

            Map<String, Object> ruleData = new HashMap<>();
            ruleData.put("ruleId", ruleId);
            ruleData.put("target", target);
            ruleData.put("type", ruleType != null ? ruleType : "DOMAIN_BLOCK");
            ruleData.put("action", action != null ? action : "DROP");
            ruleData.put("threatCategory", category != null ? category : "Zero-Trust Sync");
            ruleData.put("originDeviceId", getDeviceId());
            ruleData.put("timestamp", FieldValue.serverTimestamp());
            ruleData.put("enabled", true);

            db.collection(COL_USERS).document(uid)
                    .collection(COL_RULES).document(ruleId)
                    .set(ruleData, SetOptions.merge())
                    .addOnSuccessListener(unused -> Log.i(TAG, "Cross-device rule synced: " + target))
                    .addOnFailureListener(e -> Log.w(TAG, "Failed syncing rule: " + e.getMessage()));
        });
    }

    /**
     * Listen for rules synced from other mesh devices (Desktop / Extension / other phones)
     * and enforce them locally via SecurityBlocklistManager.
     */
    public synchronized void startCrossDeviceRuleSyncListener() {
        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
        FirebaseFirestore db = getDb();
        if (user == null || db == null) return;
        if (mRulesListener != null) return; // Already listening

        String uid = user.getUid();
        String myDeviceId = getDeviceId();

        mRulesListener = db.collection(COL_USERS).document(uid)
                .collection(COL_RULES)
                .addSnapshotListener((querySnapshots, e) -> {
                    if (e != null) {
                        Log.w(TAG, "Rules sync listener error: " + e.getMessage());
                        return;
                    }
                    if (querySnapshots == null) return;

                    for (DocumentChange dc : querySnapshots.getDocumentChanges()) {
                        DocumentSnapshot doc = dc.getDocument();
                        String origin = doc.getString("originDeviceId");
                        // Do not re-process rules originating from this device
                        if (myDeviceId.equals(origin)) continue;

                        String target = doc.getString("target");
                        String type = doc.getString("type");
                        String action = doc.getString("action");
                        String category = doc.getString("threatCategory");
                        Boolean enabled = doc.getBoolean("enabled");

                        if (target == null || target.isEmpty()) continue;

                        SecurityBlocklistManager blm = SecurityBlocklistManager.getInstance(mContext);
                        if (dc.getType() == DocumentChange.Type.REMOVED || (enabled != null && !enabled)) {
                            Log.i(TAG, "Cross-device rule removed: " + target);
                            blm.unblock(target);
                        } else if (dc.getType() == DocumentChange.Type.ADDED || dc.getType() == DocumentChange.Type.MODIFIED) {
                            if ("DROP".equalsIgnoreCase(action)) {
                                String reason = "Mesh Sync: " + (category != null ? category : "Cross-Device Threat");
                                String source = "Mesh:" + (origin != null ? origin : "Remote");
                                if ("IP_BLOCK".equalsIgnoreCase(type)) {
                                    blm.blockIp(target, reason, source);
                                } else {
                                    blm.blockDomain(target, reason, source);
                                }
                                Log.i(TAG, "Cross-device rule applied locally: " + target + " [" + type + "]");
                            }
                        }
                    }
                });
    }

    public synchronized void stopAllMeshListeners() {
        if (mCommandListener != null) {
            mCommandListener.remove();
            mCommandListener = null;
        }
        if (mDeviceLoginListener != null) {
            mDeviceLoginListener.remove();
            mDeviceLoginListener = null;
        }
        if (mRulesListener != null) {
            mRulesListener.remove();
            mRulesListener = null;
        }
    }
}

