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

package com.kotsafe.security.services;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;

import androidx.core.app.NotificationCompat;

import com.kotsafe.security.ActionReceiver;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.AntivirusScanActivity;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.model.AntivirusScanEngine;
import com.kotsafe.security.model.ScanModeConfig;
import com.kotsafe.security.model.SecurityNotificationHub;

import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.kotsafe.security.model.FirewallLogDbHelper;
import com.kotsafe.security.model.FirewallLogEntry;
import com.kotsafe.security.model.NetworkSecurityMonitor;

import java.io.File;
import java.io.FileWriter;

/**
 * Foreground service ensuring uninterrupted background scanning even when the user exits the screen.
 * Posts an ongoing notification during scanning and an alert notification upon completion.
 * See Implementation Plan v2 §4.1.
 */
public class AntivirusScanService extends Service {
    private static final String TAG = "AntivirusScanService";

    public static final String ACTION_START_SCAN = "com.kotsafe.security.action.START_SCAN";
    public static final String ACTION_STOP_SCAN = "com.kotsafe.security.action.STOP_SCAN";
    public static final String ACTION_SIMULATE_ATTACK = ActionReceiver.ACTION_SIMULATE_ATTACK;
    public static final String ACTION_SIMULATE_ATTACK_LEGACY = ActionReceiver.ACTION_SIMULATE_ATTACK_LEGACY;
    public static final String EXTRA_SCAN_MODE = "extra_scan_mode";

    public static final String NOTIF_CHANNEL_ID = "antivirus_scan_channel";
    public static final int NOTIF_ID_ONGOING = 4001;
    public static final int NOTIF_ID_COMPLETE = 4002;

    public interface ScanServiceListener {
        void onPhaseChanged(String phaseName, int progressPercent);
        void onFileProgress(String fileName, int current, int total);
        void onScanCompleted(AntivirusScanEngine.ScanResult result);
    }

    private static final CopyOnWriteArrayList<ScanServiceListener> sListeners = new CopyOnWriteArrayList<>();
    private static volatile boolean sIsScanning = false;
    private static volatile AntivirusScanEngine.ScanResult sLastResult = null;
    private static volatile ScanModeConfig.ScanMode sCurrentMode = ScanModeConfig.ScanMode.FULL;
    private static volatile String sCurrentPhase = "Initializing";
    private static volatile int sCurrentProgress = 0;
    private static volatile String sCurrentFileName = "";
    private static volatile int sCurrentFileIndex = 0;
    private static volatile int sTotalFiles = 0;

    private final IBinder mBinder = new LocalBinder();
    private ExecutorService mExecutor;
    private NotificationManager mNotificationManager;
    private NotificationCompat.Builder mOngoingBuilder;

    public class LocalBinder extends Binder {
        public AntivirusScanService getService() {
            return AntivirusScanService.this;
        }
    }

    public static boolean isScanning() {
        return sIsScanning;
    }

    public static AntivirusScanEngine.ScanResult getLastResult() {
        return sLastResult;
    }

    public static void setLastResult(AntivirusScanEngine.ScanResult result) {
        sLastResult = result;
    }

    public static ScanModeConfig.ScanMode getCurrentMode() {
        return sCurrentMode;
    }

    public static String getCurrentPhase() {
        return sCurrentPhase;
    }

    public static int getCurrentProgress() {
        return sCurrentProgress;
    }

    public static String getCurrentFileName() {
        return sCurrentFileName;
    }

    public static int getCurrentFileIndex() {
        return sCurrentFileIndex;
    }

    public static int getTotalFiles() {
        return sTotalFiles;
    }

    public static void registerListener(ScanServiceListener listener) {
        if (listener != null && !sListeners.contains(listener)) {
            sListeners.add(listener);
        }
    }

    public static void unregisterListener(ScanServiceListener listener) {
        if (listener != null) {
            sListeners.remove(listener);
        }
    }

    public static void startScan(Context context, ScanModeConfig.ScanMode mode) {
        Intent intent = new Intent(context, AntivirusScanService.class);
        intent.setAction(ACTION_START_SCAN);
        intent.putExtra(EXTRA_SCAN_MODE, mode != null ? mode.name() : ScanModeConfig.ScanMode.FULL.name());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        mExecutor = Executors.newSingleThreadExecutor();
        mNotificationManager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            if (ACTION_START_SCAN.equals(intent.getAction())) {
                String modeStr = intent.getStringExtra(EXTRA_SCAN_MODE);
                ScanModeConfig.ScanMode mode = ScanModeConfig.ScanMode.FULL;
                if (modeStr != null) {
                    try {
                        mode = ScanModeConfig.ScanMode.valueOf(modeStr);
                    } catch (Exception ignored) {}
                }
                startBackgroundScan(mode);
            } else if (ACTION_SIMULATE_ATTACK.equals(intent.getAction()) || ACTION_SIMULATE_ATTACK_LEGACY.equals(intent.getAction())) {
                startSimulationAndScan();
            }
        }
        return START_NOT_STICKY;
    }

    private void startSimulationAndScan() {
        if (sIsScanning) {
            Log.w(TAG, "Scan already in progress, skipping simulation trigger");
            return;
        }
        sIsScanning = true;
        sCurrentMode = ScanModeConfig.ScanMode.DEEP;
        sCurrentPhase = "Executing Multi-Attack Simulation Suite";
        sCurrentProgress = 5;

        Notification ongoingNotification = buildOngoingNotification("Running Security Attack Simulation & Deep Forensic Audit...", 5);
        try {
            startForeground(NOTIF_ID_ONGOING, ongoingNotification);
        } catch (Exception e) {
            Log.e(TAG, "startForeground error: " + e.getMessage());
        }

        mExecutor.execute(() -> {
            android.util.Log.i("SecuritySimulation", "=== STARTING COMPREHENSIVE ATTACK SIMULATION IN FOREGROUND SERVICE ===");
            try {
                // 1. Data Exfiltration simulation (DGA domain + hostile port + rapid payload)
                android.util.Log.i("SecuritySimulation", "[Attack 1] Simulating Data Exfiltration & C2 Traffic...");
                FirewallLogEntry entry1 = new FirewallLogEntry();
                entry1.timestamp = System.currentTimeMillis();
                entry1.appName = "SuspiciousSpyware";
                entry1.packageName = "com.dummy.malware.spyware";
                entry1.dstIp = "198.51.100.42";
                entry1.dstPort = 4444;
                entry1.domainOrUrl = "qxj89k1z04bvwl7y-exfil.top";
                entry1.protocol = "TCP";
                entry1.isBackground = true;
                entry1.action = FirewallLogEntry.ACTION_ALERT;
                FirewallLogDbHelper.getInstance(this).insertLog(entry1);

                NetworkSecurityMonitor.getInstance(this).onConnection(
                        "SuspiciousSpyware",
                        "com.dummy.malware.spyware",
                        "198.51.100.42",
                        4444,
                        "qxj89k1z04bvwl7y-exfil.top",
                        "http://qxj89k1z04bvwl7y-exfil.top:4444/upload?leak=passwords_and_tokens",
                        "POST"
                );

                // 2. Trojan Horse / Banking C2 Beacon simulation (Dynamic DNS + hostile port)
                android.util.Log.i("SecuritySimulation", "[Attack 2] Simulating Trojan Banking C2 Beacon...");
                FirewallLogEntry entry2 = new FirewallLogEntry();
                entry2.timestamp = System.currentTimeMillis();
                entry2.appName = "TrojanBanker";
                entry2.packageName = "com.dummy.trojan.banker";
                entry2.dstIp = "203.0.113.88";
                entry2.dstPort = 1337;
                entry2.domainOrUrl = "trojan-c2.duckdns.org";
                entry2.protocol = "TCP";
                entry2.isBackground = true;
                entry2.action = FirewallLogEntry.ACTION_ALERT;
                FirewallLogDbHelper.getInstance(this).insertLog(entry2);

                NetworkSecurityMonitor.getInstance(this).onConnection(
                        "TrojanBanker",
                        "com.dummy.trojan.banker",
                        "203.0.113.88",
                        1337,
                        "trojan-c2.duckdns.org",
                        "http://trojan-c2.duckdns.org:1337/beacon?status=active&victim=device",
                        "GET"
                );

                // 3. Worm Scanning / Command Injection Reconnaissance
                android.util.Log.i("SecuritySimulation", "[Attack 3] Simulating Worm Recon & Command Injection...");
                FirewallLogEntry entry3 = new FirewallLogEntry();
                entry3.timestamp = System.currentTimeMillis();
                entry3.appName = "WormScanner";
                entry3.packageName = "com.dummy.worm.scanner";
                entry3.dstIp = "198.51.100.99";
                entry3.dstPort = 8554;
                entry3.domainOrUrl = "198.51.100.99:8554";
                entry3.protocol = "TCP";
                entry3.isBackground = true;
                entry3.action = FirewallLogEntry.ACTION_ALERT;
                FirewallLogDbHelper.getInstance(this).insertLog(entry3);

                NetworkSecurityMonitor.getInstance(this).onConnection(
                        "WormScanner",
                        "com.dummy.worm.scanner",
                        "198.51.100.99",
                        8554,
                        "198.51.100.99",
                        "http://198.51.100.99:8554/vuln.php?cmd=cat%20/etc/passwd&exec=payload",
                        "GET"
                );

                Thread.sleep(1000); // Allow async network monitor queues to settle

                // 4. Trigger Manual Deep Antivirus Scan
                android.util.Log.i("SecuritySimulation", "[Attack 4] Triggering Manual DEEP Antivirus Scan across entire phone...");
                AntivirusScanEngine.ScanProgressListener progressListener = new AntivirusScanEngine.ScanProgressListener() {
                    @Override
                    public void onPhaseChanged(String phaseName, int progressPercent) {
                        sCurrentPhase = phaseName;
                        sCurrentProgress = progressPercent;
                        updateOngoingNotification(phaseName, progressPercent);
                        android.util.Log.i("SecuritySimulation", "Scan Progress [" + progressPercent + "%]: " + phaseName);
                    }

                    @Override
                    public void onFileProgress(String fileName, int current, int total) {
                        sCurrentFileName = fileName;
                        sCurrentFileIndex = current;
                        sTotalFiles = total;
                    }
                };

                AntivirusScanEngine.ScanResult result = AntivirusScanEngine.runScan(
                        getApplicationContext(),
                        ScanModeConfig.ScanMode.DEEP,
                        progressListener
                );

                sLastResult = result;
                sIsScanning = false;

                String report = AntivirusScanEngine.generateAuditReport(getApplicationContext(), result);
                android.util.Log.i("SecuritySimulation", "=== FORENSIC SCAN AUDIT REPORT ===\n" + report);

                File outReport = new File(getApplicationContext().getFilesDir(), "antivirus_security_audit_report.md");
                try (FileWriter writer = new FileWriter(outReport)) {
                    writer.write(report);
                    android.util.Log.i("SecuritySimulation", "Audit report written to: " + outReport.getAbsolutePath());
                }

                // Post completion notification
                postCompletionNotification(result, ScanModeConfig.ScanMode.DEEP);

            } catch (Exception e) {
                android.util.Log.e("SecuritySimulation", "Error during simulation scan: " + e.getMessage(), e);
            } finally {
                sIsScanning = false;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE);
                } else {
                    stopForeground(true);
                }
                stopSelf();
            }
        });
    }

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    NOTIF_CHANNEL_ID,
                    "Antivirus Scanner",
                    NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Shows background progress and results for antivirus scans");
            channel.setShowBadge(true);
            if (mNotificationManager != null) {
                mNotificationManager.createNotificationChannel(channel);
            }
        }
    }

    private void startBackgroundScan(ScanModeConfig.ScanMode mode) {
        if (sIsScanning) {
            Log.d(TAG, "Scan already in progress");
            return;
        }

        sIsScanning = true;
        sCurrentMode = mode;
        sCurrentPhase = "Starting " + mode.name() + " Scan...";
        sCurrentProgress = 0;
        sCurrentFileName = "";
        sCurrentFileIndex = 0;
        sTotalFiles = 0;

        // Start Foreground with Ongoing Notification
        Notification ongoingNotification = buildOngoingNotification(sCurrentPhase, 0);
        try {
            startForeground(NOTIF_ID_ONGOING, ongoingNotification);
        } catch (Exception e) {
            Log.e(TAG, "startForeground error: " + e.getMessage());
        }

        mExecutor.execute(() -> {
            Log.i(TAG, "Executing " + mode.name() + " scan in background service");
            AntivirusScanEngine.ScanProgressListener progressListener = new AntivirusScanEngine.ScanProgressListener() {
                @Override
                public void onPhaseChanged(String phaseName, int progressPercent) {
                    sCurrentPhase = phaseName;
                    sCurrentProgress = progressPercent;
                    updateOngoingNotification(phaseName, progressPercent);

                    for (ScanServiceListener l : sListeners) {
                        try { l.onPhaseChanged(phaseName, progressPercent); } catch (Exception ignored) {}
                    }
                }

                @Override
                public void onFileProgress(String fileName, int current, int total) {
                    sCurrentFileName = fileName;
                    sCurrentFileIndex = current;
                    sTotalFiles = total;

                    for (ScanServiceListener l : sListeners) {
                        try { l.onFileProgress(fileName, current, total); } catch (Exception ignored) {}
                    }
                }
            };

            AntivirusScanEngine.ScanResult result = null;
            try {
                result = AntivirusScanEngine.runScan(getApplicationContext(), mode, progressListener);
            } catch (Exception e) {
                Log.e(TAG, "Error during scan: " + e.getMessage());
            }

            sIsScanning = false;
            sLastResult = result;

            if (result != null && result.threatsDetected > 0 && result.evidenceList != null) {
                try {
                    AlertStore alertStore = AlertStore.getInstance(getApplicationContext());
                    for (AntivirusEvidenceItem item : result.evidenceList) {
                        if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity) ||
                            AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity)) {
                            alertStore.add(
                                    AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity) ?
                                            AlertRecord.Severity.HIGH : AlertRecord.Severity.MEDIUM,
                                    AlertRecord.AlertType.MALWARE,
                                    item.title != null && !item.title.isEmpty() ? item.title : "Malware Threat Found",
                                    item.details != null && !item.details.isEmpty() ? item.details : item.subtitle,
                                    item.packageName != null && !item.packageName.isEmpty() ? item.packageName : "Antivirus Scan"
                            );
                        }
                    }
                } catch (Exception ignored) {}
            }

            // Save & Log Forensic Audit Report
            if (result != null) {
                String auditReport = AntivirusScanEngine.generateAuditReport(getApplicationContext(), result);
                android.util.Log.i("SecuritySimulation", "=== FORENSIC SCAN AUDIT REPORT ===\n" + auditReport);
                try {
                    java.io.File reportFile = new java.io.File(getApplicationContext().getFilesDir(), "security_scan_audit_report.md");
                    try (java.io.FileWriter writer = new java.io.FileWriter(reportFile)) {
                        writer.write(auditReport);
                    }
                    java.io.File extDir = getApplicationContext().getExternalFilesDir(null);
                    if (extDir != null) {
                        java.io.File extReport = new java.io.File(extDir, "security_scan_audit_report.md");
                        try (java.io.FileWriter writer = new java.io.FileWriter(extReport)) {
                            writer.write(auditReport);
                        }
                    }
                } catch (Exception ignored) {}
            }

            // Notify completion
            postCompletionNotification(result, mode);

            for (ScanServiceListener l : sListeners) {
                try { l.onScanCompleted(result); } catch (Exception ignored) {}
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } else {
                stopForeground(true);
            }
            stopSelf();
        });
    }

    private Notification buildOngoingNotification(String text, int progress) {
        return SecurityNotificationHub.getInstance(this).buildOngoingSentinelNotification(
                "KotSafe " + (sCurrentMode != null ? sCurrentMode.name() : "DEEP") + " Scan",
                text,
                progress,
                true
        );
    }

    private void updateOngoingNotification(String text, int progress) {
        SecurityNotificationHub.getInstance(this).updateOngoingProgress(text, progress);
    }

    private void postCompletionNotification(AntivirusScanEngine.ScanResult result, ScanModeConfig.ScanMode mode) {
        SecurityNotificationHub.getInstance(this).postScanCompleteNotification(result);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        if (mExecutor != null) {
            mExecutor.shutdown();
        }
    }
}
