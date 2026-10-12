/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

/**
 * Listens for PACKAGE_ADDED / PACKAGE_REPLACED broadcasts.
 * When a new app is installed, immediately queues a P0 critical scan of its APK.
 * This ensures newly installed apps are checked before the user runs them.
 *
 * Registered in AndroidManifest.xml — works even when the app is not in foreground.
 */
public class AppInstallMonitor extends BroadcastReceiver {
    private static final String TAG = "AppInstallMonitor";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getData() == null) return;

        String action = intent.getAction();
        if (!Intent.ACTION_PACKAGE_ADDED.equals(action)
                && !Intent.ACTION_PACKAGE_REPLACED.equals(action)) return;

        String packageName = intent.getData().getSchemeSpecificPart();
        if (packageName == null || packageName.isEmpty()) return;

        boolean isReplacing = Intent.ACTION_PACKAGE_REPLACED.equals(action)
            || intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
        String label = isReplacing ? "Updated" : "New install";
        Log.i(TAG, label + " detected: " + packageName);

        // Record the app's dangerous runtime permission inventory and observed grant
        // changes alongside its network activity timeline.
        PermissionTimelineMonitor.getInstance(context)
            .onPackageInstalledOrUpdated(packageName, isReplacing);

        // Publish to central SecurityEventBus for CrossDomainCorrelationEngine
        try {
            com.kotsafe.security.security.event.SecurityEvent.Builder eventBuilder =
                    new com.kotsafe.security.security.event.SecurityEvent.Builder(
                            com.kotsafe.security.security.event.SecurityEvent.Domain.ANTIVIRUS,
                            isReplacing ? com.kotsafe.security.security.event.EventTypes.APP_UPDATED : com.kotsafe.security.security.event.EventTypes.APP_INSTALLED)
                            .severity(com.kotsafe.security.security.event.SecurityEvent.Severity.INFO)
                            .title((isReplacing ? "App Updated: " : "New App Installed: ") + packageName)
                            .description("Package " + packageName + " was " + (isReplacing ? "updated" : "installed") + " on the device.")
                            .subject(packageName, -1)
                            .attribute("is_replacing", isReplacing);
            com.kotsafe.security.security.event.SecurityEventBus.getInstance().publish(eventBuilder.build());
        } catch (Exception ignored) {}

        // Queue a P0 critical scan for this specific APK
        SecurityTaskScheduler scheduler = SecurityTaskScheduler.getInstance(context);
        scheduler.submitCritical("AppInstallScan:" + packageName, () -> {
            try {
                android.content.pm.PackageManager pm = context.getPackageManager();
                android.content.pm.PackageInfo pkgInfo = pm.getPackageInfo(packageName,
                        android.content.pm.PackageManager.GET_SERVICES);
                android.content.pm.ApplicationInfo ai = pkgInfo.applicationInfo;
                if (ai == null || ai.sourceDir == null) return;

                java.io.File apkFile = new java.io.File(ai.sourceDir);
                if (!apkFile.exists()) return;

                String sha256 = FileHashScanner.computeHash(apkFile, "SHA-256");
                String appLabel = pm.getApplicationLabel(ai).toString();
                Log.d(TAG, "Scanning new APK: " + appLabel + " sha256=" + sha256);

                boolean isSystem = Utils.classifyAppInstall(ai) == Utils.AppInstallClass.SYSTEM;
                BuiltInThreatSignatureCatalog.SignatureRule builtInRule = BuiltInThreatSignatureCatalog.lookup(sha256);
                if (!isSystem && builtInRule != null) {
                    SecurityRulesDb rulesDb = SecurityRulesDb.getInstance(context);
                    if (rulesDb.findBlockRule(sha256) == null) {
                        rulesDb.quarantineHash(sha256, builtInRule.reason, SecurityRulesDb.SOURCE_TI);
                    }
                    if (rulesDb.findBlockRule(packageName) == null) {
                        rulesDb.quarantineApp(packageName, builtInRule.reason, SecurityRulesDb.SOURCE_TI);
                    }
                    SmartScreenManager.getInstance(context).showFirewallBlockPage(
                            appLabel,
                            "APP",
                            builtInRule.reason,
                            appLabel,
                            packageName
                    );
                    SecurityDatabase db = SecurityDatabase.getInstance(context);
                    db.evidence().insertEvidence(
                            "APP",
                            "Built-in signature match for installed app: " + appLabel,
                            builtInRule.reason,
                            95,
                            EvidenceDbHelper.VERDICT_MALICIOUS,
                            packageName,
                            sha256,
                            "HASH",
                            "TI"
                    );
                    QuarantineVaultManager.getInstance(context).quarantineApp(packageName, appLabel, "Built-in Signature", builtInRule.reason);
                    QuarantineVaultManager.getInstance(context).quarantineHash(sha256, "Built-in Signature", builtInRule.reason);
                    Log.w(TAG, "Built-in signature match for new install: " + packageName + " family=" + builtInRule.family);
                }

                // Query TI router immediately for this new hash
                ThreatIntelRouter router = ThreatIntelRouter.getInstance(context);
                ThreatIntelProvider.ThreatReport report = router.queryHash(sha256);

                // Official Android, Google, Samsung, and OEM apps are whitelisted and must NEVER show in suspicious activity
                if (isSystem) {
                    // Update the hash DB as clean and return
                    FileHashDbHelper hashDb = FileHashDbHelper.getInstance(context);
                    FileHashEntry entry = new FileHashEntry();
                    entry.fileName = apkFile.getName();
                    entry.filePath = apkFile.getAbsolutePath();
                    entry.packageName = packageName;
                    entry.appName = appLabel;
                    entry.sha256 = sha256;
                    entry.fileSize = apkFile.length();
                    entry.fileLastModified = apkFile.lastModified();
                    entry.fileClass = FileHashEntry.FILE_CLASS_APK;
                    entry.scanType = FileHashEntry.SCAN_TYPE_APP;
                    entry.scanPriority = FileHashEntry.PRIORITY_LOW;
                    entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                    entry.isSystemApp = true;
                    entry.threatStatus = FileHashEntry.THREAT_CLEAN;
                    hashDb.upsertFileHash(entry);
                    return;
                }

                // Check Firewall Security Rules
                SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(context);
                boolean isBlocked = secMgr.isHashBlocked(sha256) || secMgr.isBlocked(packageName);
                if (isBlocked && !isSystem) {
                    SecurityRulesDb.SecurityRule rule = secMgr.findBlockRule(sha256);
                    if (rule == null) rule = secMgr.findBlockRule(packageName);
                    String ruleReason = (rule != null && rule.reason != null) ? rule.reason : "Firewall Policy";
                    SmartScreenManager.getInstance(context).showFirewallBlockPage(
                            appLabel, "APP", ruleReason, appLabel, packageName);
                }

                // Inspect installer origin (Pillar 2.3)
                String installer = null;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
                    try {
                        android.content.pm.InstallSourceInfo srcInfo = pm.getInstallSourceInfo(packageName);
                        installer = srcInfo.getInstallingPackageName();
                    } catch (Exception ignored) {}
                } else {
                    try {
                        //noinspection deprecation
                        installer = pm.getInstallerPackageName(packageName);
                    } catch (Exception ignored) {}
                }
                boolean isSideloaded = (installer == null || !installer.equals("com.android.vending"));

                // Store in evidence if suspicious or malicious (for non-system apps only)
                if (isBlocked || (report != null && (report.isMalicious || report.isSuspicious))) {
                    SecurityDatabase db = SecurityDatabase.getInstance(context);
                    String verdict = isBlocked || (report != null && report.isMalicious)
                            ? EvidenceDbHelper.VERDICT_MALICIOUS
                            : EvidenceDbHelper.VERDICT_SUSPICIOUS;
                    int risk = isBlocked ? 95 : (report != null && report.riskScore > 0 ? report.riskScore : (report != null && report.isMalicious ? 85 : 45));

                    String details = isBlocked ? "Blocked by security rule policy"
                            : (report != null && report.details != null ? report.details : "Flagged by threat intelligence");
                    if (isSideloaded) details += " [Sideloaded]";

                    long evidenceId = db.evidence().insertEvidence(
                            "APP", "Suspicious app installed: " + appLabel,
                            details,
                            risk, verdict, packageName, sha256, "HASH", "TI"
                    );

                    // User prompt via SmartScreen for non-system apps (let user decide rather than silent auto-block)
                    if (verdict.equals(EvidenceDbHelper.VERDICT_MALICIOUS) && (report == null || report.confidence >= 0.8f)) {
                        SmartScreenManager.getInstance(context).showInstallAlert(
                                context, appLabel, packageName, sha256, verdict, report);
                    }
                }

                // Always update the hash DB
                FileHashDbHelper hashDb = FileHashDbHelper.getInstance(context);
                FileHashEntry entry = new FileHashEntry();
                entry.fileName = apkFile.getName();
                entry.filePath = apkFile.getAbsolutePath();
                entry.packageName = packageName;
                entry.appName = appLabel;
                entry.sha256 = sha256;
                entry.fileSize = apkFile.length();
                entry.fileLastModified = apkFile.lastModified();
                entry.fileClass = FileHashEntry.FILE_CLASS_APK;
                entry.scanType = FileHashEntry.SCAN_TYPE_APP;
                entry.scanPriority = FileHashEntry.PRIORITY_CRITICAL;
                entry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                entry.isSystemApp = isSystem;
                entry.threatStatus = isSystem ? FileHashEntry.THREAT_CLEAN
                        : (isBlocked || (report != null && report.isMalicious)
                        ? FileHashEntry.THREAT_MALICIOUS
                        : (report != null && report.isSuspicious)
                        ? FileHashEntry.THREAT_SUSPICIOUS : FileHashEntry.THREAT_CLEAN);
                hashDb.upsertFileHash(entry);

                // Multi-Split APK Coverage for newly installed packages
                if (ai.splitSourceDirs != null && ai.splitSourceDirs.length > 0) {
                    for (String splitPath : ai.splitSourceDirs) {
                        if (splitPath == null) continue;
                        java.io.File splitFile = new java.io.File(splitPath);
                        if (!splitFile.exists() || !splitFile.canRead()) continue;
                        String splitSha256 = FileHashScanner.computeHash(splitFile, "SHA-256");
                        if (splitSha256 != null && !splitSha256.isEmpty()) {
                            FileHashEntry splitEntry = new FileHashEntry();
                            splitEntry.fileName = splitFile.getName();
                            splitEntry.filePath = splitFile.getAbsolutePath();
                            splitEntry.packageName = packageName;
                            splitEntry.appName = appLabel + " (" + splitFile.getName() + ")";
                            splitEntry.sha256 = splitSha256;
                            splitEntry.fileSize = splitFile.length();
                            splitEntry.fileLastModified = splitFile.lastModified();
                            splitEntry.fileClass = FileHashEntry.FILE_CLASS_APK;
                            splitEntry.scanType = FileHashEntry.SCAN_TYPE_APP;
                            splitEntry.scanPriority = FileHashEntry.PRIORITY_HIGH;
                            splitEntry.scanStatus = FileHashEntry.SCAN_STATUS_DONE;
                            splitEntry.isSystemApp = isSystem;
                            splitEntry.threatStatus = isSystem ? FileHashEntry.THREAT_CLEAN : FileHashEntry.THREAT_CLEAN;
                            hashDb.upsertFileHash(splitEntry);
                        }
                    }
                }

            } catch (Exception e) {
                Log.e(TAG, "App install scan error for " + packageName + ": " + e.getMessage());
            }
        });
    }
}
