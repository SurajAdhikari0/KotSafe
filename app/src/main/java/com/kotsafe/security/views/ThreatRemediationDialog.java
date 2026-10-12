/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * ThreatRemediationDialog
 * =======================
 * Defender-style interactive Action Center BottomSheet dialog for 1-click threat remediation:
 * - Quarantine to Sandboxed Vault (Encrypted & Isolated)
 * - Permanently Shred & Delete
 * - Block in KotSafe Firewall (Drop sockets & SmartScreen)
 * - Allow on Device / Mark as False Positive (Whitelist)
 * - Uninstall Malicious Application
 * - Query VirusTotal / AlienVault OTX
 */

package com.kotsafe.security.views;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.AntivirusEvidenceItem;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.MitreCorrelator;
import com.kotsafe.security.model.QuarantineVaultManager;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.ThreatIntelManager;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.button.MaterialButton;

import java.io.File;
import java.util.List;

public class ThreatRemediationDialog {

    public interface RemediationCallback {
        void onActionCompleted();
    }

    public static void show(Context context, AntivirusEvidenceItem item, RemediationCallback callback) {
        if (context == null || item == null) return;

        BottomSheetDialog sheet = new BottomSheetDialog(context);
        View view = LayoutInflater.from(context).inflate(R.layout.dialog_threat_remediation, null);
        sheet.setContentView(view);

        ImageView ivIcon = view.findViewById(R.id.dialog_threat_icon);
        TextView tvTitle = view.findViewById(R.id.dialog_threat_title);
        TextView tvSubtitle = view.findViewById(R.id.dialog_threat_subtitle);
        TextView tvBadge = view.findViewById(R.id.dialog_threat_badge);
        TextView tvDetails = view.findViewById(R.id.dialog_threat_details);

        View pathContainer = view.findViewById(R.id.dialog_path_container);
        TextView tvDialogPath = view.findViewById(R.id.tv_dialog_path);
        ImageView btnCopyPath = view.findViewById(R.id.btn_copy_path);

        View hashContainer = view.findViewById(R.id.dialog_hash_container);
        TextView tvDialogHash = view.findViewById(R.id.tv_dialog_hash);
        ImageView btnCopyHash = view.findViewById(R.id.btn_copy_hash);

        MaterialButton btnQuarantine = view.findViewById(R.id.btn_action_quarantine);
        MaterialButton btnShredDelete = view.findViewById(R.id.btn_action_shred_delete);
        MaterialButton btnFirewallBlock = view.findViewById(R.id.btn_action_firewall_block);
        MaterialButton btnUninstallApp = view.findViewById(R.id.btn_action_uninstall_app);
        MaterialButton btnAllowWhitelist = view.findViewById(R.id.btn_action_allow_whitelist);
        MaterialButton btnVirusTotal = view.findViewById(R.id.btn_action_virustotal);
        MaterialButton btnOtx = view.findViewById(R.id.btn_action_otx);

        tvTitle.setText(item.title);
        tvSubtitle.setText(item.subtitle);
        tvDetails.setText(item.details);
        tvBadge.setText(item.severity);

        // Populate Forensic Path
        String dispPath = item.getDisplayPath();
        if (dispPath != null && !dispPath.isEmpty()) {
            pathContainer.setVisibility(View.VISIBLE);
            tvDialogPath.setText(dispPath);
            btnCopyPath.setOnClickListener(v -> {
                android.content.ClipboardManager cm = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("File Path", dispPath));
                    Toast.makeText(context, "Copied file path to clipboard", Toast.LENGTH_SHORT).show();
                }
            });
        } else {
            pathContainer.setVisibility(View.GONE);
        }

        // Populate Forensic SHA-256 Hash
        String dispHash = item.getDisplaySha256();
        if (dispHash != null && !dispHash.isEmpty()) {
            hashContainer.setVisibility(View.VISIBLE);
            tvDialogHash.setText(dispHash);
            btnCopyHash.setOnClickListener(v -> {
                android.content.ClipboardManager cm = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm != null) {
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("SHA-256 Hash", dispHash));
                    Toast.makeText(context, "Copied SHA-256 to clipboard", Toast.LENGTH_SHORT).show();
                }
            });
        } else {
            hashContainer.setVisibility(View.GONE);
        }

        // Populate MITRE ATT&CK Mobile Correlation
        View mitreContainer = view.findViewById(R.id.dialog_mitre_container);
        TextView tvMitreBreakdown = view.findViewById(R.id.tv_dialog_mitre_breakdown);
        TextView btnMitreLink = view.findViewById(R.id.btn_dialog_mitre_link);

        List<MitreCorrelator.MitreTtp> ttps = MitreCorrelator.correlate(item);
        if (ttps != null && !ttps.isEmpty()) {
            if (mitreContainer != null) mitreContainer.setVisibility(View.VISIBLE);
            if (tvMitreBreakdown != null) tvMitreBreakdown.setText(MitreCorrelator.formatTtpBreakdown(ttps));
            if (btnMitreLink != null) {
                final String firstUrl = ttps.get(0).mitreUrl;
                btnMitreLink.setOnClickListener(v -> {
                    try {
                        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(firstUrl != null ? firstUrl : "https://attack.mitre.org/matrices/mobile/"));
                        context.startActivity(intent);
                    } catch (Exception ignored) {}
                });
            }
        } else {
            if (mitreContainer != null) mitreContainer.setVisibility(View.GONE);
        }

        if (AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)) {
            tvBadge.setTextColor(0xFFE91E63);
            tvBadge.setBackgroundResource(R.drawable.bg_badge_threat);
        } else if (AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity)) {
            tvBadge.setTextColor(0xFFE91E63);
            tvBadge.setBackgroundResource(R.drawable.bg_badge_threat);
        } else {
            tvBadge.setTextColor(0xFFFFA000);
            tvBadge.setBackgroundResource(R.drawable.bg_badge_low_risk);
        }

        boolean isStorage = AntivirusEvidenceItem.TYPE_STORAGE_FILE.equals(item.type);
        boolean isApp = AntivirusEvidenceItem.TYPE_APP_HASH.equals(item.type)
                || AntivirusEvidenceItem.TYPE_SERVICE_HASH.equals(item.type)
                || AntivirusEvidenceItem.TYPE_YARA_MATCH.equals(item.type);
        boolean isNetwork = AntivirusEvidenceItem.TYPE_IP.equals(item.type)
                || AntivirusEvidenceItem.TYPE_URL.equals(item.type);

        // Check if file exists on storage or disk (KotSafe core files are strictly protected)
        File candidateFile = null;
        if (dispPath != null && !dispPath.isEmpty()) {
            boolean isKotSafePath = dispPath.contains("com.kotsafe.security")
                    || (context != null && (dispPath.equals(context.getPackageCodePath())
                    || (context.getApplicationInfo() != null && dispPath.startsWith(context.getApplicationInfo().dataDir))));
            if (!isKotSafePath) {
                File f = new File(dispPath);
                if (f.exists()) candidateFile = f;
            }
        }

        // Configure Quarantine Button
        if (candidateFile != null) {
            btnQuarantine.setVisibility(View.VISIBLE);
            File finalFile = candidateFile;
            btnQuarantine.setOnClickListener(v -> {
                sheet.dismiss();
                new AlertDialog.Builder(context)
                        .setTitle("Quarantine to Isolated Vault?")
                        .setMessage("Moving this file will encrypt it with AES-256 and isolate it in the Sandboxed Quarantine Vault. It will be removed from storage and made completely unexecutable.")
                        .setPositiveButton("Quarantine Now", (d, w) -> {
                            boolean ok = QuarantineVaultManager.getInstance(context).quarantineFile(
                                    finalFile,
                                    "STORAGE_THREAT",
                                    item.details
                            );
                            if (ok) {
                                item.isQuarantined = true;
                                item.severity = AntivirusEvidenceItem.SEVERITY_RESOLVED;
                                item.verdict = "QUARANTINED";
                                item.details = "[QUARANTINED IN ENCRYPTED VAULT] " + (item.details != null ? item.details : "");
                                Toast.makeText(context, "File safely isolated in Quarantine Vault", Toast.LENGTH_SHORT).show();
                                if (callback != null) callback.onActionCompleted();
                                if (context instanceof com.kotsafe.security.activities.AntivirusScanActivity) {
                                    ((com.kotsafe.security.activities.AntivirusScanActivity) context).reanalyzeAndDisplayScore(1);
                                }
                            } else {
                                Toast.makeText(context, "Failed to quarantine file", Toast.LENGTH_SHORT).show();
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });
        } else {
            btnQuarantine.setVisibility(View.GONE);
        }

        // Configure Shred & Delete Button
        if (candidateFile != null) {
            btnShredDelete.setVisibility(View.VISIBLE);
            File finalFile = candidateFile;
            btnShredDelete.setOnClickListener(v -> {
                sheet.dismiss();
                new AlertDialog.Builder(context)
                        .setTitle("Permanently Shred File?")
                        .setMessage("This will overwrite the file blocks with zeros and permanently delete " + finalFile.getName() + " from your device. This cannot be undone.")
                        .setPositiveButton("Shred & Delete", (d, w) -> {
                            QuarantineVaultManager.shredFile(finalFile);
                            item.severity = AntivirusEvidenceItem.SEVERITY_CLEAN;
                            item.verdict = "SHREDDED";
                            item.details = "[PERMANENTLY SHREDDED & DELETED] " + (item.details != null ? item.details : "");
                            Toast.makeText(context, "File permanently shredded and deleted", Toast.LENGTH_SHORT).show();
                            if (callback != null) callback.onActionCompleted();
                            if (context instanceof com.kotsafe.security.activities.AntivirusScanActivity) {
                                ((com.kotsafe.security.activities.AntivirusScanActivity) context).reanalyzeAndDisplayScore(1);
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });
        } else {
            btnShredDelete.setVisibility(View.GONE);
        }

        boolean isSelf = item.packageName != null && (item.packageName.equals(context.getPackageName()) || item.packageName.startsWith("com.kotsafe.security") || item.packageName.startsWith("com.kotsafe.security"));
        boolean isProtectedApp = item.isSystemApp || isSelf || (item.packageName != null
            && Utils.isVerifiedGoogleTrustedService(context, item.packageName));

        // Configure App Uninstall Button
        if (isApp && item.packageName != null && !item.packageName.isEmpty() && !isProtectedApp) {
            btnUninstallApp.setVisibility(View.VISIBLE);
            btnUninstallApp.setOnClickListener(v -> {
                sheet.dismiss();
                Intent intent = new Intent(Intent.ACTION_DELETE);
                intent.setData(Uri.parse("package:" + item.packageName));
                intent.putExtra(Intent.EXTRA_RETURN_RESULT, true);
                context.startActivity(intent);
            });
        } else {
            btnUninstallApp.setVisibility(View.GONE);
        }

        // Configure Firewall Block Button (Only for verified hostile threats; non-malicious sites/services are protected)
        boolean isHostileThreat = AntivirusEvidenceItem.SEVERITY_MALICIOUS.equals(item.severity)
                || AntivirusEvidenceItem.SEVERITY_SUSPICIOUS.equals(item.severity);
        boolean isProtectedTarget = (item.iocValue != null && (SecurityBlocklistManager.isOfficialOrTrustedDomain(item.iocValue)
                || SecurityBlocklistManager.isCloudflareCdnIp(item.iocValue)))
                || (item.packageName != null && Utils.isVerifiedGoogleTrustedService(context, item.packageName));

        if ((isNetwork || (isApp && !isProtectedApp)) && isHostileThreat && !isProtectedTarget) {
            btnFirewallBlock.setVisibility(View.VISIBLE);
            btnFirewallBlock.setOnClickListener(v -> {
                sheet.dismiss();
                SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(context);
                if (AntivirusEvidenceItem.TYPE_IP.equals(item.type)) {
                    secMgr.blockIp(item.iocValue, "Blocked via KotSafe Action Center: " + item.title, "USER_ACTION");
                    Toast.makeText(context, "Blocked IP " + item.iocValue + " in Firewall", Toast.LENGTH_SHORT).show();
                } else if (AntivirusEvidenceItem.TYPE_URL.equals(item.type)) {
                    secMgr.blockDomain(item.iocValue, "Blocked via KotSafe Action Center: " + item.title, "USER_ACTION");
                    Toast.makeText(context, "Blocked Domain " + item.iocValue + " in Firewall", Toast.LENGTH_SHORT).show();
                } else if (item.packageName != null && !item.packageName.isEmpty()) {
                    secMgr.blockApp(item.packageName, "Blocked via KotSafe Action Center: " + item.title, "USER_ACTION");
                    Toast.makeText(context, "App network access isolated in Firewall", Toast.LENGTH_SHORT).show();
                }
                if (callback != null) callback.onActionCompleted();
            });
        } else {
            btnFirewallBlock.setVisibility(View.GONE);
        }

        // Configure Allow on Device / Whitelist Button (Defender Style)
        btnAllowWhitelist.setVisibility(View.VISIBLE);
        btnAllowWhitelist.setOnClickListener(v -> {
            sheet.dismiss();
            SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(context);
            if (AntivirusEvidenceItem.TYPE_IP.equals(item.type)) {
                secMgr.whitelist("IP", item.iocValue, "GLOBAL", "Allowed on Device by User");
            } else if (AntivirusEvidenceItem.TYPE_URL.equals(item.type)) {
                secMgr.whitelist("DOMAIN", item.iocValue, "GLOBAL", "Allowed on Device by User");
            } else if (item.iocValue != null && !item.iocValue.isEmpty() && item.iocValue.length() == 64) {
                secMgr.whitelist("HASH", item.iocValue, "GLOBAL", "Allowed on Device by User");
            } else if (item.packageName != null && !item.packageName.isEmpty()) {
                secMgr.whitelist("APP", item.packageName, "GLOBAL", "Allowed on Device by User");
            }
            Toast.makeText(context, "Allowed on Device: Added to Trusted Whitelist", Toast.LENGTH_SHORT).show();
            if (callback != null) callback.onActionCompleted();
        });

        // Configure VirusTotal & OTX lookup
        btnVirusTotal.setOnClickListener(v -> {
            if (item.iocValue != null && !item.iocValue.isEmpty()) {
                ThreatIntelManager.openVirusTotalAuto(context, item.iocValue, item.type);
            }
        });

        btnOtx.setOnClickListener(v -> {
            if (item.iocValue != null && !item.iocValue.isEmpty()) {
                ThreatIntelManager.openOtxAuto(context, item.iocValue, item.type);
            }
        });

        sheet.show();
    }
}
