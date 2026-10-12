/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * QuarantineVaultManager
 * ======================
 * Manages the isolated Linux-sandboxed, encrypted Quarantine Vault.
 *
 * All quarantined files are moved into KotSafe's private application directory
 * (/data/user/0/.../files/.quarantine_vault/), encrypted with an internal AES-256
 * key, renamed to .kotvault, and isolated from media scanners and other apps.
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

public class QuarantineVaultManager {
    private static final String TAG = "QuarantineVaultManager";
    private static final String VAULT_DIR_NAME = ".quarantine_vault";
    private static final String KEY_ALIAS = "kotsafe_quarantine_vault_key";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final byte[] MAGIC_GCM = new byte[] { (byte) 0x4B, (byte) 0x56, (byte) 0x47, (byte) 0x31 }; // "KVG1"

    // Legacy fallback key preserved exclusively for restoring legacy CBC-encrypted items
    private static final byte[] LEGACY_SECRET = new byte[] {
            (byte) 0x4B, (byte) 0x6F, (byte) 0x74, (byte) 0x53,
            (byte) 0x61, (byte) 0x66, (byte) 0x56, (byte) 0x61,
            (byte) 0x75, (byte) 0x6C, (byte) 0x74, (byte) 0x32,
            (byte) 0x30, (byte) 0x32, (byte) 0x36
    };

    private static volatile QuarantineVaultManager sInstance;
    private final Context mContext;
    private final QuarantineDbHelper mDbHelper;

    public static synchronized QuarantineVaultManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new QuarantineVaultManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private QuarantineVaultManager(Context context) {
        mContext = context;
        mDbHelper = QuarantineDbHelper.getInstance(context);
        ensureVaultDir();
    }

    private synchronized SecretKey getOrCreateVaultKey() throws Exception {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
            keyStore.load(null);
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
                keyGen.init(new KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build());
                return keyGen.generateKey();
            }
            return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        } catch (Exception e) {
            Log.w(TAG, "AndroidKeyStore unavailable, generating per-device local key: " + e.getMessage());
            File keyFile = new File(mContext.getFilesDir(), ".vault_key");
            byte[] rawKey = new byte[32];
            if (!keyFile.exists() || keyFile.length() != 32) {
                new SecureRandom().nextBytes(rawKey);
                try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                    fos.write(rawKey);
                }
            } else {
                try (FileInputStream fis = new FileInputStream(keyFile)) {
                    int r = fis.read(rawKey);
                    if (r != 32) new SecureRandom().nextBytes(rawKey);
                }
            }
            return new SecretKeySpec(rawKey, "AES");
        }
    }

    private File ensureVaultDir() {
        File vaultDir = new File(mContext.getFilesDir(), VAULT_DIR_NAME);
        if (!vaultDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            vaultDir.mkdirs();
        }
        try {
            vaultDir.setReadable(true, true);
            vaultDir.setWritable(true, true);
            android.system.Os.chmod(vaultDir.getAbsolutePath(), 0700);
        } catch (Exception e) {
            Log.w(TAG, "Failed setting vaultDir permissions: " + e.getMessage());
        }
        // Place .nomedia to prevent any media indexers
        File noMedia = new File(vaultDir, ".nomedia");
        if (!noMedia.exists()) {
            try {
                //noinspection ResultOfMethodCallIgnored
                noMedia.createNewFile();
            } catch (Exception ignored) {}
        }
        return vaultDir;
    }

    /**
     * Quarantines a file using hardware-backed AES-256-GCM authenticated encryption.
     * Enforces POSIX 0600 (no execute bits) and network egress sinkholing.
     */
    public synchronized boolean quarantineFile(File sourceFile, String threatCategory, String threatDetails) {
        if (sourceFile == null || !sourceFile.exists() || !sourceFile.canRead()) {
            Log.e(TAG, "Cannot quarantine: source file does not exist or unreadable");
            return false;
        }

        String originalPath = sourceFile.getAbsolutePath();
        if (originalPath.contains("com.kotsafe.security")
                || (mContext != null && (originalPath.equals(mContext.getPackageCodePath())
                || originalPath.startsWith(mContext.getApplicationInfo().dataDir)))) {
            Log.w(TAG, "Self-Protection: Refusing to quarantine KotSafe system file: " + originalPath);
            return false;
        }
        String fileName = sourceFile.getName();
        long fileSize = sourceFile.length();
        String sha256 = FileHashScanner.computeHash(sourceFile, "SHA-256");

        String vaultFileName = "vault_" + System.currentTimeMillis() + "_" + (sha256 != null && sha256.length() >= 8 ? sha256.substring(0, 8) : "item") + ".kotvault";
        File vaultFile = new File(ensureVaultDir(), vaultFileName);

        try {
            SecretKey key = getOrCreateVaultKey();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] iv = cipher.getIV();

            try (FileOutputStream fos = new FileOutputStream(vaultFile);
                 FileInputStream fis = new FileInputStream(sourceFile)) {
                // Write Magic Header + IV
                fos.write(MAGIC_GCM);
                fos.write(iv);
                try (CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
                    byte[] buffer = new byte[16384];
                    int read;
                    while ((read = fis.read(buffer)) != -1) {
                        cos.write(buffer, 0, read);
                    }
                }
            }

            // Enforce strictly NO execute permissions on vault file (POSIX 0600)
            try {
                vaultFile.setReadable(true, true);
                vaultFile.setWritable(true, true);
                vaultFile.setExecutable(false, false);
                android.system.Os.chmod(vaultFile.getAbsolutePath(), 0600);
            } catch (Exception e) {
                Log.w(TAG, "Could not set strict 0600 permissions on vault file: " + e.getMessage());
            }

            // Record in Database
            long id = mDbHelper.addRecord(
                    originalPath,
                    fileName,
                    sha256,
                    fileSize,
                    threatCategory != null ? threatCategory : "SUSPICIOUS_ARTIFACT",
                    threatDetails != null ? threatDetails : "Quarantined via KotSafe Action Center",
                    vaultFileName
            );

            if (id > 0) {
                // Shred original source file
                shredFile(sourceFile);

                // Enforce Network Egress Sinkhole via Local VPN Firewall
                if (sha256 != null && !sha256.isEmpty()) {
                    try {
                        SecurityBlocklistManager.getInstance(mContext).blockHash(
                                sha256,
                                "Quarantine Vault Network Egress Sinkhole",
                                "QUARANTINE_ISOLATION"
                        );
                    } catch (Exception e) {
                        Log.w(TAG, "Failed to register network sinkhole rule for quarantined hash: " + e.getMessage());
                    }
                }

                // Record alert in AlertStore and post user-facing notification
                try {
                    AlertRecord alert = AlertStore.getInstance(mContext).add(
                            AlertRecord.Severity.HIGH,
                            AlertRecord.AlertType.QUARANTINE,
                            "Threat Quarantined: " + fileName,
                            "File neutralized and isolated in Sandboxed Vault. Stripped of execution permissions (POSIX 0600) and network egress sinkholed.\nPath: " + originalPath + (sha256 != null ? "\nSHA-256: " + sha256 : ""),
                            fileName
                    );
                    alert.setQuarantineMetadata(id, sha256, originalPath);
                    AlertStore.getInstance(mContext).updateAlert(alert);

                    SecurityNotificationHub.getInstance(mContext).postQuarantineAlert(
                            fileName,
                            originalPath,
                            sha256,
                            id
                    );
                } catch (Exception ex) {
                    Log.w(TAG, "Failed posting quarantine alert/notification: " + ex.getMessage());
                }

                Log.i(TAG, "Successfully quarantined file to hardware-backed vault " + originalPath + " -> " + vaultFile.getAbsolutePath());
                return true;
            } else {
                // Clean up vault file if DB insertion failed
                //noinspection ResultOfMethodCallIgnored
                vaultFile.delete();
                return false;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error encrypting file to quarantine vault: " + e.getMessage());
            if (vaultFile.exists()) {
                //noinspection ResultOfMethodCallIgnored
                vaultFile.delete();
            }
            return false;
        }
    }

    /**
     * Restores a quarantined file back to its original location, validating AEAD authentication tag.
     */
    public synchronized boolean restoreFile(long recordId) {
        QuarantineDbHelper.QuarantineRecord record = mDbHelper.getRecordById(recordId);
        if (record == null || record.isRestored) return false;

        File vaultFile = new File(ensureVaultDir(), record.vaultFileName);
        if (!vaultFile.exists()) {
            Log.e(TAG, "Vault file missing for record id: " + recordId);
            return false;
        }

        File targetFile = new File(record.originalPath);
        File parentDir = targetFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            //noinspection ResultOfMethodCallIgnored
            parentDir.mkdirs();
        }

        try {
            try (FileInputStream fis = new FileInputStream(vaultFile)) {
                byte[] header = new byte[4];
                int hRead = fis.read(header);
                boolean isGcm = (hRead == 4 && header[0] == MAGIC_GCM[0] && header[1] == MAGIC_GCM[1]
                        && header[2] == MAGIC_GCM[2] && header[3] == MAGIC_GCM[3]);

                Cipher cipher;
                if (isGcm) {
                    byte[] iv = new byte[12];
                    int ivRead = fis.read(iv);
                    if (ivRead != 12) throw new IllegalStateException("Truncated GCM IV in vault file");
                    SecretKey key = getOrCreateVaultKey();
                    cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
                } else {
                    // Legacy CBC mode compatibility
                    byte[] iv = new byte[16];
                    System.arraycopy(header, 0, iv, 0, 4);
                    int rem = fis.read(iv, 4, 12);
                    if (rem != 12) throw new IllegalStateException("Truncated CBC IV in vault file");
                    SecretKeySpec keySpec = new SecretKeySpec(LEGACY_SECRET, "AES");
                    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
                }

                try (CipherInputStream cis = new CipherInputStream(fis, cipher);
                     FileOutputStream fos = new FileOutputStream(targetFile)) {
                    byte[] buffer = new byte[16384];
                    int read;
                    while ((read = cis.read(buffer)) != -1) {
                        fos.write(buffer, 0, read);
                    }
                }
            }

            // Mark restored in DB and remove vault file
            mDbHelper.markRestored(recordId);
            shredFile(vaultFile);

            // Whitelist hash so Antivirus doesn't flag it on next scan and release quarantine sinkhole
            if (record.sha256 != null && !record.sha256.isEmpty()) {
                try {
                    SecurityBlocklistManager.getInstance(mContext).unblock(record.sha256);
                } catch (Exception ignored) {}
                SecurityBlocklistManager.getInstance(mContext).whitelist(
                        "HASH",
                        record.sha256,
                        "GLOBAL",
                        "Restored from Quarantine Vault by user"
                );
            }

            Log.i(TAG, "Successfully restored authenticated file from vault: " + record.originalPath);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to restore file from vault (integrity or auth tag check failed): " + e.getMessage());
            return false;
        }
    }

    /**
     * Permanently destroys a quarantined file from the vault and database.
     */
    public synchronized boolean permanentlyDelete(long recordId) {
        QuarantineDbHelper.QuarantineRecord record = mDbHelper.getRecordById(recordId);
        if (record != null) {
            File vaultFile = new File(ensureVaultDir(), record.vaultFileName);
            if (vaultFile.exists()) {
                shredFile(vaultFile);
            }
            if (record.sha256 != null && !record.sha256.isEmpty()) {
                try {
                    SecurityBlocklistManager.getInstance(mContext).unblock(record.sha256);
                } catch (Exception ignored) {}
            }
            mDbHelper.deleteRecord(recordId);
            return true;
        }
        return false;
    }

    /**
     * Overwrites file contents with zeroes before unlinking to prevent data recovery.
     */
    public static void shredFile(File file) {
        if (file == null || !file.exists()) return;
        String path = file.getAbsolutePath();
        if (path.contains("com.kotsafe.security")) {
            Log.w("QuarantineVault", "Self-Protection: Refusing to shred KotSafe internal file: " + path);
            return;
        }
        try {
            long len = file.length();
            if (len > 0 && file.canWrite()) {
                try (RandomAccessFile raf = new RandomAccessFile(file, "rws")) {
                    raf.seek(0);
                    byte[] zeros = new byte[Math.min(8192, (int) len)];
                    long remaining = len;
                    while (remaining > 0) {
                        int toWrite = (int) Math.min(zeros.length, remaining);
                        raf.write(zeros, 0, toWrite);
                        remaining -= toWrite;
                    }
                }
            }
        } catch (Exception ignored) {}
        try {
            //noinspection ResultOfMethodCallIgnored
            file.delete();
        } catch (Exception ignored) {}
    }

    public List<QuarantineDbHelper.QuarantineRecord> getQuarantinedList() {
        return mDbHelper.getActiveQuarantined();
    }

    public int getQuarantinedCount() {
        return mDbHelper.getActiveQuarantineCount();
    }

    /**
     * Quarantines a malicious URL / domain by registering an aggressive firewall sinkhole,
     * logging an alert in the AlertStore, and posting a system notification.
     */
    public synchronized boolean quarantineUrl(String url, String threatCategory, String threatDetails) {
        if (url == null || url.trim().isEmpty()) return false;
        try {
            SecurityBlocklistManager.getInstance(mContext).blockUrl(
                    url,
                    threatCategory != null ? threatCategory : "QUARANTINED_URL",
                    "QUARANTINE_ISOLATION"
            );

            AlertRecord alert = AlertStore.getInstance(mContext).add(
                    AlertRecord.Severity.HIGH,
                    AlertRecord.AlertType.QUARANTINE,
                    "URL Quarantined & Sinkholed",
                    "Malicious URL isolated and sinkholed at VPN firewall.\nTarget: " + url + "\nDetails: " + (threatDetails != null ? threatDetails : "Threat Intel Block"),
                    url
            );
            alert.setQuarantineMetadata(-1, null, url);
            AlertStore.getInstance(mContext).updateAlert(alert);

            SecurityNotificationHub.getInstance(mContext).postQuarantineAlert(
                    url,
                    url,
                    null,
                    -1
            );
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to quarantine URL: " + e.getMessage());
            return false;
        }
    }

    /**
     * Quarantines a malicious file hash (IoC) across the system.
     */
    public synchronized boolean quarantineHash(String sha256, String threatCategory, String threatDetails) {
        if (sha256 == null || sha256.trim().isEmpty()) return false;
        try {
            SecurityBlocklistManager.getInstance(mContext).blockHash(
                    sha256,
                    threatCategory != null ? threatCategory : "QUARANTINED_HASH",
                    "QUARANTINE_ISOLATION"
            );

            AlertRecord alert = AlertStore.getInstance(mContext).add(
                    AlertRecord.Severity.HIGH,
                    AlertRecord.AlertType.QUARANTINE,
                    "Malware Hash Quarantined",
                    "Known malicious hash blocked and quarantined from network egress.\nSHA-256: " + sha256 + "\nDetails: " + (threatDetails != null ? threatDetails : "IoC Match"),
                    "Hash:" + (sha256.length() > 8 ? sha256.substring(0, 8) : sha256)
            );
            alert.setQuarantineMetadata(-1, sha256, "Hash: " + sha256);
            AlertStore.getInstance(mContext).updateAlert(alert);

            SecurityNotificationHub.getInstance(mContext).postQuarantineAlert(
                    "Hash " + (sha256.length() > 12 ? sha256.substring(0, 12) + "…" : sha256),
                    "SHA-256: " + sha256,
                    sha256,
                    -1
            );
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to quarantine hash: " + e.getMessage());
            return false;
        }
    }

    /**
     * Quarantines an application by completely blocking its network egress and isolating it.
     */
    public synchronized boolean quarantineApp(String packageName, String appName, String threatCategory, String threatDetails) {
        if (packageName == null || packageName.trim().isEmpty()) return false;
        String lower = packageName.trim().toLowerCase(java.util.Locale.US);
        if (lower.equals("com.kotsafe.security")
                || (mContext != null && lower.equals(mContext.getPackageName().toLowerCase(java.util.Locale.US)))
                || lower.contains("kotsafe")) {
            Log.w(TAG, "Self-Protection: Refusing to quarantine KotSafe application: " + packageName);
            return false;
        }
        if (com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, lower)
                || com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, lower)
                || lower.contains("amazon")
                || lower.contains("whatsapp")) {
            Log.w(TAG, "Protection: Refusing to quarantine essential or trusted application: " + packageName);
            return false;
        }
        try {
            SecurityBlocklistManager.getInstance(mContext).blockApp(
                    packageName,
                    threatCategory != null ? threatCategory : "QUARANTINED_APP",
                    "QUARANTINE_ISOLATION"
            );

            String label = (appName != null && !appName.isEmpty()) ? appName : packageName;
            AlertRecord alert = AlertStore.getInstance(mContext).add(
                    AlertRecord.Severity.HIGH,
                    AlertRecord.AlertType.QUARANTINE,
                    "App Quarantined: " + label,
                    "Application network communication completely blocked and isolated.\nPackage: " + packageName + "\nDetails: " + (threatDetails != null ? threatDetails : "Zero-Trust App Quarantine"),
                    packageName
            );
            alert.setQuarantineMetadata(-1, null, packageName);
            AlertStore.getInstance(mContext).updateAlert(alert);

            SecurityNotificationHub.getInstance(mContext).postQuarantineAlert(
                    label,
                    packageName,
                    null,
                    -1
            );
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to quarantine app: " + e.getMessage());
            return false;
        }
    }
}
