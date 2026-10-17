/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;

import com.google.android.gms.auth.api.signin.GoogleSignIn;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.AuthCredential;
import android.util.Base64;
import android.util.Log;
import com.google.firebase.auth.EmailAuthProvider;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.firestore.FieldValue;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.SetOptions;
import com.kotsafe.security.R;
import com.kotsafe.security.activities.LoginActivity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.Query;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Central identity and authentication manager for KotSafe.
 * Enforces Zero-Trust auth gates across P2P mesh nodes, account security,
 * password resets, and session lifecycle.
 */
public class KotSafeUserManager {

    public static final String KEY_GUEST_MODE = "guest_mode_active";
    public static final String KEY_2FA_ENABLED = "auth_2fa_enabled";
    public static final String KEY_2FA_SECRET = "auth_2fa_secret";
    public static final String CRYPTO_PREFIX = "enc:v1:";
    private static final String APP_SALT = "KotSafe-ZeroTrust-Cloud-Salt-2026";

    private static SecretKey deriveUserCryptoKey(String uid) {
        try {
            String seed = (uid != null ? uid : "default_uid") + APP_SALT;
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = sha256.digest(seed.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 unavailable", e);
        }
    }

    public static String encryptSecretForCloud(String uid, String plaintextSecret) {
        if (plaintextSecret == null || plaintextSecret.isEmpty()) return plaintextSecret;
        if (plaintextSecret.startsWith(CRYPTO_PREFIX)) return plaintextSecret;
        try {
            SecretKey key = deriveUserCryptoKey(uid);
            byte[] iv = new byte[12]; // 96-bit standard GCM IV
            new SecureRandom().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ciphertext = cipher.doFinal(plaintextSecret.getBytes(StandardCharsets.UTF_8));

            ByteBuffer buffer = ByteBuffer.allocate(iv.length + ciphertext.length);
            buffer.put(iv);
            buffer.put(ciphertext);
            return CRYPTO_PREFIX + Base64.encodeToString(buffer.array(), Base64.NO_WRAP);
        } catch (Exception e) {
            Log.e("KotSafeUserManager", "Failed to encrypt secret: " + e.getMessage());
            return plaintextSecret;
        }
    }

    public static String decryptSecretFromCloud(String uid, String rawSecret) {
        if (rawSecret == null || !rawSecret.startsWith(CRYPTO_PREFIX)) {
            return rawSecret;
        }
        try {
            String b64 = rawSecret.substring(CRYPTO_PREFIX.length());
            byte[] combined = Base64.decode(b64, Base64.NO_WRAP);
            if (combined.length < 12 + 16) return rawSecret;

            byte[] iv = new byte[12];
            System.arraycopy(combined, 0, iv, 0, 12);
            byte[] ciphertext = new byte[combined.length - 12];
            System.arraycopy(combined, 12, ciphertext, 0, ciphertext.length);

            SecretKey key = deriveUserCryptoKey(uid);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] decrypted = cipher.doFinal(ciphertext);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e("KotSafeUserManager", "Failed to decrypt secret: " + e.getMessage());
            return null;
        }
    }

    public interface Callback<T> {
        void onSuccess(T result);
        void onError(String message);
    }

    public static boolean isGuestMode(Context context) {
        if (context == null) return false;
        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        return prefs.getBoolean(KEY_GUEST_MODE, false);
    }

    public static void setGuestMode(Context context, boolean active) {
        if (context == null) return;
        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_GUEST_MODE, active).apply();
    }

    public static boolean isUserAuthenticated(Context context) {
        if (context == null) return false;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                if (user != null && !user.isAnonymous()) {
                    boolean isPasswordUser = false;
                    for (com.google.firebase.auth.UserInfo info : user.getProviderData()) {
                        if ("password".equals(info.getProviderId())) {
                            isPasswordUser = true;
                            break;
                        }
                    }
                    if (isPasswordUser && !user.isEmailVerified()) {
                        return false;
                    }
                    return true;
                } else if (user == null) {
                    return false;
                }
            }
        } catch (Exception ignored) {}

        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        String email = prefs.getString(LoginActivity.KEY_LOGGED_IN_EMAIL, null);
        return email != null && !email.trim().isEmpty();
    }

    public static String getLoggedInEmail(Context context) {
        if (context == null) return null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                if (user != null && user.getEmail() != null && !user.getEmail().isEmpty()) {
                    return user.getEmail();
                }
            }
        } catch (Exception ignored) {}

        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        return prefs.getString(LoginActivity.KEY_LOGGED_IN_EMAIL, null);
    }

    public static String getDisplayName(Context context) {
        if (context == null) return "KotSafe Sentinel";
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                if (user != null && user.getDisplayName() != null && !user.getDisplayName().isEmpty()) {
                    return user.getDisplayName();
                }
            }
        } catch (Exception ignored) {}

        String email = getLoggedInEmail(context);
        if (email != null && email.contains("@")) {
            return email.substring(0, email.indexOf('@'));
        }
        return "KotSafe Sentinel";
    }

    public static String getUid(Context context) {
        if (context == null) return null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
                if (user != null) return user.getUid();
            }
        } catch (Exception ignored) {}

        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        return prefs.getString(LoginActivity.KEY_LOGGED_IN_UID, null);
    }

    public static final String EXTRA_AUTH_REQUIRED_MESSAGE = "extra_auth_required_message";

    /**
     * Redirect immediately to Login screen with notice pill and toast
     */
    public static void redirectToLoginWithNotice(Activity activity, String featureName) {
        if (activity == null || activity.isFinishing()) return;
        Toast.makeText(activity, "You need to sign-in to use this feature", Toast.LENGTH_LONG).show();
        Intent intent = new Intent(activity, LoginActivity.class);
        intent.putExtra(EXTRA_AUTH_REQUIRED_MESSAGE, "You need to sign-in to use this feature");
        intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        activity.startActivity(intent);
    }

    /**
     * Show Zero-Trust dialog requiring authentication before proceeding
     */
    public static void showAuthRequiredDialog(Activity activity, String featureName) {
        if (activity == null || activity.isFinishing()) return;

        new AlertDialog.Builder(activity)
                .setTitle("🔒 Cloud Authentication Required")
                .setMessage("To use " + featureName + ", you must be signed in with your KotSafe Cloud identity.\n\n" +
                        "Authentication verifies peer trust, protects personal mesh nodes, and activates end-to-end tunnel encryption.")
                .setPositiveButton("Sign In Now", (dialog, which) -> {
                    dialog.dismiss();
                    redirectToLoginWithNotice(activity, featureName);
                })
                .setNegativeButton("Cancel", (dialog, which) -> dialog.dismiss())
                .setCancelable(true)
                .show();
    }

    /**
     * Send password reset email via Firebase Auth
     */
    public static void sendPasswordResetEmail(Context context, String email, Callback<Void> callback) {
        if (email == null || email.trim().isEmpty()) {
            if (callback != null) callback.onError("Please provide a valid email address.");
            return;
        }

        try {
            FirebaseAuth.getInstance().sendPasswordResetEmail(email.trim())
                    .addOnSuccessListener(unused -> {
                        if (callback != null) callback.onSuccess(null);
                    })
                    .addOnFailureListener(e -> {
                        if (callback != null) callback.onError(e.getMessage());
                    });
        } catch (Exception e) {
            if (callback != null) callback.onError(e.getMessage());
        }
    }

    /**
     * Change user password with re-authentication
     */
    public static void changePassword(String currentPassword, String newPassword, Callback<Void> callback) {
        FirebaseUser user = FirebaseAuth.getInstance().getCurrentUser();
        if (user == null || user.getEmail() == null) {
            if (callback != null) callback.onError("You must be signed in to change your password.");
            return;
        }

        if (newPassword == null || newPassword.length() < 8) {
            if (callback != null) callback.onError("New password must be at least 8 characters long.");
            return;
        }

        AuthCredential credential = EmailAuthProvider.getCredential(user.getEmail(), currentPassword);
        user.reauthenticate(credential).addOnSuccessListener(unused -> {
            user.updatePassword(newPassword).addOnSuccessListener(res -> {
                if (callback != null) callback.onSuccess(null);
            }).addOnFailureListener(e -> {
                if (callback != null) callback.onError("Password update failed: " + e.getMessage());
            });
        }).addOnFailureListener(e -> {
            if (callback != null) callback.onError("Current password is incorrect.");
        });
    }

    /**
     * Complete sign out clearing session and tokens
     */
    public static void signOut(Activity activity, Runnable onComplete) {
        try {
            if (!FirebaseApp.getApps(activity).isEmpty()) {
                FirebaseAuth.getInstance().signOut();
            }
            GoogleSignIn.getClient(activity, GoogleSignInOptions.DEFAULT_SIGN_IN).signOut();
        } catch (Exception ignored) {}

        SharedPreferences prefs = activity.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        prefs.edit()
                .remove(LoginActivity.KEY_LOGGED_IN_EMAIL)
                .remove(LoginActivity.KEY_LOGGED_IN_UID)
                .remove(KEY_GUEST_MODE)
                .remove(KEY_2FA_ENABLED)
                .remove(KEY_2FA_SECRET)
                .remove(KEY_2FA_LAST_USED_WINDOW)
                .remove(KEY_2FA_ENROLLED_AT)
                .apply();

        Toast.makeText(activity, "Signed out successfully", Toast.LENGTH_SHORT).show();
        if (onComplete != null) onComplete.run();
    }

    /**
     * Check if Two-Factor Authentication (2FA) is enabled for the current account.
     * Queries Firestore live, falling back to local cached preferences.
     */
    public static void isTwoFactorEnabled(Context context, Callback<Boolean> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Context null");
            return;
        }

        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}

        if (user == null) {
            SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
            boolean local2fa = prefs.getBoolean(KEY_2FA_ENABLED, false);
            if (callback != null) callback.onSuccess(local2fa);
            return;
        }

        String uid = user.getUid();
        try {
            FirebaseFirestore db = FirebaseFirestore.getInstance();
            db.collection("users").document(uid).get()
                    .addOnSuccessListener(snapshot -> {
                        boolean enabled = false;
                        if (snapshot.exists()) {
                            Boolean f2a = snapshot.getBoolean("twoFactorEnabled");
                            enabled = f2a != null && f2a;
                        }
                        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
                        prefs.edit().putBoolean(KEY_2FA_ENABLED, enabled).apply();
                        if (callback != null) callback.onSuccess(enabled);
                    })
                    .addOnFailureListener(e -> {
                        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
                        boolean local2fa = prefs.getBoolean(KEY_2FA_ENABLED, false);
                        if (callback != null) callback.onSuccess(local2fa);
                    });
        } catch (Exception e) {
            SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
            boolean local2fa = prefs.getBoolean(KEY_2FA_ENABLED, false);
            if (callback != null) callback.onSuccess(local2fa);
        }
    }

    /**
     * Retrieve the user's enrolled TOTP secret key
     */
    public static void getTwoFactorSecret(Context context, Callback<String> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Context null");
            return;
        }

        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}

        if (user == null) {
            SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
            String secret = prefs.getString(KEY_2FA_SECRET, null);
            if (callback != null) callback.onSuccess(secret);
            return;
        }

        String uid = user.getUid();
        try {
            FirebaseFirestore db = FirebaseFirestore.getInstance();
            db.collection("users").document(uid).get()
                    .addOnSuccessListener(snapshot -> {
                        String secret = null;
                        if (snapshot.exists()) {
                            String cloudRaw = snapshot.getString("twoFactorSecret");
                            if (cloudRaw == null || cloudRaw.isEmpty()) {
                                cloudRaw = snapshot.getString("securityPosture.twoFactorSecret");
                            }
                            if (cloudRaw != null && !cloudRaw.isEmpty()) {
                                if (cloudRaw.startsWith(CRYPTO_PREFIX)) {
                                    secret = decryptSecretFromCloud(uid, cloudRaw);
                                } else {
                                    secret = cloudRaw;
                                    // Auto-upgrade existing plaintext secret to AES-256-GCM in Firestore
                                    String encrypted = encryptSecretForCloud(uid, cloudRaw);
                                    Map<String, Object> up = new HashMap<>();
                                    up.put("twoFactorSecret", encrypted);
                                    if (snapshot.contains("securityPosture.twoFactorSecret")) {
                                        up.put("securityPosture.twoFactorSecret", FieldValue.delete());
                                    }
                                    db.collection("users").document(uid).update(up);
                                }
                            }
                        }
                        if (secret == null) {
                            SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
                            secret = prefs.getString(KEY_2FA_SECRET, null);
                        }
                        if (callback != null) callback.onSuccess(secret);
                    })
                    .addOnFailureListener(e -> {
                        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
                        String secret = prefs.getString(KEY_2FA_SECRET, null);
                        if (callback != null) callback.onSuccess(secret);
                    });
        } catch (Exception e) {
            SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
            String secret = prefs.getString(KEY_2FA_SECRET, null);
            if (callback != null) callback.onSuccess(secret);
        }
    }

    public static final String KEY_2FA_LAST_USED_WINDOW = "kotsafe_2fa_last_used_window";
    public static final String KEY_2FA_ENROLLED_AT = "kotsafe_2fa_enrolled_at";

    public static long getLastUsedTotpWindow(Context context) {
        if (context == null) return -1;
        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        return prefs.getLong(KEY_2FA_LAST_USED_WINDOW, -1);
    }

    public static void updateLastUsedTotpWindow(Context context, long window) {
        if (context == null) return;
        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        prefs.edit().putLong(KEY_2FA_LAST_USED_WINDOW, window).apply();
    }

    /**
     * Automatically scan and upgrade existing plaintext 2FA secrets in Firestore to AES-256-GCM
     */
    public static void autoEncryptPlaintextSecretIfPresent(Context context) {
        if (context == null) return;
        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}
        if (user == null) return;

        String uid = user.getUid();
        try {
            FirebaseFirestore db = FirebaseFirestore.getInstance();
            db.collection("users").document(uid).get()
                    .addOnSuccessListener(snapshot -> {
                        if (snapshot.exists()) {
                            String raw = snapshot.getString("twoFactorSecret");
                            boolean fromPosture = false;
                            if (raw == null || raw.isEmpty()) {
                                raw = snapshot.getString("securityPosture.twoFactorSecret");
                                fromPosture = true;
                            }
                            if (raw != null && !raw.isEmpty() && !raw.startsWith(CRYPTO_PREFIX)) {
                                String encrypted = encryptSecretForCloud(uid, raw);
                                Map<String, Object> up = new HashMap<>();
                                up.put("twoFactorSecret", encrypted);
                                if (fromPosture || snapshot.contains("securityPosture.twoFactorSecret")) {
                                    up.put("securityPosture.twoFactorSecret", FieldValue.delete());
                                }
                                db.collection("users").document(uid).update(up);
                                Log.i("KotSafeUserManager", "Upgraded Firestore 2FA secret to AES-256-GCM!");
                            }
                        }
                    });
        } catch (Exception ignored) {}
    }

    /**
     * Enable 2FA after verifying the first 6-digit TOTP code with replay check
     */
    public static void enableTwoFactor(Context context, String secret, String verificationCode, Callback<Void> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Invalid application context.");
            return;
        }

        long lastWindow = getLastUsedTotpWindow(context);
        TotpHelper.TotpValidationResult result = TotpHelper.verifyCodeWithWindow(secret, verificationCode, lastWindow);

        if (!result.isValid) {
            if (callback != null) callback.onError(result.errorMessage != null ? result.errorMessage : "Invalid 6-digit code. Please verify against your Authenticator app.");
            return;
        }

        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        prefs.edit()
                .putBoolean(KEY_2FA_ENABLED, true)
                .putString(KEY_2FA_SECRET, secret)
                .putLong(KEY_2FA_LAST_USED_WINDOW, result.matchedWindow)
                .putLong(KEY_2FA_ENROLLED_AT, System.currentTimeMillis())
                .apply();

        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}

        if (user != null) {
            String uid = user.getUid();
            String encryptedSecret = encryptSecretForCloud(uid, secret);

            java.util.Map<String, Object> update = new java.util.HashMap<>();
            update.put("uid", uid);
            if (user.getEmail() != null) update.put("email", user.getEmail());
            if (user.getDisplayName() != null) update.put("displayName", user.getDisplayName());
            update.put("deviceStatus", "ONLINE");
            update.put("activeDeviceModel", android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL);
            update.put("lastActiveTime", FieldValue.serverTimestamp());
            update.put("twoFactorEnabled", true);
            update.put("twoFactorSecret", encryptedSecret);
            update.put("twoFactorType", "TOTP");
            update.put("twoFactorEnrolledAt", FieldValue.serverTimestamp());

            try {
                FirebaseFirestore.getInstance().collection("users").document(uid)
                        .set(update, SetOptions.merge())
                        .addOnSuccessListener(unused -> {
                            logSecurityEvent(context, "TWO_FACTOR_ENABLED", "2-Step Verification enabled", "Authenticator App (TOTP) paired with Zero-Knowledge AES-256 encryption");
                            if (callback != null) callback.onSuccess(null);
                        })
                        .addOnFailureListener(e -> {
                            String err = e.getMessage() != null ? e.getMessage() : "Network error syncing 2FA to cloud";
                            if (callback != null) callback.onError(err);
                        });
                return;
            } catch (Exception e) {
                if (callback != null) callback.onError("Cloud error: " + e.getMessage());
                return;
            }
        }

        if (callback != null) callback.onSuccess(null);
    }

    /**
     * Disable 2FA in Firestore and local settings
     */
    public static void disableTwoFactor(Context context, Callback<Void> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Invalid context");
            return;
        }

        SharedPreferences prefs = context.getSharedPreferences(LoginActivity.PREF_AUTH, Context.MODE_PRIVATE);
        prefs.edit()
                .putBoolean(KEY_2FA_ENABLED, false)
                .remove(KEY_2FA_SECRET)
                .remove(KEY_2FA_LAST_USED_WINDOW)
                .remove(KEY_2FA_ENROLLED_AT)
                .apply();

        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}

        if (user != null) {
            String uid = user.getUid();
            java.util.Map<String, Object> update = new java.util.HashMap<>();
            update.put("twoFactorEnabled", false);
            update.put("twoFactorSecret", FieldValue.delete());
            update.put("securityPosture.twoFactorSecret", FieldValue.delete());
            update.put("securityPosture.twoFactorEnabled", false);
            update.put("twoFactorRevokedAt", FieldValue.serverTimestamp());
            update.put("twoFactorLastRevocationReason", "User requested with verified authentication");
            update.put("deviceStatus", "ONLINE");
            update.put("lastActiveTime", FieldValue.serverTimestamp());

            try {
                FirebaseFirestore.getInstance().collection("users").document(uid)
                        .set(update, SetOptions.merge())
                        .addOnSuccessListener(unused -> {
                            logSecurityEvent(context, "TWO_FACTOR_DISABLED", "2-Step Verification disabled", "Two-factor authentication turned off with verified credentials");
                            if (callback != null) callback.onSuccess(null);
                        })
                        .addOnFailureListener(e -> {
                            String err = e.getMessage() != null ? e.getMessage() : "Network error updating cloud 2FA";
                            if (callback != null) callback.onError(err);
                        });
                return;
            } catch (Exception e) {
                if (callback != null) callback.onError("Cloud error: " + e.getMessage());
                return;
            }
        }

        if (callback != null) callback.onSuccess(null);
    }

    /**
     * Google-grade 2FA Revocation: Requires current 6-digit Authenticator code verification
     */
    public static void disableTwoFactorWithTotp(Context context, String totpCode, Callback<Void> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Invalid context");
            return;
        }

        getTwoFactorSecret(context, new Callback<String>() {
            @Override
            public void onSuccess(String secret) {
                if (secret == null || secret.isEmpty()) {
                    // No secret found, disable directly
                    disableTwoFactor(context, callback);
                    return;
                }

                long lastWindow = getLastUsedTotpWindow(context);
                TotpHelper.TotpValidationResult result = TotpHelper.verifyCodeWithWindow(secret, totpCode, lastWindow);
                if (!result.isValid) {
                    if (callback != null) callback.onError(result.errorMessage != null ? result.errorMessage : "Invalid 6-digit code. Please enter the current code from your Authenticator app.");
                    return;
                }

                updateLastUsedTotpWindow(context, result.matchedWindow);
                disableTwoFactor(context, callback);
            }

            @Override
            public void onError(String message) {
                if (callback != null) callback.onError("Could not verify secret: " + message);
            }
        });
    }

    /**
     * Google-grade 2FA Revocation Fallback: Requires re-authenticating with account password
     */
    public static void disableTwoFactorWithPassword(Context context, String password, Callback<Void> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Invalid context");
            return;
        }

        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}

        if (user == null || user.getEmail() == null) {
            if (callback != null) callback.onError("You must be signed in to verify your password.");
            return;
        }

        AuthCredential credential = EmailAuthProvider.getCredential(user.getEmail(), password);
        user.reauthenticate(credential)
                .addOnSuccessListener(unused -> disableTwoFactor(context, callback))
                .addOnFailureListener(e -> {
                    if (callback != null) callback.onError("Incorrect password. Identity verification failed.");
                });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // 10 Single-Use Backup / Recovery Codes
    // ─────────────────────────────────────────────────────────────────────────────

    public static String hashBackupCode(String uid, String rawCode) {
        if (rawCode == null) return "";
        String clean = rawCode.replace("-", "").replaceAll("\\s+", "").trim();
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] input = (clean + ":" + uid + ":kotsafe_backup_salt_2026").getBytes(StandardCharsets.UTF_8);
            byte[] digest = md.digest(input);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return clean;
        }
    }

    public static void generateAndSaveBackupCodes(Context context, Callback<List<String>> callback) {
        if (context == null) {
            if (callback != null) callback.onError("Invalid context");
            return;
        }
        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}
        if (user == null) {
            if (callback != null) callback.onError("No authenticated user");
            return;
        }

        String uid = user.getUid();
        SecureRandom rand = new SecureRandom();
        List<String> rawCodes = new ArrayList<>();
        List<Map<String, Object>> listToStore = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            int part1 = 1000 + rand.nextInt(9000);
            int part2 = 1000 + rand.nextInt(9000);
            String code = String.format(java.util.Locale.US, "%04d-%04d", part1, part2);
            rawCodes.add(code);

            Map<String, Object> item = new HashMap<>();
            item.put("hash", hashBackupCode(uid, code));
            item.put("used", false);
            item.put("createdAt", System.currentTimeMillis());
            listToStore.add(item);
        }

        FirebaseFirestore.getInstance().collection("users").document(uid)
                .update("twoFactorBackupCodes", listToStore)
                .addOnSuccessListener(unused -> {
                    logSecurityEvent(context, "BACKUP_CODES_GENERATED", "10 Backup codes generated", "New single-use recovery codes created");
                    if (callback != null) callback.onSuccess(rawCodes);
                })
                .addOnFailureListener(e -> {
                    FirebaseFirestore.getInstance().collection("users").document(uid)
                            .set(java.util.Collections.singletonMap("twoFactorBackupCodes", listToStore), SetOptions.merge())
                            .addOnSuccessListener(u -> {
                                logSecurityEvent(context, "BACKUP_CODES_GENERATED", "10 Backup codes generated", "New single-use recovery codes created");
                                if (callback != null) callback.onSuccess(rawCodes);
                            })
                            .addOnFailureListener(err -> {
                                if (callback != null) callback.onError(err.getMessage());
                            });
                });
    }

    public static void getBackupCodesRemainingCount(Context context, Callback<Integer> callback) {
        if (context == null) {
            if (callback != null) callback.onSuccess(0);
            return;
        }
        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}
        if (user == null) {
            if (callback != null) callback.onSuccess(0);
            return;
        }

        FirebaseFirestore.getInstance().collection("users").document(user.getUid()).get()
                .addOnSuccessListener(snapshot -> {
                    int remaining = 0;
                    if (snapshot.exists()) {
                        List<Map<String, Object>> codes = (List<Map<String, Object>>) snapshot.get("twoFactorBackupCodes");
                        if (codes != null) {
                            for (Map<String, Object> item : codes) {
                                Boolean used = (Boolean) item.get("used");
                                if (used == null || !used) {
                                    remaining++;
                                }
                            }
                        }
                    }
                    if (callback != null) callback.onSuccess(remaining);
                })
                .addOnFailureListener(e -> {
                    if (callback != null) callback.onSuccess(0);
                });
    }

    public static void verifyAndConsumeBackupCode(Context context, String inputCode, Callback<Boolean> callback) {
        if (context == null || inputCode == null || inputCode.trim().isEmpty()) {
            if (callback != null) callback.onError("Invalid backup code");
            return;
        }

        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}
        if (user == null) {
            if (callback != null) callback.onError("No authenticated user");
            return;
        }

        String uid = user.getUid();
        String targetHash = hashBackupCode(uid, inputCode);
        FirebaseFirestore db = FirebaseFirestore.getInstance();

        db.collection("users").document(uid).get()
                .addOnSuccessListener(snapshot -> {
                    if (!snapshot.exists()) {
                        if (callback != null) callback.onSuccess(false);
                        return;
                    }
                    List<Map<String, Object>> codes = (List<Map<String, Object>>) snapshot.get("twoFactorBackupCodes");
                    if (codes == null || codes.isEmpty()) {
                        if (callback != null) callback.onSuccess(false);
                        return;
                    }

                    boolean matched = false;
                    List<Map<String, Object>> updatedList = new ArrayList<>();
                    for (Map<String, Object> item : codes) {
                        Map<String, Object> copy = new HashMap<>(item);
                        String h = (String) copy.get("hash");
                        Boolean used = (Boolean) copy.get("used");
                        if (!matched && targetHash.equals(h) && (used == null || !used)) {
                            copy.put("used", true);
                            copy.put("usedAt", System.currentTimeMillis());
                            matched = true;
                        }
                        updatedList.add(copy);
                    }

                    if (matched) {
                        db.collection("users").document(uid).update("twoFactorBackupCodes", updatedList);
                        logSecurityEvent(context, "BACKUP_CODE_USED", "Backup code used", "Single-use recovery code verified");
                        if (callback != null) callback.onSuccess(true);
                    } else {
                        if (callback != null) callback.onSuccess(false);
                    }
                })
                .addOnFailureListener(e -> {
                    if (callback != null) callback.onError(e.getMessage());
                });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Security Activity Audit Trail
    // ─────────────────────────────────────────────────────────────────────────────

    public static void logSecurityEvent(Context context, String eventType, String title, String description) {
        if (context == null) return;
        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}
        if (user == null) return;

        try {
            String uid = user.getUid();
            String deviceId = CloudSyncManager.getInstance(context).getDeviceId();
            Map<String, Object> event = new HashMap<>();
            event.put("eventType", eventType);
            event.put("title", title);
            event.put("description", description);
            event.put("deviceModel", android.os.Build.MANUFACTURER + " " + android.os.Build.MODEL);
            event.put("deviceId", deviceId != null ? deviceId : "unknown");
            event.put("timestamp", FieldValue.serverTimestamp());

            FirebaseFirestore.getInstance().collection("users").document(uid)
                    .collection("securityLogs")
                    .add(event);
        } catch (Exception ignored) {}
    }

    public static void getRecentSecurityLogs(Context context, int limit, Callback<List<Map<String, Object>>> callback) {
        if (context == null) {
            if (callback != null) callback.onSuccess(new ArrayList<>());
            return;
        }
        FirebaseUser user = null;
        try {
            if (!FirebaseApp.getApps(context).isEmpty()) {
                user = FirebaseAuth.getInstance().getCurrentUser();
            }
        } catch (Exception ignored) {}
        if (user == null) {
            if (callback != null) callback.onSuccess(new ArrayList<>());
            return;
        }

        try {
            FirebaseFirestore.getInstance().collection("users").document(user.getUid())
                    .collection("securityLogs")
                    .orderBy("timestamp", Query.Direction.DESCENDING)
                    .limit(limit > 0 ? limit : 20)
                    .get()
                    .addOnSuccessListener(querySnapshot -> {
                        List<Map<String, Object>> logs = new ArrayList<>();
                        for (DocumentSnapshot doc : querySnapshot.getDocuments()) {
                            Map<String, Object> data = doc.getData();
                            if (data != null) {
                                logs.add(data);
                            }
                        }
                        if (callback != null) callback.onSuccess(logs);
                    })
                    .addOnFailureListener(e -> {
                        if (callback != null) callback.onError(e.getMessage());
                    });
        } catch (Exception e) {
            if (callback != null) callback.onError(e.getMessage());
        }
    }
}
