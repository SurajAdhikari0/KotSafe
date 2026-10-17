/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.util.concurrent.Executor;

/**
 * Central Biometric Security Manager for KotSafe.
 * Manages fingerprint and face unlock authentication across app security gates.
 */
public class BiometricLockManager {
    public static final String PREF_BIOMETRICS = "kotsafe_biometric_prefs";
    public static final String KEY_BIOMETRIC_ENABLED = "biometric_lock_enabled";

    public static boolean isBiometricSupported(Context context) {
        if (context == null) return false;
        try {
            BiometricManager bm = BiometricManager.from(context);
            int status = bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.BIOMETRIC_WEAK);
            return status == BiometricManager.BIOMETRIC_SUCCESS;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isBiometricEnabled(Context context) {
        if (context == null) return false;
        SharedPreferences prefs = context.getSharedPreferences(PREF_BIOMETRICS, Context.MODE_PRIVATE);
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, false);
    }

    public static void setBiometricEnabled(Context context, boolean enabled) {
        if (context == null) return;
        SharedPreferences prefs = context.getSharedPreferences(PREF_BIOMETRICS, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).apply();
    }

    public interface AuthCallback {
        void onSuccess();
        void onError(String message);
        void onCancelled();
    }

    public static void authenticate(FragmentActivity activity, String title, String subtitle, AuthCallback callback) {
        if (activity == null || activity.isFinishing()) {
            if (callback != null) callback.onError("Invalid activity state");
            return;
        }

        Executor executor = ContextCompat.getMainExecutor(activity);
        BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                if (errorCode == BiometricPrompt.ERROR_USER_CANCELED || errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                    if (callback != null) callback.onCancelled();
                } else {
                    if (callback != null) callback.onError(errString.toString());
                }
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                if (callback != null) callback.onSuccess();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
            }
        });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title != null ? title : "KotSafe Biometric Security")
                .setSubtitle(subtitle != null ? subtitle : "Verify your identity using fingerprint or face")
                .setNegativeButtonText("Cancel")
                .setConfirmationRequired(false)
                .build();

        biometricPrompt.authenticate(promptInfo);
    }
}
