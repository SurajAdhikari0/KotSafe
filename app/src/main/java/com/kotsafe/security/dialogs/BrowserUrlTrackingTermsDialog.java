/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.dialogs;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.provider.Settings;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.kotsafe.security.R;
import com.kotsafe.security.model.Prefs;

public class BrowserUrlTrackingTermsDialog {

    public interface OnTermsAcceptedListener {
        void onAccepted();
    }

    public static void show(@NonNull Context context, @Nullable OnTermsAcceptedListener listener) {
        View dialogView = LayoutInflater.from(context).inflate(R.layout.dialog_browser_url_tracking_terms, null);

        new MaterialAlertDialogBuilder(context)
                .setView(dialogView)
                .setCancelable(true)
                .setNegativeButton("Decline", (dialog, which) -> dialog.dismiss())
                .setPositiveButton("Accept & Enable", (dialog, which) -> {
                    Prefs.setBrowserUrlTermsAccepted(context, true);
                    if (listener != null) {
                        listener.onAccepted();
                    }
                    launchAccessibilitySettings(context);
                })
                .show();
    }

    public static void launchAccessibilitySettings(@NonNull Context context) {
        try {
            Intent intent;
            if (Build.VERSION.SDK_INT >= 34) {
                intent = new Intent("android.settings.ACCESSIBILITY_DETAILS_SETTINGS");
                intent.setData(android.net.Uri.parse("package:" + context.getPackageName()));
                intent.putExtra(Intent.EXTRA_COMPONENT_NAME,
                        new android.content.ComponentName(context, com.kotsafe.security.services.BrowserAccessibilityService.class).flattenToString());
            } else {
                intent = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
                intent.putExtra(":settings:fragment_args_key",
                        context.getPackageName() + "/" + com.kotsafe.security.services.BrowserAccessibilityService.class.getName());
            }
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);

            String tip = "Scroll to 'Downloaded Apps' ➔ Tap 'KotSafe Web Protection' ➔ Turn On";
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                tip += "\n(If greyed out on Android 13+, tap App Info ➔ 3 dots ➔ 'Allow restricted settings')";
            }
            Toast.makeText(context.getApplicationContext(), tip, Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            try {
                Intent fallback = new Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS);
                fallback.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                context.startActivity(fallback);
                Toast.makeText(context.getApplicationContext(),
                        "Scroll to 'Downloaded Apps' ➔ 'KotSafe Web Protection' to enable",
                        Toast.LENGTH_LONG).show();
            } catch (Exception e2) {
                Toast.makeText(context.getApplicationContext(), "Could not open Accessibility Settings directly", Toast.LENGTH_SHORT).show();
            }
        }
    }
}
