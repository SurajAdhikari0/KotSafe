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
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.services;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.os.Build;
import android.os.IBinder;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.view.WindowManager.LayoutParams;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.kotsafe.security.R;

/**
 * Optional FLAG_SECURE overlay for a user-selected sensitive-app workflow.
 * Android applies secure flags to the flagged window; this overlay does not establish
 * that another application's content is protected or that a capture session was detected.
 * Device/OEM verification is required before presenting any stronger claim.
 */
public class ScreenshotBlockOverlayService extends Service {

    public static final String ACTION_SHOW_OVERLAY = "com.kotsafe.security.SCREENSHOT_BLOCK_SHOW";
    public static final String ACTION_HIDE_OVERLAY = "com.kotsafe.security.SCREENSHOT_BLOCK_HIDE";

    private static final String CHANNEL_ID = "screenshot_block_channel";
    private static final int    NOTIF_ID   = 7788;
    private static final String TAG        = "ScreenshotBlockOverlay";

    private WindowManager mWindowManager;
    private View          mOverlayView;
    private boolean       mOverlayAttached = false;

    @Override
    public void onCreate() {
        super.onCreate();
        mWindowManager = (WindowManager) getSystemService(WINDOW_SERVICE);
        createNotificationChannel();
        startForeground(NOTIF_ID, buildNotification());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent == null) return START_STICKY;
        String action = intent.getAction();
        if (ACTION_SHOW_OVERLAY.equals(action)) {
            showOverlay();
        } else if (ACTION_HIDE_OVERLAY.equals(action)) {
            hideOverlay();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        hideOverlay();
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) { return null; }

    // ── Overlay management ────────────────────────────────────────────────────

    private void showOverlay() {
        if (mOverlayAttached) return;
        if (!Settings.canDrawOverlays(this)) {
            android.util.Log.w(TAG, "canDrawOverlays=false — overlay permission not granted");
            return;
        }

        // Create a 1×1 invisible-but-visible view.
        // Color is fully transparent black so the user sees nothing,
        // but the view IS visible to the compositor (alpha stays at 1f).
        if (mOverlayView == null) {
            mOverlayView = new View(this);
            mOverlayView.setBackgroundColor(Color.TRANSPARENT);
            // alpha MUST stay 1f — zero alpha skips the surface from SurfaceFlinger
        }

        int overlayType = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? LayoutParams.TYPE_APPLICATION_OVERLAY
                : LayoutParams.TYPE_SYSTEM_ALERT;

        // 1×1 pixel window positioned off-screen edge (top-left, 0 size effectively
        // but we use 1×1 so the compositor creates a real surface layer).
        LayoutParams params = new LayoutParams(
                1,   // 1 px width
                1,   // 1 px height
                overlayType,
                LayoutParams.FLAG_NOT_FOCUSABLE
                        | LayoutParams.FLAG_NOT_TOUCHABLE
                        | LayoutParams.FLAG_LAYOUT_NO_LIMITS
                        | LayoutParams.FLAG_SECURE,   // ← marks entire frame as secure
                PixelFormat.TRANSPARENT);
        params.gravity = Gravity.TOP | Gravity.START;
        params.x = 0;
        params.y = 0;

        try {
            mWindowManager.addView(mOverlayView, params);
            mOverlayAttached = true;
            android.util.Log.i(TAG, "FLAG_SECURE overlay shown; cross-app capture protection is not verified");
        } catch (Exception e) {
            android.util.Log.e(TAG, "Failed to add overlay: " + e.getMessage());
        }
    }

    private void hideOverlay() {
        if (!mOverlayAttached || mOverlayView == null) return;
        try {
            mWindowManager.removeViewImmediate(mOverlayView);
            android.util.Log.i(TAG, "FLAG_SECURE overlay HIDDEN — screenshots allowed");
        } catch (Exception e) {
            android.util.Log.e(TAG, "Failed to remove overlay: " + e.getMessage());
        } finally {
            mOverlayAttached = false;
            mOverlayView = null;  // recreate fresh on next show to avoid stale state
        }
    }

    // ── Notification ──────────────────────────────────────────────────────────

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID,
                    "Screenshot Protection",
                    NotificationManager.IMPORTANCE_MIN);
            ch.setDescription("Optional secure overlay; cross-app capture coverage varies by device");
            ch.setShowBadge(false);
            ch.setSound(null, null);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification() {
        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("Secure Overlay Active")
                .setContentText("Cross-app capture protection is not verified; stop sharing before entering payment details")
                .setPriority(NotificationCompat.PRIORITY_MIN)
                .setOngoing(true)
                .setSilent(true)
                .setShowWhen(false)
                .build();
    }
}
