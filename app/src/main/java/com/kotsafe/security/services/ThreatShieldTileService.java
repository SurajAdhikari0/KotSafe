/*
 * KotSafe - Cyber Security Threat Shield Quick Settings Shade Tile
 * Allows 1-tap toggling of Total Defense and Firewall protection from Android status bar.
 */

package com.kotsafe.security.services;

import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.CaptureHelper;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.model.CaptureSettings;
import com.kotsafe.security.R;

@RequiresApi(api = Build.VERSION_CODES.N)
public class ThreatShieldTileService extends TileService {

    @Override
    public void onStartListening() {
        super.onStartListening();
        updateTileState();
    }

    @Override
    public void onClick() {
        super.onClick();
        Context ctx = getApplicationContext();

        if (CaptureService.isServiceActive()) {
            // Disarm shield
            CaptureService.stopService();
            Toast.makeText(ctx, "KotSafe Shield Paused", Toast.LENGTH_SHORT).show();
        } else {
            // Arm shield
            CaptureSettings settings = CaptureService.getCaptureSettings();
            if (settings == null) {
                settings = new CaptureSettings(ctx, androidx.preference.PreferenceManager.getDefaultSharedPreferences(ctx));
            }
            final CaptureSettings finalSettings = settings;

            Intent intent = new Intent(ctx, CaptureService.class);
            intent.putExtra("settings", finalSettings);
            try {
                ContextCompat.startForegroundService(ctx, intent);
                Toast.makeText(ctx, "KotSafe Shield Armed & Active", Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(ctx, "Failed to start shield: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        }

        new Handler(Looper.getMainLooper()).postDelayed(this::updateTileState, 600);
    }

    private void updateTileState() {
        Tile tile = getQsTile();
        if (tile == null) return;

        Context ctx = getApplicationContext();
        boolean active = CaptureService.isServiceActive();

        tile.setIcon(Icon.createWithResource(ctx, R.drawable.ic_shield));
        tile.setLabel("KotSafe Defense");

        if (active) {
            tile.setState(Tile.STATE_ACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.setSubtitle("Shield Armed");
            }
        } else {
            tile.setState(Tile.STATE_INACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.setSubtitle("Paused");
            }
        }

        tile.updateTile();
    }
}
