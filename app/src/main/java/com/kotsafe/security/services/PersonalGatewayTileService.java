/*
 * KotSafe - Personal Gateway Quick Settings Shade Tile
 */

package com.kotsafe.security.services;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.drawable.Icon;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.R;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.p2p.GatewayFeatureGate;
import com.kotsafe.security.p2p.GatewayPreferenceKeys;
import com.kotsafe.security.p2p.GatewayTelemetry;

@RequiresApi(api = Build.VERSION_CODES.N)
public class PersonalGatewayTileService extends TileService {

    @Override
    public void onStartListening() {
        super.onStartListening();
        updateTileState();
    }

    @Override
    public void onClick() {
        super.onClick();
        Context ctx = getApplicationContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);

        boolean clientEnabled = prefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        boolean exitEnabled = prefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);

        if (exitEnabled) {
            Toast.makeText(ctx, "Personal Gateway is currently hosting as Exit Node", Toast.LENGTH_SHORT).show();
            updateTileState();
            return;
        }

        if (clientEnabled) {
            // Stop client mode
            prefs.edit()
                    .putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false)
                    .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, false)
                    .apply();
            Toast.makeText(ctx, "Personal Gateway tunnel stopped", Toast.LENGTH_SHORT).show();
        } else {
            // Check if pairing exists
            String bundle = prefs.getString(GatewayPreferenceKeys.PAIRING_BUNDLE, "");
            String token = prefs.getString(Prefs.PREF_P2P_BACKEND_PAIRING, "");
            if (bundle.isEmpty() && token.isEmpty()) {
                Toast.makeText(ctx, "Pair with an Exit Node in Settings first", Toast.LENGTH_LONG).show();
                updateTileState();
                return;
            }

            // Start client mode
            prefs.edit()
                    .putBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, true)
                    .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, true)
                    .putString(Prefs.PREF_SOCKS5_PROXY_IP_KEY, "127.0.0.1")
                    .putString(Prefs.PREF_SOCKS5_PROXY_HOST_KEY, "127.0.0.1")
                    .putString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, "8095")
                    .putBoolean(Prefs.PREF_SOCKS5_AUTH_ENABLED_KEY, false)
                    .apply();

            Toast.makeText(ctx, "Personal Gateway tunnel active", Toast.LENGTH_SHORT).show();
        }

        updateTileState();
    }

    private void updateTileState() {
        Tile tile = getQsTile();
        if (tile == null) return;

        Context ctx = getApplicationContext();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        boolean clientEnabled = prefs.getBoolean(GatewayPreferenceKeys.CLIENT_ENABLED, false);
        boolean exitEnabled = prefs.getBoolean(GatewayPreferenceKeys.EXIT_ENABLED, false);

        tile.setIcon(Icon.createWithResource(ctx, R.drawable.ic_bolt));
        tile.setLabel(getString(R.string.p2p_exit_node_title));

        if (clientEnabled) {
            tile.setState(Tile.STATE_ACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                boolean direct = GatewayTelemetry.getInstance().isDirectP2PActive();
                tile.setSubtitle(direct ? "Direct P2P UDP" : "Relay Tunnel");
            }
        } else if (exitEnabled) {
            tile.setState(Tile.STATE_ACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.setSubtitle("Host Exit Active");
            }
        } else {
            tile.setState(Tile.STATE_INACTIVE);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.setSubtitle("Disconnected");
            }
        }

        tile.updateTile();
    }
}
