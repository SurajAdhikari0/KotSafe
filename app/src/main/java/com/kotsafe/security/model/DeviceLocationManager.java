/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Build;
import android.os.Bundle;
import android.widget.Toast;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;

/**
 * Enterprise Fleet Live Location & Incident Geofencing Manager.
 * DISABLED BY DEFAULT for complete user privacy.
 * When enabled by an enterprise administrator or power user, provides device location telemetry
 * for incident response, rogue Wi-Fi geofencing, and emergency live location sharing.
 */
public class DeviceLocationManager {

    private static final String TAG = "DeviceLocationManager";

    public static final String PREF_LOCATION_ENABLED = "pref_enterprise_location_sharing_enabled";
    public static final String PREF_ATTACH_TO_SIEM = "pref_attach_location_to_siem_alerts";

    private static volatile DeviceLocationManager sInstance;

    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final LocationManager mLocationManager;
    private volatile Location mLastLocation;

    public static DeviceLocationManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (DeviceLocationManager.class) {
                if (sInstance == null) {
                    sInstance = new DeviceLocationManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private DeviceLocationManager(Context context) {
        mContext = context;
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        mLocationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
    }

    public static synchronized void resetInstanceForTesting() {
        sInstance = null;
    }

    /**
     * Checks if Enterprise Location Sharing is enabled.
     * Default is FALSE (Disabled by default).
     */
    public boolean isLocationEnabled() {
        return PreferenceManager.getDefaultSharedPreferences(mContext).getBoolean(PREF_LOCATION_ENABLED, false);
    }

    /**
     * Checks if Location should be attached to Enterprise SIEM telemetry payloads.
     */
    public boolean isAttachToSiemEnabled() {
        return isLocationEnabled() && PreferenceManager.getDefaultSharedPreferences(mContext).getBoolean(PREF_ATTACH_TO_SIEM, false);
    }

    public boolean hasLocationPermission() {
        return ContextCompat.checkSelfPermission(mContext, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(mContext, Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    /**
     * Retrieves the best last known device location from available providers.
     */
    public Location getLastKnownLocation() {
        if (!hasLocationPermission() || mLocationManager == null) {
            return mLastLocation;
        }

        Location bestLocation = mLastLocation;
        try {
            List<String> providers = mLocationManager.getProviders(true);
            for (String provider : providers) {
                try {
                    Location l = mLocationManager.getLastKnownLocation(provider);
                    if (l != null) {
                        if (bestLocation == null || l.getAccuracy() < bestLocation.getAccuracy() || l.getTime() > bestLocation.getTime()) {
                            bestLocation = l;
                        }
                    }
                } catch (SecurityException ignored) {}
            }
        } catch (Exception e) {
            Log.w(TAG, "Error acquiring location: " + e.getMessage());
        }

        if (bestLocation != null) {
            mLastLocation = bestLocation;
        }
        return bestLocation;
    }

    /**
     * Returns location formatted as a JSON object for telemetry / SIEM logging.
     * Returns null if location sharing is disabled or unavailable.
     */
    public JSONObject getLocationTelemetryJson() {
        if (!isLocationEnabled()) return null;

        Location loc = getLastKnownLocation();
        if (loc == null) return null;

        try {
            JSONObject obj = new JSONObject();
            obj.put("latitude", loc.getLatitude());
            obj.put("longitude", loc.getLongitude());
            obj.put("accuracy_meters", loc.getAccuracy());
            if (loc.hasAltitude()) obj.put("altitude", loc.getAltitude());
            if (loc.hasSpeed()) obj.put("speed_mps", loc.getSpeed());
            obj.put("provider", loc.getProvider());
            obj.put("timestamp", loc.getTime());

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
            sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
            obj.put("iso_time", sdf.format(new Date(loc.getTime())));

            return obj;
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Share live device location via standard Android share chooser.
     */
    public void shareLiveLocation(Activity activity) {
        if (!hasLocationPermission()) {
            ActivityCompat.requestPermissions(activity,
                    new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION},
                    1001);
            Toast.makeText(activity, "Grant Location permission to share live coordinates", Toast.LENGTH_SHORT).show();
            return;
        }

        Location loc = getLastKnownLocation();
        if (loc == null) {
            // Attempt single passive/network refresh
            requestSingleLocationUpdate();
            Toast.makeText(activity, "Acquiring GPS / Network satellite fix... Please try again in a moment.", Toast.LENGTH_LONG).show();
            return;
        }

        double lat = loc.getLatitude();
        double lon = loc.getLongitude();
        float acc = loc.getAccuracy();
        long time = loc.getTime();

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.getDefault());
        String timeStr = sdf.format(new Date(time));

        String text = "📍 KotSafe Device Live Location Report\n"
                + "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                + "Latitude: " + lat + "\n"
                + "Longitude: " + lon + "\n"
                + "Accuracy: ±" + String.format(Locale.US, "%.1f", acc) + " meters\n"
                + "Fix Time: " + timeStr + "\n"
                + "━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                + "Google Maps: https://www.google.com/maps?q=" + lat + "," + lon + "\n"
                + "OpenStreetMap: https://www.openstreetmap.org/?mlat=" + lat + "&mlon=" + lon + "#map=17/" + lat + "/" + lon;

        Intent sendIntent = new Intent();
        sendIntent.setAction(Intent.ACTION_SEND);
        sendIntent.putExtra(Intent.EXTRA_SUBJECT, "KotSafe Device Live Location");
        sendIntent.putExtra(Intent.EXTRA_TEXT, text);
        sendIntent.setType("text/plain");

        Intent shareIntent = Intent.createChooser(sendIntent, "Share KotSafe Live Location");
        activity.startActivity(shareIntent);
    }

    private void requestSingleLocationUpdate() {
        if (!hasLocationPermission() || mLocationManager == null) return;
        try {
            String provider = mLocationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
                    ? LocationManager.NETWORK_PROVIDER
                    : (mLocationManager.isProviderEnabled(LocationManager.GPS_PROVIDER) ? LocationManager.GPS_PROVIDER : null);
            if (provider == null) return;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                mLocationManager.getCurrentLocation(provider, null, mContext.getMainExecutor(), location -> {
                    if (location != null) {
                        mLastLocation = location;
                    }
                });
            } else {
                LocationListener listener = new LocationListener() {
                    @Override public void onLocationChanged(Location location) {
                        mLastLocation = location;
                        try { mLocationManager.removeUpdates(this); } catch (Exception ignored) {}
                    }
                    @Override public void onStatusChanged(String p, int status, Bundle extras) {}
                    @Override public void onProviderEnabled(String p) {}
                    @Override public void onProviderDisabled(String p) {}
                };
                mLocationManager.requestSingleUpdate(provider, listener, null);
            }
        } catch (SecurityException ignored) {
        } catch (Exception e) {
            Log.w(TAG, "Single update request error: " + e.getMessage());
        }
    }
}
