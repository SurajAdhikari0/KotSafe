/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Encrypted Upstream DNS-over-HTTPS (DoH) Client (RFC 8484).
 *
 * Tunnels non-blocked DNS queries to privacy-first encrypted resolvers,
 * completely preventing ISP eavesdropping, Wi-Fi snooping, and DNS hijacking.
 */
public class DnsOverHttpsResolver {
    private static final String TAG = "DnsOverHttpsResolver";

    public static final String PREF_DOH_ENABLED = "pref_doh_enabled";
    public static final String PREF_DOH_PROVIDER = "pref_doh_provider";
    public static final String PREF_DOH_CUSTOM_URL = "pref_doh_custom_url";

    public static final String PROVIDER_SYSTEM = "system";
    public static final String PROVIDER_CLOUDFLARE = "cloudflare";
    public static final String PROVIDER_QUAD9 = "quad9";
    public static final String PROVIDER_ADGUARD = "adguard";
    public static final String PROVIDER_GOOGLE = "google";
    public static final String PROVIDER_MULLVAD = "mullvad";
    public static final String PROVIDER_CONTROLD = "controld";
    public static final String PROVIDER_CLEANBROWSING = "cleanbrowsing";
    public static final String PROVIDER_CUSTOM = "custom";

    public static final String URL_CLOUDFLARE = "https://cloudflare-dns.com/dns-query";
    public static final String URL_QUAD9 = "https://dns.quad9.net/dns-query";
    public static final String URL_ADGUARD = "https://dns.adguard-dns.com/dns-query";
    public static final String URL_GOOGLE = "https://dns.google/dns-query";
    public static final String URL_MULLVAD = "https://adblock.doh.mullvad.net/dns-query";
    public static final String URL_CONTROLD = "https://freedns.controld.com/p2";
    public static final String URL_CLEANBROWSING = "https://doh.cleanbrowsing.org/doh/family-filter/";

    private static DnsOverHttpsResolver sInstance;
    private final Context mContext;
    private final SharedPreferences mPrefs;

    public static synchronized DnsOverHttpsResolver getInstance(@NonNull Context context) {
        if (sInstance == null) {
            sInstance = new DnsOverHttpsResolver(context.getApplicationContext());
        }
        return sInstance;
    }

    private DnsOverHttpsResolver(Context context) {
        mContext = context;
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
    }

    public boolean isDohEnabled() {
        return mPrefs.getBoolean(PREF_DOH_ENABLED, false);
    }

    public void setDohEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_DOH_ENABLED, enabled).apply();
    }

    @NonNull
    public String getActiveEndpointUrl() {
        String provider = mPrefs.getString(PREF_DOH_PROVIDER, PROVIDER_CLOUDFLARE);
        switch (provider) {
            case PROVIDER_QUAD9:
                return URL_QUAD9;
            case PROVIDER_ADGUARD:
                return URL_ADGUARD;
            case PROVIDER_GOOGLE:
                return URL_GOOGLE;
            case PROVIDER_MULLVAD:
                return URL_MULLVAD;
            case PROVIDER_CONTROLD:
                return URL_CONTROLD;
            case PROVIDER_CLEANBROWSING:
                return URL_CLEANBROWSING;
            case PROVIDER_CUSTOM:
                String custom = mPrefs.getString(PREF_DOH_CUSTOM_URL, "");
                return !custom.isEmpty() ? custom : URL_CLOUDFLARE;
            case PROVIDER_CLOUDFLARE:
            default:
                return URL_CLOUDFLARE;
        }
    }

    /**
     * Resolves a binary RFC 1035 DNS query using RFC 8484 DNS-over-HTTPS POST.
     *
     * @param queryPacket Raw binary query packet
     * @return Binary DNS response packet from upstream encrypted resolver, or null on failure.
     */
    @Nullable
    public byte[] queryDoh(@NonNull byte[] queryPacket) {
        if (!isDohEnabled() || queryPacket.length < 12) {
            return null;
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(getActiveEndpointUrl());
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(5000);
            conn.setRequestProperty("Content-Type", "application/dns-message");
            conn.setRequestProperty("Accept", "application/dns-message");
            conn.setRequestProperty("User-Agent", "KotSafe-DoH/2.0");

            try (OutputStream out = conn.getOutputStream()) {
                out.write(queryPacket);
                out.flush();
            }

            int code = conn.getResponseCode();
            if (code == HttpURLConnection.HTTP_OK) {
                try (InputStream in = conn.getInputStream();
                     ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
                    byte[] buf = new byte[2048];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        baos.write(buf, 0, n);
                    }
                    return baos.toByteArray();
                }
            } else {
                Log.w(TAG, "DoH request returned HTTP " + code);
            }
        } catch (Exception e) {
            Log.w(TAG, "DoH query error: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
        return null;
    }
}
