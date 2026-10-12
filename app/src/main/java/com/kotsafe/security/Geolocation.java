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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.model.Geomodel;
import com.maxmind.db.Reader;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/* A class to query geolocation info from IP addresses. */
public class Geolocation {
    private static final String TAG = "Geolocation";
    public static final String PREF_CUSTOM_COUNTRY_URL = "pref_geo_custom_country_url";
    public static final String PREF_CUSTOM_ASN_URL = "pref_geo_custom_asn_url";
    public static final String PREF_AUTO_UPDATE_GEOIP = "pref_auto_update_geoip";

    private final Context mContext;
    private Reader mCountryReader;
    private Reader mAsnReader;

    public Geolocation(Context ctx) {
        mContext = ctx.getApplicationContext();
        openDb();
    }

    @Override
    public void finalize() {
        Utils.safeClose(mCountryReader);
        Utils.safeClose(mAsnReader);
        mCountryReader = null;
        mAsnReader = null;
    }

    private void openDb() {
        try {
            File countryFile = getCountryFile(mContext);
            if (countryFile.exists()) {
                mCountryReader = new Reader(countryFile);
                Log.d(TAG, "Country DB loaded: " + mCountryReader.getMetadata());
            }
        } catch (IOException e) {
            Log.i(TAG, "Country DB load failed: " + e.getMessage());
            mCountryReader = null;
        }

        try {
            File asnFile = getAsnFile(mContext);
            if (asnFile.exists()) {
                mAsnReader = new Reader(asnFile);
                Log.d(TAG, "ASN DB loaded: " + mAsnReader.getMetadata());
            }
        } catch (IOException e) {
            Log.i(TAG, "ASN DB load failed: " + e.getMessage());
            mAsnReader = null;
        }
    }

    public boolean isAvailable() {
        return (mCountryReader != null) || (mAsnReader != null);
    }

    public boolean isCountryAvailable() {
        return mCountryReader != null;
    }

    public boolean isAsnAvailable() {
        return mAsnReader != null;
    }

    public static boolean isAvailable(Context ctx) {
        return isCountryDbAvailable(ctx) || isAsnDbAvailable(ctx);
    }

    public static boolean isCountryDbAvailable(Context ctx) {
        return getCountryDbDate(ctx) != null;
    }

    public static boolean isAsnDbAvailable(Context ctx) {
        return getAsnDbDate(ctx) != null;
    }

    public static File getCountryFile(Context ctx) {
        return new File(ctx.getFilesDir() + "/dbip_country_lite.mmdb");
    }

    public static File getAsnFile(Context ctx) {
        return new File(ctx.getFilesDir() + "/dbip_asn_lite.mmdb");
    }

    public static Date getDbDate(File file) throws IOException {
        try(Reader reader = new Reader(file)) {
            return reader.getMetadata().getBuildDate();
        }
    }

    public static @Nullable Date getDbDate(Context ctx) {
        return getCountryDbDate(ctx);
    }

    public static @Nullable Date getCountryDbDate(Context ctx) {
        try {
            File f = getCountryFile(ctx);
            if (f.exists()) return getDbDate(f);
        } catch (IOException ignored) {}
        return null;
    }

    public static @Nullable Date getAsnDbDate(Context ctx) {
        try {
            File f = getAsnFile(ctx);
            if (f.exists()) return getDbDate(f);
        } catch (IOException ignored) {}
        return null;
    }

    public static long getDbSize(Context ctx) {
        return getCountryDbSize(ctx) + getAsnDbSize(ctx);
    }

    public static long getCountryDbSize(Context ctx) {
        File f = getCountryFile(ctx);
        return f.exists() ? f.length() : 0;
    }

    public static long getAsnDbSize(Context ctx) {
        File f = getAsnFile(ctx);
        return f.exists() ? f.length() : 0;
    }

    @SuppressWarnings("ResultOfMethodCallIgnored")
    public static void deleteDb(Context ctx) {
        getCountryFile(ctx).delete();
        getAsnFile(ctx).delete();
    }

    public static boolean importCountryDb(Context ctx, InputStream is) {
        return importStreamToTarget(ctx, is, getCountryFile(ctx));
    }

    public static boolean importAsnDb(Context ctx, InputStream is) {
        return importStreamToTarget(ctx, is, getAsnFile(ctx));
    }

    public static boolean importDbFromUri(Context ctx, Uri uri, boolean isAsn) {
        try (InputStream is = ctx.getContentResolver().openInputStream(uri)) {
            if (is == null) return false;
            return isAsn ? importAsnDb(ctx, is) : importCountryDb(ctx, is);
        } catch (Exception e) {
            Log.e(TAG, "Failed importing DB from uri: " + e.getMessage());
            return false;
        }
    }

    private static boolean importStreamToTarget(Context ctx, InputStream is, File targetFile) {
        File tmpFile = new File(ctx.getCacheDir(), "imported_geo_" + System.currentTimeMillis() + ".mmdb");
        try (OutputStream os = new FileOutputStream(tmpFile)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = is.read(buf)) > 0) {
                os.write(buf, 0, len);
            }
            os.flush();

            // Validate MMDB structure
            getDbDate(tmpFile);

            // Replace target file
            if (targetFile.exists()) targetFile.delete();
            return tmpFile.renameTo(targetFile);
        } catch (Exception e) {
            Log.e(TAG, "Error validating/importing MMDB: " + e.getMessage());
            if (tmpFile.exists()) tmpFile.delete();
            return false;
        }
    }

    @SuppressLint("SimpleDateFormat")
    public static boolean downloadDb(Context ctx) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
        String customCountry = prefs.getString(PREF_CUSTOM_COUNTRY_URL, "").trim();
        String customAsn = prefs.getString(PREF_CUSTOM_ASN_URL, "").trim();

        List<String> countryCandidates = getCountryDownloadCandidates(customCountry);
        List<String> asnCandidates = getAsnDownloadCandidates(customAsn);

        boolean countrySuccess = false;
        for (String url : countryCandidates) {
            Log.i(TAG, "Attempting Country DB download from: " + url);
            if (downloadAndProcess(ctx, "country", url, getCountryFile(ctx))) {
                countrySuccess = true;
                break;
            }
        }

        boolean asnSuccess = false;
        for (String url : asnCandidates) {
            Log.i(TAG, "Attempting ASN DB download from: " + url);
            if (downloadAndProcess(ctx, "asn", url, getAsnFile(ctx))) {
                asnSuccess = true;
                break;
            }
        }

        return countrySuccess && asnSuccess;
    }

    private static List<String> getCountryDownloadCandidates(String customUrl) {
        List<String> list = new ArrayList<>();
        if (!customUrl.isEmpty()) {
            list.add(customUrl);
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM", Locale.US);
        Calendar cal = Calendar.getInstance();

        // 1. Current month
        String m0 = sdf.format(cal.getTime());
        list.add("https://download.db-ip.com/free/dbip-country-lite-" + m0 + ".mmdb.gz");

        // 2. Previous month
        cal.add(Calendar.MONTH, -1);
        String m1 = sdf.format(cal.getTime());
        list.add("https://download.db-ip.com/free/dbip-country-lite-" + m1 + ".mmdb.gz");

        // 3. 2 months ago
        cal.add(Calendar.MONTH, -1);
        String m2 = sdf.format(cal.getTime());
        list.add("https://download.db-ip.com/free/dbip-country-lite-" + m2 + ".mmdb.gz");

        // 4. Reliable CDN / GitHub Mirrors
        list.add("https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb");
        list.add("https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-Country.mmdb");

        return list;
    }

    private static List<String> getAsnDownloadCandidates(String customUrl) {
        List<String> list = new ArrayList<>();
        if (!customUrl.isEmpty()) {
            list.add(customUrl);
        }

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM", Locale.US);
        Calendar cal = Calendar.getInstance();

        // 1. Current month
        String m0 = sdf.format(cal.getTime());
        list.add("https://download.db-ip.com/free/dbip-asn-lite-" + m0 + ".mmdb.gz");

        // 2. Previous month
        cal.add(Calendar.MONTH, -1);
        String m1 = sdf.format(cal.getTime());
        list.add("https://download.db-ip.com/free/dbip-asn-lite-" + m1 + ".mmdb.gz");

        // 3. 2 months ago
        cal.add(Calendar.MONTH, -1);
        String m2 = sdf.format(cal.getTime());
        list.add("https://download.db-ip.com/free/dbip-asn-lite-" + m2 + ".mmdb.gz");

        // 4. Reliable CDN / GitHub Mirrors
        list.add("https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb");
        list.add("https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/GeoLite2-ASN.mmdb");

        return list;
    }

    private static boolean downloadAndProcess(Context ctx, String label, String url, File dst) {
        File tmp_file = new File(ctx.getCacheDir(), "geoip_" + label + "_tmp_" + System.currentTimeMillis());
        try {
            boolean rv = Utils.downloadFile(url, tmp_file.getAbsolutePath());
            if (!rv || !tmp_file.exists() || tmp_file.length() == 0) {
                Log.w(TAG, "Could not download " + label + " db from " + url);
                return false;
            }

            if (url.endsWith(".gz")) {
                try (FileInputStream is = new FileInputStream(tmp_file.getAbsolutePath())) {
                    if (!Utils.ungzip(is, dst.getAbsolutePath())) {
                        Log.w(TAG, "ungzip of " + tmp_file + " failed");
                        return false;
                    }
                }
            } else {
                // Plain MMDB format
                if (dst.exists()) dst.delete();
                if (!tmp_file.renameTo(dst)) {
                    // Fallback copy
                    try (InputStream in = new FileInputStream(tmp_file);
                         OutputStream out = new FileOutputStream(dst)) {
                        byte[] buffer = new byte[8192];
                        int read;
                        while ((read = in.read(buffer)) != -1) {
                            out.write(buffer, 0, read);
                        }
                    }
                }
            }

            // Verify database format
            getDbDate(dst);
            Log.i(TAG, "Successfully acquired and validated " + label + " database");
            return true;
        } catch (Exception e) {
            Log.w(TAG, "Validation failed for " + label + ": " + e.getMessage());
            if (dst.exists()) dst.delete();
            return false;
        } finally {
            if (tmp_file.exists()) tmp_file.delete();
        }
    }

    public String getCountryCode(InetAddress addr) {
        if(mCountryReader != null) {
            try {
                Geomodel.CountryResult res = mCountryReader.get(addr, Geomodel.CountryResult.class);
                if ((res != null) && (res.country != null) && (res.country.isoCode != null))
                    return res.country.isoCode;
            } catch (IOException e) {
                Log.d(TAG, "Country lookup error: " + e.getMessage());
            }
        }
        return "";
    }

    public Geomodel.ASN getASN(InetAddress addr) {
        if(mAsnReader != null) {
            try {
                Geomodel.ASN res = mAsnReader.get(addr, Geomodel.ASN.class);
                if (res != null)
                    return res;
            } catch (IOException e) {
                Log.d(TAG, "ASN lookup error: " + e.getMessage());
            }
        }
        return new Geomodel.ASN();
    }

    public Geomodel.GeoInfo lookup(InetAddress addr) {
        String ipStr = addr.getHostAddress();
        String countryCode = getCountryCode(addr);
        String countryName = getCountryName(countryCode);
        String flag = countryCodeToEmoji(countryCode);

        Geomodel.ASN asn = getASN(addr);
        long asnNumber = asn != null ? asn.number : 0;
        String asnName = asn != null ? asn.asname : "";

        return new Geomodel.GeoInfo(ipStr, countryCode, countryName, flag, asnNumber, asnName);
    }

    public static String getCountryName(String isoCode) {
        if (isoCode == null || isoCode.trim().isEmpty()) return "Unknown";
        try {
            Locale locale = new Locale("", isoCode.toUpperCase(Locale.US));
            String name = locale.getDisplayCountry(Locale.ENGLISH);
            return (name != null && !name.isEmpty()) ? name : isoCode;
        } catch (Exception ignored) {
            return isoCode;
        }
    }

    public static String countryCodeToEmoji(String isoCode) {
        if (isoCode == null || isoCode.length() != 2) return "";
        isoCode = isoCode.toUpperCase(Locale.US);
        int firstChar = Character.codePointAt(isoCode, 0) - 0x41 + 0x1F1E6;
        int secondChar = Character.codePointAt(isoCode, 1) - 0x41 + 0x1F1E6;
        if (firstChar < 0x1F1E6 || firstChar > 0x1F1FF || secondChar < 0x1F1E6 || secondChar > 0x1F1FF) {
            return "";
        }
        return new String(Character.toChars(firstChar)) + new String(Character.toChars(secondChar));
    }
}
