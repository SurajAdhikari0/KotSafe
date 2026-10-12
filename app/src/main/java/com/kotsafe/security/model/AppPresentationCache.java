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
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.os.Process;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe presentation cache for app metadata, package names, labels, and system status.
 * Eliminates repeated PackageManager queries and ownership lookups during row rendering.
 */
public class AppPresentationCache {
    private static final String TAG = "AppPresentationCache";
    private static final AppPresentationCache INSTANCE = new AppPresentationCache();

    public static AppPresentationCache getInstance() {
        return INSTANCE;
    }

    public static final class Presentation {
        public final int uid;
        public final String appLabel;
        public final String packageName;
        public final boolean isSystemApp;
        public final boolean isSystemService;
        public final boolean canBlockAppWide;

        public Presentation(int uid, String appLabel, String packageName,
                            boolean isSystemApp, boolean isSystemService, boolean canBlockAppWide) {
            this.uid = uid;
            this.appLabel = appLabel != null ? appLabel : "";
            this.packageName = packageName != null ? packageName : "";
            this.isSystemApp = isSystemApp;
            this.isSystemService = isSystemService;
            this.canBlockAppWide = canBlockAppWide;
        }
    }

    private final Map<Integer, Presentation> mCache = new ConcurrentHashMap<>();

    @NonNull
    public Presentation getPresentation(int uid, @Nullable Context context, @Nullable AppsResolver appsResolver) {
        Presentation existing = mCache.get(uid);
        if (existing != null) {
            return existing;
        }

        String appLabel = "";
        String packageName = "";
        boolean isSystemApp = false;
        boolean isSystemService = false;

        Context ctx = context != null ? context : KotSafe.getInstance();

        if (uid < 0) {
            appLabel = "System DNS";
            packageName = "android.dns";
            isSystemService = true;
            isSystemApp = true;
        } else if (uid == 1000) {
            appLabel = "Android System";
            packageName = "android";
            isSystemService = true;
            isSystemApp = true;
        } else if (uid < 10000 || Utils.isSystemUid(uid)) {
            appLabel = "Android System Core (" + uid + ")";
            packageName = "android.core";
            isSystemService = true;
            isSystemApp = true;
        } else {
            if (appsResolver != null) {
                AppDescriptor app = appsResolver.getAppByUid(uid, 0);
                if (app != null) {
                    appLabel = app.getName() != null ? app.getName() : "";
                    packageName = app.getPackageName() != null ? app.getPackageName() : "";
                }
            }
            if (ctx != null && Utils.isSystemApp(ctx, uid)) {
                isSystemApp = true;
                if (appLabel.isEmpty()) {
                    appLabel = "System App (" + uid + ")";
                }
            }
        }

        if (appLabel.isEmpty()) {
            appLabel = "UID " + uid;
        }

        // App-wide firewall blocking is only safe for 3rd party user apps (Process.FIRST_APPLICATION_UID)
        // and cannot target the app itself (Process.myUid())
        boolean canBlock = uid >= Process.FIRST_APPLICATION_UID && uid != Process.myUid();

        Presentation result = new Presentation(uid, appLabel, packageName, isSystemApp, isSystemService, canBlock);
        mCache.put(uid, result);
        return result;
    }

    public void clear() {
        mCache.clear();
    }
}
