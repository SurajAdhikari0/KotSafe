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

import android.graphics.drawable.Drawable;
import android.os.Handler;
import android.os.Looper;
import android.widget.ImageView;

import androidx.annotation.Nullable;
import androidx.collection.LruCache;

import com.kotsafe.security.model.AppDescriptor;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AppIconLoader {
    private static final ExecutorService sExecutor = Executors.newFixedThreadPool(4);
    private static final Handler sMainHandler = new Handler(Looper.getMainLooper());
    private static final LruCache<String, Drawable> sIconCache = new LruCache<>(128);

    public static void setIcon(ImageView imageView, @Nullable AppDescriptor app, @Nullable Drawable placeholder) {
        if (app == null) {
            imageView.setImageDrawable(placeholder);
            imageView.setTag(null);
            return;
        }

        String pkgName = app.getPackageName();
        String cacheKey = (pkgName != null && !pkgName.isEmpty()) ? pkgName : ("uid_" + app.getUid());

        // 1. Direct AppDescriptor cached icon check
        Drawable cached = app.getCachedIcon();
        if (cached != null) {
            imageView.setImageDrawable(cached);
            imageView.setTag(null);
            return;
        }

        // 2. Global LruCache check (instant main-thread hit)
        Drawable lruIcon = sIconCache.get(cacheKey);
        if (lruIcon != null) {
            app.setLoadedIcon(lruIcon);
            imageView.setImageDrawable(lruIcon);
            imageView.setTag(null);
            return;
        }

        imageView.setImageDrawable(placeholder);
        imageView.setTag(cacheKey);

        sExecutor.execute(() -> {
            Drawable icon = app.loadIcon();
            if (icon != null) {
                sIconCache.put(cacheKey, icon);
            }

            sMainHandler.post(() -> {
                // ensure that the imageView still points to this app (e.g. due to possible recycle)
                if (cacheKey.equals(imageView.getTag())) {
                    app.setLoadedIcon(icon);

                    if (icon != null)
                        imageView.setImageDrawable(icon);

                    imageView.setTag(null);
                }
            });
        });
    }
}
