/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Manages fetching, caching, and read-tracking for Admin broadcast notifications and threat bulletins.
 */
public class NotificationCenterManager {

    private static final String TAG = "KotSafeNotifications";
    public static final String NOTIFICATIONS_ENDPOINT = "https://kotsafe.com/api/notifications?platform=android&limit=30";
    private static final String PREF_NAME = "kotsafe_broadcast_notifications";
    private static final String KEY_READ_IDS = "read_notification_ids";

    private static volatile NotificationCenterManager sInstance;

    private final Context mAppContext;
    private final SharedPreferences mPrefs;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());
    private final List<NotificationBulletin> mCachedBulletins = new ArrayList<>();
    private int mUnreadCount = 0;

    public interface NotificationCallback {
        void onSuccess(List<NotificationBulletin> bulletins, int unreadCount);
        void onError(String error);
    }

    public interface UnreadCountCallback {
        void onCountReady(int unreadCount);
    }

    private NotificationCenterManager(Context context) {
        mAppContext = context.getApplicationContext();
        mPrefs = mAppContext.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
    }

    public static NotificationCenterManager getInstance(Context context) {
        if (sInstance == null) {
            synchronized (NotificationCenterManager.class) {
                if (sInstance == null) {
                    sInstance = new NotificationCenterManager(context);
                }
            }
        }
        return sInstance;
    }

    private Set<String> getReadIds() {
        return new HashSet<>(mPrefs.getStringSet(KEY_READ_IDS, new HashSet<>()));
    }

    private void saveReadIds(Set<String> readIds) {
        mPrefs.edit().putStringSet(KEY_READ_IDS, readIds).apply();
    }

    public int getCachedUnreadCount() {
        return mUnreadCount;
    }

    public List<NotificationBulletin> getCachedBulletins() {
        return new ArrayList<>(mCachedBulletins);
    }

    /**
     * Asynchronously checks unread count by fetching the latest bulletins.
     */
    public void checkUnreadCountAsync(UnreadCountCallback callback) {
        fetchNotifications(new NotificationCallback() {
            @Override
            public void onSuccess(List<NotificationBulletin> bulletins, int unreadCount) {
                if (callback != null) {
                    callback.onCountReady(unreadCount);
                }
            }

            @Override
            public void onError(String error) {
                if (callback != null) {
                    callback.onCountReady(mUnreadCount);
                }
            }
        });
    }

    /**
     * Fetches real-time notifications from the KotSafe server.
     */
    public void fetchNotifications(NotificationCallback callback) {
        mExecutor.execute(() -> {
            HttpURLConnection connection = null;
            try {
                URL url = new URL(NOTIFICATIONS_ENDPOINT);
                connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                connection.setConnectTimeout(8000);
                connection.setReadTimeout(8000);
                connection.setRequestProperty("Accept", "application/json");
                connection.setRequestProperty("User-Agent", "KotSafe-Android/" + android.os.Build.VERSION.RELEASE);

                int code = connection.getResponseCode();
                if (code >= 200 && code < 300) {
                    InputStream in = connection.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    reader.close();

                    JSONObject root = new JSONObject(sb.toString());
                    JSONArray array = root.optJSONArray("notifications");
                    Set<String> readIds = getReadIds();

                    List<NotificationBulletin> list = new ArrayList<>();
                    int unread = 0;

                    if (array != null) {
                        for (int i = 0; i < array.length(); i++) {
                            JSONObject item = array.getJSONObject(i);
                            long id = item.optLong("id", 0);
                            boolean isRead = readIds.contains(String.valueOf(id));
                            if (!isRead) {
                                unread++;
                            }
                            NotificationBulletin b = NotificationBulletin.fromJson(item, isRead);
                            if (b != null) {
                                list.add(b);
                            }
                        }
                    }

                    synchronized (mCachedBulletins) {
                        mCachedBulletins.clear();
                        mCachedBulletins.addAll(list);
                        mUnreadCount = unread;
                    }

                    final int finalUnread = unread;
                    mMainHandler.post(() -> {
                        if (callback != null) {
                            callback.onSuccess(list, finalUnread);
                        }
                    });
                } else {
                    mMainHandler.post(() -> {
                        if (callback != null) {
                            callback.onError("Server returned status " + code);
                        }
                    });
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to load notifications: " + e.getMessage());
                mMainHandler.post(() -> {
                    if (callback != null) {
                        callback.onError(e.getMessage());
                    }
                });
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        });
    }

    /**
     * Marks a single notification as read.
     */
    public void markAsRead(long id) {
        mExecutor.execute(() -> {
            Set<String> readIds = getReadIds();
            readIds.add(String.valueOf(id));
            saveReadIds(readIds);

            synchronized (mCachedBulletins) {
                int unread = 0;
                for (NotificationBulletin b : mCachedBulletins) {
                    if (b.getId() == id) {
                        b.setRead(true);
                    }
                    if (!b.isRead()) {
                        unread++;
                    }
                }
                mUnreadCount = unread;
            }
        });
    }

    /**
     * Marks all active notifications as read.
     */
    public void markAllAsRead() {
        mExecutor.execute(() -> {
            Set<String> readIds = getReadIds();
            synchronized (mCachedBulletins) {
                for (NotificationBulletin b : mCachedBulletins) {
                    b.setRead(true);
                    readIds.add(String.valueOf(b.getId()));
                }
                mUnreadCount = 0;
            }
            saveReadIds(readIds);
        });
    }
}

