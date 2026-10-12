/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * SecurityEventBus
 * ================
 * Central, high-throughput asynchronous security event bus.
 * Connects Firewall, Antivirus, and Physical subsystems with zero blocking.
 */

package com.kotsafe.security.security.event;

import android.os.Handler;
import android.os.Looper;

import com.kotsafe.security.Log;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecurityEventBus {
    private static final String TAG = "SecurityEventBus";

    public interface SecurityEventListener {
        void onSecurityEvent(SecurityEvent event);
    }

    private static volatile SecurityEventBus sInstance;
    private final ExecutorService mEventDispatcherPool = Executors.newFixedThreadPool(2);
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    private final List<SecurityEventListener> mGlobalListeners = new CopyOnWriteArrayList<>();
    private final Map<SecurityEvent.Domain, List<SecurityEventListener>> mDomainListeners = new ConcurrentHashMap<>();
    private final Map<String, List<SecurityEventListener>> mTypeListeners = new ConcurrentHashMap<>();

    public static SecurityEventBus getInstance() {
        if (sInstance == null) {
            synchronized (SecurityEventBus.class) {
                if (sInstance == null) {
                    sInstance = new SecurityEventBus();
                }
            }
        }
        return sInstance;
    }

    private SecurityEventBus() {}

    public void publish(SecurityEvent event) {
        if (event == null) return;
        mEventDispatcherPool.submit(() -> dispatchInternal(event));
    }

    private void dispatchInternal(SecurityEvent event) {
        try {
            // 1. Global Listeners
            for (SecurityEventListener listener : mGlobalListeners) {
                safeNotify(listener, event);
            }

            // 2. Domain Listeners
            List<SecurityEventListener> domainList = mDomainListeners.get(event.getDomain());
            if (domainList != null) {
                for (SecurityEventListener listener : domainList) {
                    safeNotify(listener, event);
                }
            }

            // 3. Type-Specific Listeners
            List<SecurityEventListener> typeList = mTypeListeners.get(event.getEventType());
            if (typeList != null) {
                for (SecurityEventListener listener : typeList) {
                    safeNotify(listener, event);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error dispatching event: " + e.getMessage());
        }
    }

    private void safeNotify(SecurityEventListener listener, SecurityEvent event) {
        try {
            listener.onSecurityEvent(event);
        } catch (Throwable t) {
            Log.e(TAG, "Listener error for event " + event.getEventType() + ": " + t.getMessage());
        }
    }

    public void subscribe(SecurityEventListener listener) {
        if (listener != null && !mGlobalListeners.contains(listener)) {
            mGlobalListeners.add(listener);
        }
    }

    public void unsubscribe(SecurityEventListener listener) {
        if (listener == null) return;
        mGlobalListeners.remove(listener);
        for (List<SecurityEventListener> list : mDomainListeners.values()) {
            list.remove(listener);
        }
        for (List<SecurityEventListener> list : mTypeListeners.values()) {
            list.remove(listener);
        }
    }

    public void subscribeDomain(SecurityEvent.Domain domain, SecurityEventListener listener) {
        if (domain == null || listener == null) return;
        mDomainListeners.computeIfAbsent(domain, d -> new CopyOnWriteArrayList<>()).add(listener);
    }

    public void subscribeType(String eventType, SecurityEventListener listener) {
        if (eventType == null || listener == null) return;
        mTypeListeners.computeIfAbsent(eventType, t -> new CopyOnWriteArrayList<>()).add(listener);
    }
}
