/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AndroidBehaviorEngine
 * =====================
 * Tracks behavioral events across applications over a sliding temporal window.
 * Aggregates install times, capability activations, and network connections
 * to detect behavioral attack patterns (e.g. immediate C2 beaconing after install).
 */

package com.kotsafe.security.model;

import android.content.Context;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AndroidBehaviorEngine {
    private static final String TAG = "AndroidBehaviorEngine";
    private static final int MAX_EVENTS_PER_APP = 50;

    public static class BehaviorEvent {
        public long timestampMs;
        public String eventType; // INSTALL, CAPABILITY, NETWORK, BLOCKED
        public String description;
        public String target; // IP, domain, or permission

        public BehaviorEvent(String eventType, String description, String target) {
            this.timestampMs = System.currentTimeMillis();
            this.eventType = eventType;
            this.description = description;
            this.target = target;
        }
    }

    private static volatile AndroidBehaviorEngine sInstance;
    private final Map<String, Deque<BehaviorEvent>> mAppEventHistory = new ConcurrentHashMap<>();

    public static AndroidBehaviorEngine getInstance() {
        if (sInstance == null) {
            synchronized (AndroidBehaviorEngine.class) {
                if (sInstance == null) {
                    sInstance = new AndroidBehaviorEngine();
                }
            }
        }
        return sInstance;
    }

    private AndroidBehaviorEngine() {}

    public void recordEvent(String packageName, String eventType, String description, String target) {
        if (packageName == null || packageName.isEmpty()) return;
        Deque<BehaviorEvent> deque = mAppEventHistory.computeIfAbsent(packageName, k -> new ArrayDeque<>());
        synchronized (deque) {
            deque.addFirst(new BehaviorEvent(eventType, description, target));
            if (deque.size() > MAX_EVENTS_PER_APP) {
                deque.removeLast();
            }
        }
    }

    public List<BehaviorEvent> getRecentEvents(String packageName) {
        if (packageName == null) return new ArrayList<>();
        Deque<BehaviorEvent> deque = mAppEventHistory.get(packageName);
        if (deque == null) return new ArrayList<>();
        synchronized (deque) {
            return new ArrayList<>(deque);
        }
    }

    public boolean hasRapidOutboundAfterInstall(String packageName, long maxWindowMs) {
        Deque<BehaviorEvent> deque = mAppEventHistory.get(packageName);
        if (deque == null) return false;
        synchronized (deque) {
            long installTime = 0;
            long firstNetworkTime = 0;
            for (BehaviorEvent e : deque) {
                if ("INSTALL".equals(e.eventType)) {
                    installTime = e.timestampMs;
                } else if ("NETWORK".equals(e.eventType) && firstNetworkTime == 0) {
                    firstNetworkTime = e.timestampMs;
                }
            }
            if (installTime > 0 && firstNetworkTime > 0) {
                return (firstNetworkTime - installTime) < maxWindowMs;
            }
        }
        return false;
    }
}
