/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * AppBehaviorGraph
 * ================
 * Tracks chronological, multi-stage application behavior lifecycle sequences:
 * App Installed -> APK Scanned -> Permission Used -> DNS Query -> Socket Egress -> File/Physical Event.
 */

package com.kotsafe.security.security.graph;

import com.kotsafe.security.security.event.SecurityEvent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class AppBehaviorGraph {
    private static volatile AppBehaviorGraph sInstance;

    public static class BehaviorNode {
        public final String nodeId;
        public final long timestamp;
        public final String eventType;
        public final String description;
        public final SecurityEvent.Severity severity;
        public final Map<String, Object> metadata;

        public BehaviorNode(SecurityEvent event) {
            this.nodeId = event.getEventId();
            this.timestamp = event.getTimestamp();
            this.eventType = event.getEventType();
            this.description = event.getDescription();
            this.severity = event.getSeverity();
            this.metadata = event.getAttributes();
        }
    }

    private final Map<String, List<BehaviorNode>> mAppChains = new ConcurrentHashMap<>();
    private static final int MAX_NODES_PER_APP = 50;

    public static AppBehaviorGraph getInstance() {
        if (sInstance == null) {
            synchronized (AppBehaviorGraph.class) {
                if (sInstance == null) {
                    sInstance = new AppBehaviorGraph();
                }
            }
        }
        return sInstance;
    }

    private AppBehaviorGraph() {}

    public void recordEvent(SecurityEvent event) {
        if (event == null) return;
        String pkg = event.getSubjectPackage();
        if (pkg == null || pkg.isEmpty()) return;

        List<BehaviorNode> chain = mAppChains.computeIfAbsent(pkg, k -> new CopyOnWriteArrayList<>());
        if (chain.size() >= MAX_NODES_PER_APP) {
            chain.remove(0);
        }
        chain.add(new BehaviorNode(event));
    }

    public List<BehaviorNode> getLifecycleChain(String packageName) {
        if (packageName == null) return Collections.emptyList();
        List<BehaviorNode> chain = mAppChains.get(packageName);
        return chain != null ? new ArrayList<>(chain) : Collections.emptyList();
    }

    public boolean hasPattern(String packageName, String firstEventType, String secondEventType, long maxWindowMs) {
        List<BehaviorNode> chain = mAppChains.get(packageName);
        if (chain == null || chain.size() < 2) return false;

        long firstTime = -1;
        for (BehaviorNode node : chain) {
            if (node.eventType.equals(firstEventType)) {
                firstTime = node.timestamp;
            } else if (firstTime > 0 && node.eventType.equals(secondEventType)) {
                if ((node.timestamp - firstTime) <= maxWindowMs) {
                    return true;
                }
            }
        }
        return false;
    }

    public void clear(String packageName) {
        if (packageName != null) {
            mAppChains.remove(packageName);
        }
    }
}
