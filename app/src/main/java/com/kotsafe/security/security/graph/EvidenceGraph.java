/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * EvidenceGraph
 * =============
 * Relational Directed Acyclic Graph (DAG) preserving causal security relationships:
 * APK [Hash] -> Threat Intel -> Domain [C2] -> IP [Destination] -> Firewall [Block Action].
 * Enables explainable forensics for UI storylines and AI analyst queries.
 */

package com.kotsafe.security.security.graph;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class EvidenceGraph {
    private static volatile EvidenceGraph sInstance;

    public enum NodeType {
        APP,
        FILE_HASH,
        CERTIFICATE,
        PERMISSION,
        DOMAIN,
        IP_ADDRESS,
        FIREWALL_ACTION,
        PHYSICAL_DEVICE,
        INCIDENT
    }

    public static class Node {
        public final String id;
        public final NodeType type;
        public final String label;
        public final Map<String, String> properties = new HashMap<>();

        public Node(String id, NodeType type, String label) {
            this.id = id;
            this.type = type;
            this.label = label;
        }

        public Node property(String key, String value) {
            if (key != null && value != null) properties.put(key, value);
            return this;
        }
    }

    public static class Edge {
        public final String fromNodeId;
        public final String toNodeId;
        public final String relationship; // e.g. "RESOLVED_TO", "COMMUNICATED_WITH", "BLOCKED_BY"

        public Edge(String fromNodeId, String toNodeId, String relationship) {
            this.fromNodeId = fromNodeId;
            this.toNodeId = toNodeId;
            this.relationship = relationship;
        }
    }

    private final Map<String, Node> mNodes = new ConcurrentHashMap<>();
    private final List<Edge> mEdges = Collections.synchronizedList(new ArrayList<>());
    private final Map<String, Set<String>> mAdjacency = new ConcurrentHashMap<>();

    public static EvidenceGraph getInstance() {
        if (sInstance == null) {
            synchronized (EvidenceGraph.class) {
                if (sInstance == null) {
                    sInstance = new EvidenceGraph();
                }
            }
        }
        return sInstance;
    }

    private EvidenceGraph() {}

    public synchronized void addNode(Node node) {
        if (node != null) {
            mNodes.put(node.id, node);
            mAdjacency.computeIfAbsent(node.id, k -> new HashSet<>());
        }
    }

    public synchronized void addEdge(String fromId, String toId, String relationship) {
        if (fromId == null || toId == null) return;
        mEdges.add(new Edge(fromId, toId, relationship));
        mAdjacency.computeIfAbsent(fromId, k -> new HashSet<>()).add(toId);
    }

    public Node getNode(String id) {
        return mNodes.get(id);
    }

    public List<Node> getConnectedNodes(String fromId) {
        Set<String> targets = mAdjacency.get(fromId);
        if (targets == null || targets.isEmpty()) return Collections.emptyList();
        List<Node> list = new ArrayList<>();
        for (String tid : targets) {
            Node n = mNodes.get(tid);
            if (n != null) list.add(n);
        }
        return list;
    }

    public String buildForensicStoryline(String startNodeId) {
        Node start = mNodes.get(startNodeId);
        if (start == null) return "No evidence trail found.";

        StringBuilder sb = new StringBuilder();
        sb.append("[").append(start.type).append("] ").append(start.label);

        Set<String> visited = new HashSet<>();
        visited.add(startNodeId);

        buildStorylineRecursive(startNodeId, sb, visited, 1);
        return sb.toString();
    }

    private void buildStorylineRecursive(String currentId, StringBuilder sb, Set<String> visited, int depth) {
        if (depth > 5) return;
        Set<String> nextIds = mAdjacency.get(currentId);
        if (nextIds == null) return;

        for (String nextId : nextIds) {
            if (visited.contains(nextId)) continue;
            visited.add(nextId);

            Node nextNode = mNodes.get(nextId);
            if (nextNode != null) {
                sb.append("\n  ↳ [").append(nextNode.type).append("] ").append(nextNode.label);
                buildStorylineRecursive(nextId, sb, visited, depth + 1);
            }
        }
    }

    public void clear() {
        mNodes.clear();
        mEdges.clear();
        mAdjacency.clear();
    }
}
