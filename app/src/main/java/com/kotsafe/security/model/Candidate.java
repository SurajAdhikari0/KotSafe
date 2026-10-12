/*
 * This file is part of KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

/**
 * Formalizes the "ip:port" endpoint strings P2PExitNodeSettings already
 * builds inline inside showPairingQrDialog(). toEndpointString() produces
 * the exact same bracketed-IPv6-aware format so probeAndApplyCandidates(),
 * which still takes List<String>, needs zero changes.
 */
public class Candidate {

    public enum Type { LAN, GLOBAL_IPV6, UPNP_PUBLIC, STUN, RELAY }

    public Type type;
    public String host;
    public int port;
    public long discoveredAt;

    public Candidate(Type type, String host, int port) {
        this.type = type;
        this.host = host;
        this.port = port;
        this.discoveredAt = System.currentTimeMillis();
    }

    /** Matches the bracket-quoting logic already used throughout P2PExitNodeSettings. */
    public String toEndpointString() {
        boolean isIpv6 = host != null && host.contains(":") && !host.startsWith("[");
        return (isIpv6 ? "[" + host + "]" : host) + ":" + port;
    }
}
