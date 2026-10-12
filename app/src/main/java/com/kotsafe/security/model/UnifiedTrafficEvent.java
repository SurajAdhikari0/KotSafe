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
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security.model;

import java.io.Serializable;

/**
 * Normalized schema for traffic events arriving from either:
 * 1. VPN MODE ("vpn") - Deep per-packet, DNS, SNI, TLS bytes
 * 2. API MODE ("api") - Passive Android APIs (NetworkStats, Accessibility, Wifi, PackageManager)
 */
public class UnifiedTrafficEvent implements Serializable {
    public static final String SOURCE_VPN = "vpn";
    public static final String SOURCE_API = "api";

    public enum EventCategory {
        NETWORK_CONN,
        BROWSER_NAV,
        USAGE_DELTA,
        WIFI_SECURITY,
        APP_SCAN
    }

    public final String sourceTag; // "vpn" | "api"
    public final int appUid;
    public final String packageName;
    public final String appName;
    public final long timestamp;
    public final String destination; // IP, Host, or URL
    public final String ip;
    public final String domain;
    public final String url;
    public final int port;
    public final String protocol; // "TCP", "UDP", "HTTPS", "DNS"
    public final long bytesSent;
    public final long bytesRcvd;
    public final String networkType; // "WIFI", "CELLULAR", "UNKNOWN"
    public final boolean isBackground;
    public final EventCategory eventCategory;
    public final String details;

    public UnifiedTrafficEvent(Builder builder) {
        this.sourceTag = builder.sourceTag;
        this.appUid = builder.appUid;
        this.packageName = builder.packageName != null ? builder.packageName : "";
        this.appName = builder.appName != null ? builder.appName : "";
        this.timestamp = builder.timestamp > 0 ? builder.timestamp : System.currentTimeMillis();
        this.destination = builder.destination != null ? builder.destination : "";
        this.ip = builder.ip != null ? builder.ip : "";
        this.domain = builder.domain != null ? builder.domain : "";
        this.url = builder.url != null ? builder.url : "";
        this.port = builder.port;
        this.protocol = builder.protocol != null ? builder.protocol : "TCP";
        this.bytesSent = builder.bytesSent;
        this.bytesRcvd = builder.bytesRcvd;
        this.networkType = builder.networkType != null ? builder.networkType : "UNKNOWN";
        this.isBackground = builder.isBackground;
        this.eventCategory = builder.eventCategory != null ? builder.eventCategory : EventCategory.NETWORK_CONN;
        this.details = builder.details != null ? builder.details : "";
    }

    public static class Builder {
        private String sourceTag = SOURCE_API;
        private int appUid = -1;
        private String packageName = "";
        private String appName = "";
        private long timestamp = System.currentTimeMillis();
        private String destination = "";
        private String ip = "";
        private String domain = "";
        private String url = "";
        private int port = 0;
        private String protocol = "TCP";
        private long bytesSent = 0;
        private long bytesRcvd = 0;
        private String networkType = "UNKNOWN";
        private boolean isBackground = false;
        private EventCategory eventCategory = EventCategory.NETWORK_CONN;
        private String details = "";

        public Builder setSourceTag(String sourceTag) {
            this.sourceTag = sourceTag;
            return this;
        }

        public Builder setAppUid(int appUid) {
            this.appUid = appUid;
            return this;
        }

        public Builder setPackageName(String packageName) {
            this.packageName = packageName;
            return this;
        }

        public Builder setAppName(String appName) {
            this.appName = appName;
            return this;
        }

        public Builder setTimestamp(long timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        public Builder setDestination(String destination) {
            this.destination = destination;
            return this;
        }

        public Builder setIp(String ip) {
            this.ip = ip;
            return this;
        }

        public Builder setDomain(String domain) {
            this.domain = domain;
            return this;
        }

        public Builder setUrl(String url) {
            this.url = url;
            return this;
        }

        public Builder setPort(int port) {
            this.port = port;
            return this;
        }

        public Builder setProtocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder setBytesSent(long bytesSent) {
            this.bytesSent = bytesSent;
            return this;
        }

        public Builder setBytesRcvd(long bytesRcvd) {
            this.bytesRcvd = bytesRcvd;
            return this;
        }

        public Builder setNetworkType(String networkType) {
            this.networkType = networkType;
            return this;
        }

        public Builder setBackground(boolean background) {
            isBackground = background;
            return this;
        }

        public Builder setEventCategory(EventCategory eventCategory) {
            this.eventCategory = eventCategory;
            return this;
        }

        public Builder setDetails(String details) {
            this.details = details;
            return this;
        }

        public UnifiedTrafficEvent build() {
            return new UnifiedTrafficEvent(this);
        }
    }

    public boolean isVpnSource() {
        return SOURCE_VPN.equalsIgnoreCase(sourceTag);
    }

    public boolean isApiSource() {
        return SOURCE_API.equalsIgnoreCase(sourceTag);
    }
}
