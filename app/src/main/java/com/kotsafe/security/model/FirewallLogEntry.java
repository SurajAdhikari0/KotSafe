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
 */

package com.kotsafe.security.model;

import java.io.Serializable;

public class FirewallLogEntry implements Serializable {
    public static final String ACTION_ALLOWED = "ALLOWED";
    public static final String ACTION_BLOCKED = "BLOCKED";
    public static final String ACTION_ALERT = "ALERT";

    public static final String VERDICT_CLEAN = "CLEAN";
    public static final String VERDICT_SUSPICIOUS = "SUSPICIOUS";
    public static final String VERDICT_MALICIOUS = "MALICIOUS";
    public static final String VERDICT_UNKNOWN = "UNKNOWN";

    public long id;
    public long timestamp;
    public int uid;
    public String packageName = "";
    public String appName = "";
    public boolean isServiceApp;

    public String srcIp = "";
    public int srcPort;
    public String dstIp = "";
    public int dstPort;
    public String protocol = "TCP"; // TCP, UDP, ICMP
    public String l7proto = "";    // DNS, HTTP, TLS, etc.
    public String domainOrUrl = ""; // Host SNI, HTTP URL, or DNS query
    public String payloadHash = ""; // SHA-256 hash of payload

    public static final String BLOCK_TYPE_ADS = "ADS";
    public static final String BLOCK_TYPE_MALWARE = "MALWARE";
    public static final String BLOCK_TYPE_PHISHING = "PHISHING";
    public static final String BLOCK_TYPE_RATE_LIMIT = "RATE_LIMIT";
    public static final String BLOCK_TYPE_FIREWALL_RULE = "FIREWALL_RULE";
    public static final String BLOCK_TYPE_LAN_RULE = "LAN_RULE";
    public static final String BLOCK_TYPE_WEB_CATEGORY = "WEB_CATEGORY";
    public static final String BLOCK_TYPE_USER = "USER";
    public static final String BLOCK_TYPE_POLICY = "POLICY";

    public String action = ACTION_ALLOWED; // ALLOWED, BLOCKED, ALERT
    public String blockReason = "";        // Wi-Fi Rule, Roaming Rule, Background Rule, etc.
    public String blockType = "";          // ADS, MALWARE, PHISHING, RATE_LIMIT, etc.
    public String networkType = "UNKNOWN"; // WIFI, CELLULAR, ROAMING, LAN
    public boolean isBackground;           // Screen off or background execution

    public long bytesSent;
    public long bytesRcvd;
    public long duration;

    public String country = "";
    public String asn = "";

    // Threat Intelligence fields (VirusTotal, AlienVault OTX, Maltrail)
    public String threatVerdict = VERDICT_UNKNOWN;
    public int threatScore = -1; // e.g. 0 to 100 (-1 = not scanned)
    public String threatSource = "";
    public String threatDetails = "";

    public FirewallLogEntry() {
        this.timestamp = System.currentTimeMillis();
    }

    public boolean isBlocked() {
        return ACTION_BLOCKED.equalsIgnoreCase(action);
    }

    public boolean isMalicious() {
        return ACTION_ALERT.equalsIgnoreCase(action) ||
                VERDICT_MALICIOUS.equalsIgnoreCase(threatVerdict) ||
                VERDICT_SUSPICIOUS.equalsIgnoreCase(threatVerdict);
    }

    public String getDisplayDestination() {
        if(domainOrUrl != null && !domainOrUrl.isEmpty()) {
            return domainOrUrl;
        }
        if(dstIp != null && !dstIp.isEmpty()) {
            return dstIp + (dstPort > 0 ? ":" + dstPort : "");
        }
        return "Unknown";
    }

    public String getFormattedBlockType() {
        if (blockType != null && !blockType.isEmpty()) {
            return blockType.toUpperCase();
        }
        String r = (blockReason != null) ? blockReason.toLowerCase() : "";
        if (r.contains("ad") || r.contains("track") || r.contains("telemetry") || r.contains("stevenblack") || r.contains("oisd")) {
            return BLOCK_TYPE_ADS;
        }
        if (r.contains("malware") || r.contains("malicious") || r.contains("c2") || r.contains("threat")) {
            return BLOCK_TYPE_MALWARE;
        }
        if (r.contains("phish")) {
            return BLOCK_TYPE_PHISHING;
        }
        if (r.contains("rate limit") || r.contains("flood guard") || r.contains("quarantine")) {
            return BLOCK_TYPE_RATE_LIMIT;
        }
        if (r.contains("web category") || r.contains("category")) {
            return BLOCK_TYPE_WEB_CATEGORY;
        }
        if (r.contains("lan")) {
            return BLOCK_TYPE_LAN_RULE;
        }
        if (r.contains("user")) {
            return BLOCK_TYPE_USER;
        }
        if (r.contains("wi-fi") || r.contains("mobile") || r.contains("roaming") || r.contains("background")) {
            return BLOCK_TYPE_FIREWALL_RULE;
        }
        return isBlocked() ? BLOCK_TYPE_POLICY : "ALLOWED";
    }
}
