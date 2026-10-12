/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import java.io.Serializable;

public class DnsActivityEntry implements Serializable {
    public static final String STATUS_BLOCKED = "BLOCKED";
    public static final String STATUS_ALLOWED = "ALLOWED";

    public long id;
    public String domain;
    public String queryType;
    public String callerApp;
    public String callerPkg;
    public String status; // BLOCKED | ALLOWED
    public String blockReason; // e.g. "StevenBlack Unified", "User Blacklist", ""
    public long timestamp;

    public boolean isBlocked() {
        return STATUS_BLOCKED.equalsIgnoreCase(status);
    }
}
