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
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

/**
 * Immutable pre-calculated metrics for Connection screen summary chips.
 * Computed in a single pass during background state building.
 */
public final class ConnectionScreenMetrics {
    public final int totalCount;
    public final int activeCount;
    public final int closedCount;
    public final int blockedCount;

    public final int countAll;
    public final int countUser;
    public final int countSystem;
    public final int countDns;
    public final int countActiveOnly;
    public final int countClosedOnly;
    public final int countBlockedOnly;
    public final int countWebOnly;

    public final long maxBytes;
    public final int untrackedCount;

    public ConnectionScreenMetrics(int totalCount, int activeCount, int closedCount, int blockedCount,
                                   int countAll, int countUser, int countSystem, int countDns,
                                   int countActiveOnly, int countClosedOnly, int countBlockedOnly, int countWebOnly,
                                   long maxBytes, int untrackedCount) {
        this.totalCount = totalCount;
        this.activeCount = activeCount;
        this.closedCount = closedCount;
        this.blockedCount = blockedCount;

        this.countAll = countAll;
        this.countUser = countUser;
        this.countSystem = countSystem;
        this.countDns = countDns;
        this.countActiveOnly = countActiveOnly;
        this.countClosedOnly = countClosedOnly;
        this.countBlockedOnly = countBlockedOnly;
        this.countWebOnly = countWebOnly;

        this.maxBytes = maxBytes;
        this.untrackedCount = untrackedCount;
    }

    public static ConnectionScreenMetrics empty() {
        return new ConnectionScreenMetrics(0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0);
    }
}
