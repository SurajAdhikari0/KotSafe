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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.DiffUtil;

import java.util.Objects;

/**
 * Immutable row representation for connection list rendering.
 * All ownership, formatting, and filtering data are pre-calculated to allow ViewHolder.bind()
 * to execute purely display logic without blocking main thread.
 */
public final class ConnectionRow {
    public static final String PAYLOAD_STATS = "PAYLOAD_STATS";
    public static final String PAYLOAD_STATUS = "PAYLOAD_STATUS";

    public static final int ROW_TYPE_NORMAL = 0;
    public static final int ROW_TYPE_APP_GROUP_HEADER = 1;
    public static final int ROW_TYPE_APP_CHILD = 2;

    public final long rowId;
    public final int rowType;
    public final int groupConnectionCount;
    public final int groupActiveCount;
    public final boolean isExpanded;

    public final ConnectionDescriptor descriptor;
    public final int incrId;
    public final int uid;
    public final String appName;
    public final String appPackage;
    public final boolean isSystemApp;
    public final boolean isSystemService;
    public final boolean canBlockAppWide;

    public final String targetDisplay;
    public final String protoAndPort;
    public final String l7proto;
    public final int ipproto;
    public final int dstPort;

    public final long sentBytes;
    public final long rcvdBytes;
    public final long totalBytes;
    public final int status;
    public final boolean isBlocked;
    public final String blockReason;
    public final String blockType;
    public final long lastSeen;
    public final long firstSeen;
    public final int aggregatedFlows;
    public final int queryCount;
    public final int blockedPkts;
    public final String country;
    public final boolean isBlacklisted;
    public final boolean isDecrypted;
    public final boolean isDns;

    public ConnectionRow(long rowId,
                         @NonNull ConnectionDescriptor descriptor,
                         @NonNull AppPresentationCache.Presentation presentation,
                         @NonNull String targetDisplay,
                         @NonNull String protoAndPort) {
        this(rowId, ROW_TYPE_NORMAL, 1, (descriptor.status < ConnectionDescriptor.CONN_STATUS_CLOSED ? 1 : 0),
                false, descriptor, presentation, targetDisplay, protoAndPort,
                descriptor.sent_bytes, descriptor.rcvd_bytes, descriptor.last_seen, descriptor.first_seen,
                descriptor.status, descriptor.is_blocked);
    }

    public ConnectionRow(long rowId,
                         int rowType,
                         int groupConnectionCount,
                         int groupActiveCount,
                         boolean isExpanded,
                         @NonNull ConnectionDescriptor descriptor,
                         @NonNull AppPresentationCache.Presentation presentation,
                         @NonNull String targetDisplay,
                         @NonNull String protoAndPort,
                         long sentBytes,
                         long rcvdBytes,
                         long lastSeen,
                         long firstSeen,
                         int status,
                         boolean isBlocked) {
        this.rowId = rowId;
        this.rowType = rowType;
        this.groupConnectionCount = groupConnectionCount;
        this.groupActiveCount = groupActiveCount;
        this.isExpanded = isExpanded;
        this.descriptor = descriptor;
        this.incrId = descriptor.incr_id;
        this.uid = descriptor.uid;
        this.isSystemApp = presentation.isSystemApp;
        this.isSystemService = presentation.isSystemService;
        this.canBlockAppWide = presentation.canBlockAppWide;
        this.isDns = descriptor.isDns();
        if (this.isDns) {
            String domain = (descriptor.info != null && !descriptor.info.isEmpty()) ? descriptor.info
                    : ((descriptor.url != null && !descriptor.url.isEmpty()) ? descriptor.url : "");
            while (domain.endsWith(".")) {
                domain = domain.substring(0, domain.length() - 1);
            }
            this.appName = domain.isEmpty() ? "DNS lookup" : domain;

            String owner = presentation.appLabel;
            String sub = owner + (domain.isEmpty() ? " • Query name unavailable" : " • DNS lookup");
            this.appPackage = sub;
            String resolverIp = (descriptor.dst_port == 53 || descriptor.dst_port == 5353) ? descriptor.dst_ip : descriptor.src_ip;
            this.targetDisplay = "Resolver • " + resolverIp;
        } else {
            this.appName = presentation.appLabel;
            this.appPackage = presentation.packageName;
            this.targetDisplay = targetDisplay;
        }

        this.protoAndPort = protoAndPort;
        this.l7proto = descriptor.l7proto != null ? descriptor.l7proto : "";
        this.ipproto = descriptor.ipproto;
        this.dstPort = descriptor.dst_port;

        this.sentBytes = sentBytes;
        this.rcvdBytes = rcvdBytes;
        this.totalBytes = sentBytes + rcvdBytes;
        this.status = status;
        this.isBlocked = isBlocked;
        this.blockReason = descriptor.block_reason != null ? descriptor.block_reason : "";
        this.blockType = descriptor.block_type != null ? descriptor.block_type : "";
        this.lastSeen = lastSeen;
        this.firstSeen = firstSeen;
        this.aggregatedFlows = descriptor.aggregated_flows;
        this.queryCount = descriptor.query_count;
        this.blockedPkts = descriptor.blocked_pkts;
        this.country = descriptor.country != null ? descriptor.country : "";
        this.isBlacklisted = descriptor.isBlacklisted();
        this.isDecrypted = descriptor.isDecrypted();
    }

    @NonNull
    public ConnectionRow asChildRow() {
        return new ConnectionRow(
                this.rowId,
                ROW_TYPE_APP_CHILD,
                1,
                (this.status < ConnectionDescriptor.CONN_STATUS_CLOSED ? 1 : 0),
                false,
                this.descriptor,
                new AppPresentationCache.Presentation(this.uid, this.appName, this.appPackage, this.isSystemApp, this.isSystemService, this.canBlockAppWide),
                this.targetDisplay,
                this.protoAndPort,
                this.sentBytes,
                this.rcvdBytes,
                this.lastSeen,
                this.firstSeen,
                this.status,
                this.isBlocked
        );
    }

    @NonNull
    public static ConnectionRow createAppGroupHeader(
            int uid,
            int totalConnections,
            int activeConnections,
            boolean isExpanded,
            long totalSent,
            long totalRcvd,
            long latestSeen,
            long earliestSeen,
            int status,
            boolean isBlocked,
            @NonNull ConnectionRow representative
    ) {
        long headerRowId = -((long) Math.abs(uid) * 1000003L + 1L);
        AppPresentationCache.Presentation presentation = new AppPresentationCache.Presentation(
                uid,
                representative.appName,
                representative.appPackage,
                representative.isSystemApp,
                representative.isSystemService,
                representative.canBlockAppWide
        );
        String targetText = totalConnections + " connections established • " + (isExpanded ? "Tap to collapse" : "Tap to expand");
        String protoText = (activeConnections > 0 ? (activeConnections + " active • ") : "") + totalConnections + " connections";

        return new ConnectionRow(
                headerRowId,
                ROW_TYPE_APP_GROUP_HEADER,
                totalConnections,
                activeConnections,
                isExpanded,
                representative.descriptor,
                presentation,
                targetText,
                protoText,
                totalSent,
                totalRcvd,
                latestSeen,
                earliestSeen,
                status,
                isBlocked
        );
    }

    public boolean hasSameContent(@NonNull ConnectionRow other) {
        return this.rowType == other.rowType
                && this.groupConnectionCount == other.groupConnectionCount
                && this.groupActiveCount == other.groupActiveCount
                && this.isExpanded == other.isExpanded
                && this.totalBytes == other.totalBytes
                && this.sentBytes == other.sentBytes
                && this.rcvdBytes == other.rcvdBytes
                && this.status == other.status
                && this.isBlocked == other.isBlocked
                && this.lastSeen == other.lastSeen
                && this.aggregatedFlows == other.aggregatedFlows
                && this.queryCount == other.queryCount
                && this.blockedPkts == other.blockedPkts
                && Objects.equals(this.targetDisplay, other.targetDisplay)
                && Objects.equals(this.blockReason, other.blockReason)
                && Objects.equals(this.l7proto, other.l7proto);
    }

    public static final DiffUtil.ItemCallback<ConnectionRow> DIFF_CALLBACK = new DiffUtil.ItemCallback<ConnectionRow>() {
        @Override
        public boolean areItemsTheSame(@NonNull ConnectionRow oldItem, @NonNull ConnectionRow newItem) {
            return oldItem.rowId == newItem.rowId && oldItem.rowType == newItem.rowType;
        }

        @Override
        public boolean areContentsTheSame(@NonNull ConnectionRow oldItem, @NonNull ConnectionRow newItem) {
            return oldItem.hasSameContent(newItem);
        }

        @Nullable
        @Override
        public Object getChangePayload(@NonNull ConnectionRow oldItem, @NonNull ConnectionRow newItem) {
            if (oldItem.isExpanded != newItem.isExpanded || oldItem.rowType != newItem.rowType) {
                return null;
            }
            if (oldItem.status != newItem.status || oldItem.isBlocked != newItem.isBlocked) {
                return PAYLOAD_STATUS;
            }
            if (oldItem.totalBytes != newItem.totalBytes || oldItem.lastSeen != newItem.lastSeen
                    || oldItem.aggregatedFlows != newItem.aggregatedFlows || oldItem.queryCount != newItem.queryCount
                    || oldItem.groupConnectionCount != newItem.groupConnectionCount
                    || oldItem.groupActiveCount != newItem.groupActiveCount) {
                return PAYLOAD_STATS;
            }
            return null;
        }
    };
}
