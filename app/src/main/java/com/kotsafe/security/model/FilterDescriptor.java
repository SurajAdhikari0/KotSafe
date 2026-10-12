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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import androidx.preference.PreferenceManager;
import android.view.LayoutInflater;
import android.view.View;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.model.ConnectionDescriptor.Status;
import com.kotsafe.security.model.ConnectionDescriptor.DecryptionStatus;
import com.kotsafe.security.model.ConnectionDescriptor.FilteringStatus;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;

import java.io.Serializable;

public class FilterDescriptor implements Serializable {
    public enum AppCategory {
        ALL,
        USER,
        SYSTEM,
        DNS,
        ACTIVE_ONLY,
        CLOSED,
        BLOCKED_ONLY,
        WEB_ONLY
    }

    public Status status;
    public boolean showMasked;
    public boolean onlyBlacklisted;
    public boolean onlyCleartext;
    public FilteringStatus filteringStatus;
    public DecryptionStatus decStatus;
    public String iface;
    public int uid = -2; // this is persistent and used internally (AppDetailsActivity)
    public long minSize = 0;
    public AppCategory appCategory = AppCategory.ALL;

    public FilterDescriptor() {
        clear();
        assert(!isSet());
    }

    public FilterDescriptor(FilterDescriptor other) {
        if (other != null) {
            this.status = other.status;
            this.showMasked = other.showMasked;
            this.onlyBlacklisted = other.onlyBlacklisted;
            this.onlyCleartext = other.onlyCleartext;
            this.filteringStatus = other.filteringStatus;
            this.decStatus = other.decStatus;
            this.iface = other.iface;
            this.uid = other.uid;
            this.minSize = other.minSize;
            this.appCategory = other.appCategory;
        } else {
            clear();
        }
    }

    public static boolean isHideSystemTrafficEnabled() {
        Context ctx = KotSafe.getInstance();
        if (ctx == null) return false;
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        return Prefs.isHideSystemTraffic(sp);
    }

    /** When enabled, closed connections leave the live lists and are shown under the Closed chip. */
    public static boolean isAutoMoveClosedEnabled() {
        Context ctx = KotSafe.getInstance();
        if (ctx == null) return false;
        SharedPreferences sp = PreferenceManager.getDefaultSharedPreferences(ctx);
        return Prefs.isAutoMoveClosed(sp);
    }

    public static AppCategory getDefaultAppCategory() {
        return AppCategory.ALL;
    }

    public boolean isSet() {
        return (status != Status.STATUS_INVALID)
                || (decStatus != DecryptionStatus.INVALID)
                || (filteringStatus != FilteringStatus.INVALID)
                || (iface != null)
                || onlyBlacklisted
                || onlyCleartext
                || (uid != -2)
                || (minSize > 0)
                || (appCategory != getDefaultAppCategory())
                || (!showMasked && !KotSafe.getInstance().getVisualizationMask().isEmpty());
    }

    public boolean matches(ConnectionDescriptor conn) {
        if (conn == null)
            return false;

        // Broad All view should include user and system traffic, but still keep DNS in its dedicated category.
        if (appCategory == AppCategory.ALL && conn.isDns()) {
            return false;
        }

        // Closed services automatically move to the Closed chip in the main feeds
        // (ALL / USER / ACTIVE_ONLY).
        // Threats (blocked/blacklisted), DNS lookups, and System services stay visible, and explicit status/app filters bypass the auto-move.
        if ((appCategory == AppCategory.ALL || appCategory == AppCategory.USER || appCategory == AppCategory.ACTIVE_ONLY)
                && status == Status.STATUS_INVALID && uid == -2
                && conn.status >= ConnectionDescriptor.CONN_STATUS_CLOSED
                && !conn.isDns() && !conn.is_blocked && !conn.isBlacklisted()
                && isAutoMoveClosedEnabled()) {
            return false;
        }

        if (appCategory != AppCategory.ALL && appCategory != AppCategory.SYSTEM && appCategory != AppCategory.DNS
                && isHideSystemTrafficEnabled()) {
            // Network Diagnostic (ICMP / ICMPv6 ping) belongs to the OS, hide it too
            if (conn.ipproto == 1 || conn.ipproto == 58)
                return false;
            if (conn.uid < 10000 || com.kotsafe.security.Utils.isSystemUid(conn.uid))
                return false;
            Context ctx = KotSafe.getInstance();
            if (ctx != null && com.kotsafe.security.Utils.isSystemApp(ctx, conn.uid))
                return false;
        }

        if (appCategory == AppCategory.USER) {
            if (conn.isDns())
                return false;
            if (conn.uid < 10000 || com.kotsafe.security.Utils.isSystemUid(conn.uid))
                return false;
            Context ctx = KotSafe.getInstance();
            if (ctx != null) {
                if (com.kotsafe.security.Utils.isSystemApp(ctx, conn.uid))
                    return false;
            }
        } else if (appCategory == AppCategory.SYSTEM) {
            // System apps (pre-installed APKs and official Android system components),
            // DNS lookups and raw ICMP network diagnostics belong to DNS/OS tabs
            if (conn.isDns())
                return false;
            if (conn.ipproto == 1 || conn.ipproto == 58)
                return false;
            if (conn.uid < 0)
                return false;
            if (!com.kotsafe.security.Utils.isSystemApp(KotSafe.getInstance(), conn.uid))
                return false;
        } else if (appCategory == AppCategory.DNS) {
            if (!conn.isDns())
                return false;
        } else if (appCategory == AppCategory.ACTIVE_ONLY) {
            if (conn.status >= ConnectionDescriptor.CONN_STATUS_CLOSED)
                return false;
        } else if (appCategory == AppCategory.CLOSED) {
            if (conn.status < ConnectionDescriptor.CONN_STATUS_CLOSED)
                return false;
        } else if (appCategory == AppCategory.BLOCKED_ONLY) {
            if (!conn.is_blocked && !conn.isBlacklisted())
                return false;
        } else if (appCategory == AppCategory.WEB_ONLY) {
            String proto = (conn.l7proto != null) ? conn.l7proto.toUpperCase() : "";
            if (!proto.contains("HTTP") && !proto.equals("TLS") && conn.dst_port != 80 && conn.dst_port != 443 && conn.dst_port != 8080)
                return false;
        }

        return (showMasked || !KotSafe.getInstance().getVisualizationMask().matches(conn))
                && (!onlyBlacklisted || conn.isBlacklisted())
                && (!onlyCleartext || conn.isCleartext())
                && ((status == Status.STATUS_INVALID) || (conn.getStatus().equals(status)))
                && ((decStatus == DecryptionStatus.INVALID) || (conn.getDecryptionStatus() == decStatus))
                && ((filteringStatus == FilteringStatus.INVALID) || ((filteringStatus == FilteringStatus.BLOCKED) == conn.is_blocked))
                && ((iface == null) || (CaptureService.getInterfaceName(conn.ifidx).equals(iface)))
                && ((uid == -2) || (uid == conn.uid))
                && ((minSize == 0) || ((conn.sent_bytes + conn.rcvd_bytes) >= minSize));
    }

    private void addChip(LayoutInflater inflater, ChipGroup group, int id, String text) {
        Chip chip = (Chip) inflater.inflate(R.layout.active_filter_chip, group, false);
        chip.setId(id);
        chip.setText(text.toLowerCase());
        group.addView(chip);
    }

    public void toChips(LayoutInflater inflater, ChipGroup group) {
        Context ctx = inflater.getContext();

        if(!showMasked)
            addChip(inflater, group, R.id.not_hidden, ctx.getString(R.string.not_hidden_filter));
        if(onlyBlacklisted)
            addChip(inflater, group, R.id.blacklisted, ctx.getString(R.string.malicious_connection_filter));
        if(onlyCleartext)
            addChip(inflater, group, R.id.only_cleartext, ctx.getString(R.string.cleartext_connection));
        if(status != Status.STATUS_INVALID) {
            String label = String.format(ctx.getString(R.string.status_filter), ConnectionDescriptor.getStatusLabel(status, ctx));
            addChip(inflater, group, R.id.status_ind, label);
        }
        if(decStatus != DecryptionStatus.INVALID) {
            String label = String.format(ctx.getString(R.string.decryption_filter), ConnectionDescriptor.getDecryptionStatusLabel(decStatus, ctx));
            addChip(inflater, group, R.id.decryption_status, label);
        }
        if(filteringStatus != FilteringStatus.INVALID) {
            String label = ctx.getString(R.string.firewall_filter, ctx.getString((filteringStatus == FilteringStatus.BLOCKED) ?
                    R.string.blocked_connection_filter : R.string.allowed_connection_filter));
            addChip(inflater, group, R.id.firewall, label);
        }
        if(iface != null)
            addChip(inflater, group, R.id.capture_interface, String.format(ctx.getString(R.string.interface_filter), iface));

        group.setVisibility(group.getChildCount() > 0 ? View.VISIBLE : View.GONE);
    }

    // clear one of the filters of toChips
    public void clear(int filter_id) {
        if(filter_id == R.id.not_hidden)
            showMasked = true;
        else if(filter_id == R.id.blacklisted)
            onlyBlacklisted = false;
        else if(filter_id == R.id.only_cleartext)
            onlyCleartext = false;
        else if(filter_id == R.id.status_ind)
            status = Status.STATUS_INVALID;
        else if(filter_id == R.id.decryption_status)
            decStatus = DecryptionStatus.INVALID;
        else if(filter_id == R.id.firewall)
            filteringStatus = FilteringStatus.INVALID;
        else if(filter_id == R.id.capture_interface)
            iface = null;
    }

    public void clear() {
        showMasked = true;
        onlyBlacklisted = false;
        onlyCleartext = false;
        status = Status.STATUS_INVALID;
        decStatus = DecryptionStatus.INVALID;
        filteringStatus = FilteringStatus.INVALID;
        iface = null;
        minSize = 0;
        appCategory = getDefaultAppCategory();
    }
}
