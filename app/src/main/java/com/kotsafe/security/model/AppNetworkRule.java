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

import androidx.annotation.NonNull;
import java.io.Serializable;
import java.util.Objects;

/**
 * Granular Network Access Control rule for an application.
 */
public class AppNetworkRule implements Serializable {
    private static final long serialVersionUID = 1L;

    private String packageName;
    private int uid;
    private boolean wifiBlocked;
    private boolean mobileBlocked;
    private boolean roamingBlocked;
    private boolean allowInBackground; // true: allowed when screen is off, false: blocked when screen is off
    private boolean lanBlocked;
    private long updatedAt;

    public AppNetworkRule() {
        this.packageName = "";
        this.uid = -1;
        this.wifiBlocked = false;
        this.mobileBlocked = false;
        this.roamingBlocked = false;
        this.allowInBackground = true;
        this.lanBlocked = false;
        this.updatedAt = System.currentTimeMillis();
    }

    public AppNetworkRule(@NonNull String packageName, int uid) {
        this.packageName = packageName;
        this.uid = uid;
        this.wifiBlocked = false;
        this.mobileBlocked = false;
        this.roamingBlocked = false;
        this.allowInBackground = true;
        this.lanBlocked = false;
        this.updatedAt = System.currentTimeMillis();
    }

    public AppNetworkRule(AppNetworkRule other) {
        this.packageName = other.packageName;
        this.uid = other.uid;
        this.wifiBlocked = other.wifiBlocked;
        this.mobileBlocked = other.mobileBlocked;
        this.roamingBlocked = other.roamingBlocked;
        this.allowInBackground = other.allowInBackground;
        this.lanBlocked = other.lanBlocked;
        this.updatedAt = other.updatedAt;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public int getUid() {
        return uid;
    }

    public void setUid(int uid) {
        this.uid = uid;
    }

    public boolean isWifiBlocked() {
        return wifiBlocked;
    }

    public void setWifiBlocked(boolean wifiBlocked) {
        this.wifiBlocked = wifiBlocked;
        this.updatedAt = System.currentTimeMillis();
    }

    public boolean isMobileBlocked() {
        return mobileBlocked;
    }

    public void setMobileBlocked(boolean mobileBlocked) {
        this.mobileBlocked = mobileBlocked;
        this.updatedAt = System.currentTimeMillis();
    }

    public boolean isRoamingBlocked() {
        return roamingBlocked;
    }

    public void setRoamingBlocked(boolean roamingBlocked) {
        this.roamingBlocked = roamingBlocked;
        this.updatedAt = System.currentTimeMillis();
    }

    public boolean isAllowInBackground() {
        return allowInBackground;
    }

    public void setAllowInBackground(boolean allowInBackground) {
        this.allowInBackground = allowInBackground;
        this.updatedAt = System.currentTimeMillis();
    }

    public boolean isLanBlocked() {
        return lanBlocked;
    }

    public void setLanBlocked(boolean lanBlocked) {
        this.lanBlocked = lanBlocked;
        this.updatedAt = System.currentTimeMillis();
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }

    /**
     * Determines whether this rule blocks on the specified active network type.
     */
    public boolean isBlockedOn(NetworkType networkType) {
        if (networkType == null)
            return false;

        switch (networkType) {
            case WIFI:
                return wifiBlocked;
            case MOBILE:
                return mobileBlocked;
            case ROAMING:
                return roamingBlocked || mobileBlocked;
            case NONE:
            default:
                return false;
        }
    }

    /**
     * Determines whether this rule blocks traffic when the screen is in the given state.
     */
    public boolean isBlockedForScreenState(boolean isScreenOn) {
        return !isScreenOn && !allowInBackground;
    }

    /**
     * Returns true if any restriction is active on this rule.
     */
    public boolean isAnyRestricted() {
        return wifiBlocked || mobileBlocked || roamingBlocked || !allowInBackground || lanBlocked;
    }

    /**
     * Returns true if both Wi-Fi and Mobile Data are blocked.
     */
    public boolean isFullyBlocked() {
        return wifiBlocked && mobileBlocked;
    }

    /**
     * Returns true if all network access is completely allowed.
     */
    public boolean isFullyAllowed() {
        return !wifiBlocked && !mobileBlocked && !roamingBlocked && allowInBackground && !lanBlocked;
    }

    public void blockAll() {
        this.wifiBlocked = true;
        this.mobileBlocked = true;
        this.roamingBlocked = true;
        this.allowInBackground = false;
        this.lanBlocked = true;
        this.updatedAt = System.currentTimeMillis();
    }

    public void allowAll() {
        this.wifiBlocked = false;
        this.mobileBlocked = false;
        this.roamingBlocked = false;
        this.allowInBackground = true;
        this.lanBlocked = false;
        this.updatedAt = System.currentTimeMillis();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppNetworkRule that = (AppNetworkRule) o;
        return uid == that.uid &&
                wifiBlocked == that.wifiBlocked &&
                mobileBlocked == that.mobileBlocked &&
                roamingBlocked == that.roamingBlocked &&
                allowInBackground == that.allowInBackground &&
                lanBlocked == that.lanBlocked &&
                Objects.equals(packageName, that.packageName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(packageName, uid, wifiBlocked, mobileBlocked, roamingBlocked, allowInBackground, lanBlocked);
    }
}
