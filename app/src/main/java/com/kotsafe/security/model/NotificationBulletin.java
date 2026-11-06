/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 *
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import org.json.JSONObject;

import java.io.Serializable;

/**
 * Represents a broadcast notification or threat bulletin sent from the KotSafe Admin Console.
 */
public class NotificationBulletin implements Serializable {

    private final long id;
    private final String title;
    private final String description;
    private final String type;
    private final String targetAudience;
    private final String actionUrl;
    private final String adminName;
    private final String timeAgo;
    private final String createdAt;
    private boolean isRead;

    public NotificationBulletin(long id, String title, String description, String type,
                                String targetAudience, String actionUrl, String adminName,
                                String timeAgo, String createdAt, boolean isRead) {
        this.id = id;
        this.title = title != null ? title : "";
        this.description = description != null ? description : "";
        this.type = type != null ? type.toLowerCase() : "info";
        this.targetAudience = targetAudience != null ? targetAudience : "all";
        this.actionUrl = actionUrl;
        this.adminName = adminName != null ? adminName : "Security Operations";
        this.timeAgo = timeAgo != null ? timeAgo : "";
        this.createdAt = createdAt != null ? createdAt : "";
        this.isRead = isRead;
    }

    public static NotificationBulletin fromJson(JSONObject json, boolean isRead) {
        if (json == null) return null;
        long id = json.optLong("id", 0);
        String title = json.optString("title", "");
        String description = json.optString("description", "");
        String type = json.optString("type", "info");
        String targetAudience = json.optString("target_audience", "all");
        String actionUrl = json.isNull("action_url") ? null : json.optString("action_url", null);
        String adminName = json.optString("admin_name", "KotSafe SOC");
        String timeAgo = json.optString("time_ago", "");
        String createdAt = json.optString("created_at", "");

        return new NotificationBulletin(id, title, description, type, targetAudience,
                actionUrl, adminName, timeAgo, createdAt, isRead);
    }

    public long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getType() {
        return type;
    }

    public String getTargetAudience() {
        return targetAudience;
    }

    public String getActionUrl() {
        return actionUrl;
    }

    public String getAdminName() {
        return adminName;
    }

    public String getTimeAgo() {
        return timeAgo;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public boolean isRead() {
        return isRead;
    }

    public void setRead(boolean read) {
        isRead = read;
    }
}

