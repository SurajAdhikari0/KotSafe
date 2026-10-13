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

public class AntivirusEvidenceItem implements Serializable {
    public static final String TYPE_IP = "IP";
    public static final String TYPE_URL = "URL";
    public static final String TYPE_SERVICE_HASH = "SERVICE_HASH";
    public static final String TYPE_APP_HASH = "APP_HASH";
    public static final String TYPE_SUSPICIOUS_PORT = "SUSPICIOUS_PORT";
    public static final String TYPE_YARA_MATCH = "YARA_MATCH";
    public static final String TYPE_STORAGE_FILE = "STORAGE_FILE";

    public static final String SEVERITY_CLEAN = "CLEAN";
    public static final String SEVERITY_LOW = "LOW";
    public static final String SEVERITY_SUSPICIOUS = "SUSPICIOUS";
    public static final String SEVERITY_MALICIOUS = "MALICIOUS";
    public static final String SEVERITY_RESOLVED = "RESOLVED";

    public boolean isQuarantined = false;

    public String filePath = "";
    public String sha256 = "";
    public String fileSizeFormatted = "";
    public String detectionSource = "";
    public String malwareFamily = "";
    public String threatCategory = "";
    public String type = TYPE_IP;
    public String title = "";
    public String subtitle = "";
    public String details = "";
    public String packageName = "";
    public String iocValue = "";
    public String severity = SEVERITY_CLEAN;
    public String verdict = "CLEAN"; // TRUSTED, CLEAN, MONITOR, SUSPICIOUS, MALICIOUS
    public String confidence = "HIGH"; // LOW, MEDIUM, HIGH
    public java.util.List<String> forensicReasons = new java.util.ArrayList<>();
    public int detectionCount = 0;
    public boolean canBlockInFirewall = true;
    public boolean isSystemApp = false;
    public boolean isWhitelisted = false;
    public String systemReason = "";

    // AI Threat Explainer & Semantic Reasoning (Phase 2)
    public String aiExplanation = "";
    public String aiActionPlan = "";
    public String aiConversationalPrompt = "";
    public java.util.List<String> mitreTechniques = new java.util.ArrayList<>();
    public int mlRiskScore = 0;

    public AntivirusEvidenceItem() {}

    public AntivirusEvidenceItem(String type, String title, String subtitle, String iocValue, String severity, String details) {
        this.type = type;
        this.title = title;
        this.subtitle = subtitle;
        this.iocValue = iocValue;
        this.severity = severity;
        this.details = details;
    }

    public String getDisplayPath() {
        if (filePath != null && !filePath.isEmpty()) {
            return filePath;
        }
        if (subtitle != null && (subtitle.startsWith("/") || subtitle.contains(java.io.File.separator))) {
            return subtitle;
        }
        return "";
    }

    public String getDisplaySha256() {
        if (sha256 != null && !sha256.isEmpty()) {
            return sha256;
        }
        if (iocValue != null && iocValue.length() == 64 && iocValue.matches("^[a-fA-F0-9]{64}$")) {
            return iocValue;
        }
        return "";
    }
}
