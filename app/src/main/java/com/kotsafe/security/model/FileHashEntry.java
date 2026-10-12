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

public class FileHashEntry implements Serializable {
    public static final String THREAT_CLEAN = "CLEAN";
    public static final String THREAT_SUSPICIOUS = "SUSPICIOUS";
    public static final String THREAT_MALICIOUS = "MALICIOUS";
    public static final String THREAT_UNKNOWN = "UNKNOWN";

    // Scan type constants
    public static final String SCAN_TYPE_APP = "APP";
    public static final String SCAN_TYPE_STORAGE = "STORAGE";
    public static final String SCAN_TYPE_DOWNLOAD = "DOWNLOAD";

    // File class constants — determines analysis depth
    public static final String FILE_CLASS_APK = "APK";
    public static final String FILE_CLASS_DEX = "DEX";
    public static final String FILE_CLASS_SO = "SO";
    public static final String FILE_CLASS_SCRIPT = "SCRIPT";
    public static final String FILE_CLASS_ARCHIVE = "ARCHIVE";
    public static final String FILE_CLASS_MEDIA = "MEDIA";
    public static final String FILE_CLASS_DOCUMENT = "DOCUMENT";
    public static final String FILE_CLASS_UNKNOWN = "UNKNOWN";

    // Scan status constants
    public static final String SCAN_STATUS_DONE = "DONE";
    public static final String SCAN_STATUS_PENDING = "PENDING";
    public static final String SCAN_STATUS_SKIPPED = "SKIPPED";

    // Priority: 0=highest (new APK/download), 1=high, 2=normal, 3=maintenance
    public static final int PRIORITY_CRITICAL = 0;
    public static final int PRIORITY_HIGH = 1;
    public static final int PRIORITY_NORMAL = 2;
    public static final int PRIORITY_LOW = 3;

    public long id;
    public String fileName = "";
    public String filePath = "";
    public String packageName = "";
    public String appName = "";
    public String sha256 = "";
    public String md5 = "";
    public String sha1 = "";          // v2: computed only when needed
    public long fileSize;
    public boolean isServiceApp;
    public boolean isSystemApp;
    public long scanTimestamp;
    public String threatStatus = THREAT_CLEAN;
    public String threatDetails = "";

    // v2 smart-scan metadata
    public long fileLastModified;     // File.lastModified() — used to skip unchanged files
    public String scanType = SCAN_TYPE_APP;
    public String mimeType = "";
    public String fileClass = FILE_CLASS_UNKNOWN;
    public int scanPriority = PRIORITY_NORMAL;
    public String scanStatus = SCAN_STATUS_DONE;

    // v3 tiered & caching fields (see Implementation Plan v2)
    public String scanTier = "QUICK";
    public int confidenceScore = 0;           // Heuristic score 0-100 or blended with VT
    public int signatureDbVersion = 0;       // 0 = pre-migration / needs re-evaluation
    public int modelVersion = 0;
    public String cloudCorrelationId = null; // Zero-cost seam for cloud reputation
    public long ctime = 0;                   // Inode metadata change time for tamper detection

    public FileHashEntry() {
        scanTimestamp = System.currentTimeMillis();
    }

    /** Returns true if this entry represents a high-risk file class (APK, DEX, SO, SCRIPT). */
    public boolean isHighRiskClass() {
        return FILE_CLASS_APK.equals(fileClass)
                || FILE_CLASS_DEX.equals(fileClass)
                || FILE_CLASS_SO.equals(fileClass)
                || FILE_CLASS_SCRIPT.equals(fileClass);
    }
}
