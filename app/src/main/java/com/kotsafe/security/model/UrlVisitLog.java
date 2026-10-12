/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

/** Simple POJO representing one URL/domain visit event. Stored in UrlVisitDbHelper. */
public class UrlVisitLog {
    public long id;
    public long timestamp;
    public String url;
    public String domain;
    public String ip;
    public String appName;
    public String packageName;
    public String method;       // GET | POST | CONNECT | etc.
    public boolean wasBlocked;
    public int riskScore;       // 0-100; populated async by NetworkSecurityMonitor
    public String verdict;      // SAFE | SUSPICIOUS | HIGH | MALICIOUS
}
