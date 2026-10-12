/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Enterprise SIEM & Syslog Telemetry Forwarder.
 * Exports incident timelines, process tampering, and behavioral anomaly events to
 * external SIEM aggregators (Elasticsearch / Logstash, Splunk HEC, or Syslog HTTP Webhook).
 */
public class SiemTelemetryForwarder {

    private static final String TAG = "SiemTelemetryForwarder";

    public static final String PREF_SIEM_ENABLED = "pref_siem_telemetry_enabled";
    public static final String PREF_SIEM_ENDPOINT = "pref_siem_endpoint_url";
    public static final String PREF_SIEM_AUTH_TOKEN = "pref_siem_auth_token";
    public static final String PREF_SIEM_FORMAT = "pref_siem_format"; // ECS, SYSLOG_JSON, CEF
    public static final String PREF_SIEM_ANONYMIZE_IP = "pref_siem_anonymize_ip";
    public static final String PREF_SIEM_DEVICE_GUID = "pref_siem_device_guid";

    public static final String FORMAT_ECS = "ECS";
    public static final String FORMAT_SYSLOG_JSON = "SYSLOG_JSON";
    public static final String FORMAT_CEF = "CEF";

    private static volatile SiemTelemetryForwarder sInstance;

    private final Context mContext;
    private final SharedPreferences mPrefs;
    private final TelemetrySpoolDb mSpoolDb;
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final AtomicBoolean mIsFlushing = new AtomicBoolean(false);
    private final String mDeviceGuid;

    public static SiemTelemetryForwarder getInstance(Context context) {
        if (sInstance == null) {
            synchronized (SiemTelemetryForwarder.class) {
                if (sInstance == null) {
                    sInstance = new SiemTelemetryForwarder(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private SiemTelemetryForwarder(Context context) {
        mContext = context;
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        mSpoolDb = TelemetrySpoolDb.getInstance(context);

        String guid = mPrefs.getString(PREF_SIEM_DEVICE_GUID, null);
        if (guid == null || guid.isEmpty()) {
            guid = UUID.randomUUID().toString();
            mPrefs.edit().putString(PREF_SIEM_DEVICE_GUID, guid).apply();
        }
        mDeviceGuid = guid;
    }

    public boolean isEnabled() {
        return mPrefs.getBoolean(PREF_SIEM_ENABLED, false);
    }

    public String getEndpointUrl() {
        return mPrefs.getString(PREF_SIEM_ENDPOINT, "").trim();
    }

    public String getAuthToken() {
        return mPrefs.getString(PREF_SIEM_AUTH_TOKEN, "").trim();
    }

    public String getFormat() {
        return mPrefs.getString(PREF_SIEM_FORMAT, FORMAT_ECS);
    }

    public boolean isAnonymizeIpEnabled() {
        return mPrefs.getBoolean(PREF_SIEM_ANONYMIZE_IP, true);
    }

    public String getDeviceGuid() {
        return mDeviceGuid;
    }

    /**
     * Spool a Unified Incident Event into local storage and trigger async forward.
     */
    public void spoolIncident(UnifiedIncidentTimeline.IncidentEvent event) {
        if (!isEnabled() || event == null) return;

        mExecutor.execute(() -> {
            try {
                String payload = formatIncident(event, getFormat());
                mSpoolDb.enqueue(event.id, event.timestampMs, event.type.name(), event.severity.name(), payload);
                triggerFlush();
            } catch (Exception e) {
                Log.w(TAG, "Failed to spool incident event: " + e.getMessage());
            }
        });
    }

    /**
     * Spool a raw security event (e.g. behavioral anomaly or memory tamper finding).
     */
    public void spoolRawEvent(String eventId, long ts, String eventType, String severity,
                              String title, String details, String packageName, String mitre) {
        if (!isEnabled()) return;

        mExecutor.execute(() -> {
            try {
                JSONObject obj = new JSONObject();
                obj.put("event_id", eventId);
                obj.put("timestamp", ts);
                obj.put("event_type", eventType);
                obj.put("severity", severity);
                obj.put("title", title);
                obj.put("details", details);
                obj.put("package", packageName != null ? packageName : "");
                obj.put("mitre", mitre != null ? mitre : "");

                String payload = formatRaw(obj, getFormat());
                mSpoolDb.enqueue(eventId, ts, eventType, severity, payload);
                triggerFlush();
            } catch (Exception e) {
                Log.w(TAG, "Failed to spool raw security event: " + e.getMessage());
            }
        });
    }

    public void triggerFlush() {
        if (!isEnabled()) return;
        String endpoint = getEndpointUrl();
        if (endpoint.isEmpty()) return;

        if (mIsFlushing.compareAndSet(false, true)) {
            mExecutor.execute(() -> {
                try {
                    flushInternal(endpoint);
                } finally {
                    mIsFlushing.set(false);
                }
            });
        }
    }

    private void flushInternal(String endpoint) {
        int maxBatches = 10;
        int batchCount = 0;

        while (batchCount < maxBatches) {
            List<TelemetrySpoolDb.SpooledEvent> batch = mSpoolDb.pollBatch(50);
            if (batch == null || batch.isEmpty()) break;

            List<Long> dbIds = new ArrayList<>(batch.size());
            for (TelemetrySpoolDb.SpooledEvent item : batch) {
                dbIds.add(item.dbId);
            }

            boolean success = transmitBatch(endpoint, batch);
            if (success) {
                mSpoolDb.markDelivered(dbIds);
                Log.d(TAG, "Successfully flushed " + dbIds.size() + " telemetry events to SIEM");
            } else {
                mSpoolDb.recordAttemptFailure(dbIds);
                Log.w(TAG, "Failed to forward telemetry batch to SIEM endpoint");
                break; // Stop loop on failure to back off
            }
            batchCount++;
        }
    }

    private boolean transmitBatch(String endpoint, List<TelemetrySpoolDb.SpooledEvent> batch) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(endpoint);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(8000);
            conn.setReadTimeout(8000);
            conn.setDoOutput(true);

            String token = getAuthToken();
            if (!token.isEmpty()) {
                if (token.startsWith("Splunk ") || token.startsWith("Bearer ")) {
                    conn.setRequestProperty("Authorization", token);
                } else {
                    conn.setRequestProperty("Authorization", "Bearer " + token);
                }
            }

            String format = getFormat();
            byte[] bodyBytes;

            if (FORMAT_CEF.equalsIgnoreCase(format)) {
                conn.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
                StringBuilder sb = new StringBuilder();
                for (TelemetrySpoolDb.SpooledEvent ev : batch) {
                    sb.append(ev.payloadJson).append("\n");
                }
                bodyBytes = sb.toString().getBytes(StandardCharsets.UTF_8);
            } else {
                // JSON or ECS Array
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                JSONArray array = new JSONArray();
                for (TelemetrySpoolDb.SpooledEvent ev : batch) {
                    try {
                        array.put(new JSONObject(ev.payloadJson));
                    } catch (Exception ignored) {
                        array.put(ev.payloadJson);
                    }
                }
                bodyBytes = array.toString().getBytes(StandardCharsets.UTF_8);
            }

            conn.setFixedLengthStreamingMode(bodyBytes.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }

            int code = conn.getResponseCode();
            return code >= 200 && code < 300;
        } catch (Exception e) {
            Log.w(TAG, "Network error transmitting SIEM telemetry: " + e.getMessage());
            return false;
        } finally {
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) {}
            }
        }
    }

    /**
     * Formats an IncidentEvent into Elastic Common Schema (ECS), Syslog JSON, or CEF.
     */
    public String formatIncident(UnifiedIncidentTimeline.IncidentEvent event, String format) {
        String target = anonymizeIfNeeded(event.target);
        String isoDate = formatIso8601(event.timestampMs);

        if (FORMAT_CEF.equalsIgnoreCase(format)) {
            // CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
            int cefSev = mapSeverityToCef(event.severity);
            return "CEF:0|KotSafe|NextGenEDR|3.0|" + event.type.name() + "|" + escapeCef(event.title) + "|"
                    + cefSev + "|msg=" + escapeCef(event.detail) + " dproc=" + escapeCef(event.sourceApp)
                    + " dst=" + escapeCef(target) + " cs1=" + escapeCef(event.mitreTechnique)
                    + " cs1Label=MitreTechnique dguid=" + mDeviceGuid;
        }

        try {
            JSONObject root = new JSONObject();
            root.put("@timestamp", isoDate);

            // ECS Structure
            JSONObject ecsEvent = new JSONObject();
            ecsEvent.put("id", event.id);
            ecsEvent.put("dataset", "kotsafe.edr");
            ecsEvent.put("category", categorizeEvent(event.type));
            ecsEvent.put("severity", mapSeverityNumber(event.severity));
            ecsEvent.put("risk_score", event.riskScore);
            ecsEvent.put("action", event.severity == UnifiedIncidentTimeline.Severity.CRITICAL ? "blocked" : "detected");
            root.put("event", ecsEvent);

            JSONObject host = new JSONObject();
            host.put("id", mDeviceGuid);
            host.put("os_name", "Android");
            host.put("os_version", Build.VERSION.RELEASE);
            root.put("host", host);

            JSONObject threat = new JSONObject();
            threat.put("technique_id", event.mitreTechnique != null ? event.mitreTechnique : "");
            threat.put("rule_name", event.title);
            threat.put("description", event.detail != null ? event.detail : "");
            root.put("threat", threat);

            JSONObject process = new JSONObject();
            process.put("name", event.sourceApp != null ? event.sourceApp : "");
            root.put("process", process);

            JSONObject destination = new JSONObject();
            destination.put("address", target != null ? target : "");
            root.put("destination", destination);

            if (DeviceLocationManager.getInstance(mContext).isAttachToSiemEnabled()) {
                JSONObject locObj = DeviceLocationManager.getInstance(mContext).getLocationTelemetryJson();
                if (locObj != null) {
                    JSONObject geo = new JSONObject();
                    JSONObject point = new JSONObject();
                    point.put("lat", locObj.optDouble("latitude"));
                    point.put("lon", locObj.optDouble("longitude"));
                    geo.put("location", point);
                    geo.put("accuracy", locObj.optDouble("accuracy_meters"));
                    root.put("geo", geo);
                }
            }

            if (FORMAT_SYSLOG_JSON.equalsIgnoreCase(format)) {
                root.put("facility", "security");
                root.put("app_name", "KotSafe");
                root.put("message", event.title + ": " + event.detail);
            }

            return root.toString();
        } catch (Exception e) {
            return event.toJson().toString();
        }
    }

    private String formatRaw(JSONObject obj, String format) {
        try {
            long ts = obj.optLong("timestamp", System.currentTimeMillis());
            String isoDate = formatIso8601(ts);

            JSONObject root = new JSONObject();
            root.put("@timestamp", isoDate);

            JSONObject ecsEvent = new JSONObject();
            ecsEvent.put("id", obj.optString("event_id"));
            ecsEvent.put("dataset", "kotsafe.edr");
            ecsEvent.put("category", obj.optString("event_type"));
            ecsEvent.put("severity", obj.optString("severity"));
            root.put("event", ecsEvent);

            JSONObject host = new JSONObject();
            host.put("id", mDeviceGuid);
            host.put("os_name", "Android");
            host.put("os_version", Build.VERSION.RELEASE);
            root.put("host", host);

            JSONObject threat = new JSONObject();
            threat.put("rule_name", obj.optString("title"));
            threat.put("description", obj.optString("details"));
            threat.put("technique_id", obj.optString("mitre"));
            root.put("threat", threat);

            JSONObject process = new JSONObject();
            process.put("name", obj.optString("package"));
            root.put("process", process);

            return root.toString();
        } catch (Exception e) {
            return obj.toString();
        }
    }

    private String anonymizeIfNeeded(String value) {
        if (value == null || value.isEmpty()) return "";
        if (!isAnonymizeIpEnabled()) return value;

        // If IPv4, zero the last octet (e.g. 192.168.1.55 -> 192.168.1.0)
        if (value.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            int lastDot = value.lastIndexOf('.');
            return value.substring(0, lastDot) + ".0";
        }
        return value;
    }

    private String formatIso8601(long epochMs) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(new Date(epochMs));
    }

    private int mapSeverityToCef(UnifiedIncidentTimeline.Severity s) {
        if (s == null) return 5;
        switch (s) {
            case CRITICAL: return 10;
            case HIGH:     return 8;
            case MEDIUM:   return 5;
            case LOW:      return 3;
            case INFO:
            default:       return 1;
        }
    }

    private int mapSeverityNumber(UnifiedIncidentTimeline.Severity s) {
        if (s == null) return 50;
        switch (s) {
            case CRITICAL: return 90;
            case HIGH:     return 70;
            case MEDIUM:   return 50;
            case LOW:      return 25;
            case INFO:
            default:       return 10;
        }
    }

    private String categorizeEvent(UnifiedIncidentTimeline.EventType type) {
        if (type == null) return "security";
        switch (type) {
            case IPS_HIT:
            case RATE_LIMIT:
            case FIREWALL_BLOCK:
            case PORT_SCAN:
            case LATERAL_MOVEMENT:
            case DNS_SINKHOLE:
            case DNS_TUNNEL:
                return "network";
            case MALWARE_DETECTED:
            case HEURISTIC_ANOMALY:
            case BEHAVIORAL_CORRELATION:
                return "malware";
            case SENSITIVE_CAPABILITY:
            case DEVICE_POSTURE_CHANGE:
                return "configuration";
            default:
                return "threat";
        }
    }

    private String escapeCef(String text) {
        if (text == null) return "";
        return text.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=");
    }
}
