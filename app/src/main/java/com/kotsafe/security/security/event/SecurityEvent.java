/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * SecurityEvent
 * =============
 * Immutable, normalized event schema representing telemetry across
 * all KotSafe subsystems.
 */

package com.kotsafe.security.security.event;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class SecurityEvent {
    public enum Domain {
        NETWORK,
        ANTIVIRUS,
        PHYSICAL,
        POSTURE,
        INTELLIGENCE,
        CORRELATION
    }

    public enum Severity {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    private final String mEventId;
    private final String mCorrelationId;
    private final long mTimestamp;
    private final Domain mDomain;
    private final String mEventType;
    private final Severity mSeverity;
    private final String mTitle;
    private final String mDescription;
    private final String mSubjectPackage;
    private final int mSubjectUid;
    private final Map<String, Object> mAttributes;

    public static class Builder {
        private String correlationId;
        private Domain domain = Domain.NETWORK;
        private String eventType = "";
        private Severity severity = Severity.INFO;
        private String title = "";
        private String description = "";
        private String subjectPackage = "";
        private int subjectUid = -1;
        private final Map<String, Object> attributes = new HashMap<>();

        public Builder(Domain domain, String eventType) {
            this.domain = domain;
            this.eventType = eventType;
            this.correlationId = UUID.randomUUID().toString();
        }

        public Builder correlationId(String correlationId) {
            if (correlationId != null && !correlationId.isEmpty()) {
                this.correlationId = correlationId;
            }
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder title(String title) {
            this.title = title;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder subject(String packageName, int uid) {
            this.subjectPackage = packageName != null ? packageName : "";
            this.subjectUid = uid;
            return this;
        }

        public Builder attribute(String key, Object value) {
            if (key != null && value != null) {
                this.attributes.put(key, value);
            }
            return this;
        }

        public Builder attributes(Map<String, Object> attrs) {
            if (attrs != null) {
                this.attributes.putAll(attrs);
            }
            return this;
        }

        public SecurityEvent build() {
            return new SecurityEvent(this);
        }
    }

    private SecurityEvent(Builder builder) {
        this.mEventId = UUID.randomUUID().toString();
        this.mCorrelationId = builder.correlationId;
        this.mTimestamp = System.currentTimeMillis();
        this.mDomain = builder.domain;
        this.mEventType = builder.eventType;
        this.mSeverity = builder.severity;
        this.mTitle = builder.title;
        this.mDescription = builder.description;
        this.mSubjectPackage = builder.subjectPackage;
        this.mSubjectUid = builder.subjectUid;
        this.mAttributes = Collections.unmodifiableMap(new HashMap<>(builder.attributes));
    }

    public String getEventId() { return mEventId; }
    public String getCorrelationId() { return mCorrelationId; }
    public long getTimestamp() { return mTimestamp; }
    public Domain getDomain() { return mDomain; }
    public String getEventType() { return mEventType; }
    public Severity getSeverity() { return mSeverity; }
    public String getTitle() { return mTitle; }
    public String getDescription() { return mDescription; }
    public String getSubjectPackage() { return mSubjectPackage; }
    public int getSubjectUid() { return mSubjectUid; }
    public Map<String, Object> getAttributes() { return mAttributes; }

    @SuppressWarnings("unchecked")
    public <T> T getAttribute(String key, T defaultValue) {
        Object val = mAttributes.get(key);
        if (val == null) return defaultValue;
        try {
            return (T) val;
        } catch (ClassCastException e) {
            return defaultValue;
        }
    }

    @Override
    public String toString() {
        return "SecurityEvent{" +
                "id='" + mEventId + '\'' +
                ", domain=" + mDomain +
                ", type='" + mEventType + '\'' +
                ", severity=" + mSeverity +
                ", package='" + mSubjectPackage + '\'' +
                ", title='" + mTitle + '\'' +
                '}';
    }
}
