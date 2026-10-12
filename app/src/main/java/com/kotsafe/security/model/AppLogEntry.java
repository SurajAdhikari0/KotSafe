/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.graphics.Color;

import androidx.annotation.NonNull;

import java.io.Serializable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Model representing a parsed line from an application, root, or MITM daemon log.
 */
public class AppLogEntry implements Serializable {

    public enum Level {
        VERBOSE,
        DEBUG,
        INFO,
        WARN,
        ERROR,
        FATAL,
        UNKNOWN
    }

    public Level level = Level.UNKNOWN;
    public String timestamp = "";
    public String tag = "";
    public String message = "";
    public String rawLine = "";
    public boolean isStackTrace = false;
    public boolean isExpanded = false;

    // Pattern 1: Standard KotSafe format -> [I] 23/Sep/2026 20:26:45 - [Tag] Message
    private static final Pattern KOTSAFE_PATTERN = Pattern.compile(
            "^\\[([A-Za-z])\\]\\s+([0-9]{1,2}/[A-Za-z]{3}/[0-9]{4}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2})\\s+-\\s+(?:\\[([^\\]]+)\\]\\s+)?(.*)$"
    );

    // Pattern 2: Logcat style -> 09-23 20:26:45.123  1234  5678 I Tag: Message
    private static final Pattern LOGCAT_PATTERN = Pattern.compile(
            "^([0-9]{2}-[0-9]{2}\\s+[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?)\\s+(?:[0-9]+\\s+[0-9]+\\s+)?([VDIWEF])\\s+([^:]+):\\s+(.*)$"
    );

    // Pattern 3: Bracketed timestamp -> [2026-09-23 20:26:45] [INFO] [Tag] Message
    private static final Pattern BRACKETED_PATTERN = Pattern.compile(
            "^\\[([^\\]]+)\\]\\s+\\[([A-Za-z]+)\\]\\s+(?:\\[([^\\]]+)\\]\\s+)?(.*)$"
    );

    public static AppLogEntry parse(@NonNull String line) {
        AppLogEntry entry = new AppLogEntry();
        entry.rawLine = line.trim();

        if (entry.rawLine.isEmpty()) {
            entry.message = "";
            return entry;
        }

        // Check if stack trace
        String trimmed = entry.rawLine;
        if (trimmed.startsWith("at ") || trimmed.startsWith("Caused by:")
                || trimmed.startsWith("java.lang.") || trimmed.startsWith("android.view.")
                || trimmed.startsWith("com.kotsafe.") || trimmed.startsWith("androidx.")
                || trimmed.startsWith("Process: ") || trimmed.startsWith("PID: ")) {
            entry.isStackTrace = true;
            entry.level = Level.ERROR;
            entry.message = trimmed;
            return entry;
        }

        // 1. Check KotSafe pattern
        Matcher m1 = KOTSAFE_PATTERN.matcher(trimmed);
        if (m1.matches()) {
            char lvlChar = Character.toUpperCase(m1.group(1).charAt(0));
            entry.level = charToLevel(lvlChar);
            entry.timestamp = m1.group(2);
            entry.tag = m1.group(3) != null ? m1.group(3).trim() : "";
            entry.message = m1.group(4) != null ? m1.group(4) : "";
            return entry;
        }

        // 2. Check Logcat pattern
        Matcher m2 = LOGCAT_PATTERN.matcher(trimmed);
        if (m2.matches()) {
            entry.timestamp = m2.group(1);
            entry.level = charToLevel(m2.group(2).charAt(0));
            entry.tag = m2.group(3) != null ? m2.group(3).trim() : "";
            entry.message = m2.group(4) != null ? m2.group(4) : "";
            return entry;
        }

        // 3. Check Bracketed pattern
        Matcher m3 = BRACKETED_PATTERN.matcher(trimmed);
        if (m3.matches()) {
            entry.timestamp = m3.group(1);
            entry.level = stringToLevel(m3.group(2));
            entry.tag = m3.group(3) != null ? m3.group(3).trim() : "";
            entry.message = m3.group(4) != null ? m3.group(4) : "";
            return entry;
        }

        // Fallback: heuristic detection
        String lower = trimmed.toLowerCase();
        if (lower.contains("error") || lower.contains("fatal") || lower.contains("exception") || lower.contains("fail")) {
            entry.level = Level.ERROR;
        } else if (lower.contains("warn")) {
            entry.level = Level.WARN;
        } else if (lower.contains("debug") || lower.contains("trace")) {
            entry.level = Level.DEBUG;
        } else if (lower.contains("info")) {
            entry.level = Level.INFO;
        } else {
            entry.level = Level.UNKNOWN;
        }

        entry.message = trimmed;
        return entry;
    }

    private static Level charToLevel(char c) {
        switch (c) {
            case 'V': return Level.VERBOSE;
            case 'D': return Level.DEBUG;
            case 'I': return Level.INFO;
            case 'W': return Level.WARN;
            case 'E': return Level.ERROR;
            case 'F':
            case 'A': return Level.FATAL;
            default:  return Level.UNKNOWN;
        }
    }

    private static Level stringToLevel(String s) {
        if (s == null) return Level.UNKNOWN;
        String upper = s.toUpperCase();
        if (upper.startsWith("ERR")) return Level.ERROR;
        if (upper.startsWith("WARN")) return Level.WARN;
        if (upper.startsWith("INF")) return Level.INFO;
        if (upper.startsWith("DEB")) return Level.DEBUG;
        if (upper.startsWith("VERB")) return Level.VERBOSE;
        if (upper.startsWith("FAT")) return Level.FATAL;
        return Level.UNKNOWN;
    }

    public int getLevelBadgeColor() {
        switch (level) {
            case FATAL:
            case ERROR:
                return Color.parseColor("#EF4444"); // Red
            case WARN:
                return Color.parseColor("#F59E0B"); // Amber
            case INFO:
                return Color.parseColor("#0EA5E9"); // Sky Blue
            case DEBUG:
                return Color.parseColor("#8B5CF6"); // Purple
            case VERBOSE:
                return Color.parseColor("#64748B"); // Slate
            default:
                return Color.parseColor("#94A3B8"); // Gray
        }
    }

    public String getLevelLabel() {
        switch (level) {
            case FATAL:   return "FATAL";
            case ERROR:   return "ERROR";
            case WARN:    return "WARN";
            case INFO:    return "INFO";
            case DEBUG:   return "DEBUG";
            case VERBOSE: return "VERBOSE";
            default:      return "LOG";
        }
    }
}
