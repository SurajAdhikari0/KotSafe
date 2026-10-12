/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ai;

import android.content.Context;
import android.content.SharedPreferences;
import androidx.preference.PreferenceManager;

/**
 * Manages configuration, credentials, and granular privacy access levels
 * for AI-powered protection and intelligence.
 */
public class AiConfig {
    public static final String PREF_AI_ENABLED = "pref_ai_protection_enabled";
    public static final String PREF_AI_PROVIDER = "pref_ai_provider";
    public static final String PREF_AI_API_KEY = "pref_ai_api_key";
    public static final String PREF_AI_MODEL = "pref_ai_model";
    public static final String PREF_AI_ENDPOINT = "pref_ai_custom_endpoint";

    // Granular Data Access Permissions (All default to false)
    public static final String PREF_ACCESS_STATUS = "pref_ai_access_status";
    public static final String PREF_ACCESS_CONNECTIONS = "pref_ai_access_connections";
    public static final String PREF_ACCESS_HTTP = "pref_ai_access_http";
    public static final String PREF_ACCESS_REPEATER = "pref_ai_access_repeater";
    public static final String PREF_ACCESS_FIREWALL = "pref_ai_access_firewall";
    public static final String PREF_ACCESS_ANTIVIRUS = "pref_ai_access_antivirus";
    public static final String PREF_ACCESS_LOGS = "pref_ai_access_logs";
    public static final String PREF_AUTOPILOT_RESOLVE = "pref_ai_autopilot_resolve";

    public enum Provider {
        LOCAL_QWEN_0_5B("Qwen 2.5 0.5B (On-Device AI - Recommended, ~350 MB)", "", "qwen2.5-0.5b-instruct-q4_k_m.gguf"),
        LOCAL_SMOLLM_135M("SmolLM-135M (On-Device Micro AI - Ultra-Light, ~90 MB)", "", "smollm2-135m-instruct-q4_k_m.gguf"),
        LOCAL_GEMMA_2B("Google Gemma 2B (On-Device Local AI - Heavy, ~1.35 GB)", "", "gemma-2b-it-gpu-int4.bin"),
        OPENAI("ChatGPT (OpenAI)", "https://api.openai.com/v1/chat/completions", "gpt-4o-mini"),
        GEMINI("Google Gemini", "https://generativelanguage.googleapis.com/v1beta/models", "gemini-1.5-flash"),
        CLAUDE("Anthropic Claude", "https://api.anthropic.com/v1/messages", "claude-3-5-sonnet-20241022"),
        LOCAL_CUSTOM("Local AI / Custom", "http://127.0.0.1:11434/v1/chat/completions", "llama3.2");

        public final String displayName;
        public final String defaultEndpoint;
        public final String defaultModel;

        Provider(String displayName, String defaultEndpoint, String defaultModel) {
            this.displayName = displayName;
            this.defaultEndpoint = defaultEndpoint;
            this.defaultModel = defaultModel;
        }

        public boolean isOnDevice() {
            return this == LOCAL_QWEN_0_5B || this == LOCAL_SMOLLM_135M || this == LOCAL_GEMMA_2B;
        }

        public static Provider fromString(String val) {
            if (val == null) return LOCAL_QWEN_0_5B;
            try {
                return Provider.valueOf(val.toUpperCase());
            } catch (Exception e) {
                return LOCAL_QWEN_0_5B;
            }
        }
    }

    private final SharedPreferences mPrefs;

    public AiConfig(Context context) {
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context.getApplicationContext());
    }

    public boolean isAiEnabled() {
        return mPrefs.getBoolean(PREF_AI_ENABLED, false);
    }

    public void setAiEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_AI_ENABLED, enabled).apply();
    }

    public Provider getProvider() {
        String p = mPrefs.getString(PREF_AI_PROVIDER, Provider.OPENAI.name());
        return Provider.fromString(p);
    }

    public void setProvider(Provider provider) {
        mPrefs.edit().putString(PREF_AI_PROVIDER, provider.name()).apply();
    }

    public String getApiKey() {
        return mPrefs.getString(PREF_AI_API_KEY, "").trim();
    }

    public void setApiKey(String key) {
        mPrefs.edit().putString(PREF_AI_API_KEY, key != null ? key.trim() : "").apply();
    }

    public String getModel() {
        String model = mPrefs.getString(PREF_AI_MODEL, "").trim();
        if (model.isEmpty()) {
            return getProvider().defaultModel;
        }
        return model;
    }

    public void setModel(String model) {
        mPrefs.edit().putString(PREF_AI_MODEL, model != null ? model.trim() : "").apply();
    }

    public String getEndpoint() {
        String ep = mPrefs.getString(PREF_AI_ENDPOINT, "").trim();
        if (ep.isEmpty()) {
            return getProvider().defaultEndpoint;
        }
        return ep;
    }

    public void setEndpoint(String endpoint) {
        mPrefs.edit().putString(PREF_AI_ENDPOINT, endpoint != null ? endpoint.trim() : "").apply();
    }

    // Granular Access Controls
    public boolean canAccessStatus() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_STATUS, false);
    }

    public boolean canAccessConnections() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_CONNECTIONS, false);
    }

    public boolean canAccessHttp() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_HTTP, false);
    }

    public boolean canAccessRepeater() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_REPEATER, false);
    }

    public boolean canAccessFirewall() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_FIREWALL, false);
    }

    public boolean canAccessAntivirus() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_ANTIVIRUS, false);
    }

    public boolean canAccessLogs() {
        return isAiEnabled() && mPrefs.getBoolean(PREF_ACCESS_LOGS, false);
    }

    public boolean isAutopilotEnabled() {
        return mPrefs.getBoolean(PREF_AUTOPILOT_RESOLVE, true);
    }

    public void setAutopilotEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(PREF_AUTOPILOT_RESOLVE, enabled).apply();
    }

    public static java.io.File getQwenModelFile(Context context) {
        java.io.File dir = new java.io.File(context.getExternalFilesDir(null), "ai_models");
        if (!dir.exists()) dir.mkdirs();
        return new java.io.File(dir, "qwen2.5-0.5b-instruct-q4_k_m.gguf");
    }

    public static boolean isQwenDownloaded(Context context) {
        java.io.File file = getQwenModelFile(context);
        // Valid quantized 4-bit Qwen 2.5 0.5B model weight is ~350 MB; verify >= 150 MB
        return file.exists() && file.length() >= 150_000_000L;
    }

    public static java.io.File getSmolLmModelFile(Context context) {
        java.io.File dir = new java.io.File(context.getExternalFilesDir(null), "ai_models");
        if (!dir.exists()) dir.mkdirs();
        return new java.io.File(dir, "smollm2-135m-instruct-q4_k_m.gguf");
    }

    public static boolean isSmolLmDownloaded(Context context) {
        java.io.File file = getSmolLmModelFile(context);
        // Valid quantized 4-bit SmolLM-135M model weight is ~90 MB; verify >= 40 MB
        return file.exists() && file.length() >= 40_000_000L;
    }

    public static java.io.File getGemmaModelFile(Context context) {
        java.io.File dir = new java.io.File(context.getExternalFilesDir(null), "ai_models");
        if (!dir.exists()) dir.mkdirs();
        return new java.io.File(dir, "gemma-2b-it-gpu-int4.bin");
    }

    public static boolean isGemmaDownloaded(Context context) {
        java.io.File file = getGemmaModelFile(context);
        // Valid quantized 4-bit Gemma 2B model weight is >= 1.0 GB
        return file.exists() && file.length() >= 500_000_000L;
    }

    public static java.io.File getModelFileForProvider(Context context, Provider provider) {
        if (provider == Provider.LOCAL_SMOLLM_135M) {
            return getSmolLmModelFile(context);
        } else if (provider == Provider.LOCAL_GEMMA_2B) {
            return getGemmaModelFile(context);
        } else {
            return getQwenModelFile(context);
        }
    }

    public static boolean isModelDownloadedForProvider(Context context, Provider provider) {
        if (provider == Provider.LOCAL_SMOLLM_135M) {
            return isSmolLmDownloaded(context);
        } else if (provider == Provider.LOCAL_GEMMA_2B) {
            return isGemmaDownloaded(context);
        } else if (provider == Provider.LOCAL_QWEN_0_5B) {
            return isQwenDownloaded(context);
        }
        return false;
    }

    public void setFullPowerMode(boolean enabled) {
        mPrefs.edit()
                .putBoolean(PREF_ACCESS_STATUS, enabled)
                .putBoolean(PREF_ACCESS_CONNECTIONS, enabled)
                .putBoolean(PREF_ACCESS_HTTP, enabled)
                .putBoolean(PREF_ACCESS_REPEATER, enabled)
                .putBoolean(PREF_ACCESS_FIREWALL, enabled)
                .putBoolean(PREF_ACCESS_ANTIVIRUS, enabled)
                .putBoolean(PREF_ACCESS_LOGS, enabled)
                .apply();
    }

    public boolean isFullPowerMode() {
        return canAccessStatus() && canAccessConnections() && canAccessHttp() &&
                canAccessRepeater() && canAccessFirewall() && canAccessAntivirus() && canAccessLogs();
    }
}
