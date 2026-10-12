/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.ai;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;

import com.kotsafe.security.Log;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.ScanReportEntry;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.BufferedSource;

/**
 * Universal asynchronous AI client supporting OpenAI (ChatGPT), Google Gemini,
 * Anthropic Claude, and Local / Custom LLM endpoints (Ollama, LM Studio).
 */
public class AiClientEngine {
    private static final String TAG = "AiClientEngine";
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private static volatile AiClientEngine sInstance;

    private final Context mContext;
    private final OkHttpClient mHttpClient;
    private final AiConfig mConfig;
    private final Handler mMainHandler;
    private final Gson mGson;

    public interface Callback {
        void onSuccess(String responseText);
        void onError(String errorMessage);
    }

    public interface StreamCallback {
        void onToken(String tokenChunk);
        void onComplete(String fullResponse);
        void onError(String errorMessage);
    }

    public static class AlertTriageResult {
        public int maliciousProbability; // 0 - 100
        public String verdict;            // e.g. "CONFIRMED MALICIOUS", "SUSPICIOUS", "LIKELY FALSE POSITIVE"
        public String reasoning;
        public String recommendation;
    }

    public interface AlertTriageCallback {
        void onResult(AlertTriageResult result);
        void onError(String error);
    }

    public static class AvTriageResult {
        public int threatRiskScore;       // 0 - 100
        public int falsePositiveChance;   // 0 - 100
        public String aiAssessment;
        public String recommendedAction;
    }

    public interface AvTriageCallback {
        void onResult(AvTriageResult result);
        void onError(String error);
    }

    public static AiClientEngine getInstance(Context context) {
        if (sInstance == null) {
            synchronized (AiClientEngine.class) {
                if (sInstance == null) {
                    sInstance = new AiClientEngine(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private AiClientEngine(Context context) {
        mContext = context.getApplicationContext();
        mConfig = new AiConfig(context);
        mMainHandler = new Handler(Looper.getMainLooper());
        mGson = new Gson();
        mHttpClient = new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(25, TimeUnit.SECONDS)
                .writeTimeout(15, TimeUnit.SECONDS)
                .build();
    }

    public AiConfig getConfig() {
        return mConfig;
    }

    /**
     * Test connection to configured AI provider
     */
    public void testConnection(Callback callback) {
        String testPrompt = "Respond with 'KotSafe AI Online' and your model name if you can read this.";
        sendChatCompletion("You are a network ping tester.", testPrompt, new Callback() {
            @Override
            public void onSuccess(String responseText) {
                mMainHandler.post(() -> callback.onSuccess(responseText));
            }

            @Override
            public void onError(String errorMessage) {
                mMainHandler.post(() -> callback.onError(errorMessage));
            }
        });
    }

    /**
     * Streams chat completion tokens in real-time for progressive rendering.
     */
    public void askAssistantStream(String userPrompt, String systemContext, StreamCallback callback) {
        if (AiAccessController.isAdversarialOrSensitiveQuery(userPrompt)) {
            String refusal = OfflineKnowledgeEngine.getSensitiveInfoRefusal();
            mMainHandler.post(() -> {
                callback.onToken(refusal);
                callback.onComplete(refusal);
            });
            return;
        }

        sendChatCompletionStream(systemContext, userPrompt, callback);
    }

    /**
     * General chat query for AI assistant with provided system/data context.
     * Enforces ironclad input-intent validation and output token sanitization.
     */
    public void askAssistant(String userPrompt, String systemContext, Callback callback) {
        askAssistantStream(userPrompt, systemContext, new StreamCallback() {
            @Override
            public void onToken(String tokenChunk) {
                // Ignore per-token events for monolithic callback
            }

            @Override
            public void onComplete(String fullResponse) {
                callback.onSuccess(fullResponse);
            }

            @Override
            public void onError(String errorMessage) {
                callback.onError(errorMessage);
            }
        });
    }

    /**
     * Analyzes security alerts and computes Malicious Probability % + True vs False Positive triage.
     */
    public void analyzeAlert(AlertRecord alert, AlertTriageCallback callback) {
        if (alert == null) {
            callback.onError("Alert is null");
            return;
        }

        String sys = "You are an expert SOC Incident Responder and Android Malware Analyst. Analyze the security alert and output valid JSON ONLY with format:\n"
                + "{\n"
                + "  \"maliciousProbability\": <integer 0-100>,\n"
                + "  \"verdict\": \"<CONFIRMED MALICIOUS | SUSPICIOUS | LIKELY FALSE POSITIVE>\",\n"
                + "  \"reasoning\": \"<detailed 1-2 sentence explanation of why this triggered and whether it is expected app telemetry or an attack>\",\n"
                + "  \"recommendation\": \"<actionable advice for user: Block Domain / Ignore False Positive / Quarantine App>\"\n"
                + "}";

        String userMsg = "Alert Title: " + alert.title + "\n"
                + "Alert Type: " + alert.type.label + "\n"
                + "Severity: " + alert.severity.name() + "\n"
                + "Source App: " + alert.sourceApp + "\n"
                + "Alert Message: " + alert.message;

        sendChatCompletion(sys, userMsg, new Callback() {
            @Override
            public void onSuccess(String responseText) {
                try {
                    String clean = extractJson(responseText);
                    JsonObject obj = JsonParser.parseString(clean).getAsJsonObject();
                    AlertTriageResult res = new AlertTriageResult();
                    res.maliciousProbability = obj.has("maliciousProbability") ? obj.get("maliciousProbability").getAsInt() : 50;
                    res.verdict = obj.has("verdict") ? obj.get("verdict").getAsString() : "SUSPICIOUS";
                    res.reasoning = obj.has("reasoning") ? obj.get("reasoning").getAsString() : responseText;
                    res.recommendation = obj.has("recommendation") ? obj.get("recommendation").getAsString() : "Review network activity.";

                    mMainHandler.post(() -> callback.onResult(res));
                } catch (Exception e) {
                    AlertTriageResult res = new AlertTriageResult();
                    res.maliciousProbability = 50;
                    res.verdict = "SUSPICIOUS";
                    res.reasoning = responseText;
                    res.recommendation = "Manually review alert details.";
                    mMainHandler.post(() -> callback.onResult(res));
                }
            }

            @Override
            public void onError(String errorMessage) {
                AlertTriageResult local = computeLocalAlertTriage(alert);
                local.reasoning += "\n\n*(Evaluated by KotSafe Offline Heuristics Engine: " + errorMessage + ")*";
                mMainHandler.post(() -> callback.onResult(local));
            }
        });
    }

    /**
     * Evaluates Antivirus Scan Report as a final outer layer of defense.
     */
    public void analyzeAntivirusReport(ScanReportEntry report, AvTriageCallback callback) {
        if (report == null) {
            callback.onError("Report is null");
            return;
        }

        String sys = "You are an Antivirus Risk & Threat Intelligence Validator. Evaluate the mobile antivirus audit results and output valid JSON ONLY with format:\n"
                + "{\n"
                + "  \"threatRiskScore\": <integer 0-100 where 0 is clean and 100 is critical malware>,\n"
                + "  \"falsePositiveChance\": <integer 0-100 indicating likelihood this flag is a benign false alarm>,\n"
                + "  \"aiAssessment\": \"<2 sentence summary explaining the posture, threats, and indicators>\",\n"
                + "  \"recommendedAction\": \"<Clean / Isolate Threats / Whitelist Verified Developer>\"\n"
                + "}";

        String userMsg = "Scan Mode: " + report.scanMode + "\n"
                + "Security Score: " + report.securityScore + "/100\n"
                + "Threats Flagged: " + report.threatsDetected + "\n"
                + "Suspicious Items: " + report.suspiciousDetected + "\n"
                + "Packages Scanned: " + report.packagesScanned + "\n"
                + "Split APKs: " + report.splitsScanned + "\n"
                + "Files Audited: " + report.storageScanned + "\n"
                + "Endpoints Checked: " + (report.ipsScanned + report.urlsScanned) + "\n"
                + "Scan Summary: " + report.summary;

        sendChatCompletion(sys, userMsg, new Callback() {
            @Override
            public void onSuccess(String responseText) {
                try {
                    String clean = extractJson(responseText);
                    JsonObject obj = JsonParser.parseString(clean).getAsJsonObject();
                    AvTriageResult res = new AvTriageResult();
                    res.threatRiskScore = obj.has("threatRiskScore") ? obj.get("threatRiskScore").getAsInt() : 20;
                    res.falsePositiveChance = obj.has("falsePositiveChance") ? obj.get("falsePositiveChance").getAsInt() : 10;
                    res.aiAssessment = obj.has("aiAssessment") ? obj.get("aiAssessment").getAsString() : responseText;
                    res.recommendedAction = obj.has("recommendedAction") ? obj.get("recommendedAction").getAsString() : "Maintain regular daily scans.";

                    mMainHandler.post(() -> callback.onResult(res));
                } catch (Exception e) {
                    AvTriageResult res = new AvTriageResult();
                    res.threatRiskScore = 30;
                    res.falsePositiveChance = 20;
                    res.aiAssessment = responseText;
                    res.recommendedAction = "Review scanned applications.";
                    mMainHandler.post(() -> callback.onResult(res));
                }
            }

            @Override
            public void onError(String errorMessage) {
                AvTriageResult local = computeLocalAvTriage(report);
                local.aiAssessment += "\n\n*(Evaluated by KotSafe Offline Heuristics Engine: " + errorMessage + ")*";
                mMainHandler.post(() -> callback.onResult(local));
            }
        });
    }

    public static AlertTriageResult computeLocalAlertTriage(AlertRecord alert) {
        AlertTriageResult res = new AlertTriageResult();
        if (alert == null) {
            res.maliciousProbability = 10;
            res.verdict = "LIKELY FALSE POSITIVE";
            res.reasoning = "No alert record provided.";
            res.recommendation = "No action required.";
            return res;
        }

        boolean isHigh = alert.severity == AlertRecord.Severity.HIGH;
        String typeStr = alert.type != null ? alert.type.name().toUpperCase(Locale.ROOT) : "";
        if (typeStr.contains("C2") || typeStr.contains("MALWARE") || typeStr.contains("TROJAN") || typeStr.contains("EXFILTRATION")) {
            res.maliciousProbability = 88;
            res.verdict = "CONFIRMED MALICIOUS";
            res.reasoning = "Signature matched known Command & Control beaconing or unauthorized exfiltration vector.";
            res.recommendation = "Block destination in Firewall immediately and review " + alert.sourceApp + " permissions.";
        } else if (isHigh || typeStr.contains("INJECTION") || typeStr.contains("PORT_SCAN")) {
            res.maliciousProbability = 65;
            res.verdict = "SUSPICIOUS";
            res.reasoning = "Elevated network anomaly detected from " + alert.sourceApp + ". Matches defense evasion or scanning tactic.";
            res.recommendation = "Monitor active socket connections in KotSafe and create custom app rule.";
        } else {
            res.maliciousProbability = 20;
            res.verdict = "LIKELY FALSE POSITIVE";
            res.reasoning = "Routine operational telemetry (multicast, background DNS check, or standard OS sync).";
            res.recommendation = "Safe to ignore. Whitelist if alert notification is repetitive.";
        }
        return res;
    }

    public static AvTriageResult computeLocalAvTriage(ScanReportEntry report) {
        AvTriageResult res = new AvTriageResult();
        if (report == null) {
            res.threatRiskScore = 0;
            res.falsePositiveChance = 0;
            res.aiAssessment = "No scan data available.";
            res.recommendedAction = "Run a scan first.";
            return res;
        }

        if (report.threatsDetected > 0) {
            res.threatRiskScore = Math.min(100, 60 + (report.threatsDetected * 15));
            res.falsePositiveChance = 10;
            res.aiAssessment = "Flagged " + report.threatsDetected + " confirmed threat(s) across audited packages and storage. Security score dropped to " + report.securityScore + "/100.";
            res.recommendedAction = "Isolate flagged threats into Quarantine Vault immediately.";
        } else if (report.suspiciousDetected > 0) {
            res.threatRiskScore = 35;
            res.falsePositiveChance = 45;
            res.aiAssessment = "Audited " + report.packagesScanned + " apps with " + report.suspiciousDetected + " suspicious item(s) (e.g. self-signed certificates or elevated permissions).";
            res.recommendedAction = "Inspect flagged applications before whitelisting.";
        } else {
            res.threatRiskScore = 5;
            res.falsePositiveChance = 2;
            res.aiAssessment = "Clean audit. All " + report.packagesScanned + " installed apps, " + report.splitsScanned + " split APKs, and storage items passed verification.";
            res.recommendedAction = "System clean. Maintain regular scheduled scans.";
        }
        return res;
    }

    private void sendChatCompletion(String systemPrompt, String userMessage, Callback callback) {
        AiConfig.Provider provider = mConfig.getProvider();
        String apiKey = mConfig.getApiKey();

        if (!provider.isOnDevice() && provider != AiConfig.Provider.LOCAL_CUSTOM && apiKey.isEmpty()) {
            callback.onError("API Key is missing. Please configure your API key in Settings -> AI Protection.");
            return;
        }

        switch (provider) {
            case LOCAL_QWEN_0_5B:
            case LOCAL_SMOLLM_135M:
            case LOCAL_GEMMA_2B:
                LocalGemmaEngine.getInstance(mContext).generateResponse(systemPrompt, userMessage, new LocalGemmaEngine.GemmaCallback() {
                    @Override
                    public void onSuccess(String responseText) {
                        callback.onSuccess(responseText);
                    }

                    @Override
                    public void onError(String errorMessage) {
                        callback.onError(errorMessage);
                    }
                });
                break;
            case GEMINI:
                executeGemini(apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
            case CLAUDE:
                executeClaude(apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
            case LOCAL_CUSTOM:
                executeOpenAiCompatible(mConfig.getEndpoint(), apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
            case OPENAI:
            default:
                executeOpenAiCompatible("https://api.openai.com/v1/chat/completions", apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
        }
    }

    private void sendChatCompletionStream(String systemPrompt, String userMessage, StreamCallback callback) {
        AiConfig.Provider provider = mConfig.getProvider();
        String apiKey = mConfig.getApiKey();

        if (!provider.isOnDevice() && provider != AiConfig.Provider.LOCAL_CUSTOM && apiKey.isEmpty()) {
            callback.onError("API Key is missing. Please configure your API key in Settings -> AI Protection.");
            return;
        }

        switch (provider) {
            case LOCAL_QWEN_0_5B:
            case LOCAL_SMOLLM_135M:
            case LOCAL_GEMMA_2B:
                LocalGemmaEngine.getInstance(mContext).generateResponse(systemPrompt, userMessage, new LocalGemmaEngine.GemmaCallback() {
                    @Override
                    public void onSuccess(String responseText) {
                        simulateTokenStream(responseText, callback);
                    }

                    @Override
                    public void onError(String errorMessage) {
                        callback.onError(errorMessage);
                    }
                });
                break;
            case GEMINI:
                executeGeminiStream(apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
            case CLAUDE:
                executeClaude(apiKey, mConfig.getModel(), systemPrompt, userMessage, new Callback() {
                    @Override
                    public void onSuccess(String responseText) {
                        simulateTokenStream(responseText, callback);
                    }

                    @Override
                    public void onError(String errorMessage) {
                        callback.onError(errorMessage);
                    }
                });
                break;
            case LOCAL_CUSTOM:
                executeOpenAiCompatibleStream(mConfig.getEndpoint(), apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
            case OPENAI:
            default:
                executeOpenAiCompatibleStream("https://api.openai.com/v1/chat/completions", apiKey, mConfig.getModel(), systemPrompt, userMessage, callback);
                break;
        }
    }

    public void simulateTokenStream(String fullResponse, StreamCallback callback) {
        if (fullResponse == null || fullResponse.isEmpty()) {
            mMainHandler.post(() -> {
                callback.onToken("");
                callback.onComplete("");
            });
            return;
        }

        String[] words = fullResponse.split("(?<=\\s)|(?=[\\n.,!?])");
        long delay = 18;
        for (int i = 0; i < words.length; i++) {
            final String word = words[i];
            final boolean isLast = (i == words.length - 1);
            mMainHandler.postDelayed(() -> {
                callback.onToken(word);
                if (isLast) {
                    callback.onComplete(fullResponse);
                }
            }, i * delay);
        }
    }

    private void executeOpenAiCompatibleStream(String endpoint, String apiKey, String model, String systemPrompt, String userMessage, StreamCallback callback) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", model);
        payload.addProperty("temperature", 0.3);
        payload.addProperty("max_tokens", 800);
        payload.addProperty("stream", true);

        JsonArray messages = new JsonArray();
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysObj = new JsonObject();
            sysObj.addProperty("role", "system");
            sysObj.addProperty("content", systemPrompt);
            messages.add(sysObj);
        }

        JsonObject userObj = new JsonObject();
        userObj.addProperty("role", "user");
        userObj.addProperty("content", userMessage);
        messages.add(userObj);

        payload.add("messages", messages);

        Request.Builder reqBuilder = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(payload.toString(), JSON));

        if (apiKey != null && !apiKey.isEmpty()) {
            reqBuilder.addHeader("Authorization", "Bearer " + apiKey);
        }

        mHttpClient.newCall(reqBuilder.build()).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                callback.onError("Connection failed: " + e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        String body = responseBody != null ? responseBody.string() : "";
                        callback.onError("API Error (" + response.code() + "): " + body);
                        return;
                    }
                    BufferedSource source = responseBody.source();
                    StringBuilder fullText = new StringBuilder();
                    while (!source.exhausted()) {
                        String line = source.readUtf8Line();
                        if (line == null) break;
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith(":")) continue;
                        if (line.startsWith("data:")) {
                            String data = line.substring(5).trim();
                            if ("[DONE]".equals(data)) break;
                            try {
                                JsonObject chunkObj = JsonParser.parseString(data).getAsJsonObject();
                                if (chunkObj.has("choices")) {
                                    JsonArray choices = chunkObj.getAsJsonArray("choices");
                                    if (choices.size() > 0) {
                                        JsonObject first = choices.get(0).getAsJsonObject();
                                        if (first.has("delta")) {
                                            JsonObject delta = first.getAsJsonObject("delta");
                                            if (delta.has("content")) {
                                                String chunk = delta.get("content").getAsString();
                                                fullText.append(chunk);
                                                mMainHandler.post(() -> callback.onToken(chunk));
                                            }
                                        }
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                    String sanitized = AiAccessController.sanitize(fullText.toString());
                    mMainHandler.post(() -> callback.onComplete(sanitized));
                } catch (Exception e) {
                    callback.onError("Streaming failed: " + e.getMessage());
                }
            }
        });
    }

    private void executeGeminiStream(String apiKey, String model, String systemPrompt, String userMessage, StreamCallback callback) {
        String url = "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":streamGenerateContent?alt=sse&key=" + apiKey;

        JsonObject payload = new JsonObject();
        JsonArray contents = new JsonArray();

        JsonObject userPart = new JsonObject();
        userPart.addProperty("role", "user");
        JsonArray parts = new JsonArray();

        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject spPart = new JsonObject();
            spPart.addProperty("text", "[System Context]:\n" + systemPrompt + "\n\n[User Request]:\n" + userMessage);
            parts.add(spPart);
        } else {
            JsonObject upPart = new JsonObject();
            upPart.addProperty("text", userMessage);
            parts.add(upPart);
        }

        userPart.add("parts", parts);
        contents.add(userPart);
        payload.add("contents", contents);

        JsonObject genConfig = new JsonObject();
        genConfig.addProperty("maxOutputTokens", 800);
        genConfig.addProperty("temperature", 0.3);
        payload.add("generationConfig", genConfig);

        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(payload.toString(), JSON))
                .build();

        mHttpClient.newCall(request).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                callback.onError("Gemini connection error: " + e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful() || responseBody == null) {
                        String body = responseBody != null ? responseBody.string() : "";
                        callback.onError("Gemini Error (" + response.code() + "): " + body);
                        return;
                    }
                    BufferedSource source = responseBody.source();
                    StringBuilder fullText = new StringBuilder();
                    while (!source.exhausted()) {
                        String line = source.readUtf8Line();
                        if (line == null) break;
                        line = line.trim();
                        if (line.isEmpty() || line.startsWith(":")) continue;
                        if (line.startsWith("data:")) {
                            String data = line.substring(5).trim();
                            try {
                                JsonObject root = JsonParser.parseString(data).getAsJsonObject();
                                if (root.has("candidates")) {
                                    JsonArray candidates = root.getAsJsonArray("candidates");
                                    if (candidates.size() > 0) {
                                        JsonObject cand = candidates.get(0).getAsJsonObject();
                                        if (cand.has("content")) {
                                            JsonObject content = cand.getAsJsonObject("content");
                                            JsonArray partList = content.getAsJsonArray("parts");
                                            if (partList.size() > 0) {
                                                String text = partList.get(0).getAsJsonObject().get("text").getAsString();
                                                fullText.append(text);
                                                mMainHandler.post(() -> callback.onToken(text));
                                            }
                                        }
                                    }
                                }
                            } catch (Exception ignored) {}
                        }
                    }
                    String sanitized = AiAccessController.sanitize(fullText.toString());
                    mMainHandler.post(() -> callback.onComplete(sanitized));
                } catch (Exception e) {
                    callback.onError("Gemini streaming failed: " + e.getMessage());
                }
            }
        });
    }

    // --- OpenAI & Local / Ollama Compatible ---
    private void executeOpenAiCompatible(String endpoint, String apiKey, String model, String systemPrompt, String userMessage, Callback callback) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", model);
        payload.addProperty("temperature", 0.3);
        payload.addProperty("max_tokens", 500);

        JsonArray messages = new JsonArray();
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject sysObj = new JsonObject();
            sysObj.addProperty("role", "system");
            sysObj.addProperty("content", systemPrompt);
            messages.add(sysObj);
        }

        JsonObject userObj = new JsonObject();
        userObj.addProperty("role", "user");
        userObj.addProperty("content", userMessage);
        messages.add(userObj);

        payload.add("messages", messages);

        Request.Builder reqBuilder = new Request.Builder()
                .url(endpoint)
                .post(RequestBody.create(payload.toString(), JSON));

        if (apiKey != null && !apiKey.isEmpty()) {
            reqBuilder.addHeader("Authorization", "Bearer " + apiKey);
        }

        mHttpClient.newCall(reqBuilder.build()).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                callback.onError("Connection failed: " + e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                try (response) {
                    String body = response.body() != null ? response.body().string() : "";
                    if (!response.isSuccessful()) {
                        callback.onError("API Error (" + response.code() + "): " + body);
                        return;
                    }
                    JsonObject root = JsonParser.parseString(body).getAsJsonObject();
                    String tokenStats = "";
                    if (root.has("usage")) {
                        try {
                            JsonObject usage = root.getAsJsonObject("usage");
                            int promptTokens = usage.has("prompt_tokens") ? usage.get("prompt_tokens").getAsInt() : 0;
                            int completionTokens = usage.has("completion_tokens") ? usage.get("completion_tokens").getAsInt() : 0;
                            int totalTokens = usage.has("total_tokens") ? usage.get("total_tokens").getAsInt() : (promptTokens + completionTokens);
                            tokenStats = "\n\n---\n*📊 Token Usage: " + totalTokens + " tokens (Input: " + promptTokens + ", Output: " + completionTokens + ")*";
                        } catch (Exception ignored) {}
                    }
                    if (root.has("choices")) {
                        JsonArray choices = root.getAsJsonArray("choices");
                        if (choices.size() > 0) {
                            JsonObject first = choices.get(0).getAsJsonObject();
                            if (first.has("message")) {
                                String content = first.getAsJsonObject("message").get("content").getAsString();
                                callback.onSuccess(content.trim() + tokenStats);
                                return;
                            }
                        }
                    }
                    callback.onSuccess(body + tokenStats);
                } catch (Exception e) {
                    callback.onError("Failed to parse response: " + e.getMessage());
                }
            }
        });
    }

    // --- Google Gemini ---
    private void executeGemini(String apiKey, String model, String systemPrompt, String userMessage, Callback callback) {
        String url = "https://generativelanguage.googleapis.com/v1beta/models/" + model + ":generateContent?key=" + apiKey;

        JsonObject payload = new JsonObject();
        JsonArray contents = new JsonArray();

        JsonObject userPart = new JsonObject();
        userPart.addProperty("role", "user");
        JsonArray parts = new JsonArray();

        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JsonObject spPart = new JsonObject();
            spPart.addProperty("text", "[System Context]:\n" + systemPrompt + "\n\n[User Request]:\n" + userMessage);
            parts.add(spPart);
        } else {
            JsonObject upPart = new JsonObject();
            upPart.addProperty("text", userMessage);
            parts.add(upPart);
        }

        userPart.add("parts", parts);
        contents.add(userPart);
        payload.add("contents", contents);

        JsonObject genConfig = new JsonObject();
        genConfig.addProperty("maxOutputTokens", 500);
        genConfig.addProperty("temperature", 0.3);
        payload.add("generationConfig", genConfig);

        Request request = new Request.Builder()
                .url(url)
                .post(RequestBody.create(payload.toString(), JSON))
                .build();

        mHttpClient.newCall(request).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                callback.onError("Gemini connection error: " + e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                try (response) {
                    String body = response.body() != null ? response.body().string() : "";
                    if (!response.isSuccessful()) {
                        callback.onError("Gemini Error (" + response.code() + "): " + body);
                        return;
                    }
                    JsonObject root = JsonParser.parseString(body).getAsJsonObject();
                    String tokenStats = "";
                    if (root.has("usageMetadata")) {
                        try {
                            JsonObject usage = root.getAsJsonObject("usageMetadata");
                            int promptTokens = usage.has("promptTokenCount") ? usage.get("promptTokenCount").getAsInt() : 0;
                            int completionTokens = usage.has("candidatesTokenCount") ? usage.get("candidatesTokenCount").getAsInt() : 0;
                            int totalTokens = usage.has("totalTokenCount") ? usage.get("totalTokenCount").getAsInt() : (promptTokens + completionTokens);
                            tokenStats = "\n\n---\n*📊 Token Usage: " + totalTokens + " tokens (Input: " + promptTokens + ", Output: " + completionTokens + ")*";
                        } catch (Exception ignored) {}
                    }
                    if (root.has("candidates")) {
                        JsonArray candidates = root.getAsJsonArray("candidates");
                        if (candidates.size() > 0) {
                            JsonObject cand = candidates.get(0).getAsJsonObject();
                            JsonObject content = cand.getAsJsonObject("content");
                            JsonArray partList = content.getAsJsonArray("parts");
                            if (partList.size() > 0) {
                                String text = partList.get(0).getAsJsonObject().get("text").getAsString();
                                callback.onSuccess(text.trim() + tokenStats);
                                return;
                            }
                        }
                    }
                    callback.onSuccess(body + tokenStats);
                } catch (Exception e) {
                    callback.onError("Failed to parse Gemini response: " + e.getMessage());
                }
            }
        });
    }

    // --- Anthropic Claude ---
    private void executeClaude(String apiKey, String model, String systemPrompt, String userMessage, Callback callback) {
        String url = "https://api.anthropic.com/v1/messages";

        JsonObject payload = new JsonObject();
        payload.addProperty("model", model);
        payload.addProperty("max_tokens", 500);
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            payload.addProperty("system", systemPrompt);
        }

        JsonArray messages = new JsonArray();
        JsonObject userMsg = new JsonObject();
        userMsg.addProperty("role", "user");
        userMsg.addProperty("content", userMessage);
        messages.add(userMsg);
        payload.add("messages", messages);

        Request request = new Request.Builder()
                .url(url)
                .addHeader("x-api-key", apiKey)
                .addHeader("anthropic-version", "2023-06-01")
                .post(RequestBody.create(payload.toString(), JSON))
                .build();

        mHttpClient.newCall(request).enqueue(new okhttp3.Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                callback.onError("Claude connection error: " + e.getMessage());
            }

            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {
                try (response) {
                    String body = response.body() != null ? response.body().string() : "";
                    if (!response.isSuccessful()) {
                        callback.onError("Claude Error (" + response.code() + "): " + body);
                        return;
                    }
                    JsonObject root = JsonParser.parseString(body).getAsJsonObject();
                    String tokenStats = "";
                    if (root.has("usage")) {
                        try {
                            JsonObject usage = root.getAsJsonObject("usage");
                            int inputTokens = usage.has("input_tokens") ? usage.get("input_tokens").getAsInt() : 0;
                            int outputTokens = usage.has("output_tokens") ? usage.get("output_tokens").getAsInt() : 0;
                            int totalTokens = inputTokens + outputTokens;
                            tokenStats = "\n\n---\n*📊 Token Usage: " + totalTokens + " tokens (Input: " + inputTokens + ", Output: " + outputTokens + ")*";
                        } catch (Exception ignored) {}
                    }
                    if (root.has("content")) {
                        JsonArray contentArr = root.getAsJsonArray("content");
                        if (contentArr.size() > 0) {
                            String text = contentArr.get(0).getAsJsonObject().get("text").getAsString();
                            callback.onSuccess(text.trim() + tokenStats);
                            return;
                        }
                    }
                    callback.onSuccess(body + tokenStats);
                } catch (Exception e) {
                    callback.onError("Failed to parse Claude response: " + e.getMessage());
                }
            }
        });
    }

    private static String extractJson(String text) {
        if (text == null) return "{}";
        int start = text.indexOf('{');
        int end = text.lastIndexOf('}');
        if (start >= 0 && end > start) {
            return text.substring(start, end + 1);
        }
        return text;
    }
}
