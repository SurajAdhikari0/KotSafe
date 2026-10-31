package com.kotsafe.security.tv;

import android.os.Handler;
import android.os.Looper;

import com.kotsafe.security.BuildConfig;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Approves a one-time TV link using the mobile app's Firebase ID token. */
public final class TvLinkApi {
    private static final ExecutorService NETWORK = Executors.newSingleThreadExecutor();
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private TvLinkApi() { }

    public interface Callback {
        void onSuccess(String message);
        void onError(String message);
    }

    public static void approve(String sessionId, String deviceCode, String firebaseIdToken,
                               Callback callback) {
        NETWORK.execute(() -> {
            try {
                JSONObject body = new JSONObject()
                        .put("sessionId", sessionId)
                        .put("deviceCode", deviceCode);
                HttpResult result = request("/v1/tv-auth/approve", body, firebaseIdToken);
                if (result.code < 200 || result.code >= 300) {
                    throw new IllegalStateException(message(result.body, "Could not approve this TV"));
                }
                JSONObject json = new JSONObject(result.body);
                MAIN.post(() -> callback.onSuccess(json.optString("message", "TV approved. Return to your TV.")));
            } catch (Exception e) {
                String error = e.getMessage() == null ? "Could not approve this TV" : e.getMessage();
                MAIN.post(() -> callback.onError(error));
            }
        });
    }

    private static HttpResult request(String path, JSONObject body, String token) throws Exception {
        String base = BuildConfig.TV_AUTH_BASE_URL == null ? "" : BuildConfig.TV_AUTH_BASE_URL.trim();
        if (!base.startsWith("https://")) {
            throw new IllegalStateException("KotSafe TV linking requires a configured HTTPS relay");
        }
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        HttpURLConnection connection = (HttpURLConnection) new URL(base + path).openConnection();
        connection.setRequestMethod("POST");
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(10_000);
        connection.setDoOutput(true);
        connection.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Authorization", "Bearer " + token);
        try (OutputStream output = connection.getOutputStream()) {
            output.write(body.toString().getBytes(StandardCharsets.UTF_8));
        }
        int code = connection.getResponseCode();
        InputStream stream = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String response = read(stream);
        connection.disconnect();
        return new HttpResult(code, response);
    }

    private static String read(InputStream input) throws Exception {
        if (input == null) return "{}";
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) result.append(line);
        }
        return result.toString();
    }

    private static String message(String body, String fallback) {
        try {
            JSONObject json = new JSONObject(body);
            String responseMessage = json.optString("message", "");
            if (!responseMessage.isEmpty()) return responseMessage;
            String error = json.optString("error", "");
            if ("not_found".equalsIgnoreCase(error)) {
                return "The KotSafe relay has not enabled TV linking yet";
            }
            return error.isEmpty() ? fallback : error;
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static final class HttpResult {
        final int code;
        final String body;
        HttpResult(int code, String body) {
            this.code = code;
            this.body = body;
        }
    }
}
