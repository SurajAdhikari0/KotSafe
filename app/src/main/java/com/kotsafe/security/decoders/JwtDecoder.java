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

package com.kotsafe.security.decoders;

import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Advanced JWT (JSON Web Token) decoder, claims inspector, and signature analyzer.
 */
public class JwtDecoder {
    private static final String TAG = "JwtDecoder";
    private static final Gson GSON_PRETTY = new GsonBuilder().setPrettyPrinting().create();

    // Regex pattern matching compact 3-part JWTs (header.payload.signature)
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*"
    );

    public enum TokenStatus {
        VALID,
        EXPIRED,
        NOT_YET_VALID,
        INSECURE_NONE,
        MALFORMED
    }

    public static class JwtClaim {
        public final String key;
        public final String value;
        public final String interpretation;

        public JwtClaim(String key, String value, String interpretation) {
            this.key = key;
            this.value = value;
            this.interpretation = interpretation;
        }
    }

    public static class JwtTokenInfo {
        public final String rawToken;
        public final String rawHeader;
        public final String rawPayload;
        public final String rawSignature;

        public final String prettyHeader;
        public final String prettyPayload;

        public final String algorithm;
        public final String keyId;
        public final String tokenType;

        public final String issuer;
        public final String subject;
        public final String audience;
        public final Long expirationTimeSeconds;
        public final Long notBeforeSeconds;
        public final Long issuedAtSeconds;
        public final String jwtId;

        public final TokenStatus status;
        public final String statusDetail;
        public final List<JwtClaim> claims = new ArrayList<>();

        public JwtTokenInfo(String rawToken, String rawHeader, String rawPayload, String rawSignature,
                            String prettyHeader, String prettyPayload, String algorithm, String keyId,
                            String tokenType, String issuer, String subject, String audience,
                            Long exp, Long nbf, Long iat, String jti,
                            TokenStatus status, String statusDetail) {
            this.rawToken = rawToken;
            this.rawHeader = rawHeader;
            this.rawPayload = rawPayload;
            this.rawSignature = rawSignature;
            this.prettyHeader = prettyHeader;
            this.prettyPayload = prettyPayload;
            this.algorithm = algorithm;
            this.keyId = keyId;
            this.tokenType = tokenType;
            this.issuer = issuer;
            this.subject = subject;
            this.audience = audience;
            this.expirationTimeSeconds = exp;
            this.notBeforeSeconds = nbf;
            this.issuedAtSeconds = iat;
            this.jwtId = jti;
            this.status = status;
            this.statusDetail = statusDetail;
        }
    }

    /**
     * Extracts and parses the first JWT found within a given raw string or header.
     */
    @Nullable
    public static JwtTokenInfo findAndParseJwt(@Nullable String text) {
        if (text == null || text.length() < 30) return null;

        // Clean up common prefixes like "Bearer "
        if (text.startsWith("Bearer ") || text.startsWith("bearer ")) {
            text = text.substring(7).trim();
        }

        Matcher matcher = JWT_PATTERN.matcher(text);
        if (matcher.find()) {
            return parse(matcher.group());
        }

        // Try direct parse if string looks like token
        int dotCount = 0;
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '.') dotCount++;
        }
        if (dotCount == 2) {
            return parse(text.trim());
        }

        return null;
    }

    /**
     * Parses a compact 3-part JWT string.
     */
    @Nullable
    public static JwtTokenInfo parse(@NonNull String jwtString) {
        try {
            String[] parts = jwtString.split("\\.");
            if (parts.length < 2 || parts.length > 3) {
                return null;
            }

            String headerJson = decodeBase64Url(parts[0]);
            String payloadJson = decodeBase64Url(parts[1]);
            String signature = (parts.length == 3) ? parts[2] : "";

            if (headerJson == null || payloadJson == null) {
                return null;
            }

            // Pretty format JSON
            String prettyHeader = formatJson(headerJson);
            String prettyPayload = formatJson(payloadJson);

            // Parse Header
            com.google.gson.JsonObject headerObj = JsonParser.parseString(headerJson).getAsJsonObject();
            String alg = headerObj.has("alg") ? headerObj.get("alg").getAsString() : "UNKNOWN";
            String typ = headerObj.has("typ") ? headerObj.get("typ").getAsString() : "JWT";
            String kid = headerObj.has("kid") ? headerObj.get("kid").getAsString() : null;

            // Parse Payload Claims
            com.google.gson.JsonObject payloadObj = JsonParser.parseString(payloadJson).getAsJsonObject();
            String iss = payloadObj.has("iss") ? payloadObj.get("iss").getAsString() : null;
            String sub = payloadObj.has("sub") ? payloadObj.get("sub").getAsString() : null;
            String aud = payloadObj.has("aud") ? payloadObj.get("aud").getAsString() : null;
            Long exp = payloadObj.has("exp") ? payloadObj.get("exp").getAsLong() : null;
            Long nbf = payloadObj.has("nbf") ? payloadObj.get("nbf").getAsLong() : null;
            Long iat = payloadObj.has("iat") ? payloadObj.get("iat").getAsLong() : null;
            String jti = payloadObj.has("jti") ? payloadObj.get("jti").getAsString() : null;

            // Validate status and expiration
            long nowSec = System.currentTimeMillis() / 1000L;
            TokenStatus status = TokenStatus.VALID;
            String statusDetail = "Token is active and valid";

            if ("none".equalsIgnoreCase(alg)) {
                status = TokenStatus.INSECURE_NONE;
                statusDetail = "CRITICAL: Unsigned token with alg: none!";
            } else if (exp != null && nowSec > exp) {
                status = TokenStatus.EXPIRED;
                long expiredAgoSec = nowSec - exp;
                statusDetail = "Expired " + formatDuration(expiredAgoSec) + " ago";
            } else if (nbf != null && nowSec < nbf) {
                status = TokenStatus.NOT_YET_VALID;
                long validInSec = nbf - nowSec;
                statusDetail = "Not valid for another " + formatDuration(validInSec);
            } else if (exp != null) {
                long remainingSec = exp - nowSec;
                statusDetail = "Valid for next " + formatDuration(remainingSec);
            }

            JwtTokenInfo info = new JwtTokenInfo(
                    jwtString, parts[0], parts[1], signature,
                    prettyHeader, prettyPayload, alg, kid, typ,
                    iss, sub, aud, exp, nbf, iat, jti,
                    status, statusDetail
            );

            // Populate structured claims list
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
            for (java.util.Map.Entry<String, JsonElement> entry : payloadObj.entrySet()) {
                String k = entry.getKey();
                String val = entry.getValue().isJsonPrimitive() ? entry.getValue().getAsString() : entry.getValue().toString();
                String interp = null;

                if ("exp".equals(k) && exp != null) {
                    interp = sdf.format(new Date(exp * 1000L)) + " (" + statusDetail + ")";
                } else if ("iat".equals(k) && iat != null) {
                    interp = sdf.format(new Date(iat * 1000L));
                } else if ("nbf".equals(k) && nbf != null) {
                    interp = sdf.format(new Date(nbf * 1000L));
                } else if ("sub".equals(k)) {
                    interp = "Subject / Principal ID";
                } else if ("iss".equals(k)) {
                    interp = "Token Issuer Authority";
                } else if ("aud".equals(k)) {
                    interp = "Target Audience Service";
                }

                info.claims.add(new JwtClaim(k, val, interp));
            }

            return info;
        } catch (Exception e) {
            return null;
        }
    }

    private static String decodeBase64Url(String base64Url) {
        try {
            byte[] bytes;
            try {
                bytes = java.util.Base64.getUrlDecoder().decode(base64Url);
            } catch (Throwable t) {
                bytes = Base64.decode(base64Url, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
            }
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String formatJson(String json) {
        try {
            JsonElement el = JsonParser.parseString(json);
            return GSON_PRETTY.toJson(el);
        } catch (Exception e) {
            return json;
        }
    }

    private static String formatDuration(long seconds) {
        if (seconds < 60) {
            return seconds + " sec";
        } else if (seconds < 3600) {
            return (seconds / 60) + " min";
        } else if (seconds < 86400) {
            long hours = seconds / 3600;
            long mins = (seconds % 3600) / 60;
            return hours + "h " + mins + "m";
        } else {
            long days = seconds / 86400;
            long hours = (seconds % 86400) / 3600;
            return days + "d " + hours + "h";
        }
    }
}
