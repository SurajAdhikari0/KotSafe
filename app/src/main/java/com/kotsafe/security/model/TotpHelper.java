/*
 * KotSafe Security Project
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * RFC 6238 TOTP (Time-based One-Time Password) Engine
 * Fully compatible with Google Authenticator, Microsoft Authenticator,
 * Authy, 1Password, and Bitwarden.
 *
 * Hardened with:
 * - RFC 6238 §5.2 Replay Attack Prevention (token window invalidation)
 * - Timing-attack resistant constant-time comparison (MessageDigest.isEqual)
 * - On-device ZXing QR Code Generation for Google Authenticator pairing
 */

package com.kotsafe.security.model;

import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TotpHelper {

    private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    public static final int TIME_STEP_SECONDS = 30;
    private static final int DIGITS = 6;
    private static final int MODULUS = 1_000_000;

    /**
     * Result of TOTP code validation with security metadata
     */
    public static class TotpValidationResult {
        public final boolean isValid;
        public final long matchedWindow;
        public final String errorMessage;

        public TotpValidationResult(boolean isValid, long matchedWindow, String errorMessage) {
            this.isValid = isValid;
            this.matchedWindow = matchedWindow;
            this.errorMessage = errorMessage;
        }
    }

    /**
     * Generate a new cryptographically secure 160-bit (20 byte) Base32 secret key
     */
    public static String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20]; // 160 bits (RFC 6238 recommendation)
        random.nextBytes(bytes);
        return encodeBase32(bytes);
    }

    /**
     * Generate standard otpauth:// URI for scanning or clicking
     */
    public static String generateOtpAuthUri(String issuer, String accountEmail, String secret) {
        String cleanIssuer = Uri.encode(issuer != null ? issuer : "KotSafe");
        String cleanEmail = Uri.encode(accountEmail != null ? accountEmail : "user@kotsafe.io");
        return "otpauth://totp/" + cleanIssuer + ":" + cleanEmail
                + "?secret=" + secret.replace(" ", "").toUpperCase(Locale.US)
                + "&issuer=" + cleanIssuer
                + "&algorithm=SHA1&digits=6&period=30";
    }

    /**
     * Generate an authentic, high-contrast QR Code Bitmap locally using ZXing.
     * No network calls or third-party servers are used, maintaining strict zero-leakage security.
     */
    public static Bitmap generateQrCode(String content, int width, int height) {
        if (content == null || content.isEmpty()) return null;
        try {
            Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            hints.put(EncodeHintType.MARGIN, 1);

            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix bitMatrix = writer.encode(content, BarcodeFormat.QR_CODE, width, height, hints);
            int bmWidth = bitMatrix.getWidth();
            int bmHeight = bitMatrix.getHeight();
            int[] pixels = new int[bmWidth * bmHeight];
            for (int y = 0; y < bmHeight; y++) {
                int offset = y * bmWidth;
                for (int x = 0; x < bmWidth; x++) {
                    pixels[offset + x] = bitMatrix.get(x, y) ? Color.BLACK : Color.WHITE;
                }
            }
            Bitmap bitmap = Bitmap.createBitmap(bmWidth, bmHeight, Bitmap.Config.ARGB_8888);
            bitmap.setPixels(pixels, 0, bmWidth, 0, 0, bmWidth, bmHeight);
            return bitmap;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Generate the current 6-digit TOTP code for the given secret
     */
    public static String generateCurrentCode(String base32Secret) {
        long currentWindow = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;
        return generateCodeForWindow(base32Secret, currentWindow);
    }

    /**
     * Security Hardened TOTP Verification:
     * 1. Window tolerance of +/- 1 time-step (90s window) for clock drift.
     * 2. Constant-time comparison to prevent side-channel timing attacks.
     * 3. Replay attack protection: rejects tokens if the matched window <= lastUsedWindow (RFC 6238 §5.2).
     */
    public static TotpValidationResult verifyCodeWithWindow(String base32Secret, String inputCode, long lastUsedWindow) {
        if (base32Secret == null || inputCode == null) {
            return new TotpValidationResult(false, -1, "Invalid verification request.");
        }
        String cleanCode = inputCode.trim().replaceAll("\\s+", "");
        if (cleanCode.length() != DIGITS) {
            return new TotpValidationResult(false, -1, "Code must be 6 digits.");
        }

        long currentWindow = System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;

        // Check window -1, 0, +1
        for (int i = -1; i <= 1; i++) {
            long targetWindow = currentWindow + i;
            String expected = generateCodeForWindow(base32Secret, targetWindow);
            if (constantTimeEquals(cleanCode, expected)) {
                // Prevent replay of previously used TOTP tokens
                if (targetWindow <= lastUsedWindow) {
                    return new TotpValidationResult(false, targetWindow,
                            "This code was already used. Please wait for the next code.");
                }
                return new TotpValidationResult(true, targetWindow, null);
            }
        }
        return new TotpValidationResult(false, -1, "Invalid code. Please check your Authenticator app.");
    }

    /**
     * Standard verification (backward compatible)
     */
    public static boolean verifyCode(String base32Secret, String inputCode) {
        TotpValidationResult result = verifyCodeWithWindow(base32Secret, inputCode, -1);
        return result.isValid;
    }

    /**
     * Constant-time string equality to prevent timing attacks
     */
    public static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    private static String generateCodeForWindow(String base32Secret, long window) {
        if (base32Secret == null || base32Secret.trim().isEmpty()) return "";
        try {
            byte[] keyBytes = decodeBase32(base32Secret);
            if (keyBytes == null || keyBytes.length == 0) return "";
            byte[] data = ByteBuffer.allocate(8).putLong(window).array();

            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec signKey = new SecretKeySpec(keyBytes, "HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            long truncatedHash = 0;
            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                truncatedHash |= (hash[offset + i] & 0xFF);
            }
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= MODULUS;

            return String.format(Locale.US, "%06d", truncatedHash);
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Base32 encoding conforming to RFC 4648
     */
    public static String encodeBase32(byte[] data) {
        if (data == null || data.length == 0) return "";
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                bitsLeft -= 5;
                int index = (buffer >> bitsLeft) & 0x1F;
                sb.append(BASE32_CHARS.charAt(index));
            }
        }
        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            sb.append(BASE32_CHARS.charAt(index));
        }
        return sb.toString();
    }

    /**
     * Base32 decoding conforming to RFC 4648
     */
    public static byte[] decodeBase32(String base32) {
        if (base32 == null) return new byte[0];
        String clean = base32.toUpperCase(Locale.US).replaceAll("[^A-Z2-7]", "");
        int numBytes = clean.length() * 5 / 8;
        byte[] result = new byte[numBytes];
        int buffer = 0;
        int bitsLeft = 0;
        int index = 0;
        for (char c : clean.toCharArray()) {
            int val = BASE32_CHARS.indexOf(c);
            if (val < 0) continue;
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                if (index < result.length) {
                    result[index++] = (byte) ((buffer >> bitsLeft) & 0xFF);
                }
            }
        }
        return result;
    }

    /**
     * Format a secret for readability (e.g. "ABCD EFGH IJKL MNOP")
     */
    public static String formatSecret(String secret) {
        if (secret == null) return "";
        String clean = secret.replace(" ", "").toUpperCase(Locale.US);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < clean.length(); i++) {
            if (i > 0 && i % 4 == 0) sb.append(' ');
            sb.append(clean.charAt(i));
        }
        return sb.toString();
    }
}
