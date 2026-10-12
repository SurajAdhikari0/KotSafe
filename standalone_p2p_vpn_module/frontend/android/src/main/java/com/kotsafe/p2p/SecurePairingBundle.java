package com.kotsafe.p2p;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Versioned QR pairing data. It deliberately has no IP address, SOCKS port,
 * SOCKS password, or relay shared secret. Candidates are discovered after
 * pairing through the authenticated control service.
 */
public final class SecurePairingBundle {
    public final String room;
    public final String pairingSecret;
    public final String controlUrl;

    public SecurePairingBundle(String room, String pairingSecret, String controlUrl) {
        if (!isRoom(room)) throw new IllegalArgumentException("invalid room");
        if (!isSecret(pairingSecret)) throw new IllegalArgumentException("invalid pairing secret");
        if (controlUrl == null || !controlUrl.startsWith("https://")) {
            throw new IllegalArgumentException("control service must use https");
        }
        this.room = room;
        this.pairingSecret = pairingSecret;
        this.controlUrl = controlUrl;
    }

    public String toQrUri() {
        return "kotsafe-gateway://pair?v=2&room=" + encode(room) + "&secret=" + encode(pairingSecret)
                + "&control=" + encode(controlUrl);
    }

    public static SecurePairingBundle parse(String raw) {
        if (raw == null || !raw.startsWith("kotsafe-gateway://pair?")) {
            throw new IllegalArgumentException("unsupported pairing QR code");
        }
        Map<String, String> values = new LinkedHashMap<>();
        String query = raw.substring(raw.indexOf('?') + 1);
        for (String part : query.split("&")) {
            String[] pair = part.split("=", 2);
            if (pair.length == 2) values.put(decode(pair[0]), decode(pair[1]));
        }
        if (!"2".equals(values.get("v"))) throw new IllegalArgumentException("unsupported pairing version");
        return new SecurePairingBundle(values.get("room"), values.get("secret"), values.get("control"));
    }

    private static boolean isRoom(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{16,96}");
    }

    private static boolean isSecret(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{40,128}");
    }

    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static String decode(String value) { return URLDecoder.decode(value, StandardCharsets.UTF_8); }
}
