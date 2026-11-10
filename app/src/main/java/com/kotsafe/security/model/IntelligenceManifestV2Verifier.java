package com.kotsafe.security.model;

import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.io.StringReader;
import java.net.IDN;
import java.net.InetAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Verifies advisory evidence snapshots. A verified match is not a blocking verdict. */
public final class IntelligenceManifestV2Verifier {
    public static final int MAX_PAYLOAD_BYTES = 2_000_000;
    public static final int MAX_ENVELOPE_BYTES = 4_100_000;
    public static final int MAX_INDICATORS = 10_000;
    private static final byte[] DOMAIN = "kotsafe-intelligence-v1:".getBytes(StandardCharsets.UTF_8);
    private static final Set<String> TYPES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "domain", "url", "ip", "sha256", "certificate_sha256")));
    private final Map<String, byte[]> trustedKeys;
    private final String tenantScope;

    /** Keys must be provisioned by the application/operator, never by the response. */
    public IntelligenceManifestV2Verifier(Map<String, byte[]> keys, String tenantScope) {
        identifier(tenantScope);
        if (keys == null || keys.isEmpty()) throw new IllegalArgumentException("Pinned signing keys required");
        this.trustedKeys = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : keys.entrySet()) {
            identifier(entry.getKey());
            if (entry.getValue() == null || entry.getValue().length != 32)
                throw new IllegalArgumentException("Expected raw Ed25519 public key");
            this.trustedKeys.put(entry.getKey(), entry.getValue().clone());
        }
        this.tenantScope = tenantScope;
    }

    public String tenantScope() { return tenantScope; }

    public Snapshot verify(byte[] envelopeBytes, long nowSeconds, long lastVersion) throws IOException {
        if (nowSeconds < 0 || lastVersion < 0) throw invalid();
        Snapshot snapshot = authenticated(envelopeBytes);
        if (snapshot.version <= lastVersion || nowSeconds < snapshot.issuedAt || nowSeconds >= snapshot.expiresAt)
            throw invalid();
        return snapshot;
    }

    /** Expired snapshots retain only their signed replay watermark after restart. */
    Snapshot restore(byte[] envelopeBytes, long nowSeconds) throws IOException {
        Snapshot snapshot = authenticated(envelopeBytes);
        if (nowSeconds < snapshot.issuedAt) throw invalid();
        return snapshot;
    }

    private Snapshot authenticated(byte[] bytes) throws IOException {
        Map<String, Object> envelope = object(parse(bytes, MAX_ENVELOPE_BYTES));
        fields(envelope, "key_id", "payload", "signature");
        String keyId = string(envelope.get("key_id"));
        byte[] key = trustedKeys.get(keyId);
        if (key == null) throw invalid();
        String signed = string(envelope.get("payload"));
        byte[] payloadBytes = signed.getBytes(StandardCharsets.UTF_8);
        if (payloadBytes.length > MAX_PAYLOAD_BYTES) throw invalid();
        String encodedSignature = string(envelope.get("signature"));
        if (!encodedSignature.matches("[A-Za-z0-9+/]{86}==")) throw invalid();
        byte[] signature;
        try { signature = Base64.decode(encodedSignature); }
        catch (RuntimeException error) { throw invalid(); }
        if (signature.length != 64) throw invalid();
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(key, 0));
        verifier.update(DOMAIN, 0, DOMAIN.length);
        verifier.update(payloadBytes, 0, payloadBytes.length);
        if (!verifier.verifySignature(signature)) throw invalid();
        Map<String, Object> payload = object(parse(payloadBytes, MAX_PAYLOAD_BYTES));
        fields(payload, "schema_version", "version", "issued_at", "expires_at", "audience", "tenant_scope", "indicators");
        if (number(payload.get("schema_version")) != 2 || !"android".equals(payload.get("audience"))
                || !tenantScope.equals(payload.get("tenant_scope"))) throw invalid();
        long version = number(payload.get("version"));
        long issued = number(payload.get("issued_at"));
        long expires = number(payload.get("expires_at"));
        if (version <= 0 || issued < 0 || expires <= issued || expires - issued > 7 * 86400L) throw invalid();
        Object rawRows = payload.get("indicators");
        if (!(rawRows instanceof List) || ((List<?>) rawRows).size() > MAX_INDICATORS) throw invalid();
        List<Indicator> rows = new ArrayList<>();
        Set<String> ids = new HashSet<>();
        for (Object raw : (List<?>) rawRows) {
            Map<String, Object> row = object(raw);
            fields(row, "id", "type", "value", "valid_until");
            String id = string(row.get("id"));
            try { identifier(id); } catch (IllegalArgumentException error) { throw invalid(); }
            String type = string(row.get("type"));
            String value = string(row.get("value"));
            if (!ids.add(id) || !TYPES.contains(type) || !value.equals(normalize(type, value))) throw invalid();
            long validUntil = number(row.get("valid_until"));
            if (validUntil <= issued || validUntil > expires) throw invalid();
            rows.add(new Indicator(id, type, value, validUntil));
        }
        return new Snapshot(version, issued, expires, tenantScope, keyId, rows);
    }

    public static String normalize(String type, String value) throws IOException {
        if (value == null || value.isEmpty() || value.length() > 8192 || !value.equals(value.trim())) throw invalid();
        for (int i = 0; i < value.length(); i++) if (value.charAt(i) < 32 || value.charAt(i) == 127) throw invalid();
        if ("domain".equals(type)) return domain(value);
        if ("sha256".equals(type) || "certificate_sha256".equals(type)) {
            if (!value.matches("[a-fA-F0-9]{64}")) throw invalid();
            return value.toLowerCase(Locale.ROOT);
        }
        if ("ip".equals(type)) return ip(value);
        if ("url".equals(type)) {
            try {
                URI uri = new URI(value);
                String scheme = uri.getScheme();
                String host = uri.getHost();
                if (scheme == null || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))
                        || host == null || uri.getRawUserInfo() != null || uri.getFragment() != null
                        || uri.getPort() > 65535 || uri.getPort() < -1) throw invalid();
                if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
                host = host.indexOf(':') >= 0 ? "[" + ip(host) + "]" : domain(host);
                String path = uri.getRawPath();
                return scheme.toLowerCase(Locale.ROOT) + "://" + host + (uri.getPort() >= 0 ? ":" + uri.getPort() : "")
                        + (path == null || path.isEmpty() ? "/" : path)
                        + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
            } catch (java.net.URISyntaxException error) { throw invalid(); }
        }
        throw invalid();
    }

    private static String domain(String value) throws IOException {
        try {
            String normalized = IDN.toASCII(value.endsWith(".") ? value.substring(0, value.length()-1) : value,
                    IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
            if (normalized.length() > 253 || normalized.isEmpty()) throw invalid();
            for (String label : normalized.split("\\.", -1))
                if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) throw invalid();
            return normalized;
        } catch (IllegalArgumentException error) { throw invalid(); }
    }

    private static String ip(String value) throws IOException {
        if (value.indexOf(':') < 0) {
            String[] pieces = value.split("\\.", -1);
            if (pieces.length != 4) throw invalid();
            for (String piece : pieces) {
                if (!piece.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(piece) > 255) throw invalid();
            }
            return value;
        }
        // The character whitelist prevents DNS resolution and rejects zone IDs.
        if (!value.matches("[0-9a-fA-F:.]+")) throw invalid();
        byte[] address;
        try { address = InetAddress.getByName(value).getAddress(); }
        catch (Exception error) { throw invalid(); }
        if (address.length == 4) { // Java collapses mapped IPv6 addresses.
            byte[] mapped = new byte[16]; mapped[10] = mapped[11] = (byte) 255;
            System.arraycopy(address, 0, mapped, 12, 4); address = mapped;
        }
        int[] words = new int[8];
        for (int i=0; i<8; i++) words[i] = ((address[i*2] & 255) << 8) | (address[i*2+1] & 255);
        int bestStart=-1, bestLength=1;
        for (int i=0; i<8;) {
            if (words[i] != 0) { i++; continue; }
            int start=i; while (i<8 && words[i]==0) i++;
            if (i-start>bestLength) { bestStart=start; bestLength=i-start; }
        }
        StringBuilder result = new StringBuilder();
        for (int i=0; i<8;) {
            if (i==bestStart) { result.append("::"); i+=bestLength; continue; }
            if (result.length()>0 && result.charAt(result.length()-1)!=':') result.append(':');
            result.append(Integer.toHexString(words[i++]));
        }
        return result.toString();
    }

    static Object parse(byte[] bytes, int limit) throws IOException {
        if (bytes == null || bytes.length > limit) throw invalid();
        String text;
        try { text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
        catch (Exception error) { throw invalid(); }
        try (JsonReader reader = new JsonReader(new StringReader(text))) {
            reader.setStrictness(Strictness.STRICT);
            Object result = read(reader, 0, new int[]{0});
            if (reader.peek() != JsonToken.END_DOCUMENT) throw invalid();
            return result;
        } catch (IllegalStateException | NumberFormatException error) { throw invalid(); }
    }

    private static Object read(JsonReader reader, int depth, int[] count) throws IOException {
        if (depth > 32 || ++count[0] > 100_000) throw invalid();
        switch (reader.peek()) {
            case BEGIN_OBJECT:
                reader.beginObject(); Map<String,Object> object = new LinkedHashMap<>();
                while (reader.hasNext()) {
                    String name = reader.nextName();
                    if (object.containsKey(name)) throw invalid();
                    object.put(name, read(reader,depth+1,count));
                }
                reader.endObject(); return object;
            case BEGIN_ARRAY:
                reader.beginArray(); List<Object> list = new ArrayList<>();
                while (reader.hasNext()) list.add(read(reader,depth+1,count));
                reader.endArray(); return list;
            case STRING: return reader.nextString();
            case NUMBER:
                String value=reader.nextString();
                if (!value.matches("0|[1-9][0-9]*")) throw invalid();
                return Long.parseLong(value);
            case BOOLEAN: return reader.nextBoolean();
            case NULL: reader.nextNull(); return null;
            default: throw invalid();
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String,Object> object(Object value) throws IOException {
        if (!(value instanceof Map)) throw invalid();
        return (Map<String,Object>) value;
    }
    private static String string(Object value) throws IOException {
        if (!(value instanceof String)) throw invalid(); return (String)value;
    }
    private static long number(Object value) throws IOException {
        if (!(value instanceof Long)) throw invalid(); return (Long)value;
    }
    private static void fields(Map<String,Object> object, String... names) throws IOException {
        if (!object.keySet().equals(new HashSet<>(Arrays.asList(names)))) throw invalid();
    }
    private static void identifier(String value) {
        if (value == null || !value.matches("[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}"))
            throw new IllegalArgumentException("Invalid scope or key identifier");
    }
    private static IOException invalid() { return new IOException("Signed intelligence snapshot validation failed"); }

    public static final class Indicator {
        public final String id, type, value;
        public final long validUntil;
        Indicator(String id, String type, String value, long validUntil) {
            this.id=id; this.type=type; this.value=value; this.validUntil=validUntil;
        }
    }
    public static final class Snapshot {
        public final long version, issuedAt, expiresAt;
        public final String tenantScope, keyId;
        public final List<Indicator> indicators;
        Snapshot(long version,long issuedAt,long expiresAt,String tenantScope,String keyId,List<Indicator> indicators) {
            this.version=version; this.issuedAt=issuedAt; this.expiresAt=expiresAt;
            this.tenantScope=tenantScope; this.keyId=keyId;
            this.indicators=Collections.unmodifiableList(new ArrayList<>(indicators));
        }
    }
}
