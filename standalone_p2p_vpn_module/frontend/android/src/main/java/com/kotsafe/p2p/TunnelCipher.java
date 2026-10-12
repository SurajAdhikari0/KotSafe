package com.kotsafe.p2p;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * End-to-end cipher for payloads crossing an untrusted relay. The pairing
 * secret never appears in a relay frame. Direction strings intentionally match
 * frontend/reference-client/secure-peer.js for cross-language compatibility.
 */
public final class TunnelCipher {
    public static final String CLIENT_TO_EXIT = "client-to-exit";
    public static final String EXIT_TO_CLIENT = "exit-to-client";

    private static final byte[] INFO = "KotSafe P2P tunnel v1 end-to-end key"
            .getBytes(StandardCharsets.UTF_8);
    private final byte[] key;
    private final SecretKeySpec aesKey;
    private final SecretKeySpec hmacKey;
    private final String room;
    private final Map<String, Long> sent = new HashMap<>();
    private final Map<String, Long> received = new HashMap<>();

    public TunnelCipher(byte[] pairingSecret, String room) throws GeneralSecurityException {
        if (pairingSecret == null || pairingSecret.length < 32) {
            throw new IllegalArgumentException("pairingSecret must contain at least 32 bytes");
        }
        if (room == null || room.length() < 16) throw new IllegalArgumentException("invalid room");
        this.room = room;
        this.key = hkdfSha256(pairingSecret, room.getBytes(StandardCharsets.UTF_8), INFO, 32);
        this.aesKey = new SecretKeySpec(this.key, "AES");
        this.hmacKey = new SecretKeySpec(this.key, "HmacSHA256");
    }

    public synchronized byte[] sealBytes(String streamId, String direction, byte[] plaintext, int offset, int len)
            throws GeneralSecurityException {
        String stateKey = streamId + ':' + direction;
        long sequence = sent.containsKey(stateKey) ? sent.get(stateKey) : 0L;
        sent.put(stateKey, sequence + 1L);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey,
                new GCMParameterSpec(128, nonceFor(streamId, direction, sequence)));
        cipher.updateAAD(aad(streamId, direction, sequence));
        byte[] encryptedWithTag = cipher.doFinal(plaintext, offset, len);
        ByteBuffer packet = ByteBuffer.allocate(Long.BYTES + encryptedWithTag.length);
        packet.putLong(sequence).put(encryptedWithTag);
        return packet.array();
    }

    public synchronized byte[] openBytes(String streamId, String direction, byte[] packet, int offset, int len)
            throws GeneralSecurityException {
        if (len < Long.BYTES + 16) throw new GeneralSecurityException("ciphertext is too short: " + len);
        ByteBuffer wrapped = ByteBuffer.wrap(packet, offset, len);
        long sequence = wrapped.getLong();
        String stateKey = streamId + ':' + direction;
        long expected = received.containsKey(stateKey) ? received.get(stateKey) : 0L;
        if (Long.compareUnsigned(sequence, expected) != 0) {
            throw new GeneralSecurityException("replayed or out-of-order packet: got " + sequence + " expected " + expected);
        }
        byte[] encryptedWithTag = new byte[wrapped.remaining()];
        wrapped.get(encryptedWithTag);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey,
                new GCMParameterSpec(128, nonceFor(streamId, direction, sequence)));
        cipher.updateAAD(aad(streamId, direction, sequence));
        byte[] plaintext = cipher.doFinal(encryptedWithTag);
        received.put(stateKey, sequence + 1L);
        return plaintext;
    }

    public synchronized void closeStream(String streamId) {
        sent.remove(streamId + ':' + CLIENT_TO_EXIT);
        sent.remove(streamId + ':' + EXIT_TO_CLIENT);
        received.remove(streamId + ':' + CLIENT_TO_EXIT);
        received.remove(streamId + ':' + EXIT_TO_CLIENT);
    }

    public synchronized String seal(String streamId, String direction, byte[] plaintext)
            throws GeneralSecurityException {
        String stateKey = streamId + ':' + direction;
        long sequence = sent.containsKey(stateKey) ? sent.get(stateKey) : 0L;
        sent.put(stateKey, sequence + 1L);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey,
                new GCMParameterSpec(128, nonceFor(streamId, direction, sequence)));
        cipher.updateAAD(aad(streamId, direction, sequence));
        byte[] encryptedWithTag = cipher.doFinal(plaintext);
        ByteBuffer packet = ByteBuffer.allocate(Long.BYTES + encryptedWithTag.length);
        packet.putLong(sequence).put(encryptedWithTag);
        return encodeBase64Url(packet.array());
    }

    public synchronized byte[] open(String streamId, String direction, String encoded)
            throws GeneralSecurityException {
        byte[] packet = decodeBase64Url(encoded);
        if (packet.length < Long.BYTES + 16) throw new GeneralSecurityException("ciphertext is too short");
        ByteBuffer wrapped = ByteBuffer.wrap(packet);
        long sequence = wrapped.getLong();
        String stateKey = streamId + ':' + direction;
        long expected = received.containsKey(stateKey) ? received.get(stateKey) : 0L;
        if (Long.compareUnsigned(sequence, expected) != 0) {
            throw new GeneralSecurityException("replayed or out-of-order packet");
        }
        byte[] encryptedWithTag = new byte[wrapped.remaining()];
        wrapped.get(encryptedWithTag);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey,
                new GCMParameterSpec(128, nonceFor(streamId, direction, sequence)));
        cipher.updateAAD(aad(streamId, direction, sequence));
        byte[] plaintext = cipher.doFinal(encryptedWithTag);
        received.put(stateKey, sequence + 1L);
        return plaintext;
    }

    private static String encodeBase64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] decodeBase64Url(String encoded) {
        return Base64.getUrlDecoder().decode(encoded);
    }

    private byte[] nonceFor(String streamId, String direction, long sequence)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        mac.update(streamId.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 0);
        mac.update(direction.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 0);
        byte[] seqBuf = new byte[8];
        long s = sequence;
        seqBuf[7] = (byte) s; s >>= 8;
        seqBuf[6] = (byte) s; s >>= 8;
        seqBuf[5] = (byte) s; s >>= 8;
        seqBuf[4] = (byte) s; s >>= 8;
        seqBuf[3] = (byte) s; s >>= 8;
        seqBuf[2] = (byte) s; s >>= 8;
        seqBuf[1] = (byte) s; s >>= 8;
        seqBuf[0] = (byte) s;
        mac.update(seqBuf);
        byte[] full = mac.doFinal();
        byte[] nonce = new byte[12];
        System.arraycopy(full, 0, nonce, 0, 12);
        return nonce;
    }

    private byte[] aad(String streamId, String direction, long sequence) {
        return (room + '\0' + streamId + '\0' + direction + '\0' + Long.toUnsignedString(sequence))
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
            throws GeneralSecurityException {
        Mac extract = Mac.getInstance("HmacSHA256");
        extract.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = extract.doFinal(ikm);
        Mac expand = Mac.getInstance("HmacSHA256");
        expand.init(new SecretKeySpec(prk, "HmacSHA256"));
        expand.update(info);
        expand.update((byte) 1);
        byte[] output = expand.doFinal();
        byte[] key = new byte[length];
        System.arraycopy(output, 0, key, 0, length);
        return key;
    }
}
