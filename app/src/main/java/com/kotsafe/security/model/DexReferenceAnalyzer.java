/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * DexReferenceAnalyzer
 * ====================
 * Parses the DEX method_ids / field_ids / string_ids tables directly and returns
 * the set of APIs the app ACTUALLY REFERENCES IN CODE.
 *
 * Why this replaces the substring scan in YaraRuleEngine.scanApk():
 *
 *   The old engine read classes.dex as raw bytes and asked "does the byte
 *   sequence 'sendTextMessage' appear anywhere?". A DEX file's string table
 *   contains every class name, method name, field name, resource name and
 *   string literal referenced ANYWHERE in the app, including inside every
 *   bundled library. So:
 *
 *     - "loadClass" is present in every app that touches a ClassLoader.
 *     - "DexClassLoader" ships inside Play Core, Firebase, Flutter, React
 *       Native and most ad SDKs.
 *     - "sendTextMessage" + "SMS_RECEIVED" are both present in any app doing
 *       SMS OTP autofill — which is nearly every banking and delivery app.
 *     - "AccessibilityService" is present in androidx.core.
 *
 *   Every one of those produced a SUSPICIOUS or MALICIOUS verdict. That is the
 *   bulk of the false positives.
 *
 *   This parser answers a much narrower question: "does the app hold a
 *   method reference to Landroid/telephony/SmsManager;->sendTextMessage?"
 *   A reference in method_ids means the compiler emitted a call site for it,
 *   which is a far stronger signal than the name appearing in a string pool.
 *
 * Still not proof of execution — nothing static is — which is exactly why the
 * output feeds AppTrustEvaluator as weighted evidence rather than becoming a
 * verdict on its own.
 *
 * Zero dependencies. Handles multi-dex.
 */

package com.kotsafe.security.model;

import com.kotsafe.security.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class DexReferenceAnalyzer {
    private static final String TAG = "DexReferenceAnalyzer";

    private static final long MAX_DEX_BYTES = 64L * 1024 * 1024;

    // DEX header field offsets (little-endian, DEX spec)
    private static final int OFF_STRING_IDS_SIZE = 0x38;
    private static final int OFF_STRING_IDS_OFF  = 0x3C;
    private static final int OFF_TYPE_IDS_SIZE   = 0x40;
    private static final int OFF_TYPE_IDS_OFF    = 0x44;
    private static final int OFF_METHOD_IDS_SIZE = 0x58;
    private static final int OFF_METHOD_IDS_OFF  = 0x5C;

    public static class DexFacts {
        /** Fully-qualified method references, e.g. "Landroid/telephony/SmsManager;->sendTextMessage" */
        public final Set<String> methodRefs = new HashSet<>();
        /** String literals and names from the string pool (used only for URL/host extraction). */
        public final Set<String> stringPool = new HashSet<>();
        /** Hosts / URLs found in the string pool. */
        public final Set<String> embeddedHosts = new HashSet<>();
        public int dexCount = 0;
        public int totalMethodRefs = 0;
        public boolean parseFailed = false;

        public boolean refs(String methodRef) {
            return methodRefs.contains(methodRef);
        }

        /** True if any reference starts with the given class prefix. */
        public boolean refsClass(String classDescriptor) {
            for (String m : methodRefs) {
                if (m.startsWith(classDescriptor + "->")) return true;
            }
            return false;
        }
    }

    // ------------------------------------------------------------------ public

    public static DexFacts analyzeApk(File apkFile) {
        DexFacts facts = new DexFacts();
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            facts.parseFailed = true;
            return facts;
        }

        try (ZipFile zip = new ZipFile(apkFile)) {
            java.util.Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                String name = e.getName();
                // classes.dex, classes2.dex, ... — top level only, no nested paths.
                if (!name.endsWith(".dex") || name.contains("/")) continue;
                if (e.getSize() > MAX_DEX_BYTES) continue;

                byte[] dex = readEntry(zip, e);
                if (dex == null) continue;
                if (parseDex(dex, facts)) facts.dexCount++;
            }
        } catch (Exception ex) {
            Log.w(TAG, "analyzeApk failed for " + apkFile.getName() + ": " + ex.getMessage());
            facts.parseFailed = true;
        }

        extractHosts(facts);
        return facts;
    }

    // ------------------------------------------------------------------ parsing

    private static boolean parseDex(byte[] dex, DexFacts facts) {
        try {
            if (dex.length < 0x70) return false;
            // Accept "dex\n035".."dex\n041" and the "cdex" (CompactDex) variants are skipped.
            if (!(dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'x' && dex[3] == '\n')) return false;

            ByteBuffer bb = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);

            int stringIdsSize = bb.getInt(OFF_STRING_IDS_SIZE);
            int stringIdsOff  = bb.getInt(OFF_STRING_IDS_OFF);
            int typeIdsSize   = bb.getInt(OFF_TYPE_IDS_SIZE);
            int typeIdsOff    = bb.getInt(OFF_TYPE_IDS_OFF);
            int methodIdsSize = bb.getInt(OFF_METHOD_IDS_SIZE);
            int methodIdsOff  = bb.getInt(OFF_METHOD_IDS_OFF);

            if (!sane(stringIdsSize, stringIdsOff, 4, dex.length)) return false;

            // ---- string_ids -> string table
            String[] strings = new String[stringIdsSize];
            for (int i = 0; i < stringIdsSize; i++) {
                int dataOff = bb.getInt(stringIdsOff + i * 4);
                strings[i] = readMUtf8(dex, dataOff);
                if (strings[i] != null && strings[i].length() <= 256) {
                    facts.stringPool.add(strings[i]);
                }
            }

            // ---- type_ids -> type descriptors
            String[] types = new String[Math.max(typeIdsSize, 0)];
            if (sane(typeIdsSize, typeIdsOff, 4, dex.length)) {
                for (int i = 0; i < typeIdsSize; i++) {
                    int descIdx = bb.getInt(typeIdsOff + i * 4);
                    types[i] = (descIdx >= 0 && descIdx < strings.length) ? strings[descIdx] : null;
                }
            }

            // ---- method_ids -> class->name pairs (the actual referenced API surface)
            if (sane(methodIdsSize, methodIdsOff, 8, dex.length)) {
                for (int i = 0; i < methodIdsSize; i++) {
                    int base = methodIdsOff + i * 8;
                    int classIdx = bb.getShort(base) & 0xFFFF;
                    int nameIdx  = bb.getInt(base + 4);
                    if (classIdx >= types.length || nameIdx < 0 || nameIdx >= strings.length) continue;
                    String cls = types[classIdx];
                    String name = strings[nameIdx];
                    if (cls == null || name == null) continue;
                    facts.methodRefs.add(cls + "->" + name);
                    facts.totalMethodRefs++;
                }
            }
            return true;
        } catch (Exception e) {
            Log.w(TAG, "parseDex error: " + e.getMessage());
            return false;
        }
    }

    private static boolean sane(int size, int off, int itemLen, int fileLen) {
        if (size <= 0 || off <= 0) return false;
        long end = (long) off + (long) size * itemLen;
        return end <= fileLen;
    }

    /** DEX string_data_item: uleb128 utf16_size, then MUTF-8 bytes, NUL-terminated. */
    private static String readMUtf8(byte[] buf, int off) {
        try {
            if (off < 0 || off >= buf.length) return null;
            int p = off;
            // skip uleb128 length
            while (p < buf.length && (buf[p] & 0x80) != 0) p++;
            p++;
            int start = p;
            while (p < buf.length && buf[p] != 0) p++;
            if (p - start > 4096) return null;              // absurd; skip
            return new String(buf, start, p - start, "UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readEntry(ZipFile zip, ZipEntry entry) {
        try (InputStream is = zip.getInputStream(entry);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] tmp = new byte[16384];
            int n;
            long total = 0;
            while ((n = is.read(tmp)) != -1) {
                total += n;
                if (total > MAX_DEX_BYTES) return null;      // zip-bomb guard
                out.write(tmp, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static void extractHosts(DexFacts facts) {
        for (String s : facts.stringPool) {
            if (s == null || s.length() < 5 || s.length() > 200) continue;
            String lower = s.toLowerCase();
            if (lower.startsWith("http://") || lower.startsWith("https://")
                    || lower.startsWith("ws://") || lower.startsWith("wss://")
                    || lower.startsWith("tcp://")) {
                try {
                    int schemeEnd = lower.indexOf("://") + 3;
                    int hostEnd = schemeEnd;
                    while (hostEnd < lower.length()) {
                        char c = lower.charAt(hostEnd);
                        if (c == '/' || c == ':' || c == '?' || c == '#') break;
                        hostEnd++;
                    }
                    String host = lower.substring(schemeEnd, hostEnd);
                    if (host.length() > 3 && host.contains(".")) facts.embeddedHosts.add(host);
                } catch (Exception ignored) {}
            } else if (lower.endsWith(".onion")) {
                facts.embeddedHosts.add(lower);
            }
        }
    }

    // ------------------------------------------------------------------ API groups
    //
    // These are the references that actually matter. Each is a precise
    // class->method pair, so a library merely *naming* something no longer
    // triggers anything.

    public static final class Api {
        public static final String SMS_SEND          = "Landroid/telephony/SmsManager;->sendTextMessage";
        public static final String SMS_SEND_MULTI    = "Landroid/telephony/SmsManager;->sendMultipartTextMessage";
        public static final String SMS_SEND_DATA     = "Landroid/telephony/SmsManager;->sendDataMessage";
        public static final String ABORT_BROADCAST   = "Landroid/content/BroadcastReceiver;->abortBroadcast";

        public static final String DEX_CLASSLOADER   = "Ldalvik/system/DexClassLoader;-><init>";
        public static final String PATH_CLASSLOADER  = "Ldalvik/system/PathClassLoader;-><init>";
        public static final String IN_MEMORY_DEX     = "Ldalvik/system/InMemoryDexClassLoader;-><init>";

        public static final String RUNTIME_EXEC      = "Ljava/lang/Runtime;->exec";
        public static final String PROCESS_BUILDER   = "Ljava/lang/ProcessBuilder;->start";

        public static final String OVERLAY_ADD_VIEW  = "Landroid/view/WindowManager;->addView";
        public static final String ACCESSIBILITY_EVT = "Landroid/accessibilityservice/AccessibilityService;->onAccessibilityEvent";
        public static final String PERFORM_GLOBAL    = "Landroid/accessibilityservice/AccessibilityService;->performGlobalAction";

        public static final String DEVICE_ADMIN_LOCK = "Landroid/app/admin/DevicePolicyManager;->lockNow";
        public static final String DEVICE_ADMIN_WIPE = "Landroid/app/admin/DevicePolicyManager;->wipeData";
        public static final String RESET_PASSWORD    = "Landroid/app/admin/DevicePolicyManager;->resetPassword";

        public static final String CIPHER_INIT       = "Ljavax/crypto/Cipher;->init";
        public static final String CIPHER_DOFINAL    = "Ljavax/crypto/Cipher;->doFinal";
        public static final String FILE_DELETE       = "Ljava/io/File;->delete";
        public static final String FILE_RENAME       = "Ljava/io/File;->renameTo";

        public static final String CAMERA_OPEN       = "Landroid/hardware/Camera;->open";
        public static final String MEDIA_RECORDER    = "Landroid/media/MediaRecorder;->start";
        public static final String AUDIO_RECORD      = "Landroid/media/AudioRecord;->startRecording";
        public static final String LOCATION_UPDATES  = "Landroid/location/LocationManager;->requestLocationUpdates";
        public static final String CONTACTS_QUERY    = "Landroid/content/ContentResolver;->query";

        public static final String PKG_INSTALL       = "Landroid/content/pm/PackageInstaller$Session;->commit";
        public static final String GET_INSTALLED     = "Landroid/content/pm/PackageManager;->getInstalledPackages";

        private Api() {}
    }

    /** Convenience: does the app reference any dynamic-code-loading constructor? */
    public static boolean usesDynamicCodeLoading(DexFacts f) {
        return f.refs(Api.DEX_CLASSLOADER) || f.refs(Api.IN_MEMORY_DEX);
    }

    /** Convenience: does the app reference programmatic SMS sending? */
    public static boolean usesSmsSending(DexFacts f) {
        return f.refs(Api.SMS_SEND) || f.refs(Api.SMS_SEND_MULTI) || f.refs(Api.SMS_SEND_DATA);
    }

    public static List<String> summarize(DexFacts f) {
        List<String> out = new ArrayList<>();
        if (usesDynamicCodeLoading(f)) out.add("dynamic code loading");
        if (usesSmsSending(f))         out.add("programmatic SMS send");
        if (f.refs(Api.RUNTIME_EXEC) || f.refs(Api.PROCESS_BUILDER)) out.add("native process execution");
        if (f.refs(Api.OVERLAY_ADD_VIEW)) out.add("window overlay");
        if (f.refs(Api.ACCESSIBILITY_EVT)) out.add("accessibility event handling");
        if (f.refs(Api.DEVICE_ADMIN_WIPE) || f.refs(Api.RESET_PASSWORD)) out.add("device admin control");
        if (f.refs(Api.AUDIO_RECORD) || f.refs(Api.MEDIA_RECORDER)) out.add("audio capture");
        if (f.refs(Api.PKG_INSTALL)) out.add("package installation");
        Collections.sort(out);
        return out;
    }
}
