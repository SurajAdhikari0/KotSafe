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

package com.kotsafe.security.model;

import com.kotsafe.security.Log;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Lightweight, zero-dependency Dalvik DEX structural analyzer for Deep Scan (Plan v2 §4.3).
 * Parses classes.dex headers, string pools, method references, dynamic loading stubs,
 * reflection density, and asset-to-code ratios.
 */
public class DexStructuralParser {
    private static final String TAG = "DexStructuralParser";

    public static class DexAnalysisResult {
        public FeatureVector featureVector = new FeatureVector();
        public boolean hasDynamicLoading;
        public boolean hasDangerousExec;
        public boolean hasSmsAbuse;
        public boolean hasPackerStub;
        public String detectedPackerName = "";
        public int heuristicConfidenceScore; // 0 - 100
        public List<String> detectedFeatures = new ArrayList<>();
    }

    /**
     * Analyzes an APK file structurally without heavy third-party bytecode libraries.
     */
    public static DexAnalysisResult analyzeApk(File apkFile) {
        DexAnalysisResult result = new DexAnalysisResult();
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return result;
        }

        long totalDexBytes = 0;
        long totalAssetBytes = 0;
        int nativeLibCount = 0;
        byte[] firstDexBytes = null;

        try (ZipFile zip = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // RedNaga APKiD Packer & Protector signatures
                if (name.contains("libjiagu.so") || name.contains("libprotectClass.so") || name.equals("assets/libjiagu.so")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "Qihoo 360 Jiagu";
                } else if (name.contains("libsecexe.so") || name.contains("libsecmain.so") || name.contains("bangcleclasses.jar")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "Bangcle SecApk";
                } else if (name.contains("libshella-") || name.contains("libtup.so") || name.equals("00000000.dex") || name.contains("libshellx-")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "Tencent Legu";
                } else if (name.contains("libdexprotector.") || name.contains("dp.arm-v7.so") || name.contains("dp.arm-v8.so")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "DexProtector";
                } else if (name.contains("libexec.so") || name.contains("libexecmain.so") || name.contains("ijiami.dat")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "Ijiami / Alibaba";
                } else if (name.contains("libDexHelper.so") || name.contains("classes0.jar")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "SecNeo DexHelper";
                } else if (name.contains("libbaiduprotect.so")) {
                    result.hasPackerStub = true;
                    result.detectedPackerName = "Baidu Protect";
                }

                if (name.endsWith(".dex")) {
                    totalDexBytes += entry.getSize();
                    if (firstDexBytes == null && "classes.dex".equals(name)) {
                        // Read first 2MB max of classes.dex for structural extraction
                        int readLen = (int) Math.min(entry.getSize(), 2 * 1024 * 1024);
                        if (readLen > 0) {
                            firstDexBytes = new byte[readLen];
                            try (InputStream is = zip.getInputStream(entry)) {
                                int totalRead = 0;
                                while (totalRead < readLen) {
                                    int r = is.read(firstDexBytes, totalRead, readLen - totalRead);
                                    if (r <= 0) break;
                                    totalRead += r;
                                }
                            }
                        }
                    }
                } else if (name.startsWith("lib/") && name.endsWith(".so")) {
                    nativeLibCount++;
                } else if (name.startsWith("assets/")) {
                    totalAssetBytes += entry.getSize();
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error inspecting APK zip: " + e.getMessage());
            return result;
        }

        result.featureVector.nativeLibCount = nativeLibCount;
        if (totalDexBytes > 0) {
            result.featureVector.assetToCodeRatio = (float) totalAssetBytes / (float) totalDexBytes;
        }

        // Detect potential packer/dropper stub: tiny DEX with huge asset payload
        if (totalDexBytes > 0 && totalDexBytes < 150_000 && totalAssetBytes > 1_000_000) {
            result.hasPackerStub = true;
            if (result.detectedPackerName.isEmpty()) {
                result.detectedPackerName = "High Asset-to-DEX Dropper Stub";
            }
            result.detectedFeatures.add("packer_stub_high_asset_ratio");
        }

        if (result.hasPackerStub && !result.detectedPackerName.isEmpty() && !result.detectedFeatures.contains("Packer: " + result.detectedPackerName)) {
            result.detectedFeatures.add("Packer: " + result.detectedPackerName);
        }

        if (firstDexBytes != null && firstDexBytes.length >= 0x70) {
            parseDexStructures(firstDexBytes, result);
        }

        // Calculate heuristic confidence score (Plan v2 §5)
        int score = 0;
        if (result.hasPackerStub) score += 35;
        if (result.hasDynamicLoading) score += 25;
        if (result.hasDangerousExec) score += 20;
        if (result.hasSmsAbuse) score += 20;
        if (result.featureVector.reflectionDensity > 0.08f) score += 15;
        if (result.featureVector.stringEntropy > 6.5f) score += 10;

        result.heuristicConfidenceScore = Math.min(100, score);
        return result;
    }

    private static void parseDexStructures(byte[] data, DexAnalysisResult result) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

            // DEX Magic check: dex\n035\0 (or 037, 038, 039)
            if (data[0] != 0x64 || data[1] != 0x65 || data[2] != 0x78 || data[3] != 0x0a) {
                return; // Not a valid DEX magic header
            }

            int stringIdsSize = buf.getInt(0x38);
            int stringIdsOff = buf.getInt(0x3c);
            int typeIdsSize = buf.getInt(0x40);
            int methodIdsSize = buf.getInt(0x58);

            int totalStringsToInspect = Math.min(stringIdsSize, 600);
            int reflectionCount = 0;
            int dynamicLoadingCount = 0;
            int dangerousExecCount = 0;
            int smsAbuseCount = 0;
            double totalEntropy = 0;
            int entropySampleCount = 0;

            Set<String> extractedTokens = new HashSet<>();

            for (int i = 0; i < totalStringsToInspect; i++) {
                int ptrOffset = stringIdsOff + (i * 4);
                if (ptrOffset + 4 > data.length) break;

                int stringDataOff = buf.getInt(ptrOffset);
                if (stringDataOff < 0 || stringDataOff >= data.length) continue;

                String s = readMutf8String(data, stringDataOff);
                if (s.isEmpty()) continue;

                if (s.length() >= 6 && entropySampleCount < 60) {
                    totalEntropy += calculateShannonEntropy(s);
                    entropySampleCount++;
                }

                if (s.contains("DexClassLoader") || s.contains("InMemoryDexClassLoader") || s.contains("PathClassLoader")) {
                    dynamicLoadingCount++;
                    extractedTokens.add("DynamicClassLoader");
                }
                if (s.contains("Method.invoke") || s.contains("Class.forName") || s.contains("getDeclaredMethod")) {
                    reflectionCount++;
                }
                if (s.contains("/system/bin/sh") || s.contains("/system/bin/su") || s.contains("ProcessBuilder") || s.contains("Runtime.getRuntime().exec")) {
                    dangerousExecCount++;
                    extractedTokens.add("ProcessExec");
                }
                if (s.contains("sendTextMessage") || s.contains("sendMultipartTextMessage")) {
                    smsAbuseCount++;
                    extractedTokens.add("SmsTelephony");
                }
                if (s.contains("ALLATORIxDEMO")) {
                    extractedTokens.add("Allatori Obfuscator");
                }
                if (s.contains("DashO-Pro") || s.contains("com.dasho.")) {
                    extractedTokens.add("DashO Obfuscator");
                }
                if (s.contains("dexguard.util") || s.contains("dexguard.")) {
                    extractedTokens.add("DexGuard Protector");
                }
            }

            if (methodIdsSize > 0) {
                result.featureVector.reflectionDensity = (float) reflectionCount / (float) Math.min(methodIdsSize, 5000);
            }
            if (entropySampleCount > 0) {
                result.featureVector.stringEntropy = (float) (totalEntropy / entropySampleCount);
            }

            result.hasDynamicLoading = dynamicLoadingCount > 0;
            result.hasDangerousExec = dangerousExecCount > 0;
            result.hasSmsAbuse = smsAbuseCount > 0;

            if (result.hasDynamicLoading) result.detectedFeatures.add("Dynamic Code Loading (DexClassLoader)");
            if (result.hasDangerousExec) result.detectedFeatures.add("Direct Shell / Root Command Execution");
            if (result.hasSmsAbuse) result.detectedFeatures.add("Background SMS Dispatch Execution");
            for (String tok : extractedTokens) {
                if ((tok.endsWith("Obfuscator") || tok.endsWith("Protector")) && !result.detectedFeatures.contains(tok)) {
                    result.detectedFeatures.add(tok);
                }
            }
            if (result.featureVector.reflectionDensity > 0.08f) {
                result.detectedFeatures.add(String.format("High Reflection Density (%.1f%%)", result.featureVector.reflectionDensity * 100));
            }

        } catch (Exception e) {
            Log.e(TAG, "parseDexStructures: " + e.getMessage());
        }
    }

    private static String readMutf8String(byte[] data, int offset) {
        try {
            // Read uleb128 utf16_size
            int p = offset;
            int utf16Size = 0;
            int shift = 0;
            while (p < data.length) {
                byte b = data[p++];
                utf16Size |= (b & 0x7f) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }

            int strStart = p;
            int strEnd = p;
            while (strEnd < data.length && data[strEnd] != 0) {
                strEnd++;
                if (strEnd - strStart > 512) break; // cap max string length
            }

            if (strEnd > strStart) {
                return new String(data, strStart, strEnd - strStart, "UTF-8");
            }
        } catch (Exception ignored) {}
        return "";
    }

    private static double calculateShannonEntropy(String s) {
        int[] freq = new int[256];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 256) freq[c]++;
        }
        double entropy = 0;
        int len = s.length();
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}
