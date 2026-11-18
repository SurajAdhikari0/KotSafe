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
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

/**
 * Deep structural scanner for commercial Android packers, protectors, and cloaked payloads.
 *
 * Identifies commercial packers (Qihoo 360 Jiagu, Bangcle SecApk, Tencent Legu, Baidu Protect,
 * DexProtector, Alibaba Ijiami, SecNeo DexHelper, APKProtect, NetEase, Medusah) and detects
 * hidden/disguised executable payloads (e.g. nested DEX files disguised as .png, .mp3, .dat).
 */
public final class AndroidPackerDetector {
    private static final String TAG = "AndroidPackerDetector";

    public static final class PackerResult {
        public boolean isPacked = false;
        public String packerName = "";
        public boolean hasHiddenPayload = false;
        public String hiddenPayloadDetails = "";
        public int riskScore = 0; // 0..100
        public List<String> indicators = new ArrayList<>();

        @Override
        public String toString() {
            return "PackerResult{isPacked=" + isPacked +
                    ", name='" + packerName + '\'' +
                    ", hiddenPayload=" + hasHiddenPayload +
                    ", score=" + riskScore +
                    ", indicators=" + indicators + '}';
        }
    }

    private AndroidPackerDetector() {}

    /**
     * Inspects an APK file for commercial packing signatures and hidden payload stubs.
     */
    public static PackerResult detect(File apkFile) {
        PackerResult result = new PackerResult();
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return result;
        }

        try (ZipFile zip = new ZipFile(apkFile)) {
            return detect(zip);
        } catch (Exception e) {
            Log.d(TAG, "Error scanning APK for packers: " + e.getMessage());
            return result;
        }
    }

    /**
     * Inspects an opened ZipFile for commercial packer signatures and hidden payloads.
     */
    public static PackerResult detect(ZipFile zip) {
        PackerResult result = new PackerResult();
        if (zip == null) return result;

        long totalDexBytes = 0;
        long totalAssetBytes = 0;
        int dexCount = 0;

        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            String lowerName = name.toLowerCase(Locale.ROOT);

            if (lowerName.endsWith(".dex")) {
                dexCount++;
                totalDexBytes += entry.getSize();
            } else if (lowerName.startsWith("assets/")) {
                totalAssetBytes += entry.getSize();
            }

            // 1. Check Commercial Native Library Protectors
            checkNativeProtector(name, lowerName, result);

            // 2. Check Disguised Executable Payloads in assets/ or res/
            if (!lowerName.endsWith(".dex") && !lowerName.endsWith(".apk") && entry.getSize() > 32) {
                if (lowerName.startsWith("assets/") || lowerName.startsWith("res/raw/")) {
                    inspectForCloakedPayload(zip, entry, result);
                }
            }
        }

        // 3. High Asset-to-DEX Dropper Stub Heuristic
        // Tiny DEX stub (< 150 KB) with large payload assets (> 1 MB)
        if (totalDexBytes > 0 && totalDexBytes < 150_000 && totalAssetBytes > 1_000_000) {
            result.isPacked = true;
            if (result.packerName.isEmpty()) {
                result.packerName = "High Asset-to-DEX Dropper Stub";
            }
            result.indicators.add("Tiny DEX stub (" + (totalDexBytes / 1024) + " KB) with oversized assets (" + (totalAssetBytes / 1024) + " KB)");
            result.riskScore = Math.max(result.riskScore, 65);
        }

        if (result.isPacked) {
            result.riskScore = Math.min(100, result.riskScore + 35);
        }
        if (result.hasHiddenPayload) {
            result.riskScore = Math.min(100, result.riskScore + 50);
        }

        return result;
    }

    private static void checkNativeProtector(String name, String lowerName, PackerResult result) {
        // Qihoo 360 Jiagu
        if (lowerName.contains("libjiagu.so") || lowerName.contains("libjiagu_art.so")
                || lowerName.contains("libjiagu_x86.so") || lowerName.contains("libprotectclass.so")
                || lowerName.equals("assets/libjiagu.so")) {
            setPacker(result, "Qihoo 360 Jiagu", "Found 360 Jiagu stub: " + name, 80);
        }
        // Bangcle SecApk / SecShell
        else if (lowerName.contains("libsecmain.so") || lowerName.contains("libsecexe.so")
                || lowerName.contains("libsecshell.so") || lowerName.contains("bangcleclasses.jar")
                || lowerName.contains("bangcle_classes.jar")) {
            setPacker(result, "Bangcle SecApk", "Found Bangcle protector stub: " + name, 80);
        }
        // Tencent Legu / Tencent Shell
        else if (lowerName.contains("libshella-") || lowerName.contains("libshellx-")
                || lowerName.contains("libtxloader.so") || lowerName.contains("libtup.so")
                || lowerName.equals("00000000.dex") || lowerName.equals("01201111.dex")) {
            setPacker(result, "Tencent Legu", "Found Tencent Legu stub: " + name, 80);
        }
        // Baidu Protect
        else if (lowerName.contains("libbaiduprotect.so") || lowerName.contains("libbaiduprotect_art.so")
                || lowerName.contains("baiduprotect.jar") || lowerName.contains("baiduprotect1.jar")) {
            setPacker(result, "Baidu Protect", "Found Baidu Protect stub: " + name, 80);
        }
        // DexProtector
        else if (lowerName.contains("libdexprotector") || lowerName.contains("dp.arm-v7.so")
                || lowerName.contains("dp.arm-v8.so") || lowerName.contains("dp.x86.so")) {
            setPacker(result, "DexProtector", "Found DexProtector stub: " + name, 75);
        }
        // Alibaba / Ijiami
        else if (lowerName.contains("libexec.so") || lowerName.contains("libexecmain.so")
                || lowerName.contains("ijiami.dat") || lowerName.contains("ijiami.ajm")
                || lowerName.contains("libmobisec.so") || lowerName.contains("libsgmain.so")) {
            setPacker(result, "Alibaba Ijiami", "Found Alibaba / Ijiami stub: " + name, 80);
        }
        // SecNeo DexHelper
        else if (lowerName.contains("libdexhelper.so") || lowerName.contains("classes0.jar")) {
            setPacker(result, "SecNeo DexHelper", "Found SecNeo DexHelper stub: " + name, 75);
        }
        // APKProtect
        else if (lowerName.contains("libapkprotect.so")) {
            setPacker(result, "APKProtect", "Found APKProtect stub: " + name, 75);
        }
        // NetEase Dun (网易易盾)
        else if (lowerName.contains("libnesec.so")) {
            setPacker(result, "NetEase Dun", "Found NetEase protector stub: " + name, 70);
        }
        // Medusah
        else if (lowerName.contains("libmedusah.so")) {
            setPacker(result, "Medusah", "Found Medusah protector stub: " + name, 70);
        }
        // Nagravision
        else if (lowerName.contains("libnagrawp.so")) {
            setPacker(result, "Nagravision", "Found Nagravision protector stub: " + name, 70);
        }
    }

    private static void inspectForCloakedPayload(ZipFile zip, ZipEntry entry, PackerResult result) {
        byte[] magic = new byte[4];
        try (InputStream is = zip.getInputStream(entry)) {
            int read = is.read(magic);
            if (read < 4) return;

            // DEX Magic check: 'd' 'e' 'x' '\n' (0x64, 0x65, 0x78, 0x0A)
            if (magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A) {
                result.hasHiddenPayload = true;
                result.hiddenPayloadDetails = "Disguised DEX bytecode found inside " + entry.getName();
                result.indicators.add("Cloaked DEX file disguised as non-DEX asset: " + entry.getName());
                result.riskScore = Math.max(result.riskScore, 90);
                return;
            }

            // ZIP / JAR Magic check: 'P' 'K' 0x03 0x04
            if (magic[0] == 0x50 && magic[1] == 0x4B && magic[2] == 0x03 && magic[3] == 0x04) {
                // If the file is not named .zip / .jar / .apk, investigate if it packages nested classes.dex
                String lower = entry.getName().toLowerCase(Locale.ROOT);
                if (!lower.endsWith(".zip") && !lower.endsWith(".jar") && !lower.endsWith(".apk")) {
                    // Inspect first 64KB of nested zip
                    byte[] buffer = new byte[Math.min((int) entry.getSize(), 65536)];
                    System.arraycopy(magic, 0, buffer, 0, 4);
                    int offset = 4;
                    while (offset < buffer.length) {
                        int r = is.read(buffer, offset, buffer.length - offset);
                        if (r <= 0) break;
                        offset += r;
                    }
                    try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(buffer, 0, offset))) {
                        ZipEntry subEntry;
                        while ((subEntry = zis.getNextEntry()) != null) {
                            if (subEntry.getName().endsWith(".dex")) {
                                result.hasHiddenPayload = true;
                                result.hiddenPayloadDetails = "Nested ZIP container inside " + entry.getName() + " contains " + subEntry.getName();
                                result.indicators.add("Cloaked ZIP/JAR archive containing DEX bytecode: " + entry.getName());
                                result.riskScore = Math.max(result.riskScore, 95);
                                break;
                            }
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception ignored) {}
    }

    private static void setPacker(PackerResult result, String name, String indicator, int score) {
        result.isPacked = true;
        if (result.packerName.isEmpty() || result.packerName.contains("Dropper Stub")) {
            result.packerName = name;
        }
        result.indicators.add(indicator);
        result.riskScore = Math.max(result.riskScore, score);
    }
}
