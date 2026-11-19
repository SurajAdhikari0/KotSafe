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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AndroidPackerDetectorTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private File createMockApk(String[] entryNames, byte[][] entryContents) throws IOException {
        File apk = tempFolder.newFile("sample_" + System.nanoTime() + ".apk");
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(apk))) {
            for (int i = 0; i < entryNames.length; i++) {
                ZipEntry entry = new ZipEntry(entryNames[i]);
                zos.putNextEntry(entry);
                if (entryContents != null && i < entryContents.length && entryContents[i] != null) {
                    zos.write(entryContents[i]);
                } else {
                    zos.write("dummy_content_bytes".getBytes(StandardCharsets.UTF_8));
                }
                zos.closeEntry();
            }
        }
        return apk;
    }

    @Test
    public void testCleanBenignApk_NoPackerOrHiddenPayload() throws IOException {
        String[] entries = new String[] {
                "AndroidManifest.xml",
                "classes.dex",
                "res/layout/activity_main.xml",
                "resources.arsc"
        };
        File apk = createMockApk(entries, null);

        AndroidPackerDetector.PackerResult result = AndroidPackerDetector.detect(apk);
        assertFalse("Clean APK should not be marked as packed", result.isPacked);
        assertFalse("Clean APK should have no hidden payload", result.hasHiddenPayload);
        assertEquals("Clean APK risk score should be 0", 0, result.riskScore);
    }

    @Test
    public void testJiaguPackerDetection() throws IOException {
        String[] entries = new String[] {
                "AndroidManifest.xml",
                "classes.dex",
                "lib/arm64-v8a/libjiagu.so",
                "assets/libjiagu.so"
        };
        File apk = createMockApk(entries, null);

        AndroidPackerDetector.PackerResult result = AndroidPackerDetector.detect(apk);
        assertTrue("360 Jiagu APK must be flagged as packed", result.isPacked);
        assertEquals("Qihoo 360 Jiagu", result.packerName);
        assertTrue("Risk score should be elevated", result.riskScore >= 80);
    }

    @Test
    public void testBangcleSecApkDetection() throws IOException {
        String[] entries = new String[] {
                "AndroidManifest.xml",
                "classes.dex",
                "lib/armeabi-v7a/libsecmain.so",
                "lib/armeabi-v7a/libsecexe.so"
        };
        File apk = createMockApk(entries, null);

        AndroidPackerDetector.PackerResult result = AndroidPackerDetector.detect(apk);
        assertTrue("Bangcle APK must be flagged as packed", result.isPacked);
        assertEquals("Bangcle SecApk", result.packerName);
        assertTrue("Risk score should be elevated", result.riskScore >= 80);
    }

    @Test
    public void testTencentLeguDetection() throws IOException {
        String[] entries = new String[] {
                "AndroidManifest.xml",
                "classes.dex",
                "lib/armeabi-v7a/libshella-4.1.0.so",
                "00000000.dex"
        };
        File apk = createMockApk(entries, null);

        AndroidPackerDetector.PackerResult result = AndroidPackerDetector.detect(apk);
        assertTrue("Tencent Legu APK must be flagged as packed", result.isPacked);
        assertEquals("Tencent Legu", result.packerName);
        assertTrue("Risk score should be elevated", result.riskScore >= 80);
    }

    @Test
    public void testCloakedDexDisguisedAsPng() throws IOException {
        byte[] fakePngWithDexHeader = new byte[] {
                0x64, 0x65, 0x78, 0x0a, // 'd' 'e' 'x' '\n'
                0x30, 0x33, 0x35, 0x00, // '0' '3' '5' '\0'
                0x00, 0x01, 0x02, 0x03,
                0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b,
                0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x11, 0x12, 0x13,
                0x14, 0x15, 0x16, 0x17,
                0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f
        };

        String[] entries = new String[] {
                "AndroidManifest.xml",
                "classes.dex",
                "assets/background_wallpaper.png"
        };
        byte[][] contents = new byte[][] {
                "manifest_stub".getBytes(StandardCharsets.UTF_8),
                "classes_dex_stub".getBytes(StandardCharsets.UTF_8),
                fakePngWithDexHeader
        };
        File apk = createMockApk(entries, contents);

        AndroidPackerDetector.PackerResult result = AndroidPackerDetector.detect(apk);
        assertTrue("Must detect hidden payload", result.hasHiddenPayload);
        assertTrue("Must explain cloaked DEX found in assets", result.hiddenPayloadDetails.contains("background_wallpaper.png"));
        assertTrue("Risk score must be at least 90 for hidden executable code", result.riskScore >= 90);
    }
}

