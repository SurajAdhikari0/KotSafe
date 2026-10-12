package com.kotsafe.security;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.Test;

public class BrowserAccessibilityManifestRegressionTest {
    @Test
    public void manifest_registers_browser_accessibility_service() throws IOException {
        Path manifestPath = Paths.get("src", "main", "AndroidManifest.xml");
        String manifest = new String(Files.readAllBytes(manifestPath), StandardCharsets.UTF_8);

        assertTrue("Main manifest must register BrowserAccessibilityService",
                manifest.contains(".services.BrowserAccessibilityService")
                        && manifest.contains("android.accessibilityservice.AccessibilityService"));
    }
}
