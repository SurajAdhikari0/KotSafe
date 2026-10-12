package com.kotsafe.security.services;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import org.junit.Test;

public class BrowserAccessibilityServiceTest {
    @Test
    public void recognizes_modern_browser_url_bar_ids() throws Exception {
        Field idsField = BrowserAccessibilityService.class.getDeclaredField("URL_BAR_VIEW_IDS");
        idsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<String> ids = (List<String>) idsField.get(null);

        assertTrue(ids.contains("search_src_text"));
        assertTrue(ids.contains("omnibox"));
        assertTrue(ids.contains("search_box_text"));
    }

    @Test
    public void cleans_and_accepts_modern_browser_urls() throws Exception {
        BrowserAccessibilityService service = new BrowserAccessibilityService();

        Method cleanUrl = BrowserAccessibilityService.class.getDeclaredMethod("cleanUrl", String.class);
        cleanUrl.setAccessible(true);
        Method looksLikeUrl = BrowserAccessibilityService.class.getDeclaredMethod("looksLikeUrl", String.class);
        looksLikeUrl.setAccessible(true);

        String cleaned = (String) cleanUrl.invoke(service, "example.com/search?q=abc");
        assertTrue(cleaned.startsWith("https://example.com/search?q=abc"));
        assertTrue((Boolean) looksLikeUrl.invoke(service, cleaned));
    }
}
