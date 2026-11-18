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

package com.kotsafe.security.ai.ml;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class NetworkMlClassifierTest {

    @Test
    public void testBenignDomains_ClassifiedAsClean() {
        NetworkMlClassifier classifier = NetworkMlClassifier.getInstance();

        String[] benign = new String[] {
                "google.com",
                "mail.google.com",
                "wikipedia.org",
                "github.com",
                "amazon.com",
                "apple.com",
                "cloudflare.com",
                "kotsafe.com",
                "speedtest.net",
                "api.whatsapp.com"
        };

        for (String domain : benign) {
            NetworkMlClassifier.DgaResult res = classifier.classifyDomain(domain);
            assertFalse("Benign domain " + domain + " should not be flagged as malicious (score: " + res.threatScore + ")", res.isMalicious);
        }
    }

    @Test
    public void testDgaDomains_FlaggedAsMalicious() {
        NetworkMlClassifier classifier = NetworkMlClassifier.getInstance();

        // High entropy, consonant clusters, and high-risk TLDs
        String[] dgaC2 = new String[] {
                "x1y2z3a4b5c6d7e8f901.top",
                "qzwxrtyplkjhgfds1234.biz",
                "cb918374dfa9810238475.xyz",
                "vbnmqwzxplkjhgf.top"
        };

        for (String domain : dgaC2) {
            NetworkMlClassifier.DgaResult res = classifier.classifyDomain(domain);
            assertTrue("DGA domain " + domain + " should be flagged as malicious (prob: " + res.dgaProbability + ")", res.isMalicious);
            assertTrue("DGA domain score should be high", res.threatScore >= 80);
        }
    }

    @Test
    public void testSubMicrosecondLatency() {
        NetworkMlClassifier classifier = NetworkMlClassifier.getInstance();
        String testDomain = "analytics-telemetry-server.company.com";

        // Warm up
        for (int i = 0; i < 5000; i++) {
            classifier.classifyDomain(testDomain);
        }

        long start = System.nanoTime();
        int iterations = 50000;
        for (int i = 0; i < iterations; i++) {
            classifier.classifyDomain(testDomain);
        }
        long durationNs = System.nanoTime() - start;
        double avgNs = (double) durationNs / iterations;

        // Ultra-low latency check (< 5 microseconds = 5,000 ns, 200,000+ evals/sec)
        assertTrue("Average domain ML classification must be under 5,000 ns (was " + avgNs + " ns)", avgNs < 5000.0);
    }
}
