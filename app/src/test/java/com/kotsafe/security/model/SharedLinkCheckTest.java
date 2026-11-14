package com.kotsafe.security.model;

import static org.junit.Assert.*;
import java.io.IOException;
import java.util.Collections;
import org.junit.Test;

public class SharedLinkCheckTest {
    private SharedLinkCheck.Result check(String text, String type, String value) throws IOException {
        return SharedLinkCheck.match(SharedLinkCheck.extract(text), Collections.singletonList(
                new IntelligenceManifestV2Verifier.Indicator("fixture",type,value,200)));
    }

    @Test public void exactUrlDoesNotFlagOtherPagesOnSameHost() throws Exception {
        String rule = "https://host.invalid/bad?case=A";
        assertEquals(SharedLinkCheck.Result.MATCH,check("Shared link: "+rule+"#part","url",rule));
        assertEquals(SharedLinkCheck.Result.UNKNOWN,check("https://host.invalid/good","url",rule));
    }

    @Test public void hostAndIpChecksAreExact() throws Exception {
        assertEquals(SharedLinkCheck.Result.MATCH,check("https://EXAMPLE.invalid/path","domain","example.invalid"));
        assertEquals(SharedLinkCheck.Result.UNKNOWN,check("https://example.invalid.fake/","domain","example.invalid"));
        assertEquals(SharedLinkCheck.Result.MATCH,check("https://[2001:db8::1]/","ip","2001:db8::1"));
    }

    @Test public void messageParenthesesPreserveTheExactLink() throws Exception {
        assertEquals(SharedLinkCheck.Result.MATCH,check("see (https://host.invalid/a(b))","url","https://host.invalid/a(b)"));
        assertEquals(SharedLinkCheck.Result.MATCH,check("https://host.invalid/a(b)","url","https://host.invalid/a(b)"));
    }

    @Test public void missingNetworkCoverageIsReported() throws Exception {
        assertEquals(SharedLinkCheck.Result.UNAVAILABLE,check("https://host.invalid","sha256","fixture"));
        assertEquals(SharedLinkCheck.Result.UNAVAILABLE,SharedLinkCheck.match("https://host.invalid/",Collections.emptyList()));
    }

    @Test public void rejectsAmbiguousAndInvalidInput() {
        for (String text : new String[]{"two https://one.invalid/ https://two.invalid/", "file:///etc/passwd",
                "https://user:pass@example.invalid", "no links here"}) {
            assertThrows(IOException.class,() -> SharedLinkCheck.extract(text));
        }
    }
}
