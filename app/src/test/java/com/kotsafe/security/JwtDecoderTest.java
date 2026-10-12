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
 *
 * Copyright 2026 - KotSafe
 */

package com.kotsafe.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.kotsafe.security.decoders.JwtDecoder;

import org.junit.Test;

public class JwtDecoderTest {

    // Valid JWT with:
    // Header: {"alg":"HS256","typ":"JWT"}
    // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022,"exp":9999999999,"iss":"auth.example.com","aud":"netpdroid"}
    private static final String VALID_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjk5OTk5OTk5OTksImlzcyI6ImF1dGguZXhhbXBsZS5jb20iLCJhdWQiOiJuZXRwZHJvaWQifQ.4gtfM2d8X_vIeR2L7v2j8o5n1m3q4p5r6s7t8u9v0wA";

    // Expired JWT with exp=100000 (year 1970)
    // Payload: {"sub":"user1","exp":100000}
    private static final String EXPIRED_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsImV4cCI6MTAwMDAwfQ.dGVzdHNpZ25hdHVyZQ";

    // Insecure token with alg: none
    // Header: {"alg":"none","typ":"JWT"}
    // Payload: {"sub":"admin"}
    private static final String NONE_ALG_TOKEN = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.";

    @Test
    public void testValidJwtParsing() {
        JwtDecoder.JwtTokenInfo jwt = JwtDecoder.parse(VALID_TOKEN);
        assertNotNull(jwt);
        assertEquals("HS256", jwt.algorithm);
        assertEquals("JWT", jwt.tokenType);
        assertEquals("1234567890", jwt.subject);
        assertEquals("auth.example.com", jwt.issuer);
        assertEquals("netpdroid", jwt.audience);
        assertEquals(Long.valueOf(9999999999L), jwt.expirationTimeSeconds);
        assertEquals(JwtDecoder.TokenStatus.VALID, jwt.status);
    }

    @Test
    public void testExpiredJwt() {
        JwtDecoder.JwtTokenInfo jwt = JwtDecoder.parse(EXPIRED_TOKEN);
        assertNotNull(jwt);
        assertEquals("user1", jwt.subject);
        assertEquals(JwtDecoder.TokenStatus.EXPIRED, jwt.status);
    }

    @Test
    public void testInsecureNoneAlgorithmJwt() {
        JwtDecoder.JwtTokenInfo jwt = JwtDecoder.parse(NONE_ALG_TOKEN);
        assertNotNull(jwt);
        assertEquals("none", jwt.algorithm);
        assertEquals("admin", jwt.subject);
        assertEquals(JwtDecoder.TokenStatus.INSECURE_NONE, jwt.status);
    }

    @Test
    public void testFindJwtInHttpAuthorizationHeader() {
        String httpPayload = "POST /api/v1/user HTTP/1.1\r\n"
                + "Host: example.com\r\n"
                + "Authorization: Bearer " + VALID_TOKEN + "\r\n"
                + "Content-Type: application/json\r\n\r\n";

        JwtDecoder.JwtTokenInfo jwt = JwtDecoder.findAndParseJwt(httpPayload);
        assertNotNull(jwt);
        assertEquals("1234567890", jwt.subject);
        assertEquals("HS256", jwt.algorithm);
    }

    @Test
    public void testFindJwtInJsonBody() {
        String jsonBody = "{\"status\":\"ok\",\"access_token\":\"" + VALID_TOKEN + "\",\"expires_in\":3600}";

        JwtDecoder.JwtTokenInfo jwt = JwtDecoder.findAndParseJwt(jsonBody);
        assertNotNull(jwt);
        assertEquals("auth.example.com", jwt.issuer);
    }

    @Test
    public void testInvalidStringReturnsNull() {
        assertNull(JwtDecoder.parse("not.a.valid.jwt.at.all"));
        assertNull(JwtDecoder.findAndParseJwt("regular HTTP text with no JWT tokens inside"));
    }
}
