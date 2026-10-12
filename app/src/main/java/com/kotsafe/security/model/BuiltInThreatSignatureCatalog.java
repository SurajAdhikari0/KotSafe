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

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Initial built-in signature layer for known bad hashes.
 *
 * This is intentionally small and deterministic so the app can flag clearly known bad
 * artifact hashes before full cloud or YARA-based threat intel is available. It is not a
 * replacement for a production malware feed, but it gives the project the first real
 * signature-based detection layer.
 */
public final class BuiltInThreatSignatureCatalog {
    private BuiltInThreatSignatureCatalog() {}

    public static final class SignatureRule {
        public final String hash;
        public final String family;
        public final String reason;
        public final String severity;
        public final int priority;

        public SignatureRule(String hash, String family, String reason, String severity, int priority) {
            this.hash = hash;
            this.family = family;
            this.reason = reason;
            this.severity = severity;
            this.priority = priority;
        }
    }

    private static final Map<String, SignatureRule> RULES = createCatalog();

    private static Map<String, SignatureRule> createCatalog() {
        Map<String, SignatureRule> map = new HashMap<>();
        String seedHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        map.put(seedHash, new SignatureRule(
                seedHash,
                "SEED_MALWARE_SIGNATURE",
                "Seed signature loaded from the built-in catalog.",
                "MALICIOUS",
                SecurityRulesDb.PRIORITY_TI
        ));
        return Collections.unmodifiableMap(map);
    }

    public static SignatureRule lookup(String value) {
        if (value == null || value.trim().isEmpty()) return null;

        String normalized = value.trim()
                .replace("SHA256:", "")
                .replace("sha256:", "")
                .replace("\"", "")
                .replace("'", "")
                .toLowerCase(Locale.US);

        if (normalized.length() != 64 || !normalized.matches("[0-9a-f]+")) {
            return null;
        }
        return RULES.get(normalized);
    }

    public static boolean isKnownMalwareHash(String value) {
        return lookup(value) != null;
    }
}
