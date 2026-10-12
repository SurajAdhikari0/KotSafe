/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * MitreMapper
 * ===========
 * Maps multi-domain causal evidence chains to standard MITRE ATT&CK for Mobile
 * tactics and techniques, providing structured context for the AI analyst.
 */

package com.kotsafe.security.security.mitre;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class MitreMapper {
    public static class TechniqueInfo {
        public final String techniqueId;
        public final String name;
        public final String tactic;
        public final String description;

        public TechniqueInfo(String id, String name, String tactic, String description) {
            this.techniqueId = id;
            this.name = name;
            this.tactic = tactic;
            this.description = description;
        }
    }

    private static final Map<String, TechniqueInfo> sTechniques = new HashMap<>();

    static {
        sTechniques.put("BANKING_TROJAN", new TechniqueInfo(
                "T1437", "Application Layer Protocol / Screenjacking", "Command and Control / Credential Access",
                "Malware uses accessibility service and overlay injection to harvest credentials and intercept 2FA tokens."
        ));
        sTechniques.put("PHYSICAL_TAMPER", new TechniqueInfo(
                "T1458", "Exploitation for Privilege Escalation / Hardware Interfacing", "Initial Access",
                "Physical BadUSB / HID device emulation injecting keystrokes over USB-OTG."
        ));
        sTechniques.put("SIM_HIJACK", new TechniqueInfo(
                "T1516", "Input Capture / SIM Swapping", "Credential Access",
                "Physical removal or swapping of the subscriber identity module to bypass SMS 2FA authentication."
        ));
        sTechniques.put("SLEEPER_DROPPER", new TechniqueInfo(
                "T1407", "Download New Code at Runtime", "Defense Evasion",
                "Application disguises itself as harmless, requesting install permissions and connecting to C2 for dynamic payloads."
        ));
        sTechniques.put("SURVEILLANCE_SPYWARE", new TechniqueInfo(
                "T1430", "Location Tracking / Audio Surveillance", "Collection",
                "Application records background audio, camera, or continuous GPS location without user consent."
        ));
    }

    public static TechniqueInfo mapPattern(String patternType) {
        if (patternType == null) return null;
        return sTechniques.get(patternType.toUpperCase());
    }

    public static Map<String, TechniqueInfo> getAllTechniques() {
        return Collections.unmodifiableMap(sTechniques);
    }
}
