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

package com.kotsafe.security.ai;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Maps Android capabilities and structural findings to standard MITRE ATT&CK Mobile Tactics & Techniques.
 */
public class MitreAttackMapper {

    public static class MitreTechnique {
        public final String id;
        public final String name;
        public final String tactic;
        public final String description;

        public MitreTechnique(String id, String name, String tactic, String description) {
            this.id = id;
            this.name = name;
            this.tactic = tactic;
            this.description = description;
        }

        @Override
        public String toString() {
            return "[" + id + " " + name + "] (" + tactic + ")";
        }
    }

    public static List<MitreTechnique> mapTechniques(List<String> capabilities) {
        if (capabilities == null || capabilities.isEmpty()) {
            return Collections.emptyList();
        }

        List<MitreTechnique> list = new ArrayList<>();
        for (String cap : capabilities) {
            String lower = cap.toLowerCase();

            if (lower.contains("accessibility") || lower.contains("overlay")) {
                list.add(new MitreTechnique("T1417", "Input Capture", "Credential Access",
                        "Abusing Accessibility services or window overlays to intercept keystrokes and PINs."));
            }
            if (lower.contains("sms") || lower.contains("2fa")) {
                list.add(new MitreTechnique("T1412", "Capture SMS Data", "Collection",
                        "Intercepting SMS messages to harvest two-factor authentication (2FA) verification codes."));
            }
            if (lower.contains("dynamic") || lower.contains("dexclassloader") || lower.contains("packer")) {
                list.add(new MitreTechnique("T1406", "Obfuscated Files or Information", "Defense Evasion",
                        "Loading secondary unvetted bytecode at runtime or concealing executable payload in encrypted assets."));
            }
            if (lower.contains("shell") || lower.contains("root") || lower.contains("process")) {
                list.add(new MitreTechnique("T1404", "Exploitation for Privilege Escalation", "Privilege Escalation",
                        "Spawning root shell binaries (/system/bin/su) to bypass Android application sandbox confinement."));
            }
            if (lower.contains("audio") || lower.contains("camera") || lower.contains("recording")) {
                list.add(new MitreTechnique("T1429", "Audio Capture", "Collection",
                        "Activating device microphone or camera without prominent foreground notification."));
            }
            if (lower.contains("location")) {
                list.add(new MitreTechnique("T1430", "Location Tracking", "Collection",
                        "Harvesting continuous GPS/network geolocation coordinates."));
            }
            if (lower.contains("fingerprint") || lower.contains("device id") || lower.contains("imei")) {
                list.add(new MitreTechnique("T1426", "Device Serial / Hardware Identifier", "Discovery",
                        "Extracting hardware identifiers (IMEI, IMSI, Android ID) for permanent device tracking."));
            }
            if (lower.contains("boot") || lower.contains("autostart")) {
                list.add(new MitreTechnique("T1402", "Broadcast Receivers", "Persistence",
                        "Registering BOOT_COMPLETED handlers to ensure background execution after reboot."));
            }
        }
        return list;
    }
}
