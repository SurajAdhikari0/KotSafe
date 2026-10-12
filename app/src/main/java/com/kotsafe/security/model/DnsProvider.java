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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class DnsProvider implements Serializable {
    public enum Category {
        ALL("All"),
        SPEED_PRIVACY("Speed & Privacy"),
        SECURITY("Security"),
        ADBLOCK("Tracker Shield"),
        FAMILY("Family Safe");

        private final String title;
        Category(String title) {
            this.title = title;
        }

        public String getTitle() {
            return title;
        }
    }

    private final String id;
    private final String name;
    private final Category category;
    private final String primaryIpv4;
    private final String secondaryIpv4;
    private final String primaryIpv6;
    private final String dohUrl;
    private final String description;
    private final boolean hasAdBlock;
    private final boolean hasMalwareProtection;
    private final boolean hasDoH;

    public DnsProvider(String id, String name, Category category,
                       String primaryIpv4, String secondaryIpv4, String primaryIpv6,
                       String dohUrl, String description,
                       boolean hasAdBlock, boolean hasMalwareProtection, boolean hasDoH) {
        this.id = id;
        this.name = name;
        this.category = category;
        this.primaryIpv4 = primaryIpv4;
        this.secondaryIpv4 = secondaryIpv4;
        this.primaryIpv6 = primaryIpv6;
        this.dohUrl = dohUrl;
        this.description = description;
        this.hasAdBlock = hasAdBlock;
        this.hasMalwareProtection = hasMalwareProtection;
        this.hasDoH = hasDoH;
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public Category getCategory() { return category; }
    public String getPrimaryIpv4() { return primaryIpv4; }
    public String getSecondaryIpv4() { return secondaryIpv4; }
    public String getPrimaryIpv6() { return primaryIpv6; }
    public String getDohUrl() { return dohUrl; }
    public String getDescription() { return description; }
    public boolean hasAdBlock() { return hasAdBlock; }
    public boolean hasMalwareProtection() { return hasMalwareProtection; }
    public boolean hasDoH() { return hasDoH; }

    private static final List<DnsProvider> PRESETS = new ArrayList<>();

    static {
        PRESETS.add(new DnsProvider(
                "cloudflare",
                "Cloudflare",
                Category.SPEED_PRIVACY,
                "1.1.1.1",
                "1.0.0.1",
                "2606:4700:4700::1111",
                "https://cloudflare-dns.com/dns-query",
                "High speed, zero-logging DNS powered by Cloudflare edge network.",
                false,
                false,
                true
        ));

        PRESETS.add(new DnsProvider(
                "quad9",
                "Quad9 Secure",
                Category.SECURITY,
                "9.9.9.9",
                "149.112.112.112",
                "2620:fe::fe",
                "https://dns.quad9.net/dns-query",
                "Blocks malware, phishing, and spyware using global threat intelligence.",
                false,
                true,
                true
        ));

        PRESETS.add(new DnsProvider(
                "adguard",
                "AdGuard DNS",
                Category.ADBLOCK,
                "94.140.14.14",
                "94.140.15.15",
                "2a10:50c0::ad1:ff",
                "https://dns.adguard-dns.com/dns-query",
                "Blocks tracking counters, telemetry, and malicious domains device-wide.",
                true,
                true,
                true
        ));

        PRESETS.add(new DnsProvider(
                "google",
                "Google Public DNS",
                Category.SPEED_PRIVACY,
                "8.8.8.8",
                "8.8.4.4",
                "2001:4860:4860::8888",
                "https://dns.google/dns-query",
                "Fast, resilient and geographically distributed anycast DNS infrastructure.",
                false,
                false,
                true
        ));

        PRESETS.add(new DnsProvider(
                "mullvad",
                "Mullvad DNS (Tracker Shield)",
                Category.ADBLOCK,
                "194.242.2.3",
                "194.242.2.4",
                "2a07:e340::3",
                "https://adblock.doh.mullvad.net/dns-query",
                "Strict privacy, zero logs with tracker and telemetry filtering by Mullvad VPN.",
                true,
                true,
                true
        ));

        PRESETS.add(new DnsProvider(
                "controld",
                "Control D",
                Category.SECURITY,
                "76.76.2.2",
                "76.76.10.2",
                "2606:1a40::2",
                "https://freedns.controld.com/p2",
                "Blocks malware, phishing, scam sites, and cryptojackers.",
                false,
                true,
                true
        ));

        PRESETS.add(new DnsProvider(
                "cleanbrowsing",
                "CleanBrowsing Family",
                Category.FAMILY,
                "185.228.168.168",
                "185.228.169.168",
                "2a0d:2a00:1::",
                "https://doh.cleanbrowsing.org/doh/family-filter/",
                "Blocks adult content, phishing, and enforces SafeSearch on search engines.",
                false,
                true,
                true
        ));

        PRESETS.add(new DnsProvider(
                "opendns",
                "OpenDNS Umbrella",
                Category.SPEED_PRIVACY,
                "208.67.222.222",
                "208.67.220.220",
                "2620:119:35::35",
                "https://doh.opendns.com/dns-query",
                "Cisco Umbrella anycast resolver with high uptime and phishing protection.",
                false,
                true,
                true
        ));
    }

    @NonNull
    public static List<DnsProvider> getPresets() {
        return Collections.unmodifiableList(PRESETS);
    }

    @Nullable
    public static DnsProvider findById(@NonNull String id) {
        for (DnsProvider p : PRESETS) {
            if (p.getId().equalsIgnoreCase(id)) {
                return p;
            }
        }
        return null;
    }

    @Nullable
    public static DnsProvider findByIpv4(@Nullable String ip) {
        if (ip == null || ip.isEmpty()) return null;
        for (DnsProvider p : PRESETS) {
            if (p.getPrimaryIpv4().equals(ip) || p.getSecondaryIpv4().equals(ip)) {
                return p;
            }
        }
        return null;
    }
}
