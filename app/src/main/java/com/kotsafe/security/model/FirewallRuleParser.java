package com.kotsafe.security.model;

import java.net.IDN;
import java.net.InetAddress;
import java.util.List;
import java.util.Locale;

/** Literal policy parsing. Hostnames are never sent through a DNS lookup to create IP rules. */
public final class FirewallRuleParser {
    private FirewallRuleParser() {}

    public static int[] uids(List<String> apps, java.util.function.ToIntFunction<String> resolvePackage) {
        java.util.Set<Integer> result = new java.util.LinkedHashSet<>();
        for (String app : apps) {
            if (app == null) throw new IllegalArgumentException("Missing app rule");
            app = app.trim();
            int uid;
            if (app.matches("[0-9]+")) {
                uid = Integer.parseInt(app);
            } else {
                if (!app.matches("[a-zA-Z_][a-zA-Z0-9_]*(?:\\.[a-zA-Z_][a-zA-Z0-9_]*)*"))
                    throw new IllegalArgumentException("Invalid app rule");
                uid = resolvePackage.applyAsInt(app);
            }
            // An uninstalled package contributes no UID; never invent an exception for it.
            if (uid >= 0) result.add(uid);
        }
        int[] values = new int[result.size()];
        int index = 0;
        for (int uid : result) values[index++] = uid;
        return values;
    }

    public static String ip(String value) {
        if (value == null) return null;
        String[] parts = value.trim().split("/", -1);
        if (parts.length > 2) return null;
        String literal = parts[0];
        if (literal.isEmpty() || !literal.matches("[0-9a-fA-F:.]+")) return null;
        int family;
        try {
            if (literal.contains(":")) {
                if (literal.contains(".")) return null; // Keep IPv4-mapped forms unambiguous.
                byte[] bytes = InetAddress.getByName(literal).getAddress();
                if (bytes.length != 16) return null;
                literal = InetAddress.getByAddress(bytes).getHostAddress();
                family = 6;
            } else {
                String[] octets = literal.split("\\.", -1);
                if (octets.length != 4) return null;
                for (String octet : octets) {
                    if (!octet.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(octet) > 255) return null;
                }
                family = 4;
            }
            int prefix = family == 4 ? 32 : 128;
            if (parts.length == 2) {
                if (!parts[1].matches("[0-9]{1,3}")) return null;
                prefix = Integer.parseInt(parts[1]);
                if (prefix > (family == 4 ? 32 : 128)) return null;
            }
            return literal + "/" + prefix;
        } catch (Exception invalid) {
            return null;
        }
    }

    public static String domain(String value) {
        if (value == null) return null;
        String host = value.trim();
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        try { host = IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT); }
        catch (IllegalArgumentException invalid) { return null; }
        if (host.isEmpty() || host.length() > 253 || ip(host) != null) return null;
        for (String label : host.split("\\.", -1)) {
            if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) return null;
        }
        return host;
    }

    public static void feedLine(String line, List<String> hosts, List<String> ips) {
        String text = line.split("#", 2)[0].trim();
        if (text.isEmpty() || text.startsWith("//")) return;
        String[] tokens = text.split("\\s+");
        if (tokens.length > 1 && (tokens[0].equals("0.0.0.0") || tokens[0].equals("127.0.0.1") || tokens[0].equals("::"))) {
            for (int i = 1; i < tokens.length; i++) {
                String host = domain(tokens[i]);
                if (host != null && host.contains(".")) hosts.add(host);
            }
        } else if (tokens.length == 1) {
            String address = ip(text);
            if (address != null) ips.add(address);
            else {
                String host = domain(text);
                // Do not turn a malformed numeric IP/CIDR into a domain rule.
                if (host != null && host.contains(".") && !text.matches("[0-9.]+") && !text.contains("/")) hosts.add(host);
            }
        }
    }
}
