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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.collection.ArraySet;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.Billing;
import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.Utils;

import java.util.Set;

public class Prefs {
    public static final String DUMP_NONE = "none";
    public static final String DUMP_HTTP_SERVER = "http_server";
    public static final String DUMP_UDP_EXPORTER = "udp_exporter";
    public static final String DUMP_TCP_EXPORTER = "tcp_exporter";
    public static final String DUMP_PCAP_FILE = "pcap_file";
    public static final String DEFAULT_DUMP_MODE = DUMP_NONE;

    public static final String IP_MODE_IPV4_ONLY = "ipv4";
    public static final String IP_MODE_IPV6_ONLY = "ipv6";
    public static final String IP_MODE_BOTH = "both";
    public static final String IP_MODE_DEFAULT = IP_MODE_IPV4_ONLY;

    public static final String BLOCK_QUIC_MODE_NEVER = "never";
    public static final String BLOCK_QUIC_MODE_ALWAYS = "always";
    public static final String BLOCK_QUIC_MODE_TO_DECRYPT = "to_decrypt";
    public static final String BLOCK_QUIC_MODE_DEFAULT = BLOCK_QUIC_MODE_NEVER;

    public static final String PAYLOAD_MODE_NONE = "none";
    public static final String PAYLOAD_MODE_MINIMAL = "minimal";
    public static final String PAYLOAD_MODE_FULL = "full";
    public static final String DEFAULT_PAYLOAD_MODE = PAYLOAD_MODE_MINIMAL;

    // used to initialize the whitelist with some safe defaults
    public static final int FIREWALL_WHITELIST_INIT_VER = 1;

    // legacy storage key (kept for backwards compatibility with existing user prefs); the value
    // may now be either an IP address or a domain name
    public static final String PREF_COLLECTOR_IP_KEY = "collector_ip_address";
    public static final String PREF_COLLECTOR_HOST_KEY = "collector_host";
    public static final String PREF_COLLECTOR_PORT_KEY = "collector_port";
    public static final String PREF_SOCKS5_PROXY_IP_KEY = "socks5_proxy_ip_address";
    public static final String PREF_SOCKS5_PROXY_HOST_KEY = "socks5_proxy_host";
    public static final String PREF_SOCKS5_PROXY_PORT_KEY = "socks5_proxy_port";
    public static final String PREF_CAPTURE_INTERFACE = "capture_interface";
    public static final String PREF_MALWARE_DETECTION = "malware_detection";
    public static final String PREF_FIREWALL = "firewall";
    public static final String PREF_TLS_DECRYPTION_KEY = "tls_decryption";
    public static final String PREF_APP_FILTER = "app_filter";
    public static final String PREF_APP_FILTER_ENABLED = "app_filter_enabled";
    public static final String PREF_HTTP_SERVER_PORT = "http_server_port";
    public static final String PREF_PCAP_DUMP_MODE = "pcap_dump_mode_v2";
    public static final String PREF_IP_MODE = "ip_mode";
    public static final String PREF_APP_LANGUAGE = "app_language";
    public static final String PREF_ROOT_CAPTURE = "root_capture";
    public static final String PREF_VISUALIZATION_MASK = "vis_mask";
    public static final String PREF_MALWARE_WHITELIST = "malware_whitelist";
    public static final String PREF_DUMP_EXTENSIONS = "dump_extensions";
    public static final String PREF_BLOCKLIST = "bl";
    public static final String PREF_FIREWALL_WHITELIST_MODE = "firewall_wl_mode";
    public static final String PREF_FIREWALL_WHITELIST_INIT_VER = "firewall_wl_init";
    public static final String PREF_FIREWALL_WHITELIST = "firewall_whitelist";
    public static final String PREF_FIREWALL_SCREEN_OFF_BLOCK = "firewall_screen_off_block";
    public static final String PREF_DECRYPTION_LIST = "decryption_list";
    public static final String PREF_START_AT_BOOT = "start_at_boot";
    public static final String PREF_SNAPLEN = "snaplen";
    public static final String PREF_MAX_PKTS_PER_FLOW = "max_pkts_per_flow";
    public static final String PREF_MAX_DUMP_SIZE = "max_dump_size";
    public static final String PREF_SOCKS5_ENABLED_KEY = "socks5_enabled";
    public static final String PREF_SOCKS5_AUTH_ENABLED_KEY = "socks5_auth_enabled";
    public static final String PREF_SOCKS5_USERNAME_KEY = "socks5_username";
    public static final String PREF_SOCKS5_PASSWORD_KEY = "socks5_password";
    public static final String PREF_TLS_DECRYPTION_SETUP_DONE = "tls_decryption_setup_ok";
    public static final String PREF_CA_INSTALLATION_SKIPPED = "ca_install_skipped";
    public static final String PREF_FULL_PAYLOAD = "full_payload";
    public static final String PREF_HIDE_SYSTEM_TRAFFIC = "hide_system_traffic";
    public static final String PREF_GROUP_BY_APP = "group_by_app";
    public static final String PREF_AUTO_MOVE_CLOSED = "auto_move_closed";
    public static final String PREF_BLOCK_QUIC = "block_quic_mode";
    public static final String PREF_AUTO_BLOCK_PRIVATE_DNS = "auto_block_private_dns";
    public static final String PREF_APP_VERSION = "appver";
    public static final String PREF_LOCKDOWN_VPN_NOTICE_SHOWN = "vpn_lockdown_notice";
    public static final String PREF_VPN_EXCEPTIONS = "vpn_exceptions";
    public static final String PREF_PORT_MAPPING = "port_mapping";
    public static final String PREF_PORT_MAPPING_ENABLED = "port_mapping_enabled";
    public static final String PREF_PORT_MAPPING_EXEMPTIONS = "port_mapping_exemptions";
    public static final String PREF_BLOCK_NEW_APPS = "block_new_apps";
    public static final String PREF_PAYLOAD_NOTICE_ACK = "payload_notice";
    public static final String PREF_REMOTE_COLLECTOR_ACK = "remote_collector_notice";
    public static final String PREF_MITMPROXY_OPTS = "mitmproxy_opts";
    public static final String PREF_DNS_SERVER_V4 = "dns_v4";
    public static final String PREF_DNS_SERVER_V6 = "dns_v6";
    public static final String PREF_USE_SYSTEM_DNS = "system_dns";
    public static final String PREF_PCAPNG_ENABLED = "pcapng_format";
    public static final String PREF_RESTART_ON_DISCONNECT = "restart_on_disconnect";
    public static final String PREF_IGNORED_MITM_VERSION = "ignored_mitm_version";
    public static final String PREF_API_KEY = "api_key";
    public static final String PREF_FILENAME_PREFIX = "filename_prefix";
    public static final String PREF_CAPTURE_LIST = "capture_list";
    public static final String PREF_CONNECTIONS_LOG_SIZE = "max_connections";
    public static final String PREF_LOCAL_NETWORK_NOTICE_SHOWN = "local_network_notice";

    public static final String PREF_ENABLE_ADVANCED_FEATURES = "enable_advanced_features";
    public static final String PREF_USE_KOTENGINE_NEXTGEN = "pref_key_use_kotengine_nextgen";
    public static final boolean DEFAULT_USE_KOTENGINE_NEXTGEN = true;

    // Privacy & Ad Tracker Shield Keys
    public static final String PREF_ADBLOCK_ENABLED = "pref_adblock_enabled";
    public static final String PREF_ADBLOCK_DOH_ENABLED = "pref_adblock_doh_enabled";
    public static final String PREF_ADBLOCK_DOH_PROVIDER = "pref_adblock_doh_provider";
    public static final String PREF_ADBLOCK_AUTO_UPDATE = "pref_adblock_auto_update";

    // Single-Socket Diagnostics (toggle between smart aggregation and raw unaggregated sockets)
    public static final String PREF_SINGLE_SOCKET_DIAGNOSTICS = "single_socket_diagnostics";

    public static boolean isSingleSocketDiagnostics(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx)
                .getBoolean(PREF_SINGLE_SOCKET_DIAGNOSTICS, false);
    }

    public static boolean isSingleSocketDiagnostics(SharedPreferences p) {
        return p.getBoolean(PREF_SINGLE_SOCKET_DIAGNOSTICS, false);
    }

    public static void setSingleSocketDiagnostics(Context ctx, boolean enabled) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putBoolean(PREF_SINGLE_SOCKET_DIAGNOSTICS, enabled).apply();
    }

    public static final String PREF_BROWSER_URL_TERMS_ACCEPTED = "pref_browser_url_terms_accepted";

    public static boolean isBrowserUrlTermsAccepted(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx)
                .getBoolean(PREF_BROWSER_URL_TERMS_ACCEPTED, false);
    }

    public static void setBrowserUrlTermsAccepted(Context ctx, boolean accepted) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit()
                .putBoolean(PREF_BROWSER_URL_TERMS_ACCEPTED, accepted).apply();
    }

    public static boolean isAdvancedFeaturesEnabled(SharedPreferences p) {
        return p.getBoolean(PREF_ENABLE_ADVANCED_FEATURES, false);
    }

    public static boolean isAdBlockEnabled(SharedPreferences p) {
        return p.getBoolean(PREF_ADBLOCK_ENABLED, false);
    }

    public static boolean isAdBlockDohEnabled(SharedPreferences p) {
        return p.getBoolean(PREF_ADBLOCK_DOH_ENABLED, false);
    }

    public static String getAdBlockDohProvider(SharedPreferences p) {
        return p.getString(PREF_ADBLOCK_DOH_PROVIDER, "cloudflare");
    }

    // P2P Personal Exit Node & Gateway Keys
    public static final String PREF_P2P_EXIT_NODE_HOST_ENABLED = "p2p_exit_node_host_enabled";
    public static final String PREF_P2P_EXIT_NODE_HOST_PORT = "p2p_exit_node_host_port";
    public static final String PREF_P2P_EXIT_NODE_HOST_TOKEN = "p2p_exit_node_host_token";
    public static final String PREF_P2P_EXIT_NODE_UPNP_ENABLED = "p2p_exit_node_upnp_enabled";
    public static final String PREF_P2P_EXIT_NODE_CLIENT_ENABLED = "p2p_exit_node_client_enabled";
    public static final String PREF_P2P_EXIT_NODE_CLIENT_HOST = "p2p_exit_node_client_host";
    public static final String PREF_P2P_EXIT_NODE_CLIENT_PORT = "p2p_exit_node_client_port";
    public static final String PREF_P2P_EXIT_NODE_CLIENT_TOKEN = "p2p_exit_node_client_token";
    public static final String PREF_P2P_ALLOW_DECRYPTION = "p2p_allow_traffic_decryption";
    public static final String PREF_P2P_DECRYPTION_KEY = "p2p_traffic_decryption_key";
    public static final String PREF_P2P_HOST_DECRYPTION_KEY = "p2p_host_client_deckey";
    public static final String PREF_P2P_CANDIDATE_ENDPOINTS = "p2p_candidate_endpoints";
    public static final String PREF_P2P_BACKEND_TYPE = "p2p_backend_type";
    public static final String PREF_P2P_BACKEND_CONFIG = "p2p_backend_config";
    public static final String PREF_P2P_DEVICE_ID = "p2p_device_id";
    public static final String PREF_P2P_BACKEND_PAIRING = "p2p_backend_pairing_token";

    // Personal Gateway Keys (v2)
    public static final String PREF_PERSONAL_GATEWAY_EXIT_ENABLED = "personal_gateway_exit_enabled";
    public static final String PREF_PERSONAL_GATEWAY_CLIENT_ENABLED = "personal_gateway_client_enabled";
    public static final String PREF_PERSONAL_GATEWAY_TRANSPORT_MODE = "personal_gateway_transport_mode";
    public static final String PREF_PERSONAL_GATEWAY_KILL_SWITCH = "personal_gateway_kill_switch";
    public static final String PREF_PERSONAL_GATEWAY_PAIRING_BUNDLE = "personal_gateway_pairing_bundle";

    /* The default maximum connections to log into the ConnectionsRegister. Older connections are dropped.
     * Average Java-heap cost is ~2 KB per connection (covers payload-minimal mode and possible new additions);
     * base app overhead is ~8 MB. The user can override this via Prefs.PREF_CONNECTIONS_LOG_SIZE,
     * bounded by the device heap (see Prefs.getMaxConnectionsLogSize). */
    public static final int DEFAULT_CONNECTIONS_LOG_SIZE = 8192;
    public static final int MIN_CONNECTIONS_LOG_SIZE = 1024;

    // Java-heap budget used to derive the max selectable connections log size.
    // Per-connection cost is a conservative average that covers payload-minimal mode.
    private static final long BYTES_PER_CONNECTION = 2L * 1024;
    private static final long HEAP_BASE_OVERHEAD = 8L * 1024 * 1024;
    private static final long HEAP_RESERVE_MIN = 24L * 1024 * 1024;

    public enum DumpMode {
        NONE,
        HTTP_SERVER,
        PCAP_FILE,
        UDP_EXPORTER,
        TCP_EXPORTER
    }

    public enum IpMode {
        IPV4_ONLY,
        IPV6_ONLY,
        BOTH,
    }

    public enum BlockQuicMode {
        NEVER,
        ALWAYS,
        TO_DECRYPT
    }

    public enum PayloadMode {
        NONE,
        MINIMAL,
        FULL
    }

    public static DumpMode getDumpMode(String pref) {
        switch (pref) {
            case DUMP_HTTP_SERVER:      return DumpMode.HTTP_SERVER;
            case DUMP_PCAP_FILE:        return DumpMode.PCAP_FILE;
            case DUMP_UDP_EXPORTER:     return DumpMode.UDP_EXPORTER;
            case DUMP_TCP_EXPORTER:     return DumpMode.TCP_EXPORTER;
            default:                    return DumpMode.NONE;
        }
    }

    public static IpMode getIPMode(String pref) {
        switch (pref) {
            case IP_MODE_IPV6_ONLY:     return IpMode.IPV6_ONLY;
            case IP_MODE_BOTH:          return IpMode.BOTH;
            default:                    return IpMode.IPV4_ONLY;
        }
    }

    public static BlockQuicMode getBlockQuicMode(String pref) {
        switch (pref) {
            case BLOCK_QUIC_MODE_ALWAYS:        return BlockQuicMode.ALWAYS;
            case BLOCK_QUIC_MODE_TO_DECRYPT:    return BlockQuicMode.TO_DECRYPT;
            default:                            return BlockQuicMode.NEVER;
        }
    }

    public static PayloadMode getPayloadMode(String pref) {
        switch (pref) {
            case PAYLOAD_MODE_MINIMAL:  return PayloadMode.MINIMAL;
            case PAYLOAD_MODE_FULL:     return PayloadMode.FULL;
            default:                    return PayloadMode.NONE;
        }
    }

    public static int getAppVersion(SharedPreferences p) {
        return p.getInt(PREF_APP_VERSION, 0);
    }

    public static void refreshAppVersion(SharedPreferences p) {
        p.edit().putInt(PREF_APP_VERSION, BuildConfig.VERSION_CODE).apply();
    }

    public static void setLockdownVpnNoticeShown(SharedPreferences p) {
        p.edit().putBoolean(PREF_LOCKDOWN_VPN_NOTICE_SHOWN, true).apply();
    }

    public static void setFirewallWhitelistInitialized(SharedPreferences p) {
        p.edit().putInt(PREF_FIREWALL_WHITELIST_INIT_VER, FIREWALL_WHITELIST_INIT_VER).apply();
    }

    public static void setPortMappingEnabled(SharedPreferences p, boolean enabled) {
        p.edit().putBoolean(PREF_PORT_MAPPING_ENABLED, enabled).apply();
    }

    public static void setLocalNetworkNoticeShown(SharedPreferences p) {
        p.edit().putBoolean(PREF_LOCAL_NETWORK_NOTICE_SHOWN, true).apply();
    }

    /* Prefs with defaults */
    public static String getCollectorHost(SharedPreferences p) { return(p.getString(PREF_COLLECTOR_HOST_KEY, "127.0.0.1")); }
    public static int getCollectorPort(SharedPreferences p)  { return(Integer.parseInt(p.getString(PREF_COLLECTOR_PORT_KEY, "1234"))); }
    public static DumpMode getDumpMode(SharedPreferences p)  { return(getDumpMode(p.getString(PREF_PCAP_DUMP_MODE, DEFAULT_DUMP_MODE))); }
    public static int getHttpServerPort(SharedPreferences p) { return(Integer.parseInt(p.getString(Prefs.PREF_HTTP_SERVER_PORT, "8080"))); }
    public static boolean getTlsDecryptionEnabled(SharedPreferences p) { return(p.getBoolean(PREF_TLS_DECRYPTION_KEY, false)); }
    public static boolean isKotEngineNextGen(SharedPreferences p) { return true; }
    public static boolean getSocks5Enabled(SharedPreferences p)     { return(p.getBoolean(PREF_SOCKS5_ENABLED_KEY, false)); }
    public static String getSocks5ProxyHost(SharedPreferences p)    { return(p.getString(PREF_SOCKS5_PROXY_IP_KEY, "0.0.0.0")); }
    public static int getSocks5ProxyPort(SharedPreferences p)       { return(Integer.parseInt(p.getString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, "8080"))); }
    public static boolean isSocks5AuthEnabled(SharedPreferences p)  { return(p.getBoolean(PREF_SOCKS5_AUTH_ENABLED_KEY, false)); }
    public static String getSocks5Username(SharedPreferences p)     { return(p.getString(PREF_SOCKS5_USERNAME_KEY, "")); }
    public static String getSocks5Password(SharedPreferences p)     { return(p.getString(PREF_SOCKS5_PASSWORD_KEY, "")); }
    public static Set<String> getAppFilter(SharedPreferences p)     { return(isAppFilterEnabled(p) ? getAppFilterRaw(p) : new ArraySet<>()); }
    public static Set<String> getAppFilterRaw(SharedPreferences p)  { return(getStringSet(p, PREF_APP_FILTER)); }
    public static boolean isAppFilterEnabled(SharedPreferences p)   { return(p.getBoolean(PREF_APP_FILTER_ENABLED, true)); }
    public static IpMode getIPMode(SharedPreferences p)          { return(getIPMode(p.getString(PREF_IP_MODE, IP_MODE_DEFAULT))); }
    public static BlockQuicMode getBlockQuicMode(SharedPreferences p) { return(getBlockQuicMode(p.getString(PREF_BLOCK_QUIC, BLOCK_QUIC_MODE_DEFAULT))); }
    public static String getAppLocale(SharedPreferences p) {
        String lang = p.getString(PREF_APP_LANGUAGE, "system");
        if ("system".equals(lang))
            return null;
        return lang;
    }
    public static boolean isRootCaptureEnabled(SharedPreferences p) { return(Utils.isRootAvailable() && p.getBoolean(PREF_ROOT_CAPTURE, false)); }
    public static boolean isCaptureMetadataEnabled(SharedPreferences p) { return(p.getBoolean(PREF_DUMP_EXTENSIONS, false)); }
    @Deprecated public static boolean isPcapdroidMetadataEnabled(SharedPreferences p) { return isCaptureMetadataEnabled(p); }
    public static String getCaptureInterface(SharedPreferences p) { return(p.getString(PREF_CAPTURE_INTERFACE, "@inet")); }
    public static boolean isMalwareDetectionEnabled(Context ctx, SharedPreferences p) {
        return(Billing.newInstance(ctx).isPurchased(Billing.MALWARE_DETECTION_SKU)
                && p.getBoolean(PREF_MALWARE_DETECTION, true));
    }
    public static boolean isFirewallEnabled(Context ctx, SharedPreferences p) {
        // NOTE: firewall can be disabled at runtime
        return(Billing.newInstance(ctx).isFirewallVisible()
                && p.getBoolean(PREF_FIREWALL, true));
    }
    public static boolean isPcapngEnabled(Context ctx, SharedPreferences p)  {
        return(Billing.newInstance(ctx).isPurchased(Billing.PCAPNG_SKU)
                && p.getBoolean(PREF_PCAPNG_ENABLED, true));
    }
    public static boolean startAtBoot(SharedPreferences p)        { return(p.getBoolean(PREF_START_AT_BOOT, true)); }
    public static boolean restartOnDisconnect(SharedPreferences p)        { return(p.getBoolean(PREF_RESTART_ON_DISCONNECT, false)); }
    public static boolean isTLSDecryptionSetupDone(SharedPreferences p)     { return(p.getBoolean(PREF_TLS_DECRYPTION_SETUP_DONE, false)); }
    public static boolean getFullPayloadMode(SharedPreferences p) { return(p.getBoolean(PREF_FULL_PAYLOAD, false)); }
    public static boolean isHideSystemTraffic(SharedPreferences p) { return(p.getBoolean(PREF_HIDE_SYSTEM_TRAFFIC, false)); }
    public static boolean isGroupByApp(SharedPreferences p) { return(p.getBoolean(PREF_GROUP_BY_APP, true)); }
    public static boolean isAutoMoveClosed(SharedPreferences p) { return(p.getBoolean(PREF_AUTO_MOVE_CLOSED, true)); }
    public static boolean isPrivateDnsBlockingEnabled(SharedPreferences p) { return(p.getBoolean(PREF_AUTO_BLOCK_PRIVATE_DNS, true)); }
    public static boolean lockdownVpnNoticeShown(SharedPreferences p)      { return(p.getBoolean(PREF_LOCKDOWN_VPN_NOTICE_SHOWN, false)); }
    public static boolean blockNewApps(SharedPreferences p)       { return(p.getBoolean(PREF_BLOCK_NEW_APPS, false)); }
    public static boolean isFirewallWhitelistMode(SharedPreferences p)     { return(p.getBoolean(PREF_FIREWALL_WHITELIST_MODE, false)); }
    public static boolean isFirewallScreenOffBlock(SharedPreferences p)     { return(p.getBoolean(PREF_FIREWALL_SCREEN_OFF_BLOCK, false)); }
    public static boolean isFirewallWhitelistInitialized(SharedPreferences p) { return(p.getInt(PREF_FIREWALL_WHITELIST_INIT_VER, 0) == FIREWALL_WHITELIST_INIT_VER); }
    public static String getMitmproxyOpts(SharedPreferences p)    { return(p.getString(PREF_MITMPROXY_OPTS, "")); }
    public static boolean isPortMappingEnabled(SharedPreferences p) { return(p.getBoolean(PREF_PORT_MAPPING_ENABLED, true)); }
    public static boolean useSystemDns(SharedPreferences p)     { return(p.getBoolean(PREF_USE_SYSTEM_DNS, true)); }
    public static String getDnsServerV4(SharedPreferences p)    { return(p.getString(PREF_DNS_SERVER_V4, "1.1.1.1")); }
    public static String getDnsServerV6(SharedPreferences p)    { return(p.getString(PREF_DNS_SERVER_V6, "2606:4700:4700::1111")); }
    public static boolean isIgnoredMitmVersion(SharedPreferences p, String v) { return p.getString(PREF_IGNORED_MITM_VERSION, "").equals(v); }
    public static String getApiKey(SharedPreferences p)         { return(p.getString(PREF_API_KEY, "")); }
    public static String getFilenamePrefix(SharedPreferences p)     { return(p.getString(PREF_FILENAME_PREFIX, "KotSafe_")); }
    public static boolean localNetworkNoticeShown(SharedPreferences p)      { return(p.getBoolean(PREF_LOCAL_NETWORK_NOTICE_SHOWN, false)); }

    // Largest connections log size the current device's Java heap can safely host.
    // Rounded down to a power of two for a user-friendly dropdown.
    public static int getMaxConnectionsLogSize() {
        long heap = Runtime.getRuntime().maxMemory();
        long reserve = Math.max(HEAP_RESERVE_MIN, heap * 15 / 100);
        long available = heap - HEAP_BASE_OVERHEAD - reserve;
        if (available < (long) MIN_CONNECTIONS_LOG_SIZE * BYTES_PER_CONNECTION)
            return MIN_CONNECTIONS_LOG_SIZE;

        long maxConn = available / BYTES_PER_CONNECTION;
        int rounded = Integer.highestOneBit((int) Math.min(maxConn, Integer.MAX_VALUE));
        return Math.max(rounded, MIN_CONNECTIONS_LOG_SIZE);
    }

    public static int getConnectionsLogSize(SharedPreferences p) {
        int val;
        try {
            val = Integer.parseInt(p.getString(PREF_CONNECTIONS_LOG_SIZE, String.valueOf(DEFAULT_CONNECTIONS_LOG_SIZE)));
        } catch (NumberFormatException e) {
            val = DEFAULT_CONNECTIONS_LOG_SIZE;
        }

        int max = getMaxConnectionsLogSize();
        if (val > max)
            val = max;
        if (val < MIN_CONNECTIONS_LOG_SIZE)
            val = MIN_CONNECTIONS_LOG_SIZE;
        return val;
    }

    public static void setConnectionsLogSize(SharedPreferences p, int size) {
        int max = getMaxConnectionsLogSize();
        if (size > max)
            size = max;
        if (size < MIN_CONNECTIONS_LOG_SIZE)
            size = MIN_CONNECTIONS_LOG_SIZE;

        p.edit().putString(PREF_CONNECTIONS_LOG_SIZE, String.valueOf(size)).apply();

        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null) {
            reg.setSize(size);
        }
    }

    // Gets a StringSet from the prefs
    // The preference should either be a StringSet or a String
    // An empty set is returned as the default value
    @SuppressLint("MutatingSharedPrefs")
    public static @NonNull Set<String> getStringSet(SharedPreferences p, String key) {
        Set<String> rv = null;

        try {
            rv = p.getStringSet(key, null);
        } catch (ClassCastException e) {
            // retry with string
            String s = p.getString(key, "");

            if (!s.isEmpty()) {
                rv = new ArraySet<>();
                rv.add(s);
            }
        }

        if (rv == null)
            rv = new ArraySet<>();

        return rv;
    }

    public static String asString(Context ctx) {
        SharedPreferences p = PreferenceManager.getDefaultSharedPreferences(ctx);

        // NOTE: possibly sensitive info like the collector IP address not shown
        return "DumpMode: " + getDumpMode(p) +
                "\nFullPayload: " + getFullPayloadMode(p) +
                "\nTLSDecryption: " + getTlsDecryptionEnabled(p) +
                "\nTLSSetupOk: " + isTLSDecryptionSetupDone(p) +
                "\nCAInstallSkipped: " + MitmAddon.isCAInstallationSkipped(ctx) +
                "\nBlockQuic: " + getBlockQuicMode(p) +
                "\nRootCapture: " + isRootCaptureEnabled(p) +
                "\nSocks5: " + getSocks5Enabled(p) +
                "\nBlockPrivateDns: " + isPrivateDnsBlockingEnabled(p) +
                "\nCaptureInterface: " + getCaptureInterface(p) +
                "\nMalwareDetection: " + isMalwareDetectionEnabled(ctx, p) +
                "\nFirewall: " + isFirewallEnabled(ctx, p) +
                "\nPCAPNG: " + isPcapngEnabled(ctx, p) +
                "\nBlockNewApps: " + blockNewApps(p) +
                "\nTargetApps: " + getAppFilter(p) +
                "\nIpMode: " + getIPMode(p) +
                "\nDumpExtensions: " + isCaptureMetadataEnabled(p) +
                "\nStartAtBoot: " + startAtBoot(p) +
                "\nConnectionsLogSize: " + getConnectionsLogSize(p) +
                "\nThemeMode: " + getThemeMode(ctx);
    }

    public static final String PREF_THEME_MODE = "theme_mode";
    public static final String THEME_MODE_SYSTEM = "system";
    public static final String THEME_MODE_LIGHT = "light";
    public static final String THEME_MODE_DARK = "dark";
    public static final String DEFAULT_THEME_MODE = THEME_MODE_DARK;

    public static String getThemeMode(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(PREF_THEME_MODE, DEFAULT_THEME_MODE);
    }

    public static void setThemeMode(Context ctx, String mode) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putString(PREF_THEME_MODE, mode).apply();
    }

    public static void applyThemeMode(String mode) {
        int nightMode;
        if (THEME_MODE_LIGHT.equals(mode)) {
            nightMode = androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_NO;
        } else if (THEME_MODE_DARK.equals(mode)) {
            nightMode = androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_YES;
        } else {
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                nightMode = androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM;
            } else {
                nightMode = androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_AUTO_BATTERY;
            }
        }
        androidx.appcompat.app.AppCompatDelegate.setDefaultNightMode(nightMode);
    }

    public static final String PREF_DETECTION_RULES_ENABLED = "pref_detection_rules_enabled";
    public static final String PREF_DETECTION_RULES_GITHUB_URL = "pref_detection_rules_github_url";
    public static final String PREF_DETECTION_RULES_LAST_SYNC = "pref_detection_rules_last_sync";

    public static final String PREF_DETECTION_RULES_GITHUB_TOKEN = "pref_detection_rules_github_token";

    public static boolean isDetectionRulesEnabled(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getBoolean(PREF_DETECTION_RULES_ENABLED, false);
    }

    public static void setDetectionRulesEnabled(Context ctx, boolean enabled) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putBoolean(PREF_DETECTION_RULES_ENABLED, enabled).apply();
    }

    public static String getDetectionRulesGithubUrl(Context ctx) {
        String defaultUrl = DetectionRulesManager.DEFAULT_GITHUB_RULES_URL;
        String saved = PreferenceManager.getDefaultSharedPreferences(ctx).getString(PREF_DETECTION_RULES_GITHUB_URL, null);
        if (saved == null || saved.isEmpty() || saved.contains("PCAPdroid") || saved.contains("emanuele-f")) {
            return defaultUrl;
        }
        return saved;
    }

    public static void setDetectionRulesGithubUrl(Context ctx, String url) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putString(PREF_DETECTION_RULES_GITHUB_URL, url).apply();
    }

    public static String getDetectionRulesGithubToken(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getString(PREF_DETECTION_RULES_GITHUB_TOKEN, "");
    }

    public static void setDetectionRulesGithubToken(Context ctx, String token) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putString(PREF_DETECTION_RULES_GITHUB_TOKEN, token != null ? token.trim() : "").apply();
    }

    public static long getDetectionRulesLastSyncTime(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getLong(PREF_DETECTION_RULES_LAST_SYNC, 0L);
    }

    public static void setDetectionRulesLastSyncTime(Context ctx, long timeMs) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putLong(PREF_DETECTION_RULES_LAST_SYNC, timeMs).apply();
    }

    public static final String PREF_AUTO_QUARANTINE = "pref_auto_quarantine";

    public static boolean isAutoQuarantineEnabled(Context ctx) {
        return PreferenceManager.getDefaultSharedPreferences(ctx).getBoolean(PREF_AUTO_QUARANTINE, false);
    }

    public static void setAutoQuarantineEnabled(Context ctx, boolean enabled) {
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putBoolean(PREF_AUTO_QUARANTINE, enabled).apply();
    }

    public static final String PREF_ENABLE_TRAFFIC_GRAPHS = "pref_enable_traffic_graphs";

    public static boolean isTrafficGraphsEnabled(Context ctx) {
        if (ctx == null) return true;
        return PreferenceManager.getDefaultSharedPreferences(ctx).getBoolean(PREF_ENABLE_TRAFFIC_GRAPHS, true);
    }

    public static void setTrafficGraphsEnabled(Context ctx, boolean enabled) {
        if (ctx == null) return;
        PreferenceManager.getDefaultSharedPreferences(ctx).edit().putBoolean(PREF_ENABLE_TRAFFIC_GRAPHS, enabled).apply();
    }
}

