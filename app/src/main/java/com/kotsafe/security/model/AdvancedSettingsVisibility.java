package com.kotsafe.security.model;

import androidx.preference.Preference;
import androidx.preference.PreferenceGroup;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Presentation policy only. Changing mode does not change protection settings. */
public final class AdvancedSettingsVisibility {
    private AdvancedSettingsVisibility() {}

    private static final Set<String> ADVANCED = new HashSet<>(Arrays.asList(
            "analytics_logs_settings", "cat_traffic_decryption", "cat_p2p_developer_tools",
            "pref_key_use_kotengine_nextgen", "root_capture", "capture_interface", "ip_mode", "vpn_exceptions",
            "cat_router_automation", "cat_streaming_pcap", "socks5_settings", "wireguard_tunnel_settings",
            "netguard_firewall_settings", "adguard_dns_settings", "cat_ai_provider_config", "cat_ai_access_levels",
            "pref_detection_rules_enabled", "pcapng_format", "dump_extensions", "dump_extensions_how_to",
            "filename_prefix", "control_permissions", "dns_v4", "dns_v6", "pref_dnscrypt_guide", "dnscrypt_link",
            "pref_dns_speed_test", "max_connections", "full_payload", "tls_decryption", "mitm_setup_wizard",
            "mitmproxy_opts", "block_quic_mode", "auto_block_private_dns", "hide_system_traffic", "geolocation",
            "http_server_port", "collector_host", "collector_port", "port_mapping", "upnp_auto_port_map",
            "wake_on_lan_tool", "kotsafe_cloud_test_connection", "auto_threat_feed_sync", "threat_feed_sync_now",
            "auto_threat_query_during_scan", "personal_gateway_relay_category", "personal_gateway_ai_category",
            "personal_gateway_local_service_access", "personal_gateway_transport_mode", "personal_gateway_telemetry_category",
            "pref_traffic_stats", "pref_app_log", "storage_management",
            "personal_gateway_relay_mode", "personal_gateway_custom_relay_url"));

    public static boolean isAdvancedOnly(String key) {
        return key != null && (ADVANCED.contains(key) || key.startsWith("otx_")
                || key.startsWith("virustotal_") || key.startsWith("urlhaus_")
                || key.startsWith("threatfox_") || key.startsWith("malwarebazaar_")
                || key.startsWith("pref_siem_") || key.startsWith("siem_")
                || key.startsWith("pref_enterprise_location_") || key.equals("pref_attach_location_to_siem_alerts")
                || key.equals("pref_action_share_live_location"));
    }

    public static void apply(PreferenceGroup group, boolean advanced) {
        if (group == null) return;
        for (int i = 0; i < group.getPreferenceCount(); i++) {
            Preference preference = group.getPreference(i);
            if (advanced) {
                Boolean original = HIDDEN.remove(preference);
                if (original != null) preference.setVisible(original);
            } else if (isAdvancedOnly(preference.getKey())) {
                HIDDEN.putIfAbsent(preference, preference.isVisible());
                preference.setVisible(false);
            }
            if (preference instanceof PreferenceGroup) {
                PreferenceGroup children = (PreferenceGroup) preference;
                apply(children, advanced);
                boolean anyVisible = false;
                for (int j = 0; j < children.getPreferenceCount(); j++) {
                    if (children.getPreference(j).isVisible()) anyVisible = true;
                }
                if (!advanced && !anyVisible) {
                    HIDDEN.putIfAbsent(children, children.isVisible());
                    children.setVisible(false);
                }
            }
        }
    }
    private static final java.util.Map<Preference, Boolean> HIDDEN = new java.util.WeakHashMap<>();
}
