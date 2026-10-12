package com.kotsafe.security.activities.prefs;

import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class SettingsSearchDialog extends BottomSheetDialogFragment {
    public static final String TAG = "SettingsSearchDialog";

    public enum ActionType {
        SCROLL,
        FRAGMENT,
        ACTIVITY,
        LANGUAGE
    }

    public static class SearchItem {
        public final String key;
        public final String title;
        public final String summary;
        public final String category;
        public final int iconRes;
        public final ActionType actionType;
        public final Class<?> targetClass;
        public final String keywords;

        public SearchItem(String key, String title, String summary, String category, int iconRes,
                          ActionType actionType, Class<?> targetClass, String keywords) {
            this.key = key;
            this.title = title;
            this.summary = summary;
            this.category = category;
            this.iconRes = iconRes;
            this.actionType = actionType;
            this.targetClass = targetClass;
            this.keywords = keywords != null ? keywords : "";
        }
    }

    public interface OnSearchItemSelectedListener {
        void onSearchItemSelected(SearchItem item);
    }

    private OnSearchItemSelectedListener mListener;
    private final List<SearchItem> mAllItems = new ArrayList<>();
    private final List<SearchItem> mFilteredItems = new ArrayList<>();
    private SearchAdapter mAdapter;
    private TextView mTvNoResults;

    public static SettingsSearchDialog newInstance() {
        return new SettingsSearchDialog();
    }

    public void setOnSearchItemSelectedListener(OnSearchItemSelectedListener listener) {
        mListener = listener;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        BottomSheetDialog dialog = (BottomSheetDialog) super.onCreateDialog(savedInstanceState);
        dialog.setOnShowListener(d -> {
            BottomSheetDialog bsd = (BottomSheetDialog) d;
            FrameLayout bottomSheet = bsd.findViewById(com.google.android.material.R.id.design_bottom_sheet);
            if (bottomSheet != null) {
                BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(bottomSheet);
                behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
                behavior.setSkipCollapsed(true);
            }
        });
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_settings_search, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        initCatalog(requireContext());

        EditText etSearch = view.findViewById(R.id.et_settings_search);
        ImageView ivClear = view.findViewById(R.id.iv_clear_search);
        mTvNoResults = view.findViewById(R.id.tv_no_results);
        RecyclerView rv = view.findViewById(R.id.rv_settings_search_results);

        rv.setLayoutManager(new LinearLayoutManager(requireContext()));
        mAdapter = new SearchAdapter();
        rv.setAdapter(mAdapter);

        // Chip shortcuts
        setupChip(view.findViewById(R.id.chip_ai), etSearch, "AI");
        setupChip(view.findViewById(R.id.chip_firewall), etSearch, "Firewall");
        setupChip(view.findViewById(R.id.chip_dns), etSearch, "DNS");
        setupChip(view.findViewById(R.id.chip_tls), etSearch, "TLS");
        setupChip(view.findViewById(R.id.chip_socks5), etSearch, "SOCKS5");
        setupChip(view.findViewById(R.id.chip_backup), etSearch, "Backup");
        setupChip(view.findViewById(R.id.chip_language), etSearch, "Language");

        filter("");

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String q = s.toString().trim();
                ivClear.setVisibility(q.isEmpty() ? View.GONE : View.VISIBLE);
                filter(q);
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        ivClear.setOnClickListener(v -> etSearch.setText(""));
    }

    private void setupChip(TextView chip, EditText etSearch, String query) {
        if (chip != null) {
            chip.setOnClickListener(v -> {
                etSearch.setText(query);
                etSearch.setSelection(query.length());
            });
        }
    }

    private void filter(String query) {
        mFilteredItems.clear();
        if (query.isEmpty()) {
            mFilteredItems.addAll(mAllItems);
        } else {
            String lower = query.toLowerCase(Locale.ROOT);
            for (SearchItem item : mAllItems) {
                if (item.title.toLowerCase(Locale.ROOT).contains(lower)
                        || item.summary.toLowerCase(Locale.ROOT).contains(lower)
                        || item.category.toLowerCase(Locale.ROOT).contains(lower)
                        || item.keywords.toLowerCase(Locale.ROOT).contains(lower)) {
                    mFilteredItems.add(item);
                }
            }
        }

        if (mTvNoResults != null) {
            mTvNoResults.setVisibility(mFilteredItems.isEmpty() ? View.VISIBLE : View.GONE);
        }
        if (mAdapter != null) {
            mAdapter.notifyDataSetChanged();
        }
    }

    private void initCatalog(Context ctx) {
        mAllItems.clear();

        // 🤖 1. AI & Autonomous Cyber Defense
        mAllItems.add(new SearchItem(
                "ai_protection_settings",
                ctx.getString(R.string.ai_protection_title),
                ctx.getString(R.string.ai_protection_summary),
                "AI Defense",
                R.drawable.ic_pref_ai_engine,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.AiProtectionSettings.class,
                "gemini gpt copilot llm assistant prompt intelligence smart neural investigate threat auto flow model api"
        ));

        mAllItems.add(new SearchItem(
                "threat_intel_settings",
                ctx.getString(R.string.threat_intel_apis),
                ctx.getString(R.string.threat_intel_apis_desc),
                "AI Defense",
                R.drawable.ic_pref_threat_intel,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.ThreatIntelApiSettings.class,
                "otx alienvault virustotal threat intelligence api key forensics reputation malicious url hash"
        ));

        mAllItems.add(new SearchItem(
                "antivirus_scan_action",
                ctx.getString(R.string.antivirus_scan),
                ctx.getString(R.string.antivirus_scan_desc),
                "AI Defense",
                R.drawable.ic_pref_antivirus,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.AntivirusScanActivity.class,
                "virus scan scanner malware clean audit trojan apk check security"
        ));

        mAllItems.add(new SearchItem(
                "pref_auto_daily_deep_scan",
                "Automatic Daily Deep Scan",
                "Run automated deep vulnerability & antivirus audit in the background every 24 hours",
                "AI Defense",
                R.drawable.ic_pref_deep_scan,
                ActionType.SCROLL,
                null,
                "scheduled scan daily 24 hours automated background audit virus"
        ));

        mAllItems.add(new SearchItem(
                "malware_detection",
                ctx.getString(R.string.malware_detection),
                ctx.getString(R.string.malware_detection_summary),
                "AI Defense",
                R.drawable.ic_pref_malware,
                ActionType.SCROLL,
                null,
                "malware real-time detection block malicious hosts domain blacklist"
        ));

        mAllItems.add(new SearchItem(
                "quarantine_vault_settings",
                "Sandboxed Quarantine Vault",
                "View, restore, or permanently shred isolated threat artifacts",
                "AI Defense",
                R.drawable.ic_pref_vault,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.QuarantineActivity.class,
                "quarantine isolated threats shred restore vault safe storage delete"
        ));

        // 🛡️ 2. Firewall & Security Rules
        mAllItems.add(new SearchItem(
                "firewall_settings",
                ctx.getString(R.string.firewall),
                ctx.getString(R.string.firewall_settings_summary),
                "Firewall",
                R.drawable.ic_pref_firewall,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.FirewallSettings.class,
                "firewall rules block apps port protocol ip access control packet filter"
        ));

        mAllItems.add(new SearchItem(
                "physical_security_settings",
                ctx.getString(R.string.physical_security_title),
                ctx.getString(R.string.physical_security_desc),
                "Firewall",
                R.drawable.ic_pref_physical_sec,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.PhysicalSecurityActivity.class,
                "physical security tamper lock sim overlay biometric intruder protection"
        ));

        mAllItems.add(new SearchItem(
                "security_permissions_setup",
                "Security Posture & Permissions",
                "Configure device protection, VPN access, battery whitelist & runtime posture",
                "Firewall",
                R.drawable.ic_pref_permissions,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.AppPermissionsActivity.class,
                "permissions battery whitelist background posture setup grant access"
        ));

        mAllItems.add(new SearchItem(
                "wifi_security_settings",
                ctx.getString(R.string.wifi_security_title),
                ctx.getString(R.string.wifi_security_summary),
                "Firewall",
                R.drawable.ic_pref_wifi_security,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.WifiSecurityActivity.class,
                "wifi wireless security wpa3 wpa2 ssid bssid gateway signal encryption captive portal rogue"
        ));

        // ⚡ 3. Capture Engine & Interfaces
        mAllItems.add(new SearchItem(
                "root_capture",
                ctx.getString(R.string.root_capture),
                ctx.getString(R.string.root_capture_summary),
                "Capture",
                R.drawable.ic_pref_root_capture,
                ActionType.SCROLL,
                null,
                "root su superuser magisk kernel capture pcap privileged"
        ));

        mAllItems.add(new SearchItem(
                "capture_interface",
                ctx.getString(R.string.capture_interface),
                "Select network interface (Wi-Fi, Mobile Data, Loopback)",
                "Capture",
                R.drawable.ic_pref_interface,
                ActionType.SCROLL,
                null,
                "interface wifi wlan rmnet eth network adapter adapter select"
        ));

        mAllItems.add(new SearchItem(
                "ip_mode",
                ctx.getString(R.string.ip_mode),
                "IPv4 only, IPv6 only, or Dual Stack",
                "Capture",
                R.drawable.ic_pref_ip_mode,
                ActionType.SCROLL,
                null,
                "ipv4 ipv6 dual stack protocol network address mode"
        ));

        mAllItems.add(new SearchItem(
                "dns_settings",
                ctx.getString(R.string.dns_servers),
                ctx.getString(R.string.dns_servers_summary),
                "Capture",
                R.drawable.ic_pref_dns,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.DnsSettings.class,
                "dns doh dnscrypt cloudflare quad9 adguard resolver domain name server"
        ));

        mAllItems.add(new SearchItem(
                "vpn_exceptions",
                ctx.getString(R.string.vpn_exemptions),
                ctx.getString(R.string.vpn_exemptions_summary),
                "Capture",
                R.drawable.ic_pref_vpn_exempt,
                ActionType.SCROLL,
                null,
                "vpn bypass exemption exempt whitelist excluded apps exclude filter"
        ));

        mAllItems.add(new SearchItem(
                "start_at_boot",
                ctx.getString(R.string.start_at_boot),
                ctx.getString(R.string.start_at_boot_summary),
                "Capture",
                R.drawable.ic_pref_boot,
                ActionType.SCROLL,
                null,
                "boot autostart auto startup start on reboot power on"
        ));

        mAllItems.add(new SearchItem(
                "restart_on_disconnect",
                ctx.getString(R.string.restart_on_disconnection),
                ctx.getString(R.string.restart_on_disconnection_summary),
                "Capture",
                R.drawable.ic_pref_restart,
                ActionType.SCROLL,
                null,
                "restart reconnect vpn disconnect resume retry network drop"
        ));

        // 🔍 4. Traffic Inspection & TLS Decryption
        mAllItems.add(new SearchItem(
                "tls_decryption",
                ctx.getString(R.string.tls_decryption),
                ctx.getString(R.string.tls_decryption_summary),
                "Traffic Inspection",
                R.drawable.ic_pref_tls,
                ActionType.SCROLL,
                null,
                "tls ssl https decryption mitm proxy certificate cert authority inspect plaintext"
        ));

        mAllItems.add(new SearchItem(
                "mitm_setup_wizard",
                ctx.getString(R.string.mitm_setup_wizard),
                ctx.getString(R.string.mitm_wizard_description),
                "Traffic Inspection",
                R.drawable.ic_pref_wizard,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.MitmSetupWizard.class,
                "mitm wizard certificate install root ca certificate trust setup"
        ));

        mAllItems.add(new SearchItem(
                "block_quic_mode",
                ctx.getString(R.string.block_quick),
                "Forces QUIC UDP traffic to fall back to TCP/TLS for deep packet inspection",
                "Traffic Inspection",
                R.drawable.ic_pref_quic,
                ActionType.SCROLL,
                null,
                "quic http3 udp block fallback tcp tls inspection"
        ));

        mAllItems.add(new SearchItem(
                "auto_block_private_dns",
                ctx.getString(R.string.block_private_dns),
                ctx.getString(R.string.block_private_dns_summary),
                "Traffic Inspection",
                R.drawable.ic_pref_block_dns,
                ActionType.SCROLL,
                null,
                "private dns dot tls android 9 10 bypass force local dns"
        ));

        mAllItems.add(new SearchItem(
                "full_payload",
                ctx.getString(R.string.full_payload),
                ctx.getString(R.string.full_payload_summary),
                "Traffic Inspection",
                R.drawable.ic_pref_payload,
                ActionType.SCROLL,
                null,
                "full payload raw packet dump body stream content hex"
        ));

        mAllItems.add(new SearchItem(
                "max_connections",
                ctx.getString(R.string.connections_log_size),
                ctx.getString(R.string.connections_log_size_dialog_sub),
                "Traffic Inspection",
                R.drawable.ic_pref_stats,
                ActionType.SCROLL,
                null,
                "max logged connections log size buffer memory ram retention fifo rollover capacity"
        ));

        mAllItems.add(new SearchItem(
                "geolocation",
                ctx.getString(R.string.geolocation),
                ctx.getString(R.string.geolocation_summary),
                "Traffic Inspection",
                R.drawable.ic_pref_geo,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.GeoipSettings.class,
                "geolocation geoip country ip map location maxmind database"
        ));

        // 📡 5. Streaming & Proxies
        mAllItems.add(new SearchItem(
                "p2p_exit_node_settings",
                ctx.getString(R.string.p2p_exit_node_title),
                ctx.getString(R.string.p2p_exit_node_summary),
                "Streaming & Mesh",
                R.drawable.ic_pref_p2p,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.P2PExitNodeSettings.class,
                "p2p mesh exit node decentralized tunnel p2p network relay"
        ));

        mAllItems.add(new SearchItem(
                "socks5_settings",
                ctx.getString(R.string.socks5_proxy),
                ctx.getString(R.string.socks5_summary),
                "Streaming & Mesh",
                R.drawable.ic_pref_socks5,
                ActionType.FRAGMENT,
                com.kotsafe.security.fragments.prefs.Socks5Settings.class,
                "socks5 proxy outbound upstream tunnel auth port"
        ));

        mAllItems.add(new SearchItem(
                "http_server_port",
                "Live HTTP PCAP Port",
                "Stream raw capture packets over local HTTP server endpoint",
                "Streaming & Mesh",
                R.drawable.ic_pref_http_server,
                ActionType.SCROLL,
                null,
                "http server live stream endpoint raw packet wireshark remote"
        ));

        mAllItems.add(new SearchItem(
                "collector_host",
                "Remote Exporter Host & Port",
                "Destination IP/host for live UDP/TCP packet stream",
                "Streaming & Mesh",
                R.drawable.ic_pref_exporter,
                ActionType.SCROLL,
                null,
                "remote exporter collector udp destination server stream forward"
        ));

        // 💾 6. Backup & Restore
        mAllItems.add(new SearchItem(
                "export_settings",
                ctx.getString(R.string.export_settings),
                ctx.getString(R.string.export_settings_summary),
                "Backup & Restore",
                R.drawable.ic_pref_export,
                ActionType.SCROLL,
                null,
                "export backup save settings rules firewall json transfer share"
        ));

        mAllItems.add(new SearchItem(
                "import_settings",
                ctx.getString(R.string.import_settings),
                ctx.getString(R.string.import_settings_summary),
                "Backup & Restore",
                R.drawable.ic_pref_import,
                ActionType.SCROLL,
                null,
                "import restore load backup merge replace json config"
        ));

        mAllItems.add(new SearchItem(
                "pcapng_format",
                ctx.getString(R.string.pcapng_format),
                ctx.getString(R.string.pcapng_format_summary),
                "Backup & Restore",
                R.drawable.ic_pref_pcapng,
                ActionType.SCROLL,
                null,
                "pcapng pcap file format dump wireshark capture format"
        ));

        // 📊 7. Analytics & Diagnostics
        mAllItems.add(new SearchItem(
                "pref_traffic_stats",
                "Traffic Statistics",
                "View real-time protocol breakdowns, bandwidth graphs and traffic metrics",
                "Analytics",
                R.drawable.ic_pref_stats,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.StatsActivity.class,
                "traffic stats bandwidth graphs charts data usage protocols metrics"
        ));

        mAllItems.add(new SearchItem(
                "pref_app_log",
                "System & Security Logs",
                "Inspect system activity, security audit trail and debug logs",
                "Analytics",
                R.drawable.ic_pref_logs,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.LogviewActivity.class,
                "logs system debug audit trail event console errors"
        ));

        mAllItems.add(new SearchItem(
                "storage_management",
                ctx.getString(R.string.storage_management),
                ctx.getString(R.string.storage_management_desc),
                "Analytics",
                R.drawable.ic_pref_storage,
                ActionType.ACTIVITY,
                com.kotsafe.security.activities.StorageManagementActivity.class,
                "storage cache clean disk memory pcap files size delete"
        ));

        // 🎨 8. Appearance & Internationalization
        mAllItems.add(new SearchItem(
                "theme_mode",
                ctx.getString(R.string.theme_mode),
                "Light, Dark, or System Default appearance",
                "Appearance",
                R.drawable.ic_pref_theme,
                ActionType.SCROLL,
                null,
                "theme dark light amoled night mode color style appearance"
        ));

        mAllItems.add(new SearchItem(
                "app_language",
                ctx.getString(R.string.app_language),
                "Choose preferred application language with country flags",
                "Appearance",
                R.drawable.ic_pref_language,
                ActionType.LANGUAGE,
                null,
                "language locale translate spanish english hindi arabic chinese french german russian flags"
        ));
    }

    private class SearchAdapter extends RecyclerView.Adapter<SearchAdapter.ViewHolder> {
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_settings_search_result, parent, false);
            return new ViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            SearchItem item = mFilteredItems.get(position);
            holder.ivIcon.setImageResource(item.iconRes);
            holder.tvTitle.setText(item.title);
            holder.tvSummary.setText(item.summary);
            holder.tvCategory.setText(item.category);

            holder.itemView.setOnClickListener(v -> {
                dismiss();
                if (mListener != null) {
                    mListener.onSearchItemSelected(item);
                }
            });
        }

        @Override
        public int getItemCount() {
            return mFilteredItems.size();
        }

        class ViewHolder extends RecyclerView.ViewHolder {
            ImageView ivIcon;
            TextView tvTitle;
            TextView tvSummary;
            TextView tvCategory;

            public ViewHolder(@NonNull View itemView) {
                super(itemView);
                ivIcon = itemView.findViewById(R.id.iv_search_icon);
                tvTitle = itemView.findViewById(R.id.tv_search_title);
                tvSummary = itemView.findViewById(R.id.tv_search_summary);
                tvCategory = itemView.findViewById(R.id.tv_search_category);
            }
        }
    }
}
