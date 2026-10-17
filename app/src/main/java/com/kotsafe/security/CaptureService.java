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

package com.kotsafe.security;

import android.annotation.TargetApi;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.Uri;
import android.net.VpnService;
import java.net.Socket;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.provider.Settings;
import android.util.Pair;
import android.util.SparseArray;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;
import androidx.core.content.ContextCompat;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.MutableLiveData;

import com.kotsafe.security.server.FirewallBlockHttpServer;
import androidx.lifecycle.Observer;

import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.FileProtectionWatcher;
import com.kotsafe.security.model.FirewallPolicy;
import com.kotsafe.security.model.NetworkType;

import java.util.Set;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.activities.AppsActivity;
import com.kotsafe.security.activities.CaptureCtrl;
import com.kotsafe.security.activities.ConnectionsActivity;
import com.kotsafe.security.activities.FirewallActivity;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.activities.StatsActivity;
import com.kotsafe.security.fragments.ConnectionsFragment;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.BlacklistDescriptor;
import com.kotsafe.security.model.Blocklist;
import com.kotsafe.security.model.CaptureSettings;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.ConnectionUpdate;
import com.kotsafe.security.model.FilterDescriptor;
import com.kotsafe.security.model.MatchList;
import com.kotsafe.security.model.PortMapping;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.pcap_dump.FileDumper;
import com.kotsafe.security.pcap_dump.HTTPServer;
import com.kotsafe.security.interfaces.PcapDumper;
import com.kotsafe.security.pcap_dump.TCPDumper;
import com.kotsafe.security.pcap_dump.UDPDumper;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.ThreatIntelManager;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.TrafficTimeSeriesCollector;
import com.kotsafe.security.mitm.MitmAPI;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

public class CaptureService extends VpnService implements Runnable {
    private static final String TAG = "CaptureService";
    private static final String VpnSessionName = "KotSafe VPN";
    private static final String NOTIFY_CHAN_VPNSERVICE = "VPNService";
    public static final String NOTIFY_CHAN_MALWARE_DETECTION = "Malware detection";
    private static final String NOTIFY_CHAN_OTHER = "Other";
    private static final int VPN_MTU = 10000;
    public static final int NOTIFY_ID_VPNSERVICE = 1;
    public static final int NOTIFY_ID_LOW_MEMORY = 2;
    public static final int NOTIFY_ID_APP_BLOCKED = 3;
    public static final String ACTION_DISMISS_NOTIFICATION = BuildConfig.APPLICATION_ID + ".ACTION_DISMISS_NOTIFICATION";
    public static final String ACTION_STOP_SERVICE = BuildConfig.APPLICATION_ID + ".ACTION_STOP_SERVICE";
    private boolean mNotificationDismissed = false;
    private BroadcastReceiver mNotificationReceiver = null;
    private static CaptureService INSTANCE;
    private static boolean HAS_ERROR = false;
    final ReentrantLock mLock = new ReentrantLock();
    final Condition mCaptureStopped = mLock.newCondition();
    private ParcelFileDescriptor mParcelFileDescriptor;
    private boolean mIsAlwaysOnVPN;
    private boolean mRevoked;
    private SharedPreferences mPrefs;
    private CaptureSettings mSettings;
    private Billing mBilling;
    private Handler mHandler;
    private Thread mCaptureThread;
    private Thread mBlacklistsUpdateThread;
    private Thread mConnUpdateThread;
    private Thread mDumperThread;
    private MitmReceiver mMitmReceiver;
    private final LinkedBlockingDeque<Pair<ConnectionDescriptor[], ConnectionUpdate[]>> mPendingUpdates = new LinkedBlockingDeque<>(32);
    private AtomicInteger mNumUpdatesInProgress = new AtomicInteger();
    private LinkedBlockingDeque<byte[]> mDumpQueue;
    private String vpn_ipv4;
    private String vpn_dns;
    private String dns_server;
    private long last_bytes;
    private int last_connections;
    private long mCaptureStartTime;
    private long mCaptureStartTimeMonotonic;
    private int[] mAppFilterUids;
    private PcapDumper mDumper;
    private ConnectionsRegister conn_reg;
    private HttpLog mHttpLog;
    private Uri mPcapUri;
    private String mPcapFname;
    private NotificationCompat.Builder mStatusBuilder;
    private NotificationCompat.Builder mMalwareBuilder;
    private com.kotsafe.security.vpn.VpnNotificationManager mNotificationManager;
    private com.kotsafe.security.vpn.VpnNetworkMonitor mNetworkMonitor;
    private com.kotsafe.security.vpn.VpnDumperController mDumperController;
    private long mMonitoredNetwork;
    private Network mUnderlyingNetwork;
    private ConnectivityManager.NetworkCallback mNetworkCallback;
    private AppsResolver mNativeAppsResolver; // can only be accessed by native code to avoid concurrency issues
    private Geolocation mNativeGeolocation;   // only native
    private boolean mMalwareDetectionEnabled;
    private boolean mBlacklistsUpdateRequested;
    private boolean mFirewallSupported;
    private boolean mFirewallEnabled;
    private boolean mBlockPrivateDns;
    private boolean mDnsEncrypted;
    private boolean mStrictDnsNoticeShown;
    private boolean mQueueFull;
    private volatile boolean mStopping;
    private Blacklists mBlacklists;
    private Blocklist mBlocklist;
    private MatchList mMalwareWhitelist;
    private MatchList mFirewallWhitelist;
    private MatchList mDecryptionList;
    private SparseArray<String> mIfIndexToName;
    private boolean mSocks5Enabled;
    private String mSocks5Address;
    private String mCollectorAddress;
    private int mSocks5Port;
    private String mSocks5Auth;
    private static final MutableLiveData<CaptureStats> lastStats = new MutableLiveData<>();
    private static final MutableLiveData<ServiceStatus> serviceStatus = new MutableLiveData<>();
    private boolean mLowMemory;
    private BroadcastReceiver mNewAppsInstallReceiver;
    private ScreenStateMonitor mScreenStateMonitor;
    private boolean mScreenOffBlockingActive;
    private NetworkStateMonitor mNetworkStateMonitor;
    private NetworkType mCurrentNetworkType = NetworkType.NONE;
    private boolean mIsScreenOn = true;
    private AppNetworkRulesManager.OnRulesChangeListener mRulesChangeListener;
    private Utils.PrivateDnsMode mPrivateDnsMode;

    /* The IP address of the virtual network interface */
    public static final String VPN_IP_ADDRESS = "10.215.173.1";
    public static final String VPN_IP6_ADDRESS = "fd00:2:fd00:1:fd00:1:fd00:1";

    /* The DNS server IP address to use to internally analyze the DNS requests.
     * It must be in the same subnet of the VPN network interface.
     * After the analysis, requests will be routed to the primary DNS server. */
    public static final String VPN_VIRTUAL_DNS_SERVER = "10.215.173.2";

    public enum ServiceStatus {
        STOPPED,
        STARTED
    }

    static {
        // KotSafe clean-room architecture: all native analytics and proxying run via KotEngineBridge (libkotengine.so)
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base.createConfigurationContext(Utils.getLocalizedConfig(base)));
    }

    @Override
    public void onCreate() {
        Log.d(CaptureService.TAG, "onCreate");
        AppsResolver.clearMappedApps();
        mNativeAppsResolver = new AppsResolver(this);
        mNativeGeolocation = new Geolocation(this);
        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);
        mSettings = new CaptureSettings(this, mPrefs); // initialize to prevent NULL pointer exceptions in methods (e.g. isRootCapture)

        INSTANCE = this;
        com.kotsafe.security.model.backend.CustomHttpProvider.setSocketProtector(sock -> {
            CaptureService vpn = CaptureService.getInstance();
            return vpn == null || vpn.protect(sock);
        });

        // Initialize and start Inbound Port Scan Honeypot Detector asynchronously to avoid blocking VPN startup
        try {
            com.kotsafe.security.model.InboundScanDetector scanDetector =
                    com.kotsafe.security.model.InboundScanDetector.getInstance(this);
            scanDetector.setListener(new com.kotsafe.security.model.InboundScanDetector.ScanListener() {
                @Override
                public void onScanDetected(com.kotsafe.security.model.InboundScanDetector.ScanAlert alert) {
                    if (alert != null) {
                        Log.w(CaptureService.TAG, "Inbound port scan detected from: " + alert.sourceIp + " (ports: " + alert.portsTouched + ")");
                        com.kotsafe.security.model.SecurityNotificationHub.getInstance(CaptureService.this)
                                .postThreatAlert(
                                        "Inbound Network Port Scan Detected",
                                        alert.sourceIp + " (Ports: " + alert.portsTouched + ")",
                                        "INBOUND_PORT_SCAN",
                                        com.kotsafe.security.model.AntivirusEvidenceItem.SEVERITY_MALICIOUS
                                );
                    }
                }

                @Override
                public void onProbe(com.kotsafe.security.model.InboundScanDetector.ProbeEvent event) {
                    if (event != null) {
                        Log.d(CaptureService.TAG, "Inbound probe on port " + event.targetPort + " from " + event.sourceIp);
                    }
                }
            });
            new Thread(() -> {
                try {
                    scanDetector.start();
                } catch (Exception e) {
                    Log.e(CaptureService.TAG, "Failed to start InboundScanDetector: " + e.getMessage());
                }
            }, "InboundScanInit").start();
        } catch (Exception e) {
            Log.e(CaptureService.TAG, "Failed to initialize InboundScanDetector: " + e.getMessage());
        }

        // Initialize clean-room KotEngine Bridge
        try {
            com.kotsafe.security.engine.KotEngineBridge bridge = com.kotsafe.security.engine.KotEngineBridge.getInstance();
            bridge.setProtectDelegate(fd -> protect(fd));
            bridge.setUidResolverDelegate((proto, saddr, sport, daddr, dport) -> getUidQ(proto, saddr, sport, daddr, dport));
            bridge.setThreatListener(alert -> {
                if (alert != null) {
                    String details = alert.getDetails();
                    if (details == null || details.trim().isEmpty()) return kotlin.Unit.INSTANCE;

                    // Do not treat formatted debug logs or truncated entries as domain IOCs
                    if (details.contains("...") || details.toLowerCase().startsWith("dns tunneling")) {
                        Log.d(CaptureService.TAG, "KotEngine Anomaly: " + details);
                        return kotlin.Unit.INSTANCE;
                    }

                    com.kotsafe.security.ai.AutonomousSocAnalyst.ThreatIncident incident =
                            new com.kotsafe.security.ai.AutonomousSocAnalyst.ThreatIncident(
                                    details,
                                    "FLOW",
                                    "NATIVE_THREAT",
                                    "KotEngine Native Anomaly Alert",
                                    details,
                                    "UID " + alert.getUid(),
                                    85,
                                    "T1071"
                            );
                    com.kotsafe.security.ai.AutonomousSocAnalyst.getInstance(CaptureService.this)
                            .triageAndRemediate(incident, null);
                }
                return kotlin.Unit.INSTANCE;
            });
            bridge.setListener(conns -> {
                if (conns != null && conns.length > 0) {
                    try {
                        ConnectionsRegister reg = getConnsRegister();
                        if (reg != null) {
                            reg.onKotEngineConnsUpdated(conns);
                        }
                    } catch (Throwable t) {
                        Log.e(CaptureService.TAG, "Error handling KotEngine connections: " + t.getMessage());
                    }
                }
                return kotlin.Unit.INSTANCE;
            });
            int rc = bridge.init(8192, 120, 1024, 0, true, 1);
            if (rc != 0) {
                Log.w(CaptureService.TAG, "KotEngineBridge init returned code: " + rc);
            }
        } catch (Throwable t) {
            Log.e(CaptureService.TAG, "KotEngineBridge init failed: " + t.getMessage());
        }

        super.onCreate();
    }


    private int abortStart() {
        stopService();
        updateServiceStatus(ServiceStatus.STOPPED);
        return START_NOT_STICKY;
    }

    private static boolean alwaysOnVpnErrorLogged = false;

    // Android does not provide a reliable API to track the always-on VPN state
    // This function tries to detect but may fail to do so
    private boolean isAlwaysOnVpnDetected() {
        try {
            if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                return isAlwaysOn();

            String always_on_vpn_app = Settings.Secure.getString(getContentResolver(), "always_on_vpn_app");
            return always_on_vpn_app.equals(getPackageName());
        } catch (Exception e) {
            if (!alwaysOnVpnErrorLogged) {
                Log.w(TAG, "Querying the always-on VPN state failed: " + e);
                alwaysOnVpnErrorLogged = true;
            }
            return false;
        }
    }

    @Override
    public int onStartCommand(@Nullable Intent intent, int flags, int startId) {
        mStopping = false;
        mRevoked = false;
        mNotificationDismissed = false;

        // startForeground must always be called since the Service is being started with
        // ContextCompat.startForegroundService.
        // NOTE: since Android 12, startForeground cannot be called when the app is in background
        // (unless invoked via an Intent).
        setupNotifications();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
            startForeground(NOTIFY_ID_VPNSERVICE, getStatusNotification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        else
            startForeground(NOTIFY_ID_VPNSERVICE, getStatusNotification());

        // NOTE: onStartCommand may be called when the capture is already running, e.g. if the user
        // turns on the always-on VPN while the capture is running in root mode
        if(mCaptureThread != null) {
            // Restarting the capture requires calling stopAndJoinThreads, which is blocking.
            // Choosing not to support this right now.
            Log.e(TAG, "Restarting the capture is not supported");
            return abortStart();
        }

        // onDestroy is not necessarily invoked between two captures on the same service instance,
        // so a receiver registered by the previous capture may still be around
        unregisterNewAppsInstallReceiver();

        if (VpnReconnectService.isAvailable())
            VpnReconnectService.stopService();

        mHandler = new Handler(Looper.getMainLooper());
        mBilling = Billing.newInstance(this);

        Log.d(CaptureService.TAG, "onStartCommand");

        // NOTE: a null intent may be delivered due to START_STICKY
        // It can be simulated by starting the capture, putting KotSafe in the background and then running:
        //  adb shell ps | grep com.kotsafe.security | awk '{print $2}' | xargs adb shell run-as com.kotsafe.security.debug kill
        CaptureSettings settings = ((intent == null) ? null : Utils.getSerializableExtra(intent, "settings", CaptureSettings.class));
        if(settings == null) {
            // Use the settings from mPrefs. They must be re-read here, as onStartCommand may be
            // invoked again on the same service instance, after a previous capture has terminated.
            mSettings = new CaptureSettings(this, mPrefs);

            // An Intent without extras is delivered in case of always on VPN
            // https://developer.android.com/guide/topics/connectivity/vpn#always-on
            mIsAlwaysOnVPN = (intent != null);
            Log.i(CaptureService.TAG, "Missing capture settings, using SharedPrefs");
        } else {
            // Use the provided settings
            mSettings = settings;
            mIsAlwaysOnVPN = false;

            if(!settings.decryption_rules_json.isBlank()) {
                KotSafe.getInstance()
                    .getDecryptionList()
                    .fromJson(settings.decryption_rules_json);
            }
        }

        mIsAlwaysOnVPN |= isAlwaysOnVpnDetected();

        Log.d(TAG, "alwaysOn? " + mIsAlwaysOnVPN);
        if(mIsAlwaysOnVPN) {
            mSettings.root_capture = false;
            mSettings.input_pcap_path = null;
        }

        // The legacy root daemon (pcapd) was removed in the clean-room migration.
        // KotEngine captures through VpnService only, so fall back transparently.
        if(mSettings.root_capture) {
            Log.i(TAG, "Root capture requested; using KotEngine VpnService path");
            mSettings.root_capture = false;
        }

        if(mSettings.readFromPcap()) {
            // Disable incompatible settings
            mSettings.dump_mode = Prefs.DumpMode.NONE;
            mSettings.app_filter.clear();
            mSettings.socks5_enabled = false;
            mSettings.tls_decryption = false;
            mSettings.root_capture = false;
            mSettings.auto_block_private_dns = false;
            mSettings.capture_interface = mSettings.input_pcap_path;
        }

        // the capture is not allowed to run without the local network permission, otherwise the
        // connections to the LAN devices would silently fail. It's normally requested by
        // CaptureHelper, but the service can also be started without it (e.g. at boot)
        if(!mSettings.readFromPcap() && !Utils.hasLocalNetworkPermission(this)) {
            Log.e(TAG, "The local network permission is not granted, cannot start the capture");
            Utils.showToastLong(this, R.string.local_network_permission_required);
            return abortStart();
        }

        if(mSettings.tls_decryption && !MitmAddon.isSupportedTarget()) {
            Log.w(TAG, "TLS decryption is not supported on this target, disabling it");
            mSettings.tls_decryption = false;
        }

        // Retrieve DNS server
        String fallbackDnsV4 = Prefs.getDnsServerV4(mPrefs);
        if ("9.9.9.9".equals(fallbackDnsV4) || fallbackDnsV4.isEmpty()) fallbackDnsV4 = "1.1.1.1";
        dns_server = fallbackDnsV4;
        mBlockPrivateDns = false;
        mStrictDnsNoticeShown = false;
        mDnsEncrypted = false;
        setPrivateDnsBlocked(false);

        // Map network interfaces
        mIfIndexToName = new SparseArray<>();

        Enumeration<NetworkInterface> ifaces = Utils.getNetworkInterfaces();
        while(ifaces.hasMoreElements()) {
            NetworkInterface iface = ifaces.nextElement();

            Log.d(TAG, "ifidx " + iface.getIndex() + " -> " + iface.getName());
            mIfIndexToName.put(iface.getIndex(), iface.getName());
        }

        if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Service.CONNECTIVITY_SERVICE);
            Network net = cm.getActiveNetwork();
            mUnderlyingNetwork = net;

            if(net != null) {
                handleLinkProperties(cm.getLinkProperties(net));

                if(Prefs.useSystemDns(mPrefs) || mSettings.root_capture) {
                    dns_server = Utils.getDnsServer(cm, net);
                    if (dns_server == null)
                        dns_server = fallbackDnsV4;
                    else {
                        mMonitoredNetwork = net.getNetworkHandle();
                        registerNetworkCallbacks();
                    }
                } else
                    dns_server = fallbackDnsV4;
            }
        }

        vpn_dns = VPN_VIRTUAL_DNS_SERVER;
        vpn_ipv4 = VPN_IP_ADDRESS;
        last_bytes = 0;
        mCaptureStartTime = System.currentTimeMillis();
        mCaptureStartTimeMonotonic = SystemClock.elapsedRealtime();
        last_connections = 0;
        mLowMemory = false;
        conn_reg = new ConnectionsRegister(this, Prefs.getConnectionsLogSize(mPrefs));
        mHttpLog = new HttpLog();
        mDumper = null;
        mDumpQueue = null;
        mPendingUpdates.clear();
        mPcapFname = null;
        HAS_ERROR = false;

        // Possibly allocate the dumper
        mCollectorAddress = "";
        if(mSettings.dump_mode == Prefs.DumpMode.HTTP_SERVER)
            mDumper = new HTTPServer(this, mSettings.http_server_port, mSettings.pcapng_format);
        else if(mSettings.dump_mode == Prefs.DumpMode.PCAP_FILE) {
            mPcapFname = !mSettings.pcap_name.isEmpty() ? mSettings.pcap_name : Utils.getUniquePcapFileName(this, mSettings.pcapng_format);

            if(!mSettings.pcap_uri.isEmpty())
                mPcapUri = Uri.parse(mSettings.pcap_uri);
            else
                mPcapUri = Utils.getDownloadsUri(this, mPcapFname);

            if(mPcapUri == null)
                return abortStart();

            mDumper = new FileDumper(this, mPcapUri);
        } else if((mSettings.dump_mode == Prefs.DumpMode.UDP_EXPORTER) ||
                (mSettings.dump_mode == Prefs.DumpMode.TCP_EXPORTER)) {
            // For UDP/TCP exporters, the dumper is allocated later in run() (after resolveHosts)
            // so that domain names in mSettings.collector_address can be resolved on a background
            // thread using the underlying (non-VPN) network.
            mCollectorAddress = mSettings.collector_address;
        }

        mDumperController = new com.kotsafe.security.vpn.VpnDumperController(
                this,
                mSettings,
                mPcapUri,
                this::reportError,
                () -> mHandler.post(CaptureService::stopPacketLoop)
        );
        mDumperController.initializeDumper(null);

        boolean isGatewayClient = mPrefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED,
                mPrefs.getBoolean(Prefs.PREF_P2P_EXIT_NODE_CLIENT_ENABLED, false));
        if (isGatewayClient) {
            mSettings.socks5_enabled = true;
            mSettings.socks5_proxy_address = "127.0.0.1";
            mSettings.socks5_proxy_port = 8095;
            mSettings.block_quic_mode = Prefs.BlockQuicMode.ALWAYS;
            mSettings.ip_mode = Prefs.IpMode.BOTH;
            if (dns_server == null || "9.9.9.9".equals(dns_server)
                    || dns_server.startsWith("192.168.") || dns_server.startsWith("10.") || dns_server.startsWith("172.")) {
                dns_server = "1.1.1.1";
            }
        }

        mSocks5Address = "";
        mSocks5Enabled = mSettings.socks5_enabled || mSettings.tls_decryption;
        if(mSocks5Enabled) {
            if(mSettings.socks5_enabled) {
                // Personal Gateway routing: block QUIC (UDP) and capture IPv6 so browser traffic falls back to TCP and doesn't leak
                mSettings.block_quic_mode = Prefs.BlockQuicMode.ALWAYS;
                mSettings.ip_mode = Prefs.IpMode.BOTH;
            }
            if(mSettings.tls_decryption) {
                // Built-in decryption
                mSocks5Address = "127.0.0.1";
                mSocks5Port = MitmReceiver.TLS_DECRYPTION_PROXY_PORT;
                mSocks5Auth = Utils.genRandomString(8) + ":" + Utils.genRandomString(8);

                mMitmReceiver = new MitmReceiver(this, mSettings, mSocks5Auth);
                try {
                    if(!mMitmReceiver.start())
                        return abortStart();
                } catch (IOException e) {
                    e.printStackTrace();
                    return abortStart();
                }
            } else {
                // SOCKS5 proxy
                mSocks5Address = mSettings.socks5_proxy_address;
                mSocks5Port = mSettings.socks5_proxy_port;

                if("127.0.0.1".equals(mSocks5Address) || "localhost".equalsIgnoreCase(mSocks5Address)) {
                    com.kotsafe.security.model.BackendProvider provider =
                            com.kotsafe.security.model.backend.BackendProviderFactory.getConfigured(this);
                    String backendToken = mPrefs.getString(Prefs.PREF_P2P_BACKEND_PAIRING, "");
                    boolean killSwitch = mPrefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.KILL_SWITCH, true);

                    if (isGatewayClient) {
                        String bundleUri = mPrefs.getString(com.kotsafe.security.p2p.GatewayPreferenceKeys.PAIRING_BUNDLE, "");
                        if (!bundleUri.isEmpty()) {
                            try {
                                com.kotsafe.security.p2p.SecurePairingBundle parsed =
                                        com.kotsafe.security.p2p.SecurePairingBundle.parse(bundleUri);
                                if (parsed != null && parsed.room != null && !parsed.room.isEmpty()) {
                                    backendToken = "client_" + parsed.room;
                                    mPrefs.edit().putString(Prefs.PREF_P2P_BACKEND_PAIRING, backendToken).apply();
                                }
                            } catch (Exception ignored) {}
                        }
                    }

                    if (provider != null && !backendToken.isEmpty()) {
                        com.kotsafe.security.model.backend.CustomHttpProvider.ensureCipherConfigured(this);
                        try {
                            int bound = provider.startRelayLoopback(backendToken, mSocks5Port);
                            if (bound == 0 && isGatewayClient && killSwitch) {
                                Log.e(TAG, "Personal Gateway relay loopback failed to bind; kill switch active - aborting capture to prevent leak");
                                mHandler.post(() -> Utils.showToastLong(this, R.string.gateway_status_disconnected));
                                return abortStart();
                            }
                        } catch (Exception e) {
                            if (isGatewayClient && killSwitch) {
                                Log.e(TAG, "Personal Gateway relay loopback failed with exception: " + e.getMessage());
                                return abortStart();
                            }
                        }
                    } else if (isGatewayClient && killSwitch) {
                        Log.e(TAG, "Personal Gateway client enabled without valid pairing; kill switch active - aborting capture to prevent leak");
                        mHandler.post(() -> Utils.showToastLong(this, R.string.gateway_scan_pairing_summary));
                        return abortStart();
                    }
                }

                if(!mSettings.socks5_username.isEmpty() && !mSettings.socks5_password.isEmpty())
                    mSocks5Auth = mSettings.socks5_username + ":" + mSettings.socks5_password;
                else
                    mSocks5Auth = null;
            }
        }

        if(mSettings.tls_decryption && !mSettings.root_capture && !mSettings.readFromPcap())
            mDecryptionList = KotSafe.getInstance().getDecryptionList();
        else
            mDecryptionList = null;

        if ((mSettings.app_filter != null) && (!mSettings.app_filter.isEmpty())) {
            ArrayList<Integer> uids = new ArrayList<>();

            for (String package_name: mSettings.app_filter) {
                int uid;

                try {
                    uid = Utils.getPackageUid(getPackageManager(), package_name, 0);
                } catch (PackageManager.NameNotFoundException e) {
                    e.printStackTrace();
                    continue;
                }

                uids.add(uid);
            }

            // populate the array only with resolved UIDs
            mAppFilterUids = new int[uids.size()];

            int i = 0;
            for (Integer uid: uids)
                mAppFilterUids[i++] = uid;
        } else
            mAppFilterUids = new int[0];

        mMalwareDetectionEnabled = !mSettings.readFromPcap() && Prefs.isMalwareDetectionEnabled(this, mPrefs);

        // NOTE: Prefs.isFirewallEnabled cannot be used here as, until the capture thread is
        // started, it determines the capture mode from the persistent preferences rather than
        // from the current settings of this capture
        mFirewallSupported = !mSettings.readFromPcap() && !mSettings.root_capture;
        mFirewallEnabled = mFirewallSupported && mPrefs.getBoolean(Prefs.PREF_FIREWALL, true);

        if(!mSettings.root_capture && !mSettings.readFromPcap()) {
            Log.i(TAG, "Using DNS server " + dns_server);

            // VPN
            /* In order to see the DNS packets into the VPN we must set an internal address as the DNS
             * server. */
            Builder builder = new Builder()
                    .setMtu(VPN_MTU);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false);

            if (getIPv4Enabled() == 1) {
                builder.addAddress(vpn_ipv4, 30)
                        .addRoute("0.0.0.0", 1)
                        .addRoute("128.0.0.0", 1)
                        .addDnsServer(vpn_dns);
            }

            if (getIPv6Enabled() == 1) {
                builder.addAddress(VPN_IP6_ADDRESS, 128);

                // Route unicast IPv6 addresses (global + ULA + site-local)
                builder.addRoute("2000::", 3);   // Global unicast (2000::/3)
                builder.addRoute("fc00::", 7);   // Unique-local (fc00::/7 covers fc00::–fdff::)
                builder.addRoute("fec0::", 10);  // Site-local (fec0::/10 covers fec0::–feff::)
                                                 // FIX C-002: site-local was previously unrouted,
                                                 // allowing apps to bypass the VPN firewall.

                try {
                    builder.addDnsServer(InetAddress.getByName(Prefs.getDnsServerV6(mPrefs)));
                } catch (UnknownHostException | IllegalArgumentException e) {
                    Log.w(TAG, "Could not set IPv6 DNS server");
                }
            } else {
                // Trap IPv6 into VPN tunnel to prevent external bypass leak when IPv4-only is selected;
                // native packet engine (capture_vpn.c line 686) will drop these packets securely.
                builder.addAddress(VPN_IP6_ADDRESS, 128);
                builder.addRoute("2000::", 3);
                builder.addRoute("fc00::", 7);
                builder.addRoute("fec0::", 10);
            }

            // ------------------------------------------------------------------
            // P2P Per-App Split Tunneling (Phase 3 / Option C)
            // ------------------------------------------------------------------
            boolean isP2PClientActive = mPrefs.getBoolean(
                    com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED,
                    mPrefs.getBoolean(Prefs.PREF_P2P_EXIT_NODE_CLIENT_ENABLED, false));

            String p2pRoutingMode = mPrefs.getString(
                    com.kotsafe.security.p2p.GatewayPreferenceKeys.APP_ROUTING_MODE,
                    com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_ALL);

            Set<String> p2pSelectedApps = mPrefs.getStringSet(
                    com.kotsafe.security.p2p.GatewayPreferenceKeys.SELECTED_APPS,
                    Collections.emptySet());

            if (isP2PClientActive
                    && !p2pSelectedApps.isEmpty()
                    && !com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_ALL.equals(p2pRoutingMode)) {

                if (com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_ONLY_SELECTED.equals(p2pRoutingMode)) {
                    // Only tunnel the chosen apps through P2P — all others bypass the VPN
                    Log.d(TAG, "[P2P Split Tunnel] ONLY_SELECTED: " + p2pSelectedApps.size() + " apps");
                    for (String pkg : p2pSelectedApps) {
                        try {
                            builder.addAllowedApplication(pkg);
                        } catch (PackageManager.NameNotFoundException e) {
                            Log.w(TAG, "[P2P Split Tunnel] package not found (allow): " + pkg);
                        }
                    }
                } else if (com.kotsafe.security.p2p.GatewayPreferenceKeys.ROUTING_MODE_BYPASS_SELECTED.equals(p2pRoutingMode)) {
                    // Tunnel everything EXCEPT the chosen apps
                    Log.d(TAG, "[P2P Split Tunnel] BYPASS_SELECTED: " + p2pSelectedApps.size() + " apps excluded");
                    for (String pkg : p2pSelectedApps) {
                        try {
                            builder.addDisallowedApplication(pkg);
                        } catch (PackageManager.NameNotFoundException e) {
                            Log.w(TAG, "[P2P Split Tunnel] package not found (disallow): " + pkg);
                        }
                    }
                    // Also apply standard VPN exceptions (they are also 'disallowed', safe to combine)
                    Set<String> exceptions = mPrefs.getStringSet(Prefs.PREF_VPN_EXCEPTIONS, Collections.emptySet());
                    for (String packageName : exceptions) {
                        if (!p2pSelectedApps.contains(packageName)) {
                            try {
                                builder.addDisallowedApplication(packageName);
                            } catch (PackageManager.NameNotFoundException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                    // Google Pay apps must bypass VPN tunnel so payments work seamlessly
                    for (String gpayPkg : new String[]{"com.google.android.apps.nbu.paisa.user", "com.google.android.apps.walletnfcrel"}) {
                        if (!p2pSelectedApps.contains(gpayPkg) && !exceptions.contains(gpayPkg)) {
                            try {
                                builder.addDisallowedApplication(gpayPkg);
                            } catch (PackageManager.NameNotFoundException ignored) {}
                        }
                    }
                    // Self-exclusion when needed
                    if (mSettings.tls_decryption || mSettings.socks5_enabled) {
                        try { builder.addDisallowedApplication(getPackageName()); } catch (PackageManager.NameNotFoundException ignored) {}
                    }
                }
            } else if ((mSettings.app_filter != null) && (!mSettings.app_filter.isEmpty())) {
                // Standard per-app capture filter (original KotSafe behaviour)
                Log.d(TAG, "Setting app filter: " + mSettings.app_filter);

                try {
                    // NOTE: the API requires a package name, however it is converted to a UID
                    // (see Vpn.java addUserToRanges). This means that vpn routing happens on a UID basis,
                    // not on a package-name basis!
                    for (String package_name: mSettings.app_filter)
                        builder.addAllowedApplication(package_name);
                } catch (PackageManager.NameNotFoundException e) {
                    String msg = String.format(getResources().getString(R.string.app_not_found), mSettings.app_filter);
                    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
                    return abortStart();
                }
            } else {
                // VPN exceptions
                Set<String> exceptions = mPrefs.getStringSet(Prefs.PREF_VPN_EXCEPTIONS, Collections.emptySet());
                for(String packageName: exceptions) {
                    try {
                        builder.addDisallowedApplication(packageName);
                    } catch (PackageManager.NameNotFoundException e) {
                        e.printStackTrace();
                    }
                }

                // Ensure Google Pay (UPI Tez & Google Wallet) bypasses VPN tunnel so payments work seamlessly
                for (String gpayPkg : new String[]{"com.google.android.apps.nbu.paisa.user", "com.google.android.apps.walletnfcrel"}) {
                    if (!exceptions.contains(gpayPkg)) {
                        try {
                            builder.addDisallowedApplication(gpayPkg);
                        } catch (PackageManager.NameNotFoundException ignored) {}
                    }
                }

                if(mSettings.tls_decryption) {
                    // Exclude the mitm addon traffic and KotSafe itself in case system-wide decryption is performed
                    // Important: cannot call addDisallowedApplication with addAllowedApplication
                    try {
                        builder.addDisallowedApplication(MitmAPI.PACKAGE_NAME);
                    } catch (PackageManager.NameNotFoundException ignored) {}
                }
                try {
                    builder.addDisallowedApplication(getPackageName());
                } catch (PackageManager.NameNotFoundException ignored) {}
            }

            // Port mappings are loaded in resolveHosts() to allow domain resolution

            try {
                mParcelFileDescriptor = builder.setSession(CaptureService.VpnSessionName).establish();
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    if (mUnderlyingNetwork != null) {
                        setUnderlyingNetworks(new Network[]{mUnderlyingNetwork});
                    } else {
                        setUnderlyingNetworks(null);
                    }
                }
            } catch (IllegalArgumentException | IllegalStateException | SecurityException e) {
                e.printStackTrace();
                Utils.showToast(this, R.string.vpn_setup_failed);
                return abortStart();
            }
        }

        mMalwareWhitelist = KotSafe.getInstance().getMalwareWhitelist();
        mBlacklists = KotSafe.getInstance().getBlacklists();
        if(mMalwareDetectionEnabled && !mBlacklists.needsUpdate(true))
            reloadBlacklists();
        checkBlacklistsUpdates(true);

        mBlocklist = KotSafe.getInstance().getBlocklist();
        mFirewallWhitelist = KotSafe.getInstance().getFirewallWhitelist();

        mNumUpdatesInProgress.set(0);
        mConnUpdateThread = new Thread(this::connUpdateWork, "UpdateListener");
        mConnUpdateThread.start();

        if(mFirewallEnabled) {
            mNewAppsInstallReceiver = new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    // executed on the main thread
                    if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
                        boolean newInstall = !intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
                        String packageName = intent.getData().getSchemeSpecificPart();

                        if(newInstall && Prefs.blockNewApps(mPrefs)) {
                                if (Utils.isVerifiedGoogleTrustedService(CaptureService.this, packageName)
                                    || Utils.isSystemApp(CaptureService.this, packageName)) {
                                Log.i(TAG, "Exempting trusted Google/system app from auto-block: " + packageName);
                                return;
                            }
                            if(!mBlocklist.addApp(packageName))
                                return;

                            mBlocklist.save();
                            reloadBlocklist();

                            AppDescriptor app = AppsResolver.resolveInstalledApp(getPackageManager(), packageName, 0);
                            String label = (app != null) ? app.getName() : packageName;

                            Log.i(TAG, "Blocking newly installed app: " + packageName + ((app != null) ? " - " + app.getUid() : ""));

                            PendingIntent pi = PendingIntent.getActivity(CaptureService.this, 0,
                                    new Intent(CaptureService.this, FirewallActivity.class), Utils.getIntentFlags(0));

                            PendingIntent unblockIntent = PendingIntent.getBroadcast(CaptureService.this, 0,
                                    new Intent(CaptureService.this, ActionReceiver.class)
                                            .putExtra(ActionReceiver.EXTRA_UNBLOCK_APP, packageName), Utils.getIntentFlags(PendingIntent.FLAG_UPDATE_CURRENT));

                            // Notify the user
                            NotificationManagerCompat man = NotificationManagerCompat.from(context);
                            if(man.areNotificationsEnabled()) {
                                Notification notification = new NotificationCompat.Builder(CaptureService.this, NOTIFY_CHAN_OTHER)
                                        .setContentIntent(pi)
                                        .setSmallIcon(R.drawable.ic_logo)
                                        .setColor(ContextCompat.getColor(CaptureService.this, R.color.colorPrimary))
                                        .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                                        .setCategory(NotificationCompat.CATEGORY_STATUS)
                                        .setContentTitle(getString(R.string.app_blocked))
                                        .setContentText(getString(R.string.app_blocked_info, label))
                                        .setAutoCancel(true)
                                        .addAction(R.drawable.ic_check_solid, getString(R.string.action_unblock), unblockIntent)
                                        .build();

                                man.notify(NOTIFY_ID_APP_BLOCKED, notification);
                            }
                        }
                    }
                }
            };

            IntentFilter filter = new IntentFilter();
            filter.addAction(Intent.ACTION_PACKAGE_ADDED);
            filter.addDataScheme("package");
            registerReceiver(mNewAppsInstallReceiver, filter);
        }

        if(mFirewallSupported) {
            mScreenStateMonitor = new ScreenStateMonitor(this, isScreenOn -> {
                Log.i(TAG, "Screen state changed: " + (isScreenOn ? "ON" : "OFF"));
                mIsScreenOn = isScreenOn;
                mScreenOffBlockingActive = FirewallPolicy.shouldBlockScreenOff(mPrefs, isScreenOn);
                if(mFirewallSupported && mFirewallEnabled) {
                    mHandler.post(this::reloadBlocklist);
                    reloadFirewallWhitelist();
                }
            });
            mScreenStateMonitor.startMonitoring();
            mIsScreenOn = mScreenStateMonitor.isScreenOn();
            mScreenOffBlockingActive = FirewallPolicy.shouldBlockScreenOff(mPrefs, mIsScreenOn);

            mNetworkStateMonitor = new NetworkStateMonitor(this, newType -> {
                Log.i(TAG, "Network state changed: " + newType);
                mCurrentNetworkType = newType;
                if(mFirewallSupported && mFirewallEnabled) {
                    mHandler.post(this::reloadBlocklist);
                }
            });
            mNetworkStateMonitor.startMonitoring();
            mCurrentNetworkType = mNetworkStateMonitor.getCurrentNetworkType();

            mRulesChangeListener = () -> {
                if(mFirewallSupported && mFirewallEnabled) {
                    mHandler.post(this::reloadBlocklist);
                }
            };
            AppNetworkRulesManager.getInstance(this).addListener(mRulesChangeListener);
            FileProtectionWatcher.getInstance(this).startWatching();
        }

        // Start Firewall Block HTTP daemon on port 8090
        FirewallBlockHttpServer.getInstance(this).start();

        // Start the native capture thread
        mQueueFull = false;
        mCaptureThread = new Thread(this, "PacketCapture");
        mCaptureThread.start();

        // If the service is killed (e.g. due to low memory), then restart it with a NULL intent
        return START_STICKY;
    }

    @Override
    public void onRevoke() {
        Log.d(CaptureService.TAG, "onRevoke");
        mRevoked = true;
        stopService();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        Log.d(CaptureService.TAG, "onDestroy");

        // Do not nullify INSTANCE to allow its settings and the connections register to be accessible
        // after the capture is stopped
        //INSTANCE = null;

        unregisterNetworkCallbacks();

        if(mBlacklists != null)
            mBlacklists.abortUpdate();

        if(mCaptureThread != null)
            mCaptureThread.interrupt();
        if(mBlacklistsUpdateThread != null)
            mBlacklistsUpdateThread.interrupt();

        unregisterNewAppsInstallReceiver();
        unregisterNotificationReceiver();

        try {
            com.kotsafe.security.model.InboundScanDetector.getInstance(this).stop();
        } catch (Exception ignored) {}

        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().destroy();
        } catch (Exception ignored) {}

        if (mNotificationManager != null) {
            mNotificationManager.destroy();
        }

        super.onDestroy();

    }

    private void unregisterNotificationReceiver() {
        if (mNotificationReceiver != null) {
            try {
                unregisterReceiver(mNotificationReceiver);
            } catch (Exception ignored) {}
            mNotificationReceiver = null;
        }
    }

    private void setupNotifications() {
        if (mNotificationManager == null) {
            mNotificationManager = new com.kotsafe.security.vpn.VpnNotificationManager(this, mPrefs, CaptureService::stopService);
        }
        mNotificationManager.setupNotifications();
    }

    private Notification getStatusNotification() {
        if (mNotificationManager == null) {
            setupNotifications();
        }
        CaptureStats stats = (lastStats != null) ? lastStats.getValue() : null;
        return mNotificationManager.getStatusNotification(stats, last_bytes, last_connections);
    }

    private void updateNotification() {
        if (mStopping || (mNotificationManager != null && mNotificationManager.isNotificationDismissed()))
            return;

        if (mNotificationManager != null) {
            CaptureStats stats = (lastStats != null) ? lastStats.getValue() : null;
            mNotificationManager.updateNotification(mStopping, stats, last_bytes, last_connections);
        }
    }

    public void showKillSwitchActiveNotification() {
        if (mStopping || (mNotificationManager != null && mNotificationManager.isNotificationDismissed()))
            return;
        if (mNotificationManager != null) {
            mNotificationManager.showKillSwitchActiveNotification(mStopping);
        }
    }

    public void restoreStatusNotification() {
        if (mStopping || (mNotificationManager != null && mNotificationManager.isNotificationDismissed()))
            return;
        if (mNotificationManager != null) {
            CaptureStats stats = (lastStats != null) ? lastStats.getValue() : null;
            mNotificationManager.restoreStatusNotification(mStopping, stats, last_bytes, last_connections);
        }
    }

    public void notifyBlacklistedConnection(ConnectionDescriptor conn) {
        if (mNotificationManager != null) {
            mNotificationManager.notifyBlacklistedConnection(conn);
        }
    }

    public void notifyLowMemory(CharSequence msg) {
        if (mNotificationManager != null) {
            mNotificationManager.notifyLowMemory(msg);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void registerNetworkCallbacks() {
        if (mNetworkMonitor == null) {
            mNetworkMonitor = new com.kotsafe.security.vpn.VpnNetworkMonitor(
                    this,
                    mPrefs,
                    mSettings,
                    networks -> {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                            setUnderlyingNetworks(networks);
                        }
                        return kotlin.Unit.INSTANCE;
                    },
                    newDns -> {
                        dns_server = newDns;
                        setDnsServer(dns_server);
                        return kotlin.Unit.INSTANCE;
                    },
                    blocked -> {
                        mBlockPrivateDns = blocked;
                        setPrivateDnsBlocked(mBlockPrivateDns);
                        return kotlin.Unit.INSTANCE;
                    }
            );
        }
        mNetworkMonitor.setMonitoredNetworkHandle(mMonitoredNetwork);
        mNetworkMonitor.register(dns_server);
    }

    private void unregisterNetworkCallbacks() {
        if (mNetworkMonitor != null) {
            mNetworkMonitor.unregister();
        }
    }

    private void unregisterNewAppsInstallReceiver() {
        if(mNewAppsInstallReceiver != null) {
            unregisterReceiver(mNewAppsInstallReceiver);
            mNewAppsInstallReceiver = null;
        }
        if(mScreenStateMonitor != null) {
            mScreenStateMonitor.stopMonitoring();
            mScreenStateMonitor = null;
        }
        if(mNetworkStateMonitor != null) {
            mNetworkStateMonitor.stopMonitoring();
            mNetworkStateMonitor = null;
        }
        if(mRulesChangeListener != null) {
            AppNetworkRulesManager.getInstance(this).removeListener(mRulesChangeListener);
            mRulesChangeListener = null;
        }
        FileProtectionWatcher.getInstance(this).stopWatching();
    }

    private void handleLinkProperties(LinkProperties linkProperties) {
        if(linkProperties == null)
            return;

        if (mNetworkMonitor != null) {
            mNetworkMonitor.handleLinkProperties(linkProperties);
            mBlockPrivateDns = mNetworkMonitor.isPrivateDnsBlocked();
            mDnsEncrypted = mNetworkMonitor.isDnsEncrypted();
        }
    }

    private void signalServicesTermination() {
        mPendingUpdates.offer(new Pair<>(null, null));
        stopPcapDump();
    }

    // NOTE: do not call this on the main thread, otherwise it will be an ANR
    private void stopAndJoinThreads() {
        signalServicesTermination();

        Log.d(TAG, "Joining threads...");

        while((mConnUpdateThread != null) && (mConnUpdateThread.isAlive())) {
            try {
                Log.d(TAG, "Joining conn update thread...");
                mConnUpdateThread.join();
            } catch (InterruptedException ignored) {
                mPendingUpdates.offer(new Pair<>(null, null));
            }
        }
        mConnUpdateThread = null;

        while((mDumperThread != null) && (mDumperThread.isAlive())) {
            try {
                Log.d(TAG, "Joining dumper thread...");
                mDumperThread.join();
            } catch (InterruptedException ignored) {
                stopPcapDump();
            }
        }
        if (mDumperController != null) {
            mDumperController.join(2000L);
            mDumperController = null;
        }
        mDumperThread = null;
        mDumper = null;

        if(mMitmReceiver != null) {
            try {
                mMitmReceiver.stop();
            } catch (IOException e) {
                e.printStackTrace();
            }
            mMitmReceiver = null;
        }

        FirewallBlockHttpServer.getInstance(this).stop();
    }

    /* Stops the running Service. The SERVICE_STATUS_STOPPED notification is sent asynchronously
     * when mCaptureThread terminates. */
    @SuppressWarnings("deprecation")
    public static void stopService() {
        CaptureService captureService = INSTANCE;
        Log.d(TAG, "stopService called (instance? " + (captureService != null) + ")");

        if(captureService == null)
            return;

        captureService.mStopping = true;
        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().stopCapture();
        } catch (Throwable ignored) {}
        stopPacketLoop();
        captureService.unregisterNotificationReceiver();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            captureService.stopForeground(STOP_FOREGROUND_REMOVE);
        else
            captureService.stopForeground(true);

        captureService.stopSelf();
    }

    /* Check if the VPN service was launched */
    public static boolean isServiceActive() {
        return((INSTANCE != null) &&
                (INSTANCE.mCaptureThread != null));
    }

    public static void updateSocks5Proxy(String address, int port) {
        CaptureService service = INSTANCE;
        if (service != null) {
            service.mSocks5Address = address != null ? address : "";
            service.mSocks5Port = port;
            service.mSocks5Enabled = (address != null && !address.isEmpty() && port > 0);
            try {
                com.kotsafe.security.engine.KotEngineBridge.getInstance().setSocks5Proxy(
                        service.mSocks5Enabled ? address : null,
                        service.mSocks5Enabled ? port : 0);
                Log.i(TAG, "Dynamically updated KotEngine SOCKS5 proxy to " + address + ":" + port);
            } catch (Throwable t) {
                Log.w(TAG, "Failed to dynamically update SOCKS5 proxy: " + t.getMessage());
            }
        }
    }

    public static MitmReceiver.Status getMitmProxyStatus() {
        if((INSTANCE == null) || (INSTANCE.mMitmReceiver == null))
            return MitmReceiver.Status.NOT_STARTED;

        return INSTANCE.mMitmReceiver.getProxyStatus();
    }

    public static boolean isLowMemory() {
        return((INSTANCE != null) && (INSTANCE.mLowMemory));
    }

    public static boolean isAlwaysOnVPN() {
        return((INSTANCE != null) && INSTANCE.mIsAlwaysOnVPN);
    }

    public static boolean checkAlwaysOnVpnActivated() {
        CaptureService instance = INSTANCE;
        if (instance == null)
            return false;

        if (!instance.mIsAlwaysOnVPN && instance.isAlwaysOnVpnDetected()) {
            Log.i(TAG, "Always-on VPN was activated");
            instance.mIsAlwaysOnVPN = true;
            return true;
        }

        return false;
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    public static boolean isLockdownVPN() {
        return ((INSTANCE != null) && INSTANCE.isLockdownEnabled());
    }

    private void checkBlacklistsUpdates(boolean firstUpdate) {
        if(!mMalwareDetectionEnabled || (mBlacklistsUpdateThread != null))
            return;

        if(mBlacklistsUpdateRequested || mBlacklists.needsUpdate(firstUpdate)) {
            mBlacklistsUpdateThread = new Thread(this::updateBlacklistsWork, "Blacklists Update");
            mBlacklistsUpdateThread.start();
        }
    }

    private void updateBlacklistsWork() {
        mBlacklistsUpdateRequested = false;
        mBlacklists.update();
        reloadBlacklists();
        mBlacklistsUpdateThread = null;
    }

    private String getIfname(int ifidx) {
        if(ifidx <= 0)
            return "";

        String rv = mIfIndexToName.get(ifidx);
        if(rv != null)
            return rv;

        // Not found, try to retrieve it
        NetworkInterface iface = null;
        try {
            iface = NetworkInterface.getByIndex(ifidx);
        } catch (SocketException ignored) {}
        rv = (iface != null) ? iface.getName() : "";

        // store it even if not found, to avoid looking up it again
        mIfIndexToName.put(ifidx, rv);
        return rv;
    }

    public static Set<String> getAppFilter() {
        return((INSTANCE != null) ? INSTANCE.mSettings.app_filter : null);
    }

    public static Uri getPcapUri() {
        return ((INSTANCE != null) ? INSTANCE.mPcapUri : null);
    }

    public static String getPcapFname() {
        return ((INSTANCE != null) ? INSTANCE.mPcapFname : null);
    }

    public static boolean isUserDefinedPcapUri() {
        return (INSTANCE == null || !INSTANCE.mSettings.pcap_uri.isEmpty());
    }

    public static long getBytes() {
        return((INSTANCE != null) ? INSTANCE.last_bytes : 0);
    }

    public static long getCaptureStartTime() {
        return((INSTANCE != null) ? INSTANCE.mCaptureStartTime : 0);
    }

    public static long getCaptureStartTimeMonotonic() {
        return((INSTANCE != null) ? INSTANCE.mCaptureStartTimeMonotonic : 0);
    }

    public static String getCollectorAddress() {
        return((INSTANCE != null) ? INSTANCE.mSettings.collector_address : "");
    }

    public static int getCollectorPort() {
        return((INSTANCE != null) ? INSTANCE.mSettings.collector_port : 0);
    }

    public static int getHTTPServerPort() {
        return((INSTANCE != null) ? INSTANCE.mSettings.http_server_port : 0);
    }

    public static Prefs.DumpMode getDumpMode() {
        return((INSTANCE != null) ? INSTANCE.mSettings.dump_mode : Prefs.DumpMode.NONE);
    }

    public static String getDNSServer() {
        return((INSTANCE != null) ? INSTANCE.getDnsServer() : "");
    }

    public static boolean isDNSEncrypted() {
        return((INSTANCE != null) && INSTANCE.mDnsEncrypted);
    }

    public static @Nullable CaptureService getInstance() {
        return INSTANCE;
    }

    public static @NonNull CaptureService requireInstance() {
        CaptureService inst = INSTANCE;
        assert(inst != null);
        return(inst);
    }

    private static volatile ConnectionsRegister sSimulatedReg;

    public static @Nullable ConnectionsRegister getConnsRegister() {
        if (sSimulatedReg != null) {
            return sSimulatedReg;
        }
        return((INSTANCE != null) ? INSTANCE.conn_reg : null);
    }

    public static void setSimulatedConnsRegister(@Nullable ConnectionsRegister reg) {
        sSimulatedReg = reg;
    }

    public static @Nullable HttpLog getHttpLog() {
        return((INSTANCE != null) ? INSTANCE.mHttpLog : null);
    }

    public static @NonNull ConnectionsRegister requireConnsRegister() {
        ConnectionsRegister reg = getConnsRegister();
        if (reg == null) {
            if (INSTANCE != null && INSTANCE.conn_reg != null) {
                return INSTANCE.conn_reg;
            }
            if (sSimulatedReg != null) {
                return sSimulatedReg;
            }
            throw new IllegalStateException("ConnectionsRegister is not available");
        }
        return reg;
    }

    public static boolean isCapturingAsRoot() {
        return((INSTANCE != null) &&
                (INSTANCE.isRootCapture() == 1));
    }

    public static boolean isDecryptingTLS() {
        return((INSTANCE != null) &&
                (INSTANCE.isTlsDecryptionEnabled() == 1));
    }

    public static boolean isMalwareDetectionEnabled() {
        return((INSTANCE != null) &&
                (INSTANCE.mMalwareDetectionEnabled));
    }

    public static boolean isReadingFromPcapFile() {
        return((INSTANCE != null) &&
                (INSTANCE.isPcapFileCapture() == 1));
    }

    public static boolean isIPv6Enabled() {
        return((INSTANCE != null) &&
                (INSTANCE.getIPv6Enabled() == 1));
    }

    public static boolean isDecryptionListEnabled() {
        return(INSTANCE != null && (INSTANCE.mDecryptionList != null));
    }

    public static Prefs.PayloadMode getCurPayloadMode() {
        if(INSTANCE == null)
            return Prefs.PayloadMode.MINIMAL;

        return INSTANCE.mSettings.full_payload ? Prefs.PayloadMode.FULL : Prefs.PayloadMode.MINIMAL;
    }

    public static void requestBlacklistsUpdate() {
        if(INSTANCE != null) {
            INSTANCE.mBlacklistsUpdateRequested = true;

            // Wake the update thread to run the blacklist thread
            INSTANCE.mPendingUpdates.offer(new Pair<>(new ConnectionDescriptor[0], null));
        }
    }

    public static String getInterfaceName(int ifidx) {
        String ifname = null;

        if(INSTANCE != null)
            ifname = INSTANCE.getIfname(ifidx);
        return (ifname != null) ? ifname : "";
    }

    public static CaptureSettings getCaptureSettings() {
        return((INSTANCE != null) ? INSTANCE.mSettings : null);
    }

    private String resolveHost(String host) {
        if((Build.VERSION.SDK_INT < Build.VERSION_CODES.M) || (mUnderlyingNetwork == null))
            return null;

        try {
            return mUnderlyingNetwork.getByName(host).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    // Resolve hostnames that the native code needs as IPs.
    // Uses the underlying (non-VPN) network to avoid routing through the VPN tunnel.
    private boolean resolveHosts() {
        if(mSocks5Enabled && !mSettings.tls_decryption && !mSocks5Address.isEmpty()
                && !Utils.validateIpAddress(mSocks5Address))
        {
            String resolved = resolveHost(mSocks5Address);
            if(resolved == null) {
                Log.e(TAG, "Could not resolve SOCKS5 proxy: " + mSocks5Address);
                mHandler.post(() -> Utils.showToastLong(this, R.string.host_resolution_failed, mSocks5Address));
                return false;
            }
            Log.i(TAG, "Resolved SOCKS5 proxy: " + mSocks5Address + " -> " + resolved);
            mSocks5Address = resolved;
        }

        if(!mCollectorAddress.isEmpty() && !Utils.validateIpAddress(mCollectorAddress)) {
            String resolved = resolveHost(mCollectorAddress);
            if(resolved == null) {
                Log.e(TAG, "Could not resolve collector host: " + mCollectorAddress);
                mHandler.post(() -> Utils.showToastLong(this, R.string.host_resolution_failed, mCollectorAddress));
                return false;
            }

            Log.i(TAG, "Resolved collector host: " + mCollectorAddress + " -> " + resolved);
            mCollectorAddress = resolved;
        }

        if(Prefs.isPortMappingEnabled(mPrefs)) {
            PortMapping portMap = new PortMapping(this);
            Iterator<PortMapping.PortMap> it = portMap.iter();

            while(it.hasNext()) {
                PortMapping.PortMap mapping = it.next();
                String ip = mapping.redirect_host;

                if(!Utils.validateIpAddress(ip)) {
                    String resolved = resolveHost(ip);
                    if(resolved == null) {
                        Log.e(TAG, "Could not resolve port mapping host: " + ip);
                        final String failedHost = ip;
                        mHandler.post(() -> Utils.showToastLong(this, R.string.host_resolution_failed, failedHost));
                        return false;
                    }
                    Log.i(TAG, "Resolved port mapping host: " + ip + " -> " + resolved);
                    ip = resolved;
                }

                addPortMapping(mapping.ipproto, mapping.orig_port, mapping.redirect_port, ip);
            }

            Set<String> exemptPkgs = mPrefs.getStringSet(Prefs.PREF_PORT_MAPPING_EXEMPTIONS, Collections.emptySet());
            if(!exemptPkgs.isEmpty()) {
                AppsResolver resolver = new AppsResolver(this);
                ArrayList<Integer> exemptUids = new ArrayList<>();

                for(String pkg : exemptPkgs) {
                    int uid = resolver.getUid(pkg);
                    if(uid == Utils.UID_NO_FILTER) {
                        Log.w(TAG, "Could not resolve UID for port mapping exemption: " + pkg);
                        continue;
                    }
                    exemptUids.add(uid);
                }

                int[] uids = new int[exemptUids.size()];
                for(int i = 0; i < exemptUids.size(); i++)
                    uids[i] = exemptUids.get(i);

                Log.d(TAG, "Setting " + uids.length + " port mapping exemptions");
                setPortMappingExemptions(uids);
            }
        }

        return true;
    }

    // Inside the mCaptureThread
    @Override
    public void run() {
        boolean hostResolved = resolveHosts();
        mUnderlyingNetwork = null;

        // Allocate the exporter dumper now that the collector host has been resolved
        // in resolveHosts(). mCollectorAddress is guaranteed to be a numeric IP here
        if(hostResolved && !mCollectorAddress.isEmpty()) {
            try {
                InetAddress addr = InetAddress.getByName(mCollectorAddress);
                InetSocketAddress sockAddr = new InetSocketAddress(addr, mSettings.collector_port);

                if(mSettings.dump_mode == Prefs.DumpMode.UDP_EXPORTER)
                    mDumper = new UDPDumper(sockAddr, mSettings.pcapng_format);
                else
                    mDumper = new TCPDumper(sockAddr, mSettings.pcapng_format);
                if (mDumperController != null) {
                    mDumperController.initializeDumper(sockAddr);
                }
            } catch (UnknownHostException e) {
                reportError(e.getLocalizedMessage());
                e.printStackTrace();
                hostResolved = false;
            }
        }

        if(hostResolved && (mDumper != null)) {
            // Max memory usage = (JAVA_PCAP_BUFFER_SIZE * 64) = 32 MB
            mDumpQueue = new LinkedBlockingDeque<>(64);

            mDumperThread = new Thread(this::dumpWork, "DumperThread");
            mDumperThread.start();
            if (mDumperController != null) {
                mDumperController.start();
            }
        }

        if(!hostResolved) {
            // fall through to cleanup
        } else if(mSettings.root_capture || mSettings.readFromPcap()) {
            // Check for INTERACT_ACROSS_USERS, required to query apps of other users/work profiles
            if(mSettings.root_capture && (checkCallingOrSelfPermission(Utils.INTERACT_ACROSS_USERS) != PackageManager.PERMISSION_GRANTED)) {
                boolean success = Utils.rootGrantPermission(this, Utils.INTERACT_ACROSS_USERS);
                mHandler.post(() -> Utils.showToast(this, success ? R.string.permission_granted : R.string.permission_grant_fail, "INTERACT_ACROSS_USERS"));
            }

            runPacketLoop(-1, this, Build.VERSION.SDK_INT);
        } else {
            if(mParcelFileDescriptor != null) {
                int fd = mParcelFileDescriptor.getFd();
                int fd_setsize = getFdSetSize();

                if((fd > 0) && (fd < fd_setsize)) {
                    Log.d(TAG, "VPN fd: " + fd + " - FD_SETSIZE: " + fd_setsize);
                    mIsAlwaysOnVPN = false;

                    Log.i(TAG, "Starting KotSafe Clean-Room KotEngine Native Capture & Proxy Engine on fd: " + fd);
                    com.kotsafe.security.engine.KotEngineBridge bridge = com.kotsafe.security.engine.KotEngineBridge.getInstance();
                    bridge.setProtectDelegate(this::protect);
                    bridge.setPrivateDnsBlocked(mSettings.auto_block_private_dns);
                    boolean isGatewayClient = mPrefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED,
                            mPrefs.getBoolean(Prefs.PREF_P2P_EXIT_NODE_CLIENT_ENABLED, false));
                    String customDns = mPrefs.getString(Prefs.PREF_DNS_SERVER_V4, "").trim();
                    if (customDns.isEmpty() || "9.9.9.9".equals(customDns)
                            || (isGatewayClient && (customDns.startsWith("192.168.") || customDns.startsWith("10.") || customDns.startsWith("172.")))) {
                        customDns = (dns_server != null && !dns_server.isEmpty() && !"9.9.9.9".equals(dns_server)) ? dns_server : "1.1.1.1";
                    }
                    bridge.setCustomDns(customDns);
                    if (mPcapUri != null && "file".equalsIgnoreCase(mPcapUri.getScheme())) {
                        bridge.setPcapDump(mPcapUri.getPath());
                    }
                    if (mSocks5Enabled && mSocks5Address != null && !mSocks5Address.isEmpty() && mSocks5Port > 0) {
                        Log.i(TAG, "KotEngine: Configuring SOCKS5 proxy to " + mSocks5Address + ":" + mSocks5Port);
                        bridge.setSocks5Proxy(mSocks5Address, mSocks5Port);
                    } else {
                        bridge.setSocks5Proxy(null, 0);
                    }
                    sendServiceStatus("started");
                    int startRc = bridge.startCapture(fd);
                    if (startRc != 0) {
                        Log.e(TAG, "KotEngineBridge.startCapture failed with code: " + startRc);
                        reportError("KotEngine failed to start on TUN fd");
                    } else {
                        if (mSocks5Enabled && mSocks5Address != null && !mSocks5Address.isEmpty() && mSocks5Port > 0) {
                            bridge.setSocks5Proxy(mSocks5Address, mSocks5Port);
                        }
                        while (!mStopping) {
                            try {
                                Thread.sleep(500);
                                long[] raw = bridge.getStats();
                                if (raw != null && raw.length >= 7) {
                                    CaptureStats stats = new CaptureStats();
                                    stats.pkts_sent = (int)raw[0];
                                    stats.bytes_sent = raw[1];
                                    stats.pkts_rcvd = (int)raw[2];
                                    stats.bytes_rcvd = raw[3];
                                    stats.pkts_dropped = (int)raw[4];
                                    stats.active_conns = (int)raw[6];
                                    stats.tot_conns = raw.length > 7 ? (int)raw[7] : (int)raw[6];
                                    stats.num_dns_queries = raw.length > 8 ? (int)raw[8] : 0;
                                    sendStatsDump(stats);
                                }
                            } catch (InterruptedException e) {
                                break;
                            }
                        }
                        bridge.stopCapture();
                    }
                    sendServiceStatus("stopped");
                } else
                    Log.e(TAG, "Invalid VPN fd: " + fd);
            }
        }

        // After the capture is stopped
        if(mMalwareDetectionEnabled)
            mBlacklists.save();

        // Important: the fd must be closed to properly terminate the VPN
        if(mParcelFileDescriptor != null) {
            try {
                mParcelFileDescriptor.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
            mParcelFileDescriptor = null;
        }

        // NOTE: join the threads here instead in onDestroy to avoid ANR
        stopAndJoinThreads();

        stopService();

        mLock.lock();
        mCaptureThread = null;
        mCaptureStopped.signalAll();
        mLock.unlock();

        // Notify
        mHandler.post(() -> {
            updateServiceStatus(ServiceStatus.STOPPED);
            CaptureCtrl.notifyCaptureStopped(this, getStats());
        });
    }

    private void connUpdateWork() {
        while(true) {
            Pair<ConnectionDescriptor[], ConnectionUpdate[]> item;
            try {
                item = mPendingUpdates.take();
            } catch (InterruptedException e) {
                continue;
            }

            if(item.first == null) { // termination request
                Log.i(TAG, "Connection update thread exit requested");
                break;
            }

            ConnectionDescriptor[] new_conns = item.first;
            ConnectionUpdate[] conns_updates = item.second;

            checkBlacklistsUpdates(false);
            if(mBlocklist.checkGracePeriods())
                mHandler.post(this::reloadBlocklist);

            if(!mLowMemory)
                checkAvailableHeap();

            if(conns_updates == null)
                // wake-up request
                continue;

            // synchronize the conn_reg to ensure that newConnections and connectionsUpdates run atomically
            // thus preventing the ConnectionsAdapter from interleaving other operations
            synchronized (conn_reg) {
                if(new_conns.length > 0)
                    conn_reg.newConnections(new_conns);

                if(conns_updates.length > 0)
                    conn_reg.connectionsUpdates(conns_updates);
            }

            int val = mNumUpdatesInProgress.decrementAndGet();
            assert(val >= 0);

            if ((val == 0) && (mHttpLog != null))
                mHttpLog.stopConnectionsUpdates();
        }
    }

    private void dumpWork() {
        Log.d(TAG, "Starting the dumper");

        try {
            mDumper.startDumper();
        } catch (IOException | SecurityException e) {
            e.printStackTrace();
            reportError(e.getLocalizedMessage());
            mHandler.post(CaptureService::stopPacketLoop);
            return;
        }

        Log.d(TAG, "Dumper running");

        while(true) {
            byte[] data;
            try {
                data = mDumpQueue.take();
            } catch (InterruptedException e) {
                continue;
            }

            if(data.length == 0) // termination request
                break;

            try {
                mDumper.dumpData(data);
            } catch (IOException e) {
                // Stop the capture
                e.printStackTrace();
                reportError(e.getLocalizedMessage());
                mHandler.post(CaptureService::stopPacketLoop);
                break;
            }
        }

        try {
            mDumper.stopDumper();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void checkAvailableHeap() {
        // This does not account per-app jvm limits
        long availableHeap = Utils.getAvailableHeap();

        if(availableHeap <= Utils.LOW_HEAP_THRESHOLD) {
            Log.w(TAG, "Detected low HEAP memory: " + Utils.formatBytes(availableHeap));
            handleLowMemory();
        }
    }

    // NOTE: this is only called on low system memory (e.g. obtained via getMemoryInfo). The app
    // may still run out of heap memory, whose monitoring requires polling (see checkAvailableHeap)
    @Override
    @SuppressWarnings("deprecation")
    public void onTrimMemory(int level) {
        // NOTE: most trim levels are not available anymore since API 34
        String lvlStr = Utils.trimlvl2str(level);
        boolean lowMemory = (level != TRIM_MEMORY_UI_HIDDEN) && (level >= TRIM_MEMORY_RUNNING_LOW);
        boolean critical = lowMemory && (level >= TRIM_MEMORY_COMPLETE);

        Log.d(TAG, "onTrimMemory: " + lvlStr + " - low=" + lowMemory + ", critical=" + critical);

        if(critical && !mLowMemory)
            handleLowMemory();
    }

    private void handleLowMemory() {
        Log.w(TAG, "handleLowMemory called");
        mLowMemory = true;
        boolean fullPayload = getCurPayloadMode() == Prefs.PayloadMode.FULL;

        if(fullPayload) {
            Log.w(TAG, "Disabling full payload");

            // Disable full payload for new connections
            mSettings.full_payload = false;
            setPayloadMode(Prefs.PayloadMode.NONE.ordinal());

            if(mSettings.tls_decryption) {
                // TLS decryption without payload has little use, stop the capture all together
                stopService();
                notifyLowMemory(getString(R.string.capture_stopped_low_memory));
            } else {
                // Release memory for existing connections
                if(conn_reg != null) {
                    conn_reg.releasePayloadMemory();

                    // *possibly* call the gc
                    System.gc();

                    Log.i(TAG, "Memory stats full payload release:\n" + Utils.getMemoryStats(this));
                }

                notifyLowMemory(getString(R.string.full_payload_disabled));
            }
        } else {
            // Relieve memory pressure by downsizing connections register and purging lingering payloads
            if(conn_reg != null) {
                conn_reg.releasePayloadMemory();
                int currentSize = conn_reg.getSize();
                if(currentSize > 500) {
                    int reducedSize = Math.max(500, currentSize / 2);
                    Log.i(TAG, "Reducing connections register size under low memory: " + currentSize + " -> " + reducedSize);
                    conn_reg.setSize(reducedSize);
                }
                System.gc();
                Log.i(TAG, "Memory stats after low memory register reduction:\n" + Utils.getMemoryStats(this));
            }
            Log.w(TAG, "low memory handled, connections register resized to prevent OOM crash");
            notifyLowMemory(getString(R.string.low_memory_info));
        }
    }

    /* The following methods are called from native code */

    public String getVpnIPv4() {
        return(vpn_ipv4);
    }

    public String getVpnDns() {
        return(vpn_dns);
    }

    public String getDnsServer() {
        return(dns_server);
    }

    public String getIpv6DnsServer() { return(Prefs.getDnsServerV6(mPrefs)); }

    public int getSocks5Enabled() { return mSocks5Enabled ? 1 : 0; }

    public String getSocks5ProxyAddress() {  return(mSocks5Address); }

    public int getSocks5ProxyPort() {  return(mSocks5Port);  }

    public String getSocks5ProxyAuth() {  return(mSocks5Auth);  }

    public int getIPv4Enabled() { return((mSettings.ip_mode != Prefs.IpMode.IPV6_ONLY) ? 1 : 0); }

    public int getIPv6Enabled() { return((mSettings.ip_mode != Prefs.IpMode.IPV4_ONLY) ? 1 : 0); }

    public int isVpnCapture() { return (isRootCapture() | isPcapFileCapture()) == 1 ? 0 : 1; }

    public int isRootCapture() { return(mSettings.root_capture ? 1 : 0); }

    public int isPcapFileCapture() { return(mSettings.readFromPcap() ? 1 : 0); }

    public int isTlsDecryptionEnabled() { return mSettings.tls_decryption ? 1 : 0; }

    public int malwareDetectionEnabled() { return(mMalwareDetectionEnabled ? 1 : 0); }

    public int firewallEnabled() { return(mFirewallEnabled ? 1 : 0); }

    public int dumpExtensionsEnabled() { return(mSettings.dump_extensions ? 1 : 0); }

    public int isPcapngEnabled() { return(mSettings.pcapng_format ? 1 : 0); }

    public int[] getAppFilterUids() { return(mAppFilterUids); }

    public int getMitmAddonUid() {
        return MitmAddon.getUid(this);
    }

    public String getCaptureInterface() { return(mSettings.capture_interface); }

    public int getSnaplen() {  return mSettings.snaplen; }

    public int getMaxPktsPerFlow() {  return mSettings.max_pkts_per_flow; }

    public int getMaxDumpSize() {  return mSettings.max_dump_size; }

    public int getPayloadMode() { return getCurPayloadMode().ordinal(); }

    public int getVpnMTU()      { return VPN_MTU; }

    public int getBlockQuickMode() { return mSettings.block_quic_mode.ordinal(); }

    // returns 1 if dumpPcapData should be called
    public int pcapDumpEnabled() {
        return((mSettings.dump_mode != Prefs.DumpMode.NONE) ? 1 : 0);
    }

    public String getPcapDumperBpf() {
        if (mDumperController != null && !mDumperController.getDumperBpf().isEmpty()) {
            return mDumperController.getDumperBpf();
        }
        return ((mDumper != null) ? mDumper.getBpf() : "");
    }

    @Override
    public boolean protect(int socket) {
        // Do not call protect in root mode
        if(mSettings.root_capture)
            return true;

        return super.protect(socket);
    }

    @Override
    public boolean protect(Socket socket) {
        if(mSettings.root_capture)
            return true;

        return super.protect(socket);
    }

    @Override
    public boolean protect(java.net.DatagramSocket socket) {
        if(mSettings.root_capture)
            return true;

        return super.protect(socket);
    }

    // from NetGuard with enhanced local socket fallback & system port mapping
    @TargetApi(Build.VERSION_CODES.Q)
    public int getUidQ(int protocol, String saddr, int sport, String daddr, int dport) {
        if (protocol != 6 /* TCP */ && protocol != 17 /* UDP */) {
            if (protocol == 1 || protocol == 58) return 1000;
            return Utils.UID_UNKNOWN;
        }

        ConnectivityManager cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        if (cm == null) {
            if (dport == 53 || dport == 5353 || sport == 53 || sport == 5353) return 1000;
            return Utils.UID_UNKNOWN;
        }

        try {
            InetSocketAddress local = new InetSocketAddress(saddr, sport);
            InetSocketAddress remote = new InetSocketAddress(daddr, dport);

            int uid = cm.getConnectionOwnerUid(protocol, local, remote);
            if (uid >= 0) return uid;

            /* Fallback 1: try wildcard local address (0.0.0.0 or ::) */
            boolean isV6 = saddr != null && saddr.contains(":");
            local = new InetSocketAddress(isV6 ? "::" : "0.0.0.0", sport);
            uid = cm.getConnectionOwnerUid(protocol, local, remote);
            if (uid >= 0) return uid;

            /* Fallback 2: try inverted socket addresses */
            uid = cm.getConnectionOwnerUid(protocol, remote, new InetSocketAddress(saddr, sport));
            if (uid >= 0) return uid;

            return Utils.UID_UNKNOWN;
        } catch (Exception e) {
            return Utils.UID_UNKNOWN;
        }
    }

    public void startConnectionsUpdate() {
        int val = mNumUpdatesInProgress.incrementAndGet();
        assert(val >= 0);

        if ((val == 1) && (mHttpLog != null))
            mHttpLog.startConnectionsUpdates();
    }

    public void updateConnections(ConnectionDescriptor[] new_conns, ConnectionUpdate[] conns_updates) {
        if(mQueueFull)
            // if the queue is full, stop receiving updates to avoid inconsistent incr_ids
            return;

        // Put the update into a queue to avoid performing much work on the capture thread.
        // This will be processed by mConnUpdateThread.
        if(!mPendingUpdates.offer(new Pair<>(new_conns, conns_updates))) {
            Log.e(TAG, "The updates queue is full, this should never happen!");
            mQueueFull = true;
            mHandler.post(CaptureService::stopPacketLoop);
        }
    }

    public static boolean isUsharkAvailable(Context ctx) {
        return new File(getLibprogPath(ctx, "ushark")).exists();
    }

    // called from native
    public void sendStatsDump(CaptureStats stats) {
        //Log.d(TAG, "sendStatsDump");

        last_bytes = stats.bytes_sent + stats.bytes_rcvd;
        last_connections = stats.tot_conns;
        mHandler.post(this::updateNotification);

        // Record live speed point in TrafficTimeSeriesCollector for GlassWire graph
        try {
            TrafficTimeSeriesCollector.getInstance().recordLiveTick(
                    stats.bytes_rcvd, stats.bytes_sent, false, 0);
        } catch (Exception ignored) {}

        // notify the observers
        lastStats.postValue(stats);
    }

    // called from native
    private void sendServiceStatus(String cur_status) {
        updateServiceStatus(cur_status.equals("started") ? ServiceStatus.STARTED : ServiceStatus.STOPPED);
    }

    private void updateServiceStatus(ServiceStatus cur_status) {
        // notify the observers
        // NOTE: new subscribers will receive the STOPPED status right after their registration
        serviceStatus.postValue(cur_status);

        if(cur_status == ServiceStatus.STARTED) {
            if(mMalwareDetectionEnabled)
                reloadMalwareWhitelist();
            if(mDecryptionList != null)
                reloadDecryptionList();
            reloadBlocklist();
            reloadFirewallWhitelist();
        } else if (cur_status == ServiceStatus.STOPPED) {
            // NOTE: an API capture is not restarted, as the starter app is notified of the stop
            // and decides itself when to capture again
            if (mRevoked && Prefs.restartOnDisconnect(mPrefs) && !mIsAlwaysOnVPN
                    && !mSettings.api_capture && (isVpnCapture() == 1)) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                    Log.i(TAG, "VPN disconnected, starting reconnect service");

                    final Intent intent = new Intent(this, VpnReconnectService.class);
                    ContextCompat.startForegroundService(this, intent);
                }
            }
        }
    }

    // NOTE: to be invoked only by the native code
    public String getApplicationByUid(int uid) {
        AppDescriptor dsc = mNativeAppsResolver.getAppByUid(uid, 0);

        if(dsc == null)
            return "";

        return dsc.getName();
    }

    public String getPackageNameByUid(int uid) {
        AppDescriptor dsc = mNativeAppsResolver.getAppByUid(uid, 0);

        if(dsc == null)
            return "";

        return dsc.getPackageName();
    }

    public void loadUidMapping(int uid, String package_name, String app_name) {
        if (uid < 0)
            return;

        AppDescriptor dsc = mNativeAppsResolver.getAppByUid(uid, 0);

        if ((dsc == null) || !dsc.getPackageName().equals(package_name)) {
            // This uid corresponds to a different app than the one on the Pcapng
            AppsResolver.addMappedApp(uid, package_name, app_name);
        }
    }

    public String getCountryCode(String host) {
        if (mNativeGeolocation == null || !mNativeGeolocation.isAvailable())
            mNativeGeolocation = new Geolocation(this);

        if (mNativeGeolocation.isAvailable()) {
            try {
                InetAddress addr = InetAddress.getByName(host);
                return mNativeGeolocation.getCountryCode(addr);
            } catch (UnknownHostException ignored) {}
        }

        return "";
    }

    /* Exports a PCAP data chunk */
    public void dumpPcapData(byte[] data) {
        if(mDumperController != null) {
            mDumperController.dumpPcapData(data);
            return;
        }
        if((mDumper != null) && (data.length > 0)) {
            while(true) {
                try {
                    // wait until the queue has space to insert the data. If the queue is full, we
                    // will experience slow-downs/drops but this is expected
                    mDumpQueue.put(data);
                    break;
                } catch (InterruptedException e) {
                    // retry
                }
            }
        }
    }

    public void stopPcapDump() {
        if (mDumperController != null) {
            mDumperController.stop();
        }
        if((mDumpQueue != null) && (mDumperThread != null) && (mDumperThread.isAlive()))
            mDumpQueue.offer(new byte[0]);
    }

    public void reportError(String msg) {
        HAS_ERROR = true;

        mHandler.post(() -> {
            String err = msg;

            // Try to get a translated string (see errors.h)
            switch (msg) {
                case "Unsupported PCAP/Pcapng file":
                    err = getString(R.string.unsupported_pcap_file);
                    break;
                case "Invalid PCAP/Pcapng file":
                    err = getString(R.string.invalid_pcap_file);
                    break;
                case "Could not open the capture interface":
                    err = getString(R.string.capture_interface_open_error);
                    break;
                case "Unsupported datalink":
                    err = getString(R.string.unsupported_pcap_datalink);
                    break;
                case "The specified PCAP/Pcapng file does not exist":
                    err = getString(R.string.pcap_file_not_exists);
                    break;
                case "PCAP/Pcapng read error":
                    err = getString(R.string.pcap_read_error);
                    break;
            }

            Toast.makeText(this, err, Toast.LENGTH_LONG).show();
        });
    }

    public String getWorkingDir() {
        return getCacheDir().getAbsolutePath();
    }
    public String getPersistentDir() { return getFilesDir().getAbsolutePath(); }

    public String getLibprogPath(String prog_name) {
        return getLibprogPath(this, prog_name);
    }

    public static String getLibprogPath(Context ctx, String prog_name) {
        // executable binaries are stored into the /lib folder of the app
        String dir = ctx.getApplicationInfo().nativeLibraryDir;
        return(dir + "/lib" + prog_name + ".so");
    }

    public void notifyBlacklistsLoaded(Blacklists.NativeBlacklistStatus[] loaded_blacklists) {
        // this is invoked from the packet capture thread. Use the handler to save time.
        mHandler.post(() -> mBlacklists.onNativeLoaded(loaded_blacklists));
    }

    public BlacklistDescriptor[] getBlacklistsInfo() {
        BlacklistDescriptor[] blsinfo = new BlacklistDescriptor[mBlacklists.getNumBlacklists()];
        int i = 0;

        Iterator<BlacklistDescriptor> it = mBlacklists.iter();
        while(it.hasNext())
            blsinfo[i++] = it.next();

        return blsinfo;
    }

    public void reloadBlocklist() {
        if(!mFirewallSupported)
            return;

        Log.i(TAG, "reloading firewall blocklist (firewallEnabled=" + mFirewallEnabled + ", network=" + mCurrentNetworkType + ", screenOn=" + mIsScreenOn + ")");
        if(!mFirewallEnabled) {
            setLanBlockedUids(new int[0]);
            reloadBlocklist(new MatchList.ListDescriptor());
            return;
        }

        MatchList.ListDescriptor ld = mBlocklist.toListDescriptor();

        // Dynamically add apps blocked by Network Access Control
        AppNetworkRulesManager rulesMgr = AppNetworkRulesManager.getInstance(this);
        Set<Integer> dynamicBlockedUids = rulesMgr.getBlockedUids(mCurrentNetworkType, mIsScreenOn);
        for(int uid : dynamicBlockedUids) {
            if(!mBlocklist.isExemptedApp(uid) && !Utils.isSystemUid(uid) && !Utils.isSystemApp(this, uid)) {
                ld.apps.add(Integer.toString(uid));
            }
        }

        // Incorporate active rules from SecurityBlocklistManager (Action Center)
        try {
            SecurityBlocklistManager secMgr = SecurityBlocklistManager.getInstance(this);
            List<SecurityRulesDb.SecurityRule> secRules = secMgr.getAllBlockRules();
            for (SecurityRulesDb.SecurityRule r : secRules) {
                if (!r.enabled) continue;
                String val = r.value != null ? r.value.trim().toLowerCase() : "";
                if (val.isEmpty()) continue;

                if (SecurityRulesDb.TYPE_DOMAIN.equalsIgnoreCase(r.type)) {
                    String cleanDomain = SecurityRulesDb.cleanHostOrValue(val);
                    ld.hosts.add(!cleanDomain.isEmpty() ? cleanDomain : val);
                } else if (SecurityRulesDb.TYPE_IP.equalsIgnoreCase(r.type)) {
                    String cleanIp = SecurityRulesDb.cleanHostOrValue(val);
                    if (!cleanIp.isEmpty()
                            && !SecurityBlocklistManager.getInstance(this).isSystemWhitelisted(cleanIp)
                            && !SecurityBlocklistManager.isLocalOrConnectedDeviceIp(cleanIp)) {
                        ld.ips.add(cleanIp);
                    }
                } else if (SecurityRulesDb.TYPE_URL.equalsIgnoreCase(r.type)) {
                    String host = SecurityBlocklistManager.extractHost(val);
                    if (host != null && !host.isEmpty()) {
                        ld.hosts.add(host);
                    }
                } else if (SecurityRulesDb.TYPE_APP.equalsIgnoreCase(r.type)) {
                    try {
                        int uid = -1;
                        try {
                            uid = Integer.parseInt(val);
                        } catch (NumberFormatException nfe) {
                            uid = Utils.getPackageUid(getPackageManager(), val, 0);
                        }
                        if (uid > 0 && !mBlocklist.isExemptedApp(uid) && !Utils.isSystemUid(uid) && !Utils.isSystemApp(this, uid)
                                && !Utils.isEssentialOrBrowserApp(this, val)) {
                            ld.apps.add(Integer.toString(uid));
                            Log.i(TAG, "Firewall blocked app rule added: " + val + " (UID " + uid + ")");
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error adding security block rules to firewall: " + e.getMessage());
        }

        // Incorporate active custom blacklist rules from Privacy & Ad Tracker Shield
        try {
            com.kotsafe.security.model.AdBlockSubscriptionManager adBlockMgr =
                    com.kotsafe.security.model.AdBlockSubscriptionManager.getInstance(this);
            if (adBlockMgr != null && adBlockMgr.isAdBlockEnabled()) {
                java.util.Set<String> customBlacklist = adBlockMgr.getSeedAndCustomHostnames();
                for (String bDomain : customBlacklist) {
                    if (bDomain != null && !bDomain.isEmpty()) {
                        ld.hosts.add(bDomain.toLowerCase().trim());
                    }
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Error adding adblock custom blacklist to firewall: " + e.getMessage());
        }

        // Apply LAN blocked UIDs
        int[] lanUids = rulesMgr.getLanBlockedUids();
        setLanBlockedUids(lanUids);

        reloadBlocklist(ld);
    }

    public void reloadFirewallWhitelist() {
        if(!mFirewallSupported)
            return;

        Log.i(TAG, "reloading firewall whitelist");
        boolean wl_mode = FirewallPolicy.shouldForceWhitelistMode(mPrefs, mIsScreenOn, Prefs.isFirewallWhitelistMode(mPrefs));
        if (wl_mode) {
            MatchList.ListDescriptor ld = mFirewallWhitelist.toListDescriptor();
            // Automatically whitelist all system apps and UIDs by default
            Utils.addSystemAppsToWhitelistDescriptor(this, ld);
            reloadFirewallWhitelist(ld);
        } else {
            reloadFirewallWhitelist(null);
        }
    }

    public void setScreenOffBlockEnabled(boolean enabled) {
        if(!mFirewallSupported)
            return;
        if(mScreenStateMonitor != null) {
            if(enabled) {
                mScreenStateMonitor.startMonitoring();
                mScreenOffBlockingActive = FirewallPolicy.shouldBlockScreenOff(mPrefs, mScreenStateMonitor.isScreenOn());
            } else {
                mScreenStateMonitor.stopMonitoring();
                mScreenOffBlockingActive = false;
            }
        }
        reloadFirewallWhitelist();
    }

    public static void reloadMalwareWhitelist() {
        if((INSTANCE == null) || !INSTANCE.mMalwareDetectionEnabled)
            return;

        Log.i(TAG, "reloading malware whitelist");
        MatchList.ListDescriptor desc = (INSTANCE.mMalwareWhitelist != null)
                ? INSTANCE.mMalwareWhitelist.toListDescriptor()
                : new MatchList.ListDescriptor();

        // 1. Automatically include all verified speedtest, diagnostic, and operating system domains
        for (String host : SecurityBlocklistManager.getBuiltinMalwareWhitelistHosts()) {
            if (!desc.hosts.contains(host)) {
                desc.hosts.add(host);
            }
        }

        // 2. Automatically include trusted Anycast DNS & relay IPs
        for (String ip : SecurityBlocklistManager.getBuiltinTrustedIps()) {
            if (!desc.ips.contains(ip)) {
                desc.ips.add(ip);
            }
        }

        // 3. Automatically include configured P2P exit node host/IP
        try {
            String p2pHost = INSTANCE.mPrefs.getString(Prefs.PREF_P2P_EXIT_NODE_CLIENT_HOST, "");
            if (p2pHost != null && !p2pHost.trim().isEmpty()) {
                p2pHost = p2pHost.trim();
                if (ThreatIntelManager.isIpAddress(p2pHost)) {
                    if (!desc.ips.contains(p2pHost)) desc.ips.add(p2pHost);
                } else {
                    if (!desc.hosts.contains(p2pHost)) desc.hosts.add(p2pHost);
                }
            }
        } catch (Exception ignored) {}

        // 4. Automatically include verified diagnostic & speed-test apps
        //    so their traffic is never flagged as malicious by heuristic engine
        for (String pkg : SecurityBlocklistManager.getBuiltinWhitelistedApps()) {
            if (!desc.apps.contains(pkg)) {
                desc.apps.add(pkg);
            }
        }

        reloadMalwareWhitelist(desc);
    }

    public static void reloadDecryptionList() {
        if((INSTANCE == null) || (INSTANCE.mDecryptionList == null))
            return;

        Log.i(TAG, "reloading TLS decryption whitelist");
        reloadDecryptionList(INSTANCE.mDecryptionList.toListDescriptor());
    }

    public static void setFirewallEnabled(boolean enabled) {
        if(INSTANCE == null)
            return;

        INSTANCE.mFirewallEnabled = enabled;
        nativeSetFirewallEnabled(enabled);
        INSTANCE.reloadBlocklist();
        INSTANCE.reloadFirewallWhitelist();
    }

    public static @NonNull CaptureStats getStats() {
        CaptureStats stats = lastStats.getValue();
        return((stats != null) ? stats : new CaptureStats());
    }

    public static void observeStats(LifecycleOwner lifecycleOwner, Observer<CaptureStats> observer) {
        lastStats.observe(lifecycleOwner, observer);
    }

    public static void observeStatus(LifecycleOwner lifecycleOwner, Observer<ServiceStatus> observer) {
        serviceStatus.observe(lifecycleOwner, observer);
    }

    public static void waitForCaptureStop() {
        if(INSTANCE == null)
            return;

        Log.d(TAG, "waitForCaptureStop " + Thread.currentThread().getName());
        INSTANCE.mLock.lock();
        try {
            while(INSTANCE.mCaptureThread != null) {
                try {
                    INSTANCE.mCaptureStopped.await();
                } catch (InterruptedException ignored) {}
            }
        } finally {
            INSTANCE.mLock.unlock();
        }
        Log.d(TAG, "waitForCaptureStop done " + Thread.currentThread().getName());
    }

    public static boolean hasError() {
        return HAS_ERROR;
    }

    public static @Nullable Utils.PrivateDnsMode getPrivateDnsMode() {
        return isServiceActive() ? INSTANCE.mPrivateDnsMode : null;
    }

    private static final java.util.Map<Integer, java.io.Writer> sLogWriters = new java.util.concurrent.ConcurrentHashMap<>();
    private static final java.util.concurrent.atomic.AtomicInteger sLoggerIdGen = new java.util.concurrent.atomic.AtomicInteger(1);

    public static int initLogger(String path, int level) {
        try {
            int id = sLoggerIdGen.getAndIncrement();
            java.io.File file = new java.io.File(path);
            java.io.File parent = file.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            sLogWriters.put(id, new java.io.BufferedWriter(new java.io.FileWriter(file, true)));
            return id;
        } catch (Exception e) {
            return -1;
        }
    }

    public static int writeLog(int logger, int lvl, String message) {
        try {
            java.io.Writer w = sLogWriters.get(logger);
            if (w != null) {
                w.write(System.currentTimeMillis() + " [" + lvl + "] " + message + "\n");
                w.flush();
                return 0;
            }
        } catch (Exception ignored) {}
        return 0;
    }

    private static void initPlatformInfo(String appver, String device, String os) {
        // Platform metadata tracked in Java
    }

    private static void runPacketLoop(int fd, CaptureService vpn, int sdk) {
        // Forwarded to KotEngineBridge
    }

    private static void stopPacketLoop() {
        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().stopCapture();
        } catch (Throwable ignored) {}
    }

    private static int getFdSetSize() {
        return 1024;
    }

    private static void setPrivateDnsBlocked(boolean to_block) {
        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().setPrivateDnsBlocked(to_block);
        } catch (Throwable ignored) {}
    }

    private static void setDnsServer(String server) {
        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().setCustomDns(server);
        } catch (Throwable ignored) {}
    }

    private static void addPortMapping(int ipproto, int orig_port, int redirect_port, String redirect_ip) {
        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().addProxyRule(orig_port, redirect_ip, redirect_port);
        } catch (Throwable ignored) {}
    }

    public static void reloadPortMappings(Context context) {
        if (INSTANCE == null) return;
        new Thread(() -> {
            try {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
                boolean enabled = Prefs.isPortMappingEnabled(prefs);
                PortMapping portMap = new PortMapping(context);
                Iterator<PortMapping.PortMap> it = portMap.iter();
                while (it.hasNext()) {
                    PortMapping.PortMap mapping = it.next();
                    if (!enabled) {
                        try {
                            com.kotsafe.security.engine.KotEngineBridge.getInstance().removeProxyRule(mapping.orig_port);
                        } catch (Throwable ignored) {}
                    } else {
                        String ip = mapping.redirect_host;
                        if (!Utils.validateIpAddress(ip)) {
                            String resolved = INSTANCE.resolveHost(ip);
                            if (resolved != null) ip = resolved;
                        }
                        addPortMapping(mapping.ipproto, mapping.orig_port, mapping.redirect_port, ip);
                    }
                }
            } catch (Throwable ignored) {}
        }).start();
    }

    private static void setPortMappingExemptions(int[] uids) {
        try {
            if (uids != null && uids.length > 0) {
                com.kotsafe.security.engine.KotEngineBridge.getInstance().setProxyExemptUid(uids[0]);
            }
        } catch (Throwable ignored) {}
    }

    private static void setLanBlockedUids(int[] uids) {
        try {
            com.kotsafe.security.engine.KotEngineBridge.getInstance().setLanBlockedUids(uids);
        } catch (Throwable ignored) {}
    }

    private static void reloadBlacklists() {
        if (INSTANCE == null) return;
        new Thread(() -> {
            try {
                com.kotsafe.security.engine.KotEngineBridge bridge = com.kotsafe.security.engine.KotEngineBridge.getInstance();
                File bldir = new File(INSTANCE.getFilesDir().getPath() + "/malware_bl");
                if (!bldir.exists() || !bldir.isDirectory()) return;
                File[] files = bldir.listFiles();
                if (files == null) return;
                for (File f : files) {
                    if (!f.isFile() || !f.getName().endsWith(".txt")) continue;
                    try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(f))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            line = line.trim();
                            if (line.isEmpty() || line.startsWith("#") || line.startsWith("//")) continue;
                            int prefix = 32;
                            int slashIdx = line.indexOf('/');
                            String ipStr = line;
                            if (slashIdx > 0) {
                                try { prefix = Integer.parseInt(line.substring(slashIdx + 1)); } catch (Exception ignored) {}
                                ipStr = line.substring(0, slashIdx);
                            }
                            try {
                                InetAddress addr = InetAddress.getByName(ipStr);
                                byte[] bytes = addr.getAddress();
                                if (bytes.length == 4) {
                                    bridge.blacklistAdd(bytes, 4, prefix);
                                } else if (bytes.length == 16) {
                                    int p6 = (slashIdx > 0) ? prefix : 128;
                                    bridge.blacklistAdd(bytes, 6, p6);
                                }
                            } catch (Exception ignored) {}
                        }
                    } catch (Exception ignored) {}
                }
            } catch (Throwable ignored) {}
        }, "KotEngineBlacklistLoader").start();
    }

    private static boolean reloadBlocklist(MatchList.ListDescriptor blocklist) {
        try {
            com.kotsafe.security.engine.KotEngineBridge bridge = com.kotsafe.security.engine.KotEngineBridge.getInstance();
            bridge.blacklistClear(4);
            bridge.blacklistClear(6);
            bridge.clearBlockedDomains();

            if (blocklist != null && blocklist.hosts != null) {
                for (String host : blocklist.hosts) {
                    if (host != null && !host.trim().isEmpty()) {
                        bridge.addBlockedDomain(host.trim().toLowerCase());
                    }
                }
            }

            if (blocklist != null && blocklist.apps != null && !blocklist.apps.isEmpty()) {
                java.util.List<Integer> parsedUids = new java.util.ArrayList<>();
                for (String appStr : blocklist.apps) {
                    if (appStr == null || appStr.trim().isEmpty()) continue;
                    try {
                        parsedUids.add(Integer.parseInt(appStr.trim()));
                    } catch (NumberFormatException ignored) {}
                }
                if (!parsedUids.isEmpty()) {
                    int[] uidArr = new int[parsedUids.size()];
                    for (int i = 0; i < parsedUids.size(); i++) {
                        uidArr[i] = parsedUids.get(i);
                    }
                    bridge.setBlockedUids(uidArr);
                } else {
                    bridge.setBlockedUids(null);
                }
            } else {
                bridge.setBlockedUids(null);
            }

            if (blocklist != null && blocklist.ips != null) {
                for (String ipStr : blocklist.ips) {
                    if (ipStr == null || ipStr.trim().isEmpty()) continue;
                    ipStr = ipStr.trim();
                    int prefix = 32;
                    int slashIdx = ipStr.indexOf('/');
                    if (slashIdx > 0) {
                        try {
                            prefix = Integer.parseInt(ipStr.substring(slashIdx + 1));
                        } catch (Exception ignored) {}
                        ipStr = ipStr.substring(0, slashIdx);
                    }
                    try {
                        InetAddress addr = InetAddress.getByName(ipStr);
                        byte[] bytes = addr.getAddress();
                        if (bytes.length == 4) {
                            bridge.blacklistAdd(bytes, 4, prefix);
                        } else if (bytes.length == 16) {
                            int p6 = (slashIdx > 0) ? prefix : 128;
                            bridge.blacklistAdd(bytes, 6, p6);
                        }
                    } catch (Exception ignored) {}
                }
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean reloadFirewallWhitelist(MatchList.ListDescriptor whitelist) {
        return true;
    }

    private static boolean reloadMalwareWhitelist(MatchList.ListDescriptor whitelist) {
        return true;
    }

    private static boolean reloadDecryptionList(MatchList.ListDescriptor whitelist) {
        return true;
    }

    public static void askStatsDump() {
        try {
            long[] stats = com.kotsafe.security.engine.KotEngineBridge.getInstance().getStats();
            if (stats != null && stats.length >= 7 && INSTANCE != null) {
                CaptureStats cs = new CaptureStats();
                cs.pkts_sent = (int)stats[0];
                cs.bytes_sent = stats[1];
                cs.pkts_rcvd = (int)stats[2];
                cs.bytes_rcvd = stats[3];
                cs.pkts_dropped = (int)stats[4];
                cs.active_conns = (int)stats[6];
                cs.tot_conns = stats.length > 7 ? (int)stats[7] : (int)stats[6];
                cs.num_dns_queries = stats.length > 8 ? (int)stats[8] : 0;
                INSTANCE.sendStatsDump(cs);
            }
        } catch (Throwable ignored) {}
    }

    public static byte[] getPcapHeader() {
        // Standard PCAP Global Header: Magic (0xa1b2c3d4), Major 2, Minor 4, Thiszone 0, Sigfigs 0, Snaplen 65535, LinkType RAW (101 / 12)
        return new byte[] {
            (byte) 0xd4, (byte) 0xc3, (byte) 0xb2, (byte) 0xa1,
            0x02, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            (byte) 0xff, (byte) 0xff, 0x00, 0x00,
            0x65, 0x00, 0x00, 0x00
        };
    }

    private static boolean sFirewallEnabled = true;
    public static void nativeSetFirewallEnabled(boolean enabled) {
        sFirewallEnabled = enabled;
    }

    public static int getNumCheckedMalwareConnections() {
        return 0;
    }

    public static int getNumCheckedFirewallConnections() {
        ConnectionsRegister reg = getConnsRegister();
        return (reg != null) ? reg.getTotalInspectedConnections() : 0;
    }

    public static int rootCmd(String prog, String args) {
        return -1;
    }

    public static void setPayloadMode(int mode) {
        // Handled by KotEngineBridge
    }

    public static List<String> getL7Protocols() {
        return java.util.Arrays.asList("DNS", "TLS", "HTTP", "QUIC", "SSH", "NTP", "DHCP", "STUN", "IMAP", "SMTP");
    }

    public static void dumpMasterSecret(byte[] secret) {
        try {
            if (secret != null) {
                com.kotsafe.security.engine.KotEngineBridge.getInstance().addTlsSecret(new String(secret, java.nio.charset.StandardCharsets.UTF_8));
            }
        } catch (Throwable ignored) {}
    }

    public static boolean hasSeenDumpExtensions() {
        return false;
    }

    public static boolean extractKeylogFromPcapng(String pcapng_path, String out_path) {
        return false;
    }
}
