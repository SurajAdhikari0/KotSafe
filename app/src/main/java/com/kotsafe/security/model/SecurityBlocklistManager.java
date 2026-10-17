/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import java.util.List;
import java.util.Locale;

/**
 * SecurityBlocklistManager — single enforcement point for all security rules.
 *
 * This is the bridge between the security engine and the VPN tunnel (CaptureService).
 * CaptureService calls isBlocked() on the packet path — must be synchronous and fast.
 *
 * All write operations (addBlock, removeBlock) update SecurityRulesDb and
 * optionally hook into the existing AppNetworkRulesManager for app-level enforcement.
 */
public class SecurityBlocklistManager {
    private static final String TAG = "SecurityBlocklistManager";

    private static SecurityBlocklistManager sInstance;

    private final Context mContext;
    private final SecurityRulesDb mRulesDb;

    public static synchronized SecurityBlocklistManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SecurityBlocklistManager(context.getApplicationContext());
        }
        return sInstance;
    }

    public enum LockdownMode {
        NORMAL,
        BLOCK_ALL,
        BLOCK_NON_ESSENTIAL
    }

    private volatile LockdownMode mLockdownMode = LockdownMode.NORMAL;
    private volatile String mLockdownReason = null;

    public void setLockdownMode(LockdownMode mode, String reason) {
        mLockdownMode = mode != null ? mode : LockdownMode.NORMAL;
        mLockdownReason = reason;
        Log.w(TAG, "Lockdown mode changed to: " + mLockdownMode + " (Reason: " + reason + ")");
    }

    public LockdownMode getLockdownMode() {
        return mLockdownMode;
    }

    public String getLockdownReason() {
        return mLockdownReason;
    }

    public void restoreNormalPolicy() {
        setLockdownMode(LockdownMode.NORMAL, null);
    }

    private final java.util.Set<String> mFastBlocked = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final java.util.Set<String> mFastWhitelisted = java.util.concurrent.ConcurrentHashMap.newKeySet();

    private SecurityBlocklistManager(Context context) {
        mContext = context;
        mRulesDb = SecurityRulesDb.getInstance(context);
        reloadCache();
    }

    private final ThreadLocal<Boolean> mInReloadCache = ThreadLocal.withInitial(() -> Boolean.FALSE);

    public void reloadCache() {
        if (mInReloadCache.get()) return;
        mInReloadCache.set(Boolean.TRUE);
        try {
            mFastBlocked.clear();
            mFastWhitelisted.clear();
            List<SecurityRulesDb.SecurityRule> all = mRulesDb.getAllRules();
            for (SecurityRulesDb.SecurityRule r : all) {
                if (r != null && r.value != null && r.enabled) {
                    // 1. Purge ANY rule that was added via heuristic behavioral quarantine
                    if (r.reason != null && r.reason.contains("Behavioral quarantine")) {
                        Log.w(TAG, "Purging false-positive behavioral quarantine rule: " + r.value + " (" + r.reason + ")");
                        mRulesDb.deleteRule(r.id);
                        continue;
                    }
                    if (SecurityRulesDb.SOURCE_HEURISTIC.equalsIgnoreCase(r.source) && SecurityRulesDb.TYPE_APP.equalsIgnoreCase(r.type)) {
                        Log.w(TAG, "Purging heuristic app rule: " + r.value);
                        mRulesDb.deleteRule(r.id);
                        continue;
                    }
                    if (SecurityRulesDb.TYPE_APP.equalsIgnoreCase(r.type)
                            && (com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, r.value)
                                || com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, r.value)
                                || r.value.contains("amazon")
                                || r.value.contains("whatsapp")
                                || r.value.contains("flipkart"))) {
                        Log.w(TAG, "Purging false-positive app block rule: " + r.value);
                        mRulesDb.deleteRule(r.id);
                        continue;
                    }
                    String clean = SecurityRulesDb.cleanHostOrValue(r.value).toLowerCase(Locale.US);
                    if ((SecurityRulesDb.TYPE_DOMAIN.equalsIgnoreCase(r.type) || SecurityRulesDb.TYPE_URL.equalsIgnoreCase(r.type))
                            && (isOfficialDomain(clean) || isTrustedAdOrAnalyticsDomain(clean) || isSystemWhitelisted(clean))) {
                        Log.w(TAG, "Purging false-positive domain/url block rule: " + clean);
                        mRulesDb.deleteRule(r.id);
                        continue;
                    }
                    if (SecurityRulesDb.ACTION_BLOCK.equalsIgnoreCase(r.action)) {
                        mFastBlocked.add(clean);
                    } else if (SecurityRulesDb.ACTION_ALLOW.equalsIgnoreCase(r.action)) {
                        mFastWhitelisted.add(clean);
                    }
                }
            }
            try {
                com.kotsafe.security.model.Blocklist bl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
                if (bl != null) {
                    for (String app : bl.toListDescriptor().apps) {
                        if (com.kotsafe.security.Utils.isEssentialOrBrowserApp(mContext, app)
                            || com.kotsafe.security.Utils.isVerifiedGoogleTrustedService(mContext, app)) {
                            Log.w(TAG, "Purging false-positive from legacy blocklist: " + app);
                            bl.removeApp(app);
                        }
                    }
                }
            } catch (Exception ignored) {}
        } catch (Exception ignored) {}
        finally {
            mInReloadCache.set(Boolean.FALSE);
        }
    }

    public boolean isFastBlocked(String value) {
        if (value == null || value.isEmpty()) return false;
        String val = SecurityRulesDb.cleanHostOrValue(value).toLowerCase(Locale.US);
        if (mFastWhitelisted.contains(val)) return false;
        if (isOfficialDomain(val) && !mFastBlocked.contains(val)) return false;
        if (isMetaWhatsAppIp(val) && !mFastBlocked.contains(val)) return false;
        if (isGoogleIp(val) && !mFastBlocked.contains(val)) return false;
        if (isCloudflareCdnIp(val) && !mFastBlocked.contains(val)) return false;
        if (isLocalOrConnectedDeviceIp(val) && !mFastBlocked.contains(val)) return false;
        if (mFastBlocked.contains(val)) return true;
        if (isKnownMalwareC2(val)) return true;
        // Check subdomain hierarchy (e.g. sub.vegamoviess.foo -> vegamoviess.foo)
        int dot = val.indexOf('.');
        while (dot > 0 && dot < val.length() - 1) {
            val = val.substring(dot + 1);
            if (isOfficialDomain(val) && !mFastBlocked.contains(val)) return false;
            if (mFastBlocked.contains(val) || isKnownMalwareC2(val)) return true;
            dot = val.indexOf('.');
        }
        return false;
    }

    private void ensureUrlDomainRules() {
        try {
            List<SecurityRulesDb.SecurityRule> urlRules = mRulesDb.getRulesByType(SecurityRulesDb.TYPE_URL);
            for (SecurityRulesDb.SecurityRule r : urlRules) {
                if (r != null && r.value != null && SecurityRulesDb.ACTION_BLOCK.equalsIgnoreCase(r.action)) {
                    String host = extractHost(r.value);
                    if (host != null && !host.isEmpty() && !host.equalsIgnoreCase(r.value)) {
                        SecurityRulesDb.SecurityRule existing = mRulesDb.findBlockRule(host);
                        if (existing == null) {
                            mRulesDb.blockDomain(host, r.reason != null ? r.reason : "Blocked via URL rule", r.source);
                            Log.i(TAG, "Auto-populated host domain rule for: " + host);
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
    }

    // ─── Fast path (called on every packet) ──────────────────────────────────

    /**
     * Checks if a value belongs to an Android system application (package, hash, or IP).
    /**
     * Checks if a domain is part of official Android, Google, Samsung, or OEM cloud infrastructure.
     */
    public static boolean isOfficialDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String d = domain.toLowerCase().trim();
        if (d.startsWith("www.")) d = d.substring(4);
        return d.equals("google.com") || d.endsWith(".google.com")
                || d.equals("googleapis.com") || d.endsWith(".googleapis.com")
                || d.equals("gstatic.com") || d.endsWith(".gstatic.com")
                || d.equals("googleusercontent.com") || d.endsWith(".googleusercontent.com")
                || d.equals("gvt1.com") || d.endsWith(".gvt1.com")
                || d.equals("1e100.net") || d.endsWith(".1e100.net")
                || d.equals("android.com") || d.endsWith(".android.com")
                || d.equals("youtube.com") || d.endsWith(".youtube.com")
                || d.equals("googlevideo.com") || d.endsWith(".googlevideo.com")
                || d.equals("ytimg.com") || d.endsWith(".ytimg.com")
                || d.equals("youtu.be") || d.endsWith(".youtu.be")
                || d.equals("ggpht.com") || d.endsWith(".ggpht.com")
                || d.equals("youtubei.googleapis.com")
                || d.equals("brave.com") || d.endsWith(".brave.com")
                || d.equals("bravesoftware.com") || d.endsWith(".bravesoftware.com")
                || d.equals("whatsapp.com") || d.endsWith(".whatsapp.com")
                || d.equals("whatsapp.net") || d.endsWith(".whatsapp.net")
                || d.equals("fbcdn.net") || d.endsWith(".fbcdn.net")
                || d.equals("facebook.com") || d.endsWith(".facebook.com")
                || d.equals("facebook.net") || d.endsWith(".facebook.net")
                || d.equals("fb.me") || d.endsWith(".fb.me")
                || d.equals("fbsbx.com") || d.endsWith(".fbsbx.com")
                || d.equals("instagram.com") || d.endsWith(".instagram.com")
                || d.equals("cdninstagram.com") || d.endsWith(".cdninstagram.com")
                || d.equals("messenger.com") || d.endsWith(".messenger.com")
                || d.equals("meta.com") || d.endsWith(".meta.com")
                || d.equals("microsoft.com") || d.endsWith(".microsoft.com")
                || d.equals("live.com") || d.endsWith(".live.com")
                || d.equals("office.com") || d.endsWith(".office.com")
                || d.equals("apple.com") || d.endsWith(".apple.com")
                || d.equals("icloud.com") || d.endsWith(".icloud.com")
                || d.equals("mzstatic.com") || d.endsWith(".mzstatic.com")
                || d.equals("cloudflare.com") || d.endsWith(".cloudflare.com")
                || d.equals("cloudflare-dns.com") || d.endsWith(".cloudflare-dns.com")
                || d.equals("cloudfront.net") || d.endsWith(".cloudfront.net")
                || d.equals("amazonaws.com") || d.endsWith(".amazonaws.com")
                || d.equals("amazon.com") || d.endsWith(".amazon.com")
                || d.equals("amazon.in") || d.endsWith(".amazon.in")
                || d.endsWith(".media-amazon.com") || d.equals("media-amazon.com")
                || d.endsWith(".ssl-images-amazon.com") || d.equals("ssl-images-amazon.com")
                || d.contains(".amazon.") || d.contains("amazon-adsystem")
                || d.equals("flipkart.com") || d.endsWith(".flipkart.com")
                || d.equals("flipkart.net") || d.endsWith(".flipkart.net")
                || d.equals("a2z.com") || d.endsWith(".a2z.com")
                || d.equals("whatismyipaddress.com") || d.endsWith(".whatismyipaddress.com")
                || d.equals("ipify.org") || d.endsWith(".ipify.org")
                || d.equals("akamai.net") || d.endsWith(".akamai.net")
                || d.equals("akamaiedge.net") || d.endsWith(".akamaiedge.net")
                || d.equals("akamaihd.net") || d.endsWith(".akamaihd.net")
                || d.equals("fastly.net") || d.endsWith(".fastly.net")
                || d.equals("github.com") || d.endsWith(".github.com")
                || d.equals("githubusercontent.com") || d.endsWith(".githubusercontent.com")
                || d.equals("jsdelivr.net") || d.endsWith(".jsdelivr.net")
                || d.equals("db-ip.com") || d.endsWith(".db-ip.com")
                || d.equals("telegram.org") || d.endsWith(".telegram.org")
                || d.equals("t.me") || d.endsWith(".t.me")
                || d.equals("signal.org") || d.endsWith(".signal.org")
                || d.equals("samsung.com") || d.endsWith(".samsung.com")
                || d.equals("samsungcloud.com") || d.endsWith(".samsungcloud.com")
                || d.equals("samsungqbe.com") || d.endsWith(".samsungqbe.com")
                || d.equals("secb2b.com") || d.endsWith(".secb2b.com")
                || d.equals("samsungdm.com") || d.endsWith(".samsungdm.com")
                || d.equals("xiaomi.com") || d.endsWith(".xiaomi.com")
                || d.equals("mi.com") || d.endsWith(".mi.com")
                || d.equals("miui.com") || d.endsWith(".miui.com")
                || d.equals("huawei.com") || d.endsWith(".huawei.com")
                || d.equals("hicloud.com") || d.endsWith(".hicloud.com")
                || d.equals("oppo.com") || d.endsWith(".oppo.com")
                || d.equals("myoppo.com") || d.endsWith(".myoppo.com")
                || d.equals("oppomobile.com") || d.endsWith(".oppomobile.com")
                || d.equals("oplus.com") || d.endsWith(".oplus.com")
                || d.equals("oplusmobile.com") || d.endsWith(".oplusmobile.com")
                || d.equals("heytap.com") || d.endsWith(".heytap.com")
                || d.equals("heytapmobile.com") || d.endsWith(".heytapmobile.com")
                || d.equals("heytapcs.com") || d.endsWith(".heytapcs.com")
                || d.equals("heytapimage.com") || d.endsWith(".heytapimage.com")
                || d.equals("coloros.com") || d.endsWith(".coloros.com")
                || d.equals("realme.com") || d.endsWith(".realme.com")
                || d.equals("oneplus.com") || d.endsWith(".oneplus.com")
                || d.equals("oneplusmobile.com") || d.endsWith(".oneplusmobile.com")
                || d.equals("vivo.com") || d.endsWith(".vivo.com")
                || d.equals("iqoo.com") || d.endsWith(".iqoo.com")
                || d.equals("nothing.tech") || d.endsWith(".nothing.tech")
                || d.equals("motorola.com") || d.endsWith(".motorola.com")
                || d.equals("lenovo.com") || d.endsWith(".lenovo.com")
                || d.equals("asus.com") || d.endsWith(".asus.com")
                || d.equals("transsion.com") || d.endsWith(".transsion.com")
                || d.equals("infinixmobility.com") || d.endsWith(".infinixmobility.com")
                || d.equals("tecno-mobile.com") || d.endsWith(".tecno-mobile.com")
                || d.equals("sony.com") || d.endsWith(".sony.com")
                || d.equals("qualcomm.com") || d.endsWith(".qualcomm.com")
                // Google FCM, Push Notifications & Play Services endpoints
                || d.equals("mtalk.google.com") || d.endsWith(".mtalk.google.com")
                || d.equals("android.apis.google.com")
                || d.equals("device-provisioning.googleapis.com")
                || d.equals("firebaseinstallations.googleapis.com")
                || d.equals("fcmconnection.googleapis.com")
                || d.equals("play.google.com") || d.equals("play.googleapis.com")
                // Captive portal detection & Network connectivity check
                || d.equals("connectivitycheck.gstatic.com")
                || d.equals("connectivitycheck.android.com")
                || d.equals("clients3.google.com") || d.equals("clients1.google.com")
                || d.equals("clients2.google.com") || d.equals("clients4.google.com")
                || d.equals("detectportal.firefox.com")
                || d.equals("captive.apple.com")
                // NTP Time Synchronization
                || d.equals("time.android.com") || d.equals("time.google.com")
                || d.equals("pool.ntp.org") || d.endsWith(".pool.ntp.org")
                || d.equals("time.cloudflare.com") || d.equals("time.apple.com")
                || d.equals("time.windows.com") || d.equals("time.nist.gov")
                // Essential Payment Gateways & Banking infrastructure
                || d.equals("googlepay.com") || d.endsWith(".googlepay.com")
                || d.equals("pay.google.com") || d.equals("payments.google.com")
                || d.equals("wallet.google.com")
                || d.equals("npci.org.in") || d.endsWith(".npci.org.in")
                || d.equals("phonepe.com") || d.endsWith(".phonepe.com")
                || d.equals("paytm.com") || d.endsWith(".paytm.com")
                || d.equals("razorpay.com") || d.endsWith(".razorpay.com")
                || d.equals("cashfree.com") || d.endsWith(".cashfree.com")
                || d.equals("billdesk.com") || d.endsWith(".billdesk.com")
                || d.equals("ccavenue.com") || d.endsWith(".ccavenue.com")
                || d.equals("paypal.com") || d.endsWith(".paypal.com")
                || d.equals("trycloudflare.com") || d.endsWith(".trycloudflare.com")
                || d.equals("kotsafe.com") || d.endsWith(".kotsafe.com")
                || d.equals("cloudflareaccess.com") || d.endsWith(".cloudflareaccess.com")
                || d.equals("abuse.ch") || d.endsWith(".abuse.ch")
                || d.equals("virustotal.com") || d.endsWith(".virustotal.com")
                || d.equals("alienvault.com") || d.endsWith(".alienvault.com")
                || isSpeedTestOrDiagnosticDomain(d);
    }

    /**
     * Checks if a destination host or IP is a confirmed high-confidence Android malware C2 endpoint
     * (Operation Epic Fury / Fake RedAlert, SharkBot / TeaBot, FluBot, Rafel RAT, SpyNote).
     */
    public static boolean isKnownMalwareC2(String hostOrIp) {
        if (hostOrIp == null || hostOrIp.isEmpty()) return false;
        String v = hostOrIp.trim().toLowerCase(Locale.US);
        return v.equals("167.160.187.43")
                || v.equals("api.redalert-israel.org")
                || v.equals("redalert.zone")
                || v.equals("185.244.150.170")
                || v.equals("194.87.139.117")
                || v.equals("sharkbot-c2.top")
                || v.equals("teabot-update.live")
                || v.equals("anatsa-transfer.xyz")
                || v.equals("flubot-update.cc")
                || v.equals("cabassous-stage.su")
                || v.equals("rafel-rat.duckdns.org")
                || v.equals("spynote-dns.ddns.net");
    }

    /**
     * Checks if a domain is a verified speedtest, bandwidth measurement, or IP verification service,
     * ensuring that speedtests and IP checks are never flagged as malicious.
     */
    public static boolean isSpeedTestOrDiagnosticDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String d = domain.toLowerCase().trim();
        if (d.startsWith("www.")) d = d.substring(4);
        return d.equals("speedtest.net") || d.endsWith(".speedtest.net")
                || d.equals("ookla.com") || d.endsWith(".ookla.com")
                || d.equals("ooklaserver.net") || d.endsWith(".ooklaserver.net")
                || d.equals("speedtestcustom.com") || d.endsWith(".speedtestcustom.com")
                || d.equals("fast.com") || d.endsWith(".fast.com")
                || d.equals("netflix.com") || d.endsWith(".netflix.com")
                || d.equals("nflxvideo.net") || d.endsWith(".nflxvideo.net")
                || d.equals("nflxext.com") || d.endsWith(".nflxext.com")
                || d.equals("nflxso.net") || d.endsWith(".nflxso.net")
                || d.equals("nflximg.net") || d.endsWith(".nflximg.net")
                || d.equals("openspeedtest.com") || d.endsWith(".openspeedtest.com")
                || d.equals("measurementlab.net") || d.endsWith(".measurementlab.net")
                || d.equals("ipinfo.io") || d.endsWith(".ipinfo.io")
                || d.equals("ipify.org") || d.endsWith(".ipify.org")
                || d.equals("whatismyip.com") || d.endsWith(".whatismyip.com")
                || d.equals("whatismyipaddress.com") || d.endsWith(".whatismyipaddress.com")
                || d.equals("icanhazip.com") || d.endsWith(".icanhazip.com")
                || d.equals("ident.me") || d.endsWith(".ident.me")
                || d.equals("ifconfig.me") || d.endsWith(".ifconfig.me")
                || d.equals("ifconfig.co") || d.endsWith(".ifconfig.co")
                || d.equals("ip.sb") || d.endsWith(".ip.sb")
                || d.equals("ip-api.com") || d.endsWith(".ip-api.com")
                || d.equals("checkip.amazonaws.com")
                || d.equals("myip.opendns.com")
                || d.equals("ipgeolocation.io") || d.endsWith(".ipgeolocation.io")
                || d.equals("ip2location.com") || d.endsWith(".ip2location.com")
                || d.equals("db-ip.com") || d.endsWith(".db-ip.com")
                || d.equals("whois.arin.net") || d.endsWith(".whois.arin.net")
                || d.equals("whois.ripe.net") || d.endsWith(".whois.ripe.net")
                || d.equals("whois.apnic.net") || d.endsWith(".whois.apnic.net")
                || d.equals("worldlink.com.np") || d.endsWith(".worldlink.com.np")
                || d.equals("subisu.net.np") || d.endsWith(".subisu.net.np")
                || d.equals("ntc.net.np") || d.endsWith(".ntc.net.np")
                || d.equals("vianet.com.np") || d.endsWith(".vianet.com.np")
                || d.equals("classic.com.np") || d.endsWith(".classic.com.np")
                || d.equals("npix.net.np") || d.endsWith(".npix.net.np")
                || d.equals("librespeed.org") || d.endsWith(".librespeed.org")
                || d.equals("testmy.net") || d.endsWith(".testmy.net")
                || d.equals("dslreports.com") || d.endsWith(".dslreports.com")
                || d.equals("speedtest.att.com")
                || d.equals("speedtest.verizon.net")
                || d.equals("speedtest.xfinity.com")
                || d.equals("speedtest.bt.com")
                || d.equals("ifconfig.io") || d.endsWith(".ifconfig.io")
                || d.equals("ipdata.co") || d.endsWith(".ipdata.co")
                || d.equals("ipstack.com") || d.endsWith(".ipstack.com")
                || d.equals("ipregistry.co") || d.endsWith(".ipregistry.co")
                || d.equals("whois.lacnic.net") || d.endsWith(".whois.lacnic.net")
                || d.equals("whois.afrinic.net") || d.endsWith(".whois.afrinic.net")
                || d.equals("bgp.he.net") || d.endsWith(".bgp.he.net")
                || d.equals("bgpview.io") || d.endsWith(".bgpview.io")
                || d.equals("peeringdb.com") || d.endsWith(".peeringdb.com")
                || d.equals("stun.cloudflare.com")
                || d.equals("stun.nextcloud.com")
                || d.equals("b-cdn.net") || d.endsWith(".b-cdn.net")
                || d.equals("bunny.net") || d.endsWith(".bunny.net")
                || d.equals("bunnycdn.com") || d.endsWith(".bunnycdn.com")
                || d.equals("edgecastcdn.net") || d.endsWith(".edgecastcdn.net")
                || d.equals("systemcdn.net") || d.endsWith(".systemcdn.net")
                || d.equals("llnwd.net") || d.endsWith(".llnwd.net")
                || d.equals("edgio.net") || d.endsWith(".edgio.net")
                || d.equals("azureedge.net") || d.endsWith(".azureedge.net")
                || d.equals("trafficmanager.net") || d.endsWith(".trafficmanager.net")
                || d.equals("msecnd.net") || d.endsWith(".msecnd.net");
    }

    /**
     * Set of built-in domain roots automatically passed to native malware whitelist
     * to protect core speedtest, diagnostic, and operating system services worldwide.
     */
    public static List<String> getBuiltinMalwareWhitelistHosts() {
        return java.util.Arrays.asList(
                "speedtest.net", "ookla.com", "ooklaserver.net", "speedtestcustom.com",
                "fast.com", "netflix.com", "nflxvideo.net", "nflxext.com", "nflxso.net", "nflximg.net",
                "openspeedtest.com", "measurementlab.net", "speed.cloudflare.com",
                "librespeed.org", "testmy.net", "dslreports.com",
                "ipinfo.io", "ipify.org", "whatismyip.com", "whatismyipaddress.com",
                "icanhazip.com", "ident.me", "ifconfig.me", "ifconfig.co", "ifconfig.io", "ip.sb", "ip-api.com",
                "checkip.amazonaws.com", "checkip.dyndns.org", "myip.opendns.com",
                "ipgeolocation.io", "ip2location.com", "db-ip.com", "ipdata.co", "ipstack.com", "ipregistry.co",
                "whois.arin.net", "whois.ripe.net", "whois.apnic.net", "whois.lacnic.net", "whois.afrinic.net",
                "bgp.he.net", "bgpview.io", "peeringdb.com",
                "dns.google", "one.one.one.one", "quad9.net",
                "google.com", "googleapis.com", "gstatic.com", "1e100.net", "googleusercontent.com",
                "cloudflare.com", "cloudflare-dns.com", "trycloudflare.com", "kotsafe.com", "cloudflareaccess.com",
                "akamai.net", "akamaiedge.net", "akamaihd.net", "fastly.net",
                "b-cdn.net", "bunny.net", "bunnycdn.com", "edgecastcdn.net", "systemcdn.net", "llnwd.net", "edgio.net",
                "azureedge.net", "trafficmanager.net", "msecnd.net",
                "apple.com", "icloud.com", "microsoft.com", "live.com", "office.com",
                "whatsapp.com", "whatsapp.net", "telegram.org", "t.me", "signal.org",
                "worldlink.com.np", "subisu.net.np", "ntc.net.np", "vianet.com.np", "classic.com.np", "npix.net.np"
        );
    }

    /**
     * Built-in trusted Anycast DNS and relay infrastructure IPs exempt from malware IP blocks.
     */
    public static List<String> getBuiltinTrustedIps() {
        return java.util.Arrays.asList(
                // DNS resolvers
                "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                // KotSafe VPS relay
                com.kotsafe.security.model.backend.BackendProviderFactory.getDirectVpsHost(),
                // Meta / WhatsApp well-known IPs (sample anchors for the CIDR ranges)
                "31.13.64.1", "31.13.65.1", "31.13.66.1", "31.13.68.1", "31.13.69.1",
                "31.13.70.1", "31.13.71.1", "31.13.72.1", "31.13.73.1", "31.13.74.1",
                "31.13.92.1", "31.13.94.1",
                "163.70.145.1", "163.70.128.1",
                "57.144.64.1",
                "179.60.192.1", "179.60.193.1", "179.60.194.1", "179.60.195.1",
                "185.60.216.1", "185.60.217.1", "185.60.218.1", "185.60.219.1",
                "66.220.144.1", "66.220.153.1",
                "69.171.224.1", "69.171.250.1",
                // Google / AS15169 well-known IP anchors (covers all major CIDR blocks)
                "74.125.24.100", "74.125.68.100", "74.125.130.100", "74.125.198.100",
                "172.217.14.100", "172.217.160.100", "172.253.56.100",
                "173.194.40.100", "173.194.192.100",
                "142.250.68.100", "142.250.185.100", "142.251.1.100",
                "209.85.128.100", "209.85.200.100",
                "216.58.192.100", "216.58.223.100",
                "216.239.32.100", "216.239.38.100",
                "64.233.160.100", "64.233.180.100",
                "66.102.1.100", "66.249.68.100",
                "108.177.8.100", "108.177.97.100",
                // Local network, gateway & connected device IP anchors
                "127.0.0.1", "192.168.1.1", "192.168.43.1", "192.168.49.1", "10.0.0.1"
        );
    }


    /**
     * Known legitimate diagnostic and speed measurement apps that should never be blocked by malware heuristics.
     */
    public static List<String> getBuiltinWhitelistedApps() {
        return java.util.Arrays.asList(
                "org.zwanoo.android.speedtest",
                "com.netflix.Speed",
                "com.google.android.apps.smetrics",
                "cz.nic.librespeed",
                "com.vrem.wifianalyzer",
                "net.he.networktools",
                "com.ubnt.usurvey",
                "org.broadbandmap"
        );
    }

    /**
     * Checks if a domain is a verified mainstream ad/telemetry delivery network,
     * ensuring it is not misclassified as malicious C2 or high-risk malware by heuristic scanners.
     */
    public static boolean isTrustedAdOrAnalyticsDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        String d = domain.toLowerCase().trim();
        if (d.startsWith("www.")) d = d.substring(4);
        return d.equals("googleadservices.com") || d.endsWith(".googleadservices.com")
                || d.equals("googlesyndication.com") || d.endsWith(".googlesyndication.com")
                || d.equals("doubleclick.net") || d.endsWith(".doubleclick.net")
                || d.equals("admob.com") || d.endsWith(".admob.com")
                || d.equals("applovin.com") || d.endsWith(".applovin.com")
                || d.equals("unityads.unity3d.com") || d.endsWith(".unityads.unity3d.com")
                || d.equals("criteo.com") || d.endsWith(".criteo.com")
                || d.equals("criteo.net") || d.endsWith(".criteo.net")
                || d.equals("ironsrc.com") || d.endsWith(".ironsrc.com")
                || d.equals("vungle.com") || d.endsWith(".vungle.com")
                || d.equals("inmobi.com") || d.endsWith(".inmobi.com")
                || d.equals("chartboost.com") || d.endsWith(".chartboost.com");
    }

    /**
     * Checks if a domain is part of official/trusted infrastructure or verified network.
     */
    public static boolean isOfficialOrTrustedDomain(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        return isOfficialDomain(domain) || isTrustedAdOrAnalyticsDomain(domain);
    }

    /**
     * Identifies official Anycast CDN and recursive DNS infrastructure IPs (e.g. Cloudflare CDN).
     */
    public static boolean isCloudflareCdnIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String s = ip.trim();
        return s.startsWith("104.16.") || s.startsWith("104.17.") || s.startsWith("104.18.")
                || s.startsWith("104.19.") || s.startsWith("104.20.") || s.startsWith("104.21.")
                || s.startsWith("104.22.") || s.startsWith("104.23.") || s.startsWith("104.24.")
                || s.startsWith("104.25.") || s.startsWith("104.26.") || s.startsWith("104.27.")
                || s.startsWith("104.28.") || s.startsWith("104.29.") || s.startsWith("104.30.")
                || s.startsWith("104.31.") || s.startsWith("172.64.") || s.startsWith("172.65.")
                || s.startsWith("172.66.") || s.startsWith("172.67.") || s.startsWith("172.68.")
                || s.startsWith("172.69.") || s.startsWith("172.70.") || s.startsWith("172.71.")
                || s.equals("1.1.1.1") || s.equals("1.0.0.1") || s.equals("8.8.8.8") || s.equals("8.8.4.4");
    }

    /**
     * Returns true if the given IP address belongs to Meta/WhatsApp infrastructure.
     *
     * WhatsApp frequently connects using raw IPs (no SNI / no domain in conn.info) on
     * these CIDR blocks. Without this guard the IP-based malware heuristics can
     * incorrectly flag and block all WhatsApp traffic.
     *
     * Sources: Meta AS32934 / AS63293 BGP announcements (public ARIN/RIPE data).
     * Ranges covered:
     *   31.13.24.0/21, 31.13.64.0/18   — European Meta edge nodes
     *   57.144.0.0/14                   — Meta global backbone (announced ~2022)
     *   66.220.144.0/20                 — Older US FB/WA servers
     *   69.171.224.0/19                 — US FB/WA servers
     *   163.70.128.0/17                 — Meta WA global edge (announced 2021+)
     *   179.60.192.0/22                 — Latin-American WA edge
     *   185.60.216.0/22                 — European WA edge
     */
    public static boolean isMetaWhatsAppIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String s = ip.trim();
        // Strip IPv6-mapped-IPv4 prefix (e.g. ::ffff:163.70.145.60)
        if (s.startsWith("::ffff:")) s = s.substring(7);
        // 31.13.24.0/21  → 31.13.24–31
        if (s.startsWith("31.13.24.") || s.startsWith("31.13.25.") || s.startsWith("31.13.26.")
                || s.startsWith("31.13.27.") || s.startsWith("31.13.28.") || s.startsWith("31.13.29.")
                || s.startsWith("31.13.30.") || s.startsWith("31.13.31.")) return true;
        // 31.13.64.0/18  → 31.13.64–127
        try {
            if (s.startsWith("31.13.")) {
                int third = Integer.parseInt(s.split("\\.")[2]);
                if (third >= 64 && third <= 127) return true;
            }
        } catch (Exception ignored) {}
        // 57.144.0.0/14  → 57.144–147.x.x
        try {
            if (s.startsWith("57.")) {
                int second = Integer.parseInt(s.split("\\.")[1]);
                if (second >= 144 && second <= 147) return true;
            }
        } catch (Exception ignored) {}
        // 66.220.144.0/20 → 66.220.144–159.x
        try {
            if (s.startsWith("66.220.")) {
                int third = Integer.parseInt(s.split("\\.")[2]);
                if (third >= 144 && third <= 159) return true;
            }
        } catch (Exception ignored) {}
        // 69.171.224.0/19 → 69.171.224–255.x
        try {
            if (s.startsWith("69.171.")) {
                int third = Integer.parseInt(s.split("\\.")[2]);
                if (third >= 224) return true;
            }
        } catch (Exception ignored) {}
        // 163.70.128.0/17 → 163.70.128–255.x
        try {
            if (s.startsWith("163.70.")) {
                int third = Integer.parseInt(s.split("\\.")[2]);
                if (third >= 128) return true;
            }
        } catch (Exception ignored) {}
        // 179.60.192.0/22 → 179.60.192–195.x
        try {
            if (s.startsWith("179.60.")) {
                int third = Integer.parseInt(s.split("\\.")[2]);
                if (third >= 192 && third <= 195) return true;
            }
        } catch (Exception ignored) {}
        // 185.60.216.0/22 → 185.60.216–219.x
        try {
            if (s.startsWith("185.60.")) {
                int third = Integer.parseInt(s.split("\\.")[2]);
                if (third >= 216 && third <= 219) return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Returns true if the given IP belongs to Google's global infrastructure (AS15169 / AS396982).
     *
     * Google apps (Gmail, Maps, Drive, Chrome, YouTube, Play Store, etc.) routinely open
     * connections to raw IPs on these CIDR blocks with no domain in conn.info.  Without this
     * guard the IP heuristics incorrectly block or flag all of those connections.
     *
     * CIDR ranges (public ARIN / RIPE / Google goog.json):
     *   8.8.4.0/24, 8.8.8.0/24           Google Public DNS
     *   34.64.0.0/10 (34.64–127.x.x)     Google Cloud global
     *   34.128.0.0/10 (34.128–191.x.x)   Google Cloud global
     *   35.184.0.0/13 (35.184–191.x.x)   Google Cloud US
     *   35.192.0.0/11 (35.192–223.x.x)   Google Cloud US
     *   35.224.0.0/12 (35.224–239.x.x)   Google Cloud US
     *   35.240.0.0/13 (35.240–247.x.x)   Google Cloud EU
     *   64.233.160.0/19                   Google front-end
     *   66.102.0.0/20                     Google services
     *   66.249.64.0/19                    Googlebot / edge
     *   72.14.192.0/18                    Google backbone
     *   74.125.0.0/16                     Google global
     *   108.177.8.0/21, 108.177.96.0/19  Google services
     *   142.250.0.0/15 (142.250–251.x.x) Google global edge (main block)
     *   172.217.0.0/16                    Google global
     *   172.253.0.0/16                    Google services
     *   173.194.0.0/16                    Google global
     *   209.85.128.0/17 (209.85.128–255) Google services
     *   216.58.192.0/19                   Google global
     *   216.239.32.0/19                   Google anycast
     */
    public static boolean isGoogleIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String s = ip.trim();
        if (s.startsWith("::ffff:")) s = s.substring(7);
        // Google Public DNS exact
        if ("8.8.8.8".equals(s) || "8.8.4.4".equals(s)) return true;
        // 34.64.0.0/10 → second octet 64–127
        try {
            if (s.startsWith("34.")) {
                int sec = Integer.parseInt(s.split("\\.")[1]);
                if (sec >= 64 && sec <= 191) return true;   // covers 34.64–191
            }
        } catch (Exception ignored) {}
        // 35.184–247 (multiple /11, /12, /13 sub-blocks)
        try {
            if (s.startsWith("35.")) {
                int sec = Integer.parseInt(s.split("\\.")[1]);
                if (sec >= 184 && sec <= 247) return true;
            }
        } catch (Exception ignored) {}
        // 64.233.160.0/19 → 64.233.160–191
        try {
            if (s.startsWith("64.233.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr >= 160 && thr <= 191) return true;
            }
        } catch (Exception ignored) {}
        // 66.102.0.0/20 → 66.102.0–15
        try {
            if (s.startsWith("66.102.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr <= 15) return true;
            }
        } catch (Exception ignored) {}
        // 66.249.64.0/19 → 66.249.64–95
        try {
            if (s.startsWith("66.249.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr >= 64 && thr <= 95) return true;
            }
        } catch (Exception ignored) {}
        // 72.14.192.0/18 → 72.14.192–255
        try {
            if (s.startsWith("72.14.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr >= 192) return true;
            }
        } catch (Exception ignored) {}
        // 74.125.0.0/16
        if (s.startsWith("74.125.")) return true;
        // 108.177.8.0/21 and 108.177.96.0/19
        try {
            if (s.startsWith("108.177.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if ((thr >= 8 && thr <= 15) || (thr >= 96 && thr <= 127)) return true;
            }
        } catch (Exception ignored) {}
        // 142.250.0.0/15 → second octet 250–251
        try {
            if (s.startsWith("142.")) {
                int sec = Integer.parseInt(s.split("\\.")[1]);
                if (sec >= 250 && sec <= 251) return true;
            }
        } catch (Exception ignored) {}
        // 172.217.0.0/16 and 172.253.0.0/16
        if (s.startsWith("172.217.") || s.startsWith("172.253.")) return true;
        // 173.194.0.0/16
        if (s.startsWith("173.194.")) return true;
        // 209.85.128.0/17 → 209.85.128–255
        try {
            if (s.startsWith("209.85.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr >= 128) return true;
            }
        } catch (Exception ignored) {}
        // 216.58.192.0/19 → 216.58.192–223
        try {
            if (s.startsWith("216.58.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr >= 192 && thr <= 223) return true;
            }
        } catch (Exception ignored) {}
        // 216.239.32.0/19 → 216.239.32–63
        try {
            if (s.startsWith("216.239.")) {
                int thr = Integer.parseInt(s.split("\\.")[2]);
                if (thr >= 32 && thr <= 63) return true;
            }
        } catch (Exception ignored) {}
        return false;
    }

    /**
     * Returns true if the IP belongs to a local LAN, loopback, gateway, Wi-Fi hotspot,
     * tethered client, or connected device on the local network subnet.
     */
    public static boolean isLocalOrConnectedDeviceIp(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String s = ip.trim();
        if (s.startsWith("::ffff:")) s = s.substring(7);

        // Loopback / localhost
        if ("127.0.0.1".equals(s) || "localhost".equalsIgnoreCase(s) || "::1".equals(s) || "0.0.0.0".equals(s)) {
            return true;
        }

        // Private IPv4 ranges (RFC 1918) & Hotspot/Tethering ranges
        // 10.0.0.0/8 (10.x.x.x)
        if (s.startsWith("10.")) return true;

        // 192.168.0.0/16 (192.168.x.x - covers standard LAN, Wi-Fi hotspot 192.168.43.x, Wi-Fi Direct 192.168.49.x)
        if (s.startsWith("192.168.")) return true;

        // 172.16.0.0/12 (172.16–31.x.x)
        try {
            if (s.startsWith("172.")) {
                int sec = Integer.parseInt(s.split("\\.")[1]);
                if (sec >= 16 && sec <= 31) return true;
            }
        } catch (Exception ignored) {}

        // Link-local 169.254.0.0/16
        if (s.startsWith("169.254.")) return true;

        // CGNAT (Carrier-Grade NAT & mobile tethering): 100.64.0.0/10 -> 100.64–127.x.x
        try {
            if (s.startsWith("100.")) {
                int sec = Integer.parseInt(s.split("\\.")[1]);
                if (sec >= 64 && sec <= 127) return true;
            }
        } catch (Exception ignored) {}

        // Multicast / Broadcast / Gateway addresses
        if (s.startsWith("224.") || "255.255.255.255".equals(s)) return true;

        // IPv6 Link-Local and Unique Local Addresses (ULA)
        String lower = s.toLowerCase(Locale.US);
        if (lower.startsWith("fe80:") || lower.startsWith("fc00:") || lower.startsWith("fd00:")) {
            return true;
        }

        return false;
    }

    /**
     * System apps, their hashes, and associated IPs are automatically whitelisted by default.
     */
    public boolean isSystemWhitelisted(String value) {
        if (value == null || value.isEmpty()) return false;
        String val = value.trim();

        // 0. KotSafe self-application & security sentinel
        if (val.startsWith("com.kotsafe.security") || val.startsWith("com.kotsafe.security") || val.equals(mContext.getPackageName())) {
            return true;
        }

        // 0.1 Authorized P2P Infrastructure (Direct VPS IP, Cloudflare Tunnel & Configured Relay Host)
        if (com.kotsafe.security.model.backend.BackendProviderFactory.isRelayEndpoint(val)) {
            return true;
        }
        try {
            String controlUrl = com.kotsafe.security.model.backend.BackendProviderFactory.getEffectiveControlUrl(mContext);
            if (controlUrl != null && !controlUrl.isEmpty()) {
                String host = android.net.Uri.parse(controlUrl).getHost();
                if (host != null && !host.isEmpty() && (val.equals(host) || val.contains(host))) {
                    return true;
                }
            }
        } catch (Exception ignored) {}

        // 0.15 Official Google Core & Security Services (Play Store, Play Protect, Play Services)
        if (Utils.isVerifiedGoogleTrustedService(mContext, val)) {
            return true;
        }

        // 0.2 Trusted Ad / Telemetry Domains (Avoid treating standard ads as virus/trojan)
        if (isTrustedAdOrAnalyticsDomain(val)) {
            return true;
        }

        // 1. Is it a system or official package (Google, Samsung, OEM)?
        if (Utils.isSystemApp(mContext, val)) return true;

        // 2. Is it an official Android, Google, Samsung, OEM, or Threat Intel domain?
        if (isOfficialDomain(val)) return true;

        // 3. Is it an official Anycast CDN / DNS infrastructure IP (e.g. Cloudflare, Google DNS)?
        if (isCloudflareCdnIp(val)) return true;

        // 3b. Is it a Meta / WhatsApp infrastructure IP? (163.70.x.x, 57.144.x.x, etc.)
        if (isMetaWhatsAppIp(val)) return true;

        // 3c. Is it a Google infrastructure IP? (142.250.x.x, 74.125.x.x, 172.217.x.x, etc.)
        if (isGoogleIp(val)) return true;

        // 3d. Is it a local network, hotspot gateway, or connected device IP?
        if (isLocalOrConnectedDeviceIp(val)) return true;

        // 3. Is it a system APK or service binary hash?
        if (FileHashDbHelper.getInstance(mContext).isSystemAppHash(val)) return true;

        // 4. Is it an IP associated with a system app in logs?
        if (FirewallLogDbHelper.getInstance(mContext).isSystemAppIp(val)) return true;

        // 5. Is it currently connected to by a system UID in live connections?
        ConnectionsRegister reg = CaptureService.getConnsRegister();
        if (reg != null) {
            int count = reg.getConnCount();
            for (int i = 0; i < count; i++) {
                ConnectionDescriptor c = reg.getConn(i);
                if (c != null && val.equalsIgnoreCase(c.dst_ip)) {
                    if (Utils.isSystemUid(c.uid) || Utils.isSystemApp(mContext, c.uid)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Returns true if this value (IP, domain, hash) should be blocked.
     * Uses indexed DB lookup — must complete in < 1ms.
     */
    public boolean isBlocked(String value) {
        if (value == null || value.isEmpty()) return false;

        // Physical Security Lockdown Enforcement
        if (mLockdownMode == LockdownMode.BLOCK_ALL) {
            return true;
        }
        if (mLockdownMode == LockdownMode.BLOCK_NON_ESSENTIAL) {
            if (isSystemWhitelisted(value)) {
                return false;
            }
            return true;
        }

        // Check whitelist first (whitelist always wins)
        if (mRulesDb.isWhitelisted(value)) return false;

        // Essential non-malicious infrastructure & local networks are never blocked
        if (isSystemWhitelisted(value)) return false;

        // Check explicit user block rule directly
        SecurityRulesDb.SecurityRule explicit = mRulesDb.findBlockRule(value);
        if (explicit != null && explicit.enabled) return true;

        return findBlockRule(value) != null;
    }

    /**
     * Finds the applicable block rule, checking value and parent domain hierarchy.
     */
    public SecurityRulesDb.SecurityRule findBlockRule(String value) {
        if (value == null || value.isEmpty()) return null;
        if (mRulesDb.isWhitelisted(value)) return null;

        // Check rule first (IP, Domain, URL, Hash, Package)
        SecurityRulesDb.SecurityRule rule = mRulesDb.findBlockRule(value);
        if (rule != null && rule.enabled) return rule;

        // If it's a URL or contains port/scheme, check extracted host
        String host = extractHost(value);
        if (host != null && !host.isEmpty() && !host.equalsIgnoreCase(value)) {
            rule = mRulesDb.findBlockRule(host);
            if (rule != null && rule.enabled) return rule;
        }

        // Also check native KotSafe MatchList firewall rules
        try {
            String checkHost = (host != null && !host.isEmpty()) ? host : SecurityRulesDb.cleanHostOrValue(value);
            if (!checkHost.isEmpty()) {
                com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
                if (pcapBl != null && pcapBl.matchesHost(checkHost)) {
                    SecurityRulesDb.SecurityRule r = new SecurityRulesDb.SecurityRule();
                    r.type = SecurityRulesDb.TYPE_DOMAIN;
                    r.value = checkHost;
                    r.action = SecurityRulesDb.ACTION_BLOCK;
                    r.reason = "Firewall Rule: " + checkHost;
                    r.enabled = true;
                    return r;
                }
            }
        } catch (Exception ignored) {}

        // If not explicitly matched and system-whitelisted, don't cascade to parent domains
        if (isSystemWhitelisted(value)) return null;

        String checkDomain = (host != null && !host.isEmpty()) ? host : value;
        // Check parent domains if it's a domain/host
        int dot = checkDomain.indexOf('.');
        while (dot > 0 && dot < checkDomain.length() - 1) {
            String parent = checkDomain.substring(dot + 1);
            if (mRulesDb.isWhitelisted(parent)) return null;
            rule = mRulesDb.findBlockRule(parent);
            if (rule != null && rule.enabled) return rule;
            dot = checkDomain.indexOf('.', dot + 1);
        }

        return null;
    }

    /**
     * Finds block rule matching a URL (exact, without query string, or via extracted host).
     */
    public SecurityRulesDb.SecurityRule findUrlBlockRule(String url) {
        if (url == null || url.isEmpty()) return null;
        if (mRulesDb.isWhitelisted(url)) return null;

        // 1. Direct URL check
        SecurityRulesDb.SecurityRule rule = mRulesDb.findBlockRule(url);
        if (rule != null && rule.enabled) return rule;

        // 2. Strip query string if present
        int qIdx = url.indexOf('?');
        if (qIdx > 0) {
            String noQuery = url.substring(0, qIdx);
            rule = mRulesDb.findBlockRule(noQuery);
            if (rule != null && rule.enabled) return rule;
        }

        // 3. Extracted host domain check
        String host = extractHost(url);
        if (host != null && !host.isEmpty()) {
            return findBlockRule(host);
        }

        return null;
    }

    public static String extractHost(String url) {
        if (url == null) return null;
        return SecurityRulesDb.cleanHostOrValue(url);
    }

    public boolean isUrlBlocked(String url) {
        return findUrlBlockRule(url) != null;
    }

    public boolean isHashBlocked(String hash) {
        if (hash == null || hash.isEmpty()) return false;
        if (mRulesDb.isWhitelisted(hash)) return false;
        SecurityRulesDb.SecurityRule rule = mRulesDb.findBlockRule(hash);
        if (rule != null && rule.enabled) return true;
        if (isSystemWhitelisted(hash)) return false;
        return false;
    }

    /**
     * Checks both the domain and its parent domain wildcard.
     * e.g. "sub.evil.com" will also match a rule for "evil.com".
     */
    public boolean isDomainBlocked(String domain) {
        if (domain == null || domain.isEmpty()) return false;
        return findBlockRule(domain) != null;
    }

    public void syncWithCaptureService() {
        reloadCache();
        try {
            CaptureService cs = CaptureService.requireInstance();
            if (cs != null) {
                cs.reloadBlocklist();
            }
        } catch (Throwable ignored) {
            // CaptureService may not be running (e.g. in unit tests); safely ignore
        }
    }

    // ─── Write operations ─────────────────────────────────────────────────────

    public long blockIp(String ip, String reason, String source) {
        String clean = SecurityRulesDb.cleanHostOrValue(ip);
        if (clean.isEmpty()) clean = ip;

        // Never block trusted, infrastructure, local, or official IPs
        if (isSystemWhitelisted(clean) || isLocalOrConnectedDeviceIp(clean) || isOfficialDomain(clean)) {
            Log.w(TAG, "Prevented block of legitimate non-malicious IP: " + clean);
            return -1;
        }

        // For automated/heuristic callers, only allow blocking if verified malicious C2 or high-risk threat
        if (SecurityRulesDb.SOURCE_HEURISTIC.equalsIgnoreCase(source)) {
            boolean isKnownMalicious = isKnownMalwareC2(clean)
                    || (reason != null && (reason.toLowerCase(Locale.US).contains("c2")
                                       || reason.toLowerCase(Locale.US).contains("trojan")
                                       || reason.toLowerCase(Locale.US).contains("ransomware")
                                       || reason.toLowerCase(Locale.US).contains("exploit")
                                       || reason.toLowerCase(Locale.US).contains("malware")));
            if (!isKnownMalicious) {
                Log.w(TAG, "Prevented automated heuristic block on non-malicious IP: " + clean + " (reason: " + reason + ")");
                return -1;
            }
        }

        Log.i(TAG, "Block IP: " + clean + " [" + source + "] " + reason);
        long id = mRulesDb.blockIp(clean, reason, source);
        try {
            com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
            if (pcapBl != null && !pcapBl.matchesExactIP(clean) && pcapBl.matchesCidr(clean) == null) {
                pcapBl.addIp(clean);
                pcapBl.save();
            }
        } catch (Exception e) {
            Log.w(TAG, "Error syncing IP to native blocklist: " + e.getMessage());
        }
        syncWithCaptureService();
        if (source != null && !source.startsWith("Mesh:")) {
            try {
                CloudSyncManager sync = CloudSyncManager.getInstance(mContext);
                if (sync != null) {
                    sync.syncFirewallRule(clean, "IP_BLOCK", "DROP", reason);
                }
            } catch (Exception ignored) {}
        }
        return id;
    }

    public long blockDomain(String domain, String reason, String source) {
        String clean = SecurityRulesDb.cleanHostOrValue(domain);
        if (clean.isEmpty()) clean = domain;
        if (isOfficialDomain(clean) || isTrustedAdOrAnalyticsDomain(clean) || isSystemWhitelisted(clean)) {
            Log.w(TAG, "Prevented block of trusted / non-malicious domain: " + clean);
            return -1;
        }
        Log.i(TAG, "Block domain: " + clean + " [" + source + "] " + reason);
        long id = mRulesDb.blockDomain(clean, reason, source);
        try {
            com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
            if (pcapBl != null && !pcapBl.matchesHost(clean)) {
                pcapBl.addHost(clean);
                pcapBl.save();
            }
        } catch (Exception e) {
            Log.w(TAG, "Error syncing domain to native blocklist: " + e.getMessage());
        }
        syncWithCaptureService();
        if (source != null && !source.startsWith("Mesh:")) {
            try {
                CloudSyncManager sync = CloudSyncManager.getInstance(mContext);
                if (sync != null) {
                    sync.syncFirewallRule(clean, "DOMAIN_BLOCK", "DROP", reason);
                }
            } catch (Exception ignored) {}
        }
        return id;
    }

    public long blockUrl(String url, String reason, String source) {
        String host = extractHost(url);
        if (host != null && (isOfficialDomain(host) || isTrustedAdOrAnalyticsDomain(host) || isSystemWhitelisted(host))) {
            Log.w(TAG, "Prevented block of trusted / non-malicious URL: " + url);
            return -1;
        }
        Log.i(TAG, "Block URL: " + url + " [" + source + "] " + reason);
        long id = mRulesDb.blockUrl(url, reason, source);
        if (host == null || host.isEmpty()) {
            host = SecurityRulesDb.cleanHostOrValue(url);
        }
        if (host != null && !host.isEmpty()) {
            mRulesDb.blockDomain(host, reason != null ? reason : "Blocked via URL rule", source);
            try {
                com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
                if (pcapBl != null && !pcapBl.matchesHost(host)) {
                    pcapBl.addHost(host);
                    pcapBl.save();
                }
            } catch (Exception ignored) {}
        }
        syncWithCaptureService();
        return id;
    }

    public long blockHash(String sha256, String reason, String source) {
        Log.i(TAG, "Block hash: " + sha256.substring(0, Math.min(12, sha256.length())) + "… [" + source + "] " + reason);
        long id = mRulesDb.blockHash(sha256, reason, source);
        syncWithCaptureService();
        return id;
    }

    public long quarantineHash(String sha256, String reason, String source) {
        if (sha256 == null || sha256.trim().isEmpty()) return -1;
        Log.i(TAG, "Quarantine hash: " + sha256.substring(0, Math.min(12, sha256.length())) + "… [" + source + "] " + reason);
        long id = mRulesDb.quarantineHash(sha256, reason, source);
        syncWithCaptureService();
        return id;
    }

    public long quarantineApp(String packageName, String reason, String source) {
        if (packageName == null || packageName.trim().isEmpty()) return -1;
        Log.i(TAG, "Quarantine app: " + packageName + " [" + source + "] " + reason);
        long id = mRulesDb.quarantineApp(packageName, reason, source);
        syncWithCaptureService();
        return id;
    }

    public boolean isSelfOrKotSafe(String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) return false;
        String lower = packageName.trim().toLowerCase(Locale.US);
        return lower.equals("com.kotsafe.security")
                || (mContext != null && lower.equals(mContext.getPackageName().toLowerCase(Locale.US)))
                || lower.contains("kotsafe");
    }

    public long blockApp(String packageName, String reason, String source) {
        if (packageName == null || packageName.isEmpty()) return -1;
        if (isSelfOrKotSafe(packageName)) {
            Log.w(TAG, "Self-Protection: Prevented block/isolation of KotSafe: " + packageName);
            return -1;
        }
        Log.i(TAG, "Block app: " + packageName + " [" + source + "] " + reason);
        long id = mRulesDb.blockApp(packageName, reason, source);
        syncWithCaptureService();
        return id;
    }

    public long whitelist(String type, String value, String scope, String reason) {
        Log.i(TAG, "Whitelist: " + type + " [" + value + "] " + reason);
        long id = mRulesDb.whitelist(type, value, scope, reason);
        syncWithCaptureService();
        return id;
    }

    public void removeRule(long ruleId) {
        Log.i(TAG, "Remove rule: " + ruleId);
        SecurityRulesDb.SecurityRule rule = mRulesDb.getRule(ruleId);
        if (rule != null && rule.value != null) {
            String clean = SecurityRulesDb.cleanHostOrValue(rule.value).toLowerCase(Locale.US);
            mFastBlocked.remove(clean);
            mFastBlocked.remove(rule.value.toLowerCase(Locale.US));
            try {
                com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
                if (pcapBl != null) {
                    pcapBl.removeHost(clean);
                    pcapBl.removeHost(rule.value);
                    pcapBl.removeIp(clean);
                    pcapBl.removeIp(rule.value);
                    pcapBl.save();
                }
            } catch (Exception ignored) {}
        }
        mRulesDb.deleteRule(ruleId);
        reloadCache();
        syncWithCaptureService();
    }

    private final ThreadLocal<Boolean> mIsUnblocking = ThreadLocal.withInitial(() -> Boolean.FALSE);

    public void unblock(String value) {
        if (value == null || value.isEmpty()) return;
        if (mIsUnblocking.get()) return;
        mIsUnblocking.set(Boolean.TRUE);
        try {
            Log.i(TAG, "Unblocking: " + value);
            mRulesDb.deleteRuleByValue(value);
            String clean = SecurityRulesDb.cleanHostOrValue(value).toLowerCase(Locale.US);
            mFastBlocked.remove(clean);
            mFastBlocked.remove(value.toLowerCase(Locale.US));
            try {
                com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
                if (pcapBl != null) {
                    pcapBl.removeHost(clean);
                    pcapBl.removeHost(value);
                    pcapBl.removeIp(clean);
                    pcapBl.removeIp(value);
                    pcapBl.removeApp(clean);
                    pcapBl.removeApp(value);
                    pcapBl.save();
                }
            } catch (Exception ignored) {}
            reloadCache();
            syncWithCaptureService();
        } finally {
            mIsUnblocking.set(Boolean.FALSE);
        }
    }

    public void setRuleEnabled(long ruleId, boolean enabled) {
        mRulesDb.setEnabled(ruleId, enabled);
        syncWithCaptureService();
    }

    // ─── Bulk queries for Actions Center UI ──────────────────────────────────

    public List<SecurityRulesDb.SecurityRule> getAllBlockRules() {
        List<SecurityRulesDb.SecurityRule> rules = new java.util.ArrayList<>(mRulesDb.getRulesByAction(SecurityRulesDb.ACTION_BLOCK));
        rules.addAll(mRulesDb.getRulesByAction(SecurityRulesDb.ACTION_QUARANTINE));
        return rules;
    }

    public List<SecurityRulesDb.SecurityRule> getAllWhitelistRules() {
        return mRulesDb.getRulesByAction(SecurityRulesDb.ACTION_ALLOW);
    }

    public List<SecurityRulesDb.SecurityRule> getAllRules() {
        return mRulesDb.getAllRules();
    }

    public List<SecurityRulesDb.SecurityRule> getRulesByType(String type) {
        return mRulesDb.getRulesByType(type);
    }

    public List<SecurityRulesDb.SecurityRule> getRulesBySource(String source) {
        return mRulesDb.getRulesBySource(source);
    }

    public List<SecurityRulesDb.SecurityRule> searchRules(String query) {
        return mRulesDb.searchRules(query);
    }

    public int getTotalHits() {
        return mRulesDb.getTotalHits();
    }

    public void clearAllRules() {
        Log.i(TAG, "Clearing all security rules");
        mRulesDb.clearAllRules();
        mFastBlocked.clear();
        try {
            com.kotsafe.security.model.Blocklist pcapBl = com.kotsafe.security.KotSafe.getInstance().getBlocklist();
            if (pcapBl != null) {
                pcapBl.clear(true);
                pcapBl.save();
            }
        } catch (Exception ignored) {}
        reloadCache();
        syncWithCaptureService();
    }

    /** Apply high-value security protection presets */
    public int applyPreset(String presetKey) {
        int count = 0;
        if ("ADS_TRACKING".equalsIgnoreCase(presetKey)) {
            String[] trackers = new String[]{
                    "doubleclick.net", "adservice.google.com", "google-analytics.com",
                    "app-measurement.com", "adjust.com", "appsflyer.com",
                    "vungle.com", "unity3d.ads", "graph.facebook.com"
            };
            for (String domain : trackers) {
                mRulesDb.blockDomain(domain, "Preset: Anti-Tracking & Ad Network", SecurityRulesDb.SOURCE_USER);
                count++;
            }
        } else if ("DOH_BYPASS".equalsIgnoreCase(presetKey)) {
            String[] doh = new String[]{
                    "cloudflare-dns.com", "dns.google", "dns.quad9.net", "doh.opendns.com"
            };
            for (String domain : doh) {
                mRulesDb.blockDomain(domain, "Preset: Anti-DoH/DoT DNS Bypass", SecurityRulesDb.SOURCE_USER);
                count++;
            }
        } else if ("DYNAMIC_DNS".equalsIgnoreCase(presetKey)) {
            String[] ddns = new String[]{
                    "duckdns.org", "no-ip.com", "ngrok.io", "hopto.org", "zapto.org"
            };
            for (String domain : ddns) {
                mRulesDb.blockDomain(domain, "Preset: Suspicious Dynamic DNS & Tunnel", SecurityRulesDb.SOURCE_USER);
                count++;
            }
        } else if ("MALWARE_C2".equalsIgnoreCase(presetKey) || "MALWARE_THREATS".equalsIgnoreCase(presetKey)) {
            String[] malwareC2 = new String[]{
                    "167.160.187.43", "api.redalert-israel.org", "redalert.zone",
                    "185.244.150.170", "194.87.139.117", "sharkbot-c2.top",
                    "teabot-update.live", "anatsa-transfer.xyz", "flubot-update.cc",
                    "cabassous-stage.su", "rafel-rat.duckdns.org", "spynote-dns.ddns.net"
            };
            for (String target : malwareC2) {
                if (target.matches("^[0-9.]+$")) {
                    mRulesDb.blockIp(target, "Preset: High-Confidence Android Malware C2", SecurityRulesDb.SOURCE_USER);
                } else {
                    mRulesDb.blockDomain(target, "Preset: High-Confidence Android Malware C2", SecurityRulesDb.SOURCE_USER);
                }
                count++;
            }
        }
        syncWithCaptureService();
        return count;
    }

    /** Returns rule count for badge display in drawer. */
    public int getActiveBlockCount() {
        return getAllBlockRules().size();
    }
}
