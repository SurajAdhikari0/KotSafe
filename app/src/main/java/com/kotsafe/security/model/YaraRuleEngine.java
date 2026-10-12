/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import org.json.JSONArray;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * In-memory YARA Rule Engine for Android binaries, APKs, and storage files.
 *
 * Implements byte pattern, string, and heuristic rule evaluation for:
 *   - Android RATs & Spyware (AhMyth, SpyNote, Dendroid)
 *   - Droppers & Stagers (dynamic DexClassLoader, encrypted reflection chains)
 *   - Mobile Ransomware (crypto locker strings, .onion C2s)
 *   - Privilege Escalation & Rootkits (su search paths, dirtycow, magisk tampering)
 *   - Banking Trojans (Accessibility + Overlay window hijacking)
 *   - Premium SMS Fraud & Meterpreter payloads
 */
public class YaraRuleEngine {
    private static final String TAG = "YaraRuleEngine";
    private static final int MAX_FILE_SCAN_BYTES = 5 * 1024 * 1024; // 5 MB ceiling per file

    public static class YaraMatch {
        public String ruleName;
        public String tags;
        public String description;
        public String severity; // "MALICIOUS" | "SUSPICIOUS" | "LOW"
        public String matchedFile;
        public List<String> matchedStrings = new ArrayList<>();
    }

    public interface YaraRuleEvaluator {
        boolean shouldTrigger(String text, List<String> hits);
    }

    public static class YaraRule {
        public String name;
        public String tags;
        public String description;
        public String severity;
        public List<String> stringPatterns = new ArrayList<>();
        public boolean matchAll = false; // true = all patterns must match; false = any pattern matches
        public List<String> extensionFilter = new ArrayList<>();
        public YaraRuleEvaluator customEvaluator = null;

        public YaraRule(String name, String tags, String description, String severity, boolean matchAll, String... patterns) {
            this(name, tags, description, severity, matchAll, (String[]) null, patterns);
        }

        public YaraRule(String name, String tags, String description, String severity, boolean matchAll, String[] extensions, String... patterns) {
            this.name = name;
            this.tags = tags;
            this.description = description;
            this.severity = severity;
            this.matchAll = matchAll;
            if (extensions != null) {
                for (String ext : extensions) {
                    this.extensionFilter.add(ext.toLowerCase());
                }
            }
            this.stringPatterns.addAll(Arrays.asList(patterns));
        }

        public YaraMatch evaluate(byte[] content, String fileName) {
            if (content == null || content.length == 0) return null;
            if (!extensionFilter.isEmpty() && fileName != null) {
                String lowerName = fileName.toLowerCase();
                boolean extMatch = false;
                for (String ext : extensionFilter) {
                    if (lowerName.endsWith(ext)) {
                        extMatch = true;
                        break;
                    }
                }
                if (!extMatch) return null;
            }

            String text = new String(content, StandardCharsets.ISO_8859_1);
            List<String> hits = new ArrayList<>();

            for (String pat : stringPatterns) {
                if (text.contains(pat)) {
                    hits.add(pat);
                }
            }

            boolean isTriggered;
            if (customEvaluator != null) {
                isTriggered = customEvaluator.shouldTrigger(text, hits);
            } else if (matchAll) {
                isTriggered = (hits.size() == stringPatterns.size());
            } else {
                isTriggered = !hits.isEmpty();
            }

            if (isTriggered) {
                YaraMatch match = new YaraMatch();
                match.ruleName = name;
                match.tags = tags;
                match.description = description;
                match.severity = severity;
                match.matchedFile = fileName;
                match.matchedStrings = hits;
                return match;
            }
            return null;
        }
    }

    private static YaraRuleEngine sInstance;
    private final Context mContext;
    private final List<YaraRule> mRules;

    public static synchronized YaraRuleEngine getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new YaraRuleEngine(context.getApplicationContext());
        }
        return sInstance;
    }

    private YaraRuleEngine(Context context) {
        mContext = context;
        mRules = new CopyOnWriteArrayList<>(buildDefaultRules());
    }

    public List<YaraRule> getRules() {
        return Collections.unmodifiableList(mRules);
    }

    public void addDynamicRule(YaraRule rule) {
        if (rule != null) {
            mRules.add(rule);
            Log.i(TAG, "Added dynamic YARA rule: " + rule.name + " (total rules: " + mRules.size() + ")");
        }
    }

    public void addDynamicRules(List<YaraRule> rules) {
        if (rules != null && !rules.isEmpty()) {
            mRules.addAll(rules);
            Log.i(TAG, "Added " + rules.size() + " dynamic YARA rules (total rules: " + mRules.size() + ")");
        }
    }

    public int getRuleCount() {
        return mRules.size();
    }

    public static List<YaraRule> buildDefaultRules() {
        List<YaraRule> list = new ArrayList<>();

        // 1. Android Spyware: AhMyth RAT (Tightened to AhMyth-specific dispatchers & package identifiers)
        YaraRule ahMythRule = new YaraRule(
                "Android_Spyware_AhMyth",
                "rat,spyware,ahmyth",
                "AhMyth Android Remote Access Trojan signature detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "ahmyth.mine.nhp", "ahmyth/mine/nhp", "AhmythService", "x0000ca", "x0000mi", "x0000sm", "x0000cl", "x0000co", "x0000lo"
        );
        ahMythRule.customEvaluator = (text, hits) -> {
            if (hits.contains("ahmyth.mine.nhp") || hits.contains("ahmyth/mine/nhp")) return true;
            if (hits.contains("AhmythService") && (hits.contains("x0000ca") || hits.contains("x0000mi") || hits.contains("x0000sm"))) return true;
            int cmdHits = 0;
            if (hits.contains("x0000ca")) cmdHits++;
            if (hits.contains("x0000mi")) cmdHits++;
            if (hits.contains("x0000sm")) cmdHits++;
            if (hits.contains("x0000cl")) cmdHits++;
            if (hits.contains("x0000co")) cmdHits++;
            if (hits.contains("x0000lo")) cmdHits++;
            return cmdHits >= 3;
        };
        list.add(ahMythRule);

        // 2. Android Trojan: SpyNote / SpyMax (Tightened to unique SpyNote identifiers & protocol)
        YaraRule spyNoteRule = new YaraRule(
                "Android_Trojan_SpyNote",
                "rat,trojan,spynote",
                "SpyNote / SpyMax Android Trojan payload pattern detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "spynote", "spymax", "spynote_server", "SpyNoteService", "<SpyNote>", "s-socket", "Client.Payload"
        );
        spyNoteRule.customEvaluator = (text, hits) -> {
            boolean hasFamily = hits.contains("spynote") || hits.contains("spymax") || hits.contains("spynote_server") || hits.contains("SpyNoteService");
            boolean hasC2 = hits.contains("<SpyNote>") || hits.contains("s-socket") || hits.contains("Client.Payload") || hits.contains("spynote_server");
            return (hasFamily && hasC2) || hits.contains("SpyNoteService") || hits.contains("spynote_server");
        };
        list.add(spyNoteRule);

        // 3. Android Ransomware: Crypto / Screen Locker (Extortion demand required; .onion alone exempt)
        YaraRule cryptoRule = new YaraRule(
                "Android_Ransomware_CryptoLocker",
                "ransomware,crypto,extortion",
                "Android ransomware encryption note or extortion pattern detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "Your files have been encrypted", ".onion", "bitcoin address", "pay ransom to decrypt", "device locked by police", "to decrypt your files"
        );
        cryptoRule.customEvaluator = (text, hits) -> {
            if (hits.contains("Your files have been encrypted")) return true;
            if (hits.contains("pay ransom to decrypt")) return true;
            if (hits.contains("device locked by police")) return true;
            if (hits.contains("bitcoin address") && (hits.contains("to decrypt your files") || text.contains("decrypt") || text.contains("ransom"))) return true;
            if (hits.contains(".onion") && (hits.contains("to decrypt your files") || text.contains("ransom") || text.contains("encrypt"))) return true;
            return false;
        };
        list.add(cryptoRule);

        // 4. Android Rootkit / Privilege Escalation (Offensive execution pairing required; defensive root checks exempt)
        YaraRule rootRule = new YaraRule(
                "Android_Root_PrivilegeEscalation",
                "root,exploit,privilege_escalation",
                "Offensive root exploit or unauthorized privilege escalation attempt detected",
                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS,
                false,
                "/system/bin/su", "/system/xbin/su", "daemonsu", "supersu", "/system/bin/failsafe/su",
                "su -c", "chmod 777", "chmod 0777", "mount -o remount,rw", "setenforce 0", "pm install -r -d", "/system/xbin/daemonsu --auto-daemon"
        );
        rootRule.customEvaluator = (text, hits) -> {
            boolean hasRootCheck = hits.contains("/system/bin/su") || hits.contains("/system/xbin/su")
                    || hits.contains("daemonsu") || hits.contains("supersu") || hits.contains("/system/bin/failsafe/su");
            boolean hasOffensiveAction = hits.contains("su -c") || hits.contains("chmod 777")
                    || hits.contains("chmod 0777") || hits.contains("mount -o remount,rw")
                    || hits.contains("setenforce 0") || hits.contains("pm install -r -d")
                    || hits.contains("/system/xbin/daemonsu --auto-daemon");
            return hasRootCheck && hasOffensiveAction;
        };
        list.add(rootRule);

        // 5. Metasploit Android Meterpreter Payload (Requires package or stager combination; isolated string exempt)
        YaraRule metasploitRule = new YaraRule(
                "Android_Metasploit_Payload",
                "metasploit,meterpreter,c2",
                "Metasploit Android Meterpreter reverse stage payload detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "com.metasploit.stage", "Meterpreter", "PayloadTrustManager"
        );
        metasploitRule.customEvaluator = (text, hits) -> {
            if (hits.contains("com.metasploit.stage")) return true;
            if (hits.contains("PayloadTrustManager") && hits.contains("Meterpreter")) return true;
            return false;
        };
        list.add(metasploitRule);

        // 6. Malicious SVG Graphic: Embedded JavaScript or XSS Tag (XML dropped to avoid resource false positives)
        list.add(new YaraRule(
                "SVG_Malicious_Script_XSS",
                "svg,xss,script,exploit",
                "Malicious SVG vector payload: embedded JavaScript, onload or XSS tag detected in image",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".svg"},
                "<script", "onload=", "onerror=", "xlink:href=\"javascript:", "<svg/onload", "data:text/html;base64"
        ));

        // 7. Malicious PDF Document: Embedded JavaScript or Launch Action
        list.add(new YaraRule(
                "PDF_Malicious_Action",
                "pdf,exploit,dropper",
                "Malicious PDF Document: embedded JavaScript, Launch action, or executable payload detected",
                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS,
                false,
                new String[]{".pdf"},
                "/JavaScript", "/JS (", "/Launch"
        ));

        // 8. CSV / Spreadsheet DDE Formula Injection
        list.add(new YaraRule(
                "Spreadsheet_Formula_Injection",
                "csv,excel,dde,formula_injection",
                "CSV/Excel Dynamic Data Exchange (DDE) formula execution injection detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".csv", ".tsv", ".xls", ".xlsx", ".ods"},
                "=cmd|", "+cmd|", "-cmd|", "@cmd|", "=powershell|", "+powershell|", "DDEAUTO", "=exec|"
        ));

        // 9. Office Document Malicious Macro / Shell Execution
        list.add(new YaraRule(
                "Office_Macro_Payload",
                "office,macro,vba,shell",
                "Office Document Macro Payload: Auto-execution macro or shell command execution detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm"},
                "AutoOpen", "Document_Open", "Workbook_Open", "WScript.Shell", "ShellExecute", "powershell.exe -enc"
        ));

        // 10. Malicious Shell / Bash Script: Reverse Shell or Destructive Command (Script extensions restricted)
        list.add(new YaraRule(
                "Script_Malicious_Shell_Reverse",
                "sh,bash,shell,reverse_shell",
                "Malicious Shell/Bash Script: Reverse shell, remote download pipe or destructive command detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".sh", ".bash", ".zsh"},
                "/bin/sh -i", "/bin/bash -i", "/dev/tcp/", "nc -e /bin/sh", "nc -e /bin/bash", "rm -rf /*", "curl | sh", "curl | bash", "wget | bash"
        ));

        // 11. Malicious Batch / PowerShell Script: Encoded Exec or Shadow Copy Deletion
        list.add(new YaraRule(
                "Script_Malicious_Windows_Batch",
                "bat,cmd,powershell,downloader",
                "Malicious Batch/PowerShell Script: Encoded execution, volume shadow deletion or dropper detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".bat", ".cmd", ".ps1", ".vbs", ".js"},
                "powershell -enc", "powershell.exe -w hidden", "certutil -urlcache -split -f", "vssadmin delete shadows", "bitsadmin /transfer", "cmd.exe /c start /min"
        ));

        // 12. Steganographic / Polyglot Image Dropper
        list.add(new YaraRule(
                "Image_Stego_Polyglot_Dropper",
                "stego,polyglot,image,dropper",
                "Polyglot / Steganographic Image Dropper: Embedded APK/DEX binary payload hidden inside photo",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"},
                "classes.dex", "AndroidManifest.xml"
        ));

        // 13. Ransomware Extortion Note in Documents
        list.add(new YaraRule(
                "Document_Ransomware_Note",
                "ransomware,note,extortion",
                "Ransomware Extortion Note: Ransom demand or decryption instructions found in document",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                new String[]{".txt", ".pdf", ".doc", ".docx", ".rtf", ".html"},
                "Your files have been encrypted", "DECRYPT_INSTRUCTIONS", "send bitcoin to", "restore your files", "pay ransom to decrypt"
        ));

        // 14. Compressed Archive with Suspicious Executable (.jar and classes.dex removed to prevent library FPs)
        list.add(new YaraRule(
                "Archive_Suspicious_Payload",
                "archive,zip,rar,payload",
                "Compressed Archive Payload: Nested executable or script payload detected inside archive",
                AntivirusEvidenceItem.SEVERITY_SUSPICIOUS,
                false,
                new String[]{".zip", ".rar", ".7z", ".tar", ".gz"},
                ".sh\u0000", ".bat\u0000", ".exe\u0000", ".vbs\u0000"
        ));

        // 15. Android Banking Trojan: BlackRock / Alien (Credential Theft & Overlay)
        YaraRule blackRockRule = new YaraRule(
                "Android_Banker_BlackRock",
                "banker,trojan,blackrock,overlay,credentials",
                "BlackRock / Alien Android Banking Trojan: Financial credential theft, overlay injection and SMS interception detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "com.blackrock.bank", "blackrock_overlay", "inject_fake_login", "steal_credentials_sms", "anti_av_kill"
        );
        blackRockRule.customEvaluator = (text, hits) -> {
            if (hits.contains("com.blackrock.bank") || hits.contains("blackrock_overlay")) return true;
            if (hits.contains("inject_fake_login") && hits.contains("steal_credentials_sms")) return true;
            return false;
        };
        list.add(blackRockRule);

        // 16. Android Spyware: Operation Epic Fury / Fake RedAlert (Pushy.me C2 & Exfiltration)
        YaraRule epicFuryRule = new YaraRule(
                "Android_Spyware_EpicFury",
                "spyware,rat,epicfury,redalert",
                "Operation Epic Fury / Fake RedAlert Android spyware: SMS/GPS surveillance and unauthorized Pushy C2 channel detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "com.red.alertx", "pushy.me", "api.redalert-israel.org", "app_redalert",
                "device_id_token", "/api/v1/update_user_token", "upload_contacts_url", "sms_interception_service"
        );
        epicFuryRule.customEvaluator = (text, hits) -> {
            if (hits.contains("com.red.alertx") || hits.contains("api.redalert-israel.org")) return true;
            if (hits.contains("pushy.me") && (hits.contains("upload_contacts_url") || hits.contains("sms_interception_service") || hits.contains("/api/v1/update_user_token"))) return true;
            if (hits.contains("device_id_token") && hits.contains("upload_contacts_url")) return true;
            return false;
        };
        list.add(epicFuryRule);

        // 17. Android Banking Trojan: SharkBot / TeaBot (ATS & Accessibility Hijack)
        YaraRule sharkBotRule = new YaraRule(
                "Android_Banker_SharkBot",
                "banker,trojan,sharkbot,ats",
                "SharkBot / TeaBot Android Banking Trojan: Automated Transfer System (ATS) accessibility hijack and overlay theft detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "com.shark.bot", "/api/shark", "ats_service", "auto_transfer", "open_fake_overlay",
                "intercept_sms_code", "disable_play_protect", "accessibility_event_type_view_clicked"
        );
        sharkBotRule.customEvaluator = (text, hits) -> {
            if (hits.contains("com.shark.bot") || hits.contains("/api/shark")) return true;
            if (hits.contains("ats_service") && hits.contains("auto_transfer")) return true;
            if ((hits.contains("open_fake_overlay") || hits.contains("disable_play_protect"))
                    && (hits.contains("intercept_sms_code") || hits.contains("accessibility_event_type_view_clicked"))) return true;
            return false;
        };
        list.add(sharkBotRule);

        // 18. Android Banking Trojan: FluBot / Cabassous (SMS Propagation & Overlay)
        YaraRule fluBotRule = new YaraRule(
                "Android_Banker_FluBot",
                "banker,flubot,cabassous,sms_stealer",
                "FluBot / Cabassous Android Banker: Automated SMS worm propagation, banking overlay and DGA command dispatch detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "org.flubot", "cabassous", "send_sms_to_all_contacts", "tracking_package_delivery",
                "open_fake_url", "disable_accessibility_uninstall", "intercept_notification_service"
        );
        fluBotRule.customEvaluator = (text, hits) -> {
            if (hits.contains("org.flubot") || hits.contains("cabassous")) return true;
            if (hits.contains("send_sms_to_all_contacts") && (hits.contains("tracking_package_delivery") || hits.contains("open_fake_url"))) return true;
            if (hits.contains("disable_accessibility_uninstall") && hits.contains("intercept_notification_service")) return true;
            return false;
        };
        list.add(fluBotRule);

        // 19. Android Fraud / Adware: Joker / Bread (Silent WAP Billing)
        YaraRule jokerRule = new YaraRule(
                "Android_Fraud_Joker",
                "fraud,adware,joker,bread,billing",
                "Joker / Bread Android Malware: Silent WAP premium billing subscription and notification listener interception detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "joker_billing", "auto_confirm_wap", "get_verification_code_sms", "send_wap_request", "notification_sms_extractor", "sub_silent_carrier"
        );
        jokerRule.customEvaluator = (text, hits) -> {
            if (hits.contains("joker_billing")) return true;
            if (hits.contains("auto_confirm_wap") && hits.contains("get_verification_code_sms")) return true;
            if (hits.contains("send_wap_request") && hits.contains("notification_sms_extractor")) return true;
            return false;
        };
        list.add(jokerRule);

        // 20. Android Advanced Rootkit: Triada / Guerrilla (Process Injection)
        YaraRule triadaRule = new YaraRule(
                "Android_Rootkit_Triada",
                "trojan,rootkit,triada,guerrilla",
                "Triada / Guerrilla Advanced Android Trojan: System process injection, Zygote tampering or backdoor payload detected",
                AntivirusEvidenceItem.SEVERITY_MALICIOUS,
                false,
                "triada_root", "/system/lib/libzygote_inject.so", "inject_zygote", "ptrace_attach_process",
                "replace_system_apk", "stealth_backdoor_service", "com.android.providers.telephony.ext"
        );
        triadaRule.customEvaluator = (text, hits) -> {
            if (hits.contains("triada_root") || hits.contains("/system/lib/libzygote_inject.so")) return true;
            if (hits.contains("inject_zygote") && hits.contains("ptrace_attach_process")) return true;
            if (hits.contains("replace_system_apk") && hits.contains("stealth_backdoor_service")) return true;
            return false;
        };
        list.add(triadaRule);

        return list;
    }

    /**
     * Scans an installed or downloaded APK archive (DEX bytecode, manifests, assets).
     */
    public List<YaraMatch> scanApk(File apkFile, String packageName) {
        List<YaraMatch> matches = new ArrayList<>();
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) return matches;

        if (packageName == null || packageName.isEmpty()) {
            try {
                if (mContext != null) {
                    PackageManager pm = mContext.getPackageManager();
                    PackageInfo pi = pm.getPackageArchiveInfo(apkFile.getAbsolutePath(), 0);
                    if (pi != null && pi.packageName != null) {
                        packageName = pi.packageName;
                    }
                }
            } catch (Exception ignored) {}
        }

        // Exempt host engine itself (its bytecode contains the signature database by definition)
        if (packageName != null && mContext != null
                && (packageName.equals(mContext.getPackageName()) || packageName.startsWith("com.kotsafe.security"))) {
            return matches;
        }

        boolean isSys = Utils.isSystemApp(mContext, packageName);

        try (ZipFile zip = new ZipFile(apkFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // Target DEX files, Manifest, native binaries, and executable/payload assets
                boolean isCandidate = name.endsWith(".dex")
                        || name.equals("AndroidManifest.xml")
                        || (name.startsWith("lib/") && name.endsWith(".so"))
                        || (name.startsWith("assets/") && (name.endsWith(".dex") || name.endsWith(".jar") || name.endsWith(".sh") || name.endsWith(".so") || name.endsWith(".bin") || name.endsWith(".apk") || name.endsWith(".py")));

                if (isCandidate) {
                    if (entry.getSize() > MAX_FILE_SCAN_BYTES || entry.getSize() <= 0) continue;

                    byte[] buffer = readZipEntry(zip, entry);
                    if (buffer == null) continue;

                    for (YaraRule rule : mRules) {
                        YaraMatch match = rule.evaluate(buffer, name);
                        if (match != null) {
                            // System app override: if system app, downgrade severity to LOW
                            if (isSys) {
                                match.severity = AntivirusEvidenceItem.SEVERITY_LOW;
                            }
                            matches.add(match);
                            recordMatchInDb(match, packageName, apkFile.getAbsolutePath());
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "scanApk error for " + apkFile.getName() + ": " + e.getMessage());
        }
        return matches;
    }

    /**
     * Scans an individual storage file (e.g. from Downloads or SD card).
     */
    public List<YaraMatch> scanFile(File file) {
        List<YaraMatch> matches = new ArrayList<>();
        if (file == null || !file.exists() || !file.canRead() || file.isDirectory()) return matches;
        if (file.length() <= 0) return matches;

        if (file.getName().toLowerCase().endsWith(".apk")) {
            return scanApk(file, null);
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) Math.min(file.length(), MAX_FILE_SCAN_BYTES)];
            int read = fis.read(data);
            if (read <= 0) return matches;

            for (YaraRule rule : mRules) {
                YaraMatch match = rule.evaluate(data, file.getName());
                if (match != null) {
                    matches.add(match);
                    recordMatchInDb(match, "", file.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "scanFile error for " + file.getName() + ": " + e.getMessage());
        }
        return matches;
    }

    private byte[] readZipEntry(ZipFile zip, ZipEntry entry) {
        try (InputStream is = zip.getInputStream(entry);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            int totalBytes = 0;
            while ((n = is.read(buf)) != -1) {
                totalBytes += n;
                if (totalBytes > MAX_FILE_SCAN_BYTES) {
                    Log.w(TAG, "Archive entry decompression exceeded limit (possible zip bomb): " + entry.getName());
                    return null;
                }
                baos.write(buf, 0, n);
            }
            return baos.toByteArray();
        } catch (Exception e) {
            return null;
        }
    }

    private void recordMatchInDb(YaraMatch match, String packageName, String filePath) {
        try {
            EvidenceDbHelper eviDb = EvidenceDbHelper.getInstance(mContext);
            JSONArray arr = new JSONArray(match.matchedStrings);
            eviDb.insertYaraEvidence(0, match.ruleName, match.tags, filePath, arr.toString());
        } catch (Exception e) {
            Log.w(TAG, "recordMatchInDb error: " + e.getMessage());
        }
    }
}
