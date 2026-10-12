package com.kotsafe.security.model;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Central release gate for the security phases described in the project plan.
 *
 * This is deliberately conservative: it is a real runtime readiness check, not a
 * marketing-only status flag. The app should not claim a security phase is ready
 * until the relevant runtime gates are enabled and the current runtime context is
 * consistent.
 */
public final class SecurityReleaseGate {
    private SecurityReleaseGate() {
    }

    public static final class CheckResult {
        public final boolean ready;
        public final boolean firewallReady;
        public final boolean screenOffReady;
        public final boolean antivirusReady;
        public final List<String> failures;
        public final List<String> warnings;

        private CheckResult(boolean ready,
                            boolean firewallReady,
                            boolean screenOffReady,
                            boolean antivirusReady,
                            List<String> failures,
                            List<String> warnings) {
            this.ready = ready;
            this.firewallReady = firewallReady;
            this.screenOffReady = screenOffReady;
            this.antivirusReady = antivirusReady;
            this.failures = Collections.unmodifiableList(new ArrayList<>(failures));
            this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
        }

        public String summary() {
            if (ready) {
                return "Ready: all core security gates are armed.";
            }
            StringBuilder sb = new StringBuilder();
            sb.append("Blocked: ");
            for (int i = 0; i < failures.size(); i++) {
                if (i > 0) sb.append("; ");
                sb.append(failures.get(i));
            }
            return sb.toString();
        }
    }

    public static CheckResult evaluate(Context context, SharedPreferences prefs) {
        if (context == null || prefs == null) {
            return new CheckResult(false, false, false, false,
                    Collections.singletonList("Security configuration is not available."),
                    Collections.emptyList());
        }

        List<String> failures = new ArrayList<>();
        List<String> warnings = new ArrayList<>();

        boolean firewallReady = Prefs.isFirewallEnabled(context, prefs);
        if (!firewallReady) {
            failures.add("Firewall not enabled.");
        }

        boolean screenOffReady = Prefs.isFirewallScreenOffBlock(prefs);
        if (!screenOffReady) {
            failures.add("Screen-off background protection is disabled.");
        }

        boolean antivirusReady = Prefs.isMalwareDetectionEnabled(context, prefs);
        if (!antivirusReady) {
            failures.add("Malware detection is disabled.");
        }

        if (!Prefs.startAtBoot(prefs)) {
            warnings.add("Boot persistence is disabled; protection may not survive reboot.");
        }

        // Runtime-only status check: the app may be configured correctly but still not
        // currently active in the live VPN layer. That is a warning, not an automatic failure,
        // because the project still has OEM-specific boot restrictions on some devices.
        if (!CaptureService.isServiceActive()) {
            warnings.add("Capture service is currently inactive.");
        }

        return new CheckResult(failures.isEmpty(), firewallReady, screenOffReady, antivirusReady,
                failures, warnings);
    }

    public static CheckResult evaluate(Context context) {
        if (context == null) {
            return evaluate(context, null);
        }
        return evaluate(context, PreferenceManager.getDefaultSharedPreferences(context));
    }
}
