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
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Debug;

import com.kotsafe.security.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Pillar 3: Runtime Memory, Frida & Process Tamper Guard.
 *
 * Scans runtime memory spaces, ptrace status, and socket ports to detect
 * active dynamic instrumentation frameworks (Frida, Xposed, Substrate),
 * RWX memory allocations (JIT spray), and unauthorized process injection.
 */
public class ProcessSecurityInspector {
    private static final String TAG = "ProcessSecurityInspector";

    // Known dynamic instrumentation artifacts
    private static final String[] FRIDA_FILES = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent.so",
            "/data/local/tmp/gadget.so",
            "/data/local/tmp/linjector"
    };

    private static final String[] TAMPER_LIBS = {
            "frida-agent",
            "frida-gadget",
            "libfrida",
            "xposed.installer",
            "edxposed",
            "lsposed",
            "libsubstrate.so",
            "substrate"
    };

    // Standard Frida listening ports
    private static final int[] FRIDA_PORTS = {27042, 27043};

    public static class InspectionReport {
        public boolean isTampered = false;
        public boolean isFridaDetected = false;
        public boolean isXposedDetected = false;
        public boolean isDebuggerAttached = false;
        public boolean hasRwxMemory = false;
        public boolean isRepackaged = false;
        public boolean isVirtualEnv = false;
        public int tracerPid = 0;
        public List<String> detectedThreats = new ArrayList<>();
        public List<String> details = new ArrayList<>();

        public String getSummary() {
            if (!isTampered) {
                return "Process Integrity Verified: No runtime instrumentation or memory tampering detected.";
            }
            return "Runtime Tampering Detected: " + android.text.TextUtils.join(" • ", detectedThreats);
        }
    }

    public static InspectionReport inspect(Context context) {
        InspectionReport report = new InspectionReport();

        // 1. Check Debugger & PTrace Attachment (TracerPid)
        checkDebuggerAndTracer(report);

        // 2. Check Frida Server Sockets (localhost 27042 / 27043)
        checkFridaPorts(report);

        // 3. Check /data/local/tmp for Frida binaries
        checkFridaBinaries(report);

        // 4. Inspect /proc/self/maps for injected libraries and dangerous RWX memory
        checkProcessMaps(report);

        // 5. Check Package Integrity & Anti-Repackaging
        checkPackageIntegrity(context, report);

        // 6. Check Dynamic Hooking ClassLoaders (Xposed / LSPosed)
        checkXposedClassLoader(report);

        // 7. Check Virtual Container / Sandbox Environment
        checkVirtualEnvironment(context, report);

        report.isTampered = report.isFridaDetected || report.isXposedDetected || report.isDebuggerAttached
                || report.hasRwxMemory || report.isRepackaged || report.isVirtualEnv;
        return report;
    }

    private static void checkDebuggerAndTracer(InspectionReport report) {
        // Android framework debugger check
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            report.isDebuggerAttached = true;
            report.detectedThreats.add("Active Debugger Attached");
            report.details.add("Android Debug.isDebuggerConnected() returned true.");
        }

        // Low-level /proc/self/status TracerPid check
        File statusFile = new File("/proc/self/status");
        if (statusFile.exists() && statusFile.canRead()) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(statusFile), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("TracerPid:")) {
                        String[] parts = line.split(":");
                        if (parts.length > 1) {
                            int tpid = Integer.parseInt(parts[1].trim());
                            report.tracerPid = tpid;
                            if (tpid > 0) {
                                report.isDebuggerAttached = true;
                                report.detectedThreats.add("PTrace Hook Attached (PID " + tpid + ")");
                                report.details.add("Process is actively being traced/hooked via ptrace by PID: " + tpid);
                            }
                        }
                        break;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Error checking TracerPid: " + e.getMessage());
            }
        }
    }

    private static void checkFridaPorts(InspectionReport report) {
        for (int port : FRIDA_PORTS) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 80);
                report.isFridaDetected = true;
                report.detectedThreats.add("Frida Server Listening on Port " + port);
                report.details.add("Active socket connection established with local instrumentation server on port " + port);
                break;
            } catch (Exception ignored) {
                // Expected when no Frida server is active
            }
        }
    }

    private static void checkFridaBinaries(InspectionReport report) {
        for (String path : FRIDA_FILES) {
            File f = new File(path);
            if (f.exists()) {
                report.isFridaDetected = true;
                report.detectedThreats.add("Dynamic Instrumentation Binary Found");
                report.details.add("Detected hook server binary at: " + path);
                break;
            }
        }
    }

    private static void checkProcessMaps(InspectionReport report) {
        File mapsFile = new File("/proc/self/maps");
        if (!mapsFile.exists() || !mapsFile.canRead()) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(mapsFile), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lowerLine = line.toLowerCase();

                // Check for known hooking libraries in process address space
                for (String lib : TAMPER_LIBS) {
                    if (lowerLine.contains(lib)) {
                        if (lib.contains("frida")) {
                            report.isFridaDetected = true;
                            report.detectedThreats.add("Frida Library Injected in Memory (" + lib + ")");
                        } else {
                            report.isXposedDetected = true;
                            report.detectedThreats.add("Xposed/LSPosed Hook Injected in Memory (" + lib + ")");
                        }
                        report.details.add("Memory mapping found: " + line.trim());
                    }
                }

                // Check for dangerous RWX (Read-Write-Execute) permissions
                // Format: 7ff23000-7ff25000 rwxp 00000000 00:00 0 [anon:...]
                if (line.contains(" rwxp ") || line.contains(" rwx ")) {
                    // Filter out legitimate zygote/art runtime Dalvik-LinearAlloc if safe
                    if (!line.contains("[dalvik-bitmap-1]") && !line.contains("[dalvik-bitmap-2]")) {
                        report.hasRwxMemory = true;
                        report.detectedThreats.add("Suspicious RWX Memory Region");
                        report.details.add("Found executable and writable memory allocation: " + line.trim());
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error checking /proc/self/maps: " + e.getMessage());
        }
    }

    private static void checkPackageIntegrity(Context context, InspectionReport report) {
        if (context == null) return;
        try {
            PackageManager pm = context.getPackageManager();
            String myPkg = context.getPackageName();
            if (myPkg != null && !myPkg.startsWith("com.kotsafe.security") && !myPkg.startsWith("com.kotsafe.security")) {
                report.isRepackaged = true;
                report.detectedThreats.add("Package Renamed / Cloned (" + myPkg + ")");
                report.details.add("Package identity does not match legitimate KotSafe namespace.");
            }

            // Check signature certificate validity
            android.content.pm.PackageInfo pi = pm.getPackageInfo(myPkg,
                    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P ? PackageManager.GET_SIGNING_CERTIFICATES : PackageManager.GET_SIGNATURES);
            android.content.pm.Signature[] sigs = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && pi.signingInfo != null) {
                sigs = pi.signingInfo.getApkContentsSigners();
            } else {
                sigs = pi.signatures;
            }

            if (sigs != null && sigs.length > 0) {
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(
                        new java.io.ByteArrayInputStream(sigs[0].toByteArray()));
                String subject = cert.getSubjectX500Principal().getName().toLowerCase(java.util.Locale.ROOT);

                // If running in release mode, verify it's not signed with generic android debug cert
                if (!com.kotsafe.security.BuildConfig.DEBUG && subject.contains("cn=android debug")) {
                    report.isRepackaged = true;
                    report.detectedThreats.add("Tampered Release Build Signed with Debug Key");
                    report.details.add("Release APK appears cracked or repackaged with an unofficial debug key.");
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error checking package integrity: " + e.getMessage());
        }
    }

    private static void checkXposedClassLoader(InspectionReport report) {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge");
            report.isXposedDetected = true;
            report.detectedThreats.add("Active Xposed Framework Hook in ClassLoader");
            report.details.add("XposedBridge class loaded dynamically in active runtime.");
        } catch (ClassNotFoundException ignored) {}

        try {
            Class.forName("me.weishu.exposed.ExposedBridge");
            report.isXposedDetected = true;
            report.detectedThreats.add("Active TaiChi / VirtualXposed Bridge Hook");
            report.details.add("ExposedBridge class loaded dynamically in active runtime.");
        } catch (ClassNotFoundException ignored) {}

        // Stack trace probe for hooking frames
        try {
            throw new Exception("StackTraceTamperProbe");
        } catch (Exception e) {
            for (StackTraceElement element : e.getStackTrace()) {
                String cls = element.getClassName();
                if (cls.contains("de.robv.android.xposed") || cls.contains("com.saurik.substrate")) {
                    report.isXposedDetected = true;
                    report.detectedThreats.add("Hook Call Frame in StackTrace (" + cls + ")");
                    break;
                }
            }
        }
    }

    private static void checkVirtualEnvironment(Context context, InspectionReport report) {
        if (context == null) return;
        try {
            String filesPath = context.getFilesDir().getAbsolutePath();
            if (filesPath.contains("io.va.exposed")
                    || filesPath.contains("com.lody.virtual")
                    || filesPath.contains("com.bly.dualapp")
                    || filesPath.contains("com.excelliance.dualaid")
                    || filesPath.contains("virtualapp")
                    || filesPath.contains("parallel")) {
                report.isVirtualEnv = true;
                report.detectedThreats.add("Running inside Virtual Sandbox / Dual Space");
                report.details.add("Sandboxed filesystem path detected: " + filesPath);
            }
        } catch (Exception ignored) {}
    }
}
