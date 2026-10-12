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

package com.kotsafe.security.tls;

import android.content.Context;
import android.net.Uri;
import android.util.LruCache;

import com.kotsafe.security.Log;
import com.kotsafe.security.Utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Manages the in-app Root CA and creates on-the-fly dynamic leaf SSLContexts
 * for intercepted TLS connections without requiring any external addon.
 */
public class TlsCaManager {
    private static final String TAG = "TlsCaManager";
    private static final String CA_DIR = "tls_ca";
    private static final String CA_KEY_FILE = "kotsafe_ca_key.p8";
    private static final String CA_CERT_FILE = "kotsafe_ca.crt";
    private static final String CA_SUBJECT = "CN=KotSafe Root CA, O=KotSafe Network Monitor, OU=Decryption Authority, C=US";
    private static final long TEN_YEARS_MS = 10L * 365 * 24 * 60 * 60 * 1000L;
    private static final long ONE_YEAR_MS = 365L * 24 * 60 * 60 * 1000L;

    private static volatile TlsCaManager sInstance;

    private final Context mContext;
    private KeyPair mCaKeyPair;
    private X509Certificate mCaCert;
    private String mCaCertPem;

    // Cache generated SSLContexts per domain to make handshakes near-instantaneous
    private final LruCache<String, SSLContext> mContextCache = new LruCache<>(128);
    private KeyPair mServerKeyPair; // reusable 2048-bit keypair for dynamic leaf certificates

    public static synchronized TlsCaManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new TlsCaManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private TlsCaManager(Context context) {
        mContext = context;
        initOrLoadCa();
        initServerKeyPair();
        autoInstallCaWithRoot();
    }

    private synchronized void initOrLoadCa() {
        File dir = new File(mContext.getFilesDir(), CA_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        File keyFile = new File(dir, CA_KEY_FILE);
        File certFile = new File(dir, CA_CERT_FILE);

        if (keyFile.exists() && certFile.exists()) {
            try {
                loadExistingCa(keyFile, certFile);
                Log.i(TAG, "Loaded existing Root CA: " + mCaCert.getSubjectX500Principal().getName());
                return;
            } catch (Exception e) {
                Log.w(TAG, "Failed loading existing CA, regenerating: " + e.getMessage());
            }
        }

        generateNewCa(keyFile, certFile);
    }

    private void loadExistingCa(File keyFile, File certFile) throws Exception {
        // Read private key (PKCS#8 DER bytes)
        byte[] keyBytes = new byte[(int) keyFile.length()];
        try (FileInputStream fis = new FileInputStream(keyFile)) {
            int read = fis.read(keyBytes);
            if (read != keyBytes.length) throw new IOException("Incomplete key read");
        }
        java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);

        // Read X509 Certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (FileInputStream fis = new FileInputStream(certFile)) {
            mCaCert = (X509Certificate) cf.generateCertificate(fis);
        }

        mCaKeyPair = new KeyPair(mCaCert.getPublicKey(), privateKey);
        mCaCertPem = certToPem(mCaCert);
    }

    private void generateNewCa(File keyFile, File certFile) {
        try {
            Log.i(TAG, "Generating new 2048-bit RSA Root CA...");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, new SecureRandom());
            mCaKeyPair = kpg.generateKeyPair();

            long now = System.currentTimeMillis() - 60_000L; // 1 min buffer for clock drift
            Date startDate = new Date(now);
            Date endDate = new Date(now + TEN_YEARS_MS);

            BigInteger serial = new BigInteger(64, new SecureRandom());
            X500Name issuer = new X500Name(CA_SUBJECT);
            X500Name subject = issuer;

            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer, serial, startDate, endDate, subject, mCaKeyPair.getPublic());

            // CA constraints: isCA = true, pathLenConstraint = null
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            // Key Usage: keyCertSign | cRLSign | digitalSignature
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(mCaKeyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            mCaCert = new JcaX509CertificateConverter().getCertificate(holder);

            // Save private key (PKCS#8)
            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write(mCaKeyPair.getPrivate().getEncoded());
            }

            // Save certificate (PEM)
            mCaCertPem = certToPem(mCaCert);
            try (FileWriter fw = new FileWriter(certFile)) {
                fw.write(mCaCertPem);
            }

            Log.i(TAG, "Root CA generated successfully! Subject=" + mCaCert.getSubjectX500Principal());
        } catch (Exception e) {
            Log.e(TAG, "Fatal: failed to generate Root CA: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed generating KotSafe Root CA", e);
        }
    }

    private void initServerKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048, new SecureRandom());
            mServerKeyPair = kpg.generateKeyPair();
        } catch (Exception e) {
            Log.e(TAG, "Failed initializing server keypair: " + e.getMessage());
        }
    }

    public X509Certificate getCaCertificate() {
        return mCaCert;
    }

    public String getCaCertificatePem() {
        return mCaCertPem;
    }

    public boolean isCaInstalled() {
        return Utils.isCAInstalled(mCaCert);
    }

    /**
     * Computes the 8-character hex old subject hash (OpenSSL/Android format: <hash>.0)
     */
    public static String computeOldSubjectHash(X509Certificate cert) {
        if (cert == null) return "00000000";
        try {
            byte[] encoded = cert.getSubjectX500Principal().getEncoded();
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(encoded);
            int hash = ((digest[0] & 0xFF)) |
                    ((digest[1] & 0xFF) << 8) |
                    ((digest[2] & 0xFF) << 16) |
                    ((digest[3] & 0xFF) << 24);
            return String.format(java.util.Locale.US, "%08x", hash);
        } catch (Exception e) {
            return "00000000";
        }
    }

    /**
     * Automatically and silently installs the Root CA certificate into Android's
     * system trust store and user store via root ('su') if root access is present.
     */
    public void autoInstallCaWithRoot() {
        new Thread(() -> {
            try {
                if (mCaCert == null) return;
                if (isCaInstalled()) {
                    Log.i(TAG, "Root CA is already installed and trusted.");
                    return;
                }

                if (!Utils.isRootAvailable()) {
                    Log.d(TAG, "Root is not available, skipping silent root CA install.");
                    return;
                }

                File tempCert = new File(mContext.getCacheDir(), "kotsafe_ca_temp.crt");
                try (FileOutputStream fos = new FileOutputStream(tempCert)) {
                    fos.write(mCaCertPem.getBytes(StandardCharsets.UTF_8));
                }

                String hash = computeOldSubjectHash(mCaCert);
                String tempPath = tempCert.getAbsolutePath();

                Log.i(TAG, "Attempting automatic root CA installation (hash: " + hash + ")...");

                Process process = Runtime.getRuntime().exec("su");
                try (java.io.DataOutputStream os = new java.io.DataOutputStream(process.getOutputStream())) {
                    os.writeBytes("HASH=$(toybox openssl x509 -inform PEM -subject_hash_old -in " + tempPath + " -noout 2>/dev/null || openssl x509 -inform PEM -subject_hash_old -in " + tempPath + " -noout 2>/dev/null)\n");
                    os.writeBytes("if [ -z \"$HASH\" ]; then HASH=\"" + hash + "\"; fi\n");

                    // 1. Install into Android user trust store
                    os.writeBytes("mkdir -p /data/misc/user/0/cacerts-added\n");
                    os.writeBytes("cp " + tempPath + " /data/misc/user/0/cacerts-added/$HASH.0\n");
                    os.writeBytes("chmod 644 /data/misc/user/0/cacerts-added/$HASH.0\n");
                    os.writeBytes("chown 1000:1000 /data/misc/user/0/cacerts-added/$HASH.0 2>/dev/null || chown system:system /data/misc/user/0/cacerts-added/$HASH.0 2>/dev/null\n");

                    // Also install for other users if present
                    os.writeBytes("for u in /data/misc/user/*; do\n");
                    os.writeBytes("  if [ -d \"$u\" ]; then\n");
                    os.writeBytes("    mkdir -p \"$u/cacerts-added\"\n");
                    os.writeBytes("    cp " + tempPath + " \"$u/cacerts-added/$HASH.0\"\n");
                    os.writeBytes("    chmod 644 \"$u/cacerts-added/$HASH.0\"\n");
                    os.writeBytes("  fi\n");
                    os.writeBytes("done\n");

                    // 2. Install into Magisk modules if Magisk is present
                    os.writeBytes("if [ -d \"/data/adb\" ]; then\n");
                    os.writeBytes("  MOD=\"/data/adb/modules/kotsafe_ca\"\n");
                    os.writeBytes("  mkdir -p \"$MOD/system/etc/security/cacerts\"\n");
                    os.writeBytes("  cp " + tempPath + " \"$MOD/system/etc/security/cacerts/$HASH.0\"\n");
                    os.writeBytes("  chmod 644 \"$MOD/system/etc/security/cacerts/$HASH.0\"\n");
                    os.writeBytes("  echo 'id=kotsafe_ca' > \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'name=KotSafe System CA' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'version=1.0' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'versionCode=1' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'author=KotSafe' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  echo 'description=Automatically trusts KotSafe Root CA system-wide' >> \"$MOD/module.prop\"\n");
                    os.writeBytes("  touch \"$MOD/auto_mount\"\n");
                    os.writeBytes("fi\n");

                    // 3. Mount overlay / direct install to /system if remountable
                    os.writeBytes("mount -o rw,remount /system 2>/dev/null || mount -o rw,remount / 2>/dev/null\n");
                    os.writeBytes("if [ -d \"/system/etc/security/cacerts\" ]; then\n");
                    os.writeBytes("  cp " + tempPath + " /system/etc/security/cacerts/$HASH.0 2>/dev/null\n");
                    os.writeBytes("  chmod 644 /system/etc/security/cacerts/$HASH.0 2>/dev/null\n");
                    os.writeBytes("fi\n");

                    // 4. Also try conscrypt apex
                    os.writeBytes("if [ -d \"/apex/com.android.conscrypt/cacerts\" ]; then\n");
                    os.writeBytes("  mount -o rw,remount /apex/com.android.conscrypt 2>/dev/null\n");
                    os.writeBytes("  cp " + tempPath + " /apex/com.android.conscrypt/cacerts/$HASH.0 2>/dev/null\n");
                    os.writeBytes("  chmod 644 /apex/com.android.conscrypt/cacerts/$HASH.0 2>/dev/null\n");
                    os.writeBytes("fi\n");

                    os.writeBytes("exit\n");
                    os.flush();
                }

                int exitCode = process.waitFor();
                tempCert.delete();
                Log.i(TAG, "Automatic root CA installation completed with exit code: " + exitCode);
            } catch (Exception e) {
                Log.w(TAG, "autoInstallCaWithRoot exception: " + e.getMessage());
            }
        }, "AutoInstallCaThread").start();
    }

    public boolean exportCaCertificate(Uri destinationUri) {
        try (OutputStream os = mContext.getContentResolver().openOutputStream(destinationUri)) {
            if (os == null) return false;
            os.write(mCaCertPem.getBytes(StandardCharsets.UTF_8));
            os.flush();
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed exporting CA certificate: " + e.getMessage());
            return false;
        }
    }

    /**
     * Dynamically generates an on-the-fly SSLContext for the given server hostname/IP.
     */
    public SSLContext getOrCreateServerSSLContext(String hostname) throws Exception {
        if (hostname == null || hostname.isEmpty()) {
            hostname = "unknown.local";
        }

        SSLContext cached = mContextCache.get(hostname);
        if (cached != null) {
            return cached;
        }

        // Generate leaf certificate signed by our Root CA
        long now = System.currentTimeMillis() - 60_000L;
        Date startDate = new Date(now);
        Date endDate = new Date(now + ONE_YEAR_MS);
        BigInteger serial = new BigInteger(64, new SecureRandom());

        X500Name issuer = new X500Name(mCaCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + hostname + ", O=KotSafe Intercepted, C=US");

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, serial, startDate, endDate, subject, mServerKeyPair.getPublic());

        // Leaf cert: isCA = false
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

        // Subject Alternative Name (SAN)
        List<GeneralName> sanList = new ArrayList<>();
        try {
            // Check if hostname is an IP address
            InetAddress addr = InetAddress.getByName(hostname);
            if (hostname.matches("^[0-9.]+$") || hostname.contains(":")) {
                sanList.add(new GeneralName(GeneralName.iPAddress, hostname));
            } else {
                sanList.add(new GeneralName(GeneralName.dNSName, hostname));
            }
        } catch (Exception ignored) {
            sanList.add(new GeneralName(GeneralName.dNSName, hostname));
        }

        GeneralNames san = new GeneralNames(sanList.toArray(new GeneralName[0]));
        builder.addExtension(Extension.subjectAlternativeName, false, san);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(mCaKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate leafCert = new JcaX509CertificateConverter().getCertificate(holder);

        // Put into in-memory KeyStore
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        Certificate[] chain = new Certificate[]{leafCert, mCaCert};
        char[] pwd = "password".toCharArray();
        ks.setKeyEntry("server", mServerKeyPair.getPrivate(), pwd, chain);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pwd);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

        mContextCache.put(hostname, sslContext);
        return sslContext;
    }

    /**
     * Returns an upstream SSLContext configured to connect to target servers
     * validating against standard system CA root certificates.
     */
    public SSLContext getUpstreamSSLContext() throws Exception {
        SSLContext sc = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        sc.init(null, tmf.getTrustManagers(), new SecureRandom());
        return sc;
    }

    private static String certToPem(X509Certificate cert) throws IOException {
        java.io.StringWriter sw = new java.io.StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw)) {
            pw.writeObject(cert);
        }
        return sw.toString();
    }
}
