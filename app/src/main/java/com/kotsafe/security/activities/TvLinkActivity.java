package com.kotsafe.security.activities;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;

import com.google.android.gms.tasks.Task;
import com.google.mlkit.vision.barcode.common.Barcode;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanner;
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions;
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseUser;
import com.google.android.material.button.MaterialButton;
import com.kotsafe.security.R;
import com.kotsafe.security.tv.TvLinkApi;

/**
 * The phone-side half of the TV sign-in flow. It accepts a verified app link or scans the QR
 * itself, then approves the exact short-lived server session after the user confirms it.
 */
public class TvLinkActivity extends BaseActivity {
    private TextView mStatus;
    private TextView mCode;
    private MaterialButton mApprove;
    private String mSessionId;
    private String mDeviceCode;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tv_link);
        mStatus = findViewById(R.id.tv_tv_link_status);
        mCode = findViewById(R.id.tv_tv_link_code);
        mApprove = findViewById(R.id.btn_tv_link_approve);
        MaterialButton scan = findViewById(R.id.btn_tv_link_scan);
        MaterialButton close = findViewById(R.id.btn_tv_link_close);
        scan.setOnClickListener(v -> scanTvCode());
        close.setOnClickListener(v -> finish());
        mApprove.setOnClickListener(v -> approveTv());
        readLink(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        readLink(intent);
    }

    private void scanTvCode() {
        try {
            GmsBarcodeScannerOptions options = new GmsBarcodeScannerOptions.Builder()
                    .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
                    .build();
            GmsBarcodeScanner scanner = GmsBarcodeScanning.getClient(this, options);
            scanner.startScan().addOnSuccessListener(barcode -> readRawLink(barcode.getRawValue()))
                    .addOnCanceledListener(() -> setStatus("Scanner closed. Scan the TV QR code when ready."))
                    .addOnFailureListener(error -> setStatus("Scanner unavailable: " + error.getMessage()));
        } catch (Exception e) {
            setStatus("Scanner unavailable. Open the QR code with KotSafe installed.");
        }
    }

    private void readLink(Intent intent) {
        readRawLink(intent == null || intent.getData() == null ? null : intent.getData().toString());
    }

    private void readRawLink(String raw) {
        try {
            Uri uri = Uri.parse(raw == null ? "" : raw);
            String sessionId = uri.getQueryParameter("sid");
            String deviceCode = uri.getQueryParameter("code");
            if (!"kotsafe".equalsIgnoreCase(uri.getScheme()) || !"tv-auth".equalsIgnoreCase(uri.getHost())
                    || !isSafeToken(sessionId) || !isSafeToken(deviceCode)) {
                mSessionId = null;
                mDeviceCode = null;
                mApprove.setEnabled(false);
                mCode.setText("No TV code scanned");
                setStatus("Scan the QR code displayed by KotSafe TV.");
                return;
            }
            mSessionId = sessionId;
            mDeviceCode = deviceCode;
            mApprove.setEnabled(true);
            mCode.setText("TV link ready");
            setStatus("Confirm only if this is the TV you are setting up. The link expires soon.");
        } catch (Exception ignored) {
            mApprove.setEnabled(false);
            setStatus("That QR code is not a valid KotSafe TV link.");
        }
    }

    private void approveTv() {
        if (mSessionId == null || mDeviceCode == null) return;
        FirebaseAuth auth = firebaseAuth();
        FirebaseUser user = auth == null ? null : auth.getCurrentUser();
        if (user == null || user.isAnonymous()) {
            setStatus("Sign in to your KotSafe account first, then scan the TV code again.");
            startActivity(new Intent(this, LoginActivity.class));
            return;
        }
        mApprove.setEnabled(false);
        setStatus("Checking your account and approving the TV…");
        Task<com.google.firebase.auth.GetTokenResult> tokenTask = user.getIdToken(true);
        tokenTask.addOnSuccessListener(token -> TvLinkApi.approve(mSessionId, mDeviceCode, token.getToken(),
                new TvLinkApi.Callback() {
                    @Override
                    public void onSuccess(String message) {
                        setStatus(message);
                        mCode.setText("Approved — return to your TV");
                        Toast.makeText(TvLinkActivity.this, "KotSafe TV approved", Toast.LENGTH_SHORT).show();
                    }

                    @Override
                    public void onError(String message) {
                        mApprove.setEnabled(true);
                        setStatus(message);
                    }
                }))
                .addOnFailureListener(error -> {
                    mApprove.setEnabled(true);
                    setStatus("Could not verify your sign-in. Please try again.");
                });
    }

    private FirebaseAuth firebaseAuth() {
        try {
            if (FirebaseApp.getApps(this).isEmpty()) FirebaseApp.initializeApp(this);
            return FirebaseAuth.getInstance();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isSafeToken(String value) {
        return value != null && value.matches("[A-Za-z0-9_-]{16,128}");
    }

    private void setStatus(String text) {
        if (mStatus != null) mStatus.setText(text);
    }
}
