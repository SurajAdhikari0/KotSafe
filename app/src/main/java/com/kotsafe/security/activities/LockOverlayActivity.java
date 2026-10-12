package com.kotsafe.security.activities;

import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.R;
import com.kotsafe.security.model.PhysicalSecurityManager;
import com.google.android.material.button.MaterialButton;

import java.util.concurrent.Executor;

public class LockOverlayActivity extends AppCompatActivity {
    private PhysicalSecurityManager mManager;
    private EditText mEtPin;
    private TextView mTvStatus;
    private MaterialButton mBtnBiometric;
    private int mAttempts = 0;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON |
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED |
                WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true);
            setTurnScreenOn(true);
        }
        setContentView(R.layout.activity_lock_overlay);

        mManager = PhysicalSecurityManager.getInstance(this);
        mEtPin = findViewById(R.id.et_lock_pin);
        mTvStatus = findViewById(R.id.tv_lock_status);
        mBtnBiometric = findViewById(R.id.btn_biometric_unlock);
        MaterialButton btnUnlock = findViewById(R.id.btn_unlock);

        if (getIntent() != null && getIntent().hasExtra("reason")) {
            String reason = getIntent().getStringExtra("reason");
            if (reason != null && mTvStatus != null) {
                mTvStatus.setText(reason);
                mTvStatus.setTextColor(0xFFFF5252);
            }
        }

        boolean biometricAvailable = checkBiometricSupport();
        if (biometricAvailable && mManager.isBiometricEnabled()) {
            mBtnBiometric.setVisibility(View.VISIBLE);
            mBtnBiometric.setOnClickListener(v -> showBiometricPrompt());
            // Automatically launch biometric prompt on display
            showBiometricPrompt();
        } else {
            mBtnBiometric.setVisibility(View.GONE);
        }

        btnUnlock.setOnClickListener(v -> {
            String pin = mEtPin.getText().toString().trim();
            if (mManager.verifyPin(pin)) {
                onUnlockSuccess();
            } else {
                mAttempts++;
                mEtPin.setText("");
                if (mAttempts >= 3) {
                    Toast.makeText(this, "Too many failed attempts. Access denied.", Toast.LENGTH_LONG).show();
                    mTvStatus.setText("Too many failed attempts");
                    mTvStatus.setTextColor(0xFFFF4444);
                } else {
                    Toast.makeText(this, "Incorrect PIN (" + (3 - mAttempts) + " attempts left)", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private boolean checkBiometricSupport() {
        BiometricManager biometricManager = BiometricManager.from(this);
        int canAuth = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        return canAuth == BiometricManager.BIOMETRIC_SUCCESS;
    }

    private void showBiometricPrompt() {
        Executor executor = ContextCompat.getMainExecutor(this);
        BiometricPrompt biometricPrompt = new BiometricPrompt(this, executor, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                // Fall back to PIN entry silently
            }

            @Override
            public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                mManager.onAuthSuccess();
                onUnlockSuccess();
            }

            @Override
            public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                mAttempts++;
                mManager.onAuthFailure();
                Toast.makeText(LockOverlayActivity.this, "Biometric authentication failed", Toast.LENGTH_SHORT).show();
            }
        });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle("KotSafe Authorization")
                .setSubtitle("Authenticate using Fingerprint, Face or Screen Lock")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build();

        biometricPrompt.authenticate(promptInfo);
    }

    private void onUnlockSuccess() {
        mManager.setSessionAuthenticated(true);
        // Clear firewall lockdown to restore normal network traffic
        mManager.setFirewallLockdownEnabled(false);
        finish();
    }

    @Override
    public void onBackPressed() {
        // Prevent bypassing the security lock overlay via keyboard or hardware back
        if (mManager.isPinSet() && !mManager.isSessionAuthenticated()) {
            Toast.makeText(this, "Authentication required to dismiss lock", Toast.LENGTH_SHORT).show();
            return;
        }
        super.onBackPressed();
    }
}
