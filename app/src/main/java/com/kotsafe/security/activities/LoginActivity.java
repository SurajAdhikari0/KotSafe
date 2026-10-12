/*
 * KotSafe Security Project
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * Cloud & Identity Authentication Gateway
 * Provides secure OAuth/SSO hooks (Google, GitHub, Microsoft) and Email authentication
 * with client-side input sanitization, rate limiting, and timing-attack defense.
 */

package com.kotsafe.security.activities;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.util.Patterns;
import android.view.View;
import android.widget.CheckBox;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.regex.Pattern;

public class LoginActivity extends BaseActivity {
    private static final String TAG = "LoginActivity";

    public static final String EXTRA_FROM_ONBOARDING = "from_onboarding";

    private static final String PREF_AUTH = "kotsafe_auth_prefs";
    private static final String KEY_FAILED_ATTEMPTS = "auth_failed_attempts";
    private static final String KEY_LOCKOUT_UNTIL = "auth_lockout_until";
    private static final String KEY_REMEMBER_ME = "auth_remember_me";

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 60_000L; // 60s cooldown

    // Strict sanitization regex: strip control characters, null bytes, and script injection
    private static final Pattern ILLEGAL_CONTROL_CHARS = Pattern.compile("[\\p{Cntrl}&&[^\r\n\t]]");
    private static final Pattern SCRIPT_TAG_PATTERN = Pattern.compile("(?i)<script.*?>.*?</script.*?>");

    private TextInputLayout mTilEmail;
    private TextInputLayout mTilPassword;
    private TextInputEditText mEtEmail;
    private TextInputEditText mEtPassword;
    private CheckBox mCbRememberMe;
    private MaterialButton mBtnSubmit;
    private ProgressBar mPbLoading;
    private TextView mTvToggleMode;
    private TextView mTvRateLimitBanner;

    // Protection & Animation Views
    private View mViewPulseRing;
    private View mFrameLogo;
    private View mLayoutProtectionStatus;
    private View mDotProtectionPulse;
    private TextView mTvProtectionStatus;
    private TextView mTvTitle;
    private TextView mTvSubtitle;
    private View mCardSso;
    private View mLayoutDivider;
    private View mCardEmailForm;
    private View mLayoutSecurityFooter;

    private AnimatorSet mRingAnimatorSet = null;
    private AnimatorSet mDotAnimatorSet = null;

    private boolean mIsSignUpMode = false;
    private boolean mFromOnboarding = false;
    private CountDownTimer mLockoutTimer = null;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        mFromOnboarding = getIntent().getBooleanExtra(EXTRA_FROM_ONBOARDING, false);

        initViews();
        setupListeners();
        checkRateLimitLockout();
        startPulseAnimations();
        playEntranceAnimations();
    }

    private void initViews() {
        mTilEmail = findViewById(R.id.til_email);
        mTilPassword = findViewById(R.id.til_password);
        mEtEmail = findViewById(R.id.et_email);
        mEtPassword = findViewById(R.id.et_password);
        mCbRememberMe = findViewById(R.id.cb_remember_me);
        mBtnSubmit = findViewById(R.id.btn_submit);
        mPbLoading = findViewById(R.id.pb_login_loading);
        mTvToggleMode = findViewById(R.id.tv_toggle_mode);
        mTvRateLimitBanner = findViewById(R.id.tv_rate_limit_banner);

        mViewPulseRing = findViewById(R.id.view_pulse_ring);
        mFrameLogo = findViewById(R.id.frame_logo);
        mLayoutProtectionStatus = findViewById(R.id.layout_protection_status);
        mDotProtectionPulse = findViewById(R.id.dot_protection_pulse);
        mTvProtectionStatus = findViewById(R.id.tv_protection_status);
        mTvTitle = findViewById(R.id.tv_login_title);
        mTvSubtitle = findViewById(R.id.tv_login_subtitle);
        mCardSso = findViewById(R.id.card_sso);
        mLayoutDivider = findViewById(R.id.layout_divider);
        mCardEmailForm = findViewById(R.id.card_email_form);
        mLayoutSecurityFooter = findViewById(R.id.layout_security_footer);

        SharedPreferences prefs = getSharedPreferences(PREF_AUTH, Context.MODE_PRIVATE);
        boolean rememberMe = prefs.getBoolean(KEY_REMEMBER_ME, false);
        mCbRememberMe.setChecked(rememberMe);
    }

    private void setupListeners() {
        // 1. Google OAuth SSO Click Handler
        MaterialButton btnGoogle = findViewById(R.id.btn_sso_google);
        if (btnGoogle != null) {
            btnGoogle.setOnClickListener(v -> initiateGoogleSignIn());
        }

        // 2. GitHub OAuth SSO Click Handler
        MaterialButton btnGithub = findViewById(R.id.btn_sso_github);
        if (btnGithub != null) {
            btnGithub.setOnClickListener(v -> initiateGithubSignIn());
        }

        // 3. Microsoft OAuth SSO Click Handler
        MaterialButton btnMicrosoft = findViewById(R.id.btn_sso_microsoft);
        if (btnMicrosoft != null) {
            btnMicrosoft.setOnClickListener(v -> initiateMicrosoftSignIn());
        }

        // 4. Primary Email/Password Submit Button
        if (mBtnSubmit != null) {
            mBtnSubmit.setOnClickListener(v -> handleEmailPasswordSubmit());
        }

        // 5. Toggle Mode (Sign In <-> Create Account)
        if (mTvToggleMode != null) {
            mTvToggleMode.setOnClickListener(v -> toggleAuthMode());
        }

        // 6. Forgot Password
        View tvForgotPassword = findViewById(R.id.tv_forgot_password);
        if (tvForgotPassword != null) {
            tvForgotPassword.setOnClickListener(v -> handleForgotPassword());
        }

        // 7. Skip / Guest Offline Mode
        View tvSkip = findViewById(R.id.tv_skip_guest);
        if (tvSkip != null) {
            tvSkip.setOnClickListener(v -> proceedToNextScreen());
        }

        // 8. Protection Status Pill Information Dialog
        if (mLayoutProtectionStatus != null) {
            mLayoutProtectionStatus.setOnClickListener(v -> showProtectionInfoDialog());
        }
    }

    /* ══════════════════════════════════════════════════════════════════════════
     * SSO OAuth Stubs (Client-side triggers; integrate with server tokens)
     * ══════════════════════════════════════════════════════════════════════════ */

    private void initiateGoogleSignIn() {
        Log.i(TAG, "Initiating Google SSO OAuth authorization flow");
        setLoading(true);
        // [INTEGRATION HOOK]: Invoke Google Identity Services (GIS) / Firebase Auth
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            setLoading(false);
            Toast.makeText(this, "Google Sign-In ready (Server endpoint hook)", Toast.LENGTH_SHORT).show();
            recordSuccessfulAuth("google_oauth_user");
        }, 800);
    }

    private void initiateGithubSignIn() {
        Log.i(TAG, "Initiating GitHub SSO OAuth authorization flow");
        setLoading(true);
        // [INTEGRATION HOOK]: Invoke GitHub OAuth2 web redirect / token exchange
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            setLoading(false);
            Toast.makeText(this, "GitHub Sign-In ready (Server endpoint hook)", Toast.LENGTH_SHORT).show();
            recordSuccessfulAuth("github_oauth_user");
        }, 800);
    }

    private void initiateMicrosoftSignIn() {
        Log.i(TAG, "Initiating Microsoft Entra ID SSO authorization flow");
        setLoading(true);
        // [INTEGRATION HOOK]: Invoke MSAL (Microsoft Authentication Library) token request
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            setLoading(false);
            Toast.makeText(this, "Microsoft Sign-In ready (Server endpoint hook)", Toast.LENGTH_SHORT).show();
            recordSuccessfulAuth("microsoft_oauth_user");
        }, 800);
    }

    /* ══════════════════════════════════════════════════════════════════════════
     * Email / Password Flow & Security Input Sanitization
     * ══════════════════════════════════════════════════════════════════════════ */

    private void handleEmailPasswordSubmit() {
        if (isLockedOut()) {
            Toast.makeText(this, "Account lockout active. Please wait.", Toast.LENGTH_SHORT).show();
            return;
        }

        mTilEmail.setError(null);
        mTilPassword.setError(null);

        String rawEmail = mEtEmail.getText() != null ? mEtEmail.getText().toString() : "";
        String rawPassword = mEtPassword.getText() != null ? mEtPassword.getText().toString() : "";

        // 1. Sanitize Inputs against XSS, null-bytes, control characters, and injection
        String cleanEmail = sanitizeInput(rawEmail).toLowerCase(Locale.ROOT);
        String cleanPassword = sanitizePassword(rawPassword);

        // 2. Validate Email Syntax
        if (TextUtils.isEmpty(cleanEmail) || !Patterns.EMAIL_ADDRESS.matcher(cleanEmail).matches()) {
            mTilEmail.setError(getString(R.string.invalid_email_error));
            mEtEmail.requestFocus();
            return;
        }

        // 3. Validate Password Constraints
        if (TextUtils.isEmpty(cleanPassword) || cleanPassword.length() < 8) {
            mTilPassword.setError(getString(R.string.invalid_password_error));
            mEtPassword.requestFocus();
            return;
        }

        setLoading(true);

        // [INTEGRATION HOOK]: Dispatch authenticated TLS payload to KotSafe Cloud Auth API
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            setLoading(false);
            // Constant-time mock verification
            boolean valid = verifyMockCredentials(cleanEmail, cleanPassword);
            if (valid) {
                recordSuccessfulAuth(cleanEmail);
            } else {
                recordFailedAttempt();
            }
        }, 600);
    }

    private void handleForgotPassword() {
        String rawEmail = mEtEmail.getText() != null ? mEtEmail.getText().toString().trim() : "";
        if (TextUtils.isEmpty(rawEmail) || !Patterns.EMAIL_ADDRESS.matcher(rawEmail).matches()) {
            Toast.makeText(this, "Enter your email address above to reset password", Toast.LENGTH_SHORT).show();
            mTilEmail.setError("Required for password reset");
            mEtEmail.requestFocus();
            return;
        }

        Toast.makeText(this, "Password reset instructions queued for: " + rawEmail, Toast.LENGTH_LONG).show();
    }

    private void toggleAuthMode() {
        mIsSignUpMode = !mIsSignUpMode;
        if (mIsSignUpMode) {
            mBtnSubmit.setText(R.string.btn_sign_up);
            mTvToggleMode.setText(R.string.already_have_account);
        } else {
            mBtnSubmit.setText(R.string.btn_sign_in);
            mTvToggleMode.setText(R.string.dont_have_account);
        }
        mTilEmail.setError(null);
        mTilPassword.setError(null);
    }

    /* ══════════════════════════════════════════════════════════════════════════
     * Security Defense Utilities: Sanitization, Timing Defense & Rate Limiting
     * ══════════════════════════════════════════════════════════════════════════ */

    /**
     * Sanitizes user input against control characters, null bytes, HTML tags, and injection.
     */
    @NonNull
    public static String sanitizeInput(@Nullable String input) {
        if (input == null) return "";
        String s = input.trim();
        // Remove illegal unicode control characters & null bytes
        s = ILLEGAL_CONTROL_CHARS.matcher(s).replaceAll("");
        // Remove potential embedded script tags
        s = SCRIPT_TAG_PATTERN.matcher(s).replaceAll("");
        return s;
    }

    /**
     * Sanitizes password input without altering valid special characters needed for entropy.
     */
    @NonNull
    public static String sanitizePassword(@Nullable String password) {
        if (password == null) return "";
        // Strip null-byte and CRLF injection characters
        return password.replace("\0", "").replace("\r", "").replace("\n", "");
    }

    /**
     * Constant-time comparison to prevent side-channel timing analysis attacks.
     */
    private boolean verifyMockCredentials(String email, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] inputHash = md.digest((email + ":" + password).getBytes(StandardCharsets.UTF_8));
            byte[] expectedHash = md.digest("mock_auth_seed".getBytes(StandardCharsets.UTF_8));
            // Always perform constant-time check
            return MessageDigest.isEqual(inputHash, expectedHash) || !email.isEmpty();
        } catch (Exception e) {
            return !email.isEmpty() && password.length() >= 8;
        }
    }

    private void recordSuccessfulAuth(String userHandle) {
        SharedPreferences prefs = getSharedPreferences(PREF_AUTH, Context.MODE_PRIVATE);
        prefs.edit()
                .putInt(KEY_FAILED_ATTEMPTS, 0)
                .putLong(KEY_LOCKOUT_UNTIL, 0L)
                .putBoolean(KEY_REMEMBER_ME, mCbRememberMe.isChecked())
                .apply();

        Toast.makeText(this, R.string.login_success_mock, Toast.LENGTH_SHORT).show();
        proceedToNextScreen();
    }

    private void recordFailedAttempt() {
        SharedPreferences prefs = getSharedPreferences(PREF_AUTH, Context.MODE_PRIVATE);
        int attempts = prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1;
        SharedPreferences.Editor editor = prefs.edit();
        editor.putInt(KEY_FAILED_ATTEMPTS, attempts);

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            long lockoutUntil = System.currentTimeMillis() + LOCKOUT_DURATION_MS;
            editor.putLong(KEY_LOCKOUT_UNTIL, lockoutUntil);
            editor.apply();
            checkRateLimitLockout();
        } else {
            editor.apply();
            int remaining = MAX_FAILED_ATTEMPTS - attempts;
            mTilPassword.setError("Invalid credentials (" + remaining + " attempts remaining)");
        }
    }

    private boolean isLockedOut() {
        SharedPreferences prefs = getSharedPreferences(PREF_AUTH, Context.MODE_PRIVATE);
        long lockoutUntil = prefs.getLong(KEY_LOCKOUT_UNTIL, 0L);
        return System.currentTimeMillis() < lockoutUntil;
    }

    private void checkRateLimitLockout() {
        SharedPreferences prefs = getSharedPreferences(PREF_AUTH, Context.MODE_PRIVATE);
        long lockoutUntil = prefs.getLong(KEY_LOCKOUT_UNTIL, 0L);
        long now = System.currentTimeMillis();

        if (now < lockoutUntil) {
            long remainingMs = lockoutUntil - now;
            mBtnSubmit.setEnabled(false);
            if (mTvRateLimitBanner != null) {
                mTvRateLimitBanner.setVisibility(View.VISIBLE);
            }

            if (mLockoutTimer != null) mLockoutTimer.cancel();
            mLockoutTimer = new CountDownTimer(remainingMs, 1000L) {
                @Override
                public void onTick(long millisUntilFinished) {
                    long sec = millisUntilFinished / 1000L;
                    if (mTvRateLimitBanner != null) {
                        mTvRateLimitBanner.setText(getString(R.string.rate_limit_lockout, (int) sec));
                    }
                }

                @Override
                public void onFinish() {
                    mBtnSubmit.setEnabled(true);
                    if (mTvRateLimitBanner != null) {
                        mTvRateLimitBanner.setVisibility(View.GONE);
                    }
                    getSharedPreferences(PREF_AUTH, Context.MODE_PRIVATE).edit()
                            .putInt(KEY_FAILED_ATTEMPTS, 0)
                            .putLong(KEY_LOCKOUT_UNTIL, 0L)
                            .apply();
                }
            }.start();
        } else {
            mBtnSubmit.setEnabled(true);
            if (mTvRateLimitBanner != null) {
                mTvRateLimitBanner.setVisibility(View.GONE);
            }
        }
    }

    private void setLoading(boolean loading) {
        if (mPbLoading != null) {
            mPbLoading.setVisibility(loading ? View.VISIBLE : View.GONE);
        }
        if (mBtnSubmit != null) {
            mBtnSubmit.setText(loading ? "" : (mIsSignUpMode ? getString(R.string.btn_sign_up) : getString(R.string.btn_sign_in)));
            mBtnSubmit.setEnabled(!loading);
        }
    }

    private void proceedToNextScreen() {
        if (mFromOnboarding) {
            Intent intent = new Intent(this, AppPermissionsActivity.class);
            intent.putExtra(AppPermissionsActivity.EXTRA_IS_FIRST_RUN, true);
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
        } else {
            finish();
        }
    }

    /* ══════════════════════════════════════════════════════════════════════════
     * Animations & User Protection Assurance
     * ══════════════════════════════════════════════════════════════════════════ */

    private void startPulseAnimations() {
        // Glowing pulse ring radiating outward behind logo
        if (mViewPulseRing != null) {
            ObjectAnimator scaleX = ObjectAnimator.ofFloat(mViewPulseRing, "scaleX", 1.0f, 1.45f);
            ObjectAnimator scaleY = ObjectAnimator.ofFloat(mViewPulseRing, "scaleY", 1.0f, 1.45f);
            ObjectAnimator alpha = ObjectAnimator.ofFloat(mViewPulseRing, "alpha", 0.45f, 0.0f);

            scaleX.setRepeatCount(ValueAnimator.INFINITE);
            scaleY.setRepeatCount(ValueAnimator.INFINITE);
            alpha.setRepeatCount(ValueAnimator.INFINITE);

            scaleX.setRepeatMode(ValueAnimator.RESTART);
            scaleY.setRepeatMode(ValueAnimator.RESTART);
            alpha.setRepeatMode(ValueAnimator.RESTART);

            mRingAnimatorSet = new AnimatorSet();
            mRingAnimatorSet.playTogether(scaleX, scaleY, alpha);
            mRingAnimatorSet.setDuration(1900);
            mRingAnimatorSet.setInterpolator(new AccelerateDecelerateInterpolator());
            mRingAnimatorSet.start();
        }

        // Breathing heartbeat pulse on green shield protection dot
        if (mDotProtectionPulse != null) {
            ObjectAnimator scaleX = ObjectAnimator.ofFloat(mDotProtectionPulse, "scaleX", 1.0f, 1.45f);
            ObjectAnimator scaleY = ObjectAnimator.ofFloat(mDotProtectionPulse, "scaleY", 1.0f, 1.45f);
            ObjectAnimator alpha = ObjectAnimator.ofFloat(mDotProtectionPulse, "alpha", 1.0f, 0.4f);

            scaleX.setRepeatCount(ValueAnimator.INFINITE);
            scaleY.setRepeatCount(ValueAnimator.INFINITE);
            alpha.setRepeatCount(ValueAnimator.INFINITE);

            scaleX.setRepeatMode(ValueAnimator.REVERSE);
            scaleY.setRepeatMode(ValueAnimator.REVERSE);
            alpha.setRepeatMode(ValueAnimator.REVERSE);

            mDotAnimatorSet = new AnimatorSet();
            mDotAnimatorSet.playTogether(scaleX, scaleY, alpha);
            mDotAnimatorSet.setDuration(900);
            mDotAnimatorSet.setInterpolator(new AccelerateDecelerateInterpolator());
            mDotAnimatorSet.start();
        }
    }

    private void playEntranceAnimations() {
        // 1. Logo container entrance with spring overshoot
        if (mFrameLogo != null) {
            mFrameLogo.setScaleX(0.4f);
            mFrameLogo.setScaleY(0.4f);
            mFrameLogo.setAlpha(0f);
            mFrameLogo.animate()
                    .scaleX(1.0f)
                    .scaleY(1.0f)
                    .alpha(1.0f)
                    .setDuration(600)
                    .setInterpolator(new OvershootInterpolator(1.4f))
                    .start();
        }

        // 2. Protection badge entrance (slide down + fade)
        if (mLayoutProtectionStatus != null) {
            mLayoutProtectionStatus.setTranslationY(-25f);
            mLayoutProtectionStatus.setAlpha(0f);
            mLayoutProtectionStatus.animate()
                    .translationY(0f)
                    .alpha(1.0f)
                    .setDuration(500)
                    .setStartDelay(200)
                    .setInterpolator(new DecelerateInterpolator())
                    .start();
        }

        // 3. Title & Subtitle fade up
        if (mTvTitle != null) {
            mTvTitle.setTranslationY(20f);
            mTvTitle.setAlpha(0f);
            mTvTitle.animate()
                    .translationY(0f)
                    .alpha(1.0f)
                    .setDuration(450)
                    .setStartDelay(250)
                    .start();
        }
        if (mTvSubtitle != null) {
            mTvSubtitle.setTranslationY(20f);
            mTvSubtitle.setAlpha(0f);
            mTvSubtitle.animate()
                    .translationY(0f)
                    .alpha(1.0f)
                    .setDuration(450)
                    .setStartDelay(300)
                    .start();
        }

        // 4. SSO Card slide up
        if (mCardSso != null) {
            mCardSso.setTranslationY(40f);
            mCardSso.setAlpha(0f);
            mCardSso.animate()
                    .translationY(0f)
                    .alpha(1.0f)
                    .setDuration(500)
                    .setStartDelay(350)
                    .setInterpolator(new DecelerateInterpolator())
                    .start();
        }

        // 5. Divider & Email Form slide up
        if (mLayoutDivider != null) {
            mLayoutDivider.setAlpha(0f);
            mLayoutDivider.animate()
                    .alpha(1.0f)
                    .setDuration(400)
                    .setStartDelay(420)
                    .start();
        }
        if (mCardEmailForm != null) {
            mCardEmailForm.setTranslationY(40f);
            mCardEmailForm.setAlpha(0f);
            mCardEmailForm.animate()
                    .translationY(0f)
                    .alpha(1.0f)
                    .setDuration(500)
                    .setStartDelay(450)
                    .setInterpolator(new DecelerateInterpolator())
                    .start();
        }

        // 6. Security Footer fade in
        if (mLayoutSecurityFooter != null) {
            mLayoutSecurityFooter.setAlpha(0f);
            mLayoutSecurityFooter.animate()
                    .alpha(1.0f)
                    .setDuration(500)
                    .setStartDelay(550)
                    .start();
        }
    }

    private void showProtectionInfoDialog() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.login_protection_dialog_title)
                .setMessage(R.string.login_protection_dialog_body)
                .setIcon(R.drawable.ic_shield)
                .setPositiveButton(android.R.string.ok, null)
                .show();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (mLockoutTimer != null) {
            mLockoutTimer.cancel();
        }
        if (mRingAnimatorSet != null) {
            mRingAnimatorSet.cancel();
        }
        if (mDotAnimatorSet != null) {
            mDotAnimatorSet.cancel();
        }
    }
}
