/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.server.FirewallBlockHttpServer;
import com.google.android.material.card.MaterialCardView;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Enterprise-grade Firewall Block Page shown when a user or app attempts to
 * connect to a blocked site, domain, URL, or hash.
 * Styled with the authentic Sophos block layout branded with KotSafe app name.
 */
public class FirewallBlockPageActivity extends AppCompatActivity {
    private static final String TAG = "FirewallBlockPage";

    private String mTarget;
    private String mTargetType;
    private String mReason;
    private String mAppName;
    private String mPackageName;

    private boolean mAboutExpanded = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_firewall_block_page);

        // Ensure HTTP block daemon is running on port 8090
        FirewallBlockHttpServer.getInstance(this).start();

        extractIntentExtras(getIntent());
        initViews();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        extractIntentExtras(intent);
        initViews();
    }

    private void extractIntentExtras(Intent intent) {
        if (intent == null) return;
        mTarget = intent.getStringExtra("target");
        mTargetType = intent.getStringExtra("target_type");
        mReason = intent.getStringExtra("reason");
        mAppName = intent.getStringExtra("app_name");
        mPackageName = intent.getStringExtra("package_name");

        if (mTarget == null || mTarget.isEmpty()) mTarget = "Unknown Destination";
        if (mTargetType == null || mTargetType.isEmpty()) mTargetType = "SITE";
        if (mReason == null || mReason.isEmpty()) mReason = "Security Threat / Restricted Sites";
        if (mAppName == null || mAppName.isEmpty()) mAppName = "Web Browser";
    }

    private void initViews() {
        TextView tvAppBrand = findViewById(R.id.tv_app_brand);
        TextView tvBlockStop = findViewById(R.id.tv_block_stop);
        TextView tvBlockTitle = findViewById(R.id.tv_block_title);
        TextView tvBlockSubtitle = findViewById(R.id.tv_block_subtitle);
        TextView tvSuggestCategory = findViewById(R.id.tv_suggest_category);

        TextView tvTargetValue = findViewById(R.id.tv_target_value);
        TextView tvCategoryValue = findViewById(R.id.tv_category_value);
        TextView tvAppName = findViewById(R.id.tv_app_name);
        TextView tvPolicyReason = findViewById(R.id.tv_policy_reason);
        TextView tvTimestamp = findViewById(R.id.tv_timestamp);
        ImageView ivAppIcon = findViewById(R.id.iv_app_icon);

        final MaterialCardView cardAbout = findViewById(R.id.card_about_details);
        final TextView tvAboutIndicator = findViewById(R.id.tv_about_indicator);
        View layoutToggleAbout = findViewById(R.id.layout_toggle_about);

        Button btnBack = findViewById(R.id.btn_back);
        Button btnUnblockSite = findViewById(R.id.btn_unblock_site);
        View btnActionCenterTop = findViewById(R.id.btn_action_center_top);
        ImageView btnCopyTarget = findViewById(R.id.btn_copy_target);

        // Header and Titles
        tvAppBrand.setText("KotSafe Security");
        tvBlockStop.setText("Stop!");

        String categoryText = (mReason != null && !mReason.isEmpty()) ? mReason : "Administrator Security Policy";
        String title = "This site is blocked by your administrator";
        String subDesc = "Your network administrator has restricted access to this destination. Contact your network administrator for assistance.";

        if ("IP".equalsIgnoreCase(mTargetType)) {
            title = "This IP address is blocked by your administrator";
            subDesc = "Your network administrator has restricted access to IP address " + mTarget + ". Contact your administrator if you believe this is in error.";
        } else if ("FILE".equalsIgnoreCase(mTargetType) || "HASH".equalsIgnoreCase(mTargetType)) {
            title = "This file is blocked by your administrator";
            subDesc = "Your administrator has blocked files matching signature " + mTarget + ". Contact your administrator if you believe this is in error.";
        } else if ("APP".equalsIgnoreCase(mTargetType)) {
            title = "This application is blocked by your administrator";
            subDesc = "Your administrator has restricted access to application " + mAppName + ". Contact your administrator for assistance.";
        } else if ("URL".equalsIgnoreCase(mTargetType)) {
            title = "This site is blocked by your administrator";
            subDesc = "Your network administrator has restricted access to URL " + mTarget + ". Contact your administrator if you think this site was blocked by mistake.";
        }

        tvBlockTitle.setText(title);
        tvBlockSubtitle.setText(subDesc);
        tvSuggestCategory.setText("Think this was blocked by mistake? Contact your network administrator to request access.");
        tvSuggestCategory.setOnClickListener(v ->
                new AlertDialog.Builder(this)
                        .setTitle("Contact Administrator")
                        .setMessage("Administrative Block Notice:\n\nTarget: " + mTarget + "\nPolicy: " + categoryText + "\n\nPlease contact your Network Security Administrator or IT Helpdesk (admin@organization.local) with the destination details to request an exception.")
                        .setPositiveButton("OK", null)
                        .show()
        );

        // Details card fields
        tvTargetValue.setText(mTarget);
        tvCategoryValue.setText(categoryText);
        tvAppName.setText(mAppName + (mPackageName != null ? " (" + mPackageName + ")" : ""));
        tvPolicyReason.setText(mReason != null ? mReason : "KotSafe Next-Gen Firewall Rule");

        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault());
        tvTimestamp.setText(sdf.format(new Date()));

        // Resolve App Icon
        if (mPackageName != null && !mPackageName.isEmpty()) {
            try {
                PackageManager pm = getPackageManager();
                Drawable icon = pm.getApplicationIcon(mPackageName);
                ivAppIcon.setImageDrawable(icon);
            } catch (Exception ignored) {
                ivAppIcon.setImageResource(R.drawable.ic_language);
            }
        }

        // Toggle About dropdown
        layoutToggleAbout.setOnClickListener(v -> {
            mAboutExpanded = !mAboutExpanded;
            cardAbout.setVisibility(mAboutExpanded ? View.VISIBLE : View.GONE);
            tvAboutIndicator.setText(mAboutExpanded ? "∨" : "›");
        });

        // Copy button
        btnCopyTarget.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            if (cm != null) {
                cm.setPrimaryClip(ClipData.newPlainText("Blocked Target", mTarget));
                Toast.makeText(this, "Copied to clipboard", Toast.LENGTH_SHORT).show();
            }
        });

        // Return to previous page button
        btnBack.setOnClickListener(v -> finish());

        // Unblock site button
        btnUnblockSite.setOnClickListener(v -> showUnblockConfirmation());

        // Action Center top button
        btnActionCenterTop.setOnClickListener(v -> {
            Intent intent = new Intent(this, SecurityActionsActivity.class);
            startActivity(intent);
        });
    }

    private void showUnblockConfirmation() {
        new AlertDialog.Builder(this)
                .setTitle("Allow Destination?")
                .setMessage("Are you sure you want to unblock " + mTarget + "?\n\nThis will add an ALLOW whitelist rule in your KotSafe firewall policy so traffic will no longer be intercepted.")
                .setPositiveButton("Unblock & Allow", (dialog, which) -> {
                    SecurityBlocklistManager mgr = SecurityBlocklistManager.getInstance(this);
                    if (mPackageName != null && !mPackageName.isEmpty()) {
                        mgr.unblock(mPackageName);
                    }
                    mgr.unblock(mTarget);
                    mgr.whitelist(
                            mTargetType,
                            mTarget,
                            SecurityRulesDb.SCOPE_EXACT,
                            "User whitelisted via Firewall Block Page"
                    );
                    Toast.makeText(this, "✓ " + mTarget + " has been unblocked and whitelisted", Toast.LENGTH_LONG).show();
                    finish();
                })
                .setNegativeButton("Keep Blocked", null)
                .show();
    }
}
