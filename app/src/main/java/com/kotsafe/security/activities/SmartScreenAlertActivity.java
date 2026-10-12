/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.SecurityDatabase;
import com.kotsafe.security.model.SecurityRulesDb;

/**
 * SmartScreen alert dialog shown when a confirmed malicious app is detected.
 * Presents threat info and gives the user 3 choices:
 *   1. Block the app (add to blocklist)
 *   2. Uninstall (launch system uninstall intent)
 *   3. Dismiss (take no action — audit trail still stored)
 */
public class SmartScreenAlertActivity extends AppCompatActivity {
    private static final String TAG = "SmartScreenAlertActivity";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_smartscreen_alert);

        String packageName = getIntent().getStringExtra("package_name");
        String sha256 = getIntent().getStringExtra("sha256");
        String verdict = getIntent().getStringExtra("verdict");

        // Populate UI
        ImageView ivIcon = findViewById(R.id.iv_threat_icon);
        TextView tvTitle = findViewById(R.id.tv_threat_title);
        TextView tvPackage = findViewById(R.id.tv_threat_package);
        TextView tvVerdict = findViewById(R.id.tv_threat_verdict);
        TextView tvSha256 = findViewById(R.id.tv_threat_sha256);
        Button btnBlock = findViewById(R.id.btn_block_app);
        Button btnUninstall = findViewById(R.id.btn_uninstall_app);
        Button btnDismiss = findViewById(R.id.btn_dismiss_alert);

        // Try to load app icon
        try {
            PackageManager pm = getPackageManager();
            Drawable icon = pm.getApplicationIcon(packageName);
            ivIcon.setImageDrawable(icon);
            String appName = pm.getApplicationLabel(
                    pm.getApplicationInfo(packageName, 0)).toString();
            tvTitle.setText("⚠ Threat: " + appName);
        } catch (Exception e) {
            tvTitle.setText("⚠ Threat Detected");
        }

        tvPackage.setText("Package: " + packageName);
        tvVerdict.setText("Verdict: " + verdict);
        tvSha256.setText("SHA-256: " + (sha256 != null ? sha256.substring(0, Math.min(16, sha256.length())) + "…" : "N/A"));

        // Block action
        btnBlock.setOnClickListener(v -> {
            if (sha256 != null) {
                SecurityDatabase.getInstance(this).rules().blockHash(
                        sha256,
                        "User blocked via SmartScreen alert",
                        SecurityRulesDb.SOURCE_USER);
            }
            SecurityDatabase.getInstance(this).rules().blockApp(
                    packageName,
                    "User blocked via SmartScreen alert",
                    SecurityRulesDb.SOURCE_USER);
            Log.i(TAG, "User blocked: " + packageName);
            finish();
        });

        // Uninstall action
        btnUninstall.setOnClickListener(v -> {
            android.net.Uri uri = android.net.Uri.fromParts("package", packageName, null);
            android.content.Intent uninstall = new android.content.Intent(
                    android.content.Intent.ACTION_DELETE, uri);
            startActivity(uninstall);
            finish();
        });

        // Dismiss
        btnDismiss.setOnClickListener(v -> {
            Log.i(TAG, "User dismissed SmartScreen for: " + packageName);
            finish();
        });
    }
}
