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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.activities;

import android.app.Service;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.text.method.LinkMovementMethod;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.text.HtmlCompat;
import androidx.core.view.MenuProvider;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.appbar.CollapsingToolbarLayout;

import com.kotsafe.security.Billing;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.Prefs;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.net.ssl.HttpsURLConnection;

import com.kotsafe.security.BuildConfig;
import com.kotsafe.security.views.BuildInfoDialog;

public class AboutActivity extends BaseActivity implements MenuProvider {
    private static final String TAG = "AboutActivity";
    private Handler mHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.about_activity);
        addMenuProvider(this);

        // Set up the collapsing toolbar
        androidx.appcompat.widget.Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle(""); // title shown by CollapsingToolbarLayout
        }

        CollapsingToolbarLayout collapsingToolbar = findViewById(R.id.collapsing_toolbar);
        if (collapsingToolbar != null) {
            collapsingToolbar.setTitle(""); // keep title hidden; we have custom views
        }

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.scrollView), (v, windowInsets) -> {
            Insets insets = windowInsets.getInsets(WindowInsetsCompat.Type.systemBars() |
                    WindowInsetsCompat.Type.displayCutout());
            int baseBottom = getResources().getDimensionPixelSize(R.dimen.about_horizontal_padding);
            v.setPadding(insets.left, 0, insets.right, insets.bottom + baseBottom);

            return windowInsets;
        });

        mHandler = new Handler(Looper.getMainLooper());

        setupBuildInfoViews();
        setupLegalAndPolicyViews();
    }

    private void setupLegalAndPolicyViews() {
        View rowPrivacy = findViewById(R.id.row_privacy_policy);
        if (rowPrivacy != null) {
            rowPrivacy.setOnClickListener(v -> showLegalDialog(
                    getString(R.string.privacy_policy_dialog_title),
                    getString(R.string.privacy_policy_dialog_body),
                    "https://kotsafe.com/privacy"
            ));
        }

        View rowTerms = findViewById(R.id.row_terms_of_service);
        if (rowTerms != null) {
            rowTerms.setOnClickListener(v -> showLegalDialog(
                    getString(R.string.terms_of_service_dialog_title),
                    getString(R.string.terms_of_service_dialog_body),
                    "https://kotsafe.com/terms"
            ));
        }

        View rowEula = findViewById(R.id.row_eula);
        if (rowEula != null) {
            rowEula.setOnClickListener(v -> showLegalDialog(
                    getString(R.string.eula_dialog_title),
                    getString(R.string.eula_dialog_body),
                    "https://kotsafe.com/legal/eula"
            ));
        }

        View rowLicenses = findViewById(R.id.row_third_party_licenses);
        if (rowLicenses != null) {
            rowLicenses.setOnClickListener(v -> showLegalDialog(
                    getString(R.string.third_party_compliance_title),
                    getString(R.string.opensource_licenses),
                    null
            ));
        }

        View rowDisclaimer = findViewById(R.id.row_legal_disclaimer);
        if (rowDisclaimer != null) {
            rowDisclaimer.setOnClickListener(v -> showLegalDialog(
                    getString(R.string.legal_disclaimer_dialog_title),
                    getString(R.string.legal_disclaimer_dialog_body),
                    null
            ));
        }

        View rowAccountLogin = findViewById(R.id.row_account_login);
        if (rowAccountLogin != null) {
            rowAccountLogin.setOnClickListener(v -> {
                Intent intent = new Intent(this, LoginActivity.class);
                startActivity(intent);
            });
        }
    }

    private void showLegalDialog(String title, String bodyHtml, @Nullable String officialUrl) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(HtmlCompat.fromHtml(bodyHtml, HtmlCompat.FROM_HTML_MODE_LEGACY))
                .setPositiveButton(android.R.string.ok, null);

        if (officialUrl != null && !officialUrl.isEmpty()) {
            builder.setNeutralButton("Open Website", (dialog, which) -> {
                try {
                    Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(officialUrl));
                    startActivity(browserIntent);
                } catch (Exception e) {
                    Toast.makeText(this, "Could not open browser", Toast.LENGTH_SHORT).show();
                }
            });
        }

        AlertDialog dialog = builder.create();
        dialog.show();
        TextView msgView = dialog.findViewById(android.R.id.message);
        if (msgView != null) {
            msgView.setMovementMethod(LinkMovementMethod.getInstance());
        }
    }

    private void setupBuildInfoViews() {
        Utils.BuildType rawBuild = Utils.getVerifiedBuild(this);
        String buildType = (rawBuild == Utils.BuildType.UNKNOWN) ? "debug" : rawBuild.toString().toLowerCase();
        String primaryAbi = Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";

        String rawVer = Utils.getAppVersion(this);
        String formattedVer = rawVer.startsWith("v") ? rawVer : ("v" + rawVer);

        // Header Pills
        TextView appVersion = findViewById(R.id.app_version);
        if (appVersion != null) {
            appVersion.setText(formattedVer);
            appVersion.setOnClickListener(v -> showBuildInfoDialog());
        }

        TextView headerFlavor = findViewById(R.id.header_build_flavor);
        if (headerFlavor != null) {
            headerFlavor.setText(buildType.substring(0, 1).toUpperCase() + buildType.substring(1));
            headerFlavor.setOnClickListener(v -> showBuildInfoDialog());
        }

        TextView headerAbi = findViewById(R.id.header_device_abi);
        if (headerAbi != null) {
            headerAbi.setText(primaryAbi);
            headerAbi.setOnClickListener(v -> showBuildInfoDialog());
        }

        View headerBadgesRow = findViewById(R.id.header_badges_row);
        if (headerBadgesRow != null) {
            headerBadgesRow.setOnClickListener(v -> showBuildInfoDialog());
        }
    }

    private void showBuildInfoDialog() {
        BuildInfoDialog.newInstance().show(getSupportFragmentManager(), BuildInfoDialog.TAG);
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.about_menu, menu);
    }

    @Override
    public boolean onMenuItemSelected(MenuItem item) {
        int id = item.getItemId();

        if(id == android.R.id.home) {
            finish();
            return true;
        } else if(id == R.id.on_boarding) {
            Intent intent = new Intent(this, OnBoardingActivity.class);
            intent.putExtra(OnBoardingActivity.ENABLE_BACK_BUTTON, true);
            startActivity(intent);
            return true;
        } else if(id == R.id.build_info) {
            showBuildInfoDialog();
            return true;
        }

        return false;
    }
}
