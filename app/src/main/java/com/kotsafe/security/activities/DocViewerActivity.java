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

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.ProgressBar;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.view.MenuProvider;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.google.android.material.appbar.MaterialToolbar;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class DocViewerActivity extends BaseActivity implements MenuProvider {
    private static final String TAG = "DocViewerActivity";

    public static final String EXTRA_DOC_TYPE = "extra_doc_type";
    public static final String DOC_DOH_DNSCRYPT = "doh_dnscrypt";
    public static final String DOC_WIRESHARK_EXTENSIONS = "wireshark_extensions";

    private static final String GITHUB_DOH_URL = "https://github.com/CyberResercher/Kotsafe/blob/main/docs/doh_dnscrypt_guide.md";
    private static final String GITHUB_WIRESHARK_URL = "https://github.com/CyberResercher/Kotsafe/blob/main/docs/wireshark_dump_extensions.md";

    private String mDocType;
    private String mDocContent = "";
    private WebView mWebView;
    private ProgressBar mProgressBar;

    public static void start(@NonNull Context context, @NonNull String docType) {
        Intent intent = new Intent(context, DocViewerActivity.class);
        intent.putExtra(EXTRA_DOC_TYPE, docType);
        context.startActivity(intent);
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_doc_viewer);
        addMenuProvider(this);

        mDocType = getIntent().getStringExtra(EXTRA_DOC_TYPE);
        if (mDocType == null) {
            mDocType = DOC_DOH_DNSCRYPT;
        }

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setDisplayShowHomeEnabled(true);
            if (DOC_WIRESHARK_EXTENSIONS.equals(mDocType)) {
                getSupportActionBar().setTitle(R.string.dump_extensions_how_to);
            } else {
                getSupportActionBar().setTitle(R.string.dnscrypt_how_to);
            }
        }

        mWebView = findViewById(R.id.doc_webview);
        mProgressBar = findViewById(R.id.doc_loading_progress);

        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(mWebView, (v, windowInsets) -> {
            androidx.core.graphics.Insets insets = windowInsets.getInsets(
                    androidx.core.view.WindowInsetsCompat.Type.systemBars() |
                    androidx.core.view.WindowInsetsCompat.Type.displayCutout());
            v.setPadding(0, 0, 0, insets.bottom);
            return windowInsets;
        });

        loadDocContent();
        setupWebView();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        mDocType = intent.getStringExtra(EXTRA_DOC_TYPE);
        if (mDocType == null) {
            mDocType = DOC_DOH_DNSCRYPT;
        }
        if (getSupportActionBar() != null) {
            if (DOC_WIRESHARK_EXTENSIONS.equals(mDocType)) {
                getSupportActionBar().setTitle(R.string.dump_extensions_how_to);
            } else {
                getSupportActionBar().setTitle(R.string.dnscrypt_how_to);
            }
        }
        if (mProgressBar != null && mWebView != null) {
            mProgressBar.setVisibility(View.VISIBLE);
            mWebView.setVisibility(View.INVISIBLE);
            loadDocContent();
            mWebView.loadUrl("file:///android_asset/docs/doc_viewer.html");
        }
    }

    private void loadDocContent() {
        String assetPath;
        if (DOC_WIRESHARK_EXTENSIONS.equals(mDocType)) {
            assetPath = "docs/wireshark_dump_extensions.md";
        } else {
            assetPath = "docs/doh_dnscrypt_guide.md";
        }

        StringBuilder sb = new StringBuilder();
        try (InputStream is = getAssets().open(assetPath);
             BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            mDocContent = sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Failed to load document asset: " + assetPath + " -> " + e.getMessage());
            mDocContent = "# Error\nUnable to load documentation guide: " + e.getMessage();
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private void setupWebView() {
        WebSettings settings = mWebView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(true);
        settings.setCacheMode(WebSettings.LOAD_DEFAULT);

        mWebView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri url = request.getUrl();
                if (url != null && url.getScheme() != null &&
                        (url.getScheme().equalsIgnoreCase("http") || url.getScheme().equalsIgnoreCase("https"))) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, url));
                    } catch (Exception e) {
                        Toast.makeText(DocViewerActivity.this, "Cannot open link: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                    return true;
                }
                return false;
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                boolean isDark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
                String base64Md = Base64.encodeToString(mDocContent.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);

                String js = "setTheme(" + isDark + "); renderMarkdown(decodeURIComponent(escape(window.atob('" + base64Md + "'))));";
                mWebView.evaluateJavascript(js, result -> {
                    mProgressBar.setVisibility(View.GONE);
                    mWebView.setVisibility(View.VISIBLE);
                });
            }
        });

        mWebView.loadUrl("file:///android_asset/docs/doc_viewer.html");
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, @NonNull MenuInflater menuInflater) {
        menu.add(Menu.NONE, 1, Menu.NONE, R.string.share)
                .setIcon(R.drawable.ic_share)
                .setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM);

        menu.add(Menu.NONE, 2, Menu.NONE, "View on GitHub")
                .setIcon(R.drawable.ic_external)
                .setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem menuItem) {
        int id = menuItem.getItemId();
        if (id == android.R.id.home) {
            finish();
            return true;
        } else if (id == 1) { // Share
            shareDocumentation();
            return true;
        } else if (id == 2) { // View on GitHub
            openGitHubUrl();
            return true;
        }
        return false;
    }

    private void shareDocumentation() {
        Intent sendIntent = new Intent(Intent.ACTION_SEND);
        sendIntent.setType("text/plain");
        String title = DOC_WIRESHARK_EXTENSIONS.equals(mDocType)
                ? getString(R.string.dump_extensions_how_to)
                : getString(R.string.dnscrypt_how_to);
        sendIntent.putExtra(Intent.EXTRA_SUBJECT, title);
        sendIntent.putExtra(Intent.EXTRA_TEXT, title + "\n\n" + mDocContent);
        startActivity(Intent.createChooser(sendIntent, getString(R.string.share)));
    }

    private void openGitHubUrl() {
        String url = DOC_WIRESHARK_EXTENSIONS.equals(mDocType) ? GITHUB_WIRESHARK_URL : GITHUB_DOH_URL;
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            Toast.makeText(this, "Cannot open browser: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    protected void onDestroy() {
        if (mWebView != null) {
            mWebView.destroy();
        }
        super.onDestroy();
    }
}
