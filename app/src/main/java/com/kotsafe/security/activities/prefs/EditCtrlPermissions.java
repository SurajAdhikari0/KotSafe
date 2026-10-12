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
 * Copyright 2026 - KotSafe Team
 */

package com.kotsafe.security.activities.prefs;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.MenuProvider;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.KotSafe;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.BaseActivity;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.adapters.CtrlPermissionsAdapter;
import com.kotsafe.security.dialogs.AppPickerDialog;
import com.kotsafe.security.dialogs.CtrlPermCodeDialog;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.CtrlPermissions;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.chip.Chip;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.security.SecureRandom;

public class EditCtrlPermissions extends BaseActivity implements MenuProvider, CtrlPermissionsAdapter.RuleActionListener {
    private static final String TAG = "EditCtrlPermissions";

    private View mEmptyContainer;
    private CtrlPermissionsAdapter mAdapter;
    private ListView mListView;
    private CtrlPermissions mPermissions;
    private TextView mTvApiKey;
    private ImageView mBtnToggleKeyVisibility;
    private Chip mChipApiStatus;
    private TextView mTvRulesCount;
    private boolean mIsKeyMasked = true;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ctrl_permissions);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setDisplayShowHomeEnabled(true);
            getSupportActionBar().setTitle(R.string.control_permissions);
        }
        addMenuProvider(this);

        mEmptyContainer = findViewById(R.id.list_empty_container);
        mListView = findViewById(R.id.listview);
        mTvApiKey = findViewById(R.id.tv_api_key);
        mBtnToggleKeyVisibility = findViewById(R.id.btn_toggle_key_visibility);
        mChipApiStatus = findViewById(R.id.chip_api_status);
        mTvRulesCount = findViewById(R.id.tv_rules_count);

        mPermissions = KotSafe.getInstance().getCtrlPermissions();
        mAdapter = new CtrlPermissionsAdapter(this, mPermissions, this);
        mListView.setAdapter(mAdapter);

        // Ensure key exists
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        if (Prefs.getApiKey(prefs).isEmpty()) {
            createNewApiKey(false);
        }
        updateApiKeyViews();

        mBtnToggleKeyVisibility.setOnClickListener(v -> {
            mIsKeyMasked = !mIsKeyMasked;
            updateApiKeyViews();
        });

        findViewById(R.id.btn_copy_key).setOnClickListener(v -> {
            String key = Prefs.getApiKey(PreferenceManager.getDefaultSharedPreferences(this));
            if (!key.isEmpty()) {
                Utils.copyToClipboard(this, key);
            }
        });

        findViewById(R.id.btn_refresh_key).setOnClickListener(v -> confirmRotateKey());

        findViewById(R.id.btn_add_app_rule).setOnClickListener(v -> openAppPicker());
        findViewById(R.id.btn_empty_add).setOnClickListener(v -> openAppPicker());

        findViewById(R.id.btn_automation_helper).setOnClickListener(v -> {
            String key = Prefs.getApiKey(PreferenceManager.getDefaultSharedPreferences(this));
            CtrlPermCodeDialog.newInstance(key).show(getSupportFragmentManager(), CtrlPermCodeDialog.TAG);
        });

        Utils.fixListviewInsetsBottom(mListView);
        recheckListSize();
    }

    private void updateApiKeyViews() {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        String key = Prefs.getApiKey(prefs);

        if (key.isEmpty()) {
            mTvApiKey.setText("No API Key generated");
            mChipApiStatus.setText("Inactive");
            mBtnToggleKeyVisibility.setImageResource(R.drawable.ic_lock);
            return;
        }

        mChipApiStatus.setText("Active");
        if (mIsKeyMasked) {
            mTvApiKey.setText("••••••••••••••••••••••••••••••••");
            mBtnToggleKeyVisibility.setImageResource(R.drawable.ic_lock);
        } else {
            mTvApiKey.setText(key);
            mBtnToggleKeyVisibility.setImageResource(R.drawable.ic_lock_open);
        }
    }

    private void openAppPicker() {
        AppPickerDialog.newInstance()
                .setOnAppSelectedListener(this::promptRuleConsent)
                .show(getSupportFragmentManager(), AppPickerDialog.TAG);
    }

    private void promptRuleConsent(@NonNull AppDescriptor app) {
        String[] options = new String[]{
                getString(R.string.allow) + " - Full automation capture access",
                getString(R.string.deny) + " - Block automation capture access"
        };

        new MaterialAlertDialogBuilder(this)
                .setTitle("Permission for " + app.getName())
                .setIcon(app.getIcon())
                .setItems(options, (dialog, which) -> {
                    CtrlPermissions.ConsentType consent = (which == 0)
                            ? CtrlPermissions.ConsentType.ALLOW
                            : CtrlPermissions.ConsentType.DENY;

                    mPermissions.add(app.getPackageName(), consent);
                    mAdapter.reload();
                    recheckListSize();
                    Toast.makeText(this, "Rule added for " + app.getName(), Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(R.string.cancel_action, (d, w) -> d.dismiss())
                .show();
    }

    @Override
    public void onToggleConsent(CtrlPermissions.Rule rule) {
        CtrlPermissions.ConsentType newConsent = (rule.consent == CtrlPermissions.ConsentType.ALLOW)
                ? CtrlPermissions.ConsentType.DENY
                : CtrlPermissions.ConsentType.ALLOW;
        mPermissions.add(rule.package_name, newConsent);
        mAdapter.reload();
    }

    @Override
    public void onDeleteRule(CtrlPermissions.Rule rule) {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.delete)
                .setMessage("Remove permission rule for " + rule.package_name + "?")
                .setPositiveButton(R.string.delete, (d, w) -> {
                    mPermissions.remove(rule.package_name);
                    mAdapter.reload();
                    recheckListSize();
                })
                .setNegativeButton(R.string.cancel_action, (d, w) -> d.dismiss())
                .show();
    }

    private void recheckListSize() {
        int count = mAdapter.getCount();
        mEmptyContainer.setVisibility(count == 0 ? View.VISIBLE : View.GONE);
        mListView.setVisibility(count == 0 ? View.GONE : View.VISIBLE);
        mTvRulesCount.setText(getString(R.string.n_selected, count).replace("selected", "configured rules"));
    }

    private void confirmRotateKey() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.warning)
                .setMessage(R.string.api_key_discard_confirm)
                .setPositiveButton(R.string.ok, (dialog, which) -> createNewApiKey(true))
                .setNegativeButton(R.string.cancel_action, (dialog, which) -> dialog.dismiss())
                .show();
    }

    private void createNewApiKey(boolean notifyUser) {
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        final int keyLength = 32;
        SecureRandom random = new SecureRandom();
        StringBuilder apiKey = new StringBuilder(keyLength);
        for (int i = 0; i < keyLength; i++) {
            int index = random.nextInt(chars.length());
            apiKey.append(chars.charAt(index));
        }

        prefs.edit()
                .putString(Prefs.PREF_API_KEY, apiKey.toString())
                .apply();

        mIsKeyMasked = false; // Show newly generated key
        updateApiKeyViews();
        if (notifyUser) {
            Toast.makeText(this, "New API key generated", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, @NonNull MenuInflater inflater) {
        inflater.inflate(R.menu.ctrl_permissions_menu, menu);
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();

        if (id == android.R.id.home) {
            finish();
            return true;
        } else if (id == R.id.user_guide) {
            Intent browserIntent = new Intent(Intent.ACTION_VIEW, Uri.parse(MainActivity.API_DOCS_URL));
            Utils.startActivity(this, browserIntent);
            return true;
        } else if (id == R.id.generate_api_key) {
            confirmRotateKey();
            return true;
        } else if (id == R.id.show_api_key) {
            mIsKeyMasked = false;
            updateApiKeyViews();
            return true;
        }

        return false;
    }
}
