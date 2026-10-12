/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.kotsafe.security.R;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.views.AppSelectDialog;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputLayout;

/**
 * Manual Block / Whitelist entry screen.
 *
 * Lets the user manually block or whitelist:
 *   - IP address
 *   - Domain
 *   - URL
 *   - SHA-256 hash
 *   - App (package name)
 */
public class ManualBlockActivity extends AppCompatActivity {
    private static final String TAG = "ManualBlockActivity";

    public static final String EXTRA_VALUE = "prefill_value";
    public static final String EXTRA_TYPE = "prefill_type";
    public static final String EXTRA_ACTION = "prefill_action";

    private EditText etValue, etReason;
    private Spinner spinnerType, spinnerAction;
    private TextInputLayout tilValue;
    private MaterialButton btnPickApp;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_manual_block);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (getSupportActionBar() == null && toolbar != null) {
            setSupportActionBar(toolbar);
        }
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Add Security Rule");
        }

        etValue   = findViewById(R.id.et_block_value);
        etReason  = findViewById(R.id.et_block_reason);
        tilValue  = findViewById(R.id.til_block_value);
        btnPickApp = findViewById(R.id.btn_pick_app);
        spinnerType   = findViewById(R.id.spinner_ioc_type);
        spinnerAction = findViewById(R.id.spinner_action);

        // Type options
        ArrayAdapter<String> typeAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item,
                new String[]{"IP", "DOMAIN", "URL", "HASH", "APP"});
        typeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerType.setAdapter(typeAdapter);

        spinnerType.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                String type = (String) spinnerType.getSelectedItem();
                boolean isApp = "APP".equalsIgnoreCase(type);
                btnPickApp.setVisibility(isApp ? View.VISIBLE : View.GONE);
                if (isApp) {
                    tilValue.setHint("App Package (e.g. com.example.app)");
                } else if ("DOMAIN".equalsIgnoreCase(type)) {
                    tilValue.setHint("Domain Name (e.g. tracking.adservice.com)");
                } else if ("IP".equalsIgnoreCase(type)) {
                    tilValue.setHint("IP Address (e.g. 198.51.100.14)");
                } else if ("HASH".equalsIgnoreCase(type)) {
                    tilValue.setHint("SHA-256 Hash");
                } else {
                    tilValue.setHint("IP / Domain / URL / Hash / Package");
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        btnPickApp.setOnClickListener(v -> {
            new AppSelectDialog(this, R.string.app, new AppSelectDialog.AppSelectListener() {
                @Override
                public void onSelectedApp(AppDescriptor app) {
                    etValue.setText(app.getPackageName());
                    if (etReason.getText().toString().isEmpty()) {
                        etReason.setText(app.getName());
                    }
                }

                @Override
                public void onAppSelectionAborted() {}
            });
        });

        // Action options
        ArrayAdapter<String> actionAdapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item,
                new String[]{"BLOCK", "ALLOW (whitelist)"});
        actionAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerAction.setAdapter(actionAdapter);

        // Pre-fill from intent (e.g. from Evidence Details)
        String prefill = getIntent().getStringExtra(EXTRA_VALUE);
        String prefillType = getIntent().getStringExtra(EXTRA_TYPE);
        String prefillAction = getIntent().getStringExtra(EXTRA_ACTION);
        if (prefill != null) etValue.setText(prefill);
        if (prefillType != null) {
            for (int i = 0; i < typeAdapter.getCount(); i++) {
                if (prefillType.equalsIgnoreCase(typeAdapter.getItem(i))) {
                    spinnerType.setSelection(i);
                    break;
                }
            }
        }
        if (prefillAction != null) {
            if (SecurityRulesDb.ACTION_ALLOW.equalsIgnoreCase(prefillAction)) {
                spinnerAction.setSelection(1);
            } else {
                spinnerAction.setSelection(0);
            }
        }

        Button btnSave = findViewById(R.id.btn_save_rule);
        btnSave.setOnClickListener(v -> saveRule());
    }

    private void saveRule() {
        String value = etValue.getText().toString().trim();
        String reason = etReason.getText().toString().trim();

        if (value.isEmpty()) {
            etValue.setError("Required");
            return;
        }

        String type = (String) spinnerType.getSelectedItem();
        boolean isBlock = spinnerAction.getSelectedItemPosition() == 0;
        String source = SecurityRulesDb.SOURCE_USER;

        // Smart input normalization
        if ("DOMAIN".equalsIgnoreCase(type)) {
            String host = SecurityBlocklistManager.extractHost(value);
            if (host != null && !host.isEmpty()) {
                value = host;
            }
        } else if ("HASH".equalsIgnoreCase(type)) {
            value = value.toLowerCase().replaceAll("[^a-f0-9]", "");
            if (value.length() != 32 && value.length() != 40 && value.length() != 64) {
                etValue.setError("Enter a valid MD5 (32), SHA-1 (40), or SHA-256 (64) hex hash");
                return;
            }
        } else if ("URL".equalsIgnoreCase(type)) {
            if (!value.startsWith("http://") && !value.startsWith("https://")) {
                value = "http://" + value;
            }
        }

        final String finalVal = value;
        SecurityBlocklistManager mgr = SecurityBlocklistManager.getInstance(this);

        if (isBlock && (mgr.isSystemWhitelisted(finalVal) || SecurityBlocklistManager.isOfficialOrTrustedDomain(finalVal) || SecurityBlocklistManager.isCloudflareCdnIp(finalVal))) {
            new androidx.appcompat.app.AlertDialog.Builder(this)
                    .setTitle("Protected Non-Malicious Resource")
                    .setMessage("This site or component (" + finalVal + ") is verified as non-malicious or essential system infrastructure.\n\nKotSafe protects non-malicious sites and critical services from blocking to preserve device functionality and connectivity.")
                    .setPositiveButton("OK", null)
                    .show();
            return;
        }

        applyRule(mgr, type, finalVal, reason, source, isBlock);
    }

    private void applyRule(SecurityBlocklistManager mgr, String type, String value, String reason, String source, boolean isBlock) {
        if (isBlock) {
            switch (type) {
                case "IP":     mgr.blockIp(value, reason, source); break;
                case "DOMAIN": mgr.blockDomain(value, reason, source); break;
                case "URL":    mgr.blockUrl(value, reason, source); break;
                case "HASH":   mgr.blockHash(value, reason, source); break;
                case "APP":    mgr.blockApp(value, reason, source); break;
            }
            if (!com.kotsafe.security.model.VpnAlertHelper.isVpnActive()) {
                Toast.makeText(this, "✓ Block rule saved. Turn on VPN in Home screen to enforce packet blocking.", Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(this, "✓ Block rule added for " + value, Toast.LENGTH_SHORT).show();
            }
        } else {
            mgr.whitelist(type, value, SecurityRulesDb.SCOPE_EXACT, reason);
            Toast.makeText(this, "✓ Whitelisted: " + value, Toast.LENGTH_SHORT).show();
        }

        finish();
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        return super.onOptionsItemSelected(item);
    }
}
