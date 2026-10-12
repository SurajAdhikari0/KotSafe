/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.model.SecurityBlocklistManager;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.model.SecurityRulesDb.SecurityRule;
import com.kotsafe.security.model.VpnAlertHelper;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.chip.Chip;
import com.google.android.material.chip.ChipGroup;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Action Center — central security console for viewing, searching, and managing
 * active firewall enforcement, whitelist rules, threat intelligence blocks, and app quarantines.
 */
public class SecurityActionsActivity extends AppCompatActivity {
    private static final String TAG = "SecurityActionsActivity";

    private SecurityBlocklistManager mBlocklist;
    private RulesAdapter mAdapter;
    private final List<SecurityRule> mRules = new ArrayList<>();
    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private String mCurrentFilter = "ALL";
    private String mSearchQuery = "";

    // Stats Views
    private TextView mTvCountBlocked, mTvCountAllowed, mTvCountHits, mTvCountTotal;
    private EditText mEtSearch;
    private ImageButton mBtnClearSearch;
    private View mEmptyLayout;
    private TextView mTvEmptyTitle, mTvEmptySubtitle;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_security_actions);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (getSupportActionBar() == null && toolbar != null) {
            setSupportActionBar(toolbar);
        }
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Action Center");
            getSupportActionBar().setSubtitle("Active Firewall & Security Rules");
        }

        mBlocklist = SecurityBlocklistManager.getInstance(this);

        // Stats views
        mTvCountBlocked = findViewById(R.id.count_blocked);
        mTvCountAllowed = findViewById(R.id.count_allowed);
        mTvCountHits    = findViewById(R.id.count_hits);
        mTvCountTotal   = findViewById(R.id.count_total);

        // Search bar
        mEtSearch = findViewById(R.id.et_rule_search);
        mBtnClearSearch = findViewById(R.id.btn_clear_search);
        mEmptyLayout = findViewById(R.id.layout_rules_empty);
        mTvEmptyTitle = findViewById(R.id.tv_empty_title);
        mTvEmptySubtitle = findViewById(R.id.tv_empty_subtitle);

        mEtSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                mSearchQuery = s.toString().trim();
                mBtnClearSearch.setVisibility(mSearchQuery.isEmpty() ? View.GONE : View.VISIBLE);
                loadRules();
            }
            @Override
            public void afterTextChanged(Editable s) {}
        });

        mBtnClearSearch.setOnClickListener(v -> mEtSearch.setText(""));

        // Empty state buttons
        MaterialButton btnEmptyAdd = findViewById(R.id.btn_empty_add_rule);
        if (btnEmptyAdd != null) {
            btnEmptyAdd.setOnClickListener(v ->
                    startActivity(new Intent(this, ManualBlockActivity.class)));
        }
        MaterialButton btnEmptyPresets = findViewById(R.id.btn_empty_presets);
        if (btnEmptyPresets != null) {
            btnEmptyPresets.setOnClickListener(v -> showPresetsDialog());
        }

        // RecyclerView
        RecyclerView rv = findViewById(R.id.rv_rules);
        rv.setLayoutManager(new LinearLayoutManager(this));
        mAdapter = new RulesAdapter(mRules);
        rv.setAdapter(mAdapter);

        // Filter chips
        ChipGroup chipGroup = findViewById(R.id.chip_group_filter);
        chipGroup.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;
            Chip chip = group.findViewById(checkedIds.get(0));
            if (chip != null) {
                String text = chip.getText().toString();
                if (text.contains("BLOCK")) mCurrentFilter = "BLOCK";
                else if (text.contains("ALLOW")) mCurrentFilter = "ALLOW";
                else if (text.contains("THREAT") || text.contains("TI")) mCurrentFilter = "TI";
                else if (text.contains("APPS")) mCurrentFilter = "APPS";
                else if (text.contains("DOMAINS")) mCurrentFilter = "DOMAINS";
                else mCurrentFilter = "ALL";
                loadRules();
            }
        });

        // FAB -> add new rule
        FloatingActionButton fab = findViewById(R.id.fab_add_rule);
        fab.setOnClickListener(v ->
                startActivity(new Intent(this, ManualBlockActivity.class)));

        loadRules();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateVpnBanner();
        loadRules();
    }

    private void updateVpnBanner() {
        View banner = findViewById(R.id.card_vpn_inactive_banner);
        if (banner != null) {
            boolean isVpnOn = VpnAlertHelper.isVpnActive();
            banner.setVisibility(isVpnOn ? View.GONE : View.VISIBLE);
            View btnStart = findViewById(R.id.btn_actions_start_vpn);
            if (btnStart != null) {
                btnStart.setOnClickListener(v -> VpnAlertHelper.openHomeToStartVpn(this));
            }
        }
    }

    private void loadRules() {
        mExecutor.execute(() -> {
            List<SecurityRule> allRules = mBlocklist.getAllRules();
            int blockedCount = 0;
            int allowedCount = 0;
            int totalHits = 0;

            for (SecurityRule r : allRules) {
                if (r.isBlock() || r.isQuarantine()) blockedCount++;
                else if (r.isAllow()) allowedCount++;
                totalHits += r.hitCount;
            }

            // Filter rules
            List<SecurityRule> filtered;
            if (!mSearchQuery.isEmpty()) {
                filtered = mBlocklist.searchRules(mSearchQuery);
            } else {
                switch (mCurrentFilter) {
                    case "BLOCK":
                        filtered = mBlocklist.getAllBlockRules();
                        break;
                    case "ALLOW":
                        filtered = mBlocklist.getAllWhitelistRules();
                        break;
                    case "TI":
                        filtered = mBlocklist.getRulesBySource(SecurityRulesDb.SOURCE_TI);
                        break;
                    case "APPS":
                        filtered = mBlocklist.getRulesByType(SecurityRulesDb.TYPE_APP);
                        break;
                    case "DOMAINS":
                        filtered = new ArrayList<>();
                        for (SecurityRule r : allRules) {
                            if (SecurityRulesDb.TYPE_DOMAIN.equals(r.type) ||
                                SecurityRulesDb.TYPE_IP.equals(r.type) ||
                                SecurityRulesDb.TYPE_URL.equals(r.type)) {
                                filtered.add(r);
                            }
                        }
                        break;
                    default:
                        filtered = allRules;
                        break;
                }
            }

            final List<SecurityRule> finalRules = filtered;
            final int finalBlocked = blockedCount;
            final int finalAllowed = allowedCount;
            final int finalHits = totalHits;
            final int finalTotal = allRules.size();

            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;

                // Update Stats
                mTvCountBlocked.setText(String.valueOf(finalBlocked));
                mTvCountAllowed.setText(String.valueOf(finalAllowed));
                mTvCountHits.setText(String.valueOf(finalHits));
                mTvCountTotal.setText(String.valueOf(finalTotal));

                // Update Rules List
                mRules.clear();
                mRules.addAll(finalRules);
                mAdapter.notifyDataSetChanged();

                if (mEmptyLayout != null) {
                    if (mRules.isEmpty()) {
                        mEmptyLayout.setVisibility(View.VISIBLE);
                        if (!mSearchQuery.isEmpty()) {
                            mTvEmptyTitle.setText("No Matching Rules");
                            mTvEmptySubtitle.setText("No rules found matching \"" + mSearchQuery + "\".");
                        } else if (!"ALL".equals(mCurrentFilter)) {
                            mTvEmptyTitle.setText("No " + mCurrentFilter + " Rules");
                            mTvEmptySubtitle.setText("No rules active under this category.");
                        } else {
                            mTvEmptyTitle.setText("No Security Rules Active");
                            mTvEmptySubtitle.setText("Add custom block or allow rules, or apply security presets to protect your network against trackers and malware.");
                        }
                    } else {
                        mEmptyLayout.setVisibility(View.GONE);
                    }
                }
            });
        });
    }

    private void showPresetsDialog() {
        String[] options = new String[]{
                "🛡️ Anti-Tracking & Ad Networks (Block 9 major ad/analytics domains)",
                "🔒 Anti-DoH/DoT DNS Bypass (Block public resolvers to enforce local firewall)",
                "⚠️ Suspicious Dynamic DNS & Tunnels (Block duckdns, ngrok, no-ip)"
        };

        new AlertDialog.Builder(this)
                .setTitle("Apply Security Presets")
                .setItems(options, (d, which) -> {
                    String presetKey;
                    if (which == 0) presetKey = "ADS_TRACKING";
                    else if (which == 1) presetKey = "DOH_BYPASS";
                    else presetKey = "DYNAMIC_DNS";

                    mExecutor.execute(() -> {
                        int added = mBlocklist.applyPreset(presetKey);
                        runOnUiThread(() -> {
                            Toast.makeText(this, "✓ " + added + " rules added from preset", Toast.LENGTH_SHORT).show();
                            loadRules();
                        });
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showClearAllDialog() {
        new AlertDialog.Builder(this)
                .setTitle("Clear All Rules?")
                .setMessage("Are you sure you want to remove all custom security, block, and whitelist rules? This action cannot be undone.")
                .setIcon(android.R.drawable.ic_dialog_alert)
                .setPositiveButton("Clear All", (d, w) -> {
                    mExecutor.execute(() -> {
                        mBlocklist.clearAllRules();
                        runOnUiThread(() -> {
                            Toast.makeText(this, "All rules cleared", Toast.LENGTH_SHORT).show();
                            loadRules();
                        });
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.security_actions_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();
        if (id == android.R.id.home) {
            finish();
            return true;
        } else if (id == R.id.action_presets) {
            showPresetsDialog();
            return true;
        } else if (id == R.id.action_add_rule) {
            startActivity(new Intent(this, ManualBlockActivity.class));
            return true;
        } else if (id == R.id.action_clear_rules) {
            showClearAllDialog();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mExecutor.shutdownNow();
    }

    // ─── Adapter ──────────────────────────────────────────────────────────────

    private class RulesAdapter extends RecyclerView.Adapter<RulesAdapter.VH> {
        private final List<SecurityRule> mList;
        private final SimpleDateFormat mSdf =
                new SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault());
        private final PackageManager mPm = getPackageManager();

        RulesAdapter(List<SecurityRule> list) {
            mList = list;
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext())
                    .inflate(R.layout.item_security_rule, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int position) {
            SecurityRule rule = mList.get(position);

            // Action Badge styling
            if (rule.isBlock()) {
                h.tvAction.setText("🛑 BLOCK");
                h.tvAction.setTextColor(Color.parseColor("#EF4444"));
                h.tvAction.setBackgroundColor(Color.parseColor("#25EF4444"));
            } else if (rule.isAllow()) {
                h.tvAction.setText("✅ ALLOW");
                h.tvAction.setTextColor(Color.parseColor("#10B981"));
                h.tvAction.setBackgroundColor(Color.parseColor("#2510B981"));
            } else {
                h.tvAction.setText("⚠️ " + rule.action);
                h.tvAction.setTextColor(Color.parseColor("#F59E0B"));
                h.tvAction.setBackgroundColor(Color.parseColor("#25F59E0B"));
            }

            h.tvType.setText(rule.type);
            h.tvSource.setText(rule.source);

            // Resolve App icon & label if type is APP
            if (SecurityRulesDb.TYPE_APP.equalsIgnoreCase(rule.type)) {
                try {
                    ApplicationInfo appInfo = mPm.getApplicationInfo(rule.value, 0);
                    CharSequence appName = mPm.getApplicationLabel(appInfo);
                    Drawable icon = mPm.getApplicationIcon(appInfo);
                    h.tvValue.setText(appName);
                    h.tvSubtitle.setText(rule.value);
                    h.tvSubtitle.setVisibility(View.VISIBLE);
                    h.ivIcon.setImageDrawable(icon);
                    h.ivIcon.setImageTintList(null);
                } catch (Exception e) {
                    h.tvValue.setText(rule.value);
                    h.tvSubtitle.setVisibility(View.GONE);
                    h.ivIcon.setImageResource(R.drawable.ic_apps);
                    h.ivIcon.setColorFilter(ContextCompat.getColor(SecurityActionsActivity.this, R.color.colorPrimary));
                }
            } else {
                h.tvValue.setText(rule.value);
                h.tvSubtitle.setVisibility(View.GONE);
                if (SecurityRulesDb.TYPE_DOMAIN.equalsIgnoreCase(rule.type)) {
                    h.ivIcon.setImageResource(R.drawable.ic_language);
                } else if (SecurityRulesDb.TYPE_IP.equalsIgnoreCase(rule.type)) {
                    h.ivIcon.setImageResource(R.drawable.ic_lan);
                } else if (SecurityRulesDb.TYPE_HASH.equalsIgnoreCase(rule.type)) {
                    h.ivIcon.setImageResource(R.drawable.ic_bug);
                } else {
                    h.ivIcon.setImageResource(R.drawable.ic_shield);
                }
                h.ivIcon.setColorFilter(ContextCompat.getColor(SecurityActionsActivity.this, R.color.colorPrimary));
            }

            // Reason & Date
            if (rule.reason != null && !rule.reason.isEmpty()) {
                h.tvReason.setText(rule.reason);
                h.tvReason.setVisibility(View.VISIBLE);
            } else {
                h.tvReason.setVisibility(View.GONE);
            }

            h.tvDate.setText(mSdf.format(new Date(rule.createdAt)));
            h.tvHits.setText("⚡ " + rule.hitCount + " hits");

            // Switch toggle
            h.switchEnabled.setOnCheckedChangeListener(null);
            h.switchEnabled.setChecked(rule.enabled);
            h.itemView.setAlpha(rule.enabled ? 1.0f : 0.45f);

            h.switchEnabled.setOnCheckedChangeListener((btn, isChecked) -> {
                rule.enabled = isChecked;
                mBlocklist.setRuleEnabled(rule.id, isChecked);
                h.itemView.setAlpha(isChecked ? 1.0f : 0.45f);
            });

            // Card click -> Rule Details Inspection
            h.itemView.setOnClickListener(v -> showRuleDetail(rule));

            // Delete button -> Confirmation Dialog
            h.btnDelete.setOnClickListener(v -> showDeleteRuleDialog(rule));
        }

        private void showRuleDetail(SecurityRule rule) {
            String details = "Value: " + rule.value +
                    "\nAction: " + rule.action +
                    "\nType: " + rule.type +
                    "\nSource: " + rule.source +
                    "\nScope: " + rule.scope +
                    "\nInterception Hits: " + rule.hitCount +
                    "\nStatus: " + (rule.enabled ? "Active" : "Disabled") +
                    "\nCreated: " + mSdf.format(new Date(rule.createdAt)) +
                    (rule.reason != null ? "\nReason: " + rule.reason : "");

            AlertDialog.Builder b = new AlertDialog.Builder(SecurityActionsActivity.this)
                    .setTitle("Rule Details")
                    .setMessage(details)
                    .setPositiveButton("Close", null)
                    .setNeutralButton("Copy Value", (d, w) -> {
                        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                        if (cm != null) {
                            cm.setPrimaryClip(ClipData.newPlainText("IOC", rule.value));
                            Toast.makeText(SecurityActionsActivity.this, "Copied to clipboard", Toast.LENGTH_SHORT).show();
                        }
                    });

            if (rule.isBlock()) {
                b.setNegativeButton("Switch to Whitelist", (d, w) -> {
                    mBlocklist.removeRule(rule.id);
                    mBlocklist.whitelist(rule.type, rule.value, SecurityRulesDb.SCOPE_EXACT, "User converted to allow");
                    loadRules();
                    Toast.makeText(SecurityActionsActivity.this, "Rule switched to Whitelist", Toast.LENGTH_SHORT).show();
                });
            } else if (rule.isAllow()) {
                b.setNegativeButton("Switch to Block", (d, w) -> {
                    mBlocklist.removeRule(rule.id);
                    if (SecurityRulesDb.TYPE_APP.equals(rule.type)) {
                        mBlocklist.blockApp(rule.value, "User converted to block", SecurityRulesDb.SOURCE_USER);
                    } else if (SecurityRulesDb.TYPE_IP.equals(rule.type)) {
                        mBlocklist.blockIp(rule.value, "User converted to block", SecurityRulesDb.SOURCE_USER);
                    } else {
                        mBlocklist.blockDomain(rule.value, "User converted to block", SecurityRulesDb.SOURCE_USER);
                    }
                    loadRules();
                    Toast.makeText(SecurityActionsActivity.this, "Rule switched to Block", Toast.LENGTH_SHORT).show();
                });
            }
            b.show();
        }

        private void showDeleteRuleDialog(SecurityRule rule) {
            new AlertDialog.Builder(SecurityActionsActivity.this)
                    .setTitle("Remove Rule")
                    .setMessage("Remove " + rule.action + " rule for " + rule.value + "?")
                    .setPositiveButton("Remove", (d, w) -> {
                        mBlocklist.removeRule(rule.id);
                        loadRules();
                        Toast.makeText(SecurityActionsActivity.this, "Rule removed", Toast.LENGTH_SHORT).show();
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        }

        @Override
        public int getItemCount() {
            return mList.size();
        }

        class VH extends RecyclerView.ViewHolder {
            ImageView ivIcon;
            TextView tvAction, tvType, tvSource, tvValue, tvSubtitle, tvReason, tvDate, tvHits;
            SwitchCompat switchEnabled;
            ImageButton btnDelete;

            VH(View v) {
                super(v);
                ivIcon        = v.findViewById(R.id.iv_rule_icon);
                tvAction      = v.findViewById(R.id.tv_rule_action);
                tvType        = v.findViewById(R.id.tv_rule_type);
                tvSource      = v.findViewById(R.id.tv_rule_source);
                tvValue       = v.findViewById(R.id.tv_rule_value);
                tvSubtitle    = v.findViewById(R.id.tv_rule_subtitle);
                tvReason      = v.findViewById(R.id.tv_rule_reason);
                tvDate        = v.findViewById(R.id.tv_rule_date);
                tvHits        = v.findViewById(R.id.tv_rule_hits);
                switchEnabled = v.findViewById(R.id.switch_rule_enabled);
                btnDelete     = v.findViewById(R.id.btn_rule_delete);
            }
        }
    }
}
