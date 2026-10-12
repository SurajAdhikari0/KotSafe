/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.format.Formatter;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.Toolbar;

import com.kotsafe.security.R;
import com.kotsafe.security.model.RetentionWorker;
import com.kotsafe.security.model.SecurityDatabase;
import com.google.android.material.button.MaterialButton;

import java.util.List;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class StorageManagementActivity extends BaseActivity {
    private static final String TAG = "StorageManagementActivity";

    private final ExecutorService mExecutor = Executors.newSingleThreadExecutor();
    private final Handler mMainHandler = new Handler(Looper.getMainLooper());

    private SecurityDatabase mSecDb;

    private TextView mTvTotalSize;
    private TextView mTvEvidenceSize;
    private TextView mTvEvidenceCount;
    private TextView mTvLogsSize;
    private TextView mTvLogsCount;
    private TextView mTvCacheSize;
    private TextView mTvCacheCount;
    private TextView mTvRulesSize;
    private TextView mTvRulesCount;

    private View mBarEvidence;
    private View mBarLogs;
    private View mBarCache;
    private View mBarRules;

    private MaterialButton mBtnClearEvidence;
    private MaterialButton mBtnClearLogs;
    private MaterialButton mBtnClearCache;
    private MaterialButton mBtnManageRules;
    private MaterialButton mBtnRunRetention;
    private MaterialButton mBtnOptimizeDatabase;
    private MaterialButton mBtnExportLogs;
    private MaterialButton mBtnClearAllExceptRules;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_storage_management);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            setSupportActionBar(toolbar);
            if (getSupportActionBar() != null) {
                getSupportActionBar().setDisplayHomeAsUpEnabled(true);
                getSupportActionBar().setTitle(R.string.storage_management);
            }
        }

        mSecDb = SecurityDatabase.getInstance(this);

        mTvTotalSize = findViewById(R.id.tv_total_size);
        mBarEvidence = findViewById(R.id.bar_evidence);
        mBarLogs = findViewById(R.id.bar_logs);
        mBarCache = findViewById(R.id.bar_cache);
        mBarRules = findViewById(R.id.bar_rules);

        mTvEvidenceSize = findViewById(R.id.tv_evidence_size);
        mTvEvidenceCount = findViewById(R.id.tv_evidence_count);
        mTvLogsSize = findViewById(R.id.tv_logs_size);
        mTvLogsCount = findViewById(R.id.tv_logs_count);
        mTvCacheSize = findViewById(R.id.tv_cache_size);
        mTvCacheCount = findViewById(R.id.tv_cache_count);
        mTvRulesSize = findViewById(R.id.tv_rules_size);
        mTvRulesCount = findViewById(R.id.tv_rules_count);

        mBtnClearEvidence = findViewById(R.id.btn_clear_evidence);
        mBtnClearLogs = findViewById(R.id.btn_clear_logs);
        mBtnClearCache = findViewById(R.id.btn_clear_cache);
        mBtnManageRules = findViewById(R.id.btn_manage_rules);
        mBtnRunRetention = findViewById(R.id.btn_run_retention);
        mBtnOptimizeDatabase = findViewById(R.id.btn_optimize_database);
        mBtnExportLogs = findViewById(R.id.btn_export_logs);
        mBtnClearAllExceptRules = findViewById(R.id.btn_clear_all_except_rules);

        mBtnClearEvidence.setOnClickListener(v -> confirmClearEvidence());
        mBtnClearLogs.setOnClickListener(v -> confirmClearLogs());
        mBtnClearCache.setOnClickListener(v -> {
            mExecutor.execute(() -> {
                int cleared = mSecDb.clearCache();
                mMainHandler.post(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    Toast.makeText(this, "Cleared " + cleared + " cached items", Toast.LENGTH_SHORT).show();
                    loadStorageStats();
                });
            });
        });

        mBtnManageRules.setOnClickListener(v -> {
            Intent intent = new Intent(this, SecurityActionsActivity.class);
            startActivity(intent);
        });

        mBtnRunRetention.setOnClickListener(v -> {
            RetentionWorker.runOnceNow(this);
            Toast.makeText(this, "Running retention cleanup worker...", Toast.LENGTH_SHORT).show();
            mMainHandler.postDelayed(this::loadStorageStats, 1200);
        });

        if (mBtnOptimizeDatabase != null) {
            mBtnOptimizeDatabase.setOnClickListener(v -> optimizeDatabases());
        }

        if (mBtnExportLogs != null) {
            mBtnExportLogs.setOnClickListener(v -> exportAllSecurityLogs());
        }

        mBtnClearAllExceptRules.setOnClickListener(v -> confirmClearAllExceptRules());

        loadStorageStats();
    }

    @Override
    protected void onResume() {
        super.onResume();
        loadStorageStats();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        mExecutor.shutdownNow();
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void loadStorageStats() {
        mExecutor.execute(() -> {
            SecurityDatabase.StorageStats stats = mSecDb.getStorageStats(this);
            mMainHandler.post(() -> {
                if (isFinishing() || isDestroyed()) return;
                updateUiWithStats(stats);
            });
        });
    }

    private void updateUiWithStats(SecurityDatabase.StorageStats stats) {
        if (isFinishing() || isDestroyed()) return;

        long total = stats.totalBytes();
        mTvTotalSize.setText(Formatter.formatFileSize(this, total));

        // Update proportional allocation bar
        if (total > 0 && mBarEvidence != null && mBarLogs != null && mBarCache != null && mBarRules != null) {
            setBarWeight(mBarEvidence, Math.max(2f, (float) stats.evidenceBytes / total * 100f));
            setBarWeight(mBarLogs, Math.max(2f, (float) stats.logsBytes / total * 100f));
            setBarWeight(mBarCache, Math.max(2f, (float) stats.cacheBytes / total * 100f));
            setBarWeight(mBarRules, Math.max(2f, (float) stats.rulesBytes / total * 100f));
        }

        mTvEvidenceSize.setText(Formatter.formatFileSize(this, stats.evidenceBytes));
        mTvEvidenceCount.setText(stats.evidenceRows + " evidence records");

        mTvLogsSize.setText(Formatter.formatFileSize(this, stats.logsBytes));
        mTvLogsCount.setText(stats.logsRows + " log entries");

        mTvCacheSize.setText(Formatter.formatFileSize(this, stats.cacheBytes));
        mTvCacheCount.setText(stats.cacheRows + " cached lookups");

        mTvRulesSize.setText(Formatter.formatFileSize(this, stats.rulesBytes));
        mTvRulesCount.setText(stats.rulesRows + " active rules");
    }

    private void setBarWeight(View view, float weight) {
        android.widget.LinearLayout.LayoutParams params = (android.widget.LinearLayout.LayoutParams) view.getLayoutParams();
        params.weight = weight;
        view.setLayoutParams(params);
    }

    private void optimizeDatabases() {
        Toast.makeText(this, "Optimizing and defragmenting databases...", Toast.LENGTH_SHORT).show();
        mExecutor.execute(() -> {
            mSecDb.optimizeDatabases();
            try {
                com.kotsafe.security.model.FirewallLogDbHelper.getInstance(this).getWritableDatabase().execSQL("VACUUM");
                com.kotsafe.security.model.DnsActivityDbHelper.getInstance(this).getWritableDatabase().execSQL("VACUUM");
            } catch (Exception ignored) {}
            mMainHandler.post(() -> {
                if (isFinishing() || isDestroyed()) return;
                Toast.makeText(this, "Databases optimized successfully (VACUUM completed)", Toast.LENGTH_SHORT).show();
                loadStorageStats();
            });
        });
    }

    private void exportAllSecurityLogs() {
        Toast.makeText(this, "Preparing security log export...", Toast.LENGTH_SHORT).show();
        mExecutor.execute(() -> {
            try {
                com.google.gson.JsonObject root = new com.google.gson.JsonObject();
                root.addProperty("export_timestamp", System.currentTimeMillis());
                root.addProperty("app", "KotSafe Security Log Export");

                com.google.gson.JsonArray eventsArr = new com.google.gson.JsonArray();

                // Firewall logs
                List<com.kotsafe.security.model.FirewallLogEntry> fwLogs =
                        com.kotsafe.security.model.FirewallLogDbHelper.getInstance(this).queryLogs("ALL", "", 200, 0);
                for (com.kotsafe.security.model.FirewallLogEntry f : fwLogs) {
                    com.google.gson.JsonObject obj = new com.google.gson.JsonObject();
                    obj.addProperty("type", "firewall");
                    obj.addProperty("host", f.domainOrUrl);
                    obj.addProperty("ip", f.dstIp);
                    obj.addProperty("port", f.dstPort);
                    obj.addProperty("action", f.action);
                    obj.addProperty("reason", f.blockReason);
                    obj.addProperty("timestamp", f.timestamp);
                    eventsArr.add(obj);
                }

                // DNS tracker logs
                List<com.kotsafe.security.model.DnsActivityEntry> dnsLogs =
                        com.kotsafe.security.model.DnsActivityDbHelper.getInstance(this).queryLogs(null, "", 200, 0);
                for (com.kotsafe.security.model.DnsActivityEntry d : dnsLogs) {
                    com.google.gson.JsonObject obj = new com.google.gson.JsonObject();
                    obj.addProperty("type", "dns");
                    obj.addProperty("domain", d.domain);
                    obj.addProperty("status", d.status);
                    obj.addProperty("queryType", d.queryType);
                    obj.addProperty("timestamp", d.timestamp);
                    eventsArr.add(obj);
                }
                root.add("security_events", eventsArr);

                String json = new com.google.gson.GsonBuilder().setPrettyPrinting().create().toJson(root);

                java.io.File file = new java.io.File(getCacheDir(), "kotsafe_security_logs_export.json");
                try (java.io.FileWriter fw = new java.io.FileWriter(file)) {
                    fw.write(json);
                }

                android.net.Uri contentUri = androidx.core.content.FileProvider.getUriForFile(
                        this, getPackageName() + ".fileprovider", file);

                mMainHandler.post(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    Intent shareIntent = new Intent(Intent.ACTION_SEND);
                    shareIntent.setType("application/json");
                    shareIntent.putExtra(Intent.EXTRA_STREAM, contentUri);
                    shareIntent.putExtra(Intent.EXTRA_SUBJECT, "KotSafe Security Logs Export");
                    shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                    startActivity(Intent.createChooser(shareIntent, "Export Security Logs"));
                });
            } catch (Exception e) {
                mMainHandler.post(() -> {
                    if (isFinishing() || isDestroyed()) return;
                    Toast.makeText(this, "Export failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                });
            }
        });
    }

    private void confirmClearEvidence() {
        new AlertDialog.Builder(this)
                .setTitle("Clear Evidence Database?")
                .setMessage("All detection IOCs, YARA forensic records and threat reports will be permanently cleared.\n\nSecurity Rules are NEVER affected.")
                .setIcon(R.drawable.ic_shield)
                .setPositiveButton("Clear Evidence", (dialog, which) -> {
                    mExecutor.execute(() -> {
                        int count = mSecDb.clearEvidence();
                        mMainHandler.post(() -> {
                            if (isFinishing() || isDestroyed()) return;
                            Toast.makeText(this, "Cleared " + count + " evidence records", Toast.LENGTH_SHORT).show();
                            loadStorageStats();
                        });
                    });
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void confirmClearLogs() {
        new AlertDialog.Builder(this)
                .setTitle("Clear Logs Database?")
                .setMessage("All URL visit history, destination logs, and scan events will be permanently cleared.\n\nSecurity Rules are NEVER affected.")
                .setIcon(R.drawable.ic_search)
                .setPositiveButton("Clear Logs", (dialog, which) -> {
                    mExecutor.execute(() -> {
                        int count = mSecDb.clearLogs();
                        mMainHandler.post(() -> {
                            if (isFinishing() || isDestroyed()) return;
                            Toast.makeText(this, "Cleared " + count + " log entries", Toast.LENGTH_SHORT).show();
                            loadStorageStats();
                        });
                    });
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void confirmClearAllExceptRules() {
        new AlertDialog.Builder(this)
                .setTitle("Clear Evidence, Logs & Cache?")
                .setMessage("This will remove all evidence, telemetry logs, and TI cache.\n\nIMPORTANT: Security Rules (blocks & whitelist) will remain completely intact.")
                .setIcon(R.drawable.ic_exclamation_triangle_solid)
                .setPositiveButton("Clear Everything Except Rules", (dialog, which) -> {
                    mExecutor.execute(() -> {
                        mSecDb.clearAllExceptRules();
                        mMainHandler.post(() -> {
                            if (isFinishing() || isDestroyed()) return;
                            Toast.makeText(this, "Evidence, logs and cache cleared", Toast.LENGTH_SHORT).show();
                            loadStorageStats();
                        });
                    });
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }
}
