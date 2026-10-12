/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.google.android.material.chip.ChipGroup;

import java.util.ArrayList;
import java.util.List;

public class AlertsCenterActivity extends AppCompatActivity {

    private AlertStore         mStore;
    private AlertsAdapter      mAdapter;
    private List<AlertRecord>  mFiltered;

    private TextView mCountHigh, mCountMedium, mCountLow, mCountTotal;
    private View     mEmptyState;
    private RecyclerView mList;

    // Current filter: null = ALL
    private AlertRecord.AlertType mCurrentType = null;
    private AlertRecord.Severity mSeverityFilter = null;
    private boolean mResolvedFilter = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_alerts_center);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        mStore = AlertStore.getInstance(this);
        mFiltered = new ArrayList<>();

        // Stats bar
        mCountHigh   = findViewById(R.id.count_high);
        mCountMedium = findViewById(R.id.count_medium);
        mCountLow    = findViewById(R.id.count_low);
        mCountTotal  = findViewById(R.id.count_total);

        View vHigh = (View) mCountHigh.getParent();
        if (vHigh != null) vHigh.setOnClickListener(v -> {
            com.google.android.material.chip.Chip c = findViewById(R.id.chip_high);
            if (c != null) c.setChecked(true);
        });
        View vMed = (View) mCountMedium.getParent();
        if (vMed != null) vMed.setOnClickListener(v -> {
            com.google.android.material.chip.Chip c = findViewById(R.id.chip_medium);
            if (c != null) c.setChecked(true);
        });
        View vLow = (View) mCountLow.getParent();
        if (vLow != null) vLow.setOnClickListener(v -> {
            com.google.android.material.chip.Chip c = findViewById(R.id.chip_low);
            if (c != null) c.setChecked(true);
        });
        View vTot = (View) mCountTotal.getParent();
        if (vTot != null) vTot.setOnClickListener(v -> {
            com.google.android.material.chip.Chip c = findViewById(R.id.chip_all);
            if (c != null) c.setChecked(true);
        });

        // RecyclerView
        mList = findViewById(R.id.alerts_list);
        mEmptyState = findViewById(R.id.empty_state);
        mAdapter = new AlertsAdapter(mFiltered);
        mList.setLayoutManager(new LinearLayoutManager(this));
        mList.setAdapter(mAdapter);

        // Filter chips
        ChipGroup chips = findViewById(R.id.filter_chips);
        chips.setOnCheckedStateChangeListener((group, checkedIds) -> {
            if (checkedIds.isEmpty()) return;
            int id = checkedIds.get(0);
            mSeverityFilter = null;
            mCurrentType = null;
            mResolvedFilter = false;
            if (id == R.id.chip_high)          { mSeverityFilter = AlertRecord.Severity.HIGH; }
            else if (id == R.id.chip_medium)   { mSeverityFilter = AlertRecord.Severity.MEDIUM; }
            else if (id == R.id.chip_low)      { mSeverityFilter = AlertRecord.Severity.LOW; }
            else if (id == R.id.chip_resolved) { mResolvedFilter = true; }
            else if (id == R.id.chip_quarantine) { mCurrentType = AlertRecord.AlertType.QUARANTINE; }
            else if (id == R.id.chip_malware)  { mCurrentType = AlertRecord.AlertType.MALWARE; }
            else if (id == R.id.chip_firewall) { mCurrentType = AlertRecord.AlertType.FIREWALL_BLOCK; }
            else if (id == R.id.chip_dns)      { mCurrentType = AlertRecord.AlertType.DNS_ANOMALY; }
            else if (id == R.id.chip_tls)      { mCurrentType = AlertRecord.AlertType.TLS_ERROR; }
            else if (id == R.id.chip_attack)   { mCurrentType = AlertRecord.AlertType.ATTACK_PATTERN; }
            refresh();
        });

        if (getIntent().getBooleanExtra("EXTRA_FILTER_QUARANTINE", false)) {
            mCurrentType = AlertRecord.AlertType.QUARANTINE;
            com.google.android.material.chip.Chip chipQ = findViewById(R.id.chip_quarantine);
            if (chipQ != null) chipQ.setChecked(true);
        }

        refresh();
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        if (intent != null && intent.getBooleanExtra("EXTRA_FILTER_QUARANTINE", false)) {
            mCurrentType = AlertRecord.AlertType.QUARANTINE;
            mSeverityFilter = null;
            com.google.android.material.chip.Chip chipQ = findViewById(R.id.chip_quarantine);
            if (chipQ != null) chipQ.setChecked(true);
            refresh();
        }
    }

    private void refresh() {
        List<AlertRecord> all = mStore.getAll();

        // Update stats
        int high = 0, medium = 0, low = 0;
        for (AlertRecord r : all) {
            if (r.severity == AlertRecord.Severity.HIGH)   high++;
            else if (r.severity == AlertRecord.Severity.MEDIUM) medium++;
            else if (r.severity == AlertRecord.Severity.LOW)    low++;
        }
        mCountHigh.setText(String.valueOf(high));
        mCountMedium.setText(String.valueOf(medium));
        mCountLow.setText(String.valueOf(low));
        mCountTotal.setText(String.valueOf(all.size()));

        // Apply filter
        mFiltered.clear();
        for (AlertRecord r : all) {
            if (mResolvedFilter && !r.isResolved()) continue;
            if (mSeverityFilter != null && r.severity != mSeverityFilter) continue;
            if (mCurrentType != null && r.type != mCurrentType) continue;
            mFiltered.add(r);
        }

        // Sort by risk priority first (Malware / High priority first), then by timestamp descending
        java.util.Collections.sort(mFiltered, (a, b) -> {
            int w = Integer.compare(b.getPriorityWeight(), a.getPriorityWeight());
            return w != 0 ? w : Long.compare(b.timestampMs, a.timestampMs);
        });

        mAdapter.notifyDataSetChanged();
        mList.setVisibility(mFiltered.isEmpty() ? View.GONE : View.VISIBLE);
        mEmptyState.setVisibility(mFiltered.isEmpty() ? View.VISIBLE : View.GONE);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(Menu.NONE, 2, Menu.NONE, "Simulate Security Alerts (All Types)").setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
        menu.add(Menu.NONE, 1, Menu.NONE, "Clear All").setShowAsAction(MenuItem.SHOW_AS_ACTION_NEVER);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) { finish(); return true; }
        if (item.getItemId() == 1) {
            new AlertDialog.Builder(this)
                    .setTitle("Clear All Alerts")
                    .setMessage("Remove all security alerts? This cannot be undone.")
                    .setPositiveButton("Clear", (d, w) -> { mStore.clearAll(); refresh(); })
                    .setNegativeButton("Cancel", null)
                    .show();
            return true;
        }
        if (item.getItemId() == 2) {
            simulateAllAlertTypes();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void simulateAllAlertTypes() {
        // 1. Medium: MITRE ATT&CK Pattern
        mStore.add(AlertRecord.Severity.MEDIUM, AlertRecord.AlertType.ATTACK_PATTERN,
                "⚔️ MITRE ATT&CK T1046: Network Service Scanning",
                "Application attempted high-frequency sequential SYN probes across local subnet 192.168.1.0/24. Reconnaissance pattern matched.",
                "com.example.scanner");

        // 2. Medium: TLS Tampering
        mStore.add(AlertRecord.Severity.MEDIUM, AlertRecord.AlertType.TLS_ERROR,
                "🔒 Insecure Cleartext Protocol / SSL Strip",
                "Outbound HTTP transmission intercepted with credential headers over unencrypted port 80. Forced TLS upgrade applied.",
                "com.android.browser");

        // 3. Low: Firewall Block
        mStore.add(AlertRecord.Severity.LOW, AlertRecord.AlertType.FIREWALL_BLOCK,
                "🛡️ [RESOLVED] Outbound Adware/Telemetry Blocked",
                "Connection to known telemetry endpoint 'analytics-sink.telemetry.net:443' blocked by KotSafe automated firewall rules.",
                "com.google.android.gms");

        // 4. Low: DNS Anomaly
        mStore.add(AlertRecord.Severity.LOW, AlertRecord.AlertType.DNS_ANOMALY,
                "🔍 High Entropy DNS Anomaly",
                "Query burst to pseudorandom domain 'a9f2bc71z.dyndns.org' flagged by Shannon Entropy analyzer (Entropy: 3.81).",
                "com.whatsapp");

        // 5. High: Quarantine Isolation
        AlertRecord qAlert = mStore.add(AlertRecord.Severity.HIGH, AlertRecord.AlertType.QUARANTINE,
                "🔒 [AUTO-RESOLVED] Malicious Payload Isolated in Vault",
                "Suspicious payload 'Trojan.Dropper.Agent.apk' automatically intercepted and isolated in hardware-encrypted AES-256 Vault.",
                "com.suspicious.downloader");
        qAlert.setQuarantineMetadata(999L, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "/storage/emulated/0/Download/Trojan.apk");
        mStore.updateAlert(qAlert);

        refresh();
        Toast.makeText(this, "Simulated alerts generated across Medium, Low, Quarantine, Firewall, DNS, TLS, and Attack", Toast.LENGTH_LONG).show();
    }

    // ── Inner RecyclerView Adapter ───────────────────────────────────────────

    private class AlertsAdapter extends RecyclerView.Adapter<AlertsAdapter.VH> {
        private final List<AlertRecord> mData;
        AlertsAdapter(List<AlertRecord> data) { mData = data; }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull android.view.ViewGroup parent, int viewType) {
            View v = getLayoutInflater().inflate(R.layout.alert_item, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int position) {
            AlertRecord r = mData.get(position);
            h.bind(r);
        }

        @Override public int getItemCount() { return mData.size(); }

        class VH extends RecyclerView.ViewHolder {
            final View     stripe;
            final TextView badge, resolvedBadge, countBadge, time, title, message, source;
            final View     btnTimeline;
            final View     btnInvestigate;
            final com.google.android.material.button.MaterialButton btnReleaseQuarantine;

            VH(View v) {
                super(v);
                stripe        = v.findViewById(R.id.severity_stripe);
                badge         = v.findViewById(R.id.alert_type_badge);
                resolvedBadge = v.findViewById(R.id.alert_resolved_badge);
                countBadge    = v.findViewById(R.id.alert_count_badge);
                time          = v.findViewById(R.id.alert_time);
                title         = v.findViewById(R.id.alert_title);
                message       = v.findViewById(R.id.alert_message);
                source        = v.findViewById(R.id.alert_source);
                btnTimeline   = v.findViewById(R.id.btn_alert_timeline);
                btnInvestigate = v.findViewById(R.id.btn_investigate_alert);
                btnReleaseQuarantine = v.findViewById(R.id.btn_release_quarantine);
            }

            void bind(AlertRecord r) {
                title.setText(r.title);
                if (r.aiAssessment != null && !r.aiAssessment.isEmpty()) {
                    message.setText(r.message + "\n\n🤖 AI SOC Assessment: " + r.aiAssessment);
                } else {
                    message.setText(r.message);
                }
                time.setText(r.getFormattedTime());
                source.setText(r.sourceApp.isEmpty() ? "" : "Source: " + r.sourceApp);

                if (resolvedBadge != null) {
                    if (r.isResolved()) {
                        resolvedBadge.setVisibility(View.VISIBLE);
                        if (r.isReleased) {
                            resolvedBadge.setText("✓ RISK ACCEPTED");
                            resolvedBadge.setTextColor(0xFFE3B341);
                            resolvedBadge.getBackground().setTint(0xFF2D2305);
                        } else if (r.title != null && r.title.contains("AUTO-RESOLVED")) {
                            resolvedBadge.setText("✓ AUTO-RESOLVED");
                            resolvedBadge.setTextColor(0xFF3FB950);
                            resolvedBadge.getBackground().setTint(0xFF132B1E);
                        } else {
                            resolvedBadge.setText("✓ RESOLVED");
                            resolvedBadge.setTextColor(0xFF3FB950);
                            resolvedBadge.getBackground().setTint(0xFF132B1E);
                        }
                    } else {
                        resolvedBadge.setVisibility(View.GONE);
                    }
                }

                if (countBadge != null) {
                    if (r.occurrenceCount > 1) {
                        countBadge.setVisibility(View.VISIBLE);
                        countBadge.setText("🔁 " + r.occurrenceCount + "x");
                    } else {
                        countBadge.setVisibility(View.GONE);
                    }
                }

                if (r.type == AlertRecord.AlertType.QUARANTINE) {
                    badge.setText("QUARANTINE");
                } else {
                    badge.setText(r.type.label.toUpperCase());
                }

                // Severity colour
                int color;
                switch (r.severity) {
                    case HIGH:   color = ContextCompat.getColor(AlertsCenterActivity.this, R.color.danger); break;
                    case MEDIUM: color = ContextCompat.getColor(AlertsCenterActivity.this, R.color.warning); break;
                    case LOW:    color = ContextCompat.getColor(AlertsCenterActivity.this, R.color.ok); break;
                    default:     color = ContextCompat.getColor(AlertsCenterActivity.this, R.color.in_progress); break;
                }
                stripe.setBackgroundColor(color);
                badge.getBackground().setTint(color);

                // Release from Quarantine button (KotSafe Vault style)
                if (btnReleaseQuarantine != null) {
                    if (r.type == AlertRecord.AlertType.QUARANTINE || r.quarantineRecordId > 0) {
                        btnReleaseQuarantine.setVisibility(View.VISIBLE);
                        if (r.isReleased) {
                            btnReleaseQuarantine.setText("✓ Released (Risk Accepted)");
                            btnReleaseQuarantine.setTextColor(0xFF3FB950);
                            btnReleaseQuarantine.setStrokeColor(android.content.res.ColorStateList.valueOf(0xFF3FB950));
                            btnReleaseQuarantine.setEnabled(false);
                        } else {
                            btnReleaseQuarantine.setText("Release (Accept Risk)");
                            btnReleaseQuarantine.setTextColor(0xFFF85149);
                            btnReleaseQuarantine.setStrokeColor(android.content.res.ColorStateList.valueOf(0xFFF85149));
                            btnReleaseQuarantine.setEnabled(true);
                            btnReleaseQuarantine.setOnClickListener(v -> promptReleaseFromQuarantine(r));
                        }
                    } else {
                        btnReleaseQuarantine.setVisibility(View.GONE);
                    }
                }

                // Timeline button
                if (btnTimeline != null) {
                    btnTimeline.setOnClickListener(v -> com.kotsafe.security.views.AlertTimelineDialog.show(getSupportFragmentManager(), r));
                }

                // Deep Threat Investigation button
                if (btnInvestigate != null) {
                    btnInvestigate.setOnClickListener(v -> com.kotsafe.security.views.ThreatInvestigationDialog.show(getSupportFragmentManager(), r));
                }

                // Click for full detail
                itemView.setOnClickListener(v -> showDetail(r));
            }
        }
    }

    private void showDetail(AlertRecord r) {
        StringBuilder detail = new StringBuilder("Type: " + r.type.label
                + "\nSeverity: " + r.severity.name()
                + "\nTime: " + r.getFormattedTime()
                + (r.sourceApp.isEmpty() ? "" : "\nSource: " + r.sourceApp)
                + (r.isReleased ? "\n\n✓ STATUS: RELEASED FROM QUARANTINE (USER ACCEPTED RISK)" : "")
                + "\n\n" + r.message);

        com.kotsafe.security.ai.AiConfig aiConfig = new com.kotsafe.security.ai.AiConfig(this);
        boolean canAiTriage = aiConfig.isAiEnabled() && aiConfig.canAccessFirewall();

        if (canAiTriage) {
            detail.append("\n\n🤖 [AI Threat Analysis: Computing malicious probability & false-positive triage...]");
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this)
                .setTitle(r.title)
                .setMessage(detail.toString());

        if ((r.type == AlertRecord.AlertType.QUARANTINE || r.quarantineRecordId > 0) && !r.isReleased) {
            builder.setPositiveButton("⏱️ Timeline", (d, w) -> {
                com.kotsafe.security.views.AlertTimelineDialog.show(getSupportFragmentManager(), r);
            });
            builder.setNeutralButton("🔍 Deep Investigate", (d, w) -> {
                com.kotsafe.security.views.ThreatInvestigationDialog.show(getSupportFragmentManager(), r);
            });
            builder.setNegativeButton("Release", (d, w) -> promptReleaseFromQuarantine(r));
        } else {
            builder.setPositiveButton("⏱️ Timeline", (d, w) -> {
                com.kotsafe.security.views.AlertTimelineDialog.show(getSupportFragmentManager(), r);
            });
            builder.setNeutralButton("🔍 Deep Investigate", (d, w) -> {
                com.kotsafe.security.views.ThreatInvestigationDialog.show(getSupportFragmentManager(), r);
            });
            builder.setNegativeButton("Close", null);
        }

        AlertDialog dialog = builder.show();

        if (canAiTriage) {
            com.kotsafe.security.ai.AiClientEngine.getInstance(this).analyzeAlert(r, new com.kotsafe.security.ai.AiClientEngine.AlertTriageCallback() {
                @Override
                public void onResult(com.kotsafe.security.ai.AiClientEngine.AlertTriageResult result) {
                    if (isFinishing() || isDestroyed()) return;
                    String updated = "Type: " + r.type.label
                            + "\nSeverity: " + r.severity.name()
                            + "\nTime: " + r.getFormattedTime()
                            + (r.sourceApp.isEmpty() ? "" : "\nSource: " + r.sourceApp)
                            + "\n\n" + r.message
                            + "\n\n───────────────────────────────"
                            + "\n🤖 AI THREAT ASSESSMENT (OUTER LAYER)"
                            + "\n• Verdict: " + result.verdict
                            + "\n• Malicious Probability: " + result.maliciousProbability + "%"
                            + " (False Positive Chance: " + (100 - result.maliciousProbability) + "%)"
                            + "\n• Analysis: " + result.reasoning
                            + "\n• Recommendation: " + result.recommendation;
                    dialog.setMessage(updated);
                }

                @Override
                public void onError(String error) {
                    if (isFinishing() || isDestroyed()) return;
                    dialog.setMessage(detail.toString().replace(
                            "[AI Threat Analysis: Computing malicious probability & false-positive triage...]",
                            "[AI Threat Analysis: " + error + "]"));
                }
            });
        }
    }

    private void promptReleaseFromQuarantine(AlertRecord r) {
        if (r == null || r.isReleased) return;

        String targetName = r.quarantinePath != null && !r.quarantinePath.isEmpty()
                ? r.quarantinePath : r.title;
        String sha = r.quarantineSha256 != null && !r.quarantineSha256.isEmpty()
                ? r.quarantineSha256 : "N/A";

        String warningMessage = "Are you sure you want to release and restore this threat from quarantine?\n\n"
                + "Target: " + targetName + "\n"
                + "SHA-256: " + sha + "\n\n"
                + "⚠️ KOTSAFE SECURITY RISK ACCEPTANCE:\n"
                + "• The file will be decrypted from AES-256-GCM isolation and restored to its original storage location.\n"
                + "• Network firewall sinkholes and execution blocks on this item will be removed.\n"
                + "• The item's digital hash will be whitelisted so KotSafe does not immediately re-quarantine it.\n\n"
                + "Do you accept full operational and security risk to restore this item?";

        new AlertDialog.Builder(this)
                .setTitle("⚠️ Release Quarantined Threat?")
                .setMessage(warningMessage)
                .setPositiveButton("Accept Risk & Release", (dialog, which) -> {
                    boolean success = false;
                    if (r.quarantineRecordId > 0) {
                        success = com.kotsafe.security.model.QuarantineVaultManager.getInstance(this).restoreFile(r.quarantineRecordId);
                    } else {
                        // Quarantine record for URL, Hash, or App
                        try {
                            if (r.quarantineSha256 != null && !r.quarantineSha256.isEmpty()) {
                                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(this).unblock(r.quarantineSha256);
                                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(this).whitelist(
                                        "HASH", r.quarantineSha256, "GLOBAL", "Restored by user - Risk accepted"
                                );
                            }
                            if (r.quarantinePath != null && !r.quarantinePath.isEmpty()) {
                                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(this).unblock(r.quarantinePath);
                                String type = r.quarantinePath.startsWith("http") ? "URL" : "APP";
                                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(this).whitelist(
                                        type, r.quarantinePath, "GLOBAL", "Restored by user - Risk accepted"
                                );
                            }
                            if (r.sourceApp != null && !r.sourceApp.isEmpty() && !r.sourceApp.equals(r.quarantinePath)) {
                                com.kotsafe.security.model.SecurityBlocklistManager.getInstance(this).unblock(r.sourceApp);
                            }
                            success = true;
                        } catch (Exception ignored) {}
                    }

                    if (success) {
                        r.isReleased = true;
                        if (!r.message.startsWith("[RELEASED FROM QUARANTINE")) {
                            r.message = "[RELEASED FROM QUARANTINE — RISK ACCEPTED BY USER]\n\n" + r.message;
                        }
                        mStore.updateAlert(r);
                        refresh();
                        android.widget.Toast.makeText(this, "Item released from quarantine. User accepted risk.", android.widget.Toast.LENGTH_LONG).show();
                    } else {
                        android.widget.Toast.makeText(this, "Failed to restore item from vault. Integrity check or file missing.", android.widget.Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton("Cancel (Keep Quarantined)", null)
                .show();
    }
}

