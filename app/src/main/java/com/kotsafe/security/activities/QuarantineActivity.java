/*
 * This file is part of KotSafe / KotSafe.
 * Copyright 2026 - KotSafe Cyber Security Project
 *
 * QuarantineActivity
 * ==================
 * UI activity for managing the Sandboxed Quarantine Vault.
 */

package com.kotsafe.security.activities;

import android.os.Bundle;
import android.text.format.Formatter;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.model.QuarantineDbHelper;
import com.kotsafe.security.model.QuarantineVaultManager;
import com.google.android.material.button.MaterialButton;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class QuarantineActivity extends AppCompatActivity {
    private RecyclerView mRecyclerView;
    private View mEmptyLayout;
    private QuarantineAdapter mAdapter;
    private QuarantineVaultManager mVaultManager;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_quarantine);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle("Quarantine Vault");
        }

        mVaultManager = QuarantineVaultManager.getInstance(this);

        mRecyclerView = findViewById(R.id.recycler_quarantine);
        mEmptyLayout = findViewById(R.id.layout_empty_vault);

        mRecyclerView.setLayoutManager(new LinearLayoutManager(this));
        mAdapter = new QuarantineAdapter();
        mRecyclerView.setAdapter(mAdapter);

        loadQuarantineItems();
    }

    private void loadQuarantineItems() {
        List<QuarantineDbHelper.QuarantineRecord> items = mVaultManager.getQuarantinedList();
        mAdapter.setItems(items);

        if (items.isEmpty()) {
            mEmptyLayout.setVisibility(View.VISIBLE);
            mRecyclerView.setVisibility(View.GONE);
        } else {
            mEmptyLayout.setVisibility(View.GONE);
            mRecyclerView.setVisibility(View.VISIBLE);
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private class QuarantineAdapter extends RecyclerView.Adapter<QuarantineAdapter.ViewHolder> {
        private final List<QuarantineDbHelper.QuarantineRecord> mList = new ArrayList<>();
        private final SimpleDateFormat mDateFormat = new SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault());

        void setItems(List<QuarantineDbHelper.QuarantineRecord> items) {
            mList.clear();
            if (items != null) mList.addAll(items);
            notifyDataSetChanged();
        }

        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View view = LayoutInflater.from(QuarantineActivity.this).inflate(R.layout.item_quarantine, parent, false);
            return new ViewHolder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            QuarantineDbHelper.QuarantineRecord item = mList.get(position);

            holder.tvFileName.setText(item.fileName);
            holder.tvCategory.setText(item.threatCategory != null ? item.threatCategory.toUpperCase(Locale.ROOT) : "THREAT");
            holder.tvSize.setText(Formatter.formatFileSize(QuarantineActivity.this, item.fileSize));
            holder.tvPath.setText(item.originalPath);
            holder.tvDate.setText("Quarantined: " + mDateFormat.format(new Date(item.quarantineTimestamp)));

            if (item.sha256 != null && !item.sha256.isEmpty()) {
                holder.tvSha256.setText(item.sha256);
                holder.btnCopyHash.setOnClickListener(v -> {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("SHA-256", item.sha256));
                        Toast.makeText(QuarantineActivity.this, "Copied SHA-256 to clipboard", Toast.LENGTH_SHORT).show();
                    }
                });
            } else {
                holder.tvSha256.setText("Unavailable");
            }

            holder.btnInspect.setOnClickListener(v -> showThreatForensicDialog(item));

            holder.btnRestore.setOnClickListener(v -> {
                new AlertDialog.Builder(QuarantineActivity.this)
                        .setTitle("Restore File?")
                        .setMessage("Do you want to restore " + item.fileName + " back to:\n" + item.originalPath + "\n\nThis will also whitelist its hash so Antivirus will not flag it again.")
                        .setPositiveButton("Restore", (d, w) -> {
                            boolean ok = mVaultManager.restoreFile(item.id);
                            if (ok) {
                                Toast.makeText(QuarantineActivity.this, "File restored successfully", Toast.LENGTH_SHORT).show();
                                loadQuarantineItems();
                            } else {
                                Toast.makeText(QuarantineActivity.this, "Failed to restore file", Toast.LENGTH_SHORT).show();
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });

            holder.btnDelete.setOnClickListener(v -> {
                new AlertDialog.Builder(QuarantineActivity.this)
                        .setTitle("Permanently Shred File?")
                        .setMessage("This will permanently overwrite with zeros and delete " + item.fileName + " from the Quarantine Vault. This action cannot be undone.")
                        .setPositiveButton("Shred & Delete", (d, w) -> {
                            boolean ok = mVaultManager.permanentlyDelete(item.id);
                            if (ok) {
                                Toast.makeText(QuarantineActivity.this, "File shredded and deleted", Toast.LENGTH_SHORT).show();
                                loadQuarantineItems();
                            } else {
                                Toast.makeText(QuarantineActivity.this, "Failed to delete file", Toast.LENGTH_SHORT).show();
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });
        }

        @Override
        public int getItemCount() {
            return mList.size();
        }

        class ViewHolder extends RecyclerView.ViewHolder {
            TextView tvFileName, tvCategory, tvSize, tvPath, tvDate, tvSha256;
            View btnCopyHash;
            MaterialButton btnInspect, btnRestore, btnDelete;

            ViewHolder(@NonNull View itemView) {
                super(itemView);
                tvFileName = itemView.findViewById(R.id.tv_quarantine_filename);
                tvCategory = itemView.findViewById(R.id.tv_quarantine_category);
                tvSize = itemView.findViewById(R.id.tv_quarantine_size);
                tvPath = itemView.findViewById(R.id.tv_quarantine_path);
                tvDate = itemView.findViewById(R.id.tv_quarantine_date);
                tvSha256 = itemView.findViewById(R.id.tv_quarantine_sha256);
                btnCopyHash = itemView.findViewById(R.id.btn_copy_quarantine_hash);
                btnInspect = itemView.findViewById(R.id.btn_quarantine_inspect);
                btnRestore = itemView.findViewById(R.id.btn_quarantine_restore);
                btnDelete = itemView.findViewById(R.id.btn_quarantine_delete);
            }
        }
    }

    private void showThreatForensicDialog(QuarantineDbHelper.QuarantineRecord item) {
        if (item == null) return;

        View dialogView = LayoutInflater.from(this).inflate(R.layout.dialog_quarantine_forensic, null);
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setView(dialogView)
                .create();

        if (dialog.getWindow() != null) {
            dialog.getWindow().setBackgroundDrawableResource(android.R.color.transparent);
        }

        TextView tvName = dialogView.findViewById(R.id.tv_forensic_filename);
        TextView tvCategory = dialogView.findViewById(R.id.tv_forensic_category);
        TextView tvSizeDate = dialogView.findViewById(R.id.tv_forensic_size_date);
        TextView tvPath = dialogView.findViewById(R.id.tv_forensic_path);
        TextView tvDetails = dialogView.findViewById(R.id.tv_forensic_details);
        TextView tvSha256 = dialogView.findViewById(R.id.tv_forensic_sha256);
        View btnClose = dialogView.findViewById(R.id.btn_forensic_close);
        View btnCopyHash = dialogView.findViewById(R.id.btn_copy_forensic_hash);

        MaterialButton btnOtx = dialogView.findViewById(R.id.btn_lookup_otx);
        MaterialButton btnBazaar = dialogView.findViewById(R.id.btn_lookup_bazaar);
        MaterialButton btnVt = dialogView.findViewById(R.id.btn_lookup_virustotal);
        MaterialButton btnRestore = dialogView.findViewById(R.id.btn_forensic_restore);
        MaterialButton btnDelete = dialogView.findViewById(R.id.btn_forensic_delete);

        tvName.setText(item.fileName);
        tvCategory.setText(item.threatCategory != null ? item.threatCategory.toUpperCase(Locale.ROOT) : "QUARANTINED THREAT");
        tvSizeDate.setText("Size: " + Formatter.formatFileSize(this, item.fileSize)
                + " • Quarantined on " + new SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault()).format(new Date(item.quarantineTimestamp)));
        tvPath.setText(item.originalPath);
        tvDetails.setText(item.threatDetails != null && !item.threatDetails.isEmpty()
                ? item.threatDetails
                : "Active threat contained inside KotSafe Sandboxed Vault. Execution stripped, network egress sinkholed.");

        final String hash = (item.sha256 != null && !item.sha256.isEmpty()) ? item.sha256 : "";
        tvSha256.setText(!hash.isEmpty() ? hash : "SHA-256 fingerprint unavailable");

        if (btnClose != null) {
            btnClose.setOnClickListener(v -> dialog.dismiss());
        }

        if (btnCopyHash != null) {
            btnCopyHash.setOnClickListener(v -> {
                if (!hash.isEmpty()) {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("SHA-256", hash));
                        Toast.makeText(this, "Copied SHA-256 to clipboard", Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        // AlienVault OTX Pulse Lookup
        if (btnOtx != null) {
            btnOtx.setOnClickListener(v -> {
                if (!hash.isEmpty()) {
                    try {
                        String url = "https://otx.alienvault.com/indicator/file/" + hash;
                        startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url)));
                    } catch (Exception e) {
                        Toast.makeText(this, "Could not open browser: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                } else {
                    Toast.makeText(this, "Hash not available for OTX lookup", Toast.LENGTH_SHORT).show();
                }
            });
        }

        // Abuse.ch MalwareBazaar Lookup
        if (btnBazaar != null) {
            btnBazaar.setOnClickListener(v -> {
                if (!hash.isEmpty()) {
                    try {
                        String url = "https://bazaar.abuse.ch/sample/" + hash + "/";
                        startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url)));
                    } catch (Exception e) {
                        Toast.makeText(this, "Could not open browser: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                } else {
                    Toast.makeText(this, "Hash not available for MalwareBazaar lookup", Toast.LENGTH_SHORT).show();
                }
            });
        }

        // VirusTotal Lookup
        if (btnVt != null) {
            btnVt.setOnClickListener(v -> {
                if (!hash.isEmpty()) {
                    try {
                        String url = "https://www.virustotal.com/gui/file/" + hash;
                        startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url)));
                    } catch (Exception e) {
                        Toast.makeText(this, "Could not open browser: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                    }
                } else {
                    Toast.makeText(this, "Hash not available for VirusTotal lookup", Toast.LENGTH_SHORT).show();
                }
            });
        }

        if (btnRestore != null) {
            btnRestore.setOnClickListener(v -> {
                dialog.dismiss();
                new AlertDialog.Builder(this)
                        .setTitle("Restore File?")
                        .setMessage("Do you want to restore " + item.fileName + " back to:\n" + item.originalPath + "\n\nThis will also whitelist its hash so Antivirus will not flag it again.")
                        .setPositiveButton("Restore", (d, w) -> {
                            boolean ok = mVaultManager.restoreFile(item.id);
                            if (ok) {
                                Toast.makeText(this, "File restored successfully", Toast.LENGTH_SHORT).show();
                                loadQuarantineItems();
                            } else {
                                Toast.makeText(this, "Failed to restore file", Toast.LENGTH_SHORT).show();
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });
        }

        if (btnDelete != null) {
            btnDelete.setOnClickListener(v -> {
                dialog.dismiss();
                new AlertDialog.Builder(this)
                        .setTitle("Permanently Shred File?")
                        .setMessage("This will permanently overwrite with zeros and delete " + item.fileName + " from the Quarantine Vault. This action cannot be undone.")
                        .setPositiveButton("Shred & Delete", (d, w) -> {
                            boolean ok = mVaultManager.permanentlyDelete(item.id);
                            if (ok) {
                                Toast.makeText(this, "File shredded and deleted", Toast.LENGTH_SHORT).show();
                                loadQuarantineItems();
                            } else {
                                Toast.makeText(this, "Failed to delete file", Toast.LENGTH_SHORT).show();
                            }
                        })
                        .setNegativeButton("Cancel", null)
                        .show();
            });
        }

        dialog.show();
    }
}
