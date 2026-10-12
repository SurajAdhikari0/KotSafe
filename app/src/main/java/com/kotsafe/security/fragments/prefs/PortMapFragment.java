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

package com.kotsafe.security.fragments.prefs;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.ActionMode;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView;
import android.widget.ArrayAdapter;
import android.widget.AutoCompleteTextView;
import android.widget.ListView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.Lifecycle;
import androidx.preference.PreferenceManager;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.prefs.PortMapExemptionsActivity;
import com.kotsafe.security.adapters.PortMappingAdapter;
import com.kotsafe.security.model.PortMapping;
import com.kotsafe.security.model.PortMapping.PortMap;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.chip.Chip;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.textfield.TextInputEditText;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;

public class PortMapFragment extends Fragment implements MenuProvider, PortMappingAdapter.OnPortMapActionListener {
    private static final String TAG = "PortMapFragment";
    private PortMappingAdapter mAdapter;
    private View mEmptyContainer;
    private ListView mListView;
    private PortMapping mPortMap;
    private SwitchCompat mMasterSwitch;
    private TextView mTvSwitchStatus;
    private TextView mTvMappingCount;
    private SwitchCompat mMenuSwitch;
    private ArrayList<PortMap> mSelected = new ArrayList<>();

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        requireActivity().addMenuProvider(this, getViewLifecycleOwner(), Lifecycle.State.RESUMED);
        return inflater.inflate(R.layout.fragment_port_mapping, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        mListView = view.findViewById(R.id.listview);
        mEmptyContainer = view.findViewById(R.id.empty_container);
        mMasterSwitch = view.findViewById(R.id.switch_port_mapping);
        mTvSwitchStatus = view.findViewById(R.id.tv_switch_status);
        mTvMappingCount = view.findViewById(R.id.tv_mapping_count);
        FloatingActionButton fabAdd = view.findViewById(R.id.fab_add_mapping);
        View btnEmptyAdd = view.findViewById(R.id.btn_empty_add);
        View btnExemptions = view.findViewById(R.id.btn_exemptions);

        mPortMap = new PortMapping(requireContext());
        mAdapter = new PortMappingAdapter(requireContext(), mPortMap, this);
        mListView.setAdapter(mAdapter);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
        boolean enabled = Prefs.isPortMappingEnabled(prefs);
        mMasterSwitch.setChecked(enabled);
        updateMasterSwitchUi(enabled);

        mMasterSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked == Prefs.isPortMappingEnabled(prefs))
                return;

            Log.d(TAG, "Port mapping is now " + (isChecked ? "enabled" : "disabled"));
            Prefs.setPortMappingEnabled(prefs, isChecked);
            updateMasterSwitchUi(isChecked);
            if (mMenuSwitch != null && mMenuSwitch.isChecked() != isChecked) {
                mMenuSwitch.setChecked(isChecked);
            }
            CaptureService.reloadPortMappings(requireContext());
            if (CaptureService.isServiceActive()) {
                android.widget.Toast.makeText(requireContext(), isChecked ? "Port mapping enabled & applied to active VPN" : "Port mapping disabled in active VPN", android.widget.Toast.LENGTH_LONG).show();
            }
        });

        btnExemptions.setOnClickListener(v -> startActivity(new Intent(requireContext(), PortMapExemptionsActivity.class)));
        fabAdd.setOnClickListener(v -> openAddDialog());
        btnEmptyAdd.setOnClickListener(v -> openAddDialog());

        mListView.setChoiceMode(ListView.CHOICE_MODE_MULTIPLE_MODAL);
        mListView.setMultiChoiceModeListener(new AbsListView.MultiChoiceModeListener() {
            @Override
            public void onItemCheckedStateChanged(ActionMode mode, int position, long id, boolean checked) {
                PortMap item = mAdapter.getItem(position);
                if (checked)
                    mSelected.add(item);
                else
                    mSelected.remove(item);
                mode.setTitle(getString(R.string.n_selected, mSelected.size()));
            }

            @Override
            public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                MenuInflater inflater = requireActivity().getMenuInflater();
                inflater.inflate(R.menu.list_edit_cab, menu);
                return true;
            }

            @Override
            public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                return false;
            }

            @Override
            public boolean onActionItemClicked(ActionMode mode, MenuItem menuItem) {
                int id = menuItem.getItemId();
                if (id == R.id.delete_entry) {
                    confirmDelete(mode);
                    return true;
                } else if (id == R.id.select_all) {
                    if (mSelected.size() >= mAdapter.getCount())
                        mode.finish();
                    else {
                        for (int i = 0; i < mAdapter.getCount(); i++) {
                            if (!mListView.isItemChecked(i))
                                mListView.setItemChecked(i, true);
                        }
                    }
                    return true;
                }
                return false;
            }

            @Override
            public void onDestroyActionMode(ActionMode mode) {
                mSelected = new ArrayList<>();
            }
        });

        Utils.fixListviewInsetsBottom(mListView);
        recheckListSize();
    }

    private void updateMasterSwitchUi(boolean enabled) {
        if (enabled) {
            mTvSwitchStatus.setText("Status: Enabled (Active)");
            mTvSwitchStatus.setTextColor(getResources().getColor(R.color.iconColorCapture, null));
        } else {
            mTvSwitchStatus.setText("Status: Disabled");
            mTvSwitchStatus.setTextColor(getResources().getColor(R.color.tabTextUnselected, null));
        }
    }

    private void recheckListSize() {
        int count = mAdapter.getCount();
        mEmptyContainer.setVisibility(count == 0 ? View.VISIBLE : View.GONE);
        mListView.setVisibility(count == 0 ? View.GONE : View.VISIBLE);
        mTvMappingCount.setText(getString(R.string.n_selected, count).replace("selected", "active rules"));
    }

    @Override
    public void onDelete(PortMap item) {
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.delete)
                .setMessage("Remove forwarding rule for Port " + item.orig_port + " -> " + item.redirect_host + ":" + item.redirect_port + "?")
                .setPositiveButton(R.string.delete, (d, w) -> {
                    mPortMap.remove(item);
                    mPortMap.save();
                    mAdapter.remove(item);
                    recheckListSize();
                    CaptureService.reloadPortMappings(requireContext());
                    if (CaptureService.isServiceActive()) {
                        android.widget.Toast.makeText(requireContext(), "Port " + item.orig_port + " rule removed from active VPN", android.widget.Toast.LENGTH_LONG).show();
                    }
                })
                .setNegativeButton(R.string.cancel_action, (d, w) -> d.dismiss())
                .show();
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater menuInflater) {
        menuInflater.inflate(R.menu.port_mapping_menu, menu);

        mMenuSwitch = (SwitchCompat) menu.findItem(R.id.toggle_btn).getActionView();
        if (mMenuSwitch != null) {
            mMenuSwitch.setChecked(Prefs.isPortMappingEnabled(PreferenceManager.getDefaultSharedPreferences(requireContext())));
            mMenuSwitch.setOnCheckedChangeListener((buttonView, isChecked) -> {
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
                if (isChecked == Prefs.isPortMappingEnabled(prefs))
                    return;

                Log.d(TAG, "Port mapping is now " + (isChecked ? "enabled" : "disabled"));
                Prefs.setPortMappingEnabled(prefs, isChecked);
                if (mMasterSwitch != null && mMasterSwitch.isChecked() != isChecked) {
                    mMasterSwitch.setChecked(isChecked);
                }
                updateMasterSwitchUi(isChecked);
                CaptureService.reloadPortMappings(requireContext());
                if (CaptureService.isServiceActive()) {
                    android.widget.Toast.makeText(requireContext(), isChecked ? "Port mapping enabled & applied to active VPN" : "Port mapping disabled in active VPN", android.widget.Toast.LENGTH_LONG).show();
                }
            });
        }
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem menuItem) {
        int id = menuItem.getItemId();
        if (id == R.id.add_mapping) {
            openAddDialog();
            return true;
        } else if (id == R.id.exemptions) {
            startActivity(new Intent(requireContext(), PortMapExemptionsActivity.class));
            return true;
        } else if (id == R.id.upnp_router_mapping) {
            showUpnpRouterDialog();
            return true;
        }
        return false;
    }

    private void showUpnpRouterDialog() {
        Context ctx = requireContext();
        String gw = com.kotsafe.security.ai.OfflineKnowledgeEngine.getDetectedLocalGateway(ctx);
        if (gw == null || gw.isEmpty()) gw = "192.168.1.1";
        String localIp = com.kotsafe.security.model.UpnpPortMapper.getLocalWifiIpAddress();

        new MaterialAlertDialogBuilder(ctx)
                .setTitle("⚡ Automated Router Port Mapping (UPnP / NAT-PMP)")
                .setMessage("Instruct your home Wi-Fi / ONT router to automatically forward external Port 1080 to this device:\n\n"
                        + "• Router Gateway: " + gw + "\n"
                        + "• Local IP: " + (localIp != null ? localIp : "Not connected to Wi-Fi") + "\n"
                        + "• Protocol: TCP (Port 1080)\n\n"
                        + "🔒 Ensure authentication is enabled on your proxy to prevent open-proxy scanning!")
                .setPositiveButton("⚡ Map Port 1080 Now", (d, w) -> {
                    AlertDialog progressDialog = new MaterialAlertDialogBuilder(ctx)
                            .setTitle("Broadcasting UPnP / NAT-PMP...")
                            .setMessage("Sending SSDP and NAT-PMP request to router gateway...")
                            .setCancelable(false)
                            .create();
                    progressDialog.show();

                    com.kotsafe.security.model.UpnpPortMapper.mapPortAsync(1080, (success, message) -> {
                        if (getActivity() == null) return;
                        getActivity().runOnUiThread(() -> {
                            progressDialog.dismiss();
                            new MaterialAlertDialogBuilder(ctx)
                                    .setTitle(success ? "✅ Port Forwarding Succeeded!" : "⚠️ Router Response")
                                    .setMessage(message)
                                    .setPositiveButton(R.string.ok, null)
                                    .show();
                        });
                    });
                })
                .setNegativeButton(R.string.cancel_action, null)
                .show();
    }

    private void openAddDialog() {
        Context ctx = requireContext();
        LayoutInflater inflater = LayoutInflater.from(ctx);
        View view = inflater.inflate(R.layout.add_port_mapping_dialog, null);

        final String[] protocols = {"TCP", "UDP"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(ctx, R.layout.dropdown_item, protocols);
        AutoCompleteTextView protoField = view.findViewById(R.id.proto);
        protoField.setText(protocols[0]);
        protoField.setAdapter(adapter);

        TextInputEditText origPortField = view.findViewById(R.id.orig_port);
        TextInputEditText redirectHostField = view.findViewById(R.id.redirect_host);
        TextInputEditText redirectPortField = view.findViewById(R.id.redirect_port);

        redirectHostField.setText("127.0.0.1");

        // Wire Quick Presets
        Chip chipBurp = view.findViewById(R.id.preset_burp);
        Chip chipMitm = view.findViewById(R.id.preset_mitmproxy);
        Chip chipDns = view.findViewById(R.id.preset_dns);
        Chip chipTor = view.findViewById(R.id.preset_tor);
        Chip chipSocks = view.findViewById(R.id.preset_socks5);

        if (chipBurp != null) {
            chipBurp.setOnClickListener(v -> {
                protoField.setText("TCP");
                origPortField.setText("8080");
                redirectHostField.setText("127.0.0.1");
                redirectPortField.setText("8080");
            });
        }
        if (chipMitm != null) {
            chipMitm.setOnClickListener(v -> {
                protoField.setText("TCP");
                origPortField.setText("8080");
                redirectHostField.setText("127.0.0.1");
                redirectPortField.setText("8080");
            });
        }
        if (chipDns != null) {
            chipDns.setOnClickListener(v -> {
                protoField.setText("UDP");
                origPortField.setText("53");
                redirectHostField.setText("127.0.0.1");
                redirectPortField.setText("5353");
            });
        }
        if (chipTor != null) {
            chipTor.setOnClickListener(v -> {
                protoField.setText("TCP");
                origPortField.setText("9050");
                redirectHostField.setText("127.0.0.1");
                redirectPortField.setText("9050");
            });
        }
        if (chipSocks != null) {
            chipSocks.setOnClickListener(v -> {
                protoField.setText("TCP");
                origPortField.setText("1080");
                redirectHostField.setText("127.0.0.1");
                redirectPortField.setText("1080");
            });
        }

        AlertDialog dialog = new MaterialAlertDialogBuilder(ctx)
                .setView(view)
                .setTitle(R.string.port_mapping)
                .setIcon(R.drawable.ic_swap_horiz)
                .setPositiveButton(R.string.add_action, (dialogInterface, i) -> {})
                .setNegativeButton(R.string.cancel_action, (dialogInterface, i) -> {})
                .create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();

        dialog.getButton(AlertDialog.BUTTON_POSITIVE)
                .setOnClickListener(v -> {
                    PortMap mapping = validateAddDialog(view);
                    if (mapping == null)
                        return;

                    boolean exists = !mPortMap.add(mapping);
                    if (exists)
                        Utils.showToastLong(requireContext(), R.string.port_mapping_exists);
                    else {
                        mPortMap.save();
                        mAdapter.add(mapping);
                        recheckListSize();
                        CaptureService.reloadPortMappings(requireContext());
                        if (CaptureService.isServiceActive()) {
                            android.widget.Toast.makeText(requireContext(), "Port " + mapping.orig_port + " redirection applied to active VPN!", android.widget.Toast.LENGTH_LONG).show();
                        }

                        if (!Prefs.isPortMappingEnabled(PreferenceManager.getDefaultSharedPreferences(requireContext())))
                            Utils.showToastLong(requireContext(), R.string.port_mapping_disabled_reminder);
                    }

                    dialog.dismiss();
                });
    }

    private PortMap validateAddDialog(View view) {
        TextInputEditText origPortField = view.findViewById(R.id.orig_port);
        TextInputEditText redirectHostField = view.findViewById(R.id.redirect_host);
        TextInputEditText redirectPortField = view.findViewById(R.id.redirect_port);

        String origPort = Objects.requireNonNull(origPortField.getText()).toString().trim();
        String redirectHost = Objects.requireNonNull(redirectHostField.getText()).toString().trim();
        String redirectPort = Objects.requireNonNull(redirectPortField.getText()).toString().trim();
        String proto = ((AutoCompleteTextView) view.findViewById(R.id.proto)).getText().toString();

        if (origPort.isEmpty()) {
            origPortField.setError(getString(R.string.required));
            return null;
        }
        if (!Utils.validatePort(origPort)) {
            origPortField.setError(getString(R.string.invalid));
            return null;
        }

        if (redirectHost.isEmpty()) {
            redirectHostField.setError(getString(R.string.required));
            return null;
        }

        if (redirectPort.isEmpty()) {
            redirectPortField.setError(getString(R.string.required));
            return null;
        }
        if (!Utils.validatePort(redirectPort)) {
            redirectPortField.setError(getString(R.string.invalid));
            return null;
        }

        int origPortInt = Integer.parseInt(origPort);
        int redirectPortInt = Integer.parseInt(redirectPort);
        int protoInt = proto.equals("TCP") ? 6 : 17;

        return new PortMap(protoInt, origPortInt, redirectPortInt, redirectHost);
    }

    private void confirmDelete(ActionMode mode) {
        new MaterialAlertDialogBuilder(requireContext())
                .setTitle(R.string.delete)
                .setMessage(R.string.items_delete_confirm)
                .setPositiveButton(R.string.delete, (dialogInterface, i) -> {
                    deleteSelected();
                    mode.finish();
                })
                .setNegativeButton(R.string.cancel_action, (dialogInterface, i) -> {})
                .show();
    }

    private void deleteSelected() {
        if (mSelected.size() >= mAdapter.getCount()) {
            mAdapter.clear();
            mPortMap.clear();
        } else {
            for (PortMap item : mSelected) {
                mAdapter.remove(item);
                mPortMap.remove(item);
            }
        }
        mPortMap.save();
        recheckListSize();
    }
}
