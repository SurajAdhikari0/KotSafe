package com.kotsafe.security.activities;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.view.MenuItem;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.Toolbar;

import com.kotsafe.security.R;
import com.kotsafe.security.model.PhysicalSecurityManager;
import com.kotsafe.security.receivers.DeviceAdminReceiverImpl;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.switchmaterial.SwitchMaterial;

public class PhysicalSecurityActivity extends BaseActivity {
    private static final String TAG = "PhysicalSecActivity";
    private static final int REQ_ENABLE_ADMIN = 1001;

    private PhysicalSecurityManager mManager;

    private SwitchMaterial mSwitchMaster;
    private TextView mTvMasterStatus;
    private TextView mTvPinStatus;
    private MaterialButton mBtnSetupPin;
    private SwitchMaterial mSwitchKotSafeAppLock;
    private SwitchMaterial mSwitchBiometric;

    private SwitchMaterial mSwitchChargerAlarm;
    private SwitchMaterial mSwitchPocketAlarm;
    private SwitchMaterial mSwitchAntiTheft;
    private MaterialButton mBtnPanicLock;
    private SwitchMaterial mSwitchTamperProtect;
    private SwitchMaterial mSwitchBadUsbAutoLock;
    private SwitchMaterial mSwitchScreenshotProtect;
    private TextView mTvScreenshotAppsCount;
    private MaterialButton mBtnManageScreenshotApps;
    private SwitchMaterial mSwitchSimSwap;
    private MaterialButton mBtnUpdateSimBaseline;
    private SwitchMaterial mSwitchFirewallLockdown;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_physical_security);

        mManager = PhysicalSecurityManager.getInstance(this);

        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle(R.string.physical_security_title);
        }

        initViews();
        updateUI();
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateUI();
    }

    private void initViews() {
        mSwitchMaster = findViewById(R.id.switch_master_security);
        mTvMasterStatus = findViewById(R.id.tv_master_status);
        mTvPinStatus = findViewById(R.id.tv_pin_status);
        mBtnSetupPin = findViewById(R.id.btn_setup_pin);

        mSwitchKotSafeAppLock = findViewById(R.id.switch_kotsafe_app_lock);
        mSwitchBiometric = findViewById(R.id.switch_biometric);

        mSwitchChargerAlarm = findViewById(R.id.switch_charger_alarm);
        mSwitchPocketAlarm = findViewById(R.id.switch_pocket_alarm);

        mSwitchAntiTheft = findViewById(R.id.switch_anti_theft);
        mBtnPanicLock = findViewById(R.id.btn_panic_lock);
        mSwitchTamperProtect = findViewById(R.id.switch_tamper_protect);
        mSwitchBadUsbAutoLock = findViewById(R.id.switch_bad_usb_auto_lock);
        mSwitchScreenshotProtect = findViewById(R.id.switch_screenshot_protect);
        mTvScreenshotAppsCount   = findViewById(R.id.tv_screenshot_apps_count);
        mBtnManageScreenshotApps = findViewById(R.id.btn_manage_screenshot_apps);
        mSwitchSimSwap = findViewById(R.id.switch_sim_swap);
        mBtnUpdateSimBaseline = findViewById(R.id.btn_update_sim_baseline);
        mSwitchFirewallLockdown = findViewById(R.id.switch_firewall_lockdown);

        mSwitchMaster.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setMasterSecurityEnabled(isChecked);
            updateUI();
        });

        mBtnSetupPin.setOnClickListener(v -> showPinSetupDialog());

        mSwitchKotSafeAppLock.setOnCheckedChangeListener((btn, isChecked) -> {
            if (isChecked && !mManager.isPinSet()) {
                mSwitchKotSafeAppLock.setChecked(false);
                Toast.makeText(this, "Please set Master PIN first", Toast.LENGTH_SHORT).show();
                showPinSetupDialog();
                return;
            }
            mManager.setKotSafeAppLockEnabled(isChecked);
        });

        mSwitchBiometric.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setBiometricEnabled(isChecked);
        });

        mSwitchChargerAlarm.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setChargerAlarmEnabled(isChecked);
        });

        mSwitchPocketAlarm.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setPocketAlarmEnabled(isChecked);
        });

        mSwitchAntiTheft.setOnCheckedChangeListener((btn, isChecked) -> {
            if (isChecked && !mManager.isDeviceAdminActive()) {
                requestDeviceAdmin();
            }
            mManager.setAntiTheftEnabled(isChecked);
        });

        mBtnPanicLock.setOnClickListener(v -> {
            if (mManager.isDeviceAdminActive()) {
                mManager.lockDeviceNow();
            } else {
                Toast.makeText(this, "Device Admin permission required for panic lock", Toast.LENGTH_SHORT).show();
                requestDeviceAdmin();
            }
        });

        mSwitchTamperProtect.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setTamperProtectionEnabled(isChecked);
        });

        mSwitchBadUsbAutoLock.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setBadUsbAutoLockEnabled(isChecked);
        });

        mSwitchScreenshotProtect.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setScreenshotProtectionEnabled(isChecked);
            if (isChecked) {
                getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
            } else {
                getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
            }
        });

        mBtnManageScreenshotApps.setOnClickListener(v ->
                startActivity(new Intent(this, ScreenshotProtectedAppsActivity.class)));

        mSwitchSimSwap.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setSimSwapDetectionEnabled(isChecked);
            if (isChecked) mManager.updateSimBaseline();
        });

        mBtnUpdateSimBaseline.setOnClickListener(v -> {
            mManager.updateSimBaseline();
            Toast.makeText(this, "SIM baseline updated", Toast.LENGTH_SHORT).show();
        });

        mSwitchFirewallLockdown.setOnCheckedChangeListener((btn, isChecked) -> {
            mManager.setFirewallLockdownEnabled(isChecked);
        });
    }

    private void updateUI() {
        boolean master = mManager.isMasterSecurityEnabled();
        boolean pinSet = mManager.isPinSet();

        mSwitchMaster.setChecked(master);
        mTvMasterStatus.setText(master ? R.string.physical_security_enabled : R.string.physical_security_disabled);
        mTvMasterStatus.setTextColor(master ? 0xFF00E676 : 0xFF888888);

        mTvPinStatus.setText(pinSet ? R.string.physical_security_pin_set : R.string.physical_security_pin_not_set);
        mBtnSetupPin.setText(pinSet ? R.string.physical_security_change_pin : R.string.physical_security_set_pin);

        mSwitchKotSafeAppLock.setEnabled(master);
        mSwitchKotSafeAppLock.setChecked(mManager.isKotSafeAppLockEnabled());

        mSwitchBiometric.setEnabled(master);
        mSwitchBiometric.setChecked(mManager.isBiometricEnabled());

        mSwitchChargerAlarm.setEnabled(master);
        mSwitchChargerAlarm.setChecked(mManager.isChargerAlarmEnabled());

        mSwitchPocketAlarm.setEnabled(master);
        mSwitchPocketAlarm.setChecked(mManager.isPocketAlarmEnabled());

        mSwitchAntiTheft.setEnabled(master);
        mSwitchAntiTheft.setChecked(mManager.isAntiTheftEnabled());

        mSwitchTamperProtect.setEnabled(master);
        mSwitchTamperProtect.setChecked(mManager.isTamperProtectionEnabled());

        if (mSwitchBadUsbAutoLock != null) {
            mSwitchBadUsbAutoLock.setEnabled(master);
            mSwitchBadUsbAutoLock.setChecked(mManager.isBadUsbAutoLockEnabled());
        }

        mSwitchScreenshotProtect.setEnabled(master);
        mSwitchScreenshotProtect.setChecked(mManager.isScreenshotProtectionEnabled());
        int protectedCount = mManager.getScreenshotProtectedPackages().size();
        if (mTvScreenshotAppsCount != null) {
            mTvScreenshotAppsCount.setText(protectedCount == 0
                    ? "No apps protected" : protectedCount + " app" + (protectedCount == 1 ? "" : "s") + " protected");
        }
        if (mBtnManageScreenshotApps != null) mBtnManageScreenshotApps.setEnabled(master);

        mSwitchSimSwap.setEnabled(master);
        mSwitchSimSwap.setChecked(mManager.isSimSwapDetectionEnabled());

        mSwitchFirewallLockdown.setEnabled(master);
        mSwitchFirewallLockdown.setChecked(mManager.isFirewallLockdownEnabled());
    }

    private void showPinSetupDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle(mManager.isPinSet() ? "Change Security PIN" : "Set Security PIN");

        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        input.setHint("Enter 4 to 8 digit PIN");
        builder.setView(input);

        builder.setPositiveButton("Save", (dialog, which) -> {
            String pin = input.getText().toString().trim();
            if (pin.length() < 4) {
                Toast.makeText(this, "PIN must be at least 4 digits", Toast.LENGTH_SHORT).show();
            } else {
                if (mManager.setPin(pin)) {
                    Toast.makeText(this, "Security PIN configured successfully", Toast.LENGTH_SHORT).show();
                    updateUI();
                } else {
                    Toast.makeText(this, "Error setting PIN", Toast.LENGTH_SHORT).show();
                }
            }
        });
        builder.setNegativeButton("Cancel", (dialog, which) -> dialog.cancel());
        builder.show();
    }

    @SuppressWarnings("deprecation")
    private void requestDeviceAdmin() {
        ComponentName adminComponent = new ComponentName(this, DeviceAdminReceiverImpl.class);
        Intent intent = new Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN);
        intent.putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminComponent);
        intent.putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "Device Admin permission is required for emergency panic lock and anti-theft controls.");
        startActivityForResult(intent, REQ_ENABLE_ADMIN);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
