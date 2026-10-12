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

package com.kotsafe.security.fragments.mitmwizard;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.content.res.AppCompatResources;

import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;

public class InstallAddon extends StepFragment {

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        setStepperStep(2);

        if (mStepTitle != null) {
            mStepTitle.setText("Install Companion Add-on");
        }
        if (mStepIcon != null) {
            mStepIcon.setImageResource(R.drawable.ic_apps);
        }

        checkAddonState();
    }

    @Override
    public void onResume() {
        super.onResume();
        checkAddonState();
    }

    private void checkAddonState() {
        Context ctx = getContext();
        if (ctx == null) return;

        boolean isInstalled = MitmAddon.isInstalled(ctx);
        String installedVer = MitmAddon.getInstalledVersionName(ctx);
        String newVer = MitmAddon.getNewVersionAvailable(ctx);

        if (isInstalled && newVer.isEmpty()) {
            // Already installed & up to date
            onAddonReady(installedVer);
        } else if (isInstalled && !newVer.isEmpty()) {
            // Update available
            onAddonUpdateAvailable(installedVer, newVer);
        } else {
            // Not installed
            onAddonMissing();
        }
    }

    private void onAddonReady(String version) {
        if (mStepBadge != null) {
            mStepBadge.setText("INSTALLED (v" + version + ")");
            mStepBadge.setTextColor(Color.parseColor("#10B981"));
        }
        if (mStepLabel != null) {
            mStepLabel.setText("Companion MITM Add-on is installed and verified. The background decryption proxy daemon is ready.");
        }
        if (mStepIcon != null) {
            mStepIcon.setImageDrawable(AppCompatResources.getDrawable(requireContext(), R.drawable.ic_check_solid));
            mStepIcon.setColorFilter(mOkColor);
        }

        if (mCardDetails != null) {
            mCardDetails.setVisibility(View.VISIBLE);
            if (mTvDetailsTitle != null) {
                mTvDetailsTitle.setText("Daemon Status: Ready");
            }
            if (mTvDetailsContent != null) {
                mTvDetailsContent.setText("• Package: com.pcapdroid.mitm\n• Version: " + version + "\n• Local SOCKS5 decryption proxy enabled");
            }
        }

        if (mSkipButton != null) {
            mSkipButton.setVisibility(View.GONE);
        }

        if (mStepButton != null) {
            mStepButton.setEnabled(true);
            mStepButton.setText("Next: Certificate Setup");
            mStepButton.setOnClickListener(v -> gotoStep(R.id.navto_install_cert));
        }
    }

    private void onAddonMissing() {
        if (mStepBadge != null) {
            mStepBadge.setText("STEP 2 OF 4 • REQUIRED");
            mStepBadge.setTextColor(Color.parseColor("#EF4444"));
        }
        if (mStepLabel != null) {
            mStepLabel.setText("The MITM Add-on is a companion package running an isolated local proxy. It decrypts TLS payloads and streams cleartext to KotSafe.");
        }

        if (mCardDetails != null) {
            mCardDetails.setVisibility(View.VISIBLE);
            if (mTvDetailsTitle != null) {
                mTvDetailsTitle.setText("Download Information:");
            }
            if (mTvDetailsContent != null) {
                mTvDetailsContent.setText(
                        "• Package: com.pcapdroid.mitm\n" +
                        "• Minimum Version: v" + MitmAddon.PACKAGE_VERSION_NAME + "\n" +
                        "• Official Source: GitHub Releases (KotSafe Security)\n" +
                        "• Safe, open-source local proxy"
                );
            }
        }

        showSkipButton(v -> gotoStep(R.id.navto_install_cert));

        if (mStepButton != null) {
            mStepButton.setEnabled(true);
            mStepButton.setText("Download MITM Add-on APK");
            mStepButton.setOnClickListener(v -> {
                Intent browserIntent = new Intent(Intent.ACTION_VIEW,
                        Uri.parse(MitmAddon.getGithubReleaseUrl(MitmAddon.PACKAGE_VERSION_NAME)));
                Utils.startActivity(requireContext(), browserIntent);
            });
        }
    }

    private void onAddonUpdateAvailable(String currentVer, String newVer) {
        if (mStepBadge != null) {
            mStepBadge.setText("UPDATE RECOMMENDED");
            mStepBadge.setTextColor(Color.parseColor("#F59E0B"));
        }
        if (mStepLabel != null) {
            mStepLabel.setText("A newer version (v" + newVer + ") of the MITM Add-on is available. You currently have v" + currentVer + ".");
        }

        showSkipButton(v -> gotoStep(R.id.navto_install_cert));

        if (mStepButton != null) {
            mStepButton.setEnabled(true);
            mStepButton.setText("Update MITM Add-on");
            mStepButton.setOnClickListener(v -> {
                Intent browserIntent = new Intent(Intent.ACTION_VIEW,
                        Uri.parse(MitmAddon.getGithubReleaseUrl(newVer)));
                Utils.startActivity(requireContext(), browserIntent);
            });
        }
    }
}
