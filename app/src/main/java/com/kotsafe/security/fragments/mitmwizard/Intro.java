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
import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.MitmAddon;
import com.kotsafe.security.R;

public class Intro extends StepFragment {
    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        setStepperStep(1);

        if (mStepTitle != null) {
            mStepTitle.setText("HTTPS & TLS Decryption");
        }
        if (mStepBadge != null) {
            mStepBadge.setText("STEP 1 OF 4 • OVERVIEW");
        }
        if (mStepLabel != null) {
            mStepLabel.setText("Modern mobile traffic is encrypted. Enable TLS decryption to inspect cleartext API requests, HTTP headers, authentication tokens, and browser activity.");
        }
        if (mStepIcon != null) {
            mStepIcon.setImageResource(R.drawable.ic_pref_tls);
        }

        if (mCardDetails != null) {
            mCardDetails.setVisibility(View.VISIBLE);
            if (mTvDetailsTitle != null) {
                mTvDetailsTitle.setText("What You Will Unlock:");
            }
            if (mTvDetailsContent != null) {
                mTvDetailsContent.setText(
                        "• Full HTTP URLs with query parameters & tracker tokens\n" +
                        "• Pretty-printed JSON & Form payload inspection\n" +
                        "• Authorization & Cookie security headers\n" +
                        "• Cleartext Browser Activity and DoH/Protobuf decoding"
                );
            }
        }

        if (mStepButton != null) {
            mStepButton.setText("Get Started");
            mStepButton.setOnClickListener(v -> routeToIntelligentNextStep());
        }
    }

    private void routeToIntelligentNextStep() {
        Context ctx = getContext();
        if (ctx == null) return;

        boolean isAddonInstalled = MitmAddon.isInstalled(ctx);
        String newVer = MitmAddon.getNewVersionAvailable(ctx);

        if (!isAddonInstalled || !newVer.isEmpty()) {
            // Add-on missing or needs update -> Go to Add-on step
            gotoStep(R.id.navto_install_addon);
        } else {
            // Add-on is already ready -> Advance to Certificate step
            gotoStep(R.id.navto_install_cert);
        }
    }
}