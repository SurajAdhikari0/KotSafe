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
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.content.res.AppCompatResources;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.MitmSetupWizard;
import com.google.android.material.button.MaterialButton;

public class StepFragment extends Fragment {
    protected TextView mStepTitle;
    protected TextView mStepBadge;
    protected TextView mStepLabel;
    protected ImageView mStepIcon;
    protected View mCardDetails;
    protected TextView mTvDetailsTitle;
    protected TextView mTvDetailsContent;
    protected MaterialButton mBtnRootAction;
    protected Button mStepButton;
    protected Button mSkipButton;
    protected NavController mNavController;
    protected int mOkColor;
    protected int mWarnColor;
    protected int mDangerColor;

    public StepFragment() {}

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container,
                             Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_mitm_wizard, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        mNavController = Navigation.findNavController(view);

        mStepTitle = view.findViewById(R.id.step_title);
        mStepBadge = view.findViewById(R.id.step_badge);
        mStepLabel = view.findViewById(R.id.step_label);
        mStepIcon = view.findViewById(R.id.step_status);
        mCardDetails = view.findViewById(R.id.card_details_box);
        mTvDetailsTitle = view.findViewById(R.id.tv_details_title);
        mTvDetailsContent = view.findViewById(R.id.tv_details_content);
        mBtnRootAction = view.findViewById(R.id.btn_root_action);
        mStepButton = view.findViewById(R.id.step_button);
        mSkipButton = view.findViewById(R.id.skip_button);

        Context ctx = requireContext();
        mOkColor = ContextCompat.getColor(ctx, R.color.ok);
        mWarnColor = ContextCompat.getColor(ctx, R.color.warning);
        mDangerColor = ContextCompat.getColor(ctx, R.color.danger);
    }

    protected void setStepperStep(int step) {
        if (getActivity() instanceof MitmSetupWizard) {
            ((MitmSetupWizard) getActivity()).setStep(step);
        }
    }

    protected void gotoStep(int action_or_dest) {
        boolean is_last_step = (action_or_dest <= 0);

        if(!is_last_step)
            mNavController.navigate(action_or_dest);
        else
            requireActivity().finish();
    }

    protected void nextStep(int action_or_dest) {
        Context ctx = requireContext();
        boolean is_last_step = (action_or_dest <= 0);
        if (mStepIcon != null) {
            mStepIcon.setImageDrawable(AppCompatResources.getDrawable(ctx, R.drawable.ic_check_solid));
            mStepIcon.setColorFilter(mOkColor);
        }

        if (mSkipButton != null) {
            mSkipButton.setVisibility(View.GONE);
        }
        if (mStepButton != null) {
            mStepButton.setEnabled(true);
            mStepButton.setText(!is_last_step ? R.string.app_intro_next_button : R.string.app_intro_done_button);
            mStepButton.setOnClickListener((view) -> gotoStep(action_or_dest));
        }
    }

    protected void showSkipButton(View.OnClickListener l) {
        if (mSkipButton != null) {
            mSkipButton.setVisibility(View.VISIBLE);
            mSkipButton.setOnClickListener(l);
        }
    }
}
