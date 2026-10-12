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

package com.kotsafe.security.activities;

import android.content.res.ColorStateList;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.widget.Toolbar;

import com.kotsafe.security.R;

public class MitmSetupWizard extends BaseActivity {
    private TextView[] mStepDots;
    private TextView[] mStepTexts;
    private View[] mStepLines;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.mitm_wizard_activity);
        setTitle(R.string.mitm_setup_wizard);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            setSupportActionBar(toolbar);
            displayBackAction();
        }

        mStepDots = new TextView[]{
                findViewById(R.id.step_dot_1),
                findViewById(R.id.step_dot_2),
                findViewById(R.id.step_dot_3),
                findViewById(R.id.step_dot_4)
        };

        mStepTexts = new TextView[]{
                findViewById(R.id.step_text_1),
                findViewById(R.id.step_text_2),
                findViewById(R.id.step_text_3),
                findViewById(R.id.step_text_4)
        };

        mStepLines = new View[]{
                findViewById(R.id.step_line_1),
                findViewById(R.id.step_line_2),
                findViewById(R.id.step_line_3)
        };

        setStep(1);
    }

    public void setStep(int step) { // step: 1, 2, 3, 4
        if (mStepDots == null) return;

        int activeColor = Color.parseColor("#0EA5E9");   // Cyan/Sky
        int completedColor = Color.parseColor("#10B981"); // Green
        int inactiveColor = Color.parseColor("#334155");  // Dark Slate
        int inactiveText = Color.parseColor("#64748B");   // Muted Slate

        for (int i = 0; i < 4; i++) {
            int stepNum = i + 1;
            TextView dot = mStepDots[i];
            TextView text = mStepTexts[i];
            if (dot == null || text == null) continue;

            if (stepNum < step) {
                // Completed step
                dot.setText("✓");
                dot.setTextColor(Color.WHITE);
                dot.setBackgroundTintList(ColorStateList.valueOf(completedColor));
                text.setTextColor(completedColor);
            } else if (stepNum == step) {
                // Active current step
                dot.setText(String.valueOf(stepNum));
                dot.setTextColor(Color.WHITE);
                dot.setBackgroundTintList(ColorStateList.valueOf(activeColor));
                text.setTextColor(activeColor);
            } else {
                // Inactive future step
                dot.setText(String.valueOf(stepNum));
                dot.setTextColor(Color.parseColor("#94A3B8"));
                dot.setBackgroundTintList(ColorStateList.valueOf(inactiveColor));
                text.setTextColor(inactiveText);
            }
        }

        // Connecting lines
        for (int i = 0; i < 3; i++) {
            View line = mStepLines[i];
            if (line == null) continue;
            if (i + 1 < step) {
                line.setBackgroundColor(completedColor);
            } else {
                line.setBackgroundColor(inactiveColor);
            }
        }
    }
}
