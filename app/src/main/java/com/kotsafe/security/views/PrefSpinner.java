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

package com.kotsafe.security.views;

import android.content.Context;
import android.content.SharedPreferences;
import android.view.View;
import android.widget.AdapterView;
import android.widget.Spinner;

import androidx.preference.PreferenceManager;

import com.kotsafe.security.adapters.PrefSpinnerAdapter;

public class PrefSpinner implements AdapterView.OnItemSelectedListener {
    private final SharedPreferences mPrefs;
    private final PrefSpinnerAdapter mAdapter;
    private final String mPrefKey;

    private PrefSpinner(Spinner spinner, int keysRes, int labelsRes, int descrRes, String prefKey, String prefDefault) {
        Context context = spinner.getContext();
        mPrefs = PreferenceManager.getDefaultSharedPreferences(context);
        mPrefKey = prefKey;
        mAdapter = new PrefSpinnerAdapter(context, keysRes, labelsRes, descrRes);

        int curSel = mAdapter.getModePos(mPrefs.getString(prefKey, prefDefault));
        spinner.setAdapter(mAdapter);
        spinner.setSelection(curSel);
        spinner.setOnItemSelectedListener(this);
    }

    public static void init(Spinner spinner, int keysRes, int labelsRes, int descrRes, String prefKey, String prefDefault) {
        new PrefSpinner(spinner, keysRes, labelsRes, descrRes, prefKey, prefDefault);
    }

    @Override
    public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
        PrefSpinnerAdapter.ModeInfo mode = (PrefSpinnerAdapter.ModeInfo) mAdapter.getItem(position);
        SharedPreferences.Editor editor = mPrefs.edit();

        editor.putString(mPrefKey, mode.key);
        editor.apply();
    }

    @Override
    public void onNothingSelected(AdapterView<?> parent) {}
}
