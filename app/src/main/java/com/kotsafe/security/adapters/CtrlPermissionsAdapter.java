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

package com.kotsafe.security.adapters;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.util.ArrayMap;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.R;
import com.kotsafe.security.interfaces.TextAdapter;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.CtrlPermissions;
import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class CtrlPermissionsAdapter extends ArrayAdapter<CtrlPermissions.Rule> implements TextAdapter {
    public interface RuleActionListener {
        void onToggleConsent(CtrlPermissions.Rule rule);
        void onDeleteRule(CtrlPermissions.Rule rule);
    }

    private final LayoutInflater mLayoutInflater;
    private final CtrlPermissions mPermissions;
    private final Context mContext;
    private final ArrayMap<String, AppDescriptor> mPkgToApp = new ArrayMap<>();
    private final RuleActionListener mListener;

    public CtrlPermissionsAdapter(Context context, CtrlPermissions perms, RuleActionListener listener) {
        super(context, R.layout.item_ctrl_permission);
        mLayoutInflater = LayoutInflater.from(context);
        mPermissions = perms;
        mContext = context;
        mListener = listener;
        reload();
    }

    public void reload() {
        clear();
        mPkgToApp.clear();
        PackageManager pm = mContext.getPackageManager();
        Iterator<CtrlPermissions.Rule> it = mPermissions.iterRules();
        List<CtrlPermissions.Rule> sorted = new ArrayList<>();

        while (it.hasNext()) {
            CtrlPermissions.Rule rule = it.next();
            AppDescriptor app = AppsResolver.resolveInstalledApp(pm, rule.package_name, 0);
            if (app != null)
                mPkgToApp.put(rule.package_name, app);

            sorted.add(rule);
        }

        Collections.sort(sorted, (o1, o2) -> {
            AppDescriptor app1 = mPkgToApp.get(o1.package_name);
            AppDescriptor app2 = mPkgToApp.get(o2.package_name);
            String name1 = (app1 != null) ? app1.getName() : o1.package_name;
            String name2 = (app2 != null) ? app2.getName() : o2.package_name;
            return name1.compareToIgnoreCase(name2);
        });

        addAll(sorted);
        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
        if (convertView == null)
            convertView = mLayoutInflater.inflate(R.layout.item_ctrl_permission, parent, false);

        CtrlPermissions.Rule rule = getItem(position);
        if (rule == null)
            return convertView;

        ImageView ivIcon = convertView.findViewById(R.id.app_icon);
        TextView tvName = convertView.findViewById(R.id.app_name);
        TextView tvPackage = convertView.findViewById(R.id.package_name);
        MaterialButton btnStatus = convertView.findViewById(R.id.btn_permission_status);
        ImageView btnDelete = convertView.findViewById(R.id.btn_delete_rule);

        AppDescriptor app = mPkgToApp.get(rule.package_name);
        if (app != null) {
            tvName.setText(app.getName());
            tvPackage.setText(app.getPackageName());
            ivIcon.setImageDrawable(app.getIcon());
        } else {
            tvName.setText(rule.package_name);
            tvPackage.setText(rule.package_name);
            ivIcon.setImageResource(R.drawable.ic_apps);
        }

        boolean isAllowed = (rule.consent == CtrlPermissions.ConsentType.ALLOW);
        if (isAllowed) {
            btnStatus.setText(R.string.allow);
            btnStatus.setTextColor(ContextCompat.getColor(mContext, R.color.iconColorCapture));
            btnStatus.setBackgroundColor(ContextCompat.getColor(mContext, R.color.catBgCapture));
            btnStatus.setStrokeColor(ColorStateList.valueOf(ContextCompat.getColor(mContext, R.color.iconColorCapture)));
        } else {
            btnStatus.setText(R.string.deny);
            btnStatus.setTextColor(ContextCompat.getColor(mContext, R.color.iconColorFirewall));
            btnStatus.setBackgroundColor(ContextCompat.getColor(mContext, R.color.catBgFirewall));
            btnStatus.setStrokeColor(ColorStateList.valueOf(ContextCompat.getColor(mContext, R.color.iconColorFirewall)));
        }

        btnStatus.setOnClickListener(v -> {
            if (mListener != null)
                mListener.onToggleConsent(rule);
        });

        btnDelete.setOnClickListener(v -> {
            if (mListener != null)
                mListener.onDeleteRule(rule);
        });

        return convertView;
    }

    @Override
    public String getItemText(int pos) {
        CtrlPermissions.Rule rule = getItem(pos);
        return rule != null ? rule.package_name : "";
    }
}
