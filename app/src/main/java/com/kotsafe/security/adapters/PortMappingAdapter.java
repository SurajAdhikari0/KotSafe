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

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.PortMapping;
import com.kotsafe.security.model.PortMapping.PortMap;

import java.util.Iterator;

public class PortMappingAdapter extends ArrayAdapter<PortMap> {
    public interface OnPortMapActionListener {
        void onDelete(PortMap item);
    }

    private final LayoutInflater mLayoutInflater;
    private final PortMapping mMappings;
    private OnPortMapActionListener mListener;

    public PortMappingAdapter(Context context, PortMapping mappings) {
        this(context, mappings, null);
    }

    public PortMappingAdapter(Context context, PortMapping mappings, OnPortMapActionListener listener) {
        super(context, R.layout.port_mapping_item);
        mLayoutInflater = LayoutInflater.from(context);
        mMappings = mappings;
        mListener = listener;
        reload();
    }

    public void setListener(OnPortMapActionListener listener) {
        mListener = listener;
    }

    @SuppressLint("SetTextI18n")
    @NonNull
    @Override
    public View getView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
        if (convertView == null)
            convertView = mLayoutInflater.inflate(R.layout.port_mapping_item, parent, false);

        PortMap mapping = getItem(position);
        if (mapping == null)
            return convertView;

        TextView tvProto = convertView.findViewById(R.id.proto);
        TextView tvOrigPort = convertView.findViewById(R.id.orig_port);
        TextView tvRedirectTo = convertView.findViewById(R.id.redirect_to);
        ImageView btnDelete = convertView.findViewById(R.id.btn_delete_mapping);

        String protoStr = Utils.proto2str(mapping.ipproto);
        tvProto.setText(protoStr);

        if ("UDP".equalsIgnoreCase(protoStr)) {
            tvProto.setTextColor(ContextCompat.getColor(getContext(), R.color.iconColorCapture));
        } else {
            tvProto.setTextColor(ContextCompat.getColor(getContext(), R.color.iconColorHttp));
        }

        tvOrigPort.setText(Integer.toString(mapping.orig_port));
        tvRedirectTo.setText(getContext().getString(R.string.ip_and_port, mapping.redirect_host, mapping.redirect_port));

        if (btnDelete != null) {
            btnDelete.setOnClickListener(v -> {
                if (mListener != null)
                    mListener.onDelete(mapping);
            });
        }

        return convertView;
    }

    public void reload() {
        clear();
        Iterator<PortMap> iterator = mMappings.iter();
        while (iterator.hasNext()) {
            PortMap item = iterator.next();
            add(item);
        }
        notifyDataSetChanged();
    }
}
