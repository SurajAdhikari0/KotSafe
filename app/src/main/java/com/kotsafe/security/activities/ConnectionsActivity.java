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

import android.os.Bundle;

import com.kotsafe.security.R;
import com.kotsafe.security.fragments.ConnectionsFragment;

public class ConnectionsActivity extends BaseActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.connections_view);
        displayBackAction(); // Use explicit back to restore the AppDetailsActivity state
        setContentView(R.layout.fragment_activity);

        getSupportFragmentManager().beginTransaction()
                .replace(R.id.fragment, new ConnectionsFragment())
                .commit();
    }
}
