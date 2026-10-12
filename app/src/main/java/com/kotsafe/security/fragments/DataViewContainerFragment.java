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

package com.kotsafe.security.fragments;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.TooltipCompat;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.Lifecycle;

import com.kotsafe.security.CaptureService;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.FilterDescriptor;
import com.google.android.material.tabs.TabLayout;

public class DataViewContainerFragment extends Fragment implements MenuProvider {
    private static final String TAG = "DataViewContainer";
    private static final String STATE_CURRENT_VIEW = "current_view";

    public static final int VIEW_CONNECTIONS = 0;
    public static final int VIEW_HTTP_LOG = 1;
    public static final int VIEW_HTTP_REPEATER = 2;

    private static final int TAB_POSITION = 1;

    private int mCurrentView = VIEW_CONNECTIONS;
    private Fragment mConnectionsFragment;
    private Fragment mHttpLogFragment;
    private Fragment mHttpRepeaterFragment;
    private OnBackPressedCallback mBackCallback;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (savedInstanceState != null) {
            mCurrentView = savedInstanceState.getInt(STATE_CURRENT_VIEW, VIEW_CONNECTIONS);
        }
    }

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        requireActivity().addMenuProvider(this, getViewLifecycleOwner(), Lifecycle.State.RESUMED);
        return inflater.inflate(R.layout.data_view_container, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        FragmentManager childFragmentManager = getChildFragmentManager();

        mConnectionsFragment = childFragmentManager.findFragmentByTag("connections");
        mHttpLogFragment = childFragmentManager.findFragmentByTag("http_log");
        mHttpRepeaterFragment = childFragmentManager.findFragmentByTag("http_repeater");

        Intent intent = requireActivity().getIntent();
        Bundle connectionArgs = null;
        if (intent != null) {
            FilterDescriptor filter = Utils.getSerializableExtra(intent,
                ConnectionsFragment.FILTER_EXTRA, FilterDescriptor.class);
            String query = intent.getStringExtra(ConnectionsFragment.QUERY_EXTRA);

            if (filter != null || (query != null && !query.isEmpty())) {
                mCurrentView = VIEW_CONNECTIONS;

                connectionArgs = new Bundle();
                if (filter != null) {
                    connectionArgs.putSerializable(ConnectionsFragment.FILTER_EXTRA, filter);
                }
                if (query != null && !query.isEmpty()) {
                    connectionArgs.putString(ConnectionsFragment.QUERY_EXTRA, query);
                }

                intent.removeExtra(ConnectionsFragment.FILTER_EXTRA);
                intent.removeExtra(ConnectionsFragment.QUERY_EXTRA);
            }
        }

        FragmentTransaction transaction = childFragmentManager.beginTransaction();

        if (mConnectionsFragment == null) {
            mConnectionsFragment = new ConnectionsFragment();
            if (connectionArgs != null) {
                mConnectionsFragment.setArguments(connectionArgs);
            }
            transaction.add(R.id.child_fragment_container, mConnectionsFragment, "connections");
        }

        if (mHttpLogFragment == null) {
            mHttpLogFragment = new HttpLogFragment();
            transaction.add(R.id.child_fragment_container, mHttpLogFragment, "http_log");
        }

        if (mHttpRepeaterFragment == null) {
            mHttpRepeaterFragment = new HttpRepeaterFragment();
            transaction.add(R.id.child_fragment_container, mHttpRepeaterFragment, "http_repeater");
        }

        if (mCurrentView == VIEW_CONNECTIONS) {
            transaction.show(mConnectionsFragment);
            transaction.hide(mHttpLogFragment);
            transaction.hide(mHttpRepeaterFragment);
        } else if (mCurrentView == VIEW_HTTP_LOG) {
            transaction.show(mHttpLogFragment);
            transaction.hide(mConnectionsFragment);
            transaction.hide(mHttpRepeaterFragment);
        } else {
            transaction.show(mHttpRepeaterFragment);
            transaction.hide(mConnectionsFragment);
            transaction.hide(mHttpLogFragment);
        }

        transaction.commit();

        mBackCallback = new OnBackPressedCallback(mCurrentView != VIEW_CONNECTIONS) {
            @Override
            public void handleOnBackPressed() {
                if (mCurrentView != VIEW_CONNECTIONS) {
                    resetToConnectionsView();
                }
            }
        };
        requireActivity().getOnBackPressedDispatcher().addCallback(getViewLifecycleOwner(), mBackCallback);

        updateTabTitle();
    }

    @Override
    public void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putInt(STATE_CURRENT_VIEW, mCurrentView);
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, @NonNull MenuInflater menuInflater) {
        if ((mCurrentView == VIEW_CONNECTIONS) && (mConnectionsFragment != null)) {
            if (mConnectionsFragment instanceof ConnectionsFragment) {
                ((ConnectionsFragment) mConnectionsFragment).onCreateMenu(menu, menuInflater);
            }
        } else if ((mCurrentView == VIEW_HTTP_LOG) && (mHttpLogFragment != null)) {
            if (mHttpLogFragment instanceof HttpLogFragment) {
                ((HttpLogFragment) mHttpLogFragment).onCreateMenu(menu, menuInflater);
            }
        }

        updateTabTitle();
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        if ((mCurrentView == VIEW_CONNECTIONS) && (mConnectionsFragment != null)) {
            if (mConnectionsFragment instanceof ConnectionsFragment) {
                if (((ConnectionsFragment) mConnectionsFragment).onMenuItemSelected(item)) {
                    return true;
                }
            }
        } else if ((mCurrentView == VIEW_HTTP_LOG) && (mHttpLogFragment != null)) {
            if (mHttpLogFragment instanceof HttpLogFragment) {
                if (((HttpLogFragment) mHttpLogFragment).onMenuItemSelected(item)) {
                    return true;
                }
            }
        }

        return false;
    }

    public int getCurrentView() {
        return mCurrentView;
    }

    public void toggleView() {
        if (mCurrentView == VIEW_CONNECTIONS) {
            switchToView(VIEW_HTTP_LOG);
        } else if (mCurrentView == VIEW_HTTP_LOG) {
            switchToView(VIEW_HTTP_REPEATER);
        } else {
            switchToView(VIEW_CONNECTIONS);
        }
    }

    public void resetToConnectionsView() {
        switchToView(VIEW_CONNECTIONS);
    }

    public void switchToHttpView() {
        switchToView(VIEW_HTTP_LOG);
    }

    public void switchToRepeaterView() {
        switchToView(VIEW_HTTP_REPEATER);
    }

    public void switchToView(int targetView) {
        if (mCurrentView == targetView) {
            return;
        }

        mCurrentView = targetView;

        if ((mConnectionsFragment == null) || (mHttpLogFragment == null) || (mHttpRepeaterFragment == null))
            return;

        FragmentTransaction transaction = getChildFragmentManager().beginTransaction();

        if (mCurrentView == VIEW_CONNECTIONS) {
            transaction.show(mConnectionsFragment);
            transaction.hide(mHttpLogFragment);
            transaction.hide(mHttpRepeaterFragment);
        } else if (mCurrentView == VIEW_HTTP_LOG) {
            transaction.hide(mConnectionsFragment);
            transaction.show(mHttpLogFragment);
            transaction.hide(mHttpRepeaterFragment);
        } else {
            transaction.hide(mConnectionsFragment);
            transaction.hide(mHttpLogFragment);
            transaction.show(mHttpRepeaterFragment);
        }

        transaction.commit();

        if (mBackCallback != null) {
            mBackCallback.setEnabled(mCurrentView != VIEW_CONNECTIONS);
        }

        updateTabTitle();

        requireActivity().invalidateMenu();
    }

    private void updateTabTitle() {
        FragmentActivity activity = getActivity();
        if (activity instanceof com.kotsafe.security.activities.MainActivity) {
            ((com.kotsafe.security.activities.MainActivity) activity).updateDataViewMode(mCurrentView);
        }

        if (activity == null) return;
        TabLayout tabLayout = activity.findViewById(R.id.tablayout);

        if (tabLayout != null) {
            TabLayout.Tab tab = tabLayout.getTabAt(TAB_POSITION);
            if (tab != null) {
                int titleRes = (mCurrentView == VIEW_CONNECTIONS) ?
                    R.string.connections_view :
                    (mCurrentView == VIEW_HTTP_LOG ? R.string.http_requests : R.string.http_repeater);
                tab.setText(getString(titleRes));
            }
        }

        View switchButton = activity.findViewById(R.id.tab_switch_button);
        if (switchButton != null) {
            int contentDescRes = (mCurrentView == VIEW_CONNECTIONS) ?
                R.string.switch_to_http :
                (mCurrentView == VIEW_HTTP_LOG ? R.string.switch_to_repeater : R.string.switch_to_connections);
            String desc = getString(contentDescRes);
            switchButton.setContentDescription(desc);
            TooltipCompat.setTooltipText(switchButton, desc);
        }
    }

}
