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
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;
import androidx.viewpager2.widget.ViewPager2;

import com.kotsafe.security.Log;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.fragments.LogviewFragment;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

public class LogviewActivity extends BaseActivity implements MenuProvider {
    private static final String TAG = "LogviewActivity";
    private ViewPager2 mPager;
    private StateAdapter mPagerAdapter;

    public static final String EXTRA_INITIAL_TAB = "initial_tab";

    public static final int POS_BROWSER_ACTIVITY = 0;
    public static final int POS_FIREWALL_LOG = 1;
    public static final int POS_DNS_ACTIVITY = 2;
    public static final int POS_FILE_HASHES = 3;
    public static final int POS_APP_LOG = 4;
    public static final int POS_ROOT_LOG = 5;
    public static final int POS_MITM_LOG = 6;
    private static final int NUM_POS = 7;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setTitle(R.string.app_log);
        displayBackAction();
        setContentView(R.layout.tabs_activity_fixed);
        addMenuProvider(this);

        mPager = findViewById(R.id.pager);
        Utils.fixViewPager2Insets(mPager);
        setupTabs();

        if(getIntent() != null && getIntent().hasExtra(EXTRA_INITIAL_TAB)) {
            int targetTab = getIntent().getIntExtra(EXTRA_INITIAL_TAB, POS_BROWSER_ACTIVITY);
            mPager.setCurrentItem(targetTab, false);
        }
    }

    private void setupTabs() {
        mPagerAdapter = new StateAdapter(this);
        mPager.setAdapter(mPagerAdapter);

        var tabLayout = (TabLayout) findViewById(R.id.tablayout);
        Utils.fixScrollableTabLayoutInsets(tabLayout);
        new TabLayoutMediator(tabLayout, mPager, (tab, position) ->
                tab.setText(getString(mPagerAdapter.getPageTitle(position)))
        ).attach();
    }

    private static class StateAdapter extends FragmentStateAdapter {
        final String mCacheDir;

        StateAdapter(final FragmentActivity fa) {
            super(fa);
            mCacheDir = fa.getCacheDir().getAbsolutePath();
        }

        @NonNull
        @Override
        public Fragment createFragment(int pos) {
            switch (pos) {
                case POS_BROWSER_ACTIVITY:
                    return com.kotsafe.security.fragments.BrowserLogsFragment.newInstance();
                case POS_FIREWALL_LOG:
                    return com.kotsafe.security.fragments.FirewallLogsFragment.newInstance();
                case POS_DNS_ACTIVITY:
                    return com.kotsafe.security.fragments.DnsActivityLogsFragment.newInstance();
                case POS_FILE_HASHES:
                    return new com.kotsafe.security.fragments.FileHashLogsFragment();
                case POS_APP_LOG:
                    return LogviewFragment.newInstance(mCacheDir + "/" + Log.DEFAULT_LOGGER_PATH);
                case POS_ROOT_LOG:
                    return LogviewFragment.newInstance(mCacheDir + "/" + Log.ROOT_LOGGER_PATH);
                case POS_MITM_LOG:
                default:
                    return LogviewFragment.newInstance(mCacheDir + "/" + Log.MITM_LOGGER_PATH);
            }
        }

        @Override
        public int getItemCount() {
            return NUM_POS;
        }

        public int getPageTitle(final int pos) {
            switch (pos) {
                case POS_BROWSER_ACTIVITY:
                    return R.string.browser_activity;
                case POS_FIREWALL_LOG:
                    return R.string.firewall;
                case POS_DNS_ACTIVITY:
                    return R.string.dns_trackers_activity;
                case POS_FILE_HASHES:
                    return R.string.file_hashes;
                case POS_APP_LOG:
                    return R.string.app;
                case POS_ROOT_LOG:
                    return R.string.root;
                case POS_MITM_LOG:
                default:
                    return R.string.mitm_addon;
            }
        }
    }

    @Override
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        // This is required to properly handle the DPAD down press on Android TV, to properly
        // focus the tab content
        if (keyCode == KeyEvent.KEYCODE_DPAD_DOWN) {
            View view = getCurrentFocus();

            Log.d(TAG, "onKeyDown focus " + view.getClass().getName());

            if (view instanceof TabLayout.TabView) {
                int pos = mPager.getCurrentItem();
                View focusOverride = null;

                Log.d(TAG, "TabLayout.TabView focus pos " + pos);

                focusOverride = findViewById(R.id.scrollView);

                if (focusOverride != null) {
                    focusOverride.requestFocus();
                    return true;
                }
            }
        }

        return super.onKeyDown(keyCode, event);
    }

    @Override
    public void onCreateMenu(@NonNull Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.log_menu, menu);
    }

    @Override
    public boolean onMenuItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();
        Fragment f = getFragmentAtPos(mPager.getCurrentItem());
        if(f instanceof LogviewFragment) {
            LogviewFragment fragment = (LogviewFragment) f;
            String logText = fragment.getLog();

            if(id == R.id.reload) {
                fragment.reloadLog();
                return true;
            } else if(id == R.id.copy_to_clipboard) {
                Utils.copyToClipboard(this, logText);
                return true;
            } else if(id == R.id.share) {
                Utils.shareText(this, getString(R.string.app_log), logText);
                return true;
            }
        }

        return false;
    }
}
