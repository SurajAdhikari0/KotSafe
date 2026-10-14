package com.kotsafe.security.activities;

import android.content.Context;
import android.content.res.Configuration;
import android.os.Bundle;
import android.view.MenuItem;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.fragment.app.Fragment;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.Prefs;

import java.util.List;
import android.content.Intent;
import android.view.WindowManager;
import com.kotsafe.security.model.PhysicalSecurityManager;

public class BaseActivity extends AppCompatActivity {
    private boolean mBackAction = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Prefs.applyThemeMode(Prefs.getThemeMode(this));
        Utils.enableEdgeToEdge(this);
        super.onCreate(savedInstanceState);

        // Anti-Tapjacking Defense: ignore touch events when window is obscured by an overlay
        View decorView = getWindow().getDecorView();
        if (decorView != null) {
            decorView.setFilterTouchesWhenObscured(true);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Utils.updateSystemBarAppearance(this);
        PhysicalSecurityManager psm = PhysicalSecurityManager.getInstance(this);
        if (psm.isScreenshotProtectionEnabled()) {
            getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        }
        if (psm.isKotSafeAppLockEnabled() && !psm.isSessionAuthenticated() && !getClass().getName().endsWith("LockOverlayActivity")) {
            Intent lockIntent = new Intent(this, LockOverlayActivity.class);
            startActivity(lockIntent);
        }
    }

    @Override
    public void setContentView(int res)  {
        super.setContentView(res);
        Utils.updateSystemBarAppearance(this);

        View root = findViewById(android.R.id.content);
        if (root != null) {
            root.setFilterTouchesWhenObscured(true);
        }

        View toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            // Fix padding of content below the toolbar
            ViewCompat.setOnApplyWindowInsetsListener(toolbar, (view, insets) -> {
                int topInset = insets.getInsets(WindowInsetsCompat.Type.statusBars() |
                        WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout()).top;
                if (topInset > 0)
                    view.setPadding(0, topInset, 0, 0); // Shift the toolbar down if needed

                return insets;
            });
        }

        View bottomNavContainer = findViewById(R.id.bottom_nav_container);
        View bottomNav = findViewById(R.id.bottom_navigation);
        if (bottomNavContainer != null) {
            final int basePadBottom = bottomNavContainer.getPaddingBottom();
            ViewCompat.setOnApplyWindowInsetsListener(bottomNavContainer, (view, insets) -> {
                int bottomInset = insets.getInsets(WindowInsetsCompat.Type.navigationBars() |
                        WindowInsetsCompat.Type.systemBars()).bottom;
                view.setPadding(view.getPaddingLeft(), view.getPaddingTop(), view.getPaddingRight(), basePadBottom + bottomInset);
                return insets;
            });
        } else if (bottomNav != null) {
            ViewCompat.setOnApplyWindowInsetsListener(bottomNav, (view, insets) -> {
                int bottomInset = insets.getInsets(WindowInsetsCompat.Type.navigationBars() |
                        WindowInsetsCompat.Type.systemBars()).bottom;
                view.setPadding(0, 0, 0, bottomInset);
                return insets;
            });
        }
    }

    @Override
    protected void attachBaseContext(Context base) {
        // Ensure the selected locale is used before the activity inflates resources.
        Configuration config = Utils.getLocalizedConfig(base);
        if (config != null) {
            super.attachBaseContext(base.createConfigurationContext(config));
            return;
        }
        super.attachBaseContext(base);
    }

    protected void displayBackAction() {
        ActionBar actionBar = getSupportActionBar();

        if(actionBar != null) {
            actionBar.setDisplayHomeAsUpEnabled(true);
            mBackAction = true;
        }
    }

    protected Fragment getFragment(Class targetClass) {
        List<Fragment> fragments = getSupportFragmentManager().getFragments();

        for(Fragment fragment : fragments) {
            if(targetClass.isInstance(fragment))
                return fragment;
        }

        return null;
    }

    protected Fragment getFragmentAtPos(int pos) {
        return getSupportFragmentManager().findFragmentByTag("f" + pos);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if(mBackAction && (item.getItemId() == android.R.id.home)) {
            getOnBackPressedDispatcher().onBackPressed();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
