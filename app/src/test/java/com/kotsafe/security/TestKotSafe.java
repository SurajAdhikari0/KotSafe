package com.kotsafe.security;

import android.app.Application;

import org.robolectric.TestLifecycleApplication;

import java.lang.reflect.Method;

/**
 * Robolectric Application stub used by all unit tests.
 * Skips KotSafe.onCreate() entirely so that:
 *   - CaptureService.initLogger() (native) is never invoked.
 *   - FileProtectionWatcher, FirewallBlockHttpServer, WorkManager, etc. are not started.
 */
public class TestKotSafe extends KotSafe implements TestLifecycleApplication {
    @Override
    public void onCreate() {
        // Mark as under test BEFORE calling the Application base (which is safe)
        KotSafe.isUnderTest = true;
        // Call Application.onCreate() directly, bypassing KotSafe/KotSafe initialisation
        // that depends on native libraries and system services not available in unit tests.
        try {
            Application.class.getDeclaredMethod("onCreate").invoke(this);
        } catch (Exception ignored) {
            // ignore – Application.onCreate() is a no-op on stock Android
        }
        // Manually wire the singleton so that KotSafe.getInstance() / KotSafe.getInstance()
        // return this instance (needed by ConnectionsRegister, MatchList, etc.)
        try {
            java.lang.reflect.Field instField = KotSafe.class.getDeclaredField("mInstance");
            instField.setAccessible(true);
            instField.set(null, new java.lang.ref.WeakReference<>(this));
        } catch (Exception ignored) {}
        // Also set a localizedContext so any code that calls getLocalizedContext() won't NPE
        try {
            java.lang.reflect.Field ctxField = KotSafe.class.getDeclaredField("mLocalizedContext");
            ctxField.setAccessible(true);
            ctxField.set(this, this);
        } catch (Exception ignored) {}
    }

    @Override
    public void beforeTest(Method method) {}

    @Override
    public void prepareTest(Object test) {}

    @Override
    public void afterTest(Method method) {}
}
