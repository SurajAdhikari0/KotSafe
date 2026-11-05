package com.kotsafe.security;

import static org.junit.Assert.*;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import com.kotsafe.security.model.FirewallRuleParser;
import com.kotsafe.security.model.MatchList;
import java.util.Arrays;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.Shadows;

@RunWith(RobolectricTestRunner.class)
public class FirewallPolicyApplicationTest {
    @Test public void generatedSystemExceptionsCanBeAppliedAsNativeUids() {
        Context context = RuntimeEnvironment.getApplication();
        PackageInfo system = new PackageInfo();
        system.packageName = "com.example.system";
        system.applicationInfo = new ApplicationInfo();
        system.applicationInfo.packageName = system.packageName;
        system.applicationInfo.flags = ApplicationInfo.FLAG_SYSTEM;
        system.applicationInfo.uid = 10055;
        Shadows.shadowOf(context.getPackageManager()).installPackage(system);
        MatchList.ListDescriptor rules = new MatchList.ListDescriptor();
        Utils.addSystemAppsToWhitelistDescriptor(context, rules);
        assertTrue(rules.apps.contains(system.packageName));
        int[] uids = FirewallRuleParser.uids(rules.apps, name -> {
            try { return Utils.getPackageUid(context.getPackageManager(), name, 0); }
            catch (PackageManager.NameNotFoundException absent) { return -1; }
        });
        assertTrue(Arrays.stream(uids).anyMatch(uid -> uid == 10055));
        assertTrue(Arrays.stream(uids).anyMatch(uid -> uid == 1000));
    }
}
