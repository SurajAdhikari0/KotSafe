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
 *
 * Copyright 2026 KotSafe Cyber Security Project
 */

package com.kotsafe.security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.pm.PackageInfo;

import com.kotsafe.security.model.OnDeviceMlClassifier;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public class OnDeviceMlClassifierTest {

    @Test
    public void testBenignPackageClassifiesClean() {
        PackageInfo benignPkg = new PackageInfo();
        benignPkg.packageName = "com.example.simplecalculator";
        benignPkg.requestedPermissions = new String[]{
                "android.permission.INTERNET"
        };

        OnDeviceMlClassifier.MlInferenceResult res = OnDeviceMlClassifier.classify(null, benignPkg, false);

        assertNotNull(res);
        assertFalse("Benign calculator should not be classified as malicious", res.isMalicious());
        assertTrue("Malware probability should be low for simple app", res.malwareProbability < 0.40);
    }

    @Test
    public void testSideloadedTrojanCombinationFlagsHighRisk() {
        PackageInfo trojanPkg = new PackageInfo();
        trojanPkg.packageName = "com.covert.bankstealer";
        trojanPkg.requestedPermissions = new String[]{
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_DEVICE_ADMIN",
                "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.INTERNET"
        };

        OnDeviceMlClassifier.MlInferenceResult res = OnDeviceMlClassifier.classify(null, trojanPkg, true);

        assertNotNull(res);
        System.out.println("DEBUG trojan prob = " + res.malwareProbability + " verdict = " + res.verdict + " factors = " + res.dominantRiskFactors);
        assertTrue("Trojan combination should flag high probability", res.malwareProbability >= 0.75);
        assertFalse("Risk factors should be extracted", res.dominantRiskFactors.isEmpty());
    }
}
