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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.core.app.ApplicationProvider;

import com.kotsafe.security.model.ProcessSecurityInspector;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;

@RunWith(RobolectricTestRunner.class)
public class ProcessSecurityInspectorTest {

    @Test
    public void testProcessInspectionRunsCleanly() {
        Context context = ApplicationProvider.getApplicationContext();
        ProcessSecurityInspector.InspectionReport report = ProcessSecurityInspector.inspect(context);

        assertNotNull("Report should not be null", report);
        assertNotNull("Summary should not be null", report.getSummary());
        assertTrue("Summary should contain integrity description",
                report.getSummary().contains("Integrity") || report.getSummary().contains("Tampering"));
    }
}
