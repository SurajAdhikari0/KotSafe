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
 * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.util;

import android.os.SystemClock;
import android.util.Log;

import androidx.annotation.NonNull;

/**
 * High-precision timing traces to measure and protect against UI latency regressions.
 */
public final class ConnectionsTimingTrace {
    private static final String TAG = "ConnectionsTiming";

    private static volatile long sVpnStartTime = 0;
    private static volatile long sFirstScreenVisibleTime = 0;

    private ConnectionsTimingTrace() {}

    public static void onVpnStarted() {
        sVpnStartTime = SystemClock.elapsedRealtime();
        Log.i(TAG, "VPN started at " + sVpnStartTime + " ms");
    }

    public static void onConnectionsScreenFirstVisible() {
        if (sFirstScreenVisibleTime == 0 && sVpnStartTime > 0) {
            sFirstScreenVisibleTime = SystemClock.elapsedRealtime();
            long latency = sFirstScreenVisibleTime - sVpnStartTime;
            Log.i(TAG, "VPN start -> Connections screen first visible: " + latency + " ms (target: <500 ms)");
        }
    }

    public static long startTrace() {
        return SystemClock.elapsedRealtime();
    }

    public static void logSnapshotCreation(long startTimeMs, int connectionCount) {
        long elapsed = SystemClock.elapsedRealtime() - startTimeMs;
        Log.d(TAG, "Connection snapshot creation: " + elapsed + " ms (" + connectionCount + " items)");
    }

    public static void logProcessing(long startTimeMs, int inCount, int outCount) {
        long elapsed = SystemClock.elapsedRealtime() - startTimeMs;
        Log.d(TAG, "Filtering, aggregation, sorting: " + elapsed + " ms (in=" + inCount + ", out=" + outCount + ")");
    }

    public static void logSummaryCalculation(long startTimeMs) {
        long elapsed = SystemClock.elapsedRealtime() - startTimeMs;
        Log.d(TAG, "Summary-chip calculation: " + elapsed + " ms");
    }

    public static void logRowBinding(long startTimeMs, int position) {
        long elapsed = SystemClock.elapsedRealtime() - startTimeMs;
        if (elapsed > 10) {
            Log.w(TAG, "Slow row binding at pos " + position + ": " + elapsed + " ms");
        }
    }

    public static void logLiveUpdateBatch(long startTimeMs, int rowCount, long generation) {
        long elapsed = SystemClock.elapsedRealtime() - startTimeMs;
        Log.d(TAG, "UI update batch [gen=" + generation + "]: " + elapsed + " ms for " + rowCount + " rows");
    }
}
