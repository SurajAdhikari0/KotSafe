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
 */

package com.kotsafe.security.model;

import android.content.Context;

import com.kotsafe.security.Log;
import com.kotsafe.security.ThreatIntelApiClient;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Persistent Rate-Limited Threat Intel Queue (Implementation Plan v2 §5 Phase 5, §2.3).
 * Drains vt_lookup_queue safely in the background with strict rate-limiting (<= 4 req/min)
 * to respect free API quotas and preserve user privacy defaults.
 */
public class VtRateLimitedQueue {
    private static final String TAG = "VtRateLimitedQueue";

    // VirusTotal free API rate limit: 4 requests per minute -> 15 seconds per request
    private static final long RATE_LIMIT_DELAY_MS = 15_000;

    private static VtRateLimitedQueue sInstance;

    private final Context mContext;
    private final FileHashDbHelper mDbHelper;
    private final ThreatIntelApiClient mApiClient;
    private final ThreatIntelRouter mRouter;
    private final ExecutorService mExecutor;
    private final AtomicBoolean mIsRunning = new AtomicBoolean(false);

    public static synchronized VtRateLimitedQueue getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new VtRateLimitedQueue(context.getApplicationContext());
        }
        return sInstance;
    }

    private VtRateLimitedQueue(Context context) {
        mContext = context;
        mDbHelper = FileHashDbHelper.getInstance(context);
        mApiClient = ThreatIntelApiClient.getInstance(context);
        mRouter = ThreatIntelRouter.getInstance(context);
        mExecutor = Executors.newSingleThreadExecutor();
    }

    /**
     * Enqueues a suspicious file hash for rate-limited cloud verification.
     */
    public void enqueue(String contentHash, String filePath) {
        if (contentHash == null || contentHash.isEmpty()) return;
        mDbHelper.enqueueVtLookup(contentHash, filePath);
        processQueue();
    }

    /**
     * Triggers asynchronous background queue processing if opt-in settings allow it.
     */
    public void processQueue() {
        // Privacy-First Default: Check if cloud queries are opted in and an API key exists
        if (!mApiClient.hasAnyApiKey() || !mApiClient.isAutoThreatQueryEnabled()) {
            Log.d(TAG, "Cloud queries disabled or missing API key. Skipping background VT queue.");
            return;
        }

        if (!mIsRunning.compareAndSet(false, true)) {
            Log.d(TAG, "Queue worker already active.");
            return;
        }

        mExecutor.execute(() -> {
            try {
                drainQueue();
            } finally {
                mIsRunning.set(false);
            }
        });
    }

    private void drainQueue() {
        Log.i(TAG, "Starting rate-limited threat intel queue drain...");

        while (true) {
            try {
                // Re-verify opt-in state before each batch
                if (!mApiClient.hasAnyApiKey() || !mApiClient.isAutoThreatQueryEnabled()) {
                    Log.d(TAG, "Cloud querying was disabled during execution. Halting queue.");
                    break;
                }

                List<String> pendingHashes = mDbHelper.getPendingVtLookups(10);
                if (pendingHashes.isEmpty()) {
                    Log.d(TAG, "No more pending hashes in VT queue.");
                    break;
                }

                for (String hash : pendingHashes) {
                    mDbHelper.updateVtLookupStatus(hash, "PROCESSING");
                    try {
                        ThreatIntelProvider.ThreatReport report = mRouter.queryHash(hash);
                        if (report != null) {
                            String threatStatus = report.isMalicious ? FileHashEntry.THREAT_MALICIOUS
                                    : report.isSuspicious ? FileHashEntry.THREAT_SUSPICIOUS
                                    : FileHashEntry.THREAT_CLEAN;
                            String details = "[" + report.provider + "] " + report.details;
                            String corrId = report.provider + ":" + (report.malwareFamily != null ? report.malwareFamily : "verified");

                            mDbHelper.updateThreatStatusByHash(hash, threatStatus, details, corrId);
                            mDbHelper.updateVtLookupStatus(hash, "COMPLETED");
                            Log.i(TAG, "Processed hash " + hash + " -> " + threatStatus);
                        } else {
                            mDbHelper.updateVtLookupStatus(hash, "COMPLETED");
                        }
                    } catch (Exception e) {
                        Log.e(TAG, "Error querying hash " + hash + ": " + e.getMessage());
                        mDbHelper.updateVtLookupStatus(hash, "FAILED");
                    }

                    // Rate limiting pause (<= 4 req/min)
                    try {
                        Thread.sleep(RATE_LIMIT_DELAY_MS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Transient error in VtRateLimitedQueue: " + e.getMessage());
                break;
            }
        }

        Log.i(TAG, "Threat intel queue drain completed.");
    }
}
