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

package com.kotsafe.security.model;

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.util.ConnectionsTimingTrace;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Coordinates asynchronous, throttled refresh of the Connections screen.
 * Merges high-frequency incoming VPN traffic bursts into coalesced batches (150-250 ms)
 * and guarantees that older background results never overwrite newer traffic state.
 */
public class ConnectionRefreshCoordinator {
    private static final String TAG = "RefreshCoordinator";
    public static final long COALESCE_WINDOW_MS = 180; // 150-250 ms acceptance target

    public interface OnStateReadyListener {
        void onStateReady(@NonNull ConnectionScreenState state);
    }

    private final ConnectionScreenStateBuilder mBuilder;
    private final ExecutorService mExecutor;
    private final Handler mMainHandler;
    private final AtomicLong mGeneration = new AtomicLong(0);
    private volatile long mCurrentVisibleGeneration = 0;

    private final AtomicBoolean mPendingDirty = new AtomicBoolean(false);
    private final Runnable mCoalesceRunnable;
    private OnStateReadyListener mListener;

    private FilterDescriptor mFilter = new FilterDescriptor();
    private String mSearchQuery = null;
    private ConnectionScreenStateBuilder.SortMode mSortMode = ConnectionScreenStateBuilder.SortMode.RECENT;
    private ConnectionsRegister mRegister;

    public ConnectionRefreshCoordinator(@NonNull ConnectionScreenStateBuilder builder,
                                        @NonNull Handler mainHandler) {
        this.mBuilder = builder;
        this.mMainHandler = mainHandler;
        this.mExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "KotSafe-ConnRefresh");
            t.setPriority(Thread.NORM_PRIORITY - 1);
            return t;
        });

        this.mCoalesceRunnable = () -> {
            mPendingDirty.set(false);
            dispatchBackgroundBuild();
        };
    }

    public void setListener(@Nullable OnStateReadyListener listener) {
        this.mListener = listener;
    }

    public void setConnectionsRegister(@Nullable ConnectionsRegister register) {
        this.mRegister = register;
    }

    public void updateFilter(@NonNull FilterDescriptor filter, boolean immediate) {
        this.mFilter = new FilterDescriptor(filter);
        requestRefresh(immediate);
    }

    public void updateSearchQuery(@Nullable String query, boolean immediate) {
        this.mSearchQuery = query;
        requestRefresh(immediate);
    }

    public void updateSortMode(@NonNull ConnectionScreenStateBuilder.SortMode sortMode, boolean immediate) {
        this.mSortMode = sortMode;
        requestRefresh(immediate);
    }

    /**
     * Request a UI update. If immediate is false (e.g. during live traffic bursts),
     * requests are coalesced within the 150-250 ms window.
     */
    public void requestRefresh(boolean immediate) {
        if (immediate) {
            mMainHandler.removeCallbacks(mCoalesceRunnable);
            mPendingDirty.set(false);
            dispatchBackgroundBuild();
        } else {
            if (mPendingDirty.compareAndSet(false, true)) {
                mMainHandler.postDelayed(mCoalesceRunnable, COALESCE_WINDOW_MS);
            }
        }
    }

    private void dispatchBackgroundBuild() {
        final ConnectionsRegister register = mRegister;
        if (register == null) return;

        final long gen = mGeneration.incrementAndGet();
        final FilterDescriptor currentFilter = new FilterDescriptor(mFilter);
        final String currentSearch = mSearchQuery;
        final ConnectionScreenStateBuilder.SortMode currentSort = mSortMode;

        mExecutor.execute(() -> {
            // Discard if a newer generation was already requested
            if (gen < mGeneration.get()) {
                return;
            }

            long startBuild = ConnectionsTimingTrace.startTrace();
            // Snapshotting takes the register monitor and copies every live connection.
            // Do it here, not in requestRefresh(), which is commonly called on the UI thread.
            List<ConnectionDescriptor> snapshot = register.getConnectionsSnapshot();
            int untracked = register.getUntrackedConnCount();
            if (gen < mGeneration.get()) {
                return;
            }
            ConnectionScreenState state = mBuilder.build(snapshot, currentFilter, currentSearch, currentSort, gen, untracked);

            mMainHandler.post(() -> {
                // Ensure monotonic progression: older async result cannot replace newer visible state
                if (state.generation >= mCurrentVisibleGeneration) {
                    mCurrentVisibleGeneration = state.generation;
                    if (mListener != null) {
                        mListener.onStateReady(state);
                    }
                    ConnectionsTimingTrace.logLiveUpdateBatch(startBuild, state.rows.size(), state.generation);
                }
            });
        });
    }

    public long getCurrentVisibleGeneration() {
        return mCurrentVisibleGeneration;
    }

    public long getLatestRequestedGeneration() {
        return mGeneration.get();
    }

    public void shutdown() {
        mMainHandler.removeCallbacks(mCoalesceRunnable);
        mExecutor.shutdownNow();
    }
}
