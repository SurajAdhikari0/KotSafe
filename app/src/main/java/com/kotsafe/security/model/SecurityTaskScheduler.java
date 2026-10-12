/*
 * This file is part of KotSafe.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.model;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;

import com.kotsafe.security.Log;

import java.util.Comparator;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Priority-based background task scheduler for the security engine.
 *
 * Uses a bounded worker pool to avoid CPU/IO contention.
 * Pool size dynamically reduced when device is in power-save mode.
 *
 * Priority levels:
 *   P0 — CRITICAL : Known malicious connection / newly downloaded APK
 *   P1 — HIGH     : New app installed / suspicious domain / YARA match
 *   P2 — NORMAL   : Changed storage file / periodic TI refresh
 *   P3 — LOW      : DB cleanup / cache vacuum / historical enrichment
 */
public class SecurityTaskScheduler {
    private static final String TAG = "SecurityTaskScheduler";

    public static final int P0_CRITICAL = 0;
    public static final int P1_HIGH     = 1;
    public static final int P2_NORMAL   = 2;
    public static final int P3_LOW      = 3;

    private static final int MAX_WORKERS = 3;
    private static final int MAX_QUEUE   = 200;

    private static SecurityTaskScheduler sInstance;

    private final Context mContext;
    private final PriorityBlockingQueue<SecurityTask> mQueue;
    private final ExecutorService mExecutor;
    private final Handler mMainHandler;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private final AtomicInteger mActiveWorkers = new AtomicInteger(0);

    public static synchronized SecurityTaskScheduler getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new SecurityTaskScheduler(context.getApplicationContext());
        }
        return sInstance;
    }

    private SecurityTaskScheduler(Context context) {
        mContext = context;
        mQueue = new PriorityBlockingQueue<>(MAX_QUEUE,
                Comparator.comparingInt(t -> t.priority));
        mExecutor = Executors.newFixedThreadPool(MAX_WORKERS);
        mMainHandler = new Handler(Looper.getMainLooper());
        mRunning.set(true);
        startDispatcher();
        Log.d(TAG, "SecurityTaskScheduler started with " + MAX_WORKERS + " workers");
    }

    // ─── Task model ───────────────────────────────────────────────────────────

    public static class SecurityTask implements Comparable<SecurityTask> {
        public final int priority;
        public final String name;
        public final Runnable work;
        public final long createdAt;

        public SecurityTask(int priority, String name, Runnable work) {
            this.priority = priority;
            this.name = name;
            this.work = work;
            this.createdAt = System.currentTimeMillis();
        }

        @Override
        public int compareTo(SecurityTask other) {
            return Integer.compare(this.priority, other.priority);
        }
    }

    // ─── Submit API ───────────────────────────────────────────────────────────

    /** Submit a critical P0 task (e.g. newly downloaded APK, confirmed malicious IOC). */
    public void submitCritical(String name, Runnable work) {
        submit(new SecurityTask(P0_CRITICAL, name, work));
    }

    /** Submit a P1 high-priority task (e.g. new app install, suspicious domain hit). */
    public void submitHigh(String name, Runnable work) {
        submit(new SecurityTask(P1_HIGH, name, work));
    }

    /** Submit a P2 normal task (e.g. changed storage file, TI enrichment). */
    public void submitNormal(String name, Runnable work) {
        submit(new SecurityTask(P2_NORMAL, name, work));
    }

    /** Submit a P3 low-priority task (e.g. DB cleanup, cache vacuum). */
    public void submitLow(String name, Runnable work) {
        submit(new SecurityTask(P3_LOW, name, work));
    }

    private void submit(SecurityTask task) {
        if (!mRunning.get()) {
            Log.w(TAG, "Scheduler stopped, dropping task: " + task.name);
            return;
        }
        if (mQueue.size() >= MAX_QUEUE) {
            Log.w(TAG, "Queue full (" + MAX_QUEUE + "), dropping P" +
                    task.priority + " task: " + task.name);
            return;
        }
        Log.d(TAG, "Queued P" + task.priority + " task: " + task.name +
                " (queue size=" + mQueue.size() + ")");
        mQueue.offer(task);
    }

    // ─── Dispatcher ───────────────────────────────────────────────────────────

    private void startDispatcher() {
        mExecutor.execute(() -> {
            while (mRunning.get()) {
                try {
                    SecurityTask task = mQueue.take(); // blocks until available
                    if (!mRunning.get()) break;

                    // Throttle if in power-save mode: only run P0/P1 tasks
                    if (isInPowerSaveMode() && task.priority >= P2_NORMAL) {
                        // Re-queue for later
                        mQueue.offer(task);
                        Thread.sleep(5000);
                        continue;
                    }

                    mActiveWorkers.incrementAndGet();
                    Log.d(TAG, "Executing P" + task.priority + " task: " + task.name);
                    try {
                        task.work.run();
                    } catch (Exception e) {
                        Log.e(TAG, "Task error [" + task.name + "]: " + e.getMessage());
                    } finally {
                        mActiveWorkers.decrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            Log.d(TAG, "Dispatcher stopped");
        });
    }

    private boolean isInPowerSaveMode() {
        try {
            PowerManager pm = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
            return pm != null && pm.isPowerSaveMode();
        } catch (Exception e) {
            return false;
        }
    }

    // ─── Status ───────────────────────────────────────────────────────────────

    public int getQueueSize()    { return mQueue.size(); }
    public int getActiveWorkers() { return mActiveWorkers.get(); }

    public void shutdown() {
        mRunning.set(false);
        mExecutor.shutdownNow();
        Log.d(TAG, "SecurityTaskScheduler shut down");
    }

    public void runOnMainThread(Runnable r) {
        mMainHandler.post(r);
    }
}
