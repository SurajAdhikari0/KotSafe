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

package com.kotsafe.security.views;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.SweepGradient;
import android.graphics.Typeface;
import android.os.SystemClock;
import android.util.AttributeSet;
import android.view.View;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

/**
 * AntivirusMatrixView renders an interactive Cyber Radar HUD:
 * - Holo Circle Progress Ring with round caps
 * - Concentric Radar Grid & Crosshairs
 * - Animated 360-degree Radar Sweep Matrix
 * - Idle Breathing Pulse
 * - 3-Stage Vector Particle Node Field (INGESTION -> ANALYSIS -> VAULT)
 * - Center Holographic Score & Status Display
 */
public class AntivirusMatrixView extends View {

    public enum NodeStatus {
        SAFE(0xFF2EA44F),
        SUSPICIOUS(0xFFDB6D28),
        THREAT(0xFFF85149);

        public final int color;
        NodeStatus(int color) {
            this.color = color;
        }
    }

    private static class ScanNode {
        String label;
        NodeStatus status;
        int accentColor;
        float startX, startY;
        float endX, endY;
        long startTime;
        boolean revealed;
    }

    private static final long TRAVEL_MS = 2200;
    private static final float REVEAL_T = 0.5f;
    private static final int MAX_NODES = 12;

    private final List<ScanNode> mNodes = new ArrayList<>();
    private final Random mRandom = new Random();

    // Paints
    private Paint mProgressTrackPaint;
    private Paint mProgressBarPaint;
    private Paint mRadarGridPaint;
    private Paint mRadarSweepPaint;
    private Paint mIdlePulsePaint;
    private Paint mTrailPaint;
    private Paint mDotPaint;
    private Paint mNodeTextPaint;
    private Paint mZonePaint;

    private Paint mCenterScorePaint;
    private Paint mCenterStatusPaint;

    // State
    private int mCurrentAccentColor = 0xFF58A6FF;
    private boolean mIsScanning = false;
    private float mProgressPercent = 0f;
    private String mScoreText = "0%";
    private String mStatusText = "READY";
    private int mStatusColor = 0xFFC9D1D9;

    private float mRadarSweepAngle = 0f;
    private long mLastFrameTime = 0;
    private float mIdlePulseScale = 0f;

    private final RectF mProgressBounds = new RectF();
    private final RectF mRadarBounds = new RectF();

    public AntivirusMatrixView(Context context) {
        super(context);
        init();
    }

    public AntivirusMatrixView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public AntivirusMatrixView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        mProgressTrackPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mProgressTrackPaint.setStyle(Paint.Style.STROKE);
        mProgressTrackPaint.setStrokeWidth(dpToPx(6.5f));
        mProgressTrackPaint.setColor(0xFF21262D);

        mProgressBarPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mProgressBarPaint.setStyle(Paint.Style.STROKE);
        mProgressBarPaint.setStrokeWidth(dpToPx(6.5f));
        mProgressBarPaint.setStrokeCap(Paint.Cap.ROUND);
        mProgressBarPaint.setColor(mCurrentAccentColor);

        mRadarGridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mRadarGridPaint.setStyle(Paint.Style.STROKE);
        mRadarGridPaint.setStrokeWidth(dpToPx(1.0f));
        mRadarGridPaint.setColor(0x2858A6FF);

        mRadarSweepPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mRadarSweepPaint.setStyle(Paint.Style.FILL);

        mIdlePulsePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mIdlePulsePaint.setStyle(Paint.Style.STROKE);
        mIdlePulsePaint.setStrokeWidth(dpToPx(1.5f));
        mIdlePulsePaint.setColor(0x442EA44F);

        mTrailPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mTrailPaint.setStyle(Paint.Style.STROKE);
        mTrailPaint.setStrokeWidth(dpToPx(1.5f));

        mDotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mDotPaint.setStyle(Paint.Style.FILL);

        mNodeTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mNodeTextPaint.setTypeface(Typeface.MONOSPACE);
        mNodeTextPaint.setTextSize(spToPx(8.5f));
        mNodeTextPaint.setColor(0x88A0AAB5);

        mZonePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mZonePaint.setTypeface(Typeface.DEFAULT_BOLD);
        mZonePaint.setTextSize(spToPx(7.5f));
        mZonePaint.setColor(0x558B949E);
        mZonePaint.setLetterSpacing(0.12f);

        mCenterScorePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mCenterScorePaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        mCenterScorePaint.setTextSize(spToPx(32f));
        mCenterScorePaint.setTextAlign(Paint.Align.CENTER);
        mCenterScorePaint.setColor(mCurrentAccentColor);

        mCenterStatusPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mCenterStatusPaint.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
        mCenterStatusPaint.setTextSize(spToPx(10f));
        mCenterStatusPaint.setTextAlign(Paint.Align.CENTER);
        mCenterStatusPaint.setLetterSpacing(0.14f);
        mCenterStatusPaint.setColor(mStatusColor);

        mVelocityPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mVelocityPaint.setTypeface(Typeface.MONOSPACE);
        mVelocityPaint.setTextSize(spToPx(9.5f));
        mVelocityPaint.setTextAlign(Paint.Align.CENTER);
        mVelocityPaint.setColor(0xFFF0B429);
    }

    private Paint mVelocityPaint;
    private float mScanVelocity = 0f;

    public void setScanVelocity(float velocity) {
        mScanVelocity = velocity;
        invalidate();
    }

    public void setAccentColor(int color) {
        mCurrentAccentColor = color;
        mProgressBarPaint.setColor(color);
        mCenterScorePaint.setColor(color);
        mRadarGridPaint.setColor((color & 0x00FFFFFF) | 0x28000000);
        invalidate();
    }

    public void setScanning(boolean scanning) {
        mIsScanning = scanning;
        if (!scanning) {
            clearNodes();
        }
        invalidate();
    }

    public void setProgress(float percent) {
        mProgressPercent = Math.max(0f, Math.min(100f, percent));
        mScoreText = Math.round(mProgressPercent) + "%";
        invalidate();
    }

    public void setScoreDisplay(String scoreText, int scoreColor) {
        mScoreText = scoreText;
        mCenterScorePaint.setColor(scoreColor);
        mProgressBarPaint.setColor(scoreColor);
        invalidate();
    }

    public void setScanStatus(String status, int color) {
        mStatusText = status.toUpperCase();
        mStatusColor = color;
        mCenterStatusPaint.setColor(color);
        invalidate();
    }

    public void clearNodes() {
        mNodes.clear();
        invalidate();
    }

    public void spawnNode(String rawName, NodeStatus status) {
        if (getWidth() <= 0 || getHeight() <= 0) return;

        String label = sanitizeLabel(rawName);
        float w = getWidth();
        float h = getHeight();

        ScanNode node = new ScanNode();
        node.label = label;
        node.status = status;
        node.accentColor = mCurrentAccentColor;
        node.startX = -dpToPx(10) + mRandom.nextFloat() * (w * 0.22f);
        node.startY = mRandom.nextFloat() * h;
        node.endX = w * 0.78f + mRandom.nextFloat() * (w * 0.25f);
        node.endY = mRandom.nextFloat() * h;
        node.startTime = SystemClock.uptimeMillis();
        node.revealed = false;

        if (mNodes.size() >= MAX_NODES) {
            mNodes.remove(0);
        }
        mNodes.add(node);
        invalidate();
    }

    private String sanitizeLabel(String raw) {
        if (raw == null || raw.isEmpty()) return "item";
        String clean = raw;
        if (clean.contains("/")) {
            clean = clean.substring(clean.lastIndexOf('/') + 1);
        }
        if (clean.contains(" ")) {
            clean = clean.split(" ")[0];
        }
        if (clean.contains(".")) {
            clean = clean.split("\\.")[0];
        }
        if (clean.length() > 9) {
            clean = clean.substring(0, 8) + "…";
        }
        return clean;
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        float w = getWidth();
        float h = getHeight();
        if (w <= 0 || h <= 0) return;

        float centerX = w / 2f;
        float centerY = h / 2f;
        float radius = Math.min(centerX, centerY) - dpToPx(24f);
        if (radius <= 0) radius = dpToPx(70f);

        long now = SystemClock.uptimeMillis();
        if (mLastFrameTime == 0) mLastFrameTime = now;
        float dt = (now - mLastFrameTime) / 1000f;
        mLastFrameTime = now;

        // 1. Draw Zone Labels
        mZonePaint.setTextAlign(Paint.Align.LEFT);
        canvas.drawText("INGESTION", dpToPx(12), dpToPx(14), mZonePaint);

        mZonePaint.setTextAlign(Paint.Align.CENTER);
        canvas.drawText("ANALYSIS", centerX, dpToPx(14), mZonePaint);

        mZonePaint.setTextAlign(Paint.Align.RIGHT);
        canvas.drawText("VAULT", w - dpToPx(12), dpToPx(14), mZonePaint);

        // 2. Draw Active Particle Nodes (Background of Radar)
        boolean hasActive = false;
        Iterator<ScanNode> it = mNodes.iterator();
        while (it.hasNext()) {
            ScanNode node = it.next();
            float elapsed = (float) (now - node.startTime);
            float t = Math.min(1.0f, Math.max(0.0f, elapsed / TRAVEL_MS));

            float x, y;
            int currentColor;

            if (t < REVEAL_T) {
                // Phase 1: Ingestion -> Converge to Center Analysis
                float localT = easeInOutQuad(t / REVEAL_T);
                x = node.startX + (centerX - node.startX) * localT;
                y = node.startY + (centerY - node.startY) * localT;
                currentColor = node.accentColor;

                mTrailPaint.setColor(currentColor);
                mTrailPaint.setAlpha(100);
                canvas.drawLine(node.startX, node.startY, x, y, mTrailPaint);
            } else {
                // Phase 2: Analysis -> Fan out to Vault
                float localT = easeInOutQuad((t - REVEAL_T) / (1.0f - REVEAL_T));
                x = centerX + (node.endX - centerX) * localT;
                y = centerY + (node.endY - centerY) * localT;
                currentColor = node.status.color;

                mTrailPaint.setColor(currentColor);
                int alpha = (int) (140 * (1.0f - (t - REVEAL_T) * 0.8f));
                mTrailPaint.setAlpha(Math.max(10, alpha));
                canvas.drawLine(centerX, centerY, x, y, mTrailPaint);
            }

            // Draw Dot
            mDotPaint.setColor(currentColor);
            canvas.drawCircle(x, y, dpToPx(3.5f), mDotPaint);

            // Draw Label
            mNodeTextPaint.setColor(0xCCA0AAB5);
            if (x < centerX) {
                mNodeTextPaint.setTextAlign(Paint.Align.LEFT);
                canvas.drawText(node.label, x + dpToPx(6), y - dpToPx(4), mNodeTextPaint);
            } else {
                mNodeTextPaint.setTextAlign(Paint.Align.RIGHT);
                canvas.drawText(node.label, x - dpToPx(6), y - dpToPx(4), mNodeTextPaint);
            }

            if (t < 1.0f) {
                hasActive = true;
            }
        }

        // 3. Draw Idle Pulse when not scanning
        if (!mIsScanning) {
            mIdlePulseScale = (mIdlePulseScale + dt * 0.45f) % 1.0f;
            float pulseR = radius * (0.85f + mIdlePulseScale * 0.25f);
            int pulseAlpha = (int) (70 * (1.0f - mIdlePulseScale));
            mIdlePulsePaint.setColor((mCurrentAccentColor & 0x00FFFFFF) | (pulseAlpha << 24));
            canvas.drawCircle(centerX, centerY, pulseR, mIdlePulsePaint);
        }

        // 4. Draw Radar Grid Inside Holo Circle
        float innerR = radius - dpToPx(6f);
        canvas.drawCircle(centerX, centerY, innerR * 0.33f, mRadarGridPaint);
        canvas.drawCircle(centerX, centerY, innerR * 0.66f, mRadarGridPaint);
        canvas.drawCircle(centerX, centerY, innerR, mRadarGridPaint);

        // Crosshairs
        canvas.drawLine(centerX - innerR, centerY, centerX + innerR, centerY, mRadarGridPaint);
        canvas.drawLine(centerX, centerY - innerR, centerX, centerY + innerR, mRadarGridPaint);

        // 5. Draw Animated Radar Sweep Matrix when Scanning
        if (mIsScanning) {
            float sweepSpeed = 160f + Math.min(450f, mScanVelocity * 4.5f);
            mRadarSweepAngle = (mRadarSweepAngle + dt * sweepSpeed) % 360f;

            canvas.save();
            canvas.rotate(mRadarSweepAngle, centerX, centerY);

            mRadarBounds.set(centerX - innerR, centerY - innerR, centerX + innerR, centerY + innerR);

            int accentAlpha = (mCurrentAccentColor & 0x00FFFFFF) | 0x55000000;
            SweepGradient sweepGrad = new SweepGradient(centerX, centerY,
                    new int[]{0x00000000, accentAlpha, 0x00000000},
                    new float[]{0f, 0.15f, 1f});
            mRadarSweepPaint.setShader(sweepGrad);
            canvas.drawCircle(centerX, centerY, innerR, mRadarSweepPaint);
            mRadarSweepPaint.setShader(null);

            canvas.restore();
        }

        // 6. Draw Holo Circle Progress Ring Track & Arc
        mProgressBounds.set(centerX - radius, centerY - radius, centerX + radius, centerY + radius);
        canvas.drawArc(mProgressBounds, 0f, 360f, false, mProgressTrackPaint);

        float sweep = (mProgressPercent / 100f) * 360f;
        if (sweep > 0.5f) {
            canvas.drawArc(mProgressBounds, -90f, sweep, false, mProgressBarPaint);
        }

        // 7. Draw Holographic Center Text (Score + Status + Scan Velocity)
        if (mIsScanning && mScanVelocity > 0.5f) {
            float velocityBaseline = centerY - dpToPx(20f);
            canvas.drawText(String.format("⚡ %.0f ops/s", mScanVelocity), centerX, velocityBaseline, mVelocityPaint);
        }

        float scoreBaseline = centerY + dpToPx(6f);
        canvas.drawText(mScoreText, centerX, scoreBaseline, mCenterScorePaint);

        float statusBaseline = centerY + dpToPx(24f);
        canvas.drawText(mStatusText, centerX, statusBaseline, mCenterStatusPaint);

        // Continuous Animation Loop
        if (hasActive || mIsScanning || !mIsScanning) {
            postInvalidateOnAnimation();
        }
    }

    private float easeInOutQuad(float t) {
        return t < 0.5f ? 2f * t * t : 1f - (float) Math.pow(-2f * t + 2f, 2) / 2f;
    }

    private float dpToPx(float dp) {
        return dp * getResources().getDisplayMetrics().density;
    }

    private float spToPx(float sp) {
        return sp * getResources().getDisplayMetrics().scaledDensity;
    }
}
