/*
 * This file is part of KotSafe.
 * Copyright (c) 2026 KotSafe Cyber Security Project. All Rights Reserved.
 */

package com.kotsafe.security.views;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.LinearGradient;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.view.View;

import androidx.annotation.Nullable;

import com.kotsafe.security.model.TrafficTimeSeriesCollector.DataPoint;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * GlassWireTrafficGraphView
 * =========================
 * Hardware-accelerated, high-performance real-time traffic wave area chart.
 * Renders smooth Cubic Bézier curves for Inbound (Download) and Outbound (Upload) flows,
 * with timeline pins for NEW apps and Security Alert events.
 * Fully adapts colors for Day Mode (Light Theme) and Night Mode (Dark Theme).
 */
public class GlassWireTrafficGraphView extends View {

    // Paints
    private Paint mCardBgPaint;
    private Paint mCardBorderPaint;
    private Paint mDownLinePaint;
    private Paint mDownFillPaint;
    private Paint mUpLinePaint;
    private Paint mUpFillPaint;
    private Paint mBaselinePaint;
    private Paint mGridPaint;
    private Paint mTextPaint;
    private Paint mAxisPaint;
    private Paint mBadgePaint;
    private Paint mBadgeTextPaint;
    private Paint mCursorPaint;
    private Paint mTooltipBgPaint;
    private Paint mLogoPaint;

    // Paths
    private final Path mDownPath = new Path();
    private final Path mDownFillPath = new Path();
    private final Path mUpPath = new Path();
    private final Path mUpFillPath = new Path();
    private final RectF mCardRect = new RectF();

    // Data
    private List<DataPoint> mDataPoints = new ArrayList<>();
    private boolean mCompactMode = false;
    private boolean mShowUpload = true;

    // Interactive Touch Scrubbing
    private float mTouchX = -1f;
    private boolean mIsTouching = false;
    private final SimpleDateFormat mTimeFmt = new SimpleDateFormat("HH:mm:ss", Locale.getDefault());

    public GlassWireTrafficGraphView(Context context) {
        super(context);
        init();
    }

    public GlassWireTrafficGraphView(Context context, @Nullable AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public GlassWireTrafficGraphView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private boolean isDarkMode() {
        return (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
    }

    private void init() {
        // Card Background
        mCardBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mCardBgPaint.setStyle(Paint.Style.FILL);

        // Card Border
        mCardBorderPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mCardBorderPaint.setStyle(Paint.Style.STROKE);
        mCardBorderPaint.setStrokeWidth(2.5f);

        // Download Curve (Cyan/Teal)
        mDownLinePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mDownLinePaint.setColor(Color.parseColor("#00B4D8"));
        mDownLinePaint.setStrokeWidth(4.5f);
        mDownLinePaint.setStyle(Paint.Style.STROKE);
        mDownLinePaint.setStrokeCap(Paint.Cap.ROUND);
        mDownLinePaint.setStrokeJoin(Paint.Join.ROUND);

        // Download Gradient Fill
        mDownFillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mDownFillPaint.setStyle(Paint.Style.FILL);

        // Upload Curve (Orange/Amber)
        mUpLinePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mUpLinePaint.setColor(Color.parseColor("#FF9E00"));
        mUpLinePaint.setStrokeWidth(3.0f);
        mUpLinePaint.setStyle(Paint.Style.STROKE);
        mUpLinePaint.setStrokeCap(Paint.Cap.ROUND);
        mUpLinePaint.setStrokeJoin(Paint.Join.ROUND);

        // Upload Gradient Fill
        mUpFillPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mUpFillPaint.setStyle(Paint.Style.FILL);

        // Bottom baseline strip (Emerald/Mint green accent like GlassWire)
        mBaselinePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mBaselinePaint.setColor(Color.parseColor("#10B981"));
        mBaselinePaint.setStrokeWidth(3.0f);
        mBaselinePaint.setStyle(Paint.Style.STROKE);

        // Grid lines
        mGridPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mGridPaint.setStrokeWidth(1.5f);
        mGridPaint.setPathEffect(new DashPathEffect(new float[]{8, 8}, 0));

        // Text & Speed HUD Labels
        mTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mTextPaint.setTextSize(26f);

        // Timeline axis markings
        mAxisPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mAxisPaint.setTextSize(20f);

        // Pins & Badges
        mBadgePaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mBadgePaint.setStyle(Paint.Style.FILL);

        mBadgeTextPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mBadgeTextPaint.setColor(Color.WHITE);
        mBadgeTextPaint.setTextSize(18f);
        mBadgeTextPaint.setTextAlign(Paint.Align.CENTER);
        mBadgeTextPaint.setFakeBoldText(true);

        // Interactive Cursor
        mCursorPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mCursorPaint.setStrokeWidth(2f);

        mTooltipBgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mTooltipBgPaint.setColor(Color.parseColor("#EE0F172A")); // Slate with alpha
        mTooltipBgPaint.setStyle(Paint.Style.FILL);

        // Shield logo paint
        mLogoPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        mLogoPaint.setStyle(Paint.Style.FILL);
    }

    public void setCompactMode(boolean compact) {
        mCompactMode = compact;
        invalidate();
    }

    public void setShowUpload(boolean show) {
        mShowUpload = show;
        invalidate();
    }

    public void setDataPoints(List<DataPoint> points) {
        if (points != null) {
            mDataPoints = new ArrayList<>(points);
        } else {
            mDataPoints.clear();
        }
        postInvalidateOnAnimation();
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        if (mCompactMode || mDataPoints.isEmpty()) return super.onTouchEvent(event);

        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
            case MotionEvent.ACTION_MOVE:
                mTouchX = event.getX();
                mIsTouching = true;
                invalidate();
                return true;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                mIsTouching = false;
                invalidate();
                return true;
        }
        return super.onTouchEvent(event);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        int width = getWidth();
        int height = getHeight();
        if (width <= 0 || height <= 0) return;

        boolean dark = isDarkMode();

        // 1. Draw GlassWire Card Background & Border
        mCardRect.set(2f, 2f, width - 2f, height - 2f);
        float cornerRadius = mCompactMode ? 18f : 24f;

        if (!dark) {
            // Day Mode: Signature GlassWire ice-blue / soft azure card
            mCardBgPaint.setShader(new LinearGradient(
                    0, 0, 0, height,
                    Color.parseColor("#EDF8FA"),
                    Color.parseColor("#F4FBFC"),
                    Shader.TileMode.CLAMP
            ));
            mCardBorderPaint.setColor(Color.parseColor("#CCE9EE"));
            mGridPaint.setColor(Color.parseColor("#BFE2E7"));
            mDownLinePaint.setColor(Color.parseColor("#0096C7")); // High-contrast vivid cyan
            mUpLinePaint.setColor(Color.parseColor("#E65100"));   // High-contrast vivid amber
            mAxisPaint.setColor(Color.parseColor("#64748B"));
            mCursorPaint.setColor(Color.parseColor("#0284C7"));
        } else {
            // Night Mode: Dark midnight slate card
            mCardBgPaint.setShader(new LinearGradient(
                    0, 0, 0, height,
                    Color.parseColor("#0B1528"),
                    Color.parseColor("#101F38"),
                    Shader.TileMode.CLAMP
            ));
            mCardBorderPaint.setColor(Color.parseColor("#1E293B"));
            mGridPaint.setColor(Color.parseColor("#24334C"));
            mDownLinePaint.setColor(Color.parseColor("#00B4D8"));
            mUpLinePaint.setColor(Color.parseColor("#FF9E00"));
            mAxisPaint.setColor(Color.parseColor("#94A3B8"));
            mCursorPaint.setColor(Color.parseColor("#B3FFFFFF"));
        }

        canvas.drawRoundRect(mCardRect, cornerRadius, cornerRadius, mCardBgPaint);
        canvas.drawRoundRect(mCardRect, cornerRadius, cornerRadius, mCardBorderPaint);

        // Chart area margins inside card
        float paddingBottom = mCompactMode ? 26f : 48f;
        float chartBottom = height - paddingBottom;
        float chartTop = mCompactMode ? 32f : 42f;
        float chartHeight = chartBottom - chartTop;

        // 2. Draw Bottom Timeline Markings
        drawTimelineAxis(canvas, width, height, chartBottom, dark);

        if (mDataPoints == null || mDataPoints.size() < 2) {
            drawEmptyBaseline(canvas, width, chartBottom, dark);
            return;
        }

        float maxSpeed = getMaxSpeed();
        if (maxSpeed <= 0.1f) maxSpeed = 10f; // Minimum scale baseline (10 KB/s)

        // 3. Draw Horizontal Grid Line & Scale Text
        drawGrid(canvas, width, chartTop, chartBottom, chartHeight, maxSpeed, dark);

        // 4. Setup Gradient Shaders for Area Fills
        if (!dark) {
            mDownFillPaint.setShader(new LinearGradient(
                    0, chartTop, 0, chartBottom,
                    Color.parseColor("#6600B4D8"), // 40% cyan
                    Color.parseColor("#0800B4D8"), // 3% cyan
                    Shader.TileMode.CLAMP
            ));
            mUpFillPaint.setShader(new LinearGradient(
                    0, chartTop, 0, chartBottom,
                    Color.parseColor("#55FF9E00"), // 33% orange
                    Color.parseColor("#05FF9E00"), // 2%
                    Shader.TileMode.CLAMP
            ));
        } else {
            mDownFillPaint.setShader(new LinearGradient(
                    0, chartTop, 0, chartBottom,
                    Color.parseColor("#7000B4D8"), // 44% cyan
                    Color.parseColor("#0500B4D8"),
                    Shader.TileMode.CLAMP
            ));
            mUpFillPaint.setShader(new LinearGradient(
                    0, chartTop, 0, chartBottom,
                    Color.parseColor("#48FF9E00"),
                    Color.parseColor("#02FF9E00"),
                    Shader.TileMode.CLAMP
            ));
        }

        // 5. Build Paths with Cubic Bézier Curves
        mDownPath.reset();
        mDownFillPath.reset();
        mUpPath.reset();
        mUpFillPath.reset();

        int n = mDataPoints.size();
        float[] xCoords = new float[n];
        float[] yDownCoords = new float[n];
        float[] yUpCoords = new float[n];

        for (int i = 0; i < n; i++) {
            DataPoint pt = mDataPoints.get(i);
            float x = ((float) i / (n - 1)) * (width - 24f) + 12f;
            float yDown = chartBottom - ((pt.downloadKbps / maxSpeed) * (chartHeight * 0.88f));
            float yUp = chartBottom - ((pt.uploadKbps / maxSpeed) * (chartHeight * 0.88f));

            xCoords[i] = x;
            yDownCoords[i] = Math.max(chartTop, Math.min(chartBottom, yDown));
            yUpCoords[i] = Math.max(chartTop, Math.min(chartBottom, yUp));
        }

        // Draw Download Splines
        buildBezierPath(mDownPath, mDownFillPath, xCoords, yDownCoords, width - 12f, chartBottom);
        canvas.drawPath(mDownFillPath, mDownFillPaint);
        canvas.drawPath(mDownPath, mDownLinePaint);

        // Draw Upload Splines (if enabled)
        if (mShowUpload) {
            buildBezierPath(mUpPath, mUpFillPath, xCoords, yUpCoords, width - 12f, chartBottom);
            canvas.drawPath(mUpFillPath, mUpFillPaint);
            canvas.drawPath(mUpPath, mUpLinePaint);
        }

        // 6. Draw Bottom Emerald Baseline Strip
        canvas.drawLine(12f, chartBottom, width - 12f, chartBottom, mBaselinePaint);

        // 7. Draw Event Pins (NEW app events and alert drops)
        drawEventPins(canvas, n, xCoords, yDownCoords);

        // 8. Draw Live Speed HUD & Security Badge
        drawSpeedHud(canvas, mDataPoints.get(n - 1), width, dark);

        // 9. Draw Interactive Touch Scrubber
        if (mIsTouching && !mCompactMode) {
            drawScrubberTooltip(canvas, width, height, chartTop, chartBottom, xCoords, n);
        }
    }

    private void drawTimelineAxis(Canvas canvas, int width, int height, float chartBottom, boolean dark) {
        float textY = chartBottom + (mCompactMode ? 18f : 26f);

        // 5 markers: -60s, -45s, -30s, -15s, NOW
        String[] labels = {"-60s", "-45s", "-30s", "-15s", "NOW"};
        float usableWidth = width - 36f;
        for (int i = 0; i < labels.length; i++) {
            float x = 18f + (i * (usableWidth / 4f));
            if (i == labels.length - 1) {
                mAxisPaint.setFakeBoldText(true);
                mAxisPaint.setColor(dark ? Color.parseColor("#38BDF8") : Color.parseColor("#0284C7"));
            } else {
                mAxisPaint.setFakeBoldText(false);
                mAxisPaint.setColor(dark ? Color.parseColor("#64748B") : Color.parseColor("#94A3B8"));
            }
            float textW = mAxisPaint.measureText(labels[i]);
            canvas.drawText(labels[i], Math.max(12f, Math.min(width - textW - 12f, x - (textW / 2f))), textY, mAxisPaint);
        }
    }

    private void buildBezierPath(Path linePath, Path fillPath, float[] x, float[] y, float width, float bottom) {
        int n = x.length;
        linePath.moveTo(x[0], y[0]);
        fillPath.moveTo(x[0], bottom);
        fillPath.lineTo(x[0], y[0]);

        for (int i = 0; i < n - 1; i++) {
            float p0x = (i > 0) ? x[i - 1] : x[0];
            float p0y = (i > 0) ? y[i - 1] : y[0];
            float p1x = x[i];
            float p1y = y[i];
            float p2x = x[i + 1];
            float p2y = y[i + 1];
            float p3x = (i + 2 < n) ? x[i + 2] : p2x;
            float p3y = (i + 2 < n) ? y[i + 2] : p2y;

            // Catmull-Rom to Cubic Bézier control points
            float c1x = p1x + (p2x - p0x) / 6f;
            float c1y = p1y + (p2y - p0y) / 6f;
            float c2x = p2x - (p3x - p1x) / 6f;
            float c2y = p2y - (p3y - p1y) / 6f;

            linePath.cubicTo(c1x, c1y, c2x, c2y, p2x, p2y);
            fillPath.cubicTo(c1x, c1y, c2x, c2y, p2x, p2y);
        }

        fillPath.lineTo(x[n - 1], bottom);
        fillPath.lineTo(x[0], bottom);
        fillPath.close();
    }

    private void drawEventPins(Canvas canvas, int n, float[] x, float[] y) {
        for (int i = 0; i < n; i++) {
            DataPoint pt = mDataPoints.get(i);
            if (pt.isNewAppEvent || pt.alertCount > 0) {
                float px = x[i];
                float py = y[i] - 22f;

                if (pt.isNewAppEvent) {
                    mBadgePaint.setColor(Color.parseColor("#10B981")); // Neon Emerald
                    canvas.drawCircle(px, py, 16f, mBadgePaint);
                    canvas.drawText("NEW", px, py + 6f, mBadgeTextPaint);
                } else {
                    mBadgePaint.setColor(Color.parseColor("#F97316")); // Vivid Safety Orange
                    canvas.drawCircle(px, py, 16f, mBadgePaint);
                    canvas.drawText(String.valueOf(pt.alertCount), px, py + 6f, mBadgeTextPaint);
                }
            }
        }
    }

    private void drawSpeedHud(Canvas canvas, DataPoint latest, int width, boolean dark) {
        String downStr = "↓ " + formatSpeed(latest.downloadKbps);
        String upStr   = "↑ " + formatSpeed(latest.uploadKbps);

        // Download Speed Pill / Text
        mTextPaint.setColor(dark ? Color.parseColor("#38BDF8") : Color.parseColor("#0284C7"));
        mTextPaint.setFakeBoldText(true);
        canvas.drawText(downStr, 18f, 26f, mTextPaint);

        if (mShowUpload) {
            float downWidth = mTextPaint.measureText(downStr);
            mTextPaint.setColor(dark ? Color.parseColor("#FBBF24") : Color.parseColor("#EA580C"));
            canvas.drawText(upStr, 18f + downWidth + 18f, 26f, mTextPaint);
        }

        // Top Right Security Badge with pulse indicator
        float badgeRight = width - 18f;
        mLogoPaint.setColor(Color.parseColor("#10B981")); // Live green pulse dot
        canvas.drawCircle(badgeRight - 66f, 20f, 4.5f, mLogoPaint);

        mTextPaint.setColor(dark ? Color.parseColor("#94A3B8") : Color.parseColor("#475569"));
        mTextPaint.setTextSize(19f);
        mTextPaint.setFakeBoldText(true);
        canvas.drawText("LIVE FLOW", badgeRight - 54f, 25f, mTextPaint);
        mTextPaint.setTextSize(26f);
    }

    private void drawGrid(Canvas canvas, int width, float top, float bottom, float height, float maxSpeed, boolean dark) {
        // Draw 50% line
        float midY = top + (height / 2f);
        canvas.drawLine(12f, midY, width - 12f, midY, mGridPaint);

        mTextPaint.setColor(dark ? Color.parseColor("#94A3B8") : Color.parseColor("#475569"));
        mTextPaint.setTextSize(20f);
        mTextPaint.setFakeBoldText(false);
        String halfSpeed = formatSpeed(maxSpeed / 2f);
        float textW = mTextPaint.measureText(halfSpeed);
        canvas.drawText(halfSpeed, width - textW - 18f, midY - 6f, mTextPaint);
        mTextPaint.setTextSize(26f);
    }

    private void drawEmptyBaseline(Canvas canvas, int width, float bottom, boolean dark) {
        canvas.drawLine(12f, bottom, width - 12f, bottom, mBaselinePaint);
        mTextPaint.setColor(dark ? Color.parseColor("#64748B") : Color.parseColor("#94A3B8"));
        mTextPaint.setTextSize(22f);
        canvas.drawText("Waiting for network activity...", 24f, bottom - 16f, mTextPaint);
        mTextPaint.setTextSize(26f);
    }

    private void drawScrubberTooltip(Canvas canvas, int width, int height, float top, float bottom, float[] xCoords, int n) {
        canvas.drawLine(mTouchX, top, mTouchX, bottom, mCursorPaint);

        // Find closest data point
        int closestIdx = 0;
        float minDiff = Float.MAX_VALUE;
        for (int i = 0; i < n; i++) {
            float diff = Math.abs(xCoords[i] - mTouchX);
            if (diff < minDiff) {
                minDiff = diff;
                closestIdx = i;
            }
        }

        DataPoint pt = mDataPoints.get(closestIdx);
        String timeStr = mTimeFmt.format(new Date(pt.timestamp));
        String speedStr = "↓" + formatSpeed(pt.downloadKbps) + "  ↑" + formatSpeed(pt.uploadKbps);

        float boxW = 230f;
        float boxH = 68f;
        float boxX = Math.max(12f, Math.min(width - boxW - 12f, mTouchX - (boxW / 2f)));
        float boxY = top + 8f;

        RectF rect = new RectF(boxX, boxY, boxX + boxW, boxY + boxH);
        canvas.drawRoundRect(rect, 14f, 14f, mTooltipBgPaint);

        mTextPaint.setColor(Color.WHITE);
        mTextPaint.setTextSize(20f);
        mTextPaint.setFakeBoldText(false);
        canvas.drawText(timeStr, boxX + 14f, boxY + 26f, mTextPaint);

        mTextPaint.setFakeBoldText(true);
        mTextPaint.setColor(Color.parseColor("#38BDF8"));
        canvas.drawText(speedStr, boxX + 14f, boxY + 52f, mTextPaint);
        mTextPaint.setTextSize(26f);
    }

    private float getMaxSpeed() {
        float max = 0f;
        for (DataPoint pt : mDataPoints) {
            if (pt.downloadKbps > max) max = pt.downloadKbps;
            if (mShowUpload && pt.uploadKbps > max) max = pt.uploadKbps;
        }
        return max;
    }

    private String formatSpeed(float kbps) {
        if (kbps >= 1024f) {
            return String.format(Locale.US, "%.1f MB/s", kbps / 1024f);
        }
        return String.format(Locale.US, "%.0f KB/s", kbps);
    }
}
