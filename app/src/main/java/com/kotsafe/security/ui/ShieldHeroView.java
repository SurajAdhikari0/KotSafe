package com.kotsafe.security.ui;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.BlurMaskFilter;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.SweepGradient;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.LinearInterpolator;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.drawable.DrawableCompat;

import com.kotsafe.security.R;

/**
 * KotSafe hero: segmented glowing ring + drifting data particles.
 * IDLE   -> shield icon + "Ready" (static)
 * RUNNING-> big text (e.g. "19.6 KB"), ring rotates, particles flow toward the ring.
 *
 * Colors come from res/values(-night)/colors.xml, so day/night switch automatically.
 */
public class ShieldHeroView extends View {

    public enum State { IDLE, RUNNING }

    private static final float DW = 350f;      // design width in dp-ish units
    private static final int SIDES = 2, ROWS = 5, COLS = 17;

    private final Paint ringPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint glowPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint thinPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint discPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint dotPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF arcRect = new RectF();

    private State state = State.IDLE;
    private String centerText = "Ready";
    private float rotation = 0f;   // degrees
    private float drift = 0f;      // 0..1

    private Drawable shieldIcon;
    private ValueAnimator rotator, drifter;
    private int ringStart, ringEnd, glowAlpha;

    public ShieldHeroView(Context c) { this(c, null); }
    public ShieldHeroView(Context c, @Nullable AttributeSet a) { this(c, a, 0); }
    public ShieldHeroView(Context c, @Nullable AttributeSet a, int s) {
        super(c, a, s);
        setLayerType(LAYER_TYPE_SOFTWARE, null); // needed for BlurMaskFilter glow
        ringPaint.setStyle(Paint.Style.STROKE);
        ringPaint.setStrokeCap(Paint.Cap.ROUND);
        glowPaint.setStyle(Paint.Style.STROKE);
        thinPaint.setStyle(Paint.Style.STROKE);
        discPaint.setStyle(Paint.Style.FILL);
        dotPaint.setStyle(Paint.Style.FILL);
        textPaint.setTextAlign(Paint.Align.CENTER);
        textPaint.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        loadColors();
    }

    private void loadColors() {
        Context c = getContext();
        ringStart = ContextCompat.getColor(c, R.color.ks_ring_start);
        ringEnd = ContextCompat.getColor(c, R.color.ks_ring_end);
        glowAlpha = c.getResources().getInteger(R.integer.ks_glow_alpha);
        discPaint.setColor(ContextCompat.getColor(c, R.color.ks_ground));
        thinPaint.setColor(ringStart);
        Drawable d = ContextCompat.getDrawable(c, R.drawable.ic_shield_check);
        if (d != null) {
            shieldIcon = DrawableCompat.wrap(d.mutate());
            DrawableCompat.setTint(shieldIcon, ringStart);
        }
    }

    public void setCenterText(@NonNull String text) { centerText = text; invalidate(); }

    public void setCenterTypeface(@NonNull Typeface tf) { textPaint.setTypeface(tf); invalidate(); }

    public void setState(@NonNull State s) {
        if (state == s) return;
        state = s;
        centerText = (s == State.IDLE) ? "Ready" : centerText;
        updateAnimators();
        invalidate();
    }

    public State getState() { return state; }

    private void updateAnimators() {
        stopAnimators();
        if (state != State.RUNNING || !isAttachedToWindow()) { rotation = 0f; drift = 0f; return; }
        rotator = ValueAnimator.ofFloat(0f, 360f);
        rotator.setDuration(14000);
        rotator.setInterpolator(new LinearInterpolator());
        rotator.setRepeatCount(ValueAnimator.INFINITE);
        rotator.addUpdateListener(a -> { rotation = (float) a.getAnimatedValue(); postInvalidateOnAnimation(); });
        rotator.start();
        drifter = ValueAnimator.ofFloat(0f, 1f);
        drifter.setDuration(6000);
        drifter.setInterpolator(new LinearInterpolator());
        drifter.setRepeatCount(ValueAnimator.INFINITE);
        drifter.addUpdateListener(a -> drift = (float) a.getAnimatedValue());
        drifter.start();
    }

    private void stopAnimators() {
        if (rotator != null) { rotator.cancel(); rotator = null; }
        if (drifter != null) { drifter.cancel(); drifter = null; }
    }

    @Override protected void onAttachedToWindow() { super.onAttachedToWindow(); loadColors(); onSizeChanged(getWidth(), getHeight(), 0, 0); updateAnimators(); }
    @Override protected void onDetachedFromWindow() { stopAnimators(); super.onDetachedFromWindow(); }

    @Override
    protected void onSizeChanged(int w, int h, int ow, int oh) {
        super.onSizeChanged(w, h, ow, oh);
        final float s = w / DW, cx = w / 2f, cy = 126f * s;
        SweepGradient sg = new SweepGradient(cx, cy, new int[]{ringStart, ringEnd, ringStart}, null);
        ringPaint.setShader(sg);
        glowPaint.setShader(sg);
        ringPaint.setStrokeWidth(7f * s);
        glowPaint.setStrokeWidth(9f * s);
        glowPaint.setMaskFilter(new BlurMaskFilter(Math.max(1f, 7f * s), BlurMaskFilter.Blur.NORMAL));
    }

    @Override
    protected void onDraw(@NonNull Canvas canvas) {
        final float w = getWidth(), h = getHeight();
        if (w <= 0) return;
        final float s = w / DW, cx = w / 2f, cy = 126f * s;

        // 1) particles
        for (int side = -1; side <= 1; side += 2) {
            for (int r = 0; r < ROWS; r++) {
                float off = (r - 2) * 15f;
                for (int i = 0; i < COLS; i++) {
                    float t = i / (float) (COLS - 1);
                    float tt = ((t - drift) % 1f + 1f) % 1f;
                    float x = cx + side * (95f + tt * 78f) * s;
                    float y = cy + (off * (1f - 0.25f * tt) * (1f + 0.9f * tt)
                            + (float) Math.sin(tt * 5f + r * 0.9f) * (6f + 10f * tt)) * s;
                    float fade = Math.min(1f, tt / 0.06f);
                    float a = (0.85f * (float) Math.pow(1f - tt, 1.2f) + 0.08f) * fade;
                    dotPaint.setColor(ringStart);
                    dotPaint.setAlpha((int) (255 * a));
                    canvas.drawCircle(x, y, (1f + 1.1f * (1f - tt)) * s, dotPaint);
                }
            }
        }

        // 2) segmented ring (+ glow)
        final float ringRadius = 86f * s;
        arcRect.set(cx - ringRadius, cy - ringRadius, cx + ringRadius, cy + ringRadius);
        glowPaint.setAlpha(glowAlpha);
        canvas.save();
        canvas.rotate(rotation - 12f, cx, cy);
        for (int i = 0; i < 8; i++) {
            float start = i * 45f;
            canvas.drawArc(arcRect, start, 38f, false, glowPaint);
            canvas.drawArc(arcRect, start, 38f, false, ringPaint);
        }
        canvas.restore();

        // 3) inner disc + hairline
        canvas.drawCircle(cx, cy, 72f * s, discPaint);
        thinPaint.setStrokeWidth(1.5f * s);
        canvas.drawCircle(cx, cy, 72f * s, thinPaint);

        // 4) center content
        if (state == State.IDLE) {
            if (shieldIcon != null) {
                int half = (int) (20f * s);
                int top = (int) (cy - 58f * s);
                shieldIcon.setBounds((int) cx - half, top, (int) cx + half, top + 2 * half);
                shieldIcon.draw(canvas);
            }
            textPaint.setColor(ContextCompat.getColor(getContext(), R.color.ks_ink));
            textPaint.setTextSize(34f * s);
            canvas.drawText(centerText, cx, cy + 22f * s, textPaint);
        } else {
            textPaint.setColor(ContextCompat.getColor(getContext(), R.color.ks_hero_num));
            textPaint.setTextSize(18f * s);
            canvas.save();
            canvas.clipRect(cx - 72f * s, cy - 72f * s, cx + 72f * s, cy + 72f * s);
            canvas.drawText(centerText, cx, cy + 10f * s, textPaint);
            canvas.restore();
        }
    }
}
