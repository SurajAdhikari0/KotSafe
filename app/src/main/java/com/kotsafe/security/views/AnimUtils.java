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

import android.animation.Animator;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.content.Context;
import android.util.TypedValue;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;
import android.widget.TextView;

import androidx.interpolator.view.animation.FastOutSlowInInterpolator;

/**
 * High-performance motion and micro-interaction utilities for KotSafe.
 * All animations are GPU-accelerated and strictly manipulate RenderThread properties.
 */
public final class AnimUtils {

    private AnimUtils() {}

    /**
     * Converts DP units to physical screen pixels.
     */
    public static float dpToPx(Context context, float dp) {
        if (context == null) return dp * 2.0f;
        return TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP,
                dp,
                context.getResources().getDisplayMetrics()
        );
    }

    /**
     * Attaches spring-physics touch scaling and micro-haptic feedback to any view or card.
     */
    @SuppressLint("ClickableViewAccessibility")
    public static void attachSpringTouch(View view) {
        if (view == null) return;

        view.setOnTouchListener((v, event) -> {
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    v.animate()
                            .scaleX(0.95f)
                            .scaleY(0.95f)
                            .setDuration(70)
                            .setInterpolator(new DecelerateInterpolator())
                            .start();
                    v.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
                    break;

                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    v.animate()
                            .scaleX(1.0f)
                            .scaleY(1.0f)
                            .setDuration(180)
                            .setInterpolator(new OvershootInterpolator(1.5f))
                            .start();
                    break;
            }
            return false; // Allow click listeners to trigger normally
        });
    }

    /**
     * Runs a staggered cascading entrance animation across an array of Views.
     * Moves views from translationY + alpha 0 -> neutral 0 + alpha 1.
     */
    public static void playStaggeredEntrance(View[] views, int baseDelayMs, int staggerMs) {
        if (views == null || views.length == 0) return;

        for (int i = 0; i < views.length; i++) {
            View v = views[i];
            if (v == null) continue;

            float offsetPx = dpToPx(v.getContext(), 32);
            v.setAlpha(0f);
            v.setTranslationY(offsetPx);

            v.animate()
                    .alpha(1.0f)
                    .translationY(0f)
                    .setStartDelay(baseDelayMs + (long) i * staggerMs)
                    .setDuration(320)
                    .setInterpolator(new DecelerateInterpolator(1.4f))
                    .start();
        }
    }

    /**
     * Smoothly counts up a numerical score in a TextView with a percentage or custom suffix.
     */
    public static ValueAnimator animateScoreCountUp(TextView textView, int startVal, int endVal, long durationMs, String suffix) {
        if (textView == null) return null;

        ValueAnimator animator = ValueAnimator.ofInt(startVal, endVal);
        animator.setDuration(durationMs > 0 ? durationMs : 800);
        animator.setInterpolator(new FastOutSlowInInterpolator());
        final String safeSuffix = suffix != null ? suffix : "";

        animator.addUpdateListener(animation -> {
            int currentVal = (int) animation.getAnimatedValue();
            textView.setText(String.format(java.util.Locale.US, "%d%s", currentVal, safeSuffix));
        });

        animator.start();
        return animator;
    }

    /**
     * Starts an infinite breathing glow animation (repeating reverse alpha pulse).
     */
    public static ObjectAnimator startBreathingGlow(View view, float minAlpha, float maxAlpha, long durationMs) {
        if (view == null) return null;

        ObjectAnimator animator = ObjectAnimator.ofFloat(view, View.ALPHA, minAlpha, maxAlpha);
        animator.setDuration(durationMs > 0 ? durationMs : 1400);
        animator.setRepeatMode(ValueAnimator.REVERSE);
        animator.setRepeatCount(ValueAnimator.INFINITE);
        animator.setInterpolator(new AccelerateDecelerateInterpolator());
        animator.start();
        return animator;
    }

    /**
     * Shakes a view horizontally to alert the user of a detected threat or validation error.
     */
    public static void shakeView(View view) {
        if (view == null) return;

        float offsetPx = dpToPx(view.getContext(), 10);
        view.animate()
                .translationXBy(-offsetPx)
                .setDuration(50)
                .withEndAction(() -> view.animate()
                        .translationXBy(offsetPx * 2)
                        .setDuration(50)
                        .withEndAction(() -> view.animate()
                                .translationXBy(-offsetPx * 1.5f)
                                .setDuration(50)
                                .withEndAction(() -> view.animate()
                                        .translationX(0f)
                                        .setDuration(50)
                                        .start())
                                .start())
                        .start())
                .start();
    }

    /**
     * Pulses a view to draw attention or indicate successful state activation.
     */
    public static void playPulse(View view) {
        if (view == null) return;
        view.animate()
                .scaleX(1.04f)
                .scaleY(1.04f)
                .setDuration(120)
                .setInterpolator(new DecelerateInterpolator())
                .withEndAction(() -> view.animate()
                        .scaleX(1.0f)
                        .scaleY(1.0f)
                        .setDuration(200)
                        .setInterpolator(new OvershootInterpolator(2.0f))
                        .start())
                .start();
    }
}

