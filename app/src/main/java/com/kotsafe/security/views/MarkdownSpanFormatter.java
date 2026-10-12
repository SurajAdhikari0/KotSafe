/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.views;

import android.content.Context;
import android.graphics.Typeface;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.BackgroundColorSpan;
import android.text.style.ForegroundColorSpan;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.text.style.TypefaceSpan;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * High-performance, lightweight Markdown & Cyber Monospace Spanned Formatter for KotSafe AI.
 * Parses headers, bolding, italics, bullet points, and dark terminal chips for IOCs/code.
 */
public final class MarkdownSpanFormatter {

    private static final Pattern PATTERN_H3 = Pattern.compile("(?m)^###\\s+(.*)$");
    private static final Pattern PATTERN_H4 = Pattern.compile("(?m)^####\\s+(.*)$");
    private static final Pattern PATTERN_BOLD = Pattern.compile("\\*\\*(.+?)\\*\\*");
    private static final Pattern PATTERN_ITALIC = Pattern.compile("(?<!\\*)\\*(?!\\*)(.+?)(?<!\\*)\\*(?!\\*)");
    private static final Pattern PATTERN_CODE = Pattern.compile("`([^`]+)`");

    private MarkdownSpanFormatter() {
    }

    public static CharSequence format(String rawText, Context context) {
        if (rawText == null || rawText.isEmpty()) {
            return "";
        }

        // Process line by line and regex replacements
        String text = rawText;

        // 1. Convert headers
        Matcher mH3 = PATTERN_H3.matcher(text);
        StringBuffer sbH3 = new StringBuffer();
        while (mH3.find()) {
            mH3.appendReplacement(sbH3, "§§H3_" + mH3.group(1).trim() + "_3H§§");
        }
        mH3.appendTail(sbH3);
        text = sbH3.toString();

        Matcher mH4 = PATTERN_H4.matcher(text);
        StringBuffer sbH4 = new StringBuffer();
        while (mH4.find()) {
            mH4.appendReplacement(sbH4, "§§H4_" + mH4.group(1).trim() + "_4H§§");
        }
        mH4.appendTail(sbH4);
        text = sbH4.toString();

        // 2. Mark bold
        Matcher mBold = PATTERN_BOLD.matcher(text);
        StringBuffer sbBold = new StringBuffer();
        while (mBold.find()) {
            mBold.appendReplacement(sbBold, "§§B_" + mBold.group(1) + "_B§§");
        }
        mBold.appendTail(sbBold);
        text = sbBold.toString();

        // 3. Mark code / IOC chips
        Matcher mCode = PATTERN_CODE.matcher(text);
        StringBuffer sbCode = new StringBuffer();
        while (mCode.find()) {
            mCode.appendReplacement(sbCode, "§§C_ " + mCode.group(1) + " _C§§");
        }
        mCode.appendTail(sbCode);
        text = sbCode.toString();

        // 4. Mark italic
        Matcher mItalic = PATTERN_ITALIC.matcher(text);
        StringBuffer sbItalic = new StringBuffer();
        while (mItalic.find()) {
            mItalic.appendReplacement(sbItalic, "§§I_" + mItalic.group(1) + "_I§§");
        }
        mItalic.appendTail(sbItalic);
        text = sbItalic.toString();

        // Now build the SpannableStringBuilder
        SpannableStringBuilder builder = new SpannableStringBuilder(text);

        // Apply H3 spans
        applyTagSpans(builder, "§§H3_", "_3H§§", (b, start, end) -> {
            b.setSpan(new StyleSpan(Typeface.BOLD), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            b.setSpan(new RelativeSizeSpan(1.15f), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            b.setSpan(new ForegroundColorSpan(0xFF38BDF8), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE); // Cyber Cyan
        });

        // Apply H4 spans
        applyTagSpans(builder, "§§H4_", "_4H§§", (b, start, end) -> {
            b.setSpan(new StyleSpan(Typeface.BOLD), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            b.setSpan(new RelativeSizeSpan(1.08f), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            b.setSpan(new ForegroundColorSpan(0xFF67E8F9), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        });

        // Apply Bold spans
        applyTagSpans(builder, "§§B_", "_B§§", (b, start, end) -> {
            b.setSpan(new StyleSpan(Typeface.BOLD), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        });

        // Apply Code / IOC chip spans
        applyTagSpans(builder, "§§C_", "_C§§", (b, start, end) -> {
            b.setSpan(new TypefaceSpan("monospace"), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            b.setSpan(new BackgroundColorSpan(0xFF1E293B), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE); // Dark slate pill
            b.setSpan(new ForegroundColorSpan(0xFF38BDF8), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE); // Cyan text
            b.setSpan(new RelativeSizeSpan(0.92f), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        });

        // Apply Italic spans
        applyTagSpans(builder, "§§I_", "_I§§", (b, start, end) -> {
            b.setSpan(new StyleSpan(Typeface.ITALIC), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        });

        return builder;
    }

    private interface SpanApplier {
        void apply(SpannableStringBuilder builder, int start, int end);
    }

    private static void applyTagSpans(SpannableStringBuilder builder, String prefix, String suffix, SpanApplier applier) {
        int index;
        while ((index = builder.toString().indexOf(prefix)) != -1) {
            int closeIndex = builder.toString().indexOf(suffix, index + prefix.length());
            if (closeIndex == -1) {
                break;
            }

            // Remove suffix first to preserve indices
            builder.delete(closeIndex, closeIndex + suffix.length());
            // Remove prefix
            builder.delete(index, index + prefix.length());

            int contentEnd = closeIndex - prefix.length();
            if (contentEnd > index) {
                applier.apply(builder, index, contentEnd);
            }
        }
    }
}
