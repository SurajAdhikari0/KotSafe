package com.kotsafe.security.activities.prefs;

import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatDelegate;
import androidx.core.os.LocaleListCompat;
import androidx.preference.PreferenceManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.model.Prefs;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.bottomsheet.BottomSheetDialog;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;
import com.google.android.material.card.MaterialCardView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class LanguagePickerDialog extends BottomSheetDialogFragment {
    public static final String TAG = "LanguagePickerDialog";

    public interface OnLanguageSelectedListener {
        void onLanguageSelected(String tag, String displayName);
    }

    private OnLanguageSelectedListener mListener;
    private LanguageAdapter mAdapter;
    private final List<LanguageItem> mAllLanguages = new ArrayList<>();
    private final List<LanguageItem> mFilteredLanguages = new ArrayList<>();
    private String mCurrentTag = "system";

    public static class LanguageItem {
        public final String tag;
        public final String flag;
        public final String nativeName;
        public final String englishName;

        public LanguageItem(String tag, String flag, String nativeName, String englishName) {
            this.tag = tag;
            this.flag = flag;
            this.nativeName = nativeName;
            this.englishName = englishName;
        }
    }

    public static LanguagePickerDialog newInstance() {
        return new LanguagePickerDialog();
    }

    public void setOnLanguageSelectedListener(OnLanguageSelectedListener listener) {
        mListener = listener;
    }

    @NonNull
    @Override
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        BottomSheetDialog dialog = (BottomSheetDialog) super.onCreateDialog(savedInstanceState);
        dialog.setOnShowListener(d -> {
            BottomSheetDialog bsd = (BottomSheetDialog) d;
            FrameLayout bottomSheet = bsd.findViewById(com.google.android.material.R.id.design_bottom_sheet);
            if (bottomSheet != null) {
                BottomSheetBehavior<FrameLayout> behavior = BottomSheetBehavior.from(bottomSheet);
                behavior.setState(BottomSheetBehavior.STATE_EXPANDED);
                behavior.setSkipCollapsed(true);
            }
        });
        return dialog;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.dialog_language_picker, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
        String savedTag = prefs.getString(Prefs.PREF_APP_LANGUAGE, "system");
        mCurrentTag = (savedTag != null && !savedTag.isEmpty()) ? savedTag : "system";

        loadLanguageCatalog(requireContext());

        RecyclerView rv = view.findViewById(R.id.rv_languages);
        EditText etSearch = view.findViewById(R.id.et_language_search);
        ImageView ivClear = view.findViewById(R.id.iv_clear_search);

        rv.setLayoutManager(new LinearLayoutManager(requireContext()));
        mAdapter = new LanguageAdapter();
        rv.setAdapter(mAdapter);

        filterLanguages("");

        etSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
                String query = s.toString().trim();
                ivClear.setVisibility(query.isEmpty() ? View.GONE : View.VISIBLE);
                filterLanguages(query);
            }

            @Override
            public void afterTextChanged(Editable s) {}
        });

        ivClear.setOnClickListener(v -> etSearch.setText(""));
    }

    private void filterLanguages(String query) {
        mFilteredLanguages.clear();
        if (query.isEmpty()) {
            mFilteredLanguages.addAll(mAllLanguages);
        } else {
            String lower = query.toLowerCase(Locale.ROOT);
            for (LanguageItem item : mAllLanguages) {
                if (item.nativeName.toLowerCase(Locale.ROOT).contains(lower)
                        || item.englishName.toLowerCase(Locale.ROOT).contains(lower)
                        || item.tag.toLowerCase(Locale.ROOT).contains(lower)) {
                    mFilteredLanguages.add(item);
                }
            }
        }
        if (mAdapter != null) {
            mAdapter.notifyDataSetChanged();
        }
    }

    private void loadLanguageCatalog(Context context) {
        mAllLanguages.clear();

        // Metadata mapping for language tags to Country Flag Emojis & Display info
        Map<String, String[]> meta = new HashMap<>();
        meta.put("en-US", new String[]{"🇺🇸", "English (United States)", "English"});
        meta.put("hi", new String[]{"🇮🇳", "हिन्दी", "Hindi (Indian Language)"});
        meta.put("ne", new String[]{"🇳🇵", "नेपाली", "Nepali (नेपाल)"});
        meta.put("ta", new String[]{"🇮🇳", "தமிழ்", "Tamil (Indian Language)"});
        meta.put("bn", new String[]{"🇧🇩", "বাংলা", "Bengali (Indian Subcontinent)"});
        meta.put("ur", new String[]{"🇵🇰", "اردو", "Urdu (Indian Subcontinent)"});
        meta.put("es", new String[]{"🇪🇸", "Español", "Spanish"});
        meta.put("fr", new String[]{"🇫🇷", "Français", "French"});
        meta.put("de", new String[]{"🇩🇪", "Deutsch", "German"});
        meta.put("it", new String[]{"🇮🇹", "Italiano", "Italian"});
        meta.put("pt", new String[]{"🇵🇹", "Português (Portugal)", "Portuguese"});
        meta.put("pt-BR", new String[]{"🇧🇷", "Português (Brasil)", "Portuguese (Brazil)"});
        meta.put("ru", new String[]{"🇷🇺", "Русский", "Russian"});
        meta.put("uk", new String[]{"🇺🇦", "Українська", "Ukrainian"});
        meta.put("ar", new String[]{"🇸🇦", "العربية", "Arabic"});
        meta.put("tr", new String[]{"🇹🇷", "Türkçe", "Turkish"});
        meta.put("az", new String[]{"🇦🇿", "Azərbaycan dili", "Azerbaijani"});
        meta.put("in", new String[]{"🇮🇩", "Bahasa Indonesia", "Indonesian"});
        meta.put("ms", new String[]{"🇲🇾", "Bahasa Melayu", "Malay"});
        meta.put("vi", new String[]{"🇻🇳", "Tiếng Việt", "Vietnamese"});
        meta.put("zh-Hans", new String[]{"🇨🇳", "简体中文", "Chinese (Simplified)"});
        meta.put("ja", new String[]{"🇯🇵", "日本語", "Japanese"});
        meta.put("ko", new String[]{"🇰🇷", "한국어", "Korean"});
        meta.put("pl", new String[]{"🇵🇱", "Polski", "Polish"});

        // 1. System Default
        mAllLanguages.add(new LanguageItem(
                "system",
                "🌐",
                getString(R.string.system_default),
                "Follow device system language"
        ));

        // 2. English
        mAllLanguages.add(new LanguageItem("en-US", "🇺🇸", "English (United States)", "English"));

        // 3. Hindi & Regional languages (Nepali placed directly below Hindi)
        mAllLanguages.add(new LanguageItem("hi", "🇮🇳", "हिन्दी", "Hindi (India)"));
        mAllLanguages.add(new LanguageItem("ne", "🇳🇵", "नेपाली", "Nepali (नेपाल)"));
        mAllLanguages.add(new LanguageItem("ta", "🇮🇳", "தமிழ்", "Tamil (India)"));

        // 4. Other languages (with Urdu and Bangla placed directly above Korean)
        String[] otherTags = new String[]{
                "es", "fr", "de", "it", "pt", "pt-BR", "ru", "uk", "ar", "tr", "az", "in", "ms", "vi", "zh-Hans", "ja", "ur", "bn", "ko", "pl"
        };
        for (String tag : otherTags) {
            String[] info = meta.get(tag);
            if (info != null) {
                mAllLanguages.add(new LanguageItem(tag, info[0], info[1], info[2]));
            }
        }
    }

    public static String getLanguageDisplayName(Context context, String tag) {
        if (tag == null || "system".equals(tag) || tag.isEmpty()) {
            return "🌐 " + context.getString(R.string.system_default);
        }
        switch (tag) {
            case "en-US": return "🇺🇸 English";
            case "hi": return "🇮🇳 हिन्दी";
            case "ne": return "🇳🇵 नेपाली";
            case "ta": return "🇮🇳 தமிழ்";
            case "ar": return "🇸🇦 العربية";
            case "az": return "🇦🇿 Azərbaycan";
            case "de": return "🇩🇪 Deutsch";
            case "es": return "🇪🇸 Español";
            case "fr": return "🇫🇷 Français";
            case "in": return "🇮🇩 Bahasa Indonesia";
            case "it": return "🇮🇹 Italiano";
            case "ja": return "🇯🇵 日本語";
            case "ur": return "🇵🇰 اردو";
            case "bn": return "🇧🇩 বাংলা";
            case "ko": return "🇰🇷 한국어";
            case "ms": return "🇲🇾 Bahasa Melayu";
            case "pl": return "🇵🇱 Polski";
            case "pt": return "🇵🇹 Português";
            case "pt-BR": return "🇧🇷 Português (BR)";
            case "ru": return "🇷🇺 Русский";
            case "tr": return "🇹🇷 Türkçe";
            case "uk": return "🇺🇦 Українська";
            case "vi": return "🇻🇳 Tiếng Việt";
            case "zh-Hans": return "🇨🇳 简体中文";
            default:
                Locale l = Locale.forLanguageTag(tag);
                return "🌍 " + l.getDisplayName(l);
        }
    }

    private class LanguageAdapter extends RecyclerView.Adapter<LanguageAdapter.ViewHolder> {
        @NonNull
        @Override
        public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_language_picker, parent, false);
            return new ViewHolder(v);
        }

        @Override
        public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
            LanguageItem item = mFilteredLanguages.get(position);
            holder.tvFlag.setText(item.flag);
            holder.tvNativeName.setText(item.nativeName);
            holder.tvEnglishName.setText(item.englishName);

            boolean isSelected = item.tag.equals(mCurrentTag);
            holder.ivSelected.setVisibility(isSelected ? View.VISIBLE : View.GONE);
            holder.card.setStrokeColor(isSelected ? 0xFF00E5FF : 0x1F888888);

            holder.itemView.setOnClickListener(v -> {
                Context ctx = requireContext();
                SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ctx);
                prefs.edit().putString(Prefs.PREF_APP_LANGUAGE, item.tag).apply();

                // Apply globally via AppCompatDelegate for Android 13+ / per-app locale API
                if ("system".equals(item.tag)) {
                    AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList());
                } else {
                    AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(item.tag));
                }

                if (mListener != null) {
                    mListener.onLanguageSelected(item.tag, item.nativeName);
                }

                dismiss();

                // Clean restart of SettingsActivity to re-inflate localized resources cleanly
                Intent intent = new Intent(ctx, SettingsActivity.class);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
                intent.setAction("lang_restart");
                startActivity(intent);
            });
        }

        @Override
        public int getItemCount() {
            return mFilteredLanguages.size();
        }

        class ViewHolder extends RecyclerView.ViewHolder {
            MaterialCardView card;
            TextView tvFlag;
            TextView tvNativeName;
            TextView tvEnglishName;
            ImageView ivSelected;

            public ViewHolder(@NonNull View itemView) {
                super(itemView);
                card = (MaterialCardView) itemView;
                tvFlag = itemView.findViewById(R.id.tv_flag);
                tvNativeName = itemView.findViewById(R.id.tv_native_name);
                tvEnglishName = itemView.findViewById(R.id.tv_english_name);
                ivSelected = itemView.findViewById(R.id.iv_selected);
            }
        }
    }
}
