/*
 * This file is part of KotSafe / KotSafe Cyber Security Project.
 * GPL-3.0 License — see <http://www.gnu.org/licenses/>
 */

package com.kotsafe.security.activities;

import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.content.ContextCompat;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import java.net.InetSocketAddress;
import java.net.Socket;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.kotsafe.security.R;
import com.kotsafe.security.activities.prefs.SettingsActivity;
import com.kotsafe.security.ai.AiAccessController;
import com.kotsafe.security.ai.AiClientEngine;
import com.kotsafe.security.ai.AiConfig;
import com.kotsafe.security.ai.OfflineKnowledgeEngine;
import com.kotsafe.security.fragments.prefs.AiProtectionSettings;
import android.widget.LinearLayout;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.chip.Chip;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.model.AlertRecord;
import com.kotsafe.security.model.AlertStore;
import com.kotsafe.security.model.CaptureStats;
import com.kotsafe.security.model.Prefs;
import com.kotsafe.security.model.SecurityRulesDb;
import com.kotsafe.security.views.AnimUtils;
import com.kotsafe.security.views.MarkdownSpanFormatter;
import com.kotsafe.security.views.ThreatInvestigationDialog;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Interactive on-device AI Security Assistant providing deep explanations
 * of KotSafe metrics, features, repeater sessions, and threat intelligence.
 */
public class AiAssistantActivity extends AppCompatActivity {

    public static class ActionDescriptor {
        public final String type;
        public final String target;
        public boolean executed;

        public ActionDescriptor(String type, String target) {
            this.type = type != null ? type.trim() : "";
            this.target = target != null ? target.trim() : "";
            this.executed = false;
        }
    }

    public static class ChatMessage {
        public String text;
        public final boolean isUser;
        public final long timestamp;
        public final List<ActionDescriptor> actions = new ArrayList<>();
        public boolean isStreaming;

        // Legacy compatibility
        public String actionType;
        public String actionTarget;
        public boolean actionExecuted;

        public ChatMessage(String text, boolean isUser) {
            this(text, isUser, null, null);
        }

        public ChatMessage(String text, boolean isUser, String actionType, String actionTarget) {
            this.text = text;
            this.isUser = isUser;
            this.timestamp = System.currentTimeMillis();
            this.actionType = actionType;
            this.actionTarget = actionTarget;
            this.actionExecuted = false;
            this.isStreaming = false;
            if (actionType != null && !actionType.isEmpty()) {
                this.actions.add(new ActionDescriptor(actionType, actionTarget));
            }
        }
    }

    private static final long AI_CHAT_HISTORY_TTL_MS = 24L * 60 * 60 * 1000L;
    private static final String PREF_AI_CHAT_HISTORY_TS = "ai_chat_history_ts";

    private RecyclerView mRvMessages;
    private ChatAdapter mAdapter;
    private final List<ChatMessage> mMessages = new ArrayList<>();

    private EditText mEtInput;
    private ImageButton mBtnSend;
    private View mLayoutThinking;
    private TextView mTvThinkingStatus;
    private TextView mTvActivePermissions;

    private AiAccessController mAccessController;
    private AiClientEngine mAiClient;
    private AiConfig mConfig;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_ai_assistant);

        Toolbar toolbar = findViewById(R.id.toolbar);
        if (toolbar != null) {
            setSupportActionBar(toolbar);
            if (getSupportActionBar() != null) {
                getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            }
        }

        mAccessController = new AiAccessController(this);
        mAiClient = AiClientEngine.getInstance(this);
        mConfig = mAccessController.getConfig();

        mRvMessages = findViewById(R.id.rv_chat_messages);
        mEtInput = findViewById(R.id.et_prompt_input);
        mBtnSend = findViewById(R.id.btn_send_prompt);
        mLayoutThinking = findViewById(R.id.layout_thinking);
        mTvThinkingStatus = findViewById(R.id.tv_thinking_status);
        mTvActivePermissions = findViewById(R.id.tv_active_permissions);
        View bannerPrivacy = findViewById(R.id.banner_privacy);

        View btnDismiss = findViewById(R.id.btn_dismiss_banner);
        if (btnDismiss != null && bannerPrivacy != null) {
            btnDismiss.setOnClickListener(v -> bannerPrivacy.setVisibility(View.GONE));
        }

        mAdapter = new ChatAdapter(mMessages);
        LinearLayoutManager lm = new LinearLayoutManager(this);
        lm.setStackFromEnd(true);
        mRvMessages.setLayoutManager(lm);
        mRvMessages.setAdapter(mAdapter);

        findViewById(R.id.btn_config_permissions).setOnClickListener(v -> {
            Intent intent = new Intent(this, SettingsActivity.class);
            intent.putExtra(SettingsActivity.TARGET_PREF_EXTRA, "ai_protection_settings");
            startActivity(intent);
        });

        if (mBtnSend != null) {
            AnimUtils.attachSpringTouch(mBtnSend);
            mBtnSend.setOnClickListener(v -> sendUserPrompt());
        }

        setupQuickChips();
        updatePermissionsBanner();
        enforceChatHistoryExpiry();
        addWelcomeMessage();
        handleIntentPrompt(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntentPrompt(intent);
    }

    private void handleIntentPrompt(Intent intent) {
        if (intent != null) {
            String p = null;
            if (intent.hasExtra("prompt")) {
                p = intent.getStringExtra("prompt");
            } else if (intent.hasExtra("prefill_query")) {
                p = intent.getStringExtra("prefill_query");
            } else if (intent.hasExtra("query")) {
                p = intent.getStringExtra("query");
            }
            if (p != null && !p.trim().isEmpty()) {
                mEtInput.setText(p);
                sendUserPrompt();
            }
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        enforceChatHistoryExpiry();
        updatePermissionsBanner();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    private void updatePermissionsBanner() {
        if (toolbarSubtitleUpdate() != null && getSupportActionBar() != null) {
            getSupportActionBar().setSubtitle(toolbarSubtitleUpdate());
        }

        View bannerPrivacy = findViewById(R.id.banner_privacy);
        if (bannerPrivacy == null) return;

        boolean allEnabled = mConfig.canAccessStatus()
                && mConfig.canAccessConnections()
                && mConfig.canAccessHttp()
                && mConfig.canAccessRepeater()
                && mConfig.canAccessFirewall()
                && mConfig.canAccessAntivirus()
                && mConfig.canAccessLogs();

        if (allEnabled) {
            // All permissions are already enabled! Hide the banner completely so it doesn't clutter the screen
            bannerPrivacy.setVisibility(View.GONE);
        } else {
            bannerPrivacy.setVisibility(View.VISIBLE);
            int count = 0;
            if (mConfig.canAccessStatus()) count++;
            if (mConfig.canAccessConnections()) count++;
            if (mConfig.canAccessHttp()) count++;
            if (mConfig.canAccessRepeater()) count++;
            if (mConfig.canAccessFirewall()) count++;
            if (mConfig.canAccessAntivirus()) count++;
            if (mConfig.canAccessLogs()) count++;

            if (count == 0) {
                mTvActivePermissions.setText("Privacy Active • Live data access is disabled");
            } else {
                mTvActivePermissions.setText("Privacy Active • " + count + " of 7 data access levels enabled");
            }
        }
    }

    private String toolbarSubtitleUpdate() {
        if (!mConfig.isAiEnabled()) return "Offline Security Intelligence (Active)";
        if (!mConfig.getProvider().isOnDevice() && mConfig.getProvider() != AiConfig.Provider.LOCAL_CUSTOM && mConfig.getApiKey().isEmpty()) {
            return "Offline Mode (No API Key Configured)";
        }
        return mConfig.getProvider().displayName;
    }

    private void enforceChatHistoryExpiry() {
        SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
        long lastHistoryTs = prefs.getLong(PREF_AI_CHAT_HISTORY_TS, 0L);
        long now = System.currentTimeMillis();

        if (lastHistoryTs == 0L || (now - lastHistoryTs) >= AI_CHAT_HISTORY_TTL_MS) {
            mMessages.clear();
            prefs.edit().putLong(PREF_AI_CHAT_HISTORY_TS, now).apply();
            if (mAdapter != null) {
                mAdapter.notifyDataSetChanged();
            }
            mMessages.add(new ChatMessage("🕒 Chat session expired after 24 hours. Your AI conversation has been reset for privacy and freshness.", false));
            if (mAdapter != null) {
                mAdapter.notifyItemInserted(mMessages.size() - 1);
            }
            return;
        }

        prefs.edit().putLong(PREF_AI_CHAT_HISTORY_TS, now).apply();
    }

    private void addWelcomeMessage() {
        if (!mMessages.isEmpty()) return;

        String welcome = buildPersonalizedWelcome();
        mMessages.add(new ChatMessage(welcome, false));
        mAdapter.notifyItemInserted(mMessages.size() - 1);
    }

    private String buildPersonalizedWelcome() {
        SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
        boolean firewallEnabled = prefs.getBoolean(Prefs.PREF_FIREWALL, false);
        boolean tlsEnabled = prefs.getBoolean(Prefs.PREF_TLS_DECRYPTION_KEY, false);
        boolean adBlockEnabled = Prefs.isAdBlockEnabled(prefs);
        boolean aiEnabled = mConfig != null && mConfig.isAiEnabled();

        CaptureStats stats = CaptureService.getStats();
        int activeConnections = stats != null ? Math.max(0, stats.active_conns) : 0;

        String alertSummary = "No recent alerts";
        try {
            AlertStore alertStore = AlertStore.getInstance(this);
            List<AlertRecord> alerts = alertStore.getAll();
            if (alerts != null && !alerts.isEmpty()) {
                int count = Math.min(alerts.size(), 5);
                alertSummary = count + " recent alerts tracked";
            }
        } catch (Exception ignored) {
            // Silent fallback: no alert store available yet.
        }

        String posture = "⚙️ Device posture: Firewall " + onOff(firewallEnabled)
                + ", HTTPS decryption " + onOff(tlsEnabled)
                + ", Tracker Shield " + onOff(adBlockEnabled)
                + ", AI mode " + (aiEnabled ? "enabled" : "offline-only")
                + ".\n"
                + "📡 Current telemetry: " + activeConnections + " active connections, " + alertSummary + ".";

        return "👋 Hello! I am KotSafe AI, your intelligent cyber security assistant.\n\n"
                + posture + "\n\n"
                + "I can help you with:\n"
                + "• 🔄 P2P Personal Gateway: Mesh tunneling, QR pairing, and split tunneling\n"
                + "• 🔑 Setting up free AI Keys (Google Gemini, OpenAI, Claude, Local AI)\n"
                + "• 🛡️ Configuring Firewall rules, blocking apps & malicious IPs\n"
                + "• ⚡ Using HTTP Repeater for security auditing & API testing\n"
                + "• 🌐 Decrypting HTTPS traffic with custom CA certificates\n"
                + "• 🧪 Antivirus Deep Scan, Split APK audits, and YARA rules\n"
                + "• 📊 Understanding Live Telemetry, RX/TX metrics & dropped packets\n\n"
                + "💡 *Security focus*: I can prioritize risk triage, live network anomalies, and the fastest steps to harden your current posture.";
    }

    private String onOff(boolean enabled) {
        return enabled ? "ON" : "OFF";
    }

    private void setupQuickChips() {
        setupChip(R.id.chip_security_audit, "Run a full security posture audit and tell me what needs attention on my device right now.");
        setupChip(R.id.chip_analyze_traffic, "Analyze active network traffic and open sockets. Highlight anything suspicious and explain the risk.");
        setupChip(R.id.chip_scan_malware, "Scan device for malware and suspicious APKs, then tell me the highest-risk apps or files.");
        setupChip(R.id.chip_threat_intel, "How do I investigate a suspicious IP, domain, or hash with AlienVault OTX and what steps should I take?");
        setupChip(R.id.chip_setup_ai, "How do I setup free AI API keys in KotSafe? Explain Google Gemini, OpenAI, and Local Ollama for private analysis.");
        setupChip(R.id.chip_explain_p2p, "How does the P2P Exit Node and Personal Gateway work? How do I pair devices and route traffic securely?");
        setupChip(R.id.chip_setup_firewall, "How do I configure the Firewall in KotSafe and which apps or domains should I block first?");
        setupChip(R.id.chip_setup_https, "How do I set up HTTPS decryption and install the CA certificate in KotSafe without breaking privacy?");
        setupChip(R.id.chip_explain_telemetry, "Explain Live Telemetry & Metrics in the Status section. What do Downloads, Uploads, Active Conns, and dropped packets mean?");
        setupChip(R.id.chip_explain_repeater, "What is HTTP Repeater, how do I use it, and how does it help security researchers test app traffic safely?");
        setupChip(R.id.chip_explain_antivirus, "How does Antivirus Deep Scan work and what are split APK and YARA checks? Give me a security action plan.");
        setupChip(R.id.chip_explain_mitre, "What is the MITRE ATT&CK framework and what do the Attack tags mean in KotSafe? Show the most relevant threats.");
        setupChip(R.id.chip_explain_connections, "Analyze the active network connections on my device and tell me if anything looks suspicious or exposed.");
    }

    private void setupChip(int chipId, String prompt) {
        Chip chip = findViewById(chipId);
        if (chip != null) {
            AnimUtils.attachSpringTouch(chip);
            chip.setOnClickListener(v -> {
                mEtInput.setText(prompt);
                sendUserPrompt();
            });
        }
    }

    private ChatMessage createAssistantMessage(String rawText) {
        String workText = rawText != null ? rawText : "";
        List<ActionDescriptor> parsedActions = new ArrayList<>();

        // Regex for [ACTION:TYPE:TARGET] or [ACTION:TYPE] or [RULE_ACTION:TYPE:TARGET]
        java.util.regex.Pattern tagPattern = java.util.regex.Pattern.compile("\\[(?:ACTION|RULE_ACTION):([A-Z0-9_]+)(?::([^]]+))?\\]");
        java.util.regex.Matcher m = tagPattern.matcher(workText);

        while (m.find()) {
            String rawType = m.group(1);
            String rawTarget = m.group(2) != null ? m.group(2).trim() : "";
            if (rawType != null) {
                String cleanType = rawType.replace("RULE_ACTION:", "").replace("BLOCK_", "").trim();
                parsedActions.add(new ActionDescriptor(cleanType, rawTarget));
            }
        }

        // Clean out action tags from display text
        String cleanText = tagPattern.matcher(workText).replaceAll("").trim();
        cleanText = styleChatGptLikeResponse(cleanText);

        ChatMessage msg = new ChatMessage(cleanText, false);
        msg.actions.addAll(parsedActions);
        if (!parsedActions.isEmpty()) {
            msg.actionType = parsedActions.get(0).type;
            msg.actionTarget = parsedActions.get(0).target;
        }
        return msg;
    }

    private String styleChatGptLikeResponse(String rawText) {
        String text = rawText == null ? "" : rawText.trim();
        if (text.isEmpty()) return "";

        if (text.contains("\n\n---\n") || text.contains("###") || text.contains("**") || text.contains("- ")) {
            return text;
        }

        String cleaned = text.replaceAll("\\s+", " ").trim();
        if (cleaned.length() <= 220) {
            return "Here’s the answer:\n\n" + cleaned;
        }

        return "Here’s the answer:\n\n" + cleaned.substring(0, 220).trim() + "...";
    }

    private void sendUserPrompt() {
        String text = mEtInput.getText() != null ? mEtInput.getText().toString().trim() : "";
        if (TextUtils.isEmpty(text)) return;

        mEtInput.setText("");
        mMessages.add(new ChatMessage(text, true));
        mAdapter.notifyItemInserted(mMessages.size() - 1);
        mRvMessages.scrollToPosition(mMessages.size() - 1);

        mLayoutThinking.setVisibility(View.VISIBLE);

        // Fast refusal for adversarial or credential queries
        if (AiAccessController.isAdversarialOrSensitiveQuery(text)) {
            mRvMessages.postDelayed(() -> {
                mLayoutThinking.setVisibility(View.GONE);
                mMessages.add(createAssistantMessage(OfflineKnowledgeEngine.getSensitiveInfoRefusal()));
                mAdapter.notifyItemInserted(mMessages.size() - 1);
                mRvMessages.smoothScrollToPosition(mMessages.size() - 1);
            }, 100);
            return;
        }

        // Fast greetings
        String q = text.toLowerCase(Locale.ROOT).trim();
        if (q.equals("hi") || q.equals("hello") || q.equals("hey") || q.equals("hlo") || q.equals("hii")) {
            mRvMessages.postDelayed(() -> {
                mLayoutThinking.setVisibility(View.GONE);
                mMessages.add(createAssistantMessage(OfflineKnowledgeEngine.getGreetingResponse()));
                mAdapter.notifyItemInserted(mMessages.size() - 1);
                mRvMessages.smoothScrollToPosition(mMessages.size() - 1);
            }, 150);
            return;
        }

        // Prepare live streaming assistant message
        final ChatMessage streamMsg = new ChatMessage("", false);
        streamMsg.isStreaming = true;
        mMessages.add(streamMsg);
        final int streamIndex = mMessages.size() - 1;
        mAdapter.notifyItemInserted(streamIndex);
        mRvMessages.scrollToPosition(streamIndex);

        boolean isAiActive = mConfig.isAiEnabled() &&
                (mConfig.getProvider().isOnDevice() || mConfig.getProvider() == AiConfig.Provider.LOCAL_CUSTOM || !mConfig.getApiKey().isEmpty());

        if (!isAiActive) {
            mTvThinkingStatus.setText("KotSafe Offline Security Expert is answering...");
            mRvMessages.postDelayed(() -> {
                String offlineAnswer = OfflineKnowledgeEngine.answerQuestion(AiAssistantActivity.this, text, mAccessController, null);
                int estTokens = com.kotsafe.security.ai.LocalGemmaEngine.estimateTokens(offlineAnswer) + com.kotsafe.security.ai.LocalGemmaEngine.estimateTokens(text);
                offlineAnswer += "\n\n---\n*📊 Built-in Engine: ~" + estTokens + " tokens processed (Offline Mode)*";
                startStreamingResponse(streamMsg, streamIndex, offlineAnswer);
            }, 200);
            return;
        }

        mTvThinkingStatus.setText("KotSafe AI (" + mConfig.getProvider().displayName + ") is reasoning...");
        String context = mAccessController.buildContextForQuery(text);

        final StringBuilder streamedTokens = new StringBuilder();
        mAiClient.askAssistantStream(text, context, new AiClientEngine.StreamCallback() {
            @Override
            public void onToken(String tokenChunk) {
                mLayoutThinking.setVisibility(View.GONE);
                streamedTokens.append(tokenChunk);
                streamMsg.text = streamedTokens.toString();
                mAdapter.notifyItemChanged(streamIndex);
                mRvMessages.scrollToPosition(streamIndex);
            }

            @Override
            public void onComplete(String fullResponse) {
                mLayoutThinking.setVisibility(View.GONE);
                ChatMessage finalMsg = createAssistantMessage(fullResponse);
                streamMsg.text = finalMsg.text;
                streamMsg.actions.clear();
                streamMsg.actions.addAll(finalMsg.actions);
                streamMsg.actionType = finalMsg.actionType;
                streamMsg.actionTarget = finalMsg.actionTarget;
                streamMsg.isStreaming = false;
                mAdapter.notifyItemChanged(streamIndex);
                mRvMessages.smoothScrollToPosition(streamIndex);
            }

            @Override
            public void onError(String errorMessage) {
                mLayoutThinking.setVisibility(View.GONE);
                String fallback = OfflineKnowledgeEngine.answerQuestion(AiAssistantActivity.this, text, mAccessController, errorMessage);
                int estTokens = com.kotsafe.security.ai.LocalGemmaEngine.estimateTokens(fallback);
                fallback += "\n\n---\n*📊 Offline Fallback: ~" + estTokens + " tokens*";
                startStreamingResponse(streamMsg, streamIndex, fallback);
            }
        });
    }

    private void startStreamingResponse(ChatMessage streamMsg, int targetIndex, String fullRawText) {
        final StringBuilder currentTokens = new StringBuilder();
        mAiClient.simulateTokenStream(fullRawText, new AiClientEngine.StreamCallback() {
            @Override
            public void onToken(String tokenChunk) {
                mLayoutThinking.setVisibility(View.GONE);
                currentTokens.append(tokenChunk);
                streamMsg.text = currentTokens.toString();
                mAdapter.notifyItemChanged(targetIndex);
                mRvMessages.scrollToPosition(targetIndex);
            }

            @Override
            public void onComplete(String fullResponse) {
                mLayoutThinking.setVisibility(View.GONE);
                ChatMessage finalMsg = createAssistantMessage(fullResponse);
                streamMsg.text = finalMsg.text;
                streamMsg.actions.clear();
                streamMsg.actions.addAll(finalMsg.actions);
                streamMsg.actionType = finalMsg.actionType;
                streamMsg.actionTarget = finalMsg.actionTarget;
                streamMsg.isStreaming = false;
                mAdapter.notifyItemChanged(targetIndex);
                mRvMessages.smoothScrollToPosition(targetIndex);
            }

            @Override
            public void onError(String errorMessage) {}
        });
    }

    @Override
    public boolean onCreateOptionsMenu(android.view.Menu menu) {
        menu.add(0, 101, 0, "Share Dossier")
                .setIcon(R.drawable.ic_share)
                .setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        } else if (item.getItemId() == 101) {
            shareIncidentDossier();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void shareIncidentDossier() {
        StringBuilder sb = new StringBuilder();
        sb.append("# 🛡️ KotSafe SOC Incident & Intelligence Dossier\n");
        sb.append("Generated: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(new Date())).append("\n\n");
        for (ChatMessage msg : mMessages) {
            if (msg.isUser) {
                sb.append("### 👤 User Inquiry:\n").append(msg.text).append("\n\n");
            } else {
                sb.append("### 🤖 KotSafe AI Forensic Response:\n").append(msg.text).append("\n\n---\n\n");
            }
        }

        Intent intent = new Intent(Intent.ACTION_SEND);
        intent.setType("text/plain");
        intent.putExtra(Intent.EXTRA_SUBJECT, "KotSafe Security Dossier");
        intent.putExtra(Intent.EXTRA_TEXT, sb.toString());
        startActivity(Intent.createChooser(intent, "Share Forensic Dossier via:"));
    }

    private void showHomeRouterSetupDialog(ActionDescriptor act, int position) {
        String detectedGateway = OfflineKnowledgeEngine.getDetectedLocalGateway(this);
        if (detectedGateway == null || detectedGateway.isEmpty()) {
            detectedGateway = "192.168.1.1";
        }

        SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
        String savedHost = prefs.getString("pref_saved_home_host", null);
        int savedPort = prefs.getInt("pref_saved_home_port", 1080);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (18 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad / 2, pad, pad / 2);

        TextView tvDesc = new TextView(this);
        tvDesc.setText("🌍 Out-of-Station (Roaming):\nEnter your home router's Public WAN IP or Dynamic DNS (e.g. myhome.duckdns.org) with port 1080 forwarded.\n\n🏠 At Home Only:\nLocal private IP (192.168.x.x) only works while connected to home Wi-Fi.");
        tvDesc.setTextSize(13);
        tvDesc.setPadding(0, 0, 0, (int) (8 * getResources().getDisplayMetrics().density));
        root.addView(tvDesc);

        final EditText etHost = new EditText(this);
        etHost.setHint("Public IP or DDNS (e.g. myhome.duckdns.org)");
        etHost.setText(savedHost != null && !savedHost.isEmpty() ? savedHost : detectedGateway);
        etHost.setSingleLine(true);
        root.addView(etHost);

        final TextView tvClassification = new TextView(this);
        tvClassification.setTextSize(12);
        tvClassification.setPadding(8, 4, 8, (int) (10 * getResources().getDisplayMetrics().density));
        root.addView(tvClassification);

        final Runnable updateClassification = () -> {
            String input = etHost.getText() != null ? etHost.getText().toString().trim() : "";
            OfflineKnowledgeEngine.EndpointClassification cl = OfflineKnowledgeEngine.classifyEndpoint(input);
            tvClassification.setText(cl.title + "\n" + cl.description);
            tvClassification.setTextColor(cl.color);
        };
        updateClassification.run();

        etHost.addTextChangedListener(new android.text.TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {
                updateClassification.run();
            }
            @Override public void afterTextChanged(android.text.Editable s) {}
        });

        final EditText etPort = new EditText(this);
        etPort.setHint("Port (default: 1080)");
        etPort.setText(String.valueOf(savedPort > 0 ? savedPort : 1080));
        etPort.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
        etPort.setSingleLine(true);
        root.addView(etPort);

        final EditText etUser = new EditText(this);
        etUser.setHint("Username (optional)");
        etUser.setSingleLine(true);
        root.addView(etUser);

        final EditText etPass = new EditText(this);
        etPass.setHint("Password (optional)");
        etPass.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        etPass.setSingleLine(true);
        root.addView(etPass);

        TextView tvSecNotice = new TextView(this);
        tvSecNotice.setText("🔒 Security Notice: Always set a Password above so unauthorized scanners cannot use your home proxy!");
        tvSecNotice.setTextSize(11);
        tvSecNotice.setTextColor(0xFFFFC107);
        tvSecNotice.setPadding(4, 6, 4, 8);
        root.addView(tvSecNotice);

        LinearLayout toolsLayout = new LinearLayout(this);
        toolsLayout.setOrientation(LinearLayout.HORIZONTAL);
        toolsLayout.setPadding(0, 4, 0, 0);

        MaterialButton btnUpnp = new MaterialButton(this, null, androidx.appcompat.R.attr.borderlessButtonStyle);
        btnUpnp.setText("⚡ Auto-UPnP");
        btnUpnp.setTextSize(12);
        btnUpnp.setOnClickListener(v -> {
            Toast.makeText(AiAssistantActivity.this, "Requesting router UPnP port mapping...", Toast.LENGTH_SHORT).show();
            com.kotsafe.security.util.UpnpPortMapper.requestAutoPortMapAsync(AiAssistantActivity.this, 1080, new com.kotsafe.security.util.UpnpPortMapper.PortMapCallback() {
                @Override
                public void onSuccess(String protocol, int externalPort, String message) {
                    new MaterialAlertDialogBuilder(AiAssistantActivity.this)
                            .setTitle("✅ Port Mapped via " + protocol)
                            .setMessage(message)
                            .setPositiveButton("OK", null)
                            .show();
                }
                @Override
                public void onFailure(String reason) {
                    new MaterialAlertDialogBuilder(AiAssistantActivity.this)
                            .setTitle("⚠️ UPnP Not Available")
                            .setMessage(reason)
                            .setPositiveButton("OK", null)
                            .show();
                }
            });
        });
        toolsLayout.addView(btnUpnp);

        MaterialButton btnWol = new MaterialButton(this, null, androidx.appcompat.R.attr.borderlessButtonStyle);
        btnWol.setText("💤 Wake PC (WoL)");
        btnWol.setTextSize(12);
        btnWol.setOnClickListener(v -> {
            String savedMac = prefs.getString("pref_saved_home_mac", "");
            final EditText etMac = new EditText(AiAssistantActivity.this);
            etMac.setHint("MAC Address (e.g. AA:BB:CC:DD:EE:FF)");
            etMac.setText(savedMac);
            new MaterialAlertDialogBuilder(AiAssistantActivity.this)
                    .setTitle("💤 Wake-on-LAN Magic Packet")
                    .setMessage("Enter the physical MAC address of your sleeping home PC or server:")
                    .setView(etMac)
                    .setPositiveButton("Send Wake Packet", (d, w) -> {
                        String mac = etMac.getText() != null ? etMac.getText().toString().trim() : "";
                        if (!mac.isEmpty()) {
                            prefs.edit().putString("pref_saved_home_mac", mac).apply();
                            com.kotsafe.security.util.WakeOnLanHelper.sendWakeOnLanAsync(mac, null, 9, new com.kotsafe.security.util.WakeOnLanHelper.WakeCallback() {
                                @Override
                                public void onSuccess(String targetMac) {
                                    Toast.makeText(AiAssistantActivity.this, "✅ WoL Magic Packet dispatched to " + targetMac + "!", Toast.LENGTH_LONG).show();
                                }
                                @Override
                                public void onError(String error) {
                                    Toast.makeText(AiAssistantActivity.this, "⚠️ " + error, Toast.LENGTH_SHORT).show();
                                }
                            });
                        }
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
        });
        toolsLayout.addView(btnWol);
        root.addView(toolsLayout);

        final String fallbackGateway = detectedGateway;
        new MaterialAlertDialogBuilder(this)
                .setTitle("🏠 Connect to Home Router Proxy")
                .setView(root)
                .setPositiveButton("Connect", (dialog, which) -> {
                    String host = etHost.getText() != null ? etHost.getText().toString().trim() : "";
                    if (host.isEmpty()) host = fallbackGateway;
                    int port = 1080;
                    try {
                        String portStr = etPort.getText() != null ? etPort.getText().toString().trim() : "";
                        if (!portStr.isEmpty()) port = Integer.parseInt(portStr);
                    } catch (Exception ignored) {}
                    String user = etUser.getText() != null ? etUser.getText().toString().trim() : "";
                    String pass = etPass.getText() != null ? etPass.getText().toString().trim() : "";

                    testAndApplyRouterProxy(host, port, user, pass, act, position);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void testAndApplyRouterProxy(String host, int port, String user, String pass,
                                         ActionDescriptor act, int position) {
        OfflineKnowledgeEngine.EndpointClassification classification = OfflineKnowledgeEngine.classifyEndpoint(host);
        boolean isPrivate = (classification == OfflineKnowledgeEngine.EndpointClassification.LOCAL_PRIVATE)
                || (classification == OfflineKnowledgeEngine.EndpointClassification.LOOPBACK);
        boolean isCgnat = (classification == OfflineKnowledgeEngine.EndpointClassification.CGNAT);

        if (isCgnat) {
            new MaterialAlertDialogBuilder(this)
                    .setTitle("⚠️ Carrier-Grade NAT (CGNAT) Detected")
                    .setMessage("The endpoint '" + host + "' is inside an ISP Carrier-Grade NAT subnet (100.64.0.0/10).\n\n"
                            + "Your telecom carrier does not assign a unique public address, so external incoming connections are blocked.\n\n"
                            + "To route traffic from outside without router port forwarding:\n"
                            + "• Use Option 1 (KotSafe P2P Mesh), which works seamlessly through CGNAT on 4G/5G!")
                    .setPositiveButton("Open P2P Gateway", (dialog, which) -> {
                        Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.prefs.SettingsActivity.class);
                        intent.putExtra(com.kotsafe.security.activities.prefs.SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                        startActivity(intent);
                    })
                    .setNeutralButton("Try Probe Anyway", (dialog, which) -> {
                        executeProbe(host, port, user, pass, act, position);
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }

        boolean isCellular = false;
        try {
            android.net.ConnectivityManager cm = (android.net.ConnectivityManager) getSystemService(android.content.Context.CONNECTIVITY_SERVICE);
            if (cm != null && cm.getActiveNetwork() != null) {
                android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());
                if (caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) {
                    isCellular = true;
                }
            }
        } catch (Exception ignored) {}

        if (isCellular && isPrivate) {
            new MaterialAlertDialogBuilder(this)
                    .setTitle("⚠️ Out-of-Station Mobile Data Warning")
                    .setMessage("You are currently on Mobile Cellular Data, but '" + host + "' is a private local Wi-Fi address (192.168.x.x).\n\n"
                            + "When you are away from home, a private IP cannot be reached directly over cellular.\n\n"
                            + "To route your traffic through home:\n"
                            + "1. Use your router's Public WAN IP or Dynamic DNS (e.g. myhome.duckdns.org) with port 1080 forwarded.\n"
                            + "2. OR use Option 1 (KotSafe P2P Mesh), which works anywhere in the world on 4G/5G without any router setup!")
                    .setPositiveButton("Open P2P Gateway", (dialog, which) -> {
                        Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.prefs.SettingsActivity.class);
                        intent.putExtra(com.kotsafe.security.activities.prefs.SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                        startActivity(intent);
                    })
                    .setNeutralButton("Try Probe Anyway", (dialog, which) -> {
                        executeProbe(host, port, user, pass, act, position);
                    })
                    .setNegativeButton("Cancel", null)
                    .show();
            return;
        }

        executeProbe(host, port, user, pass, act, position);
    }

    private void executeProbe(String host, int port, String user, String pass,
                              ActionDescriptor act, int position) {
        Toast.makeText(this, "Testing reachability to " + host + ":" + port + "...", Toast.LENGTH_SHORT).show();

        new Thread(() -> {
            boolean reachable = false;
            String errorMsg = "";
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), 3500);
                reachable = true;
            } catch (Exception e) {
                errorMsg = e.getMessage() != null ? e.getMessage() : "Connection timed out";
            }

            final boolean isReachable = reachable;
            final String finalErrorMsg = errorMsg;

            runOnUiThread(() -> {
                if (isFinishing() || isDestroyed()) return;

                if (isReachable) {
                    applyRouterProxyConfig(host, port, user, pass);
                    if (act != null) {
                        act.executed = true;
                        if (mAdapter != null) mAdapter.notifyItemChanged(position);
                    }
                    Toast.makeText(AiAssistantActivity.this, "✅ Connected to Home Router Proxy (" + host + ":" + port + ")!", Toast.LENGTH_LONG).show();

                    mMessages.add(createAssistantMessage("✅ **Successfully Connected to Home Router SOCKS5 Proxy**\n\n"
                            + "• **Target Gateway**: `" + host + ":" + port + "`\n"
                            + "• **Port Probe Status**: Reachable (Verified)\n"
                            + "• **Profile Saved**: KotSafe has remembered this home setup. Future out-of-station connections can be 1-tap activated.\n"
                            + "• **Capture Pipeline**: Dynamic SOCKS5 routing engaged.\n"
                            + "• **QUIC Fallback**: Enforced for seamless proxy tunneling."));
                    if (mAdapter != null) {
                        mAdapter.notifyItemInserted(mMessages.size() - 1);
                        mRvMessages.smoothScrollToPosition(mMessages.size() - 1);
                    }
                } else {
                    new MaterialAlertDialogBuilder(AiAssistantActivity.this)
                            .setTitle("⚠️ Probe Warning: " + host + ":" + port)
                            .setMessage("Could not establish direct TCP connection to " + host + ":" + port + " (" + finalErrorMsg + ").\n\n"
                                    + "Common reasons:\n"
                                    + "1. Router Port Forwarding is not enabled on port " + port + ".\n"
                                    + "2. SOCKS5 daemon is not running on the home device/router.\n"
                                    + "3. Your home ISP is behind CGNAT (which blocks inbound ports).\n\n"
                                    + "Recommendation: Use KotSafe P2P Mesh if you don't want to deal with port forwarding.")
                            .setPositiveButton("Open P2P Gateway", (dialog, which) -> {
                                Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.prefs.SettingsActivity.class);
                                intent.putExtra(com.kotsafe.security.activities.prefs.SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                                startActivity(intent);
                            })
                            .setNeutralButton("Force Apply Anyway", (dialog, which) -> {
                                applyRouterProxyConfig(host, port, user, pass);
                                if (act != null) {
                                    act.executed = true;
                                    if (mAdapter != null) mAdapter.notifyItemChanged(position);
                                }
                                Toast.makeText(AiAssistantActivity.this, "Configuration force-applied!", Toast.LENGTH_SHORT).show();

                                mMessages.add(createAssistantMessage("⚠️ **Router SOCKS5 Config Force-Applied**\n\n"
                                        + "• **Target Gateway**: `" + host + ":" + port + "`\n"
                                        + "• **Note**: Endpoint was unreachable during pre-flight probe. Ensure port-forwarding is enabled."));
                                if (mAdapter != null) {
                                    mAdapter.notifyItemInserted(mMessages.size() - 1);
                                    mRvMessages.smoothScrollToPosition(mMessages.size() - 1);
                                }
                            })
                            .setNegativeButton("Cancel", null)
                            .show();
                }
            });
        }).start();
    }

    private void applyRouterProxyConfig(String host, int port, String user, String pass) {
        SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this);
        boolean hasAuth = (user != null && !user.isEmpty());

        prefs.edit()
                .putBoolean(Prefs.PREF_SOCKS5_ENABLED_KEY, true)
                .putString(Prefs.PREF_SOCKS5_PROXY_IP_KEY, host)
                .putString(Prefs.PREF_SOCKS5_PROXY_HOST_KEY, host)
                .putString(Prefs.PREF_SOCKS5_PROXY_PORT_KEY, String.valueOf(port))
                .putBoolean(Prefs.PREF_SOCKS5_AUTH_ENABLED_KEY, hasAuth)
                .putString(Prefs.PREF_SOCKS5_USERNAME_KEY, user != null ? user : "")
                .putString(Prefs.PREF_SOCKS5_PASSWORD_KEY, pass != null ? pass : "")
                .putString(Prefs.PREF_BLOCK_QUIC, Prefs.BLOCK_QUIC_MODE_ALWAYS)
                .putString(Prefs.PREF_IP_MODE, Prefs.IP_MODE_BOTH)
                .putString("pref_saved_home_host", host)
                .putInt("pref_saved_home_port", port)
                .putString("pref_saved_home_user", user != null ? user : "")
                .putString("pref_saved_home_pass", pass != null ? pass : "")
                .putLong("pref_saved_home_timestamp", System.currentTimeMillis())
                .apply();

        if (CaptureService.isServiceActive()) {
            CaptureService.updateSocks5Proxy(host, port);
        }
    }

    // --- Recycler View Adapter ---
    private class ChatAdapter extends RecyclerView.Adapter<ChatAdapter.VH> {
        private final List<ChatMessage> mData;
        private final SimpleDateFormat mTimeFmt = new SimpleDateFormat("hh:mm a", Locale.getDefault());

        ChatAdapter(List<ChatMessage> data) {
            mData = data;
        }

        @NonNull
        @Override
        public VH onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            View v = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_ai_chat_message, parent, false);
            return new VH(v);
        }

        @Override
        public void onBindViewHolder(@NonNull VH h, int position) {
            ChatMessage msg = mData.get(position);
            h.tvBody.setText(MarkdownSpanFormatter.format(msg.text, AiAssistantActivity.this));
            h.tvTime.setText(mTimeFmt.format(new Date(msg.timestamp)));

            if (msg.isUser) {
                h.ivIcon.setImageResource(R.drawable.ic_profile_avatar);
                h.ivIcon.setColorFilter(ContextCompat.getColor(AiAssistantActivity.this, R.color.colorAccent));
                h.tvSender.setText("You");
                h.tvSender.setTextColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.colorAccent));
                h.cardBubble.setCardBackgroundColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatUserBubbleBg));
                h.cardBubble.setStrokeColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatUserBubbleStroke));
                h.tvBody.setTextColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatUserBubbleText));
                h.layoutDynamicAction.setVisibility(View.GONE);
            } else {
                h.ivIcon.setImageResource(R.drawable.ic_bolt);
                int accentColor = ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatAssistantSenderText);
                h.ivIcon.setColorFilter(accentColor);
                h.tvSender.setText("KotSafe AI");
                h.tvSender.setTextColor(accentColor);
                h.cardBubble.setCardBackgroundColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatAssistantBubbleBg));
                h.cardBubble.setStrokeColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatAssistantBubbleStroke));
                h.tvBody.setTextColor(ContextCompat.getColor(AiAssistantActivity.this, R.color.aiChatAssistantBubbleText));

                if (msg.actions != null && !msg.actions.isEmpty()) {
                    h.layoutDynamicAction.setVisibility(View.VISIBLE);
                    h.layoutDynamicAction.removeAllViews();
                    for (int i = 0; i < msg.actions.size(); i++) {
                        ActionDescriptor act = msg.actions.get(i);
                        MaterialButton btn = new MaterialButton(AiAssistantActivity.this, null, com.google.android.material.R.attr.materialButtonStyle);
                        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                                LinearLayout.LayoutParams.WRAP_CONTENT,
                                (int) (38 * getResources().getDisplayMetrics().density)
                        );
                        if (i > 0) {
                            lp.topMargin = (int) (6 * getResources().getDisplayMetrics().density);
                        }
                        btn.setLayoutParams(lp);
                        btn.setCornerRadius((int) (19 * getResources().getDisplayMetrics().density));
                        btn.setTextSize(android.util.TypedValue.COMPLEX_UNIT_SP, 11);
                        btn.setTypeface(null, android.graphics.Typeface.BOLD);
                        btn.setTextColor(0xFFFFFFFF);
                        bindAction(btn, act, msg, h.getBindingAdapterPosition());
                        h.layoutDynamicAction.addView(btn);
                    }
                } else {
                    h.layoutDynamicAction.setVisibility(View.GONE);
                }
            }
        }

        private void bindAction(MaterialButton btn, ActionDescriptor act, ChatMessage msg, int position) {
            boolean isAdBlockAction = "ENABLE_ADBLOCK".equalsIgnoreCase(act.type) || "TOGGLE_ADBLOCK".equalsIgnoreCase(act.type);
            boolean isFwAction = "TOGGLE_FIREWALL".equalsIgnoreCase(act.type);
            boolean isAvAction = "TOGGLE_ANTIVIRUS".equalsIgnoreCase(act.type);
            boolean isInvestigateAction = "INVESTIGATE".equalsIgnoreCase(act.type);
            boolean isStartScanAction = "START_SCAN".equalsIgnoreCase(act.type) || "ANTIVIRUS".equalsIgnoreCase(act.type);
            boolean isViewTrafficAction = "VIEW_TRAFFIC".equalsIgnoreCase(act.type);
            boolean isStartVpnAction = "START_VPN".equalsIgnoreCase(act.type);
            boolean isIgnoreBatteryAction = "IGNORE_BATTERY".equalsIgnoreCase(act.type);
            boolean isOpenP2pAction = "OPEN_P2P".equalsIgnoreCase(act.type);
            boolean isReconnectP2pAction = "RECONNECT_P2P".equalsIgnoreCase(act.type);
            boolean isConnectRouterProxyAction = "CONNECT_ROUTER_PROXY".equalsIgnoreCase(act.type);
            boolean isSetupRouterProxyAction = "SETUP_ROUTER_PROXY".equalsIgnoreCase(act.type);
            boolean isReconnectSavedHomeAction = "RECONNECT_SAVED_HOME".equalsIgnoreCase(act.type);
            boolean isOpenAiSettingsAction = "OPEN_AI_SETTINGS".equalsIgnoreCase(act.type);
            boolean isOpenFirewallAction = "OPEN_FIREWALL".equalsIgnoreCase(act.type);

            boolean canRepeat = isInvestigateAction || isStartScanAction || isViewTrafficAction || isStartVpnAction || isOpenP2pAction || isReconnectP2pAction || isConnectRouterProxyAction || isSetupRouterProxyAction || isReconnectSavedHomeAction || isOpenAiSettingsAction || isOpenFirewallAction;

            if (act.executed && !canRepeat) {
                if (isAdBlockAction) {
                    btn.setText("✓ All Ads & Trackers Blocked");
                } else if (isFwAction) {
                    boolean enable = !"DISABLE".equalsIgnoreCase(act.target);
                    btn.setText(enable ? "✓ Firewall is ON" : "✓ Firewall is OFF (Standby)");
                } else if (isAvAction) {
                    boolean enable = !"DISABLE".equalsIgnoreCase(act.target);
                    btn.setText(enable ? "✓ Antivirus is ARMED" : "✓ Antivirus is STANDBY");
                } else if (isIgnoreBatteryAction) {
                    btn.setText("✓ Battery Optimizations Exempted");
                } else {
                    btn.setText("✓ Blocked in Firewall");
                }
                btn.setEnabled(false);
                btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF334155));
            } else {
                if (isInvestigateAction) {
                    btn.setText("🔍 Open Deep Threat Investigation (" + act.target + ")");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF0284C7));
                } else if (isStartScanAction) {
                    btn.setText("🦠 Launch Full Antivirus & YARA Scan");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF059669));
                } else if (isViewTrafficAction) {
                    btn.setText("📊 Open Live Traffic & Sockets Inspector");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF0EA5E9));
                } else if (isStartVpnAction) {
                    btn.setText("▶️ Launch Packet Sentinel & VPN");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF2563EB));
                } else if (isIgnoreBatteryAction) {
                    btn.setText("⚡ Unrestrict Battery for KotSafe");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFF59E0B));
                } else if (isOpenAiSettingsAction) {
                    btn.setText("🔑 Configure Free Gemini AI Key");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF8B5CF6));
                } else if (isOpenP2pAction) {
                    btn.setText("📱 Open P2P Mesh Gateway (Zero-Config)");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF6366F1));
                } else if (isReconnectSavedHomeAction) {
                    btn.setText("⚡ 1-Tap Connect to Saved Home (" + act.target + ")");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF10B981));
                } else if (isReconnectP2pAction) {
                    btn.setText("🔄 Reconnect P2P Gateway");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF10B981));
                } else if (isConnectRouterProxyAction) {
                    btn.setText("🌐 Connect & Route to Router (" + act.target + ")");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF0284C7));
                } else if (isSetupRouterProxyAction) {
                    btn.setText("🌐 Configure Router Port Forwarding");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFF0284C7));
                } else if (isAdBlockAction) {
                    btn.setText("🛑 Activate Global Ad & Tracker Shield");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFEF4444));
                } else if (isFwAction) {
                    boolean enable = !"DISABLE".equalsIgnoreCase(act.target);
                    btn.setText(enable ? "🛡️ Turn ON Firewall" : "⏸️ Turn OFF Firewall");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFEF4444));
                } else if (isAvAction) {
                    boolean enable = !"DISABLE".equalsIgnoreCase(act.target);
                    btn.setText(enable ? "🦠 Turn ON Antivirus" : "⏸️ Turn OFF Antivirus");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFEF4444));
                } else if (isOpenFirewallAction) {
                    btn.setText("🛡️ Open Firewall Rules (No-Root)");
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFDC2626));
                } else {
                    btn.setText("🛡️ Apply Rule: Block " + act.target);
                    btn.setBackgroundTintList(android.content.res.ColorStateList.valueOf(0xFFEF4444));
                }

                btn.setEnabled(true);
                AnimUtils.attachSpringTouch(btn);
                btn.setOnClickListener(v -> {
                    if (isOpenFirewallAction) {
                        Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.FirewallActivity.class);
                        startActivity(intent);
                        return;
                    }
                    if (isInvestigateAction) {
                        ThreatInvestigationDialog.show(getSupportFragmentManager(), act.target, "KotSafe AI Assistant Investigation");
                        return;
                    }
                    if (isStartScanAction) {
                        Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.AntivirusScanActivity.class);
                        startActivity(intent);
                        return;
                    }
                    if (isViewTrafficAction) {
                        Intent intent = new Intent(AiAssistantActivity.this, MainActivity.class);
                        intent.putExtra("open_tab", "connections");
                        startActivity(intent);
                        return;
                    }
                    if (isStartVpnAction) {
                        Intent intent = new Intent(AiAssistantActivity.this, MainActivity.class);
                        startActivity(intent);
                        Toast.makeText(AiAssistantActivity.this, "Tap START to activate VPN protection", Toast.LENGTH_SHORT).show();
                        return;
                    }
                    if (isIgnoreBatteryAction) {
                        try {
                            Intent intent = new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                            intent.setData(Uri.parse("package:" + getPackageName()));
                            startActivity(intent);
                        } catch (Exception e) {
                            try {
                                Intent intent = new Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
                                startActivity(intent);
                            } catch (Exception ex) {
                                Toast.makeText(AiAssistantActivity.this, "Open Android Settings > Apps > KotSafe > Battery", Toast.LENGTH_LONG).show();
                            }
                        }
                        act.executed = true;
                        notifyItemChanged(position);
                        return;
                    }
                    if (isOpenAiSettingsAction) {
                        Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.prefs.SettingsActivity.class);
                        intent.putExtra(com.kotsafe.security.activities.prefs.SettingsActivity.TARGET_PREF_EXTRA, "ai_protection_settings");
                        startActivity(intent);
                        return;
                    }
                    if (isOpenP2pAction) {
                        Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.prefs.SettingsActivity.class);
                        intent.putExtra(com.kotsafe.security.activities.prefs.SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                        startActivity(intent);
                        return;
                    }
                    if (isReconnectP2pAction) {
                        SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(AiAssistantActivity.this);
                        boolean isClient = prefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, false);
                        boolean isExit = prefs.getBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.EXIT_ENABLED, false);
                        if (isClient) {
                            prefs.edit().putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, false).apply();
                            com.kotsafe.security.model.P2PExitNodeService.stop(AiAssistantActivity.this);
                            mRvMessages.postDelayed(() -> {
                                prefs.edit().putBoolean(com.kotsafe.security.p2p.GatewayPreferenceKeys.CLIENT_ENABLED, true).apply();
                                com.kotsafe.security.model.P2PExitNodeService.start(AiAssistantActivity.this);
                                Toast.makeText(AiAssistantActivity.this, "🔄 Reconnecting P2P Client...", Toast.LENGTH_SHORT).show();
                            }, 500);
                        } else if (isExit) {
                            com.kotsafe.security.model.P2PExitNodeService.stop(AiAssistantActivity.this);
                            mRvMessages.postDelayed(() -> {
                                com.kotsafe.security.model.P2PExitNodeService.start(AiAssistantActivity.this);
                                Toast.makeText(AiAssistantActivity.this, "🔄 Restarted P2P Exit Node", Toast.LENGTH_SHORT).show();
                            }, 500);
                        } else {
                            Intent intent = new Intent(AiAssistantActivity.this, com.kotsafe.security.activities.prefs.SettingsActivity.class);
                            intent.putExtra(com.kotsafe.security.activities.prefs.SettingsActivity.TARGET_PREF_EXTRA, "p2p_exit_node_settings");
                            startActivity(intent);
                        }
                        act.executed = true;
                        notifyItemChanged(position);
                        return;
                    }
                    if (isReconnectSavedHomeAction) {
                        String[] parts = act.target.split(":");
                        String host = parts[0].trim();
                        int port = 1080;
                        if (parts.length > 1) {
                            try { port = Integer.parseInt(parts[1].trim()); } catch (Exception ignored) {}
                        }
                        SharedPreferences prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(AiAssistantActivity.this);
                        String user = prefs.getString("pref_saved_home_user", "");
                        String pass = prefs.getString("pref_saved_home_pass", "");
                        testAndApplyRouterProxy(host, port, user, pass, act, position);
                        return;
                    }
                    if (isConnectRouterProxyAction) {
                        String[] parts = act.target.split(":");
                        String host = parts[0].trim();
                        int port = 1080;
                        if (parts.length > 1) {
                            try { port = Integer.parseInt(parts[1].trim()); } catch (Exception ignored) {}
                        }
                        testAndApplyRouterProxy(host, port, "", "", act, position);
                        return;
                    }
                    if (isSetupRouterProxyAction) {
                        showHomeRouterSetupDialog(act, position);
                        return;
                    }
                    if (isAdBlockAction) {
                        com.kotsafe.security.model.AdBlockSubscriptionManager.getInstance(AiAssistantActivity.this)
                                .setAdBlockEnabled(true);
                        act.executed = true;
                        Toast.makeText(AiAssistantActivity.this, "🛑 All Ads & Trackers are now BLOCKED globally!", Toast.LENGTH_SHORT).show();
                        notifyItemChanged(position);
                        return;
                    }
                    if (isFwAction) {
                        boolean enable = !"DISABLE".equalsIgnoreCase(act.target);
                        androidx.preference.PreferenceManager.getDefaultSharedPreferences(AiAssistantActivity.this)
                                .edit().putBoolean(Prefs.PREF_FIREWALL, enable).apply();
                        CaptureService.setFirewallEnabled(enable);
                        act.executed = true;
                        Toast.makeText(AiAssistantActivity.this, enable ? "🛡️ Firewall is now ON!" : "Firewall turned OFF (Standby)", Toast.LENGTH_SHORT).show();
                        notifyItemChanged(position);
                        return;
                    }
                    if (isAvAction) {
                        boolean enable = !"DISABLE".equalsIgnoreCase(act.target);
                        androidx.preference.PreferenceManager.getDefaultSharedPreferences(AiAssistantActivity.this)
                                .edit()
                                .putBoolean(Prefs.PREF_MALWARE_DETECTION, enable)
                                .putBoolean("pref_auto_daily_deep_scan", enable)
                                .apply();
                        act.executed = true;
                        Toast.makeText(AiAssistantActivity.this, enable ? "🦠 Real-time Antivirus is now ARMED!" : "Antivirus turned OFF (Standby)", Toast.LENGTH_SHORT).show();
                        notifyItemChanged(position);
                        return;
                    }
                    SecurityRulesDb db = SecurityRulesDb.getInstance(AiAssistantActivity.this);
                    if ("IP".equalsIgnoreCase(act.type)) {
                        db.blockIp(act.target, "Blocked via KotSafe AI Assistant", SecurityRulesDb.SOURCE_USER);
                    } else if ("APP".equalsIgnoreCase(act.type)) {
                        db.blockApp(act.target, "Blocked via KotSafe AI Assistant", SecurityRulesDb.SOURCE_USER);
                    } else {
                        db.blockDomain(act.target, "Blocked via KotSafe AI Assistant", SecurityRulesDb.SOURCE_USER);
                    }
                    act.executed = true;
                    Toast.makeText(AiAssistantActivity.this, "Rule applied: " + act.target + " is blocked!", Toast.LENGTH_SHORT).show();
                    notifyItemChanged(position);
                });
            }
        }

        @Override
        public int getItemCount() {
            return mData.size();
        }

        class VH extends RecyclerView.ViewHolder {
            final ImageView ivIcon;
            final TextView tvSender;
            final TextView tvTime;
            final MaterialCardView cardBubble;
            final TextView tvBody;
            final LinearLayout layoutDynamicAction;
            final MaterialButton btnActionApplyRule;

            VH(View v) {
                super(v);
                ivIcon = v.findViewById(R.id.iv_sender_icon);
                tvSender = v.findViewById(R.id.tv_sender_name);
                tvTime = v.findViewById(R.id.tv_message_time);
                cardBubble = v.findViewById(R.id.card_message_bubble);
                tvBody = v.findViewById(R.id.tv_message_body);
                layoutDynamicAction = v.findViewById(R.id.layout_dynamic_action);
                btnActionApplyRule = v.findViewById(R.id.btn_action_apply_rule);
            }
        }
    }
}
