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
 * * Copyright 2026 - KotSafe Cyber Security Project
 */

package com.kotsafe.security.fragments;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Pair;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TableLayout;
import android.widget.TextView;
import java.util.List;
import java.util.Locale;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.kotsafe.security.AppsResolver;
import com.kotsafe.security.CaptureService;
import com.kotsafe.security.ConnectionsRegister;
import com.kotsafe.security.R;
import com.kotsafe.security.Utils;
import com.kotsafe.security.activities.ConnectionDetailsActivity;
import com.kotsafe.security.activities.MainActivity;
import com.kotsafe.security.activities.MenuActionHandler;
import com.kotsafe.security.AppIconLoader;
import com.kotsafe.security.model.AppDescriptor;
import com.kotsafe.security.model.AppNetworkRule;
import com.kotsafe.security.model.AppNetworkRulesManager;
import com.kotsafe.security.model.ConnectionDescriptor;
import com.kotsafe.security.model.Prefs;
import com.haipq.android.flagkit.FlagImageView;
import android.graphics.drawable.Drawable;
import androidx.preference.PreferenceManager;
import androidx.viewpager2.widget.ViewPager2;

public class ConnectionOverview extends Fragment implements ConnectionDetailsActivity.ConnUpdateListener, MenuActionHandler {
    private static final String TAG = "ConnectionOverview";
    private ConnectionDetailsActivity mActivity;
    private ConnectionDescriptor mConn;
    private TableLayout mTable;
    private TextView mNacStatus;
    private TextView mBytesView;
    private TextView mPayloadLen;
    private TextView mPacketsView;
    private TextView mDurationView;
    private TextView mBlockedPkts;
    private View mBlockedPktsRow;
    private TextView mStatus;
    private TextView mDecStatus;
    private ImageView mDecIcon;
    private TextView mFirstSeen;
    private TextView mLastSeen;
    //private TextView mTcpFlags;
    private TextView mError;
    private TextView mSocketErrno;
    private View mSocketErrnoRow;
    private View mSocketErrnoInfo;
    private ImageView mBlacklistedIp;
    private ImageView mBlacklistedHost;
    private LinearLayout mSocketContainer;
    private TextView mSocketBadge;
    private TextView mSocketSummary;
    private View mCardDnsAttribution;
    private TextView mDnsExplanation;
    private TextView mCorrelatedHeader;
    private LinearLayout mCorrelatedContainer;
    private TextView mNoCorrelatedApps;

    public static ConnectionOverview newInstance(int conn_id) {
        ConnectionOverview fragment = new ConnectionOverview();
        Bundle args = new Bundle();
        args.putInt("conn_id", conn_id);
        fragment.setArguments(args);
        return fragment;
    }

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        mActivity = (ConnectionDetailsActivity) context;
        mActivity.addConnUpdateListener(this);
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mActivity.removeConnUpdateListener(this);
        mActivity = null;
    }

    @Override
    public View onCreateView(LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        return inflater.inflate(R.layout.connection_overview, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        TextView appLabel = view.findViewById(R.id.detail_app);
        TextView proto = view.findViewById(R.id.detail_protocol);
        TextView info_label = view.findViewById(R.id.detail_info_label);
        TextView info = view.findViewById(R.id.detail_info);
        TextView url = view.findViewById(R.id.detail_url);
        View url_row = view.findViewById(R.id.detail_url_row);
        View info_row = view.findViewById(R.id.detail_info_row);
        TextView source = view.findViewById(R.id.detail_source);
        TextView destination = view.findViewById(R.id.detail_destination);
        TextView country = view.findViewById(R.id.country_name);
        FlagImageView country_flag = view.findViewById(R.id.country_flag);
        TextView srcCountry = view.findViewById(R.id.source_country_name);
        FlagImageView srcCountryFlag = view.findViewById(R.id.source_country_flag);
        TextView asn = view.findViewById(R.id.asn);
        mTable = view.findViewById(R.id.table);
        mPayloadLen = view.findViewById(R.id.detail_payload);
        mBytesView = view.findViewById(R.id.detail_bytes);
        mPacketsView = view.findViewById(R.id.detail_packets);
        mBlockedPkts = view.findViewById(R.id.blocked_pkts);
        mBlockedPktsRow = view.findViewById(R.id.blocked_row);
        mDurationView = view.findViewById(R.id.detail_duration);
        mStatus = view.findViewById(R.id.detail_status);
        mDecStatus = view.findViewById(R.id.detail_decryption_status);
        mDecIcon = view.findViewById(R.id.decryption_icon);
        mFirstSeen = view.findViewById(R.id.first_seen);
        mLastSeen = view.findViewById(R.id.last_seen);
        //mTcpFlags = view.findViewById(R.id.tcp_flags);
        mError = view.findViewById(R.id.error_msg);
        mSocketErrno = view.findViewById(R.id.detail_errno);
        mSocketErrnoRow = view.findViewById(R.id.error_row);
        mSocketErrnoInfo = view.findViewById(R.id.error_info);
        mBlacklistedIp = view.findViewById(R.id.blacklisted_ip);
        mBlacklistedHost = view.findViewById(R.id.blacklisted_host);
        mSocketContainer = view.findViewById(R.id.socket_sessions_container);
        mSocketBadge = view.findViewById(R.id.socket_sessions_count_badge);
        mSocketSummary = view.findViewById(R.id.socket_diagnostics_summary);
        mCardDnsAttribution = view.findViewById(R.id.card_dns_app_attribution);
        mDnsExplanation = view.findViewById(R.id.tv_dns_system_explanation);
        mCorrelatedHeader = view.findViewById(R.id.tv_correlated_apps_header);
        mCorrelatedContainer = view.findViewById(R.id.container_correlated_apps);
        mNoCorrelatedApps = view.findViewById(R.id.tv_no_correlated_apps);

        Bundle args = getArguments();
        assert args != null;
        ConnectionsRegister reg = CaptureService.requireConnsRegister();

        mConn = reg.getConnById(args.getInt("conn_id"));
        if(mConn == null) {
            Utils.showToast(requireContext(), R.string.connection_not_found);
            mActivity.finish();
            return;
        }

        view.findViewById(R.id.whois_ip).setOnClickListener(v -> {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://search.arin.net/rdap/?query=" + mConn.dst_ip));
            Utils.startActivity(mActivity, intent);
        });

        View cardAiFlow = view.findViewById(R.id.card_ai_flow_analysis);
        View btnRunAiFlow = view.findViewById(R.id.btn_run_ai_flow);
        View.OnClickListener aiFlowListener = v -> {
            if (mConn != null && getActivity() != null) {
                com.kotsafe.security.views.ConnectionAiFlowDialog.newInstance(mConn.incr_id)
                        .show(getChildFragmentManager(), "ConnectionAiFlowDialog");
            }
        };
        if (cardAiFlow != null) cardAiFlow.setOnClickListener(aiFlowListener);
        if (btnRunAiFlow != null) btnRunAiFlow.setOnClickListener(aiFlowListener);

        View btnDeepInvestigate = view.findViewById(R.id.btn_deep_threat_investigate);
        if (btnDeepInvestigate != null) {
            btnDeepInvestigate.setOnClickListener(v -> {
                if (mConn != null && getActivity() != null) {
                    String target = (mConn.info != null && !mConn.info.isEmpty()) ? mConn.info : mConn.dst_ip;
                    String type = (mConn.info != null && !mConn.info.isEmpty()) ? "DOMAIN" : "IP";
                    String pkg = "";
                    try {
                        AppsResolver resolver = new AppsResolver(requireContext());
                        AppDescriptor app = resolver.getAppByUid(mConn.uid, 0);
                        if (app != null) pkg = app.getPackageName();
                    } catch (Exception ignored) {}
                    com.kotsafe.security.views.ThreatInvestigationDialog.show(
                            getChildFragmentManager(), target, type, pkg, "Live Connection: Port " + mConn.dst_port);
                }
            });
        }

        View btnTimeline = view.findViewById(R.id.btn_app_activity_timeline);
        View.OnClickListener timelineListener = v -> {
            if (mConn != null && getActivity() != null) {
                com.kotsafe.security.views.AppTimelineDialog.newInstance(mConn.uid, mConn.incr_id)
                        .show(getChildFragmentManager(), "AppTimelineDialog");
            }
        };
        if (btnTimeline != null) btnTimeline.setOnClickListener(timelineListener);

        View appIconHeader = view.findViewById(R.id.overview_app_icon);
        if (appIconHeader != null) appIconHeader.setOnClickListener(timelineListener);

        if(mConn != null) {
            String l4proto = Utils.proto2str(mConn.ipproto);
            //if(l4proto.equals("TCP"))
            //    view.findViewById(R.id.tcp_flags_row).setVisibility(View.VISIBLE);

            if(!mConn.l7proto.equals(l4proto))
                proto.setText(String.format(getResources().getString(R.string.app_and_proto), mConn.l7proto, l4proto));
            else
                proto.setText(mConn.l7proto);

            CharSequence protoMsg = null;
            if (mConn.l7proto.equals("DNS"))
                protoMsg = getString(R.string.dns_conn_info);
            else if ((mConn.l7proto.equals("TLS")) || (mConn.l7proto.equals("HTTPS")))
                protoMsg = Utils.getText(view.getContext(), R.string.tls_conn_info, MainActivity.TLS_DECRYPTION_DOCS_URL);

            if (protoMsg != null) {
                final CharSequence msg = protoMsg;
                View protoInfo = view.findViewById(R.id.protocol_info);
                protoInfo.setVisibility(View.VISIBLE);

                protoInfo.setOnClickListener(view1 -> {
                    Context ctx = getContext();
                    if (ctx != null)
                        Utils.showHelpDialog(ctx, msg);
                });
            }

            if(l4proto.equals("ICMP")) {
                source.setText(mConn.src_ip);
                destination.setText(mConn.dst_ip);
            } else {
                if (mConn.ipver == 6) {
                    source.setText(String.format(getResources().getString(R.string.ipv6_and_port), mConn.src_ip, mConn.src_port));
                    destination.setText(String.format(getResources().getString(R.string.ipv6_and_port), mConn.dst_ip, mConn.dst_port));
                } else {
                    source.setText(String.format(getResources().getString(R.string.ip_and_port), mConn.src_ip, mConn.src_port));
                    destination.setText(String.format(getResources().getString(R.string.ip_and_port), mConn.dst_ip, mConn.dst_port));
                }
            }

            if((mConn.info != null) && (!mConn.info.isEmpty())) {
                if(mConn.l7proto.equals("DNS"))
                    info_label.setText(R.string.query);
                else if(mConn.l7proto.equals("HTTP"))
                    info_label.setText(R.string.host);
                info.setText(mConn.info);
            } else
                info_row.setVisibility(View.GONE);

            AppDescriptor app = (mConn.uid >= 0) ? (new AppsResolver(mActivity)).getAppByUid(mConn.uid, 0) : null;
            if (app == null && mConn.uid < 0) {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    CaptureService service = CaptureService.getInstance();
                    if (service != null) {
                        int resolvedUid = service.getUidQ(mConn.ipproto, mConn.src_ip, mConn.src_port, mConn.dst_ip, mConn.dst_port);
                        if (resolvedUid >= 0) {
                            mConn.uid = resolvedUid;
                            app = (new AppsResolver(mActivity)).getAppByUid(mConn.uid, 0);
                        }
                    }
                }
                if (app == null) {
                    if (mConn.dst_port == 53 || mConn.dst_port == 5353 || mConn.src_port == 53 || mConn.src_port == 5353
                            || mConn.ipproto == 1 || mConn.ipproto == 58) {
                        mConn.uid = 1000;
                        app = (new AppsResolver(mActivity)).getAppByUid(1000, 0);
                    }
                }
            }

            if (app != null) {
                appLabel.setText(String.format(getResources().getString(R.string.app_and_proto), app.getName(), Integer.toString(mConn.uid)));
            } else if (mConn.uid == 1000) {
                appLabel.setText("Android System (UID 1000)");
            } else if (mConn.uid == android.os.Process.myUid()) {
                appLabel.setText("KotSafe (Security Engine)");
            } else if (mConn.uid > 10000) {
                appLabel.setText("App (UID " + mConn.uid + ")");
            } else if (mConn.uid > 0) {
                appLabel.setText("System Service (UID " + mConn.uid + ")");
            } else {
                if (mConn.dst_port == 53 || mConn.dst_port == 5353 || mConn.src_port == 53) {
                    appLabel.setText("Android System (DNS Resolver)");
                } else if (mConn.ipproto == 1 || mConn.ipproto == 58) {
                    appLabel.setText("Android System (ICMP / Ping)");
                } else if (mConn.info != null && !mConn.info.isEmpty()) {
                    appLabel.setText(mConn.info + " (Web Service)");
                } else {
                    appLabel.setText("System Network Daemon");
                }
            }

            ImageView appIcon = view.findViewById(R.id.overview_app_icon);
            if (appIcon != null) {
                Drawable unknown = ContextCompat.getDrawable(mActivity, R.drawable.ic_image);
                AppIconLoader.setIcon(appIcon, app, unknown);
            }

            View copySrc = view.findViewById(R.id.copy_source_btn);
            if (copySrc != null) {
                copySrc.setOnClickListener(v -> {
                    Utils.copyToClipboard(mActivity, mConn.src_ip + ":" + mConn.src_port);
                    Utils.showToast(mActivity, R.string.copied);
                });
            }
            View copyDst = view.findViewById(R.id.copy_dest_btn);
            if (copyDst != null) {
                copyDst.setOnClickListener(v -> {
                    Utils.copyToClipboard(mActivity, mConn.dst_ip + ":" + mConn.dst_port);
                    Utils.showToast(mActivity, R.string.copied);
                });
            }
            View copyHost = view.findViewById(R.id.copy_host_btn);
            if (copyHost != null) {
                copyHost.setOnClickListener(v -> {
                    if (mConn.info != null && !mConn.info.isEmpty()) {
                        Utils.copyToClipboard(mActivity, mConn.info);
                        Utils.showToast(mActivity, R.string.copied);
                    }
                });
            }
            View copyUrl = view.findViewById(R.id.copy_url_btn);
            if (copyUrl != null) {
                copyUrl.setOnClickListener(v -> {
                    if (mConn.url != null && !mConn.url.isEmpty()) {
                        Utils.copyToClipboard(mActivity, mConn.url);
                        Utils.showToast(mActivity, R.string.copied);
                    }
                });
            }

            mNacStatus = view.findViewById(R.id.detail_network_access_status);
            View nacBtn = view.findViewById(R.id.detail_network_access_btn);
            if (mNacStatus != null && nacBtn != null) {
                refreshNacStatus();

                nacBtn.setOnClickListener(v -> {
                    if (mActivity != null) {
                        ViewPager2 pager = mActivity.findViewById(R.id.pager);
                        if (pager != null && pager.getAdapter() != null) {
                            pager.setCurrentItem(pager.getAdapter().getItemCount() - 1, true);
                        }
                    }
                });
            }

            view.findViewById(R.id.decryption_status_row)
                    .setVisibility(CaptureService.isDecryptingTLS() ? View.VISIBLE : View.GONE);

            boolean has_scripts = (mConn.js_injected_scripts != null) && !mConn.js_injected_scripts.isEmpty();
            view.findViewById(R.id.injected_scripts_row)
                    .setVisibility(has_scripts ? View.VISIBLE : View.GONE);
            if(has_scripts)
                ((TextView)view.findViewById(R.id.injected_scripts)).setText(mConn.js_injected_scripts);

            if(mConn.url != null && !mConn.url.isEmpty())
                url.setText(mConn.url);
            else
                url_row.setVisibility(View.GONE);

            String srcCountryCode = (mConn.src_country != null && !mConn.src_country.isEmpty() && !mConn.src_country.equals("ZZ"))
                    ? mConn.src_country
                    : Utils.getIpCountryCode(mActivity, mConn.src_ip);
            if(srcCountryCode != null && !srcCountryCode.isEmpty() && !srcCountryCode.equals("ZZ")) {
                mConn.src_country = srcCountryCode;
                srcCountry.setText(Utils.getCountryName(mActivity, srcCountryCode));
                srcCountryFlag.setCountryCode(srcCountryCode);
                view.findViewById(R.id.source_country_row).setVisibility(View.VISIBLE);
            } else
                view.findViewById(R.id.source_country_row).setVisibility(View.GONE);

            String dstCountryCode = (mConn.country != null && !mConn.country.isEmpty() && !mConn.country.equals("ZZ"))
                    ? mConn.country
                    : Utils.getIpCountryCode(mActivity, mConn.dst_ip);
            if(dstCountryCode != null && !dstCountryCode.isEmpty() && !dstCountryCode.equals("ZZ")) {
                mConn.country = dstCountryCode;
                country.setText(Utils.getCountryName(mActivity, dstCountryCode));
                country_flag.setCountryCode(dstCountryCode);
                view.findViewById(R.id.country_row).setVisibility(View.VISIBLE);
            } else
                view.findViewById(R.id.country_row).setVisibility(View.GONE);

            if(mConn.asn.isKnown())
                asn.setText(mConn.asn.toString());
            else
                view.findViewById(R.id.asn_row).setVisibility(View.GONE);

            if(mConn.ifidx > 0) {
                String ifname = CaptureService.getInterfaceName(mConn.ifidx);

                if(!ifname.isEmpty()) {
                    view.findViewById(R.id.interface_row).setVisibility(View.VISIBLE);
                    ((TextView) view.findViewById(R.id.capture_interface)).setText(ifname);
                }
            }

            connectionUpdated();
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshNacStatus();
    }

    private void refreshNacStatus() {
        if (mNacStatus == null || mActivity == null || mConn == null)
            return;
        AppNetworkRule rule = AppNetworkRulesManager.getInstance(mActivity).getRule(mConn.uid);
        boolean isFwOn = Prefs.isFirewallEnabled(mActivity, PreferenceManager.getDefaultSharedPreferences(mActivity));
        if (rule != null && rule.isAnyRestricted() && isFwOn) {
            StringBuilder sb = new StringBuilder();
            if (rule.isWifiBlocked()) sb.append("Wi-Fi Blocked, ");
            if (rule.isMobileBlocked()) sb.append("Mobile Blocked, ");
            if (rule.isRoamingBlocked()) sb.append("Roaming Blocked, ");
            if (!rule.isAllowInBackground()) sb.append("Background Blocked, ");
            if (rule.isLanBlocked()) sb.append("LAN Blocked, ");
            String s = sb.toString();
            if (s.endsWith(", ")) s = s.substring(0, s.length() - 2);
            mNacStatus.setText(s);
            mNacStatus.setTextColor(ContextCompat.getColor(mActivity, R.color.statusError));
        } else if (!isFwOn && rule != null && rule.isAnyRestricted()) {
            mNacStatus.setText("Firewall Disabled (Rules Inactive)");
            mNacStatus.setTextColor(ContextCompat.getColor(mActivity, R.color.warning));
        } else {
            mNacStatus.setText("All Networks Allowed");
            mNacStatus.setTextColor(ContextCompat.getColor(mActivity, R.color.ok));
        }
    }

    @Override
    public boolean handleMenuAction(MenuItem item) {
        int id = item.getItemId();

        if(id == R.id.copy_to_clipboard) {
            ClipboardManager clipboard = (ClipboardManager) mActivity.getSystemService(Context.CLIPBOARD_SERVICE);
            ClipData clip = ClipData.newPlainText(getString(R.string.connection_details), getContents());
            clipboard.setPrimaryClip(clip);

            Utils.showToast(mActivity, R.string.copied);
            return true;
        } else if(id == R.id.share) {
            Utils.shareText(mActivity, getString(R.string.connection_details), getContents());
            return true;
        }

        return false;
    }

    private String getContents() {
        if (mConn == null || mActivity == null)
            return "";
        StringBuilder sb = new StringBuilder();
        sb.append("Application: ").append(mConn.uid).append("\n");
        sb.append("Protocol: ").append(mConn.l7proto).append(" (").append(Utils.proto2str(mConn.ipproto)).append(")\n");
        if (mConn.info != null && !mConn.info.isEmpty())
            sb.append("Host/SNI: ").append(mConn.info).append("\n");
        if (mConn.url != null && !mConn.url.isEmpty())
            sb.append("URL: ").append(mConn.url).append("\n");
        sb.append("Client: ").append(mConn.src_ip).append(":").append(mConn.src_port).append("\n");
        sb.append("Remote: ").append(mConn.dst_ip).append(":").append(mConn.dst_port).append("\n");
        if (mConn.country != null && !mConn.country.isEmpty())
            sb.append("Country: ").append(Utils.getCountryName(mActivity, mConn.country)).append("\n");
        if (mConn.asn != null && mConn.asn.isKnown())
            sb.append("ASN: ").append(mConn.asn).append("\n");
        sb.append("Traffic: ").append(Utils.formatBytes(mConn.rcvd_bytes)).append(" down, ").append(Utils.formatBytes(mConn.sent_bytes)).append(" up\n");
        sb.append("Packets: ").append(mConn.rcvd_pkts).append(" down, ").append(mConn.sent_pkts).append(" up\n");
        sb.append("Duration: ").append(Utils.formatDuration(mActivity, (mConn.last_seen - mConn.first_seen) / 1000)).append("\n");
        sb.append("Status: ").append(mConn.getStatusLabel(mActivity)).append("\n");
        return sb.toString();
    }

    @Override
    public void connectionUpdated() {
        Context context = mBytesView.getContext();

        mPayloadLen.setText(Utils.formatBytes(mConn.payload_length));
        mBytesView.setText(String.format(getResources().getString(R.string.rcvd_and_sent), Utils.formatBytes(mConn.rcvd_bytes), Utils.formatBytes(mConn.sent_bytes)));
        mPacketsView.setText(String.format(getResources().getString(R.string.rcvd_and_sent), Utils.formatIntShort(mConn.rcvd_pkts), Utils.formatIntShort(mConn.sent_pkts)));

        if(mConn.blocked_pkts > 0) {
            mBlockedPkts.setText(String.format(getResources().getString(R.string.n_pkts), Utils.formatIntShort(mConn.blocked_pkts)));
            mBlockedPktsRow.setVisibility(View.VISIBLE);
        }

        mDurationView.setText(Utils.formatDuration(context, (mConn.last_seen - mConn.first_seen) / 1000));
        mFirstSeen.setText(Utils.formatEpochMillis(mActivity, mConn.first_seen));
        mLastSeen.setText(Utils.formatEpochMillis(mActivity, mConn.last_seen));
        mStatus.setText(mConn.getStatusLabel(mActivity));
        if (mConn.status < ConnectionDescriptor.CONN_STATUS_CLOSED) {
            mStatus.setBackgroundResource(R.drawable.badge_pill_active);
            mStatus.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeActiveFg));
        } else if (mConn.is_blocked || mConn.isBlacklisted()) {
            mStatus.setBackgroundResource(R.drawable.badge_pill_blocked);
            mStatus.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeBlockedFg));
        } else {
            mStatus.setBackgroundResource(R.drawable.badge_pill_closed);
            mStatus.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeClosedFg));
        }
        mDecStatus.setText(mConn.getDecryptionStatusLabel(mActivity));
        Utils.setDecryptionIcon(mDecIcon, mConn);
        refreshNacStatus();
        //mTcpFlags.setText(Utils.tcpFlagsToStr(mConn.getRcvdTcpFlags()) + " <- " + Utils.tcpFlagsToStr(mConn.getSentTcpFlags()));
        mBlacklistedIp.setVisibility(mConn.isBlacklistedIp() ? View.VISIBLE : View.GONE);
        mBlacklistedHost.setVisibility(mConn.isBlacklistedHost() ? View.VISIBLE : View.GONE);

        if (mConn.error > 0) {
            mSocketErrnoRow.setVisibility(View.VISIBLE);

            Pair<Integer, Integer> errnoInfo = getSocketErrnoInfo(mConn.error);
            mSocketErrno.setText(context.getString(R.string.error_code_with_text,
                    context.getString((errnoInfo != null) ? errnoInfo.first : R.string.unknown_app),
                    mConn.error));

            if (errnoInfo != null) {
                final int msgId = errnoInfo.second;

                mSocketErrnoInfo.setOnClickListener(view -> {
                    Context ctx = getContext();
                    if (ctx != null)
                        Utils.showHelpDialog(ctx, msgId);
                });
            } else
                mSocketErrnoInfo.setVisibility(View.GONE);
        }

        if(mConn.decryption_error != null) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.danger));
            mError.setText(mConn.decryption_error);
            mError.setVisibility(View.VISIBLE);
        } else if(mConn.is_blocked || mConn.isBlacklisted()) {
            String category = mConn.getBlockCategory();
            String reason = mConn.getBlockReasonLabel(context);
            mError.setTextColor(ContextCompat.getColor(context, R.color.danger));
            mError.setText("🛑 " + context.getString(R.string.connection_blocked_detail) + " [" + category + "]\nReason: " + reason);
            mError.setVisibility(View.VISIBLE);
        } else if(!mConn.hasSeenStart()) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.warning));
            mError.setText(context.getString(R.string.connection_start_not_seen));
            mError.setVisibility(View.VISIBLE);
        } else if(mConn.isPortMappingApplied()) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.colorTabText));
            mError.setText(context.getString(R.string.connection_redirected_port_map));
            mError.setVisibility(View.VISIBLE);
        } else if(mConn.payload_length == 0) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.warning));
            mError.setText(context.getString(R.string.warn_no_app_data));
            mError.setVisibility(View.VISIBLE);
        } else if(mConn.netd_block_missed) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.warning));
            mError.setText(context.getString(R.string.netd_block_missed));
            mError.setVisibility(View.VISIBLE);
        } else if(mConn.getDecryptionStatus() == ConnectionDescriptor.DecryptionStatus.ENCRYPTED) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.colorTabText));
            mError.setText(R.string.decryption_info_no_rule);
            mError.setVisibility(View.VISIBLE);
        } else if((mConn.getDecryptionStatus() == ConnectionDescriptor.DecryptionStatus.NOT_DECRYPTABLE)
                && mConn.l7proto.equals("QUIC") &&
                CaptureService.isDecryptingTLS()) {
            mError.setTextColor(ContextCompat.getColor(context, R.color.warning));
            mError.setText(R.string.decrypt_quic_notice);
            mError.setVisibility(View.VISIBLE);
        } else
            mError.setVisibility(View.GONE);

        renderSingleSocketDiagnostics();
        renderDnsSourceAttribution();
    }

    private void renderSingleSocketDiagnostics() {
        if (mSocketContainer == null || mConn == null || mActivity == null)
            return;

        mSocketContainer.removeAllViews();
        List<ConnectionDescriptor.SocketSession> sessions = mConn.getSocketSessions();
        int count = sessions.size();

        if (mSocketBadge != null) {
            mSocketBadge.setText(count + (count == 1 ? " Socket" : " Sockets"));
        }

        if (mSocketSummary != null) {
            if (count > 1) {
                mSocketSummary.setText(String.format(Locale.getDefault(),
                        "Aggregated flow combining %d ephemeral sockets. Each session's client port, lifecycle, and transfer are detailed below:", count));
            } else {
                mSocketSummary.setText("Single-socket session with granular lifecycle state and throughput metrics:");
            }
        }

        LayoutInflater inflater = LayoutInflater.from(mActivity);
        for (int i = 0; i < sessions.size(); i++) {
            ConnectionDescriptor.SocketSession session = sessions.get(i);
            View row = inflater.inflate(R.layout.item_single_socket_session, mSocketContainer, false);

            TextView endpoint = row.findViewById(R.id.socket_endpoint);
            TextView protoBadge = row.findViewById(R.id.socket_proto_badge);
            TextView statusBadge = row.findViewById(R.id.socket_status_badge);
            TextView traffic = row.findViewById(R.id.socket_traffic);
            TextView time = row.findViewById(R.id.socket_time);

            endpoint.setText(String.format(Locale.getDefault(), ":%d → :%d", session.src_port, session.dst_port));

            if (protoBadge != null) {
                String l7 = (!session.l7proto.isEmpty()) ? session.l7proto : (mConn.l7proto != null ? mConn.l7proto : "");
                if (!l7.isEmpty()) {
                    protoBadge.setText(l7);
                    protoBadge.setVisibility(View.VISIBLE);
                } else {
                    protoBadge.setVisibility(View.GONE);
                }
            }

            statusBadge.setText(session.getTcpStateString());

            switch (session.tcp_state) {
                case 1: // SYN_SENT
                case 3: // FIN_WAIT
                    statusBadge.setBackgroundResource(R.drawable.badge_pill_proto);
                    statusBadge.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeProtoFg));
                    break;
                case 2: // ESTABLISHED
                    statusBadge.setBackgroundResource(R.drawable.badge_pill_active);
                    statusBadge.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeActiveFg));
                    break;
                case 4: // CLOSED
                    statusBadge.setBackgroundResource(R.drawable.badge_pill_closed);
                    statusBadge.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeClosedFg));
                    break;
                case 5: // RESET
                    statusBadge.setBackgroundResource(R.drawable.badge_pill_blocked);
                    statusBadge.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeBlockedFg));
                    break;
                default:
                    statusBadge.setBackgroundResource(R.drawable.badge_pill_proto);
                    statusBadge.setTextColor(ContextCompat.getColor(mActivity, R.color.badgeProtoFg));
                    break;
            }

            traffic.setText(String.format(Locale.getDefault(), "↑ %s · ↓ %s",
                    Utils.formatBytes(session.sent_bytes), Utils.formatBytes(session.rcvd_bytes)));

            String formattedDuration = session.getFormattedDuration();
            time.setText(String.format(Locale.getDefault(), "%s · %s", formattedDuration, Utils.formatEpochMillis(mActivity, session.last_seen)));

            row.setOnClickListener(v -> {
                String copyText = String.format(Locale.getDefault(),
                        "%s:%d -> %s:%d [%s] (Sent: %s, Rcvd: %s, Duration: %s)",
                        mConn.src_ip, session.src_port, mConn.dst_ip, session.dst_port,
                        session.getTcpStateString(), Utils.formatBytes(session.sent_bytes),
                        Utils.formatBytes(session.rcvd_bytes), formattedDuration);
                Utils.copyToClipboard(mActivity, copyText);
                android.widget.Toast.makeText(mActivity, "Socket info copied to clipboard", android.widget.Toast.LENGTH_SHORT).show();
            });

            mSocketContainer.addView(row);
        }
    }

    private Pair<Integer, Integer> getSocketErrnoInfo(int errno) {
        return switch (errno) {
            case 32 -> /* EPIPE */
                    new Pair<>(R.string.errno_epipe, R.string.errno_epipe_msg);
            case 100 -> /* ENETDOWN */
                    new Pair<>(R.string.errno_enetdown, R.string.errno_enetdown_msg);
            case 101 -> /* ENETUNREACH */
                    new Pair<>(R.string.errno_enetunreach, R.string.errno_enetunreach_msg);
            case 102 -> /* ENETRESET */
                    new Pair<>(R.string.errno_enetreset, R.string.errno_enetreset_msg);
            case 103 -> /* ECONNABORTED */
                    new Pair<>(R.string.errno_econnaborted, R.string.errno_econnaborted_msg);
            case 104 -> /* ECONNRESET */
                    new Pair<>(R.string.errno_econnreset, R.string.errno_econnreset_msg);
            case 110 -> /* ETIMEDOUT */
                    new Pair<>(R.string.errno_etimedout, R.string.errno_etimedout_msg);
            case 111 -> /* ECONNREFUSED */
                    new Pair<>(R.string.errno_econnrefused, R.string.errno_econnrefused_msg);
            case 113 -> /* EHOSTUNREACH */
                    new Pair<>(R.string.errno_ehostunreach, R.string.errno_ehostunreach_msg);
            default -> null;
        };
    }

    private void renderDnsSourceAttribution() {
        if (mCardDnsAttribution == null || mConn == null || mActivity == null)
            return;

        boolean isSystemOrDns = (mConn.uid == 1000 || mConn.uid <= 0 || mConn.isDns());
        if (!isSystemOrDns) {
            mCardDnsAttribution.setVisibility(View.GONE);
            return;
        }

        mCardDnsAttribution.setVisibility(View.VISIBLE);
        if (mCorrelatedContainer != null) {
            mCorrelatedContainer.removeAllViews();
        }

        ConnectionsRegister reg = CaptureService.requireConnsRegister();
        long targetTime = mConn.last_seen > 0 ? mConn.last_seen : mConn.first_seen;
        List<ConnectionsRegister.CorrelatedApp> correlatedApps = reg.getCorrelatedAppsForTimestamp(targetTime, 5000);

        if (correlatedApps.isEmpty()) {
            if (mNoCorrelatedApps != null) mNoCorrelatedApps.setVisibility(View.VISIBLE);
            if (mCorrelatedHeader != null) mCorrelatedHeader.setVisibility(View.GONE);
            return;
        }

        if (mNoCorrelatedApps != null) mNoCorrelatedApps.setVisibility(View.GONE);
        if (mCorrelatedHeader != null) mCorrelatedHeader.setVisibility(View.VISIBLE);

        LayoutInflater inflater = LayoutInflater.from(mActivity);
        Drawable unknown = ContextCompat.getDrawable(mActivity, R.drawable.ic_image);

        for (ConnectionsRegister.CorrelatedApp item : correlatedApps) {
            View itemView = inflater.inflate(R.layout.item_correlated_app, mCorrelatedContainer, false);
            ImageView appIcon = itemView.findViewById(R.id.correlated_app_icon);
            TextView appName = itemView.findViewById(R.id.correlated_app_name);
            TextView appPkg = itemView.findViewById(R.id.correlated_app_pkg);
            TextView appTiming = itemView.findViewById(R.id.correlated_app_timing);
            com.google.android.material.button.MaterialButton btnTimeline = itemView.findViewById(R.id.btn_correlated_timeline);
            com.google.android.material.button.MaterialButton btnFirewall = itemView.findViewById(R.id.btn_correlated_firewall);

            AppDescriptor app = item.app;
            if (appIcon != null) {
                AppIconLoader.setIcon(appIcon, app, unknown);
            }
            if (appName != null) {
                appName.setText(app.getName());
            }
            if (appPkg != null) {
                appPkg.setText(app.getPackageName() + " • UID " + app.getUid());
            }
            if (appTiming != null) {
                double deltaSec = item.timeDeltaMs / 1000.0;
                if (deltaSec < 0.8) {
                    if (item.sampleTarget != null && !item.sampleTarget.isEmpty()) {
                        appTiming.setText(getString(R.string.app_correlated_time_same) + " (" + item.sampleTarget + ")");
                    } else {
                        appTiming.setText(getString(R.string.app_correlated_time_same));
                    }
                } else {
                    String target = (item.sampleTarget != null && !item.sampleTarget.isEmpty()) ? item.sampleTarget : "traffic";
                    appTiming.setText(String.format(Locale.getDefault(), getString(R.string.app_correlated_time_delta), deltaSec, target));
                }
            }

            if (btnTimeline != null) {
                btnTimeline.setOnClickListener(v -> {
                    if (mActivity != null) {
                        com.kotsafe.security.views.AppTimelineDialog.newInstance(app.getUid(), mConn.incr_id)
                                .show(getChildFragmentManager(), "AppTimelineDialog");
                    }
                });
            }

            AppNetworkRulesManager mgr = AppNetworkRulesManager.getInstance(mActivity);
            AppNetworkRule rule = mgr.getRule(app.getPackageName(), app.getUid());
            boolean isAppBlocked = rule != null && rule.isAnyRestricted();

            if (btnFirewall != null) {
                if (isAppBlocked) {
                    btnFirewall.setText(R.string.app_blocked);
                    btnFirewall.setTextColor(ContextCompat.getColor(mActivity, R.color.statusError));
                    btnFirewall.setStrokeColorResource(R.color.statusError);
                } else {
                    btnFirewall.setText(R.string.app_correlated_firewall);
                }

                btnFirewall.setOnClickListener(v -> {
                    if (mActivity == null) return;
                    AppNetworkRule currentRule = mgr.getRule(app.getPackageName(), app.getUid());
                    boolean blocked = currentRule != null && currentRule.isWifiBlocked() && currentRule.isMobileBlocked();

                    new com.google.android.material.dialog.MaterialAlertDialogBuilder(mActivity)
                            .setTitle(app.getName() + " - Firewall")
                            .setMessage(blocked
                                    ? "This application is currently blocked by KotSafe Firewall."
                                    : "Block all network traffic (Wi-Fi & Mobile) for " + app.getName() + " to prevent all ads, trackers, and background connections?")
                            .setPositiveButton(blocked ? "Unblock App" : "Block App", (d, w) -> {
                                currentRule.setWifiBlocked(!blocked);
                                currentRule.setMobileBlocked(!blocked);
                                mgr.setRule(currentRule);
                                Utils.showToast(mActivity, blocked ? R.string.app_unblocked : R.string.app_blocked_info, app.getName());
                                renderDnsSourceAttribution();
                            })
                            .setNeutralButton("App Details", (d, w) -> {
                                Intent intent = new Intent(mActivity, com.kotsafe.security.activities.AppDetailsActivity.class);
                                intent.putExtra(com.kotsafe.security.activities.AppDetailsActivity.APP_UID_EXTRA, app.getUid());
                                Utils.startActivity(mActivity, intent);
                            })
                            .setNegativeButton(android.R.string.cancel, null)
                            .show();
                });
            }

            if (mCorrelatedContainer != null) {
                mCorrelatedContainer.addView(itemView);
            }
        }
    }
}
